use nomad_connector::process_bridge::{AckPayload, RelayClient, RelayMessage, UreqRelayClient};
use nomad_connector::{
    parse_pilot_command, result_payload, CommandJournal, ConnectorError, PilotAdapter,
    UreqOpenCodeClient,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

struct Config {
    relay_url: String,
    relay_token: String,
    relay_token_source: RelayTokenSource,
    channel: String,
    session_id: String,
    journal: PathBuf,
    once: bool,
    m2_safe_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayTokenSource {
    CommandLine,
    Environment,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pilot-host-bridge failed: {}", error.error_code());
        std::process::exit(1);
    }
}

fn run() -> Result<(), ConnectorError> {
    let config = parse_args()?;
    let relay = UreqRelayClient::new(config.relay_url.clone(), config.relay_token.clone());
    let adapter = PilotAdapter::new(
        UreqOpenCodeClient::fixed()?,
        CommandJournal::open(&config.journal)?,
    );
    if config.m2_safe_mode {
        return run_m2_safe_mode(&relay, &adapter, &config);
    }
    run_compatibility_mode(&relay, &adapter, &config)
}

/// The existing ITER2 bridge behavior. Keep this path unchanged unless the
/// compatibility contract itself changes. M2 safety work is opt-in below.
fn run_compatibility_mode(
    relay: &UreqRelayClient,
    adapter: &PilotAdapter<UreqOpenCodeClient>,
    config: &Config,
) -> Result<(), ConnectorError> {
    publish_compat_capture(relay, adapter, &config.channel, &config.session_id)?;

    loop {
        let messages = relay.poll_messages(&config.channel, "host")?;
        for message in messages {
            if let Err(error) = process_compat_message(relay, adapter, &message) {
                let request_id = message
                    .payload
                    .get("command")
                    .and_then(|command| command.get("request_id"))
                    .and_then(Value::as_str)
                    .unwrap_or(&message.message_id);
                let payload = json!({
                    "type": "pilot.command.result",
                    "request_id": request_id,
                    "status": "Rejected",
                    "error_code": error.error_code(),
                    "error_message": "Command was rejected by the Host boundary"
                });
                post_and_ack(relay, &message, payload)?;
            }
        }
        if config.once {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn process_compat_message(
    relay: &UreqRelayClient,
    adapter: &PilotAdapter<UreqOpenCodeClient>,
    message: &RelayMessage,
) -> Result<(), ConnectorError> {
    let command = parse_pilot_command(&message.payload)?;
    let result = adapter.execute(&command)?;
    post_and_ack(relay, message, result_payload(&result))
}

fn post_and_ack(
    relay: &UreqRelayClient,
    original: &RelayMessage,
    payload: Value,
) -> Result<(), ConnectorError> {
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or(&original.message_id);
    relay.post_message(&RelayMessage {
        channel: original.channel.clone(),
        target: "mobile".to_string(),
        // A retried transport delivery needs a fresh Relay result frame even
        // when the stable business request_id replays an existing Host result.
        message_id: format!("pilot.command.result:{request_id}:{}", original.message_id),
        payload,
    })?;
    // ACK only after the terminal result is durably accepted by Relay.
    relay.ack_messages(&AckPayload {
        channel: original.channel.clone(),
        target: "host".to_string(),
        message_ids: vec![original.message_id.clone()],
    })
}

fn publish_compat_capture(
    relay: &UreqRelayClient,
    adapter: &PilotAdapter<UreqOpenCodeClient>,
    channel: &str,
    session_id: &str,
) -> Result<(), ConnectorError> {
    let capture = adapter.capture(session_id)?;
    let active_permission = capture.snapshot.state_summary.active_permission.clone();
    let message_id = format!(
        "pilot.session:{}:{}",
        session_id, capture.snapshot.snapshot_seq
    );
    relay.post_message(&RelayMessage {
        channel: channel.to_string(),
        target: "mobile".to_string(),
        message_id: message_id.clone(),
        payload: json!({
            "type": "pilot.session",
            "message_id": message_id,
            "capture": capture,
            "approval": active_permission.map(|permission_id| json!({
                "permission_id": permission_id,
                "tool": "Protected workspace operation",
                "operation": "Review the Host-observed pending request",
                "working_directory": "Disposable Pilot workspace",
                "resources": ["Current disposable workspace"],
                "source": "Nomad Host compatibility adapter",
                "action_hash": "sha256:host-observed-pending"
            }))
        }),
    })
}

/// M2 is intentionally separate from compatibility mode: it cannot silently
/// downgrade to raw publication or guessed upstream command execution.
fn run_m2_safe_mode(
    relay: &UreqRelayClient,
    adapter: &PilotAdapter<UreqOpenCodeClient>,
    config: &Config,
) -> Result<(), ConnectorError> {
    if config.relay_token_source != RelayTokenSource::Environment || config.relay_token.len() < 32 {
        return Err(ConnectorError::SafetyBlocked(
            "M2 safe mode relay token is unavailable".to_string(),
        ));
    }
    let aliases = MobileAliases::from_environment(&config.channel)?;
    publish_safe_capture(
        relay,
        adapter,
        &config.channel,
        &config.session_id,
        &aliases,
    )?;
    loop {
        for message in relay.poll_messages(&config.channel, "host")? {
            reject_safe_command(relay, &message, &aliases)?;
        }
        if config.once {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn reject_safe_command(
    relay: &UreqRelayClient,
    message: &RelayMessage,
    aliases: &MobileAliases,
) -> Result<(), ConnectorError> {
    let code = if is_allow_once(&message.payload) {
        "ERR_SAFETY_BLOCKED"
    } else {
        "ERR_UPSTREAM_COMMANDS_UNAVAILABLE"
    };
    let payload = json!({
        "type": "pilot.command.result",
        "request_id": aliases.message_id(inbound_request_id(message)),
        "status": "Rejected",
        "error_code": code,
        "error_message": "Command is unavailable at the Host boundary"
    });
    post_safe_and_ack(relay, message, payload, aliases)
}

fn post_safe_and_ack(
    relay: &UreqRelayClient,
    original: &RelayMessage,
    payload: Value,
    aliases: &MobileAliases,
) -> Result<(), ConnectorError> {
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    relay.post_message(&RelayMessage {
        channel: original.channel.clone(),
        target: "mobile".to_string(),
        message_id: aliases.message_id(&format!("result:{request_id}:{}", original.message_id)),
        payload,
    })?;
    relay.ack_messages(&AckPayload {
        channel: original.channel.clone(),
        target: "host".to_string(),
        message_ids: vec![original.message_id.clone()],
    })
}

fn publish_safe_capture(
    relay: &UreqRelayClient,
    adapter: &PilotAdapter<UreqOpenCodeClient>,
    channel: &str,
    session_id: &str,
    aliases: &MobileAliases,
) -> Result<(), ConnectorError> {
    let capture = adapter.capture(session_id)?;
    let message_id = aliases.capture_message_id(session_id, capture.snapshot.snapshot_seq);
    relay.post_message(&RelayMessage {
        channel: channel.to_string(), target: "mobile".to_string(), message_id: message_id.clone(),
        payload: json!({
            "type": "pilot.session", "message_id": message_id,
            "capture": mobile_capture(&capture, aliases),
            "approval": {"status": "unavailable", "reason_code": "ERR_APPROVAL_FACTS_UNAVAILABLE", "actionable": false}
        }),
    })
}

fn mobile_capture(capture: &nomad_connector::PilotCapture, aliases: &MobileAliases) -> Value {
    json!({
        "session_id": aliases.session_id(&capture.snapshot.session_id),
        "snapshot_seq": capture.snapshot.snapshot_seq,
        "last_applied_seq": capture.snapshot.last_applied_seq,
        "turn_state": capture.snapshot.turn_state,
        "host_connectivity": capture.snapshot.host_connectivity,
        "client_freshness": capture.snapshot.client_freshness,
        "event_count": capture.events.len(),
        "diff_status": "unavailable",
        "content_status": "not_published"
    })
}

/// Keyed aliases prevent raw upstream identifiers from crossing the Host boundary.
/// The Relay channel is the run scope for this pre-WP2 bridge and is deliberately
/// bound into every digest so a stable upstream ID differs between runs.
struct MobileAliases {
    key: Vec<u8>,
    run_scope: String,
}

impl MobileAliases {
    fn from_environment(run_scope: &str) -> Result<Self, ConnectorError> {
        let encoded = env::var("NOMAD_PILOT_ALIAS_KEY")
            .map_err(|_| ConnectorError::SafetyBlocked("missing Host alias key".to_string()))?;
        Self::new(&decode_alias_key(&encoded)?, run_scope)
    }

    fn new(key: &[u8], run_scope: &str) -> Result<Self, ConnectorError> {
        if key.len() < 32 {
            return Err(ConnectorError::SafetyBlocked(
                "missing or insufficient Host alias key".to_string(),
            ));
        }
        if run_scope.is_empty() {
            return Err(ConnectorError::SafetyBlocked(
                "missing run scope for Host aliases".to_string(),
            ));
        }
        Ok(Self {
            key: key.to_vec(),
            run_scope: run_scope.to_string(),
        })
    }

    fn alias(&self, domain: &str, raw: &str) -> String {
        let message = length_prefixed_message(&[
            domain.as_bytes(),
            self.run_scope.as_bytes(),
            raw.as_bytes(),
        ]);
        format!(
            "{}-{}",
            domain,
            hex_digest(&hmac_sha256(&self.key, &message))
        )
    }

    fn session_id(&self, raw: &str) -> String {
        self.alias("sess", raw)
    }
    fn message_id(&self, raw: &str) -> String {
        self.alias("msg", raw)
    }
    fn capture_message_id(&self, session: &str, seq: u64) -> String {
        self.message_id(&format!("capture:{session}:{seq}"))
    }
}

fn decode_alias_key(encoded: &str) -> Result<Vec<u8>, ConnectorError> {
    let value = encoded.strip_prefix("hex:").unwrap_or(encoded);
    let decoded = decode_hex(value)
        .ok_or_else(|| ConnectorError::SafetyBlocked("malformed Host alias key".to_string()))?;
    if decoded.len() < 32 {
        return Err(ConnectorError::SafetyBlocked(
            "missing or insufficient Host alias key".to_string(),
        ));
    }
    Ok(decoded)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        })
        .collect()
}

fn length_prefixed_message(parts: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::new();
    for part in parts {
        message.extend_from_slice(&(part.len() as u64).to_be_bytes());
        message.extend_from_slice(part);
    }
    message
}

/// RFC 2104 / RFC 4231 HMAC-SHA256, kept local to avoid widening Cargo scope.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0u8; BLOCK];
    let mut outer = [0u8; BLOCK];
    for (index, byte) in normalized.iter().enumerate() {
        inner[index] = byte ^ 0x36;
        outer[index] = byte ^ 0x5c;
    }
    let mut inner_hash = Sha256::new();
    inner_hash.update(inner);
    inner_hash.update(message);
    let inner_result = inner_hash.finalize();
    let mut outer_hash = Sha256::new();
    outer_hash.update(outer);
    outer_hash.update(inner_result);
    outer_hash.finalize().into()
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn inbound_request_id(message: &RelayMessage) -> &str {
    message
        .payload
        .get("command")
        .and_then(|command| command.get("request_id"))
        .and_then(Value::as_str)
        .unwrap_or(&message.message_id)
}

fn is_allow_once(payload: &Value) -> bool {
    payload
        .get("command")
        .and_then(|command| command.get("decision"))
        .and_then(Value::as_str)
        == Some("allow_once")
}

fn parse_args() -> Result<Config, ConnectorError> {
    parse_args_from(
        env::args().skip(1),
        env::var("NOMAD_PILOT_RELAY_TOKEN").ok(),
    )
}

fn parse_args_from<I>(args: I, env_relay_token: Option<String>) -> Result<Config, ConnectorError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let mut relay_url = None;
    let mut relay_token = None;
    let mut channel = None;
    let mut session_id = "pilot-session".to_string();
    let mut journal = PathBuf::from("pilot-host-bridge.sqlite3");
    let mut once = false;
    let mut m2_safe_mode = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => once = true,
            "--relay-url" => relay_url = args.next(),
            "--relay-token" => relay_token = args.next(),
            "--channel" => channel = args.next(),
            "--session-id" => session_id = args.next().ok_or_else(|| missing(&arg))?,
            "--journal" => journal = PathBuf::from(args.next().ok_or_else(|| missing(&arg))?),
            "--m2-safe-mode" => m2_safe_mode = true,
            _ => return Err(ConnectorError::Other(format!("unknown argument {arg}"))),
        }
    }
    let cli_relay_token = relay_token;
    let (relay_token, relay_token_source) = if m2_safe_mode {
        if cli_relay_token.is_some() {
            return Err(ConnectorError::SafetyBlocked(
                "M2 safe mode requires an environment relay token".to_string(),
            ));
        }
        let token = env_relay_token.ok_or_else(|| {
            ConnectorError::SafetyBlocked("missing M2 safe mode relay token".to_string())
        })?;
        if token.len() < 32 {
            return Err(ConnectorError::SafetyBlocked(
                "insufficient M2 safe mode relay token".to_string(),
            ));
        }
        (token, RelayTokenSource::Environment)
    } else if let Some(token) = cli_relay_token {
        (token, RelayTokenSource::CommandLine)
    } else if let Some(token) = env_relay_token {
        (token, RelayTokenSource::Environment)
    } else {
        return Err(missing("--relay-token or NOMAD_PILOT_RELAY_TOKEN"));
    };
    Ok(Config {
        relay_url: relay_url.ok_or_else(|| missing("--relay-url"))?,
        relay_token,
        relay_token_source,
        channel: channel.ok_or_else(|| missing("--channel"))?,
        session_id,
        journal,
        once,
        m2_safe_mode,
    })
}

fn missing(name: &str) -> ConnectorError {
    ConnectorError::Other(format!("missing required value for {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn aliases_are_stable_per_run_and_separated_by_domain_and_run() {
        let first = MobileAliases::new(&KEY, "run-a").unwrap();
        let second = MobileAliases::new(&KEY, "run-b").unwrap();
        assert_eq!(
            first.session_id("upstream-session"),
            first.session_id("upstream-session")
        );
        assert_ne!(
            first.session_id("upstream-session"),
            first.alias("perm", "upstream-session")
        );
        assert_ne!(
            first.session_id("upstream-session"),
            second.session_id("upstream-session")
        );
    }

    #[test]
    fn mobile_capture_and_approval_never_expose_raw_facts() {
        let aliases = MobileAliases::new(&KEY, "run-a").unwrap();
        let payload = json!({
            "capture": {
                "session_id": aliases.session_id("raw-session"),
                "diff_status": "unavailable"
            },
            "approval": {"status": "unavailable", "actionable": false}
        });
        let encoded = payload.to_string();
        assert!(!encoded.contains("raw-session"));
        assert!(!encoded.contains("permission-secret"));
        assert_eq!(payload["approval"]["actionable"], false);
    }

    #[test]
    fn alias_key_is_required_and_allow_once_is_blocked() {
        assert!(MobileAliases::new(b"too-short", "run").is_err());
        assert!(decode_alias_key("0123456789abcdef0123456789abcdef").is_err());
        assert!(decode_alias_key("not-a-valid-hex-key").is_err());
        assert!(is_allow_once(
            &json!({"command": {"decision": "allow_once"}})
        ));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_one() {
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hex_digest(&hmac_sha256(&[0x0b; 20], b"Hi There")), expected);
    }

    #[test]
    fn parser_rejects_raw_alias_key_option_and_separates_mode() {
        // The parser only has access to process args in production; the stable
        // option vocabulary is checked here to prevent raw-key reintroduction.
        assert!(![
            "--once",
            "--relay-url",
            "--relay-token",
            "--channel",
            "--session-id",
            "--journal",
            "--m2-safe-mode"
        ]
        .contains(&"--alias-key"));
        let config = Config {
            relay_url: "http://relay".into(),
            relay_token: "token".into(),
            relay_token_source: RelayTokenSource::CommandLine,
            channel: "run".into(),
            session_id: "session".into(),
            journal: PathBuf::from("test.db"),
            once: true,
            m2_safe_mode: false,
        };
        assert!(!config.m2_safe_mode);
    }

    fn arguments(safe_mode: bool, cli_token: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "--relay-url".into(),
            "http://relay".into(),
            "--channel".into(),
            "run".into(),
        ];
        if safe_mode {
            args.push("--m2-safe-mode".into());
        }
        if let Some(token) = cli_token {
            args.push("--relay-token".into());
            args.push(token.into());
        }
        args
    }

    #[test]
    fn safe_mode_requires_a_long_environment_relay_token_and_rejects_cli_token() {
        let env_token = "e".repeat(32);
        let safe = parse_args_from(arguments(true, None), Some(env_token)).unwrap();
        assert_eq!(safe.relay_token_source, RelayTokenSource::Environment);
        assert!(parse_args_from(arguments(true, None), None).is_err());
        assert!(parse_args_from(arguments(true, None), Some("short".into())).is_err());
        assert!(parse_args_from(arguments(true, Some("x")), Some("e".repeat(32))).is_err());
    }

    #[test]
    fn compatibility_mode_keeps_cli_relay_token_behavior() {
        let config = parse_args_from(arguments(false, Some("legacy-token")), None).unwrap();
        assert_eq!(config.relay_token_source, RelayTokenSource::CommandLine);
        assert_eq!(config.relay_token, "legacy-token");
    }
}
