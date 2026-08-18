use nomad_connector::process_bridge::{AckPayload, RelayClient, RelayMessage, UreqRelayClient};
use nomad_connector::{
    parse_pilot_command, result_payload, CommandJournal, ConnectorError, PilotAdapter,
    UreqOpenCodeClient,
};
use serde_json::{json, Value};
use std::env;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

struct Config {
    relay_url: String,
    relay_token: String,
    channel: String,
    session_id: String,
    journal: PathBuf,
    once: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pilot-host-bridge failed: {}", error.error_code());
        std::process::exit(1);
    }
}

fn run() -> Result<(), ConnectorError> {
    let config = parse_args()?;
    let relay = UreqRelayClient::new(config.relay_url, config.relay_token);
    let adapter = PilotAdapter::new(
        UreqOpenCodeClient::fixed()?,
        CommandJournal::open(&config.journal)?,
    );
    publish_capture(&relay, &adapter, &config.channel, &config.session_id)?;

    loop {
        let messages = relay.poll_messages(&config.channel, "host")?;
        for message in messages {
            if let Err(error) = process_message(&relay, &adapter, &message) {
                // Invalid commands are returned as explicit fail-closed results.
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
                post_and_ack(&relay, &message, payload)?;
            }
        }
        if config.once {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn process_message(
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

fn publish_capture(
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

fn parse_args() -> Result<Config, ConnectorError> {
    let mut args = env::args().skip(1);
    let mut relay_url = None;
    let mut relay_token = None;
    let mut channel = None;
    let mut session_id = "pilot-session".to_string();
    let mut journal = PathBuf::from("pilot-host-bridge.sqlite3");
    let mut once = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => once = true,
            "--relay-url" => relay_url = args.next(),
            "--relay-token" => relay_token = args.next(),
            "--channel" => channel = args.next(),
            "--session-id" => session_id = args.next().ok_or_else(|| missing(&arg))?,
            "--journal" => journal = PathBuf::from(args.next().ok_or_else(|| missing(&arg))?),
            _ => return Err(ConnectorError::Other(format!("unknown argument {arg}"))),
        }
    }
    Ok(Config {
        relay_url: relay_url.ok_or_else(|| missing("--relay-url"))?,
        relay_token: relay_token.ok_or_else(|| missing("--relay-token"))?,
        channel: channel.ok_or_else(|| missing("--channel"))?,
        session_id,
        journal,
        once,
    })
}

fn missing(name: &str) -> ConnectorError {
    ConnectorError::Other(format!("missing required value for {name}"))
}
