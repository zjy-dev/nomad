use crate::error::ConnectorError;
use crate::journal::CommandJournal;
use crate::opencode_adapter::{PilotAdapter, PilotCapture, UreqOpenCodeClient};
use crate::projection::ProjectedEvent;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const ALPHA_SCHEMA: &str = "nomad.alpha.readonly.host.v1";
const LOCAL_ALPHA_SOURCE: &str = "local-alpha-projector";
const MAX_FRAME_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_PROJECTED_EVENTS: usize = 32;
const MAX_SAFE_ID_BYTES: usize = 32;
const RELAY_MAGIC: u32 = 0x4E4D_4401;
const RELAY_PROTOCOL_VERSION: u16 = 1;
const RELAY_FLAG_REQUEST: u16 = 0x0001;
const RELAY_HEADER_SIZE: usize = 48;
const RELAY_SIGNATURE_SIZE: usize = 64;
const FIXED_DEVICE_ID_HEX: &str = "00112233445566778899aabbccddeeff";
const FIXED_PUBLIC_KEY_HEX: &str =
    "91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864";
const PRIVATE_KEY_ENV: &str = "NOMAD_ALPHA_DEVICE_PRIVATE_KEY_HEX";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlphaProjectorConfig {
    pub relay_url: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlphaProjectorReceipt {
    pub status: String,
    pub frame_id: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlphaReadonlyProjection {
    pub schema: String,
    pub status: String,
    pub session: AlphaReadonlySession,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub events: Vec<AlphaReadonlyEvent>,
    pub changes: AlphaReadonlyChanges,
    pub provenance: AlphaReadonlyProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlphaReadonlySession {
    pub session_id: String,
    pub turn_id: Option<String>,
    pub semantics_version: String,
    pub turn_state: String,
    pub host_connectivity: String,
    pub client_freshness: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlphaReadonlyEvent {
    pub session_id: String,
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub event_type: String,
    pub seq: u64,
    pub timestamp: String,
    pub durable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlphaReadonlyChanges {
    pub status: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlphaReadonlyProvenance {
    pub source: String,
    pub relay_ingress_verified: bool,
    pub gateway_schema_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayFrameAccepted {
    frame_id: String,
    #[serde(default)]
    new: bool,
}

pub fn run_alpha_projector(
    config: &AlphaProjectorConfig,
) -> Result<AlphaProjectorReceipt, ConnectorError> {
    validate_relay_url(&config.relay_url)?;
    let adapter = PilotAdapter::new(UreqOpenCodeClient::fixed()?, CommandJournal::open_memory()?);
    let capture = adapter.capture(&config.session_id)?;
    let projection = build_alpha_projection(&capture)?;
    let payload = projection_payload_bytes(&projection)?;
    let envelope = sign_projection_envelope(&payload)?;
    let accepted = post_frame(&config.relay_url, &envelope)?;
    Ok(AlphaProjectorReceipt {
        status: if accepted.new {
            "accepted".to_string()
        } else {
            "duplicate".to_string()
        },
        frame_id: accepted.frame_id,
        digest: projection
            .digest
            .clone()
            .ok_or_else(|| ConnectorError::Projection("projection digest missing".to_string()))?,
    })
}

pub fn build_alpha_projection(
    capture: &PilotCapture,
) -> Result<AlphaReadonlyProjection, ConnectorError> {
    let mut projection = AlphaReadonlyProjection {
        schema: ALPHA_SCHEMA.to_string(),
        status: "available".to_string(),
        session: AlphaReadonlySession {
            session_id: safe_identifier("sess", &capture.snapshot.session_id, MAX_SAFE_ID_BYTES),
            turn_id: capture
                .snapshot
                .turn_id
                .as_ref()
                .map(|turn_id| safe_identifier("turn", turn_id, MAX_SAFE_ID_BYTES)),
            semantics_version: capture.snapshot.version.clone(),
            turn_state: capture.snapshot.turn_state.as_str().to_string(),
            host_connectivity: enum_name(&serde_json::to_value(
                &capture.snapshot.host_connectivity,
            )?),
            client_freshness: enum_name(&serde_json::to_value(&capture.snapshot.client_freshness)?),
            updated_at: capture.snapshot.created_at.clone(),
        },
        seq: capture.snapshot.last_applied_seq,
        digest: None,
        events: bounded_events(&capture.events),
        changes: bounded_changes(),
        provenance: AlphaReadonlyProvenance {
            source: LOCAL_ALPHA_SOURCE.to_string(),
            relay_ingress_verified: false,
            gateway_schema_verified: false,
        },
    };
    let digest = projection_digest(&projection)?;
    projection.digest = Some(digest);
    validate_projection(&projection)?;
    Ok(projection)
}

pub fn projection_payload_bytes(
    projection: &AlphaReadonlyProjection,
) -> Result<Vec<u8>, ConnectorError> {
    validate_projection(projection)?;
    let payload = canonical_json(&serde_json::to_value(projection)?)?.into_bytes();
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(ConnectorError::Projection(format!(
            "alpha projection exceeds {MAX_FRAME_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(payload)
}

pub fn projection_digest(projection: &AlphaReadonlyProjection) -> Result<String, ConnectorError> {
    let mut value = serde_json::to_value(projection)?;
    let object = value.as_object_mut().ok_or_else(|| {
        ConnectorError::Projection("alpha projection must serialize to object".to_string())
    })?;
    object.remove("digest");
    let canonical = canonical_json(&value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
}

pub fn canonical_json(value: &Value) -> Result<String, ConnectorError> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out)
}

pub fn sign_projection_envelope(payload: &[u8]) -> Result<Vec<u8>, ConnectorError> {
    let keypair = load_signing_keypair_bytes_from_env()?;
    sign_projection_envelope_with_keypair_bytes(payload, &keypair)
}

fn sign_projection_envelope_with_keypair_bytes(
    payload: &[u8],
    keypair_bytes: &[u8; 64],
) -> Result<Vec<u8>, ConnectorError> {
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(ConnectorError::Projection(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_BYTES} bytes"
        )));
    }
    let device_id = decode_fixed_device_id()?;
    let mut nonce_bytes = [0_u8; 8];
    getrandom(&mut nonce_bytes)
        .map_err(|error| ConnectorError::Other(format!("random nonce failed: {error}")))?;
    let nonce = u64::from_be_bytes(nonce_bytes);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ConnectorError::Other(format!("system time error: {error}")))?
        .as_secs() as i64;
    // This local-alpha identity is a test fixture only. It is not pairing,
    // not production trust material, and must never leave process memory.
    let signing_key = signing_key_from_keypair_bytes(keypair_bytes)?;
    let signing_data = relay_signing_bytes(device_id, nonce, timestamp, payload);
    let signature = signing_key.sign(&signing_data).to_bytes();

    let mut envelope = vec![0_u8; RELAY_HEADER_SIZE + RELAY_SIGNATURE_SIZE + payload.len()];
    envelope[0..4].copy_from_slice(&RELAY_MAGIC.to_be_bytes());
    envelope[4..6].copy_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    envelope[6..8].copy_from_slice(&RELAY_FLAG_REQUEST.to_be_bytes());
    envelope[8..24].copy_from_slice(&device_id);
    envelope[24..32].copy_from_slice(&nonce.to_be_bytes());
    envelope[32..40].copy_from_slice(&(timestamp as u64).to_be_bytes());
    envelope[40..42].copy_from_slice(&(RELAY_SIGNATURE_SIZE as u16).to_be_bytes());
    envelope[48..48 + RELAY_SIGNATURE_SIZE].copy_from_slice(&signature);
    envelope[48 + RELAY_SIGNATURE_SIZE..].copy_from_slice(payload);
    Ok(envelope)
}

pub fn fixed_verifying_key() -> Result<VerifyingKey, ConnectorError> {
    let bytes = decode_hex_exact(FIXED_PUBLIC_KEY_HEX, 32)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        ConnectorError::SafetyBlocked("invalid fixed public key length".to_string())
    })?;
    VerifyingKey::from_bytes(&array).map_err(|error| {
        ConnectorError::SafetyBlocked(format!("invalid fixed public key: {error}"))
    })
}

fn post_frame(relay_url: &str, envelope: &[u8]) -> Result<RelayFrameAccepted, ConnectorError> {
    let base = relay_url.trim_end_matches('/');
    let response = ureq::post(&format!("{base}/v1/frame"))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(envelope)
        .map_err(map_relay_post_error)?;
    let body = response.into_string().map_err(|error| {
        ConnectorError::ProtocolMismatch(format!("invalid relay body: {error}"))
    })?;
    serde_json::from_str(&body)
        .map_err(|error| ConnectorError::ProtocolMismatch(format!("invalid relay JSON: {error}")))
}

fn map_relay_post_error(error: ureq::Error) -> ConnectorError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = response
                .into_string()
                .unwrap_or_else(|_| "unreadable relay response".to_string());
            ConnectorError::OpenCodeHttpStatus {
                status,
                message: body,
            }
        }
        ureq::Error::Transport(error) => {
            ConnectorError::OpenCodeUnreachable(format!("relay /v1/frame unreachable: {error}"))
        }
    }
}

fn validate_relay_url(relay_url: &str) -> Result<(), ConnectorError> {
    let url = Url::parse(relay_url)
        .map_err(|error| ConnectorError::NonLoopbackUrl(format!("{relay_url}: {error}")))?;
    if url.scheme() != "http" {
        return Err(ConnectorError::NonLoopbackUrl(format!(
            "{relay_url}: expected http scheme"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ConnectorError::NonLoopbackUrl(format!("{relay_url}: missing host")))?;
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1");
    if !is_loopback {
        return Err(ConnectorError::NonLoopbackUrl(relay_url.to_string()));
    }
    if url.port().is_none() {
        return Err(ConnectorError::NonLoopbackUrl(format!(
            "{relay_url}: missing port"
        )));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(ConnectorError::NonLoopbackUrl(format!(
            "{relay_url}: base URL must not include a path"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConnectorError::NonLoopbackUrl(format!(
            "{relay_url}: query or fragment not allowed"
        )));
    }
    Ok(())
}

fn relay_signing_bytes(device_id: [u8; 16], nonce: u64, timestamp: i64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; RELAY_HEADER_SIZE + payload.len()];
    bytes[0..4].copy_from_slice(&RELAY_MAGIC.to_be_bytes());
    bytes[4..6].copy_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    bytes[6..8].copy_from_slice(&RELAY_FLAG_REQUEST.to_be_bytes());
    bytes[8..24].copy_from_slice(&device_id);
    bytes[24..32].copy_from_slice(&nonce.to_be_bytes());
    bytes[32..40].copy_from_slice(&(timestamp as u64).to_be_bytes());
    bytes[40..42].copy_from_slice(&(RELAY_SIGNATURE_SIZE as u16).to_be_bytes());
    bytes[48..].copy_from_slice(payload);
    bytes
}

fn load_signing_keypair_bytes_from_env() -> Result<Zeroizing<[u8; 64]>, ConnectorError> {
    let encoded = Zeroizing::new(
        env::var(PRIVATE_KEY_ENV)
            .map_err(|_| ConnectorError::SafetyBlocked(format!("missing {PRIVATE_KEY_ENV}")))?,
    );
    let mut keypair_bytes = decode_hex_exact(encoded.as_str(), 64)?;
    let mut keypair = Zeroizing::new([0_u8; 64]);
    keypair.copy_from_slice(keypair_bytes.as_slice());
    keypair_bytes.zeroize();
    signing_key_from_keypair_bytes(&keypair)?;
    Ok(keypair)
}

fn signing_key_from_keypair_bytes(keypair_bytes: &[u8; 64]) -> Result<SigningKey, ConnectorError> {
    let signing_key = SigningKey::from_keypair_bytes(keypair_bytes).map_err(|error| {
        ConnectorError::SafetyBlocked(format!("invalid alpha private key: {error}"))
    })?;
    if signing_key.verifying_key().to_bytes() != fixed_verifying_key()?.to_bytes() {
        return Err(ConnectorError::SafetyBlocked(
            "alpha private key does not match fixed local-alpha identity".to_string(),
        ));
    }
    Ok(signing_key)
}

fn decode_fixed_device_id() -> Result<[u8; 16], ConnectorError> {
    let bytes = decode_hex_exact(FIXED_DEVICE_ID_HEX, 16)?;
    bytes
        .try_into()
        .map_err(|_| ConnectorError::SafetyBlocked("invalid fixed alpha device id".to_string()))
}

fn decode_hex_exact(value: &str, expected_len: usize) -> Result<Vec<u8>, ConnectorError> {
    let raw = value.strip_prefix("hex:").unwrap_or(value).trim();
    if raw.len() != expected_len * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConnectorError::SafetyBlocked(format!(
            "expected {expected_len}-byte lowercase hex value"
        )));
    }
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|chunk| u8::from_str_radix(chunk, 16).ok())
                .ok_or_else(|| ConnectorError::SafetyBlocked("invalid hex".to_string()))
        })
        .collect()
}

fn bounded_events(events: &[ProjectedEvent]) -> Vec<AlphaReadonlyEvent> {
    events
        .iter()
        .skip(events.len().saturating_sub(MAX_PROJECTED_EVENTS))
        .map(|event| AlphaReadonlyEvent {
            session_id: safe_identifier("sess", &event.session_id, MAX_SAFE_ID_BYTES),
            event_id: safe_identifier("evt", &event.event_id, MAX_SAFE_ID_BYTES),
            turn_id: event
                .turn_id
                .as_ref()
                .map(|turn_id| safe_identifier("turn", turn_id, MAX_SAFE_ID_BYTES)),
            event_type: event.event_type.clone(),
            seq: event.seq,
            timestamp: event.timestamp.clone(),
            durable: event.durable,
        })
        .collect()
}

fn bounded_changes() -> AlphaReadonlyChanges {
    AlphaReadonlyChanges {
        status: "unavailable".to_string(),
        files: Vec::new(),
    }
}

fn safe_identifier(domain: &str, raw: &str, hex_bytes: usize) -> String {
    let digest = Sha256::digest(format!("{domain}:{raw}").as_bytes());
    format!("{domain}-{:x}", digest)
        .chars()
        .take(domain.len() + 1 + hex_bytes)
        .collect()
}

fn enum_name(value: &Value) -> String {
    value.as_str().unwrap_or("Unknown").to_string()
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), ConnectorError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(boolean) => {
            if *boolean {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(string) => out.push_str(&serde_json::to_string(string)?),
        Value::Array(array) => {
            out.push('[');
            for (index, entry) in array.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(entry, out)?;
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            let mut sorted = object
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical_json(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn validate_projection(projection: &AlphaReadonlyProjection) -> Result<(), ConnectorError> {
    if projection.schema != ALPHA_SCHEMA {
        return Err(ConnectorError::Projection(
            "unexpected alpha host schema".to_string(),
        ));
    }
    if projection.status != "available" {
        return Err(ConnectorError::Projection(
            "alpha host projection must be available".to_string(),
        ));
    }
    if projection.session.semantics_version != "1.0.0" {
        return Err(ConnectorError::Projection(
            "alpha host projection semantics_version must be 1.0.0".to_string(),
        ));
    }
    validate_turn_state(&projection.session.turn_state)?;
    validate_host_connectivity(&projection.session.host_connectivity)?;
    validate_client_freshness(&projection.session.client_freshness)?;
    validate_rfc3339(&projection.session.updated_at, "session.updated_at")?;
    validate_alias("sess", &projection.session.session_id)?;
    if let Some(turn_id) = projection.session.turn_id.as_deref() {
        validate_alias("turn", turn_id)?;
    }
    if projection.changes.status != "unavailable" || !projection.changes.files.is_empty() {
        return Err(ConnectorError::Projection(
            "alpha host projection changes must be unavailable with empty files".to_string(),
        ));
    }
    if projection.provenance.source != LOCAL_ALPHA_SOURCE
        || projection.provenance.relay_ingress_verified
        || projection.provenance.gateway_schema_verified
    {
        return Err(ConnectorError::Projection(
            "alpha host projection provenance must remain unverified at Host".to_string(),
        ));
    }
    let mut last_seq = None;
    for event in &projection.events {
        validate_event_type(&event.event_type)?;
        validate_alias("sess", &event.session_id)?;
        validate_alias("evt", &event.event_id)?;
        if let Some(turn_id) = event.turn_id.as_deref() {
            validate_alias("turn", turn_id)?;
        }
        if event.session_id != projection.session.session_id {
            return Err(ConnectorError::Projection(
                "event session alias does not match top-level session alias".to_string(),
            ));
        }
        if !event.durable {
            return Err(ConnectorError::Projection(
                "alpha host projection events must all be durable".to_string(),
            ));
        }
        validate_rfc3339(&event.timestamp, "event.timestamp")?;
        if event.seq > projection.seq {
            return Err(ConnectorError::Projection(
                "event seq must not exceed top-level seq".to_string(),
            ));
        }
        if let Some(previous) = last_seq {
            if event.seq <= previous {
                return Err(ConnectorError::Projection(
                    "event seq must be strictly increasing".to_string(),
                ));
            }
        }
        last_seq = Some(event.seq);
    }
    Ok(())
}

fn validate_turn_state(value: &str) -> Result<(), ConnectorError> {
    match value {
        "None" | "Running" | "NeedsInput" | "NeedsPermission" | "Stopping" | "Completed"
        | "Cancelled" | "Failed" | "OutcomeUnknown" => Ok(()),
        _ => Err(ConnectorError::Projection(format!(
            "invalid turn_state {value}"
        ))),
    }
}

fn validate_host_connectivity(value: &str) -> Result<(), ConnectorError> {
    match value {
        "Online" | "Offline" => Ok(()),
        _ => Err(ConnectorError::Projection(format!(
            "invalid host_connectivity {value}"
        ))),
    }
}

fn validate_client_freshness(value: &str) -> Result<(), ConnectorError> {
    match value {
        "Live" | "Reconnecting" | "Stale" => Ok(()),
        _ => Err(ConnectorError::Projection(format!(
            "invalid client_freshness {value}"
        ))),
    }
}

fn validate_event_type(value: &str) -> Result<(), ConnectorError> {
    match value {
        "session.created"
        | "session.updated"
        | "turn.started"
        | "turn.stopping"
        | "turn.completed"
        | "turn.cancelled"
        | "turn.failed"
        | "turn.outcome_unknown"
        | "message.accepted"
        | "message.completed"
        | "tool.started"
        | "tool.completed"
        | "tool.failed"
        | "permission.requested"
        | "permission.resolved"
        | "diff.updated"
        | "session.compacted" => Ok(()),
        _ => Err(ConnectorError::Projection(format!(
            "invalid event_type {value}"
        ))),
    }
}

fn validate_alias(domain: &str, value: &str) -> Result<(), ConnectorError> {
    let expected_len = domain.len() + 1 + MAX_SAFE_ID_BYTES;
    let prefix = format!("{domain}-");
    if value.len() != expected_len
        || !value.starts_with(&prefix)
        || !value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ConnectorError::Projection(format!(
            "invalid {domain} alias shape"
        )));
    }
    Ok(())
}

fn validate_rfc3339(value: &str, field: &str) -> Result<(), ConnectorError> {
    time::OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|error| ConnectorError::Projection(format!("{field} is not RFC3339: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opencode_adapter::{CaptureSource, OpenCodeSession};
    use crate::projection::{ClientFreshness, HostConnectivity, Snapshot, StateSummary, TurnState};
    use ed25519_dalek::{Signature, Verifier};
    use serde_json::json;

    const TEST_KEYPAIR_HEX: &str =
        "8cd8ac5b730d8f625d9631bb0a6cd7e7d66f6bde56d356b8af602534fe7fc54b91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864";

    fn sample_capture(events: usize) -> PilotCapture {
        let snapshot_seq = (events as u64).max(7);
        let projected = (0..events)
            .map(|index| ProjectedEvent {
                event_type: if index % 2 == 0 {
                    "tool.started".to_string()
                } else {
                    "message.accepted".to_string()
                },
                session_id: "pilot-session".to_string(),
                turn_id: Some("turn-1".to_string()),
                event_id: format!("event-{index}"),
                seq: index as u64 + 1,
                timestamp: "2026-08-18T08:00:00Z".to_string(),
                durable: true,
                payload: Some(json!({"ignored":"dto"})),
            })
            .collect::<Vec<_>>();
        PilotCapture {
            source: CaptureSource {
                transport: "http".to_string(),
                interface: "fixed".to_string(),
                opencode_version: "1.18.16".to_string(),
                evidence: "test".to_string(),
            },
            session: OpenCodeSession {
                id: "pilot-session".to_string(),
                version: "1.18.16".to_string(),
                status: "running".to_string(),
                turn_id: Some("turn-1".to_string()),
                updated_at: "2026-08-18T08:00:00Z".to_string(),
            },
            snapshot: Snapshot {
                session_id: "pilot-session".to_string(),
                snapshot_seq,
                digest: Some("sha256:old".to_string()),
                last_applied_seq: snapshot_seq,
                turn_state: TurnState::NeedsPermission,
                turn_id: Some("turn-1".to_string()),
                host_connectivity: HostConnectivity::Online,
                client_freshness: ClientFreshness::Live,
                state_summary: StateSummary::default(),
                created_at: "2026-08-18T08:00:06Z".to_string(),
                version: "1.0.0".to_string(),
            },
            events: projected,
            diff: Vec::new(),
        }
    }

    #[test]
    fn canonical_digest_omits_top_level_digest_and_sorts_keys() {
        let projection = AlphaReadonlyProjection {
            schema: ALPHA_SCHEMA.to_string(),
            status: "available".to_string(),
            session: AlphaReadonlySession {
                session_id: "sess-abc".to_string(),
                turn_id: Some("turn-abc".into()),
                semantics_version: "1.0.0".to_string(),
                turn_state: "Running".to_string(),
                host_connectivity: "Online".to_string(),
                client_freshness: "Live".to_string(),
                updated_at: "2026-08-18T08:00:06Z".to_string(),
            },
            seq: 7,
            digest: Some("sha256:placeholder".to_string()),
            events: vec![AlphaReadonlyEvent {
                session_id: "sess-1".to_string(),
                event_id: "evt-1".to_string(),
                turn_id: Some("turn-1".to_string()),
                event_type: "turn.started".to_string(),
                seq: 1,
                timestamp: "2026-08-18T08:00:00Z".to_string(),
                durable: true,
            }],
            changes: AlphaReadonlyChanges {
                status: "unavailable".to_string(),
                files: vec![],
            },
            provenance: AlphaReadonlyProvenance {
                source: LOCAL_ALPHA_SOURCE.to_string(),
                relay_ingress_verified: false,
                gateway_schema_verified: false,
            },
        };
        let digest = projection_digest(&projection).unwrap();
        let mut value = serde_json::to_value(&projection).unwrap();
        value.as_object_mut().unwrap().remove("digest");
        let expected = format!(
            "sha256:{:x}",
            Sha256::digest(canonical_json(&value).unwrap().as_bytes())
        );
        assert_eq!(digest, expected);
    }

    #[test]
    fn bounded_projection_removes_raw_upstream_dto_and_stays_under_64k() {
        let projection = build_alpha_projection(&sample_capture(256)).unwrap();
        assert_eq!(projection.events.len(), MAX_PROJECTED_EVENTS);
        assert_eq!(projection.changes.files.len(), 0);
        assert_eq!(projection.changes.status, "unavailable");
        let payload = projection_payload_bytes(&projection).unwrap();
        assert!(payload.len() <= MAX_FRAME_PAYLOAD_BYTES);
        let value: Value = serde_json::from_slice(&payload).unwrap();
        assert!(value["events"][0]["session_id"].is_string());
        assert!(value["events"][0]["event_id"].is_string());
        assert!(value["events"][0]["turn_id"].is_string());
        assert!(value["events"][0]["event_type"].is_string());
        assert!(value["events"][0].get("payload").is_none());
        assert_eq!(value["changes"]["status"], "unavailable");
        assert_eq!(value["changes"]["files"], Value::Array(vec![]));
        assert_eq!(value["events"][0]["seq"], 225);
        assert_eq!(value["events"][31]["seq"], 256);
    }

    #[test]
    fn payload_bytes_are_exact_canonical_json_bytes() {
        let projection = build_alpha_projection(&sample_capture(4)).unwrap();
        let payload = projection_payload_bytes(&projection).unwrap();
        let expected = canonical_json(&serde_json::to_value(&projection).unwrap())
            .unwrap()
            .into_bytes();
        assert_eq!(payload, expected);
    }

    #[test]
    fn invalid_event_type_fails_closed_instead_of_truncating() {
        let mut capture = sample_capture(1);
        capture.events[0].event_type = "tool.started.future.invalid".to_string();
        let error = build_alpha_projection(&capture).unwrap_err();
        assert!(matches!(error, ConnectorError::Projection(_)));
    }

    #[test]
    fn signed_envelope_matches_fixed_identity_and_signature() {
        let key_bytes = decode_hex_exact(TEST_KEYPAIR_HEX, 64).unwrap();
        let keypair: [u8; 64] = key_bytes.as_slice().try_into().unwrap();
        let payload = br#"{"schema":"nomad.alpha.readonly.host.v1"}"#;
        let envelope = sign_projection_envelope_with_keypair_bytes(payload, &keypair).unwrap();
        assert_eq!(
            u32::from_be_bytes(envelope[0..4].try_into().unwrap()),
            RELAY_MAGIC
        );
        assert_eq!(
            u16::from_be_bytes(envelope[4..6].try_into().unwrap()),
            RELAY_PROTOCOL_VERSION
        );
        assert_eq!(&envelope[8..24], &decode_fixed_device_id().unwrap());
        let signature: [u8; 64] = envelope[48..112].try_into().unwrap();
        let payload_offset = RELAY_HEADER_SIZE + RELAY_SIGNATURE_SIZE;
        let signing_data = relay_signing_bytes(
            decode_fixed_device_id().unwrap(),
            u64::from_be_bytes(envelope[24..32].try_into().unwrap()),
            i64::from_be_bytes(envelope[32..40].try_into().unwrap()),
            &envelope[payload_offset..],
        );
        fixed_verifying_key()
            .unwrap()
            .verify(&signing_data, &Signature::from_bytes(&signature))
            .unwrap();
    }
}
