use crate::error::ConnectorError;
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const APPLICATION_SCHEMA: &str = "nomad.remote.application-envelope.v1";
const PROJECTION_SCHEMA: &str = "nomad.remote.projection.v1";
const COMMAND_SCHEMA: &str = "nomad.remote.command.v1";
const RECEIPT_SCHEMA: &str = "nomad.remote.receipt.v1";
const RELAY_FRAME_SCHEMA: &str = "nomad.relay.opaque-frame.v2";
const RELAY_CRYPTO_SUITE: &str = "p256-hkdf-sha256-aes256gcm-v1";
const SNAPSHOT_SCHEMA: &str = "nomad.product-host.snapshot.v1";
const COMMAND_BODY_SCHEMA: &str = "nomad.gateway.command.v1";
const RECEIPT_BODY_SCHEMA: &str = "nomad.gateway.command-receipt.v1";
const CAPABILITY_SCHEMA: &str = "nomad.product-host.command-capability.v1";
const QUESTION_SUMMARY_SCHEMA: &str = "nomad.product-host.pending-question-summary.v1";
const MAX_CANONICAL_BYTES: usize = 32 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 4_096;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_SAFE_STRING_BYTES: usize = 512;
const MAX_COMMAND_CANONICAL_BYTES: usize = 16 * 1024;
const MAX_REPLY_CONTENT_BYTES: usize = 8 * 1024;
const MAX_DIFF_FILE_COUNT: usize = 256;
const MAX_CAPABILITY_TTL_SECONDS: i64 = 30;
const EXACT_SUMMARY_QUESTION_COUNT: u8 = 1;
const EXACT_SUMMARY_ANSWER_MODE: &str = "free_text";
const EXACT_SUMMARY_RESPONSE_HINT: &str = "single_short_reply";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FrameDirection {
    HostToDevice,
    DeviceToHost,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrameBinding {
    pub(crate) schema: String,
    pub(crate) crypto_suite: String,
    pub(crate) mailbox_id: String,
    pub(crate) direction: FrameDirection,
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) message_id: String,
}

impl FrameBinding {
    pub(crate) fn validate(&self) -> Result<(), RemoteApplicationError> {
        if self.schema != RELAY_FRAME_SCHEMA
            || self.crypto_suite != RELAY_CRYPTO_SUITE
            || !prefixed_hex(&self.mailbox_id, "mbx-", 64)
            || !prefixed_hex(&self.message_id, "msg-", 32)
            || self.epoch == 0
            || self.sequence == 0
            || self.epoch > MAX_SAFE_INTEGER
            || self.sequence > MAX_SAFE_INTEGER
        {
            return Err(RemoteApplicationError::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplicationEnvelope {
    pub(crate) common: EnvelopeCommon,
    pub(crate) payload: ApplicationPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EnvelopeCommon {
    pub(crate) schema: String,
    pub(crate) kind: EnvelopeKind,
    pub(crate) mailbox_id: String,
    pub(crate) direction: FrameDirection,
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) message_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeKind {
    Projection,
    Command,
    Receipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApplicationPayload {
    Projection(Box<ProjectionPayload>),
    Command(CommandPayload),
    Receipt(ReceiptPayload),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProjectionPayload {
    pub(crate) snapshot: ProductSnapshotEnvelope,
    pub(crate) capability: Option<CommandCapability>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommandPayload {
    pub(crate) command: GatewayCommand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptPayload {
    pub(crate) receipt: CommandReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProductSnapshotEnvelope {
    pub(crate) schema: String,
    pub(crate) host_instance_id: String,
    pub(crate) snapshot_seq: u64,
    pub(crate) digest: String,
    pub(crate) snapshot: ProductSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProductSnapshot {
    pub(crate) session_alias: String,
    pub(crate) updated_at: String,
    pub(crate) turn_state: SnapshotTurnState,
    pub(crate) pending_input_alias: Option<String>,
    pub(crate) pending_permission_alias: Option<String>,
    pub(crate) diff_file_count: usize,
    pub(crate) writable: bool,
    pub(crate) evidence_class: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotTurnState {
    Running,
    NeedsInput,
    NeedsPermission,
    Completed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommandCapability {
    pub(crate) schema: String,
    pub(crate) capability_id: String,
    pub(crate) snapshot_seq: u64,
    pub(crate) snapshot_digest: String,
    pub(crate) next_command_seq: u64,
    pub(crate) issued_at: String,
    pub(crate) expires_at: String,
    pub(crate) view: bool,
    pub(crate) reply: Option<ReplyCapability>,
    pub(crate) deny: Option<DenyCapability>,
    pub(crate) stop: Option<StopCapability>,
    pub(crate) allow_once: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplyCapability {
    pub(crate) turn_alias: String,
    pub(crate) input_alias: String,
    pub(crate) summary: Option<PendingQuestionSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingQuestionSummary {
    pub(crate) schema: String,
    pub(crate) question_count: u8,
    pub(crate) answer_mode: String,
    pub(crate) response_hint: String,
    pub(crate) prompt: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DenyCapability {
    pub(crate) permission_alias: String,
    pub(crate) action_hash: String,
    pub(crate) expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StopCapability {
    pub(crate) turn_alias: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GatewayCommand {
    Reply(ReplyCommand),
    Deny(DenyCommand),
    Stop(StopCommand),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplyCommand {
    pub(crate) capability_id: String,
    pub(crate) request_id: String,
    pub(crate) nonce: String,
    pub(crate) command_seq: u64,
    pub(crate) expected_snapshot_seq: u64,
    pub(crate) expected_snapshot_digest: String,
    pub(crate) issued_at: String,
    pub(crate) expires_at: String,
    pub(crate) turn_alias: String,
    pub(crate) input_alias: String,
    pub(crate) content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DenyCommand {
    pub(crate) capability_id: String,
    pub(crate) request_id: String,
    pub(crate) nonce: String,
    pub(crate) command_seq: u64,
    pub(crate) expected_snapshot_seq: u64,
    pub(crate) expected_snapshot_digest: String,
    pub(crate) issued_at: String,
    pub(crate) expires_at: String,
    pub(crate) permission_alias: String,
    pub(crate) action_hash: String,
    pub(crate) permission_expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StopCommand {
    pub(crate) capability_id: String,
    pub(crate) request_id: String,
    pub(crate) nonce: String,
    pub(crate) command_seq: u64,
    pub(crate) expected_snapshot_seq: u64,
    pub(crate) expected_snapshot_digest: String,
    pub(crate) issued_at: String,
    pub(crate) expires_at: String,
    pub(crate) turn_alias: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommandReceipt {
    pub(crate) schema: String,
    pub(crate) receipt_id: String,
    pub(crate) request_id: String,
    pub(crate) action: ReceiptAction,
    pub(crate) snapshot_seq: u64,
    pub(crate) snapshot_digest: String,
    pub(crate) accepted_at: String,
    pub(crate) status: ReceiptStatus,
    pub(crate) error_code: ReceiptErrorCode,
    pub(crate) idempotent_replay: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptAction {
    Reply,
    Deny,
    Stop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptStatus {
    HostAccepted,
    Dispatching,
    DispatchAcknowledged,
    Rejected,
    Stale,
    Expired,
    OutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptErrorCode(pub(crate) String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RemoteApplicationError {
    #[error("REMOTE_APPLICATION_SIZE")]
    Size,
    #[error("REMOTE_APPLICATION_JSON")]
    Json,
    #[error("REMOTE_APPLICATION_CANONICAL")]
    Canonical,
    #[error("REMOTE_APPLICATION_BINDING")]
    Binding,
    #[error("REMOTE_APPLICATION_SHAPE")]
    Shape,
}

impl From<RemoteApplicationError> for ConnectorError {
    fn from(error: RemoteApplicationError) -> Self {
        match error {
            RemoteApplicationError::Size => ConnectorError::ProtocolMismatch(
                "remote application envelope exceeds bounds".into(),
            ),
            RemoteApplicationError::Json => {
                ConnectorError::ProtocolMismatch("remote application envelope JSON invalid".into())
            }
            RemoteApplicationError::Canonical => ConnectorError::ProtocolMismatch(
                "remote application envelope canonical form invalid".into(),
            ),
            RemoteApplicationError::Binding => ConnectorError::ProtocolMismatch(
                "remote application envelope binding mismatch".into(),
            ),
            RemoteApplicationError::Shape => {
                ConnectorError::ProtocolMismatch("remote application envelope shape invalid".into())
            }
        }
    }
}

pub(crate) fn parse_application_envelope(
    raw: &[u8],
    binding: &FrameBinding,
) -> Result<ApplicationEnvelope, RemoteApplicationError> {
    binding.validate()?;
    if raw.is_empty() || raw.len() > MAX_CANONICAL_BYTES {
        return Err(RemoteApplicationError::Size);
    }
    lexical_json_budget(raw)?;
    let value = strict_json(raw)?;
    let canonical = canonical_json(&value)?;
    if canonical.as_bytes() != raw {
        return Err(RemoteApplicationError::Canonical);
    }
    let envelope = parse_envelope_value(value)?;
    validate_binding(&envelope.common, binding)?;
    Ok(envelope)
}

pub(crate) fn canonical_encode_application_envelope(
    envelope: &ApplicationEnvelope,
) -> Result<Vec<u8>, RemoteApplicationError> {
    let value = envelope_to_value(envelope)?;
    let canonical = canonical_json(&value)?;
    if canonical.len() > MAX_CANONICAL_BYTES {
        return Err(RemoteApplicationError::Size);
    }
    Ok(canonical.into_bytes())
}

fn parse_envelope_value(value: Value) -> Result<ApplicationEnvelope, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &[
            "schema",
            "kind",
            "mailbox_id",
            "direction",
            "epoch",
            "sequence",
            "message_id",
            "payload",
        ],
        &[
            "schema",
            "kind",
            "mailbox_id",
            "direction",
            "epoch",
            "sequence",
            "message_id",
            "payload",
        ],
    )?;
    let common = EnvelopeCommon {
        schema: exact_string(&map, "schema", APPLICATION_SCHEMA)?,
        kind: parse_kind(required_string(&map, "kind")?)?,
        mailbox_id: require_prefixed_hex(&map, "mailbox_id", "mbx-", 64)?,
        direction: parse_direction(required_string(&map, "direction")?)?,
        epoch: require_safe_integer(&map, "epoch")?,
        sequence: require_safe_integer(&map, "sequence")?,
        message_id: require_prefixed_hex(&map, "message_id", "msg-", 32)?,
    };
    let payload_value = map
        .get("payload")
        .cloned()
        .ok_or(RemoteApplicationError::Shape)?;
    let payload = match common.kind {
        EnvelopeKind::Projection => {
            ApplicationPayload::Projection(Box::new(parse_projection_payload(payload_value)?))
        }
        EnvelopeKind::Command => ApplicationPayload::Command(parse_command_payload(payload_value)?),
        EnvelopeKind::Receipt => ApplicationPayload::Receipt(parse_receipt_payload(payload_value)?),
    };
    validate_kind_direction(common.kind, common.direction)?;
    Ok(ApplicationEnvelope { common, payload })
}

fn parse_projection_payload(value: Value) -> Result<ProjectionPayload, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &["schema", "snapshot", "capability"],
        &["schema", "snapshot", "capability"],
    )?;
    exact_string(&map, "schema", PROJECTION_SCHEMA)?;
    let snapshot = parse_snapshot_envelope(
        map.get("snapshot")
            .cloned()
            .ok_or(RemoteApplicationError::Shape)?,
    )?;
    let capability = match map.get("capability") {
        Some(Value::Null) => None,
        Some(value) => Some(parse_capability(value.clone())?),
        None => return Err(RemoteApplicationError::Shape),
    };
    if let Some(capability) = capability.as_ref() {
        if capability.snapshot_seq != snapshot.snapshot_seq
            || capability.snapshot_digest != snapshot.digest
            || !capability.view
        {
            return Err(RemoteApplicationError::Shape);
        }
    }
    Ok(ProjectionPayload {
        snapshot,
        capability,
    })
}

fn parse_command_payload(value: Value) -> Result<CommandPayload, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(&map, &["schema", "command"], &["schema", "command"])?;
    exact_string(&map, "schema", COMMAND_SCHEMA)?;
    let command = parse_gateway_command(
        map.get("command")
            .cloned()
            .ok_or(RemoteApplicationError::Shape)?,
    )?;
    let canonical = canonical_json(&gateway_command_to_value(&command))?;
    if canonical.len() > MAX_COMMAND_CANONICAL_BYTES {
        return Err(RemoteApplicationError::Size);
    }
    Ok(CommandPayload { command })
}

fn parse_receipt_payload(value: Value) -> Result<ReceiptPayload, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(&map, &["schema", "receipt"], &["schema", "receipt"])?;
    exact_string(&map, "schema", RECEIPT_SCHEMA)?;
    let receipt = parse_receipt(
        map.get("receipt")
            .cloned()
            .ok_or(RemoteApplicationError::Shape)?,
    )?;
    Ok(ReceiptPayload { receipt })
}

fn parse_snapshot_envelope(
    value: Value,
) -> Result<ProductSnapshotEnvelope, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &[
            "schema",
            "host_instance_id",
            "snapshot_seq",
            "digest",
            "snapshot",
        ],
        &[
            "schema",
            "host_instance_id",
            "snapshot_seq",
            "digest",
            "snapshot",
        ],
    )?;
    let snapshot = parse_snapshot(
        map.get("snapshot")
            .cloned()
            .ok_or(RemoteApplicationError::Shape)?,
    )?;
    let envelope = ProductSnapshotEnvelope {
        schema: exact_string(&map, "schema", SNAPSHOT_SCHEMA)?,
        host_instance_id: require_ascii_token(&map, "host_instance_id", 128)?,
        snapshot_seq: require_safe_integer(&map, "snapshot_seq")?,
        digest: require_sha256_digest(&map, "digest")?,
        snapshot,
    };
    if envelope.digest != compute_snapshot_digest(&envelope)? {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(envelope)
}

fn parse_snapshot(value: Value) -> Result<ProductSnapshot, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &[
            "session_alias",
            "updated_at",
            "turn_state",
            "pending_input_alias",
            "pending_permission_alias",
            "diff_file_count",
            "writable",
            "evidence_class",
        ],
        &[
            "session_alias",
            "updated_at",
            "turn_state",
            "pending_input_alias",
            "pending_permission_alias",
            "diff_file_count",
            "writable",
            "evidence_class",
        ],
    )?;
    Ok(ProductSnapshot {
        session_alias: require_alias(&map, "session_alias", "sess-")?,
        updated_at: require_millisecond_utc_string(&map, "updated_at")?,
        turn_state: parse_turn_state(required_string(&map, "turn_state")?)?,
        pending_input_alias: require_optional_alias(&map, "pending_input_alias", "input-")?,
        pending_permission_alias: require_optional_alias(
            &map,
            "pending_permission_alias",
            "permission-",
        )?,
        diff_file_count: require_diff_file_count(&map, "diff_file_count")?,
        writable: require_false_bool(&map, "writable")?,
        evidence_class: exact_string_value(
            required_string(&map, "evidence_class")?,
            "official_registry_shape_only_not_provider_lifecycle",
        )?,
    })
}

fn parse_capability(value: Value) -> Result<CommandCapability, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &[
            "schema",
            "capability_id",
            "snapshot_seq",
            "snapshot_digest",
            "next_command_seq",
            "issued_at",
            "expires_at",
            "view",
            "reply",
            "deny",
            "stop",
            "allow_once",
        ],
        &[
            "schema",
            "capability_id",
            "snapshot_seq",
            "snapshot_digest",
            "next_command_seq",
            "issued_at",
            "expires_at",
            "view",
            "reply",
            "deny",
            "stop",
            "allow_once",
        ],
    )?;
    let allow_once = require_bool(&map, "allow_once")?;
    let view = require_bool(&map, "view")?;
    if allow_once || !view {
        return Err(RemoteApplicationError::Shape);
    }
    let issued_at = require_whole_second_utc_string(&map, "issued_at")?;
    let expires_at = require_whole_second_utc_string(&map, "expires_at")?;
    validate_ttl_window(&issued_at, &expires_at, MAX_CAPABILITY_TTL_SECONDS)?;
    Ok(CommandCapability {
        schema: exact_string(&map, "schema", CAPABILITY_SCHEMA)?,
        capability_id: require_ascii_token(&map, "capability_id", 128)?,
        snapshot_seq: require_safe_integer(&map, "snapshot_seq")?,
        snapshot_digest: require_sha256_digest(&map, "snapshot_digest")?,
        next_command_seq: require_safe_integer(&map, "next_command_seq")?,
        issued_at,
        expires_at,
        view,
        reply: parse_optional_object_field(&map, "reply", parse_reply_capability)?,
        deny: parse_optional_object_field(&map, "deny", parse_deny_capability)?,
        stop: parse_optional_object_field(&map, "stop", parse_stop_capability)?,
        allow_once,
    })
}

fn parse_reply_capability(value: Value) -> Result<ReplyCapability, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &["turn_alias", "input_alias", "summary"],
        &["turn_alias", "input_alias", "summary"],
    )?;
    Ok(ReplyCapability {
        turn_alias: require_alias(&map, "turn_alias", "turn-")?,
        input_alias: require_alias(&map, "input_alias", "input-")?,
        summary: match map.get("summary") {
            Some(value) => Some(parse_pending_question_summary(value.clone())?),
            None => return Err(RemoteApplicationError::Shape),
        },
    })
}

fn parse_pending_question_summary(
    value: Value,
) -> Result<PendingQuestionSummary, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &[
            "schema",
            "question_count",
            "answer_mode",
            "response_hint",
            "prompt",
        ],
        &[
            "schema",
            "question_count",
            "answer_mode",
            "response_hint",
            "prompt",
        ],
    )?;
    Ok(PendingQuestionSummary {
        schema: exact_string(&map, "schema", QUESTION_SUMMARY_SCHEMA)?,
        question_count: exact_u8(&map, "question_count", EXACT_SUMMARY_QUESTION_COUNT)?,
        answer_mode: exact_ascii_token(&map, "answer_mode", EXACT_SUMMARY_ANSWER_MODE, 64)?,
        response_hint: exact_ascii_token(&map, "response_hint", EXACT_SUMMARY_RESPONSE_HINT, 64)?,
        prompt: require_safe_string(&map, "prompt", 160)?,
    })
}

fn parse_deny_capability(value: Value) -> Result<DenyCapability, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &["permission_alias", "action_hash", "expires_at"],
        &["permission_alias", "action_hash", "expires_at"],
    )?;
    Ok(DenyCapability {
        permission_alias: require_alias(&map, "permission_alias", "permission-")?,
        action_hash: require_sha256_digest(&map, "action_hash")?,
        expires_at: require_rfc3339_string(&map, "expires_at")?,
    })
}

fn parse_stop_capability(value: Value) -> Result<StopCapability, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(&map, &["turn_alias"], &["turn_alias"])?;
    Ok(StopCapability {
        turn_alias: require_alias(&map, "turn_alias", "turn-")?,
    })
}

fn parse_gateway_command(value: Value) -> Result<GatewayCommand, RemoteApplicationError> {
    let map = object(value)?;
    let action = required_string(&map, "action")?;
    match action {
        "reply" => {
            exact_keys(
                &map,
                &[
                    "schema",
                    "capability_id",
                    "request_id",
                    "nonce",
                    "command_seq",
                    "expected_snapshot_seq",
                    "expected_snapshot_digest",
                    "issued_at",
                    "expires_at",
                    "action",
                    "turn_alias",
                    "input_alias",
                    "content",
                ],
                &[
                    "schema",
                    "capability_id",
                    "request_id",
                    "nonce",
                    "command_seq",
                    "expected_snapshot_seq",
                    "expected_snapshot_digest",
                    "issued_at",
                    "expires_at",
                    "action",
                    "turn_alias",
                    "input_alias",
                    "content",
                ],
            )?;
            validate_command_common(&map)?;
            Ok(GatewayCommand::Reply(ReplyCommand {
                capability_id: require_ascii_token(&map, "capability_id", 128)?,
                request_id: require_ascii_token(&map, "request_id", 128)?,
                nonce: require_ascii_token(&map, "nonce", 128)?,
                command_seq: require_safe_integer(&map, "command_seq")?,
                expected_snapshot_seq: require_safe_integer(&map, "expected_snapshot_seq")?,
                expected_snapshot_digest: require_sha256_digest(&map, "expected_snapshot_digest")?,
                issued_at: require_rfc3339_string(&map, "issued_at")?,
                expires_at: require_rfc3339_string(&map, "expires_at")?,
                turn_alias: require_alias(&map, "turn_alias", "turn-")?,
                input_alias: require_alias(&map, "input_alias", "input-")?,
                content: require_reply_content(&map, "content")?,
            }))
        }
        "deny" => {
            exact_keys(
                &map,
                &[
                    "schema",
                    "capability_id",
                    "request_id",
                    "nonce",
                    "command_seq",
                    "expected_snapshot_seq",
                    "expected_snapshot_digest",
                    "issued_at",
                    "expires_at",
                    "action",
                    "permission_alias",
                    "action_hash",
                    "permission_expires_at",
                ],
                &[
                    "schema",
                    "capability_id",
                    "request_id",
                    "nonce",
                    "command_seq",
                    "expected_snapshot_seq",
                    "expected_snapshot_digest",
                    "issued_at",
                    "expires_at",
                    "action",
                    "permission_alias",
                    "action_hash",
                    "permission_expires_at",
                ],
            )?;
            validate_command_common(&map)?;
            Ok(GatewayCommand::Deny(DenyCommand {
                capability_id: require_ascii_token(&map, "capability_id", 128)?,
                request_id: require_ascii_token(&map, "request_id", 128)?,
                nonce: require_ascii_token(&map, "nonce", 128)?,
                command_seq: require_safe_integer(&map, "command_seq")?,
                expected_snapshot_seq: require_safe_integer(&map, "expected_snapshot_seq")?,
                expected_snapshot_digest: require_sha256_digest(&map, "expected_snapshot_digest")?,
                issued_at: require_rfc3339_string(&map, "issued_at")?,
                expires_at: require_rfc3339_string(&map, "expires_at")?,
                permission_alias: require_alias(&map, "permission_alias", "permission-")?,
                action_hash: require_sha256_digest(&map, "action_hash")?,
                permission_expires_at: require_rfc3339_string(&map, "permission_expires_at")?,
            }))
        }
        "stop" => {
            exact_keys(
                &map,
                &[
                    "schema",
                    "capability_id",
                    "request_id",
                    "nonce",
                    "command_seq",
                    "expected_snapshot_seq",
                    "expected_snapshot_digest",
                    "issued_at",
                    "expires_at",
                    "action",
                    "turn_alias",
                ],
                &[
                    "schema",
                    "capability_id",
                    "request_id",
                    "nonce",
                    "command_seq",
                    "expected_snapshot_seq",
                    "expected_snapshot_digest",
                    "issued_at",
                    "expires_at",
                    "action",
                    "turn_alias",
                ],
            )?;
            validate_command_common(&map)?;
            Ok(GatewayCommand::Stop(StopCommand {
                capability_id: require_ascii_token(&map, "capability_id", 128)?,
                request_id: require_ascii_token(&map, "request_id", 128)?,
                nonce: require_ascii_token(&map, "nonce", 128)?,
                command_seq: require_safe_integer(&map, "command_seq")?,
                expected_snapshot_seq: require_safe_integer(&map, "expected_snapshot_seq")?,
                expected_snapshot_digest: require_sha256_digest(&map, "expected_snapshot_digest")?,
                issued_at: require_rfc3339_string(&map, "issued_at")?,
                expires_at: require_rfc3339_string(&map, "expires_at")?,
                turn_alias: require_alias(&map, "turn_alias", "turn-")?,
            }))
        }
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn validate_command_common(map: &Map<String, Value>) -> Result<(), RemoteApplicationError> {
    exact_string(map, "schema", COMMAND_BODY_SCHEMA)?;
    exact_string_value(
        required_string(map, "action")?,
        required_string(map, "action")?,
    )?;
    Ok(())
}

fn parse_receipt(value: Value) -> Result<CommandReceipt, RemoteApplicationError> {
    let map = object(value)?;
    exact_keys(
        &map,
        &[
            "schema",
            "receipt_id",
            "request_id",
            "action",
            "snapshot_seq",
            "snapshot_digest",
            "accepted_at",
            "status",
            "error_code",
            "idempotent_replay",
        ],
        &[
            "schema",
            "receipt_id",
            "request_id",
            "action",
            "snapshot_seq",
            "snapshot_digest",
            "accepted_at",
            "status",
            "error_code",
            "idempotent_replay",
        ],
    )?;
    Ok(CommandReceipt {
        schema: exact_string(&map, "schema", RECEIPT_BODY_SCHEMA)?,
        receipt_id: require_ascii_token(&map, "receipt_id", 128)?,
        request_id: require_ascii_token(&map, "request_id", 128)?,
        action: parse_receipt_action(required_string(&map, "action")?)?,
        snapshot_seq: require_safe_integer(&map, "snapshot_seq")?,
        snapshot_digest: require_sha256_digest(&map, "snapshot_digest")?,
        accepted_at: require_whole_second_utc_string(&map, "accepted_at")?,
        status: parse_receipt_status(required_string(&map, "status")?)?,
        error_code: parse_error_code(required_string(&map, "error_code")?)?,
        idempotent_replay: require_bool(&map, "idempotent_replay")?,
    })
}

fn parse_error_code(value: &str) -> Result<ReceiptErrorCode, RemoteApplicationError> {
    if matches!(
        value,
        "OK" | "ERR_DUPLICATE_REQUEST"
            | "ERR_REQUEST_STALE"
            | "ERR_REQUEST_EXPIRED"
            | "ERR_INCOMPATIBLE_VERSION"
            | "ERR_REQUEST_REVOKED"
            | "ERR_OUTCOME_UNKNOWN"
            | "ERR_COMMAND_REJECTED"
            | "ERR_PERMISSION_DENIED"
            | "ERR_SAFETY_BLOCKED"
            | "ERR_HOST_OFFLINE"
    ) {
        return Ok(ReceiptErrorCode(value.to_owned()));
    }
    Err(RemoteApplicationError::Shape)
}

fn validate_binding(
    common: &EnvelopeCommon,
    binding: &FrameBinding,
) -> Result<(), RemoteApplicationError> {
    if common.mailbox_id != binding.mailbox_id
        || common.direction != binding.direction
        || common.epoch != binding.epoch
        || common.sequence != binding.sequence
        || common.message_id != binding.message_id
    {
        return Err(RemoteApplicationError::Binding);
    }
    Ok(())
}

fn validate_kind_direction(
    kind: EnvelopeKind,
    direction: FrameDirection,
) -> Result<(), RemoteApplicationError> {
    match (kind, direction) {
        (EnvelopeKind::Projection, FrameDirection::HostToDevice)
        | (EnvelopeKind::Receipt, FrameDirection::HostToDevice)
        | (EnvelopeKind::Command, FrameDirection::DeviceToHost) => Ok(()),
        _ => Err(RemoteApplicationError::Binding),
    }
}

fn parse_kind(value: &str) -> Result<EnvelopeKind, RemoteApplicationError> {
    match value {
        "projection" => Ok(EnvelopeKind::Projection),
        "command" => Ok(EnvelopeKind::Command),
        "receipt" => Ok(EnvelopeKind::Receipt),
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn parse_direction(value: &str) -> Result<FrameDirection, RemoteApplicationError> {
    match value {
        "host_to_device" => Ok(FrameDirection::HostToDevice),
        "device_to_host" => Ok(FrameDirection::DeviceToHost),
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn parse_turn_state(value: &str) -> Result<SnapshotTurnState, RemoteApplicationError> {
    match value {
        "Running" => Ok(SnapshotTurnState::Running),
        "Completed" => Ok(SnapshotTurnState::Completed),
        "NeedsInput" => Ok(SnapshotTurnState::NeedsInput),
        "NeedsPermission" => Ok(SnapshotTurnState::NeedsPermission),
        "OutcomeUnknown" => Ok(SnapshotTurnState::OutcomeUnknown),
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn parse_receipt_action(value: &str) -> Result<ReceiptAction, RemoteApplicationError> {
    match value {
        "reply" => Ok(ReceiptAction::Reply),
        "deny" => Ok(ReceiptAction::Deny),
        "stop" => Ok(ReceiptAction::Stop),
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn parse_receipt_status(value: &str) -> Result<ReceiptStatus, RemoteApplicationError> {
    match value {
        "HostAccepted" => Ok(ReceiptStatus::HostAccepted),
        "Dispatching" => Ok(ReceiptStatus::Dispatching),
        "DispatchAcknowledged" => Ok(ReceiptStatus::DispatchAcknowledged),
        "Rejected" => Ok(ReceiptStatus::Rejected),
        "Stale" => Ok(ReceiptStatus::Stale),
        "Expired" => Ok(ReceiptStatus::Expired),
        "OutcomeUnknown" => Ok(ReceiptStatus::OutcomeUnknown),
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn envelope_to_value(envelope: &ApplicationEnvelope) -> Result<Value, RemoteApplicationError> {
    let payload = payload_to_value(&envelope.payload)?;
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(APPLICATION_SCHEMA.into()));
    map.insert(
        "kind".into(),
        Value::String(
            match envelope.common.kind {
                EnvelopeKind::Projection => "projection",
                EnvelopeKind::Command => "command",
                EnvelopeKind::Receipt => "receipt",
            }
            .into(),
        ),
    );
    map.insert(
        "mailbox_id".into(),
        Value::String(envelope.common.mailbox_id.clone()),
    );
    map.insert(
        "direction".into(),
        Value::String(
            match envelope.common.direction {
                FrameDirection::HostToDevice => "host_to_device",
                FrameDirection::DeviceToHost => "device_to_host",
            }
            .into(),
        ),
    );
    map.insert("epoch".into(), Value::Number(envelope.common.epoch.into()));
    map.insert(
        "sequence".into(),
        Value::Number(envelope.common.sequence.into()),
    );
    map.insert(
        "message_id".into(),
        Value::String(envelope.common.message_id.clone()),
    );
    map.insert("payload".into(), payload);
    Ok(Value::Object(map))
}

fn payload_to_value(payload: &ApplicationPayload) -> Result<Value, RemoteApplicationError> {
    match payload {
        ApplicationPayload::Projection(value) => projection_to_value(value),
        ApplicationPayload::Command(value) => command_payload_to_value(value),
        ApplicationPayload::Receipt(value) => receipt_payload_to_value(value),
    }
}

fn projection_to_value(payload: &ProjectionPayload) -> Result<Value, RemoteApplicationError> {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(PROJECTION_SCHEMA.into()));
    map.insert(
        "snapshot".into(),
        snapshot_envelope_to_value(&payload.snapshot),
    );
    map.insert(
        "capability".into(),
        match &payload.capability {
            Some(value) => capability_to_value(value)?,
            None => Value::Null,
        },
    );
    Ok(Value::Object(map))
}

fn snapshot_envelope_to_value(snapshot: &ProductSnapshotEnvelope) -> Value {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(snapshot.schema.clone()));
    map.insert(
        "host_instance_id".into(),
        Value::String(snapshot.host_instance_id.clone()),
    );
    map.insert(
        "snapshot_seq".into(),
        Value::Number(snapshot.snapshot_seq.into()),
    );
    map.insert("digest".into(), Value::String(snapshot.digest.clone()));
    map.insert("snapshot".into(), snapshot_to_value(&snapshot.snapshot));
    Value::Object(map)
}

fn snapshot_to_value(snapshot: &ProductSnapshot) -> Value {
    let mut map = Map::new();
    map.insert(
        "session_alias".into(),
        Value::String(snapshot.session_alias.clone()),
    );
    map.insert(
        "updated_at".into(),
        Value::String(snapshot.updated_at.clone()),
    );
    map.insert(
        "turn_state".into(),
        Value::String(
            match snapshot.turn_state {
                SnapshotTurnState::Running => "Running",
                SnapshotTurnState::Completed => "Completed",
                SnapshotTurnState::NeedsInput => "NeedsInput",
                SnapshotTurnState::NeedsPermission => "NeedsPermission",
                SnapshotTurnState::OutcomeUnknown => "OutcomeUnknown",
            }
            .into(),
        ),
    );
    map.insert(
        "pending_input_alias".into(),
        optional_string_value(snapshot.pending_input_alias.as_ref()),
    );
    map.insert(
        "pending_permission_alias".into(),
        optional_string_value(snapshot.pending_permission_alias.as_ref()),
    );
    map.insert(
        "diff_file_count".into(),
        Value::Number((snapshot.diff_file_count as u64).into()),
    );
    map.insert("writable".into(), Value::Bool(snapshot.writable));
    map.insert(
        "evidence_class".into(),
        Value::String(snapshot.evidence_class.clone()),
    );
    Value::Object(map)
}

fn capability_to_value(value: &CommandCapability) -> Result<Value, RemoteApplicationError> {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(value.schema.clone()));
    map.insert(
        "capability_id".into(),
        Value::String(value.capability_id.clone()),
    );
    map.insert(
        "snapshot_seq".into(),
        Value::Number(value.snapshot_seq.into()),
    );
    map.insert(
        "snapshot_digest".into(),
        Value::String(value.snapshot_digest.clone()),
    );
    map.insert(
        "next_command_seq".into(),
        Value::Number(value.next_command_seq.into()),
    );
    map.insert("issued_at".into(), Value::String(value.issued_at.clone()));
    map.insert("expires_at".into(), Value::String(value.expires_at.clone()));
    map.insert("view".into(), Value::Bool(value.view));
    map.insert(
        "reply".into(),
        match &value.reply {
            Some(reply) => reply_capability_to_value(reply),
            None => Value::Null,
        },
    );
    map.insert(
        "deny".into(),
        match &value.deny {
            Some(deny) => deny_capability_to_value(deny),
            None => Value::Null,
        },
    );
    map.insert(
        "stop".into(),
        match &value.stop {
            Some(stop) => stop_capability_to_value(stop),
            None => Value::Null,
        },
    );
    map.insert("allow_once".into(), Value::Bool(value.allow_once));
    Ok(Value::Object(map))
}

fn reply_capability_to_value(value: &ReplyCapability) -> Value {
    let mut map = Map::new();
    map.insert("turn_alias".into(), Value::String(value.turn_alias.clone()));
    map.insert(
        "input_alias".into(),
        Value::String(value.input_alias.clone()),
    );
    map.insert(
        "summary".into(),
        match &value.summary {
            Some(summary) => pending_question_summary_to_value(summary),
            None => Value::Null,
        },
    );
    Value::Object(map)
}

fn pending_question_summary_to_value(value: &PendingQuestionSummary) -> Value {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(value.schema.clone()));
    map.insert(
        "question_count".into(),
        Value::Number((u64::from(value.question_count)).into()),
    );
    map.insert(
        "answer_mode".into(),
        Value::String(value.answer_mode.clone()),
    );
    map.insert(
        "response_hint".into(),
        Value::String(value.response_hint.clone()),
    );
    map.insert("prompt".into(), Value::String(value.prompt.clone()));
    Value::Object(map)
}

fn deny_capability_to_value(value: &DenyCapability) -> Value {
    let mut map = Map::new();
    map.insert(
        "permission_alias".into(),
        Value::String(value.permission_alias.clone()),
    );
    map.insert(
        "action_hash".into(),
        Value::String(value.action_hash.clone()),
    );
    map.insert("expires_at".into(), Value::String(value.expires_at.clone()));
    Value::Object(map)
}

fn stop_capability_to_value(value: &StopCapability) -> Value {
    let mut map = Map::new();
    map.insert("turn_alias".into(), Value::String(value.turn_alias.clone()));
    Value::Object(map)
}

fn command_payload_to_value(payload: &CommandPayload) -> Result<Value, RemoteApplicationError> {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(COMMAND_SCHEMA.into()));
    let command = gateway_command_to_value(&payload.command);
    let canonical = canonical_json(&command)?;
    if canonical.len() > MAX_COMMAND_CANONICAL_BYTES {
        return Err(RemoteApplicationError::Size);
    }
    map.insert("command".into(), command);
    Ok(Value::Object(map))
}

fn gateway_command_to_value(command: &GatewayCommand) -> Value {
    let mut map = Map::new();
    match command {
        GatewayCommand::Reply(value) => {
            insert_command_common(&mut map, value);
            map.insert("action".into(), Value::String("reply".into()));
            map.insert("turn_alias".into(), Value::String(value.turn_alias.clone()));
            map.insert(
                "input_alias".into(),
                Value::String(value.input_alias.clone()),
            );
            map.insert("content".into(), Value::String(value.content.clone()));
        }
        GatewayCommand::Deny(value) => {
            insert_command_common(&mut map, value);
            map.insert("action".into(), Value::String("deny".into()));
            map.insert(
                "permission_alias".into(),
                Value::String(value.permission_alias.clone()),
            );
            map.insert(
                "action_hash".into(),
                Value::String(value.action_hash.clone()),
            );
            map.insert(
                "permission_expires_at".into(),
                Value::String(value.permission_expires_at.clone()),
            );
        }
        GatewayCommand::Stop(value) => {
            insert_command_common(&mut map, value);
            map.insert("action".into(), Value::String("stop".into()));
            map.insert("turn_alias".into(), Value::String(value.turn_alias.clone()));
        }
    }
    Value::Object(map)
}

trait CommandCommon {
    fn capability_id(&self) -> &str;
    fn request_id(&self) -> &str;
    fn nonce(&self) -> &str;
    fn command_seq(&self) -> u64;
    fn expected_snapshot_seq(&self) -> u64;
    fn expected_snapshot_digest(&self) -> &str;
    fn issued_at(&self) -> &str;
    fn expires_at(&self) -> &str;
}

impl CommandCommon for ReplyCommand {
    fn capability_id(&self) -> &str {
        &self.capability_id
    }
    fn request_id(&self) -> &str {
        &self.request_id
    }
    fn nonce(&self) -> &str {
        &self.nonce
    }
    fn command_seq(&self) -> u64 {
        self.command_seq
    }
    fn expected_snapshot_seq(&self) -> u64 {
        self.expected_snapshot_seq
    }
    fn expected_snapshot_digest(&self) -> &str {
        &self.expected_snapshot_digest
    }
    fn issued_at(&self) -> &str {
        &self.issued_at
    }
    fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

impl CommandCommon for DenyCommand {
    fn capability_id(&self) -> &str {
        &self.capability_id
    }
    fn request_id(&self) -> &str {
        &self.request_id
    }
    fn nonce(&self) -> &str {
        &self.nonce
    }
    fn command_seq(&self) -> u64 {
        self.command_seq
    }
    fn expected_snapshot_seq(&self) -> u64 {
        self.expected_snapshot_seq
    }
    fn expected_snapshot_digest(&self) -> &str {
        &self.expected_snapshot_digest
    }
    fn issued_at(&self) -> &str {
        &self.issued_at
    }
    fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

impl CommandCommon for StopCommand {
    fn capability_id(&self) -> &str {
        &self.capability_id
    }
    fn request_id(&self) -> &str {
        &self.request_id
    }
    fn nonce(&self) -> &str {
        &self.nonce
    }
    fn command_seq(&self) -> u64 {
        self.command_seq
    }
    fn expected_snapshot_seq(&self) -> u64 {
        self.expected_snapshot_seq
    }
    fn expected_snapshot_digest(&self) -> &str {
        &self.expected_snapshot_digest
    }
    fn issued_at(&self) -> &str {
        &self.issued_at
    }
    fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

fn insert_command_common(map: &mut Map<String, Value>, value: &impl CommandCommon) {
    map.insert("schema".into(), Value::String(COMMAND_BODY_SCHEMA.into()));
    map.insert(
        "capability_id".into(),
        Value::String(value.capability_id().to_owned()),
    );
    map.insert(
        "request_id".into(),
        Value::String(value.request_id().to_owned()),
    );
    map.insert("nonce".into(), Value::String(value.nonce().to_owned()));
    map.insert(
        "command_seq".into(),
        Value::Number(value.command_seq().into()),
    );
    map.insert(
        "expected_snapshot_seq".into(),
        Value::Number(value.expected_snapshot_seq().into()),
    );
    map.insert(
        "expected_snapshot_digest".into(),
        Value::String(value.expected_snapshot_digest().to_owned()),
    );
    map.insert(
        "issued_at".into(),
        Value::String(value.issued_at().to_owned()),
    );
    map.insert(
        "expires_at".into(),
        Value::String(value.expires_at().to_owned()),
    );
}

fn receipt_payload_to_value(payload: &ReceiptPayload) -> Result<Value, RemoteApplicationError> {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(RECEIPT_SCHEMA.into()));
    map.insert("receipt".into(), receipt_to_value(&payload.receipt));
    Ok(Value::Object(map))
}

fn receipt_to_value(value: &CommandReceipt) -> Value {
    let mut map = Map::new();
    map.insert("schema".into(), Value::String(value.schema.clone()));
    map.insert("receipt_id".into(), Value::String(value.receipt_id.clone()));
    map.insert("request_id".into(), Value::String(value.request_id.clone()));
    map.insert(
        "action".into(),
        Value::String(
            match value.action {
                ReceiptAction::Reply => "reply",
                ReceiptAction::Deny => "deny",
                ReceiptAction::Stop => "stop",
            }
            .into(),
        ),
    );
    map.insert(
        "snapshot_seq".into(),
        Value::Number(value.snapshot_seq.into()),
    );
    map.insert(
        "snapshot_digest".into(),
        Value::String(value.snapshot_digest.clone()),
    );
    map.insert(
        "accepted_at".into(),
        Value::String(value.accepted_at.clone()),
    );
    map.insert(
        "status".into(),
        Value::String(
            match value.status {
                ReceiptStatus::HostAccepted => "HostAccepted",
                ReceiptStatus::Dispatching => "Dispatching",
                ReceiptStatus::DispatchAcknowledged => "DispatchAcknowledged",
                ReceiptStatus::Rejected => "Rejected",
                ReceiptStatus::Stale => "Stale",
                ReceiptStatus::Expired => "Expired",
                ReceiptStatus::OutcomeUnknown => "OutcomeUnknown",
            }
            .into(),
        ),
    );
    map.insert(
        "error_code".into(),
        Value::String(value.error_code.0.clone()),
    );
    map.insert(
        "idempotent_replay".into(),
        Value::Bool(value.idempotent_replay),
    );
    Value::Object(map)
}

fn optional_string_value(value: Option<&String>) -> Value {
    match value {
        Some(value) => Value::String(value.clone()),
        None => Value::Null,
    }
}

fn lexical_json_budget(raw: &[u8]) -> Result<(), RemoteApplicationError> {
    let mut stack = [0_u8; MAX_JSON_DEPTH];
    let mut depth = 0_usize;
    let mut nodes = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_primitive = false;

    for &byte in raw {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => {
                in_primitive = false;
                add_json_node(&mut nodes)?;
                in_string = true;
            }
            b'{' | b'[' => {
                in_primitive = false;
                add_json_node(&mut nodes)?;
                if depth == MAX_JSON_DEPTH {
                    return Err(RemoteApplicationError::Size);
                }
                stack[depth] = byte;
                depth += 1;
            }
            b'}' | b']' => {
                in_primitive = false;
                if depth == 0
                    || (byte == b'}' && stack[depth - 1] != b'{')
                    || (byte == b']' && stack[depth - 1] != b'[')
                {
                    return Err(RemoteApplicationError::Json);
                }
                depth -= 1;
            }
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => in_primitive = false,
            _ if !in_primitive => {
                add_json_node(&mut nodes)?;
                in_primitive = true;
            }
            _ => {}
        }
    }

    if in_string || escaped || depth != 0 {
        return Err(RemoteApplicationError::Json);
    }
    Ok(())
}

fn add_json_node(nodes: &mut usize) -> Result<(), RemoteApplicationError> {
    *nodes = nodes.checked_add(1).ok_or(RemoteApplicationError::Size)?;
    if *nodes > MAX_JSON_NODES {
        Err(RemoteApplicationError::Size)
    } else {
        Ok(())
    }
}

struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded duplicate-free JSON")
    }

    fn visit_unit<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: DeError>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: DeError>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: DeError>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: DeError>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            values.insert(key, map.next_value_seed(StrictSeed)?);
        }
        Ok(Value::Object(values))
    }
}

fn strict_json(raw: &[u8]) -> Result<Value, RemoteApplicationError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSeed
        .deserialize(&mut deserializer)
        .map_err(|_| RemoteApplicationError::Json)?;
    deserializer
        .end()
        .map_err(|_| RemoteApplicationError::Json)?;
    Ok(value)
}

fn canonical_json(value: &Value) -> Result<String, RemoteApplicationError> {
    fn write(value: &Value, out: &mut String) -> Result<(), RemoteApplicationError> {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => out.push_str(&value.to_string()),
            Value::String(value) => out.push_str(
                &serde_json::to_string(value).map_err(|_| RemoteApplicationError::Canonical)?,
            ),
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    write(value, out)?;
                }
                out.push(']');
            }
            Value::Object(values) => {
                out.push('{');
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    out.push_str(
                        &serde_json::to_string(key)
                            .map_err(|_| RemoteApplicationError::Canonical)?,
                    );
                    out.push(':');
                    write(
                        values.get(*key).ok_or(RemoteApplicationError::Canonical)?,
                        out,
                    )?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out)
}

fn object(value: Value) -> Result<Map<String, Value>, RemoteApplicationError> {
    value
        .as_object()
        .cloned()
        .ok_or(RemoteApplicationError::Shape)
}

fn exact_keys(
    map: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), RemoteApplicationError> {
    if map.keys().all(|key| allowed.contains(&key.as_str()))
        && required.iter().all(|key| map.contains_key(*key))
    {
        Ok(())
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn required_string<'a>(
    map: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, RemoteApplicationError> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or(RemoteApplicationError::Shape)
}

fn exact_string(
    map: &Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<String, RemoteApplicationError> {
    exact_string_value(required_string(map, key)?, expected)
}

fn exact_string_value(value: &str, expected: &str) -> Result<String, RemoteApplicationError> {
    if value == expected {
        Ok(value.to_owned())
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_bool(map: &Map<String, Value>, key: &str) -> Result<bool, RemoteApplicationError> {
    map.get(key)
        .and_then(Value::as_bool)
        .ok_or(RemoteApplicationError::Shape)
}

fn require_safe_integer(
    map: &Map<String, Value>,
    key: &str,
) -> Result<u64, RemoteApplicationError> {
    let value = map
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(RemoteApplicationError::Shape)?;
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(value)
}

fn require_safe_usize(
    map: &Map<String, Value>,
    key: &str,
) -> Result<usize, RemoteApplicationError> {
    let value = map
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(RemoteApplicationError::Shape)?;
    usize::try_from(value).map_err(|_| RemoteApplicationError::Shape)
}

fn require_diff_file_count(
    map: &Map<String, Value>,
    key: &str,
) -> Result<usize, RemoteApplicationError> {
    let value = require_safe_usize(map, key)?;
    if value <= MAX_DIFF_FILE_COUNT {
        Ok(value)
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_false_bool(map: &Map<String, Value>, key: &str) -> Result<bool, RemoteApplicationError> {
    let value = require_bool(map, key)?;
    if !value {
        Ok(value)
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_u8(map: &Map<String, Value>, key: &str) -> Result<u8, RemoteApplicationError> {
    let value = map
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(RemoteApplicationError::Shape)?;
    u8::try_from(value).map_err(|_| RemoteApplicationError::Shape)
}

fn exact_u8(
    map: &Map<String, Value>,
    key: &str,
    expected: u8,
) -> Result<u8, RemoteApplicationError> {
    let value = require_u8(map, key)?;
    if value == expected {
        Ok(value)
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_safe_string(
    map: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if value.is_empty() || value.len() > maximum || !value.is_ascii() {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(value.to_owned())
}

fn require_reply_content(
    map: &Map<String, Value>,
    key: &str,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if value.is_empty() || value.len() > MAX_REPLY_CONTENT_BYTES || value.trim().is_empty() {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(value.to_owned())
}

fn require_ascii_token(
    map: &Map<String, Value>,
    key: &str,
    maximum: usize,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
    {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(value.to_owned())
}

fn exact_ascii_token(
    map: &Map<String, Value>,
    key: &str,
    expected: &str,
    maximum: usize,
) -> Result<String, RemoteApplicationError> {
    let value = require_ascii_token(map, key, maximum)?;
    if value == expected {
        Ok(value)
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_prefixed_hex(
    map: &Map<String, Value>,
    key: &str,
    prefix: &str,
    hex_len: usize,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if prefixed_hex(value, prefix, hex_len) {
        Ok(value.to_owned())
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_alias(
    map: &Map<String, Value>,
    key: &str,
    prefix: &str,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if value.starts_with(prefix)
        && value.len() == prefix.len() + 32
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_optional_alias(
    map: &Map<String, Value>,
    key: &str,
    prefix: &str,
) -> Result<Option<String>, RemoteApplicationError> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(_)) => require_alias(map, key, prefix).map(Some),
        _ => Err(RemoteApplicationError::Shape),
    }
}

fn require_sha256_digest(
    map: &Map<String, Value>,
    key: &str,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err(RemoteApplicationError::Shape)
    }
}

fn require_rfc3339_string(
    map: &Map<String, Value>,
    key: &str,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    if value.is_empty() || value.len() > MAX_SAFE_STRING_BYTES || !value.is_ascii() {
        return Err(RemoteApplicationError::Shape);
    }
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| RemoteApplicationError::Shape)?;
    Ok(value.to_owned())
}

fn require_whole_second_utc_string(
    map: &Map<String, Value>,
    key: &str,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    parse_exact_whole_second_utc(value)?;
    Ok(value.to_owned())
}

fn require_millisecond_utc_string(
    map: &Map<String, Value>,
    key: &str,
) -> Result<String, RemoteApplicationError> {
    let value = required_string(map, key)?;
    parse_exact_millisecond_utc(value)?;
    Ok(value.to_owned())
}

fn parse_exact_whole_second_utc(value: &str) -> Result<OffsetDateTime, RemoteApplicationError> {
    let parsed = parse_utc_rfc3339(value)?;
    if format_whole_second_utc(&parsed)? != value {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(parsed)
}

fn parse_exact_millisecond_utc(value: &str) -> Result<OffsetDateTime, RemoteApplicationError> {
    let parsed = parse_utc_rfc3339(value)?;
    if format_millisecond_utc(&parsed)? != value {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(parsed)
}

fn parse_utc_rfc3339(value: &str) -> Result<OffsetDateTime, RemoteApplicationError> {
    if value.is_empty() || value.len() > MAX_SAFE_STRING_BYTES || !value.is_ascii() {
        return Err(RemoteApplicationError::Shape);
    }
    let parsed =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| RemoteApplicationError::Shape)?;
    if parsed.offset() != time::UtcOffset::UTC {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(parsed)
}

fn format_whole_second_utc(value: &OffsetDateTime) -> Result<String, RemoteApplicationError> {
    let normalized = value
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|_| RemoteApplicationError::Shape)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        normalized.year(),
        u8::from(normalized.month()),
        normalized.day(),
        normalized.hour(),
        normalized.minute(),
        normalized.second()
    ))
}

fn format_millisecond_utc(value: &OffsetDateTime) -> Result<String, RemoteApplicationError> {
    let normalized = value
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond((value.nanosecond() / 1_000_000) * 1_000_000)
        .map_err(|_| RemoteApplicationError::Shape)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        normalized.year(),
        u8::from(normalized.month()),
        normalized.day(),
        normalized.hour(),
        normalized.minute(),
        normalized.second(),
        normalized.nanosecond() / 1_000_000
    ))
}

fn validate_ttl_window(
    issued_at: &str,
    expires_at: &str,
    max_ttl_seconds: i64,
) -> Result<(), RemoteApplicationError> {
    let issued = parse_exact_whole_second_utc(issued_at)?;
    let expires = parse_exact_whole_second_utc(expires_at)?;
    if expires <= issued || expires - issued > time::Duration::seconds(max_ttl_seconds) {
        return Err(RemoteApplicationError::Shape);
    }
    Ok(())
}

fn compute_snapshot_digest(
    envelope: &ProductSnapshotEnvelope,
) -> Result<String, RemoteApplicationError> {
    let mut value = snapshot_envelope_to_value(envelope);
    value
        .as_object_mut()
        .ok_or(RemoteApplicationError::Canonical)?
        .remove("digest")
        .ok_or(RemoteApplicationError::Canonical)?;
    let canonical = canonical_json(&value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
}

fn parse_optional_object_field<T>(
    map: &Map<String, Value>,
    key: &str,
    parser: fn(Value) -> Result<T, RemoteApplicationError>,
) -> Result<Option<T>, RemoteApplicationError> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => parser(value.clone()).map(Some),
        None => Err(RemoteApplicationError::Shape),
    }
}

fn prefixed_hex(value: &str, prefix: &str, hex_len: usize) -> bool {
    value.len() == prefix.len() + hex_len
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn binding(direction: FrameDirection) -> FrameBinding {
        FrameBinding {
            schema: RELAY_FRAME_SCHEMA.into(),
            crypto_suite: RELAY_CRYPTO_SUITE.into(),
            mailbox_id: format!("mbx-{}", "a".repeat(64)),
            direction,
            epoch: 7,
            sequence: 9,
            message_id: format!("msg-{}", "b".repeat(32)),
        }
    }

    fn projection_value() -> Value {
        let mut value = serde_json::json!({
            "schema": APPLICATION_SCHEMA,
            "kind": "projection",
            "mailbox_id": format!("mbx-{}", "a".repeat(64)),
            "direction": "host_to_device",
            "epoch": 7,
            "sequence": 9,
            "message_id": format!("msg-{}", "b".repeat(32)),
            "payload": {
                "schema": PROJECTION_SCHEMA,
                "snapshot": {
                    "schema": SNAPSHOT_SCHEMA,
                    "host_instance_id": "host-0123456789abcdef0123456789abcdef",
                    "snapshot_seq": 3,
                    "digest": "",
                    "snapshot": {
                        "session_alias": "sess-0123456789abcdef0123456789abcdef",
                        "updated_at": "2026-08-26T09:00:00.000Z",
                        "turn_state": "Running",
                        "pending_input_alias": null,
                        "pending_permission_alias": null,
                        "diff_file_count": 0,
                        "writable": false,
                        "evidence_class": "official_registry_shape_only_not_provider_lifecycle"
                    }
                },
                "capability": {
                    "schema": CAPABILITY_SCHEMA,
                    "capability_id": "cap_0123456789abcdef0123456789abcdef01234567",
                    "snapshot_seq": 3,
                    "snapshot_digest": "",
                    "next_command_seq": 4,
                    "issued_at": "2026-08-26T09:00:00Z",
                    "expires_at": "2026-08-26T09:00:30Z",
                    "view": true,
                    "reply": {
                        "turn_alias": "turn-11111111111111111111111111111111",
                        "input_alias": "input-22222222222222222222222222222222",
                        "summary": {
                            "schema": QUESTION_SUMMARY_SCHEMA,
                            "question_count": 1,
                            "answer_mode": "free_text",
                            "response_hint": "single_short_reply",
                            "prompt": "Provide a short reply for: branch name."
                        }
                    },
                    "deny": null,
                    "stop": {
                        "turn_alias": "turn-11111111111111111111111111111111"
                    },
                    "allow_once": false
                }
            }
        });
        let digest = snapshot_digest_from_projection(&value);
        value["payload"]["snapshot"]["digest"] = Value::String(digest.clone());
        value["payload"]["capability"]["snapshot_digest"] = Value::String(digest);
        value
    }

    fn command_value() -> Value {
        serde_json::json!({
            "schema": APPLICATION_SCHEMA,
            "kind": "command",
            "mailbox_id": format!("mbx-{}", "a".repeat(64)),
            "direction": "device_to_host",
            "epoch": 7,
            "sequence": 9,
            "message_id": format!("msg-{}", "b".repeat(32)),
            "payload": {
                "schema": COMMAND_SCHEMA,
                "command": {
                    "schema": COMMAND_BODY_SCHEMA,
                    "capability_id": "capability_00000001",
                    "request_id": "request_00000001",
                    "nonce": "nonce_0000000001",
                    "command_seq": 2,
                    "expected_snapshot_seq": 7,
                    "expected_snapshot_digest": format!("sha256:{}", "e".repeat(64)),
                    "issued_at": "2026-08-26T09:00:00Z",
                    "expires_at": "2026-08-26T09:00:30Z",
                    "action": "reply",
                    "turn_alias": "turn-11111111111111111111111111111111",
                    "input_alias": "input-22222222222222222222222222222222",
                    "content": "short reply"
                }
            }
        })
    }

    fn receipt_value() -> Value {
        serde_json::json!({
            "schema": APPLICATION_SCHEMA,
            "kind": "receipt",
            "mailbox_id": format!("mbx-{}", "a".repeat(64)),
            "direction": "host_to_device",
            "epoch": 7,
            "sequence": 9,
            "message_id": format!("msg-{}", "b".repeat(32)),
            "payload": {
                "schema": RECEIPT_SCHEMA,
                "receipt": {
                    "schema": RECEIPT_BODY_SCHEMA,
                    "receipt_id": "receipt_00000001",
                    "request_id": "request_00000001",
                    "action": "reply",
                    "snapshot_seq": 7,
                    "snapshot_digest": format!("sha256:{}", "f".repeat(64)),
                    "accepted_at": "2026-08-26T09:00:02Z",
                    "status": "DispatchAcknowledged",
                    "error_code": "OK",
                    "idempotent_replay": false
                }
            }
        })
    }

    fn canonical_bytes(value: &Value) -> Vec<u8> {
        canonical_json(value).unwrap().into_bytes()
    }

    fn snapshot_digest_from_projection(value: &Value) -> String {
        let mut snapshot = value["payload"]["snapshot"].clone();
        snapshot.as_object_mut().unwrap().remove("digest");
        let canonical = canonical_json(&snapshot).unwrap();
        format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()))
    }

    #[test]
    fn projection_command_and_receipt_parse_with_exact_binding() {
        let projection = parse_application_envelope(
            &canonical_bytes(&projection_value()),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();
        assert!(matches!(
            projection.payload,
            ApplicationPayload::Projection(_)
        ));

        let command = parse_application_envelope(
            &canonical_bytes(&command_value()),
            &binding(FrameDirection::DeviceToHost),
        )
        .unwrap();
        assert!(matches!(command.payload, ApplicationPayload::Command(_)));

        let receipt = parse_application_envelope(
            &canonical_bytes(&receipt_value()),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();
        assert!(matches!(receipt.payload, ApplicationPayload::Receipt(_)));
    }

    #[test]
    fn common_field_mismatch_fails_before_acceptance() {
        let raw = canonical_bytes(&command_value());
        let mut wrong = binding(FrameDirection::DeviceToHost);
        wrong.message_id = format!("msg-{}", "c".repeat(32));
        assert_eq!(
            parse_application_envelope(&raw, &wrong),
            Err(RemoteApplicationError::Binding)
        );
    }

    #[test]
    fn kind_direction_unknown_action_and_allow_once_fail_closed() {
        let mut wrong_kind = command_value();
        wrong_kind["direction"] = Value::String("host_to_device".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&wrong_kind),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Binding)
        );

        let mut unknown_action = command_value();
        unknown_action["payload"]["command"]["action"] = Value::String("approve".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&unknown_action),
                &binding(FrameDirection::DeviceToHost)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut allow_once = projection_value();
        allow_once["payload"]["capability"]["allow_once"] = Value::Bool(true);
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&allow_once),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut missing_summary = projection_value();
        missing_summary["payload"]["capability"]["reply"]["summary"] = Value::Null;
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&missing_summary),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );
    }

    #[test]
    fn duplicate_unknown_trailing_and_noncanonical_fail_closed() {
        let duplicate = br#"{"schema":"nomad.remote.application-envelope.v1","schema":"nomad.remote.application-envelope.v1","kind":"receipt","mailbox_id":"mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","direction":"host_to_device","epoch":7,"sequence":9,"message_id":"msg-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","payload":{"schema":"nomad.remote.receipt.v1","receipt":{"schema":"nomad.gateway.command-receipt.v1","receipt_id":"receipt_00000001","request_id":"request_00000001","action":"reply","snapshot_seq":7,"snapshot_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","accepted_at":"2026-08-26T09:00:02Z","status":"DispatchAcknowledged","error_code":"OK","idempotent_replay":false}}}"#;
        assert_eq!(
            parse_application_envelope(duplicate, &binding(FrameDirection::HostToDevice)),
            Err(RemoteApplicationError::Json)
        );

        let mut unknown = receipt_value();
        unknown["extra"] = Value::Bool(true);
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&unknown),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut trailing = canonical_bytes(&receipt_value());
        trailing.push(b' ');
        assert_eq!(
            parse_application_envelope(&trailing, &binding(FrameDirection::HostToDevice)),
            Err(RemoteApplicationError::Canonical)
        );

        let noncanonical = br#"{"schema":"nomad.remote.application-envelope.v1","kind":"receipt","mailbox_id":"mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","direction":"host_to_device","epoch":7,"sequence":9,"message_id":"msg-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","payload":{"receipt":{"accepted_at":"2026-08-26T09:00:02Z","action":"reply","error_code":"OK","idempotent_replay":false,"receipt_id":"receipt_00000001","request_id":"request_00000001","schema":"nomad.gateway.command-receipt.v1","snapshot_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","snapshot_seq":7,"status":"DispatchAcknowledged"},"schema":"nomad.remote.receipt.v1"}}"#;
        assert_eq!(
            parse_application_envelope(noncanonical, &binding(FrameDirection::HostToDevice)),
            Err(RemoteApplicationError::Canonical)
        );
    }

    #[test]
    fn size_depth_nodes_and_status_binding_fail_closed() {
        let mut over = projection_value();
        over["payload"]["snapshot"]["snapshot"]["evidence_class"] =
            Value::String("x".repeat(MAX_CANONICAL_BYTES));
        let over = canonical_bytes(&over);
        assert_eq!(
            parse_application_envelope(&over, &binding(FrameDirection::HostToDevice)),
            Err(RemoteApplicationError::Size)
        );

        let mut nested = vec![b'['; MAX_JSON_DEPTH + 1];
        nested.extend(std::iter::repeat_n(b']', MAX_JSON_DEPTH + 1));
        assert_eq!(
            parse_application_envelope(&nested, &binding(FrameDirection::HostToDevice)),
            Err(RemoteApplicationError::Size)
        );

        let mut nodes = Vec::with_capacity(MAX_JSON_NODES * 5 + 2);
        nodes.push(b'[');
        for index in 0..=MAX_JSON_NODES {
            if index != 0 {
                nodes.push(b',');
            }
            nodes.extend_from_slice(b"null");
        }
        nodes.push(b']');
        assert_eq!(
            parse_application_envelope(&nodes, &binding(FrameDirection::HostToDevice)),
            Err(RemoteApplicationError::Size)
        );

        let mut bad_status = receipt_value();
        bad_status["payload"]["receipt"]["status"] = Value::String("Success".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_status),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_error = receipt_value();
        bad_error["payload"]["receipt"]["error_code"] = Value::Null;
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_error),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut removed_error = receipt_value();
        removed_error["payload"]["receipt"]["error_code"] =
            Value::String("COMMAND_UNAVAILABLE".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&removed_error),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );
    }

    #[test]
    fn stale_expired_and_command_size_limits_follow_current_c3() {
        for status in [
            "HostAccepted",
            "Dispatching",
            "DispatchAcknowledged",
            "Rejected",
            "Stale",
            "Expired",
            "OutcomeUnknown",
        ] {
            let mut value = receipt_value();
            value["payload"]["receipt"]["status"] = Value::String(status.into());
            let parsed = parse_application_envelope(
                &canonical_bytes(&value),
                &binding(FrameDirection::HostToDevice),
            )
            .unwrap();
            assert!(matches!(parsed.payload, ApplicationPayload::Receipt(_)));
        }

        let mut expired = receipt_value();
        expired["payload"]["receipt"]["status"] = Value::String("Expired".into());
        expired["payload"]["receipt"]["error_code"] = Value::String("ERR_REQUEST_EXPIRED".into());
        parse_application_envelope(
            &canonical_bytes(&expired),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();

        let mut stale = receipt_value();
        stale["payload"]["receipt"]["status"] = Value::String("Stale".into());
        stale["payload"]["receipt"]["error_code"] = Value::String("ERR_REQUEST_STALE".into());
        parse_application_envelope(
            &canonical_bytes(&stale),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();

        let mut revoked = receipt_value();
        revoked["payload"]["receipt"]["status"] = Value::String("Rejected".into());
        revoked["payload"]["receipt"]["error_code"] = Value::String("ERR_REQUEST_REVOKED".into());
        parse_application_envelope(
            &canonical_bytes(&revoked),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();

        let mut incompatible = receipt_value();
        incompatible["payload"]["receipt"]["status"] = Value::String("Rejected".into());
        incompatible["payload"]["receipt"]["error_code"] =
            Value::String("ERR_INCOMPATIBLE_VERSION".into());
        parse_application_envelope(
            &canonical_bytes(&incompatible),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();

        let mut large = command_value();
        large["payload"]["command"]["content"] =
            Value::String("x".repeat(MAX_REPLY_CONTENT_BYTES + 1));
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&large),
                &binding(FrameDirection::DeviceToHost)
            ),
            Err(RemoteApplicationError::Shape)
        );
    }

    #[test]
    fn digest_time_projection_and_summary_constraints_fail_closed() {
        let mut bad_digest = projection_value();
        bad_digest["payload"]["snapshot"]["digest"] =
            Value::String(format!("sha256:{}", "c".repeat(64)));
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_digest),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_cap_digest = projection_value();
        bad_cap_digest["payload"]["capability"]["snapshot_digest"] =
            Value::String(format!("sha256:{}", "d".repeat(64)));
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_cap_digest),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_cap_seq = projection_value();
        bad_cap_seq["payload"]["capability"]["snapshot_seq"] = Value::Number(4_u64.into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_cap_seq),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_updated_at = projection_value();
        bad_updated_at["payload"]["snapshot"]["snapshot"]["updated_at"] =
            Value::String("2026-08-26T09:00:00Z".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_updated_at),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_diff = projection_value();
        bad_diff["payload"]["snapshot"]["snapshot"]["diff_file_count"] =
            Value::Number(257_u64.into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_diff),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_writable = projection_value();
        bad_writable["payload"]["snapshot"]["snapshot"]["writable"] = Value::Bool(true);
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_writable),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_ttl = projection_value();
        bad_ttl["payload"]["capability"]["expires_at"] =
            Value::String("2026-08-26T09:00:31Z".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_ttl),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_fractional = projection_value();
        bad_fractional["payload"]["capability"]["issued_at"] =
            Value::String("2026-08-26T09:00:00.123Z".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_fractional),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_summary_count = projection_value();
        bad_summary_count["payload"]["capability"]["reply"]["summary"]["question_count"] =
            Value::Number(2_u64.into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_summary_count),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_summary_hint = projection_value();
        bad_summary_hint["payload"]["capability"]["reply"]["summary"]["response_hint"] =
            Value::String("multi_turn".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_summary_hint),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut blank_reply = command_value();
        blank_reply["payload"]["command"]["content"] = Value::String("   ".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&blank_reply),
                &binding(FrameDirection::DeviceToHost)
            ),
            Err(RemoteApplicationError::Shape)
        );

        let mut bad_receipt_time = receipt_value();
        bad_receipt_time["payload"]["receipt"]["accepted_at"] =
            Value::String("2026-08-26T09:00:02.000Z".into());
        assert_eq!(
            parse_application_envelope(
                &canonical_bytes(&bad_receipt_time),
                &binding(FrameDirection::HostToDevice)
            ),
            Err(RemoteApplicationError::Shape)
        );
    }

    #[test]
    fn canonical_encode_round_trips_and_sorts_keys() {
        let envelope = parse_application_envelope(
            &canonical_bytes(&projection_value()),
            &binding(FrameDirection::HostToDevice),
        )
        .unwrap();
        let encoded = canonical_encode_application_envelope(&envelope).unwrap();
        let reparsed =
            parse_application_envelope(&encoded, &binding(FrameDirection::HostToDevice)).unwrap();
        assert_eq!(envelope, reparsed);
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.starts_with("{\"direction\""));
        assert!(text.contains("\"kind\":\"projection\""));
    }

    #[derive(Deserialize)]
    struct SharedVectorEntry {
        canonical_json: String,
        frame_binding: SharedVectorBinding,
    }

    #[derive(Deserialize)]
    struct SharedVectorBinding {
        mailbox_id: String,
        direction: String,
        epoch: u64,
        sequence: u64,
        message_id: String,
    }

    #[derive(Deserialize)]
    struct SharedVectorFile {
        marker: String,
        projection: SharedVectorEntry,
        command: SharedVectorEntry,
        receipt: SharedVectorEntry,
    }

    fn shared_vector() -> SharedVectorFile {
        serde_json::from_str(include_str!(
            "../../contracts/vectors/remote-application-v1.json"
        ))
        .unwrap()
    }

    fn shared_binding(binding: &SharedVectorBinding) -> FrameBinding {
        FrameBinding {
            schema: RELAY_FRAME_SCHEMA.into(),
            crypto_suite: RELAY_CRYPTO_SUITE.into(),
            mailbox_id: binding.mailbox_id.clone(),
            direction: match binding.direction.as_str() {
                "host_to_device" => FrameDirection::HostToDevice,
                "device_to_host" => FrameDirection::DeviceToHost,
                other => panic!("unexpected direction: {other}"),
            },
            epoch: binding.epoch,
            sequence: binding.sequence,
            message_id: binding.message_id.clone(),
        }
    }

    #[test]
    fn shared_application_vectors_parse_and_roundtrip_byte_exact() {
        let vectors = shared_vector();
        assert_eq!(vectors.marker, "TEST_ONLY_VECTOR");

        for entry in [&vectors.projection, &vectors.command, &vectors.receipt] {
            let binding = shared_binding(&entry.frame_binding);
            let parsed =
                parse_application_envelope(entry.canonical_json.as_bytes(), &binding).unwrap();
            let encoded = canonical_encode_application_envelope(&parsed).unwrap();
            assert_eq!(encoded, entry.canonical_json.as_bytes());
        }
    }
}
