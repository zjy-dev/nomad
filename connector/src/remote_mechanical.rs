use crate::error::ConnectorError;
use crate::remote_application::{
    canonical_encode_application_envelope, parse_application_envelope, ApplicationEnvelope,
    ApplicationPayload, CommandCapability, CommandPayload, CommandReceipt, EnvelopeCommon,
    EnvelopeKind, FrameBinding, FrameDirection, ProductSnapshot, ProductSnapshotEnvelope,
    ProjectionPayload, ReceiptAction, ReceiptErrorCode, ReceiptPayload, ReceiptStatus,
    SnapshotTurnState, StopCapability,
};
use crate::remote_crypto::{
    commitment, encrypt, Direction, EndpointKeys, FrameMetadata, OpaqueFrame, SharedContext,
};
use crate::remote_mailbox::{
    HostRelayV2Client, PendingOutboundFrame, RelayOpaqueFrame, RemoteDirection, RemoteMailboxState,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::path::PathBuf;
use time::format_description::parse_borrowed;
use time::OffsetDateTime;

const APPLICATION_SCHEMA: &str = "nomad.remote.application-envelope.v1";
const SNAPSHOT_SCHEMA: &str = "nomad.product-host.snapshot.v1";
const RECEIPT_BODY_SCHEMA: &str = "nomad.gateway.command-receipt.v1";
const FRAME_SCHEMA: &str = "nomad.relay.opaque-frame.v2";
const CRYPTO_SUITE: &str = "p256-hkdf-sha256-aes256gcm-v1";
const EVIDENCE_CLASS: &str = "official_registry_shape_only_not_provider_lifecycle";
const HOST_INSTANCE_ID: &str = "host-0123456789abcdef0123456789abcdef";
const SESSION_ALIAS: &str = "sess-11111111111111111111111111111111";
const TURN_ALIAS: &str = "turn-11111111111111111111111111111111";
const ERR_SAFETY_BLOCKED: &str = "ERR_SAFETY_BLOCKED";
const HOST_TOKEN_ENV: &str = "NOMAD_REMOTE_V2_HOST_TOKEN";
const MESSAGE_ID_SCOPE_PROJECTION: &str = "publish-projection";
const MESSAGE_ID_SCOPE_RECEIPT: &str = "consume-command-receipt";
const BUCKETS: [usize; 5] = [512, 2048, 8192, 32768, 65536];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MechanicalPhase {
    PublishProjection,
    ConsumeCommand,
    Revoke,
}

impl MechanicalPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::PublishProjection => "publish-projection",
            Self::ConsumeCommand => "consume-command",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MechanicalConfig {
    phase: MechanicalPhase,
    relay_url: String,
    state_path: PathBuf,
}

struct MechanicalRuntime {
    vector: FixedVector,
    host_keys: EndpointKeys,
    relay: HostRelayV2Client,
    state: RemoteMailboxState,
}

struct FixedVector {
    mailbox_id: String,
    epoch: u64,
    context: SharedContext,
    device_agreement_public: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct MechanicalJsonOutput {
    pub phase: String,
    pub status: String,
    pub mailbox_id: String,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_through_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked_through_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_semantics: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VectorContract {
    marker: String,
    frame: VectorFrame,
    host_signing_public_key_sec1: String,
    host_agreement_public_key_sec1: String,
    device_signing_public_key_sec1: String,
    device_agreement_public_key_sec1: String,
    host_signing_commitment: String,
    host_agreement_commitment: String,
    device_signing_commitment: String,
    device_agreement_commitment: String,
    host_signing_private_key_pkcs8: String,
    host_agreement_private_key_pkcs8: String,
    device_signing_private_key_pkcs8: String,
    device_agreement_private_key_pkcs8: String,
}

#[derive(Debug, Deserialize)]
struct VectorFrame {
    mailbox_id: String,
    epoch: u64,
}

pub fn remote_v2_mechanical_entrypoint() -> Result<MechanicalJsonOutput, ConnectorError> {
    let config = parse_args_from(env::args().skip(1))?;
    run_with_config(config)
}

fn run_with_config(config: MechanicalConfig) -> Result<MechanicalJsonOutput, ConnectorError> {
    let token = take_host_token()?;
    let vector = load_fixed_vector()?;
    let host_keys = EndpointKeys::from_pkcs8_base64(
        &vector.1.host_signing_private_key_pkcs8,
        &vector.1.host_agreement_private_key_pkcs8,
    )
    .map_err(|_| ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into()))?;
    let state = RemoteMailboxState::open(&config.state_path)
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    let relay = HostRelayV2Client::new(&config.relay_url, &token, true).map_err(|_| {
        ConnectorError::Other("remote v2 helper relay configuration invalid".into())
    })?;
    let runtime = MechanicalRuntime {
        vector: vector.0,
        host_keys,
        relay,
        state,
    };
    match config.phase {
        MechanicalPhase::PublishProjection => publish_projection(runtime),
        MechanicalPhase::ConsumeCommand => consume_command(runtime),
        MechanicalPhase::Revoke => revoke(runtime),
    }
}

fn parse_args_from<I>(args: I) -> Result<MechanicalConfig, ConnectorError>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut phase = None;
    let mut relay_url = None;
    let mut state_path = None;
    let mut iter = args.into_iter().map(Into::into);
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| ConnectorError::Other(format!("missing value for {flag}")))?;
        match flag.as_str() {
            "--phase" => {
                phase = Some(match value.as_str() {
                    "publish-projection" => MechanicalPhase::PublishProjection,
                    "consume-command" => MechanicalPhase::ConsumeCommand,
                    "revoke" => MechanicalPhase::Revoke,
                    _ => {
                        return Err(ConnectorError::Other(
                            "nomad-remote-v2-mechanical requires --phase publish-projection|consume-command|revoke".into(),
                        ))
                    }
                })
            }
            "--relay-url" => relay_url = Some(value),
            "--state" => state_path = Some(PathBuf::from(value)),
            _ => {
                return Err(ConnectorError::Other(format!(
                    "unknown argument {flag}; expected --phase --relay-url --state"
                )))
            }
        }
    }
    Ok(MechanicalConfig {
        phase: phase.ok_or_else(|| {
            ConnectorError::Other(
                "nomad-remote-v2-mechanical requires --phase publish-projection|consume-command|revoke".into(),
            )
        })?,
        relay_url: relay_url.ok_or_else(|| {
            ConnectorError::Other("nomad-remote-v2-mechanical requires --relay-url".into())
        })?,
        state_path: state_path.ok_or_else(|| {
            ConnectorError::Other("nomad-remote-v2-mechanical requires --state".into())
        })?,
    })
}

fn take_host_token() -> Result<String, ConnectorError> {
    let token = env::var(HOST_TOKEN_ENV).map_err(|_| {
        ConnectorError::Other(format!(
            "nomad-remote-v2-mechanical requires {HOST_TOKEN_ENV}"
        ))
    })?;
    env::remove_var(HOST_TOKEN_ENV);
    if token.is_empty() {
        return Err(ConnectorError::Other(
            "nomad-remote-v2-mechanical host token must be non-empty".into(),
        ));
    }
    Ok(token)
}

fn publish_projection(runtime: MechanicalRuntime) -> Result<MechanicalJsonOutput, ConnectorError> {
    let (frame, reused_pending) = flush_or_publish_projection(
        &runtime.state,
        &runtime.relay,
        &runtime.vector,
        &runtime.host_keys,
    )?;
    Ok(MechanicalJsonOutput {
        phase: MechanicalPhase::PublishProjection.as_str().into(),
        status: if reused_pending {
            "republished_pending_frame"
        } else {
            "published_projection"
        }
        .into(),
        mailbox_id: runtime.vector.mailbox_id.clone(),
        epoch: runtime.vector.epoch,
        published_sequence: Some(frame.sequence),
        message_id: Some(frame.message_id),
        read_sequence: None,
        applied_through_sequence: None,
        acked_through_sequence: None,
        request_id: None,
        receipt_sequence: None,
        receipt_message_id: None,
        restart_semantics: Some(
            "publish-projection reuses any durable pending host_to_device frame byte-for-byte until publish succeeds; otherwise it reserves exactly one new sequence and emits one new projection frame".into(),
        ),
    })
}

fn consume_command(runtime: MechanicalRuntime) -> Result<MechanicalJsonOutput, ConnectorError> {
    let _ = flush_pending_outbound_if_any(&runtime.state, &runtime.relay, &runtime.vector)?;
    let initial_cursor = runtime
        .state
        .cursor(
            &runtime.vector.mailbox_id,
            RemoteDirection::DeviceToHost,
            runtime.vector.epoch,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    let frames = runtime
        .relay
        .read_device_to_host_frames(
            &runtime.vector.mailbox_id,
            runtime.vector.epoch,
            initial_cursor.acked_through_sequence,
        )
        .map_err(|_| ConnectorError::HostOffline)?;
    if frames.is_empty() {
        return Ok(MechanicalJsonOutput {
            phase: MechanicalPhase::ConsumeCommand.as_str().into(),
            status: "idle".into(),
            mailbox_id: runtime.vector.mailbox_id.clone(),
            epoch: runtime.vector.epoch,
            published_sequence: None,
            message_id: None,
            read_sequence: Some(initial_cursor.read_through_sequence),
            applied_through_sequence: Some(initial_cursor.applied_through_sequence),
            acked_through_sequence: Some(initial_cursor.acked_through_sequence),
            request_id: None,
            receipt_sequence: None,
            receipt_message_id: None,
            restart_semantics: Some(
                "consume-command resumes from durable acked_through_sequence; unread or unacked device_to_host frames are re-read on restart until they are acked".into(),
            ),
        });
    }
    let relay_frame: RelayOpaqueFrame = serde_json::from_slice(&frames[0])
        .map_err(|_| ConnectorError::ProtocolMismatch("remote v2 helper frame invalid".into()))?;
    runtime
        .state
        .persist_read_through_sequence(
            &runtime.vector.mailbox_id,
            RemoteDirection::DeviceToHost,
            runtime.vector.epoch,
            relay_frame.sequence,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    let crypto_frame = relay_frame_to_crypto(&relay_frame);
    let plaintext = runtime
        .host_keys
        .decrypt_from_device(&crypto_frame, &runtime.vector.context)
        .map_err(|_| {
            ConnectorError::ProtocolMismatch("remote v2 helper frame authentication failed".into())
        })?;
    let canonical_plaintext = canonical_json_value(&plaintext).map_err(|_| {
        ConnectorError::ProtocolMismatch("remote v2 helper application payload invalid".into())
    })?;
    let binding = frame_binding_from_relay(&relay_frame);
    let envelope = parse_application_envelope(canonical_plaintext.as_bytes(), &binding)?;
    let command = match envelope.payload {
        ApplicationPayload::Command(command) => command,
        _ => {
            return Err(ConnectorError::ProtocolMismatch(
                "remote v2 helper expected a command envelope".into(),
            ))
        }
    };
    let request_id = request_id_from_command(&command).to_string();
    if relay_frame.sequence > initial_cursor.applied_through_sequence {
        runtime
            .state
            .persist_applied_through_sequence(
                &runtime.vector.mailbox_id,
                RemoteDirection::DeviceToHost,
                runtime.vector.epoch,
                relay_frame.sequence,
            )
            .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    }
    if relay_frame.sequence > initial_cursor.acked_through_sequence {
        runtime
            .relay
            .ack_device_to_host(
                &runtime.vector.mailbox_id,
                runtime.vector.epoch,
                relay_frame.sequence,
            )
            .map_err(|_| ConnectorError::HostOffline)?;
        runtime
            .state
            .persist_acked_through_sequence(
                &runtime.vector.mailbox_id,
                RemoteDirection::DeviceToHost,
                runtime.vector.epoch,
                relay_frame.sequence,
            )
            .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    }
    let (receipt_frame, _) = publish_rejection_receipt(
        &runtime.state,
        &runtime.relay,
        &runtime.vector,
        &runtime.host_keys,
        &command,
    )?;
    let final_cursor = runtime
        .state
        .cursor(
            &runtime.vector.mailbox_id,
            RemoteDirection::DeviceToHost,
            runtime.vector.epoch,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    Ok(MechanicalJsonOutput {
        phase: MechanicalPhase::ConsumeCommand.as_str().into(),
        status: "rejected_safety_blocked".into(),
        mailbox_id: runtime.vector.mailbox_id.clone(),
        epoch: runtime.vector.epoch,
        published_sequence: None,
        message_id: None,
        read_sequence: Some(relay_frame.sequence),
        applied_through_sequence: Some(final_cursor.applied_through_sequence),
        acked_through_sequence: Some(final_cursor.acked_through_sequence),
        request_id: Some(request_id),
        receipt_sequence: Some(receipt_frame.sequence),
        receipt_message_id: Some(receipt_frame.message_id),
        restart_semantics: Some(
            "consume-command persists applied_through_sequence before ACK, advances acked_through_sequence only after relay ACK succeeds, and republishes any older durable pending host_to_device frame before emitting a new receipt".into(),
        ),
    })
}

fn revoke(runtime: MechanicalRuntime) -> Result<MechanicalJsonOutput, ConnectorError> {
    runtime
        .relay
        .delete_mailbox(&runtime.vector.mailbox_id)
        .map_err(|_| ConnectorError::HostOffline)?;
    Ok(MechanicalJsonOutput {
        phase: MechanicalPhase::Revoke.as_str().into(),
        status: "revoked".into(),
        mailbox_id: runtime.vector.mailbox_id.clone(),
        epoch: runtime.vector.epoch,
        published_sequence: None,
        message_id: None,
        read_sequence: None,
        applied_through_sequence: None,
        acked_through_sequence: None,
        request_id: None,
        receipt_sequence: None,
        receipt_message_id: None,
        restart_semantics: Some(
            "revoke is best-effort DELETE against the fixed mailbox_id from the test vector and has no local durable retry queue".into(),
        ),
    })
}

fn flush_or_publish_projection(
    state: &RemoteMailboxState,
    relay: &HostRelayV2Client,
    vector: &FixedVector,
    host_keys: &EndpointKeys,
) -> Result<(RelayOpaqueFrame, bool), ConnectorError> {
    if let Some(frame) = flush_pending_outbound_if_any(state, relay, vector)? {
        return Ok((frame, true));
    }
    let now = OffsetDateTime::now_utc();
    let sequence = state
        .reserve_outbound_sequence(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    let envelope = build_projection_envelope(
        vector,
        sequence,
        &message_id_for(sequence, MESSAGE_ID_SCOPE_PROJECTION),
        now,
    )?;
    let plaintext = canonical_encode_application_envelope(&envelope)?;
    let frame = encrypt_application_bytes(
        vector,
        host_keys,
        Direction::HostToDevice,
        sequence,
        &message_id_for(sequence, MESSAGE_ID_SCOPE_PROJECTION),
        now,
        &plaintext,
    )?;
    let canonical_frame_bytes = serde_json::to_vec(&frame)?;
    state
        .store_pending_outbound_frame(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
            sequence,
            &canonical_frame_bytes,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    relay
        .publish_frame(&canonical_frame_bytes)
        .map_err(|_| ConnectorError::HostOffline)?;
    state
        .clear_pending_outbound_frame(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
            sequence,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    Ok((frame, false))
}

fn publish_rejection_receipt(
    state: &RemoteMailboxState,
    relay: &HostRelayV2Client,
    vector: &FixedVector,
    host_keys: &EndpointKeys,
    command: &CommandPayload,
) -> Result<(RelayOpaqueFrame, bool), ConnectorError> {
    if let Some(frame) = flush_pending_outbound_if_any(state, relay, vector)? {
        return Ok((frame, true));
    }
    let sequence = state
        .reserve_outbound_sequence(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    let now = OffsetDateTime::now_utc();
    let message_id = message_id_for(sequence, MESSAGE_ID_SCOPE_RECEIPT);
    let envelope = build_rejection_receipt_envelope(vector, sequence, &message_id, now, command)?;
    let plaintext = canonical_encode_application_envelope(&envelope)?;
    let frame = encrypt_application_bytes(
        vector,
        host_keys,
        Direction::HostToDevice,
        sequence,
        &message_id,
        now,
        &plaintext,
    )?;
    let canonical_frame_bytes = serde_json::to_vec(&frame)?;
    state
        .store_pending_outbound_frame(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
            sequence,
            &canonical_frame_bytes,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    relay
        .publish_frame(&canonical_frame_bytes)
        .map_err(|_| ConnectorError::HostOffline)?;
    state
        .clear_pending_outbound_frame(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
            sequence,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    Ok((frame, false))
}

fn flush_pending_outbound_if_any(
    state: &RemoteMailboxState,
    relay: &HostRelayV2Client,
    vector: &FixedVector,
) -> Result<Option<RelayOpaqueFrame>, ConnectorError> {
    let pending = state
        .pending_outbound_frame(
            &vector.mailbox_id,
            RemoteDirection::HostToDevice,
            vector.epoch,
        )
        .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
    match pending {
        Some(PendingOutboundFrame {
            sequence,
            inbound_sequence: _,
            canonical_frame_bytes,
        }) => {
            let frame: RelayOpaqueFrame =
                serde_json::from_slice(&canonical_frame_bytes).map_err(|_| {
                    ConnectorError::ProtocolMismatch("remote v2 helper frame invalid".into())
                })?;
            relay
                .publish_frame(&canonical_frame_bytes)
                .map_err(|_| ConnectorError::HostOffline)?;
            state
                .clear_pending_outbound_frame(
                    &vector.mailbox_id,
                    RemoteDirection::HostToDevice,
                    vector.epoch,
                    sequence,
                )
                .map_err(|_| ConnectorError::Other("remote v2 helper state unavailable".into()))?;
            Ok(Some(frame))
        }
        None => Ok(None),
    }
}

fn build_projection_envelope(
    vector: &FixedVector,
    sequence: u64,
    message_id: &str,
    now: OffsetDateTime,
) -> Result<ApplicationEnvelope, ConnectorError> {
    let snapshot = ProductSnapshot {
        session_alias: SESSION_ALIAS.into(),
        updated_at: format_millisecond_utc(now)?,
        turn_state: SnapshotTurnState::Running,
        pending_input_alias: None,
        pending_permission_alias: None,
        diff_file_count: 0,
        writable: false,
        evidence_class: EVIDENCE_CLASS.into(),
    };
    let mut snapshot_envelope = ProductSnapshotEnvelope {
        schema: SNAPSHOT_SCHEMA.into(),
        host_instance_id: HOST_INSTANCE_ID.into(),
        snapshot_seq: sequence,
        digest: String::new(),
        snapshot,
    };
    snapshot_envelope.digest = snapshot_digest(&snapshot_envelope)?;
    let issued_at = format_whole_second_utc(now)?;
    let expires_at = format_whole_second_utc(now + time::Duration::seconds(30))?;
    let capability = CommandCapability {
        schema: "nomad.product-host.command-capability.v1".into(),
        capability_id: format!("capability_{sequence:016x}"),
        snapshot_seq: snapshot_envelope.snapshot_seq,
        snapshot_digest: snapshot_envelope.digest.clone(),
        next_command_seq: 1,
        issued_at,
        expires_at,
        view: true,
        reply: None,
        deny: None,
        stop: Some(StopCapability {
            turn_alias: TURN_ALIAS.into(),
        }),
        allow_once: false,
    };
    Ok(ApplicationEnvelope {
        common: EnvelopeCommon {
            schema: APPLICATION_SCHEMA.into(),
            kind: EnvelopeKind::Projection,
            mailbox_id: vector.mailbox_id.clone(),
            direction: FrameDirection::HostToDevice,
            epoch: vector.epoch,
            sequence,
            message_id: message_id.into(),
        },
        payload: ApplicationPayload::Projection(Box::new(ProjectionPayload {
            snapshot: snapshot_envelope,
            capability: Some(capability),
        })),
    })
}

fn build_rejection_receipt_envelope(
    vector: &FixedVector,
    sequence: u64,
    message_id: &str,
    now: OffsetDateTime,
    command: &CommandPayload,
) -> Result<ApplicationEnvelope, ConnectorError> {
    let receipt = CommandReceipt {
        schema: RECEIPT_BODY_SCHEMA.into(),
        receipt_id: receipt_id_for(sequence),
        request_id: request_id_from_command(command).into(),
        action: receipt_action_from_command(command),
        snapshot_seq: expected_snapshot_seq_from_command(command),
        snapshot_digest: expected_snapshot_digest_from_command(command).into(),
        accepted_at: format_whole_second_utc(now)?,
        status: ReceiptStatus::Rejected,
        error_code: ReceiptErrorCode(ERR_SAFETY_BLOCKED.into()),
        idempotent_replay: false,
    };
    Ok(ApplicationEnvelope {
        common: EnvelopeCommon {
            schema: APPLICATION_SCHEMA.into(),
            kind: EnvelopeKind::Receipt,
            mailbox_id: vector.mailbox_id.clone(),
            direction: FrameDirection::HostToDevice,
            epoch: vector.epoch,
            sequence,
            message_id: message_id.into(),
        },
        payload: ApplicationPayload::Receipt(ReceiptPayload { receipt }),
    })
}

fn encrypt_application_bytes(
    vector: &FixedVector,
    host_keys: &EndpointKeys,
    direction: Direction,
    sequence: u64,
    message_id: &str,
    now: OffsetDateTime,
    plaintext: &[u8],
) -> Result<RelayOpaqueFrame, ConnectorError> {
    let issued_at = now.unix_timestamp();
    let expires_at = issued_at + 600;
    let plaintext_value: Value = serde_json::from_slice(plaintext).map_err(|_| {
        ConnectorError::ProtocolMismatch("remote v2 helper application payload invalid".into())
    })?;
    let padding = padding_for_plaintext(plaintext.len())?;
    let frame = encrypt(
        FrameMetadata {
            schema: FRAME_SCHEMA.into(),
            crypto_suite: CRYPTO_SUITE.into(),
            mailbox_id: vector.mailbox_id.clone(),
            direction,
            epoch: vector.epoch,
            sequence,
            message_id: message_id.into(),
            issued_at,
            expires_at,
            nonce: String::new(),
        },
        &plaintext_value,
        host_keys,
        &vector.device_agreement_public,
        &vector.context,
        &padding,
    )
    .map_err(|_| ConnectorError::ProtocolMismatch("remote v2 helper encryption failed".into()))?;
    Ok(RelayOpaqueFrame {
        schema: frame.schema,
        crypto_suite: frame.crypto_suite,
        mailbox_id: frame.mailbox_id,
        direction: RemoteDirection::HostToDevice,
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id,
        issued_at: frame.issued_at,
        expires_at: frame.expires_at,
        nonce: frame.nonce,
        ciphertext: frame.ciphertext,
    })
}

fn relay_frame_to_crypto(frame: &RelayOpaqueFrame) -> OpaqueFrame {
    OpaqueFrame {
        schema: frame.schema.clone(),
        crypto_suite: frame.crypto_suite.clone(),
        mailbox_id: frame.mailbox_id.clone(),
        direction: match frame.direction {
            RemoteDirection::HostToDevice => Direction::HostToDevice,
            RemoteDirection::DeviceToHost => Direction::DeviceToHost,
        },
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id.clone(),
        issued_at: frame.issued_at,
        expires_at: frame.expires_at,
        nonce: frame.nonce.clone(),
        ciphertext: frame.ciphertext.clone(),
    }
}

fn frame_binding_from_relay(frame: &RelayOpaqueFrame) -> FrameBinding {
    FrameBinding {
        schema: frame.schema.clone(),
        crypto_suite: frame.crypto_suite.clone(),
        mailbox_id: frame.mailbox_id.clone(),
        direction: match frame.direction {
            RemoteDirection::HostToDevice => FrameDirection::HostToDevice,
            RemoteDirection::DeviceToHost => FrameDirection::DeviceToHost,
        },
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id.clone(),
    }
}

fn request_id_from_command(command: &CommandPayload) -> &str {
    match &command.command {
        crate::remote_application::GatewayCommand::Reply(value) => &value.request_id,
        crate::remote_application::GatewayCommand::Deny(value) => &value.request_id,
        crate::remote_application::GatewayCommand::Stop(value) => &value.request_id,
    }
}

fn expected_snapshot_seq_from_command(command: &CommandPayload) -> u64 {
    match &command.command {
        crate::remote_application::GatewayCommand::Reply(value) => value.expected_snapshot_seq,
        crate::remote_application::GatewayCommand::Deny(value) => value.expected_snapshot_seq,
        crate::remote_application::GatewayCommand::Stop(value) => value.expected_snapshot_seq,
    }
}

fn expected_snapshot_digest_from_command(command: &CommandPayload) -> &str {
    match &command.command {
        crate::remote_application::GatewayCommand::Reply(value) => &value.expected_snapshot_digest,
        crate::remote_application::GatewayCommand::Deny(value) => &value.expected_snapshot_digest,
        crate::remote_application::GatewayCommand::Stop(value) => &value.expected_snapshot_digest,
    }
}

fn receipt_action_from_command(command: &CommandPayload) -> ReceiptAction {
    match &command.command {
        crate::remote_application::GatewayCommand::Reply(_) => ReceiptAction::Reply,
        crate::remote_application::GatewayCommand::Deny(_) => ReceiptAction::Deny,
        crate::remote_application::GatewayCommand::Stop(_) => ReceiptAction::Stop,
    }
}

fn message_id_for(sequence: u64, scope: &str) -> String {
    let digest = Sha256::digest(format!("{scope}:{sequence}").as_bytes());
    format!("msg-{}", hex_lower(&digest[..16]))
}

fn receipt_id_for(sequence: u64) -> String {
    let digest = Sha256::digest(format!("receipt:{sequence}").as_bytes());
    format!("receipt_{}", hex_lower(&digest[..16]))
}

fn snapshot_digest(snapshot: &ProductSnapshotEnvelope) -> Result<String, ConnectorError> {
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
    map.insert(
        "snapshot".into(),
        snapshot_payload_value(&snapshot.snapshot),
    );
    let canonical =
        canonical_json_value(&Value::Object(map)).map_err(|_| ConnectorError::DigestMismatch)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
}

fn snapshot_payload_value(snapshot: &ProductSnapshot) -> Value {
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
                SnapshotTurnState::NeedsInput => "NeedsInput",
                SnapshotTurnState::NeedsPermission => "NeedsPermission",
                SnapshotTurnState::Completed => "Completed",
                SnapshotTurnState::OutcomeUnknown => "OutcomeUnknown",
            }
            .into(),
        ),
    );
    map.insert(
        "pending_input_alias".into(),
        match &snapshot.pending_input_alias {
            Some(value) => Value::String(value.clone()),
            None => Value::Null,
        },
    );
    map.insert(
        "pending_permission_alias".into(),
        match &snapshot.pending_permission_alias {
            Some(value) => Value::String(value.clone()),
            None => Value::Null,
        },
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

fn padding_for_plaintext(plaintext_len: usize) -> Result<Vec<u8>, ConnectorError> {
    let bucket = BUCKETS
        .into_iter()
        .find(|size| *size >= plaintext_len + 4)
        .ok_or_else(|| {
            ConnectorError::ProtocolMismatch("remote v2 helper plaintext too large".into())
        })?;
    Ok(vec![0_u8; bucket - plaintext_len - 4])
}

fn canonical_json_value(value: &Value) -> Result<String, ()> {
    fn write(value: &Value, out: &mut String) -> Result<(), ()> {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => out.push_str(&value.to_string()),
            Value::String(value) => out.push_str(&serde_json::to_string(value).map_err(|_| ())?),
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
                    out.push_str(&serde_json::to_string(key).map_err(|_| ())?);
                    out.push(':');
                    write(values.get(*key).ok_or(())?, out)?;
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

fn format_whole_second_utc(value: OffsetDateTime) -> Result<String, ConnectorError> {
    let format = parse_borrowed::<3>("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
        .map_err(|_| ConnectorError::Other("remote v2 helper time format invalid".into()))?;
    value
        .replace_nanosecond(0)
        .map_err(|_| ConnectorError::Other("remote v2 helper time format invalid".into()))?
        .format(&format)
        .map_err(|_| ConnectorError::Other("remote v2 helper time format invalid".into()))
}

fn format_millisecond_utc(value: OffsetDateTime) -> Result<String, ConnectorError> {
    let format =
        parse_borrowed::<3>("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z")
            .map_err(|_| ConnectorError::Other("remote v2 helper time format invalid".into()))?;
    value
        .replace_nanosecond((value.nanosecond() / 1_000_000) * 1_000_000)
        .map_err(|_| ConnectorError::Other("remote v2 helper time format invalid".into()))?
        .format(&format)
        .map_err(|_| ConnectorError::Other("remote v2 helper time format invalid".into()))
}

fn load_fixed_vector() -> Result<(FixedVector, VectorContract), ConnectorError> {
    let contract: VectorContract = serde_json::from_str(include_str!(
        "../../contracts/vectors/remote-envelope-v2.json"
    ))
    .map_err(|_| ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into()))?;
    if contract.marker != "TEST_ONLY_VECTOR" {
        return Err(ConnectorError::ProtocolMismatch(
            "remote v2 helper marker mismatch".into(),
        ));
    }
    let host_keys = EndpointKeys::from_pkcs8_base64(
        &contract.host_signing_private_key_pkcs8,
        &contract.host_agreement_private_key_pkcs8,
    )
    .map_err(|_| ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into()))?;
    let device_keys = EndpointKeys::from_pkcs8_base64(
        &contract.device_signing_private_key_pkcs8,
        &contract.device_agreement_private_key_pkcs8,
    )
    .map_err(|_| ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into()))?;
    let host_signing_commitment = commitment(&host_keys.signing_public()).map_err(|_| {
        ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into())
    })?;
    let host_agreement_commitment = commitment(&host_keys.agreement_public()).map_err(|_| {
        ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into())
    })?;
    let device_signing_commitment = commitment(&device_keys.signing_public()).map_err(|_| {
        ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into())
    })?;
    let device_agreement_commitment =
        commitment(&device_keys.agreement_public()).map_err(|_| {
            ConnectorError::ProtocolMismatch("remote v2 helper test vector invalid".into())
        })?;
    if hex_lower(&host_signing_commitment) != contract.host_signing_commitment
        || hex_lower(&host_agreement_commitment) != contract.host_agreement_commitment
        || hex_lower(&device_signing_commitment) != contract.device_signing_commitment
        || hex_lower(&device_agreement_commitment) != contract.device_agreement_commitment
    {
        return Err(ConnectorError::ProtocolMismatch(
            "remote v2 helper commitment mismatch".into(),
        ));
    }
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(host_keys.signing_public())
        != contract.host_signing_public_key_sec1
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(host_keys.agreement_public())
            != contract.host_agreement_public_key_sec1
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_keys.signing_public())
            != contract.device_signing_public_key_sec1
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_keys.agreement_public())
            != contract.device_agreement_public_key_sec1
    {
        return Err(ConnectorError::ProtocolMismatch(
            "remote v2 helper public key mismatch".into(),
        ));
    }
    let context = SharedContext {
        mailbox_id: contract.frame.mailbox_id.clone(),
        epoch: contract.frame.epoch,
        host_signing_commitment,
        host_agreement_commitment,
        device_signing_commitment,
        device_agreement_commitment,
    };
    Ok((
        FixedVector {
            mailbox_id: contract.frame.mailbox_id.clone(),
            epoch: contract.frame.epoch,
            context,
            device_agreement_public: device_keys.agreement_public(),
        },
        contract,
    ))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn parser_accepts_exact_cli() {
        let config = parse_args_from([
            "--phase",
            "publish-projection",
            "--relay-url",
            "http://127.0.0.1:8080",
            "--state",
            "/tmp/remote-v2.db",
        ])
        .unwrap();
        assert_eq!(config.phase, MechanicalPhase::PublishProjection);
        assert_eq!(config.relay_url, "http://127.0.0.1:8080");
        assert_eq!(config.state_path, PathBuf::from("/tmp/remote-v2.db"));
    }

    #[test]
    fn parser_rejects_unknown_phase() {
        let error = parse_args_from([
            "--phase",
            "publish",
            "--relay-url",
            "http://127.0.0.1:8080",
            "--state",
            "/tmp/remote-v2.db",
        ])
        .unwrap_err();
        assert_eq!(error.error_code(), "ERR_INTERNAL");
        assert!(error.to_string().contains("requires --phase"));
    }

    #[test]
    fn parser_requires_all_flags() {
        let error = parse_args_from(["--phase", "revoke", "--relay-url", "https://relay.example"])
            .unwrap_err();
        assert!(error.to_string().contains("--state"));
    }

    #[test]
    fn take_host_token_removes_environment() {
        let _guard = env_lock();
        env::set_var(HOST_TOKEN_ENV, "top-secret-token");
        let token = take_host_token().unwrap();
        assert_eq!(token, "top-secret-token");
        assert!(env::var(HOST_TOKEN_ENV).is_err());
    }

    #[test]
    fn load_fixed_vector_verifies_contract() {
        let (vector, _) = load_fixed_vector().unwrap();
        assert_eq!(
            vector.mailbox_id,
            "mbx-abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(vector.epoch, 3);
    }

    #[test]
    fn missing_host_token_is_rejected() {
        let _guard = env_lock();
        env::remove_var(HOST_TOKEN_ENV);
        let error = take_host_token().unwrap_err();
        assert_eq!(error.error_code(), "ERR_INTERNAL");
        assert!(error.to_string().contains(HOST_TOKEN_ENV));
    }
}
