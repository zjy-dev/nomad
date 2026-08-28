//! Strict authenticated command HTTP for the private Product Host UDS.

use crate::adapters::opencode::{OpenCodeCommandCapability, OpenCodeSafeCommand};
use crate::device_authority::{
    AuthenticatedDeviceFact, CurrentActiveDevice, PairingChallenge, RevokeOutcome,
};
use crate::error::ConnectorError;
use crate::host_command_authority::{HostCommand, HostCommandReceipt, ResolvedHostCommandRequest};
use crate::pairing_coordinator::{
    ActiveRemoteBinding, CreatedJoin, PairingCoordinatorError, PairingStatusResponse,
    SignedProvisioningBundle, StartedJoin,
};
use crate::remote_application::GatewayCommand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const CAPABILITY_PATH: &str = "/internal/commands/capability";
pub(crate) const COMMAND_PATH: &str = "/internal/commands";
pub(crate) const DEVICE_CURRENT_PATH: &str = "/internal/devices/current";
pub(crate) const DEVICE_CHALLENGE_PATH: &str = "/internal/devices/pairing/challenge";
pub(crate) const DEVICE_CONFIRM_PATH: &str = "/internal/devices/pairing/confirm";
pub(crate) const DEVICE_REVOKE_PATH: &str = "/internal/devices/revoke";
pub(crate) const PAIRING_CREATE_PATH: &str = "/internal/pairing/joins";
pub(crate) const PAIRING_APPROVE_PATH: &str = "/internal/pairing/joins/approve";
pub(crate) const PAIRING_CANCEL_PATH: &str = "/internal/pairing/joins/cancel";
pub(crate) const PAIRING_STATUS_PATH: &str = "/internal/pairing/joins/status";
pub(crate) const PAIRING_START_PATH: &str = "/internal/pairing/join/start";
pub(crate) const PAIRING_CONFIRM_PATH: &str = "/internal/pairing/join/confirm";
pub(crate) const PAIRING_COMPLETE_PATH: &str = "/internal/pairing/join/complete";
pub(crate) const PAIRING_ABORT_PATH: &str = "/internal/pairing/join/abort";
const MAX_HEAD: usize = 8 * 1024;
const MAX_COMMAND: usize = 16 * 1024;
const MAX_ADMIN_BODY: usize = 4 * 1024;
const MAX_NONCES: usize = 4096;
const AUTH_WINDOW_SECONDS: i64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandProtocolError {
    InvalidRequest,
    Unauthorized,
    Unavailable,
    Stale,
    Expired,
    OutcomeUnknown,
    Internal,
}

impl From<PairingCoordinatorError> for CommandProtocolError {
    fn from(error: PairingCoordinatorError) -> Self {
        match error {
            PairingCoordinatorError::Invalid | PairingCoordinatorError::InvalidProof => {
                Self::InvalidRequest
            }
            PairingCoordinatorError::NotFound
            | PairingCoordinatorError::Expired
            | PairingCoordinatorError::Consumed
            | PairingCoordinatorError::DesktopApprovalRequired
            | PairingCoordinatorError::Conflict => Self::Stale,
            PairingCoordinatorError::Relay
            | PairingCoordinatorError::Storage
            | PairingCoordinatorError::Crypto => Self::Unavailable,
        }
    }
}

pub(crate) enum ProductHostRequest {
    ReadCurrent,
    ReadStream(u64),
    CommandCapability,
    Command(Box<ParsedProductCommand>),
    DeviceCurrent,
    DevicePairingChallenge(Box<ParsedPairingChallengeRequest>),
    DevicePairingConfirm(Box<ParsedPairingConfirmRequest>),
    DeviceRevoke(Box<ParsedDeviceRevokeRequest>),
    PairingCreate,
    PairingApprove(Box<ParsedPairingApproveRequest>),
    PairingCancel(Box<ParsedPairingCancelRequest>),
    PairingStatus(Box<ParsedPairingStatusRequest>),
    PairingStart(Box<ParsedPairingStartRequest>),
    PairingConfirm(Box<ParsedM3ePairingConfirmRequest>),
    PairingComplete(Box<ParsedPairingCompleteRequest>),
    PairingAbort(Box<ParsedPairingAbortRequest>),
}

#[derive(Clone)]
pub(crate) struct ParsedPairingApproveRequest {
    pub(crate) join_id: String,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
    pub(crate) comparison_code: String,
}

#[derive(Clone)]
pub(crate) struct ParsedPairingCancelRequest {
    pub(crate) join_id: String,
}

#[derive(Clone)]
pub(crate) struct ParsedPairingStatusRequest {
    pub(crate) join_id: String,
}

#[derive(Clone)]
pub(crate) struct ParsedPairingStartRequest {
    pub(crate) join_id: String,
    pub(crate) join_secret: Zeroizing<String>,
    pub(crate) device_signing_public_key_sec1: [u8; 65],
    pub(crate) device_agreement_public_key_sec1: [u8; 65],
}

impl std::fmt::Debug for ParsedPairingStartRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedPairingStartRequest")
            .field("join_id", &self.join_id)
            .field("join_secret", &"<redacted>")
            .field("device_keys", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ParsedM3ePairingConfirmRequest {
    pub(crate) join_cookie_capability: Zeroizing<String>,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
    pub(crate) device_signing_signature_p1363: [u8; 64],
    pub(crate) device_agreement_mac: [u8; 32],
}

impl std::fmt::Debug for ParsedM3ePairingConfirmRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedM3ePairingConfirmRequest")
            .field("join_cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("expected_epoch", &self.expected_epoch)
            .field("proofs", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ParsedPairingCompleteRequest {
    pub(crate) join_cookie_capability: Zeroizing<String>,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
    pub(crate) device_vault_signature_p1363: [u8; 64],
}

impl std::fmt::Debug for ParsedPairingCompleteRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedPairingCompleteRequest")
            .field("join_cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("expected_epoch", &self.expected_epoch)
            .field("device_vault_signature_p1363", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ParsedPairingAbortRequest {
    pub(crate) join_cookie_capability: Zeroizing<String>,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
}

impl std::fmt::Debug for ParsedPairingAbortRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedPairingAbortRequest")
            .field("join_cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("expected_epoch", &self.expected_epoch)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ParsedProductCommand {
    common: Common,
    command: ParsedAction,
}

#[derive(Clone)]
pub(crate) struct ParsedPairingChallengeRequest {
    signing_public_key: [u8; 65],
    agreement_public_key: [u8; 65],
}

impl ParsedPairingChallengeRequest {
    pub(crate) fn signing_public_key(&self) -> &[u8; 65] {
        &self.signing_public_key
    }

    pub(crate) fn agreement_public_key(&self) -> &[u8; 65] {
        &self.agreement_public_key
    }
}

#[derive(Clone)]
pub(crate) struct ParsedPairingConfirmRequest {
    challenge_id: String,
    challenge: Vec<u8>,
    signature: Vec<u8>,
}

impl ParsedPairingConfirmRequest {
    pub(crate) fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub(crate) fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    pub(crate) fn signature(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Clone)]
pub(crate) struct ParsedDeviceRevokeRequest {
    device_alias: String,
    expected_epoch: u64,
}

impl ParsedDeviceRevokeRequest {
    pub(crate) fn device_alias(&self) -> &str {
        &self.device_alias
    }

    pub(crate) fn expected_epoch(&self) -> u64 {
        self.expected_epoch
    }
}

#[derive(Clone)]
enum ParsedAction {
    Reply {
        turn_alias: String,
        input_alias: String,
        content: String,
    },
    Deny {
        permission_alias: String,
        action_hash: String,
        permission_expires_at: String,
    },
    Stop {
        turn_alias: String,
    },
}

impl TryFrom<GatewayCommand> for ParsedProductCommand {
    type Error = CommandProtocolError;

    fn try_from(command: GatewayCommand) -> Result<Self, Self::Error> {
        let (mut common, command) = match command {
            GatewayCommand::Reply(value) => {
                let common = Common {
                    schema: "nomad.gateway.command.v1".into(),
                    capability_id: value.capability_id,
                    request_id: value.request_id,
                    nonce: value.nonce,
                    command_seq: value.command_seq,
                    expected_snapshot_seq: value.expected_snapshot_seq,
                    expected_snapshot_digest: value.expected_snapshot_digest,
                    issued_at: value.issued_at,
                    expires_at: value.expires_at,
                };
                (
                    common,
                    ParsedAction::Reply {
                        turn_alias: value.turn_alias,
                        input_alias: value.input_alias,
                        content: value.content,
                    },
                )
            }
            GatewayCommand::Deny(value) => {
                let permission_expires_at = whole_second_utc(&value.permission_expires_at)?;
                let common = Common {
                    schema: "nomad.gateway.command.v1".into(),
                    capability_id: value.capability_id,
                    request_id: value.request_id,
                    nonce: value.nonce,
                    command_seq: value.command_seq,
                    expected_snapshot_seq: value.expected_snapshot_seq,
                    expected_snapshot_digest: value.expected_snapshot_digest,
                    issued_at: value.issued_at,
                    expires_at: value.expires_at,
                };
                (
                    common,
                    ParsedAction::Deny {
                        permission_alias: value.permission_alias,
                        action_hash: value.action_hash,
                        permission_expires_at,
                    },
                )
            }
            GatewayCommand::Stop(value) => {
                let common = Common {
                    schema: "nomad.gateway.command.v1".into(),
                    capability_id: value.capability_id,
                    request_id: value.request_id,
                    nonce: value.nonce,
                    command_seq: value.command_seq,
                    expected_snapshot_seq: value.expected_snapshot_seq,
                    expected_snapshot_digest: value.expected_snapshot_digest,
                    issued_at: value.issued_at,
                    expires_at: value.expires_at,
                };
                (
                    common,
                    ParsedAction::Stop {
                        turn_alias: value.turn_alias,
                    },
                )
            }
        };
        common.issued_at = whole_second_utc(&common.issued_at)?;
        common.expires_at = whole_second_utc(&common.expires_at)?;
        let parsed = Self { common, command };
        // Reuse the Host authority constructor as the final structural check.
        parsed.clone().into_resolved()?;
        Ok(parsed)
    }
}

impl ParsedProductCommand {
    pub(crate) fn capability_id(&self) -> &str {
        &self.common.capability_id
    }
    pub(crate) fn request_id(&self) -> &str {
        &self.common.request_id
    }
    pub(crate) fn command_seq(&self) -> u64 {
        self.common.command_seq
    }
    pub(crate) fn snapshot_seq(&self) -> u64 {
        self.common.expected_snapshot_seq
    }
    pub(crate) fn snapshot_digest(&self) -> &str {
        &self.common.expected_snapshot_digest
    }
    pub(crate) fn expires_at(&self) -> &str {
        &self.common.expires_at
    }
    pub(crate) fn issued_at(&self) -> &str {
        &self.common.issued_at
    }
    pub(crate) fn safe_command(&self) -> OpenCodeSafeCommand {
        match &self.command {
            ParsedAction::Reply {
                turn_alias,
                input_alias,
                content,
            } => OpenCodeSafeCommand::Reply {
                turn_alias: turn_alias.clone(),
                input_alias: input_alias.clone(),
                content: Zeroizing::new(content.clone()),
            },
            ParsedAction::Deny {
                permission_alias,
                action_hash,
                permission_expires_at,
            } => OpenCodeSafeCommand::Deny {
                permission_alias: permission_alias.clone(),
                action_hash: action_hash.clone(),
                permission_expires_at: permission_expires_at.clone(),
            },
            ParsedAction::Stop { turn_alias } => OpenCodeSafeCommand::Stop {
                turn_alias: turn_alias.clone(),
            },
        }
    }
    pub(crate) fn into_resolved(self) -> Result<ResolvedHostCommandRequest, CommandProtocolError> {
        let command = match self.command {
            ParsedAction::Reply {
                turn_alias,
                input_alias,
                content,
            } => HostCommand::reply(turn_alias, input_alias, content),
            ParsedAction::Deny {
                permission_alias,
                action_hash,
                permission_expires_at,
            } => HostCommand::deny(permission_alias, action_hash, permission_expires_at),
            ParsedAction::Stop { turn_alias } => HostCommand::stop(turn_alias),
        }
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
        ResolvedHostCommandRequest::new(
            self.common.capability_id,
            self.common.request_id,
            self.common.nonce,
            self.common.command_seq,
            self.common.expected_snapshot_seq,
            self.common.expected_snapshot_digest,
            self.common.issued_at,
            self.common.expires_at,
            command,
        )
        .map_err(|_| CommandProtocolError::InvalidRequest)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reply_for_test(
        capability_id: String,
        request_id: String,
        nonce: String,
        command_seq: u64,
        snapshot_seq: u64,
        snapshot_digest: String,
        issued_at: String,
        expires_at: String,
        turn_alias: String,
        input_alias: String,
        content: String,
    ) -> Self {
        Self {
            common: Common {
                schema: "nomad.gateway.command.v1".into(),
                capability_id,
                request_id,
                nonce,
                command_seq,
                expected_snapshot_seq: snapshot_seq,
                expected_snapshot_digest: snapshot_digest,
                issued_at,
                expires_at,
            },
            command: ParsedAction::Reply {
                turn_alias,
                input_alias,
                content,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn replace_snapshot_digest_for_test(&mut self, digest: String) {
        self.common.expected_snapshot_digest = digest;
    }
}

pub(crate) struct CommandTransportAuthenticator {
    key: Zeroizing<[u8; 32]>,
    nonces: Mutex<NonceCache>,
}

impl std::fmt::Debug for CommandTransportAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommandTransportAuthenticator(<redacted>)")
    }
}

struct NonceCache {
    set: HashSet<String>,
    order: VecDeque<(i64, String)>,
}

impl CommandTransportAuthenticator {
    pub(crate) fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            key,
            nonces: Mutex::new(NonceCache {
                set: HashSet::new(),
                order: VecDeque::new(),
            }),
        }
    }

    fn verify(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        time: &str,
        nonce: &str,
        mac: &str,
    ) -> Result<(), CommandProtocolError> {
        let timestamp = time
            .parse::<i64>()
            .ok()
            .filter(|value| value.to_string() == time)
            .ok_or(CommandProtocolError::Unauthorized)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CommandProtocolError::Unauthorized)?
            .as_secs() as i64;
        if now.abs_diff(timestamp) > AUTH_WINDOW_SECONDS as u64
            || nonce.len() != 32
            || !lower_hex(nonce)
            || mac.len() != 64
            || !lower_hex(mac)
        {
            return Err(CommandProtocolError::Unauthorized);
        }
        let body_digest = format!("{:x}", Sha256::digest(body));
        let mut material = Zeroizing::new(format!(
            "nomad.product-host.transport.v1\n{method}\n{path}\n{time}\n{nonce}\n{body_digest}"
        ));
        let mut expected = crate::run_binding::hmac_sha256(&*self.key, material.as_bytes());
        material.zeroize();
        let supplied = decode_hex(mac).ok_or(CommandProtocolError::Unauthorized)?;
        let valid = constant_time_equal(&expected, &supplied);
        expected.zeroize();
        if !valid {
            return Err(CommandProtocolError::Unauthorized);
        }
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?;
        let expired: Vec<String> = nonces
            .order
            .iter()
            .filter(|(expires_at, _)| *expires_at < now)
            .map(|(_, nonce)| nonce.clone())
            .collect();
        nonces.order.retain(|(expires_at, _)| *expires_at >= now);
        for nonce in expired {
            nonces.set.remove(&nonce);
        }
        if nonces.set.contains(nonce) || nonces.order.len() >= MAX_NONCES {
            return Err(CommandProtocolError::Unauthorized);
        }
        nonces.set.insert(nonce.to_string());
        nonces.order.push_back((
            timestamp.saturating_add(AUTH_WINDOW_SECONDS),
            nonce.to_string(),
        ));
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
enum WireCommand {
    Reply {
        schema: String,
        capability_id: String,
        request_id: String,
        nonce: String,
        command_seq: u64,
        expected_snapshot_seq: u64,
        expected_snapshot_digest: String,
        issued_at: String,
        expires_at: String,
        turn_alias: String,
        input_alias: String,
        content: String,
    },
    Deny {
        schema: String,
        capability_id: String,
        request_id: String,
        nonce: String,
        command_seq: u64,
        expected_snapshot_seq: u64,
        expected_snapshot_digest: String,
        issued_at: String,
        expires_at: String,
        permission_alias: String,
        action_hash: String,
        permission_expires_at: String,
    },
    Stop {
        schema: String,
        capability_id: String,
        request_id: String,
        nonce: String,
        command_seq: u64,
        expected_snapshot_seq: u64,
        expected_snapshot_digest: String,
        issued_at: String,
        expires_at: String,
        turn_alias: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingChallengeRequest {
    signing_public_key: String,
    agreement_public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingConfirmRequest {
    challenge_id: String,
    challenge: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDeviceRevokeRequest {
    device_alias: String,
    expected_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingCreateRequest {
    schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingApproveRequest {
    schema: String,
    join_id: String,
    challenge_id: String,
    expected_epoch: u64,
    comparison_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingCancelRequest {
    schema: String,
    join_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingStatusRequest {
    schema: String,
    join_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingStartRequest {
    schema: String,
    join_id: String,
    join_secret: String,
    device_signing_public_key_sec1: String,
    device_agreement_public_key_sec1: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireM3ePairingConfirmRequest {
    schema: String,
    join_cookie_capability: String,
    challenge_id: String,
    expected_epoch: u64,
    device_signing_signature_p1363: String,
    device_agreement_mac: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingCompleteRequest {
    schema: String,
    join_cookie_capability: String,
    challenge_id: String,
    expected_epoch: u64,
    device_vault_signature_p1363: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePairingAbortRequest {
    schema: String,
    join_cookie_capability: String,
    challenge_id: String,
    expected_epoch: u64,
}

#[derive(Clone)]
struct Common {
    schema: String,
    capability_id: String,
    request_id: String,
    nonce: String,
    command_seq: u64,
    expected_snapshot_seq: u64,
    expected_snapshot_digest: String,
    issued_at: String,
    expires_at: String,
}

impl WireCommand {
    fn resolve(self) -> Result<ParsedProductCommand, CommandProtocolError> {
        let (mut common, command) = match self {
            Self::Reply {
                schema,
                capability_id,
                request_id,
                nonce,
                command_seq,
                expected_snapshot_seq,
                expected_snapshot_digest,
                issued_at,
                expires_at,
                turn_alias,
                input_alias,
                content,
            } => (
                Common {
                    schema,
                    capability_id,
                    request_id,
                    nonce,
                    command_seq,
                    expected_snapshot_seq,
                    expected_snapshot_digest,
                    issued_at,
                    expires_at,
                },
                ParsedAction::Reply {
                    turn_alias,
                    input_alias,
                    content,
                },
            ),
            Self::Deny {
                schema,
                capability_id,
                request_id,
                nonce,
                command_seq,
                expected_snapshot_seq,
                expected_snapshot_digest,
                issued_at,
                expires_at,
                permission_alias,
                action_hash,
                permission_expires_at,
            } => (
                Common {
                    schema,
                    capability_id,
                    request_id,
                    nonce,
                    command_seq,
                    expected_snapshot_seq,
                    expected_snapshot_digest,
                    issued_at,
                    expires_at,
                },
                ParsedAction::Deny {
                    permission_alias,
                    action_hash,
                    permission_expires_at,
                },
            ),
            Self::Stop {
                schema,
                capability_id,
                request_id,
                nonce,
                command_seq,
                expected_snapshot_seq,
                expected_snapshot_digest,
                issued_at,
                expires_at,
                turn_alias,
            } => (
                Common {
                    schema,
                    capability_id,
                    request_id,
                    nonce,
                    command_seq,
                    expected_snapshot_seq,
                    expected_snapshot_digest,
                    issued_at,
                    expires_at,
                },
                ParsedAction::Stop { turn_alias },
            ),
        };
        if common.schema != "nomad.gateway.command.v1" {
            return Err(CommandProtocolError::InvalidRequest);
        }
        common.issued_at = whole_second_utc(&common.issued_at)?;
        common.expires_at = whole_second_utc(&common.expires_at)?;
        Ok(ParsedProductCommand { common, command })
    }
}

pub(crate) fn read_product_request(
    stream: &mut UnixStream,
    desktop_auth: &CommandTransportAuthenticator,
    join_auth: Option<&CommandTransportAuthenticator>,
) -> Result<ProductHostRequest, CommandProtocolError> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while head.len() < MAX_HEAD {
        if stream
            .read(&mut byte)
            .map_err(|_| CommandProtocolError::InvalidRequest)?
            == 0
        {
            return Err(CommandProtocolError::InvalidRequest);
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !head.ends_with(b"\r\n\r\n")
        || head
            .iter()
            .any(|byte| !matches!(byte, b'\r' | b'\n' | b' '..=b'~'))
    {
        return Err(CommandProtocolError::InvalidRequest);
    }
    let text = std::str::from_utf8(&head).map_err(|_| CommandProtocolError::InvalidRequest)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(CommandProtocolError::InvalidRequest)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(CommandProtocolError::InvalidRequest)?;
    let path = parts.next().ok_or(CommandProtocolError::InvalidRequest)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(CommandProtocolError::InvalidRequest);
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(CommandProtocolError::InvalidRequest);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(CommandProtocolError::InvalidRequest)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(CommandProtocolError::InvalidRequest);
        }
        let name = name.to_ascii_lowercase();
        if headers.iter().any(|(existing, _)| existing == &name) {
            return Err(CommandProtocolError::InvalidRequest);
        }
        headers.push((name, value.trim_matches(' ').to_string()));
    }
    let get = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if get("host").is_none_or(str::is_empty)
        || get("connection").is_some_and(|value| !value.eq_ignore_ascii_case("close"))
        || get("accept").is_some_and(|value| value != "application/json" && value != "*/*")
        || get("authorization").is_some()
        || get("transfer-encoding").is_some()
    {
        return Err(CommandProtocolError::InvalidRequest);
    }
    let body_len = match (method, path) {
        ("GET", "/internal/session/current") => {
            if get("content-length").is_some() || get("content-type").is_some() {
                return Err(CommandProtocolError::InvalidRequest);
            }
            0
        }
        ("GET", path) if path.starts_with("/internal/session/stream?") => {
            let raw = path
                .strip_prefix("/internal/session/stream?after_snapshot_seq=")
                .ok_or(CommandProtocolError::InvalidRequest)?;
            if raw.is_empty()
                || !raw.bytes().all(|byte| byte.is_ascii_digit())
                || get("content-length").is_some()
                || get("content-type").is_some()
            {
                return Err(CommandProtocolError::InvalidRequest);
            }
            0
        }
        ("GET", CAPABILITY_PATH) => {
            if get("content-length").is_some() || get("content-type").is_some() {
                return Err(CommandProtocolError::InvalidRequest);
            }
            0
        }
        ("GET", DEVICE_CURRENT_PATH) => {
            if get("content-length").is_some() || get("content-type").is_some() {
                return Err(CommandProtocolError::InvalidRequest);
            }
            0
        }
        ("POST", COMMAND_PATH) => {
            if get("content-type") != Some("application/json") {
                return Err(CommandProtocolError::InvalidRequest);
            }
            let raw = get("content-length").ok_or(CommandProtocolError::InvalidRequest)?;
            raw.parse::<usize>()
                .ok()
                .filter(|length| length.to_string() == raw && *length > 0 && *length <= MAX_COMMAND)
                .ok_or(CommandProtocolError::InvalidRequest)?
        }
        (
            "POST",
            DEVICE_CHALLENGE_PATH
            | DEVICE_CONFIRM_PATH
            | DEVICE_REVOKE_PATH
            | PAIRING_CREATE_PATH
            | PAIRING_APPROVE_PATH
            | PAIRING_CANCEL_PATH
            | PAIRING_STATUS_PATH
            | PAIRING_START_PATH
            | PAIRING_CONFIRM_PATH
            | PAIRING_COMPLETE_PATH
            | PAIRING_ABORT_PATH,
        ) => {
            if get("content-type") != Some("application/json") {
                return Err(CommandProtocolError::InvalidRequest);
            }
            let raw = get("content-length").ok_or(CommandProtocolError::InvalidRequest)?;
            raw.parse::<usize>()
                .ok()
                .filter(|length| {
                    length.to_string() == raw && *length > 0 && *length <= MAX_ADMIN_BODY
                })
                .ok_or(CommandProtocolError::InvalidRequest)?
        }
        _ => return Err(CommandProtocolError::InvalidRequest),
    };
    if headers.iter().any(|(name, _)| {
        !matches!(
            name.as_str(),
            "host"
                | "connection"
                | "accept"
                | "content-type"
                | "content-length"
                | "x-nomad-transport-time"
                | "x-nomad-transport-nonce"
                | "x-nomad-transport-mac"
        )
    }) {
        return Err(CommandProtocolError::InvalidRequest);
    }
    let mut body = Zeroizing::new(vec![0_u8; body_len]);
    stream
        .read_exact(&mut body)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    stream
        .set_nonblocking(true)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => {}
        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        _ => return Err(CommandProtocolError::InvalidRequest),
    }
    stream
        .set_nonblocking(false)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    if method == "GET"
        && (path == "/internal/session/current"
            || path.starts_with("/internal/session/stream?after_snapshot_seq="))
    {
        if headers
            .iter()
            .any(|(name, _)| !matches!(name.as_str(), "host" | "connection" | "accept"))
        {
            return Err(CommandProtocolError::InvalidRequest);
        }
        if path == "/internal/session/current" {
            return Ok(ProductHostRequest::ReadCurrent);
        }
        let raw = path
            .strip_prefix("/internal/session/stream?after_snapshot_seq=")
            .ok_or(CommandProtocolError::InvalidRequest)?;
        return Ok(ProductHostRequest::ReadStream(
            raw.parse()
                .map_err(|_| CommandProtocolError::InvalidRequest)?,
        ));
    }
    let auth = if is_join_transport_path(path) {
        join_auth.ok_or(CommandProtocolError::Unauthorized)?
    } else {
        desktop_auth
    };
    auth.verify(
        method,
        path,
        &body,
        get("x-nomad-transport-time").ok_or(CommandProtocolError::Unauthorized)?,
        get("x-nomad-transport-nonce").ok_or(CommandProtocolError::Unauthorized)?,
        get("x-nomad-transport-mac").ok_or(CommandProtocolError::Unauthorized)?,
    )?;
    if method == "GET" {
        return match path {
            CAPABILITY_PATH => Ok(ProductHostRequest::CommandCapability),
            DEVICE_CURRENT_PATH => Ok(ProductHostRequest::DeviceCurrent),
            _ => Err(CommandProtocolError::InvalidRequest),
        };
    }
    let value = crate::stock_event_adapter::strict_json(&body)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    if is_m3e_pairing_path(path)
        && crate::alpha_projector::canonical_json(&value)
            .map_err(|_| CommandProtocolError::InvalidRequest)?
            .as_bytes()
            != body.as_slice()
    {
        return Err(CommandProtocolError::InvalidRequest);
    }
    match path {
        COMMAND_PATH => {
            let wire: WireCommand =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            Ok(ProductHostRequest::Command(Box::new(wire.resolve()?)))
        }
        DEVICE_CHALLENGE_PATH => {
            let wire: WirePairingChallengeRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            Ok(ProductHostRequest::DevicePairingChallenge(Box::new(
                resolve_pairing_challenge_request(wire)?,
            )))
        }
        DEVICE_CONFIRM_PATH => {
            let wire: WirePairingConfirmRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            Ok(ProductHostRequest::DevicePairingConfirm(Box::new(
                resolve_pairing_confirm_request(wire)?,
            )))
        }
        DEVICE_REVOKE_PATH => {
            let wire: WireDeviceRevokeRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            Ok(ProductHostRequest::DeviceRevoke(Box::new(
                resolve_device_revoke_request(wire)?,
            )))
        }
        PAIRING_CREATE_PATH => {
            let wire: WirePairingCreateRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.pairing.create.v1" {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingCreate)
        }
        PAIRING_APPROVE_PATH => {
            let wire: WirePairingApproveRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.pairing.desktop-approve.v1"
                || !join_id(&wire.join_id)
                || !challenge_id(&wire.challenge_id)
                || wire.expected_epoch == 0
                || !comparison_code(&wire.comparison_code)
            {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingApprove(Box::new(
                ParsedPairingApproveRequest {
                    join_id: wire.join_id,
                    challenge_id: wire.challenge_id,
                    expected_epoch: wire.expected_epoch,
                    comparison_code: wire.comparison_code,
                },
            )))
        }
        PAIRING_CANCEL_PATH => {
            let wire: WirePairingCancelRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.pairing.cancel.v1" || !join_id(&wire.join_id) {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingCancel(Box::new(
                ParsedPairingCancelRequest {
                    join_id: wire.join_id,
                },
            )))
        }
        PAIRING_STATUS_PATH => {
            let wire: WirePairingStatusRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.pairing.status.v1" || !join_id(&wire.join_id) {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingStatus(Box::new(
                ParsedPairingStatusRequest {
                    join_id: wire.join_id,
                },
            )))
        }
        PAIRING_START_PATH => {
            let wire: WirePairingStartRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            let signing = base64url_exact::<65>(&wire.device_signing_public_key_sec1)?;
            let agreement = base64url_exact::<65>(&wire.device_agreement_public_key_sec1)?;
            if wire.schema != "nomad.m3e.internal.pairing-start.v1"
                || !join_id(&wire.join_id)
                || base64url_exact::<32>(&wire.join_secret).is_err()
                || signing[0] != 4
                || agreement[0] != 4
                || signing == agreement
            {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingStart(Box::new(
                ParsedPairingStartRequest {
                    join_id: wire.join_id,
                    join_secret: Zeroizing::new(wire.join_secret),
                    device_signing_public_key_sec1: signing,
                    device_agreement_public_key_sec1: agreement,
                },
            )))
        }
        PAIRING_CONFIRM_PATH => {
            let wire: WireM3ePairingConfirmRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.internal.pairing-confirm.v1"
                || !challenge_id(&wire.challenge_id)
                || wire.expected_epoch == 0
            {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingConfirm(Box::new(
                ParsedM3ePairingConfirmRequest {
                    join_cookie_capability: Zeroizing::new(require_capability(
                        wire.join_cookie_capability,
                    )?),
                    challenge_id: wire.challenge_id,
                    expected_epoch: wire.expected_epoch,
                    device_signing_signature_p1363: base64url_exact(
                        &wire.device_signing_signature_p1363,
                    )?,
                    device_agreement_mac: base64url_exact(&wire.device_agreement_mac)?,
                },
            )))
        }
        PAIRING_COMPLETE_PATH => {
            let wire: WirePairingCompleteRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.internal.pairing-complete.v1"
                || !challenge_id(&wire.challenge_id)
                || wire.expected_epoch == 0
            {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingComplete(Box::new(
                ParsedPairingCompleteRequest {
                    join_cookie_capability: Zeroizing::new(require_capability(
                        wire.join_cookie_capability,
                    )?),
                    challenge_id: wire.challenge_id,
                    expected_epoch: wire.expected_epoch,
                    device_vault_signature_p1363: base64url_exact(
                        &wire.device_vault_signature_p1363,
                    )?,
                },
            )))
        }
        PAIRING_ABORT_PATH => {
            let wire: WirePairingAbortRequest =
                serde_json::from_value(value).map_err(|_| CommandProtocolError::InvalidRequest)?;
            if wire.schema != "nomad.m3e.internal.pairing-abort.v1"
                || !challenge_id(&wire.challenge_id)
                || wire.expected_epoch == 0
            {
                return Err(CommandProtocolError::InvalidRequest);
            }
            Ok(ProductHostRequest::PairingAbort(Box::new(
                ParsedPairingAbortRequest {
                    join_cookie_capability: Zeroizing::new(require_capability(
                        wire.join_cookie_capability,
                    )?),
                    challenge_id: wire.challenge_id,
                    expected_epoch: wire.expected_epoch,
                },
            )))
        }
        _ => Err(CommandProtocolError::InvalidRequest),
    }
}

fn is_m3e_pairing_path(path: &str) -> bool {
    matches!(
        path,
        PAIRING_CREATE_PATH
            | PAIRING_APPROVE_PATH
            | PAIRING_CANCEL_PATH
            | PAIRING_STATUS_PATH
            | PAIRING_START_PATH
            | PAIRING_CONFIRM_PATH
            | PAIRING_COMPLETE_PATH
            | PAIRING_ABORT_PATH
    )
}

fn is_join_transport_path(path: &str) -> bool {
    matches!(
        path,
        PAIRING_START_PATH | PAIRING_CONFIRM_PATH | PAIRING_COMPLETE_PATH | PAIRING_ABORT_PATH
    )
}

pub(crate) fn write_capability(
    stream: &mut UnixStream,
    capability: &OpenCodeCommandCapability,
) -> Result<(), CommandProtocolError> {
    write_json(stream, 200, capability)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireReceipt<'a> {
    schema: &'static str,
    receipt_id: &'a str,
    request_id: &'a str,
    action: &'a str,
    snapshot_seq: u64,
    snapshot_digest: &'a str,
    accepted_at: &'a str,
    status: &'a str,
    error_code: &'a str,
    idempotent_replay: bool,
}

pub(crate) fn write_receipt(
    stream: &mut UnixStream,
    receipt: &HostCommandReceipt,
    snapshot_seq: u64,
    snapshot_digest: &str,
) -> Result<(), CommandProtocolError> {
    write_json(
        stream,
        200,
        &WireReceipt {
            schema: "nomad.product-host.command-receipt.v1",
            receipt_id: &receipt.receipt_id,
            request_id: &receipt.request_id,
            action: &receipt.kind,
            snapshot_seq,
            snapshot_digest,
            accepted_at: &receipt.accepted_at,
            status: &receipt.status,
            error_code: receipt.error_code.as_deref().unwrap_or("OK"),
            idempotent_replay: receipt.idempotent_replay,
        },
    )
}

pub(crate) fn write_protocol_error(
    stream: &mut UnixStream,
    error: CommandProtocolError,
) -> Result<(), CommandProtocolError> {
    let (status, code) = match error {
        CommandProtocolError::InvalidRequest => (400, "INVALID_REQUEST"),
        CommandProtocolError::Unauthorized => (401, "UNAUTHORIZED"),
        CommandProtocolError::Stale => (409, "ERR_REQUEST_STALE"),
        CommandProtocolError::Expired => (409, "ERR_REQUEST_EXPIRED"),
        CommandProtocolError::OutcomeUnknown => (409, "ERR_OUTCOME_UNKNOWN"),
        CommandProtocolError::Unavailable => (503, "COMMAND_UNAVAILABLE"),
        CommandProtocolError::Internal => (503, "COMMAND_UNAVAILABLE"),
    };
    write_json(
        stream,
        status,
        &serde_json::json!({"schema":"nomad.product-host.error.v1","code":code}),
    )
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireDeviceCurrent<'a> {
    schema: &'static str,
    principal_alias: &'a str,
    paired: bool,
    device: Option<WireCurrentDevice<'a>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireCurrentDevice<'a> {
    device_alias: &'a str,
    pairing_epoch: u64,
}

pub(crate) fn write_device_current(
    stream: &mut UnixStream,
    principal_alias: &str,
    current: &CurrentActiveDevice,
) -> Result<(), CommandProtocolError> {
    let device = match current {
        CurrentActiveDevice::Unpaired => None,
        CurrentActiveDevice::Active(device) => Some(WireCurrentDevice {
            device_alias: &device.device_alias,
            pairing_epoch: device.pairing_epoch,
        }),
    };
    write_json(
        stream,
        200,
        &WireDeviceCurrent {
            schema: "nomad.product-host.device-current.v1",
            principal_alias,
            paired: device.is_some(),
            device,
        },
    )
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingChallenge<'a> {
    schema: &'static str,
    principal_alias: &'a str,
    challenge_id: &'a str,
    challenge: String,
    prospective_epoch: u64,
    issued_at: String,
    expires_at: String,
}

pub(crate) fn write_pairing_challenge(
    stream: &mut UnixStream,
    principal_alias: &str,
    challenge: &PairingChallenge,
) -> Result<(), CommandProtocolError> {
    write_json(
        stream,
        200,
        &WirePairingChallenge {
            schema: "nomad.product-host.device-pairing-challenge.v1",
            principal_alias,
            challenge_id: challenge.challenge_id(),
            challenge: base64_standard(challenge.challenge_bytes()),
            prospective_epoch: challenge.prospective_epoch(),
            issued_at: unix_to_rfc3339(challenge.issued_at_unix())?,
            expires_at: unix_to_rfc3339(challenge.expires_at_unix())?,
        },
    )
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WirePairingConfirm<'a> {
    schema: &'static str,
    principal_alias: &'a str,
    device_alias: &'a str,
    pairing_epoch: u64,
}

pub(crate) fn write_pairing_confirm(
    stream: &mut UnixStream,
    principal_alias: &str,
    fact: &AuthenticatedDeviceFact,
) -> Result<(), CommandProtocolError> {
    write_json(
        stream,
        200,
        &WirePairingConfirm {
            schema: "nomad.product-host.device-pairing-confirmed.v1",
            principal_alias,
            device_alias: &fact.device_alias,
            pairing_epoch: fact.pairing_epoch,
        },
    )
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireRevoke<'a> {
    schema: &'static str,
    principal_alias: &'a str,
    device_alias: &'a str,
    status: &'a str,
    prior_epoch: Option<u64>,
    revoked_epoch: u64,
}

pub(crate) fn write_revoke(
    stream: &mut UnixStream,
    principal_alias: &str,
    device_alias: &str,
    outcome: RevokeOutcome,
) -> Result<(), CommandProtocolError> {
    let (status, prior_epoch, revoked_epoch) = match outcome {
        RevokeOutcome::Revoked {
            prior_epoch,
            revoked_epoch,
        } => ("revoked", Some(prior_epoch), revoked_epoch),
        RevokeOutcome::AlreadyRevoked { revoked_epoch } => ("already_revoked", None, revoked_epoch),
    };
    write_json(
        stream,
        200,
        &WireRevoke {
            schema: "nomad.product-host.device-revoke.v1",
            principal_alias,
            device_alias,
            status,
            prior_epoch,
            revoked_epoch,
        },
    )
}

pub(crate) fn write_pairing_created(
    stream: &mut UnixStream,
    created: &CreatedJoin,
) -> Result<(), CommandProtocolError> {
    #[derive(Serialize)]
    struct Response<'a> {
        schema: &'static str,
        join_id: &'a str,
        join_secret: &'a str,
        expires_at: String,
    }
    write_json(
        stream,
        200,
        &Response {
            schema: "nomad.m3e.pairing.created.v1",
            join_id: &created.join_id,
            join_secret: created.join_secret.as_str(),
            expires_at: unix_to_rfc3339(created.expires_at_unix)?,
        },
    )
}

pub(crate) fn write_pairing_status(
    stream: &mut UnixStream,
    status: &PairingStatusResponse,
) -> Result<(), CommandProtocolError> {
    write_json(stream, 200, status)
}

pub(crate) fn write_pairing_started(
    stream: &mut UnixStream,
    started: &StartedJoin,
) -> Result<(), CommandProtocolError> {
    #[derive(Serialize)]
    struct BrowserStart<'a> {
        schema: &'static str,
        challenge_id: &'a str,
        challenge_bytes_b64: String,
        prospective_epoch: u64,
        host_signing_public_key_sec1: String,
        host_agreement_public_key_sec1: String,
        issued_at: String,
        expires_at: String,
    }
    #[derive(Serialize)]
    struct Response<'a> {
        schema: &'static str,
        join_cookie_capability: &'a str,
        join_cookie_max_age_seconds: i64,
        browser_start: BrowserStart<'a>,
    }
    let max_age = started
        .expires_at_unix
        .checked_sub(started.issued_at_unix)
        .filter(|value| (1..=120).contains(value))
        .ok_or(CommandProtocolError::Internal)?;
    write_json(
        stream,
        200,
        &Response {
            schema: "nomad.m3e.pairing.host-start.v1",
            join_cookie_capability: started.cookie_capability.as_str(),
            join_cookie_max_age_seconds: max_age,
            browser_start: BrowserStart {
                schema: "nomad.m3e.pairing.start-response.v1",
                challenge_id: &started.challenge_id,
                challenge_bytes_b64: base64url(&started.challenge_bytes),
                prospective_epoch: started.prospective_epoch,
                host_signing_public_key_sec1: base64url(&started.host_signing_public_sec1),
                host_agreement_public_key_sec1: base64url(&started.host_agreement_public_sec1),
                issued_at: unix_to_rfc3339(started.issued_at_unix)?,
                expires_at: unix_to_rfc3339(started.expires_at_unix)?,
            },
        },
    )
}

pub(crate) fn write_pairing_confirmed(
    stream: &mut UnixStream,
    bundle: &SignedProvisioningBundle,
) -> Result<(), CommandProtocolError> {
    #[derive(Serialize)]
    struct Response<'a> {
        schema: &'static str,
        signed_provisioning_bundle: &'a SignedProvisioningBundle,
    }
    write_json(
        stream,
        200,
        &Response {
            schema: "nomad.m3e.pairing.confirm-response.v1",
            signed_provisioning_bundle: bundle,
        },
    )
}

pub(crate) fn write_pairing_completed(
    stream: &mut UnixStream,
    binding: &ActiveRemoteBinding,
) -> Result<(), CommandProtocolError> {
    #[derive(Serialize)]
    struct Response<'a> {
        schema: &'static str,
        device_alias: &'a str,
        pairing_epoch: u64,
    }
    write_json(
        stream,
        200,
        &Response {
            schema: "nomad.m3e.pairing.complete-response.v1",
            device_alias: &binding.device_alias,
            pairing_epoch: binding.pairing_epoch,
        },
    )
}

pub(crate) fn write_no_content(stream: &mut UnixStream) -> Result<(), CommandProtocolError> {
    stream
        .write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        )
        .map_err(|_| CommandProtocolError::Internal)
}

pub(crate) fn write_pairing_error(
    stream: &mut UnixStream,
    error: PairingCoordinatorError,
) -> Result<(), CommandProtocolError> {
    let (status, code) = match error {
        PairingCoordinatorError::Invalid => (400, "PAIRING_INVALID"),
        PairingCoordinatorError::NotFound => (404, "PAIRING_NOT_FOUND"),
        PairingCoordinatorError::Expired => (409, "PAIRING_EXPIRED"),
        PairingCoordinatorError::Consumed => (409, "PAIRING_REPLAY"),
        PairingCoordinatorError::DesktopApprovalRequired => {
            (409, "PAIRING_DESKTOP_APPROVAL_REQUIRED")
        }
        PairingCoordinatorError::InvalidProof => (400, "PAIRING_PROOF_INVALID"),
        PairingCoordinatorError::Conflict => (409, "PAIRING_CONFLICT"),
        PairingCoordinatorError::Relay => (503, "PAIRING_RELAY_UNAVAILABLE"),
        PairingCoordinatorError::Storage => (503, "PAIRING_STORAGE"),
        PairingCoordinatorError::Crypto => (503, "PAIRING_CRYPTO"),
    };
    write_json(
        stream,
        status,
        &serde_json::json!({"schema":"nomad.product-host.error.v1","code":code}),
    )
}

pub(crate) fn map_connector_error(error: &ConnectorError) -> CommandProtocolError {
    match error {
        ConnectorError::StaleRequest(_) => CommandProtocolError::Stale,
        ConnectorError::ExpiredRequest(_) => CommandProtocolError::Expired,
        ConnectorError::OutcomeUnknown => CommandProtocolError::OutcomeUnknown,
        ConnectorError::HostOffline | ConnectorError::OpenCodeUnreachable(_) => {
            CommandProtocolError::Unavailable
        }
        _ => CommandProtocolError::Internal,
    }
}

fn write_json<T: Serialize>(
    stream: &mut UnixStream,
    status: u16,
    value: &T,
) -> Result<(), CommandProtocolError> {
    let body = serde_json::to_vec(value).map_err(|_| CommandProtocolError::Internal)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => return Err(CommandProtocolError::Internal),
    };
    let head = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .map_err(|_| CommandProtocolError::Internal)
}

fn whole_second_utc(value: &str) -> Result<String, CommandProtocolError> {
    let parsed =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| CommandProtocolError::InvalidRequest)?;
    if parsed.offset() != time::UtcOffset::UTC {
        return Err(CommandProtocolError::InvalidRequest);
    }
    let parsed = parsed
        .replace_nanosecond(0)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        parsed.year(),
        u8::from(parsed.month()),
        parsed.day(),
        parsed.hour(),
        parsed.minute(),
        parsed.second()
    ))
}

fn unix_to_rfc3339(value: i64) -> Result<String, CommandProtocolError> {
    let timestamp =
        OffsetDateTime::from_unix_timestamp(value).map_err(|_| CommandProtocolError::Internal)?;
    timestamp
        .format(&Rfc3339)
        .map_err(|_| CommandProtocolError::Internal)
}

fn base64_standard(raw: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.encode(raw)
}

fn base64url(raw: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(raw)
}

fn base64url_exact<const N: usize>(value: &str) -> Result<[u8; N], CommandProtocolError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    if value.is_empty() || value.bytes().any(|byte| byte == b'=') {
        return Err(CommandProtocolError::InvalidRequest);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(CommandProtocolError::InvalidRequest);
    }
    decoded
        .try_into()
        .map_err(|_| CommandProtocolError::InvalidRequest)
}

fn require_capability(value: String) -> Result<String, CommandProtocolError> {
    base64url_exact::<32>(&value)?;
    Ok(value)
}

fn join_id(value: &str) -> bool {
    prefixed_lower_hex(value, "join-", 32)
}

fn challenge_id(value: &str) -> bool {
    value.len() >= 18
        && value.len() <= 138
        && value.starts_with("challenge-")
        && value[10..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn comparison_code(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn prefixed_lower_hex(value: &str, prefix: &str, hex_len: usize) -> bool {
    value.len() == prefix.len() + hex_len
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn base64_exact<const N: usize>(value: &str) -> Result<[u8; N], CommandProtocolError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    if STANDARD.encode(&decoded) != value {
        return Err(CommandProtocolError::InvalidRequest);
    }
    decoded
        .try_into()
        .map_err(|_| CommandProtocolError::InvalidRequest)
}

fn base64_vec(value: &str, exact_len: usize) -> Result<Vec<u8>, CommandProtocolError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| CommandProtocolError::InvalidRequest)?;
    if decoded.len() != exact_len || STANDARD.encode(&decoded) != value {
        return Err(CommandProtocolError::InvalidRequest);
    }
    Ok(decoded)
}

fn resolve_pairing_challenge_request(
    wire: WirePairingChallengeRequest,
) -> Result<ParsedPairingChallengeRequest, CommandProtocolError> {
    Ok(ParsedPairingChallengeRequest {
        signing_public_key: base64_exact(&wire.signing_public_key)?,
        agreement_public_key: base64_exact(&wire.agreement_public_key)?,
    })
}

fn resolve_pairing_confirm_request(
    wire: WirePairingConfirmRequest,
) -> Result<ParsedPairingConfirmRequest, CommandProtocolError> {
    if wire.challenge_id.is_empty() || wire.challenge_id.len() > 128 {
        return Err(CommandProtocolError::InvalidRequest);
    }
    Ok(ParsedPairingConfirmRequest {
        challenge_id: wire.challenge_id,
        challenge: base64_vec(&wire.challenge, 32)?,
        signature: base64_vec(&wire.signature, 64)?,
    })
}

fn resolve_device_revoke_request(
    wire: WireDeviceRevokeRequest,
) -> Result<ParsedDeviceRevokeRequest, CommandProtocolError> {
    if wire.device_alias.is_empty() || wire.device_alias.len() > 128 || wire.expected_epoch == 0 {
        return Err(CommandProtocolError::InvalidRequest);
    }
    Ok(ParsedDeviceRevokeRequest {
        device_alias: wire.device_alias,
        expected_epoch: wire.expected_epoch,
    })
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !lower_hex(value) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use std::io::Write;

    fn auth() -> CommandTransportAuthenticator {
        CommandTransportAuthenticator::new(Zeroizing::new(key()))
    }

    fn key() -> [u8; 32] {
        std::array::from_fn(|index| index as u8)
    }

    #[test]
    fn frozen_transport_hmac_vector_matches_gateway() {
        let authenticator = auth();
        assert!(authenticator
            .verify(
                "GET",
                CAPABILITY_PATH,
                b"",
                "1770000000",
                "00112233445566778899aabbccddeeff",
                "37109e4261445a87b51a8967c30365f10ff7bedb9233db8bb1d2459d527c58ed",
            )
            .is_err());
        let body_digest = format!("{:x}", Sha256::digest(b""));
        let material = format!("nomad.product-host.transport.v1\nGET\n{CAPABILITY_PATH}\n1770000000\n00112233445566778899aabbccddeeff\n{body_digest}");
        assert_eq!(
            hex(&crate::run_binding::hmac_sha256(
                &key(),
                material.as_bytes(),
            )),
            "37109e4261445a87b51a8967c30365f10ff7bedb9233db8bb1d2459d527c58ed"
        );
    }

    #[test]
    fn current_time_auth_is_single_use_and_constant_shape() {
        let authenticator = auth();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = "00112233445566778899aabbccddeeff";
        let digest = format!("{:x}", Sha256::digest(b""));
        let material = format!(
            "nomad.product-host.transport.v1\nGET\n{CAPABILITY_PATH}\n{now}\n{nonce}\n{digest}"
        );
        let mac = hex(&crate::run_binding::hmac_sha256(
            &key(),
            material.as_bytes(),
        ));
        assert_eq!(
            authenticator.verify("GET", CAPABILITY_PATH, b"", &now, nonce, &mac),
            Ok(())
        );
        assert_eq!(
            authenticator.verify("GET", CAPABILITY_PATH, b"", &now, nonce, &mac),
            Err(CommandProtocolError::Unauthorized)
        );
        assert_eq!(
            authenticator.verify(
                "GET",
                CAPABILITY_PATH,
                b"",
                "1",
                "ffeeddccbbaa99887766554433221100",
                &mac
            ),
            Err(CommandProtocolError::Unauthorized)
        );
    }

    #[test]
    fn live_nonce_capacity_never_evicts_a_replayable_nonce() {
        let authenticator = auth();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        {
            let mut cache = authenticator.nonces.lock().unwrap();
            for index in 0..MAX_NONCES {
                let nonce = format!("{index:032x}");
                cache.set.insert(nonce.clone());
                cache.order.push_back((now + AUTH_WINDOW_SECONDS, nonce));
            }
        }
        let fresh_nonce = "ffffffffffffffffffffffffffffffff";
        let time = now.to_string();
        let digest = format!("{:x}", Sha256::digest(b""));
        let material = format!(
            "nomad.product-host.transport.v1\nGET\n{CAPABILITY_PATH}\n{time}\n{fresh_nonce}\n{digest}"
        );
        let mac = hex(&crate::run_binding::hmac_sha256(
            &key(),
            material.as_bytes(),
        ));
        assert_eq!(
            authenticator.verify("GET", CAPABILITY_PATH, b"", &time, fresh_nonce, &mac),
            Err(CommandProtocolError::Unauthorized)
        );
        let cache = authenticator.nonces.lock().unwrap();
        assert!(cache.set.contains(&format!("{:032x}", 0)));
        assert_eq!(cache.set.len(), MAX_NONCES);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sec1_test_key(seed: u8) -> String {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
        STANDARD.encode(secret.public_key().to_encoded_point(false).as_bytes())
    }

    fn signed_request(method: &str, path: &str, body: &[u8], nonce: &str) -> Vec<u8> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let digest = format!("{:x}", Sha256::digest(body));
        let material =
            format!("nomad.product-host.transport.v1\n{method}\n{path}\n{now}\n{nonce}\n{digest}");
        let mac = hex(&crate::run_binding::hmac_sha256(
            &key(),
            material.as_bytes(),
        ));
        let content = if method == "POST" {
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
        } else {
            String::new()
        };
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n{content}X-Nomad-Transport-Time: {now}\r\nX-Nomad-Transport-Nonce: {nonce}\r\nX-Nomad-Transport-Mac: {mac}\r\n\r\n").into_bytes();
        request.extend_from_slice(body);
        request
    }

    fn parse(
        raw: &[u8],
        authenticator: &CommandTransportAuthenticator,
    ) -> Result<ProductHostRequest, CommandProtocolError> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(raw).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        read_product_request(&mut server, authenticator, Some(authenticator))
    }

    fn unsigned_request(method: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let content = if body.is_empty() {
            String::new()
        } else {
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
        };
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n{content}\r\n"
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    #[test]
    fn exact_c2_reads_are_anonymous_but_every_other_route_requires_hmac() {
        assert!(matches!(
            parse(
                &unsigned_request("GET", "/internal/session/current", b""),
                &auth()
            ),
            Ok(ProductHostRequest::ReadCurrent)
        ));
        assert!(matches!(
            parse(
                &unsigned_request("GET", "/internal/session/stream?after_snapshot_seq=7", b""),
                &auth()
            ),
            Ok(ProductHostRequest::ReadStream(7))
        ));

        for (method, path, body) in [
            ("GET", CAPABILITY_PATH, b"".as_slice()),
            ("GET", DEVICE_CURRENT_PATH, b"".as_slice()),
            ("POST", COMMAND_PATH, b"{}".as_slice()),
            ("POST", DEVICE_CHALLENGE_PATH, b"{}".as_slice()),
            ("POST", DEVICE_CONFIRM_PATH, b"{}".as_slice()),
            ("POST", DEVICE_REVOKE_PATH, b"{}".as_slice()),
            ("POST", PAIRING_CREATE_PATH, b"{}".as_slice()),
            ("POST", PAIRING_APPROVE_PATH, b"{}".as_slice()),
            ("POST", PAIRING_CANCEL_PATH, b"{}".as_slice()),
            ("POST", PAIRING_STATUS_PATH, b"{}".as_slice()),
            ("POST", PAIRING_START_PATH, b"{}".as_slice()),
            ("POST", PAIRING_CONFIRM_PATH, b"{}".as_slice()),
            ("POST", PAIRING_COMPLETE_PATH, b"{}".as_slice()),
            ("POST", PAIRING_ABORT_PATH, b"{}".as_slice()),
        ] {
            assert_eq!(
                parse(&unsigned_request(method, path, body), &auth()).err(),
                Some(CommandProtocolError::Unauthorized),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn anonymous_c2_reads_reject_ambient_auth_bad_query_and_nonempty_framing() {
        for raw in [
            b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nAuthorization: secret\r\nConnection: close\r\n\r\n".as_slice(),
            b"GET /internal/session/current?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
            b"GET /internal/session/stream?after_snapshot_seq=1&x=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
            b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".as_slice(),
            b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".as_slice(),
        ] {
            assert_eq!(
                parse(raw, &auth()).err(),
                Some(CommandProtocolError::InvalidRequest)
            );
        }
    }

    #[test]
    fn exact_capability_and_reply_are_parsed_but_ambient_auth_is_rejected() {
        assert!(matches!(
            parse(
                &signed_request(
                    "GET",
                    CAPABILITY_PATH,
                    b"",
                    "00112233445566778899aabbccddeeff"
                ),
                &auth()
            ),
            Ok(ProductHostRequest::CommandCapability)
        ));
        let body = br#"{"schema":"nomad.gateway.command.v1","capability_id":"capability_00000001","request_id":"request_00000001","nonce":"nonce_0000000001","command_seq":2,"expected_snapshot_seq":7,"expected_snapshot_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issued_at":"2026-08-25T09:00:00.123Z","expires_at":"2026-08-25T09:00:30.000Z","action":"reply","turn_alias":"turn-11111111111111111111111111111111","input_alias":"input-22222222222222222222222222222222","content":"secret content"}"#;
        assert!(matches!(
            parse(
                &signed_request(
                    "POST",
                    COMMAND_PATH,
                    body,
                    "ffeeddccbbaa99887766554433221100"
                ),
                &auth()
            ),
            Ok(ProductHostRequest::Command(_))
        ));
        let mut ambient = signed_request(
            "GET",
            CAPABILITY_PATH,
            b"",
            "11112222333344445555666677778888",
        );
        let at = ambient
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        ambient.splice(at..at, b"\r\nAuthorization: secret".iter().copied());
        assert_eq!(
            parse(&ambient, &auth()).err(),
            Some(CommandProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn admin_routes_require_signed_fd11_and_strict_bounded_schemas() {
        assert!(matches!(
            parse(
                &signed_request(
                    "GET",
                    DEVICE_CURRENT_PATH,
                    b"",
                    "00112233445566778899aabbccddeeff"
                ),
                &auth()
            ),
            Ok(ProductHostRequest::DeviceCurrent)
        ));

        let challenge_body = format!(
            "{{\"signing_public_key\":\"{}\",\"agreement_public_key\":\"{}\"}}",
            sec1_test_key(1),
            sec1_test_key(2)
        );
        assert!(matches!(
            parse(
                &signed_request(
                    "POST",
                    DEVICE_CHALLENGE_PATH,
                    challenge_body.as_bytes(),
                    "10112233445566778899aabbccddeeff"
                ),
                &auth()
            ),
            Ok(ProductHostRequest::DevicePairingChallenge(_))
        ));

        let confirm_body = br#"{"challenge_id":"challenge-00112233445566778899aabbccddeeff","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#;
        assert!(matches!(
            parse(
                &signed_request(
                    "POST",
                    DEVICE_CONFIRM_PATH,
                    confirm_body,
                    "20112233445566778899aabbccddeeff"
                ),
                &auth()
            ),
            Ok(ProductHostRequest::DevicePairingConfirm(_))
        ));

        let revoke_body =
            br#"{"device_alias":"device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_epoch":7}"#;
        assert!(matches!(
            parse(
                &signed_request(
                    "POST",
                    DEVICE_REVOKE_PATH,
                    revoke_body,
                    "30112233445566778899aabbccddeeff"
                ),
                &auth()
            ),
            Ok(ProductHostRequest::DeviceRevoke(_))
        ));

        let unknown_field = format!(
            "{{\"signing_public_key\":\"{}\",\"agreement_public_key\":\"{}\",\"principal_alias\":\"caller\"}}",
            sec1_test_key(1),
            sec1_test_key(2)
        );
        assert_eq!(
            parse(
                &signed_request(
                    "POST",
                    DEVICE_CHALLENGE_PATH,
                    unknown_field.as_bytes(),
                    "40112233445566778899aabbccddeeff"
                ),
                &auth()
            )
            .err(),
            Some(CommandProtocolError::InvalidRequest)
        );

        let wrong_length = format!(
            "{{\"signing_public_key\":\"{}\",\"agreement_public_key\":\"{}\"}}",
            STANDARD.encode([0_u8; 32]),
            sec1_test_key(1)
        );
        assert_eq!(
            parse(
                &signed_request(
                    "POST",
                    DEVICE_CHALLENGE_PATH,
                    wrong_length.as_bytes(),
                    "45112233445566778899aabbccddeeff"
                ),
                &auth()
            )
            .err(),
            Some(CommandProtocolError::InvalidRequest)
        );

        let unsigned = b"GET /internal/devices/current HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        assert_eq!(
            parse(unsigned, &auth()).err(),
            Some(CommandProtocolError::Unauthorized)
        );
    }

    #[test]
    fn m3e_pairing_routes_require_exact_authenticated_internal_schemas() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let join_id = format!("join-{}", "a".repeat(32));
        let challenge_id = format!("challenge-{}", "b".repeat(32));
        let capability = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let signing_public = URL_SAFE_NO_PAD.encode(
            p256::SecretKey::from_slice(&[3_u8; 32])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let agreement_public = URL_SAFE_NO_PAD.encode(
            p256::SecretKey::from_slice(&[4_u8; 32])
                .unwrap()
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let cases = [
            (
                PAIRING_CREATE_PATH,
                r#"{"schema":"nomad.m3e.pairing.create.v1"}"#.to_owned(),
                "pairing-create",
            ),
            (
                PAIRING_APPROVE_PATH,
                format!(
                    r#"{{"schema":"nomad.m3e.pairing.desktop-approve.v1","join_id":"{join_id}","challenge_id":"{challenge_id}","expected_epoch":1,"comparison_code":"042913"}}"#
                ),
                "pairing-approve",
            ),
            (
                PAIRING_CANCEL_PATH,
                format!(r#"{{"schema":"nomad.m3e.pairing.cancel.v1","join_id":"{join_id}"}}"#),
                "pairing-cancel",
            ),
            (
                PAIRING_STATUS_PATH,
                format!(r#"{{"schema":"nomad.m3e.pairing.status.v1","join_id":"{join_id}"}}"#),
                "pairing-status",
            ),
            (
                PAIRING_START_PATH,
                format!(
                    r#"{{"schema":"nomad.m3e.internal.pairing-start.v1","join_id":"{join_id}","join_secret":"{capability}","device_signing_public_key_sec1":"{signing_public}","device_agreement_public_key_sec1":"{agreement_public}"}}"#
                ),
                "pairing-start",
            ),
            (
                PAIRING_CONFIRM_PATH,
                format!(
                    r#"{{"schema":"nomad.m3e.internal.pairing-confirm.v1","join_cookie_capability":"{capability}","challenge_id":"{challenge_id}","expected_epoch":1,"device_signing_signature_p1363":"{}","device_agreement_mac":"{}"}}"#,
                    URL_SAFE_NO_PAD.encode([5_u8; 64]),
                    URL_SAFE_NO_PAD.encode([6_u8; 32])
                ),
                "pairing-confirm",
            ),
            (
                PAIRING_COMPLETE_PATH,
                format!(
                    r#"{{"schema":"nomad.m3e.internal.pairing-complete.v1","join_cookie_capability":"{capability}","challenge_id":"{challenge_id}","expected_epoch":1,"device_vault_signature_p1363":"{}"}}"#,
                    URL_SAFE_NO_PAD.encode([8_u8; 64])
                ),
                "pairing-complete",
            ),
            (
                PAIRING_ABORT_PATH,
                format!(
                    r#"{{"schema":"nomad.m3e.internal.pairing-abort.v1","join_cookie_capability":"{capability}","challenge_id":"{challenge_id}","expected_epoch":1}}"#
                ),
                "pairing-abort",
            ),
        ];
        for (index, (path, body, expected)) in cases.into_iter().enumerate() {
            let body = crate::alpha_projector::canonical_json(
                &serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            )
            .unwrap();
            let nonce = format!("9{index:031x}");
            let parsed = parse(
                &signed_request("POST", path, body.as_bytes(), &nonce),
                &auth(),
            )
            .unwrap();
            let actual = match parsed {
                ProductHostRequest::PairingCreate => "pairing-create",
                ProductHostRequest::PairingApprove(_) => "pairing-approve",
                ProductHostRequest::PairingCancel(_) => "pairing-cancel",
                ProductHostRequest::PairingStatus(_) => "pairing-status",
                ProductHostRequest::PairingStart(_) => "pairing-start",
                ProductHostRequest::PairingConfirm(_) => "pairing-confirm",
                ProductHostRequest::PairingComplete(_) => "pairing-complete",
                ProductHostRequest::PairingAbort(_) => "pairing-abort",
                _ => panic!("unexpected route"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn pairing_hmac_is_bound_to_exact_path_and_body() {
        let body = br#"{"schema":"nomad.m3e.pairing.create.v1"}"#;
        let mut wrong_path = signed_request(
            "POST",
            PAIRING_CREATE_PATH,
            body,
            "a0112233445566778899aabbccddeeff",
        );
        let offset = wrong_path
            .windows(PAIRING_CREATE_PATH.len())
            .position(|window| window == PAIRING_CREATE_PATH.as_bytes())
            .unwrap();
        wrong_path.splice(
            offset..offset + PAIRING_CREATE_PATH.len(),
            PAIRING_STATUS_PATH.bytes(),
        );
        assert_eq!(
            parse(&wrong_path, &auth()).err(),
            Some(CommandProtocolError::Unauthorized)
        );

        let duplicate =
            br#"{"schema":"nomad.m3e.pairing.create.v1","schema":"nomad.m3e.pairing.create.v1"}"#;
        assert_eq!(
            parse(
                &signed_request(
                    "POST",
                    PAIRING_CREATE_PATH,
                    duplicate,
                    "b0112233445566778899aabbccddeeff"
                ),
                &auth()
            )
            .err(),
            Some(CommandProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn desktop_and_join_transport_keys_cannot_cross_routes() {
        fn keyed_auth(byte: u8) -> CommandTransportAuthenticator {
            CommandTransportAuthenticator::new(Zeroizing::new([byte; 32]))
        }
        fn signed_with_key(
            key: &[u8; 32],
            method: &str,
            path: &str,
            body: &[u8],
            nonce: &str,
        ) -> Vec<u8> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();
            let digest = format!("{:x}", Sha256::digest(body));
            let material = format!(
                "nomad.product-host.transport.v1\n{method}\n{path}\n{now}\n{nonce}\n{digest}"
            );
            let mac = hex(&crate::run_binding::hmac_sha256(key, material.as_bytes()));
            let content = format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
            let mut request = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n{content}X-Nomad-Transport-Time: {now}\r\nX-Nomad-Transport-Nonce: {nonce}\r\nX-Nomad-Transport-Mac: {mac}\r\n\r\n"
            )
            .into_bytes();
            request.extend_from_slice(body);
            request
        }
        fn parse_with_two(
            raw: &[u8],
            desktop: &CommandTransportAuthenticator,
            join: Option<&CommandTransportAuthenticator>,
        ) -> Result<ProductHostRequest, CommandProtocolError> {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(raw).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            read_product_request(&mut server, desktop, join)
        }

        let desktop_key = [11_u8; 32];
        let join_key = [12_u8; 32];
        let join_body = crate::alpha_projector::canonical_json(&serde_json::json!({
            "schema":"nomad.m3e.internal.pairing-abort.v1",
            "join_cookie_capability":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "challenge_id":"challenge-00112233445566778899aabbccddeeff",
            "expected_epoch":1
        }))
        .unwrap();
        let join_request = signed_with_key(
            &join_key,
            "POST",
            PAIRING_ABORT_PATH,
            join_body.as_bytes(),
            "e0112233445566778899aabbccddeeff",
        );
        assert!(matches!(
            parse_with_two(&join_request, &keyed_auth(11), Some(&keyed_auth(12))),
            Ok(ProductHostRequest::PairingAbort(_))
        ));
        assert_eq!(
            parse_with_two(&join_request, &keyed_auth(11), None).err(),
            Some(CommandProtocolError::Unauthorized)
        );
        assert_eq!(
            parse_with_two(
                &signed_with_key(
                    &desktop_key,
                    "POST",
                    PAIRING_ABORT_PATH,
                    join_body.as_bytes(),
                    "e1112233445566778899aabbccddeeff",
                ),
                &keyed_auth(11),
                Some(&keyed_auth(12)),
            )
            .err(),
            Some(CommandProtocolError::Unauthorized)
        );

        let desktop_body =
            br#"{"device_alias":"device-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_epoch":1}"#;
        assert_eq!(
            parse_with_two(
                &signed_with_key(
                    &join_key,
                    "POST",
                    DEVICE_REVOKE_PATH,
                    desktop_body,
                    "e2112233445566778899aabbccddeeff",
                ),
                &keyed_auth(11),
                Some(&keyed_auth(12)),
            )
            .err(),
            Some(CommandProtocolError::Unauthorized)
        );
        assert!(matches!(
            parse_with_two(
                &signed_with_key(
                    &desktop_key,
                    "POST",
                    DEVICE_REVOKE_PATH,
                    desktop_body,
                    "e3112233445566778899aabbccddeeff",
                ),
                &keyed_auth(11),
                Some(&keyed_auth(12)),
            ),
            Ok(ProductHostRequest::DeviceRevoke(_))
        ));
    }

    #[test]
    fn strict_framing_rejects_trailing_chunked_duplicate_and_oversize() {
        let exact = signed_request(
            "GET",
            CAPABILITY_PATH,
            b"",
            "10112233445566778899aabbccddeeff",
        );
        for mutate in [
            |mut bytes: Vec<u8>| {
                bytes.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
                bytes
            },
            |bytes: Vec<u8>| {
                let text = String::from_utf8(bytes).unwrap().replace(
                    "Connection: close\r\n",
                    "Connection: close\r\nTransfer-Encoding: chunked\r\n",
                );
                text.into_bytes()
            },
            |bytes: Vec<u8>| {
                let text = String::from_utf8(bytes).unwrap().replace(
                    "Host: localhost\r\n",
                    "Host: localhost\r\nHost: localhost\r\n",
                );
                text.into_bytes()
            },
        ] {
            assert_eq!(
                parse(&mutate(exact.clone()), &auth()).err(),
                Some(CommandProtocolError::InvalidRequest)
            );
        }
    }
}
