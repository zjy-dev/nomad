//! Single fail-closed authority boundary for product Host commands.
//!
//! This module is crate-private until production pairing can construct the
//! authenticated context. Legacy bridge commands cannot call it directly.

use crate::error::ConnectorError;
use crate::journal::{CommandJournal, HostAuthorityClaim, JournalCommand};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Mutex;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroize;

const VERSION: &str = "nomad.host-command.v1";
const MAX_WIRE_BYTES: usize = 72 * 1024;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_TTL_SECONDS: i64 = 60;

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "action",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum HostCommand {
    Reply(ReplyBody),
    Deny(DenyBody),
    Stop(StopBody),
}

impl HostCommand {
    pub(crate) fn reply(
        target_turn_alias: String,
        target_input_alias: String,
        content: String,
    ) -> Result<Self, ConnectorError> {
        let command = Self::Reply(ReplyBody {
            target_turn_id: target_turn_alias,
            target_input_id: target_input_alias,
            content,
        });
        validate_command(&command)?;
        Ok(command)
    }

    pub(crate) fn deny(
        permission_alias: String,
        action_hash: String,
        permission_expires_at: String,
    ) -> Result<Self, ConnectorError> {
        let command = Self::Deny(DenyBody {
            permission_id: permission_alias,
            action_hash,
            permission_expires_at,
        });
        validate_command(&command)?;
        Ok(command)
    }

    pub(crate) fn stop(target_turn_alias: String) -> Result<Self, ConnectorError> {
        let command = Self::Stop(StopBody {
            target_turn_id: target_turn_alias,
        });
        validate_command(&command)?;
        Ok(command)
    }

    pub(crate) fn action(&self) -> &'static str {
        command_kind(self)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplyBody {
    target_turn_id: String,
    target_input_id: String,
    content: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenyBody {
    permission_id: String,
    action_hash: String,
    permission_expires_at: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StopBody {
    target_turn_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostCommandEnvelope {
    version: String,
    capability_id: String,
    request_id: String,
    run_id: String,
    session_id: String,
    device_id: String,
    pairing_epoch: u64,
    nonce: String,
    command_seq: u64,
    expected_snapshot_seq: u64,
    expected_snapshot_digest: String,
    issued_at: String,
    expires_at: String,
    command: HostCommand,
    auth_tag: String,
}

pub(crate) struct AuthenticatedDeviceSession {
    principal_id: String,
    device_id: String,
    run_id: String,
    session_id: String,
    pairing_epoch: u64,
    command_key: [u8; 32],
    revoked: bool,
}

impl AuthenticatedDeviceSession {
    pub(crate) fn new_local(
        principal_alias: String,
        device_alias: String,
        run_alias: String,
        session_alias: String,
        pairing_epoch: u64,
        command_key: [u8; 32],
    ) -> Result<Self, ConnectorError> {
        if !safe_id(&principal_alias, 128)
            || !safe_id(&device_alias, 128)
            || !safe_id(&run_alias, 128)
            || !safe_id(&session_alias, 128)
            || pairing_epoch == 0
            || constant_time_equal(&command_key, &[0; 32])
        {
            return Err(blocked("invalid local device session"));
        }
        Ok(Self {
            principal_id: principal_alias,
            device_id: device_alias,
            run_id: run_alias,
            session_id: session_alias,
            pairing_epoch,
            command_key,
            revoked: false,
        })
    }
}

pub(crate) struct ResolvedHostCommandRequest {
    capability_id: String,
    request_id: String,
    nonce: String,
    command_seq: u64,
    expected_snapshot_seq: u64,
    expected_snapshot_digest: String,
    issued_at: String,
    expires_at: String,
    command: HostCommand,
}

impl ResolvedHostCommandRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        capability_id: String,
        request_id: String,
        nonce: String,
        command_seq: u64,
        expected_snapshot_seq: u64,
        expected_snapshot_digest: String,
        issued_at: String,
        expires_at: String,
        command: HostCommand,
    ) -> Result<Self, ConnectorError> {
        if !safe_id(&capability_id, 128)
            || !safe_id(&request_id, 128)
            || !safe_id(&nonce, 128)
            || command_seq == 0
            || expected_snapshot_seq == 0
            || !digest(&expected_snapshot_digest)
        {
            return Err(blocked("invalid resolved command metadata"));
        }
        strict_time(&issued_at)?;
        strict_time(&expires_at)?;
        validate_command(&command)?;
        Ok(Self {
            capability_id,
            request_id,
            nonce,
            command_seq,
            expected_snapshot_seq,
            expected_snapshot_digest,
            issued_at,
            expires_at,
            command,
        })
    }
}

impl Drop for AuthenticatedDeviceSession {
    fn drop(&mut self) {
        self.command_key.zeroize();
    }
}

impl fmt::Debug for AuthenticatedDeviceSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedDeviceSession")
            .field("identity", &"<redacted>")
            .field("command_key", &"<redacted>")
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct CurrentCommandState {
    pub run_id: String,
    pub session_id: String,
    pub snapshot_seq: u64,
    pub snapshot_digest: String,
    pub next_command_seq: u64,
    pub online: bool,
    pub live: bool,
    pub reconciliation_pending: bool,
    pub active_turn_id: Option<String>,
    pub active_input_id: Option<String>,
    pub active_permission: Option<CurrentPermission>,
}

#[derive(Clone)]
pub(crate) struct CurrentPermission {
    pub permission_id: String,
    pub action_hash: String,
    pub expires_at: String,
}

pub(crate) trait TrustedCommandState {
    fn refresh_current(&self, session_id: &str) -> Result<CurrentCommandState, ConnectorError>;
}

pub(crate) trait TrustedCommandReconciler {
    fn verify_terminal_outcome(
        &self,
        request_id: &str,
    ) -> Result<AuthoritativeReconciliationFacts, ConnectorError>;
}

pub(crate) struct AuthoritativeReconciliationFacts {
    pub principal_id: String,
    pub device_id: String,
    pub run_id: String,
    pub session_id: String,
    pub pairing_epoch: u64,
    pub request_id: String,
    pub terminal: ReconciledTerminal,
    pub snapshot_seq: u64,
    pub snapshot_digest: String,
}

pub(crate) enum ReconciledTerminal {
    Completed { accepted_at_seq: u64 },
    Rejected { error_code: &'static str },
}

/// An opaque, non-cloneable, non-serializable capability. Only this authority
/// module can construct it after validating trusted reconciliation facts.
pub(crate) struct VerifiedHostReconciliation {
    proof_id: String,
    authority_scope: String,
    request_id: String,
    terminal_status: &'static str,
    terminal_error_code: Option<String>,
    accepted_at_seq: Option<u64>,
    seal: [u8; 32],
}

impl VerifiedHostReconciliation {
    pub(super) fn proof_id(&self) -> &str {
        &self.proof_id
    }

    pub(super) fn authority_scope(&self) -> &str {
        &self.authority_scope
    }

    pub(super) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(super) fn terminal_status(&self) -> &'static str {
        self.terminal_status
    }

    pub(super) fn accepted_at_seq(&self) -> Option<u64> {
        self.accepted_at_seq
    }

    pub(super) fn terminal_error_code(&self) -> Option<&str> {
        self.terminal_error_code.as_deref()
    }

    pub(super) fn seal_hex(&self) -> String {
        hex(&self.seal)
    }

    #[cfg(test)]
    fn duplicate_for_replay_test(&self) -> Self {
        Self {
            proof_id: self.proof_id.clone(),
            authority_scope: self.authority_scope.clone(),
            request_id: self.request_id.clone(),
            terminal_status: self.terminal_status,
            terminal_error_code: self.terminal_error_code.clone(),
            accepted_at_seq: self.accepted_at_seq,
            seal: self.seal,
        }
    }
}

impl Drop for VerifiedHostReconciliation {
    fn drop(&mut self) {
        self.seal.zeroize();
    }
}

impl fmt::Debug for VerifiedHostReconciliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHostReconciliation")
            .field("binding", &"<redacted>")
            .field("terminal_status", &self.terminal_status)
            .finish()
    }
}

pub(crate) trait AgentCommandAdapter {
    fn execute_once(
        &self,
        command: AuthorizedHostCommand,
    ) -> Result<AdapterOutcome, ConnectorError>;
}

pub(crate) struct AuthorizedHostCommand {
    request_id: String,
    command: HostCommand,
}

impl AuthorizedHostCommand {
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }
    pub(crate) fn action(&self) -> &'static str {
        self.command.action()
    }

    pub(crate) fn into_parts(self) -> AuthorizedCommandParts {
        match self.command {
            HostCommand::Reply(body) => AuthorizedCommandParts::Reply {
                request_id: self.request_id,
                turn_alias: body.target_turn_id,
                input_alias: body.target_input_id,
                content: body.content,
            },
            HostCommand::Deny(body) => AuthorizedCommandParts::Deny {
                request_id: self.request_id,
                permission_alias: body.permission_id,
                action_hash: body.action_hash,
                permission_expires_at: body.permission_expires_at,
            },
            HostCommand::Stop(body) => AuthorizedCommandParts::Stop {
                request_id: self.request_id,
                turn_alias: body.target_turn_id,
            },
        }
    }
}

pub(crate) enum AuthorizedCommandParts {
    Reply {
        request_id: String,
        turn_alias: String,
        input_alias: String,
        content: String,
    },
    Deny {
        request_id: String,
        permission_alias: String,
        action_hash: String,
        permission_expires_at: String,
    },
    Stop {
        request_id: String,
        turn_alias: String,
    },
}

pub(crate) enum AdapterOutcome {
    Completed { accepted_at_seq: u64 },
    Rejected { error_code: &'static str },
    OutcomeUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostCommandReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub kind: String,
    pub accepted_at: String,
    pub status: String,
    pub error_code: Option<String>,
    pub accepted_at_seq: Option<u64>,
    pub idempotent_replay: bool,
}

pub(crate) struct HostCommandAuthority<'a, S, A> {
    state: S,
    adapter: A,
    journal: &'a CommandJournal,
}

impl<'a, S: TrustedCommandState, A: AgentCommandAdapter> HostCommandAuthority<'a, S, A> {
    pub(crate) fn new(state: S, adapter: A, journal: &'a CommandJournal) -> Self {
        Self {
            state,
            adapter,
            journal,
        }
    }

    pub(crate) fn execute_json(
        &self,
        auth: &AuthenticatedDeviceSession,
        raw: &[u8],
    ) -> Result<HostCommandReceipt, ConnectorError> {
        self.execute_json_with_now(auth, raw, OffsetDateTime::now_utc())
    }

    pub(crate) fn execute_resolved_local(
        &self,
        auth: &AuthenticatedDeviceSession,
        request: ResolvedHostCommandRequest,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        self.execute_resolved_local_at(auth, request, OffsetDateTime::now_utc())
    }

    fn execute_resolved_local_at(
        &self,
        auth: &AuthenticatedDeviceSession,
        request: ResolvedHostCommandRequest,
        now: OffsetDateTime,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        let mut envelope = HostCommandEnvelope {
            version: VERSION.into(),
            capability_id: request.capability_id,
            request_id: request.request_id,
            run_id: auth.run_id.clone(),
            session_id: auth.session_id.clone(),
            device_id: auth.device_id.clone(),
            pairing_epoch: auth.pairing_epoch,
            nonce: request.nonce,
            command_seq: request.command_seq,
            expected_snapshot_seq: request.expected_snapshot_seq,
            expected_snapshot_digest: request.expected_snapshot_digest,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            command: request.command,
            auth_tag: String::new(),
        };
        envelope.auth_tag = auth_tag(auth, &envelope)?;
        self.execute(auth, envelope, now)
    }

    #[cfg(test)]
    fn execute_json_at(
        &self,
        auth: &AuthenticatedDeviceSession,
        raw: &[u8],
        now: OffsetDateTime,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        self.execute_json_with_now(auth, raw, now)
    }

    fn execute_json_with_now(
        &self,
        auth: &AuthenticatedDeviceSession,
        raw: &[u8],
        now: OffsetDateTime,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
            return Err(blocked("invalid command envelope"));
        }
        let value = crate::stock_event_adapter::strict_json(raw)
            .map_err(|_| blocked("invalid command envelope"))?;
        let envelope: HostCommandEnvelope =
            serde_json::from_value(value).map_err(|_| blocked("invalid command envelope"))?;
        self.execute(auth, envelope, now)
    }

    pub(crate) fn complete_authenticated_reconciliation<R: TrustedCommandReconciler>(
        &self,
        auth: &AuthenticatedDeviceSession,
        request_id: &str,
        reconciler: &R,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        if auth.revoked
            || !safe_id(&auth.principal_id, 128)
            || !safe_id(&auth.device_id, 128)
            || !safe_id(&auth.run_id, 128)
            || !safe_id(&auth.session_id, 128)
            || !safe_id(request_id, 128)
        {
            return Err(blocked("authenticated reconciliation rejected"));
        }
        let state = self.state.refresh_current(&auth.session_id)?;
        if !state.online
            || !state.live
            || state.reconciliation_pending
            || state.run_id != auth.run_id
            || state.session_id != auth.session_id
        {
            return Err(ConnectorError::HostOffline);
        }
        let scope = authority_scope(auth)?;
        let facts = reconciler.verify_terminal_outcome(request_id)?;
        if facts.principal_id != auth.principal_id
            || facts.device_id != auth.device_id
            || facts.run_id != auth.run_id
            || facts.session_id != auth.session_id
            || facts.pairing_epoch != auth.pairing_epoch
            || facts.request_id != request_id
            || facts.snapshot_seq != state.snapshot_seq
            || facts.snapshot_digest != state.snapshot_digest
        {
            return Err(ConnectorError::StaleRequest(
                "reconciliation proof binding changed".into(),
            ));
        }
        let (terminal_status, accepted_at_seq, error_code) = match facts.terminal {
            ReconciledTerminal::Completed { accepted_at_seq }
                if accepted_at_seq != 0 && accepted_at_seq <= facts.snapshot_seq =>
            {
                ("Completed", Some(accepted_at_seq), None)
            }
            ReconciledTerminal::Rejected { error_code } => (
                "Rejected",
                None,
                Some(public_rejection_code(error_code).to_string()),
            ),
            ReconciledTerminal::Completed { .. } => {
                return Err(ConnectorError::StaleRequest(
                    "reconciliation terminal sequence is not in snapshot".into(),
                ));
            }
        };
        let saved = self
            .journal
            .get_host_authority_command(request_id)?
            .ok_or_else(|| ConnectorError::StaleRequest("unknown reconciliation request".into()))?;
        if saved.0.status != "OutcomeUnknown"
            && saved.0.status != "HostAccepted"
            && saved.0.status != "Dispatching"
        {
            return Err(ConnectorError::StaleRequest(
                "reconciliation request is already terminal".into(),
            ));
        }
        let receipt = HostCommandReceipt {
            receipt_id: saved.2,
            request_id: request_id.into(),
            kind: saved.0.command_type,
            accepted_at: saved.0.created_at,
            status: terminal_status.into(),
            error_code: error_code.clone(),
            accepted_at_seq,
            idempotent_replay: false,
        };
        let proof = seal_reconciliation(
            auth,
            &scope,
            request_id,
            &facts,
            terminal_status,
            accepted_at_seq,
            error_code.as_deref(),
        )?;
        self.journal
            .reconcile_host_authority(proof, &serde_json::to_string(&receipt)?)?;
        Ok(receipt)
    }

    fn execute(
        &self,
        auth: &AuthenticatedDeviceSession,
        envelope: HostCommandEnvelope,
        now: OffsetDateTime,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        validate_authenticated_binding(auth, &envelope)?;
        let binding = binding_digest(auth, &envelope)?;
        if let Some((command, saved_binding, saved_receipt)) = self
            .journal
            .get_host_authority_command(&envelope.request_id)?
        {
            return replay(command, &binding, &saved_binding, saved_receipt);
        }
        validate_time_window(&envelope, now)?;
        let state = self.state.refresh_current(&envelope.session_id)?;
        validate_state(auth, &envelope, &state, now)?;
        let kind = command_kind(&envelope.command);
        let authority_scope = authority_scope(auth)?;
        #[derive(Serialize)]
        struct NonceMaterial<'a> {
            domain: &'static str,
            principal_id: &'a str,
            device_id: &'a str,
            run_id: &'a str,
            session_id: &'a str,
            pairing_epoch: u64,
            nonce: &'a str,
        }
        let mut nonce_material = serde_json::to_vec(&NonceMaterial {
            domain: "nomad.host-command.nonce.v1",
            principal_id: &auth.principal_id,
            device_id: &auth.device_id,
            run_id: &auth.run_id,
            session_id: &auth.session_id,
            pairing_epoch: auth.pairing_epoch,
            nonce: &envelope.nonce,
        })?;
        let nonce_digest = keyed_digest(&auth.command_key, b"nonce-v1", &nonce_material);
        nonce_material.zeroize();
        let receipt_id = random_receipt_id()?;
        let prepared = HostCommandReceipt {
            receipt_id: receipt_id.clone(),
            request_id: envelope.request_id.clone(),
            kind: kind.into(),
            accepted_at: receipt_time(now)?,
            status: "HostAccepted".into(),
            error_code: None,
            accepted_at_seq: None,
            idempotent_replay: false,
        };
        let row = JournalCommand {
            request_id: envelope.request_id.clone(),
            command_type: kind.into(),
            session_id: envelope.session_id.clone(),
            seq: envelope.command_seq,
            status: "HostAccepted".into(),
            accepted_at_seq: None,
            result_json: serde_json::to_string(&prepared)?,
            created_at: prepared.accepted_at.clone(),
        };
        match self.journal.claim_host_authority_command(
            &row,
            &binding,
            &receipt_id,
            &authority_scope,
            envelope.command_seq,
            &nonce_digest,
        )? {
            HostAuthorityClaim::Existing {
                command,
                binding_digest: saved,
                receipt_id: saved_receipt,
            } => {
                return replay(*command, &binding, &saved, saved_receipt);
            }
            HostAuthorityClaim::Inserted => {}
        }
        self.journal
            .transition_host_authority_to_dispatching(&envelope.request_id, &authority_scope)?;
        let authorized = AuthorizedHostCommand {
            request_id: envelope.request_id.clone(),
            command: envelope.command,
        };
        let receipt = match self.adapter.execute_once(authorized) {
            Ok(AdapterOutcome::Completed { accepted_at_seq }) => HostCommandReceipt {
                status: "DispatchAcknowledged".into(),
                accepted_at_seq: Some(accepted_at_seq),
                ..prepared
            },
            Ok(AdapterOutcome::Rejected { error_code }) => HostCommandReceipt {
                status: "Rejected".into(),
                error_code: Some(public_rejection_code(error_code).into()),
                ..prepared
            },
            Ok(AdapterOutcome::OutcomeUnknown) | Err(_) => HostCommandReceipt {
                status: "OutcomeUnknown".into(),
                error_code: Some("ERR_OUTCOME_UNKNOWN".into()),
                ..prepared
            },
        };
        self.journal.update_host_authority_outcome(
            &receipt.request_id,
            &authority_scope,
            &receipt.status,
            receipt.accepted_at_seq,
            &serde_json::to_string(&receipt)?,
        )?;
        Ok(receipt)
    }
}

/// One process-owned authority with a single serialized SQLite connection.
/// Each call borrows that same journal only for the duration of the existing
/// validation/claim/dispatch core; no self-reference or leaked lifetime is used.
pub(crate) struct OwnedHostCommandAuthority<S, A> {
    state: S,
    adapter: A,
    journal: Mutex<CommandJournal>,
}

impl<S: TrustedCommandState + Clone, A: AgentCommandAdapter + Clone>
    OwnedHostCommandAuthority<S, A>
{
    pub(crate) fn new(state: S, adapter: A, journal: CommandJournal) -> Self {
        Self {
            state,
            adapter,
            journal: Mutex::new(journal),
        }
    }

    pub(crate) fn execute_resolved_local(
        &self,
        auth: &AuthenticatedDeviceSession,
        request: ResolvedHostCommandRequest,
    ) -> Result<HostCommandReceipt, ConnectorError> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| ConnectorError::Journal("host authority lock failed".into()))?;
        HostCommandAuthority::new(self.state.clone(), self.adapter.clone(), &journal)
            .execute_resolved_local(auth, request)
    }

    pub(crate) fn contains_request(&self, request_id: &str) -> Result<bool, ConnectorError> {
        self.journal
            .lock()
            .map_err(|_| ConnectorError::Journal("host authority lock failed".into()))?
            .get_host_authority_command(request_id)
            .map(|saved| saved.is_some())
    }

    pub(crate) fn next_command_sequence(
        &self,
        auth: &AuthenticatedDeviceSession,
    ) -> Result<u64, ConnectorError> {
        let scope = authority_scope(auth)?;
        self.journal
            .lock()
            .map_err(|_| ConnectorError::Journal("host authority lock failed".into()))?
            .next_host_authority_sequence(&scope)
    }
}

fn validate_authenticated_binding(
    auth: &AuthenticatedDeviceSession,
    envelope: &HostCommandEnvelope,
) -> Result<(), ConnectorError> {
    if envelope.version != VERSION
        || !safe_id(&auth.principal_id, 128)
        || !safe_id(&envelope.capability_id, 128)
        || !safe_id(&envelope.request_id, 128)
        || !safe_id(&envelope.run_id, 128)
        || !safe_id(&envelope.session_id, 128)
        || !safe_id(&envelope.device_id, 128)
        || !safe_id(&envelope.nonce, 128)
        || envelope.command_seq == 0
        || envelope.expected_snapshot_seq == 0
        || !digest(&envelope.expected_snapshot_digest)
        || auth.revoked
        || auth.run_id != envelope.run_id
        || auth.session_id != envelope.session_id
        || auth.device_id != envelope.device_id
        || auth.pairing_epoch != envelope.pairing_epoch
        || envelope.auth_tag.len() != 64
        || !envelope
            .auth_tag
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(blocked("command authentication binding rejected"));
    }
    validate_command(&envelope.command)?;
    strict_time(&envelope.issued_at)?;
    strict_time(&envelope.expires_at)?;
    let mut expected = auth_tag(auth, envelope)?;
    let authenticated = constant_time_equal(expected.as_bytes(), envelope.auth_tag.as_bytes());
    expected.zeroize();
    if !authenticated {
        return Err(blocked("command authentication binding rejected"));
    }
    Ok(())
}

fn validate_time_window(
    envelope: &HostCommandEnvelope,
    now: OffsetDateTime,
) -> Result<(), ConnectorError> {
    let issued = strict_time(&envelope.issued_at)?;
    let expires = strict_time(&envelope.expires_at)?;
    if issued > now
        || expires <= now
        || expires <= issued
        || expires - issued > time::Duration::seconds(MAX_TTL_SECONDS)
    {
        return Err(ConnectorError::ExpiredRequest("command expired".into()));
    }
    Ok(())
}

fn replay(
    command: JournalCommand,
    binding: &str,
    saved_binding: &str,
    saved_receipt: String,
) -> Result<HostCommandReceipt, ConnectorError> {
    if saved_binding != binding {
        return Err(ConnectorError::StaleRequest(
            "request binding conflict".into(),
        ));
    }
    if matches!(command.status.as_str(), "HostAccepted" | "Dispatching") {
        return Err(ConnectorError::OutcomeUnknown);
    }
    let mut receipt: HostCommandReceipt = serde_json::from_str(&command.result_json)?;
    receipt.receipt_id = saved_receipt;
    receipt.idempotent_replay = true;
    Ok(receipt)
}

fn validate_state(
    auth: &AuthenticatedDeviceSession,
    envelope: &HostCommandEnvelope,
    state: &CurrentCommandState,
    now: OffsetDateTime,
) -> Result<(), ConnectorError> {
    if !state.online || !state.live || state.reconciliation_pending {
        return Err(ConnectorError::HostOffline);
    }
    if state.run_id != auth.run_id
        || state.session_id != auth.session_id
        || state.snapshot_seq != envelope.expected_snapshot_seq
        || state.snapshot_digest != envelope.expected_snapshot_digest
        || state.next_command_seq != envelope.command_seq
    {
        return Err(ConnectorError::StaleRequest(
            "authoritative snapshot changed".into(),
        ));
    }
    match &envelope.command {
        HostCommand::Reply(body)
            if state.active_turn_id.as_ref() == Some(&body.target_turn_id)
                && state.active_input_id.as_ref() == Some(&body.target_input_id) =>
        {
            Ok(())
        }
        HostCommand::Deny(body)
            if state.active_permission.as_ref().is_some_and(|current| {
                current.permission_id == body.permission_id
                    && current.action_hash == body.action_hash
                    && current.expires_at == body.permission_expires_at
                    && strict_time(&current.expires_at).is_ok_and(|expiry| expiry > now)
            }) =>
        {
            Ok(())
        }
        HostCommand::Stop(body) if state.active_turn_id.as_ref() == Some(&body.target_turn_id) => {
            Ok(())
        }
        _ => Err(ConnectorError::StaleRequest(
            "command target changed".into(),
        )),
    }
}

fn validate_command(command: &HostCommand) -> Result<(), ConnectorError> {
    let valid = match command {
        HostCommand::Reply(body) => {
            safe_id(&body.target_turn_id, 128)
                && safe_id(&body.target_input_id, 128)
                && !body.content.is_empty()
                && body.content.len() <= MAX_TEXT_BYTES
        }
        HostCommand::Deny(body) => {
            safe_id(&body.permission_id, 128)
                && digest(&body.action_hash)
                && strict_time(&body.permission_expires_at).is_ok()
        }
        HostCommand::Stop(body) => safe_id(&body.target_turn_id, 128),
    };
    if valid {
        Ok(())
    } else {
        Err(blocked("invalid command body"))
    }
}

fn command_kind(command: &HostCommand) -> &'static str {
    match command {
        HostCommand::Reply(_) => "reply",
        HostCommand::Deny(_) => "deny",
        HostCommand::Stop(_) => "stop",
    }
}

fn public_rejection_code(code: &str) -> &'static str {
    match code {
        "ERR_PERMISSION_DENIED" => "ERR_PERMISSION_DENIED",
        "ERR_REQUEST_STALE" => "ERR_REQUEST_STALE",
        "ERR_HOST_OFFLINE" => "ERR_HOST_OFFLINE",
        "ERR_COMMAND_REJECTED" => "ERR_COMMAND_REJECTED",
        _ => "ERR_COMMAND_REJECTED",
    }
}

fn binding_digest(
    auth: &AuthenticatedDeviceSession,
    envelope: &HostCommandEnvelope,
) -> Result<String, ConnectorError> {
    #[derive(Serialize)]
    struct BindingMaterial<'a> {
        domain: &'static str,
        principal_id: &'a str,
        device_id: &'a str,
        run_id: &'a str,
        session_id: &'a str,
        pairing_epoch: u64,
        version: &'a str,
        capability_id: &'a str,
        request_id: &'a str,
        nonce: &'a str,
        command_seq: u64,
        expected_snapshot_seq: u64,
        expected_snapshot_digest: &'a str,
        issued_at: &'a str,
        expires_at: &'a str,
        command: &'a HostCommand,
    }
    let mut material = serde_json::to_vec(&BindingMaterial {
        domain: "nomad.host-command.binding.v1",
        principal_id: &auth.principal_id,
        device_id: &auth.device_id,
        run_id: &auth.run_id,
        session_id: &auth.session_id,
        pairing_epoch: auth.pairing_epoch,
        version: &envelope.version,
        capability_id: &envelope.capability_id,
        request_id: &envelope.request_id,
        nonce: &envelope.nonce,
        command_seq: envelope.command_seq,
        expected_snapshot_seq: envelope.expected_snapshot_seq,
        expected_snapshot_digest: &envelope.expected_snapshot_digest,
        issued_at: &envelope.issued_at,
        expires_at: &envelope.expires_at,
        command: &envelope.command,
    })?;
    let result = keyed_digest(&auth.command_key, b"binding-v1", &material);
    material.zeroize();
    Ok(result)
}

fn authority_scope(auth: &AuthenticatedDeviceSession) -> Result<String, ConnectorError> {
    #[derive(Serialize)]
    struct ScopeMaterial<'a> {
        domain: &'static str,
        principal_id: &'a str,
        device_id: &'a str,
        run_id: &'a str,
        session_id: &'a str,
        pairing_epoch: u64,
    }
    let mut material = serde_json::to_vec(&ScopeMaterial {
        domain: "nomad.host-command.authority-scope.v1",
        principal_id: &auth.principal_id,
        device_id: &auth.device_id,
        run_id: &auth.run_id,
        session_id: &auth.session_id,
        pairing_epoch: auth.pairing_epoch,
    })?;
    let result = keyed_digest(&auth.command_key, b"authority-scope-v1", &material);
    material.zeroize();
    Ok(result)
}

fn seal_reconciliation(
    auth: &AuthenticatedDeviceSession,
    authority_scope: &str,
    request_id: &str,
    facts: &AuthoritativeReconciliationFacts,
    terminal_status: &'static str,
    accepted_at_seq: Option<u64>,
    terminal_error_code: Option<&str>,
) -> Result<VerifiedHostReconciliation, ConnectorError> {
    #[derive(Serialize)]
    struct ReconciliationMaterial<'a> {
        domain: &'static str,
        authority_scope: &'a str,
        request_id: &'a str,
        principal_id: &'a str,
        device_id: &'a str,
        run_id: &'a str,
        session_id: &'a str,
        pairing_epoch: u64,
        terminal_status: &'a str,
        terminal_error_code: Option<&'a str>,
        accepted_at_seq: Option<u64>,
        snapshot_seq: u64,
        snapshot_digest: &'a str,
        proof_id: &'a str,
    }
    let proof_id = random_proof_id()?;
    let mut material = serde_json::to_vec(&ReconciliationMaterial {
        domain: "nomad.host-command.reconciliation.v1",
        authority_scope,
        request_id,
        principal_id: &facts.principal_id,
        device_id: &facts.device_id,
        run_id: &facts.run_id,
        session_id: &facts.session_id,
        pairing_epoch: facts.pairing_epoch,
        terminal_status,
        terminal_error_code,
        accepted_at_seq,
        snapshot_seq: facts.snapshot_seq,
        snapshot_digest: &facts.snapshot_digest,
        proof_id: &proof_id,
    })?;
    let seal = keyed_mac(&auth.command_key, b"reconciliation-v1", &material);
    material.zeroize();
    Ok(VerifiedHostReconciliation {
        proof_id,
        authority_scope: authority_scope.into(),
        request_id: request_id.into(),
        terminal_status,
        terminal_error_code: terminal_error_code.map(str::to_string),
        accepted_at_seq,
        seal,
    })
}

fn auth_tag(
    auth: &AuthenticatedDeviceSession,
    envelope: &HostCommandEnvelope,
) -> Result<String, ConnectorError> {
    #[derive(Serialize)]
    struct AuthenticationMaterial<'a> {
        domain: &'static str,
        principal_id: &'a str,
        version: &'a str,
        capability_id: &'a str,
        request_id: &'a str,
        run_id: &'a str,
        session_id: &'a str,
        device_id: &'a str,
        pairing_epoch: u64,
        nonce: &'a str,
        command_seq: u64,
        expected_snapshot_seq: u64,
        expected_snapshot_digest: &'a str,
        issued_at: &'a str,
        expires_at: &'a str,
        command: &'a HostCommand,
    }
    let mut material = serde_json::to_vec(&AuthenticationMaterial {
        domain: "nomad.host-command.authentication.v1",
        principal_id: &auth.principal_id,
        version: &envelope.version,
        capability_id: &envelope.capability_id,
        request_id: &envelope.request_id,
        run_id: &envelope.run_id,
        session_id: &envelope.session_id,
        device_id: &envelope.device_id,
        pairing_epoch: envelope.pairing_epoch,
        nonce: &envelope.nonce,
        command_seq: envelope.command_seq,
        expected_snapshot_seq: envelope.expected_snapshot_seq,
        expected_snapshot_digest: &envelope.expected_snapshot_digest,
        issued_at: &envelope.issued_at,
        expires_at: &envelope.expires_at,
        command: &envelope.command,
    })?;
    let result = keyed_digest(&auth.command_key, b"authentication-v1", &material);
    material.zeroize();
    Ok(result)
}

fn keyed_digest(master_key: &[u8; 32], purpose: &[u8], material: &[u8]) -> String {
    let mut mac = keyed_mac(master_key, purpose, material);
    let result = hex(&mac);
    mac.zeroize();
    result
}

fn keyed_mac(master_key: &[u8; 32], purpose: &[u8], material: &[u8]) -> [u8; 32] {
    let mut derivation_material = Vec::with_capacity(VERSION.len() + purpose.len() + 24);
    derivation_material.extend_from_slice(b"nomad.host-command.kdf.v1");
    derivation_material.extend_from_slice(&(purpose.len() as u64).to_be_bytes());
    derivation_material.extend_from_slice(purpose);
    let mut subkey = crate::run_binding::hmac_sha256(master_key, &derivation_material);
    derivation_material.zeroize();

    let mut mac_material = Vec::with_capacity(material.len() + purpose.len() + 24);
    mac_material.extend_from_slice(b"nomad.host-command.mac.v1");
    mac_material.extend_from_slice(&(purpose.len() as u64).to_be_bytes());
    mac_material.extend_from_slice(purpose);
    mac_material.extend_from_slice(&(material.len() as u64).to_be_bytes());
    mac_material.extend_from_slice(material);
    let mac = crate::run_binding::hmac_sha256(&subkey, &mac_material);
    subkey.zeroize();
    mac_material.zeroize();
    mac
}

fn strict_time(value: &str) -> Result<OffsetDateTime, ConnectorError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return Err(ConnectorError::ExpiredRequest(
            "invalid command time".into(),
        ));
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ConnectorError::ExpiredRequest("invalid command time".into()))
}
fn receipt_time(value: OffsetDateTime) -> Result<String, ConnectorError> {
    let value = value
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|_| blocked("receipt time unavailable"))?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    ))
}
fn safe_id(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
}
fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0_u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn random_receipt_id() -> Result<String, ConnectorError> {
    random_public_id("rcpt")
}
fn random_proof_id() -> Result<String, ConnectorError> {
    random_public_id("proof")
}
fn random_public_id(prefix: &str) -> Result<String, ConnectorError> {
    let mut raw = [0_u8; 16];
    getrandom::getrandom(&mut raw).map_err(|_| blocked("receipt id unavailable"))?;
    let receipt_id = format!("{prefix}_{}", hex(&raw));
    raw.zeroize();
    Ok(receipt_id)
}
fn blocked(message: &str) -> ConnectorError {
    ConnectorError::SafetyBlocked(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    struct State(CurrentCommandState);
    impl TrustedCommandState for State {
        fn refresh_current(&self, _: &str) -> Result<CurrentCommandState, ConnectorError> {
            Ok(self.0.clone())
        }
    }
    struct Reconciler(AuthoritativeReconciliationFacts);
    impl TrustedCommandReconciler for Reconciler {
        fn verify_terminal_outcome(
            &self,
            _: &str,
        ) -> Result<AuthoritativeReconciliationFacts, ConnectorError> {
            Ok(AuthoritativeReconciliationFacts {
                principal_id: self.0.principal_id.clone(),
                device_id: self.0.device_id.clone(),
                run_id: self.0.run_id.clone(),
                session_id: self.0.session_id.clone(),
                pairing_epoch: self.0.pairing_epoch,
                request_id: self.0.request_id.clone(),
                terminal: match self.0.terminal {
                    ReconciledTerminal::Completed { accepted_at_seq } => {
                        ReconciledTerminal::Completed { accepted_at_seq }
                    }
                    ReconciledTerminal::Rejected { error_code } => {
                        ReconciledTerminal::Rejected { error_code }
                    }
                },
                snapshot_seq: self.0.snapshot_seq,
                snapshot_digest: self.0.snapshot_digest.clone(),
            })
        }
    }
    struct Adapter(Rc<Cell<u32>>, AdapterOutcome);
    impl AgentCommandAdapter for Adapter {
        fn execute_once(
            &self,
            command: AuthorizedHostCommand,
        ) -> Result<AdapterOutcome, ConnectorError> {
            let _ = (command.request_id(), command.action());
            self.0.set(self.0.get() + 1);
            Ok(match self.1 {
                AdapterOutcome::Completed { accepted_at_seq } => {
                    AdapterOutcome::Completed { accepted_at_seq }
                }
                AdapterOutcome::Rejected { error_code } => AdapterOutcome::Rejected { error_code },
                AdapterOutcome::OutcomeUnknown => AdapterOutcome::OutcomeUnknown,
            })
        }
    }
    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-08-25T09:00:30Z", &Rfc3339).unwrap()
    }
    fn auth() -> AuthenticatedDeviceSession {
        AuthenticatedDeviceSession {
            principal_id: "p1".into(),
            device_id: "d1".into(),
            run_id: "r1".into(),
            session_id: "s1".into(),
            pairing_epoch: 1,
            command_key: [7; 32],
            revoked: false,
        }
    }
    fn state() -> CurrentCommandState {
        CurrentCommandState {
            run_id: "r1".into(),
            session_id: "s1".into(),
            snapshot_seq: 9,
            snapshot_digest: format!("sha256:{}", "a".repeat(64)),
            next_command_seq: 1,
            online: true,
            live: true,
            reconciliation_pending: false,
            active_turn_id: Some("t1".into()),
            active_input_id: Some("q1".into()),
            active_permission: Some(CurrentPermission {
                permission_id: "perm1".into(),
                action_hash: format!("sha256:{}", "b".repeat(64)),
                expires_at: "2026-08-25T09:01:00Z".into(),
            }),
        }
    }
    fn reconciliation(request_id: &str) -> Reconciler {
        Reconciler(AuthoritativeReconciliationFacts {
            principal_id: "p1".into(),
            device_id: "d1".into(),
            run_id: "r1".into(),
            session_id: "s1".into(),
            pairing_epoch: 1,
            request_id: request_id.into(),
            terminal: ReconciledTerminal::Completed { accepted_at_seq: 9 },
            snapshot_seq: 9,
            snapshot_digest: format!("sha256:{}", "a".repeat(64)),
        })
    }
    fn envelope(command: HostCommand) -> HostCommandEnvelope {
        let auth = auth();
        let mut e = HostCommandEnvelope {
            version: VERSION.into(),
            capability_id: "capability-1".into(),
            request_id: "request-abc".into(),
            run_id: "r1".into(),
            session_id: "s1".into(),
            device_id: "d1".into(),
            pairing_epoch: 1,
            nonce: "nonce1".into(),
            command_seq: 1,
            expected_snapshot_seq: 9,
            expected_snapshot_digest: format!("sha256:{}", "a".repeat(64)),
            issued_at: "2026-08-25T09:00:00Z".into(),
            expires_at: "2026-08-25T09:01:00Z".into(),
            command,
            auth_tag: String::new(),
        };
        e.auth_tag = auth_tag(&auth, &e).unwrap();
        e
    }
    fn resign(auth: &AuthenticatedDeviceSession, envelope: &mut HostCommandEnvelope) {
        envelope.auth_tag = auth_tag(auth, envelope).unwrap();
    }
    fn run(command: HostCommand) -> (HostCommandReceipt, u32) {
        let j = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &j,
        );
        let raw = serde_json::to_vec(&envelope(command)).unwrap();
        let first = authority.execute_json_at(&auth(), &raw, now()).unwrap();
        let replay = authority.execute_json_at(&auth(), &raw, now()).unwrap();
        assert!(replay.idempotent_replay);
        assert_eq!(first.receipt_id, replay.receipt_id);
        (first, calls.get())
    }
    #[test]
    fn reply_deny_stop_execute_exactly_once() {
        for command in [
            HostCommand::Reply(ReplyBody {
                target_turn_id: "t1".into(),
                target_input_id: "q1".into(),
                content: "answer".into(),
            }),
            HostCommand::Deny(DenyBody {
                permission_id: "perm1".into(),
                action_hash: format!("sha256:{}", "b".repeat(64)),
                permission_expires_at: "2026-08-25T09:01:00Z".into(),
            }),
            HostCommand::Stop(StopBody {
                target_turn_id: "t1".into(),
            }),
        ] {
            let (receipt, calls) = run(command);
            assert_eq!(receipt.status, "DispatchAcknowledged");
            assert_eq!(calls, 1);
        }
    }
    #[test]
    fn unknown_allow_once_expired_tamper_and_stale_are_zero_call() {
        let j = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &j,
        );
        for raw in [
            br#"{"action":"allow_once"}"#.to_vec(),
            br#"{"action":"always"}"#.to_vec(),
            br#"{"action":"question_reject"}"#.to_vec(),
            br#"{"action":"interrupt_and_send"}"#.to_vec(),
            br#"{"action":"future_action"}"#.to_vec(),
            br#"{}"#.to_vec(),
        ] {
            assert!(authority.execute_json_at(&auth(), &raw, now()).is_err());
        }
        let mut expired = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        expired.expires_at = "2026-08-25T09:00:30Z".into();
        expired.auth_tag = auth_tag(&auth(), &expired).unwrap();
        assert!(authority.execute(&auth(), expired, now()).is_err());
        let mut tampered = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        tampered.command_seq = 2;
        assert!(authority.execute(&auth(), tampered, now()).is_err());
        assert_eq!(calls.get(), 0);
    }
    #[test]
    fn binding_conflict_and_inflight_replay_never_dispatch_twice() {
        let j = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(calls.clone(), AdapterOutcome::OutcomeUnknown),
            &j,
        );
        let one = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        let receipt = authority.execute(&auth(), one, now()).unwrap();
        assert_eq!(receipt.status, "OutcomeUnknown");
        let mut changed = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        changed.nonce = "other".into();
        changed.auth_tag = auth_tag(&auth(), &changed).unwrap();
        assert!(authority.execute(&auth(), changed, now()).is_err());
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn command_sequence_and_nonce_are_unique_inside_authority_scope() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &journal,
        );
        let first = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        authority.execute(&auth(), first, now()).unwrap();

        let mut same_seq = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        same_seq.request_id = "request-other".into();
        same_seq.nonce = "nonce-other".into();
        same_seq.auth_tag = auth_tag(&auth(), &same_seq).unwrap();
        assert!(authority.execute(&auth(), same_seq, now()).is_err());

        let mut same_nonce = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        same_nonce.request_id = "request-third".into();
        same_nonce.command_seq = 2;
        same_nonce.auth_tag = auth_tag(&auth(), &same_nonce).unwrap();
        let mut next = state();
        next.next_command_seq = 2;
        let next_authority = HostCommandAuthority::new(
            State(next),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 11,
                },
            ),
            &journal,
        );
        assert!(next_authority.execute(&auth(), same_nonce, now()).is_err());
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn receipt_is_content_safe() {
        let (receipt, _) = run(HostCommand::Reply(ReplyBody {
            target_turn_id: "t1".into(),
            target_input_id: "q1".into(),
            content: "SECRET_REPLY".into(),
        }));
        let text = format!("{:?} {}", receipt, serde_json::to_string(&receipt).unwrap());
        for forbidden in ["SECRET_REPLY", "perm1", "sha256:"] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn rejected_adapter_outcome_is_terminal() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Rejected {
                    error_code: "ERR_PERMISSION_DENIED",
                },
            ),
            &journal,
        );
        let receipt = authority
            .execute(
                &auth(),
                envelope(HostCommand::Deny(DenyBody {
                    permission_id: "perm1".into(),
                    action_hash: format!("sha256:{}", "b".repeat(64)),
                    permission_expires_at: "2026-08-25T09:01:00Z".into(),
                })),
                now(),
            )
            .unwrap();
        assert_eq!(receipt.status, "Rejected");
        assert_eq!(receipt.error_code.as_deref(), Some("ERR_PERMISSION_DENIED"));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn adapter_detail_is_never_exposed_as_a_browser_error_code() {
        let journal = CommandJournal::open_memory().unwrap();
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                Rc::new(Cell::new(0)),
                AdapterOutcome::Rejected {
                    error_code: "provider HTTP 500 SECRET",
                },
            ),
            &journal,
        );
        let receipt = authority
            .execute(
                &auth(),
                envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "t1".into(),
                })),
                now(),
            )
            .unwrap();
        assert_eq!(receipt.error_code.as_deref(), Some("ERR_COMMAND_REJECTED"));
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("provider"));
        assert!(!serialized.contains("SECRET"));
    }

    #[test]
    fn duplicate_json_key_is_rejected_before_state_or_adapter() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &journal,
        );
        let raw = br#"{"version":"nomad.host-command.v1","version":"nomad.host-command.v1"}"#;
        assert!(authority.execute_json_at(&auth(), raw, now()).is_err());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn trailing_and_oversize_envelopes_fail_before_adapter() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &journal,
        );
        let mut trailing = serde_json::to_vec(&envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        })))
        .unwrap();
        trailing.extend_from_slice(b" trailing");
        assert!(authority
            .execute_json_at(&auth(), &trailing, now())
            .is_err());
        assert!(authority
            .execute_json_at(&auth(), &vec![b'x'; MAX_WIRE_BYTES + 1], now())
            .is_err());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn every_authenticated_field_and_principal_is_mac_bound() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &journal,
        );
        let base = envelope(HostCommand::Reply(ReplyBody {
            target_turn_id: "t1".into(),
            target_input_id: "q1".into(),
            content: "answer".into(),
        }));
        let mut cases = Vec::new();
        macro_rules! tamper {
            ($field:ident, $value:expr) => {{
                let mut changed = base.clone();
                changed.$field = $value;
                cases.push(changed);
            }};
        }
        tamper!(version, "nomad.host-command.v2".into());
        tamper!(capability_id, "capability-other".into());
        tamper!(request_id, "request-other".into());
        tamper!(run_id, "r2".into());
        tamper!(session_id, "s2".into());
        tamper!(device_id, "d2".into());
        tamper!(pairing_epoch, 2);
        tamper!(nonce, "nonce-other".into());
        tamper!(command_seq, 2);
        tamper!(expected_snapshot_seq, 10);
        tamper!(
            expected_snapshot_digest,
            format!("sha256:{}", "c".repeat(64))
        );
        tamper!(issued_at, "2026-08-25T09:00:01Z".into());
        tamper!(expires_at, "2026-08-25T09:00:59Z".into());
        let mut changed_command = base.clone();
        changed_command.command = HostCommand::Reply(ReplyBody {
            target_turn_id: "t1".into(),
            target_input_id: "q1".into(),
            content: "different".into(),
        });
        cases.push(changed_command);
        for changed in cases {
            assert!(authority.execute(&auth(), changed, now()).is_err());
        }

        let mut other_principal = auth();
        other_principal.principal_id = "p2".into();
        assert!(authority.execute(&other_principal, base, now()).is_err());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn future_zero_length_long_ttl_and_noncanonical_times_fail_closed() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &journal,
        );
        let session = auth();
        let mut cases = Vec::new();
        let mut future = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        future.issued_at = "2026-08-25T09:00:31Z".into();
        future.expires_at = "2026-08-25T09:01:00Z".into();
        cases.push(future);
        let mut zero = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        zero.expires_at = zero.issued_at.clone();
        cases.push(zero);
        let mut long = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        long.expires_at = "2026-08-25T09:01:01Z".into();
        cases.push(long);
        let mut fractional = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        fractional.issued_at = "2026-08-25T09:00:00.0Z".into();
        cases.push(fractional);
        for mut command in cases {
            resign(&session, &mut command);
            assert!(authority.execute(&session, command, now()).is_err());
        }
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn offline_not_live_and_state_reconciliation_are_zero_call() {
        for mutate in [
            |state: &mut CurrentCommandState| state.online = false,
            |state: &mut CurrentCommandState| state.live = false,
            |state: &mut CurrentCommandState| state.reconciliation_pending = true,
        ] {
            let journal = CommandJournal::open_memory().unwrap();
            let calls = Rc::new(Cell::new(0));
            let mut current = state();
            mutate(&mut current);
            let authority = HostCommandAuthority::new(
                State(current),
                Adapter(
                    calls.clone(),
                    AdapterOutcome::Completed {
                        accepted_at_seq: 10,
                    },
                ),
                &journal,
            );
            assert!(authority
                .execute(
                    &auth(),
                    envelope(HostCommand::Stop(StopBody {
                        target_turn_id: "t1".into(),
                    })),
                    now(),
                )
                .is_err());
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn signed_snapshot_and_target_mismatches_are_zero_call() {
        let base_state = state();
        let session = auth();
        let cases = [
            {
                let mut command = envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "t1".into(),
                }));
                command.expected_snapshot_seq = 8;
                resign(&session, &mut command);
                command
            },
            {
                let mut command = envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "t1".into(),
                }));
                command.expected_snapshot_digest = format!("sha256:{}", "c".repeat(64));
                resign(&session, &mut command);
                command
            },
            {
                let mut command = envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "other-turn".into(),
                }));
                resign(&session, &mut command);
                command
            },
            {
                let mut command = envelope(HostCommand::Reply(ReplyBody {
                    target_turn_id: "t1".into(),
                    target_input_id: "other-input".into(),
                    content: "answer".into(),
                }));
                resign(&session, &mut command);
                command
            },
            {
                let mut command = envelope(HostCommand::Deny(DenyBody {
                    permission_id: "perm1".into(),
                    action_hash: format!("sha256:{}", "c".repeat(64)),
                    permission_expires_at: "2026-08-25T09:01:00Z".into(),
                }));
                resign(&session, &mut command);
                command
            },
        ];
        for command in cases {
            let journal = CommandJournal::open_memory().unwrap();
            let calls = Rc::new(Cell::new(0));
            let authority = HostCommandAuthority::new(
                State(base_state.clone()),
                Adapter(
                    calls.clone(),
                    AdapterOutcome::Completed {
                        accepted_at_seq: 10,
                    },
                ),
                &journal,
            );
            assert!(authority.execute(&session, command, now()).is_err());
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn outcome_unknown_blocks_next_request_until_authenticated_reconciliation() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let session = auth();
        let scope = authority_scope(&session).unwrap();
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(calls.clone(), AdapterOutcome::OutcomeUnknown),
            &journal,
        );
        let first = authority
            .execute(
                &session,
                envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "t1".into(),
                })),
                now(),
            )
            .unwrap();
        assert_eq!(first.status, "OutcomeUnknown");
        assert!(journal
            .host_authority_reconciliation_required(&scope)
            .unwrap());

        let mut second = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        second.request_id = "request-second".into();
        second.command_seq = 2;
        second.nonce = "nonce-second".into();
        resign(&session, &mut second);
        let mut next = state();
        next.next_command_seq = 2;
        let blocked_authority = HostCommandAuthority::new(
            State(next.clone()),
            Adapter(calls.clone(), AdapterOutcome::OutcomeUnknown),
            &journal,
        );
        assert!(matches!(
            blocked_authority.execute(&session, second.clone(), now()),
            Err(ConnectorError::OutcomeUnknown)
        ));
        assert_eq!(calls.get(), 1);

        assert!(matches!(
            blocked_authority.complete_authenticated_reconciliation(
                &session,
                "request-other",
                &reconciliation("request-other"),
            ),
            Err(ConnectorError::StaleRequest(_))
        ));
        assert!(journal
            .host_authority_reconciliation_required(&scope)
            .unwrap());
        blocked_authority
            .complete_authenticated_reconciliation(
                &session,
                "request-abc",
                &reconciliation("request-abc"),
            )
            .unwrap();
        assert!(!journal
            .host_authority_reconciliation_required(&scope)
            .unwrap());
        let completed = HostCommandAuthority::new(
            State(next),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 11,
                },
            ),
            &journal,
        )
        .execute(&session, second, now())
        .unwrap();
        assert_eq!(completed.status, "DispatchAcknowledged");
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn reconciliation_requires_trusted_bound_terminal_facts() {
        type FactsMutation = Box<dyn Fn(&mut AuthoritativeReconciliationFacts)>;
        let mutations: Vec<FactsMutation> = vec![
            Box::new(|facts| facts.principal_id = "other-principal".into()),
            Box::new(|facts| facts.device_id = "other-device".into()),
            Box::new(|facts| facts.run_id = "other-run".into()),
            Box::new(|facts| facts.session_id = "other-session".into()),
            Box::new(|facts| facts.pairing_epoch += 1),
            Box::new(|facts| facts.request_id = "other-request".into()),
            Box::new(|facts| facts.snapshot_seq += 1),
            Box::new(|facts| facts.snapshot_digest = format!("sha256:{}", "c".repeat(64))),
        ];
        for mutate in mutations {
            let journal = CommandJournal::open_memory().unwrap();
            let session = auth();
            let authority = HostCommandAuthority::new(
                State(state()),
                Adapter(Rc::new(Cell::new(0)), AdapterOutcome::OutcomeUnknown),
                &journal,
            );
            authority
                .execute(
                    &session,
                    envelope(HostCommand::Stop(StopBody {
                        target_turn_id: "t1".into(),
                    })),
                    now(),
                )
                .unwrap();
            let mut facts = reconciliation("request-abc").0;
            mutate(&mut facts);
            assert!(matches!(
                authority.complete_authenticated_reconciliation(
                    &session,
                    "request-abc",
                    &Reconciler(facts),
                ),
                Err(ConnectorError::StaleRequest(_))
            ));
            assert!(journal
                .host_authority_reconciliation_required(&authority_scope(&session).unwrap())
                .unwrap());
        }

        let journal = CommandJournal::open_memory().unwrap();
        let mut revoked = auth();
        let valid = auth();
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(Rc::new(Cell::new(0)), AdapterOutcome::OutcomeUnknown),
            &journal,
        );
        authority
            .execute(
                &valid,
                envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "t1".into(),
                })),
                now(),
            )
            .unwrap();
        revoked.revoked = true;
        assert!(matches!(
            authority.complete_authenticated_reconciliation(
                &revoked,
                "request-abc",
                &reconciliation("request-abc"),
            ),
            Err(ConnectorError::SafetyBlocked(_))
        ));
    }

    #[test]
    fn reconciliation_proof_is_single_use_and_debug_is_redacted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.db");
        let session = auth();
        let scope = authority_scope(&session).unwrap();
        let journal = CommandJournal::open(&path).unwrap();
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(Rc::new(Cell::new(0)), AdapterOutcome::OutcomeUnknown),
            &journal,
        );
        authority
            .execute(
                &session,
                envelope(HostCommand::Stop(StopBody {
                    target_turn_id: "t1".into(),
                })),
                now(),
            )
            .unwrap();
        let facts = reconciliation("request-abc").0;
        let proof = seal_reconciliation(
            &session,
            &scope,
            "request-abc",
            &facts,
            "Completed",
            Some(10),
            None,
        )
        .unwrap();
        let replay_copy = proof.duplicate_for_replay_test();
        let debug = format!("{session:?} {proof:?}");
        for secret in ["p1", "d1", "r1", "s1", &hex(&session.command_key)] {
            assert!(!debug.contains(secret));
        }
        let receipt = HostCommandReceipt {
            receipt_id: "rcpt_reconciled".into(),
            request_id: "request-abc".into(),
            kind: "stop".into(),
            accepted_at: "2026-08-25 9:00:30.0 +00:00:00".into(),
            status: "Completed".into(),
            error_code: None,
            accepted_at_seq: Some(10),
            idempotent_replay: false,
        };
        journal
            .reconcile_host_authority(proof, &serde_json::to_string(&receipt).unwrap())
            .unwrap();
        assert!(matches!(
            journal
                .reconcile_host_authority(replay_copy, &serde_json::to_string(&receipt).unwrap()),
            Err(ConnectorError::StaleRequest(_))
        ));
    }

    #[test]
    fn terminal_replay_is_byte_stable_except_for_replay_flag() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Rejected {
                    error_code: "ERR_PERMISSION_DENIED",
                },
            ),
            &journal,
        );
        let command = envelope(HostCommand::Deny(DenyBody {
            permission_id: "perm1".into(),
            action_hash: format!("sha256:{}", "b".repeat(64)),
            permission_expires_at: "2026-08-25T09:01:00Z".into(),
        }));
        let first = authority.execute(&auth(), command.clone(), now()).unwrap();
        let replay = authority.execute(&auth(), command, now()).unwrap();
        assert_eq!(first.receipt_id, replay.receipt_id);
        assert_eq!(first.request_id, replay.request_id);
        assert_eq!(first.kind, replay.kind);
        assert_eq!(first.status, replay.status);
        assert_eq!(first.error_code, replay.error_code);
        assert_eq!(first.accepted_at_seq, replay.accepted_at_seq);
        assert!(!first.idempotent_replay);
        assert!(replay.idempotent_replay);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn terminal_replay_survives_file_database_reopen_without_adapter_call() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.db");
        let command = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        let first_calls = Rc::new(Cell::new(0));
        let first = {
            let journal = CommandJournal::open(&path).unwrap();
            HostCommandAuthority::new(
                State(state()),
                Adapter(
                    first_calls.clone(),
                    AdapterOutcome::Completed {
                        accepted_at_seq: 10,
                    },
                ),
                &journal,
            )
            .execute(&auth(), command.clone(), now())
            .unwrap()
        };
        assert_eq!(first_calls.get(), 1);

        let replay_calls = Rc::new(Cell::new(0));
        let replay = {
            let journal = CommandJournal::open(&path).unwrap();
            HostCommandAuthority::new(
                State(state()),
                Adapter(replay_calls.clone(), AdapterOutcome::OutcomeUnknown),
                &journal,
            )
            .execute(&auth(), command, now())
            .unwrap()
        };
        assert_eq!(first.receipt_id, replay.receipt_id);
        assert_eq!(first.status, replay.status);
        assert_eq!(first.accepted_at_seq, replay.accepted_at_seq);
        assert!(replay.idempotent_replay);
        assert_eq!(replay_calls.get(), 0);
    }

    #[test]
    fn binding_digest_is_keyed_and_not_a_plain_low_entropy_content_hash() {
        let command = envelope(HostCommand::Reply(ReplyBody {
            target_turn_id: "t1".into(),
            target_input_id: "q1".into(),
            content: "yes".into(),
        }));
        let first = binding_digest(&auth(), &command).unwrap();
        let mut other_key = auth();
        other_key.command_key = [8; 32];
        let second = binding_digest(&other_key, &command).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert!(!first.contains("yes"));
    }

    #[test]
    fn capability_is_mac_and_replay_bound_before_adapter() {
        let journal = CommandJournal::open_memory().unwrap();
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(state()),
            Adapter(
                calls.clone(),
                AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                },
            ),
            &journal,
        );
        let original = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        let mut unauthenticated_change = original.clone();
        unauthenticated_change.capability_id = "capability-other".into();
        assert!(authority
            .execute(&auth(), unauthenticated_change, now())
            .is_err());
        assert_eq!(calls.get(), 0);

        authority.execute(&auth(), original, now()).unwrap();
        let mut changed_binding = envelope(HostCommand::Stop(StopBody {
            target_turn_id: "t1".into(),
        }));
        changed_binding.capability_id = "capability-other".into();
        resign(&auth(), &mut changed_binding);
        assert!(matches!(
            authority.execute(&auth(), changed_binding, now()),
            Err(ConnectorError::StaleRequest(_))
        ));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn resolved_local_signs_internally_and_journal_bytes_are_content_safe() {
        struct CanaryAdapter(Rc<Cell<u32>>, &'static str);
        impl AgentCommandAdapter for CanaryAdapter {
            fn execute_once(
                &self,
                command: AuthorizedHostCommand,
            ) -> Result<AdapterOutcome, ConnectorError> {
                assert_eq!(self.1, "RAW_SESSION_ID_CANARY");
                assert_eq!(command.request_id(), "safe-request");
                assert_eq!(command.action(), "reply");
                self.0.set(self.0.get() + 1);
                Ok(AdapterOutcome::Completed {
                    accepted_at_seq: 10,
                })
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.db");
        let journal = CommandJournal::open(&path).unwrap();
        let auth = AuthenticatedDeviceSession::new_local(
            "principal-alias".into(),
            "device-alias".into(),
            "run-alias".into(),
            "session-alias".into(),
            1,
            [b'K'; 32],
        )
        .unwrap();
        let mut current = state();
        current.run_id = "run-alias".into();
        current.session_id = "session-alias".into();
        current.active_turn_id = Some("turn-alias".into());
        current.active_input_id = Some("input-alias".into());
        let calls = Rc::new(Cell::new(0));
        let authority = HostCommandAuthority::new(
            State(current),
            CanaryAdapter(calls.clone(), "RAW_SESSION_ID_CANARY"),
            &journal,
        );
        let request = ResolvedHostCommandRequest::new(
            "CAPABILITY_SECRET_CANARY".into(),
            "safe-request".into(),
            "safe-nonce".into(),
            1,
            9,
            format!("sha256:{}", "a".repeat(64)),
            "2026-08-25T09:00:00Z".into(),
            "2026-08-25T09:01:00Z".into(),
            HostCommand::reply(
                "turn-alias".into(),
                "input-alias".into(),
                "REPLY_CONTENT_CANARY".into(),
            )
            .unwrap(),
        )
        .unwrap();
        let receipt = authority
            .execute_resolved_local_at(&auth, request, now())
            .unwrap();
        assert_eq!(receipt.status, "DispatchAcknowledged");
        assert_eq!(calls.get(), 1);
        drop(authority);
        drop(journal);

        let mut database_bytes = Vec::new();
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("authority.db")
            {
                database_bytes.extend(std::fs::read(entry.path()).unwrap());
            }
        }
        let database = String::from_utf8_lossy(&database_bytes);
        for forbidden in [
            "RAW_SESSION_ID_CANARY",
            "REPLY_CONTENT_CANARY",
            "CAPABILITY_SECRET_CANARY",
            "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
        ] {
            assert!(!database.contains(forbidden), "leaked {forbidden}");
        }
        assert!(database.contains("session-alias"));
    }
}
