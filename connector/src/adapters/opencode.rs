//! Public OpenCode adapter surface.
//!
//! OpenCode-specific types and operations are intentionally collected under
//! this namespace so the crate root remains agent-neutral.
//!
//! ```
//! use nomad_connector::adapters::opencode::{PilotAdapter, UreqOpenCodeClient};
//! let _ = std::any::type_name::<PilotAdapter<UreqOpenCodeClient>>();
//! ```
//!
//! ```compile_fail
//! use nomad_connector::PilotAdapter;
//! ```
//!
//! ```compile_fail
//! use nomad_connector::nomad_host_entrypoint;
//! ```

pub use crate::alpha_projector::{
    build_alpha_projection, canonical_json as alpha_canonical_json, projection_digest,
    projection_payload_bytes, run_alpha_projector, sign_projection_envelope, AlphaProjectorConfig,
    AlphaProjectorReceipt, AlphaReadonlyChanges, AlphaReadonlyEvent, AlphaReadonlyProjection,
    AlphaReadonlyProvenance, AlphaReadonlySession,
};
pub use crate::opencode_adapter::{
    AdapterCommandResult, CaptureSource, FileDiff, OpenCodeClient, OpenCodeCommandResponse,
    OpenCodeEvent, OpenCodeSession, PilotAdapter, PilotCapture, PilotCommand, UreqOpenCodeClient,
};
pub use crate::pilot_bridge::{parse_pilot_command, result_payload};
pub use crate::stock_event_adapter::{
    observe_official_stock_envelope, OfficialStockObservation, StockEventClassification,
    StockEventEnvelopeError, STOCK_EVENT_EVIDENCE_CLASS,
};
pub use crate::stock_opencode::{
    adapter_support_matrix, current_release_authorization, AdapterSupportMatrix,
    CapabilityIssuanceRules, CurrentReleaseAuthorization, FailClosedRules, M2ActionDigests,
    M2CapabilityReceipts, NoCapabilityRules, PendingInputRules, RealLifecycleEvidence,
    StockBlockedCommandResult, StockCommand, StockCommandBoundary, StockCommandHttp,
    StockCommandRequest, StockCommandResult, StockCommandTransport, StockHttpRequest,
    StockObservationOutcome, StockOpenCodeAdapter, StockReconciliation,
    StockReconciliationStatus, StockSnapshotFacts, UreqStockCommandHttp,
    VerifiedM2Capabilities, APPROVAL_EXPIRED_OR_INVALID, COMMAND_SHAPE_SOURCE,
    REAL_LIFECYCLE_EVIDENCE_REQUIRED, STOCK_VERSION,
};
pub use crate::stock_snapshot::{
    project_stock_snapshot, StockReadonlySnapshot, STOCK_SNAPSHOT_EVIDENCE_CLASS,
};
pub use crate::url_gate::{
    check_version, validate_loopback, EXPECTED_BASE_URL, EXPECTED_COMMIT, EXPECTED_HOSTNAME,
    EXPECTED_PORT, EXPECTED_VERSION,
};

/// OpenCode-specific startup and release-authority entrypoints. These are not
/// agent-neutral crate-root APIs.
pub mod startup {
    pub use crate::host_startup::{
        nomad_host_entrypoint, HostStartupError, HOST_PREREQUISITES_BLOCKED,
        HOST_PREREQUISITES_VERIFIED,
    };
    pub use crate::native_supervisor::{
        native_supervisor_entrypoint, NativeSupervisorError, NATIVE_SUPERVISOR_BLOCKED,
    };
}

// C3 deliberately has a concrete OpenCode dispatcher, not a generic Agent
// command trait. Raw IDs enter only through crate-private constructors.
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const C3_MAX_SUCCESS_BODY: u64 = 4096;
const C3_MAX_FACT_ROUTE_BODY: usize = 4 * 1024 * 1024;
const C3_CAPABILITY_SCHEMA: &str = "nomad.product-host.command-capability.v1";
const C3_CAPABILITY_SECONDS: i64 = 30;

/// One of the only three upstream commands admitted by C3.
pub(crate) enum OpenCodeCommand {
    Reply {
        raw_session: Zeroizing<String>,
        raw_question: Zeroizing<String>,
        content: Zeroizing<String>,
    },
    Deny {
        raw_session: Zeroizing<String>,
        raw_permission: Zeroizing<String>,
    },
    Stop {
        raw_session: Zeroizing<String>,
    },
}

impl OpenCodeCommand {
    fn reply(raw_session: String, raw_question: String, content: String) -> Self {
        Self::Reply {
            raw_session: Zeroizing::new(raw_session),
            raw_question: Zeroizing::new(raw_question),
            content: Zeroizing::new(content),
        }
    }

    fn deny(raw_session: String, raw_permission: String) -> Self {
        Self::Deny {
            raw_session: Zeroizing::new(raw_session),
            raw_permission: Zeroizing::new(raw_permission),
        }
    }

    fn stop(raw_session: String) -> Self {
        Self::Stop {
            raw_session: Zeroizing::new(raw_session),
        }
    }
}

impl fmt::Debug for OpenCodeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self {
            Self::Reply { .. } => "Reply",
            Self::Deny { .. } => "Deny",
            Self::Stop { .. } => "Stop",
        };
        formatter
            .debug_struct("OpenCodeCommand")
            .field("action", &action)
            .field("raw_fields", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenCodeDispatchOutcome {
    DispatchAcknowledged,
    Rejected { error_code: &'static str },
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OpenCodeDispatcherError {
    #[error("OpenCode command dispatcher configuration rejected")]
    InvalidConfiguration,
}

#[derive(Clone)]
pub(crate) struct OpenCodeCommandDispatcher {
    origin: String,
    authorization: Arc<Zeroizing<String>>,
    agent: ureq::Agent,
}

impl fmt::Debug for OpenCodeCommandDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenCodeCommandDispatcher(<redacted>)")
    }
}

impl OpenCodeCommandDispatcher {
    /// Builds the production dispatcher for the exact owned OpenCode origin
    /// received from Host bootstrap. Origin and credential remain Host-only.
    pub(crate) fn new(
        origin: &str,
        server_password: Zeroizing<String>,
    ) -> Result<Self, OpenCodeDispatcherError> {
        Self::build(origin, server_password, Duration::from_secs(5))
    }

    fn build(
        origin: &str,
        server_password: Zeroizing<String>,
        timeout: Duration,
    ) -> Result<Self, OpenCodeDispatcherError> {
        validate_dispatch_origin(origin)?;
        let mut userinfo = Zeroizing::new(String::from("opencode:"));
        userinfo.push_str(server_password.as_str());
        let authorization = Arc::new(Zeroizing::new(format!(
            "Basic {}",
            BASE64_STANDARD.encode(userinfo.as_bytes())
        )));
        userinfo.zeroize();
        drop(server_password);
        Ok(Self {
            origin: origin.trim_end_matches('/').to_string(),
            authorization,
            agent: ureq::AgentBuilder::new()
                .try_proxy_from_env(false)
                .redirects(0)
                .timeout_connect(timeout)
                .timeout_read(timeout)
                .timeout_write(timeout)
                .build(),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        origin: &str,
        server_password: Zeroizing<String>,
    ) -> Result<Self, OpenCodeDispatcherError> {
        Self::build(origin, server_password, Duration::from_secs(2))
    }

    /// Performs exactly one POST. Any ambiguous transport or malformed 2xx
    /// response is OutcomeUnknown and is never retried here.
    pub(crate) fn dispatch_once(&self, command: OpenCodeCommand) -> OpenCodeDispatchOutcome {
        let (segments, body) = match command {
            OpenCodeCommand::Reply {
                raw_session,
                raw_question,
                content,
            } => {
                let body = match serde_json::to_vec(&serde_json::json!({
                    "answers": [[content.as_str()]]
                })) {
                    Ok(body) => Zeroizing::new(body),
                    Err(_) => return OpenCodeDispatchOutcome::OutcomeUnknown,
                };
                (
                    vec![
                        "api".into(),
                        "session".into(),
                        raw_session.to_string(),
                        "question".into(),
                        raw_question.to_string(),
                        "reply".into(),
                    ],
                    Some(body),
                )
            }
            OpenCodeCommand::Deny {
                raw_session,
                raw_permission,
            } => (
                vec![
                    "api".into(),
                    "session".into(),
                    raw_session.to_string(),
                    "permission".into(),
                    raw_permission.to_string(),
                    "reply".into(),
                ],
                Some(Zeroizing::new(br#"{"reply":"reject"}"#.to_vec())),
            ),
            OpenCodeCommand::Stop { raw_session } => (
                vec![
                    "api".into(),
                    "session".into(),
                    raw_session.to_string(),
                    "interrupt".into(),
                ],
                None,
            ),
        };
        let url = match c3_command_url(&self.origin, &segments) {
            Ok(url) => url,
            Err(_) => return OpenCodeDispatchOutcome::OutcomeUnknown,
        };
        let request = self
            .agent
            .post(url.as_str())
            .set("Authorization", self.authorization.as_str());
        let result = match body.as_deref() {
            Some(body) => request
                .set("Content-Type", "application/json")
                .send_bytes(body.as_slice()),
            None => request.call(),
        };
        classify_dispatch_response(result)
    }
}

fn validate_dispatch_origin(origin: &str) -> Result<(), OpenCodeDispatcherError> {
    let parsed = Url::parse(origin).map_err(|_| OpenCodeDispatcherError::InvalidConfiguration)?;
    let port = parsed
        .port()
        .ok_or(OpenCodeDispatcherError::InvalidConfiguration)?;
    if parsed.scheme() != "http"
        || parsed.host_str() != Some("127.0.0.1")
        || !(1024..=65535).contains(&port)
        || origin.ends_with('/')
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(OpenCodeDispatcherError::InvalidConfiguration);
    }
    Ok(())
}

fn c3_command_url<S: AsRef<str>>(
    origin: &str,
    segments: &[S],
) -> Result<Url, OpenCodeDispatcherError> {
    let mut url = Url::parse(origin).map_err(|_| OpenCodeDispatcherError::InvalidConfiguration)?;
    let mut path = url
        .path_segments_mut()
        .map_err(|_| OpenCodeDispatcherError::InvalidConfiguration)?;
    path.clear();
    for segment in segments {
        path.push(segment.as_ref());
    }
    drop(path);
    Ok(url)
}

fn classify_dispatch_response(
    result: Result<ureq::Response, ureq::Error>,
) -> OpenCodeDispatchOutcome {
    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => {
            return OpenCodeDispatchOutcome::Rejected {
                error_code: c3_status_code(status),
            };
        }
        Err(ureq::Error::Transport(_)) => return OpenCodeDispatchOutcome::OutcomeUnknown,
    };
    if !response
        .header("Content-Type")
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return OpenCodeDispatchOutcome::OutcomeUnknown;
    }
    let mut raw = Vec::new();
    if response
        .into_reader()
        .take(C3_MAX_SUCCESS_BODY + 1)
        .read_to_end(&mut raw)
        .is_err()
        || raw.is_empty()
        || raw.len() as u64 > C3_MAX_SUCCESS_BODY
        || serde_json::from_slice::<Value>(&raw).is_err()
    {
        OpenCodeDispatchOutcome::OutcomeUnknown
    } else {
        OpenCodeDispatchOutcome::DispatchAcknowledged
    }
}

fn c3_status_code(status: u16) -> &'static str {
    match status {
        400 => "ERR_UPSTREAM_BAD_REQUEST",
        401 | 403 => "ERR_UPSTREAM_REJECTED",
        404 | 409 | 410 => "ERR_TARGET_STALE",
        429 => "ERR_UPSTREAM_BUSY",
        _ => "ERR_UPSTREAM_REJECTED",
    }
}

/// Exact private binding for one stable five-route observation. Raw run,
/// Session, and process identifiers are zeroized and never serialized.
#[derive(Clone)]
pub(crate) struct OpenCodeCommandFactsBinding {
    process_identity: Zeroizing<String>,
    run_id: Zeroizing<String>,
    raw_session: Zeroizing<String>,
    snapshot_seq: u64,
    snapshot_digest: String,
    next_command_seq: u64,
}

impl OpenCodeCommandFactsBinding {
    pub(crate) fn new(
        process_identity: String,
        run_id: String,
        raw_session: String,
        snapshot_seq: u64,
        snapshot_digest: String,
        next_command_seq: u64,
    ) -> Result<Self, OpenCodeFactsError> {
        if process_identity.is_empty()
            || run_id.is_empty()
            || raw_session.is_empty()
            || snapshot_seq == 0
            || next_command_seq == 0
            || !is_c3_digest(&snapshot_digest)
        {
            return Err(OpenCodeFactsError::InvalidFacts);
        }
        Ok(Self {
            process_identity: Zeroizing::new(process_identity),
            run_id: Zeroizing::new(run_id),
            raw_session: Zeroizing::new(raw_session),
            snapshot_seq,
            snapshot_digest,
            next_command_seq,
        })
    }
}

impl fmt::Debug for OpenCodeCommandFactsBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCodeCommandFactsBinding")
            .field("private_binding", &"<redacted>")
            .field("snapshot_seq", &self.snapshot_seq)
            .field("snapshot_digest", &self.snapshot_digest)
            .field("next_command_seq", &self.next_command_seq)
            .finish()
    }
}

/// The exact five OpenCode 1.18.16 route bodies used by the C2 projector.
/// Construction requires two byte-identical samples, making instability fail
/// closed before command facts exist.
pub(crate) struct OpenCodeFiveRouteBatch {
    session: Zeroizing<Vec<u8>>,
    status: Zeroizing<Vec<u8>>,
    question: Zeroizing<Vec<u8>>,
    permission: Zeroizing<Vec<u8>>,
    diff: Zeroizing<Vec<u8>>,
}

impl OpenCodeFiveRouteBatch {
    pub(crate) fn stable(
        first: [&[u8]; 5],
        second: [&[u8]; 5],
    ) -> Result<Self, OpenCodeFactsError> {
        if first
            .iter()
            .chain(second.iter())
            .any(|body| body.is_empty() || body.len() > C3_MAX_FACT_ROUTE_BODY)
            || first
                .iter()
                .zip(second.iter())
                .any(|(left, right)| left != right)
        {
            return Err(OpenCodeFactsError::InvalidFacts);
        }
        Ok(Self {
            session: Zeroizing::new(first[0].to_vec()),
            status: Zeroizing::new(first[1].to_vec()),
            question: Zeroizing::new(first[2].to_vec()),
            permission: Zeroizing::new(first[3].to_vec()),
            diff: Zeroizing::new(first[4].to_vec()),
        })
    }
}

impl fmt::Debug for OpenCodeFiveRouteBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenCodeFiveRouteBatch(<redacted>)")
    }
}

/// Authoritative private targets extracted from one stable observation.
/// This type intentionally has no Serialize implementation or raw accessors.
#[derive(Clone)]
pub(crate) struct OpenCodeCommandFacts {
    binding: OpenCodeCommandFactsBinding,
    raw_question: Option<Zeroizing<String>>,
    raw_permission: Option<Zeroizing<String>>,
    active_turn: Zeroizing<String>,
    permission_action_hash: Option<String>,
    pending_question_summary: Option<PendingQuestionSummary>,
    observed_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl fmt::Debug for OpenCodeCommandFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCodeCommandFacts")
            .field("private_facts", &"<redacted>")
            .field("snapshot_seq", &self.binding.snapshot_seq)
            .finish()
    }
}

impl OpenCodeCommandFacts {
    pub(crate) fn parse_stable(
        binding: OpenCodeCommandFactsBinding,
        batch: OpenCodeFiveRouteBatch,
    ) -> Result<Self, OpenCodeFactsError> {
        Self::parse_stable_at(binding, batch, OffsetDateTime::now_utc())
    }

    /// Parses a fresh stable observation while retaining this authority
    /// window. This makes expiry an exact fact compared during resolution,
    /// rather than silently extending it on every re-read.
    #[allow(dead_code)] // Reserved for a future same-window refresh; C3 composes fresh windows explicitly.
    pub(crate) fn refresh_stable(
        &self,
        binding: OpenCodeCommandFactsBinding,
        batch: OpenCodeFiveRouteBatch,
    ) -> Result<Self, OpenCodeFactsError> {
        Self::parse_stable_at(binding, batch, self.observed_at)
    }

    fn parse_stable_at(
        binding: OpenCodeCommandFactsBinding,
        batch: OpenCodeFiveRouteBatch,
        observed_at: OffsetDateTime,
    ) -> Result<Self, OpenCodeFactsError> {
        // Reuse the C2 exact-shape validator for all five routes. This does not
        // infer targets from C2 aliases; raw targets are parsed below.
        crate::stock_snapshot::project_stock_snapshot(
            &binding.raw_session,
            &batch.session,
            &batch.status,
            &batch.question,
            &batch.permission,
            &batch.diff,
        )
        .map_err(|_| OpenCodeFactsError::InvalidFacts)?;
        let questions = strict_c3_array(&batch.question)?;
        let permissions = strict_c3_array(&batch.permission)?;
        let question = one_session_target(&questions, &binding.raw_session)?;
        let permission = one_session_target(&permissions, &binding.raw_session)?;
        // Mixing both target kinds is ambiguous. With neither, Stop is still
        // valid only for the exact currently-busy Session: interrupt itself is
        // session-scoped in OpenCode 1.18.16.
        if question.is_some() && permission.is_some() {
            return Err(OpenCodeFactsError::NoCapability);
        }
        let selected = permission.or(question);
        let active_turn = match selected
            .and_then(|value| value.get("tool"))
            .and_then(Value::as_object)
            .and_then(|tool| tool.get("messageID"))
            .and_then(Value::as_str)
            .filter(|value| valid_raw_target(value))
        {
            Some(raw_turn) => raw_turn.to_string(),
            None if selected.is_none() && session_is_busy(&batch.status, &binding.raw_session)? => {
                private_session_turn(&binding)
            }
            None => return Err(OpenCodeFactsError::NoCapability),
        };
        let raw_question = question
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            .map(|value| Zeroizing::new(value.to_string()));
        let pending_question_summary = question.and_then(pending_question_summary);
        let raw_permission = permission
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            .map(|value| Zeroizing::new(value.to_string()));
        let permission_action_hash = permission.map(|value| {
            format!(
                "sha256:{:x}",
                Sha256::digest(crate::snapshot::canonical_json(value).as_bytes())
            )
        });
        Ok(Self {
            binding,
            raw_question,
            raw_permission,
            active_turn: Zeroizing::new(active_turn),
            permission_action_hash,
            pending_question_summary,
            observed_at,
            expires_at: observed_at + time::Duration::seconds(C3_CAPABILITY_SECONDS),
        })
    }

    pub(crate) fn capability(&self) -> Result<OpenCodeCommandCapability, OpenCodeFactsError> {
        self.capability_at(OffsetDateTime::now_utc())
    }

    fn capability_at(
        &self,
        now: OffsetDateTime,
    ) -> Result<OpenCodeCommandCapability, OpenCodeFactsError> {
        if now < self.observed_at || now >= self.expires_at {
            return Err(OpenCodeFactsError::NoCapability);
        }
        let reply = self.raw_question.as_ref().map(|question| ReplyCapability {
            turn_alias: c3_alias(&self.binding.run_id, "turn", &self.active_turn),
            input_alias: c3_alias(&self.binding.run_id, "input", question),
            summary: self.pending_question_summary.clone(),
        });
        let deny = self.raw_permission.as_ref().and_then(|permission| {
            self.permission_action_hash
                .as_ref()
                .map(|action_hash| DenyCapability {
                    permission_alias: c3_alias(&self.binding.run_id, "permission", permission),
                    action_hash: action_hash.clone(),
                    // This is the Host-issued authorization expiry, not an
                    // upstream permission field (OpenCode has none).
                    expires_at: c3_time(self.expires_at).expect("validated Host time"),
                })
        });
        Ok(OpenCodeCommandCapability {
            schema: C3_CAPABILITY_SCHEMA,
            capability_id: c3_capability_id(self),
            snapshot_seq: self.binding.snapshot_seq,
            snapshot_digest: self.binding.snapshot_digest.clone(),
            next_command_seq: self.binding.next_command_seq,
            issued_at: c3_time(self.observed_at)?,
            expires_at: c3_time(self.expires_at)?,
            view: true,
            reply,
            deny,
            stop: Some(StopCapability {
                turn_alias: c3_alias(&self.binding.run_id, "turn", &self.active_turn),
            }),
            allow_once: false,
        })
    }

    /// Resolves only safe aliases against a newly parsed authoritative facts
    /// object. Every raw binding and target must still be identical.
    pub(crate) fn resolve_fresh(
        &self,
        fresh: &Self,
        capability: &OpenCodeCommandCapability,
        request: OpenCodeSafeCommand,
    ) -> Result<OpenCodeCommand, OpenCodeFactsError> {
        self.resolve_fresh_at(fresh, capability, request, OffsetDateTime::now_utc())
    }

    fn resolve_fresh_at(
        &self,
        fresh: &Self,
        capability: &OpenCodeCommandCapability,
        request: OpenCodeSafeCommand,
        now: OffsetDateTime,
    ) -> Result<OpenCodeCommand, OpenCodeFactsError> {
        if now < self.observed_at
            || now >= self.expires_at
            || now < fresh.observed_at
            || now >= fresh.expires_at
            || !self.same_authority(fresh)
            || capability.capability_id != c3_capability_id(self)
            || capability.snapshot_seq != self.binding.snapshot_seq
            || capability.snapshot_digest != self.binding.snapshot_digest
            || capability.next_command_seq != self.binding.next_command_seq
            || capability.allow_once
            || capability.expires_at != c3_time(self.expires_at)?
        {
            return Err(OpenCodeFactsError::Stale);
        }
        match request {
            OpenCodeSafeCommand::Reply {
                turn_alias,
                input_alias,
                content,
            } => {
                let raw = fresh
                    .raw_question
                    .as_ref()
                    .ok_or(OpenCodeFactsError::Stale)?;
                let safe = capability.reply.as_ref().ok_or(OpenCodeFactsError::Stale)?;
                if safe.turn_alias != turn_alias
                    || safe.input_alias != input_alias
                    || turn_alias != c3_alias(&fresh.binding.run_id, "turn", &fresh.active_turn)
                    || input_alias != c3_alias(&fresh.binding.run_id, "input", raw)
                {
                    return Err(OpenCodeFactsError::Stale);
                }
                Ok(OpenCodeCommand::reply(
                    fresh.binding.raw_session.to_string(),
                    raw.to_string(),
                    content.to_string(),
                ))
            }
            OpenCodeSafeCommand::Deny {
                permission_alias,
                action_hash,
                permission_expires_at,
            } => {
                let raw = fresh
                    .raw_permission
                    .as_ref()
                    .ok_or(OpenCodeFactsError::Stale)?;
                let safe = capability.deny.as_ref().ok_or(OpenCodeFactsError::Stale)?;
                if safe.permission_alias != permission_alias
                    || safe.action_hash != action_hash
                    || safe.expires_at != permission_expires_at
                    || fresh.permission_action_hash.as_deref() != Some(action_hash.as_str())
                    || permission_expires_at != c3_time(fresh.expires_at)?
                    || permission_alias != c3_alias(&fresh.binding.run_id, "permission", raw)
                {
                    return Err(OpenCodeFactsError::Stale);
                }
                Ok(OpenCodeCommand::deny(
                    fresh.binding.raw_session.to_string(),
                    raw.to_string(),
                ))
            }
            OpenCodeSafeCommand::Stop { turn_alias } => {
                let safe = capability.stop.as_ref().ok_or(OpenCodeFactsError::Stale)?;
                if safe.turn_alias != turn_alias
                    || turn_alias != c3_alias(&fresh.binding.run_id, "turn", &fresh.active_turn)
                {
                    return Err(OpenCodeFactsError::Stale);
                }
                Ok(OpenCodeCommand::stop(fresh.binding.raw_session.to_string()))
            }
        }
    }

    fn same_authority(&self, fresh: &Self) -> bool {
        self.binding.process_identity == fresh.binding.process_identity
            && self.binding.run_id == fresh.binding.run_id
            && self.binding.raw_session == fresh.binding.raw_session
            && self.binding.snapshot_seq == fresh.binding.snapshot_seq
            && self.binding.snapshot_digest == fresh.binding.snapshot_digest
            && self.binding.next_command_seq == fresh.binding.next_command_seq
            && self.raw_question == fresh.raw_question
            && self.raw_permission == fresh.raw_permission
            && self.active_turn == fresh.active_turn
            && self.permission_action_hash == fresh.permission_action_hash
            && self.pending_question_summary == fresh.pending_question_summary
            && self.observed_at == fresh.observed_at
            && self.expires_at == fresh.expires_at
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenCodeCommandCapability {
    pub(crate) schema: &'static str,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplyCapability {
    pub(crate) turn_alias: String,
    pub(crate) input_alias: String,
    pub(crate) summary: Option<PendingQuestionSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingQuestionSummary {
    pub(crate) schema: &'static str,
    pub(crate) question_count: u8,
    pub(crate) answer_mode: &'static str,
    pub(crate) response_hint: &'static str,
    pub(crate) prompt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenyCapability {
    pub(crate) permission_alias: String,
    pub(crate) action_hash: String,
    pub(crate) expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StopCapability {
    pub(crate) turn_alias: String,
}

pub(crate) enum OpenCodeSafeCommand {
    Reply {
        turn_alias: String,
        input_alias: String,
        content: Zeroizing<String>,
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

impl fmt::Debug for OpenCodeSafeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenCodeSafeCommand(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OpenCodeFactsError {
    #[error("OpenCode command facts are invalid")]
    InvalidFacts,
    #[error("OpenCode command capability is unavailable")]
    NoCapability,
    #[error("OpenCode command facts are stale")]
    Stale,
}

fn strict_c3_array(raw: &[u8]) -> Result<Vec<Value>, OpenCodeFactsError> {
    crate::stock_event_adapter::strict_json(raw)
        .map_err(|_| OpenCodeFactsError::InvalidFacts)?
        .as_array()
        .cloned()
        .ok_or(OpenCodeFactsError::InvalidFacts)
}

fn one_session_target<'a>(
    values: &'a [Value],
    session: &str,
) -> Result<Option<&'a Value>, OpenCodeFactsError> {
    let matching: Vec<_> = values
        .iter()
        .filter(|value| value.get("sessionID").and_then(Value::as_str) == Some(session))
        .collect();
    if matching.len() > 1 {
        Err(OpenCodeFactsError::NoCapability)
    } else {
        Ok(matching.first().copied())
    }
}

fn pending_question_summary(envelope: &Value) -> Option<PendingQuestionSummary> {
    let questions = envelope.get("questions")?.as_array()?;
    if questions.len() != 1 {
        return None;
    }
    let question = questions[0].as_object()?;
    let options = question.get("options")?.as_array()?;
    if !options.is_empty()
        || question.get("multiple").is_some_and(|value| value != false)
        || question.get("custom") != Some(&Value::Bool(true))
    {
        return None;
    }
    let field = safe_question_field(question.get("question")?.as_str()?)?;
    let prompt = format!("Provide a short reply for: {field}.");
    if prompt.len() > 160 {
        return None;
    }
    Some(PendingQuestionSummary {
        schema: "nomad.product-host.pending-question-summary.v1",
        question_count: 1,
        answer_mode: "free_text",
        response_hint: "single_short_reply",
        prompt,
    })
}

fn safe_question_field(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 96 || !raw.is_ascii() {
        return None;
    }
    let trimmed = raw.trim().trim_end_matches(['?', '.']).trim();
    let lower = trimmed.to_ascii_lowercase();
    let without_please = lower.strip_prefix("please ").unwrap_or(&lower);
    let field = ["provide ", "enter ", "specify ", "clarify "]
        .iter()
        .find_map(|verb| without_please.strip_prefix(verb))?
        .trim();
    if field.is_empty()
        || field.len() > 48
        || !field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b' ' || byte == b'-')
    {
        return None;
    }
    let words: Vec<_> = field.split_whitespace().collect();
    if words.is_empty() || words.len() > 6 || words.iter().any(|word| word.len() > 20) {
        return None;
    }
    const FORBIDDEN: &[&str] = &[
        "secret",
        "password",
        "token",
        "api",
        "key",
        "private",
        "provider",
        "model",
        "credential",
    ];
    if words.iter().any(|word| FORBIDDEN.contains(word))
        || field
            .as_bytes()
            .windows(5)
            .any(|window| window.iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    Some(words.join(" "))
}

fn valid_raw_target(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn session_is_busy(raw: &[u8], session: &str) -> Result<bool, OpenCodeFactsError> {
    let value = crate::stock_event_adapter::strict_json(raw)
        .map_err(|_| OpenCodeFactsError::InvalidFacts)?;
    Ok(value
        .as_object()
        .and_then(|statuses| statuses.get(session))
        .and_then(Value::as_object)
        .and_then(|status| status.get("type"))
        .and_then(Value::as_str)
        == Some("busy"))
}

fn private_session_turn(binding: &OpenCodeCommandFactsBinding) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nomad.c3.session-turn.v1\0");
    digest.update(binding.run_id.as_bytes());
    digest.update(b"\0");
    digest.update(binding.raw_session.as_bytes());
    digest.update(binding.snapshot_seq.to_be_bytes());
    digest.update(binding.snapshot_digest.as_bytes());
    format!("session-turn-{}", &format!("{:x}", digest.finalize())[..32])
}

fn c3_alias(run_id: &str, kind: &str, raw: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nomad.c3.command-alias.v1\0");
    digest.update(run_id.as_bytes());
    digest.update(b"\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(raw.as_bytes());
    format!("{kind}-{}", &format!("{:x}", digest.finalize())[..32])
}

fn c3_capability_id(facts: &OpenCodeCommandFacts) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nomad.c3.capability.v1\0");
    digest.update(facts.binding.run_id.as_bytes());
    digest.update(b"\0");
    digest.update(facts.binding.process_identity.as_bytes());
    digest.update(b"\0");
    digest.update(facts.binding.raw_session.as_bytes());
    digest.update(facts.binding.snapshot_seq.to_be_bytes());
    digest.update(facts.binding.snapshot_digest.as_bytes());
    digest.update(facts.binding.next_command_seq.to_be_bytes());
    digest.update(facts.observed_at.unix_timestamp_nanos().to_be_bytes());
    format!("cap_{}", &format!("{:x}", digest.finalize())[..40])
}

fn c3_time(value: OffsetDateTime) -> Result<String, OpenCodeFactsError> {
    let value = value
        .replace_nanosecond(0)
        .map_err(|_| OpenCodeFactsError::InvalidFacts)?;
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

fn is_c3_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod c3_dispatch_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;

    #[derive(Debug)]
    struct Request {
        method: String,
        path: String,
        authorization: String,
        body: Vec<u8>,
    }

    fn read_request(stream: &mut TcpStream) -> Request {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !raw.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            raw.extend_from_slice(&buffer[..count]);
        }
        let head_end = raw.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
        let mut lines = head.split("\r\n");
        let mut start = lines.next().unwrap().split_ascii_whitespace();
        let method = start.next().unwrap().to_string();
        let path = start.next().unwrap().to_string();
        let mut length = 0;
        let mut authorization = String::new();
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().unwrap();
            }
            if name.eq_ignore_ascii_case("authorization") {
                authorization = value.trim().to_string();
            }
        }
        while raw.len() - head_end < length {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            raw.extend_from_slice(&buffer[..count]);
        }
        Request {
            method,
            path,
            authorization,
            body: raw[head_end..head_end + length].to_vec(),
        }
    }

    fn server(
        response: Option<&'static [u8]>,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    ) -> (String, Arc<Mutex<Vec<Request>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(Vec::new()));
        let output = Arc::clone(&captured);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            output.lock().unwrap().push(read_request(&mut stream));
            calls.fetch_add(1, Ordering::SeqCst);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            if let Some(response) = response {
                let _ = stream.write_all(response);
            }
        });
        (origin, captured, handle)
    }

    fn dispatcher(origin: &str, timeout: Duration) -> OpenCodeCommandDispatcher {
        OpenCodeCommandDispatcher::build(
            origin,
            Zeroizing::new("host-only-password".into()),
            timeout,
        )
        .unwrap()
    }

    const JSON_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

    #[test]
    fn emits_exact_routes_bodies_and_zero_byte_stop() {
        let cases = [
            (
                OpenCodeCommand::reply(
                    "session/raw".into(),
                    "question %/raw".into(),
                    "content".into(),
                ),
                "/api/session/session%2Fraw/question/question%20%25%2Fraw/reply",
                br#"{"answers":[["content"]]}"#.as_slice(),
            ),
            (
                OpenCodeCommand::deny("session/raw".into(), "permission/%raw".into()),
                "/api/session/session%2Fraw/permission/permission%2F%25raw/reply",
                br#"{"reply":"reject"}"#.as_slice(),
            ),
            (
                OpenCodeCommand::stop("session/raw".into()),
                "/api/session/session%2Fraw/interrupt",
                b"".as_slice(),
            ),
        ];
        for (command, expected_path, expected_body) in cases {
            let calls = Arc::new(AtomicUsize::new(0));
            let (origin, captured, handle) =
                server(Some(JSON_OK), Duration::ZERO, Arc::clone(&calls));
            assert_eq!(
                dispatcher(&origin, Duration::from_secs(1)).dispatch_once(command),
                OpenCodeDispatchOutcome::DispatchAcknowledged
            );
            handle.join().unwrap();
            let requests = captured.lock().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method, "POST");
            assert_eq!(requests[0].path, expected_path);
            assert_eq!(requests[0].body, expected_body);
            assert_eq!(
                requests[0].authorization,
                format!(
                    "Basic {}",
                    BASE64_STANDARD.encode(b"opencode:host-only-password")
                )
            );
        }
    }

    #[test]
    fn path_segments_are_encoded_once_and_configured_origin_is_strict() {
        const CONFIGURED_ORIGIN: &str = "http://127.0.0.1:45123";
        let url = c3_command_url(
            CONFIGURED_ORIGIN,
            &["api", "session", "already%2F/raw", "interrupt"],
        )
        .unwrap();
        assert_eq!(url.origin().ascii_serialization(), CONFIGURED_ORIGIN);
        assert_eq!(url.path(), "/api/session/already%252F%2Fraw/interrupt");
        let production =
            OpenCodeCommandDispatcher::new(CONFIGURED_ORIGIN, Zeroizing::new("secret".into()))
                .unwrap();
        assert_eq!(production.origin, CONFIGURED_ORIGIN);
        for rejected in [
            "http://localhost:45123",
            "https://127.0.0.1:45123",
            "http://127.0.0.1:45123/",
            "http://127.0.0.1:45123/path",
            "http://127.0.0.1:1023",
            "http://127.0.0.1",
            "http://user@127.0.0.1:45123",
        ] {
            assert!(
                OpenCodeCommandDispatcher::new(rejected, Zeroizing::new("secret".into())).is_err()
            );
        }
    }

    #[test]
    fn timeout_disconnect_and_malformed_success_are_unknown_without_second_post() {
        let cases = [
            (None, Duration::ZERO),
            (Some(JSON_OK), Duration::from_millis(150)),
            (
                Some(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .as_slice(),
                ),
                Duration::ZERO,
            ),
            (
                Some(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{"
                        .as_slice(),
                ),
                Duration::ZERO,
            ),
        ];
        for (response, delay) in cases {
            let calls = Arc::new(AtomicUsize::new(0));
            let (origin, _, handle) = server(response, delay, Arc::clone(&calls));
            assert_eq!(
                dispatcher(&origin, Duration::from_millis(50))
                    .dispatch_once(OpenCodeCommand::stop("session".into())),
                OpenCodeDispatchOutcome::OutcomeUnknown
            );
            handle.join().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn errors_and_debug_never_expose_raw_ids_content_or_credential() {
        let command = OpenCodeCommand::reply(
            "raw-session-secret".into(),
            "raw-question-secret".into(),
            "content-secret".into(),
        );
        let command_debug = format!("{command:?}");
        assert!(command_debug.contains("<redacted>"));
        assert!(!command_debug.contains("secret"));
        let dispatcher = OpenCodeCommandDispatcher::new(
            "http://127.0.0.1:4096",
            Zeroizing::new("credential-secret".into()),
        )
        .unwrap();
        assert_eq!(
            format!("{dispatcher:?}"),
            "OpenCodeCommandDispatcher(<redacted>)"
        );
        assert!(!OpenCodeDispatcherError::InvalidConfiguration
            .to_string()
            .contains("secret"));
    }
}

#[cfg(test)]
mod c3_facts_tests {
    use super::*;

    const SESSION: &[u8] = br#"{"id":"ses_secret","slug":"s","projectID":"p","directory":"/workspace","title":"t","version":"1.18.16","time":{"created":1,"updated":2}}"#;
    const STATUS: &[u8] = br#"{"ses_secret":{"type":"busy"}}"#;
    const QUESTION: &[u8] = br#"[{"id":"que_secret","sessionID":"ses_secret","questions":[{"question":"private question","header":"private header","options":[]}],"tool":{"messageID":"msg_secret","callID":"call_secret"}}]"#;
    const SAFE_QUESTION: &[u8] = br#"[{"id":"que_secret","sessionID":"ses_secret","questions":[{"question":"Please provide deployment region?","header":"arbitrary private header","options":[],"multiple":false,"custom":true}],"tool":{"messageID":"msg_secret","callID":"call_secret"}}]"#;
    const PERMISSION: &[u8] = br#"[{"id":"per_secret","sessionID":"ses_secret","permission":"bash","patterns":["private command"],"metadata":{"private":"value"},"always":false,"tool":{"messageID":"msg_secret","callID":"call_secret"}}]"#;
    const EMPTY: &[u8] = b"[]";

    fn binding() -> OpenCodeCommandFactsBinding {
        OpenCodeCommandFactsBinding::new(
            "process_secret".into(),
            "run_secret".into(),
            "ses_secret".into(),
            7,
            format!("sha256:{}", "a".repeat(64)),
            8,
        )
        .unwrap()
    }

    fn batch(question: &[u8], permission: &[u8]) -> OpenCodeFiveRouteBatch {
        let routes = [SESSION, STATUS, question, permission, EMPTY];
        OpenCodeFiveRouteBatch::stable(routes, routes).unwrap()
    }

    fn question_facts(now: OffsetDateTime) -> OpenCodeCommandFacts {
        OpenCodeCommandFacts::parse_stable_at(binding(), batch(QUESTION, EMPTY), now).unwrap()
    }

    fn safe_question_facts(now: OffsetDateTime) -> OpenCodeCommandFacts {
        OpenCodeCommandFacts::parse_stable_at(binding(), batch(SAFE_QUESTION, EMPTY), now).unwrap()
    }

    fn permission_facts(now: OffsetDateTime) -> OpenCodeCommandFacts {
        OpenCodeCommandFacts::parse_stable_at(binding(), batch(EMPTY, PERMISSION), now).unwrap()
    }

    #[test]
    fn parses_official_question_and_permission_shapes_without_c2_alias_input() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let question = question_facts(now);
        assert_eq!(
            question.raw_question.as_ref().map(|value| value.as_str()),
            Some("que_secret")
        );
        assert!(question.raw_permission.is_none());
        assert_eq!(question.active_turn.as_str(), "msg_secret");
        assert!(question.permission_action_hash.is_none());

        let permission = permission_facts(now);
        assert_eq!(
            permission
                .raw_permission
                .as_ref()
                .map(|value| value.as_str()),
            Some("per_secret")
        );
        assert!(permission.raw_question.is_none());
        assert_eq!(permission.active_turn.as_str(), "msg_secret");
        assert!(permission
            .permission_action_hash
            .as_deref()
            .is_some_and(is_c3_digest));
        assert!(permission.capability_at(now).unwrap().deny.is_some());
    }

    #[test]
    fn capability_is_safe_run_scoped_and_valid_for_exactly_thirty_seconds() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let first = question_facts(now);
        let capability = first.capability_at(now).unwrap();
        let wire = serde_json::to_string(&capability).unwrap();
        assert_eq!(capability.schema, C3_CAPABILITY_SCHEMA);
        assert_eq!(capability.snapshot_seq, 7);
        assert_eq!(capability.next_command_seq, 8);
        assert!(capability.view);
        assert!(!capability.allow_once);
        assert!(capability.reply.is_some());
        assert!(capability.deny.is_none());
        assert!(capability.stop.is_some());
        assert_eq!(
            capability.expires_at,
            c3_time(now + time::Duration::seconds(30)).unwrap()
        );
        for secret in [
            "process_secret",
            "run_secret",
            "ses_secret",
            "que_secret",
            "msg_secret",
            "private question",
        ] {
            assert!(!wire.contains(secret), "capability leaked {secret}");
        }
        assert!(wire.contains("\"allow_once\":false"));
        assert!(matches!(
            first.capability_at(now + time::Duration::seconds(30)),
            Err(OpenCodeFactsError::NoCapability)
        ));

        let mut other_run = question_facts(now);
        other_run.binding.run_id = Zeroizing::new("run_other".into());
        let other = other_run.capability_at(now).unwrap();
        assert_ne!(
            capability.reply.unwrap().input_alias,
            other.reply.unwrap().input_alias
        );
    }

    #[test]
    fn pending_question_summary_is_template_generated_and_capability_only() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let capability = safe_question_facts(now).capability_at(now).unwrap();
        let summary = capability.reply.as_ref().unwrap().summary.as_ref().unwrap();
        assert_eq!(
            summary.schema,
            "nomad.product-host.pending-question-summary.v1"
        );
        assert_eq!(summary.question_count, 1);
        assert_eq!(summary.answer_mode, "free_text");
        assert_eq!(summary.response_hint, "single_short_reply");
        assert_eq!(
            summary.prompt,
            "Provide a short reply for: deployment region."
        );
        let wire = serde_json::to_string(&capability).unwrap();
        for private in [
            "Please provide",
            "arbitrary private header",
            "que_secret",
            "msg_secret",
        ] {
            assert!(!wire.contains(private));
        }
    }

    #[test]
    fn pending_question_summary_rejects_unsafe_or_ambiguous_text() {
        let unsafe_questions = [
            "provide /private/path",
            "provide api key",
            "provide user@example.com",
            "provide model name",
            "provide abcdefghijklmnopqrstu",
            "provide build 12345",
            "what should I do",
            "provide 地区",
        ];
        for raw in unsafe_questions {
            let value = serde_json::json!({
                "id": "que_secret", "sessionID": "ses_secret",
                "questions": [{"question": raw, "header": "h", "options": [], "multiple": false, "custom": true}],
                "tool": {"messageID": "msg_secret", "callID": "call_secret"}
            });
            assert!(pending_question_summary(&value).is_none(), "accepted {raw}");
        }
        let choices = serde_json::json!({
            "questions": [{"question": "provide region", "header": "h", "options": [{"label": "x", "description": "y"}], "multiple": false, "custom": true}]
        });
        assert!(pending_question_summary(&choices).is_none());
    }

    #[test]
    fn resolves_safe_alias_only_when_every_fresh_fact_still_matches() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let original = question_facts(now);
        let capability = original.capability_at(now).unwrap();
        let reply = capability.reply.as_ref().unwrap();
        let resolved = original
            .resolve_fresh_at(
                &original,
                &capability,
                OpenCodeSafeCommand::Reply {
                    turn_alias: reply.turn_alias.clone(),
                    input_alias: reply.input_alias.clone(),
                    content: Zeroizing::new("content".into()),
                },
                now + time::Duration::seconds(1),
            )
            .unwrap();
        assert!(matches!(resolved, OpenCodeCommand::Reply { .. }));

        type FactsMutation = Box<dyn Fn(&mut OpenCodeCommandFacts)>;
        let mutations: Vec<FactsMutation> = vec![
            Box::new(|facts| facts.binding.process_identity = Zeroizing::new("changed".into())),
            Box::new(|facts| facts.binding.run_id = Zeroizing::new("changed".into())),
            Box::new(|facts| facts.binding.raw_session = Zeroizing::new("changed".into())),
            Box::new(|facts| facts.binding.snapshot_seq += 1),
            Box::new(|facts| facts.binding.snapshot_digest = format!("sha256:{}", "c".repeat(64))),
            Box::new(|facts| facts.binding.next_command_seq += 1),
            Box::new(|facts| facts.raw_question = Some(Zeroizing::new("que_changed".into()))),
            Box::new(|facts| facts.active_turn = Zeroizing::new("msg_changed".into())),
            Box::new(|facts| {
                facts.permission_action_hash = Some(format!("sha256:{}", "d".repeat(64)))
            }),
            Box::new(|facts| facts.expires_at -= time::Duration::seconds(1)),
        ];
        for mutate in mutations {
            let mut fresh = original.clone();
            mutate(&mut fresh);
            let reply = capability.reply.as_ref().unwrap();
            assert!(matches!(
                original.resolve_fresh_at(
                    &fresh,
                    &capability,
                    OpenCodeSafeCommand::Reply {
                        turn_alias: reply.turn_alias.clone(),
                        input_alias: reply.input_alias.clone(),
                        content: Zeroizing::new("content".into()),
                    },
                    now + time::Duration::seconds(1),
                ),
                Err(OpenCodeFactsError::Stale)
            ));
        }
    }

    #[test]
    fn official_permission_uses_host_authorization_expiry_for_deny() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let facts = permission_facts(now);
        let capability = facts.capability_at(now).unwrap();
        assert_eq!(
            capability.deny.as_ref().unwrap().expires_at,
            capability.expires_at
        );
        assert!(capability.stop.is_some());
        let wire = serde_json::to_value(capability).unwrap();
        assert!(wire.get("deny").unwrap().is_object());
    }

    #[test]
    fn capability_has_exact_frozen_keys() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let wire = serde_json::to_value(question_facts(now).capability_at(now).unwrap()).unwrap();
        let keys: std::collections::BTreeSet<_> = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "allow_once",
                "capability_id",
                "deny",
                "expires_at",
                "issued_at",
                "next_command_seq",
                "reply",
                "schema",
                "snapshot_digest",
                "snapshot_seq",
                "stop",
                "view",
            ])
        );
        let reply_keys: std::collections::BTreeSet<_> = wire["reply"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            reply_keys,
            std::collections::BTreeSet::from(["input_alias", "summary", "turn_alias"])
        );
        let stop_keys: std::collections::BTreeSet<_> = wire["stop"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(stop_keys, std::collections::BTreeSet::from(["turn_alias"]));
    }

    #[test]
    fn deny_dto_and_resolution_bind_host_authorization_expiry() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let facts = permission_facts(now);
        let capability = facts.capability_at(now).unwrap();
        let deny = capability.deny.as_ref().unwrap();
        let wire = serde_json::to_value(&capability).unwrap();
        let keys: std::collections::BTreeSet<_> = wire["deny"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from(["action_hash", "expires_at", "permission_alias",])
        );
        assert_eq!(deny.expires_at, capability.expires_at);
        assert!(matches!(
            facts.resolve_fresh_at(
                &facts,
                &capability,
                OpenCodeSafeCommand::Deny {
                    permission_alias: deny.permission_alias.clone(),
                    action_hash: deny.action_hash.clone(),
                    permission_expires_at: deny.expires_at.clone(),
                },
                now + time::Duration::seconds(1),
            ),
            Ok(OpenCodeCommand::Deny { .. })
        ));
        assert!(matches!(
            facts.resolve_fresh_at(
                &facts,
                &capability,
                OpenCodeSafeCommand::Deny {
                    permission_alias: deny.permission_alias.clone(),
                    action_hash: deny.action_hash.clone(),
                    permission_expires_at: c3_time(facts.expires_at + time::Duration::seconds(1))
                        .unwrap(),
                },
                now + time::Duration::seconds(1),
            ),
            Err(OpenCodeFactsError::Stale)
        ));
    }

    #[test]
    fn stop_resolution_is_bound_to_fresh_turn_alias() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let facts = question_facts(now);
        let capability = facts.capability_at(now).unwrap();
        let turn_alias = capability.stop.as_ref().unwrap().turn_alias.clone();
        assert!(matches!(
            facts.resolve_fresh_at(
                &facts,
                &capability,
                OpenCodeSafeCommand::Stop { turn_alias },
                now + time::Duration::seconds(1),
            ),
            Ok(OpenCodeCommand::Stop { .. })
        ));
    }

    #[test]
    fn busy_session_without_tool_turn_gets_session_scoped_stop_only() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let facts =
            OpenCodeCommandFacts::parse_stable_at(binding(), batch(EMPTY, EMPTY), now).unwrap();
        let capability = facts.capability_at(now).unwrap();
        assert!(capability.reply.is_none());
        assert!(capability.deny.is_none());
        let stop = capability.stop.unwrap();
        assert!(stop.turn_alias.starts_with("turn-"));
        assert!(!stop.turn_alias.contains("ses_secret"));
    }

    #[test]
    fn rejects_unstable_ambiguous_incomplete_or_duplicate_raw_facts() {
        assert!(matches!(
            OpenCodeFiveRouteBatch::stable(
                [SESSION, STATUS, QUESTION, EMPTY, EMPTY],
                [SESSION, STATUS, EMPTY, EMPTY, EMPTY]
            ),
            Err(OpenCodeFactsError::InvalidFacts)
        ));
        assert!(matches!(
            OpenCodeCommandFacts::parse_stable_at(
                binding(),
                batch(QUESTION, PERMISSION),
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(OpenCodeFactsError::NoCapability)
        ));
        let missing_tool = br#"[{"id":"que_secret","sessionID":"ses_secret","questions":[]}]"#;
        assert!(matches!(
            OpenCodeCommandFacts::parse_stable_at(
                binding(),
                batch(missing_tool, EMPTY),
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(OpenCodeFactsError::NoCapability)
        ));
        let duplicate = br#"[{"id":"que_secret","sessionID":"ses_secret","questions":[],"tool":{"messageID":"msg_secret","callID":"call_secret"}},{"id":"que_other","sessionID":"ses_secret","questions":[],"tool":{"messageID":"msg_other","callID":"call_other"}}]"#;
        assert!(matches!(
            OpenCodeCommandFacts::parse_stable_at(
                binding(),
                batch(duplicate, EMPTY),
                OffsetDateTime::UNIX_EPOCH
            ),
            Err(OpenCodeFactsError::InvalidFacts | OpenCodeFactsError::NoCapability)
        ));
    }

    #[test]
    fn facts_batches_safe_commands_and_errors_are_debug_redacted() {
        let now = OffsetDateTime::from_unix_timestamp(1_777_777_777).unwrap();
        let facts = question_facts(now);
        for output in [
            format!("{facts:?}"),
            format!("{:?}", batch(QUESTION, EMPTY)),
            format!(
                "{:?}",
                OpenCodeSafeCommand::Reply {
                    turn_alias: "turn".into(),
                    input_alias: "input".into(),
                    content: Zeroizing::new("content_secret".into()),
                }
            ),
        ] {
            assert!(output.contains("<redacted>"));
            assert!(!output.contains("secret"));
        }
        assert!(!OpenCodeFactsError::Stale.to_string().contains("secret"));
    }
}
