//! Stock OpenCode anti-corruption boundary. Production M1 observation records
//! unknown identities only; it publishes no durable stock replay or semantics.
//! The verified durable writer is test-only and exists solely to exercise Host
//! persistence mechanics before Provider-backed evidence arrives.
use crate::error::ConnectorError;
use crate::journal::{CommandJournal, InsertOrGetCommand, JournalCommand, StockObservationWrite};
use crate::projection::{
    ClientFreshness, HostConnectivity, ProjectedEvent, Snapshot, StateSummary, TurnState,
};
use crate::release_bundle::VerifiedHistoricalEvidence;
use crate::snapshot::{compute_digest, to_canonical_value};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use url::Url;

/// This committed fixture is shape evidence only. It is intentionally compiled
/// into the binary so changing a route/body requires an explicit evidence diff.
const COMMAND_SHAPES: &str =
    include_str!("../../testkit/stock-opencode/real-task/command-shapes.json");
pub const REAL_LIFECYCLE_EVIDENCE_REQUIRED: &str = "BLOCKED_REAL_LIFECYCLE_EVIDENCE_REQUIRED";
pub const APPROVAL_EXPIRED_OR_INVALID: &str = "APPROVAL_EXPIRED_OR_INVALID";
pub const COMMAND_SHAPE_SOURCE: &str = "official_shape_only_not_lifecycle";
const MAX_COMMAND_CONTENT: usize = 16 * 1024;
const MAX_ANSWER_GROUPS: usize = 64;
const MAX_ANSWERS_PER_GROUP: usize = 64;
const MAX_ANSWER_BYTES: usize = 16 * 1024;
const MAX_ENCODED_BODY: usize = 32 * 1024;
const MAX_COMMAND_PATH: usize = 2048;
const APPROVAL_SCHEMA: &str = "nomad.stock-opencode.approval-record.v1";
const APPROVAL_SCOPE: &str = "nomad.m2.complete-evidence-bundle";
const APPROVAL_SIGNING_NAMESPACE: &str = "nomad-m2-release-authorization-v1";
const MAX_APPROVAL_VALIDITY_SECONDS: i64 = 2_592_000;

/// Proves only that the approval sealed into one embedded release is current.
/// It deliberately carries no run, launch, capability, or command authority.
#[allow(dead_code)] // The digest scope is consumed only by the later d2b authorization gate.
pub struct CurrentReleaseAuthorization {
    release_index_digest: String,
    bundle_manifest_digest: String,
    approval_record_digest: String,
    approval_signature_raw_digest: String,
    approval_scope: String,
}

/// Validate the zero-skew validity window of an already sealed embedded approval.
/// This does not repeat SSHSIG verification and cannot authorize a command.
pub fn current_release_authorization(
    evidence: &VerifiedHistoricalEvidence,
) -> Result<CurrentReleaseAuthorization, ConnectorError> {
    evaluate_current_release_authorization(evidence, OffsetDateTime::now_utc())
}

#[cfg(test)]
pub(crate) fn current_release_authorization_at(
    evidence: &VerifiedHistoricalEvidence,
    now_utc: OffsetDateTime,
) -> Result<CurrentReleaseAuthorization, ConnectorError> {
    evaluate_current_release_authorization(evidence, now_utc)
}

fn evaluate_current_release_authorization(
    evidence: &VerifiedHistoricalEvidence,
    now_utc: OffsetDateTime,
) -> Result<CurrentReleaseAuthorization, ConnectorError> {
    let fields = evidence.current_approval_fields();
    let valid_sealed_fields = fields.is_embedded
        && fields.approval_schema_version == APPROVAL_SCHEMA
        && fields.approval_scope == APPROVAL_SCOPE
        && fields.signing_namespace == APPROVAL_SIGNING_NAMESPACE
        && lower_hex_digest(fields.release_index_digest)
        && lower_hex_digest(fields.bundle_manifest_digest)
        && lower_hex_digest(fields.evidence_manifest_digest)
        && lower_hex_digest(fields.approval_record_digest)
        && lower_hex_digest(fields.approval_signature_raw_digest)
        && !fields.reviewed_version.is_empty()
        && !fields.trust_root_id.is_empty();
    let valid_window = approval_window_is_current(fields.issued_at, fields.expires_at, now_utc);
    if !valid_sealed_fields || !valid_window {
        return Err(ConnectorError::SafetyBlocked(
            APPROVAL_EXPIRED_OR_INVALID.into(),
        ));
    }
    Ok(CurrentReleaseAuthorization {
        release_index_digest: fields.release_index_digest.into(),
        bundle_manifest_digest: fields.bundle_manifest_digest.into(),
        approval_record_digest: fields.approval_record_digest.into(),
        approval_signature_raw_digest: fields.approval_signature_raw_digest.into(),
        approval_scope: fields.approval_scope.into(),
    })
}

fn approval_window_is_current(issued_raw: &str, expires_raw: &str, now: OffsetDateTime) -> bool {
    parse_exact_approval_time(issued_raw)
        .zip(parse_exact_approval_time(expires_raw))
        .is_some_and(|(issued, expires)| {
            issued < expires
                && expires - issued <= time::Duration::seconds(MAX_APPROVAL_VALIDITY_SECONDS)
                && issued <= now
                && expires > now
        })
}

fn parse_exact_approval_time(raw: &str) -> Option<OffsetDateTime> {
    let bytes = raw.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .into_iter()
            .any(|index| !bytes[index].is_ascii_digit())
    {
        return None;
    }
    let number = |start: usize, end: usize| raw.get(start..end)?.parse::<u16>().ok();
    let year = i32::from(number(0, 4)?);
    let month = Month::try_from(u8::try_from(number(5, 7)?).ok()?).ok()?;
    let day = u8::try_from(number(8, 10)?).ok()?;
    let hour = u8::try_from(number(11, 13)?).ok()?;
    let minute = u8::try_from(number(14, 16)?).ok()?;
    let second = u8::try_from(number(17, 19)?).ok()?;
    let date = Date::from_calendar_date(year, month, day).ok()?;
    let clock = Time::from_hms(hour, minute, second).ok()?;
    Some(PrimitiveDateTime::new(date, clock).assume_utc())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShapeFixture {
    schema: String,
    runtime_provenance_digest: String,
    classification: String,
    actions: BTreeMap<String, ShapeAction>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShapeAction {
    digest: String,
    operation_id: String,
    method: String,
    route: String,
    request: Value,
    responses: Value,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M2ActionDigests {
    pub session_prompt: String,
    pub question_reply: String,
    pub question_reject: String,
    pub permission_reply: String,
    pub stop: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum StockCommand {
    SessionPrompt {
        content: String,
    },
    QuestionReply {
        answers: Vec<Vec<String>>,
    },
    PermissionDeny,
    Stop,
    /// Captured as a separate route but deliberately not wired to product flow.
    QuestionReject,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StockCommandRequest {
    pub business_request_id: String,
    pub session_id: String,
    pub target_id: Option<String>,
    pub seq: u64,
    pub command: StockCommand,
    pub created_at: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StockCommandResult {
    pub status: String,
    pub error_code: Option<String>,
    pub response_status: Option<u16>,
    pub shape_digest: String,
    pub idempotent_replay: bool,
}
impl std::fmt::Debug for StockCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StockCommand(<redacted>)")
    }
}
impl std::fmt::Debug for StockCommandRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StockCommandRequest(<redacted>)")
    }
}
impl std::fmt::Debug for StockCommandResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StockCommandResult")
            .field("status", &self.status)
            .field("error_code", &self.error_code)
            .field("response_status", &self.response_status)
            .field("shape_digest", &self.shape_digest)
            .field("idempotent_replay", &self.idempotent_replay)
            .finish()
    }
}

/// Content-free receipt bundle. A boolean is intentionally insufficient: shape
/// evidence and real lifecycle evidence are independently required.
#[derive(Debug, Clone)]
pub struct M2CapabilityReceipts {
    pub runtime_provenance_digest: String,
    pub action_shape_digests: M2ActionDigests,
    pub source_classification: String,
    pub real_lifecycle_evidence: RealLifecycleEvidence,
}
#[derive(Debug, Clone)]
pub enum RealLifecycleEvidence {
    Unavailable,
}
#[derive(Debug, Clone)]
pub struct VerifiedM2Capabilities(());
impl VerifiedM2Capabilities {
    pub fn from_receipts(receipts: M2CapabilityReceipts) -> Result<Self, ConnectorError> {
        let contract = load_shape_contract()?;
        if receipts.runtime_provenance_digest != contract.runtime_provenance_digest
            || receipts.source_classification != contract.classification
            || receipts.action_shape_digests != contract.digests
        {
            return Err(ConnectorError::SafetyBlocked(
                "M2 capability receipt does not match committed shapes".into(),
            ));
        }
        match receipts.real_lifecycle_evidence {
            RealLifecycleEvidence::Unavailable => Err(ConnectorError::SafetyBlocked(
                REAL_LIFECYCLE_EVIDENCE_REQUIRED.into(),
            )),
        }
    }
}
struct ShapeContract {
    runtime_provenance_digest: String,
    classification: String,
    digests: M2ActionDigests,
    routes: BTreeMap<String, String>,
}
fn load_shape_contract() -> Result<ShapeContract, ConnectorError> {
    parse_shape_contract(COMMAND_SHAPES)
}
fn parse_shape_contract(raw: &str) -> Result<ShapeContract, ConnectorError> {
    let fixture: ShapeFixture = serde_json::from_str(raw)
        .map_err(|_| ConnectorError::SafetyBlocked("M2 command shape fixture is invalid".into()))?;
    let wanted = [
        (
            "session_prompt",
            "v2.session.prompt",
            "/api/session/{sessionID}/prompt",
        ),
        (
            "question_reply",
            "v2.session.question.reply",
            "/api/session/{sessionID}/question/{requestID}/reply",
        ),
        (
            "question_reject",
            "v2.session.question.reject",
            "/api/session/{sessionID}/question/{requestID}/reject",
        ),
        (
            "permission_reply",
            "v2.session.permission.reply",
            "/api/session/{sessionID}/permission/{requestID}/reply",
        ),
        (
            "stop",
            "v2.session.interrupt",
            "/api/session/{sessionID}/interrupt",
        ),
    ];
    if fixture.schema != "nomad.stock-opencode.command-shapes.v1"
        || fixture.classification != COMMAND_SHAPE_SOURCE
        || !lower_hex_digest(&fixture.runtime_provenance_digest)
        || fixture.actions.len() != wanted.len()
    {
        return Err(ConnectorError::SafetyBlocked(
            "M2 fixture classification is not shape-only".into(),
        ));
    }
    let mut routes = BTreeMap::new();
    let mut digest = BTreeMap::new();
    for (name, operation_id, route) in wanted {
        let action = fixture
            .actions
            .get(name)
            .ok_or_else(|| ConnectorError::SafetyBlocked("M2 fixture action missing".into()))?;
        if action.operation_id != operation_id
            || action.route != route
            || action.method != "post"
            || !lower_hex_digest(&action.digest)
            || action.digest != shape_digest(action)?
            || !semantic_shape_matches(name, action)
        {
            return Err(ConnectorError::SafetyBlocked(
                "M2 fixture action mismatch".into(),
            ));
        }
        routes.insert(name.into(), route.into());
        digest.insert(name, action.digest.clone());
    }
    Ok(ShapeContract {
        runtime_provenance_digest: fixture.runtime_provenance_digest,
        classification: fixture.classification,
        digests: M2ActionDigests {
            session_prompt: digest.remove("session_prompt").unwrap(),
            question_reply: digest.remove("question_reply").unwrap(),
            question_reject: digest.remove("question_reject").unwrap(),
            permission_reply: digest.remove("permission_reply").unwrap(),
            stop: digest.remove("stop").unwrap(),
        },
        routes,
    })
}
fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn shape_digest(action: &ShapeAction) -> Result<String, ConnectorError> {
    let value = serde_json::json!({"operation_id": action.operation_id, "route": action.route, "method": action.method, "request": action.request, "responses": action.responses});
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical_ascii_json(&value)?.as_bytes())
    ))
}
fn canonical_ascii_json(value: &Value) -> Result<String, ConnectorError> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => Ok(v.to_string()),
        Value::String(v) => {
            if !v.is_ascii() {
                return Err(ConnectorError::SafetyBlocked(
                    "non-ascii shape fixture".into(),
                ));
            }
            Ok(serde_json::to_string(v)?)
        }
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_ascii_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut pairs = Vec::new();
            for key in keys {
                if !key.is_ascii() {
                    return Err(ConnectorError::SafetyBlocked(
                        "non-ascii shape fixture".into(),
                    ));
                }
                pairs.push(format!(
                    "{}:{}",
                    serde_json::to_string(key)?,
                    canonical_ascii_json(&values[key])?
                ));
            }
            Ok(format!("{{{}}}", pairs.join(",")))
        }
    }
}
fn semantic_shape_matches(name: &str, action: &ShapeAction) -> bool {
    if name == "stop" {
        return action.request.as_object().is_some_and(|v| v.is_empty());
    }
    let Some(json) = action.request.get("application/json") else {
        return name == "question_reject"
            && action.request.as_object().is_some_and(|v| v.is_empty());
    };
    match name {
        "session_prompt" => {
            json.pointer("/properties/prompt/properties/text/type")
                == Some(&Value::String("string".into()))
                && json.pointer("/required").is_some_and(|v| {
                    v.as_array()
                        .is_some_and(|a| a.contains(&Value::String("prompt".into())))
                })
                && json.pointer("/properties/prompt/type") == Some(&Value::String("object".into()))
                && json
                    .pointer("/properties/prompt/required")
                    .is_some_and(|v| {
                        v.as_array()
                            .is_some_and(|a| a.contains(&Value::String("text".into())))
                    })
        }
        "question_reply" => {
            json.pointer("/properties/answers/type") == Some(&Value::String("array".into()))
                && json.pointer("/properties/answers/items/type")
                    == Some(&Value::String("array".into()))
                && json.pointer("/properties/answers/items/items/type")
                    == Some(&Value::String("string".into()))
                && json.pointer("/required").is_some_and(|v| {
                    v.as_array()
                        .is_some_and(|a| a.contains(&Value::String("answers".into())))
                })
        }
        "permission_reply" => {
            json.pointer("/properties/reply/type") == Some(&Value::String("string".into()))
                && json.pointer("/required").is_some_and(|v| {
                    v.as_array()
                        .is_some_and(|a| a.contains(&Value::String("reply".into())))
                })
                && json
                    .pointer("/properties/reply/enum")
                    .and_then(Value::as_array)
                    .is_some_and(|a| {
                        a == &[
                            Value::String("once".into()),
                            Value::String("always".into()),
                            Value::String("reject".into()),
                        ]
                    })
        }
        _ => false,
    }
}

pub struct StockHttpRequest {
    pub path: String,
    pub body: Option<String>,
    pub content_type: Option<&'static str>,
}
pub trait StockCommandHttp {
    fn post(&self, request: StockHttpRequest) -> Result<u16, ConnectorError>;
}

pub struct UreqStockCommandHttp {
    base_url: String,
    agent: ureq::Agent,
}
impl UreqStockCommandHttp {
    pub fn new(base_url: &str) -> Result<Self, ConnectorError> {
        validate_harness_origin(base_url)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(2))
                .timeout_read(Duration::from_secs(5))
                .timeout_write(Duration::from_secs(5))
                .build(),
        })
    }
}
impl StockCommandHttp for UreqStockCommandHttp {
    fn post(&self, command: StockHttpRequest) -> Result<u16, ConnectorError> {
        let request = self
            .agent
            .post(&format!("{}{}", self.base_url, command.path));
        let response = match command.body {
            Some(body) => request
                .set(
                    "Content-Type",
                    command.content_type.unwrap_or("application/json"),
                )
                .send_string(&body),
            None => request.call(),
        };
        match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => Ok(response.status()),
            Err(_) => Err(ConnectorError::OpenCodeUnreachable(
                "stock-command-loopback".into(),
            )),
        }
    }
}

pub struct StockCommandTransport<H> {
    journal: CommandJournal,
    http: H,
}
impl<H: StockCommandHttp> StockCommandTransport<H> {
    pub fn new(journal: CommandJournal, http: H) -> Self {
        Self { journal, http }
    }
    pub fn execute(
        &self,
        _capabilities: &VerifiedM2Capabilities,
        request: StockCommandRequest,
    ) -> Result<StockCommandResult, ConnectorError> {
        validate_stock_command_request(&request)?;
        let (http_request, shape_digest, command_type) = encode_stock_command(&request)?;
        let body = http_request.body.as_ref();
        let binding = fingerprint(
            &serde_json::json!({"command": command_type, "session": request.session_id, "target": request.target_id, "seq": request.seq, "body_digest": body.as_ref().map(|v| text_fingerprint(v)).unwrap_or_default()}),
        );
        let prepared = StockCommandResult {
            status: "Prepared".into(),
            error_code: None,
            response_status: None,
            shape_digest: shape_digest.clone(),
            idempotent_replay: false,
        };
        let row = JournalCommand {
            request_id: request.business_request_id.clone(),
            command_type: command_type.into(),
            session_id: request.session_id.clone(),
            seq: request.seq,
            status: "Prepared".into(),
            accepted_at_seq: None,
            result_json: serde_json::to_string(&prepared)?,
            created_at: request.created_at.clone(),
        };
        match self.journal.insert_or_get_bound_command(&row, &binding)? {
            InsertOrGetCommand::Existing(existing) => return existing_command_result(existing),
            InsertOrGetCommand::Inserted => {}
        }
        self.journal
            .transition_prepared_to_executing(&request.business_request_id)?;
        let outcome = match self.http.post(http_request) {
            Ok(status) if (200..300).contains(&status) => StockCommandResult {
                status: "Completed".into(),
                error_code: None,
                response_status: Some(status),
                shape_digest: shape_digest.clone(),
                idempotent_replay: false,
            },
            Ok(status) => StockCommandResult {
                status: "Rejected".into(),
                error_code: Some("UPSTREAM_REJECTED".into()),
                response_status: Some(status),
                shape_digest: shape_digest.clone(),
                idempotent_replay: false,
            },
            Err(_) => StockCommandResult {
                status: "OutcomeUnknown".into(),
                error_code: Some("ERR_OUTCOME_UNKNOWN".into()),
                response_status: None,
                shape_digest,
                idempotent_replay: false,
            },
        };
        self.journal.update_outcome(
            &request.business_request_id,
            &outcome.status,
            None,
            &serde_json::to_string(&outcome)?,
        )?;
        Ok(outcome)
    }
}
fn existing_command_result(existing: JournalCommand) -> Result<StockCommandResult, ConnectorError> {
    match existing.status.as_str() {
        "Completed" | "Rejected" | "OutcomeUnknown" => {
            let mut result: StockCommandResult = serde_json::from_str(&existing.result_json)?;
            result.idempotent_replay = true;
            Ok(result)
        }
        "Prepared" | "Executing" => Err(ConnectorError::OutcomeUnknown),
        _ => Err(ConnectorError::OutcomeUnknown),
    }
}
fn validate_stock_command_request(request: &StockCommandRequest) -> Result<(), ConnectorError> {
    if !safe_id(&request.business_request_id)
        || !safe_id(&request.session_id)
        || request.target_id.as_ref().is_some_and(|v| !safe_id(v))
        || request.seq == 0
        || !is_datetime(&request.created_at)
    {
        return Err(ConnectorError::StaleRequest(
            "invalid stock command binding".into(),
        ));
    }
    match request.command {
        StockCommand::SessionPrompt { .. } | StockCommand::Stop if request.target_id.is_some() => {
            return Err(ConnectorError::StaleRequest(
                "command must not have target".into(),
            ))
        }
        StockCommand::QuestionReply { .. }
        | StockCommand::QuestionReject
        | StockCommand::PermissionDeny
            if request.target_id.is_none() =>
        {
            return Err(ConnectorError::StaleRequest(
                "command requires target".into(),
            ))
        }
        _ => {}
    }
    Ok(())
}
fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}
fn validate_harness_origin(value: &str) -> Result<(), ConnectorError> {
    let url = Url::parse(value)
        .map_err(|_| ConnectorError::NonLoopbackUrl("invalid stock command origin".into()))?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().filter(|p| *p != 0).is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConnectorError::NonLoopbackUrl(
            "stock command origin must be bare 127.0.0.1 http origin".into(),
        ));
    }
    Ok(())
}
fn encode_stock_command(
    request: &StockCommandRequest,
) -> Result<(StockHttpRequest, String, &'static str), ConnectorError> {
    let contract = load_shape_contract()?;
    let session = &request.session_id;
    let encoded = match &request.command {
        StockCommand::SessionPrompt { content }
            if !content.is_empty() && content.len() <= MAX_COMMAND_CONTENT =>
        {
            Ok((
                StockHttpRequest {
                    path: contract.routes["session_prompt"].replace("{sessionID}", session),
                    body: Some(serde_json::to_string(
                        &serde_json::json!({"prompt": {"text": content}}),
                    )?),
                    content_type: Some("application/json"),
                },
                contract.digests.session_prompt,
                "session_prompt",
            ))
        }
        StockCommand::QuestionReply { answers } => {
            let target = request.target_id.as_ref().ok_or_else(|| {
                ConnectorError::StaleRequest("question reply requires request target".into())
            })?;
            validate_answers(answers)?;
            Ok((
                StockHttpRequest {
                    path: contract.routes["question_reply"]
                        .replace("{sessionID}", session)
                        .replace("{requestID}", target),
                    body: Some(serde_json::to_string(
                        &serde_json::json!({"answers": answers}),
                    )?),
                    content_type: Some("application/json"),
                },
                contract.digests.question_reply,
                "question_reply",
            ))
        }
        StockCommand::PermissionDeny => {
            let target = request.target_id.as_ref().ok_or_else(|| {
                ConnectorError::StaleRequest("permission deny requires request target".into())
            })?;
            Ok((
                StockHttpRequest {
                    path: contract.routes["permission_reply"]
                        .replace("{sessionID}", session)
                        .replace("{requestID}", target),
                    body: Some("{\"reply\":\"reject\"}".into()),
                    content_type: Some("application/json"),
                },
                contract.digests.permission_reply,
                "permission_deny",
            ))
        }
        StockCommand::Stop => Ok((
            StockHttpRequest {
                path: contract.routes["stop"].replace("{sessionID}", session),
                body: None,
                content_type: None,
            },
            contract.digests.stop,
            "stop",
        )),
        StockCommand::QuestionReject => {
            let target = request.target_id.as_ref().ok_or_else(|| {
                ConnectorError::StaleRequest("question reject requires request target".into())
            })?;
            Ok((
                StockHttpRequest {
                    path: contract.routes["question_reject"]
                        .replace("{sessionID}", session)
                        .replace("{requestID}", target),
                    body: None,
                    content_type: None,
                },
                contract.digests.question_reject,
                "question_reject",
            ))
        }
        StockCommand::SessionPrompt { .. } => Err(ConnectorError::StaleRequest(
            "prompt content cannot be empty".into(),
        )),
    };
    encoded.and_then(validate_wire_request)
}
fn validate_wire_request(
    request: (StockHttpRequest, String, &'static str),
) -> Result<(StockHttpRequest, String, &'static str), ConnectorError> {
    let (http, digest, command) = request;
    if !http.path.starts_with("/api/session/")
        || http.path.len() > MAX_COMMAND_PATH
        || !http.path.is_ascii()
        || http
            .path
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#' | b'%'))
        || http
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_ENCODED_BODY)
        || http.body.is_some() != http.content_type.is_some()
    {
        return Err(ConnectorError::StaleRequest(
            "invalid encoded stock command".into(),
        ));
    }
    Ok((http, digest, command))
}
fn validate_answers(answers: &[Vec<String>]) -> Result<(), ConnectorError> {
    if answers.is_empty()
        || answers.len() > MAX_ANSWER_GROUPS
        || answers
            .iter()
            .any(|group| group.is_empty() || group.len() > MAX_ANSWERS_PER_GROUP)
        || answers.iter().flatten().any(|answer| answer.is_empty())
        || answers.iter().flatten().map(String::len).sum::<usize>() > MAX_ANSWER_BYTES
    {
        return Err(ConnectorError::StaleRequest(
            "invalid question answers".into(),
        ));
    }
    Ok(())
}

pub const STOCK_VERSION: &str = "1.18.16";
const MAX_COUNT: u64 = 1_000_000;
const MAX_PENDING: usize = 1000;
const MAX_ID: usize = 512;
#[derive(Deserialize)]
struct StockEventEnvelope {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    properties: Value,
}
#[derive(Debug, Clone, PartialEq)]
pub enum StockObservationOutcome {
    Duplicate { nomad_seq: u64 },
    UnknownRequiresReconciliation,
    InvalidRequiresReconciliation { reason: String },
    MutationRequiresReconciliation,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StockSnapshotFacts {
    session_id: String,
    session_exists: bool,
    message_count: u64,
    diff_file_count: u64,
    pending_permission_count: u16,
    pending_question_count: u16,
}
impl StockSnapshotFacts {
    pub fn validated(
        session_id: String,
        session_exists: bool,
        message_count: u64,
        diff_file_count: u64,
        pending_permission_count: u16,
        pending_question_count: u16,
    ) -> Result<Self, ConnectorError> {
        if session_id.is_empty()
            || session_id.len() > MAX_ID
            || message_count > MAX_COUNT
            || diff_file_count > MAX_COUNT
            || usize::from(pending_permission_count) > MAX_PENDING
            || usize::from(pending_question_count) > MAX_PENDING
        {
            return Err(ConnectorError::ProtocolMismatch(
                "invalid bounded stock snapshot facts".into(),
            ));
        }
        Ok(Self {
            session_id,
            session_exists,
            message_count,
            diff_file_count,
            pending_permission_count,
            pending_question_count,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockReconciliation {
    pub snapshot: Option<Snapshot>,
    pub required_before: bool,
    pub status: StockReconciliationStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockReconciliationStatus {
    Reconciled,
    SessionMissing,
    NoDurableBaseline,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockCommandBoundary {
    Reply,
    DenyPermission,
    Stop,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StockBlockedCommandResult {
    pub request_id: String,
    pub status: String,
    pub error_code: String,
    pub idempotent_replay: bool,
}
impl StockCommandBoundary {
    pub fn execute(&self) -> Result<(), ConnectorError> {
        Err(ConnectorError::Other(format!(
            "BLOCKED_UNSUPPORTED: {self:?}: request shape is not contract-evidenced"
        )))
    }
}
pub struct StockOpenCodeAdapter {
    journal: CommandJournal,
}
impl StockOpenCodeAdapter {
    pub fn new(journal: CommandJournal) -> Self {
        Self { journal }
    }
    pub fn observe_json(
        &self,
        session_id: &str,
        raw: &str,
        observed_at: &str,
    ) -> Result<StockObservationOutcome, ConnectorError> {
        if session_id.trim().is_empty() || session_id.len() > MAX_ID {
            return Err(ConnectorError::ProtocolMismatch(
                "invalid stock session_id".into(),
            ));
        }
        validate_datetime(observed_at)?;
        let value: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => {
                self.journal
                    .mark_stock_reconciliation_required(session_id)?;
                return Ok(StockObservationOutcome::InvalidRequiresReconciliation {
                    reason: "invalid stock event envelope".into(),
                });
            }
        };
        let object = match value.as_object() {
            Some(v) => v,
            None => {
                self.journal
                    .mark_stock_reconciliation_required(session_id)?;
                return Ok(StockObservationOutcome::InvalidRequiresReconciliation {
                    reason: "stock event envelope must be an object".into(),
                });
            }
        };
        if object.len() != 3
            || !object.contains_key("id")
            || !object.contains_key("type")
            || !object.contains_key("properties")
        {
            self.journal
                .mark_stock_reconciliation_required(session_id)?;
            return Ok(StockObservationOutcome::InvalidRequiresReconciliation {
                reason: "stock event envelope fields are invalid".into(),
            });
        }
        let event: StockEventEnvelope = serde_json::from_value(value.clone()).map_err(|_| {
            ConnectorError::ProtocolMismatch("stock event envelope fields are invalid".into())
        })?;
        if event.id.trim().is_empty()
            || event.id.len() > MAX_ID
            || event.event_type.trim().is_empty()
            || event.event_type.len() > MAX_ID
        {
            self.journal
                .mark_stock_reconciliation_required(session_id)?;
            return Ok(StockObservationOutcome::InvalidRequiresReconciliation {
                reason: "stock event id is empty".into(),
            });
        }
        if !event.properties.is_object() {
            self.journal
                .mark_stock_reconciliation_required(session_id)?;
            return Ok(StockObservationOutcome::InvalidRequiresReconciliation {
                reason: "stock event properties must be an object".into(),
            });
        }
        match self.journal.record_unknown_stock_observation(
            session_id,
            &event.id,
            &fingerprint(&value),
            observed_at,
        )? {
            StockObservationWrite::Applied { .. } => {
                Ok(StockObservationOutcome::UnknownRequiresReconciliation)
            }
            StockObservationWrite::Duplicate { .. } => {
                Ok(StockObservationOutcome::Duplicate { nomad_seq: 0 })
            }
            StockObservationWrite::Mutation => {
                Ok(StockObservationOutcome::MutationRequiresReconciliation)
            }
        }
    }
    pub fn replay_after(
        &self,
        session_id: &str,
        after_seq: u64,
    ) -> Result<Vec<ProjectedEvent>, ConnectorError> {
        self.journal.stock_events_after(session_id, after_seq)
    }
    pub fn latest_snapshot(&self, session_id: &str) -> Result<Option<Snapshot>, ConnectorError> {
        Ok(self
            .journal
            .latest_stock_snapshot(session_id)?
            .map(|(_, s)| s))
    }
    pub fn reconcile(
        &self,
        facts: StockSnapshotFacts,
        observed_at: &str,
    ) -> Result<StockReconciliation, ConnectorError> {
        validate_datetime(observed_at)?;
        let required_before = self
            .journal
            .stock_reconciliation_required(&facts.session_id)?;
        let digest = compute_digest(&serde_json::to_value(&facts)?);
        if let Some((previous_digest, snapshot)) =
            self.journal.latest_stock_snapshot(&facts.session_id)?
        {
            if previous_digest == digest {
                if required_before {
                    self.journal
                        .reconfirm_snapshot_and_clear(&facts.session_id)?;
                }
                return Ok(StockReconciliation {
                    snapshot: Some(snapshot),
                    required_before,
                    status: StockReconciliationStatus::Reconciled,
                });
            }
        }
        if !facts.session_exists {
            return Ok(StockReconciliation {
                snapshot: None,
                required_before,
                status: StockReconciliationStatus::SessionMissing,
            });
        }
        let seq = self.journal.current_stock_seq(&facts.session_id)?;
        if seq == 0 {
            return Ok(StockReconciliation {
                snapshot: None,
                required_before,
                status: StockReconciliationStatus::NoDurableBaseline,
            });
        }
        let status = StockReconciliationStatus::Reconciled;
        let state = if !facts.session_exists {
            TurnState::OutcomeUnknown
        } else if facts.pending_permission_count > 0 {
            TurnState::NeedsPermission
        } else if facts.pending_question_count > 0 {
            TurnState::NeedsInput
        } else {
            TurnState::OutcomeUnknown
        };
        let mut snapshot = Snapshot {
            session_id: facts.session_id.clone(),
            snapshot_seq: seq,
            digest: None,
            last_applied_seq: seq,
            turn_state: state,
            turn_id: None,
            host_connectivity: HostConnectivity::Online,
            client_freshness: ClientFreshness::Reconnecting,
            state_summary: StateSummary {
                session_status: Some(if facts.session_exists {
                    "observed".into()
                } else {
                    "missing".into()
                }),
                active_turn: None,
                active_permission: None,
                diff_file_count: facts.diff_file_count,
                test_status: None,
                tool_states: Vec::new(),
            },
            created_at: observed_at.into(),
            version: "1.0.0".into(),
        };
        snapshot.digest = Some(compute_digest(&to_canonical_value(&snapshot)));
        if status == StockReconciliationStatus::Reconciled {
            self.journal
                .persist_snapshot_and_clear(&digest, &snapshot)?;
        }
        Ok(StockReconciliation {
            snapshot: Some(snapshot),
            required_before,
            status,
        })
    }
    pub fn execute_blocked_command(
        &self,
        boundary: StockCommandBoundary,
        request_id: &str,
        session_id: &str,
        seq: u64,
        created_at: &str,
    ) -> Result<StockBlockedCommandResult, ConnectorError> {
        if request_id.trim().is_empty()
            || request_id.len() > MAX_ID
            || session_id.trim().is_empty()
            || session_id.len() > MAX_ID
            || seq == 0
            || !is_datetime(created_at)
        {
            return Err(ConnectorError::StaleRequest(
                "invalid blocked command binding".into(),
            ));
        }
        let kind = format!("stock_{boundary:?}");
        let pending = StockBlockedCommandResult {
            request_id: request_id.into(),
            status: "Blocked".into(),
            error_code: "BLOCKED_UNSUPPORTED".into(),
            idempotent_replay: false,
        };
        let command = JournalCommand {
            request_id: request_id.into(),
            command_type: kind.clone(),
            session_id: session_id.into(),
            seq,
            status: pending.status.clone(),
            accepted_at_seq: None,
            result_json: serde_json::to_string(&pending)?,
            created_at: created_at.into(),
        };
        if let InsertOrGetCommand::Existing(existing) =
            self.journal.insert_or_get_command(&command)?
        {
            if existing.command_type != kind
                || existing.session_id != session_id
                || existing.seq != seq
            {
                return Err(ConnectorError::StaleRequest(
                    "request_id binding conflict".into(),
                ));
            }
            let mut r: StockBlockedCommandResult = serde_json::from_str(&existing.result_json)?;
            r.idempotent_replay = true;
            return Ok(r);
        }
        Ok(pending)
    }
    #[cfg(test)]
    fn persist_verified_projection(
        &self,
        upstream_id: &str,
        fingerprint: &str,
        mut event: ProjectedEvent,
    ) -> Result<StockObservationWrite, ConnectorError> {
        event.seq = self.journal.next_stock_seq(&event.session_id)?;
        event.event_id = format!("stock:{}:{}", event.session_id, upstream_id);
        self.journal.persist_projected_stock_event(
            &event.session_id,
            upstream_id,
            fingerprint,
            &event,
        )
    }
}
fn validate_datetime(value: &str) -> Result<(), ConnectorError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|_| ())
        .map_err(|_| ConnectorError::ProtocolMismatch("invalid RFC3339 date-time".into()))
}
fn is_datetime(value: &str) -> bool {
    validate_datetime(value).is_ok()
}
fn fingerprint(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("valid JSON"))
    )
}
fn text_fingerprint(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    use tempfile::NamedTempFile;

    fn approval_utc(
        year: i32,
        month: Month,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> OffsetDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(year, month, day).unwrap(),
            Time::from_hms(hour, minute, second).unwrap(),
        )
        .assume_utc()
    }

    #[test]
    fn approval_window_has_zero_skew_and_open_expiry() {
        let issued = approval_utc(2026, Month::August, 20, 0, 0, 0);
        assert!(approval_window_is_current(
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            issued
        ));
        assert!(approval_window_is_current(
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            approval_utc(2026, Month::August, 20, 23, 59, 59)
        ));
        assert!(!approval_window_is_current(
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            approval_utc(2026, Month::August, 21, 0, 0, 0)
        ));
        assert!(!approval_window_is_current(
            "2026-08-20T00:00:01Z",
            "2026-08-21T00:00:00Z",
            issued
        ));
    }

    #[test]
    fn approval_window_enforces_order_and_maximum_duration() {
        let now = approval_utc(2026, Month::August, 20, 0, 0, 0);
        assert!(!approval_window_is_current(
            "2026-08-20T00:00:00Z",
            "2026-08-20T00:00:00Z",
            now
        ));
        assert!(!approval_window_is_current(
            "2026-08-21T00:00:00Z",
            "2026-08-20T00:00:00Z",
            now
        ));
        assert!(approval_window_is_current(
            "2026-08-20T00:00:00Z",
            "2026-09-19T00:00:00Z",
            now
        ));
        assert!(!approval_window_is_current(
            "2026-08-20T00:00:00Z",
            "2026-09-19T00:00:01Z",
            now
        ));
    }

    #[test]
    fn approval_window_rejects_non_exact_or_invalid_utc_text() {
        let now = approval_utc(2026, Month::August, 20, 0, 0, 0);
        for issued in [
            "2026-08-20T00:00:00+00:00",
            "2026-08-20T00:00:00.0Z",
            "2026-08-20",
            "2026-08-20T00:00:00z",
            " 2026-08-20T00:00:00Z",
            "2026-8-20T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-08-20T24:00:00Z",
            "2026-08-20T00:00:60Z",
        ] {
            assert!(!approval_window_is_current(
                issued,
                "2026-08-21T00:00:00Z",
                now
            ));
        }
    }
    type CommandCalls = Rc<RefCell<Vec<StockHttpRequest>>>;
    struct MockCommandHttp {
        calls: CommandCalls,
        status: u16,
        fail: bool,
    }
    impl StockCommandHttp for MockCommandHttp {
        fn post(&self, request: StockHttpRequest) -> Result<u16, ConnectorError> {
            self.calls.borrow_mut().push(request);
            if self.fail {
                Err(ConnectorError::OpenCodeUnreachable("mock".into()))
            } else {
                Ok(self.status)
            }
        }
    }
    fn verified_test_capability() -> VerifiedM2Capabilities {
        VerifiedM2Capabilities(())
    }
    fn command_request(id: &str, command: StockCommand) -> StockCommandRequest {
        StockCommandRequest {
            business_request_id: id.into(),
            session_id: "session_1".into(),
            target_id: match command {
                StockCommand::SessionPrompt { .. } | StockCommand::Stop => None,
                _ => Some("target_1".into()),
            },
            seq: 1,
            command,
            created_at: "2026-08-19T00:00:00Z".into(),
        }
    }
    fn a(p: &std::path::Path) -> StockOpenCodeAdapter {
        StockOpenCodeAdapter::new(CommandJournal::open(p).unwrap())
    }
    fn facts() -> StockSnapshotFacts {
        StockSnapshotFacts::validated("s".into(), true, 1, 2, 1, 0).unwrap()
    }
    fn event(seq: u64) -> ProjectedEvent {
        ProjectedEvent {
            event_type: "session.updated".into(),
            session_id: "s".into(),
            turn_id: None,
            event_id: format!("stock:s:e{seq}"),
            seq,
            timestamp: "2026-08-19T00:00:00Z".into(),
            durable: true,
            payload: Some(json!({"verified":true})),
        }
    }
    #[test]
    fn stock_names_are_unknown() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        assert!(matches!(
            x.observe_json(
                "s",
                r#"{"id":"x","type":"permission.asked","properties":{}}"#,
                "2026-08-19T00:00:00Z"
            )
            .unwrap(),
            StockObservationOutcome::UnknownRequiresReconciliation
        ));
    }
    #[test]
    fn durable_replay_restart_no_gaps() {
        let f = NamedTempFile::new().unwrap();
        let x = a(f.path());
        assert!(matches!(
            x.persist_verified_projection("a", "fa", event(1)).unwrap(),
            StockObservationWrite::Applied { nomad_seq: 1 }
        ));
        assert!(matches!(
            x.persist_verified_projection("b", "fb", event(2)).unwrap(),
            StockObservationWrite::Applied { nomad_seq: 2 }
        ));
        drop(x);
        let replay = a(f.path()).replay_after("s", 0).unwrap();
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].seq, 1);
        assert_eq!(replay[1].seq, 2);
        assert_eq!(replay[0].event_id, "stock:s:a");
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&a(f.path()).replay_after("s", 0).unwrap()).unwrap()
        );
    }
    #[test]
    fn mutation_and_duplicate_are_distinct() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.persist_verified_projection("raw", "one", event(1))
            .unwrap();
        assert!(matches!(
            x.persist_verified_projection("raw", "one", event(1))
                .unwrap(),
            StockObservationWrite::Duplicate { .. }
        ));
        assert_eq!(
            x.persist_verified_projection("raw", "two", event(1))
                .unwrap(),
            StockObservationWrite::Mutation
        );
    }
    #[test]
    fn snapshot_persists_and_identical_facts_reuse() {
        let f = NamedTempFile::new().unwrap();
        let x = a(f.path());
        x.persist_verified_projection("baseline", "baseline", event(0))
            .unwrap();
        let one = x.reconcile(facts(), "2026-08-19T00:00:00Z").unwrap();
        assert!(!x.journal.stock_reconciliation_required("s").unwrap());
        drop(x);
        let y = a(f.path());
        assert_eq!(y.latest_snapshot("s").unwrap(), one.snapshot.clone());
        let two = y.reconcile(facts(), "2026-08-19T00:01:00Z").unwrap();
        assert_eq!(two.snapshot, one.snapshot);
        assert!(y
            .replay_after("s", two.snapshot.as_ref().unwrap().last_applied_seq)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn missing_session_does_not_clear_flag() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.observe_json(
            "s",
            r#"{"id":"x","type":"x","properties":{}}"#,
            "2026-08-19T00:00:00Z",
        )
        .unwrap();
        let f = StockSnapshotFacts::validated("s".into(), false, 0, 0, 0, 0).unwrap();
        assert_eq!(
            x.reconcile(f, "2026-08-19T00:00:00Z").unwrap().status,
            StockReconciliationStatus::SessionMissing
        );
        assert!(x.journal.stock_reconciliation_required("s").unwrap());
    }
    #[test]
    fn invalid_inputs_fail_closed() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        for raw in [
            "{",
            r#"{"id":"x","type":"x","properties":{},"extra":1}"#,
            r#"{"id":"","type":"x","properties":{}}"#,
            r#"{"id":"x","type":"x","properties":[]}"#,
        ] {
            assert!(matches!(
                x.observe_json("s", raw, "2026-08-19T00:00:00Z").unwrap(),
                StockObservationOutcome::InvalidRequiresReconciliation { .. }
            ));
        }
        assert!(x.journal.stock_reconciliation_required("s").unwrap());
    }
    #[test]
    fn command_binding_conflict_rejected() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.execute_blocked_command(
            StockCommandBoundary::Stop,
            "r",
            "s",
            1,
            "2026-08-19T00:00:00Z",
        )
        .unwrap();
        assert!(matches!(
            x.execute_blocked_command(
                StockCommandBoundary::Reply,
                "r",
                "s",
                1,
                "2026-08-19T00:00:00Z"
            ),
            Err(ConnectorError::StaleRequest(_))
        ));
    }
    #[test]
    fn same_facts_after_invalid_reconfirms_and_clears_flag() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.persist_verified_projection("baseline", "baseline", event(0))
            .unwrap();
        x.reconcile(facts(), "2026-08-19T00:00:00Z").unwrap();
        x.observe_json("s", "{", "2026-08-19T00:01:00Z").unwrap();
        assert!(x.journal.stock_reconciliation_required("s").unwrap());
        x.reconcile(facts(), "2026-08-19T00:01:00Z").unwrap();
        assert!(!x.journal.stock_reconciliation_required("s").unwrap());
    }
    #[test]
    fn mutation_reasserts_reconciliation_after_snapshot() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.observe_json(
            "s",
            r#"{"id":"x","type":"one","properties":{}}"#,
            "2026-08-19T00:00:00Z",
        )
        .unwrap();
        x.persist_verified_projection("baseline", "baseline", event(0))
            .unwrap();
        x.reconcile(facts(), "2026-08-19T00:00:00Z").unwrap();
        assert!(!x.journal.stock_reconciliation_required("s").unwrap());
        assert_eq!(
            x.observe_json(
                "s",
                r#"{"id":"x","type":"two","properties":{}}"#,
                "2026-08-19T00:01:00Z"
            )
            .unwrap(),
            StockObservationOutcome::MutationRequiresReconciliation
        );
        assert!(x.journal.stock_reconciliation_required("s").unwrap());
    }
    #[test]
    fn invalid_session_and_command_binding_are_rejected() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        assert!(matches!(
            x.observe_json("", "{}", "2026-08-19T00:00:00Z"),
            Err(ConnectorError::ProtocolMismatch(_))
        ));
        assert!(matches!(
            x.execute_blocked_command(
                StockCommandBoundary::Stop,
                "",
                "s",
                1,
                "2026-08-19T00:00:00Z"
            ),
            Err(ConnectorError::StaleRequest(_))
        ));
    }
    #[test]
    fn unknown_outcomes_and_snapshots_do_not_expose_raw_identifiers() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        let outcome = x
            .observe_json(
                "s",
                r#"{"id":"private-upstream-id","type":"private.type","properties":{}}"#,
                "2026-08-19T00:00:00Z",
            )
            .unwrap();
        assert_eq!(
            outcome,
            StockObservationOutcome::UnknownRequiresReconciliation
        );
        x.persist_verified_projection("baseline", "baseline", event(0))
            .unwrap();
        let snapshot = x
            .reconcile(facts(), "2026-08-19T00:00:00Z")
            .unwrap()
            .snapshot
            .unwrap();
        assert_eq!(snapshot.state_summary.active_permission, None);
        assert!(!format!("{snapshot:?}").contains("private-upstream-id"));
    }
    #[test]
    fn verified_writer_rejects_unbounded_or_invalid_projection() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        let mut invalid = event(1);
        invalid.durable = false;
        assert!(x.persist_verified_projection("a", "f", invalid).is_err());
    }
    #[test]
    fn no_durable_baseline_returns_no_snapshot_and_keeps_flag() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.observe_json(
            "s",
            r#"{"id":"x","type":"x","properties":{}}"#,
            "2026-08-19T00:00:00Z",
        )
        .unwrap();
        let result = x.reconcile(facts(), "2026-08-19T00:00:00Z").unwrap();
        assert_eq!(result.status, StockReconciliationStatus::NoDurableBaseline);
        assert_eq!(result.snapshot, None);
        assert!(x.journal.stock_reconciliation_required("s").unwrap());
    }
    #[test]
    fn malformed_rfc3339_is_rejected_before_stock_write() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        assert!(matches!(
            x.observe_json(
                "s",
                r#"{"id":"x","type":"x","properties":{}}"#,
                "2026-99-99T25:00:00+99:00"
            ),
            Err(ConnectorError::ProtocolMismatch(_))
        ));
    }
    #[test]
    fn verified_event_preserves_flag_until_snapshot_reconcile() {
        let x = StockOpenCodeAdapter::new(CommandJournal::open_memory().unwrap());
        x.observe_json(
            "s",
            r#"{"id":"unknown","type":"x","properties":{}}"#,
            "2026-08-19T00:00:00Z",
        )
        .unwrap();
        x.persist_verified_projection("baseline", "baseline", event(0))
            .unwrap();
        assert!(x.journal.stock_reconciliation_required("s").unwrap());
        x.reconcile(facts(), "2026-08-19T00:01:00Z").unwrap();
        assert!(!x.journal.stock_reconciliation_required("s").unwrap());
    }
    #[test]
    fn file_backed_same_command_binding_replays_across_connections() {
        let file = NamedTempFile::new().unwrap();
        let first = a(file.path());
        let initial = first
            .execute_blocked_command(
                StockCommandBoundary::Stop,
                "request",
                "s",
                1,
                "2026-08-19T00:00:00Z",
            )
            .unwrap();
        drop(first);
        let second = a(file.path());
        let replay = second
            .execute_blocked_command(
                StockCommandBoundary::Stop,
                "request",
                "s",
                1,
                "2026-08-19T00:00:00Z",
            )
            .unwrap();
        assert!(!initial.idempotent_replay);
        assert!(replay.idempotent_replay);
        assert!(matches!(
            second.execute_blocked_command(
                StockCommandBoundary::Reply,
                "request",
                "s",
                1,
                "2026-08-19T00:00:00Z",
            ),
            Err(ConnectorError::StaleRequest(_))
        ));
    }
    #[test]
    fn m2_exact_shapes_ids_and_stop_header_semantics() {
        let calls = Rc::new(RefCell::new(vec![]));
        let transport = StockCommandTransport::new(
            CommandJournal::open_memory().unwrap(),
            MockCommandHttp {
                calls: calls.clone(),
                status: 204,
                fail: false,
            },
        );
        transport
            .execute(
                &verified_test_capability(),
                command_request(
                    "p",
                    StockCommand::SessionPrompt {
                        content: "x".into(),
                    },
                ),
            )
            .unwrap();
        transport
            .execute(
                &verified_test_capability(),
                command_request("r", StockCommand::QuestionReject),
            )
            .unwrap();
        transport
            .execute(
                &verified_test_capability(),
                command_request(
                    "q",
                    StockCommand::QuestionReply {
                        answers: vec![vec!["yes".into()]],
                    },
                ),
            )
            .unwrap();
        transport
            .execute(
                &verified_test_capability(),
                command_request("d", StockCommand::PermissionDeny),
            )
            .unwrap();
        let mut stop = command_request("s", StockCommand::Stop);
        stop.target_id = None;
        transport
            .execute(&verified_test_capability(), stop)
            .unwrap();
        let calls = calls.borrow();
        assert_eq!(calls[0].path, "/api/session/session_1/prompt");
        assert_eq!(calls[0].body.as_deref(), Some(r#"{"prompt":{"text":"x"}}"#));
        assert_eq!(calls[0].content_type, Some("application/json"));
        assert_eq!(
            calls[1].path,
            "/api/session/session_1/question/target_1/reject"
        );
        assert!(calls[1].body.is_none() && calls[1].content_type.is_none());
        assert_eq!(
            calls[2].path,
            "/api/session/session_1/question/target_1/reply"
        );
        assert_eq!(calls[2].body.as_deref(), Some(r#"{"answers":[["yes"]]}"#));
        assert_eq!(calls[2].content_type, Some("application/json"));
        assert_eq!(
            calls[3].path,
            "/api/session/session_1/permission/target_1/reply"
        );
        assert_eq!(calls[3].body.as_deref(), Some(r#"{"reply":"reject"}"#));
        assert_eq!(calls[3].content_type, Some("application/json"));
        assert_eq!(calls[4].path, "/api/session/session_1/interrupt");
        assert!(calls[4].body.is_none() && calls[4].content_type.is_none());
        drop(calls);
        for bad in ["x/y", "x?y", "x%20", "é"] {
            let mut request = command_request("bad", StockCommand::Stop);
            request.session_id = bad.into();
            assert!(transport
                .execute(&verified_test_capability(), request)
                .is_err());
        }
        let max = "x".repeat(MAX_COMMAND_CONTENT);
        assert!(transport
            .execute(
                &verified_test_capability(),
                command_request("max", StockCommand::SessionPrompt { content: max })
            )
            .is_ok());
        let too_large = "x".repeat(MAX_COMMAND_CONTENT + 1);
        assert!(transport
            .execute(
                &verified_test_capability(),
                command_request("over", StockCommand::SessionPrompt { content: too_large })
            )
            .is_err());
    }
    #[test]
    fn m2_http_failure_and_restart_rows_never_reissue() {
        let file = NamedTempFile::new().unwrap();
        let calls = Rc::new(RefCell::new(vec![]));
        let first = StockCommandTransport::new(
            CommandJournal::open(file.path()).unwrap(),
            MockCommandHttp {
                calls: calls.clone(),
                status: 204,
                fail: true,
            },
        );
        let request = command_request("once", StockCommand::PermissionDeny);
        let result = first
            .execute(&verified_test_capability(), request.clone())
            .unwrap();
        assert_eq!(result.status, "OutcomeUnknown");
        assert_eq!(result.error_code.as_deref(), Some("ERR_OUTCOME_UNKNOWN"));
        assert!(!format!("{result:?}").contains("target_1"));
        drop(first);
        let second_calls = Rc::new(RefCell::new(vec![]));
        let second = StockCommandTransport::new(
            CommandJournal::open(file.path()).unwrap(),
            MockCommandHttp {
                calls: second_calls.clone(),
                status: 204,
                fail: false,
            },
        );
        assert!(
            second
                .execute(&verified_test_capability(), request)
                .unwrap()
                .idempotent_replay
        );
        assert!(second_calls.borrow().is_empty());
        let prepared = command_request("prepared", StockCommand::Stop);
        let row = JournalCommand {
            request_id: prepared.business_request_id.clone(),
            command_type: "stop".into(),
            session_id: prepared.session_id.clone(),
            seq: 1,
            status: "Prepared".into(),
            accepted_at_seq: None,
            result_json: "{}".into(),
            created_at: prepared.created_at.clone(),
        };
        let j = CommandJournal::open(file.path()).unwrap();
        j.insert_or_get_bound_command(&row, "prepared-binding")
            .unwrap();
        drop(j);
        let third = StockCommandTransport::new(
            CommandJournal::open(file.path()).unwrap(),
            MockCommandHttp {
                calls: second_calls.clone(),
                status: 204,
                fail: false,
            },
        );
        assert!(matches!(
            third.execute(&verified_test_capability(), prepared),
            Err(ConnectorError::StaleRequest(_)) | Err(ConnectorError::OutcomeUnknown)
        ));
        assert!(second_calls.borrow().is_empty());
    }
    #[test]
    fn m2_completed_command_reopens_as_zero_http_replay() {
        let file = NamedTempFile::new().unwrap();
        let first_calls = Rc::new(RefCell::new(vec![]));
        let first = StockCommandTransport::new(
            CommandJournal::open(file.path()).unwrap(),
            MockCommandHttp {
                calls: first_calls.clone(),
                status: 204,
                fail: false,
            },
        );
        let request = command_request("completed", StockCommand::PermissionDeny);
        assert_eq!(
            first
                .execute(&verified_test_capability(), request.clone())
                .unwrap()
                .status,
            "Completed"
        );
        assert_eq!(first_calls.borrow().len(), 1);
        drop(first);
        let replay_calls = Rc::new(RefCell::new(vec![]));
        let replay = StockCommandTransport::new(
            CommandJournal::open(file.path()).unwrap(),
            MockCommandHttp {
                calls: replay_calls.clone(),
                status: 204,
                fail: false,
            },
        )
        .execute(&verified_test_capability(), request)
        .unwrap();
        assert!(replay.idempotent_replay);
        assert!(replay_calls.borrow().is_empty());
    }
    #[test]
    fn m2_origin_is_bare_random_loopback_only() {
        assert!(UreqStockCommandHttp::new("http://127.0.0.1:43123").is_ok());
        for bad in [
            "http://localhost:43123",
            "https://127.0.0.1:43123",
            "http://127.0.0.1:43123/x",
            "http://user@127.0.0.1:43123",
            "http://127.0.0.1:0",
        ] {
            assert!(UreqStockCommandHttp::new(bad).is_err());
        }
    }
    #[test]
    fn m2_fixture_digest_and_semantic_tampering_blocks() {
        assert!(load_shape_contract().is_ok());
        for (from, to) in [
            ("v2.session.prompt", "v2.session.prompt.bad"),
            ("\"type\": \"string\"", "\"type\": \"number\""),
            ("\"204\": {}", "\"204\": {\"unexpected\":true}"),
        ] {
            let modified = COMMAND_SHAPES.replacen(from, to, 1);
            assert!(parse_shape_contract(&modified).is_err(), "tamper {from}");
        }
    }
}
