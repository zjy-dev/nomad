//! Fixed-version OpenCode HTTP boundary for Controlled Pilot v0.2.
//!
//! The boundary is deliberately narrow: one exact loopback origin, one upstream
//! version, a bounded durable-event capture, and three writable operations.
//! Network ambiguity, malformed JSON, gaps, and unknown event types fail closed.

use crate::error::ConnectorError;
use crate::journal::{CommandJournal, JournalCommand};
use crate::projection::{
    project_events, project_to_state_summary, ClientFreshness, HostConnectivity, ProjectedEvent,
    Snapshot,
};
use crate::snapshot::{compute_digest, to_canonical_value};
use crate::url_gate::{check_version, EXPECTED_BASE_URL};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Read;
use std::time::{Duration, SystemTime};

const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;
const CONTRACT_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCodeSession {
    pub id: String,
    pub version: String,
    pub status: String,
    #[serde(rename = "turnID", default)]
    pub turn_id: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenCodeEvent {
    pub id: String,
    pub seq: u64,
    pub timestamp: String,
    pub durable: bool,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    #[serde(rename = "turnID", default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileDiff {
    pub file: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub additions: u64,
    pub deletions: u64,
    pub patch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCodeCommandResponse {
    pub request_id: String,
    pub status: String,
    #[serde(default)]
    pub accepted_at_seq: Option<u64>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub duplicate: bool,
    #[serde(default)]
    pub upstream_pending_bound: Option<bool>,
}

pub trait OpenCodeClient {
    fn preflight(&self) -> Result<String, ConnectorError>;
    fn session(&self, session_id: &str) -> Result<OpenCodeSession, ConnectorError>;
    fn events(&self, session_id: &str, after: u64) -> Result<Vec<OpenCodeEvent>, ConnectorError>;
    fn diff(&self, session_id: &str) -> Result<Vec<FileDiff>, ConnectorError>;
    fn reply(
        &self,
        session_id: &str,
        request_id: &str,
        content: &str,
    ) -> Result<OpenCodeCommandResponse, ConnectorError>;
    fn deny(
        &self,
        session_id: &str,
        permission_id: &str,
        request_id: &str,
    ) -> Result<OpenCodeCommandResponse, ConnectorError>;
    fn stop(
        &self,
        session_id: &str,
        target_turn_id: &str,
        request_id: &str,
    ) -> Result<OpenCodeCommandResponse, ConnectorError>;
    fn source_label(&self) -> &str;
}

pub struct UreqOpenCodeClient {
    base_url: String,
    agent: ureq::Agent,
}

impl UreqOpenCodeClient {
    pub fn new(base_url: &str) -> Result<Self, ConnectorError> {
        let normalized = base_url.trim_end_matches('/');
        if normalized != EXPECTED_BASE_URL {
            return Err(ConnectorError::NonLoopbackUrl(format!(
                "{base_url}: pilot adapter requires exact origin {EXPECTED_BASE_URL}"
            )));
        }
        Ok(Self {
            base_url: normalized.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(2))
                .timeout_read(Duration::from_secs(5))
                .timeout_write(Duration::from_secs(5))
                .build(),
        })
    }

    pub fn fixed() -> Result<Self, ConnectorError> {
        Self::new(EXPECTED_BASE_URL)
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, ConnectorError> {
        let response = self
            .agent
            .get(&format!("{}{}", self.base_url, path))
            .call()
            .map_err(|error| map_ureq_error(error, &self.base_url))?;
        parse_json_response(response)
    }

    fn post_command(
        &self,
        path: &str,
        request_id: &str,
        body: &Value,
    ) -> Result<OpenCodeCommandResponse, ConnectorError> {
        let request = self
            .agent
            .post(&format!("{}{}", self.base_url, path))
            .set("Content-Type", "application/json")
            .set("Idempotency-Key", request_id);
        match request.send_string(&serde_json::to_string(body)?) {
            Ok(response) => parse_json_response(response),
            Err(ureq::Error::Status(_, response)) => {
                let parsed: OpenCodeCommandResponse = parse_json_response(response)?;
                Ok(parsed)
            }
            Err(error) => Err(map_ureq_error(error, &self.base_url)),
        }
    }
}

impl OpenCodeClient for UreqOpenCodeClient {
    fn preflight(&self) -> Result<String, ConnectorError> {
        #[derive(Deserialize)]
        struct Health {
            healthy: bool,
            version: String,
        }
        let health: Health = self.get_json("/global/health")?;
        if !health.healthy {
            return Err(ConnectorError::ProtocolMismatch(
                "/global/health reported unhealthy".to_string(),
            ));
        }
        check_version(&health.version)?;
        Ok(health.version)
    }

    fn session(&self, session_id: &str) -> Result<OpenCodeSession, ConnectorError> {
        self.get_json(&format!("/session/{session_id}"))
    }

    fn events(&self, session_id: &str, after: u64) -> Result<Vec<OpenCodeEvent>, ConnectorError> {
        let response = self
            .agent
            .get(&format!(
                "{}/event?sessionID={session_id}&after={after}",
                self.base_url
            ))
            .call()
            .map_err(|error| map_ureq_error(error, &self.base_url))?;
        let content_type = response
            .header("Content-Type")
            .unwrap_or("application/json")
            .to_ascii_lowercase();
        if content_type.contains("text/event-stream") {
            let body = read_bounded(response)?;
            parse_sse_events(&body)
        } else {
            parse_json_response(response)
        }
    }

    fn diff(&self, session_id: &str) -> Result<Vec<FileDiff>, ConnectorError> {
        self.get_json(&format!("/session/{session_id}/diff"))
    }

    fn reply(
        &self,
        session_id: &str,
        request_id: &str,
        content: &str,
    ) -> Result<OpenCodeCommandResponse, ConnectorError> {
        self.post_command(
            &format!("/session/{session_id}/prompt_async"),
            request_id,
            &json!({"request_id": request_id, "content": content}),
        )
    }

    fn deny(
        &self,
        session_id: &str,
        permission_id: &str,
        request_id: &str,
    ) -> Result<OpenCodeCommandResponse, ConnectorError> {
        self.post_command(
            &format!("/session/{session_id}/permissions/{permission_id}"),
            request_id,
            &json!({"request_id": request_id, "allow": false}),
        )
    }

    fn stop(
        &self,
        session_id: &str,
        target_turn_id: &str,
        request_id: &str,
    ) -> Result<OpenCodeCommandResponse, ConnectorError> {
        self.post_command(
            &format!("/session/{session_id}/abort"),
            request_id,
            &json!({
                "request_id": request_id,
                "target_turn_id": target_turn_id
            }),
        )
    }

    fn source_label(&self) -> &str {
        "fixed-opencode-http"
    }
}

fn map_ureq_error(error: ureq::Error, base_url: &str) -> ConnectorError {
    match error {
        ureq::Error::Status(status, response) => {
            let message = read_bounded(response).unwrap_or_else(|_| "unreadable response".into());
            ConnectorError::OpenCodeHttpStatus { status, message }
        }
        ureq::Error::Transport(transport) => {
            ConnectorError::OpenCodeUnreachable(format!("{base_url}: {transport}"))
        }
    }
}

fn read_bounded(response: ureq::Response) -> Result<String, ConnectorError> {
    let mut reader = response.into_reader().take(MAX_BODY_BYTES + 1);
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .map_err(|error| ConnectorError::ProtocolMismatch(format!("response read: {error}")))?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(ConnectorError::ProtocolMismatch(format!(
            "response exceeds {MAX_BODY_BYTES} bytes"
        )));
    }
    Ok(body)
}

fn parse_json_response<T: for<'de> Deserialize<'de>>(
    response: ureq::Response,
) -> Result<T, ConnectorError> {
    let body = read_bounded(response)?;
    serde_json::from_str(&body).map_err(|error| {
        ConnectorError::ProtocolMismatch(format!("invalid JSON response: {error}"))
    })
}

fn parse_sse_events(body: &str) -> Result<Vec<OpenCodeEvent>, ConnectorError> {
    let mut events = Vec::new();
    for frame in body.split("\n\n") {
        let data = frame
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        let event = serde_json::from_str(&data).map_err(|error| {
            ConnectorError::ProtocolMismatch(format!("invalid SSE data JSON: {error}"))
        })?;
        events.push(event);
    }
    Ok(events)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSource {
    pub transport: String,
    pub interface: String,
    pub opencode_version: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PilotCapture {
    pub source: CaptureSource,
    pub session: OpenCodeSession,
    pub snapshot: Snapshot,
    pub events: Vec<ProjectedEvent>,
    pub diff: Vec<FileDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command_type", rename_all = "snake_case")]
pub enum PilotCommand {
    Reply {
        request_id: String,
        session_id: String,
        seq: u64,
        content: String,
    },
    PermissionDecision {
        request_id: String,
        session_id: String,
        seq: u64,
        permission_id: String,
        decision: String,
        action_hash: String,
        expires_at: String,
    },
    Stop {
        request_id: String,
        session_id: String,
        seq: u64,
        target_turn_id: String,
    },
}

impl PilotCommand {
    fn request_id(&self) -> &str {
        match self {
            Self::Reply { request_id, .. }
            | Self::PermissionDecision { request_id, .. }
            | Self::Stop { request_id, .. } => request_id,
        }
    }

    fn session_id(&self) -> &str {
        match self {
            Self::Reply { session_id, .. }
            | Self::PermissionDecision { session_id, .. }
            | Self::Stop { session_id, .. } => session_id,
        }
    }

    fn seq(&self) -> u64 {
        match self {
            Self::Reply { seq, .. }
            | Self::PermissionDecision { seq, .. }
            | Self::Stop { seq, .. } => *seq,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Reply { .. } => "reply",
            Self::PermissionDecision { .. } => "permission_decision",
            Self::Stop { .. } => "stop",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterCommandResult {
    pub request_id: String,
    pub command_type: String,
    pub status: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub idempotent_replay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_pending_bound: Option<bool>,
}

pub struct PilotAdapter<C> {
    client: C,
    journal: CommandJournal,
}

impl<C: OpenCodeClient> PilotAdapter<C> {
    pub fn new(client: C, journal: CommandJournal) -> Self {
        Self { client, journal }
    }

    pub fn capture(&self, session_id: &str) -> Result<PilotCapture, ConnectorError> {
        let version = self.client.preflight()?;
        let session = self.client.session(session_id)?;
        check_version(&session.version)?;
        if session.id != session_id {
            return Err(ConnectorError::ProtocolMismatch(format!(
                "requested session {session_id}, received {}",
                session.id
            )));
        }
        let upstream_events = self.client.events(session_id, 0)?;
        let events = project_upstream_events(session_id, &upstream_events)?;
        if events.is_empty() {
            return Err(ConnectorError::ProtocolMismatch(
                "durable event stream is empty".to_string(),
            ));
        }
        let diff = self.client.diff(session_id)?;
        let state = project_events(&events);
        let mut state_summary = project_to_state_summary(&events);
        state_summary.diff_file_count = diff.len() as u64;
        let last = events.last().expect("events checked non-empty");
        let mut snapshot = Snapshot {
            session_id: session_id.to_string(),
            snapshot_seq: last.seq,
            digest: None,
            last_applied_seq: last.seq,
            turn_state: state.turn_state,
            turn_id: state.turn_id,
            host_connectivity: HostConnectivity::Online,
            client_freshness: ClientFreshness::Live,
            state_summary,
            created_at: last.timestamp.clone(),
            version: CONTRACT_VERSION.to_string(),
        };
        snapshot.digest = Some(compute_digest(&to_canonical_value(&snapshot)));
        Ok(PilotCapture {
            source: CaptureSource {
                transport: "http".to_string(),
                interface: self.client.source_label().to_string(),
                opencode_version: version,
                evidence: "fixed-interface; fake responses are not live OpenCode certification"
                    .to_string(),
            },
            session,
            snapshot,
            events,
            diff,
        })
    }

    pub fn execute(&self, command: &PilotCommand) -> Result<AdapterCommandResult, ConnectorError> {
        if command.request_id().is_empty() || command.session_id().is_empty() || command.seq() == 0
        {
            return Err(ConnectorError::StaleRequest(
                "request_id, session_id and positive seq are required".to_string(),
            ));
        }
        if let Some(existing) = self.journal.get_by_request_id(command.request_id())? {
            return self.replay_existing(existing);
        }

        if let PilotCommand::PermissionDecision { decision, .. } = command {
            if decision == "allow_once" {
                let result = AdapterCommandResult {
                    request_id: command.request_id().to_string(),
                    command_type: command.name().to_string(),
                    status: "Rejected".to_string(),
                    error_code: "ERR_SAFETY_BLOCKED".to_string(),
                    error_message: Some("allow_once is disabled for Controlled Pilot v0.2".into()),
                    accepted_at_seq: None,
                    event_id: None,
                    idempotent_replay: false,
                    upstream_pending_bound: None,
                };
                self.insert_final(command, &result)?;
                return Ok(result);
            }
            if decision != "deny" {
                return Err(ConnectorError::SafetyBlocked(format!(
                    "unsupported permission decision {decision}"
                )));
            }
        }

        self.client.preflight()?;
        let pending = AdapterCommandResult {
            request_id: command.request_id().to_string(),
            command_type: command.name().to_string(),
            status: "OutcomeUnknown".to_string(),
            error_code: "ERR_OUTCOME_UNKNOWN".to_string(),
            error_message: Some("Host execution began without a durable upstream result".into()),
            accepted_at_seq: None,
            event_id: None,
            idempotent_replay: false,
            upstream_pending_bound: None,
        };
        self.journal.insert(&JournalCommand {
            request_id: command.request_id().to_string(),
            command_type: command.name().to_string(),
            session_id: command.session_id().to_string(),
            seq: command.seq(),
            status: "Executing".to_string(),
            accepted_at_seq: None,
            result_json: serde_json::to_string(&pending)?,
            created_at: unix_timestamp(),
        })?;

        let upstream = match command {
            PilotCommand::Reply {
                session_id,
                request_id,
                content,
                ..
            } => {
                if content.trim().is_empty() {
                    let result = rejected_result(command, "ERR_REQUEST_STALE", "reply is empty");
                    self.store_result(&result)?;
                    return Ok(result);
                }
                self.client.reply(session_id, request_id, content)
            }
            PilotCommand::PermissionDecision {
                session_id,
                request_id,
                permission_id,
                action_hash,
                expires_at,
                ..
            } => {
                if permission_id.is_empty() || action_hash.is_empty() || expires_at.is_empty() {
                    let result = rejected_result(
                        command,
                        "ERR_REQUEST_STALE",
                        "deny requires permission_id, action_hash and expires_at",
                    );
                    self.store_result(&result)?;
                    return Ok(result);
                }
                self.client.deny(session_id, permission_id, request_id)
            }
            PilotCommand::Stop {
                session_id,
                request_id,
                target_turn_id,
                ..
            } => self.client.stop(session_id, target_turn_id, request_id),
        };

        match upstream {
            Ok(response) => {
                if response.request_id != command.request_id() {
                    return Err(ConnectorError::ProtocolMismatch(format!(
                        "command response request_id mismatch: expected {}, got {}",
                        command.request_id(),
                        response.request_id
                    )));
                }
                let result = AdapterCommandResult {
                    request_id: response.request_id,
                    command_type: command.name().to_string(),
                    status: response.status,
                    error_code: response.error_code.unwrap_or_else(|| "OK".to_string()),
                    error_message: response.error_message,
                    accepted_at_seq: response.accepted_at_seq,
                    event_id: response.event_id,
                    idempotent_replay: response.duplicate,
                    upstream_pending_bound: response.upstream_pending_bound,
                };
                self.store_result(&result)?;
                Ok(result)
            }
            Err(error) => {
                self.store_result(&pending)?;
                Err(error)
            }
        }
    }

    fn insert_final(
        &self,
        command: &PilotCommand,
        result: &AdapterCommandResult,
    ) -> Result<(), ConnectorError> {
        self.journal.insert(&JournalCommand {
            request_id: command.request_id().to_string(),
            command_type: command.name().to_string(),
            session_id: command.session_id().to_string(),
            seq: command.seq(),
            status: result.status.clone(),
            accepted_at_seq: result.accepted_at_seq,
            result_json: serde_json::to_string(result)?,
            created_at: unix_timestamp(),
        })
    }

    fn store_result(&self, result: &AdapterCommandResult) -> Result<(), ConnectorError> {
        self.journal.update_outcome(
            &result.request_id,
            &result.status,
            result.accepted_at_seq,
            &serde_json::to_string(result)?,
        )
    }

    fn replay_existing(
        &self,
        existing: JournalCommand,
    ) -> Result<AdapterCommandResult, ConnectorError> {
        let mut result: AdapterCommandResult = serde_json::from_str(&existing.result_json)
            .map_err(|error| ConnectorError::Journal(format!("invalid saved result: {error}")))?;
        if existing.status == "Executing" {
            result.status = "OutcomeUnknown".to_string();
            result.error_code = "ERR_OUTCOME_UNKNOWN".to_string();
            self.store_result(&result)?;
        }
        result.idempotent_replay = true;
        Ok(result)
    }
}

fn rejected_result(command: &PilotCommand, code: &str, message: &str) -> AdapterCommandResult {
    AdapterCommandResult {
        request_id: command.request_id().to_string(),
        command_type: command.name().to_string(),
        status: "Rejected".to_string(),
        error_code: code.to_string(),
        error_message: Some(message.to_string()),
        accepted_at_seq: None,
        event_id: None,
        idempotent_replay: false,
        upstream_pending_bound: None,
    }
}

fn project_upstream_events(
    session_id: &str,
    upstream: &[OpenCodeEvent],
) -> Result<Vec<ProjectedEvent>, ConnectorError> {
    let mut seen_ids = HashSet::new();
    let mut projected = Vec::with_capacity(upstream.len());
    for (expected_seq, event) in (1_u64..).zip(upstream.iter()) {
        if !event.durable {
            return Err(ConnectorError::ProtocolMismatch(format!(
                "event {} is not durable",
                event.id
            )));
        }
        if event.session_id != session_id {
            return Err(ConnectorError::ProtocolMismatch(format!(
                "event {} belongs to unexpected session {}",
                event.id, event.session_id
            )));
        }
        if event.seq != expected_seq {
            return Err(ConnectorError::ProtocolMismatch(format!(
                "durable event gap: expected seq {expected_seq}, got {}",
                event.seq
            )));
        }
        if event.id.is_empty() || !seen_ids.insert(event.id.clone()) {
            return Err(ConnectorError::ProtocolMismatch(format!(
                "empty or duplicate event id {}",
                event.id
            )));
        }
        if event.timestamp.is_empty() {
            return Err(ConnectorError::ProtocolMismatch(format!(
                "event {} has no timestamp",
                event.id
            )));
        }
        projected.push(project_one(event)?);
    }
    Ok(projected)
}

fn project_one(event: &OpenCodeEvent) -> Result<ProjectedEvent, ConnectorError> {
    let status = event.data.get("status").and_then(Value::as_str);
    let transition = event.data.get("transition").and_then(Value::as_str);
    let mapped = match event.event_type.as_str() {
        "session.created" => "session.created",
        "session.updated" => "session.updated",
        "session.status" => match (status, transition) {
            (Some("running"), Some("turn_started")) => "turn.started",
            (Some("idle" | "completed"), _) => "turn.completed",
            (Some("aborted"), _) => "turn.cancelled",
            (Some("error"), _) => "turn.failed",
            (Some("reconnecting" | "connected" | "running"), _) => "session.updated",
            _ => return unknown_event(event),
        },
        "message.updated" => {
            if event.data.get("kind").and_then(Value::as_str) == Some("question") {
                "message.accepted"
            } else if status == Some("completed") {
                "message.completed"
            } else {
                "message.accepted"
            }
        }
        "permission.updated" => {
            if status == Some("pending") {
                "permission.requested"
            } else if matches!(status, Some("denied" | "allowed" | "expired")) {
                "permission.resolved"
            } else {
                return unknown_event(event);
            }
        }
        "permission.replied" => "permission.resolved",
        "tool.started" => "tool.started",
        "tool.completed" => "tool.completed",
        "tool.error" => "tool.failed",
        "session.diff" | "file.edited" => "diff.updated",
        "session.compacted" => "session.compacted",
        _ => return unknown_event(event),
    };
    let mut payload = event.data.clone();
    if event.event_type == "message.updated"
        && event.data.get("kind").and_then(Value::as_str) == Some("question")
    {
        payload["action"] = Value::String("question".to_string());
    }
    if let Some(tool_name) = payload.get("toolName").cloned() {
        payload["tool_name"] = tool_name;
    }
    if let Some(permission_id) = payload.get("id").cloned() {
        if event.event_type.starts_with("permission.") {
            payload["permission_id"] = permission_id;
        }
    }
    Ok(ProjectedEvent {
        event_type: mapped.to_string(),
        session_id: event.session_id.clone(),
        turn_id: event.turn_id.clone(),
        event_id: event.id.clone(),
        seq: event.seq,
        timestamp: event.timestamp.clone(),
        durable: true,
        payload: Some(payload).filter(|value| !value.as_object().is_some_and(|map| map.is_empty())),
    })
}

fn unknown_event<T>(event: &OpenCodeEvent) -> Result<T, ConnectorError> {
    Err(ConnectorError::ProtocolMismatch(format!(
        "unknown or unsupported event {} ({})",
        event.event_type, event.id
    )))
}

fn unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_accepts_bounded_frames() {
        let body = "data: {\"id\":\"s:1\",\"seq\":1,\"timestamp\":\"2026-08-18T00:00:00Z\",\"durable\":true,\"type\":\"session.created\",\"sessionID\":\"s\",\"data\":{}}\n\n";
        let events = parse_sse_events(body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 1);
    }

    #[test]
    fn unknown_event_fails_closed() {
        let event = OpenCodeEvent {
            id: "s:1".into(),
            seq: 1,
            timestamp: "2026-08-18T00:00:00Z".into(),
            durable: true,
            event_type: "future.event".into(),
            session_id: "s".into(),
            turn_id: None,
            data: json!({}),
        };
        let error = project_upstream_events("s", &[event]).unwrap_err();
        assert!(matches!(error, ConnectorError::ProtocolMismatch(_)));
    }
}
