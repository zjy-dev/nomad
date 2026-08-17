//! Test-only Host → Relay → Mobile process bridge.
//!
//! This module implements the Host side of the process loop described in
//! `testkit/process-loop/spec.md`. It publishes synthetic checkpoints to
//! Mobile and consumes commands from Mobile through the test Relay API.

use crate::error::ConnectorError;
use crate::journal::CommandJournal;
use crate::permission::PermissionService;
use crate::stop_interrupt::{StopCommand, StopInterruptService};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A raw Relay message as received from or sent to the Relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayMessage {
    pub channel: String,
    pub target: String,
    pub message_id: String,
    pub payload: Value,
}

/// ACK payload for acknowledging processed messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckPayload {
    pub channel: String,
    pub target: String,
    pub message_ids: Vec<String>,
}

/// Command decision sent back to Mobile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_code: Option<String>,
}

/// Abstracts over the Relay HTTP API so we can mock it in unit tests.
pub trait RelayClient {
    fn post_message(&self, msg: &RelayMessage) -> Result<(), ConnectorError>;
    fn poll_messages(
        &self,
        channel: &str,
        target: &str,
    ) -> Result<Vec<RelayMessage>, ConnectorError>;
    fn ack_messages(&self, ack: &AckPayload) -> Result<(), ConnectorError>;
}

/// Real HTTP implementation using `ureq`.
pub struct UreqRelayClient {
    relay_url: String,
    token: String,
}

impl UreqRelayClient {
    pub fn new(relay_url: String, token: String) -> Self {
        Self { relay_url, token }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

impl RelayClient for UreqRelayClient {
    fn post_message(&self, msg: &RelayMessage) -> Result<(), ConnectorError> {
        let body = serde_json::to_string(msg)?;
        ureq::post(&format!("{}/v1/test/messages", self.relay_url))
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| ConnectorError::Other(format!("relay post: {e}")))?;
        Ok(())
    }

    fn poll_messages(
        &self,
        channel: &str,
        target: &str,
    ) -> Result<Vec<RelayMessage>, ConnectorError> {
        let url = format!(
            "{}/v1/test/messages?channel={}&target={}",
            self.relay_url, channel, target
        );
        let response = ureq::get(&url)
            .set("Authorization", &self.auth_header())
            .call()
            .map_err(|e| ConnectorError::Other(format!("relay get: {e}")))?;
        let body = response
            .into_string()
            .map_err(|e| ConnectorError::Other(format!("relay read: {e}")))?;
        let msgs: Vec<RelayMessage> = serde_json::from_str(&body)?;
        Ok(msgs)
    }

    fn ack_messages(&self, ack: &AckPayload) -> Result<(), ConnectorError> {
        let body = serde_json::to_string(ack)?;
        ureq::post(&format!("{}/v1/test/ack", self.relay_url))
            .set("Authorization", &self.auth_header())
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| ConnectorError::Other(format!("relay ack: {e}")))?;
        Ok(())
    }
}

/// Dispatches individual incoming Relay messages through the correct
/// service layer and produces a command result for Mobile.
///
/// The dispatcher owns a `Rc<CommandJournal>` so it can be cloned
/// cheaply in tests without leaking.
pub struct BridgeDispatcher {
    pub journal: Rc<CommandJournal>,
    seq: AtomicU64,
}

impl BridgeDispatcher {
    pub fn new(journal: Rc<CommandJournal>) -> Self {
        Self {
            journal,
            seq: AtomicU64::new(1),
        }
    }

    pub fn from_journal(journal: CommandJournal) -> Self {
        Self {
            journal: Rc::new(journal),
            seq: AtomicU64::new(1),
        }
    }

    /// Dispatch a single Relay message and return the resulting command
    /// result (if any) that should be posted back to Mobile.
    pub fn dispatch(&self, msg: &RelayMessage) -> Result<Option<CommandResult>, ConnectorError> {
        let msg_type = msg
            .payload
            .get("type")
            .and_then(|t| t.as_str())
            .or_else(|| msg.payload.get("message_type").and_then(|t| t.as_str()))
            .unwrap_or("unknown");

        match msg_type {
            "pair.request" => self.handle_pair_request(msg),
            "command" => self.handle_command(msg),
            _ => Ok(None),
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    fn handle_pair_request(
        &self,
        msg: &RelayMessage,
    ) -> Result<Option<CommandResult>, ConnectorError> {
        let code = msg
            .payload
            .get("comparison_code")
            .and_then(|c| c.as_str())
            .unwrap_or("");

        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(Some(CommandResult {
                status: "Rejected".to_string(),
                error_code: Some("ERR_REQUEST_STALE".to_string()),
                error_message: Some(format!(
                    "comparison_code must be exactly 6 digits, got: '{code}'"
                )),
                comparison_code: None,
            }));
        }

        Ok(Some(CommandResult {
            status: "HostAccepted".to_string(),
            error_code: None,
            error_message: None,
            comparison_code: Some(code.to_string()),
        }))
    }

    fn handle_command(&self, msg: &RelayMessage) -> Result<Option<CommandResult>, ConnectorError> {
        let action = msg
            .payload
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string();

        let request_id = msg
            .payload
            .get("request_id")
            .and_then(|r| r.as_str())
            .unwrap_or(&msg.message_id)
            .to_string();

        let session_id = msg
            .payload
            .get("session_id")
            .and_then(|s| s.as_str())
            .unwrap_or(&msg.channel)
            .to_string();

        match action.as_str() {
            "deny" => {
                let perm_id = msg
                    .payload
                    .get("permission_id")
                    .and_then(|p| p.as_str())
                    .unwrap_or("perm_default")
                    .to_string();
                let action_hash = msg
                    .payload
                    .get("action_hash")
                    .and_then(|a| a.as_str())
                    .unwrap_or("")
                    .to_string();
                let expires_at = msg
                    .payload
                    .get("expires_at")
                    .and_then(|e| e.as_str())
                    .unwrap_or("")
                    .to_string();

                let perm_svc = PermissionService::new(&self.journal);
                match perm_svc.deny(
                    &request_id,
                    &session_id,
                    &perm_id,
                    &action_hash,
                    &expires_at,
                ) {
                    Ok(cmd) => Ok(Some(CommandResult {
                        status: cmd.status,
                        error_code: None,
                        error_message: None,
                        comparison_code: None,
                    })),
                    Err(e) => {
                        let code = e.error_code().to_string();
                        Ok(Some(CommandResult {
                            status: "Error".to_string(),
                            error_code: Some(code),
                            error_message: Some(e.to_string()),
                            comparison_code: None,
                        }))
                    }
                }
            }
            "stop" => {
                let target_turn_id = msg
                    .payload
                    .get("target_turn_id")
                    .and_then(|t| t.as_str())
                    .unwrap_or(&msg.message_id)
                    .to_string();

                let stop_cmd = StopCommand {
                    request_id: request_id.clone(),
                    session_id: session_id.clone(),
                    target_turn_id,
                };

                let current_seq = self.next_seq();
                let stop_svc = StopInterruptService::new(&self.journal);
                match stop_svc.accept_stop(&stop_cmd, current_seq) {
                    Ok(_outcome) => Ok(Some(CommandResult {
                        status: "HostAccepted".to_string(),
                        error_code: None,
                        error_message: None,
                        comparison_code: None,
                    })),
                    Err(e) => {
                        let code = e.error_code().to_string();
                        Ok(Some(CommandResult {
                            status: "Error".to_string(),
                            error_code: Some(code),
                            error_message: Some(e.to_string()),
                            comparison_code: None,
                        }))
                    }
                }
            }
            "allow_once" => Ok(Some(CommandResult {
                status: "Rejected".to_string(),
                error_code: Some("ERR_SAFETY_BLOCKED".to_string()),
                error_message: Some(
                    "allow_once is not supported on Host; safety always blocked".to_string(),
                ),
                comparison_code: None,
            })),
            _ => Ok(Some(CommandResult {
                status: "Error".to_string(),
                error_code: Some("ERR_UNKNOWN_ACTION".to_string()),
                error_message: Some(format!("Unknown command action: {action}")),
                comparison_code: None,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::CommandJournal;

    fn dispatcher() -> (Rc<CommandJournal>, BridgeDispatcher) {
        let j = Rc::new(CommandJournal::open_memory().unwrap());
        let d = BridgeDispatcher::new(Rc::clone(&j));
        (j, d)
    }

    #[test]
    fn pair_request_dispatched() {
        let (_, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_001".into(),
            payload: serde_json::json!({
                "type": "pair.request",
                "comparison_code": "123456",
            }),
        };
        let result = disp.dispatch(&msg).unwrap();
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.status, "HostAccepted");
        assert_eq!(r.comparison_code.as_deref(), Some("123456"));
        assert!(r.error_code.is_none());
    }

    #[test]
    fn pair_request_missing_code_rejected() {
        let (_, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_no_code".into(),
            payload: serde_json::json!({
                "type": "pair.request",
            }),
        };
        let result = disp.dispatch(&msg).unwrap().unwrap();
        assert_eq!(result.status, "Rejected");
        assert_eq!(result.error_code.as_deref(), Some("ERR_REQUEST_STALE"));
    }

    #[test]
    fn pair_request_short_code_rejected() {
        let (_, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_short".into(),
            payload: serde_json::json!({
                "type": "pair.request",
                "comparison_code": "12345",
            }),
        };
        let result = disp.dispatch(&msg).unwrap().unwrap();
        assert_eq!(result.status, "Rejected");
        assert_eq!(result.error_code.as_deref(), Some("ERR_REQUEST_STALE"));
    }

    #[test]
    fn pair_request_non_numeric_code_rejected() {
        let (_, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_nonnum".into(),
            payload: serde_json::json!({
                "type": "pair.request",
                "comparison_code": "12345a",
            }),
        };
        let result = disp.dispatch(&msg).unwrap().unwrap();
        assert_eq!(result.status, "Rejected");
        assert_eq!(result.error_code.as_deref(), Some("ERR_REQUEST_STALE"));
    }

    #[test]
    fn command_deny_dispatched() {
        let (journal, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_002".into(),
            payload: serde_json::json!({
                "type": "command",
                "action": "deny",
                "request_id": "req_001",
                "session_id": "sess_1",
                "permission_id": "perm_001",
                "action_hash": "hash_abc",
                "expires_at": "2026-08-17T20:00:00Z",
            }),
        };
        let result = disp.dispatch(&msg).unwrap();
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.status, "HostAccepted");

        let cmd = journal.get_by_request_id("req_001").unwrap();
        assert!(cmd.is_some());
        assert_eq!(cmd.unwrap().status, "HostAccepted");
    }

    #[test]
    fn command_stop_dispatched() {
        let (journal, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_003".into(),
            payload: serde_json::json!({
                "type": "command",
                "action": "stop",
                "request_id": "req_002",
                "session_id": "sess_1",
                "target_turn_id": "turn_001",
            }),
        };
        let result = disp.dispatch(&msg).unwrap();
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.status, "HostAccepted");

        let cmd = journal.get_by_request_id("req_002").unwrap();
        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        assert_eq!(cmd.command_type, "stop");
        assert_eq!(cmd.status, "HostAccepted");
        assert!(cmd.accepted_at_seq.is_some());
    }

    #[test]
    fn command_allow_once_rejected() {
        let (_, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_004".into(),
            payload: serde_json::json!({
                "type": "command",
                "action": "allow_once",
                "request_id": "req_003",
            }),
        };
        let result = disp.dispatch(&msg).unwrap();
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.status, "Rejected");
        assert_eq!(r.error_code.as_deref(), Some("ERR_SAFETY_BLOCKED"));
    }

    #[test]
    fn unknown_message_type_returns_none() {
        let (_, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_005".into(),
            payload: serde_json::json!({
                "type": "unknown_type",
            }),
        };
        let result = disp.dispatch(&msg).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn duplicate_deny_handled() {
        let (journal, disp) = dispatcher();
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "msg_006".into(),
            payload: serde_json::json!({
                "type": "command",
                "action": "deny",
                "request_id": "req_dup",
                "session_id": "sess_dup",
                "permission_id": "perm_001",
                "action_hash": "h",
                "expires_at": "t",
            }),
        };
        let r1 = disp.dispatch(&msg).unwrap().unwrap();
        assert_eq!(r1.status, "HostAccepted");

        let r2 = disp.dispatch(&msg).unwrap().unwrap();
        assert_eq!(r2.status, "Error");
        assert_eq!(r2.error_code.as_deref(), Some("ERR_DUPLICATE_REQUEST"));

        let all = journal.get_by_session("sess_dup").unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn command_result_serialization() {
        let r = CommandResult {
            status: "HostAccepted".into(),
            error_code: None,
            error_message: None,
            comparison_code: Some("123456".into()),
        };
        let json_str = serde_json::to_string(&r).unwrap();
        assert!(json_str.contains("HostAccepted"));
        assert!(json_str.contains("123456"));
        assert!(!json_str.contains("error_code"));
    }

    #[test]
    fn command_result_error_serialization() {
        let r = CommandResult {
            status: "Rejected".into(),
            error_code: Some("ERR_SAFETY_BLOCKED".into()),
            error_message: Some("allow_once blocked".into()),
            comparison_code: None,
        };
        let json_str = serde_json::to_string(&r).unwrap();
        assert!(json_str.contains("ERR_SAFETY_BLOCKED"));
        assert!(!json_str.contains("comparison_code"));
    }

    #[test]
    fn relay_message_roundtrip() {
        let msg = RelayMessage {
            channel: "ch1".into(),
            target: "host".into(),
            message_id: "mid_001".into(),
            payload: serde_json::json!({"type": "test"}),
        };
        let json_str = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn ack_payload_serialization() {
        let ack = AckPayload {
            channel: "ch1".into(),
            target: "mobile".into(),
            message_ids: vec!["m1".into(), "m2".into()],
        };
        let json_str = serde_json::to_string(&ack).unwrap();
        assert!(json_str.contains("m1"));
        assert!(json_str.contains("m2"));
    }
}
