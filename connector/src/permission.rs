use crate::error::ConnectorError;
use crate::journal::{CommandJournal, JournalCommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub permission_id: String,
    pub action: String,
    pub action_hash: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionDecision {
    #[serde(rename = "allow_once")]
    AllowOnce,
    #[serde(rename = "deny")]
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionViewResult {
    pub permission_id: String,
    pub action: String,
    pub status: String,
    pub decision: Option<PermissionDecision>,
    pub expires_at: Option<String>,
    pub no_allow_once: bool,
}

pub struct PermissionService<'a> {
    journal: &'a CommandJournal,
}

impl<'a> PermissionService<'a> {
    pub fn new(journal: &'a CommandJournal) -> Self {
        Self { journal }
    }

    /// HC-009 conclusion: NO-GO for allow_once.
    /// Always returns the capability flag set to false.
    pub fn allow_once_capability(&self) -> bool {
        false
    }

    /// View a pending permission. Returns immutable projection only.
    pub fn view(&self, permission_id: &str) -> Result<PermissionViewResult, ConnectorError> {
        let cmd = self.journal.get_by_request_id(permission_id)?;
        if let Some(c) = cmd {
            let result: Value = serde_json::from_str(&c.result_json)?;
            let decision = serde_json::from_value::<PermissionDecision>(
                result.get("decision").cloned().unwrap_or(Value::Null),
            )
            .ok();
            Ok(PermissionViewResult {
                permission_id: c.request_id.clone(),
                action: result
                    .get("action")
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                status: c.status.clone(),
                decision,
                expires_at: result
                    .get("expires_at")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string()),
                no_allow_once: true,
            })
        } else {
            Ok(PermissionViewResult {
                permission_id: permission_id.to_string(),
                action: "unknown".to_string(),
                status: "pending".to_string(),
                decision: None,
                expires_at: None,
                no_allow_once: true,
            })
        }
    }

    /// Deny a permission. Returns OK (per HC-010, deny is supported).
    pub fn deny(
        &self,
        request_id: &str,
        session_id: &str,
        permission_id: &str,
        _action_hash: &str,
        _expires_at: &str,
    ) -> Result<JournalCommand, ConnectorError> {
        let existing = self.journal.get_by_request_id(request_id)?;
        if existing.is_some() {
            return Err(ConnectorError::DuplicateRequest(request_id.to_string()));
        }

        // Check if permission already resolved
        let existing_perm = self.journal.get_by_request_id(permission_id)?;
        if let Some(perm) = existing_perm {
            let result: Value = serde_json::from_str(&perm.result_json)?;
            if let Some(code) = result.get("error_code").and_then(|c| c.as_str()) {
                if code == "OK" && perm.status == "Completed" {
                    return Err(ConnectorError::StaleRequest(format!(
                        "Permission {permission_id} already resolved"
                    )));
                }
            }
        }

        let result_json = serde_json::json!({
            "error_code": "OK",
            "decision": "deny",
            "resolved_at_seq": serde_json::Value::Null,
            "event_id": serde_json::Value::Null,
        });

        let cmd = JournalCommand {
            request_id: request_id.to_string(),
            command_type: "permission_decision".to_string(),
            session_id: session_id.to_string(),
            seq: 0,
            status: "HostAccepted".to_string(),
            accepted_at_seq: None,
            result_json: serde_json::to_string(&result_json)?,
            created_at: chrono_now(),
        };
        self.journal.insert(&cmd)?;
        Ok(cmd)
    }

    /// Stop a permission request. HC-009 NO-GO path: Stop does not imply allow.
    pub fn stop(
        &self,
        request_id: &str,
        session_id: &str,
        _permission_id: &str,
    ) -> Result<JournalCommand, ConnectorError> {
        let existing = self.journal.get_by_request_id(request_id)?;
        if existing.is_some() {
            return Err(ConnectorError::DuplicateRequest(request_id.to_string()));
        }

        let result_json = serde_json::json!({
            "error_code": "OK",
            "decision": "stopped",
            "resolved_at_seq": serde_json::Value::Null,
            "event_id": serde_json::Value::Null,
        });

        let cmd = JournalCommand {
            request_id: request_id.to_string(),
            command_type: "permission_decision".to_string(),
            session_id: session_id.to_string(),
            seq: 0,
            status: "Revoked".to_string(),
            accepted_at_seq: None,
            result_json: serde_json::to_string(&result_json)?,
            created_at: chrono_now(),
        };
        self.journal.insert(&cmd)?;
        Ok(cmd)
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::CommandJournal;

    #[test]
    fn allow_once_always_false() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&j);
        assert!(!svc.allow_once_capability());
    }

    #[test]
    fn view_pending_permission() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&j);
        let result = svc.view("perm_001").unwrap();
        assert_eq!(result.permission_id, "perm_001");
        assert_eq!(result.status, "pending");
        assert!(result.no_allow_once);
    }

    #[test]
    fn deny_success() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&j);
        let cmd = svc
            .deny(
                "req_deny_001",
                "sess_1",
                "perm_001",
                "hash_abc",
                "2026-08-17T20:00:00Z",
            )
            .unwrap();
        assert_eq!(cmd.status, "HostAccepted");
    }

    #[test]
    fn duplicate_deny_rejected() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&j);
        svc.deny("req_dup", "sess_1", "perm_1", "h", "t").unwrap();
        let err = svc
            .deny("req_dup", "sess_1", "perm_1", "h", "t")
            .unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }

    #[test]
    fn stop_revokes_permission() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&j);
        let cmd = svc.stop("req_stop_001", "sess_1", "perm_1").unwrap();
        assert_eq!(cmd.status, "Revoked");
    }
}
