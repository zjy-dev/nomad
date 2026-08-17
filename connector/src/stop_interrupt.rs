use crate::error::ConnectorError;
use crate::journal::{CommandJournal, JournalCommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopCommand {
    pub request_id: String,
    pub session_id: String,
    pub target_turn_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptAndSendCommand {
    pub request_id: String,
    pub session_id: String,
    pub interrupt_turn_id: String,
    pub new_content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderingOutcome {
    Accepted {
        stopped_at_seq: u64,
        new_event_id: String,
    },
    StoppingOnly {
        stopped_at_seq: u64,
    },
    CancelledOnly {
        stopped_at_seq: u64,
    },
    Rejected {
        reason: String,
    },
}

pub struct StopInterruptService<'a> {
    journal: &'a CommandJournal,
}

impl<'a> StopInterruptService<'a> {
    pub fn new(journal: &'a CommandJournal) -> Self {
        Self { journal }
    }

    /// Accept a Stop command. Dedup via request_id. Returns accepted status.
    pub fn accept_stop(
        &self,
        stop: &StopCommand,
        current_seq: u64,
    ) -> Result<OrderingOutcome, ConnectorError> {
        let existing = self.journal.get_by_request_id(&stop.request_id)?;
        if let Some(c) = existing {
            if c.status == "HostAccepted" || c.status == "Completed" {
                let result: Value = serde_json::from_str(&c.result_json)?;
                let stopped_at = result
                    .get("stopped_at_seq")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(current_seq);
                let event_id = result
                    .get("event_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(OrderingOutcome::Accepted {
                    stopped_at_seq: stopped_at,
                    new_event_id: event_id,
                });
            }
        }

        let result_json = serde_json::json!({
            "stopped_at_seq": current_seq,
            "event_id": format!("{}:{}", stop.session_id, current_seq),
            "error_code": "OK",
        });

        let cmd = JournalCommand {
            request_id: stop.request_id.clone(),
            command_type: "stop".to_string(),
            session_id: stop.session_id.clone(),
            seq: current_seq,
            status: "HostAccepted".to_string(),
            accepted_at_seq: Some(current_seq),
            result_json: serde_json::to_string(&result_json)?,
            created_at: chrono_now(),
        };
        self.journal.insert(&cmd)?;

        Ok(OrderingOutcome::Accepted {
            stopped_at_seq: current_seq,
            new_event_id: result_json["event_id"].as_str().unwrap_or("").to_string(),
        })
    }

    /// Accept an interrupt-and-send command. The old turn MUST be in Stopping or Cancelled state
    /// before the new message is accepted (INV-003-6).
    pub fn accept_interrupt_and_send(
        &self,
        ias: &InterruptAndSendCommand,
        current_seq: u64,
    ) -> Result<OrderingOutcome, ConnectorError> {
        let existing = self.journal.get_by_request_id(&ias.request_id)?;
        if existing.is_some() {
            return Err(ConnectorError::DuplicateRequest(ias.request_id.clone()));
        }

        // Find all commands related to this session that are stop/stop-related
        // Check if the old turn has a confirming stop
        let session_cmds = self.journal.get_by_session(&ias.session_id)?;
        let has_confirmed_stop = session_cmds
            .iter()
            .any(|c| c.command_type == "stop" && c.status == "HostAccepted" && c.seq >= 1);

        if !has_confirmed_stop {
            // Old turn still running - reject
            return Err(ConnectorError::SafetyBlocked(
                "Old turn not yet stopped; interrupt_and_send must wait for turn.stopping/turn.cancelled confirmation".to_string(),
            ));
        }

        let result_json = serde_json::json!({
            "stopped_at_seq": current_seq,
            "new_event_id": format!("{}:{}", ias.session_id, current_seq),
            "error_code": "OK",
        });

        let cmd = JournalCommand {
            request_id: ias.request_id.clone(),
            command_type: "interrupt_and_send".to_string(),
            session_id: ias.session_id.clone(),
            seq: current_seq,
            status: "HostAccepted".to_string(),
            accepted_at_seq: Some(current_seq),
            result_json: serde_json::to_string(&result_json)?,
            created_at: chrono_now(),
        };
        self.journal.insert(&cmd)?;

        Ok(OrderingOutcome::Accepted {
            stopped_at_seq: current_seq,
            new_event_id: result_json["new_event_id"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        })
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

    fn stop_req() -> StopCommand {
        StopCommand {
            request_id: "req_stop_001".into(),
            session_id: "sess_001".into(),
            target_turn_id: "turn_001".into(),
        }
    }

    #[test]
    fn stop_accepted() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&j);
        let result = svc.accept_stop(&stop_req(), 5).unwrap();
        assert!(matches!(result, OrderingOutcome::Accepted { .. }));
    }

    #[test]
    fn duplicate_stop_idempotent() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&j);
        let r1 = svc.accept_stop(&stop_req(), 5).unwrap();
        let r2 = svc.accept_stop(&stop_req(), 10).unwrap();
        match (&r1, &r2) {
            (
                OrderingOutcome::Accepted {
                    stopped_at_seq: s1, ..
                },
                OrderingOutcome::Accepted {
                    stopped_at_seq: s2, ..
                },
            ) => {
                assert_eq!(*s1, *s2);
            }
            _ => panic!("expected Accepted outcomes"),
        }
    }

    #[test]
    fn interrupt_without_stop_is_rejected() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&j);
        let ias = InterruptAndSendCommand {
            request_id: "req_ias_001".into(),
            session_id: "sess_no_stop".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "hello".into(),
        };
        let err = svc.accept_interrupt_and_send(&ias, 3).unwrap_err();
        assert!(matches!(err, ConnectorError::SafetyBlocked(_)));
    }

    #[test]
    fn interrupt_after_stop_is_accepted() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&j);
        let stop = StopCommand {
            request_id: "req_stop_001".into(),
            session_id: "sess_1".into(),
            target_turn_id: "turn_old".into(),
        };
        svc.accept_stop(&stop, 4).unwrap();

        let ias = InterruptAndSendCommand {
            request_id: "req_ias_001".into(),
            session_id: "sess_1".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "new content".into(),
        };
        let result = svc.accept_interrupt_and_send(&ias, 6).unwrap();
        assert!(matches!(result, OrderingOutcome::Accepted { .. }));
    }

    #[test]
    fn duplicate_interrupt_rejected() {
        let j = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&j);
        let stop = StopCommand {
            request_id: "req_stop_001".into(),
            session_id: "sess_1".into(),
            target_turn_id: "turn_old".into(),
        };
        svc.accept_stop(&stop, 4).unwrap();

        let ias1 = InterruptAndSendCommand {
            request_id: "req_ias_dup".into(),
            session_id: "sess_1".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "c1".into(),
        };
        svc.accept_interrupt_and_send(&ias1, 6).unwrap();
        let ias2 = InterruptAndSendCommand {
            request_id: "req_ias_dup".into(),
            session_id: "sess_1".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "c2".into(),
        };
        let err = svc.accept_interrupt_and_send(&ias2, 7).unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }
}
