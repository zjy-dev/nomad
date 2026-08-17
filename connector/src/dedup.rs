use crate::error::ConnectorError;
use crate::journal::CommandJournal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupResult {
    pub is_duplicate: bool,
    pub existing_status: Option<String>,
    pub existing_result: Option<serde_json::Value>,
}

pub struct ReplyDedup<'a> {
    journal: &'a CommandJournal,
}

impl<'a> ReplyDedup<'a> {
    pub fn new(journal: &'a CommandJournal) -> Self {
        Self { journal }
    }

    pub fn check(&self, request_id: &str) -> Result<DedupResult, ConnectorError> {
        let existing = self.journal.get_by_request_id(request_id)?;
        if let Some(cmd) = existing {
            let result_json: serde_json::Value =
                serde_json::from_str(&cmd.result_json).unwrap_or(serde_json::Value::Null);
            Ok(DedupResult {
                is_duplicate: true,
                existing_status: Some(cmd.status),
                existing_result: Some(result_json),
            })
        } else {
            Ok(DedupResult {
                is_duplicate: false,
                existing_status: None,
                existing_result: None,
            })
        }
    }

    pub fn record(&self, cmd: &crate::journal::JournalCommand) -> Result<(), ConnectorError> {
        let existing = self.journal.get_by_request_id(&cmd.request_id)?;
        if existing.is_some() {
            return Err(ConnectorError::DuplicateRequest(cmd.request_id.clone()));
        }
        self.journal.insert(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::CommandJournal;

    #[test]
    fn new_request_not_duplicate() {
        let j = CommandJournal::open_memory().unwrap();
        let d = ReplyDedup::new(&j);
        let r = d.check("req_new").unwrap();
        assert!(!r.is_duplicate);
        assert!(r.existing_status.is_none());
    }

    #[test]
    fn existing_request_is_duplicate() {
        let j = CommandJournal::open_memory().unwrap();
        let cmd = crate::journal::JournalCommand {
            request_id: "req_dup".into(),
            command_type: "reply".into(),
            session_id: "s1".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(5),
            result_json: r#"{"error_code":"OK"}"#.into(),
            created_at: "2026-08-17T10:00:00Z".into(),
        };
        j.insert(&cmd).unwrap();
        let d = ReplyDedup::new(&j);
        let r = d.check("req_dup").unwrap();
        assert!(r.is_duplicate);
        assert_eq!(r.existing_status.unwrap(), "HostAccepted");
    }

    #[test]
    fn record_duplicate_fails() {
        let j = CommandJournal::open_memory().unwrap();
        let d = ReplyDedup::new(&j);
        let cmd = crate::journal::JournalCommand {
            request_id: "req_once".into(),
            command_type: "reply".into(),
            session_id: "s1".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: None,
            result_json: "{}".into(),
            created_at: "t1".into(),
        };
        d.record(&cmd).unwrap();
        let err = d.record(&cmd).unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }

    #[test]
    fn million_retries_yield_once() {
        let j = CommandJournal::open_memory().unwrap();
        let d = ReplyDedup::new(&j);
        let cmd = crate::journal::JournalCommand {
            request_id: "req_many".into(),
            command_type: "reply".into(),
            session_id: "s1".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(10),
            result_json: r#"{"error_code":"OK","accepted_at_seq":10}"#.into(),
            created_at: "t1".into(),
        };
        d.record(&cmd).unwrap();

        for i in 0..1_000_000 {
            let r = d.check("req_many").unwrap();
            assert!(r.is_duplicate, "iter {i}");
            assert_eq!(r.existing_status.as_deref(), Some("HostAccepted"));
        }
    }
}
