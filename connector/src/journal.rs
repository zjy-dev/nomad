use crate::error::ConnectorError;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalCommand {
    pub request_id: String,
    pub command_type: String,
    pub session_id: String,
    pub seq: u64,
    pub status: String,
    pub accepted_at_seq: Option<u64>,
    pub result_json: String,
    pub created_at: String,
}

pub struct CommandJournal {
    conn: Connection,
}

impl CommandJournal {
    pub fn open(db_path: &Path) -> Result<Self, ConnectorError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS commands (
                 request_id TEXT PRIMARY KEY,
                 command_type TEXT NOT NULL,
                 session_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 accepted_at_seq INTEGER,
                 result_json TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id, seq);
             CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status);",
        )?;
        Ok(Self { conn })
    }

    pub fn open_memory() -> Result<Self, ConnectorError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS commands (
                 request_id TEXT PRIMARY KEY,
                 command_type TEXT NOT NULL,
                 session_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 accepted_at_seq INTEGER,
                 result_json TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id, seq);
             CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status);",
        )?;
        Ok(Self { conn })
    }

    pub fn insert(&self, cmd: &JournalCommand) -> Result<(), ConnectorError> {
        self.conn.execute(
            "INSERT INTO commands (request_id, command_type, session_id, seq, status, accepted_at_seq, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                cmd.request_id,
                cmd.command_type,
                cmd.session_id,
                cmd.seq,
                cmd.status,
                cmd.accepted_at_seq,
                cmd.result_json,
                cmd.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<JournalCommand>, ConnectorError> {
        let mut stmt = self.conn.prepare(
            "SELECT request_id, command_type, session_id, seq, status, accepted_at_seq, result_json, created_at
             FROM commands WHERE request_id = ?1",
        )?;
        let rows = stmt.query_map(params![request_id], |row| {
            Ok(JournalCommand {
                request_id: row.get(0)?,
                command_type: row.get(1)?,
                session_id: row.get(2)?,
                seq: row.get(3)?,
                status: row.get(4)?,
                accepted_at_seq: row.get(5)?,
                result_json: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        let mut result = None;
        for row in rows {
            result = Some(row?);
        }
        Ok(result)
    }

    pub fn get_by_session(&self, session_id: &str) -> Result<Vec<JournalCommand>, ConnectorError> {
        let mut stmt = self.conn.prepare(
            "SELECT request_id, command_type, session_id, seq, status, accepted_at_seq, result_json, created_at
             FROM commands WHERE session_id = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(JournalCommand {
                request_id: row.get(0)?,
                command_type: row.get(1)?,
                session_id: row.get(2)?,
                seq: row.get(3)?,
                status: row.get(4)?,
                accepted_at_seq: row.get(5)?,
                result_json: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        let mut cmds = Vec::new();
        for row in rows {
            cmds.push(row?);
        }
        Ok(cmds)
    }

    pub fn update_status(
        &self,
        request_id: &str,
        status: &str,
        accepted_at_seq: Option<u64>,
    ) -> Result<(), ConnectorError> {
        self.conn.execute(
            "UPDATE commands SET status = ?1, accepted_at_seq = ?2 WHERE request_id = ?3",
            params![status, accepted_at_seq, request_id],
        )?;
        Ok(())
    }

    pub fn transaction<F>(&self, f: F) -> Result<(), ConnectorError>
    where
        F: FnOnce(&Connection) -> Result<(), ConnectorError>,
    {
        let tx = self.conn.unchecked_transaction()?;
        f(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cmd() -> JournalCommand {
        JournalCommand {
            request_id: "req_001".into(),
            command_type: "reply".into(),
            session_id: "sess_001".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(5),
            result_json: r#"{"error_code":"OK"}"#.into(),
            created_at: "2026-08-17T10:00:00Z".into(),
        }
    }

    #[test]
    fn insert_and_get() {
        let j = CommandJournal::open_memory().unwrap();
        let cmd = sample_cmd();
        j.insert(&cmd).unwrap();
        let got = j.get_by_request_id("req_001").unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().status, "HostAccepted");
    }

    #[test]
    fn get_nonexistent() {
        let j = CommandJournal::open_memory().unwrap();
        let got = j.get_by_request_id("no_such").unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn get_by_session_ordered() {
        let j = CommandJournal::open_memory().unwrap();
        let c1 = JournalCommand {
            request_id: "req_b".into(),
            seq: 2,
            ..sample_cmd()
        };
        let c2 = JournalCommand {
            request_id: "req_a".into(),
            seq: 1,
            ..sample_cmd()
        };
        j.insert(&c1).unwrap();
        j.insert(&c2).unwrap();
        let list = j.get_by_session("sess_001").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].seq, 1);
        assert_eq!(list[1].seq, 2);
    }

    #[test]
    fn update_status() {
        let j = CommandJournal::open_memory().unwrap();
        let cmd = sample_cmd();
        j.insert(&cmd).unwrap();
        j.update_status("req_001", "Completed", Some(10)).unwrap();
        let got = j.get_by_request_id("req_001").unwrap().unwrap();
        assert_eq!(got.status, "Completed");
        assert_eq!(got.accepted_at_seq, Some(10));
    }

    #[test]
    fn duplicate_request_id_fails() {
        let j = CommandJournal::open_memory().unwrap();
        let c1 = sample_cmd();
        let c2 = JournalCommand {
            command_type: "stop".into(),
            ..sample_cmd()
        };
        j.insert(&c1).unwrap();
        let result = j.insert(&c2);
        assert!(result.is_err());
    }
}
