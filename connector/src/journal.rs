use crate::error::ConnectorError;
use crate::projection::{ProjectedEvent, Snapshot};
use rusqlite::{params, Connection, OptionalExtension};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StockObservationWrite {
    Applied { nomad_seq: u64 },
    Duplicate { nomad_seq: u64 },
    Mutation,
}

#[derive(Debug, Clone)]
pub enum InsertOrGetCommand {
    Inserted,
    Existing(JournalCommand),
}

impl CommandJournal {
    pub fn open(db_path: &Path) -> Result<Self, ConnectorError> {
        let conn = Connection::open(db_path)?;
        Self::initialize(&conn)?;
        Ok(Self { conn })
    }
    pub fn open_memory() -> Result<Self, ConnectorError> {
        let conn = Connection::open_in_memory()?;
        Self::initialize(&conn)?;
        Ok(Self { conn })
    }
    fn initialize(conn: &Connection) -> Result<(), ConnectorError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS commands (
                 request_id TEXT PRIMARY KEY, command_type TEXT NOT NULL,
                 session_id TEXT NOT NULL, seq INTEGER NOT NULL, status TEXT NOT NULL,
                 accepted_at_seq INTEGER, result_json TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS stock_command_bindings (
                 request_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id, seq);
             CREATE TABLE IF NOT EXISTS stock_event_cursor (
                 session_id TEXT PRIMARY KEY, last_nomad_seq INTEGER NOT NULL,
                 reconciliation_required INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS stock_observations (
                 session_id TEXT NOT NULL, upstream_event_id TEXT NOT NULL,
                 content_fingerprint TEXT NOT NULL, nomad_seq INTEGER, outcome TEXT NOT NULL,
                 projected_event_json TEXT, observed_at TEXT NOT NULL,
                 PRIMARY KEY (session_id, upstream_event_id), UNIQUE (session_id, nomad_seq)
             );
             CREATE TABLE IF NOT EXISTS stock_snapshots (
                 session_id TEXT PRIMARY KEY, facts_digest TEXT NOT NULL, snapshot_json TEXT NOT NULL
             );",
        )?;
        Ok(())
    }
    pub fn insert(&self, cmd: &JournalCommand) -> Result<(), ConnectorError> {
        self.conn.execute(
            "INSERT INTO commands (request_id, command_type, session_id, seq, status, accepted_at_seq, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![cmd.request_id, cmd.command_type, cmd.session_id, cmd.seq, cmd.status, cmd.accepted_at_seq, cmd.result_json, cmd.created_at],
        )?;
        Ok(())
    }
    pub fn get_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<JournalCommand>, ConnectorError> {
        self.conn.query_row("SELECT request_id,command_type,session_id,seq,status,accepted_at_seq,result_json,created_at FROM commands WHERE request_id=?1", params![request_id], |r| Ok(JournalCommand { request_id:r.get(0)?,command_type:r.get(1)?,session_id:r.get(2)?,seq:r.get(3)?,status:r.get(4)?,accepted_at_seq:r.get(5)?,result_json:r.get(6)?,created_at:r.get(7)? })).optional().map_err(Into::into)
    }
    pub fn get_by_session(&self, session_id: &str) -> Result<Vec<JournalCommand>, ConnectorError> {
        let mut stmt=self.conn.prepare("SELECT request_id,command_type,session_id,seq,status,accepted_at_seq,result_json,created_at FROM commands WHERE session_id=?1 ORDER BY seq")?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok(JournalCommand {
                request_id: r.get(0)?,
                command_type: r.get(1)?,
                session_id: r.get(2)?,
                seq: r.get(3)?,
                status: r.get(4)?,
                accepted_at_seq: r.get(5)?,
                result_json: r.get(6)?,
                created_at: r.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
    pub fn update_status(
        &self,
        request_id: &str,
        status: &str,
        accepted_at_seq: Option<u64>,
    ) -> Result<(), ConnectorError> {
        self.conn.execute(
            "UPDATE commands SET status=?1,accepted_at_seq=?2 WHERE request_id=?3",
            params![status, accepted_at_seq, request_id],
        )?;
        Ok(())
    }
    pub fn update_outcome(
        &self,
        request_id: &str,
        status: &str,
        accepted_at_seq: Option<u64>,
        result_json: &str,
    ) -> Result<(), ConnectorError> {
        if self.conn.execute(
            "UPDATE commands SET status=?1,accepted_at_seq=?2,result_json=?3 WHERE request_id=?4",
            params![status, accepted_at_seq, result_json, request_id],
        )? != 1
        {
            return Err(ConnectorError::Journal(format!(
                "request_id {request_id} is missing during outcome update"
            )));
        }
        Ok(())
    }

    /// Atomically writes a command or returns the existing request binding.
    /// The caller decides whether that binding is an idempotent replay.
    pub fn insert_or_get_command(
        &self,
        cmd: &JournalCommand,
    ) -> Result<InsertOrGetCommand, ConnectorError> {
        let inserted = self.conn.execute(
            "INSERT INTO commands (request_id, command_type, session_id, seq, status, accepted_at_seq, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(request_id) DO NOTHING",
            params![cmd.request_id, cmd.command_type, cmd.session_id, cmd.seq, cmd.status, cmd.accepted_at_seq, cmd.result_json, cmd.created_at],
        )?;
        if inserted == 1 {
            return Ok(InsertOrGetCommand::Inserted);
        }
        self.get_by_request_id(&cmd.request_id)?
            .map(InsertOrGetCommand::Existing)
            .ok_or_else(|| {
                ConnectorError::Journal("command insert conflict without saved row".into())
            })
    }
    /// Writes the immutable command binding with the command. A reused business
    /// request must have precisely the same command/session/target/sequence/body
    /// digest; callers must never infer equivalence from the request id alone.
    pub fn insert_or_get_bound_command(
        &self,
        cmd: &JournalCommand,
        binding_digest: &str,
    ) -> Result<InsertOrGetCommand, ConnectorError> {
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT INTO commands (request_id, command_type, session_id, seq, status, accepted_at_seq, result_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(request_id) DO NOTHING",
            params![cmd.request_id, cmd.command_type, cmd.session_id, cmd.seq, cmd.status, cmd.accepted_at_seq, cmd.result_json, cmd.created_at],
        )?;
        if inserted == 1 {
            tx.execute(
                "INSERT INTO stock_command_bindings (request_id, binding_digest) VALUES (?1, ?2)",
                params![cmd.request_id, binding_digest],
            )?;
            tx.commit()?;
            return Ok(InsertOrGetCommand::Inserted);
        }
        let saved: Option<(JournalCommand, String)> = tx.query_row(
            "SELECT c.request_id,c.command_type,c.session_id,c.seq,c.status,c.accepted_at_seq,c.result_json,c.created_at,b.binding_digest FROM commands c JOIN stock_command_bindings b ON b.request_id=c.request_id WHERE c.request_id=?1",
            params![cmd.request_id],
            |r| Ok((JournalCommand { request_id:r.get(0)?, command_type:r.get(1)?, session_id:r.get(2)?, seq:r.get(3)?, status:r.get(4)?, accepted_at_seq:r.get(5)?, result_json:r.get(6)?, created_at:r.get(7)? }, r.get(8)?)),
        ).optional()?;
        let (existing, existing_digest) = saved.ok_or_else(|| {
            ConnectorError::Journal("bound command conflict without saved row".into())
        })?;
        if existing_digest != binding_digest {
            return Err(ConnectorError::StaleRequest(
                "request_id binding conflict".into(),
            ));
        }
        tx.commit()?;
        Ok(InsertOrGetCommand::Existing(existing))
    }

    /// The durable transition immediately before an upstream HTTP attempt.
    /// It deliberately has no recovery path: an observed Executing row means
    /// the upstream outcome is unknown after a crash.
    pub fn transition_prepared_to_executing(&self, request_id: &str) -> Result<(), ConnectorError> {
        if self.conn.execute(
            "UPDATE commands SET status='Executing' WHERE request_id=?1 AND status='Prepared'",
            params![request_id],
        )? != 1
        {
            return Err(ConnectorError::OutcomeUnknown);
        }
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
    pub fn mark_stock_reconciliation_required(
        &self,
        session_id: &str,
    ) -> Result<(), ConnectorError> {
        self.conn.execute("INSERT INTO stock_event_cursor(session_id,last_nomad_seq,reconciliation_required) VALUES(?1,0,1) ON CONFLICT(session_id) DO UPDATE SET reconciliation_required=1",params![session_id])?;
        Ok(())
    }
    pub fn stock_reconciliation_required(&self, session_id: &str) -> Result<bool, ConnectorError> {
        Ok(self
            .conn
            .query_row(
                "SELECT reconciliation_required FROM stock_event_cursor WHERE session_id=?1",
                params![session_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0)
            != 0)
    }
    pub fn record_unknown_stock_observation(
        &self,
        session_id: &str,
        upstream_id: &str,
        fingerprint: &str,
        observed_at: &str,
    ) -> Result<StockObservationWrite, ConnectorError> {
        let tx = self.conn.unchecked_transaction()?;
        let prior:Option<String>=tx.query_row("SELECT content_fingerprint FROM stock_observations WHERE session_id=?1 AND upstream_event_id=?2",params![session_id,upstream_id],|r|r.get(0)).optional()?;
        if let Some(old) = prior {
            if old == fingerprint {
                tx.rollback()?;
                return Ok(StockObservationWrite::Duplicate { nomad_seq: 0 });
            }
            tx.execute("INSERT INTO stock_event_cursor(session_id,last_nomad_seq,reconciliation_required) VALUES(?1,0,1) ON CONFLICT(session_id) DO UPDATE SET reconciliation_required=1",params![session_id])?;
            tx.commit()?;
            return Ok(StockObservationWrite::Mutation);
        }
        tx.execute("INSERT INTO stock_observations(session_id,upstream_event_id,content_fingerprint,nomad_seq,outcome,projected_event_json,observed_at) VALUES(?1,?2,?3,NULL,'unknown',NULL,?4)",params![session_id,upstream_id,fingerprint,observed_at])?;
        tx.execute("INSERT INTO stock_event_cursor(session_id,last_nomad_seq,reconciliation_required) VALUES(?1,0,1) ON CONFLICT(session_id) DO UPDATE SET reconciliation_required=1",params![session_id])?;
        tx.commit()?;
        Ok(StockObservationWrite::Applied { nomad_seq: 0 })
    }
    #[cfg(test)]
    pub(crate) fn persist_projected_stock_event(
        &self,
        session_id: &str,
        upstream_id: &str,
        fingerprint: &str,
        event: &ProjectedEvent,
    ) -> Result<StockObservationWrite, ConnectorError> {
        if event.session_id != session_id
            || !event.durable
            || event.event_id != format!("stock:{session_id}:{upstream_id}")
            || !is_rfc3339_datetime(&event.timestamp)
            || event.payload.as_ref().is_some_and(|payload| {
                serde_json::to_vec(payload).map_or(true, |bytes| bytes.len() > 64 * 1024)
            })
        {
            return Err(ConnectorError::ProtocolMismatch(
                "invalid verified stock projection boundary".into(),
            ));
        }
        let serialized = serde_json::to_string(event)?;
        let tx = self.conn.unchecked_transaction()?;
        let prior:Option<(String,u64)>=tx.query_row("SELECT content_fingerprint,nomad_seq FROM stock_observations WHERE session_id=?1 AND upstream_event_id=?2",params![session_id,upstream_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((old, seq)) = prior {
            tx.rollback()?;
            return Ok(if old == fingerprint {
                StockObservationWrite::Duplicate { nomad_seq: seq }
            } else {
                StockObservationWrite::Mutation
            });
        }
        let last: Option<u64> = tx
            .query_row(
                "SELECT last_nomad_seq FROM stock_event_cursor WHERE session_id=?1",
                params![session_id],
                |r| r.get(0),
            )
            .optional()?;
        let seq = last
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ConnectorError::Journal("stock Nomad sequence overflow".into()))?;
        if event.seq != seq {
            return Err(ConnectorError::Journal(
                "projected event sequence not Host allocated".into(),
            ));
        }
        tx.execute("INSERT INTO stock_observations(session_id,upstream_event_id,content_fingerprint,nomad_seq,outcome,projected_event_json,observed_at) VALUES(?1,?2,?3,?4,'applied',?5,?6)",params![session_id,upstream_id,fingerprint,seq,serialized,event.timestamp])?;
        tx.execute("INSERT INTO stock_event_cursor(session_id,last_nomad_seq,reconciliation_required) VALUES(?1,?2,0) ON CONFLICT(session_id) DO UPDATE SET last_nomad_seq=excluded.last_nomad_seq",params![session_id,seq])?;
        tx.commit()?;
        Ok(StockObservationWrite::Applied { nomad_seq: seq })
    }
    pub fn current_stock_seq(&self, session_id: &str) -> Result<u64, ConnectorError> {
        Ok(self
            .conn
            .query_row(
                "SELECT last_nomad_seq FROM stock_event_cursor WHERE session_id=?1",
                params![session_id],
                |r| r.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(0))
    }
    #[cfg(test)]
    pub(crate) fn next_stock_seq(&self, session_id: &str) -> Result<u64, ConnectorError> {
        self.current_stock_seq(session_id)?
            .checked_add(1)
            .ok_or_else(|| ConnectorError::Journal("stock Nomad sequence overflow".into()))
    }
    pub fn stock_events_after(
        &self,
        session_id: &str,
        after_seq: u64,
    ) -> Result<Vec<ProjectedEvent>, ConnectorError> {
        let current_seq = self.current_stock_seq(session_id)?;
        if after_seq > current_seq {
            return Err(ConnectorError::Journal(
                "ERR_CURSOR_AHEAD: replay cursor exceeds current sequence".into(),
            ));
        }
        let mut s=self.conn.prepare("SELECT projected_event_json FROM stock_observations WHERE session_id=?1 AND nomad_seq>?2 AND projected_event_json IS NOT NULL ORDER BY nomad_seq")?;
        let rows = s.query_map(params![session_id, after_seq], |r| r.get::<_, String>(0))?;
        let events = rows
            .map(|row| serde_json::from_str(&row?).map_err(ConnectorError::from))
            .collect::<Result<Vec<ProjectedEvent>, ConnectorError>>()?;
        if events.is_empty() {
            return if current_seq == after_seq {
                Ok(events)
            } else {
                Err(ConnectorError::Journal(
                    "ERR_GAP: replay events missing before current sequence".into(),
                ))
            };
        }
        let mut expected = after_seq
            .checked_add(1)
            .ok_or_else(|| ConnectorError::Journal("ERR_GAP: replay sequence overflow".into()))?;
        for event in &events {
            if event.seq != expected {
                return Err(ConnectorError::Journal(
                    "ERR_GAP: stock replay is not contiguous".into(),
                ));
            }
            expected = expected.checked_add(1).ok_or_else(|| {
                ConnectorError::Journal("ERR_GAP: replay sequence overflow".into())
            })?;
        }
        if events.last().is_some_and(|event| event.seq != current_seq) {
            return Err(ConnectorError::Journal(
                "ERR_GAP: replay tail does not reach current sequence".into(),
            ));
        }
        Ok(events)
    }
    pub fn persist_snapshot_and_clear(
        &self,
        facts_digest: &str,
        snapshot: &Snapshot,
    ) -> Result<(), ConnectorError> {
        let text = serde_json::to_string(snapshot)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("INSERT INTO stock_snapshots(session_id,facts_digest,snapshot_json) VALUES(?1,?2,?3) ON CONFLICT(session_id) DO UPDATE SET facts_digest=excluded.facts_digest,snapshot_json=excluded.snapshot_json",params![snapshot.session_id,facts_digest,text])?;
        tx.execute(
            "UPDATE stock_event_cursor SET reconciliation_required=0 WHERE session_id=?1",
            params![snapshot.session_id],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Re-confirms an existing snapshot and clears the flag in the same
    /// transaction. Used when facts are unchanged but a later observation
    /// requires reconciliation again.
    pub fn reconfirm_snapshot_and_clear(&self, session_id: &str) -> Result<(), ConnectorError> {
        let tx = self.conn.unchecked_transaction()?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM stock_snapshots WHERE session_id=?1",
                params![session_id],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ConnectorError::Journal(
                "cannot reconfirm missing stock snapshot".into(),
            ));
        }
        tx.execute(
            "UPDATE stock_event_cursor SET reconciliation_required=0 WHERE session_id=?1",
            params![session_id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn latest_stock_snapshot(
        &self,
        session_id: &str,
    ) -> Result<Option<(String, Snapshot)>, ConnectorError> {
        self.conn
            .query_row(
                "SELECT facts_digest,snapshot_json FROM stock_snapshots WHERE session_id=?1",
                params![session_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(d, s)| Ok((d, serde_json::from_str(&s)?)))
            .transpose()
    }
}

#[cfg(test)]
fn is_rfc3339_datetime(value: &str) -> bool {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).is_ok()
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
        j.insert(&sample_cmd()).unwrap();
        assert_eq!(
            j.get_by_request_id("req_001").unwrap().unwrap().status,
            "HostAccepted"
        );
    }
    #[test]
    fn get_nonexistent() {
        assert!(CommandJournal::open_memory()
            .unwrap()
            .get_by_request_id("none")
            .unwrap()
            .is_none());
    }
    #[test]
    fn get_by_session_ordered() {
        let j = CommandJournal::open_memory().unwrap();
        j.insert(&JournalCommand {
            request_id: "b".into(),
            seq: 2,
            ..sample_cmd()
        })
        .unwrap();
        j.insert(&JournalCommand {
            request_id: "a".into(),
            seq: 1,
            ..sample_cmd()
        })
        .unwrap();
        assert_eq!(j.get_by_session("sess_001").unwrap()[0].seq, 1);
    }
    #[test]
    fn update_status() {
        let j = CommandJournal::open_memory().unwrap();
        j.insert(&sample_cmd()).unwrap();
        j.update_status("req_001", "Completed", Some(10)).unwrap();
        assert_eq!(
            j.get_by_request_id("req_001")
                .unwrap()
                .unwrap()
                .accepted_at_seq,
            Some(10)
        );
    }
    #[test]
    fn duplicate_request_id_fails() {
        let j = CommandJournal::open_memory().unwrap();
        j.insert(&sample_cmd()).unwrap();
        assert!(j.insert(&sample_cmd()).is_err());
    }
    #[test]
    fn update_outcome_replaces_status_and_result() {
        let j = CommandJournal::open_memory().unwrap();
        j.insert(&sample_cmd()).unwrap();
        j.update_outcome(
            "req_001",
            "OutcomeUnknown",
            None,
            r#"{"error_code":"ERR_OUTCOME_UNKNOWN"}"#,
        )
        .unwrap();
        assert!(j
            .get_by_request_id("req_001")
            .unwrap()
            .unwrap()
            .result_json
            .contains("ERR_OUTCOME_UNKNOWN"));
    }
    #[test]
    fn transaction_rolls_back_all_changes_on_error() {
        let j = CommandJournal::open_memory().unwrap();
        let r = j.transaction(|c| {
            c.execute(
                "INSERT INTO commands VALUES('x','r','s',1,'x',NULL,'{}','t')",
                [],
            )?;
            Err(ConnectorError::Journal("forced".into()))
        });
        assert!(r.is_err());
        assert!(j.get_by_request_id("x").unwrap().is_none());
    }

    #[test]
    fn stock_replay_rejects_a_persisted_gap() {
        let journal = CommandJournal::open_memory().unwrap();
        journal.transaction(|conn| {
            conn.execute(
                "INSERT INTO stock_observations (session_id, upstream_event_id, content_fingerprint, nomad_seq, outcome, projected_event_json, observed_at)
                 VALUES ('s', 'gap', 'f', 2, 'applied', ?1, '2026-08-19T00:00:00Z')",
                params![r#"{"event_type":"session.updated","session_id":"s","turn_id":null,"event_id":"stock:s:gap","seq":2,"timestamp":"2026-08-19T00:00:00Z","durable":true,"payload":null}"#],
            )?;
            Ok(())
        }).unwrap();
        assert!(journal
            .stock_events_after("s", 0)
            .unwrap_err()
            .to_string()
            .contains("ERR_GAP"));
    }

    fn set_stock_cursor(journal: &CommandJournal, seq: u64) {
        journal.transaction(|conn| {
            conn.execute(
                "INSERT INTO stock_event_cursor (session_id, last_nomad_seq, reconciliation_required)
                 VALUES ('s', ?1, 0)",
                params![seq],
            )?;
            Ok(())
        }).unwrap();
    }

    #[test]
    fn stock_replay_rejects_empty_events_before_cursor() {
        let journal = CommandJournal::open_memory().unwrap();
        set_stock_cursor(&journal, 3);
        assert!(journal
            .stock_events_after("s", 0)
            .unwrap_err()
            .to_string()
            .contains("ERR_GAP"));
    }

    #[test]
    fn stock_replay_rejects_missing_tail() {
        let journal = CommandJournal::open_memory().unwrap();
        journal.transaction(|conn| {
            conn.execute(
                "INSERT INTO stock_observations (session_id, upstream_event_id, content_fingerprint, nomad_seq, outcome, projected_event_json, observed_at)
                 VALUES ('s', 'one', 'f', 1, 'applied', ?1, '2026-08-19T00:00:00Z')",
                params![r#"{"event_type":"session.updated","session_id":"s","turn_id":null,"event_id":"stock:s:one","seq":1,"timestamp":"2026-08-19T00:00:00Z","durable":true,"payload":null}"#],
            )?;
            conn.execute(
                "INSERT INTO stock_observations (session_id, upstream_event_id, content_fingerprint, nomad_seq, outcome, projected_event_json, observed_at)
                 VALUES ('s', 'two', 'f', 2, 'applied', ?1, '2026-08-19T00:00:00Z')",
                params![r#"{"event_type":"session.updated","session_id":"s","turn_id":null,"event_id":"stock:s:two","seq":2,"timestamp":"2026-08-19T00:00:00Z","durable":true,"payload":null}"#],
            )?;
            conn.execute("INSERT INTO stock_event_cursor VALUES ('s', 3, 0)", [])?;
            Ok(())
        }).unwrap();
        assert!(journal
            .stock_events_after("s", 0)
            .unwrap_err()
            .to_string()
            .contains("ERR_GAP"));
    }

    #[test]
    fn stock_replay_allows_empty_at_current_cursor_and_rejects_ahead() {
        let journal = CommandJournal::open_memory().unwrap();
        set_stock_cursor(&journal, 3);
        assert!(journal.stock_events_after("s", 3).unwrap().is_empty());
        assert!(journal
            .stock_events_after("s", 4)
            .unwrap_err()
            .to_string()
            .contains("ERR_CURSOR_AHEAD"));
    }
}
