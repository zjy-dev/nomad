use crate::error::ConnectorError;
use crate::host_command_authority::VerifiedHostReconciliation;
use crate::projection::{ProjectedEvent, Snapshot};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct UmaskGuard {
    previous: libc::mode_t,
    _lock: MutexGuard<'static, ()>,
}

impl UmaskGuard {
    fn restrict() -> Self {
        static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = UMASK_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = unsafe { libc::umask(0o077) };
        Self {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

fn recovery_receipt(result_json: &str) -> Result<String, ConnectorError> {
    let mut receipt: serde_json::Value = serde_json::from_str(result_json)?;
    let object = receipt
        .as_object_mut()
        .ok_or_else(|| ConnectorError::Journal("invalid host authority receipt".into()))?;
    object.insert(
        "status".into(),
        serde_json::Value::String("OutcomeUnknown".into()),
    );
    object.insert(
        "error_code".into(),
        serde_json::Value::String("ERR_OUTCOME_UNKNOWN".into()),
    );
    serde_json::to_string(&receipt).map_err(Into::into)
}

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

#[derive(Debug, Clone)]
pub(crate) enum HostAuthorityClaim {
    Inserted,
    Existing {
        command: Box<JournalCommand>,
        binding_digest: String,
        receipt_id: String,
    },
}

impl CommandJournal {
    pub fn open(db_path: &Path) -> Result<Self, ConnectorError> {
        let file_name = db_path
            .file_name()
            .ok_or_else(|| ConnectorError::Journal("invalid journal path".into()))?;
        let canonical_parent = db_path
            .parent()
            .ok_or_else(|| ConnectorError::Journal("invalid journal path".into()))?
            .canonicalize()
            .map_err(|_| ConnectorError::Journal("invalid journal parent".into()))?;
        validate_private_directory(&canonical_parent)?;
        let canonical_path = canonical_parent.join(file_name);
        let _umask = UmaskGuard::restrict();
        let (guard, identity) = open_private_database(&canonical_path)?;
        // SQLite may open pre-existing WAL/SHM paths during initialization.
        // Reject any unsafe sidecar before giving SQLite the database path,
        // then revalidate after WAL creation.
        validate_sqlite_sidecars(&canonical_path)?;
        let conn = Connection::open_with_flags(
            &canonical_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        validate_private_file(&canonical_path, Some(identity))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Self::initialize(&conn, true)?;
        validate_private_file(&canonical_path, Some(identity))?;
        validate_sqlite_sidecars(&canonical_path)?;
        drop(guard);
        Ok(Self { conn })
    }
    pub fn open_memory() -> Result<Self, ConnectorError> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Self::initialize(&conn, false)?;
        Ok(Self { conn })
    }
    fn initialize(conn: &Connection, file_backed: bool) -> Result<(), ConnectorError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS commands (
                 request_id TEXT PRIMARY KEY, command_type TEXT NOT NULL,
                 session_id TEXT NOT NULL, seq INTEGER NOT NULL, status TEXT NOT NULL,
                 accepted_at_seq INTEGER, result_json TEXT NOT NULL, created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS stock_command_bindings (
                 request_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS host_authority_bindings (
                 request_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL,
                 receipt_id TEXT NOT NULL, authority_scope TEXT NOT NULL,
                 command_seq INTEGER NOT NULL, nonce_digest TEXT NOT NULL,
                 recovery_result_json TEXT NOT NULL,
                 UNIQUE(authority_scope, command_seq),
                 UNIQUE(authority_scope, nonce_digest)
             );
             CREATE TABLE IF NOT EXISTS host_authority_scopes (
                 authority_scope TEXT PRIMARY KEY,
                 reconciliation_required INTEGER NOT NULL DEFAULT 0
                     CHECK(reconciliation_required IN (0,1)),
                 active_request_id TEXT
             );
             CREATE TABLE IF NOT EXISTS host_authority_reconciliation_proofs (
                 proof_id TEXT PRIMARY KEY,
                 authority_scope TEXT NOT NULL,
                 request_id TEXT NOT NULL UNIQUE,
                 terminal_status TEXT NOT NULL,
                 accepted_at_seq INTEGER,
                 seal TEXT NOT NULL
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
        let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if file_backed && !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(ConnectorError::Journal(
                "host authority requires SQLite journal_mode=WAL".into(),
            ));
        }
        let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        if synchronous != 2 {
            return Err(ConnectorError::Journal(
                "host authority requires SQLite synchronous=FULL".into(),
            ));
        }
        Self::validate_host_authority_schema(conn)?;
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        let incomplete_without_recovery: i64 = tx.query_row(
            "SELECT COUNT(*) FROM commands c JOIN host_authority_bindings b ON b.request_id=c.request_id
             WHERE c.status IN ('HostAccepted','Dispatching') AND b.recovery_result_json=''",
            [],
            |row| row.get(0),
        )?;
        if incomplete_without_recovery != 0 {
            return Err(ConnectorError::Journal(
                "host authority cannot recover an incomplete legacy record".into(),
            ));
        }
        tx.execute(
            "UPDATE commands SET status='OutcomeUnknown',
                 result_json=(SELECT b.recovery_result_json FROM host_authority_bindings b WHERE b.request_id=commands.request_id)
             WHERE request_id IN (
                 SELECT b.request_id FROM host_authority_bindings b
                 WHERE commands.status IN ('HostAccepted','Dispatching')
             )",
            [],
        )?;
        tx.execute(
            "INSERT INTO host_authority_scopes(authority_scope,reconciliation_required,active_request_id)
             SELECT b.authority_scope,1,b.request_id
             FROM host_authority_bindings b JOIN commands c ON c.request_id=b.request_id
             WHERE c.status='OutcomeUnknown'
             ON CONFLICT(authority_scope) DO UPDATE SET
                 reconciliation_required=1, active_request_id=excluded.active_request_id",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn validate_host_authority_schema(conn: &Connection) -> Result<(), ConnectorError> {
        fn columns(conn: &Connection, table: &str) -> Result<Vec<String>, ConnectorError> {
            let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let rows = statement.query_map([], |row| row.get(1))?;
            rows.collect::<Result<Vec<String>, _>>().map_err(Into::into)
        }
        let expected = [
            (
                "host_authority_bindings",
                &[
                    "request_id",
                    "binding_digest",
                    "receipt_id",
                    "authority_scope",
                    "command_seq",
                    "nonce_digest",
                    "recovery_result_json",
                ][..],
            ),
            (
                "host_authority_scopes",
                &[
                    "authority_scope",
                    "reconciliation_required",
                    "active_request_id",
                ][..],
            ),
            (
                "host_authority_reconciliation_proofs",
                &[
                    "proof_id",
                    "authority_scope",
                    "request_id",
                    "terminal_status",
                    "accepted_at_seq",
                    "seal",
                ][..],
            ),
        ];
        for (table, wanted) in expected {
            if columns(conn, table)? != wanted {
                return Err(ConnectorError::Journal(format!(
                    "unsupported host authority schema for {table}"
                )));
            }
        }
        Ok(())
    }

    fn immediate_transaction(&self) -> Result<Transaction<'_>, ConnectorError> {
        Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate).map_err(Into::into)
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

    /// Atomically reserves a product Host command before any Agent side effect.
    /// The binding digest remains Host-internal and is never returned in a
    /// browser receipt.
    pub(crate) fn claim_host_authority_command(
        &self,
        command: &JournalCommand,
        binding_digest: &str,
        receipt_id: &str,
        authority_scope: &str,
        command_seq: u64,
        nonce_digest: &str,
    ) -> Result<HostAuthorityClaim, ConnectorError> {
        let tx = self.immediate_transaction()?;
        let saved: Option<(JournalCommand, String, String)> = tx.query_row(
            "SELECT c.request_id,c.command_type,c.session_id,c.seq,c.status,c.accepted_at_seq,c.result_json,c.created_at,b.binding_digest,b.receipt_id
             FROM commands c JOIN host_authority_bindings b ON b.request_id=c.request_id WHERE c.request_id=?1",
            params![command.request_id],
            |row| Ok((JournalCommand { request_id:row.get(0)?, command_type:row.get(1)?, session_id:row.get(2)?, seq:row.get(3)?, status:row.get(4)?, accepted_at_seq:row.get(5)?, result_json:row.get(6)?, created_at:row.get(7)? }, row.get(8)?, row.get(9)?)),
        ).optional()?;
        if let Some((existing, existing_digest, existing_receipt)) = saved {
            if matches!(existing.status.as_str(), "HostAccepted" | "Dispatching") {
                Self::set_host_authority_gate(&tx, authority_scope, &existing.request_id, true)?;
            }
            tx.commit()?;
            return Ok(HostAuthorityClaim::Existing {
                command: Box::new(existing),
                binding_digest: existing_digest,
                receipt_id: existing_receipt,
            });
        }

        // Recover the gate before inspecting it. This covers a crash or a
        // concurrent caller observing a committed Prepared row.
        let in_flight: Option<String> = tx
            .query_row(
                "SELECT b.request_id FROM host_authority_bindings b
                 JOIN commands c ON c.request_id=b.request_id
                 WHERE b.authority_scope=?1 AND c.status IN ('HostAccepted','Dispatching') LIMIT 1",
                params![authority_scope],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(request_id) = in_flight {
            Self::set_host_authority_gate(&tx, authority_scope, &request_id, true)?;
        }
        let blocked = tx
            .query_row(
                "SELECT reconciliation_required FROM host_authority_scopes WHERE authority_scope=?1",
                params![authority_scope],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0)
            != 0;
        if blocked {
            return Err(ConnectorError::OutcomeUnknown);
        }

        tx.execute(
            "INSERT INTO commands (request_id,command_type,session_id,seq,status,accepted_at_seq,result_json,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![command.request_id, command.command_type, command.session_id, command.seq, command.status, command.accepted_at_seq, command.result_json, command.created_at],
        )?;
        if let Err(error) = tx.execute(
            "INSERT INTO host_authority_bindings (request_id,binding_digest,receipt_id,authority_scope,command_seq,nonce_digest,recovery_result_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![command.request_id, binding_digest, receipt_id, authority_scope, command_seq, nonce_digest, recovery_receipt(&command.result_json)?],
        ) {
            return match error {
                rusqlite::Error::SqliteFailure(inner, _)
                    if inner.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(ConnectorError::StaleRequest(
                        "command sequence or nonce conflict".into(),
                    ))
                }
                other => Err(other.into()),
            };
        }
        tx.commit()?;
        Ok(HostAuthorityClaim::Inserted)
    }

    pub(crate) fn get_host_authority_command(
        &self,
        request_id: &str,
    ) -> Result<Option<(JournalCommand, String, String)>, ConnectorError> {
        let tx = self.immediate_transaction()?;
        let saved = tx
            .query_row(
                "SELECT c.request_id,c.command_type,c.session_id,c.seq,c.status,c.accepted_at_seq,c.result_json,c.created_at,b.binding_digest,b.receipt_id
                 FROM commands c JOIN host_authority_bindings b ON b.request_id=c.request_id WHERE c.request_id=?1",
                params![request_id],
                |row| Ok((JournalCommand { request_id:row.get(0)?, command_type:row.get(1)?, session_id:row.get(2)?, seq:row.get(3)?, status:row.get(4)?, accepted_at_seq:row.get(5)?, result_json:row.get(6)?, created_at:row.get(7)? }, row.get(8)?, row.get(9)?)),
            )
            .optional()?;
        if let Some((command, _, _)) = &saved {
            if matches!(command.status.as_str(), "HostAccepted" | "Dispatching") {
                let scope: String = tx.query_row(
                    "SELECT authority_scope FROM host_authority_bindings WHERE request_id=?1",
                    params![request_id],
                    |row| row.get(0),
                )?;
                Self::set_host_authority_gate(&tx, &scope, request_id, true)?;
            }
        }
        tx.commit()?;
        Ok(saved)
    }

    pub(crate) fn next_host_authority_sequence(
        &self,
        authority_scope: &str,
    ) -> Result<u64, ConnectorError> {
        let maximum: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(command_seq), 0) FROM host_authority_bindings WHERE authority_scope=?1",
            params![authority_scope],
            |row| row.get(0),
        )?;
        u64::try_from(maximum)
            .ok()
            .and_then(|value| value.checked_add(1))
            .filter(|value| *value <= 9_007_199_254_740_991)
            .ok_or_else(|| ConnectorError::Journal("command sequence exhausted".into()))
    }

    /// The durable transition immediately before an upstream HTTP attempt.
    /// It deliberately has no recovery path: an observed Dispatching row means
    /// the upstream outcome is unknown after a crash.
    pub(crate) fn transition_host_authority_to_dispatching(
        &self,
        request_id: &str,
        authority_scope: &str,
    ) -> Result<(), ConnectorError> {
        let tx = self.immediate_transaction()?;
        if tx.execute(
            "UPDATE commands SET status='Dispatching' WHERE request_id=?1 AND status='HostAccepted'",
            params![request_id],
        )? != 1
        {
            return Err(ConnectorError::OutcomeUnknown);
        }
        Self::set_host_authority_gate(&tx, authority_scope, request_id, true)?;
        tx.commit()?;
        Ok(())
    }

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

    pub(crate) fn update_host_authority_outcome(
        &self,
        request_id: &str,
        authority_scope: &str,
        status: &str,
        accepted_at_seq: Option<u64>,
        result_json: &str,
    ) -> Result<(), ConnectorError> {
        if !matches!(
            status,
            "DispatchAcknowledged" | "Rejected" | "OutcomeUnknown"
        ) {
            return Err(ConnectorError::Journal(
                "invalid host authority terminal status".into(),
            ));
        }
        let tx = self.immediate_transaction()?;
        if tx.execute(
            "UPDATE commands SET status=?1,accepted_at_seq=?2,result_json=?3
             WHERE request_id=?4 AND status='Dispatching'",
            params![status, accepted_at_seq, result_json, request_id],
        )? != 1
        {
            return Err(ConnectorError::OutcomeUnknown);
        }
        if status == "OutcomeUnknown" {
            Self::set_host_authority_gate(&tx, authority_scope, request_id, true)?;
        } else if tx.execute(
            "UPDATE host_authority_scopes
             SET reconciliation_required=0,active_request_id=NULL
             WHERE authority_scope=?1 AND reconciliation_required=1 AND active_request_id=?2",
            params![authority_scope, request_id],
        )? != 1
        {
            return Err(ConnectorError::OutcomeUnknown);
        }
        tx.commit()?;
        Ok(())
    }

    fn set_host_authority_gate(
        conn: &Connection,
        authority_scope: &str,
        request_id: &str,
        required: bool,
    ) -> Result<(), ConnectorError> {
        conn.execute(
            "INSERT INTO host_authority_scopes(authority_scope,reconciliation_required,active_request_id)
             VALUES(?1,?2,?3)
             ON CONFLICT(authority_scope) DO UPDATE SET
                 reconciliation_required=excluded.reconciliation_required,
                 active_request_id=excluded.active_request_id",
            params![
                authority_scope,
                i64::from(required),
                if required { Some(request_id) } else { None }
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn host_authority_reconciliation_required(
        &self,
        authority_scope: &str,
    ) -> Result<bool, ConnectorError> {
        Ok(self
            .conn
            .query_row(
                "SELECT reconciliation_required FROM host_authority_scopes WHERE authority_scope=?1",
                params![authority_scope],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0)
            != 0)
    }

    /// Atomically consumes an opaque authority-issued reconciliation proof,
    /// writes the authoritative terminal outcome, and clears only its exact
    /// active scope/request gate. No raw clear-gate API exists.
    pub(crate) fn reconcile_host_authority(
        &self,
        proof: VerifiedHostReconciliation,
        result_json: &str,
    ) -> Result<(), ConnectorError> {
        let tx = self.immediate_transaction()?;
        let inserted = tx.execute(
            "INSERT INTO host_authority_reconciliation_proofs
             (proof_id,authority_scope,request_id,terminal_status,accepted_at_seq,seal)
             VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT DO NOTHING",
            params![
                proof.proof_id(),
                proof.authority_scope(),
                proof.request_id(),
                proof.terminal_status(),
                proof.accepted_at_seq(),
                proof.seal_hex(),
            ],
        )?;
        if inserted != 1 {
            return Err(ConnectorError::StaleRequest(
                "reconciliation proof replay".into(),
            ));
        }
        if tx.execute(
            "UPDATE commands SET status=?1,accepted_at_seq=?2,result_json=?3
             WHERE request_id=?4 AND status IN ('HostAccepted','Dispatching','OutcomeUnknown')
             AND EXISTS (
                 SELECT 1 FROM host_authority_bindings b
                 WHERE b.request_id=commands.request_id AND b.authority_scope=?5
             )",
            params![
                proof.terminal_status(),
                proof.accepted_at_seq(),
                result_json,
                proof.request_id(),
                proof.authority_scope(),
            ],
        )? != 1
        {
            return Err(ConnectorError::StaleRequest(
                "reconciliation proof does not match authority binding".into(),
            ));
        }
        if tx.execute(
            "UPDATE host_authority_scopes
             SET reconciliation_required=0,active_request_id=NULL
             WHERE authority_scope=?1 AND reconciliation_required=1 AND active_request_id=?2",
            params![proof.authority_scope(), proof.request_id()],
        )? != 1
        {
            return Err(ConnectorError::StaleRequest(
                "reconciliation does not match active authority request".into(),
            ));
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn host_authority_uses_full_synchronous(&self) -> Result<bool, ConnectorError> {
        Ok(self
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?
            == 2)
    }
    #[cfg(test)]
    pub(crate) fn transaction<F>(&self, f: F) -> Result<(), ConnectorError>
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

fn validate_private_directory(path: &Path) -> Result<(), ConnectorError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ConnectorError::Journal("invalid journal parent".into()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ConnectorError::Journal(
            "journal parent is not private".into(),
        ));
    }
    Ok(())
}

fn open_private_database(path: &Path) -> Result<(File, FileIdentity), ConnectorError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.create_new(true).mode(PRIVATE_FILE_MODE).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            existing
                .open(path)
                .map_err(|_| ConnectorError::Journal("unsafe journal file".into()))?
        }
        Err(_) => {
            return Err(ConnectorError::Journal(
                "could not create private journal file".into(),
            ));
        }
    };
    let identity = validate_open_private_file(&file)?;
    validate_private_file(path, Some(identity))?;
    Ok((file, identity))
}

fn validate_open_private_file(file: &File) -> Result<FileIdentity, ConnectorError> {
    let metadata = file
        .metadata()
        .map_err(|_| ConnectorError::Journal("unsafe journal file".into()))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(ConnectorError::Journal("unsafe journal file".into()));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_private_file(
    path: &Path,
    expected: Option<FileIdentity>,
) -> Result<FileIdentity, ConnectorError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ConnectorError::Journal("unsafe journal file".into()))?;
    let identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
        || expected.is_some_and(|wanted| wanted != identity)
    {
        return Err(ConnectorError::Journal("unsafe journal file".into()));
    }
    Ok(identity)
}

fn validate_sqlite_sidecars(db_path: &Path) -> Result<(), ConnectorError> {
    for path in sqlite_sidecars(db_path) {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                validate_private_file(&path, None)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(ConnectorError::Journal(
                    "could not inspect journal sidecar".into(),
                ));
            }
        }
    }
    Ok(())
}

fn sqlite_sidecars(db_path: &Path) -> [PathBuf; 2] {
    [
        PathBuf::from(format!("{}-wal", db_path.display())),
        PathBuf::from(format!("{}-shm", db_path.display())),
    ]
}

#[cfg(test)]
fn is_rfc3339_datetime(value: &str) -> bool {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    fn authority_cmd(request_id: &str, seq: u64) -> JournalCommand {
        JournalCommand {
            request_id: request_id.into(),
            command_type: "stop".into(),
            session_id: "s".into(),
            seq,
            status: "HostAccepted".into(),
            accepted_at_seq: None,
            result_json: format!(
                r#"{{"receipt_id":"rcpt_{request_id}","request_id":"{request_id}","kind":"stop","status":"HostAccepted","error_code":null,"accepted_at_seq":null,"idempotent_replay":false}}"#
            ),
            created_at: "2026-08-25T09:00:00Z".into(),
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
    fn host_authority_file_database_is_full_synchronous() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.db");
        let journal = CommandJournal::open(&path).unwrap();
        assert!(journal.host_authority_uses_full_synchronous().unwrap());
        for artifact in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let metadata = fs::symlink_metadata(artifact).unwrap();
            assert!(metadata.is_file());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.permissions().mode() & 0o777, PRIVATE_FILE_MODE);
        }
        drop(journal);
        assert!(CommandJournal::open(&path)
            .unwrap()
            .host_authority_uses_full_synchronous()
            .unwrap());
    }

    #[test]
    fn file_database_rejects_unsafe_main_file_and_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let main = directory.path().join("authority.db");
        fs::write(&main, []).unwrap();
        fs::set_permissions(&main, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            CommandJournal::open(&main),
            Err(ConnectorError::Journal(message)) if message == "unsafe journal file"
        ));

        fs::set_permissions(&main, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let wal = PathBuf::from(format!("{}-wal", main.display()));
        fs::write(&wal, []).unwrap();
        fs::set_permissions(&wal, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            CommandJournal::open(&main),
            Err(ConnectorError::Journal(message)) if message == "unsafe journal file"
        ));
    }

    #[test]
    fn file_database_rejects_symlink_main_and_sidecar() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.db");
        fs::write(&target, []).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let main = directory.path().join("authority.db");
        symlink(&target, &main).unwrap();
        assert!(CommandJournal::open(&main).is_err());

        fs::remove_file(&main).unwrap();
        fs::write(&main, []).unwrap();
        fs::set_permissions(&main, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        let wal = PathBuf::from(format!("{}-wal", main.display()));
        symlink(&target, &wal).unwrap();
        assert!(CommandJournal::open(&main).is_err());

        fs::remove_file(&wal).unwrap();
        let missing = directory.path().join("missing-sidecar");
        symlink(&missing, &wal).unwrap();
        assert!(CommandJournal::open(&main).is_err());
    }

    #[test]
    fn accepted_and_dispatching_rows_become_unknown_after_reopen() {
        for dispatching in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("authority.db");
            let scope = "scope-a";
            {
                let journal = CommandJournal::open(&path).unwrap();
                journal
                    .claim_host_authority_command(
                        &authority_cmd("first", 1),
                        "binding-1",
                        "receipt-1",
                        scope,
                        1,
                        "nonce-1",
                    )
                    .unwrap();
                if dispatching {
                    journal
                        .transition_host_authority_to_dispatching("first", scope)
                        .unwrap();
                }
            }
            let reopened = CommandJournal::open(&path).unwrap();
            let recovered = reopened
                .get_host_authority_command("first")
                .unwrap()
                .unwrap()
                .0;
            assert_eq!(recovered.status, "OutcomeUnknown");
            assert!(recovered.result_json.contains("ERR_OUTCOME_UNKNOWN"));
            assert!(reopened
                .host_authority_reconciliation_required(scope)
                .unwrap());
            assert!(matches!(
                reopened.claim_host_authority_command(
                    &authority_cmd("second", 2),
                    "binding-2",
                    "receipt-2",
                    scope,
                    2,
                    "nonce-2",
                ),
                Err(ConnectorError::OutcomeUnknown)
            ));
        }
    }

    #[test]
    fn concurrent_file_claims_have_one_winner_and_one_fail_closed_loser() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority.db");
        CommandJournal::open(&path).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (1..=2)
            .map(|seq| {
                let path = path.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let journal = CommandJournal::open(&path).unwrap();
                    barrier.wait();
                    journal.claim_host_authority_command(
                        &authority_cmd(&format!("request-{seq}"), seq),
                        &format!("binding-{seq}"),
                        &format!("receipt-{seq}"),
                        "scope-concurrent",
                        seq,
                        &format!("nonce-{seq}"),
                    )
                })
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Ok(HostAuthorityClaim::Inserted)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(ConnectorError::OutcomeUnknown)))
                .count(),
            1
        );
    }

    #[test]
    fn terminal_outcome_and_gate_change_commit_together() {
        let journal = CommandJournal::open_memory().unwrap();
        let scope = "scope-terminal";
        journal
            .claim_host_authority_command(
                &authority_cmd("completed", 1),
                "binding-1",
                "receipt-1",
                scope,
                1,
                "nonce-1",
            )
            .unwrap();
        journal
            .transition_host_authority_to_dispatching("completed", scope)
            .unwrap();
        assert!(journal
            .host_authority_reconciliation_required(scope)
            .unwrap());
        journal
            .update_host_authority_outcome(
                "completed",
                scope,
                "DispatchAcknowledged",
                Some(10),
                r#"{"status":"DispatchAcknowledged"}"#,
            )
            .unwrap();
        assert!(!journal
            .host_authority_reconciliation_required(scope)
            .unwrap());

        journal
            .claim_host_authority_command(
                &authority_cmd("unknown", 2),
                "binding-2",
                "receipt-2",
                scope,
                2,
                "nonce-2",
            )
            .unwrap();
        journal
            .transition_host_authority_to_dispatching("unknown", scope)
            .unwrap();
        journal
            .update_host_authority_outcome(
                "unknown",
                scope,
                "OutcomeUnknown",
                None,
                r#"{"status":"OutcomeUnknown"}"#,
            )
            .unwrap();
        assert!(journal
            .host_authority_reconciliation_required(scope)
            .unwrap());
        assert!(matches!(
            journal.claim_host_authority_command(
                &authority_cmd("blocked", 3),
                "binding-3",
                "receipt-3",
                scope,
                3,
                "nonce-3",
            ),
            Err(ConnectorError::OutcomeUnknown)
        ));
    }

    #[test]
    fn host_authority_sequence_is_scoped_persistent_and_monotonic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority-sequence.db");
        let scope = "scope-sequence";
        {
            let journal = CommandJournal::open(&path).unwrap();
            assert_eq!(journal.next_host_authority_sequence(scope).unwrap(), 1);
            journal
                .claim_host_authority_command(
                    &authority_cmd("first-sequence", 1),
                    "binding-1",
                    "receipt-1",
                    scope,
                    1,
                    "nonce-1",
                )
                .unwrap();
            journal
                .transition_host_authority_to_dispatching("first-sequence", scope)
                .unwrap();
            journal
                .update_host_authority_outcome(
                    "first-sequence",
                    scope,
                    "DispatchAcknowledged",
                    Some(1),
                    r#"{"status":"DispatchAcknowledged"}"#,
                )
                .unwrap();
            assert_eq!(journal.next_host_authority_sequence(scope).unwrap(), 2);
            assert_eq!(
                journal.next_host_authority_sequence("other-scope").unwrap(),
                1
            );
        }
        let reopened = CommandJournal::open(&path).unwrap();
        assert_eq!(reopened.next_host_authority_sequence(scope).unwrap(), 2);
    }

    #[test]
    fn terminal_writeback_failure_keeps_scope_blocked() {
        let journal = CommandJournal::open_memory().unwrap();
        let scope = "scope-writeback-failure";
        journal
            .claim_host_authority_command(
                &authority_cmd("inflight", 1),
                "binding-1",
                "receipt-1",
                scope,
                1,
                "nonce-1",
            )
            .unwrap();
        journal
            .transition_host_authority_to_dispatching("inflight", scope)
            .unwrap();
        assert!(journal
            .update_host_authority_outcome(
                "wrong-request",
                scope,
                "DispatchAcknowledged",
                Some(10),
                r#"{"status":"DispatchAcknowledged"}"#,
            )
            .is_err());
        assert!(journal
            .host_authority_reconciliation_required(scope)
            .unwrap());
        assert!(matches!(
            journal.claim_host_authority_command(
                &authority_cmd("blocked", 2),
                "binding-2",
                "receipt-2",
                scope,
                2,
                "nonce-2",
            ),
            Err(ConnectorError::OutcomeUnknown)
        ));
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
