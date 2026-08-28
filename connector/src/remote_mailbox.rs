#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

const FRAME_SCHEMA: &str = "nomad.relay.opaque-frame.v2";
const ACK_SCHEMA: &str = "nomad.relay.opaque-ack.v2";
const FRAME_SUITE: &str = "p256-hkdf-sha256-aes256gcm-v1";
const MAX_WIRE_BYTES: usize = 96 * 1024;
const MAX_READ_FRAMES: usize = 100;
const MAX_ACK_BODY_BYTES: usize = 4096;
const MAX_RECEIPT_RESPONSE_BYTES: u64 = 1024;
const MAX_FRAME_LIST_RESPONSE_BYTES: u64 =
    (MAX_WIRE_BYTES as u64 * MAX_READ_FRAMES as u64) + MAX_READ_FRAMES as u64 + 2;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TTL_SECONDS: i64 = 600;
const PRIVATE_FILE_MODE: u32 = 0o600;
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteDirection {
    HostToDevice,
    DeviceToHost,
}

impl RemoteDirection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HostToDevice => "host_to_device",
            Self::DeviceToHost => "device_to_host",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayOpaqueFrame {
    pub schema: String,
    pub crypto_suite: String,
    pub mailbox_id: String,
    pub direction: RemoteDirection,
    pub epoch: u64,
    pub sequence: u64,
    pub message_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayOpaqueAck {
    pub schema: String,
    pub mailbox_id: String,
    pub direction: RemoteDirection,
    pub epoch: u64,
    pub acked_through_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingOutboundFrame {
    pub sequence: u64,
    pub inbound_sequence: Option<u64>,
    pub canonical_frame_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableMailboxCursor {
    pub next_sequence: u64,
    pub read_through_sequence: u64,
    pub applied_through_sequence: u64,
    pub acked_through_sequence: u64,
    pub pending_sequence: Option<u64>,
    pub pending_inbound_sequence: Option<u64>,
    pub pending_frame_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoisonReasonCode {
    AuthenticationFailed,
    ApplicationInvalid,
    CommandInvalid,
}

impl PoisonReasonCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::ApplicationInvalid => "APPLICATION_INVALID",
            Self::CommandInvalid => "COMMAND_INVALID",
        }
    }

    fn parse(value: &str) -> Result<Self, RemoteMailboxError> {
        match value {
            "AUTHENTICATION_FAILED" => Ok(Self::AuthenticationFailed),
            "APPLICATION_INVALID" => Ok(Self::ApplicationInvalid),
            "COMMAND_INVALID" => Ok(Self::CommandInvalid),
            _ => Err(RemoteMailboxError::InvalidState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurablePoisonDisposition {
    pub(crate) inbound_sequence: u64,
    pub(crate) reason_code: PoisonReasonCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayClientRole {
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishReceipt {
    pub stored: bool,
    pub idempotent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AckReceipt {
    pub acked: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RemoteMailboxError {
    #[error("remote mailbox configuration invalid")]
    InvalidConfig,
    #[error("remote mailbox frame invalid")]
    InvalidFrame,
    #[error("remote mailbox acknowledgement invalid")]
    InvalidAck,
    #[error("remote mailbox state invalid")]
    InvalidState,
    #[error("remote mailbox state conflict")]
    StateConflict,
    #[error("remote mailbox protocol invalid")]
    Protocol,
    #[error("remote mailbox unavailable")]
    Unavailable,
    #[error("remote mailbox HTTP {0}")]
    HttpStatus(u16),
    #[error("remote mailbox sqlite")]
    Sqlite(#[source] rusqlite::Error),
    #[error("remote mailbox io")]
    Io(#[source] std::io::Error),
    #[error("remote mailbox json")]
    Json(#[source] serde_json::Error),
}

impl From<rusqlite::Error> for RemoteMailboxError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<std::io::Error> for RemoteMailboxError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for RemoteMailboxError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

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

#[derive(Debug)]
pub(crate) struct RemoteMailboxState {
    conn: Connection,
}

impl RemoteMailboxState {
    pub(crate) fn open(db_path: &Path) -> Result<Self, RemoteMailboxError> {
        validate_no_symlink_components(db_path)?;
        let file_name = db_path
            .file_name()
            .ok_or(RemoteMailboxError::InvalidState)?;
        let absolute_parent =
            absolutize_path(db_path.parent().ok_or(RemoteMailboxError::InvalidState)?)?;
        validate_private_directory(&absolute_parent)?;
        let canonical_parent = absolute_parent
            .canonicalize()
            .map_err(|_| RemoteMailboxError::InvalidState)?;
        let canonical_path = canonical_parent.join(file_name);
        let _umask = UmaskGuard::restrict();
        let (guard, identity) = open_private_database(&canonical_path)?;
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

    pub(crate) fn open_memory() -> Result<Self, RemoteMailboxError> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Self::initialize(&conn, false)?;
        Ok(Self { conn })
    }

    fn initialize(conn: &Connection, file_backed: bool) -> Result<(), RemoteMailboxError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS remote_mailbox_state (
                 mailbox_id TEXT NOT NULL,
                 direction TEXT NOT NULL,
                 epoch INTEGER NOT NULL,
                 next_sequence INTEGER NOT NULL DEFAULT 1,
                 read_through_sequence INTEGER NOT NULL DEFAULT 0,
                 applied_through_sequence INTEGER NOT NULL DEFAULT 0,
                 acked_through_sequence INTEGER NOT NULL DEFAULT 0,
                 pending_sequence INTEGER,
                 pending_inbound_sequence INTEGER,
                 pending_frame_bytes BLOB,
                 PRIMARY KEY(mailbox_id, direction, epoch)
             );
             CREATE TABLE IF NOT EXISTS remote_mailbox_poison (
                 mailbox_id TEXT NOT NULL,
                 epoch INTEGER NOT NULL,
                 inbound_sequence INTEGER NOT NULL,
                 reason_code TEXT NOT NULL CHECK (reason_code IN (
                     'AUTHENTICATION_FAILED',
                     'APPLICATION_INVALID',
                     'COMMAND_INVALID'
                 )),
                 PRIMARY KEY(mailbox_id, epoch, inbound_sequence)
             );",
        )?;
        let has_pending_inbound = {
            let mut statement = conn.prepare("PRAGMA table_info(remote_mailbox_state)")?;
            let mut rows = statement.query([])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == "pending_inbound_sequence" {
                    found = true;
                }
            }
            found
        };
        if !has_pending_inbound {
            conn.execute(
                "ALTER TABLE remote_mailbox_state ADD COLUMN pending_inbound_sequence INTEGER",
                [],
            )?;
        }
        let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if file_backed && !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(RemoteMailboxError::InvalidState);
        }
        let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        if synchronous != 2 {
            return Err(RemoteMailboxError::InvalidState);
        }
        Ok(())
    }

    pub(crate) fn reserve_outbound_sequence(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
    ) -> Result<u64, RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let (current, pending_sequence): (u64, Option<u64>) = tx.query_row(
            "SELECT next_sequence, pending_sequence FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if pending_sequence.is_some() {
            return Err(RemoteMailboxError::StateConflict);
        }
        let next = current
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_INTEGER)
            .ok_or(RemoteMailboxError::StateConflict)?;
        tx.execute(
            "UPDATE remote_mailbox_state SET next_sequence=?4 WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch, next],
        )?;
        tx.commit()?;
        Ok(current)
    }

    pub(crate) fn store_pending_outbound_frame(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
        sequence: u64,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        if direction != RemoteDirection::HostToDevice {
            return Err(RemoteMailboxError::InvalidState);
        }
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let existing: Option<(Option<u64>, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT pending_sequence, pending_frame_bytes FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
                params![mailbox_id, direction.as_str(), epoch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((Some(saved_sequence), Some(saved_bytes))) = existing {
            if saved_sequence == sequence && saved_bytes == canonical_frame_bytes {
                tx.commit()?;
                return Ok(());
            }
            return Err(RemoteMailboxError::StateConflict);
        }
        let next_sequence: u64 = tx.query_row(
            "SELECT next_sequence FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch],
            |row| row.get(0),
        )?;
        let expected_sequence = sequence
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_INTEGER)
            .ok_or(RemoteMailboxError::StateConflict)?;
        if next_sequence != expected_sequence {
            return Err(RemoteMailboxError::StateConflict);
        }
        let frame = parse_canonical_frame(canonical_frame_bytes)?;
        if frame.mailbox_id != mailbox_id
            || frame.direction != direction
            || frame.epoch != epoch
            || frame.sequence != sequence
        {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET pending_sequence=?4, pending_inbound_sequence=NULL, pending_frame_bytes=?5 WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![
                mailbox_id,
                direction.as_str(),
                epoch,
                sequence,
                canonical_frame_bytes
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn pending_outbound_frame(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
    ) -> Result<Option<PendingOutboundFrame>, RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        self.conn
            .query_row(
                "SELECT pending_sequence, pending_inbound_sequence, pending_frame_bytes FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
                params![mailbox_id, direction.as_str(), epoch],
                |row| {
                    let sequence: Option<u64> = row.get(0)?;
                    let inbound_sequence: Option<u64> = row.get(1)?;
                    let bytes: Option<Vec<u8>> = row.get(2)?;
                    match (sequence, bytes) {
                        (Some(sequence), Some(canonical_frame_bytes)) => Ok(Some(
                            PendingOutboundFrame {
                                sequence,
                                inbound_sequence,
                                canonical_frame_bytes,
                            },
                        )),
                        (None, None) => Ok(None),
                        _ => Err(rusqlite::Error::InvalidQuery),
                    }
                },
            )
            .optional()
            .map_err(RemoteMailboxError::from)
            .map(|value| value.flatten())
    }

    pub(crate) fn clear_pending_outbound_frame(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
        sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let updated = tx.execute(
            "UPDATE remote_mailbox_state
             SET pending_sequence=NULL, pending_inbound_sequence=NULL, pending_frame_bytes=NULL
             WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3 AND pending_sequence=?4",
            params![mailbox_id, direction.as_str(), epoch, sequence],
        )?;
        if updated != 1 {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn store_pending_response_frame(
        &self,
        mailbox_id: &str,
        epoch: u64,
        inbound_sequence: u64,
        outbound_sequence: u64,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        if inbound_sequence == 0 || inbound_sequence > MAX_SAFE_INTEGER {
            return Err(RemoteMailboxError::InvalidState);
        }
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::HostToDevice, epoch)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let existing: (Option<u64>, Option<u64>, Option<Vec<u8>>, u64) = tx.query_row(
            "SELECT pending_sequence, pending_inbound_sequence, pending_frame_bytes, next_sequence
             FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction='host_to_device' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if let (Some(saved_outbound), Some(saved_inbound), Some(saved_bytes), _) = &existing {
            if *saved_outbound == outbound_sequence
                && *saved_inbound == inbound_sequence
                && saved_bytes == canonical_frame_bytes
            {
                tx.commit()?;
                return Ok(());
            }
            return Err(RemoteMailboxError::StateConflict);
        }
        if existing.0.is_some() || existing.1.is_some() || existing.2.is_some() {
            return Err(RemoteMailboxError::InvalidState);
        }
        if existing.3
            != outbound_sequence
                .checked_add(1)
                .ok_or(RemoteMailboxError::StateConflict)?
        {
            return Err(RemoteMailboxError::StateConflict);
        }
        let read_through: u64 = tx.query_row(
            "SELECT read_through_sequence FROM remote_mailbox_state
             WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| row.get(0),
        )?;
        if inbound_sequence > read_through {
            return Err(RemoteMailboxError::StateConflict);
        }
        let frame = parse_canonical_frame(canonical_frame_bytes)?;
        if frame.mailbox_id != mailbox_id
            || frame.direction != RemoteDirection::HostToDevice
            || frame.epoch != epoch
            || frame.sequence != outbound_sequence
        {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state
             SET pending_sequence=?3, pending_inbound_sequence=?4, pending_frame_bytes=?5
             WHERE mailbox_id=?1 AND direction='host_to_device' AND epoch=?2",
            params![
                mailbox_id,
                epoch,
                outbound_sequence,
                inbound_sequence,
                canonical_frame_bytes
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn mark_response_applied(
        &self,
        mailbox_id: &str,
        epoch: u64,
        inbound_sequence: u64,
        outbound_sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::HostToDevice, epoch)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        require_pending_response(&tx, mailbox_id, epoch, inbound_sequence, outbound_sequence)?;
        let (read, applied, acked): (u64, u64, u64) = tx.query_row(
            "SELECT read_through_sequence, applied_through_sequence, acked_through_sequence
             FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if inbound_sequence > read || inbound_sequence < applied || inbound_sequence < acked {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET applied_through_sequence=?3
             WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch, inbound_sequence],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn complete_response_ack(
        &self,
        mailbox_id: &str,
        epoch: u64,
        inbound_sequence: u64,
        outbound_sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::HostToDevice, epoch)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        require_pending_response(&tx, mailbox_id, epoch, inbound_sequence, outbound_sequence)?;
        let (applied, acked): (u64, u64) = tx.query_row(
            "SELECT applied_through_sequence, acked_through_sequence
             FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if applied != inbound_sequence || inbound_sequence < acked {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET acked_through_sequence=?3
             WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch, inbound_sequence],
        )?;
        tx.execute(
            "UPDATE remote_mailbox_state
             SET pending_sequence=NULL, pending_inbound_sequence=NULL, pending_frame_bytes=NULL
             WHERE mailbox_id=?1 AND direction='host_to_device' AND epoch=?2",
            params![mailbox_id, epoch],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn persist_poison_disposition(
        &self,
        mailbox_id: &str,
        epoch: u64,
        inbound_sequence: u64,
        reason_code: PoisonReasonCode,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        if inbound_sequence == 0 || inbound_sequence > MAX_SAFE_INTEGER {
            return Err(RemoteMailboxError::InvalidState);
        }
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::HostToDevice, epoch)?;
        let (read, applied, acked): (u64, u64, u64) = tx.query_row(
            "SELECT read_through_sequence, applied_through_sequence, acked_through_sequence
             FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if inbound_sequence > read
            || inbound_sequence < applied
            || inbound_sequence <= acked
            || applied > acked && applied != inbound_sequence
        {
            return Err(RemoteMailboxError::StateConflict);
        }
        let pending_response: Option<u64> = tx.query_row(
            "SELECT pending_inbound_sequence FROM remote_mailbox_state
             WHERE mailbox_id=?1 AND direction='host_to_device' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| row.get(0),
        )?;
        if pending_response.is_some() {
            return Err(RemoteMailboxError::StateConflict);
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT reason_code FROM remote_mailbox_poison
                 WHERE mailbox_id=?1 AND epoch=?2 AND inbound_sequence=?3",
                params![mailbox_id, epoch, inbound_sequence],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if existing != reason_code.as_str() => {
                return Err(RemoteMailboxError::StateConflict);
            }
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT INTO remote_mailbox_poison
                     (mailbox_id, epoch, inbound_sequence, reason_code) VALUES (?1, ?2, ?3, ?4)",
                    params![mailbox_id, epoch, inbound_sequence, reason_code.as_str()],
                )?;
            }
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET applied_through_sequence=?3
             WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch, inbound_sequence],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn pending_poison_disposition(
        &self,
        mailbox_id: &str,
        epoch: u64,
    ) -> Result<Option<DurablePoisonDisposition>, RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let acked: u64 = tx.query_row(
            "SELECT acked_through_sequence FROM remote_mailbox_state
             WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| row.get(0),
        )?;
        let pending: Option<(u64, String)> = tx
            .query_row(
                "SELECT inbound_sequence, reason_code FROM remote_mailbox_poison
                 WHERE mailbox_id=?1 AND epoch=?2 AND inbound_sequence>?3
                 ORDER BY inbound_sequence ASC LIMIT 1",
                params![mailbox_id, epoch, acked],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let pending = pending
            .map(|(inbound_sequence, reason)| {
                Ok::<DurablePoisonDisposition, RemoteMailboxError>(DurablePoisonDisposition {
                    inbound_sequence,
                    reason_code: PoisonReasonCode::parse(&reason)?,
                })
            })
            .transpose()?;
        tx.commit()?;
        Ok(pending)
    }

    pub(crate) fn complete_poison_ack(
        &self,
        mailbox_id: &str,
        epoch: u64,
        inbound_sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let poison_exists = tx
            .query_row(
                "SELECT 1 FROM remote_mailbox_poison
                 WHERE mailbox_id=?1 AND epoch=?2 AND inbound_sequence=?3",
                params![mailbox_id, epoch, inbound_sequence],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let (applied, acked): (u64, u64) = tx.query_row(
            "SELECT applied_through_sequence, acked_through_sequence
             FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if !poison_exists || applied != inbound_sequence || inbound_sequence < acked {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET acked_through_sequence=?3
             WHERE mailbox_id=?1 AND direction='device_to_host' AND epoch=?2",
            params![mailbox_id, epoch, inbound_sequence],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn validate_ingress_state(&self) -> Result<(), RemoteMailboxError> {
        let invalid: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM remote_mailbox_state
             WHERE next_sequence < 1
                OR read_through_sequence < applied_through_sequence
                OR applied_through_sequence < acked_through_sequence
                OR ((pending_sequence IS NULL) != (pending_frame_bytes IS NULL))
                OR (pending_inbound_sequence IS NOT NULL AND pending_sequence IS NULL)",
            [],
            |row| row.get(0),
        )?;
        if invalid != 0 {
            return Err(RemoteMailboxError::InvalidState);
        }
        let orphaned_applied: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM remote_mailbox_state inbound
             WHERE inbound.direction='device_to_host'
               AND inbound.applied_through_sequence > inbound.acked_through_sequence
               AND NOT EXISTS (
                   SELECT 1 FROM remote_mailbox_state outbound
                   WHERE outbound.mailbox_id=inbound.mailbox_id
                     AND outbound.epoch=inbound.epoch
                     AND outbound.direction='host_to_device'
                     AND outbound.pending_inbound_sequence=inbound.applied_through_sequence
               )
               AND NOT EXISTS (
                   SELECT 1 FROM remote_mailbox_poison poison
                   WHERE poison.mailbox_id=inbound.mailbox_id
                     AND poison.epoch=inbound.epoch
                     AND poison.inbound_sequence=inbound.applied_through_sequence
               )",
            [],
            |row| row.get(0),
        )?;
        if orphaned_applied != 0 {
            return Err(RemoteMailboxError::InvalidState);
        }
        Ok(())
    }

    pub(crate) fn persist_read_through_sequence(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
        read_through_sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let current: u64 = tx.query_row(
            "SELECT read_through_sequence FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch],
            |row| row.get(0),
        )?;
        if read_through_sequence < current {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET read_through_sequence=?4 WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch, read_through_sequence],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn persist_applied_through_sequence(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
        applied_through_sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let (current_applied, current_acked): (u64, u64) = tx.query_row(
            "SELECT applied_through_sequence, acked_through_sequence FROM remote_mailbox_state
             WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if applied_through_sequence < current_applied || applied_through_sequence < current_acked {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET applied_through_sequence=?4 WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![
                mailbox_id,
                direction.as_str(),
                epoch,
                applied_through_sequence
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn persist_acked_through_sequence(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
        acked_through_sequence: u64,
    ) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let (current_applied, current_acked): (u64, u64) = tx.query_row(
            "SELECT applied_through_sequence, acked_through_sequence FROM remote_mailbox_state
             WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if acked_through_sequence < current_acked || acked_through_sequence > current_applied {
            return Err(RemoteMailboxError::StateConflict);
        }
        tx.execute(
            "UPDATE remote_mailbox_state SET acked_through_sequence=?4 WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch, acked_through_sequence],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn cursor(
        &self,
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
    ) -> Result<DurableMailboxCursor, RemoteMailboxError> {
        validate_stream_key(mailbox_id, direction, epoch)?;
        let tx = immediate_transaction(&self.conn)?;
        ensure_stream_row(&tx, mailbox_id, direction, epoch)?;
        let cursor = tx.query_row(
            "SELECT next_sequence, read_through_sequence, applied_through_sequence, acked_through_sequence, pending_sequence, pending_inbound_sequence, pending_frame_bytes
             FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction=?2 AND epoch=?3",
            params![mailbox_id, direction.as_str(), epoch],
            |row| {
                Ok(DurableMailboxCursor {
                    next_sequence: row.get(0)?,
                    read_through_sequence: row.get(1)?,
                    applied_through_sequence: row.get(2)?,
                    acked_through_sequence: row.get(3)?,
                    pending_sequence: row.get(4)?,
                    pending_inbound_sequence: row.get(5)?,
                    pending_frame_bytes: row.get(6)?,
                })
            },
        )?;
        tx.commit()?;
        Ok(cursor)
    }
}

pub(crate) struct HostRelayV2Client {
    base_url: Url,
    bearer: Zeroizing<String>,
    agent: ureq::Agent,
}

impl Clone for HostRelayV2Client {
    fn clone(&self) -> Self {
        Self {
            base_url: self.base_url.clone(),
            bearer: Zeroizing::new(self.bearer.to_string()),
            agent: self.agent.clone(),
        }
    }
}

impl fmt::Debug for HostRelayV2Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRelayV2Client")
            .field("base_url", &self.base_url)
            .field("bearer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HostRelayV2Client {
    pub(crate) fn new(
        base_url: &str,
        bearer: &str,
        allow_loopback_test_http: bool,
    ) -> Result<Self, RemoteMailboxError> {
        let url = Url::parse(base_url).map_err(|_| RemoteMailboxError::InvalidConfig)?;
        validate_base_url(&url, allow_loopback_test_http)?;
        validate_bearer(bearer)?;
        Ok(Self {
            base_url: url,
            bearer: Zeroizing::new(bearer.to_string()),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(HTTP_CONNECT_TIMEOUT)
                .timeout_read(HTTP_READ_TIMEOUT)
                .timeout_write(HTTP_WRITE_TIMEOUT)
                .build(),
        })
    }

    pub(crate) fn publish_frame(
        &self,
        canonical_frame_bytes: &[u8],
    ) -> Result<PublishReceipt, RemoteMailboxError> {
        let frame = parse_canonical_frame(canonical_frame_bytes)?;
        if frame.direction != RemoteDirection::HostToDevice {
            return Err(RemoteMailboxError::InvalidFrame);
        }
        let response = self
            .agent
            .post(self.mailbox_path(&frame.mailbox_id, "frames").as_str())
            .set("Authorization", &self.authorization_header())
            .set("Content-Type", "application/json")
            .send_bytes(canonical_frame_bytes)
            .map_err(map_ureq_error)?;
        let status = response.status();
        let receipt: PublishReceiptWire =
            decode_json_response(response, "application/json", MAX_RECEIPT_RESPONSE_BYTES)?;
        match (status, receipt.stored, receipt.idempotent) {
            (201, true, false) => Ok(PublishReceipt {
                stored: true,
                idempotent: false,
            }),
            (200, false, true) => Ok(PublishReceipt {
                stored: false,
                idempotent: true,
            }),
            _ => Err(RemoteMailboxError::Protocol),
        }
    }

    pub(crate) fn read_device_to_host_frames(
        &self,
        mailbox_id: &str,
        epoch: u64,
        after_sequence: u64,
    ) -> Result<Vec<Vec<u8>>, RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::DeviceToHost, epoch)?;
        let url = format!(
            "{}?direction=device_to_host&after_sequence={after_sequence}",
            self.mailbox_path(mailbox_id, "frames")
        );
        let response = self
            .agent
            .get(&url)
            .set("Authorization", &self.authorization_header())
            .call()
            .map_err(map_ureq_error)?;
        let content_type = response
            .header("Content-Type")
            .ok_or(RemoteMailboxError::Protocol)?;
        if content_type != "application/json" {
            return Err(RemoteMailboxError::Protocol);
        }
        let body = read_bounded_bytes(response, MAX_FRAME_LIST_RESPONSE_BYTES)?;
        let frames: Vec<RelayOpaqueFrame> = decode_json_slice(&body)?;
        if frames.len() > MAX_READ_FRAMES {
            return Err(RemoteMailboxError::Protocol);
        }
        let mut out = Vec::with_capacity(frames.len());
        let mut last_sequence = after_sequence;
        for frame in frames {
            validate_frame_fields(&frame)?;
            if frame.mailbox_id != mailbox_id
                || frame.direction != RemoteDirection::DeviceToHost
                || frame.epoch != epoch
                || frame.sequence <= last_sequence
            {
                return Err(RemoteMailboxError::Protocol);
            }
            let canonical = serde_json::to_vec(&frame)?;
            parse_canonical_frame(&canonical)?;
            out.push(canonical);
            last_sequence = frame.sequence;
        }
        Ok(out)
    }

    pub(crate) fn ack_device_to_host(
        &self,
        mailbox_id: &str,
        epoch: u64,
        acked_through_sequence: u64,
    ) -> Result<AckReceipt, RemoteMailboxError> {
        let ack = RelayOpaqueAck {
            schema: ACK_SCHEMA.to_string(),
            mailbox_id: mailbox_id.to_string(),
            direction: RemoteDirection::DeviceToHost,
            epoch,
            acked_through_sequence,
        };
        let bytes = canonical_ack_bytes(&ack)?;
        let response = self
            .agent
            .post(self.mailbox_path(mailbox_id, "acks").as_str())
            .set("Authorization", &self.authorization_header())
            .set("Content-Type", "application/json")
            .send_bytes(&bytes)
            .map_err(map_ureq_error)?;
        if response.status() != 200 {
            return Err(RemoteMailboxError::Protocol);
        }
        let receipt: AckReceiptWire =
            decode_json_response(response, "application/json", MAX_RECEIPT_RESPONSE_BYTES)?;
        if !receipt.acked {
            return Err(RemoteMailboxError::Protocol);
        }
        Ok(AckReceipt { acked: true })
    }

    pub(crate) fn delete_mailbox(&self, mailbox_id: &str) -> Result<(), RemoteMailboxError> {
        validate_stream_key(mailbox_id, RemoteDirection::HostToDevice, 1)?;
        let response = self
            .agent
            .delete(self.mailbox_path(mailbox_id, "").trim_end_matches('/'))
            .set("Authorization", &self.authorization_header())
            .call()
            .map_err(map_ureq_error)?;
        if response.status() != 204 {
            return Err(RemoteMailboxError::HttpStatus(response.status()));
        }
        Ok(())
    }

    fn mailbox_path(&self, mailbox_id: &str, suffix: &str) -> String {
        let mut base = self.base_url.as_str().trim_end_matches('/').to_string();
        base.push_str("/v2/mailboxes/");
        base.push_str(mailbox_id);
        if !suffix.is_empty() {
            base.push('/');
            base.push_str(suffix);
        }
        base
    }

    fn authorization_header(&self) -> String {
        format!("Bearer {}", self.bearer.as_str())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishReceiptWire {
    stored: bool,
    idempotent: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckReceiptWire {
    acked: bool,
}

fn validate_base_url(url: &Url, allow_loopback_test_http: bool) -> Result<(), RemoteMailboxError> {
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "" && url.path() != "/")
        || url.cannot_be_a_base()
    {
        return Err(RemoteMailboxError::InvalidConfig);
    }
    let host = url.host_str().ok_or(RemoteMailboxError::InvalidConfig)?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_loopback_test_http && is_loopback_host(host) => Ok(()),
        _ => Err(RemoteMailboxError::InvalidConfig),
    }
}

fn validate_bearer(bearer: &str) -> Result<(), RemoteMailboxError> {
    if bearer.is_empty()
        || bearer.len() > 4096
        || bearer.chars().any(|ch| ch <= ' ' || ch == '\u{7f}')
    {
        return Err(RemoteMailboxError::InvalidConfig);
    }
    Ok(())
}

fn validate_stream_key(
    mailbox_id: &str,
    _direction: RemoteDirection,
    epoch: u64,
) -> Result<(), RemoteMailboxError> {
    if !prefixed_hex(mailbox_id, "mbx-", 64) || epoch == 0 || epoch > MAX_SAFE_INTEGER {
        return Err(RemoteMailboxError::InvalidState);
    }
    Ok(())
}

pub(crate) fn parse_canonical_frame(raw: &[u8]) -> Result<RelayOpaqueFrame, RemoteMailboxError> {
    if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
        return Err(RemoteMailboxError::InvalidFrame);
    }
    let frame: RelayOpaqueFrame = decode_json_exact(raw)?;
    validate_frame_fields(&frame)?;
    let canonical = serde_json::to_vec(&frame)?;
    if canonical != raw {
        return Err(RemoteMailboxError::InvalidFrame);
    }
    Ok(frame)
}

fn canonical_ack_bytes(ack: &RelayOpaqueAck) -> Result<Vec<u8>, RemoteMailboxError> {
    validate_ack_fields(ack)?;
    Ok(serde_json::to_vec(ack)?)
}

fn validate_frame_fields(frame: &RelayOpaqueFrame) -> Result<(), RemoteMailboxError> {
    if frame.schema != FRAME_SCHEMA
        || frame.crypto_suite != FRAME_SUITE
        || !prefixed_hex(&frame.mailbox_id, "mbx-", 64)
        || frame.epoch == 0
        || frame.epoch > MAX_SAFE_INTEGER
        || frame.sequence == 0
        || frame.sequence > MAX_SAFE_INTEGER
        || !prefixed_hex(&frame.message_id, "msg-", 32)
        || frame.issued_at <= 0
        || frame.expires_at <= frame.issued_at
        || frame.expires_at - frame.issued_at > MAX_TTL_SECONDS
    {
        return Err(RemoteMailboxError::InvalidFrame);
    }
    let issued_at = u64::try_from(frame.issued_at).map_err(|_| RemoteMailboxError::InvalidFrame)?;
    let expires_at =
        u64::try_from(frame.expires_at).map_err(|_| RemoteMailboxError::InvalidFrame)?;
    if issued_at > MAX_SAFE_INTEGER || expires_at > MAX_SAFE_INTEGER {
        return Err(RemoteMailboxError::InvalidFrame);
    }
    let nonce =
        decode_base64url_nopad(&frame.nonce).map_err(|_| RemoteMailboxError::InvalidFrame)?;
    if nonce.len() != 12 {
        return Err(RemoteMailboxError::InvalidFrame);
    }
    let ciphertext =
        decode_base64url_nopad(&frame.ciphertext).map_err(|_| RemoteMailboxError::InvalidFrame)?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_WIRE_BYTES {
        return Err(RemoteMailboxError::InvalidFrame);
    }
    Ok(())
}

fn validate_ack_fields(ack: &RelayOpaqueAck) -> Result<(), RemoteMailboxError> {
    if ack.schema != ACK_SCHEMA
        || !prefixed_hex(&ack.mailbox_id, "mbx-", 64)
        || ack.epoch == 0
        || ack.epoch > MAX_SAFE_INTEGER
        || ack.acked_through_sequence == 0
        || ack.acked_through_sequence > MAX_SAFE_INTEGER
    {
        return Err(RemoteMailboxError::InvalidAck);
    }
    Ok(())
}

fn decode_json_exact<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> Result<T, RemoteMailboxError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut deserializer)?;
    deserializer
        .end()
        .map_err(|_| RemoteMailboxError::Protocol)?;
    Ok(value)
}

fn decode_json_slice<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> Result<T, RemoteMailboxError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut deserializer)?;
    deserializer
        .end()
        .map_err(|_| RemoteMailboxError::Protocol)?;
    Ok(value)
}

fn map_ureq_error(error: ureq::Error) -> RemoteMailboxError {
    match error {
        ureq::Error::Status(status, _) => RemoteMailboxError::HttpStatus(status),
        ureq::Error::Transport(_) => RemoteMailboxError::Unavailable,
    }
}

fn decode_json_response<T: for<'de> Deserialize<'de>>(
    response: ureq::Response,
    expected_content_type: &str,
    max_bytes: u64,
) -> Result<T, RemoteMailboxError> {
    let content_type = response
        .header("Content-Type")
        .ok_or(RemoteMailboxError::Protocol)?;
    if content_type != expected_content_type {
        return Err(RemoteMailboxError::Protocol);
    }
    let body = read_bounded_bytes(response, max_bytes)?;
    decode_json_slice(&body)
}

fn read_bounded_bytes(
    response: ureq::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, RemoteMailboxError> {
    let mut reader = response.into_reader().take(max_bytes + 1);
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    if body.len() as u64 > max_bytes {
        return Err(RemoteMailboxError::Protocol);
    }
    Ok(body)
}

fn prefixed_hex(value: &str, prefix: &str, hex_len: usize) -> bool {
    value.len() == prefix.len() + hex_len
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_base64url_nopad(value: &str) -> Result<Vec<u8>, RemoteMailboxError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'=' | b' ' | b'\r' | b'\n' | b'\t'))
    {
        return Err(RemoteMailboxError::Protocol);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| RemoteMailboxError::Protocol)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(RemoteMailboxError::Protocol);
    }
    Ok(decoded)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn immediate_transaction(conn: &Connection) -> Result<Transaction<'_>, RemoteMailboxError> {
    Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(Into::into)
}

fn absolutize_path(path: &Path) -> Result<PathBuf, RemoteMailboxError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn validate_no_symlink_components(path: &Path) -> Result<(), RemoteMailboxError> {
    let absolute = absolutize_path(path)?;
    let target = absolute.parent().ok_or(RemoteMailboxError::InvalidState)?;
    let mut current = PathBuf::new();
    for component in target.components() {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| RemoteMailboxError::InvalidState)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RemoteMailboxError::InvalidState);
        }
    }
    Ok(())
}

fn ensure_stream_row(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    direction: RemoteDirection,
    epoch: u64,
) -> Result<(), RemoteMailboxError> {
    tx.execute(
        "INSERT INTO remote_mailbox_state (mailbox_id, direction, epoch) VALUES (?1, ?2, ?3)
         ON CONFLICT(mailbox_id, direction, epoch) DO NOTHING",
        params![mailbox_id, direction.as_str(), epoch],
    )?;
    Ok(())
}

fn require_pending_response(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    epoch: u64,
    inbound_sequence: u64,
    outbound_sequence: u64,
) -> Result<(), RemoteMailboxError> {
    let pending: (Option<u64>, Option<u64>, Option<Vec<u8>>) = tx.query_row(
        "SELECT pending_sequence, pending_inbound_sequence, pending_frame_bytes
         FROM remote_mailbox_state WHERE mailbox_id=?1 AND direction='host_to_device' AND epoch=?2",
        params![mailbox_id, epoch],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if pending.0 != Some(outbound_sequence)
        || pending.1 != Some(inbound_sequence)
        || pending.2.is_none()
    {
        return Err(RemoteMailboxError::StateConflict);
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), RemoteMailboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RemoteMailboxError::InvalidState)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(RemoteMailboxError::InvalidState);
    }
    Ok(())
}

fn open_private_database(path: &Path) -> Result<(File, FileIdentity), RemoteMailboxError> {
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
                .map_err(|_| RemoteMailboxError::InvalidState)?
        }
        Err(_) => return Err(RemoteMailboxError::InvalidState),
    };
    let identity = validate_open_private_file(&file)?;
    validate_private_file(path, Some(identity))?;
    Ok((file, identity))
}

fn validate_open_private_file(file: &File) -> Result<FileIdentity, RemoteMailboxError> {
    let metadata = file
        .metadata()
        .map_err(|_| RemoteMailboxError::InvalidState)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(RemoteMailboxError::InvalidState);
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_private_file(
    path: &Path,
    expected: Option<FileIdentity>,
) -> Result<FileIdentity, RemoteMailboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RemoteMailboxError::InvalidState)?;
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
        return Err(RemoteMailboxError::InvalidState);
    }
    Ok(identity)
}

fn validate_sqlite_sidecars(db_path: &Path) -> Result<(), RemoteMailboxError> {
    for path in sqlite_sidecars(db_path) {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                validate_private_file(&path, None)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RemoteMailboxError::InvalidState),
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
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread;
    use std::time::Instant;

    use std::os::unix::fs::symlink;

    #[test]
    fn remote_mailbox_state_reserves_sequence_and_persists_pending_retry_bytes() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("ab");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 3, 1);

        let reserved = state
            .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 3)
            .unwrap();
        assert_eq!(reserved, 1);

        state
            .store_pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 3, 1, &frame)
            .unwrap();

        let pending = state
            .pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 3)
            .unwrap()
            .unwrap();
        assert_eq!(pending.sequence, 1);
        assert_eq!(pending.canonical_frame_bytes, frame);

        let cursor = state
            .cursor(&mailbox_id, RemoteDirection::HostToDevice, 3)
            .unwrap();
        assert_eq!(cursor.next_sequence, 2);
        assert_eq!(cursor.pending_sequence, Some(1));
    }

    #[test]
    fn remote_mailbox_state_reserve_conflicts_when_pending_exists() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("ac");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 3, 1);
        state
            .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 3)
            .unwrap();
        state
            .store_pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 3, 1, &frame)
            .unwrap();

        let err = state
            .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 3)
            .unwrap_err();
        assert!(matches!(err, RemoteMailboxError::StateConflict));
    }

    #[test]
    fn remote_mailbox_state_rejects_pending_frame_mutation_for_same_reserved_sequence() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("cd");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 5, 1);
        let mut mutated_frame: RelayOpaqueFrame = serde_json::from_slice(&frame).unwrap();
        mutated_frame.message_id = message_id("56");
        let mutated = serde_json::to_vec(&mutated_frame).unwrap();

        let reserved = state
            .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 5)
            .unwrap();
        assert_eq!(reserved, 1);
        state
            .store_pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 5, 1, &frame)
            .unwrap();

        let err = state
            .store_pending_outbound_frame(
                &mailbox_id,
                RemoteDirection::HostToDevice,
                5,
                1,
                &mutated,
            )
            .unwrap_err();
        assert!(matches!(err, RemoteMailboxError::StateConflict));
    }

    #[test]
    fn response_association_is_atomic_across_applied_and_ack_restart_boundaries() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("c1");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 5, 1);
        state
            .persist_read_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 5, 22)
            .unwrap();
        assert_eq!(
            state
                .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 5)
                .unwrap(),
            1
        );
        state
            .store_pending_response_frame(&mailbox_id, 5, 22, 1, &frame)
            .unwrap();

        let pending = state
            .pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 5)
            .unwrap()
            .unwrap();
        assert_eq!(pending.sequence, 1);
        assert_eq!(pending.inbound_sequence, Some(22));
        assert_eq!(pending.canonical_frame_bytes, frame);
        state.mark_response_applied(&mailbox_id, 5, 22, 1).unwrap();
        let cursor = state
            .cursor(&mailbox_id, RemoteDirection::DeviceToHost, 5)
            .unwrap();
        assert_eq!(cursor.applied_through_sequence, 22);
        assert_eq!(cursor.acked_through_sequence, 0);
        assert_eq!(
            state
                .pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 5)
                .unwrap()
                .unwrap()
                .inbound_sequence,
            Some(22)
        );

        state.complete_response_ack(&mailbox_id, 5, 22, 1).unwrap();
        let cursor = state
            .cursor(&mailbox_id, RemoteDirection::DeviceToHost, 5)
            .unwrap();
        assert_eq!(cursor.acked_through_sequence, 22);
        assert!(state
            .pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 5)
            .unwrap()
            .is_none());
    }

    #[test]
    fn response_association_rejects_wrong_inbound_or_outbound_tuple() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("c2");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 6, 1);
        state
            .persist_read_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 6, 4)
            .unwrap();
        state
            .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 6)
            .unwrap();
        state
            .store_pending_response_frame(&mailbox_id, 6, 4, 1, &frame)
            .unwrap();

        assert!(matches!(
            state.mark_response_applied(&mailbox_id, 6, 3, 1),
            Err(RemoteMailboxError::StateConflict)
        ));
        assert!(matches!(
            state.complete_response_ack(&mailbox_id, 6, 4, 2),
            Err(RemoteMailboxError::StateConflict)
        ));
        let cursor = state
            .cursor(&mailbox_id, RemoteDirection::DeviceToHost, 6)
            .unwrap();
        assert_eq!(cursor.applied_through_sequence, 0);
        assert_eq!(cursor.acked_through_sequence, 0);
    }

    #[test]
    fn file_backed_response_association_survives_restart_until_ack_completion() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = canonical_root.join("remote-mailbox.sqlite3");
        let mailbox_id = mailbox_id("c3");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 9, 1);
        {
            let state = RemoteMailboxState::open(&path).unwrap();
            state
                .persist_read_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 9, 31)
                .unwrap();
            state
                .reserve_outbound_sequence(&mailbox_id, RemoteDirection::HostToDevice, 9)
                .unwrap();
            state
                .store_pending_response_frame(&mailbox_id, 9, 31, 1, &frame)
                .unwrap();
            state.mark_response_applied(&mailbox_id, 9, 31, 1).unwrap();
        }

        let reopened = RemoteMailboxState::open(&path).unwrap();
        reopened.validate_ingress_state().unwrap();
        let pending = reopened
            .pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 9)
            .unwrap()
            .unwrap();
        assert_eq!(pending.inbound_sequence, Some(31));
        assert_eq!(pending.canonical_frame_bytes, frame);
        let cursor = reopened
            .cursor(&mailbox_id, RemoteDirection::DeviceToHost, 9)
            .unwrap();
        assert_eq!(cursor.applied_through_sequence, 31);
        assert_eq!(cursor.acked_through_sequence, 0);
        reopened
            .complete_response_ack(&mailbox_id, 9, 31, 1)
            .unwrap();
        assert!(reopened
            .pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 9)
            .unwrap()
            .is_none());
    }

    #[test]
    fn durable_poison_is_content_free_idempotent_and_survives_restart_until_ack() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = canonical_root.join("remote-mailbox.sqlite3");
        let mailbox_id = mailbox_id("c4");
        {
            let state = RemoteMailboxState::open(&path).unwrap();
            state
                .persist_read_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 11, 42)
                .unwrap();
            state
                .persist_poison_disposition(
                    &mailbox_id,
                    11,
                    42,
                    PoisonReasonCode::ApplicationInvalid,
                )
                .unwrap();
            state
                .persist_poison_disposition(
                    &mailbox_id,
                    11,
                    42,
                    PoisonReasonCode::ApplicationInvalid,
                )
                .unwrap();
            assert!(matches!(
                state.persist_poison_disposition(
                    &mailbox_id,
                    11,
                    42,
                    PoisonReasonCode::CommandInvalid,
                ),
                Err(RemoteMailboxError::StateConflict)
            ));
        }

        let reopened = RemoteMailboxState::open(&path).unwrap();
        reopened.validate_ingress_state().unwrap();
        assert_eq!(
            reopened
                .pending_poison_disposition(&mailbox_id, 11)
                .unwrap(),
            Some(DurablePoisonDisposition {
                inbound_sequence: 42,
                reason_code: PoisonReasonCode::ApplicationInvalid,
            })
        );
        let persisted: (String, u64, u64, String) = reopened
            .conn
            .query_row(
                "SELECT mailbox_id, epoch, inbound_sequence, reason_code
                 FROM remote_mailbox_poison",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(persisted.0, mailbox_id);
        assert_eq!(persisted.1, 11);
        assert_eq!(persisted.2, 42);
        assert_eq!(persisted.3, "APPLICATION_INVALID");
        reopened.complete_poison_ack(&mailbox_id, 11, 42).unwrap();
        assert!(reopened
            .pending_poison_disposition(&mailbox_id, 11)
            .unwrap()
            .is_none());
    }

    #[test]
    fn remote_mailbox_state_store_pending_requires_prior_reserve() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("ce");
        let frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 5, 1);

        let err = state
            .store_pending_outbound_frame(&mailbox_id, RemoteDirection::HostToDevice, 5, 1, &frame)
            .unwrap_err();
        assert!(matches!(err, RemoteMailboxError::StateConflict));
    }

    #[test]
    fn remote_mailbox_state_persists_applied_before_ack_and_blocks_regression() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("ef");

        state
            .persist_read_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 2, 7)
            .unwrap();
        state
            .persist_applied_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 2, 7)
            .unwrap();
        state
            .persist_acked_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 2, 7)
            .unwrap();

        let cursor = state
            .cursor(&mailbox_id, RemoteDirection::DeviceToHost, 2)
            .unwrap();
        assert_eq!(cursor.read_through_sequence, 7);
        assert_eq!(cursor.applied_through_sequence, 7);
        assert_eq!(cursor.acked_through_sequence, 7);

        let err = state
            .persist_acked_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 2, 8)
            .unwrap_err();
        assert!(matches!(err, RemoteMailboxError::StateConflict));

        let regression = state
            .persist_read_through_sequence(&mailbox_id, RemoteDirection::DeviceToHost, 2, 6)
            .unwrap_err();
        assert!(matches!(regression, RemoteMailboxError::StateConflict));
    }

    #[test]
    fn remote_mailbox_state_file_backed_enforces_private_wal_full() {
        let dir = tempfile::tempdir().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        fs::set_permissions(&canonical_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let db_path = canonical_dir.join("remote-mailbox.sqlite3");
        let state = RemoteMailboxState::open(&db_path).unwrap();
        let journal_mode: String = state
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let synchronous: i64 = state
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();

        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        assert_eq!(synchronous, 2);
        assert_eq!(
            fs::metadata(&db_path).unwrap().permissions().mode() & 0o777,
            PRIVATE_FILE_MODE
        );
    }

    #[test]
    fn remote_mailbox_state_rejects_symlink_parent_component() {
        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let link_parent = dir.path().join("link");
        symlink(&real_parent, &link_parent).unwrap();

        let err =
            RemoteMailboxState::open(&link_parent.join("remote-mailbox.sqlite3")).unwrap_err();
        assert!(matches!(err, RemoteMailboxError::InvalidState));
    }

    #[test]
    fn remote_mailbox_client_rejects_non_https_without_explicit_loopback_test() {
        assert!(HostRelayV2Client::new("https://relay.example.test", "bearer", false).is_ok());
        assert!(HostRelayV2Client::new("https://relay.example.test/", "bearer", false).is_ok());
        assert!(HostRelayV2Client::new("http://127.0.0.1:4011", "bearer", false).is_err());
        assert!(HostRelayV2Client::new("http://example.com:4011", "bearer", true).is_err());
        assert!(HostRelayV2Client::new("http://127.0.0.1:4011", "bearer", true).is_ok());
    }

    #[test]
    fn remote_mailbox_client_debug_redacts_bearer() {
        let client =
            HostRelayV2Client::new("https://relay.example.test/", "super-secret-token", false)
                .unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn remote_mailbox_state_rejects_next_sequence_overflow_past_js_safe_integer() {
        let state = RemoteMailboxState::open_memory().unwrap();
        let mailbox_id = mailbox_id("aa");
        state
            .conn
            .execute(
                "INSERT INTO remote_mailbox_state (mailbox_id, direction, epoch, next_sequence)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    mailbox_id,
                    RemoteDirection::HostToDevice.as_str(),
                    1_u64,
                    MAX_SAFE_INTEGER
                ],
            )
            .unwrap();

        let err = state
            .reserve_outbound_sequence(
                "mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                RemoteDirection::HostToDevice,
                1,
            )
            .unwrap_err();
        assert!(matches!(err, RemoteMailboxError::StateConflict));
    }

    #[test]
    fn remote_mailbox_client_publish_uses_authorization_only_and_round_trips_host_role_calls() {
        let mailbox_id = mailbox_id("12");
        let publish_frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 1, 1);
        let read_frame = canonical_frame(&mailbox_id, RemoteDirection::DeviceToHost, 1, 2);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mailbox_id_server = mailbox_id.clone();
        let publish_frame_server = publish_frame.clone();
        let read_frame_server = read_frame.clone();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let publish_request = read_http_request(&mut stream);
            assert!(publish_request.starts_with("POST /v2/mailboxes/"));
            assert!(publish_request.contains("\r\nAuthorization: Bearer host-secret\r\n"));
            assert!(!publish_request.contains("host-secret?"));
            assert!(!publish_request.contains("X-Authorization"));
            assert!(publish_request.ends_with(std::str::from_utf8(&publish_frame_server).unwrap()));
            write_http_response(
                &mut stream,
                201,
                "Created",
                "application/json",
                br#"{"stored":true,"idempotent":false}"#,
            );

            let (mut stream, _) = listener.accept().unwrap();
            let read_request = read_http_request(&mut stream);
            assert!(read_request.starts_with(&format!(
                "GET /v2/mailboxes/{mailbox_id_server}/frames?direction=device_to_host&after_sequence=1 HTTP/1.1\r\n"
            )));
            assert!(read_request.contains("\r\nAuthorization: Bearer host-secret\r\n"));
            let body = format!("[{}]", std::str::from_utf8(&read_frame_server).unwrap());
            write_http_response(&mut stream, 200, "OK", "application/json", body.as_bytes());

            let (mut stream, _) = listener.accept().unwrap();
            let ack_request = read_http_request(&mut stream);
            assert!(ack_request.starts_with(&format!(
                "POST /v2/mailboxes/{mailbox_id_server}/acks HTTP/1.1\r\n"
            )));
            assert!(ack_request.contains(r#""direction":"device_to_host""#));
            write_http_response(
                &mut stream,
                200,
                "OK",
                "application/json",
                br#"{"acked":true}"#,
            );

            let (mut stream, _) = listener.accept().unwrap();
            let delete_request = read_http_request(&mut stream);
            assert!(delete_request.starts_with(&format!(
                "DELETE /v2/mailboxes/{mailbox_id_server} HTTP/1.1\r\n"
            )));
            write_http_response(&mut stream, 204, "No Content", "", b"");
        });

        let client =
            HostRelayV2Client::new(&format!("http://{addr}"), "host-secret", true).unwrap();
        let publish = client.publish_frame(&publish_frame).unwrap();
        assert_eq!(
            publish,
            PublishReceipt {
                stored: true,
                idempotent: false,
            }
        );

        let read = client
            .read_device_to_host_frames(&mailbox_id, 1, 1)
            .unwrap();
        assert_eq!(read, vec![read_frame]);

        let ack = client.ack_device_to_host(&mailbox_id, 1, 2).unwrap();
        assert_eq!(ack, AckReceipt { acked: true });

        client.delete_mailbox(&mailbox_id).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn remote_mailbox_client_publish_requires_exact_status_and_receipt_pair() {
        let mailbox_id = mailbox_id("13");
        let publish_frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 1, 1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_http_request(&mut stream);
            write_http_response(
                &mut stream,
                201,
                "Created",
                "application/json",
                br#"{"stored":false,"idempotent":true}"#,
            );
        });

        let client =
            HostRelayV2Client::new(&format!("http://{addr}"), "host-secret", true).unwrap();
        let err = client.publish_frame(&publish_frame).unwrap_err();
        assert!(matches!(err, RemoteMailboxError::Protocol));
        handle.join().unwrap();
    }

    #[test]
    fn remote_mailbox_client_ack_requires_exact_status_and_true_body() {
        let mailbox_id = mailbox_id("14");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_http_request(&mut stream);
            write_http_response(
                &mut stream,
                200,
                "OK",
                "application/json",
                br#"{"acked":false}"#,
            );
        });

        let client =
            HostRelayV2Client::new(&format!("http://{addr}"), "host-secret", true).unwrap();
        let err = client.ack_device_to_host(&mailbox_id, 1, 1).unwrap_err();
        assert!(matches!(err, RemoteMailboxError::Protocol));
        handle.join().unwrap();
    }

    #[test]
    fn remote_mailbox_client_does_not_follow_redirects() {
        let mailbox_id = mailbox_id("15");
        let publish_frame = canonical_frame(&mailbox_id, RemoteDirection::HostToDevice, 1, 1);
        let redirect_target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_target_addr = redirect_target_listener.local_addr().unwrap();
        let redirected = Arc::new(AtomicBool::new(false));
        let redirected_server = Arc::clone(&redirected);
        let target_handle = thread::spawn(move || {
            redirect_target_listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(750);
            while Instant::now() < deadline {
                match redirect_target_listener.accept() {
                    Ok((mut stream, _)) => {
                        redirected_server.store(true, Ordering::SeqCst);
                        let _ = read_http_request(&mut stream);
                        write_http_response(
                            &mut stream,
                            200,
                            "OK",
                            "application/json",
                            br#"{"stored":true,"idempotent":false}"#,
                        );
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        });

        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_addr = redirect_listener.local_addr().unwrap();
        let redirect_handle = thread::spawn(move || {
            let (mut stream, _) = redirect_listener.accept().unwrap();
            let _request = read_http_request(&mut stream);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{redirect_target_addr}/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let client =
            HostRelayV2Client::new(&format!("http://{redirect_addr}"), "host-secret", true)
                .unwrap();
        assert!(client.publish_frame(&publish_frame).is_err());
        redirect_handle.join().unwrap();
        target_handle.join().unwrap();
        assert!(!redirected.load(Ordering::SeqCst));
    }

    #[test]
    fn remote_mailbox_client_rejects_oversize_frame_list_response() {
        let mailbox_id = mailbox_id("16");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_http_request(&mut stream);
            let body = vec![b' '; (MAX_FRAME_LIST_RESPONSE_BYTES as usize) + 1];
            write_http_response(&mut stream, 200, "OK", "application/json", &body);
        });

        let client =
            HostRelayV2Client::new(&format!("http://{addr}"), "host-secret", true).unwrap();
        let err = client
            .read_device_to_host_frames(&mailbox_id, 1, 0)
            .unwrap_err();
        assert!(matches!(err, RemoteMailboxError::Protocol));
        handle.join().unwrap();
    }

    fn mailbox_id(byte_pair: &str) -> String {
        format!("mbx-{}", byte_pair.repeat(32))
    }

    fn message_id(byte_pair: &str) -> String {
        format!("msg-{}", byte_pair.repeat(16))
    }

    fn canonical_frame(
        mailbox_id: &str,
        direction: RemoteDirection,
        epoch: u64,
        sequence: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&RelayOpaqueFrame {
            schema: FRAME_SCHEMA.to_string(),
            crypto_suite: FRAME_SUITE.to_string(),
            mailbox_id: mailbox_id.to_string(),
            direction,
            epoch,
            sequence,
            message_id: message_id("34"),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_600,
            nonce: URL_SAFE_NO_PAD.encode([0_u8; 12]),
            ciphertext: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        })
        .unwrap()
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = Vec::new();
        let mut headers_end = None;
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if headers_end.is_none() {
                headers_end = find_headers_end(&buf);
            }
            if let Some(index) = headers_end {
                let headers = String::from_utf8_lossy(&buf[..index]);
                let content_length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if buf.len() >= index + content_length {
                    break;
                }
            }
        }
        String::from_utf8(buf).unwrap()
    }

    fn find_headers_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
    }

    fn write_http_response(
        stream: &mut TcpStream,
        status: u16,
        reason: &str,
        content_type: &str,
        body: &[u8],
    ) {
        let mut response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if !content_type.is_empty() {
            response.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        response.push_str("\r\n");
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
    }
}
