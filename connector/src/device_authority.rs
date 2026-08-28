use crate::run_binding::canonical;
use getrandom::getrandom;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    PublicKey,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const PAIRING_TRANSCRIPT_VERSION: &[u8] = b"nomad.device-authority.pairing.v2";
const CHALLENGE_DIGEST_VERSION: &[u8] = b"nomad.device-authority.challenge.v2\n";
const PUBLIC_KEY_DIGEST_VERSION: &[u8] = b"nomad.device-authority.public-key-digest.v2";
const DEVICE_ALIAS_VERSION: &[u8] = b"nomad.device-authority.device-alias.v2";
const CHALLENGE_BYTES: usize = 32;
const CHALLENGE_ID_BYTES: usize = 16;
const PUBLIC_KEY_BYTES: usize = 65;
const SIGNATURE_BYTES: usize = 64;
const CHALLENGE_TTL_SECONDS: i64 = 120;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SQLITE_BUSY_TIMEOUT_MS: i64 = 5_000;
const REGISTRY_BASENAME: &str = "host-device-registry.sqlite3";
const REGISTRY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS registry_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    current_epoch INTEGER NOT NULL CHECK (current_epoch BETWEEN 0 AND 9223372036854775807),
    time_floor_unix INTEGER NOT NULL
);
INSERT OR IGNORE INTO registry_meta (singleton, current_epoch, time_floor_unix) VALUES (1, 0, 0);

CREATE TABLE IF NOT EXISTS device_registry (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_alias TEXT NOT NULL,
    principal_alias TEXT NOT NULL,
    signing_key_digest BLOB NOT NULL CHECK (length(signing_key_digest) = 32),
    agreement_key_digest BLOB NOT NULL CHECK (length(agreement_key_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    activated_epoch INTEGER NOT NULL UNIQUE CHECK (activated_epoch >= 1),
    revoked_epoch INTEGER CHECK (revoked_epoch IS NULL OR revoked_epoch >= 2),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (device_alias, activated_epoch)
);
CREATE UNIQUE INDEX IF NOT EXISTS device_registry_one_active_idx
    ON device_registry (state) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS device_registry_alias_idx
    ON device_registry (device_alias, activated_epoch DESC);

CREATE TABLE IF NOT EXISTS pairing_challenge (
    challenge_id TEXT PRIMARY KEY,
    challenge_digest BLOB NOT NULL CHECK (length(challenge_digest) = 32),
    signing_public_key BLOB CHECK (signing_public_key IS NULL OR length(signing_public_key) = 65),
    agreement_public_key BLOB CHECK (agreement_public_key IS NULL OR length(agreement_public_key) = 65),
    signing_key_digest BLOB NOT NULL CHECK (length(signing_key_digest) = 32),
    agreement_key_digest BLOB NOT NULL CHECK (length(agreement_key_digest) = 32),
    principal_alias TEXT NOT NULL,
    device_alias TEXT NOT NULL,
    prospective_epoch INTEGER NOT NULL CHECK (prospective_epoch >= 1),
    issued_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    consumed_at_unix INTEGER,
    invalidated_at_unix INTEGER
);
CREATE INDEX IF NOT EXISTS pairing_challenge_epoch_idx
    ON pairing_challenge (prospective_epoch, consumed_at_unix, invalidated_at_unix);
CREATE UNIQUE INDEX IF NOT EXISTS pairing_challenge_one_pending_idx
    ON pairing_challenge ((1))
    WHERE consumed_at_unix IS NULL AND invalidated_at_unix IS NULL;
"#;

#[derive(Clone)]
pub(crate) struct DeviceAuthority {
    db_path: PathBuf,
}

impl DeviceAuthority {
    pub(crate) fn open(path: &Path) -> Result<Self, DeviceAuthorityError> {
        let authority = Self {
            db_path: path.to_path_buf(),
        };
        authority.with_connection(|connection| {
            connection
                .execute_batch(REGISTRY_SCHEMA)
                .map_err(|_| DeviceAuthorityError::Storage)
        })?;
        Ok(authority)
    }

    pub(crate) fn begin_pairing(
        &self,
        principal_alias: &str,
        signing_public_key: &[u8],
        agreement_public_key: &[u8],
        now: OffsetDateTime,
    ) -> Result<PairingChallenge, DeviceAuthorityError> {
        if !valid_alias("principal", principal_alias) {
            return Err(DeviceAuthorityError::InvalidInput);
        }
        let (signing_public_key, agreement_public_key) =
            parse_pairing_public_keys(signing_public_key, agreement_public_key)?;
        let signing_commitment = public_key_digest(signing_public_key.as_slice());
        let agreement_commitment = public_key_digest(agreement_public_key.as_slice());
        let device_alias = device_alias(&signing_commitment, &agreement_commitment);
        let mut challenge = Zeroizing::new([0_u8; CHALLENGE_BYTES]);
        getrandom(challenge.as_mut()).map_err(|_| DeviceAuthorityError::Storage)?;
        let mut challenge_id_bytes = Zeroizing::new([0_u8; CHALLENGE_ID_BYTES]);
        getrandom(challenge_id_bytes.as_mut()).map_err(|_| DeviceAuthorityError::Storage)?;
        let challenge_id = Zeroizing::new(format!(
            "challenge-{}",
            hex_lower(challenge_id_bytes.as_ref())
        ));
        let challenge_digest = challenge_digest(challenge.as_ref());
        let challenge_record = BeginPairingRecord {
            challenge_id: challenge_id.to_string(),
            challenge_digest: challenge_digest.to_vec(),
            signing_public_key: signing_public_key.to_vec(),
            agreement_public_key: agreement_public_key.to_vec(),
            signing_key_digest: signing_commitment.to_vec(),
            agreement_key_digest: agreement_commitment.to_vec(),
            principal_alias: principal_alias.to_owned(),
            device_alias,
            prospective_epoch: 0,
            issued_at_unix: 0,
            expires_at_unix: 0,
        };
        let (prospective_epoch, issued_at_unix, expires_at_unix) =
            self.with_connection(|connection| {
                let tx = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|_| DeviceAuthorityError::Storage)?;
                let issued_at_unix = effective_now(&tx, now.unix_timestamp())?;
                let expires_at_unix = issued_at_unix
                    .checked_add(CHALLENGE_TTL_SECONDS)
                    .ok_or(DeviceAuthorityError::InvalidInput)?;
                let prospective_epoch = next_epoch(current_epoch(&tx)?)?;
                tx.execute(
                    "UPDATE pairing_challenge
                    SET invalidated_at_unix = ?1,
                        signing_public_key = NULL,
                        agreement_public_key = NULL
                  WHERE consumed_at_unix IS NULL AND invalidated_at_unix IS NULL",
                    params![issued_at_unix],
                )
                .map_err(|_| DeviceAuthorityError::Storage)?;
                let mut record = challenge_record;
                record.prospective_epoch = prospective_epoch;
                record.issued_at_unix = issued_at_unix;
                record.expires_at_unix = expires_at_unix;
                tx.execute(
                    "INSERT INTO pairing_challenge (
                    challenge_id,
                    challenge_digest,
                    signing_public_key,
                    agreement_public_key,
                    signing_key_digest,
                    agreement_key_digest,
                    principal_alias,
                    device_alias,
                    prospective_epoch,
                    issued_at_unix,
                    expires_at_unix,
                    consumed_at_unix,
                    invalidated_at_unix
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL)",
                    params![
                        record.challenge_id,
                        record.challenge_digest,
                        record.signing_public_key,
                        record.agreement_public_key,
                        record.signing_key_digest,
                        record.agreement_key_digest,
                        record.principal_alias,
                        record.device_alias,
                        i64::try_from(record.prospective_epoch)
                            .map_err(|_| DeviceAuthorityError::Storage)?,
                        record.issued_at_unix,
                        record.expires_at_unix,
                    ],
                )
                .map_err(|_| DeviceAuthorityError::Storage)?;
                tx.commit().map_err(|_| DeviceAuthorityError::Storage)?;
                Ok((prospective_epoch, issued_at_unix, expires_at_unix))
            })?;
        Ok(PairingChallenge {
            challenge_id,
            challenge,
            prospective_epoch,
            issued_at_unix,
            expires_at_unix,
        })
    }

    pub(crate) fn confirm_pairing(
        &self,
        challenge_id: &str,
        challenge_bytes: &[u8],
        signature: &[u8],
        now: OffsetDateTime,
    ) -> Result<AuthenticatedDeviceFact, DeviceAuthorityError> {
        if !valid_challenge_id(challenge_id) || challenge_bytes.len() != CHALLENGE_BYTES {
            return Err(DeviceAuthorityError::InvalidInput);
        }
        let signature = parse_signature(signature)?;
        let confirmed =
            self.confirm_pairing_with_validator(challenge_id, challenge_bytes, now, |challenge| {
                let signing_public_key = challenge
                    .signing_public_key
                    .ok_or(DeviceAuthorityError::Storage)?;
                let _agreement_public_key = challenge
                    .agreement_public_key
                    .ok_or(DeviceAuthorityError::Storage)?;
                let signing_verifying_key = VerifyingKey::from_sec1_bytes(&signing_public_key)
                    .map_err(|_| DeviceAuthorityError::Storage)?;
                let transcript = pairing_transcript(PairingTranscript {
                    challenge_bytes,
                    signing_key_digest: &challenge.signing_key_digest,
                    agreement_key_digest: &challenge.agreement_key_digest,
                    principal_alias: &challenge.principal_alias,
                    device_alias: &challenge.device_alias,
                    prospective_epoch: challenge.prospective_epoch,
                    issued_at_unix: challenge.issued_at_unix,
                    expires_at_unix: challenge.expires_at_unix,
                });
                signing_verifying_key
                    .verify(&transcript, &signature)
                    .map_err(|_| DeviceAuthorityError::InvalidProof)
            })?;
        Ok(confirmed)
    }

    pub(crate) fn confirm_pairing_preverified(
        &self,
        challenge_id: &str,
        challenge_bytes: &[u8],
        signing_public_key: &[u8],
        agreement_public_key: &[u8],
        now: OffsetDateTime,
    ) -> Result<AuthenticatedDeviceFact, DeviceAuthorityError> {
        if !valid_challenge_id(challenge_id) || challenge_bytes.len() != CHALLENGE_BYTES {
            return Err(DeviceAuthorityError::InvalidInput);
        }
        let (signing_public_key, agreement_public_key) =
            parse_pairing_public_keys(signing_public_key, agreement_public_key)?;
        let signing_commitment = public_key_digest(&signing_public_key);
        let agreement_commitment = public_key_digest(&agreement_public_key);
        self.confirm_pairing_with_validator(challenge_id, challenge_bytes, now, |challenge| {
            if challenge.signing_key_digest.len() != 32
                || challenge.agreement_key_digest.len() != 32
            {
                return Err(DeviceAuthorityError::Storage);
            }
            if !constant_time_equal(&challenge.signing_key_digest, &signing_commitment)
                || !constant_time_equal(&challenge.agreement_key_digest, &agreement_commitment)
            {
                return Err(DeviceAuthorityError::InvalidProof);
            }
            Ok(())
        })
    }

    fn confirm_pairing_with_validator(
        &self,
        challenge_id: &str,
        challenge_bytes: &[u8],
        now: OffsetDateTime,
        validator: impl FnOnce(&LoadedChallenge) -> Result<(), DeviceAuthorityError>,
    ) -> Result<AuthenticatedDeviceFact, DeviceAuthorityError> {
        let confirmed = self.with_connection(|connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| DeviceAuthorityError::Storage)?;
            let challenge =
                load_challenge(&tx, challenge_id)?.ok_or(DeviceAuthorityError::InvalidInput)?;
            if challenge.consumed_at_unix.is_some() || challenge.invalidated_at_unix.is_some() {
                return Err(DeviceAuthorityError::ChallengeConsumed);
            }
            if !constant_time_equal(
                &challenge.challenge_digest,
                &challenge_digest(challenge_bytes),
            ) {
                return Err(DeviceAuthorityError::InvalidInput);
            }
            let effective_now = effective_now(&tx, now.unix_timestamp())?;
            if effective_now > challenge.expires_at_unix {
                tx.execute(
                    "UPDATE pairing_challenge
                        SET invalidated_at_unix = ?2,
                            signing_public_key = NULL,
                            agreement_public_key = NULL
                      WHERE challenge_id = ?1",
                    params![challenge_id, effective_now],
                )
                .map_err(|_| DeviceAuthorityError::Storage)?;
                tx.commit().map_err(|_| DeviceAuthorityError::Storage)?;
                return Err(DeviceAuthorityError::ChallengeExpired);
            }
            let expected_epoch = next_epoch(current_epoch(&tx)?)?;
            if expected_epoch != challenge.prospective_epoch {
                return Err(DeviceAuthorityError::Conflict);
            }
            validator(&challenge)?;
            let consumed = tx
                .execute(
                    "UPDATE pairing_challenge
                        SET consumed_at_unix = ?2,
                            signing_public_key = NULL,
                            agreement_public_key = NULL
                      WHERE challenge_id = ?1
                        AND consumed_at_unix IS NULL",
                    params![challenge_id, effective_now],
                )
                .map_err(|_| DeviceAuthorityError::Storage)?;
            if consumed != 1 {
                return Err(DeviceAuthorityError::ChallengeConsumed);
            }
            tx.execute(
                "UPDATE device_registry
                    SET state = 'revoked',
                        revoked_epoch = ?1,
                        updated_at = ?2
                  WHERE state = 'active'",
                params![
                    i64::try_from(challenge.prospective_epoch)
                        .map_err(|_| DeviceAuthorityError::Storage)?,
                    effective_now,
                ],
            )
            .map_err(|_| DeviceAuthorityError::Storage)?;
            tx.execute(
                "INSERT INTO device_registry (
                    device_alias,
                    principal_alias,
                    signing_key_digest,
                    agreement_key_digest,
                    state,
                    activated_epoch,
                    revoked_epoch,
                    created_at,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, NULL, ?6, ?6)",
                params![
                    challenge.device_alias,
                    challenge.principal_alias,
                    challenge.signing_key_digest.as_slice(),
                    challenge.agreement_key_digest.as_slice(),
                    i64::try_from(challenge.prospective_epoch)
                        .map_err(|_| DeviceAuthorityError::Storage)?,
                    effective_now,
                ],
            )
            .map_err(|_| DeviceAuthorityError::Storage)?;
            set_current_epoch(&tx, challenge.prospective_epoch)?;
            tx.commit().map_err(|_| DeviceAuthorityError::Storage)?;
            Ok(AuthenticatedDeviceFact {
                principal_alias: challenge.principal_alias,
                device_alias: challenge.device_alias,
                pairing_epoch: challenge.prospective_epoch,
                signing_commitment: challenge
                    .signing_key_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| DeviceAuthorityError::Storage)?,
                agreement_commitment: challenge
                    .agreement_key_digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| DeviceAuthorityError::Storage)?,
            })
        })?;
        Ok(confirmed)
    }

    pub(crate) fn revoke(
        &self,
        device_alias: &str,
        expected_epoch: u64,
        now: OffsetDateTime,
    ) -> Result<RevokeOutcome, DeviceAuthorityError> {
        if !valid_alias("device", device_alias) || expected_epoch == 0 {
            return Err(DeviceAuthorityError::InvalidInput);
        }
        self.with_connection(|connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| DeviceAuthorityError::Storage)?;
            let effective_now = effective_now(&tx, now.unix_timestamp())?;
            let current_epoch = current_epoch(&tx)?;
            let active = load_active_device(&tx)?;
            if let Some(active) = active {
                if active.device_alias != device_alias {
                    return Err(DeviceAuthorityError::Unpaired);
                }
                if active.pairing_epoch != expected_epoch || current_epoch != expected_epoch {
                    return Err(DeviceAuthorityError::EpochMismatch);
                }
                let revoked_epoch = next_epoch(expected_epoch)?;
                tx.execute(
                    "UPDATE device_registry
                        SET state = 'revoked',
                            revoked_epoch = ?1,
                            updated_at = ?2
                      WHERE row_id = ?3
                        AND state = 'active'",
                    params![
                        i64::try_from(revoked_epoch).map_err(|_| DeviceAuthorityError::Storage)?,
                        effective_now,
                        active.row_id,
                    ],
                )
                .map_err(|_| DeviceAuthorityError::Storage)?;
                set_current_epoch(&tx, revoked_epoch)?;
                tx.execute(
                    "UPDATE pairing_challenge
                        SET invalidated_at_unix = ?1,
                            signing_public_key = NULL,
                            agreement_public_key = NULL
                      WHERE consumed_at_unix IS NULL AND invalidated_at_unix IS NULL",
                    params![effective_now],
                )
                .map_err(|_| DeviceAuthorityError::Storage)?;
                tx.commit().map_err(|_| DeviceAuthorityError::Storage)?;
                return Ok(RevokeOutcome::Revoked {
                    prior_epoch: expected_epoch,
                    revoked_epoch,
                });
            }

            let latest = load_latest_device_for_alias(&tx, device_alias)?;
            if let Some(latest) = latest {
                let idempotent_epoch = next_epoch(expected_epoch)?;
                if latest.state == DeviceState::Revoked
                    && latest.revoked_epoch == Some(idempotent_epoch)
                    && current_epoch == idempotent_epoch
                {
                    tx.commit().map_err(|_| DeviceAuthorityError::Storage)?;
                    return Ok(RevokeOutcome::AlreadyRevoked {
                        revoked_epoch: idempotent_epoch,
                    });
                }
            }
            Err(DeviceAuthorityError::EpochMismatch)
        })
    }

    pub(crate) fn current_active(&self) -> Result<CurrentActiveDevice, DeviceAuthorityError> {
        self.with_connection(|connection| {
            let active = load_active_device(connection)?;
            Ok(match active {
                Some(active) => CurrentActiveDevice::Active(AuthenticatedDeviceFact {
                    principal_alias: active.principal_alias,
                    device_alias: active.device_alias,
                    pairing_epoch: active.pairing_epoch,
                    signing_commitment: active.signing_commitment,
                    agreement_commitment: active.agreement_commitment,
                }),
                None => CurrentActiveDevice::Unpaired,
            })
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, DeviceAuthorityError>,
    ) -> Result<T, DeviceAuthorityError> {
        let secure_path = SecureRegistryPath::prepare(&self.db_path)?;
        let mut connection = secure_path.open_sqlite()?;
        let operation_result = operation(&mut connection);
        let close_result = secure_path.finish(connection);
        match (operation_result, close_result) {
            (_, Err(error)) => Err(error),
            (Err(error), _) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    #[cfg(test)]
    fn latest_epoch_for_test(&self) -> Result<u64, DeviceAuthorityError> {
        self.with_connection(|connection| current_epoch(connection))
    }
}

impl fmt::Debug for DeviceAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthority")
            .field("db_path", &"<redacted>")
            .finish()
    }
}

pub(crate) struct PairingChallenge {
    challenge_id: Zeroizing<String>,
    challenge: Zeroizing<[u8; CHALLENGE_BYTES]>,
    prospective_epoch: u64,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

impl PairingChallenge {
    pub(crate) fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub(crate) fn challenge_bytes(&self) -> &[u8] {
        self.challenge.as_ref()
    }

    pub(crate) fn prospective_epoch(&self) -> u64 {
        self.prospective_epoch
    }

    pub(crate) fn issued_at_unix(&self) -> i64 {
        self.issued_at_unix
    }

    pub(crate) fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }
}

impl fmt::Debug for PairingChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingChallenge")
            .field("challenge_id", &"<redacted>")
            .field("challenge", &"<redacted>")
            .field("prospective_epoch", &self.prospective_epoch)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedDeviceFact {
    pub(crate) principal_alias: String,
    pub(crate) device_alias: String,
    pub(crate) pairing_epoch: u64,
    pub(crate) signing_commitment: [u8; 32],
    pub(crate) agreement_commitment: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CurrentActiveDevice {
    Unpaired,
    Active(AuthenticatedDeviceFact),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RevokeOutcome {
    Revoked {
        prior_epoch: u64,
        revoked_epoch: u64,
    },
    AlreadyRevoked {
        revoked_epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DeviceAuthorityError {
    #[error("DEVICE_AUTHORITY_INPUT")]
    InvalidInput,
    #[error("DEVICE_AUTHORITY_PROOF")]
    InvalidProof,
    #[error("DEVICE_AUTHORITY_EXPIRED")]
    ChallengeExpired,
    #[error("DEVICE_AUTHORITY_REPLAY")]
    ChallengeConsumed,
    #[error("DEVICE_AUTHORITY_CONFLICT")]
    Conflict,
    #[error("DEVICE_AUTHORITY_EPOCH")]
    EpochMismatch,
    #[error("DEVICE_AUTHORITY_UNPAIRED")]
    Unpaired,
    #[error("DEVICE_AUTHORITY_SAFETY")]
    Safety,
    #[error("DEVICE_AUTHORITY_STORAGE")]
    Storage,
}

struct BeginPairingRecord {
    challenge_id: String,
    challenge_digest: Vec<u8>,
    signing_public_key: Vec<u8>,
    agreement_public_key: Vec<u8>,
    signing_key_digest: Vec<u8>,
    agreement_key_digest: Vec<u8>,
    principal_alias: String,
    device_alias: String,
    prospective_epoch: u64,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

#[derive(Clone)]
struct LoadedChallenge {
    challenge_digest: Vec<u8>,
    signing_public_key: Option<[u8; PUBLIC_KEY_BYTES]>,
    agreement_public_key: Option<[u8; PUBLIC_KEY_BYTES]>,
    signing_key_digest: Vec<u8>,
    agreement_key_digest: Vec<u8>,
    principal_alias: String,
    device_alias: String,
    prospective_epoch: u64,
    issued_at_unix: i64,
    expires_at_unix: i64,
    consumed_at_unix: Option<i64>,
    invalidated_at_unix: Option<i64>,
}

struct PairingTranscript<'a> {
    challenge_bytes: &'a [u8],
    signing_key_digest: &'a [u8],
    agreement_key_digest: &'a [u8],
    principal_alias: &'a str,
    device_alias: &'a str,
    prospective_epoch: u64,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceState {
    Active,
    Revoked,
}

#[derive(Clone)]
struct LoadedDevice {
    row_id: i64,
    principal_alias: String,
    device_alias: String,
    pairing_epoch: u64,
    signing_commitment: [u8; 32],
    agreement_commitment: [u8; 32],
    state: DeviceState,
    revoked_epoch: Option<u64>,
}

struct SecureRegistryPath {
    db_path: PathBuf,
    wal_path: PathBuf,
    shm_path: PathBuf,
    db_identity: FileIdentity,
}

impl SecureRegistryPath {
    fn prepare(path: &Path) -> Result<Self, DeviceAuthorityError> {
        validate_registry_path(path)?;
        let parent = path.parent().ok_or(DeviceAuthorityError::Safety)?;
        validate_parent_dir(parent)?;
        create_secure_file_if_missing(path)?;
        let wal_path = sidecar_path(path, b"-wal");
        let shm_path = sidecar_path(path, b"-shm");
        let db_identity = validate_secure_file(path, None)?;
        validate_optional_secure_file(&wal_path)?;
        validate_optional_secure_file(&shm_path)?;
        Ok(Self {
            db_path: path.to_path_buf(),
            wal_path,
            shm_path,
            db_identity,
        })
    }

    fn open_sqlite(&self) -> Result<Connection, DeviceAuthorityError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&self.db_path, flags)
            .map_err(|_| DeviceAuthorityError::Storage)?;
        validate_secure_file(&self.db_path, Some(self.db_identity))?;
        connection
            .busy_timeout(SQLITE_BUSY_TIMEOUT)
            .map_err(|_| DeviceAuthorityError::Storage)?;
        connection
            .pragma_update(None, "busy_timeout", SQLITE_BUSY_TIMEOUT_MS)
            .map_err(|_| DeviceAuthorityError::Storage)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| DeviceAuthorityError::Storage)?;
        connection
            .pragma_update(None, "secure_delete", "ON")
            .map_err(|_| DeviceAuthorityError::Storage)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| DeviceAuthorityError::Storage)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| DeviceAuthorityError::Storage)?;
        Ok(connection)
    }

    fn finish(self, connection: Connection) -> Result<(), DeviceAuthorityError> {
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| DeviceAuthorityError::Storage)?;
        connection
            .close()
            .map_err(|_| DeviceAuthorityError::Storage)?;
        validate_secure_file(&self.db_path, Some(self.db_identity))?;
        validate_optional_secure_file(&self.wal_path)?;
        validate_optional_secure_file(&self.shm_path)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ParentFacts {
    is_dir: bool,
    is_symlink: bool,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy)]
struct FileFacts {
    is_file: bool,
    is_symlink: bool,
    uid: u32,
    mode: u32,
    nlink: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

fn validate_registry_path(path: &Path) -> Result<(), DeviceAuthorityError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(DeviceAuthorityError::Safety);
    }
    if path.file_name().and_then(|name| name.to_str()) != Some(REGISTRY_BASENAME) {
        return Err(DeviceAuthorityError::Safety);
    }
    Ok(())
}

fn validate_parent_dir(path: &Path) -> Result<(), DeviceAuthorityError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DeviceAuthorityError::Safety)?;
    let facts = ParentFacts {
        is_dir: metadata.is_dir(),
        is_symlink: metadata.file_type().is_symlink(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o777,
    };
    validate_parent_facts(facts, current_euid())?;
    if fs::canonicalize(path).map_err(|_| DeviceAuthorityError::Safety)? != path {
        return Err(DeviceAuthorityError::Safety);
    }
    Ok(())
}

fn validate_parent_facts(
    facts: ParentFacts,
    expected_uid: u32,
) -> Result<(), DeviceAuthorityError> {
    if !facts.is_dir || facts.is_symlink || facts.uid != expected_uid || facts.mode != 0o700 {
        return Err(DeviceAuthorityError::Safety);
    }
    Ok(())
}

fn create_secure_file_if_missing(path: &Path) -> Result<(), DeviceAuthorityError> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => sync_new_file(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(DeviceAuthorityError::Safety),
    }
}

fn sync_new_file(file: File) -> Result<(), DeviceAuthorityError> {
    let metadata = file.metadata().map_err(|_| DeviceAuthorityError::Safety)?;
    let facts = FileFacts {
        is_file: metadata.is_file(),
        is_symlink: metadata.file_type().is_symlink(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o777,
        nlink: metadata.nlink(),
    };
    validate_file_facts(facts, current_euid())?;
    file.sync_all().map_err(|_| DeviceAuthorityError::Safety)
}

fn validate_secure_file(
    path: &Path,
    expected: Option<FileIdentity>,
) -> Result<FileIdentity, DeviceAuthorityError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DeviceAuthorityError::Safety)?;
    let facts = FileFacts {
        is_file: metadata.is_file(),
        is_symlink: metadata.file_type().is_symlink(),
        uid: metadata.uid(),
        mode: metadata.permissions().mode() & 0o777,
        nlink: metadata.nlink(),
    };
    validate_file_facts(facts, current_euid())?;
    let identity = FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    if expected.is_some_and(|wanted| wanted != identity) {
        return Err(DeviceAuthorityError::Safety);
    }
    Ok(identity)
}

fn validate_optional_secure_file(path: &Path) -> Result<(), DeviceAuthorityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let facts = FileFacts {
                is_file: metadata.is_file(),
                is_symlink: metadata.file_type().is_symlink(),
                uid: metadata.uid(),
                mode: metadata.permissions().mode() & 0o777,
                nlink: metadata.nlink(),
            };
            validate_file_facts(facts, current_euid())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DeviceAuthorityError::Safety),
    }
}

fn validate_file_facts(facts: FileFacts, expected_uid: u32) -> Result<(), DeviceAuthorityError> {
    if !facts.is_file
        || facts.is_symlink
        || facts.uid != expected_uid
        || facts.mode != 0o600
        || facts.nlink != 1
    {
        return Err(DeviceAuthorityError::Safety);
    }
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &[u8]) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(suffix);
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn parse_signing_public_key(input: &[u8]) -> Result<[u8; PUBLIC_KEY_BYTES], DeviceAuthorityError> {
    let bytes: [u8; PUBLIC_KEY_BYTES] = input
        .try_into()
        .map_err(|_| DeviceAuthorityError::InvalidInput)?;
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| DeviceAuthorityError::InvalidInput)?;
    Ok(bytes)
}

fn parse_agreement_public_key(
    input: &[u8],
) -> Result<[u8; PUBLIC_KEY_BYTES], DeviceAuthorityError> {
    let bytes: [u8; PUBLIC_KEY_BYTES] = input
        .try_into()
        .map_err(|_| DeviceAuthorityError::InvalidInput)?;
    PublicKey::from_sec1_bytes(&bytes).map_err(|_| DeviceAuthorityError::InvalidInput)?;
    Ok(bytes)
}

fn parse_pairing_public_keys(
    signing_public_key: &[u8],
    agreement_public_key: &[u8],
) -> Result<([u8; PUBLIC_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]), DeviceAuthorityError> {
    let signing = parse_signing_public_key(signing_public_key)?;
    let agreement = parse_agreement_public_key(agreement_public_key)?;
    if constant_time_equal(&signing, &agreement) {
        return Err(DeviceAuthorityError::InvalidInput);
    }
    Ok((signing, agreement))
}

fn parse_signature(input: &[u8]) -> Result<Signature, DeviceAuthorityError> {
    if input.len() != SIGNATURE_BYTES {
        return Err(DeviceAuthorityError::InvalidInput);
    }
    Signature::from_slice(input).map_err(|_| DeviceAuthorityError::InvalidInput)
}

fn valid_challenge_id(value: &str) -> bool {
    let Some(raw) = value.strip_prefix("challenge-") else {
        return false;
    };
    raw.len() == CHALLENGE_ID_BYTES * 2
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn public_key_digest(public_key: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical(&[PUBLIC_KEY_DIGEST_VERSION, public_key])).into()
}

fn device_alias(signing_commitment: &[u8; 32], agreement_commitment: &[u8; 32]) -> String {
    let digest = Sha256::digest(canonical(&[
        DEVICE_ALIAS_VERSION,
        b"device",
        signing_commitment,
        agreement_commitment,
    ]));
    format!("device-{}", &hex_lower(&digest)[..32])
}

fn valid_alias(domain: &str, value: &str) -> bool {
    let prefix = format!("{domain}-");
    let digest_len = if domain == "device" { 32 } else { 64 };
    value.len() == prefix.len() + digest_len
        && value.starts_with(&prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn pairing_transcript(input: PairingTranscript<'_>) -> Vec<u8> {
    canonical(&[
        PAIRING_TRANSCRIPT_VERSION,
        input.challenge_bytes,
        input.signing_key_digest,
        input.agreement_key_digest,
        input.principal_alias.as_bytes(),
        input.device_alias.as_bytes(),
        &input.prospective_epoch.to_be_bytes(),
        &input.issued_at_unix.to_be_bytes(),
        &input.expires_at_unix.to_be_bytes(),
    ])
}

fn challenge_digest(challenge_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest([CHALLENGE_DIGEST_VERSION, challenge_bytes].concat()).into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn current_epoch(connection: &Connection) -> Result<u64, DeviceAuthorityError> {
    let epoch = connection
        .query_row(
            "SELECT current_epoch FROM registry_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| DeviceAuthorityError::Storage)?;
    u64::try_from(epoch).map_err(|_| DeviceAuthorityError::Storage)
}

fn set_current_epoch(connection: &Connection, epoch: u64) -> Result<(), DeviceAuthorityError> {
    connection
        .execute(
            "UPDATE registry_meta SET current_epoch = ?1 WHERE singleton = 1",
            params![i64::try_from(epoch).map_err(|_| DeviceAuthorityError::Storage)?],
        )
        .map_err(|_| DeviceAuthorityError::Storage)?;
    Ok(())
}

fn next_epoch(current: u64) -> Result<u64, DeviceAuthorityError> {
    if current >= i64::MAX as u64 {
        return Err(DeviceAuthorityError::EpochMismatch);
    }
    current
        .checked_add(1)
        .ok_or(DeviceAuthorityError::EpochMismatch)
}

fn effective_now(connection: &Connection, supplied: i64) -> Result<i64, DeviceAuthorityError> {
    let floor = connection
        .query_row(
            "SELECT time_floor_unix FROM registry_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| DeviceAuthorityError::Storage)?;
    let effective = supplied.max(floor);
    connection
        .execute(
            "UPDATE registry_meta SET time_floor_unix = ?1 WHERE singleton = 1",
            params![effective],
        )
        .map_err(|_| DeviceAuthorityError::Storage)?;
    Ok(effective)
}

fn load_challenge(
    connection: &Connection,
    challenge_id: &str,
) -> Result<Option<LoadedChallenge>, DeviceAuthorityError> {
    connection
        .query_row(
            "SELECT
                challenge_digest,
                signing_public_key,
                agreement_public_key,
                signing_key_digest,
                agreement_key_digest,
                principal_alias,
                device_alias,
                prospective_epoch,
                issued_at_unix,
                expires_at_unix,
                consumed_at_unix,
                invalidated_at_unix
             FROM pairing_challenge
             WHERE challenge_id = ?1",
            params![challenge_id],
            |row| {
                let signing_public_key = row
                    .get::<_, Option<Vec<u8>>>(1)?
                    .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                    .transpose()?;
                let agreement_public_key = row
                    .get::<_, Option<Vec<u8>>>(2)?
                    .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                    .transpose()?;
                let prospective_epoch = row.get::<_, i64>(7)?;
                Ok(LoadedChallenge {
                    challenge_digest: row.get(0)?,
                    signing_public_key,
                    agreement_public_key,
                    signing_key_digest: row.get(3)?,
                    agreement_key_digest: row.get(4)?,
                    principal_alias: row.get(5)?,
                    device_alias: row.get(6)?,
                    prospective_epoch: u64::try_from(prospective_epoch)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    issued_at_unix: row.get(8)?,
                    expires_at_unix: row.get(9)?,
                    consumed_at_unix: row.get(10)?,
                    invalidated_at_unix: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|_| DeviceAuthorityError::Storage)
}

fn load_active_device(
    connection: &Connection,
) -> Result<Option<LoadedDevice>, DeviceAuthorityError> {
    connection
        .query_row(
            "SELECT row_id, principal_alias, device_alias, activated_epoch,
                    signing_key_digest, agreement_key_digest, state, revoked_epoch
             FROM device_registry
             WHERE state = 'active'
             LIMIT 1",
            [],
            loaded_device_from_row,
        )
        .optional()
        .map_err(|_| DeviceAuthorityError::Storage)
}

fn load_latest_device_for_alias(
    connection: &Connection,
    device_alias: &str,
) -> Result<Option<LoadedDevice>, DeviceAuthorityError> {
    connection
        .query_row(
            "SELECT row_id, principal_alias, device_alias, activated_epoch,
                    signing_key_digest, agreement_key_digest, state, revoked_epoch
             FROM device_registry
             WHERE device_alias = ?1
             ORDER BY activated_epoch DESC
             LIMIT 1",
            params![device_alias],
            loaded_device_from_row,
        )
        .optional()
        .map_err(|_| DeviceAuthorityError::Storage)
}

fn loaded_device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LoadedDevice> {
    let pairing_epoch = row.get::<_, i64>(3)?;
    let signing_commitment: [u8; 32] = row
        .get::<_, Vec<u8>>(4)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let agreement_commitment: [u8; 32] = row
        .get::<_, Vec<u8>>(5)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let revoked_epoch = row.get::<_, Option<i64>>(7)?;
    let state = match row.get::<_, String>(6)?.as_str() {
        "active" => DeviceState::Active,
        "revoked" => DeviceState::Revoked,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(LoadedDevice {
        row_id: row.get(0)?,
        principal_alias: row.get(1)?,
        device_alias: row.get(2)?,
        pairing_epoch: u64::try_from(pairing_epoch).map_err(|_| rusqlite::Error::InvalidQuery)?,
        signing_commitment,
        agreement_commitment,
        state,
        revoked_epoch: revoked_epoch
            .map(|epoch| u64::try_from(epoch).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
    })
}

fn current_euid() -> u32 {
    // SAFETY: `geteuid` is a side-effect-free libc query.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{signature::Signer, SigningKey},
        elliptic_curve::sec1::ToEncodedPoint,
        SecretKey,
    };
    use std::fs::Permissions;
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::TempDir;

    fn setup_registry() -> (TempDir, PathBuf, DeviceAuthority) {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("state");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
        let parent = fs::canonicalize(parent).unwrap();
        let db_path = parent.join(REGISTRY_BASENAME);
        let authority = DeviceAuthority::open(&db_path).unwrap();
        (root, db_path, authority)
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn agreement_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn agreement_public_bytes(key: &SecretKey) -> [u8; PUBLIC_KEY_BYTES] {
        key.public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn signing_public_bytes(key: &SigningKey) -> [u8; PUBLIC_KEY_BYTES] {
        VerifyingKey::from(key)
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn confirm_signature(
        signing_key: &SigningKey,
        agreement_key: &SecretKey,
        challenge: &PairingChallenge,
    ) -> Signature {
        let signing_public_key = signing_public_bytes(signing_key);
        let agreement_public_key = agreement_public_bytes(agreement_key);
        let signing_commitment = public_key_digest(&signing_public_key);
        let agreement_commitment = public_key_digest(&agreement_public_key);
        let device_alias = device_alias(&signing_commitment, &agreement_commitment);
        let transcript = pairing_transcript(PairingTranscript {
            challenge_bytes: challenge.challenge_bytes(),
            signing_key_digest: &signing_commitment,
            agreement_key_digest: &agreement_commitment,
            principal_alias: test_principal(),
            device_alias: &device_alias,
            prospective_epoch: challenge.prospective_epoch(),
            issued_at_unix: challenge.issued_at_unix(),
            expires_at_unix: challenge.expires_at_unix(),
        });
        signing_key.sign(&transcript)
    }

    fn test_principal() -> &'static str {
        "principal-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    fn begin(
        authority: &DeviceAuthority,
        signing_key: &SigningKey,
        agreement_key: &SecretKey,
        now: OffsetDateTime,
    ) -> PairingChallenge {
        authority
            .begin_pairing(
                test_principal(),
                &signing_public_bytes(signing_key),
                &agreement_public_bytes(agreement_key),
                now,
            )
            .unwrap()
    }

    fn confirm(
        authority: &DeviceAuthority,
        signing_key: &SigningKey,
        agreement_key: &SecretKey,
        challenge: &PairingChallenge,
        now: OffsetDateTime,
    ) -> Result<AuthenticatedDeviceFact, DeviceAuthorityError> {
        authority.confirm_pairing(
            challenge.challenge_id(),
            challenge.challenge_bytes(),
            confirm_signature(signing_key, agreement_key, challenge)
                .to_bytes()
                .as_slice(),
            now,
        )
    }

    fn read_table_count(path: &Path, sql: &str) -> i64 {
        let connection = Connection::open(path).unwrap();
        connection.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    #[test]
    fn challenge_expires_is_single_use_and_cannot_be_consumed_by_second_key() {
        let (_root, _db_path, authority) = setup_registry();
        let first_signing = signing_key(7);
        let first_agreement = agreement_key(8);
        let second_signing = signing_key(9);
        let second_agreement = agreement_key(10);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(10);
        let challenge = authority
            .begin_pairing(
                test_principal(),
                &signing_public_bytes(&first_signing),
                &agreement_public_bytes(&first_agreement),
                now,
            )
            .unwrap();

        let wrong_signature = confirm_signature(&second_signing, &second_agreement, &challenge);
        assert_eq!(
            authority.confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                wrong_signature.to_bytes().as_slice(),
                now,
            ),
            Err(DeviceAuthorityError::InvalidProof)
        );
        assert_eq!(
            authority.current_active().unwrap(),
            CurrentActiveDevice::Unpaired
        );

        assert_eq!(
            authority.confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                confirm_signature(&first_signing, &first_agreement, &challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(CHALLENGE_TTL_SECONDS + 1),
            ),
            Err(DeviceAuthorityError::ChallengeExpired)
        );
        assert_eq!(authority.latest_epoch_for_test().unwrap(), 0);

        let fresh = begin(&authority, &first_signing, &first_agreement, now);
        let active = authority
            .confirm_pairing(
                fresh.challenge_id(),
                fresh.challenge_bytes(),
                confirm_signature(&first_signing, &first_agreement, &fresh)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(30),
            )
            .unwrap();
        assert_eq!(active.pairing_epoch, 1);
        assert_eq!(
            authority.confirm_pairing(
                fresh.challenge_id(),
                fresh.challenge_bytes(),
                confirm_signature(&first_signing, &first_agreement, &fresh)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(31),
            ),
            Err(DeviceAuthorityError::ChallengeConsumed)
        );
    }

    #[test]
    fn concurrent_confirmation_has_one_winner() {
        let (_root, _db_path, authority) = setup_registry();
        let authority = Arc::new(authority);
        let signing_key = signing_key(11);
        let agreement_key = agreement_key(12);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        let signature = confirm_signature(&signing_key, &agreement_key, &challenge).to_bytes();
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            let challenge_id = challenge.challenge_id().to_owned();
            let challenge_bytes = challenge.challenge_bytes().to_vec();
            handles.push(thread::spawn(move || {
                barrier.wait();
                authority.confirm_pairing(
                    &challenge_id,
                    &challenge_bytes,
                    signature.as_slice(),
                    now,
                )
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let winners = outcomes.iter().filter(|result| result.is_ok()).count();
        assert_eq!(winners, 1);
        assert!(outcomes.contains(&Err(DeviceAuthorityError::ChallengeConsumed)));
        assert_eq!(authority.latest_epoch_for_test().unwrap(), 1);
    }

    #[test]
    fn replacement_and_revocation_strictly_advance_epoch() {
        let (_root, _db_path, authority) = setup_registry();
        let first_signing = signing_key(21);
        let first_agreement = agreement_key(22);
        let second_signing = signing_key(23);
        let second_agreement = agreement_key(24);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
        let first_challenge = begin(&authority, &first_signing, &first_agreement, now);
        let first_active = authority
            .confirm_pairing(
                first_challenge.challenge_id(),
                first_challenge.challenge_bytes(),
                confirm_signature(&first_signing, &first_agreement, &first_challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(1),
            )
            .unwrap();
        assert_eq!(first_active.pairing_epoch, 1);

        let second_challenge = begin(
            &authority,
            &second_signing,
            &second_agreement,
            now + time::Duration::seconds(2),
        );
        let second_active = authority
            .confirm_pairing(
                second_challenge.challenge_id(),
                second_challenge.challenge_bytes(),
                confirm_signature(&second_signing, &second_agreement, &second_challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(3),
            )
            .unwrap();
        assert_eq!(second_active.pairing_epoch, 2);
        assert_eq!(
            authority.current_active().unwrap(),
            CurrentActiveDevice::Active(second_active.clone())
        );

        assert_eq!(
            authority
                .revoke(
                    &second_active.device_alias,
                    second_active.pairing_epoch,
                    now + time::Duration::seconds(4),
                )
                .unwrap(),
            RevokeOutcome::Revoked {
                prior_epoch: 2,
                revoked_epoch: 3,
            }
        );
        assert_eq!(
            authority.current_active().unwrap(),
            CurrentActiveDevice::Unpaired
        );
        assert_eq!(authority.latest_epoch_for_test().unwrap(), 3);
    }

    #[test]
    fn restart_preserves_state_tombstones_consumed_challenges_and_epoch() {
        let (_root, db_path, authority) = setup_registry();
        let signing_key = signing_key(31);
        let agreement_key = agreement_key(32);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(3);
        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        let active = authority
            .confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                confirm_signature(&signing_key, &agreement_key, &challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(1),
            )
            .unwrap();
        drop(authority);

        let reopened = DeviceAuthority::open(&db_path).unwrap();
        assert_eq!(
            reopened.current_active().unwrap(),
            CurrentActiveDevice::Active(active.clone())
        );
        assert_eq!(
            reopened.confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                confirm_signature(&signing_key, &agreement_key, &challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(2),
            ),
            Err(DeviceAuthorityError::ChallengeConsumed)
        );
        assert_eq!(
            reopened
                .revoke(
                    &active.device_alias,
                    active.pairing_epoch,
                    now + time::Duration::seconds(3)
                )
                .unwrap(),
            RevokeOutcome::Revoked {
                prior_epoch: 1,
                revoked_epoch: 2,
            }
        );
        drop(reopened);

        let reopened = DeviceAuthority::open(&db_path).unwrap();
        assert_eq!(
            reopened.current_active().unwrap(),
            CurrentActiveDevice::Unpaired
        );
        assert_eq!(reopened.latest_epoch_for_test().unwrap(), 2);
        assert_eq!(
            read_table_count(
                &db_path,
                "SELECT COUNT(*) FROM device_registry WHERE state = 'revoked' AND revoked_epoch = 2",
            ),
            1
        );
    }

    #[test]
    fn expired_challenge_stays_expired_after_clock_rollback_and_restart() {
        let (_root, db_path, authority) = setup_registry();
        let signing_key = signing_key(35);
        let agreement_key = agreement_key(36);
        let issued = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(30);
        let challenge = begin(&authority, &signing_key, &agreement_key, issued);
        assert_eq!(
            confirm(
                &authority,
                &signing_key,
                &agreement_key,
                &challenge,
                issued + time::Duration::seconds(CHALLENGE_TTL_SECONDS + 1),
            ),
            Err(DeviceAuthorityError::ChallengeExpired)
        );
        drop(authority);

        let reopened = DeviceAuthority::open(&db_path).unwrap();
        assert_eq!(
            confirm(
                &reopened,
                &signing_key,
                &agreement_key,
                &challenge,
                issued - time::Duration::hours(1),
            ),
            Err(DeviceAuthorityError::ChallengeConsumed)
        );
        assert_eq!(reopened.latest_epoch_for_test().unwrap(), 0);
        let floor = reopened
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT time_floor_unix FROM registry_meta WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| DeviceAuthorityError::Storage)
            })
            .unwrap();
        assert_eq!(
            floor,
            (issued + time::Duration::seconds(CHALLENGE_TTL_SECONDS + 1)).unix_timestamp()
        );
    }

    #[test]
    fn active_registry_retains_only_key_digest_and_terminal_challenge_clears_key() {
        let (_root, db_path, authority) = setup_registry();
        let signing_key = signing_key(37);
        let agreement_key = agreement_key(38);
        let raw_signing_key = signing_public_bytes(&signing_key);
        let raw_agreement_key = agreement_public_bytes(&agreement_key);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(31);
        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        confirm(&authority, &signing_key, &agreement_key, &challenge, now).unwrap();
        drop(authority);

        let connection = Connection::open(&db_path).unwrap();
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(device_registry)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!columns
            .iter()
            .any(|column| column == "signing_public_key" || column == "agreement_public_key"));
        let pending_key_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pairing_challenge
                 WHERE signing_public_key IS NOT NULL OR agreement_public_key IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending_key_count, 0);
        drop(connection);

        let bytes = fs::read(&db_path).unwrap();
        assert!(!bytes
            .windows(raw_signing_key.len())
            .any(|window| window == raw_signing_key));
        assert!(!bytes
            .windows(raw_agreement_key.len())
            .any(|window| window == raw_agreement_key));
    }

    #[test]
    fn wrong_challenge_bytes_and_epoch_overflow_fail_without_mutation() {
        let (_root, db_path, authority) = setup_registry();
        let signing_key = signing_key(39);
        let agreement_key = agreement_key(40);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(32);
        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        let mut wrong = challenge.challenge_bytes().to_vec();
        wrong[0] ^= 1;
        assert_eq!(
            authority.confirm_pairing(
                challenge.challenge_id(),
                &wrong,
                confirm_signature(&signing_key, &agreement_key, &challenge)
                    .to_bytes()
                    .as_slice(),
                now,
            ),
            Err(DeviceAuthorityError::InvalidInput)
        );
        assert_eq!(authority.latest_epoch_for_test().unwrap(), 0);
        drop(authority);

        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "UPDATE registry_meta SET current_epoch = ?1 WHERE singleton = 1",
                params![i64::MAX],
            )
            .unwrap();
        drop(connection);
        let reopened = DeviceAuthority::open(&db_path).unwrap();
        assert!(matches!(
            reopened.begin_pairing(
                test_principal(),
                &signing_public_bytes(&signing_key),
                &agreement_public_bytes(&agreement_key),
                now
            ),
            Err(DeviceAuthorityError::EpochMismatch)
        ));
        assert_eq!(reopened.latest_epoch_for_test().unwrap(), i64::MAX as u64);
    }

    #[test]
    fn revoke_followed_by_stale_facts_has_no_current_active_session() {
        let (_root, _db_path, authority) = setup_registry();
        let current_signing_key = signing_key(41);
        let current_agreement_key = agreement_key(42);
        let replacement_signing_key = signing_key(43);
        let replacement_agreement_key = agreement_key(44);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(4);
        let challenge = begin(
            &authority,
            &current_signing_key,
            &current_agreement_key,
            now,
        );
        let active = authority
            .confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                confirm_signature(&current_signing_key, &current_agreement_key, &challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(1),
            )
            .unwrap();
        authority
            .revoke(
                &active.device_alias,
                active.pairing_epoch,
                now + time::Duration::seconds(2),
            )
            .unwrap();
        assert_eq!(
            authority.current_active().unwrap(),
            CurrentActiveDevice::Unpaired
        );
        assert_eq!(
            authority.revoke(
                &active.device_alias,
                active.pairing_epoch,
                now + time::Duration::seconds(3)
            ),
            Ok(RevokeOutcome::AlreadyRevoked { revoked_epoch: 2 })
        );
        let replacement_challenge = begin(
            &authority,
            &replacement_signing_key,
            &replacement_agreement_key,
            now + time::Duration::seconds(4),
        );
        let replacement_active = authority
            .confirm_pairing(
                replacement_challenge.challenge_id(),
                replacement_challenge.challenge_bytes(),
                confirm_signature(
                    &replacement_signing_key,
                    &replacement_agreement_key,
                    &replacement_challenge,
                )
                .to_bytes()
                .as_slice(),
                now + time::Duration::seconds(5),
            )
            .unwrap();
        assert_eq!(replacement_active.pairing_epoch, 3);
        assert!(matches!(
            authority.revoke(
                &active.device_alias,
                replacement_active.pairing_epoch,
                now + time::Duration::seconds(6)
            ),
            Err(DeviceAuthorityError::EpochMismatch | DeviceAuthorityError::Unpaired)
        ));
    }

    #[test]
    fn unsafe_parent_main_wal_and_shm_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("state");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o755)).unwrap();
        let bad_parent_db = parent.join(REGISTRY_BASENAME);
        assert!(matches!(
            DeviceAuthority::open(&bad_parent_db),
            Err(DeviceAuthorityError::Safety)
        ));

        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
        let parent = fs::canonicalize(parent).unwrap();
        let db_path = parent.join(REGISTRY_BASENAME);
        let real = parent.join("real.sqlite3");
        fs::write(&real, []).unwrap();
        fs::set_permissions(&real, Permissions::from_mode(0o600)).unwrap();
        symlink(&real, &db_path).unwrap();
        assert!(matches!(
            DeviceAuthority::open(&db_path),
            Err(DeviceAuthorityError::Safety)
        ));
        fs::remove_file(&db_path).unwrap();

        let authority = DeviceAuthority::open(&db_path).unwrap();
        let wal_path = sidecar_path(&db_path, b"-wal");
        let shm_path = sidecar_path(&db_path, b"-shm");
        let hardlink_source = parent.join("hardlink-source");
        fs::write(&hardlink_source, []).unwrap();
        fs::set_permissions(&hardlink_source, Permissions::from_mode(0o600)).unwrap();
        if wal_path.exists() {
            fs::remove_file(&wal_path).unwrap();
        }
        fs::hard_link(&hardlink_source, &wal_path).unwrap();
        assert_eq!(
            authority.current_active(),
            Err(DeviceAuthorityError::Safety)
        );

        fs::remove_file(&wal_path).unwrap();
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&wal_path)
            .unwrap();
        if !shm_path.exists() {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&shm_path)
                .unwrap();
        }
        fs::set_permissions(&shm_path, Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            authority.current_active(),
            Err(DeviceAuthorityError::Safety)
        );
    }

    #[test]
    fn metadata_validators_fail_for_wrong_owner_and_links() {
        assert_eq!(
            validate_parent_facts(
                ParentFacts {
                    is_dir: true,
                    is_symlink: false,
                    uid: current_euid() + 1,
                    mode: 0o700,
                },
                current_euid(),
            ),
            Err(DeviceAuthorityError::Safety)
        );
        assert_eq!(
            validate_file_facts(
                FileFacts {
                    is_file: true,
                    is_symlink: false,
                    uid: current_euid() + 1,
                    mode: 0o600,
                    nlink: 1,
                },
                current_euid(),
            ),
            Err(DeviceAuthorityError::Safety)
        );
        assert_eq!(
            validate_file_facts(
                FileFacts {
                    is_file: true,
                    is_symlink: false,
                    uid: current_euid(),
                    mode: 0o600,
                    nlink: 2,
                },
                current_euid(),
            ),
            Err(DeviceAuthorityError::Safety)
        );
    }

    #[test]
    fn database_content_scan_contains_no_seeded_canaries() {
        let (_root, db_path, authority) = setup_registry();
        let signing_key = signing_key(51);
        let agreement_key = agreement_key(52);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(5);
        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        let active = authority
            .confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                confirm_signature(&signing_key, &agreement_key, &challenge)
                    .to_bytes()
                    .as_slice(),
                now + time::Duration::seconds(1),
            )
            .unwrap();
        authority
            .revoke(
                &active.device_alias,
                active.pairing_epoch,
                now + time::Duration::seconds(2),
            )
            .unwrap();

        let canaries = [
            "seeded-agent-id-canary",
            "seeded-provider-canary",
            "seeded-reply-canary",
        ];
        for path in [
            &db_path,
            &sidecar_path(&db_path, b"-wal"),
            &sidecar_path(&db_path, b"-shm"),
        ] {
            let Ok(bytes) = fs::read(path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            for canary in canaries {
                assert!(!text.contains(canary));
            }
        }
    }

    #[test]
    fn debug_and_errors_do_not_print_challenge_signature_public_key_or_path() {
        let (_root, db_path, authority) = setup_registry();
        let signing_key = signing_key(61);
        let agreement_key = agreement_key(62);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(6);
        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        let signature = confirm_signature(&signing_key, &agreement_key, &challenge).to_bytes();

        let authority_debug = format!("{authority:?}");
        assert!(!authority_debug.contains(db_path.to_string_lossy().as_ref()));

        let challenge_debug = format!("{challenge:?}");
        assert!(!challenge_debug.contains(challenge.challenge_id()));
        assert!(!challenge_debug.contains(&hex_lower(challenge.challenge_bytes())));

        let error = authority
            .confirm_pairing(
                "not-a-valid-challenge",
                challenge.challenge_bytes(),
                signature.as_slice(),
                now,
            )
            .unwrap_err();
        let error_text = format!("{error:?} {error}");
        assert!(!error_text.contains(challenge.challenge_id()));
        assert!(!error_text.contains(&hex_lower(&signing_public_bytes(&signing_key))));
        assert!(!error_text.contains(&hex_lower(&agreement_public_bytes(&agreement_key))));
        assert!(!error_text.contains(&hex_lower(signature.as_slice())));
        assert!(!error_text.contains(db_path.to_string_lossy().as_ref()));
    }

    #[test]
    fn malformed_duplicate_trailing_and_oversized_inputs_fail_before_mutation() {
        let (_root, _db_path, authority) = setup_registry();
        let signing_key = signing_key(71);
        let agreement_key = agreement_key(72);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(7);
        assert!(matches!(
            authority.begin_pairing(
                test_principal(),
                &[7_u8; PUBLIC_KEY_BYTES - 1],
                &[8_u8; PUBLIC_KEY_BYTES],
                now
            ),
            Err(DeviceAuthorityError::InvalidInput)
        ));
        assert!(matches!(
            authority.begin_pairing(
                test_principal(),
                &[7_u8; PUBLIC_KEY_BYTES],
                &[8_u8; PUBLIC_KEY_BYTES - 1],
                now
            ),
            Err(DeviceAuthorityError::InvalidInput)
        ));
        assert_eq!(authority.latest_epoch_for_test().unwrap(), 0);

        let challenge = begin(&authority, &signing_key, &agreement_key, now);
        let valid_signature =
            confirm_signature(&signing_key, &agreement_key, &challenge).to_bytes();

        for (challenge_id, signature, expected) in [
            (
                "ABCDEF",
                valid_signature[..].to_vec(),
                DeviceAuthorityError::InvalidInput,
            ),
            (
                challenge.challenge_id(),
                valid_signature[..SIGNATURE_BYTES - 1].to_vec(),
                DeviceAuthorityError::InvalidInput,
            ),
            (
                challenge.challenge_id(),
                {
                    let mut oversized = valid_signature.to_vec();
                    oversized.push(0);
                    oversized
                },
                DeviceAuthorityError::InvalidInput,
            ),
        ] {
            assert_eq!(
                authority.confirm_pairing(
                    challenge_id,
                    challenge.challenge_bytes(),
                    signature.as_slice(),
                    now,
                ),
                Err(expected)
            );
            assert_eq!(
                authority.current_active().unwrap(),
                CurrentActiveDevice::Unpaired
            );
            assert_eq!(authority.latest_epoch_for_test().unwrap(), 0);
        }

        let active = authority
            .confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                valid_signature.as_slice(),
                now,
            )
            .unwrap();
        assert_eq!(active.pairing_epoch, 1);
        assert_eq!(
            authority.confirm_pairing(
                challenge.challenge_id(),
                challenge.challenge_bytes(),
                valid_signature.as_slice(),
                now,
            ),
            Err(DeviceAuthorityError::ChallengeConsumed)
        );
        assert_eq!(authority.latest_epoch_for_test().unwrap(), 1);
    }

    #[test]
    fn pairing_rejects_duplicate_or_invalid_p256_public_keys() {
        let (_root, _db_path, authority) = setup_registry();
        let signing_key = signing_key(81);
        let agreement_key = agreement_key(82);
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(8);
        let signing_public = signing_public_bytes(&signing_key);
        let agreement_public = agreement_public_bytes(&agreement_key);
        assert!(
            begin(&authority, &signing_key, &agreement_key, now)
                .challenge_bytes()
                .len()
                == CHALLENGE_BYTES
        );
        assert!(matches!(
            authority.begin_pairing(test_principal(), &signing_public, &signing_public, now),
            Err(DeviceAuthorityError::InvalidInput)
        ));
        let mut invalid_public = agreement_public;
        invalid_public[0] = 0x05;
        assert!(matches!(
            authority.begin_pairing(test_principal(), &signing_public, &invalid_public, now),
            Err(DeviceAuthorityError::InvalidInput)
        ));
    }
}
