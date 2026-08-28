use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use getrandom::getrandom;
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::device_authority::{
    AuthenticatedDeviceFact, CurrentActiveDevice, DeviceAuthority, DeviceAuthorityError,
    RevokeOutcome,
};
use crate::run_binding::{canonical, constant_time_eq, hmac_sha256};

const JOIN_TTL_SECONDS: i64 = 120;
const JOIN_RANDOM_BYTES: usize = 32;
const COOKIE_RANDOM_BYTES: usize = 32;
const BEARER_RANDOM_BYTES: usize = 32;
const MAILBOX_RANDOM_BYTES: usize = 32;
const WRAP_NONCE_BYTES: usize = 12;
const PAIRING_PREFIX: &[u8] = b"nomad.m3e.pairing.v1\n";
const SIGNING_PROOF_PREFIX: &[u8] = b"nomad.m3e.signing-proof.v1\n";
const AGREEMENT_PROOF_INFO: &[u8] = b"nomad.m3e.agreement-proof.v1";
const COMPARISON_PREFIX: &[u8] = b"nomad.m3e.compare.v1\n";
const HOST_IDENTITY_PREFIX: &[u8] = b"nomad.m3e.host-identity-commitment.v1\n";
const DEVICE_KEY_PREFIX: &[u8] = b"nomad.m3e.device-key-commitment.v1\n";
const VAULT_KEY_PREFIX: &[u8] = b"nomad.m3e.browser-vault.v1\n";
const VAULT_COMMIT_PREFIX: &[u8] = b"nomad.m3e.vault-commit.v1\n";
pub(crate) const INTERNAL_START_SCHEMA: &str = "nomad.m3e.internal.pairing-start.v1";
pub(crate) const INTERNAL_CONFIRM_SCHEMA: &str = "nomad.m3e.internal.pairing-confirm.v1";
pub(crate) const INTERNAL_COMPLETE_SCHEMA: &str = "nomad.m3e.internal.pairing-complete.v1";
pub(crate) const INTERNAL_ABORT_SCHEMA: &str = "nomad.m3e.internal.pairing-abort.v1";
const DURABLE_STORE_VERSION: &str = "nomad.m3e.pairing-store.v1";
const AT_REST_KEY_INFO: &[u8] = b"nomad.m3e.host-bearer-at-rest.v1\n";
const AT_REST_AAD_PREFIX: &[u8] = b"nomad.m3e.host-bearer-record.v1\n";
const AUTHORITY_PUBLIC_KEY_DIGEST_VERSION: &[u8] = b"nomad.device-authority.public-key-digest.v2";
const AUTHORITY_DEVICE_ALIAS_VERSION: &[u8] = b"nomad.device-authority.device-alias.v2";
const STORE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS pairing_coordinator_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version TEXT NOT NULL,
    payload BLOB NOT NULL
);
"#;
const REMOTE_PRINCIPAL: &str =
    "principal-c013cb434103a3b3206ccfa30788602d3865b70019ddbec32e461207eb430554";

/// The single Product Host lock shared by pairing, revoke, and remote command admission.
#[derive(Default)]
pub(crate) struct DeviceCommandGate(Mutex<()>);

pub(crate) struct DeviceCommandGuard<'a> {
    owner: &'a DeviceCommandGate,
    _guard: MutexGuard<'a, ()>,
}

impl DeviceCommandGate {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn lock(&self) -> Result<DeviceCommandGuard<'_>, PairingCoordinatorError> {
        let guard = self
            .0
            .lock()
            .map_err(|_| PairingCoordinatorError::Storage)?;
        Ok(DeviceCommandGuard {
            owner: self,
            _guard: guard,
        })
    }
}

impl fmt::Debug for DeviceCommandGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DeviceCommandGate").finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JoinState {
    Created,
    StartedAwaitingDesktopApproval,
    DesktopApproved,
    Prepared,
    AuthorityActive,
    ProvisionedPendingVault,
    Active,
    Cancelled,
    Expired,
    Compensated,
    ExpiredCompensated,
    Revoked,
}

#[derive(Clone)]
pub(crate) struct JoinSession {
    join_id: String,
    join_secret_digest: Option<[u8; 32]>,
    cookie_digest: Option<[u8; 32]>,
    created_at_unix: i64,
    expires_at_unix: i64,
    state: JoinState,
    challenge_id: Option<String>,
    challenge_bytes: Option<Zeroizing<Vec<u8>>>,
    prospective_epoch: Option<u64>,
    device_signing_public_sec1: Option<[u8; 65]>,
    device_agreement_public_sec1: Option<[u8; 65]>,
    comparison_code: Option<String>,
    completed_vault_proof_digest: Option<[u8; 32]>,
    replacement_prior_join_id: Option<String>,
    pending: Option<PendingBinding>,
    authority_cleanup_needed: bool,
    relay_cleanup_needed: bool,
    terminal_device_alias: Option<String>,
    revoked_epoch: Option<u64>,
}

impl JoinSession {
    fn clear_capabilities(&mut self) {
        self.cookie_digest = None;
        self.challenge_bytes = None;
        self.device_signing_public_sec1 = None;
        self.device_agreement_public_sec1 = None;
    }
}

#[derive(Clone)]
struct PendingBinding {
    device: AuthenticatedDeviceFact,
    device_signing_public_sec1: [u8; 65],
    device_agreement_public_sec1: [u8; 65],
    mailbox_id: String,
    host_bearer: Zeroizing<String>,
    signed_bundle: Option<SignedProvisioningBundle>,
}

pub(crate) trait JoinSessionStore: Send + Sync + 'static {
    fn load_all(&self) -> Result<HashMap<String, JoinSession>, PairingCoordinatorError>;
    fn replace_all(
        &self,
        sessions: &HashMap<String, JoinSession>,
    ) -> Result<(), PairingCoordinatorError>;
}

/// Focused E1 storage used only by unit tests.
#[derive(Default)]
pub(crate) struct MemoryJoinSessionStore {
    sessions: Mutex<HashMap<String, JoinSession>>,
}

impl JoinSessionStore for MemoryJoinSessionStore {
    fn load_all(&self) -> Result<HashMap<String, JoinSession>, PairingCoordinatorError> {
        self.sessions
            .lock()
            .map(|sessions| sessions.clone())
            .map_err(|_| PairingCoordinatorError::Storage)
    }

    fn replace_all(
        &self,
        sessions: &HashMap<String, JoinSession>,
    ) -> Result<(), PairingCoordinatorError> {
        *self
            .sessions
            .lock()
            .map_err(|_| PairingCoordinatorError::Storage)? = sessions.clone();
        Ok(())
    }
}

pub(crate) struct SqliteJoinSessionStore {
    db_path: PathBuf,
    parent_identity: (u64, u64),
    db_identity: (u64, u64),
    lock_identity: (u64, u64),
    at_rest_key: Zeroizing<[u8; 32]>,
}

impl SqliteJoinSessionStore {
    pub(crate) fn open(
        db_path: &Path,
        identity: &dyn HostPairingIdentity,
    ) -> Result<Self, PairingCoordinatorError> {
        let db_path = prepare_store_path(db_path)?;
        let parent_identity =
            directory_identity(db_path.parent().ok_or(PairingCoordinatorError::Storage)?)?;
        let db_identity = private_file_identity(&db_path)?;
        let lock_identity = private_file_identity(&sidecar_path(&db_path, b".lock"))?;
        let shared = identity.derive_agreement_shared(&identity.agreement_public_sec1())?;
        let mut at_rest_key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(None, shared.as_ref())
            .expand(AT_REST_KEY_INFO, at_rest_key.as_mut())
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        let store = Self {
            db_path,
            parent_identity,
            db_identity,
            lock_identity,
            at_rest_key,
        };
        store.with_connection(|connection| {
            connection
                .execute_batch(STORE_SCHEMA)
                .map_err(|_| PairingCoordinatorError::Storage)
        })?;
        store.load_all()?;
        Ok(store)
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, PairingCoordinatorError>,
    ) -> Result<T, PairingCoordinatorError> {
        validate_store_path(&self.db_path)?;
        let parent = self
            .db_path
            .parent()
            .ok_or(PairingCoordinatorError::Storage)?;
        if directory_identity(parent)? != self.parent_identity
            || private_file_identity(&self.db_path)? != self.db_identity
        {
            return Err(PairingCoordinatorError::Storage);
        }
        let wal_path = sidecar_path(&self.db_path, b"-wal");
        let shm_path = sidecar_path(&self.db_path, b"-shm");
        let lock_path = sidecar_path(&self.db_path, b".lock");
        validate_optional_private_file(&wal_path)?;
        validate_optional_private_file(&shm_path)?;
        // This lock and the before/after inode checks protect against accidental and
        // same-user concurrent replacement. The 0700 parent is the OS trust boundary.
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| PairingCoordinatorError::Storage)?;
        validate_private_file_metadata(
            &lock_file
                .metadata()
                .map_err(|_| PairingCoordinatorError::Storage)?,
        )?;
        let opened_lock_identity = {
            let metadata = lock_file
                .metadata()
                .map_err(|_| PairingCoordinatorError::Storage)?;
            (metadata.dev(), metadata.ino())
        };
        if opened_lock_identity != self.lock_identity
            || private_file_identity(&lock_path)? != self.lock_identity
        {
            return Err(PairingCoordinatorError::Storage);
        }
        // SAFETY: lock_file owns a valid descriptor for the validated DB file.
        if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(PairingCoordinatorError::Storage);
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(&self.db_path, flags)
            .map_err(|_| PairingCoordinatorError::Storage)?;
        connection
            .pragma_update(None, "secure_delete", "ON")
            .map_err(|_| PairingCoordinatorError::Storage)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| PairingCoordinatorError::Storage)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| PairingCoordinatorError::Storage)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| PairingCoordinatorError::Storage)?;
        let result = operation(&mut connection);
        secure_optional_sidecar(&wal_path)?;
        secure_optional_sidecar(&shm_path)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| PairingCoordinatorError::Storage)?;
        connection
            .close()
            .map_err(|_| PairingCoordinatorError::Storage)?;
        if private_file_identity(&self.db_path)? != self.db_identity {
            return Err(PairingCoordinatorError::Storage);
        }
        if directory_identity(parent)? != self.parent_identity {
            return Err(PairingCoordinatorError::Storage);
        }
        if private_file_identity(&lock_path)? != self.lock_identity {
            return Err(PairingCoordinatorError::Storage);
        }
        validate_optional_private_file(&wal_path)?;
        validate_optional_private_file(&shm_path)?;
        result
    }

    fn encrypt_state(
        &self,
        sessions: &HashMap<String, JoinSession>,
    ) -> Result<Vec<u8>, PairingCoordinatorError> {
        let durable = DurableState::from_sessions(sessions);
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(&durable).map_err(|_| PairingCoordinatorError::Storage)?,
        );
        let nonce = random_array::<WRAP_NONCE_BYTES>()?;
        let cipher = Aes256Gcm::new_from_slice(self.at_rest_key.as_ref())
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext.as_slice(),
                    aad: AT_REST_AAD_PREFIX,
                },
            )
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        plaintext.zeroize();
        let mut payload = Vec::with_capacity(WRAP_NONCE_BYTES + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        Ok(payload)
    }

    fn decrypt_state(
        &self,
        payload: &[u8],
    ) -> Result<HashMap<String, JoinSession>, PairingCoordinatorError> {
        if payload.len() <= WRAP_NONCE_BYTES + 16 {
            return Err(PairingCoordinatorError::Storage);
        }
        let cipher = Aes256Gcm::new_from_slice(self.at_rest_key.as_ref())
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&payload[..WRAP_NONCE_BYTES]),
                    aes_gcm::aead::Payload {
                        msg: &payload[WRAP_NONCE_BYTES..],
                        aad: AT_REST_AAD_PREFIX,
                    },
                )
                .map_err(|_| PairingCoordinatorError::Storage)?,
        );
        let durable: DurableState = serde_json::from_slice(plaintext.as_slice())
            .map_err(|_| PairingCoordinatorError::Storage)?;
        durable.into_sessions()
    }
}

impl JoinSessionStore for SqliteJoinSessionStore {
    fn load_all(&self) -> Result<HashMap<String, JoinSession>, PairingCoordinatorError> {
        self.with_connection(|connection| {
            let record = connection
                .query_row(
                    "SELECT version, payload FROM pairing_coordinator_state WHERE singleton = 1",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
                .map_err(|_| PairingCoordinatorError::Storage)?;
            match record {
                None => Ok(HashMap::new()),
                Some((version, payload)) if version == DURABLE_STORE_VERSION => {
                    self.decrypt_state(&payload)
                }
                Some(_) => Err(PairingCoordinatorError::Storage),
            }
        })
    }

    fn replace_all(
        &self,
        sessions: &HashMap<String, JoinSession>,
    ) -> Result<(), PairingCoordinatorError> {
        validate_sessions(sessions)?;
        let payload = self.encrypt_state(sessions)?;
        self.with_connection(|connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| PairingCoordinatorError::Storage)?;
            tx.execute(
                "INSERT INTO pairing_coordinator_state (singleton, version, payload)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET version = excluded.version, payload = excluded.payload",
                params![DURABLE_STORE_VERSION, payload],
            )
            .map_err(|_| PairingCoordinatorError::Storage)?;
            tx.commit().map_err(|_| PairingCoordinatorError::Storage)
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableState {
    version: String,
    sessions: Vec<DurableJoinSession>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableJoinSession {
    join_id: String,
    join_secret_digest: Option<String>,
    cookie_digest: Option<String>,
    created_at_unix: i64,
    expires_at_unix: i64,
    state: JoinState,
    challenge_id: Option<String>,
    challenge_bytes: Option<String>,
    prospective_epoch: Option<u64>,
    device_signing_public_sec1: Option<String>,
    device_agreement_public_sec1: Option<String>,
    comparison_code: Option<String>,
    completed_vault_proof_digest: Option<String>,
    replacement_prior_join_id: Option<String>,
    pending: Option<DurablePendingBinding>,
    authority_cleanup_needed: bool,
    relay_cleanup_needed: bool,
    terminal_device_alias: Option<String>,
    revoked_epoch: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePendingBinding {
    principal_alias: String,
    device_alias: String,
    pairing_epoch: u64,
    signing_commitment: String,
    agreement_commitment: String,
    device_signing_public_sec1: String,
    device_agreement_public_sec1: String,
    mailbox_id: String,
    #[serde(
        serialize_with = "serialize_zeroizing_string",
        deserialize_with = "deserialize_zeroizing_string"
    )]
    host_bearer: Zeroizing<String>,
    signed_bundle: Option<SignedProvisioningBundle>,
}

fn serialize_zeroizing_string<S>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl DurableState {
    fn from_sessions(sessions: &HashMap<String, JoinSession>) -> Self {
        let mut sessions: Vec<_> = sessions
            .values()
            .map(DurableJoinSession::from_session)
            .collect();
        sessions.sort_by(|left, right| left.join_id.cmp(&right.join_id));
        Self {
            version: DURABLE_STORE_VERSION.to_owned(),
            sessions,
        }
    }

    fn into_sessions(self) -> Result<HashMap<String, JoinSession>, PairingCoordinatorError> {
        if self.version != DURABLE_STORE_VERSION {
            return Err(PairingCoordinatorError::Storage);
        }
        let mut sessions = HashMap::new();
        for durable in self.sessions {
            let session = durable.into_session()?;
            if sessions.insert(session.join_id.clone(), session).is_some() {
                return Err(PairingCoordinatorError::Storage);
            }
        }
        validate_sessions(&sessions)?;
        Ok(sessions)
    }
}

impl DurableJoinSession {
    fn from_session(session: &JoinSession) -> Self {
        Self {
            join_id: session.join_id.clone(),
            join_secret_digest: session.join_secret_digest.map(|value| hex_lower(&value)),
            cookie_digest: session.cookie_digest.map(|value| hex_lower(&value)),
            created_at_unix: session.created_at_unix,
            expires_at_unix: session.expires_at_unix,
            state: session.state,
            challenge_id: session.challenge_id.clone(),
            challenge_bytes: session
                .challenge_bytes
                .as_ref()
                .map(|value| URL_SAFE_NO_PAD.encode(value.as_slice())),
            prospective_epoch: session.prospective_epoch,
            device_signing_public_sec1: session
                .device_signing_public_sec1
                .map(|value| URL_SAFE_NO_PAD.encode(value)),
            device_agreement_public_sec1: session
                .device_agreement_public_sec1
                .map(|value| URL_SAFE_NO_PAD.encode(value)),
            comparison_code: session.comparison_code.clone(),
            completed_vault_proof_digest: session
                .completed_vault_proof_digest
                .map(|value| hex_lower(&value)),
            replacement_prior_join_id: session.replacement_prior_join_id.clone(),
            pending: session
                .pending
                .as_ref()
                .map(DurablePendingBinding::from_pending),
            authority_cleanup_needed: session.authority_cleanup_needed,
            relay_cleanup_needed: session.relay_cleanup_needed,
            terminal_device_alias: session.terminal_device_alias.clone(),
            revoked_epoch: session.revoked_epoch,
        }
    }

    fn into_session(self) -> Result<JoinSession, PairingCoordinatorError> {
        let challenge_bytes = self
            .challenge_bytes
            .map(|value| {
                decode_base64_exact::<32>(&value).map(|bytes| Zeroizing::new(bytes.to_vec()))
            })
            .transpose()?;
        let session = JoinSession {
            join_id: self.join_id,
            join_secret_digest: self
                .join_secret_digest
                .map(|value| decode_hex_exact::<32>(&value))
                .transpose()?,
            cookie_digest: self
                .cookie_digest
                .map(|value| decode_hex_exact::<32>(&value))
                .transpose()?,
            created_at_unix: self.created_at_unix,
            expires_at_unix: self.expires_at_unix,
            state: self.state,
            challenge_id: self.challenge_id,
            challenge_bytes,
            prospective_epoch: self.prospective_epoch,
            device_signing_public_sec1: self
                .device_signing_public_sec1
                .map(|value| decode_base64_exact::<65>(&value))
                .transpose()?,
            device_agreement_public_sec1: self
                .device_agreement_public_sec1
                .map(|value| decode_base64_exact::<65>(&value))
                .transpose()?,
            comparison_code: self.comparison_code,
            completed_vault_proof_digest: self
                .completed_vault_proof_digest
                .map(|value| decode_hex_exact::<32>(&value))
                .transpose()?,
            replacement_prior_join_id: self.replacement_prior_join_id,
            pending: self
                .pending
                .map(DurablePendingBinding::into_pending)
                .transpose()?,
            authority_cleanup_needed: self.authority_cleanup_needed,
            relay_cleanup_needed: self.relay_cleanup_needed,
            terminal_device_alias: self.terminal_device_alias,
            revoked_epoch: self.revoked_epoch,
        };
        validate_session(&session)?;
        Ok(session)
    }
}

impl DurablePendingBinding {
    fn from_pending(pending: &PendingBinding) -> Self {
        Self {
            principal_alias: pending.device.principal_alias.clone(),
            device_alias: pending.device.device_alias.clone(),
            pairing_epoch: pending.device.pairing_epoch,
            signing_commitment: hex_lower(&pending.device.signing_commitment),
            agreement_commitment: hex_lower(&pending.device.agreement_commitment),
            device_signing_public_sec1: URL_SAFE_NO_PAD.encode(pending.device_signing_public_sec1),
            device_agreement_public_sec1: URL_SAFE_NO_PAD
                .encode(pending.device_agreement_public_sec1),
            mailbox_id: pending.mailbox_id.clone(),
            host_bearer: pending.host_bearer.clone(),
            signed_bundle: pending.signed_bundle.clone(),
        }
    }

    fn into_pending(self) -> Result<PendingBinding, PairingCoordinatorError> {
        let signing_public = decode_base64_exact::<65>(&self.device_signing_public_sec1)?;
        let agreement_public = decode_base64_exact::<65>(&self.device_agreement_public_sec1)?;
        parse_public(&signing_public)?;
        parse_public(&agreement_public)?;
        let signing_commitment = decode_hex_exact::<32>(&self.signing_commitment)?;
        let agreement_commitment = decode_hex_exact::<32>(&self.agreement_commitment)?;
        if authority_public_key_digest(&signing_public) != signing_commitment
            || authority_public_key_digest(&agreement_public) != agreement_commitment
            || authority_device_alias(&signing_commitment, &agreement_commitment)
                != self.device_alias
        {
            return Err(PairingCoordinatorError::Storage);
        }
        Ok(PendingBinding {
            device: AuthenticatedDeviceFact {
                principal_alias: self.principal_alias,
                device_alias: self.device_alias,
                pairing_epoch: self.pairing_epoch,
                signing_commitment,
                agreement_commitment,
            },
            device_signing_public_sec1: signing_public,
            device_agreement_public_sec1: agreement_public,
            mailbox_id: self.mailbox_id,
            host_bearer: self.host_bearer,
            signed_bundle: self.signed_bundle,
        })
    }
}

impl fmt::Debug for SqliteJoinSessionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteJoinSessionStore")
            .field("db_path", &"<redacted>")
            .field("at_rest_key", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for MemoryJoinSessionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryJoinSessionStore")
            .field("sessions", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for RelayProvisionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayProvisionRequest")
            .field("schema", &self.schema)
            .field("mailbox_id", &self.mailbox_id)
            .field("epoch", &self.epoch)
            .field("digests_and_commitments", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelayProvisionRequest {
    pub(crate) schema: String,
    pub(crate) mailbox_id: String,
    pub(crate) epoch: u64,
    pub(crate) host_token_digest: String,
    pub(crate) device_token_digest: String,
    pub(crate) host_identity_commitment: String,
    pub(crate) device_key_commitment: String,
}

pub(crate) trait RelayProvisioner: Send + Sync + 'static {
    fn provision(&self, request: &RelayProvisionRequest) -> Result<(), PairingCoordinatorError>;
    fn revoke(&self, mailbox_id: &str, host_bearer: &str) -> Result<(), PairingCoordinatorError>;
}

/// Private-key operations needed from the Host identity without exposing key material.
pub(crate) trait HostPairingIdentity: Send + Sync + 'static {
    fn signing_public_sec1(&self) -> [u8; 65];
    fn agreement_public_sec1(&self) -> [u8; 65];
    fn signing_commitment(&self) -> [u8; 32];
    fn agreement_commitment(&self) -> [u8; 32];
    fn sign_p1363(&self, message: &[u8]) -> Result<[u8; 64], PairingCoordinatorError>;
    fn derive_agreement_shared(
        &self,
        peer_public_sec1: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PairingCoordinatorError>;
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CreatedJoin {
    pub(crate) join_id: String,
    pub(crate) join_secret: Zeroizing<String>,
    pub(crate) expires_at_unix: i64,
}

impl fmt::Debug for CreatedJoin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedJoin")
            .field("join_id", &self.join_id)
            .field("join_secret", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StartedJoin {
    pub(crate) cookie_capability: Zeroizing<String>,
    pub(crate) challenge_id: String,
    pub(crate) challenge_bytes: Zeroizing<Vec<u8>>,
    pub(crate) prospective_epoch: u64,
    pub(crate) host_signing_public_sec1: [u8; 65],
    pub(crate) host_agreement_public_sec1: [u8; 65],
    pub(crate) issued_at_unix: i64,
    pub(crate) expires_at_unix: i64,
    pub(crate) comparison_code: String,
}

impl fmt::Debug for StartedJoin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartedJoin")
            .field("cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("challenge_bytes", &"<redacted>")
            .field("prospective_epoch", &self.prospective_epoch)
            .field("host_signing_public_sec1", &"<redacted>")
            .field("host_agreement_public_sec1", &"<redacted>")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("comparison_code", &self.comparison_code)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisioningBundle {
    pub(crate) schema: String,
    pub(crate) device_alias: String,
    pub(crate) pairing_epoch: u64,
    pub(crate) mailbox_id: String,
    pub(crate) relay_base_url: String,
    pub(crate) host_signing_public_key_sec1: String,
    pub(crate) host_agreement_public_key_sec1: String,
    pub(crate) wrapped_device_bearer: String,
    pub(crate) wrap_nonce: String,
    pub(crate) issued_at: String,
}

impl fmt::Debug for ProvisioningBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisioningBundle")
            .field("schema", &self.schema)
            .field("device_alias", &self.device_alias)
            .field("pairing_epoch", &self.pairing_epoch)
            .field("mailbox_id", &self.mailbox_id)
            .field("relay_base_url", &self.relay_base_url)
            .field("host_keys", &"<redacted>")
            .field("wrapped_device_bearer", &"<redacted>")
            .field("wrap_nonce", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedProvisioningBundle {
    pub(crate) schema: String,
    pub(crate) bundle: ProvisioningBundle,
    pub(crate) provisioning_signature_p1363: String,
}

impl fmt::Debug for SignedProvisioningBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedProvisioningBundle")
            .field("schema", &self.schema)
            .field("bundle", &self.bundle)
            .field("provisioning_signature_p1363", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PairingCoordinatorError {
    #[error("PAIRING_NOT_FOUND")]
    NotFound,
    #[error("PAIRING_INVALID")]
    Invalid,
    #[error("PAIRING_EXPIRED")]
    Expired,
    #[error("PAIRING_REPLAY")]
    Consumed,
    #[error("PAIRING_DESKTOP_APPROVAL_REQUIRED")]
    DesktopApprovalRequired,
    #[error("PAIRING_PROOF_INVALID")]
    InvalidProof,
    #[error("PAIRING_CONFLICT")]
    Conflict,
    #[error("PAIRING_RELAY_UNAVAILABLE")]
    Relay,
    #[error("PAIRING_STORAGE")]
    Storage,
    #[error("PAIRING_CRYPTO")]
    Crypto,
}

impl From<DeviceAuthorityError> for PairingCoordinatorError {
    fn from(error: DeviceAuthorityError) -> Self {
        match error {
            DeviceAuthorityError::ChallengeExpired => Self::Expired,
            DeviceAuthorityError::ChallengeConsumed => Self::Consumed,
            DeviceAuthorityError::InvalidProof => Self::InvalidProof,
            DeviceAuthorityError::Conflict | DeviceAuthorityError::EpochMismatch => Self::Conflict,
            DeviceAuthorityError::Storage => Self::Storage,
            _ => Self::Invalid,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CancelJoinRequest {
    pub(crate) schema: String,
    pub(crate) join_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbortJoinRequest {
    pub(crate) schema: String,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairingStatusRequest {
    pub(crate) schema: String,
    pub(crate) join_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairingStatusResponse {
    pub(crate) schema: String,
    pub(crate) join_id: String,
    pub(crate) state: String,
    pub(crate) challenge_id: Option<String>,
    pub(crate) expected_epoch: Option<u64>,
    pub(crate) comparison_code: Option<String>,
    pub(crate) expires_at: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPairingStartRequest {
    pub(crate) schema: String,
    pub(crate) join_id: String,
    pub(crate) join_secret: String,
    pub(crate) device_signing_public_key_sec1: String,
    pub(crate) device_agreement_public_key_sec1: String,
}

impl fmt::Debug for HostPairingStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostPairingStartRequest")
            .field("schema", &self.schema)
            .field("join_id", &self.join_id)
            .field("join_secret", &"<redacted>")
            .field("device_keys", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPairingConfirmRequest {
    pub(crate) schema: String,
    pub(crate) join_cookie_capability: String,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
    pub(crate) device_signing_signature_p1363: String,
    pub(crate) device_agreement_mac: String,
}

impl fmt::Debug for HostPairingConfirmRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostPairingConfirmRequest")
            .field("schema", &self.schema)
            .field("join_cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("expected_epoch", &self.expected_epoch)
            .field("proofs", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPairingCompleteRequest {
    pub(crate) schema: String,
    pub(crate) join_cookie_capability: String,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
    pub(crate) device_vault_signature_p1363: String,
}

impl fmt::Debug for HostPairingCompleteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostPairingCompleteRequest")
            .field("schema", &self.schema)
            .field("join_cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("expected_epoch", &self.expected_epoch)
            .field("device_vault_signature_p1363", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPairingAbortRequest {
    pub(crate) schema: String,
    pub(crate) join_cookie_capability: String,
    pub(crate) challenge_id: String,
    pub(crate) expected_epoch: u64,
}

impl fmt::Debug for HostPairingAbortRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostPairingAbortRequest")
            .field("schema", &self.schema)
            .field("join_cookie_capability", &"<redacted>")
            .field("challenge_id", &"<redacted>")
            .field("expected_epoch", &self.expected_epoch)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ActiveRemoteBinding {
    pub(crate) device_alias: String,
    pub(crate) pairing_epoch: u64,
    pub(crate) mailbox_id: String,
    pub(crate) host_bearer: Zeroizing<String>,
    pub(crate) host_signing_commitment: [u8; 32],
    pub(crate) host_agreement_commitment: [u8; 32],
    pub(crate) device_signing_commitment: [u8; 32],
    pub(crate) device_agreement_commitment: [u8; 32],
    pub(crate) device_signing_public_sec1: [u8; 65],
    pub(crate) device_agreement_public_sec1: [u8; 65],
}

impl fmt::Debug for ActiveRemoteBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveRemoteBinding")
            .field("device_alias", &self.device_alias)
            .field("pairing_epoch", &self.pairing_epoch)
            .field("mailbox_id", &self.mailbox_id)
            .field("host_bearer", &"<redacted>")
            .field("commitments", &"<redacted>")
            .field("device_public_keys", &"<redacted>")
            .finish()
    }
}

pub(crate) struct PairingCoordinator {
    gate: Arc<DeviceCommandGate>,
    authority: DeviceAuthority,
    identity: Arc<dyn HostPairingIdentity>,
    relay: Arc<dyn RelayProvisioner>,
    store: Arc<dyn JoinSessionStore>,
    relay_base_url: String,
    #[cfg(test)]
    crash_after_authority_commit: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for PairingCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCoordinator")
            .field("gate", &self.gate)
            .field("authority", &"<redacted>")
            .field("identity", &"<redacted>")
            .field("relay", &"<redacted>")
            .field("store", &"<redacted>")
            .field("relay_base_url", &self.relay_base_url)
            .finish()
    }
}

impl PairingCoordinator {
    pub(crate) fn new(
        gate: Arc<DeviceCommandGate>,
        authority: DeviceAuthority,
        identity: Arc<dyn HostPairingIdentity>,
        relay: Arc<dyn RelayProvisioner>,
        store: Arc<dyn JoinSessionStore>,
        relay_base_url: String,
    ) -> Result<Self, PairingCoordinatorError> {
        let relay_url =
            Url::parse(&relay_base_url).map_err(|_| PairingCoordinatorError::Invalid)?;
        let raw_authority = relay_base_url
            .strip_prefix("https://")
            .ok_or(PairingCoordinatorError::Invalid)?;
        if raw_authority.is_empty()
            || raw_authority.starts_with('/')
            || relay_url.scheme() != "https"
            || relay_url.host_str().is_none()
            || !relay_url.username().is_empty()
            || relay_url.password().is_some()
            || relay_url.query().is_some()
            || relay_url.fragment().is_some()
        {
            return Err(PairingCoordinatorError::Invalid);
        }
        store.load_all()?;
        Ok(Self {
            gate,
            authority,
            identity,
            relay,
            store,
            relay_base_url,
            #[cfg(test)]
            crash_after_authority_commit: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub(crate) fn new_with_startup_recovery(
        gate: Arc<DeviceCommandGate>,
        authority: DeviceAuthority,
        identity: Arc<dyn HostPairingIdentity>,
        relay: Arc<dyn RelayProvisioner>,
        store: Arc<dyn JoinSessionStore>,
        relay_base_url: String,
        now: OffsetDateTime,
    ) -> Result<Self, PairingCoordinatorError> {
        let coordinator = Self::new(gate, authority, identity, relay, store, relay_base_url)?;
        coordinator.recover_pending_on_startup(now)?;
        Ok(coordinator)
    }

    pub(crate) fn create_join(
        &self,
        now: OffsetDateTime,
    ) -> Result<CreatedJoin, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let expired_pending: Vec<_> = {
            let sessions = self.sessions()?;
            if sessions.values().any(|session| {
                session.state == JoinState::ProvisionedPendingVault
                    && now.unix_timestamp() <= session.expires_at_unix
            }) {
                return Err(PairingCoordinatorError::Conflict);
            }
            sessions
                .values()
                .filter_map(|session| expired_pending_snapshot(session, now.unix_timestamp()))
                .collect()
        };
        for (join_id, device, mailbox_id, host_bearer) in expired_pending {
            self.compensate_candidate(
                &join_id,
                &device,
                &mailbox_id,
                &host_bearer,
                now,
                JoinState::ExpiredCompensated,
            )?;
        }
        let mut sessions = self.sessions()?;
        for session in sessions.values_mut().filter(|session| {
            matches!(
                session.state,
                JoinState::Created
                    | JoinState::StartedAwaitingDesktopApproval
                    | JoinState::DesktopApproved
            )
        }) {
            session.state = JoinState::Cancelled;
            session.join_secret_digest = None;
            session.clear_capabilities();
        }
        let join_id = random_prefixed_hex("join-", 16)?;
        let join_secret = random_base64(JOIN_RANDOM_BYTES)?;
        let expires_at_unix = now
            .unix_timestamp()
            .checked_add(JOIN_TTL_SECONDS)
            .ok_or(PairingCoordinatorError::Invalid)?;
        sessions.insert(
            join_id.clone(),
            JoinSession {
                join_id: join_id.clone(),
                join_secret_digest: Some(sha256(join_secret.as_bytes())),
                cookie_digest: None,
                created_at_unix: now.unix_timestamp(),
                expires_at_unix,
                state: JoinState::Created,
                challenge_id: None,
                challenge_bytes: None,
                prospective_epoch: None,
                device_signing_public_sec1: None,
                device_agreement_public_sec1: None,
                comparison_code: None,
                completed_vault_proof_digest: None,
                replacement_prior_join_id: None,
                pending: None,
                authority_cleanup_needed: false,
                relay_cleanup_needed: false,
                terminal_device_alias: None,
                revoked_epoch: None,
            },
        );
        self.persist_sessions(&sessions)?;
        Ok(CreatedJoin {
            join_id,
            join_secret,
            expires_at_unix,
        })
    }

    /// Authenticated start consumes the join secret and returns the raw Host-generated
    /// cookie capability exactly once. Only its SHA-256 digest remains in the store.
    pub(crate) fn start_join(
        &self,
        join_id: &str,
        join_secret: &str,
        device_signing_public_sec1: &[u8],
        device_agreement_public_sec1: &[u8],
        now: OffsetDateTime,
    ) -> Result<StartedJoin, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let signing_public = parse_public(device_signing_public_sec1)?;
        let agreement_public = parse_public(device_agreement_public_sec1)?;
        if signing_public == agreement_public {
            return Err(PairingCoordinatorError::Invalid);
        }
        let signing_public: [u8; 65] = signing_public
            .try_into()
            .map_err(|_| PairingCoordinatorError::Invalid)?;
        let agreement_public: [u8; 65] = agreement_public
            .try_into()
            .map_err(|_| PairingCoordinatorError::Invalid)?;

        let mut sessions = self.sessions()?;
        let session = sessions
            .get_mut(join_id)
            .ok_or(PairingCoordinatorError::NotFound)?;
        expire_if_needed(session, now.unix_timestamp());
        if session.state == JoinState::Expired {
            self.persist_sessions(&sessions)?;
            return Err(PairingCoordinatorError::Expired);
        }
        if session.state != JoinState::Created {
            return Err(PairingCoordinatorError::Consumed);
        }
        let expected_secret = session
            .join_secret_digest
            .ok_or(PairingCoordinatorError::Consumed)?;
        if !constant_time_eq(&expected_secret, &sha256(join_secret.as_bytes())) {
            return Err(PairingCoordinatorError::Invalid);
        }

        let challenge = self.authority.begin_pairing(
            REMOTE_PRINCIPAL,
            &signing_public,
            &agreement_public,
            now,
        )?;
        let transcript = transcript_hash(TranscriptInput {
            join_id,
            challenge_id: challenge.challenge_id(),
            challenge_bytes: challenge.challenge_bytes(),
            prospective_epoch: challenge.prospective_epoch(),
            host_signing_public_sec1: &self.identity.signing_public_sec1(),
            host_agreement_public_sec1: &self.identity.agreement_public_sec1(),
            device_signing_public_sec1: &signing_public,
            device_agreement_public_sec1: &agreement_public,
        });
        let comparison_code = comparison_code(&transcript);
        let cookie_capability = random_base64(COOKIE_RANDOM_BYTES)?;
        session.join_secret_digest = None;
        session.cookie_digest = Some(sha256(cookie_capability.as_bytes()));
        session.state = JoinState::StartedAwaitingDesktopApproval;
        session.challenge_id = Some(challenge.challenge_id().to_owned());
        session.challenge_bytes = Some(Zeroizing::new(challenge.challenge_bytes().to_vec()));
        session.prospective_epoch = Some(challenge.prospective_epoch());
        session.device_signing_public_sec1 = Some(signing_public);
        session.device_agreement_public_sec1 = Some(agreement_public);
        session.comparison_code = Some(comparison_code.clone());
        let expires_at_unix = session.expires_at_unix;
        self.persist_sessions(&sessions)?;
        Ok(StartedJoin {
            cookie_capability,
            challenge_id: challenge.challenge_id().to_owned(),
            challenge_bytes: Zeroizing::new(challenge.challenge_bytes().to_vec()),
            prospective_epoch: challenge.prospective_epoch(),
            host_signing_public_sec1: self.identity.signing_public_sec1(),
            host_agreement_public_sec1: self.identity.agreement_public_sec1(),
            issued_at_unix: challenge.issued_at_unix(),
            expires_at_unix,
            comparison_code,
        })
    }

    pub(crate) fn approve_join(
        &self,
        join_id: &str,
        challenge_id: &str,
        expected_epoch: u64,
        displayed_comparison_code: &str,
        now: OffsetDateTime,
    ) -> Result<(), PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let mut sessions = self.sessions()?;
        let session = sessions
            .get_mut(join_id)
            .ok_or(PairingCoordinatorError::NotFound)?;
        expire_if_needed(session, now.unix_timestamp());
        if session.state == JoinState::Expired {
            self.persist_sessions(&sessions)?;
            return Err(PairingCoordinatorError::Expired);
        }
        if session.state != JoinState::StartedAwaitingDesktopApproval
            || session.challenge_id.as_deref() != Some(challenge_id)
            || session.prospective_epoch != Some(expected_epoch)
            || session.comparison_code.as_deref() != Some(displayed_comparison_code)
        {
            return Err(PairingCoordinatorError::Invalid);
        }
        session.state = JoinState::DesktopApproved;
        self.persist_sessions(&sessions)?;
        Ok(())
    }

    pub(crate) fn cancel_join(
        &self,
        request: &CancelJoinRequest,
    ) -> Result<(), PairingCoordinatorError> {
        if request.schema != "nomad.m3e.pairing.cancel.v1" {
            return Err(PairingCoordinatorError::Invalid);
        }
        let _gate = self.gate.lock()?;
        let mut sessions = self.sessions()?;
        let session = sessions
            .get_mut(&request.join_id)
            .ok_or(PairingCoordinatorError::NotFound)?;
        if matches!(
            session.state,
            JoinState::ProvisionedPendingVault | JoinState::Active
        ) {
            return Err(PairingCoordinatorError::Conflict);
        }
        session.state = JoinState::Cancelled;
        session.join_secret_digest = None;
        session.clear_capabilities();
        self.persist_sessions(&sessions)?;
        Ok(())
    }

    pub(crate) fn pairing_status(
        &self,
        request: &PairingStatusRequest,
        now: OffsetDateTime,
    ) -> Result<PairingStatusResponse, PairingCoordinatorError> {
        if request.schema != "nomad.m3e.pairing.status.v1" {
            return Err(PairingCoordinatorError::Invalid);
        }
        let _gate = self.gate.lock()?;
        let pending_expired = {
            let mut sessions = self.sessions()?;
            let session = sessions
                .get_mut(&request.join_id)
                .ok_or(PairingCoordinatorError::NotFound)?;
            if session.state == JoinState::ProvisionedPendingVault
                && now.unix_timestamp() > session.expires_at_unix
            {
                session.pending.as_ref().map(|pending| {
                    (
                        session.join_id.clone(),
                        pending.device.clone(),
                        pending.mailbox_id.clone(),
                        pending.host_bearer.clone(),
                    )
                })
            } else {
                expire_if_needed(session, now.unix_timestamp());
                self.persist_sessions(&sessions)?;
                None
            }
        };
        if let Some((join_id, device, mailbox_id, host_bearer)) = pending_expired {
            self.compensate_candidate(
                &join_id,
                &device,
                &mailbox_id,
                &host_bearer,
                now,
                JoinState::ExpiredCompensated,
            )?;
        }
        let sessions = self.sessions()?;
        let session = sessions
            .get(&request.join_id)
            .ok_or(PairingCoordinatorError::NotFound)?;
        let expires_at = format_unix_seconds(session.expires_at_unix)
            .map_err(|_| PairingCoordinatorError::Storage)?;
        Ok(PairingStatusResponse {
            schema: "nomad.m3e.pairing.status-response.v1".to_owned(),
            join_id: session.join_id.clone(),
            state: join_state_text(session.state).to_owned(),
            challenge_id: session.challenge_id.clone(),
            expected_epoch: session.prospective_epoch,
            comparison_code: session.comparison_code.clone(),
            expires_at,
        })
    }

    pub(crate) fn confirm_join(
        &self,
        cookie_capability: &str,
        challenge_id: &str,
        expected_epoch: u64,
        device_signing_signature_p1363: &[u8],
        device_agreement_mac: &[u8],
        now: OffsetDateTime,
    ) -> Result<SignedProvisioningBundle, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let cookie_digest = sha256(cookie_capability.as_bytes());
        let expired_pending = {
            let mut sessions = self.sessions()?;
            let session = session_by_cookie_mut(&mut sessions, &cookie_digest)?;
            expired_pending_snapshot(session, now.unix_timestamp())
        };
        if let Some((join_id, device, mailbox_id, host_bearer)) = expired_pending {
            self.compensate_candidate(
                &join_id,
                &device,
                &mailbox_id,
                &host_bearer,
                now,
                JoinState::ExpiredCompensated,
            )?;
            return Err(PairingCoordinatorError::Expired);
        }
        let session = {
            let mut sessions = self.sessions()?;
            let session = session_by_cookie_mut(&mut sessions, &cookie_digest)?;
            expire_if_needed(session, now.unix_timestamp());
            if session.state == JoinState::Expired {
                self.persist_sessions(&sessions)?;
                return Err(PairingCoordinatorError::Expired);
            }
            if session.challenge_id.as_deref() != Some(challenge_id)
                || session.prospective_epoch != Some(expected_epoch)
            {
                return Err(PairingCoordinatorError::Invalid);
            }
            if session.state == JoinState::ProvisionedPendingVault {
                return session
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.signed_bundle.clone())
                    .ok_or(PairingCoordinatorError::Storage);
            }
            if session.state == JoinState::StartedAwaitingDesktopApproval {
                return Err(PairingCoordinatorError::DesktopApprovalRequired);
            }
            if session.state != JoinState::DesktopApproved {
                return Err(PairingCoordinatorError::Consumed);
            }
            session.clone()
        };

        let challenge_bytes = session
            .challenge_bytes
            .as_deref()
            .ok_or(PairingCoordinatorError::Storage)?;
        let signing_public = session
            .device_signing_public_sec1
            .ok_or(PairingCoordinatorError::Storage)?;
        let agreement_public = session
            .device_agreement_public_sec1
            .ok_or(PairingCoordinatorError::Storage)?;
        let transcript = transcript_hash(TranscriptInput {
            join_id: &session.join_id,
            challenge_id,
            challenge_bytes,
            prospective_epoch: expected_epoch,
            host_signing_public_sec1: &self.identity.signing_public_sec1(),
            host_agreement_public_sec1: &self.identity.agreement_public_sec1(),
            device_signing_public_sec1: &signing_public,
            device_agreement_public_sec1: &agreement_public,
        });
        verify_dual_proof(
            &signing_public,
            &transcript,
            device_signing_signature_p1363,
            self.identity.as_ref(),
            &agreement_public,
            device_agreement_mac,
        )?;
        let signing_commitment = authority_public_key_digest(&signing_public);
        let agreement_commitment = authority_public_key_digest(&agreement_public);
        let candidate = AuthenticatedDeviceFact {
            principal_alias: REMOTE_PRINCIPAL.to_owned(),
            device_alias: authority_device_alias(&signing_commitment, &agreement_commitment),
            pairing_epoch: expected_epoch,
            signing_commitment,
            agreement_commitment,
        };
        let mailbox_id = random_prefixed_hex("mbx-", MAILBOX_RANDOM_BYTES)?;
        let host_bearer = random_base64(BEARER_RANDOM_BYTES)?;
        let device_bearer = random_base64(BEARER_RANDOM_BYTES)?;
        let request = RelayProvisionRequest {
            schema: "nomad.relay.mailbox-provision.v1".to_owned(),
            mailbox_id: mailbox_id.clone(),
            epoch: candidate.pairing_epoch,
            host_token_digest: hex_lower(&sha256(host_bearer.as_bytes())),
            device_token_digest: hex_lower(&sha256(device_bearer.as_bytes())),
            host_identity_commitment: hex_lower(&composite_commitment(
                HOST_IDENTITY_PREFIX,
                &self.identity.signing_commitment(),
                &self.identity.agreement_commitment(),
            )),
            device_key_commitment: hex_lower(&composite_commitment(
                DEVICE_KEY_PREFIX,
                &candidate.signing_commitment,
                &candidate.agreement_commitment,
            )),
        };
        {
            let mut sessions = self.sessions()?;
            let replacement_prior_join_id = sessions
                .values()
                .find(|existing| existing.state == JoinState::Active)
                .map(|existing| existing.join_id.clone());
            let current = sessions
                .get_mut(&session.join_id)
                .ok_or(PairingCoordinatorError::Storage)?;
            current.pending = Some(PendingBinding {
                device: candidate.clone(),
                device_signing_public_sec1: signing_public,
                device_agreement_public_sec1: agreement_public,
                mailbox_id: mailbox_id.clone(),
                host_bearer: host_bearer.clone(),
                signed_bundle: None,
            });
            current.replacement_prior_join_id = replacement_prior_join_id;
            current.state = JoinState::Prepared;
            self.persist_sessions(&sessions)?;
        }
        {
            let mut sessions = self.sessions()?;
            let current = sessions
                .get_mut(&session.join_id)
                .ok_or(PairingCoordinatorError::Storage)?;
            if current.state != JoinState::Prepared {
                return Err(PairingCoordinatorError::Conflict);
            }
        }
        let device = self.authority.confirm_pairing_preverified(
            challenge_id,
            challenge_bytes,
            &signing_public,
            &agreement_public,
            now,
        )?;
        #[cfg(test)]
        assert!(
            !self
                .crash_after_authority_commit
                .load(std::sync::atomic::Ordering::SeqCst),
            "injected crash after authority commit"
        );
        let replaced: Vec<_> = {
            let mut sessions = self.sessions()?;
            let mut replaced = Vec::new();
            for existing in sessions.values_mut().filter(|existing| {
                existing.state == JoinState::Active && existing.join_id != session.join_id
            }) {
                if let Some(pending) = existing.pending.as_ref() {
                    replaced.push((
                        existing.join_id.clone(),
                        pending.mailbox_id.clone(),
                        pending.host_bearer.clone(),
                    ));
                }
                existing.state = JoinState::Revoked;
                existing.authority_cleanup_needed = false;
                existing.relay_cleanup_needed = true;
                existing.terminal_device_alias = existing
                    .pending
                    .as_ref()
                    .map(|pending| pending.device.device_alias.clone());
                existing.revoked_epoch = Some(device.pairing_epoch);
                existing.clear_capabilities();
                if let Some(pending) = existing.pending.as_mut() {
                    pending.signed_bundle = None;
                }
            }
            let current = sessions
                .get_mut(&session.join_id)
                .ok_or(PairingCoordinatorError::Storage)?;
            current.state = JoinState::AuthorityActive;
            self.persist_sessions(&sessions)?;
            replaced
        };
        for (join_id, prior_mailbox_id, prior_host_bearer) in replaced {
            if self
                .relay
                .revoke(&prior_mailbox_id, &prior_host_bearer)
                .is_ok()
            {
                let mut sessions = self.sessions()?;
                let prior = sessions
                    .get_mut(&join_id)
                    .ok_or(PairingCoordinatorError::Storage)?;
                prior.relay_cleanup_needed = false;
                self.persist_sessions(&sessions)?;
            }
        }
        let provisioned = self.relay.provision(&request).is_ok();
        if !provisioned {
            self.compensate_candidate(
                &session.join_id,
                &device,
                &mailbox_id,
                &host_bearer,
                now,
                JoinState::Compensated,
            )?;
            return Err(PairingCoordinatorError::Relay);
        }

        let bundle_result = self.build_signed_bundle(
            &device,
            &mailbox_id,
            &agreement_public,
            device_bearer.as_str(),
            now,
        );
        let signed_bundle = match bundle_result {
            Ok(bundle) => bundle,
            Err(error) => {
                self.compensate_candidate(
                    &session.join_id,
                    &device,
                    &mailbox_id,
                    &host_bearer,
                    now,
                    JoinState::Compensated,
                )?;
                return Err(error);
            }
        };

        let persisted = {
            let mut sessions = self.sessions()?;
            let current = sessions
                .get_mut(&session.join_id)
                .ok_or(PairingCoordinatorError::Storage)?;
            if current.state != JoinState::AuthorityActive
                || current.challenge_id.as_deref() != Some(challenge_id)
                || current.prospective_epoch != Some(expected_epoch)
            {
                false
            } else {
                current.pending = Some(PendingBinding {
                    device: device.clone(),
                    device_signing_public_sec1: signing_public,
                    device_agreement_public_sec1: agreement_public,
                    mailbox_id: mailbox_id.clone(),
                    host_bearer: host_bearer.clone(),
                    signed_bundle: Some(signed_bundle.clone()),
                });
                current.state = JoinState::ProvisionedPendingVault;
                self.persist_sessions(&sessions)?;
                true
            }
        };
        if !persisted {
            // This cannot race while the shared gate is held; fail closed if the store disagrees.
            self.compensate_candidate(
                &session.join_id,
                &device,
                &mailbox_id,
                &host_bearer,
                now,
                JoinState::Compensated,
            )?;
            return Err(PairingCoordinatorError::Storage);
        }
        Ok(signed_bundle)
    }

    pub(crate) fn complete_join(
        &self,
        cookie_capability: &str,
        challenge_id: &str,
        expected_epoch: u64,
        device_vault_signature_p1363: &[u8],
        now: OffsetDateTime,
    ) -> Result<ActiveRemoteBinding, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let cookie_digest = sha256(cookie_capability.as_bytes());
        let expired_pending = {
            let mut sessions = self.sessions()?;
            let session = session_by_cookie_mut(&mut sessions, &cookie_digest)?;
            expired_pending_snapshot(session, now.unix_timestamp())
        };
        if let Some((join_id, device, mailbox_id, host_bearer)) = expired_pending {
            self.compensate_candidate(
                &join_id,
                &device,
                &mailbox_id,
                &host_bearer,
                now,
                JoinState::ExpiredCompensated,
            )?;
            return Err(PairingCoordinatorError::Expired);
        }
        let mut sessions = self.sessions()?;
        let session = session_by_cookie_mut(&mut sessions, &cookie_digest)?;
        if now.unix_timestamp() > session.expires_at_unix {
            session.cookie_digest = None;
            self.persist_sessions(&sessions)?;
            return Err(PairingCoordinatorError::Expired);
        }
        if session.challenge_id.as_deref() != Some(challenge_id)
            || session.prospective_epoch != Some(expected_epoch)
        {
            return Err(PairingCoordinatorError::Invalid);
        }
        if !matches!(
            session.state,
            JoinState::ProvisionedPendingVault | JoinState::Active
        ) {
            return Err(PairingCoordinatorError::Conflict);
        }
        let pending = session
            .pending
            .as_ref()
            .ok_or(PairingCoordinatorError::Storage)?;
        let canonical_signed = canonical_json(
            &serde_json::to_value(
                pending
                    .signed_bundle
                    .as_ref()
                    .ok_or(PairingCoordinatorError::Storage)?,
            )
            .map_err(|_| PairingCoordinatorError::Storage)?,
        )?;
        let mut material = Vec::from(VAULT_COMMIT_PREFIX);
        material.extend_from_slice(&sha256(canonical_signed.as_bytes()));
        let vault_commit_digest = sha256(&material);
        material.zeroize();
        let proof_digest = sha256(device_vault_signature_p1363);
        if session.state == JoinState::Active {
            return if session.completed_vault_proof_digest == Some(proof_digest) {
                active_from_session(session, self.identity.as_ref())
            } else {
                Err(PairingCoordinatorError::InvalidProof)
            };
        }
        let signing_public = session
            .device_signing_public_sec1
            .ok_or(PairingCoordinatorError::Storage)?;
        verify_p1363(
            &signing_public,
            &vault_commit_digest,
            device_vault_signature_p1363,
        )?;

        session.state = JoinState::Active;
        session.completed_vault_proof_digest = Some(proof_digest);
        session.join_secret_digest = None;
        session.challenge_bytes = None;
        session.device_agreement_public_sec1 = None;
        let active = active_from_session(session, self.identity.as_ref())?;
        self.persist_sessions(&sessions)?;
        Ok(active)
    }

    pub(crate) fn abort_join(
        &self,
        cookie_capability: &str,
        request: &AbortJoinRequest,
        now: OffsetDateTime,
    ) -> Result<(), PairingCoordinatorError> {
        if request.schema != "nomad.m3e.pairing.abort.v1" {
            return Err(PairingCoordinatorError::Invalid);
        }
        let _gate = self.gate.lock()?;
        let cookie_digest = sha256(cookie_capability.as_bytes());
        let snapshot = {
            let mut sessions = self.sessions()?;
            let session = session_by_cookie_mut(&mut sessions, &cookie_digest)?;
            if session.state == JoinState::Compensated
                && now.unix_timestamp() > session.expires_at_unix
            {
                session.cookie_digest = None;
                self.persist_sessions(&sessions)?;
                return Err(PairingCoordinatorError::Expired);
            }
            if session.challenge_id.as_deref() != Some(&request.challenge_id)
                || session.prospective_epoch != Some(request.expected_epoch)
            {
                return Err(PairingCoordinatorError::Invalid);
            }
            if session.state == JoinState::Compensated {
                return Ok(());
            }
            if session.state != JoinState::ProvisionedPendingVault {
                return Err(PairingCoordinatorError::Conflict);
            }
            let pending = session
                .pending
                .as_ref()
                .ok_or(PairingCoordinatorError::Storage)?;
            (
                session.join_id.clone(),
                pending.device.clone(),
                pending.mailbox_id.clone(),
                pending.host_bearer.clone(),
            )
        };
        self.compensate_candidate(
            &snapshot.0,
            &snapshot.1,
            &snapshot.2,
            &snapshot.3,
            now,
            JoinState::Compensated,
        )
    }

    pub(crate) fn active_binding(
        &self,
    ) -> Result<Option<ActiveRemoteBinding>, PairingCoordinatorError> {
        let gate = self.gate.lock()?;
        self.active_binding_locked(&gate)
    }

    pub(crate) fn command_guard(&self) -> Result<DeviceCommandGuard<'_>, PairingCoordinatorError> {
        self.gate.lock()
    }

    pub(crate) fn device_command_gate(&self) -> Arc<DeviceCommandGate> {
        Arc::clone(&self.gate)
    }

    pub(crate) fn active_binding_locked(
        &self,
        guard: &DeviceCommandGuard<'_>,
    ) -> Result<Option<ActiveRemoteBinding>, PairingCoordinatorError> {
        if !std::ptr::eq(guard.owner, self.gate.as_ref()) {
            return Err(PairingCoordinatorError::Conflict);
        }
        let sessions = self.sessions()?;
        let binding = sessions
            .values()
            .find(|session| session.state == JoinState::Active)
            .map(|session| active_from_session(session, self.identity.as_ref()))
            .transpose()?;
        match (binding, self.authority.current_active()?) {
            (None, _) => Ok(None),
            (Some(binding), CurrentActiveDevice::Active(device))
                if binding.device_alias == device.device_alias
                    && binding.pairing_epoch == device.pairing_epoch
                    && binding.device_signing_commitment == device.signing_commitment
                    && binding.device_agreement_commitment == device.agreement_commitment =>
            {
                Ok(Some(binding))
            }
            _ => Err(PairingCoordinatorError::Conflict),
        }
    }

    pub(crate) fn revoke_device(
        &self,
        device_alias: &str,
        expected_epoch: u64,
        now: OffsetDateTime,
    ) -> Result<RevokeOutcome, PairingCoordinatorError> {
        let gate = self.gate.lock()?;
        self.revoke_device_locked(&gate, device_alias, expected_epoch, now)
    }

    pub(crate) fn revoke_device_locked(
        &self,
        guard: &DeviceCommandGuard<'_>,
        device_alias: &str,
        expected_epoch: u64,
        now: OffsetDateTime,
    ) -> Result<RevokeOutcome, PairingCoordinatorError> {
        if !std::ptr::eq(guard.owner, self.gate.as_ref()) {
            return Err(PairingCoordinatorError::Conflict);
        }
        let snapshot = {
            let mut sessions = self.sessions()?;
            let session = sessions
                .values()
                .find(|session| {
                    matches!(session.state, JoinState::Active | JoinState::Revoked)
                        && session.pending.as_ref().is_some_and(|pending| {
                            pending.device.device_alias == device_alias
                                && pending.device.pairing_epoch == expected_epoch
                        })
                })
                .ok_or(PairingCoordinatorError::Invalid)?;
            let pending = session
                .pending
                .as_ref()
                .ok_or(PairingCoordinatorError::Storage)?;
            if pending.device.device_alias != device_alias
                || pending.device.pairing_epoch != expected_epoch
            {
                return Err(PairingCoordinatorError::Conflict);
            }
            let snapshot = (
                session.join_id.clone(),
                pending.mailbox_id.clone(),
                pending.host_bearer.clone(),
            );
            let intent = sessions
                .get_mut(&snapshot.0)
                .ok_or(PairingCoordinatorError::Storage)?;
            intent.state = JoinState::Revoked;
            intent.authority_cleanup_needed = true;
            intent.relay_cleanup_needed = true;
            intent.terminal_device_alias = Some(device_alias.to_owned());
            intent.clear_capabilities();
            if let Some(pending) = intent.pending.as_mut() {
                pending.signed_bundle = None;
            }
            self.persist_sessions(&sessions)?;
            snapshot
        };
        let outcome = self.authority.revoke(device_alias, expected_epoch, now)?;
        let cleanup_failed = self.relay.revoke(&snapshot.1, &snapshot.2).is_err();
        let mut sessions = self.sessions()?;
        let session = sessions
            .get_mut(&snapshot.0)
            .ok_or(PairingCoordinatorError::Storage)?;
        session.authority_cleanup_needed = false;
        session.relay_cleanup_needed = cleanup_failed;
        session.terminal_device_alias = Some(device_alias.to_owned());
        session.revoked_epoch = Some(match outcome {
            RevokeOutcome::Revoked { revoked_epoch, .. }
            | RevokeOutcome::AlreadyRevoked { revoked_epoch } => revoked_epoch,
        });
        session.clear_capabilities();
        if let Some(pending) = session.pending.as_mut() {
            pending.signed_bundle = None;
        }
        self.persist_sessions(&sessions)?;
        Ok(outcome)
    }

    pub(crate) fn recover_pending_on_startup(
        &self,
        now: OffsetDateTime,
    ) -> Result<usize, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let pending: Vec<_> = {
            let sessions = self.sessions()?;
            sessions
                .values()
                .filter(|session| {
                    matches!(
                        session.state,
                        JoinState::Prepared
                            | JoinState::AuthorityActive
                            | JoinState::ProvisionedPendingVault
                    )
                })
                .filter_map(|session| {
                    session.pending.as_ref().map(|pending| {
                        (
                            session.join_id.clone(),
                            pending.device.clone(),
                            pending.mailbox_id.clone(),
                            pending.host_bearer.clone(),
                        )
                    })
                })
                .collect()
        };
        for (join_id, device, mailbox_id, host_bearer) in &pending {
            let current = self.authority.current_active()?;
            let candidate_was_active = matches!(
                current,
                CurrentActiveDevice::Active(ref active)
                    if active.device_alias == device.device_alias
                        && active.pairing_epoch == device.pairing_epoch
            );
            let replacement_prior = self
                .sessions()?
                .get(join_id)
                .and_then(|session| session.replacement_prior_join_id.clone());
            if candidate_was_active {
                self.compensate_candidate(
                    join_id,
                    device,
                    mailbox_id,
                    host_bearer,
                    now,
                    JoinState::Compensated,
                )?;
            } else {
                let cleanup_failed = if matches!(
                    self.sessions()?.get(join_id).map(|session| session.state),
                    Some(JoinState::Prepared)
                ) {
                    false
                } else {
                    self.relay.revoke(mailbox_id, host_bearer).is_err()
                };
                let mut sessions = self.sessions()?;
                let session = sessions
                    .get_mut(join_id)
                    .ok_or(PairingCoordinatorError::Storage)?;
                session.state = JoinState::Compensated;
                session.authority_cleanup_needed = false;
                session.relay_cleanup_needed = cleanup_failed;
                session.clear_capabilities();
                if let Some(pending) = session.pending.as_mut() {
                    pending.signed_bundle = None;
                }
                self.persist_sessions(&sessions)?;
            }
            if candidate_was_active {
                let Some(prior_join_id) = replacement_prior else {
                    continue;
                };
                let mut sessions = self.sessions()?;
                if let Some(prior) = sessions.get_mut(&prior_join_id) {
                    prior.state = JoinState::Revoked;
                    prior.authority_cleanup_needed = false;
                    prior.relay_cleanup_needed = true;
                    prior.terminal_device_alias = prior
                        .pending
                        .as_ref()
                        .map(|binding| binding.device.device_alias.clone());
                    prior.revoked_epoch = Some(device.pairing_epoch);
                    prior.clear_capabilities();
                    if let Some(binding) = prior.pending.as_mut() {
                        binding.signed_bundle = None;
                    }
                    self.persist_sessions(&sessions)?;
                }
            }
        }
        self.retry_cleanup_locked()?;
        Ok(pending.len())
    }

    pub(crate) fn retry_cleanup(&self) -> Result<usize, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        self.retry_cleanup_locked()
    }

    fn retry_cleanup_locked(&self) -> Result<usize, PairingCoordinatorError> {
        let authority_candidates: Vec<_> = self
            .sessions()?
            .values()
            .filter(|session| session.authority_cleanup_needed)
            .filter_map(|session| {
                session.pending.as_ref().map(|pending| {
                    (
                        session.join_id.clone(),
                        pending.device.device_alias.clone(),
                        pending.device.pairing_epoch,
                    )
                })
            })
            .collect();
        let mut cleaned = 0;
        for (join_id, device_alias, pairing_epoch) in authority_candidates {
            if self
                .authority
                .revoke(&device_alias, pairing_epoch, OffsetDateTime::now_utc())
                .is_ok()
            {
                let mut sessions = self.sessions()?;
                let session = sessions
                    .get_mut(&join_id)
                    .ok_or(PairingCoordinatorError::Storage)?;
                session.authority_cleanup_needed = false;
                self.persist_sessions(&sessions)?;
                cleaned += 1;
            }
        }
        let relay_candidates: Vec<_> = self
            .sessions()?
            .values()
            .filter(|session| session.relay_cleanup_needed)
            .filter_map(|session| {
                session.pending.as_ref().map(|pending| {
                    (
                        session.join_id.clone(),
                        pending.mailbox_id.clone(),
                        pending.host_bearer.clone(),
                    )
                })
            })
            .collect();
        for (join_id, mailbox_id, host_bearer) in relay_candidates {
            if self.relay.revoke(&mailbox_id, &host_bearer).is_ok() {
                let mut sessions = self.sessions()?;
                let session = sessions
                    .get_mut(&join_id)
                    .ok_or(PairingCoordinatorError::Storage)?;
                session.relay_cleanup_needed = false;
                self.persist_sessions(&sessions)?;
                cleaned += 1;
            }
        }
        Ok(cleaned)
    }

    /// E2 calls this during startup before enabling remote command admission.
    pub(crate) fn recover_expired_pending(
        &self,
        now: OffsetDateTime,
    ) -> Result<usize, PairingCoordinatorError> {
        let _gate = self.gate.lock()?;
        let expired: Vec<_> = {
            let sessions = self.sessions()?;
            sessions
                .values()
                .filter(|session| {
                    session.state == JoinState::ProvisionedPendingVault
                        && now.unix_timestamp() > session.expires_at_unix
                })
                .filter_map(|session| {
                    session.pending.as_ref().map(|pending| {
                        (
                            session.join_id.clone(),
                            pending.device.clone(),
                            pending.mailbox_id.clone(),
                            pending.host_bearer.clone(),
                        )
                    })
                })
                .collect()
        };
        for (join_id, device, mailbox_id, host_bearer) in &expired {
            self.compensate_candidate(
                join_id,
                device,
                mailbox_id,
                host_bearer,
                now,
                JoinState::ExpiredCompensated,
            )?;
        }
        Ok(expired.len())
    }

    fn compensate_candidate(
        &self,
        join_id: &str,
        device: &AuthenticatedDeviceFact,
        mailbox_id: &str,
        host_bearer: &str,
        now: OffsetDateTime,
        terminal_state: JoinState,
    ) -> Result<(), PairingCoordinatorError> {
        let authority_result =
            self.authority
                .revoke(&device.device_alias, device.pairing_epoch, now);
        let cleanup_failed = self.relay.revoke(mailbox_id, host_bearer).is_err();
        let mut sessions = self.sessions()?;
        let session = sessions
            .get_mut(join_id)
            .ok_or(PairingCoordinatorError::Storage)?;
        session.state = terminal_state;
        session.authority_cleanup_needed = authority_result.is_err();
        session.relay_cleanup_needed = cleanup_failed;
        session.terminal_device_alias = Some(device.device_alias.clone());
        session.revoked_epoch = match authority_result {
            Ok(RevokeOutcome::Revoked { revoked_epoch, .. })
            | Ok(RevokeOutcome::AlreadyRevoked { revoked_epoch }) => Some(revoked_epoch),
            Err(_) => None,
        };
        session.join_secret_digest = None;
        session.challenge_bytes = None;
        session.device_signing_public_sec1 = None;
        session.device_agreement_public_sec1 = None;
        if let Some(pending) = session.pending.as_mut() {
            pending.signed_bundle = None;
        }
        self.persist_sessions(&sessions)?;
        authority_result.map(|_| ()).map_err(Into::into)
    }

    fn build_signed_bundle(
        &self,
        device: &AuthenticatedDeviceFact,
        mailbox_id: &str,
        device_agreement_public_sec1: &[u8],
        device_bearer: &str,
        now: OffsetDateTime,
    ) -> Result<SignedProvisioningBundle, PairingCoordinatorError> {
        let shared = self
            .identity
            .derive_agreement_shared(device_agreement_public_sec1)?;
        let mut vault_key = Zeroizing::new([0_u8; 32]);
        let mut info = Vec::from(VAULT_KEY_PREFIX);
        info.extend_from_slice(mailbox_id.as_bytes());
        info.push(b'\n');
        info.extend_from_slice(device.pairing_epoch.to_string().as_bytes());
        Hkdf::<Sha256>::new(None, shared.as_ref())
            .expand(&info, vault_key.as_mut())
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        info.zeroize();
        let nonce = random_array::<WRAP_NONCE_BYTES>()?;
        let cipher = Aes256Gcm::new_from_slice(vault_key.as_ref())
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        let wrapped = cipher
            .encrypt(Nonce::from_slice(&nonce), device_bearer.as_bytes())
            .map_err(|_| PairingCoordinatorError::Crypto)?;
        let issued_at = format_unix_seconds(now.unix_timestamp())?;
        let bundle = ProvisioningBundle {
            schema: "nomad.m3e.provisioning-bundle.v1".to_owned(),
            device_alias: device.device_alias.clone(),
            pairing_epoch: device.pairing_epoch,
            mailbox_id: mailbox_id.to_owned(),
            relay_base_url: self.relay_base_url.clone(),
            host_signing_public_key_sec1: URL_SAFE_NO_PAD
                .encode(self.identity.signing_public_sec1()),
            host_agreement_public_key_sec1: URL_SAFE_NO_PAD
                .encode(self.identity.agreement_public_sec1()),
            wrapped_device_bearer: URL_SAFE_NO_PAD.encode(wrapped),
            wrap_nonce: URL_SAFE_NO_PAD.encode(nonce),
            issued_at,
        };
        let canonical = canonical_json(
            &serde_json::to_value(&bundle).map_err(|_| PairingCoordinatorError::Storage)?,
        )?;
        let signature = self.identity.sign_p1363(canonical.as_bytes())?;
        Ok(SignedProvisioningBundle {
            schema: "nomad.m3e.signed-provisioning-bundle.v1".to_owned(),
            bundle,
            provisioning_signature_p1363: URL_SAFE_NO_PAD.encode(signature),
        })
    }

    fn sessions(&self) -> Result<HashMap<String, JoinSession>, PairingCoordinatorError> {
        self.store.load_all()
    }

    fn persist_sessions(
        &self,
        sessions: &HashMap<String, JoinSession>,
    ) -> Result<(), PairingCoordinatorError> {
        self.store.replace_all(sessions)
    }
}

struct TranscriptInput<'a> {
    join_id: &'a str,
    challenge_id: &'a str,
    challenge_bytes: &'a [u8],
    prospective_epoch: u64,
    host_signing_public_sec1: &'a [u8],
    host_agreement_public_sec1: &'a [u8],
    device_signing_public_sec1: &'a [u8],
    device_agreement_public_sec1: &'a [u8],
}

fn transcript_hash(input: TranscriptInput<'_>) -> [u8; 32] {
    let mut transcript = Vec::from(PAIRING_PREFIX);
    for part in [
        input.join_id.as_bytes(),
        input.challenge_id.as_bytes(),
        hex_lower(&sha256(input.challenge_bytes)).as_bytes(),
        input.prospective_epoch.to_string().as_bytes(),
        hex_lower(&sha256(input.host_signing_public_sec1)).as_bytes(),
        hex_lower(&sha256(input.host_agreement_public_sec1)).as_bytes(),
        hex_lower(&sha256(input.device_signing_public_sec1)).as_bytes(),
        hex_lower(&sha256(input.device_agreement_public_sec1)).as_bytes(),
    ] {
        transcript.extend_from_slice(part);
        transcript.push(b'\n');
    }
    transcript.pop();
    sha256(&transcript)
}

fn comparison_code(transcript_hash: &[u8; 32]) -> String {
    let mut material = Vec::from(COMPARISON_PREFIX);
    material.extend_from_slice(transcript_hash);
    let digest = sha256(&material);
    let first_24_bits =
        (u32::from(digest[0]) << 16) | (u32::from(digest[1]) << 8) | u32::from(digest[2]);
    format!("{:06}", first_24_bits % 1_000_000)
}

fn verify_dual_proof(
    device_signing_public_sec1: &[u8],
    transcript_hash: &[u8; 32],
    signing_proof: &[u8],
    host_identity: &dyn HostPairingIdentity,
    device_agreement_public_sec1: &[u8],
    agreement_mac: &[u8],
) -> Result<(), PairingCoordinatorError> {
    let mut signing_material = Vec::from(SIGNING_PROOF_PREFIX);
    signing_material.extend_from_slice(transcript_hash);
    let signing_digest = sha256(&signing_material);
    verify_p1363(device_signing_public_sec1, &signing_digest, signing_proof)?;

    let shared = host_identity.derive_agreement_shared(device_agreement_public_sec1)?;
    let mut agreement_key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, shared.as_ref())
        .expand(AGREEMENT_PROOF_INFO, agreement_key.as_mut())
        .map_err(|_| PairingCoordinatorError::Crypto)?;
    let expected_mac = hmac_sha256(agreement_key.as_ref(), transcript_hash);
    if agreement_mac.len() != expected_mac.len() || !constant_time_eq(agreement_mac, &expected_mac)
    {
        return Err(PairingCoordinatorError::InvalidProof);
    }
    Ok(())
}

fn verify_p1363(
    signing_public_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PairingCoordinatorError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(signing_public_sec1)
        .map_err(|_| PairingCoordinatorError::Invalid)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| PairingCoordinatorError::InvalidProof)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| PairingCoordinatorError::InvalidProof)
}

fn composite_commitment(prefix: &[u8], first: &[u8; 32], second: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::from(prefix);
    material.extend_from_slice(first);
    material.extend_from_slice(second);
    sha256(&material)
}

fn authority_public_key_digest(public_key: &[u8]) -> [u8; 32] {
    sha256(&canonical(&[
        AUTHORITY_PUBLIC_KEY_DIGEST_VERSION,
        public_key,
    ]))
}

fn authority_device_alias(
    signing_commitment: &[u8; 32],
    agreement_commitment: &[u8; 32],
) -> String {
    let digest = sha256(&canonical(&[
        AUTHORITY_DEVICE_ALIAS_VERSION,
        b"device",
        signing_commitment,
        agreement_commitment,
    ]));
    format!("device-{}", &hex_lower(&digest)[..32])
}

fn active_from_session(
    session: &JoinSession,
    identity: &dyn HostPairingIdentity,
) -> Result<ActiveRemoteBinding, PairingCoordinatorError> {
    if session.state != JoinState::Active {
        return Err(PairingCoordinatorError::Conflict);
    }
    let pending = session
        .pending
        .as_ref()
        .ok_or(PairingCoordinatorError::Storage)?;
    Ok(ActiveRemoteBinding {
        device_alias: pending.device.device_alias.clone(),
        pairing_epoch: pending.device.pairing_epoch,
        mailbox_id: pending.mailbox_id.clone(),
        host_bearer: pending.host_bearer.clone(),
        host_signing_commitment: identity.signing_commitment(),
        host_agreement_commitment: identity.agreement_commitment(),
        device_signing_commitment: pending.device.signing_commitment,
        device_agreement_commitment: pending.device.agreement_commitment,
        device_signing_public_sec1: pending.device_signing_public_sec1,
        device_agreement_public_sec1: pending.device_agreement_public_sec1,
    })
}

fn session_by_cookie_mut<'a>(
    sessions: &'a mut HashMap<String, JoinSession>,
    cookie_digest: &[u8; 32],
) -> Result<&'a mut JoinSession, PairingCoordinatorError> {
    sessions
        .values_mut()
        .find(|session| {
            session
                .cookie_digest
                .as_ref()
                .is_some_and(|digest| constant_time_eq(digest, cookie_digest))
        })
        .ok_or(PairingCoordinatorError::Invalid)
}

fn expired_pending_snapshot(
    session: &JoinSession,
    now_unix: i64,
) -> Option<(String, AuthenticatedDeviceFact, String, Zeroizing<String>)> {
    if session.state != JoinState::ProvisionedPendingVault || now_unix <= session.expires_at_unix {
        return None;
    }
    session.pending.as_ref().map(|pending| {
        (
            session.join_id.clone(),
            pending.device.clone(),
            pending.mailbox_id.clone(),
            pending.host_bearer.clone(),
        )
    })
}

fn expire_if_needed(session: &mut JoinSession, now_unix: i64) {
    if now_unix > session.expires_at_unix
        && matches!(
            session.state,
            JoinState::Created
                | JoinState::StartedAwaitingDesktopApproval
                | JoinState::DesktopApproved
        )
    {
        session.state = JoinState::Expired;
        session.join_secret_digest = None;
        session.clear_capabilities();
    }
}

fn join_state_text(state: JoinState) -> &'static str {
    match state {
        JoinState::Created => "created",
        JoinState::StartedAwaitingDesktopApproval => "started_awaiting_desktop_approval",
        JoinState::DesktopApproved => "desktop_approved",
        JoinState::Prepared | JoinState::AuthorityActive => "desktop_approved",
        JoinState::ProvisionedPendingVault => "provisioned_pending_vault",
        JoinState::Active => "active",
        JoinState::Cancelled => "cancelled",
        JoinState::Expired => "expired",
        JoinState::Compensated => "compensated",
        JoinState::ExpiredCompensated => "expired",
        JoinState::Revoked => "revoked",
    }
}

fn parse_public(raw: &[u8]) -> Result<Vec<u8>, PairingCoordinatorError> {
    if raw.len() != 65 || raw.first() != Some(&4) {
        return Err(PairingCoordinatorError::Invalid);
    }
    let point = PublicKey::from_sec1_bytes(raw).map_err(|_| PairingCoordinatorError::Invalid)?;
    Ok(point.to_encoded_point(false).as_bytes().to_vec())
}

fn decode_base64_exact<const N: usize>(value: &str) -> Result<[u8; N], PairingCoordinatorError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PairingCoordinatorError::Storage)?;
    decoded
        .try_into()
        .map_err(|_| PairingCoordinatorError::Storage)
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], PairingCoordinatorError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PairingCoordinatorError::Storage);
    }
    let mut decoded = [0_u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Ok(decoded)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, PairingCoordinatorError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PairingCoordinatorError::Storage),
    }
}

fn prepare_store_path(path: &Path) -> Result<PathBuf, PairingCoordinatorError> {
    validate_store_path_shape(path)?;
    let parent = path.parent().ok_or(PairingCoordinatorError::Storage)?;
    validate_private_parent(parent)?;
    create_private_file(path)?;
    create_private_file(&sidecar_path(path, b".lock"))?;
    validate_store_path(path)?;
    Ok(path.to_path_buf())
}

fn create_private_file(path: &Path) -> Result<(), PairingCoordinatorError> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            validate_private_file_metadata(
                &file
                    .metadata()
                    .map_err(|_| PairingCoordinatorError::Storage)?,
            )?;
            file.sync_all()
                .map_err(|_| PairingCoordinatorError::Storage)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(PairingCoordinatorError::Storage),
    }
    validate_private_file_metadata(
        &fs::symlink_metadata(path).map_err(|_| PairingCoordinatorError::Storage)?,
    )
}

fn validate_store_path_shape(path: &Path) -> Result<(), PairingCoordinatorError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || path.file_name().and_then(|name| name.to_str()) != Some("pairing-coordinator.sqlite3")
    {
        return Err(PairingCoordinatorError::Storage);
    }
    Ok(())
}

fn validate_private_parent(parent: &Path) -> Result<(), PairingCoordinatorError> {
    let metadata = fs::symlink_metadata(parent).map_err(|_| PairingCoordinatorError::Storage)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.mode() & 0o777 != 0o700
        || fs::canonicalize(parent).map_err(|_| PairingCoordinatorError::Storage)? != parent
    {
        return Err(PairingCoordinatorError::Storage);
    }
    Ok(())
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), PairingCoordinatorError> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(PairingCoordinatorError::Storage);
    }
    Ok(())
}

fn private_file_identity(path: &Path) -> Result<(u64, u64), PairingCoordinatorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PairingCoordinatorError::Storage)?;
    validate_private_file_metadata(&metadata)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn directory_identity(path: &Path) -> Result<(u64, u64), PairingCoordinatorError> {
    validate_private_parent(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| PairingCoordinatorError::Storage)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn validate_optional_private_file(path: &Path) -> Result<(), PairingCoordinatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_file_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PairingCoordinatorError::Storage),
    }
}

fn secure_optional_sidecar(path: &Path) -> Result<(), PairingCoordinatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != current_euid()
                || metadata.nlink() != 1
            {
                return Err(PairingCoordinatorError::Storage);
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| PairingCoordinatorError::Storage)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PairingCoordinatorError::Storage),
    }
}

fn sidecar_path(path: &Path, suffix: &[u8]) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(suffix);
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn validate_store_path(path: &Path) -> Result<(), PairingCoordinatorError> {
    validate_store_path_shape(path)?;
    validate_private_parent(path.parent().ok_or(PairingCoordinatorError::Storage)?)?;
    validate_private_file_metadata(
        &fs::symlink_metadata(path).map_err(|_| PairingCoordinatorError::Storage)?,
    )
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no arguments and no side effects.
    unsafe { libc::geteuid() }
}

fn validate_sessions(
    sessions: &HashMap<String, JoinSession>,
) -> Result<(), PairingCoordinatorError> {
    let active_count = sessions
        .values()
        .filter(|session| session.state == JoinState::Active)
        .count();
    if active_count > 1 {
        return Err(PairingCoordinatorError::Storage);
    }
    for (key, session) in sessions {
        if key != &session.join_id {
            return Err(PairingCoordinatorError::Storage);
        }
        validate_session(session)?;
    }
    Ok(())
}

fn validate_session(session: &JoinSession) -> Result<(), PairingCoordinatorError> {
    if session.created_at_unix <= 0
        || session.expires_at_unix <= session.created_at_unix
        || !session.join_id.starts_with("join-")
        || session.join_id.len() != 37
        || !session.join_id[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PairingCoordinatorError::Storage);
    }
    if matches!(
        session.state,
        JoinState::Prepared
            | JoinState::AuthorityActive
            | JoinState::ProvisionedPendingVault
            | JoinState::Active
            | JoinState::Revoked
    ) && session.pending.is_none()
    {
        return Err(PairingCoordinatorError::Storage);
    }
    if let Some(pending) = &session.pending {
        if pending.device.pairing_epoch == 0
            || !pending.mailbox_id.starts_with("mbx-")
            || pending.mailbox_id.len() != 68
            || pending.host_bearer.is_empty()
            || parse_public(&pending.device_signing_public_sec1).is_err()
            || parse_public(&pending.device_agreement_public_sec1).is_err()
            || authority_public_key_digest(&pending.device_signing_public_sec1)
                != pending.device.signing_commitment
            || authority_public_key_digest(&pending.device_agreement_public_sec1)
                != pending.device.agreement_commitment
            || authority_device_alias(
                &pending.device.signing_commitment,
                &pending.device.agreement_commitment,
            ) != pending.device.device_alias
        {
            return Err(PairingCoordinatorError::Storage);
        }
    }
    Ok(())
}

fn random_prefixed_hex(prefix: &str, bytes: usize) -> Result<String, PairingCoordinatorError> {
    let mut random = Zeroizing::new(vec![0_u8; bytes]);
    getrandom(random.as_mut_slice()).map_err(|_| PairingCoordinatorError::Crypto)?;
    Ok(format!("{prefix}{}", hex_lower(random.as_slice())))
}

fn random_base64(bytes: usize) -> Result<Zeroizing<String>, PairingCoordinatorError> {
    let mut random = Zeroizing::new(vec![0_u8; bytes]);
    getrandom(random.as_mut_slice()).map_err(|_| PairingCoordinatorError::Crypto)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice())))
}

fn random_array<const N: usize>() -> Result<[u8; N], PairingCoordinatorError> {
    let mut random = [0_u8; N];
    getrandom(&mut random).map_err(|_| PairingCoordinatorError::Crypto)?;
    Ok(random)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn format_unix_seconds(timestamp: i64) -> Result<String, PairingCoordinatorError> {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|_| PairingCoordinatorError::Invalid)?
        .format(&Rfc3339)
        .map_err(|_| PairingCoordinatorError::Invalid)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_json(value: &serde_json::Value) -> Result<String, PairingCoordinatorError> {
    fn write(
        value: &serde_json::Value,
        output: &mut String,
    ) -> Result<(), PairingCoordinatorError> {
        match value {
            serde_json::Value::Null => output.push_str("null"),
            serde_json::Value::Bool(value) => {
                output.push_str(if *value { "true" } else { "false" })
            }
            serde_json::Value::Number(value) => output.push_str(&value.to_string()),
            serde_json::Value::String(value) => output.push_str(
                &serde_json::to_string(value).map_err(|_| PairingCoordinatorError::Storage)?,
            ),
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(value, output)?;
                }
                output.push(']');
            }
            serde_json::Value::Object(values) => {
                output.push('{');
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(
                        &serde_json::to_string(key)
                            .map_err(|_| PairingCoordinatorError::Storage)?,
                    );
                    output.push(':');
                    write(&values[key], output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }

    let mut output = String::new();
    write(value, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdh::diffie_hellman,
        ecdsa::{signature::Signer, SigningKey},
        SecretKey,
    };
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestIdentity {
        signing: SigningKey,
        agreement: SecretKey,
    }

    impl TestIdentity {
        fn new() -> Self {
            Self {
                signing: SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap(),
                agreement: SecretKey::from_slice(&[8_u8; 32]).unwrap(),
            }
        }
    }

    impl HostPairingIdentity for TestIdentity {
        fn signing_public_sec1(&self) -> [u8; 65] {
            self.signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        fn agreement_public_sec1(&self) -> [u8; 65] {
            self.agreement
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        fn signing_commitment(&self) -> [u8; 32] {
            sha256(&self.signing_public_sec1())
        }

        fn agreement_commitment(&self) -> [u8; 32] {
            sha256(&self.agreement_public_sec1())
        }

        fn sign_p1363(&self, message: &[u8]) -> Result<[u8; 64], PairingCoordinatorError> {
            let signature: Signature = self.signing.sign(message);
            Ok(signature.to_bytes().into())
        }

        fn derive_agreement_shared(
            &self,
            peer_public_sec1: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>, PairingCoordinatorError> {
            let peer = PublicKey::from_sec1_bytes(peer_public_sec1)
                .map_err(|_| PairingCoordinatorError::Invalid)?;
            let shared = diffie_hellman(self.agreement.to_nonzero_scalar(), peer.as_affine());
            let shared_bytes: [u8; 32] = shared
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| PairingCoordinatorError::Crypto)?;
            Ok(Zeroizing::new(shared_bytes))
        }
    }

    #[derive(Default)]
    struct TestRelay {
        fail_provision: bool,
        fail_revoke: AtomicBool,
        panic_on_provision: AtomicBool,
        provisions: Mutex<Vec<RelayProvisionRequest>>,
        revocations: Mutex<Vec<String>>,
    }

    impl RelayProvisioner for TestRelay {
        fn provision(
            &self,
            request: &RelayProvisionRequest,
        ) -> Result<(), PairingCoordinatorError> {
            self.provisions.lock().unwrap().push(request.clone());
            assert!(
                !self.panic_on_provision.load(Ordering::SeqCst),
                "injected crash before Relay provision"
            );
            if self.fail_provision {
                Err(PairingCoordinatorError::Relay)
            } else {
                Ok(())
            }
        }

        fn revoke(
            &self,
            mailbox_id: &str,
            _host_bearer: &str,
        ) -> Result<(), PairingCoordinatorError> {
            self.revocations.lock().unwrap().push(mailbox_id.to_owned());
            if self.fail_revoke.load(Ordering::SeqCst) {
                Err(PairingCoordinatorError::Relay)
            } else {
                Ok(())
            }
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        coordinator: PairingCoordinator,
        identity: Arc<TestIdentity>,
        relay: Arc<TestRelay>,
        device_signing: SigningKey,
        device_agreement: SecretKey,
        now: OffsetDateTime,
    }

    fn fixture(fail_provision: bool) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let state = root_path.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
        let authority = DeviceAuthority::open(&state.join("host-device-registry.sqlite3")).unwrap();
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay {
            fail_provision,
            fail_revoke: AtomicBool::new(false),
            panic_on_provision: AtomicBool::new(false),
            ..TestRelay::default()
        });
        let coordinator = PairingCoordinator::new(
            Arc::new(DeviceCommandGate::new()),
            authority,
            identity.clone(),
            relay.clone(),
            Arc::new(MemoryJoinSessionStore::default()),
            "https://relay.example/v2".to_owned(),
        )
        .unwrap();
        Fixture {
            _root: root,
            coordinator,
            identity,
            relay,
            device_signing: SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap(),
            device_agreement: SecretKey::from_slice(&[10_u8; 32]).unwrap(),
            now: OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap(),
        }
    }

    fn signing_public(key: &SigningKey) -> [u8; 65] {
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn agreement_public(key: &SecretKey) -> [u8; 65] {
        key.public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn start(fixture: &Fixture) -> (CreatedJoin, StartedJoin) {
        let created = fixture.coordinator.create_join(fixture.now).unwrap();
        let started = fixture
            .coordinator
            .start_join(
                &created.join_id,
                &created.join_secret,
                &signing_public(&fixture.device_signing),
                &agreement_public(&fixture.device_agreement),
                fixture.now,
            )
            .unwrap();
        (created, started)
    }

    fn proofs(
        fixture: &Fixture,
        created: &CreatedJoin,
        started: &StartedJoin,
    ) -> ([u8; 64], [u8; 32]) {
        let transcript = transcript_hash(TranscriptInput {
            join_id: &created.join_id,
            challenge_id: &started.challenge_id,
            challenge_bytes: &started.challenge_bytes,
            prospective_epoch: started.prospective_epoch,
            host_signing_public_sec1: &fixture.identity.signing_public_sec1(),
            host_agreement_public_sec1: &fixture.identity.agreement_public_sec1(),
            device_signing_public_sec1: &signing_public(&fixture.device_signing),
            device_agreement_public_sec1: &agreement_public(&fixture.device_agreement),
        });
        let mut signing_material = Vec::from(SIGNING_PROOF_PREFIX);
        signing_material.extend_from_slice(&transcript);
        let signature: Signature = fixture.device_signing.sign(&sha256(&signing_material));
        let shared = diffie_hellman(
            fixture.device_agreement.to_nonzero_scalar(),
            PublicKey::from_sec1_bytes(&fixture.identity.agreement_public_sec1())
                .unwrap()
                .as_affine(),
        );
        let mut agreement_key = [0_u8; 32];
        Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_slice())
            .expand(AGREEMENT_PROOF_INFO, &mut agreement_key)
            .unwrap();
        (
            signature.to_bytes().into(),
            hmac_sha256(&agreement_key, &transcript),
        )
    }

    fn approve_and_confirm(
        fixture: &Fixture,
        created: &CreatedJoin,
        started: &StartedJoin,
    ) -> SignedProvisioningBundle {
        fixture
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                fixture.now,
            )
            .unwrap();
        let (signature, agreement_mac) = proofs(fixture, created, started);
        fixture
            .coordinator
            .confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &agreement_mac,
                fixture.now,
            )
            .unwrap()
    }

    fn vault_signature(fixture: &Fixture, bundle: &SignedProvisioningBundle) -> [u8; 64] {
        let canonical = canonical_json(&serde_json::to_value(bundle).unwrap()).unwrap();
        let mut material = Vec::from(VAULT_COMMIT_PREFIX);
        material.extend_from_slice(&sha256(canonical.as_bytes()));
        let signature: Signature = fixture.device_signing.sign(&sha256(&material));
        signature.to_bytes().into()
    }

    #[test]
    fn transcript_and_comparison_match_frozen_byte_contract() {
        let transcript = transcript_hash(TranscriptInput {
            join_id: "join-0123456789abcdef0123456789abcdef",
            challenge_id: "challenge-0123456789abcdef0123456789abcdef",
            challenge_bytes: &[0x11; 32],
            prospective_epoch: 7,
            host_signing_public_sec1: &signing_public(
                &SigningKey::from_bytes((&[1; 32]).into()).unwrap(),
            ),
            host_agreement_public_sec1: &agreement_public(
                &SecretKey::from_slice(&[2; 32]).unwrap(),
            ),
            device_signing_public_sec1: &signing_public(
                &SigningKey::from_bytes((&[3; 32]).into()).unwrap(),
            ),
            device_agreement_public_sec1: &agreement_public(
                &SecretKey::from_slice(&[4; 32]).unwrap(),
            ),
        });
        // Independently cross-checked against the browser WebCrypto implementation.
        assert_eq!(
            hex_lower(&transcript),
            "4d18112dcc6d37ebd2651ba67f9e5f51069c4463f3eea536e3fd10d1e407750b"
        );
        assert_eq!(comparison_code(&transcript), "635419");
    }

    #[test]
    fn join_secret_and_cookie_are_one_shot_and_ttl_bounded() {
        let fixture = fixture(false);
        let (created, started) = start(&fixture);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&*created.join_secret).unwrap().len(),
            32
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&*started.cookie_capability)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(started.expires_at_unix - fixture.now.unix_timestamp(), 120);
        assert_eq!(
            fixture.coordinator.start_join(
                &created.join_id,
                &created.join_secret,
                &signing_public(&fixture.device_signing),
                &agreement_public(&fixture.device_agreement),
                fixture.now,
            ),
            Err(PairingCoordinatorError::Consumed)
        );
        let rendered = format!("{created:?} {started:?}");
        assert!(!rendered.contains(&*created.join_secret));
        assert!(!rendered.contains(&*started.cookie_capability));

        let fresh = fixture.coordinator.create_join(fixture.now).unwrap();
        assert_eq!(
            fixture.coordinator.start_join(
                &fresh.join_id,
                &fresh.join_secret,
                &signing_public(&fixture.device_signing),
                &agreement_public(&fixture.device_agreement),
                fixture.now + time::Duration::seconds(121),
            ),
            Err(PairingCoordinatorError::Expired)
        );
    }

    #[test]
    fn desktop_approval_and_each_dual_proof_are_required() {
        let fixture = fixture(false);
        let (created, started) = start(&fixture);
        let (signature, agreement_mac) = proofs(&fixture, &created, &started);
        assert_eq!(
            fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &agreement_mac,
                fixture.now,
            ),
            Err(PairingCoordinatorError::DesktopApprovalRequired)
        );
        fixture
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                fixture.now,
            )
            .unwrap();
        let mut bad_signature = signature;
        bad_signature[0] ^= 1;
        assert_eq!(
            fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &bad_signature,
                &agreement_mac,
                fixture.now
            ),
            Err(PairingCoordinatorError::InvalidProof)
        );
        let mut bad_mac = agreement_mac;
        bad_mac[0] ^= 1;
        assert_eq!(
            fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &bad_mac,
                fixture.now
            ),
            Err(PairingCoordinatorError::InvalidProof)
        );
    }

    #[test]
    fn provision_is_digest_only_pending_until_idempotent_vault_commit() {
        let fixture = fixture(false);
        let (created, started) = start(&fixture);
        let bundle = approve_and_confirm(&fixture, &created, &started);
        assert!(fixture.coordinator.active_binding().unwrap().is_none());
        let request = fixture.relay.provisions.lock().unwrap()[0].clone();
        assert_eq!(request.schema, "nomad.relay.mailbox-provision.v1");
        for digest in [
            &request.host_token_digest,
            &request.device_token_digest,
            &request.host_identity_commitment,
            &request.device_key_commitment,
        ] {
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }
        let signature = vault_signature(&fixture, &bundle);
        let first = fixture
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                fixture.now,
            )
            .unwrap();
        let retry = fixture
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                fixture.now,
            )
            .unwrap();
        assert_eq!(first.device_alias, retry.device_alias);
        let guard = fixture.coordinator.command_guard().unwrap();
        assert!(fixture
            .coordinator
            .active_binding_locked(&guard)
            .unwrap()
            .is_some());
    }

    #[test]
    fn provision_failure_compensates_authority_and_attempts_relay_delete() {
        let fixture = fixture(true);
        let (created, started) = start(&fixture);
        fixture
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                fixture.now,
            )
            .unwrap();
        let (signature, mac) = proofs(&fixture, &created, &started);
        assert_eq!(
            fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &mac,
                fixture.now
            ),
            Err(PairingCoordinatorError::Relay)
        );
        assert!(matches!(
            fixture.coordinator.authority.current_active().unwrap(),
            crate::device_authority::CurrentActiveDevice::Unpaired
        ));
        assert_eq!(fixture.relay.revocations.lock().unwrap().len(), 1);
    }

    #[test]
    fn abort_and_revoke_remove_eligibility_before_relay_cleanup() {
        let first = fixture(false);
        let (created, started) = start(&first);
        let _bundle = approve_and_confirm(&first, &created, &started);
        first
            .coordinator
            .abort_join(
                &started.cookie_capability,
                &AbortJoinRequest {
                    schema: "nomad.m3e.pairing.abort.v1".into(),
                    challenge_id: started.challenge_id.clone(),
                    expected_epoch: started.prospective_epoch,
                },
                first.now,
            )
            .unwrap();
        first
            .coordinator
            .abort_join(
                &started.cookie_capability,
                &AbortJoinRequest {
                    schema: "nomad.m3e.pairing.abort.v1".into(),
                    challenge_id: started.challenge_id.clone(),
                    expected_epoch: started.prospective_epoch,
                },
                first.now,
            )
            .unwrap();
        assert_eq!(first.relay.revocations.lock().unwrap().len(), 1);
        assert_eq!(
            first.coordinator.abort_join(
                &started.cookie_capability,
                &AbortJoinRequest {
                    schema: "nomad.m3e.pairing.abort.v1".into(),
                    challenge_id: started.challenge_id.clone(),
                    expected_epoch: started.prospective_epoch,
                },
                first.now + time::Duration::seconds(121),
            ),
            Err(PairingCoordinatorError::Expired)
        );
        assert!(first.coordinator.active_binding().unwrap().is_none());
        assert_eq!(first.relay.revocations.lock().unwrap().len(), 1);

        let second = fixture(false);
        let (created, started) = start(&second);
        let bundle = approve_and_confirm(&second, &created, &started);
        let signature = vault_signature(&second, &bundle);
        let active = second
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                second.now,
            )
            .unwrap();
        let outcome = second
            .coordinator
            .revoke_device(&active.device_alias, active.pairing_epoch, second.now)
            .unwrap();
        assert!(matches!(outcome, RevokeOutcome::Revoked { .. }));
        assert!(second.coordinator.active_binding().unwrap().is_none());
        assert!(matches!(
            second
                .coordinator
                .revoke_device(&active.device_alias, active.pairing_epoch, second.now)
                .unwrap(),
            RevokeOutcome::AlreadyRevoked { .. }
        ));
        assert_eq!(second.relay.revocations.lock().unwrap().len(), 2);
    }

    #[test]
    fn pending_expiry_compensates_from_confirm_complete_status_and_recovery() {
        for trigger in 0..4 {
            let fixture = fixture(false);
            let (created, started) = start(&fixture);
            let bundle = approve_and_confirm(&fixture, &created, &started);
            let expired = fixture.now + time::Duration::seconds(121);
            match trigger {
                0 => {
                    let (signature, mac) = proofs(&fixture, &created, &started);
                    assert_eq!(
                        fixture.coordinator.confirm_join(
                            &started.cookie_capability,
                            &started.challenge_id,
                            started.prospective_epoch,
                            &signature,
                            &mac,
                            expired
                        ),
                        Err(PairingCoordinatorError::Expired)
                    );
                }
                1 => {
                    let signature = vault_signature(&fixture, &bundle);
                    assert_eq!(
                        fixture.coordinator.complete_join(
                            &started.cookie_capability,
                            &started.challenge_id,
                            started.prospective_epoch,
                            &signature,
                            expired
                        ),
                        Err(PairingCoordinatorError::Expired)
                    );
                }
                2 => {
                    let status = fixture
                        .coordinator
                        .pairing_status(
                            &PairingStatusRequest {
                                schema: "nomad.m3e.pairing.status.v1".into(),
                                join_id: created.join_id.clone(),
                            },
                            expired,
                        )
                        .unwrap();
                    assert_eq!(status.state, "expired");
                }
                _ => assert_eq!(
                    fixture
                        .coordinator
                        .recover_expired_pending(expired)
                        .unwrap(),
                    1
                ),
            }
            assert!(matches!(
                fixture.coordinator.authority.current_active().unwrap(),
                crate::device_authority::CurrentActiveDevice::Unpaired
            ));
            assert!(fixture.coordinator.active_binding().unwrap().is_none());
            assert_eq!(fixture.relay.revocations.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn bundle_signature_and_wrapped_bearer_are_browser_compatible() {
        let fixture = fixture(false);
        let (created, started) = start(&fixture);
        let bundle = approve_and_confirm(&fixture, &created, &started);
        let canonical = canonical_json(&serde_json::to_value(&bundle.bundle).unwrap()).unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&bundle.provisioning_signature_p1363)
                .unwrap(),
        )
        .unwrap();
        fixture
            .identity
            .signing
            .verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .unwrap();

        let host_agreement =
            PublicKey::from_sec1_bytes(&fixture.identity.agreement_public_sec1()).unwrap();
        let shared = diffie_hellman(
            fixture.device_agreement.to_nonzero_scalar(),
            host_agreement.as_affine(),
        );
        let mut key = [0_u8; 32];
        let info = format!(
            "nomad.m3e.browser-vault.v1\n{}\n{}",
            bundle.bundle.mailbox_id, bundle.bundle.pairing_epoch
        );
        Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_slice())
            .expand(info.as_bytes(), &mut key)
            .unwrap();
        let plaintext = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&URL_SAFE_NO_PAD.decode(&bundle.bundle.wrap_nonce).unwrap()),
                URL_SAFE_NO_PAD
                    .decode(&bundle.bundle.wrapped_device_bearer)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(plaintext).unwrap().len(), 32);
    }

    #[test]
    fn relay_url_and_secret_debug_are_strict() {
        for invalid in [
            "http://relay.example/v2",
            "https://user@relay.example/v2",
            "https://relay.example/v2?q=1",
            "https:///v2",
        ] {
            let fixture = fixture(false);
            assert_eq!(
                PairingCoordinator::new(
                    fixture.coordinator.gate.clone(),
                    fixture.coordinator.authority.clone(),
                    fixture.identity.clone(),
                    fixture.relay.clone(),
                    fixture.coordinator.store.clone(),
                    invalid.into()
                )
                .unwrap_err(),
                PairingCoordinatorError::Invalid
            );
        }
        let request = RelayProvisionRequest {
            schema: "nomad.relay.mailbox-provision.v1".into(),
            mailbox_id: "mbx-secret".into(),
            epoch: 1,
            host_token_digest: "host-secret".into(),
            device_token_digest: "device-secret".into(),
            host_identity_commitment: "host-commitment-secret".into(),
            device_key_commitment: "device-commitment-secret".into(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("host-secret"));
        assert!(!debug.contains("device-secret"));
        assert!(!debug.contains("commitment-secret"));
    }

    #[test]
    fn create_after_pending_expiry_compensates_before_new_join() {
        let fixture = fixture(false);
        let (created, started) = start(&fixture);
        let _bundle = approve_and_confirm(&fixture, &created, &started);
        assert_eq!(
            fixture.coordinator.create_join(fixture.now),
            Err(PairingCoordinatorError::Conflict)
        );
        let replacement = fixture
            .coordinator
            .create_join(fixture.now + time::Duration::seconds(121))
            .unwrap();
        assert_ne!(replacement.join_id, created.join_id);
        assert!(matches!(
            fixture.coordinator.authority.current_active().unwrap(),
            crate::device_authority::CurrentActiveDevice::Unpaired
        ));
        assert_eq!(fixture.relay.revocations.lock().unwrap().len(), 1);
    }

    #[test]
    fn shared_gate_serializes_and_rejects_foreign_guard() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let gate = Arc::new(DeviceCommandGate::new());
        let held = gate.lock().unwrap();
        let worker_gate = gate.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _guard = worker_gate.lock().unwrap();
            entered_tx.send(()).unwrap();
        });
        assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(held);
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();

        let first = fixture(false);
        let second = fixture(false);
        assert!(Arc::ptr_eq(
            &first.coordinator.device_command_gate(),
            &first.coordinator.gate
        ));
        let foreign = first.coordinator.command_guard().unwrap();
        assert_eq!(
            second.coordinator.active_binding_locked(&foreign),
            Err(PairingCoordinatorError::Conflict)
        );
    }

    #[test]
    fn status_and_internal_wrapper_shapes_are_exact() {
        let fixture = fixture(false);
        let created = fixture.coordinator.create_join(fixture.now).unwrap();
        let status = fixture
            .coordinator
            .pairing_status(
                &PairingStatusRequest {
                    schema: "nomad.m3e.pairing.status.v1".into(),
                    join_id: created.join_id,
                },
                fixture.now,
            )
            .unwrap();
        let status_json = serde_json::to_value(status).unwrap();
        assert!(status_json.get("expected_epoch").is_some());
        assert!(status_json.get("prospective_epoch").is_none());

        for schema in [
            INTERNAL_START_SCHEMA,
            INTERNAL_CONFIRM_SCHEMA,
            INTERNAL_COMPLETE_SCHEMA,
            INTERNAL_ABORT_SCHEMA,
        ] {
            assert!(schema.starts_with("nomad.m3e.internal."));
        }
        assert_eq!(
            format_unix_seconds(1_788_000_000).unwrap(),
            "2026-08-29T10:40:00Z"
        );
    }

    fn durable_paths(root: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let canonical_root = root.path().canonicalize().unwrap();
        let state = canonical_root.join("durable");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
        (
            state.join("pairing-coordinator.sqlite3"),
            state.join("host-device-registry.sqlite3"),
        )
    }

    fn durable_coordinator(
        db_path: &Path,
        authority_path: &Path,
        identity: Arc<TestIdentity>,
        relay: Arc<TestRelay>,
        recover: bool,
        now: OffsetDateTime,
    ) -> PairingCoordinator {
        let store: Arc<dyn JoinSessionStore> =
            Arc::new(SqliteJoinSessionStore::open(db_path, identity.as_ref()).unwrap());
        let args = (
            Arc::new(DeviceCommandGate::new()),
            DeviceAuthority::open(authority_path).unwrap(),
            identity,
            relay,
            store,
            "https://relay.example/v2".to_owned(),
        );
        if recover {
            PairingCoordinator::new_with_startup_recovery(
                args.0, args.1, args.2, args.3, args.4, args.5, now,
            )
            .unwrap()
        } else {
            PairingCoordinator::new(args.0, args.1, args.2, args.3, args.4, args.5).unwrap()
        }
    }

    #[test]
    fn durable_store_reopens_active_binding_without_plaintext_secrets() {
        let root = tempfile::tempdir().unwrap();
        let (db_path, authority_path) = durable_paths(&root);
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay::default());
        let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
        let coordinator = durable_coordinator(
            &db_path,
            &authority_path,
            identity.clone(),
            relay.clone(),
            false,
            now,
        );
        let device_signing = SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap();
        let device_agreement = SecretKey::from_slice(&[10_u8; 32]).unwrap();
        let created = coordinator.create_join(now).unwrap();
        let raw_join_secret = created.join_secret.to_string();
        let started = coordinator
            .start_join(
                &created.join_id,
                &created.join_secret,
                &signing_public(&device_signing),
                &agreement_public(&device_agreement),
                now,
            )
            .unwrap();
        coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                now,
            )
            .unwrap();
        let fixture = Fixture {
            _root: root,
            coordinator,
            identity: identity.clone(),
            relay: relay.clone(),
            device_signing,
            device_agreement,
            now,
        };
        let (signing_proof, agreement_mac) = proofs(&fixture, &created, &started);
        let bundle = fixture
            .coordinator
            .confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signing_proof,
                &agreement_mac,
                now,
            )
            .unwrap();
        let host_bearer = fixture
            .coordinator
            .sessions()
            .unwrap()
            .values()
            .find_map(|session| session.pending.as_ref())
            .unwrap()
            .host_bearer
            .to_string();
        let vault_proof = vault_signature(&fixture, &bundle);
        fixture
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &vault_proof,
                now,
            )
            .unwrap();
        let raw_db = fs::read(&db_path).unwrap();
        assert!(!raw_db
            .windows(raw_join_secret.len())
            .any(|window| window == raw_join_secret.as_bytes()));
        assert!(!raw_db
            .windows(host_bearer.len())
            .any(|window| window == host_bearer.as_bytes()));
        assert!(!raw_db
            .windows(started.cookie_capability.len())
            .any(|window| window == started.cookie_capability.as_bytes()));
        for sidecar in [
            sidecar_path(&db_path, b"-wal"),
            sidecar_path(&db_path, b"-shm"),
        ] {
            if let Ok(raw) = fs::read(sidecar) {
                assert!(!raw
                    .windows(raw_join_secret.len())
                    .any(|window| window == raw_join_secret.as_bytes()));
                assert!(!raw
                    .windows(host_bearer.len())
                    .any(|window| window == host_bearer.as_bytes()));
            }
        }
        let connection = Connection::open(&db_path).unwrap();
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
        drop(connection);
        let reopened = durable_coordinator(&db_path, &authority_path, identity, relay, false, now);
        assert!(reopened.active_binding().unwrap().is_some());
        assert!(fixture._root.path().exists());
    }

    #[test]
    fn durable_restart_compensates_pending_candidate() {
        let root = tempfile::tempdir().unwrap();
        let (db_path, authority_path) = durable_paths(&root);
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay::default());
        let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
        let coordinator = durable_coordinator(
            &db_path,
            &authority_path,
            identity.clone(),
            relay.clone(),
            false,
            now,
        );
        let mut durable_fixture = Fixture {
            _root: root,
            coordinator,
            identity: identity.clone(),
            relay: relay.clone(),
            device_signing: SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap(),
            device_agreement: SecretKey::from_slice(&[10_u8; 32]).unwrap(),
            now,
        };
        let (created, started) = start(&durable_fixture);
        let _bundle = approve_and_confirm(&durable_fixture, &created, &started);
        let placeholder = fixture(false);
        let old = std::mem::replace(&mut durable_fixture.coordinator, placeholder.coordinator);
        drop(old);
        let reopened = durable_coordinator(
            &db_path,
            &authority_path,
            identity,
            relay.clone(),
            true,
            now,
        );
        assert!(reopened.active_binding().unwrap().is_none());
        assert_eq!(relay.revocations.lock().unwrap().len(), 1);
    }

    #[test]
    fn durable_store_fails_closed_on_corruption_and_unsafe_paths() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let unsafe_parent = canonical_root.join("unsafe");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, Permissions::from_mode(0o755)).unwrap();
        let identity = TestIdentity::new();
        assert!(matches!(
            SqliteJoinSessionStore::open(
                &unsafe_parent.join("pairing-coordinator.sqlite3"),
                &identity
            ),
            Err(PairingCoordinatorError::Storage)
        ));
        assert!(matches!(
            SqliteJoinSessionStore::open(Path::new("pairing-coordinator.sqlite3"), &identity),
            Err(PairingCoordinatorError::Storage)
        ));

        let safe_parent = canonical_root.join("safe");
        fs::create_dir(&safe_parent).unwrap();
        fs::set_permissions(&safe_parent, Permissions::from_mode(0o700)).unwrap();
        let db_path = safe_parent.join("pairing-coordinator.sqlite3");
        let store = SqliteJoinSessionStore::open(&db_path, &identity).unwrap();
        let connection = Connection::open(&db_path).unwrap();
        connection.execute("INSERT INTO pairing_coordinator_state (singleton, version, payload) VALUES (1, ?1, ?2)", params![DURABLE_STORE_VERSION, vec![0_u8; 48]]).unwrap();
        drop(connection);
        assert!(matches!(
            store.load_all(),
            Err(PairingCoordinatorError::Storage)
        ));

        let other_identity = TestIdentity {
            signing: SigningKey::from_bytes((&[11_u8; 32]).into()).unwrap(),
            agreement: SecretKey::from_slice(&[12_u8; 32]).unwrap(),
        };
        assert!(matches!(
            SqliteJoinSessionStore::open(&db_path, &other_identity),
            Err(PairingCoordinatorError::Storage)
        ));

        let symlink_parent = canonical_root.join("symlink-parent");
        std::os::unix::fs::symlink(&safe_parent, &symlink_parent).unwrap();
        assert!(matches!(
            SqliteJoinSessionStore::open(
                &symlink_parent.join("pairing-coordinator.sqlite3"),
                &identity
            ),
            Err(PairingCoordinatorError::Storage)
        ));
        assert!(matches!(
            SqliteJoinSessionStore::open(
                &safe_parent
                    .join("..")
                    .join("safe")
                    .join("pairing-coordinator.sqlite3"),
                &identity
            ),
            Err(PairingCoordinatorError::Storage)
        ));

        let alternate_parent = canonical_root.join("alternate");
        fs::create_dir(&alternate_parent).unwrap();
        fs::set_permissions(&alternate_parent, Permissions::from_mode(0o700)).unwrap();
        let alternate_path = alternate_parent.join("pairing-coordinator.sqlite3");
        let good_identity = TestIdentity::new();
        let good_store = SqliteJoinSessionStore::open(&alternate_path, &good_identity).unwrap();
        let mut sessions = HashMap::new();
        sessions.insert(
            "join-0123456789abcdef0123456789abcdef".to_owned(),
            JoinSession {
                join_id: "join-0123456789abcdef0123456789abcdef".to_owned(),
                join_secret_digest: Some([3_u8; 32]),
                cookie_digest: None,
                created_at_unix: 1_788_000_000,
                expires_at_unix: 1_788_000_120,
                state: JoinState::Created,
                challenge_id: None,
                challenge_bytes: None,
                prospective_epoch: None,
                device_signing_public_sec1: None,
                device_agreement_public_sec1: None,
                comparison_code: None,
                completed_vault_proof_digest: None,
                replacement_prior_join_id: None,
                pending: None,
                authority_cleanup_needed: false,
                relay_cleanup_needed: false,
                terminal_device_alias: None,
                revoked_epoch: None,
            },
        );
        good_store.replace_all(&sessions).unwrap();
        assert!(matches!(
            SqliteJoinSessionStore::open(&alternate_path, &other_identity),
            Err(PairingCoordinatorError::Storage)
        ));
    }

    #[test]
    fn durable_store_detects_target_replacement_without_writing_replacement() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();
        let state = canonical_root.join("race");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, Permissions::from_mode(0o700)).unwrap();
        let db_path = state.join("pairing-coordinator.sqlite3");
        let displaced = state.join("displaced.sqlite3");
        let store = SqliteJoinSessionStore::open(&db_path, &TestIdentity::new()).unwrap();
        fs::rename(&db_path, &displaced).unwrap();
        let marker = b"replacement-must-stay-unchanged";
        fs::write(&db_path, marker).unwrap();
        fs::set_permissions(&db_path, Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.replace_all(&HashMap::new()),
            Err(PairingCoordinatorError::Storage)
        ));
        assert_eq!(fs::read(&db_path).unwrap(), marker);
    }

    #[test]
    fn cleanup_retry_survives_reopen_without_restoring_eligibility() {
        let root = tempfile::tempdir().unwrap();
        let (db_path, authority_path) = durable_paths(&root);
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay {
            fail_revoke: AtomicBool::new(true),
            panic_on_provision: AtomicBool::new(false),
            ..TestRelay::default()
        });
        let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
        let coordinator = durable_coordinator(
            &db_path,
            &authority_path,
            identity.clone(),
            relay.clone(),
            false,
            now,
        );
        let mut durable_fixture = Fixture {
            _root: root,
            coordinator,
            identity: identity.clone(),
            relay: relay.clone(),
            device_signing: SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap(),
            device_agreement: SecretKey::from_slice(&[10_u8; 32]).unwrap(),
            now,
        };
        let (created, started) = start(&durable_fixture);
        let bundle = approve_and_confirm(&durable_fixture, &created, &started);
        let signature = vault_signature(&durable_fixture, &bundle);
        let active = durable_fixture
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                now,
            )
            .unwrap();
        durable_fixture
            .coordinator
            .revoke_device(&active.device_alias, active.pairing_epoch, now)
            .unwrap();
        assert!(durable_fixture
            .coordinator
            .active_binding()
            .unwrap()
            .is_none());
        let placeholder = fixture(false);
        let old = std::mem::replace(&mut durable_fixture.coordinator, placeholder.coordinator);
        drop(old);
        let reopened = durable_coordinator(
            &db_path,
            &authority_path,
            identity,
            relay.clone(),
            false,
            now,
        );
        assert!(reopened.active_binding().unwrap().is_none());
        relay.fail_revoke.store(false, Ordering::SeqCst);
        assert_eq!(reopened.retry_cleanup().unwrap(), 1);
        assert_eq!(reopened.retry_cleanup().unwrap(), 0);
    }

    #[test]
    fn crash_before_relay_provision_leaves_recoverable_authority_active_intent() {
        let root = tempfile::tempdir().unwrap();
        let (db_path, authority_path) = durable_paths(&root);
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay {
            panic_on_provision: AtomicBool::new(true),
            ..TestRelay::default()
        });
        let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
        let coordinator = durable_coordinator(
            &db_path,
            &authority_path,
            identity.clone(),
            relay.clone(),
            false,
            now,
        );
        let fixture = Fixture {
            _root: root,
            coordinator,
            identity: identity.clone(),
            relay: relay.clone(),
            device_signing: SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap(),
            device_agreement: SecretKey::from_slice(&[10_u8; 32]).unwrap(),
            now,
        };
        let (created, started) = start(&fixture);
        fixture
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                now,
            )
            .unwrap();
        let (signature, mac) = proofs(&fixture, &created, &started);
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &mac,
                now,
            );
        }));
        assert!(crashed.is_err());
        assert!(matches!(
            fixture
                .coordinator
                .sessions()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .state,
            JoinState::AuthorityActive
        ));
        relay.panic_on_provision.store(false, Ordering::SeqCst);
        let reopened = durable_coordinator(&db_path, &authority_path, identity, relay, false, now);
        assert_eq!(reopened.recover_pending_on_startup(now).unwrap(), 1);
        assert!(reopened.active_binding().unwrap().is_none());
        assert!(matches!(
            reopened.authority.current_active().unwrap(),
            CurrentActiveDevice::Unpaired
        ));
    }

    #[test]
    fn durable_load_rejects_public_key_commitment_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let (db_path, authority_path) = durable_paths(&root);
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay::default());
        let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
        let coordinator = durable_coordinator(
            &db_path,
            &authority_path,
            identity.clone(),
            relay,
            false,
            now,
        );
        let fixture = Fixture {
            _root: root,
            coordinator,
            identity: identity.clone(),
            relay: Arc::new(TestRelay::default()),
            device_signing: SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap(),
            device_agreement: SecretKey::from_slice(&[10_u8; 32]).unwrap(),
            now,
        };
        let (created, started) = start(&fixture);
        fixture
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                now,
            )
            .unwrap();
        let (signature, mac) = proofs(&fixture, &created, &started);
        fixture
            .relay
            .panic_on_provision
            .store(true, Ordering::SeqCst);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &mac,
                now,
            )
        }));
        let store = SqliteJoinSessionStore::open(&db_path, identity.as_ref()).unwrap();
        let mut sessions = store.load_all().unwrap();
        let pending = sessions
            .values_mut()
            .next()
            .unwrap()
            .pending
            .as_mut()
            .unwrap();
        pending.device.signing_commitment[0] ^= 1;
        // The write-side validator refuses to persist the mismatch, and load therefore
        // never makes attacker-controlled frame keys authoritative.
        assert!(matches!(
            store.replace_all(&sessions),
            Err(PairingCoordinatorError::Storage)
        ));
    }

    #[test]
    fn replacement_crash_after_authority_commit_tombstones_prior_active_on_recovery() {
        let root = tempfile::tempdir().unwrap();
        let (db_path, authority_path) = durable_paths(&root);
        let identity = Arc::new(TestIdentity::new());
        let relay = Arc::new(TestRelay::default());
        let now = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
        let coordinator = durable_coordinator(
            &db_path,
            &authority_path,
            identity.clone(),
            relay.clone(),
            false,
            now,
        );
        let first = Fixture {
            _root: root,
            coordinator,
            identity: identity.clone(),
            relay: relay.clone(),
            device_signing: SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap(),
            device_agreement: SecretKey::from_slice(&[10_u8; 32]).unwrap(),
            now,
        };
        let (created, started) = start(&first);
        let bundle = approve_and_confirm(&first, &created, &started);
        let vault_proof = vault_signature(&first, &bundle);
        let prior = first
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &vault_proof,
                first.now,
            )
            .unwrap();

        let created = first.coordinator.create_join(first.now).unwrap();
        let second_signing = SigningKey::from_bytes((&[21_u8; 32]).into()).unwrap();
        let second_agreement = SecretKey::from_slice(&[22_u8; 32]).unwrap();
        let started = first
            .coordinator
            .start_join(
                &created.join_id,
                &created.join_secret,
                &signing_public(&second_signing),
                &agreement_public(&second_agreement),
                first.now,
            )
            .unwrap();
        first
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                first.now,
            )
            .unwrap();
        let replacement_fixture = Fixture {
            device_signing: second_signing,
            device_agreement: second_agreement,
            ..first
        };
        let (signature, mac) = proofs(&replacement_fixture, &created, &started);
        replacement_fixture
            .coordinator
            .crash_after_authority_commit
            .store(true, Ordering::SeqCst);
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replacement_fixture.coordinator.confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &mac,
                replacement_fixture.now,
            )
        }));
        assert!(crashed.is_err());
        let retained_root = replacement_fixture._root.path().to_path_buf();
        let reopened = durable_coordinator(&db_path, &authority_path, identity, relay, true, now);
        assert_eq!(reopened.recover_pending_on_startup(now).unwrap(), 0);
        let sessions = reopened.sessions().unwrap();
        assert!(!sessions
            .values()
            .any(|session| session.state == JoinState::Active));
        let prior_session = sessions
            .values()
            .find(|session| {
                session
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.device.device_alias == prior.device_alias)
            })
            .unwrap();
        assert_eq!(prior_session.state, JoinState::Revoked);
        drop(sessions);
        assert!(reopened.active_binding().unwrap().is_none());
        assert!(retained_root.exists());
    }
}
