#![allow(dead_code)]

use crate::remote_crypto::{commitment, EndpointKeys, RemoteCryptoError, SecretString};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::{pkcs8::EncodePrivateKey, rand_core::OsRng, sec1::ToEncodedPoint},
    SecretKey,
};
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

const KEYCHAIN_SERVICE: &str = "dev.nomad.connector.host-device-identity.v1";
const KEYCHAIN_ACCOUNT: &str = "host-device-identity-bundle";
const BUNDLE_VERSION: &str = "host-device-identity-bundle-v1";
const TEST_SERVICE: &str = "dev.nomad.connector.host-device-identity.test";
const TEST_ACCOUNT: &str = "memory";

#[derive(Clone)]
pub(crate) struct HostDeviceIdentity {
    endpoint_keys: Arc<EndpointKeys>,
    signing_public_sec1: [u8; 65],
    agreement_public_sec1: [u8; 65],
    signing_commitment: [u8; 32],
    agreement_commitment: [u8; 32],
}

impl fmt::Debug for HostDeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostDeviceIdentity")
            .field("endpoint_keys", &"<redacted>")
            .field("signing_public_sec1", &"<redacted>")
            .field("agreement_public_sec1", &"<redacted>")
            .field("signing_commitment", &"<redacted>")
            .field("agreement_commitment", &"<redacted>")
            .finish()
    }
}

impl HostDeviceIdentity {
    pub(crate) fn endpoint_keys(&self) -> Arc<EndpointKeys> {
        Arc::clone(&self.endpoint_keys)
    }

    pub(crate) fn signing_public_sec1(&self) -> [u8; 65] {
        self.signing_public_sec1
    }

    pub(crate) fn agreement_public_sec1(&self) -> [u8; 65] {
        self.agreement_public_sec1
    }

    pub(crate) fn signing_commitment(&self) -> [u8; 32] {
        self.signing_commitment
    }

    pub(crate) fn agreement_commitment(&self) -> [u8; 32] {
        self.agreement_commitment
    }

    pub(crate) fn sign_p1363(&self, message: &[u8]) -> Result<[u8; 64], RemoteCryptoError> {
        self.endpoint_keys.sign_p1363(message)
    }

    pub(crate) fn derive_agreement_shared(
        &self,
        peer_public_sec1: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, RemoteCryptoError> {
        self.endpoint_keys.derive_agreement_shared(peer_public_sec1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HostDeviceIdentityError {
    #[error("host device identity authorization required")]
    AuthorizationRequired,
    #[error("host device identity authorization denied")]
    UserDenied,
    #[error("host device identity keychain locked")]
    KeychainLocked,
    #[error("host device identity backend unavailable")]
    BackendUnavailable,
    #[error("host device identity corrupt")]
    Corrupt,
    #[error("host device identity invariant violated")]
    Invariant,
    #[error("host device identity crypto invalid")]
    Crypto,
    #[error("host device identity os error")]
    Os,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostIdentityPreflightStatus {
    Ready,
    AuthRequired,
    UserDenied,
    KeychainLocked,
    Corrupt,
    Unavailable,
}

impl HostIdentityPreflightStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::UserDenied => "USER_DENIED",
            Self::KeychainLocked => "KEYCHAIN_LOCKED",
            Self::Corrupt => "CORRUPT",
            Self::Unavailable => "UNAVAILABLE",
        }
    }

    pub const fn canonical_json(self) -> &'static str {
        match self {
            Self::Ready => r#"{"status":"READY"}"#,
            Self::AuthRequired => r#"{"status":"AUTH_REQUIRED"}"#,
            Self::UserDenied => r#"{"status":"USER_DENIED"}"#,
            Self::KeychainLocked => r#"{"status":"KEYCHAIN_LOCKED"}"#,
            Self::Corrupt => r#"{"status":"CORRUPT"}"#,
            Self::Unavailable => r#"{"status":"UNAVAILABLE"}"#,
        }
    }

    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl From<RemoteCryptoError> for HostDeviceIdentityError {
    fn from(_: RemoteCryptoError) -> Self {
        Self::Crypto
    }
}

trait IdentitySecretStore: Send + Sync + 'static {
    fn load_bundle(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, HostDeviceIdentityError>;
    fn create_bundle_if_absent(
        &self,
        service: &str,
        account: &str,
        bundle: &[u8],
    ) -> Result<(), HostDeviceIdentityError>;
}

#[cfg(target_os = "macos")]
#[derive(Clone, Default)]
struct MacOsKeychainStore;

#[cfg(target_os = "macos")]
impl IdentitySecretStore for MacOsKeychainStore {
    fn load_bundle(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, HostDeviceIdentityError> {
        use security_framework::os::macos::keychain::SecKeychain;

        let keychain = SecKeychain::default().map_err(classify_macos_error)?;
        match keychain.find_generic_password(service, account) {
            Ok((password, _item)) => Ok(Some(Zeroizing::new(password.as_ref().to_vec()))),
            Err(error) if error.code() == MACOS_ERR_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(classify_macos_error(error)),
        }
    }

    fn create_bundle_if_absent(
        &self,
        service: &str,
        account: &str,
        bundle: &[u8],
    ) -> Result<(), HostDeviceIdentityError> {
        use security_framework::os::macos::keychain::SecKeychain;

        let keychain = SecKeychain::default().map_err(classify_macos_error)?;
        match keychain.add_generic_password(service, account, bundle) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == MACOS_ERR_DUPLICATE_ITEM => Ok(()),
            Err(error) => Err(classify_macos_error(error)),
        }
    }
}

#[cfg(target_os = "macos")]
const MACOS_ERR_USER_CANCELED: i32 = -128;
#[cfg(target_os = "macos")]
const MACOS_ERR_NOT_AVAILABLE: i32 = -25291;
#[cfg(target_os = "macos")]
const MACOS_ERR_AUTH_FAILED: i32 = -25293;
#[cfg(target_os = "macos")]
const MACOS_ERR_NO_SUCH_KEYCHAIN: i32 = -25294;
#[cfg(target_os = "macos")]
const MACOS_ERR_INVALID_KEYCHAIN: i32 = -25295;
#[cfg(target_os = "macos")]
const MACOS_ERR_DUPLICATE_ITEM: i32 = -25299;
#[cfg(target_os = "macos")]
const MACOS_ERR_ITEM_NOT_FOUND: i32 = -25300;
#[cfg(target_os = "macos")]
const MACOS_ERR_NO_DEFAULT_KEYCHAIN: i32 = -25307;
#[cfg(target_os = "macos")]
const MACOS_ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;
#[cfg(target_os = "macos")]
const MACOS_ERR_WRONG_VERSION: i32 = -25310;
#[cfg(target_os = "macos")]
const MACOS_ERR_NO_STORAGE_MODULE: i32 = -25312;
#[cfg(target_os = "macos")]
const MACOS_ERR_INTERACTION_REQUIRED: i32 = -25315;
#[cfg(target_os = "macos")]
const MACOS_ERR_DATA_NOT_AVAILABLE: i32 = -25316;
#[cfg(target_os = "macos")]
const MACOS_ERR_DARK_WAKE: i32 = -25320;
#[cfg(target_os = "macos")]
const MACOS_ERR_DECODE: i32 = -26275;
#[cfg(target_os = "macos")]
const MACOS_ERR_SERVICE_NOT_AVAILABLE: i32 = -67585;
#[cfg(target_os = "macos")]
const MACOS_ERR_NO_ACCESS_FOR_ITEM: i32 = -25243;

#[cfg(target_os = "macos")]
fn classify_macos_error(error: security_framework::base::Error) -> HostDeviceIdentityError {
    match error.code() {
        MACOS_ERR_USER_CANCELED => HostDeviceIdentityError::UserDenied,
        MACOS_ERR_INTERACTION_NOT_ALLOWED | MACOS_ERR_INTERACTION_REQUIRED => {
            if default_keychain_is_locked() == Some(true) {
                HostDeviceIdentityError::KeychainLocked
            } else {
                HostDeviceIdentityError::AuthorizationRequired
            }
        }
        MACOS_ERR_AUTH_FAILED => match default_keychain_is_locked() {
            Some(true) => HostDeviceIdentityError::KeychainLocked,
            Some(false) => HostDeviceIdentityError::UserDenied,
            None => HostDeviceIdentityError::BackendUnavailable,
        },
        MACOS_ERR_NO_ACCESS_FOR_ITEM => HostDeviceIdentityError::UserDenied,
        MACOS_ERR_DATA_NOT_AVAILABLE => HostDeviceIdentityError::KeychainLocked,
        MACOS_ERR_INVALID_KEYCHAIN | MACOS_ERR_WRONG_VERSION | MACOS_ERR_DECODE => {
            HostDeviceIdentityError::Corrupt
        }
        MACOS_ERR_NOT_AVAILABLE
        | MACOS_ERR_NO_SUCH_KEYCHAIN
        | MACOS_ERR_NO_DEFAULT_KEYCHAIN
        | MACOS_ERR_NO_STORAGE_MODULE
        | MACOS_ERR_DARK_WAKE
        | MACOS_ERR_SERVICE_NOT_AVAILABLE => HostDeviceIdentityError::BackendUnavailable,
        _ => HostDeviceIdentityError::Os,
    }
}

#[cfg(target_os = "macos")]
fn default_keychain_is_locked() -> Option<bool> {
    use std::ffi::c_void;

    const MACOS_ERR_SUCCESS: i32 = 0;
    const MACOS_KEYCHAIN_UNLOCKED: u32 = 1;

    extern "C" {
        fn SecKeychainGetStatus(keychain: *const c_void, status: *mut u32) -> i32;
    }

    let mut status = 0_u32;
    // A null keychain means the user's default keychain per Security.framework.
    let result = unsafe { SecKeychainGetStatus(std::ptr::null(), &mut status) };
    (result == MACOS_ERR_SUCCESS).then_some(status & MACOS_KEYCHAIN_UNLOCKED == 0)
}

#[cfg(target_os = "macos")]
struct NonInteractiveKeychainGuard {
    _lock: Option<security_framework::os::macos::keychain::KeychainUserInteractionLock>,
}

#[cfg(target_os = "macos")]
impl NonInteractiveKeychainGuard {
    fn enter() -> Result<Self, HostDeviceIdentityError> {
        use security_framework::os::macos::keychain::SecKeychain;

        let was_allowed = SecKeychain::user_interaction_allowed().map_err(classify_macos_error)?;
        let lock = if was_allowed {
            Some(SecKeychain::disable_user_interaction().map_err(classify_macos_error)?)
        } else {
            None
        };
        Ok(Self { _lock: lock })
    }
}

#[cfg(target_os = "macos")]
struct InteractiveKeychainGuard {
    restore_disabled: bool,
}

#[cfg(target_os = "macos")]
impl InteractiveKeychainGuard {
    fn enter() -> Result<Self, HostDeviceIdentityError> {
        use security_framework::os::macos::keychain::SecKeychain;

        let was_allowed = SecKeychain::user_interaction_allowed().map_err(classify_macos_error)?;
        if !was_allowed {
            set_macos_keychain_user_interaction(true)?;
        }
        Ok(Self {
            restore_disabled: !was_allowed,
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for InteractiveKeychainGuard {
    fn drop(&mut self) {
        if self.restore_disabled {
            let _ = set_macos_keychain_user_interaction(false);
        }
    }
}

#[cfg(target_os = "macos")]
fn set_macos_keychain_user_interaction(allowed: bool) -> Result<(), HostDeviceIdentityError> {
    extern "C" {
        fn SecKeychainSetUserInteractionAllowed(state: u8) -> i32;
    }

    let result = unsafe { SecKeychainSetUserInteractionAllowed(u8::from(allowed)) };
    if result == 0 {
        Ok(())
    } else {
        Err(classify_macos_error(
            security_framework::base::Error::from_code(result),
        ))
    }
}

#[derive(Clone, Default)]
struct MemorySecretStore {
    inner: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    load_error: Arc<Mutex<Option<HostDeviceIdentityError>>>,
}

impl IdentitySecretStore for MemorySecretStore {
    fn load_bundle(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, HostDeviceIdentityError> {
        if service != TEST_SERVICE || account != TEST_ACCOUNT {
            return Err(HostDeviceIdentityError::Invariant);
        }
        if let Some(error) = *self
            .load_error
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
        {
            return Err(error);
        }
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone())
    }

    fn create_bundle_if_absent(
        &self,
        service: &str,
        account: &str,
        bundle: &[u8],
    ) -> Result<(), HostDeviceIdentityError> {
        if service != TEST_SERVICE || account != TEST_ACCOUNT {
            return Err(HostDeviceIdentityError::Invariant);
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if guard.is_none() {
            *guard = Some(Zeroizing::new(bundle.to_vec()));
        }
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityBundle {
    version: String,
    signing_pkcs8_base64: SecretString,
    agreement_pkcs8_base64: SecretString,
    signing_commitment_hex: String,
    agreement_commitment_hex: String,
}

pub(crate) fn load_or_create_host_device_identity(
) -> Result<HostDeviceIdentity, HostDeviceIdentityError> {
    #[cfg(target_os = "macos")]
    {
        load_or_create_with_store(&MacOsKeychainStore, KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(HostDeviceIdentityError::BackendUnavailable)
    }
}

pub fn preflight_host_device_identity_noninteractive() -> HostIdentityPreflightStatus {
    #[cfg(target_os = "macos")]
    {
        let guard = match NonInteractiveKeychainGuard::enter() {
            Ok(guard) => guard,
            Err(error) => return preflight_status_from_error(error),
        };
        let result = load_or_create_host_device_identity();
        drop(guard);
        preflight_status_from_result(result)
    }

    #[cfg(not(target_os = "macos"))]
    {
        preflight_status_from_result(load_or_create_host_device_identity())
    }
}

pub fn authorize_host_device_identity() -> HostIdentityPreflightStatus {
    #[cfg(target_os = "macos")]
    {
        let result = {
            let guard = match InteractiveKeychainGuard::enter() {
                Ok(guard) => guard,
                Err(error) => return preflight_status_from_error(error),
            };
            let result = load_or_create_host_device_identity();
            drop(guard);
            result
        };
        if let Err(error) = result {
            return preflight_status_from_error(error);
        }
        preflight_host_device_identity_noninteractive()
    }

    #[cfg(not(target_os = "macos"))]
    {
        HostIdentityPreflightStatus::Unavailable
    }
}

fn preflight_with_store<S: IdentitySecretStore>(
    store: &S,
    service: &str,
    account: &str,
) -> HostIdentityPreflightStatus {
    preflight_status_from_result(load_or_create_with_store(store, service, account))
}

fn preflight_status_from_result(
    result: Result<HostDeviceIdentity, HostDeviceIdentityError>,
) -> HostIdentityPreflightStatus {
    match result {
        Ok(_) => HostIdentityPreflightStatus::Ready,
        Err(error) => preflight_status_from_error(error),
    }
}

fn preflight_status_from_error(error: HostDeviceIdentityError) -> HostIdentityPreflightStatus {
    match error {
        HostDeviceIdentityError::AuthorizationRequired => HostIdentityPreflightStatus::AuthRequired,
        HostDeviceIdentityError::UserDenied => HostIdentityPreflightStatus::UserDenied,
        HostDeviceIdentityError::KeychainLocked => HostIdentityPreflightStatus::KeychainLocked,
        HostDeviceIdentityError::Corrupt
        | HostDeviceIdentityError::Invariant
        | HostDeviceIdentityError::Crypto => HostIdentityPreflightStatus::Corrupt,
        HostDeviceIdentityError::BackendUnavailable | HostDeviceIdentityError::Os => {
            HostIdentityPreflightStatus::Unavailable
        }
    }
}

fn load_or_create_with_store<S: IdentitySecretStore>(
    store: &S,
    service: &str,
    account: &str,
) -> Result<HostDeviceIdentity, HostDeviceIdentityError> {
    ensure_fixed_locator(service, account)?;
    if let Some(existing) = store.load_bundle(service, account)? {
        return decode_identity_bundle(existing);
    }

    let bundle = generate_identity_bundle()?;
    store.create_bundle_if_absent(service, account, bundle.as_slice())?;
    let stored = store
        .load_bundle(service, account)?
        .ok_or(HostDeviceIdentityError::Invariant)?;
    decode_identity_bundle(stored)
}

fn ensure_fixed_locator(service: &str, account: &str) -> Result<(), HostDeviceIdentityError> {
    if service.is_empty() || account.is_empty() {
        return Err(HostDeviceIdentityError::Invariant);
    }
    Ok(())
}

fn generate_identity_bundle() -> Result<Zeroizing<Vec<u8>>, HostDeviceIdentityError> {
    let signing = SigningKey::random(&mut OsRng);
    let agreement = SecretKey::random(&mut OsRng);
    let signing_public = signing.verifying_key().to_encoded_point(false);
    let agreement_public = agreement.public_key().to_encoded_point(false);
    if signing_public.as_bytes() == agreement_public.as_bytes() {
        return Err(HostDeviceIdentityError::Invariant);
    }

    let signing_pkcs8 = signing
        .to_pkcs8_der()
        .map_err(|_| HostDeviceIdentityError::Crypto)?;
    let agreement_pkcs8 = agreement
        .to_pkcs8_der()
        .map_err(|_| HostDeviceIdentityError::Crypto)?;
    let signing_commitment = commitment(signing_public.as_bytes())?;
    let agreement_commitment = commitment(agreement_public.as_bytes())?;
    if signing_commitment == agreement_commitment {
        return Err(HostDeviceIdentityError::Invariant);
    }

    let bundle = IdentityBundle {
        version: BUNDLE_VERSION.to_string(),
        signing_pkcs8_base64: SecretString::new(URL_SAFE_NO_PAD.encode(signing_pkcs8.as_bytes())),
        agreement_pkcs8_base64: SecretString::new(
            URL_SAFE_NO_PAD.encode(agreement_pkcs8.as_bytes()),
        ),
        signing_commitment_hex: encode_hex(&signing_commitment),
        agreement_commitment_hex: encode_hex(&agreement_commitment),
    };
    let mut json = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *json, &bundle).map_err(|_| HostDeviceIdentityError::Corrupt)?;
    Ok(json)
}

fn decode_identity_bundle(
    mut bundle_bytes: Zeroizing<Vec<u8>>,
) -> Result<HostDeviceIdentity, HostDeviceIdentityError> {
    let bundle: IdentityBundle = serde_json::from_slice(bundle_bytes.as_slice())
        .map_err(|_| HostDeviceIdentityError::Corrupt)?;
    if bundle.version != BUNDLE_VERSION
        || bundle.signing_pkcs8_base64.is_empty()
        || bundle.agreement_pkcs8_base64.is_empty()
        || bundle.signing_pkcs8_base64.as_str() == bundle.agreement_pkcs8_base64.as_str()
    {
        return Err(HostDeviceIdentityError::Corrupt);
    }

    let endpoint_keys = Arc::new(
        EndpointKeys::from_pkcs8_base64(
            bundle.signing_pkcs8_base64.as_str(),
            bundle.agreement_pkcs8_base64.as_str(),
        )
        .map_err(|_| HostDeviceIdentityError::Crypto)?,
    );
    let signing_public_vec = endpoint_keys.signing_public();
    let agreement_public_vec = endpoint_keys.agreement_public();
    let signing_public_sec1: [u8; 65] = signing_public_vec
        .try_into()
        .map_err(|_| HostDeviceIdentityError::Invariant)?;
    let agreement_public_sec1: [u8; 65] = agreement_public_vec
        .try_into()
        .map_err(|_| HostDeviceIdentityError::Invariant)?;
    if signing_public_sec1 == agreement_public_sec1 {
        return Err(HostDeviceIdentityError::Invariant);
    }

    let signing_commitment = commitment(&signing_public_sec1)?;
    let agreement_commitment = commitment(&agreement_public_sec1)?;
    if signing_commitment == agreement_commitment {
        return Err(HostDeviceIdentityError::Invariant);
    }
    if decode_hex32(&bundle.signing_commitment_hex)? != signing_commitment
        || decode_hex32(&bundle.agreement_commitment_hex)? != agreement_commitment
    {
        return Err(HostDeviceIdentityError::Invariant);
    }

    bundle_bytes.as_mut_slice().zeroize();
    Ok(HostDeviceIdentity {
        endpoint_keys,
        signing_public_sec1,
        agreement_public_sec1,
        signing_commitment,
        agreement_commitment,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex32(value: &str) -> Result<[u8; 32], HostDeviceIdentityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HostDeviceIdentityError::Corrupt);
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = decode_hex_nibble(chunk[0])?;
        let lo = decode_hex_nibble(chunk[1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, HostDeviceIdentityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(HostDeviceIdentityError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn memory_backend_generates_stable_reopen_identity() {
        let store = MemorySecretStore::default();
        let first = load_or_create_with_store(&store, TEST_SERVICE, TEST_ACCOUNT).unwrap();
        let second = load_or_create_with_store(&store, TEST_SERVICE, TEST_ACCOUNT).unwrap();

        assert_eq!(first.signing_public_sec1(), second.signing_public_sec1());
        assert_eq!(
            first.agreement_public_sec1(),
            second.agreement_public_sec1()
        );
        assert_eq!(first.signing_commitment(), second.signing_commitment());
        assert_eq!(first.agreement_commitment(), second.agreement_commitment());
    }

    #[test]
    fn memory_backend_preflight_maps_every_public_status_without_detail() {
        let ready_store = MemorySecretStore::default();
        assert_eq!(
            preflight_with_store(&ready_store, TEST_SERVICE, TEST_ACCOUNT),
            HostIdentityPreflightStatus::Ready
        );

        let corrupt_store = MemorySecretStore::default();
        corrupt_store
            .create_bundle_if_absent(TEST_SERVICE, TEST_ACCOUNT, br#"{"version":"invalid"}"#)
            .unwrap();
        assert_eq!(
            preflight_with_store(&corrupt_store, TEST_SERVICE, TEST_ACCOUNT),
            HostIdentityPreflightStatus::Corrupt
        );

        let cases = [
            (
                HostDeviceIdentityError::AuthorizationRequired,
                HostIdentityPreflightStatus::AuthRequired,
            ),
            (
                HostDeviceIdentityError::UserDenied,
                HostIdentityPreflightStatus::UserDenied,
            ),
            (
                HostDeviceIdentityError::KeychainLocked,
                HostIdentityPreflightStatus::KeychainLocked,
            ),
            (
                HostDeviceIdentityError::BackendUnavailable,
                HostIdentityPreflightStatus::Unavailable,
            ),
            (
                HostDeviceIdentityError::Os,
                HostIdentityPreflightStatus::Unavailable,
            ),
        ];
        for (error, expected) in cases {
            let store = MemorySecretStore::default();
            *store
                .load_error
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(error);
            assert_eq!(
                preflight_with_store(&store, TEST_SERVICE, TEST_ACCOUNT),
                expected
            );
        }
    }

    #[test]
    fn preflight_status_json_is_exact_canonical_and_content_free() {
        let cases = [
            (HostIdentityPreflightStatus::Ready, r#"{"status":"READY"}"#),
            (
                HostIdentityPreflightStatus::AuthRequired,
                r#"{"status":"AUTH_REQUIRED"}"#,
            ),
            (
                HostIdentityPreflightStatus::UserDenied,
                r#"{"status":"USER_DENIED"}"#,
            ),
            (
                HostIdentityPreflightStatus::KeychainLocked,
                r#"{"status":"KEYCHAIN_LOCKED"}"#,
            ),
            (
                HostIdentityPreflightStatus::Corrupt,
                r#"{"status":"CORRUPT"}"#,
            ),
            (
                HostIdentityPreflightStatus::Unavailable,
                r#"{"status":"UNAVAILABLE"}"#,
            ),
        ];

        for (status, expected) in cases {
            assert_eq!(status.canonical_json(), expected);
            assert_eq!(
                serde_json::to_string(&serde_json::json!({
                    "status": status.code()
                }))
                .unwrap(),
                expected
            );
            assert!(!expected.contains(KEYCHAIN_SERVICE));
            assert!(!expected.contains(KEYCHAIN_ACCOUNT));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn noninteractive_guard_disables_interaction_and_restores_original_state_on_unwind() {
        use security_framework::os::macos::keychain::SecKeychain;

        static INTERACTION_TEST_LOCK: Mutex<()> = Mutex::new(());
        let _serial = INTERACTION_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let original = SecKeychain::user_interaction_allowed().unwrap();
        let unwind = std::panic::catch_unwind(|| {
            let _guard = NonInteractiveKeychainGuard::enter().unwrap();
            assert!(!SecKeychain::user_interaction_allowed().unwrap());
            panic!("exercise guard unwind");
        });
        assert!(unwind.is_err());
        assert_eq!(SecKeychain::user_interaction_allowed().unwrap(), original);
    }

    #[test]
    fn memory_backend_concurrent_first_create_has_one_winner_state() {
        let store = MemorySecretStore::default();
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            threads.push(thread::spawn(move || {
                load_or_create_with_store(&store, TEST_SERVICE, TEST_ACCOUNT)
                    .unwrap()
                    .signing_public_sec1()
            }));
        }

        let first = threads.remove(0).join().unwrap();
        for handle in threads {
            assert_eq!(handle.join().unwrap(), first);
        }
    }

    #[test]
    fn malformed_persisted_bundle_fails_closed_without_rotation() {
        let store = MemorySecretStore::default();
        let corrupt = br#"{"version":"nope"}"#;
        store
            .create_bundle_if_absent(TEST_SERVICE, TEST_ACCOUNT, corrupt)
            .unwrap();
        let err = load_or_create_with_store(&store, TEST_SERVICE, TEST_ACCOUNT).unwrap_err();
        assert!(matches!(
            err,
            HostDeviceIdentityError::Corrupt | HostDeviceIdentityError::Invariant
        ));
        let persisted = store
            .load_bundle(TEST_SERVICE, TEST_ACCOUNT)
            .unwrap()
            .unwrap();
        assert_eq!(persisted.as_slice(), corrupt);
    }

    #[test]
    fn host_crypto_capabilities_sign_and_agree_without_exporting_private_keys() {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let host =
            load_or_create_with_store(&MemorySecretStore::default(), TEST_SERVICE, TEST_ACCOUNT)
                .unwrap();
        let peer = EndpointKeys::from_scalars([41_u8; 32], [42_u8; 32]).unwrap();
        let message = b"nomad pairing transcript";

        let signature = Signature::from_slice(&host.sign_p1363(message).unwrap()).unwrap();
        let verifying = VerifyingKey::from_sec1_bytes(&host.signing_public_sec1()).unwrap();
        verifying.verify(message, &signature).unwrap();

        let host_shared = host
            .derive_agreement_shared(&peer.agreement_public())
            .unwrap();
        let peer_shared = peer
            .derive_agreement_shared(&host.agreement_public_sec1())
            .unwrap();
        assert_eq!(*host_shared, *peer_shared);
    }

    #[test]
    fn endpoint_capability_handle_reuses_identity_without_exposing_key_bytes() {
        let host =
            load_or_create_with_store(&MemorySecretStore::default(), TEST_SERVICE, TEST_ACCOUNT)
                .unwrap();
        let first = host.endpoint_keys();
        let second = host.endpoint_keys();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.signing_public(), host.signing_public_sec1());
        assert_eq!(first.agreement_public(), host.agreement_public_sec1());
        assert!(format!("{host:?}").contains("<redacted>"));
    }

    #[test]
    fn debug_output_redacts_identity_material() {
        let store = MemorySecretStore::default();
        let identity = load_or_create_with_store(&store, TEST_SERVICE, TEST_ACCOUNT).unwrap();
        let rendered = format!("{identity:?}");
        assert!(!rendered.contains(&encode_hex(&identity.signing_commitment())));
        assert!(!rendered.contains(&encode_hex(&identity.agreement_commitment())));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn non_macos_production_loader_fails_closed() {
        #[cfg(not(target_os = "macos"))]
        {
            let err = load_or_create_host_device_identity().unwrap_err();
            assert!(matches!(err, HostDeviceIdentityError::BackendUnavailable));
        }
    }
}
