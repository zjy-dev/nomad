//! Endpoint-only codec for Relay v2 opaque frames. Relay must never import it.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use p256::{
    ecdh::diffie_hellman,
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const FRAME_SCHEMA: &str = "nomad.relay.opaque-frame.v2";
const CRYPTO_SUITE: &str = "p256-hkdf-sha256-aes256gcm-v1";
const SALT_PREFIX: &[u8] = b"nomad.remote-envelope.salt.v2\n";
const INFO_PREFIX: &[u8] = b"nomad.remote-envelope.key.v2\n";
const NONCE_PREFIX: &[u8] = b"nomad.remote-envelope.nonce.v2\n";
const AAD_PREFIX: &[u8] = b"nomad.remote-envelope.v2\n";
const SEALED_VERSION: u8 = 1;
const PUBLIC_KEY_BYTES: usize = 65;
const SIGNATURE_BYTES: usize = 64;
const TAG_BYTES: usize = 16;
const MAX_JSON_BYTES: usize = 32 * 1024;
const MAX_WIRE_BYTES: usize = 96 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const BUCKETS: [usize; 5] = [512, 2048, 8192, 32768, 65536];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    HostToDevice,
    DeviceToHost,
}

impl Direction {
    fn text(self) -> &'static str {
        match self {
            Self::HostToDevice => "host_to_device",
            Self::DeviceToHost => "device_to_host",
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedContext {
    pub mailbox_id: String,
    pub epoch: u64,
    pub host_signing_commitment: [u8; 32],
    pub host_agreement_commitment: [u8; 32],
    pub device_signing_commitment: [u8; 32],
    pub device_agreement_commitment: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrameMetadata {
    pub schema: String,
    pub crypto_suite: String,
    pub mailbox_id: String,
    pub direction: Direction,
    pub epoch: u64,
    pub sequence: u64,
    pub message_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpaqueFrame {
    pub schema: String,
    pub crypto_suite: String,
    pub mailbox_id: String,
    pub direction: Direction,
    pub epoch: u64,
    pub sequence: u64,
    pub message_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RemoteCryptoError {
    #[error("REMOTE_CRYPTO_INVALID")]
    Invalid,
    #[error("REMOTE_CRYPTO_AUTH")]
    Authentication,
    #[error("REMOTE_CRYPTO_SIZE")]
    Size,
}

/// An owned secret encoded as text. It deliberately has no `Clone` or `Debug`
/// implementation and clears its allocation on every drop path.
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SecretString {}

pub(crate) struct EndpointKeys {
    signing: SigningKey,
    agreement: SecretKey,
}

impl EndpointKeys {
    pub(crate) fn from_scalars(
        signing: [u8; 32],
        agreement: [u8; 32],
    ) -> Result<Self, RemoteCryptoError> {
        let signing = Zeroizing::new(signing);
        let agreement = Zeroizing::new(agreement);
        Ok(Self {
            signing: SigningKey::from_bytes((&*signing).into())
                .map_err(|_| RemoteCryptoError::Invalid)?,
            agreement: SecretKey::from_slice(agreement.as_ref())
                .map_err(|_| RemoteCryptoError::Invalid)?,
        })
    }

    pub(crate) fn from_pkcs8_base64(
        signing_pkcs8_base64: &str,
        agreement_pkcs8_base64: &str,
    ) -> Result<Self, RemoteCryptoError> {
        let signing_der = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(signing_pkcs8_base64)
                .map_err(|_| RemoteCryptoError::Invalid)?,
        );
        let agreement_der = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(agreement_pkcs8_base64)
                .map_err(|_| RemoteCryptoError::Invalid)?,
        );
        Ok(Self {
            signing: SigningKey::from_pkcs8_der(signing_der.as_slice())
                .map_err(|_| RemoteCryptoError::Invalid)?,
            agreement: SecretKey::from_pkcs8_der(agreement_der.as_slice())
                .map_err(|_| RemoteCryptoError::Invalid)?,
        })
    }

    pub(crate) fn sign_p1363(&self, message: &[u8]) -> Result<[u8; 64], RemoteCryptoError> {
        let signature: Signature = self.signing.sign(message);
        Ok(signature.to_bytes().into())
    }

    pub(crate) fn derive_agreement_shared(
        &self,
        peer_public_sec1: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, RemoteCryptoError> {
        derive_shared(&self.agreement, peer_public_sec1)
    }

    pub(crate) fn signing_public(&self) -> Vec<u8> {
        VerifyingKey::from(&self.signing)
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn agreement_public(&self) -> Vec<u8> {
        self.agreement
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn decrypt_from_device(
        &self,
        frame: &OpaqueFrame,
        context: &SharedContext,
    ) -> Result<Value, RemoteCryptoError> {
        decrypt(
            frame,
            &self.agreement,
            context,
            &context.device_signing_commitment,
            &context.device_agreement_commitment,
        )
    }

    pub(crate) fn decrypt_from_host(
        &self,
        frame: &OpaqueFrame,
        context: &SharedContext,
    ) -> Result<Value, RemoteCryptoError> {
        decrypt(
            frame,
            &self.agreement,
            context,
            &context.host_signing_commitment,
            &context.host_agreement_commitment,
        )
    }
}

pub(crate) fn commitment(public: &[u8]) -> Result<[u8; 32], RemoteCryptoError> {
    parse_public(public)?;
    Ok(Sha256::digest(public).into())
}

pub(crate) fn derive_shared(
    private: &SecretKey,
    peer_public: &[u8],
) -> Result<Zeroizing<[u8; 32]>, RemoteCryptoError> {
    let peer = parse_public(peer_public)?;
    let shared = diffie_hellman(private.to_nonzero_scalar(), peer.as_affine());
    Ok(Zeroizing::new(
        shared
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| RemoteCryptoError::Invalid)?,
    ))
}

pub(crate) fn derive_salt(context: &SharedContext) -> Result<[u8; 32], RemoteCryptoError> {
    validate_context(context)?;
    let mut material = Vec::from(SALT_PREFIX);
    material.extend_from_slice(context.mailbox_id.as_bytes());
    for commitment in [
        context.host_signing_commitment,
        context.host_agreement_commitment,
        context.device_signing_commitment,
        context.device_agreement_commitment,
    ] {
        material.push(b'\n');
        material.extend_from_slice(hex_lower(&commitment).as_bytes());
    }
    material.push(b'\n');
    material.extend_from_slice(context.epoch.to_string().as_bytes());
    Ok(Sha256::digest(material).into())
}

pub(crate) fn derive_direction_key(
    shared: &[u8; 32],
    salt: &[u8; 32],
    direction: Direction,
) -> Result<Zeroizing<[u8; 32]>, RemoteCryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut info = Vec::from(INFO_PREFIX);
    info.extend_from_slice(direction.text().as_bytes());
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| RemoteCryptoError::Invalid)?;
    info.zeroize();
    Ok(key)
}

pub(crate) fn deterministic_nonce(
    direction: Direction,
    sequence: u64,
) -> Result<[u8; 12], RemoteCryptoError> {
    if sequence == 0 || sequence > MAX_SAFE_INTEGER {
        return Err(RemoteCryptoError::Invalid);
    }
    let mut material = Vec::from(NONCE_PREFIX);
    material.extend_from_slice(direction.text().as_bytes());
    let digest = Sha256::digest(material);
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&digest[..4]);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    Ok(nonce)
}

fn metadata(frame: &OpaqueFrame) -> FrameMetadata {
    FrameMetadata {
        schema: frame.schema.clone(),
        crypto_suite: frame.crypto_suite.clone(),
        mailbox_id: frame.mailbox_id.clone(),
        direction: frame.direction,
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id.clone(),
        issued_at: frame.issued_at,
        expires_at: frame.expires_at,
        nonce: frame.nonce.clone(),
    }
}

pub(crate) fn aad(meta: &FrameMetadata) -> Result<Vec<u8>, RemoteCryptoError> {
    validate_metadata(meta)?;
    let value = serde_json::to_value(meta).map_err(|_| RemoteCryptoError::Invalid)?;
    let mut out = Vec::from(AAD_PREFIX);
    out.extend_from_slice(canonical_json(&value)?.as_bytes());
    Ok(out)
}

pub(crate) fn encrypt(
    mut meta: FrameMetadata,
    plaintext: &Value,
    sender: &EndpointKeys,
    recipient_agreement_public: &[u8],
    context: &SharedContext,
    padding: &[u8],
) -> Result<OpaqueFrame, RemoteCryptoError> {
    validate_context(context)?;
    if meta.mailbox_id != context.mailbox_id || meta.epoch != context.epoch {
        return Err(RemoteCryptoError::Invalid);
    }
    let nonce = deterministic_nonce(meta.direction, meta.sequence)?;
    meta.nonce = URL_SAFE_NO_PAD.encode(nonce);
    validate_metadata(&meta)?;
    let aad = aad(&meta)?;
    let json = canonical_json(plaintext)?;
    let mut padded = Zeroizing::new(encode_padded(json.as_bytes(), padding)?);
    let shared = derive_shared(&sender.agreement, recipient_agreement_public)?;
    let salt = derive_salt(context)?;
    let key = derive_direction_key(&shared, &salt, meta.direction)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| RemoteCryptoError::Invalid)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: padded.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| RemoteCryptoError::Authentication)?;
    padded.zeroize();
    let digest = Sha256::digest([aad.as_slice(), ciphertext.as_slice()].concat());
    let signature: Signature = sender.signing.sign(digest.as_slice());
    let mut sealed =
        Vec::with_capacity(1 + PUBLIC_KEY_BYTES * 2 + SIGNATURE_BYTES + ciphertext.len());
    sealed.push(SEALED_VERSION);
    sealed.extend_from_slice(&sender.signing_public());
    sealed.extend_from_slice(&sender.agreement_public());
    sealed.extend_from_slice(signature.to_bytes().as_slice());
    sealed.extend_from_slice(&ciphertext);
    if sealed.len() > MAX_WIRE_BYTES {
        return Err(RemoteCryptoError::Size);
    }
    Ok(OpaqueFrame {
        schema: meta.schema,
        crypto_suite: meta.crypto_suite,
        mailbox_id: meta.mailbox_id,
        direction: meta.direction,
        epoch: meta.epoch,
        sequence: meta.sequence,
        message_id: meta.message_id,
        issued_at: meta.issued_at,
        expires_at: meta.expires_at,
        nonce: meta.nonce,
        ciphertext: URL_SAFE_NO_PAD.encode(sealed),
    })
}

pub(crate) fn decrypt(
    frame: &OpaqueFrame,
    recipient_agreement_private: &SecretKey,
    context: &SharedContext,
    expected_signing_commitment: &[u8; 32],
    expected_agreement_commitment: &[u8; 32],
) -> Result<Value, RemoteCryptoError> {
    validate_frame(frame)?;
    validate_context(context)?;
    if frame.mailbox_id != context.mailbox_id || frame.epoch != context.epoch {
        return Err(RemoteCryptoError::Invalid);
    }
    let expected_nonce = deterministic_nonce(frame.direction, frame.sequence)?;
    let wire_nonce = URL_SAFE_NO_PAD
        .decode(&frame.nonce)
        .map_err(|_| RemoteCryptoError::Invalid)?;
    if !constant_time_equal(&wire_nonce, &expected_nonce) {
        return Err(RemoteCryptoError::Authentication);
    }
    let sealed = URL_SAFE_NO_PAD
        .decode(&frame.ciphertext)
        .map_err(|_| RemoteCryptoError::Invalid)?;
    let prefix = 1 + PUBLIC_KEY_BYTES * 2 + SIGNATURE_BYTES;
    if sealed.len() < prefix + TAG_BYTES || sealed[0] != SEALED_VERSION {
        return Err(RemoteCryptoError::Invalid);
    }
    let signing_public = &sealed[1..1 + PUBLIC_KEY_BYTES];
    let agreement_public = &sealed[1 + PUBLIC_KEY_BYTES..1 + PUBLIC_KEY_BYTES * 2];
    if !constant_time_equal(&commitment(signing_public)?, expected_signing_commitment)
        || !constant_time_equal(
            &commitment(agreement_public)?,
            expected_agreement_commitment,
        )
    {
        return Err(RemoteCryptoError::Authentication);
    }
    let signature = Signature::from_slice(&sealed[1 + PUBLIC_KEY_BYTES * 2..prefix])
        .map_err(|_| RemoteCryptoError::Invalid)?;
    let ciphertext = &sealed[prefix..];
    let aad = aad(&metadata(frame))?;
    let digest = Sha256::digest([aad.as_slice(), ciphertext].concat());
    let verifying =
        VerifyingKey::from_sec1_bytes(signing_public).map_err(|_| RemoteCryptoError::Invalid)?;
    verifying
        .verify(digest.as_slice(), &signature)
        .map_err(|_| RemoteCryptoError::Authentication)?;
    let shared = derive_shared(recipient_agreement_private, agreement_public)?;
    let salt = derive_salt(context)?;
    let key = derive_direction_key(&shared, &salt, frame.direction)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| RemoteCryptoError::Invalid)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&expected_nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RemoteCryptoError::Authentication)?,
    );
    decode_padded(&plaintext)
}

fn parse_public(raw: &[u8]) -> Result<PublicKey, RemoteCryptoError> {
    if raw.len() != PUBLIC_KEY_BYTES || raw.first() != Some(&4) {
        return Err(RemoteCryptoError::Invalid);
    }
    PublicKey::from_sec1_bytes(raw).map_err(|_| RemoteCryptoError::Invalid)
}

fn validate_context(context: &SharedContext) -> Result<(), RemoteCryptoError> {
    if !prefixed_hex(&context.mailbox_id, "mbx-", 64)
        || context.epoch == 0
        || context.epoch > MAX_SAFE_INTEGER
    {
        return Err(RemoteCryptoError::Invalid);
    }
    Ok(())
}

fn validate_metadata(meta: &FrameMetadata) -> Result<(), RemoteCryptoError> {
    if meta.schema != FRAME_SCHEMA
        || meta.crypto_suite != CRYPTO_SUITE
        || !prefixed_hex(&meta.mailbox_id, "mbx-", 64)
        || meta.epoch == 0
        || meta.epoch > MAX_SAFE_INTEGER
        || meta.sequence == 0
        || meta.sequence > MAX_SAFE_INTEGER
        || !prefixed_hex(&meta.message_id, "msg-", 32)
        || meta.issued_at <= 0
        || meta.issued_at as u64 > MAX_SAFE_INTEGER
        || meta.expires_at <= meta.issued_at
        || meta.expires_at as u64 > MAX_SAFE_INTEGER
        || meta.expires_at - meta.issued_at > 600
    {
        return Err(RemoteCryptoError::Invalid);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&meta.nonce)
        .map_err(|_| RemoteCryptoError::Invalid)?;
    if nonce.len() != 12 {
        return Err(RemoteCryptoError::Invalid);
    }
    Ok(())
}

fn validate_frame(frame: &OpaqueFrame) -> Result<(), RemoteCryptoError> {
    validate_metadata(&metadata(frame))?;
    let raw = URL_SAFE_NO_PAD
        .decode(&frame.ciphertext)
        .map_err(|_| RemoteCryptoError::Invalid)?;
    if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
        return Err(RemoteCryptoError::Size);
    }
    Ok(())
}

fn canonical_json(value: &Value) -> Result<String, RemoteCryptoError> {
    fn write(value: &Value, out: &mut String) -> Result<(), RemoteCryptoError> {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => out.push_str(&value.to_string()),
            Value::String(value) => {
                out.push_str(&serde_json::to_string(value).map_err(|_| RemoteCryptoError::Invalid)?)
            }
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    write(value, out)?;
                }
                out.push(']');
            }
            Value::Object(values) => {
                out.push('{');
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    out.push_str(
                        &serde_json::to_string(key).map_err(|_| RemoteCryptoError::Invalid)?,
                    );
                    out.push(':');
                    write(&values[key], out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out)
}

fn encode_padded(json: &[u8], padding: &[u8]) -> Result<Vec<u8>, RemoteCryptoError> {
    if json.len() > MAX_JSON_BYTES {
        return Err(RemoteCryptoError::Size);
    }
    let bucket = BUCKETS
        .into_iter()
        .find(|size| *size >= json.len() + 4)
        .ok_or(RemoteCryptoError::Size)?;
    if padding.len() != bucket - json.len() - 4 {
        return Err(RemoteCryptoError::Size);
    }
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(json);
    out.extend_from_slice(padding);
    Ok(out)
}

fn decode_padded(raw: &[u8]) -> Result<Value, RemoteCryptoError> {
    if !BUCKETS.contains(&raw.len()) || raw.len() < 4 {
        return Err(RemoteCryptoError::Size);
    }
    let length = u32::from_be_bytes(
        raw[..4]
            .try_into()
            .map_err(|_| RemoteCryptoError::Invalid)?,
    ) as usize;
    if length > MAX_JSON_BYTES || length + 4 > raw.len() {
        return Err(RemoteCryptoError::Invalid);
    }
    let text = std::str::from_utf8(&raw[4..4 + length]).map_err(|_| RemoteCryptoError::Invalid)?;
    let value = crate::stock_event_adapter::strict_json(text.as_bytes())
        .map_err(|_| RemoteCryptoError::Invalid)?;
    if canonical_json(&value)? != text {
        return Err(RemoteCryptoError::Invalid);
    }
    Ok(value)
}

fn prefixed_hex(value: &str, prefix: &str, digits: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|raw| {
        raw.len() == digits
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::pkcs8::DecodePrivateKey;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct WebVector {
        marker: String,
        frame: OpaqueFrame,
        host_signing_public_key_sec1: String,
        host_agreement_public_key_sec1: String,
        device_signing_public_key_sec1: String,
        device_agreement_public_key_sec1: String,
        host_signing_commitment: String,
        host_agreement_commitment: String,
        device_signing_commitment: String,
        device_agreement_commitment: String,
        shared_secret: String,
        salt: String,
        host_to_device_key: String,
        device_to_host_key: String,
        nonce: String,
        aad: String,
        ciphertext_and_tag: String,
        sealed_packet: String,
        canonical_plaintext_json: String,
        host_signing_private_key_pkcs8: SecretString,
        host_agreement_private_key_pkcs8: SecretString,
        device_signing_private_key_pkcs8: SecretString,
        device_agreement_private_key_pkcs8: SecretString,
    }

    fn keys(signing: u8, agreement: u8) -> EndpointKeys {
        EndpointKeys::from_scalars([signing; 32], [agreement; 32]).unwrap()
    }

    fn context(host: &EndpointKeys, device: &EndpointKeys) -> SharedContext {
        SharedContext {
            mailbox_id: format!("mbx-{}", "ab".repeat(32)),
            epoch: 3,
            host_signing_commitment: commitment(&host.signing_public()).unwrap(),
            host_agreement_commitment: commitment(&host.agreement_public()).unwrap(),
            device_signing_commitment: commitment(&device.signing_public()).unwrap(),
            device_agreement_commitment: commitment(&device.agreement_public()).unwrap(),
        }
    }

    fn meta(direction: Direction, sequence: u64) -> FrameMetadata {
        FrameMetadata {
            schema: FRAME_SCHEMA.into(),
            crypto_suite: CRYPTO_SUITE.into(),
            mailbox_id: format!("mbx-{}", "ab".repeat(32)),
            direction,
            epoch: 3,
            sequence,
            message_id: format!("msg-{}", "cd".repeat(16)),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_600,
            nonce: "placeholder".into(),
        }
    }

    #[test]
    fn both_directions_round_trip_and_keys_separate() {
        let host = keys(1, 2);
        let device = keys(3, 4);
        let context = context(&host, &device);
        let value = json!({"alpha":["x",true],"zebra":1});
        let padding = vec![0_u8; 512 - 4 - canonical_json(&value).unwrap().len()];
        let h2d = encrypt(
            meta(Direction::HostToDevice, 11),
            &value,
            &host,
            &device.agreement_public(),
            &context,
            &padding,
        )
        .unwrap();
        assert_eq!(
            decrypt(
                &h2d,
                &device.agreement,
                &context,
                &context.host_signing_commitment,
                &context.host_agreement_commitment
            )
            .unwrap(),
            value
        );
        let d2h = encrypt(
            meta(Direction::DeviceToHost, 12),
            &value,
            &device,
            &host.agreement_public(),
            &context,
            &padding,
        )
        .unwrap();
        assert_eq!(
            decrypt(
                &d2h,
                &host.agreement,
                &context,
                &context.device_signing_commitment,
                &context.device_agreement_commitment
            )
            .unwrap(),
            value
        );
        let shared = derive_shared(&host.agreement, &device.agreement_public()).unwrap();
        let salt = derive_salt(&context).unwrap();
        assert_ne!(
            *derive_direction_key(&shared, &salt, Direction::HostToDevice).unwrap(),
            *derive_direction_key(&shared, &salt, Direction::DeviceToHost).unwrap()
        );
    }

    #[test]
    fn mutations_fail_closed() {
        let host = keys(5, 6);
        let device = keys(7, 8);
        let context = context(&host, &device);
        let value = json!({"msg":"hello"});
        let padding = vec![1_u8; 512 - 4 - canonical_json(&value).unwrap().len()];
        let frame = encrypt(
            meta(Direction::HostToDevice, 21),
            &value,
            &host,
            &device.agreement_public(),
            &context,
            &padding,
        )
        .unwrap();
        let mut nonce = frame.clone();
        nonce.nonce = URL_SAFE_NO_PAD.encode([0_u8; 12]);
        assert_eq!(
            decrypt(
                &nonce,
                &device.agreement,
                &context,
                &context.host_signing_commitment,
                &context.host_agreement_commitment
            ),
            Err(RemoteCryptoError::Authentication)
        );
        let mut ciphertext = frame.clone();
        let mut sealed = URL_SAFE_NO_PAD.decode(&ciphertext.ciphertext).unwrap();
        sealed[130] ^= 1;
        ciphertext.ciphertext = URL_SAFE_NO_PAD.encode(sealed);
        assert!(decrypt(
            &ciphertext,
            &device.agreement,
            &context,
            &context.host_signing_commitment,
            &context.host_agreement_commitment
        )
        .is_err());
        let mut wrong = context.host_signing_commitment;
        wrong[0] ^= 1;
        assert_eq!(
            decrypt(
                &frame,
                &device.agreement,
                &context,
                &wrong,
                &context.host_agreement_commitment
            ),
            Err(RemoteCryptoError::Authentication)
        );
    }

    #[test]
    fn nonce_and_canonical_plaintext_are_exact() {
        assert_eq!(
            hex_lower(&deterministic_nonce(Direction::HostToDevice, 7).unwrap()),
            "35dcaba90000000000000007"
        );
        assert_eq!(
            hex_lower(&deterministic_nonce(Direction::DeviceToHost, 9).unwrap()),
            "2ead77030000000000000009"
        );
        assert_eq!(
            canonical_json(&json!({"b":1,"a":2})).unwrap(),
            "{\"a\":2,\"b\":1}"
        );
        assert!(decode_padded(&[0_u8; 511]).is_err());
    }

    #[test]
    fn endpoint_capabilities_use_sha256_p1363_and_zeroizing_ecdh() {
        let host = keys(31, 32);
        let peer = keys(33, 34);
        let message = b"webcrypto-compatible message";

        let signature_bytes = host.sign_p1363(message).unwrap();
        assert_eq!(signature_bytes.len(), SIGNATURE_BYTES);
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        VerifyingKey::from_sec1_bytes(&host.signing_public())
            .unwrap()
            .verify(message, &signature)
            .unwrap();
        VerifyingKey::from_sec1_bytes(&host.signing_public())
            .unwrap()
            .verify_prehash(&Sha256::digest(message), &signature)
            .unwrap();

        let host_shared = host
            .derive_agreement_shared(&peer.agreement_public())
            .unwrap();
        let peer_shared = peer
            .derive_agreement_shared(&host.agreement_public())
            .unwrap();
        assert_eq!(*host_shared, *peer_shared);
    }

    #[test]
    fn decrypts_webcrypto_fixed_vector_byte_for_byte() {
        let vector: WebVector = serde_json::from_str(include_str!(
            "../../contracts/vectors/remote-envelope-v2.json"
        ))
        .unwrap();
        assert_eq!(vector.marker, "TEST_ONLY_VECTOR");
        let decode_b64 = |value: &str| Zeroizing::new(URL_SAFE_NO_PAD.decode(value).unwrap());
        let decode_hex_vec = |value: &str| {
            (0..value.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let decode_hex = |value: &str| -> [u8; 32] {
            let bytes = decode_hex_vec(value);
            bytes.try_into().unwrap()
        };
        let host_agreement = SecretKey::from_pkcs8_der(&decode_b64(
            vector.host_agreement_private_key_pkcs8.as_str(),
        ))
        .unwrap();
        let device_agreement = SecretKey::from_pkcs8_der(&decode_b64(
            vector.device_agreement_private_key_pkcs8.as_str(),
        ))
        .unwrap();
        let host_signing =
            SigningKey::from_pkcs8_der(&decode_b64(vector.host_signing_private_key_pkcs8.as_str()))
                .unwrap();
        let device_signing = SigningKey::from_pkcs8_der(&decode_b64(
            vector.device_signing_private_key_pkcs8.as_str(),
        ))
        .unwrap();
        assert_eq!(
            VerifyingKey::from(&host_signing)
                .to_encoded_point(false)
                .as_bytes(),
            decode_b64(&vector.host_signing_public_key_sec1).as_slice()
        );
        assert_eq!(
            host_agreement
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
            decode_b64(&vector.host_agreement_public_key_sec1).as_slice()
        );
        assert_eq!(
            VerifyingKey::from(&device_signing)
                .to_encoded_point(false)
                .as_bytes(),
            decode_b64(&vector.device_signing_public_key_sec1).as_slice()
        );
        assert_eq!(
            device_agreement
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
            decode_b64(&vector.device_agreement_public_key_sec1).as_slice()
        );
        let context = SharedContext {
            mailbox_id: vector.frame.mailbox_id.clone(),
            epoch: vector.frame.epoch,
            host_signing_commitment: decode_hex(&vector.host_signing_commitment),
            host_agreement_commitment: decode_hex(&vector.host_agreement_commitment),
            device_signing_commitment: decode_hex(&vector.device_signing_commitment),
            device_agreement_commitment: decode_hex(&vector.device_agreement_commitment),
        };
        let shared = derive_shared(
            &device_agreement,
            &decode_b64(&vector.host_agreement_public_key_sec1),
        )
        .unwrap();
        assert_eq!(*shared, decode_hex(&vector.shared_secret));
        let salt = derive_salt(&context).unwrap();
        assert_eq!(salt, decode_hex(&vector.salt));
        assert_eq!(
            *derive_direction_key(&shared, &salt, Direction::HostToDevice).unwrap(),
            decode_hex(&vector.host_to_device_key)
        );
        assert_eq!(
            *derive_direction_key(&shared, &salt, Direction::DeviceToHost).unwrap(),
            decode_hex(&vector.device_to_host_key)
        );
        assert_eq!(
            deterministic_nonce(Direction::HostToDevice, 11)
                .unwrap()
                .as_slice(),
            decode_hex_vec(&vector.nonce)
        );
        assert_eq!(
            aad(&metadata(&vector.frame)).unwrap(),
            decode_b64(&vector.aad).as_slice()
        );
        let sealed = decode_b64(&vector.sealed_packet);
        assert_eq!(
            sealed.as_slice(),
            decode_b64(&vector.frame.ciphertext).as_slice()
        );
        let prefix = 1 + PUBLIC_KEY_BYTES * 2 + SIGNATURE_BYTES;
        assert_eq!(
            &sealed[prefix..],
            decode_b64(&vector.ciphertext_and_tag).as_slice()
        );
        let plaintext = decrypt(
            &vector.frame,
            &device_agreement,
            &context,
            &context.host_signing_commitment,
            &context.host_agreement_commitment,
        )
        .unwrap();
        assert_eq!(
            canonical_json(&plaintext).unwrap(),
            vector.canonical_plaintext_json
        );

        let host = EndpointKeys {
            signing: host_signing,
            agreement: host_agreement,
        };
        let json_value: Value = serde_json::from_str(&vector.canonical_plaintext_json).unwrap();
        let padding = vec![0_u8; 512 - 4 - vector.canonical_plaintext_json.len()];
        let rust_frame = encrypt(
            metadata(&vector.frame),
            &json_value,
            &host,
            &decode_b64(&vector.device_agreement_public_key_sec1),
            &context,
            &padding,
        )
        .unwrap();
        let rust_packet = URL_SAFE_NO_PAD.decode(&rust_frame.ciphertext).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                &rust_packet[1 + PUBLIC_KEY_BYTES * 2..1 + PUBLIC_KEY_BYTES * 2 + SIGNATURE_BYTES]
            ),
            "I1AMVNcw1SaRpx-aqXSmGDHvo4KMZ4462z9uldpvtcMW2EyChGobt08c6uStkUtRMY8gzIMf0YNHEnt35gGOcQ"
        );
    }
}
