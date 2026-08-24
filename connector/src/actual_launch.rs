//! Authenticated, bounded C1a launch-provenance envelope parsing.
//! This module creates no capability and grants no command authority.
use crate::run_binding::{
    canonical, constant_time_eq, hmac_sha256, HostRunBinding, RunBinding, RunBindingError,
};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
#[cfg(unix)]
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::time::Duration;

const MAGIC: &[u8; 8] = b"NOMADALP";
const VERSION: u16 = 1;
const MAX_PAYLOAD: usize = 65_536;
const MAX_PATH: usize = 4096;
const MAX_DEPENDENCIES: u64 = 65_535;
const SCHEMA: &str = "nomad.actual-launch-provenance.v1";
const PACKAGE_NAME: &str = "opencode-ai";
const VERSION_VALUE: &str = "1.18.16";
const NPM_VERSION: &str = "11.12.1";
const ADAPTER_ID: &str = "opencode";
const HMAC_DOMAIN: &[u8] = b"nomad-actual-launch-provenance-v1";
const CLAIM_DOMAIN: &[u8] = b"nomad-c1a-transport-claim-v1";
const FIELDS: &[&str] = &[
    "schema_version",
    "run_id",
    "package_name",
    "package_version",
    "package_lock_raw_digest",
    "full_locked_dependency_count",
    "full_locked_dependency_digest",
    "installed_platform_dependency_count",
    "installed_platform_dependency_digest",
    "entrypoint_realpath",
    "entrypoint_raw_digest",
    "npm_executable_realpath",
    "npm_version",
    "task_spec_digest",
    "fixture_manifest_digest",
    "adapter_id",
    "adapter_version",
];

/// Opaque actual-launch facts. Only the crate-private authenticated adoption
/// path can construct this type. It is deliberately not Clone or serializable.
pub struct ActualLaunchProvenance {
    run_id: String,
    package_name: String,
    package_version: String,
    package_lock_raw_digest: String,
    full_locked_dependency_count: u64,
    full_locked_dependency_digest: String,
    installed_platform_dependency_count: u64,
    installed_platform_dependency_digest: String,
    entrypoint_realpath: String,
    entrypoint_raw_digest: String,
    npm_executable_realpath: String,
    npm_version: String,
    task_spec_digest: String,
    fixture_manifest_digest: String,
    adapter_id: String,
    adapter_version: String,
}

impl ActualLaunchProvenance {
    fn sealed_invariants(&self) -> bool {
        lower_hex_64(&self.run_id)
            && self.package_name == PACKAGE_NAME
            && self.package_version == VERSION_VALUE
            && lower_hex_64(&self.package_lock_raw_digest)
            && (1..=MAX_DEPENDENCIES).contains(&self.full_locked_dependency_count)
            && lower_hex_64(&self.full_locked_dependency_digest)
            && (1..=MAX_DEPENDENCIES).contains(&self.installed_platform_dependency_count)
            && lower_hex_64(&self.installed_platform_dependency_digest)
            && valid_absolute_path(&self.entrypoint_realpath)
            && lower_hex_64(&self.entrypoint_raw_digest)
            && valid_absolute_path(&self.npm_executable_realpath)
            && self.npm_version == NPM_VERSION
            && lower_hex_64(&self.task_spec_digest)
            && lower_hex_64(&self.fixture_manifest_digest)
            && self.adapter_id == ADAPTER_ID
            && self.adapter_version == VERSION_VALUE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActualLaunchError {
    Arguments,
    Descriptor,
    Secret,
    Binding,
    Io,
    Frame,
    Authentication,
    Claim,
    Schema,
    Canonical,
}

impl fmt::Display for ActualLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Arguments => "actual launch arguments rejected",
            Self::Descriptor => "actual launch descriptors rejected",
            Self::Secret => "actual launch secret rejected",
            Self::Binding => "actual launch binding rejected",
            Self::Io => "actual launch input failed",
            Self::Frame => "actual launch frame rejected",
            Self::Authentication => "actual launch authentication failed",
            Self::Claim => "actual launch transport claim rejected",
            Self::Schema => "actual launch schema rejected",
            Self::Canonical => "actual launch canonical form rejected",
        })
    }
}
impl std::error::Error for ActualLaunchError {}

#[cfg(unix)]
#[cfg(feature = "actual_launch_test_helper")]
pub fn actual_launch_adopter_entrypoint() -> Result<(), ActualLaunchError> {
    adopt_actual_launch_from_process_args().map(drop)
}

#[cfg(unix)]
pub(crate) fn adopt_actual_launch_from_process_args(
) -> Result<ActualLaunchProvenance, ActualLaunchError> {
    // Dedicated-process ownership boundary: from exec until the three
    // `OwnedFd` values below are created, this process is single-threaded and
    // performs only argv parsing, F_GETFD liveness checks and challenge
    // decoding. It opens, closes and duplicates no descriptor, so a validated
    // numeric FD cannot be reused by intervening adopter code.
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() != 4 {
        return Err(ActualLaunchError::Arguments);
    }
    let binding_fd = parse_fd(&arguments[0])?;
    let secret_fd = parse_fd(&arguments[1])?;
    let provenance_fd = parse_fd(&arguments[2])?;
    if binding_fd == secret_fd || binding_fd == provenance_fd || secret_fd == provenance_fd {
        return Err(ActualLaunchError::Descriptor);
    }
    for descriptor in [binding_fd, secret_fd, provenance_fd] {
        // SAFETY: F_GETFD only inspects the numeric descriptor. The dedicated
        // adopter is single-threaded until ownership is established below.
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
            return Err(ActualLaunchError::Descriptor);
        }
    }
    let challenge = parse_challenge(&arguments[3])?;
    // SAFETY: this dedicated process receives ownership of exactly these three
    // inherited descriptors. Pairwise numeric distinctness is checked above;
    // the OS identities and types are checked before any protocol operation.
    let binding = unsafe { OwnedFd::from_raw_fd(binding_fd) };
    let secret = unsafe { OwnedFd::from_raw_fd(secret_fd) };
    let provenance = unsafe { OwnedFd::from_raw_fd(provenance_fd) };
    adopt_from_owned_fds(binding, secret, provenance, challenge)
}

#[cfg(not(unix))]
#[cfg(feature = "actual_launch_test_helper")]
pub fn actual_launch_adopter_entrypoint() -> Result<(), ActualLaunchError> {
    Err(ActualLaunchError::Descriptor)
}

#[cfg(not(unix))]
pub(crate) fn adopt_actual_launch_from_process_args(
) -> Result<ActualLaunchProvenance, ActualLaunchError> {
    Err(ActualLaunchError::Descriptor)
}

#[cfg(unix)]
fn parse_fd(raw: &str) -> Result<RawFd, ActualLaunchError> {
    raw.parse::<RawFd>()
        .ok()
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or(ActualLaunchError::Arguments)
}

#[cfg(unix)]
fn parse_challenge(raw: &str) -> Result<[u8; 32], ActualLaunchError> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ActualLaunchError::Arguments);
    }
    let mut result = [0u8; 32];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    if result.iter().all(|byte| *byte == 0) {
        return Err(ActualLaunchError::Arguments);
    }
    Ok(result)
}

#[cfg(unix)]
fn hex_value(value: u8) -> Result<u8, ActualLaunchError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ActualLaunchError::Arguments),
    }
}

#[cfg(unix)]
fn adopt_from_owned_fds(
    binding_fd: OwnedFd,
    secret_fd: OwnedFd,
    provenance_fd: OwnedFd,
    challenge: [u8; 32],
) -> Result<ActualLaunchProvenance, ActualLaunchError> {
    validate_descriptors(&binding_fd, &secret_fd, &provenance_fd)?;
    set_cloexec(&binding_fd)?;
    set_cloexec(&secret_fd)?;
    set_cloexec(&provenance_fd)?;

    let mut secret_file = File::from(secret_fd);
    let mut secret = OwnedSecret([0u8; 32]);
    if secret_file.read_exact(&mut secret.0).is_err() {
        return Err(ActualLaunchError::Secret);
    }
    let mut trailing = [0u8; 1];
    match secret_file.read(&mut trailing) {
        Ok(0) => {}
        _ => {
            return Err(ActualLaunchError::Secret);
        }
    }
    drop(secret_file);
    if secret.0.iter().all(|byte| *byte == 0) {
        return Err(ActualLaunchError::Secret);
    }

    let mut host =
        HostRunBinding::new(challenge, secret.0).map_err(|_| ActualLaunchError::Binding)?;
    let mut socket = UnixStream::from(binding_fd);
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ActualLaunchError::Descriptor)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ActualLaunchError::Descriptor)?;
    let binding = host.handshake(&mut socket).map_err(map_binding_error)?;
    drop(socket);
    let mut provenance_file = File::from(provenance_fd);
    adopt_authenticated_envelope(&mut provenance_file, &binding, &mut secret.0)
}

#[cfg(unix)]
struct OwnedSecret([u8; 32]);
#[cfg(unix)]
impl Drop for OwnedSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[cfg(unix)]
fn map_binding_error(_: RunBindingError) -> ActualLaunchError {
    ActualLaunchError::Binding
}

#[cfg(unix)]
fn validate_descriptors(
    binding: &OwnedFd,
    secret: &OwnedFd,
    provenance: &OwnedFd,
) -> Result<(), ActualLaunchError> {
    let identities = [
        fd_identity(binding)?,
        fd_identity(secret)?,
        fd_identity(provenance)?,
    ];
    if identities[0] == identities[1]
        || identities[0] == identities[2]
        || identities[1] == identities[2]
        || !is_unix_stream(binding)?
        || !is_read_pipe(secret)?
        || !is_read_pipe(provenance)?
    {
        return Err(ActualLaunchError::Descriptor);
    }
    Ok(())
}

#[cfg(unix)]
fn fd_identity(fd: &OwnedFd) -> Result<(u64, u64), ActualLaunchError> {
    // SAFETY: `stat` is initialized by fstat for a live owned descriptor.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(ActualLaunchError::Descriptor);
    }
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

#[cfg(unix)]
fn is_read_pipe(fd: &OwnedFd) -> Result<bool, ActualLaunchError> {
    // SAFETY: fcntl is called with a live owned descriptor and no pointer arg.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(ActualLaunchError::Descriptor);
    }
    // SAFETY: initialized by fstat as above.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(ActualLaunchError::Descriptor);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFIFO
        && (flags & libc::O_ACCMODE) == libc::O_RDONLY)
}

#[cfg(unix)]
fn is_unix_stream(fd: &OwnedFd) -> Result<bool, ActualLaunchError> {
    let mut socket_type: libc::c_int = 0;
    let mut type_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut type_length,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Ok(false);
    }
    // SAFETY: sockaddr_storage is sufficiently sized and length is initialized.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_length,
        )
    } != 0
        || i32::from(address.ss_family) != libc::AF_UNIX
    {
        return Ok(false);
    }
    address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    Ok(unsafe {
        libc::getpeername(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_length,
        )
    } == 0)
}

#[cfg(unix)]
fn set_cloexec(fd: &OwnedFd) -> Result<(), ActualLaunchError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(ActualLaunchError::Descriptor);
    }
    Ok(())
}

pub(crate) fn adopt_authenticated_envelope<R: Read>(
    reader: &mut R,
    binding: &RunBinding,
    secret: &mut [u8; 32],
) -> Result<ActualLaunchProvenance, ActualLaunchError> {
    let secret = SecretGuard(secret);
    let mut header = [0u8; 78];
    reader
        .read_exact(&mut header)
        .map_err(|_| ActualLaunchError::Io)?;
    if &header[..8] != MAGIC || u16::from_be_bytes([header[8], header[9]]) != VERSION {
        return Err(ActualLaunchError::Frame);
    }
    let payload_len = u32::from_be_bytes([header[10], header[11], header[12], header[13]]) as usize;
    if payload_len == 0 || payload_len > MAX_PAYLOAD {
        return Err(ActualLaunchError::Frame);
    }
    let expected_digest = &header[14..46];
    let expected_mac = &header[46..78];
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .map_err(|_| ActualLaunchError::Io)?;
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(ActualLaunchError::Frame),
        Err(_) => return Err(ActualLaunchError::Io),
    }
    let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
    if !constant_time_eq(&payload_digest, expected_digest) {
        return Err(ActualLaunchError::Authentication);
    }
    let mac = provenance_mac(secret.as_ref(), &binding.run_id, &payload_digest);
    if !constant_time_eq(&mac, expected_mac) {
        return Err(ActualLaunchError::Authentication);
    }
    let claim = transport_claim(&binding.run_id, &payload_digest);
    if !constant_time_eq(claim.as_bytes(), binding.capability_digest.as_bytes()) {
        return Err(ActualLaunchError::Claim);
    }
    parse_payload(&payload, &binding.run_id)
}

struct SecretGuard<'a>(&'a mut [u8; 32]);
impl SecretGuard<'_> {
    fn as_ref(&self) -> &[u8; 32] {
        self.0
    }
}
impl Drop for SecretGuard<'_> {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub(crate) fn provenance_mac(
    secret: &[u8; 32],
    run_id: &str,
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    hmac_sha256(
        secret,
        &canonical(&[
            HMAC_DOMAIN,
            &VERSION.to_be_bytes(),
            run_id.as_bytes(),
            payload_digest,
        ]),
    )
}

pub(crate) fn transport_claim(run_id: &str, payload_digest: &[u8; 32]) -> String {
    format!(
        "{:x}",
        Sha256::digest(canonical(&[
            CLAIM_DOMAIN,
            &VERSION.to_be_bytes(),
            run_id.as_bytes(),
            payload_digest,
        ]))
    )
}

fn parse_payload(
    raw: &[u8],
    expected_run_id: &str,
) -> Result<ActualLaunchProvenance, ActualLaunchError> {
    let value = strict_json(raw)?;
    if canonical_json(&value)?.as_bytes() != raw {
        return Err(ActualLaunchError::Canonical);
    }
    let object = value.as_object().ok_or(ActualLaunchError::Schema)?;
    if object.len() != FIELDS.len() || !FIELDS.iter().all(|field| object.contains_key(*field)) {
        return Err(ActualLaunchError::Schema);
    }
    let string = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(ActualLaunchError::Schema)
    };
    let count = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .filter(|count| (1..=MAX_DEPENDENCIES).contains(count))
            .ok_or(ActualLaunchError::Schema)
    };
    let run_id = string("run_id")?;
    let package_name = string("package_name")?;
    let package_version = string("package_version")?;
    let package_lock_raw_digest = string("package_lock_raw_digest")?;
    let full_locked_dependency_digest = string("full_locked_dependency_digest")?;
    let installed_platform_dependency_digest = string("installed_platform_dependency_digest")?;
    let entrypoint_realpath = string("entrypoint_realpath")?;
    let entrypoint_raw_digest = string("entrypoint_raw_digest")?;
    let npm_executable_realpath = string("npm_executable_realpath")?;
    let npm_version = string("npm_version")?;
    let task_spec_digest = string("task_spec_digest")?;
    let fixture_manifest_digest = string("fixture_manifest_digest")?;
    let adapter_id = string("adapter_id")?;
    let adapter_version = string("adapter_version")?;
    if string("schema_version")? != SCHEMA
        || run_id != expected_run_id
        || !lower_hex_64(&run_id)
        || package_name != PACKAGE_NAME
        || package_version != VERSION_VALUE
        || npm_version != NPM_VERSION
        || adapter_id != ADAPTER_ID
        || adapter_version != VERSION_VALUE
        || ![
            &package_lock_raw_digest,
            &full_locked_dependency_digest,
            &installed_platform_dependency_digest,
            &entrypoint_raw_digest,
            &task_spec_digest,
            &fixture_manifest_digest,
        ]
        .into_iter()
        .all(|digest| lower_hex_64(digest))
        || !valid_absolute_path(&entrypoint_realpath)
        || !valid_absolute_path(&npm_executable_realpath)
    {
        return Err(ActualLaunchError::Schema);
    }
    let provenance = ActualLaunchProvenance {
        run_id,
        package_name,
        package_version,
        package_lock_raw_digest,
        full_locked_dependency_count: count("full_locked_dependency_count")?,
        full_locked_dependency_digest,
        installed_platform_dependency_count: count("installed_platform_dependency_count")?,
        installed_platform_dependency_digest,
        entrypoint_realpath,
        entrypoint_raw_digest,
        npm_executable_realpath,
        npm_version,
        task_spec_digest,
        fixture_manifest_digest,
        adapter_id,
        adapter_version,
    };
    if !provenance.sealed_invariants() {
        return Err(ActualLaunchError::Schema);
    }
    Ok(provenance)
}

fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_absolute_path(value: &str) -> bool {
    value.len() <= MAX_PATH
        && value.is_ascii()
        && value.starts_with('/')
        && value != "/"
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && !value.contains('\\')
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\0'))
}

struct StrictSeed;
impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}
struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate-free JSON")
    }
    fn visit_unit<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: DeError>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: DeError>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: DeError>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: DeError>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number"))
    }
    fn visit_str<E: DeError>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: DeError>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate"));
            }
            values.insert(key, map.next_value_seed(StrictSeed)?);
        }
        Ok(Value::Object(values))
    }
}
fn strict_json(raw: &[u8]) -> Result<Value, ActualLaunchError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSeed
        .deserialize(&mut deserializer)
        .map_err(|_| ActualLaunchError::Schema)?;
    deserializer.end().map_err(|_| ActualLaunchError::Schema)?;
    Ok(value)
}
fn canonical_json(value: &Value) -> Result<String, ActualLaunchError> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) if value.is_ascii() => {
            serde_json::to_string(value).map_err(|_| ActualLaunchError::Canonical)
        }
        Value::String(_) => Err(ActualLaunchError::Canonical),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut pairs = Vec::new();
            for key in keys {
                if !key.is_ascii() {
                    return Err(ActualLaunchError::Canonical);
                }
                pairs.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|_| ActualLaunchError::Canonical)?,
                    canonical_json(&values[key])?
                ));
            }
            Ok(format!("{{{}}}", pairs.join(",")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_binding::{proxy_handshake, RunBindingHello};
    use serde_json::json;
    use std::io::{Cursor, Read, Write};
    use std::os::fd::FromRawFd;
    use std::thread;

    struct OneByteReader(Cursor<Vec<u8>>);
    impl Read for OneByteReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(1);
            self.0.read(&mut output[..length])
        }
    }

    fn payload(run_id: &str) -> Vec<u8> {
        canonical_json(&json!({
            "adapter_id":"opencode", "adapter_version":"1.18.16",
            "entrypoint_raw_digest":"1".repeat(64), "entrypoint_realpath":"/locked/node_modules/opencode/bin/opencode",
            "fixture_manifest_digest":"2".repeat(64), "full_locked_dependency_count":12,
            "full_locked_dependency_digest":"3".repeat(64), "installed_platform_dependency_count":3,
            "installed_platform_dependency_digest":"4".repeat(64), "npm_executable_realpath":"/usr/local/bin/npm",
            "npm_version":"11.12.1", "package_lock_raw_digest":"5".repeat(64),
            "package_name":"opencode-ai", "package_version":"1.18.16", "run_id":run_id,
            "schema_version":"nomad.actual-launch-provenance.v1", "task_spec_digest":"6".repeat(64)
        })).unwrap().into_bytes()
    }
    fn frame(payload: &[u8], run_id: &str, secret: &[u8; 32]) -> (Vec<u8>, RunBinding) {
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let mut raw = MAGIC.to_vec();
        raw.extend(VERSION.to_be_bytes());
        raw.extend((payload.len() as u32).to_be_bytes());
        raw.extend(digest);
        raw.extend(provenance_mac(secret, run_id, &digest));
        raw.extend(payload);
        (
            raw,
            RunBinding {
                run_id: run_id.into(),
                proxy_origin: "http://127.0.0.1:43123".into(),
                capability_digest: transport_claim(run_id, &digest),
            },
        )
    }

    #[cfg(unix)]
    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        // SAFETY: the two-element output array is valid for libc::pipe.
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returns two new descriptors owned by this test.
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    #[cfg(unix)]
    fn write_and_close(descriptor: OwnedFd, bytes: &[u8]) {
        let mut file = File::from(descriptor);
        file.write_all(bytes).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn real_unix_descriptors_complete_binding_and_adoption() {
        let run_id = "a".repeat(64);
        let secret = [7u8; 32];
        let challenge = [9u8; 32];
        let payload = payload(&run_id);
        let (envelope, expected_binding) = frame(&payload, &run_id, &secret);
        let hello = RunBindingHello {
            run_id: run_id.clone(),
            proxy_origin: expected_binding.proxy_origin.clone(),
            nonce: "b".repeat(64),
            capability_digest: expected_binding.capability_digest.clone(),
        };
        let (binding_child, mut binding_parent) = UnixStream::pair().unwrap();
        let (secret_read, secret_write) = pipe_pair();
        let (provenance_read, provenance_write) = pipe_pair();
        write_and_close(secret_write, &secret);
        write_and_close(provenance_write, &envelope);
        let peer = thread::spawn(move || proxy_handshake(&mut binding_parent, hello, secret));
        let result = adopt_from_owned_fds(
            binding_child.into(),
            secret_read,
            provenance_read,
            challenge,
        );
        assert!(result.is_ok());
        assert!(peer.join().unwrap().is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn descriptor_alias_swap_and_write_end_fail_closed() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let (secret_read, secret_write) = pipe_pair();
        // SAFETY: dup creates a new descriptor referring to the same pipe identity.
        let duplicate = unsafe { libc::dup(secret_read.as_raw_fd()) };
        assert!(duplicate >= 0);
        let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
        assert_eq!(
            validate_descriptors(&socket.into(), &secret_read, &duplicate),
            Err(ActualLaunchError::Descriptor)
        );
        drop(secret_write);

        let (binding_pipe, binding_write) = pipe_pair();
        let (secret_read, secret_write) = pipe_pair();
        let (provenance_read, provenance_write) = pipe_pair();
        assert!(matches!(
            adopt_from_owned_fds(binding_pipe, secret_read, provenance_read, [1; 32]),
            Err(ActualLaunchError::Descriptor)
        ));
        drop((binding_write, secret_write, provenance_write));

        let (socket, _peer) = UnixStream::pair().unwrap();
        let (secret_read, secret_write) = pipe_pair();
        let (provenance_read, provenance_write) = pipe_pair();
        assert!(matches!(
            adopt_from_owned_fds(socket.into(), secret_write, provenance_read, [1; 32]),
            Err(ActualLaunchError::Descriptor)
        ));
        drop((secret_read, provenance_write));
    }

    #[test]
    #[cfg(unix)]
    fn secret_pipe_requires_exact_length_and_eof() {
        for secret_bytes in [vec![7u8; 31], vec![7u8; 33], vec![0u8; 32]] {
            let (socket, _peer) = UnixStream::pair().unwrap();
            let (secret_read, secret_write) = pipe_pair();
            let (provenance_read, provenance_write) = pipe_pair();
            write_and_close(secret_write, &secret_bytes);
            drop(provenance_write);
            assert!(matches!(
                adopt_from_owned_fds(socket.into(), secret_read, provenance_read, [1; 32]),
                Err(ActualLaunchError::Secret)
            ));
        }
    }

    #[test]
    #[cfg(unix)]
    fn descriptor_cloexec_and_challenge_policy_are_exact() {
        let (read_end, write_end) = pipe_pair();
        set_cloexec(&read_end).unwrap();
        let flags = unsafe { libc::fcntl(read_end.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        drop((read_end, write_end));
        assert!(parse_challenge(&"01".repeat(32)).is_ok());
        for invalid in ["00".repeat(32), "A1".repeat(32), "1".repeat(63)] {
            assert_eq!(parse_challenge(&invalid), Err(ActualLaunchError::Arguments));
        }
    }
    #[test]
    fn valid_canonical_envelope_adopts_opaque_value() {
        let run = "a".repeat(64);
        let mut secret = [7u8; 32];
        let (raw, binding) = frame(&payload(&run), &run, &secret);
        assert!(adopt_authenticated_envelope(&mut Cursor::new(raw), &binding, &mut secret).is_ok());
        assert_eq!(secret, [0; 32]);
        let mut secret = [7u8; 32];
        let (raw, binding) = frame(&payload(&run), &run, &secret);
        assert!(adopt_authenticated_envelope(
            &mut OneByteReader(Cursor::new(raw)),
            &binding,
            &mut secret
        )
        .is_ok());
        assert_eq!(secret, [0; 32]);
    }
    #[test]
    fn frame_digest_mac_claim_and_trailing_fail_closed() {
        let run = "a".repeat(64);
        let secret = [7u8; 32];
        for mode in 0..6 {
            let mut owned_secret = secret;
            let (mut raw, mut binding) = frame(&payload(&run), &run, &owned_secret);
            match mode {
                0 => raw[0] ^= 1,
                1 => raw[9] ^= 1,
                2 => raw[14] ^= 1,
                3 => raw[46] ^= 1,
                4 => binding.capability_digest = "0".repeat(64),
                _ => raw.push(0),
            }
            assert!(adopt_authenticated_envelope(
                &mut Cursor::new(raw),
                &binding,
                &mut owned_secret
            )
            .is_err());
            assert_eq!(owned_secret, [0; 32]);
        }
        let mut owned_secret = secret;
        let (raw, binding) = frame(&payload(&run), &run, &owned_secret);
        assert!(adopt_authenticated_envelope(
            &mut Cursor::new(raw[..raw.len() - 1].to_vec()),
            &binding,
            &mut owned_secret
        )
        .is_err());
        assert_eq!(owned_secret, [0; 32]);
        let (raw, binding) = frame(&payload(&run), &run, &secret);
        let mut wrong_secret = [8u8; 32];
        assert!(
            adopt_authenticated_envelope(&mut Cursor::new(raw), &binding, &mut wrong_secret)
                .is_err()
        );
        assert_eq!(wrong_secret, [0; 32]);
    }
    #[test]
    fn strict_schema_run_canonical_path_and_count_reject() {
        let run = "a".repeat(64);
        let secret = [7u8; 32];
        let valid: Value = serde_json::from_slice(&payload(&run)).unwrap();
        let mut cases = Vec::new();
        let mut x = valid.clone();
        x.as_object_mut().unwrap().insert("extra".into(), json!(1));
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut x = valid.clone();
        x.as_object_mut().unwrap().remove("npm_version");
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut x = valid.clone();
        x["run_id"] = json!("b".repeat(64));
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut x = valid.clone();
        x["entrypoint_realpath"] = json!("/locked/../escape");
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut x = valid.clone();
        x["entrypoint_realpath"] = json!("/locked/line\nbreak");
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut x = valid.clone();
        x["entrypoint_realpath"] = json!("/locked\\windows");
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut x = valid.clone();
        x["npm_executable_realpath"] = json!("/usr/local/工具/npm");
        cases.push(serde_json::to_vec(&x).unwrap());
        let mut x = valid.clone();
        x["full_locked_dependency_count"] = json!(0);
        cases.push(canonical_json(&x).unwrap().into_bytes());
        let mut noncanonical = payload(&run);
        noncanonical.push(b' ');
        cases.push(noncanonical);
        let duplicate = payload(&run);
        let mut duplicate = String::from_utf8(duplicate).unwrap();
        duplicate.pop();
        duplicate.push_str(",\"run_id\":\"");
        duplicate.push_str(&run);
        duplicate.push_str("\"}");
        cases.push(duplicate.into_bytes());
        for payload in cases {
            let mut owned_secret = secret;
            let (raw, binding) = frame(&payload, &run, &owned_secret);
            assert!(adopt_authenticated_envelope(
                &mut Cursor::new(raw),
                &binding,
                &mut owned_secret
            )
            .is_err());
            assert_eq!(owned_secret, [0; 32]);
        }
    }
    #[test]
    fn errors_are_content_free() {
        for error in [
            ActualLaunchError::Io,
            ActualLaunchError::Frame,
            ActualLaunchError::Authentication,
            ActualLaunchError::Claim,
            ActualLaunchError::Schema,
            ActualLaunchError::Canonical,
        ] {
            let shown = format!("{error:?} {error}");
            assert!(!shown.contains(&"a".repeat(64)));
            assert!(shown.len() < 100);
        }
    }
}
