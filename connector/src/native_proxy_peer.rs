//! Test-feature-only native proxy peer for the N2b1 four-descriptor contract.
//! It authenticates the already-bound proxy origin but deliberately does not
//! accept connections, forward HTTP, or create command authority.

use crate::run_binding::{proxy_handshake, RunBindingHello};
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

pub const NATIVE_PROXY_PEER_BLOCKED: &str = "BLOCKED_NATIVE_PROXY_PEER";
pub const NATIVE_PROXY_PEER_READY: &str = "NATIVE_PROXY_PEER_READY";
const CONFIG_SCHEMA: &str = "nomad.native-proxy-peer.v1";
const MAX_CONFIG: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeProxyPeerError;

impl std::fmt::Display for NativeProxyPeerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(NATIVE_PROXY_PEER_BLOCKED)
    }
}
impl std::error::Error for NativeProxyPeerError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyConfig {
    schema_version: String,
    run_id: String,
    nonce: String,
    capability_digest: String,
    proxy_origin: String,
}

struct Secret([u8; 32]);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Accepts exactly four descriptor arguments: listener, binding, secret, config.
pub fn native_proxy_peer_entrypoint() -> Result<(), NativeProxyPeerError> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.len() != 4 {
        return Err(NativeProxyPeerError);
    }
    let descriptors = [
        parse_fd(&raw[0])?,
        parse_fd(&raw[1])?,
        parse_fd(&raw[2])?,
        parse_fd(&raw[3])?,
    ];
    if (0..descriptors.len()).any(|left| {
        (left + 1..descriptors.len()).any(|right| descriptors[left] == descriptors[right])
    }) {
        return Err(NativeProxyPeerError);
    }
    // SAFETY: every numeric descriptor is distinct and ownership is acquired once.
    let owned = unsafe { descriptors.map(|descriptor| OwnedFd::from_raw_fd(descriptor)) };
    run(owned)
}

fn parse_fd(raw: &str) -> Result<RawFd, NativeProxyPeerError> {
    raw.parse::<RawFd>()
        .ok()
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
        .ok_or(NativeProxyPeerError)
}

fn run(descriptors: [OwnedFd; 4]) -> Result<(), NativeProxyPeerError> {
    for descriptor in &descriptors {
        set_cloexec(descriptor)?;
    }
    if !is_connected_unix_stream(&descriptors[1])?
        || !is_read_pipe(&descriptors[2])?
        || !is_read_pipe(&descriptors[3])?
    {
        return Err(NativeProxyPeerError);
    }
    let origin = listener_origin(&descriptors[0])?;
    let [listener, binding, secret_reader, config_reader] = descriptors;

    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let secret = read_secret(secret_reader, deadline)?;
    let config = read_config(config_reader, deadline)?;
    if config.schema_version != CONFIG_SCHEMA || config.proxy_origin != origin {
        return Err(NativeProxyPeerError);
    }

    let mut binding = UnixStream::from(binding);
    binding
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| NativeProxyPeerError)?;
    binding
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|_| NativeProxyPeerError)?;
    proxy_handshake(
        &mut binding,
        RunBindingHello {
            run_id: config.run_id,
            proxy_origin: config.proxy_origin,
            nonce: config.nonce,
            capability_digest: config.capability_digest,
        },
        secret.0,
    )
    .map_err(|_| NativeProxyPeerError)?;
    drop((listener, binding, secret));
    Ok(())
}

fn set_cloexec(descriptor: &OwnedFd) -> Result<(), NativeProxyPeerError> {
    // SAFETY: fcntl operates on a live owned descriptor.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFD,
                flags | libc::FD_CLOEXEC,
            )
        } != 0
    {
        return Err(NativeProxyPeerError);
    }
    Ok(())
}

fn is_read_pipe(descriptor: &OwnedFd) -> Result<bool, NativeProxyPeerError> {
    // SAFETY: fcntl operates on a live descriptor.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(NativeProxyPeerError);
    }
    // SAFETY: fstat initializes the stat buffer for a live descriptor.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeProxyPeerError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFIFO
        && (flags & libc::O_ACCMODE) == libc::O_RDONLY)
}

fn is_connected_unix_stream(descriptor: &OwnedFd) -> Result<bool, NativeProxyPeerError> {
    let mut socket_type: libc::c_int = 0;
    let mut type_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes an integer to valid storage.
    if unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
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
    // SAFETY: sockaddr_storage is large enough for the returned address.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            descriptor.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } != 0
        || i32::from(address.ss_family) != libc::AF_UNIX
    {
        return Ok(false);
    }
    length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    Ok(unsafe {
        libc::getpeername(
            descriptor.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } == 0)
}

fn listener_origin(descriptor: &OwnedFd) -> Result<String, NativeProxyPeerError> {
    let mut socket_type: libc::c_int = 0;
    let mut option_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes integers to valid storage.
    let type_ok = unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut option_length,
        )
    } == 0;
    if !type_ok || socket_type != libc::SOCK_STREAM {
        return Err(NativeProxyPeerError);
    }
    // SAFETY: sockaddr_in is valid writable storage and its size is supplied.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            descriptor.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    } != 0
        || i32::from(address.sin_family) != libc::AF_INET
        || address.sin_addr.s_addr != u32::from_ne_bytes([127, 0, 0, 1])
    {
        return Err(NativeProxyPeerError);
    }
    let port = u16::from_be(address.sin_port);
    if port == 0 {
        return Err(NativeProxyPeerError);
    }
    // Darwin does not expose SO_ACCEPTCONN. Re-applying listen is idempotent
    // for an inherited listener and guarantees the received bound socket is
    // listening before the child treats its origin as valid.
    if unsafe { libc::listen(descriptor.as_raw_fd(), 128) } != 0 {
        return Err(NativeProxyPeerError);
    }
    Ok(format!("http://127.0.0.1:{port}"))
}

fn read_secret(descriptor: OwnedFd, deadline: Instant) -> Result<Secret, NativeProxyPeerError> {
    set_nonblocking(&descriptor)?;
    let mut reader = File::from(descriptor);
    let mut secret = Secret([0; 32]);
    let mut offset = 0;
    while offset < secret.0.len() {
        if Instant::now() >= deadline {
            return Err(NativeProxyPeerError);
        }
        match reader.read(&mut secret.0[offset..]) {
            Ok(0) => return Err(NativeProxyPeerError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return Err(NativeProxyPeerError),
        }
    }
    let mut trailing = [0; 1];
    loop {
        if Instant::now() >= deadline {
            return Err(NativeProxyPeerError);
        }
        match reader.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(NativeProxyPeerError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return Err(NativeProxyPeerError),
        }
    }
    if secret.0.iter().all(|byte| *byte == 0) {
        return Err(NativeProxyPeerError);
    }
    Ok(secret)
}

fn read_config(
    descriptor: OwnedFd,
    deadline: Instant,
) -> Result<ProxyConfig, NativeProxyPeerError> {
    set_nonblocking(&descriptor)?;
    let raw = read_until_eof(File::from(descriptor), MAX_CONFIG + 1, deadline)?;
    if raw.is_empty() || raw.len() > MAX_CONFIG {
        return Err(NativeProxyPeerError);
    }
    // Deserialize the typed schema before using Value for the canonical byte
    // comparison so serde rejects duplicate and unknown object fields.
    let config: ProxyConfig = serde_json::from_slice(&raw).map_err(|_| NativeProxyPeerError)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&raw);
    let value = Value::deserialize(&mut deserializer).map_err(|_| NativeProxyPeerError)?;
    deserializer.end().map_err(|_| NativeProxyPeerError)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| NativeProxyPeerError)?;
    if canonical != raw {
        return Err(NativeProxyPeerError);
    }
    Ok(config)
}

fn set_nonblocking(descriptor: &OwnedFd) -> Result<(), NativeProxyPeerError> {
    // SAFETY: fcntl operates on a live owned descriptor.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                descriptor.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        } != 0
    {
        return Err(NativeProxyPeerError);
    }
    Ok(())
}

fn read_until_eof(
    mut reader: File,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NativeProxyPeerError> {
    let mut output = Vec::new();
    let mut buffer = [0; 512];
    loop {
        if Instant::now() >= deadline {
            return Err(NativeProxyPeerError);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) if output.len() + count <= limit => {
                output.extend_from_slice(&buffer[..count]);
            }
            Ok(_) => return Err(NativeProxyPeerError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return Err(NativeProxyPeerError),
        }
    }
}
