//! Test-feature-only, one-shot GET audit proxy. It has no production entrypoint,
//! SSE support, command route, Provider access, or process-launch authority.

use crate::run_binding::{
    canonical, constant_time_eq, hmac_sha256, proxy_handshake, RunBindingHello,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

pub const NATIVE_AUDIT_PROXY_BLOCKED: &str = "BLOCKED_NATIVE_AUDIT_PROXY";
pub const NATIVE_AUDIT_PROXY_READY: &[u8] = b"NATIVE_AUDIT_PROXY_READY\n";
const SCHEMA: &str = "nomad.native-audit-proxy.v1";
const ROUTE_POLICY: &str = "audit-get-v1";
const DEADLINE_MS: u64 = 5_000;
const MAX_CONFIG: usize = 8_192;
const MAX_REQUEST: usize = 8_192;
const MAX_RESPONSE_HEADERS: usize = 8_192;
const MAX_RESPONSE_BODY: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeAuditProxyError;
impl fmt::Display for NativeAuditProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(NATIVE_AUDIT_PROXY_BLOCKED)
    }
}
impl std::error::Error for NativeAuditProxyError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    deadline_ms: u64,
    max_request_bytes: usize,
    max_response_body_bytes: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditConfig {
    capability_digest: String,
    config_mac: String,
    limits: Limits,
    nonce: String,
    proxy_origin: String,
    route_policy: String,
    run_id: String,
    schema_version: String,
    session_id: String,
    upstream_origin: String,
    workspace_dev: u64,
    workspace_ino: u64,
}

struct Secret([u8; 32]);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Produces the only accepted canonical configuration shape for process tests.
#[allow(clippy::too_many_arguments)]
pub fn native_audit_proxy_config(
    run_id: &str,
    nonce: &str,
    capability_digest: &str,
    proxy_origin: &str,
    upstream_origin: &str,
    session_id: &str,
    workspace_dev: u64,
    workspace_ino: u64,
    secret: &[u8; 32],
) -> Result<Vec<u8>, NativeAuditProxyError> {
    let mut config = AuditConfig {
        capability_digest: capability_digest.into(),
        config_mac: String::new(),
        limits: Limits {
            deadline_ms: DEADLINE_MS,
            max_request_bytes: MAX_REQUEST,
            max_response_body_bytes: MAX_RESPONSE_BODY,
        },
        nonce: nonce.into(),
        proxy_origin: proxy_origin.into(),
        route_policy: ROUTE_POLICY.into(),
        run_id: run_id.into(),
        schema_version: SCHEMA.into(),
        session_id: session_id.into(),
        upstream_origin: upstream_origin.into(),
        workspace_dev,
        workspace_ino,
    };
    config.config_mac = hex(&config_mac(secret, &config));
    serde_json::to_vec(&config).map_err(|_| NativeAuditProxyError)
}

/// Accepts exactly listener, binding, secret-reader, config-reader, workspace
/// directory and ready-writer descriptor arguments, in that order.
pub fn native_audit_proxy_entrypoint() -> Result<(), NativeAuditProxyError> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.len() != 6 {
        return Err(NativeAuditProxyError);
    }
    let mut numbers = Vec::with_capacity(6);
    for item in raw {
        numbers.push(
            item.parse::<RawFd>()
                .ok()
                .filter(|fd| *fd > libc::STDERR_FILENO)
                .ok_or(NativeAuditProxyError)?,
        );
    }
    if numbers.iter().copied().collect::<HashSet<_>>().len() != 6 {
        return Err(NativeAuditProxyError);
    }
    // SAFETY: each validated numeric descriptor is distinct and adopted once.
    let descriptors: Vec<OwnedFd> = numbers
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect();
    let descriptors: [OwnedFd; 6] = descriptors.try_into().map_err(|_| NativeAuditProxyError)?;
    run(descriptors)
}

fn run(descriptors: [OwnedFd; 6]) -> Result<(), NativeAuditProxyError> {
    let deadline = Instant::now() + Duration::from_millis(DEADLINE_MS);
    for descriptor in &descriptors {
        set_cloexec(descriptor)?;
    }
    if !is_connected_unix_stream(&descriptors[1])?
        || !is_pipe(&descriptors[2], libc::O_RDONLY)?
        || !is_pipe(&descriptors[3], libc::O_RDONLY)?
        || !is_directory(&descriptors[4])?
        || !is_pipe(&descriptors[5], libc::O_WRONLY)?
    {
        return Err(NativeAuditProxyError);
    }
    let proxy_origin = listener_origin(&descriptors[0])?;
    let [listener_fd, binding_fd, secret_fd, config_fd, workspace_fd, ready_fd] = descriptors;
    let workspace_metadata = File::from(workspace_fd)
        .metadata()
        .map_err(|_| NativeAuditProxyError)?;
    let secret = read_secret(secret_fd, deadline)?;
    let config = read_config(config_fd, deadline)?;
    validate_config(
        &config,
        &secret.0,
        &proxy_origin,
        workspace_metadata.dev(),
        workspace_metadata.ino(),
    )?;

    let mut binding = UnixStream::from(binding_fd);
    set_stream_deadline(&binding, deadline)?;
    proxy_handshake(
        &mut binding,
        RunBindingHello {
            run_id: config.run_id.clone(),
            proxy_origin: config.proxy_origin.clone(),
            nonce: config.nonce.clone(),
            capability_digest: config.capability_digest.clone(),
        },
        secret.0,
    )
    .map_err(|_| NativeAuditProxyError)?;
    drop(binding);

    write_ready(ready_fd, deadline)?;
    let listener = TcpListener::from(listener_fd);
    listener
        .set_nonblocking(true)
        .map_err(|_| NativeAuditProxyError)?;
    let mut client = accept_one(&listener, deadline)?;
    set_stream_deadline(&client, deadline)?;
    match serve_one(&mut client, &config, deadline) {
        Ok(()) => Ok(()),
        Err(Failure::Request) => {
            let _ = write_fixed_error(&mut client, 400, deadline);
            Err(NativeAuditProxyError)
        }
        Err(Failure::Upstream) => {
            let _ = write_fixed_error(&mut client, 502, deadline);
            Err(NativeAuditProxyError)
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Request,
    Upstream,
}

fn serve_one(
    client: &mut TcpStream,
    config: &AuditConfig,
    deadline: Instant,
) -> Result<(), Failure> {
    let request = read_headers(client, MAX_REQUEST, deadline).map_err(|_| Failure::Request)?;
    let target = validate_request(&request, &config.proxy_origin, &config.session_id)
        .map_err(|_| Failure::Request)?;
    reject_buffered_body(client).map_err(|_| Failure::Request)?;
    let upstream = parse_origin(&config.upstream_origin).map_err(|_| Failure::Upstream)?;
    let mut server = TcpStream::connect_timeout(
        &upstream,
        remaining(deadline).map_err(|_| Failure::Upstream)?,
    )
    .map_err(|_| Failure::Upstream)?;
    set_stream_deadline(&server, deadline).map_err(|_| Failure::Upstream)?;
    let outbound = format!(
        "GET {target} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        upstream.ip(),
        upstream.port()
    );
    server
        .write_all(outbound.as_bytes())
        .map_err(|_| Failure::Upstream)?;
    server.flush().map_err(|_| Failure::Upstream)?;
    let response_headers =
        read_headers(&mut server, MAX_RESPONSE_HEADERS, deadline).map_err(|_| Failure::Upstream)?;
    let response = validate_response_headers(&response_headers).map_err(|_| Failure::Upstream)?;
    let mut body = vec![0; response.content_length];
    server
        .read_exact(&mut body)
        .map_err(|_| Failure::Upstream)?;
    let mut trailing = [0u8; 1];
    if server.read(&mut trailing).map_err(|_| Failure::Upstream)? != 0 {
        return Err(Failure::Upstream);
    }
    parse_strict_json(&body).map_err(|_| Failure::Upstream)?;
    let head = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        body.len()
    );
    client
        .write_all(head.as_bytes())
        .map_err(|_| Failure::Request)?;
    client.write_all(&body).map_err(|_| Failure::Request)?;
    client.flush().map_err(|_| Failure::Request)
}

fn reject_buffered_body(client: &TcpStream) -> Result<(), NativeAuditProxyError> {
    let mut byte = [0u8; 1];
    // SAFETY: recv only writes at most one byte into the live buffer. DONTWAIT
    // observes already-buffered smuggling bytes without delaying an ordinary
    // keep-alive HTTP client that waits for the response.
    let count = unsafe {
        libc::recv(
            client.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if count > 0 {
        return Err(NativeAuditProxyError);
    }
    if count == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().kind() {
        std::io::ErrorKind::WouldBlock => Ok(()),
        _ => Err(NativeAuditProxyError),
    }
}

pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    pub(crate) content_length: usize,
}

pub(crate) fn validate_request<'a>(
    raw: &'a [u8],
    proxy_origin: &str,
    session_id: &str,
) -> Result<&'a str, NativeAuditProxyError> {
    validate_ascii_headers(raw)?;
    let text = std::str::from_utf8(raw).map_err(|_| NativeAuditProxyError)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut request_parts = lines.next().ok_or(NativeAuditProxyError)?.split(' ');
    let method = request_parts.next().ok_or(NativeAuditProxyError)?;
    let target = request_parts.next().ok_or(NativeAuditProxyError)?;
    let version = request_parts.next().ok_or(NativeAuditProxyError)?;
    if request_parts.next().is_some() || method != "GET" || version != "HTTP/1.1" {
        return Err(NativeAuditProxyError);
    }
    validate_target(target, session_id)?;
    let expected_host = proxy_origin
        .strip_prefix("http://")
        .ok_or(NativeAuditProxyError)?;
    let mut host = None;
    let mut content_length = None;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(NativeAuditProxyError);
        }
        let (name, value) = line.split_once(':').ok_or(NativeAuditProxyError)?;
        if name.is_empty()
            || name.trim() != name
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(NativeAuditProxyError);
        }
        let value = value.trim_matches(' ');
        let lower = name.to_ascii_lowercase();
        if lower == "host" {
            if host.replace(value).is_some() {
                return Err(NativeAuditProxyError);
            }
        } else if lower == "content-length" {
            if content_length.replace(value).is_some() {
                return Err(NativeAuditProxyError);
            }
        } else if lower == "transfer-encoding"
            || lower == "upgrade"
            || lower.starts_with("proxy-")
            || lower == "authorization"
            || lower == "cookie"
        {
            return Err(NativeAuditProxyError);
        }
    }
    if host != Some(expected_host) {
        return Err(NativeAuditProxyError);
    }
    if let Some(length) = content_length {
        if length != "0" {
            return Err(NativeAuditProxyError);
        }
    }
    Ok(target)
}

fn validate_target(target: &str, session_id: &str) -> Result<(), NativeAuditProxyError> {
    if !target.starts_with('/')
        || target.contains("//")
        || target.contains(['?', '#', '\\'])
        || !target.is_ascii()
        || target.split('/').any(|part| part == "." || part == "..")
    {
        return Err(NativeAuditProxyError);
    }
    let bytes = target.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(NativeAuditProxyError);
            }
            let value =
                hex_byte(bytes[index + 1], bytes[index + 2]).ok_or(NativeAuditProxyError)?;
            if value == b'/' || value == b'\\' || value == b'.' || value <= 0x1f || value == 0x7f {
                return Err(NativeAuditProxyError);
            }
            index += 3;
        } else {
            if bytes[index] <= 0x1f || bytes[index] == 0x7f {
                return Err(NativeAuditProxyError);
            }
            index += 1;
        }
    }
    if !safe_id(session_id) {
        return Err(NativeAuditProxyError);
    }
    let allowed = target == "/global/health"
        || target == "/doc"
        || target == "/question"
        || target == "/permission"
        || target == format!("/session/{session_id}")
        || target == format!("/session/{session_id}/diff");
    allowed.then_some(()).ok_or(NativeAuditProxyError)
}

pub(crate) fn validate_response_headers(raw: &[u8]) -> Result<ResponseHead, NativeAuditProxyError> {
    validate_ascii_headers(raw)?;
    let text = std::str::from_utf8(raw).map_err(|_| NativeAuditProxyError)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status_line = lines.next().ok_or(NativeAuditProxyError)?;
    let mut parts = status_line.split(' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(NativeAuditProxyError);
    }
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (200..300).contains(value))
        .ok_or(NativeAuditProxyError)?;
    let mut length = None;
    let mut content_type = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(NativeAuditProxyError)?;
        let lower = name.to_ascii_lowercase();
        let value = value.trim_matches(' ');
        if lower == "content-length" {
            if length.replace(value).is_some() {
                return Err(NativeAuditProxyError);
            }
        } else if lower == "content-type" {
            if content_type.replace(value).is_some() {
                return Err(NativeAuditProxyError);
            }
        } else if lower == "transfer-encoding" {
            return Err(NativeAuditProxyError);
        }
    }
    let content_length = length
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value <= MAX_RESPONSE_BODY)
        .ok_or(NativeAuditProxyError)?;
    let content_type = content_type.ok_or(NativeAuditProxyError)?;
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(NativeAuditProxyError);
    }
    Ok(ResponseHead {
        status,
        content_length,
    })
}

pub(crate) fn validate_ascii_headers(raw: &[u8]) -> Result<(), NativeAuditProxyError> {
    if raw.len() < 4 || !raw.ends_with(b"\r\n\r\n") {
        return Err(NativeAuditProxyError);
    }
    for (index, byte) in raw.iter().copied().enumerate() {
        if byte == b'\r' {
            if raw.get(index + 1) != Some(&b'\n') {
                return Err(NativeAuditProxyError);
            }
        } else if byte == b'\n' {
            if index == 0 || raw[index - 1] != b'\r' {
                return Err(NativeAuditProxyError);
            }
        } else if !(0x20..=0x7e).contains(&byte) {
            return Err(NativeAuditProxyError);
        }
    }
    Ok(())
}

pub(crate) fn read_headers<R: Read>(
    reader: &mut R,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NativeAuditProxyError> {
    let mut output = Vec::new();
    let mut byte = [0u8; 1];
    while output.len() < limit {
        if Instant::now() >= deadline {
            return Err(NativeAuditProxyError);
        }
        match reader.read(&mut byte) {
            Ok(0) => return Err(NativeAuditProxyError),
            Ok(_) => {
                output.push(byte[0]);
                if output.ends_with(b"\r\n\r\n") {
                    return Ok(output);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(NativeAuditProxyError),
        }
    }
    Err(NativeAuditProxyError)
}

pub(crate) fn parse_strict_json(raw: &[u8]) -> Result<Value, NativeAuditProxyError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = NoDuplicates
        .deserialize(&mut deserializer)
        .map_err(|_| NativeAuditProxyError)?;
    deserializer.end().map_err(|_| NativeAuditProxyError)?;
    Ok(value)
}

struct NoDuplicates;
impl<'de> DeserializeSeed<'de> for NoDuplicates {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}
struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value without duplicate object keys")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: de::Deserializer<'de>>(self, value: D) -> Result<Value, D::Error> {
        NoDuplicates.deserialize(value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Value, A::Error> {
        let mut output = Vec::new();
        while let Some(value) = values.next_element_seed(NoDuplicates)? {
            output.push(value);
        }
        Ok(Value::Array(output))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<Value, A::Error> {
        let mut output = serde_json::Map::new();
        while let Some(key) = values.next_key::<String>()? {
            if output.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            output.insert(key, values.next_value_seed(NoDuplicates)?);
        }
        Ok(Value::Object(output))
    }
}

fn validate_config(
    config: &AuditConfig,
    secret: &[u8; 32],
    origin: &str,
    workspace_dev: u64,
    workspace_ino: u64,
) -> Result<(), NativeAuditProxyError> {
    if config.schema_version != SCHEMA
        || config.route_policy != ROUTE_POLICY
        || config.limits.deadline_ms != DEADLINE_MS
        || config.limits.max_request_bytes != MAX_REQUEST
        || config.limits.max_response_body_bytes != MAX_RESPONSE_BODY
        || config.proxy_origin != origin
        || config.workspace_dev != workspace_dev
        || config.workspace_ino != workspace_ino
        || !lower_hex_64(&config.run_id)
        || !lower_hex_64(&config.nonce)
        || !lower_hex_64(&config.capability_digest)
        || !safe_id(&config.session_id)
        || parse_origin(&config.upstream_origin).is_err()
    {
        return Err(NativeAuditProxyError);
    }
    let supplied = decode_hex_32(&config.config_mac).ok_or(NativeAuditProxyError)?;
    constant_time_eq(&supplied, &config_mac(secret, config))
        .then_some(())
        .ok_or(NativeAuditProxyError)
}

fn config_mac(secret: &[u8; 32], config: &AuditConfig) -> [u8; 32] {
    hmac_sha256(
        secret,
        &canonical(&[
            b"nomad-native-audit-proxy-config-v1",
            config.run_id.as_bytes(),
            config.proxy_origin.as_bytes(),
            config.upstream_origin.as_bytes(),
            config.nonce.as_bytes(),
            config.capability_digest.as_bytes(),
            config.workspace_dev.to_string().as_bytes(),
            config.workspace_ino.to_string().as_bytes(),
            config.route_policy.as_bytes(),
            config.session_id.as_bytes(),
            config.limits.deadline_ms.to_string().as_bytes(),
            config.limits.max_request_bytes.to_string().as_bytes(),
            config.limits.max_response_body_bytes.to_string().as_bytes(),
        ]),
    )
}

fn read_config(fd: OwnedFd, deadline: Instant) -> Result<AuditConfig, NativeAuditProxyError> {
    set_nonblocking(&fd)?;
    let raw = read_until_eof(File::from(fd), MAX_CONFIG + 1, deadline)?;
    if raw.is_empty() || raw.len() > MAX_CONFIG {
        return Err(NativeAuditProxyError);
    }
    let config: AuditConfig = serde_json::from_slice(&raw).map_err(|_| NativeAuditProxyError)?;
    let value = parse_strict_json(&raw)?;
    if serde_json::to_vec(&value).map_err(|_| NativeAuditProxyError)? != raw {
        return Err(NativeAuditProxyError);
    }
    Ok(config)
}

fn read_secret(fd: OwnedFd, deadline: Instant) -> Result<Secret, NativeAuditProxyError> {
    set_nonblocking(&fd)?;
    let mut reader = File::from(fd);
    let mut secret = Secret([0; 32]);
    let mut offset = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(NativeAuditProxyError);
        }
        let read = if offset < secret.0.len() {
            reader.read(&mut secret.0[offset..])
        } else {
            let mut trailing = [0u8; 1];
            let result = reader.read(&mut trailing);
            trailing.fill(0);
            result
        };
        match read {
            Ok(0) if offset == secret.0.len() && secret.0.iter().any(|byte| *byte != 0) => {
                return Ok(secret);
            }
            Ok(0) => return Err(NativeAuditProxyError),
            Ok(count) if offset < secret.0.len() => offset += count,
            Ok(_) => return Err(NativeAuditProxyError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(NativeAuditProxyError),
        }
    }
}

fn read_until_eof(
    mut reader: File,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NativeAuditProxyError> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        if Instant::now() >= deadline {
            return Err(NativeAuditProxyError);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) if output.len() + count <= limit => {
                output.extend_from_slice(&buffer[..count])
            }
            Ok(_) => return Err(NativeAuditProxyError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => return Err(NativeAuditProxyError),
        }
    }
}

fn write_ready(fd: OwnedFd, deadline: Instant) -> Result<(), NativeAuditProxyError> {
    set_nonblocking(&fd)?;
    let mut writer = File::from(fd);
    let mut offset = 0;
    while offset < NATIVE_AUDIT_PROXY_READY.len() {
        if Instant::now() >= deadline {
            return Err(NativeAuditProxyError);
        }
        match writer.write(&NATIVE_AUDIT_PROXY_READY[offset..]) {
            Ok(0) => return Err(NativeAuditProxyError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => return Err(NativeAuditProxyError),
        }
    }
    Ok(())
}

fn write_fixed_error(
    stream: &mut TcpStream,
    status: u16,
    deadline: Instant,
) -> Result<(), NativeAuditProxyError> {
    set_stream_deadline(stream, deadline)?;
    let response =
        format!("HTTP/1.1 {status} Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .map_err(|_| NativeAuditProxyError)
}

fn accept_one(
    listener: &TcpListener,
    deadline: Instant,
) -> Result<TcpStream, NativeAuditProxyError> {
    loop {
        if Instant::now() >= deadline {
            return Err(NativeAuditProxyError);
        }
        match listener.accept() {
            Ok((stream, address)) if address.ip() == Ipv4Addr::LOCALHOST => return Ok(stream),
            Ok(_) => return Err(NativeAuditProxyError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => return Err(NativeAuditProxyError),
        }
    }
}

pub(crate) fn parse_origin(value: &str) -> Result<SocketAddr, NativeAuditProxyError> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|rest| rest.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(NativeAuditProxyError)?;
    Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}

fn listener_origin(fd: &OwnedFd) -> Result<String, NativeAuditProxyError> {
    let mut socket_type: libc::c_int = 0;
    let mut option_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt and getsockname write into correctly sized storage.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut option_length,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(NativeAuditProxyError);
    }
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    } != 0
        || i32::from(address.sin_family) != libc::AF_INET
        || address.sin_addr.s_addr != u32::from_ne_bytes([127, 0, 0, 1])
        || unsafe { libc::listen(fd.as_raw_fd(), 1) } != 0
    {
        return Err(NativeAuditProxyError);
    }
    let port = u16::from_be(address.sin_port);
    if port == 0 {
        return Err(NativeAuditProxyError);
    }
    Ok(format!("http://127.0.0.1:{port}"))
}

fn is_connected_unix_stream(fd: &OwnedFd) -> Result<bool, NativeAuditProxyError> {
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Ok(false);
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
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
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } == 0)
}

fn is_pipe(fd: &OwnedFd, direction: libc::c_int) -> Result<bool, NativeAuditProxyError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if flags < 0 || unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeAuditProxyError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFIFO && (flags & libc::O_ACCMODE) == direction)
}
fn is_directory(fd: &OwnedFd) -> Result<bool, NativeAuditProxyError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeAuditProxyError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}
fn set_cloexec(fd: &OwnedFd) -> Result<(), NativeAuditProxyError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(NativeAuditProxyError);
    }
    Ok(())
}
fn set_nonblocking(fd: &OwnedFd) -> Result<(), NativeAuditProxyError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(NativeAuditProxyError);
    }
    Ok(())
}
fn set_stream_deadline(
    stream: &impl StreamTimeout,
    deadline: Instant,
) -> Result<(), NativeAuditProxyError> {
    let timeout = remaining(deadline)?;
    stream
        .set_timeouts(Some(timeout))
        .map_err(|_| NativeAuditProxyError)
}
trait StreamTimeout {
    fn set_timeouts(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}
impl StreamTimeout for TcpStream {
    fn set_timeouts(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }
}
impl StreamTimeout for UnixStream {
    fn set_timeouts(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }
}
pub(crate) fn remaining(deadline: Instant) -> Result<Duration, NativeAuditProxyError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(NativeAuditProxyError)
}
pub(crate) fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hex_byte(high: u8, low: u8) -> Option<u8> {
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    Some(digit(high)? * 16 + digit(low)?)
}
fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = hex_byte(value.as_bytes()[index * 2], value.as_bytes()[index * 2 + 1])?;
    }
    Some(output)
}
fn hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
