//! Test-feature-only authenticated SSE observation proxy with exactly one
//! bounded reconnect cycle (N2c2b/S2). This module deliberately adds no
//! command, Provider, production, or default supervisor wiring.

use crate::native_audit_proxy::{
    parse_origin as parse_http_origin, parse_strict_json, read_headers,
    remaining as audit_remaining, safe_id, validate_response_headers,
};
use crate::native_sse_proxy::{
    parse_origin as parse_sse_origin, read_http_headers, reject_buffered_body, set_send_buffer,
    validate_client_request, validate_upstream_response, SseParser, SseReadOutcome, EVENT_IDLE_MS,
    MAX_HEADERS, TOTAL_DEADLINE_MS,
};
use crate::run_binding::{
    canonical, constant_time_eq, hmac_sha256, proxy_handshake, RunBindingHello,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

pub const NATIVE_SSE_RECONNECT_BLOCKED: &str = "BLOCKED_NATIVE_SSE_RECONNECT";
pub const NATIVE_SSE_RECONNECT_READY: &[u8] = b"NATIVE_SSE_RECONNECT_READY\n";
const SCHEMA: &str = "nomad.native-sse-reconnect.v1";
const ROUTE_POLICY: &str = "sse-single-reconnect-v1";
const MAX_CONFIG: usize = 8_192;
const SNAPSHOT_MAX_BODY: usize = 65_536;
const SNAPSHOT_MAX_HEADERS: usize = 8_192;
const RECONNECT_BACKOFF_MS: u64 = 100;

const SNAPSHOT_ROUTES: [&str; 4] = [
    "/session/{session}",
    "/question",
    "/permission",
    "/session/{session}/diff",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSseReconnectError;
impl fmt::Display for NativeSseReconnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(NATIVE_SSE_RECONNECT_BLOCKED)
    }
}
impl std::error::Error for NativeSseReconnectError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    event_idle_ms: u64,
    max_headers_bytes: usize,
    max_snapshot_body_bytes: usize,
    reconnect_backoff_ms: u64,
    total_deadline_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReconnectConfig {
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

struct SecretTrailer([u8; 1]);
impl Drop for SecretTrailer {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn native_sse_reconnect_config(
    run_id: &str,
    nonce: &str,
    capability_digest: &str,
    proxy_origin: &str,
    upstream_origin: &str,
    session_id: &str,
    workspace_dev: u64,
    workspace_ino: u64,
    secret: &[u8; 32],
) -> Result<Vec<u8>, NativeSseReconnectError> {
    let mut config = ReconnectConfig {
        capability_digest: capability_digest.into(),
        config_mac: String::new(),
        limits: Limits {
            event_idle_ms: EVENT_IDLE_MS,
            max_headers_bytes: MAX_HEADERS,
            max_snapshot_body_bytes: SNAPSHOT_MAX_BODY,
            reconnect_backoff_ms: RECONNECT_BACKOFF_MS,
            total_deadline_ms: TOTAL_DEADLINE_MS,
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
    serde_json::to_vec(&config).map_err(|_| NativeSseReconnectError)
}

/// Accepts exactly listener, binding, secret-reader, config-reader, workspace
/// directory and ready-writer descriptor arguments, in that order.
pub fn native_sse_reconnect_entrypoint() -> Result<(), NativeSseReconnectError> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.len() != 6 {
        return Err(NativeSseReconnectError);
    }
    let mut numbers = Vec::with_capacity(6);
    for item in raw {
        numbers.push(
            item.parse::<RawFd>()
                .ok()
                .filter(|fd| *fd > libc::STDERR_FILENO)
                .ok_or(NativeSseReconnectError)?,
        );
    }
    if numbers.iter().copied().collect::<HashSet<_>>().len() != 6 {
        return Err(NativeSseReconnectError);
    }
    let descriptors: Vec<OwnedFd> = numbers
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect();
    let descriptors: [OwnedFd; 6] = descriptors
        .try_into()
        .map_err(|_| NativeSseReconnectError)?;
    run(descriptors)
}

fn run(descriptors: [OwnedFd; 6]) -> Result<(), NativeSseReconnectError> {
    let deadline = Instant::now() + Duration::from_millis(TOTAL_DEADLINE_MS);
    for descriptor in &descriptors {
        set_cloexec(descriptor)?;
    }
    if !is_connected_unix_stream(&descriptors[1])?
        || !is_pipe(&descriptors[2], libc::O_RDONLY)?
        || !is_pipe(&descriptors[3], libc::O_RDONLY)?
        || !is_directory(&descriptors[4])?
        || !is_pipe(&descriptors[5], libc::O_WRONLY)?
    {
        return Err(NativeSseReconnectError);
    }
    let proxy_origin = listener_origin(&descriptors[0])?;
    let [listener_fd, binding_fd, secret_fd, config_fd, workspace_fd, ready_fd] = descriptors;
    let workspace = File::from(workspace_fd)
        .metadata()
        .map_err(|_| NativeSseReconnectError)?;
    let secret = read_secret(secret_fd, deadline)?;
    let config = read_config(config_fd, deadline)?;
    validate_config(
        &config,
        &secret.0,
        &proxy_origin,
        workspace.dev(),
        workspace.ino(),
    )?;

    let mut binding = UnixStream::from(binding_fd);
    set_unix_deadline(&binding, deadline)?;
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
    .map_err(|_| NativeSseReconnectError)?;
    drop(binding);
    write_ready(ready_fd, deadline)?;

    let listener = TcpListener::from(listener_fd);
    listener
        .set_nonblocking(true)
        .map_err(|_| NativeSseReconnectError)?;
    let mut client = accept_one(&listener, deadline)?;
    set_tcp_deadline(&client, deadline)?;
    match serve_one(&mut client, &config, deadline) {
        Ok(()) => Ok(()),
        Err(failure) => {
            if !failure.committed {
                let _ = write_fixed_error(&mut client, failure.status, deadline);
            }
            Err(NativeSseReconnectError)
        }
    }
}

#[derive(Clone, Copy)]
struct Failure {
    committed: bool,
    status: u16,
}
impl Failure {
    fn request() -> Self {
        Self {
            committed: false,
            status: 400,
        }
    }
    fn upstream() -> Self {
        Self {
            committed: false,
            status: 502,
        }
    }
    fn stream() -> Self {
        Self {
            committed: true,
            status: 502,
        }
    }
}

fn serve_one(
    client: &mut TcpStream,
    config: &ReconnectConfig,
    deadline: Instant,
) -> Result<(), Failure> {
    let request =
        read_http_headers(client, MAX_HEADERS, deadline).map_err(|_| Failure::request())?;
    validate_client_request(&request, &config.proxy_origin).map_err(|_| Failure::request())?;
    reject_buffered_body(client).map_err(|_| Failure::request())?;
    set_send_buffer(client, 8_192).map_err(|_| Failure::upstream())?;

    let upstream = parse_sse_origin(&config.upstream_origin).map_err(|_| Failure::upstream())?;
    let mut parser = SseParser::reconnect(&config.session_id);
    let mut first_server =
        open_validated_sse(upstream, deadline).map_err(|_| Failure::upstream())?;

    client
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        )
        .map_err(|_| Failure::stream())?;
    client.flush().map_err(|_| Failure::stream())?;

    let first_stream_delivered =
        stream_event_body(&mut parser, client, &mut first_server, deadline)
            .map_err(|_| Failure::stream())?;
    if first_stream_delivered == 0 {
        return Err(Failure::stream());
    }

    fetch_snapshots(config, deadline).map_err(|_| Failure::stream())?;
    sleep_until_backoff(deadline).map_err(|_| Failure::stream())?;
    parser.begin_reconnect_stream();
    let mut second_server =
        open_validated_sse(upstream, deadline).map_err(|_| Failure::stream())?;
    stream_event_body(&mut parser, client, &mut second_server, deadline)
        .map_err(|_| Failure::stream())?;
    Ok(())
}

fn open_validated_sse(
    upstream: std::net::SocketAddr,
    deadline: Instant,
) -> Result<TcpStream, NativeSseReconnectError> {
    let mut server = TcpStream::connect_timeout(&upstream, remaining(deadline)?)
        .map_err(|_| NativeSseReconnectError)?;
    set_tcp_deadline(&server, deadline)?;
    let outbound = format!(
        "GET /event HTTP/1.1\r\nHost: {}:{}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        upstream.ip(),
        upstream.port()
    );
    server
        .write_all(outbound.as_bytes())
        .map_err(|_| NativeSseReconnectError)?;
    server.flush().map_err(|_| NativeSseReconnectError)?;
    let response = read_http_headers(&mut server, MAX_HEADERS, deadline)
        .map_err(|_| NativeSseReconnectError)?;
    validate_upstream_response(&response).map_err(|_| NativeSseReconnectError)?;
    Ok(server)
}

fn stream_event_body(
    parser: &mut SseParser<'_>,
    client: &mut TcpStream,
    server: &mut TcpStream,
    deadline: Instant,
) -> Result<usize, NativeSseReconnectError> {
    let mut delivered = 0usize;
    loop {
        let event_deadline = (Instant::now() + Duration::from_millis(EVENT_IDLE_MS)).min(deadline);
        let Some(outcome) = parser
            .read_event_outcome(server, event_deadline)
            .map_err(|_| NativeSseReconnectError)?
        else {
            return Ok(delivered);
        };
        if let SseReadOutcome::Deliver(event) = outcome {
            delivered = delivered.checked_add(1).ok_or(NativeSseReconnectError)?;
            set_tcp_deadline(client, deadline)?;
            client
                .write_all(&event)
                .map_err(|_| NativeSseReconnectError)?;
            client.flush().map_err(|_| NativeSseReconnectError)?;
        }
    }
}

fn fetch_snapshots(
    config: &ReconnectConfig,
    deadline: Instant,
) -> Result<(), NativeSseReconnectError> {
    let upstream =
        parse_http_origin(&config.upstream_origin).map_err(|_| NativeSseReconnectError)?;
    for route in snapshot_routes(&config.session_id) {
        let mut server = TcpStream::connect_timeout(
            &upstream,
            audit_remaining(deadline).map_err(|_| NativeSseReconnectError)?,
        )
        .map_err(|_| NativeSseReconnectError)?;
        set_tcp_deadline(&server, deadline)?;
        let outbound = format!(
            "GET {route} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            upstream.ip(),
            upstream.port()
        );
        server
            .write_all(outbound.as_bytes())
            .map_err(|_| NativeSseReconnectError)?;
        server.flush().map_err(|_| NativeSseReconnectError)?;
        let response_headers = read_headers(&mut server, SNAPSHOT_MAX_HEADERS, deadline)
            .map_err(|_| NativeSseReconnectError)?;
        let response =
            validate_response_headers(&response_headers).map_err(|_| NativeSseReconnectError)?;
        let mut body = vec![0; response.content_length];
        server
            .read_exact(&mut body)
            .map_err(|_| NativeSseReconnectError)?;
        let mut trailing = [0u8; 1];
        if server
            .read(&mut trailing)
            .map_err(|_| NativeSseReconnectError)?
            != 0
        {
            return Err(NativeSseReconnectError);
        }
        parse_strict_json(&body).map_err(|_| NativeSseReconnectError)?;
    }
    Ok(())
}

fn snapshot_routes(session_id: &str) -> [String; 4] {
    [
        SNAPSHOT_ROUTES[0].replace("{session}", session_id),
        SNAPSHOT_ROUTES[1].to_string(),
        SNAPSHOT_ROUTES[2].to_string(),
        SNAPSHOT_ROUTES[3].replace("{session}", session_id),
    ]
}

fn sleep_until_backoff(deadline: Instant) -> Result<(), NativeSseReconnectError> {
    let wait = Duration::from_millis(RECONNECT_BACKOFF_MS);
    if remaining(deadline)? < wait {
        return Err(NativeSseReconnectError);
    }
    thread::sleep(wait);
    Ok(())
}

fn validate_config(
    config: &ReconnectConfig,
    secret: &[u8; 32],
    origin: &str,
    workspace_dev: u64,
    workspace_ino: u64,
) -> Result<(), NativeSseReconnectError> {
    if config.schema_version != SCHEMA
        || config.route_policy != ROUTE_POLICY
        || config.limits.event_idle_ms != EVENT_IDLE_MS
        || config.limits.max_headers_bytes != MAX_HEADERS
        || config.limits.max_snapshot_body_bytes != SNAPSHOT_MAX_BODY
        || config.limits.reconnect_backoff_ms != RECONNECT_BACKOFF_MS
        || config.limits.total_deadline_ms != TOTAL_DEADLINE_MS
        || config.proxy_origin != origin
        || config.workspace_dev != workspace_dev
        || config.workspace_ino != workspace_ino
        || !lower_hex_64(&config.run_id)
        || !lower_hex_64(&config.nonce)
        || !lower_hex_64(&config.capability_digest)
        || !safe_id(&config.session_id)
        || parse_sse_origin(&config.upstream_origin).is_err()
    {
        return Err(NativeSseReconnectError);
    }
    let supplied = decode_hex_32(&config.config_mac).ok_or(NativeSseReconnectError)?;
    constant_time_eq(&supplied, &config_mac(secret, config))
        .then_some(())
        .ok_or(NativeSseReconnectError)
}

fn config_mac(secret: &[u8; 32], config: &ReconnectConfig) -> [u8; 32] {
    hmac_sha256(
        secret,
        &canonical(&[
            b"nomad-native-sse-reconnect-config-v1",
            config.run_id.as_bytes(),
            config.proxy_origin.as_bytes(),
            config.upstream_origin.as_bytes(),
            config.nonce.as_bytes(),
            config.capability_digest.as_bytes(),
            config.workspace_dev.to_string().as_bytes(),
            config.workspace_ino.to_string().as_bytes(),
            config.route_policy.as_bytes(),
            config.session_id.as_bytes(),
            config.limits.event_idle_ms.to_string().as_bytes(),
            config.limits.max_headers_bytes.to_string().as_bytes(),
            config.limits.max_snapshot_body_bytes.to_string().as_bytes(),
            config.limits.reconnect_backoff_ms.to_string().as_bytes(),
            config.limits.total_deadline_ms.to_string().as_bytes(),
        ]),
    )
}

fn read_config(fd: OwnedFd, deadline: Instant) -> Result<ReconnectConfig, NativeSseReconnectError> {
    set_nonblocking(&fd)?;
    let raw = read_until_eof(File::from(fd), MAX_CONFIG + 1, deadline)?;
    if raw.is_empty() || raw.len() > MAX_CONFIG {
        return Err(NativeSseReconnectError);
    }
    let config: ReconnectConfig =
        serde_json::from_slice(&raw).map_err(|_| NativeSseReconnectError)?;
    let value = parse_strict_json(&raw).map_err(|_| NativeSseReconnectError)?;
    if serde_json::to_vec(&value).map_err(|_| NativeSseReconnectError)? != raw {
        return Err(NativeSseReconnectError);
    }
    Ok(config)
}

fn read_secret(fd: OwnedFd, deadline: Instant) -> Result<Secret, NativeSseReconnectError> {
    set_nonblocking(&fd)?;
    let mut reader = File::from(fd);
    let mut secret = Secret([0; 32]);
    let mut offset = 0;
    while offset < secret.0.len() {
        if Instant::now() >= deadline {
            return Err(NativeSseReconnectError);
        }
        match reader.read(&mut secret.0[offset..]) {
            Ok(0) => return Err(NativeSseReconnectError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseReconnectError),
        }
    }
    let mut trailing = SecretTrailer([0]);
    loop {
        if Instant::now() >= deadline {
            return Err(NativeSseReconnectError);
        }
        match reader.read(&mut trailing.0) {
            Ok(0) => break,
            Ok(_) => return Err(NativeSseReconnectError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseReconnectError),
        }
    }
    if secret.0.iter().all(|byte| *byte == 0) {
        return Err(NativeSseReconnectError);
    }
    Ok(secret)
}

fn read_until_eof(
    mut reader: File,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NativeSseReconnectError> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        if Instant::now() >= deadline {
            return Err(NativeSseReconnectError);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) if output.len() + count <= limit => {
                output.extend_from_slice(&buffer[..count])
            }
            Ok(_) => return Err(NativeSseReconnectError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseReconnectError),
        }
    }
}

fn write_ready(fd: OwnedFd, deadline: Instant) -> Result<(), NativeSseReconnectError> {
    set_nonblocking(&fd)?;
    let mut writer = File::from(fd);
    let mut offset = 0;
    while offset < NATIVE_SSE_RECONNECT_READY.len() {
        if Instant::now() >= deadline {
            return Err(NativeSseReconnectError);
        }
        match writer.write(&NATIVE_SSE_RECONNECT_READY[offset..]) {
            Ok(0) => return Err(NativeSseReconnectError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseReconnectError),
        }
    }
    Ok(())
}

fn write_fixed_error(
    stream: &mut TcpStream,
    status: u16,
    deadline: Instant,
) -> Result<(), NativeSseReconnectError> {
    set_tcp_deadline(stream, deadline)?;
    stream
        .write_all(
            format!("HTTP/1.1 {status} Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|_| NativeSseReconnectError)
}

fn accept_one(
    listener: &TcpListener,
    deadline: Instant,
) -> Result<TcpStream, NativeSseReconnectError> {
    loop {
        if Instant::now() >= deadline {
            return Err(NativeSseReconnectError);
        }
        match listener.accept() {
            Ok((stream, address)) if address.ip() == Ipv4Addr::LOCALHOST => return Ok(stream),
            Ok(_) => return Err(NativeSseReconnectError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseReconnectError),
        }
    }
}

fn listener_origin(fd: &OwnedFd) -> Result<String, NativeSseReconnectError> {
    let mut socket_type: libc::c_int = 0;
    let mut option_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
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
        return Err(NativeSseReconnectError);
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
        return Err(NativeSseReconnectError);
    }
    let port = u16::from_be(address.sin_port);
    if port == 0 {
        return Err(NativeSseReconnectError);
    }
    Ok(format!("http://127.0.0.1:{port}"))
}

fn is_connected_unix_stream(fd: &OwnedFd) -> Result<bool, NativeSseReconnectError> {
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

fn is_pipe(fd: &OwnedFd, direction: libc::c_int) -> Result<bool, NativeSseReconnectError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if flags < 0 || unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeSseReconnectError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFIFO && (flags & libc::O_ACCMODE) == direction)
}

fn is_directory(fd: &OwnedFd) -> Result<bool, NativeSseReconnectError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeSseReconnectError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

fn set_cloexec(fd: &OwnedFd) -> Result<(), NativeSseReconnectError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(NativeSseReconnectError);
    }
    Ok(())
}

fn set_nonblocking(fd: &OwnedFd) -> Result<(), NativeSseReconnectError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(NativeSseReconnectError);
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, NativeSseReconnectError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(NativeSseReconnectError)
}

fn set_tcp_deadline(stream: &TcpStream, deadline: Instant) -> Result<(), NativeSseReconnectError> {
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| NativeSseReconnectError)
}

fn set_unix_deadline(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(), NativeSseReconnectError> {
    let timeout = remaining(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| NativeSseReconnectError)
}

fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = hex_digit(value.as_bytes()[index * 2])? * 16
            + hex_digit(value.as_bytes()[index * 2 + 1])?;
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
