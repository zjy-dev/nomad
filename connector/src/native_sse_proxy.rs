//! Test-feature-only authenticated one-shot SSE observation proxy (N2c2a/S1).
//! This module deliberately has no reconnect, command, Provider, or production path.

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

pub const NATIVE_SSE_PROXY_BLOCKED: &str = "BLOCKED_NATIVE_SSE_PROXY";
pub const NATIVE_SSE_PROXY_READY: &[u8] = b"NATIVE_SSE_PROXY_READY\n";
const SCHEMA: &str = "nomad.native-sse-proxy.v1";
const ROUTE_POLICY: &str = "sse-single-stream-v1";
pub(crate) const TOTAL_DEADLINE_MS: u64 = 15_000;
pub(crate) const EVENT_IDLE_MS: u64 = 2_000;
const MAX_CONFIG: usize = 8_192;
pub(crate) const MAX_HEADERS: usize = 8_192;
const MAX_LINE: usize = 8_192;
const MAX_EVENT: usize = 32_768;
const MAX_EVENTS: usize = 256;
const MAX_STREAM: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSseProxyError;
impl fmt::Display for NativeSseProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(NATIVE_SSE_PROXY_BLOCKED)
    }
}
impl std::error::Error for NativeSseProxyError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    event_idle_ms: u64,
    max_event_bytes: usize,
    max_events: usize,
    max_line_bytes: usize,
    max_stream_bytes: usize,
    total_deadline_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SseConfig {
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
pub fn native_sse_proxy_config(
    run_id: &str,
    nonce: &str,
    capability_digest: &str,
    proxy_origin: &str,
    upstream_origin: &str,
    session_id: &str,
    workspace_dev: u64,
    workspace_ino: u64,
    secret: &[u8; 32],
) -> Result<Vec<u8>, NativeSseProxyError> {
    let mut config = SseConfig {
        capability_digest: capability_digest.into(),
        config_mac: String::new(),
        limits: Limits {
            event_idle_ms: EVENT_IDLE_MS,
            max_event_bytes: MAX_EVENT,
            max_events: MAX_EVENTS,
            max_line_bytes: MAX_LINE,
            max_stream_bytes: MAX_STREAM,
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
    serde_json::to_vec(&config).map_err(|_| NativeSseProxyError)
}

/// Accepts exactly listener, binding, secret-reader, config-reader, workspace
/// directory and ready-writer descriptor arguments, in that order.
pub fn native_sse_proxy_entrypoint() -> Result<(), NativeSseProxyError> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.len() != 6 {
        return Err(NativeSseProxyError);
    }
    let mut numbers = Vec::with_capacity(6);
    for item in raw {
        numbers.push(
            item.parse::<RawFd>()
                .ok()
                .filter(|fd| *fd > libc::STDERR_FILENO)
                .ok_or(NativeSseProxyError)?,
        );
    }
    if numbers.iter().copied().collect::<HashSet<_>>().len() != 6 {
        return Err(NativeSseProxyError);
    }
    // SAFETY: all validated descriptors are distinct and adopted exactly once.
    let descriptors: Vec<OwnedFd> = numbers
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect();
    run(descriptors.try_into().map_err(|_| NativeSseProxyError)?)
}

fn run(descriptors: [OwnedFd; 6]) -> Result<(), NativeSseProxyError> {
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
        return Err(NativeSseProxyError);
    }
    let proxy_origin = listener_origin(&descriptors[0])?;
    let [listener_fd, binding_fd, secret_fd, config_fd, workspace_fd, ready_fd] = descriptors;
    let workspace = File::from(workspace_fd)
        .metadata()
        .map_err(|_| NativeSseProxyError)?;
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
    .map_err(|_| NativeSseProxyError)?;
    drop(binding);
    write_ready(ready_fd, deadline)?;

    let listener = TcpListener::from(listener_fd);
    listener
        .set_nonblocking(true)
        .map_err(|_| NativeSseProxyError)?;
    let mut client = accept_one(&listener, deadline)?;
    set_stream_deadline(&client, deadline)?;
    match serve_one(&mut client, &config, deadline) {
        Ok(()) => Ok(()),
        Err(failure) => {
            if !failure.committed {
                let _ = write_fixed_error(&mut client, failure.status, deadline);
            }
            Err(NativeSseProxyError)
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

fn serve_one(client: &mut TcpStream, config: &SseConfig, deadline: Instant) -> Result<(), Failure> {
    let request =
        read_http_headers(client, MAX_HEADERS, deadline).map_err(|_| Failure::request())?;
    validate_client_request(&request, &config.proxy_origin).map_err(|_| Failure::request())?;
    reject_buffered_body(client).map_err(|_| Failure::request())?;

    let upstream = parse_origin(&config.upstream_origin).map_err(|_| Failure::upstream())?;
    let mut server = TcpStream::connect_timeout(
        &upstream,
        remaining(deadline).map_err(|_| Failure::upstream())?,
    )
    .map_err(|_| Failure::upstream())?;
    set_stream_deadline(&server, deadline).map_err(|_| Failure::upstream())?;
    let outbound = format!(
        "GET /event HTTP/1.1\r\nHost: {}:{}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        upstream.ip(), upstream.port()
    );
    server
        .write_all(outbound.as_bytes())
        .map_err(|_| Failure::upstream())?;
    server.flush().map_err(|_| Failure::upstream())?;
    let response =
        read_http_headers(&mut server, MAX_HEADERS, deadline).map_err(|_| Failure::upstream())?;
    validate_upstream_response(&response).map_err(|_| Failure::upstream())?;

    set_send_buffer(client, 8_192).map_err(|_| Failure::upstream())?;
    client
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n")
        .map_err(|_| Failure::stream())?;
    client.flush().map_err(|_| Failure::stream())?;

    let mut parser = SseParser::new(&config.session_id);
    loop {
        let event_deadline = (Instant::now() + Duration::from_millis(EVENT_IDLE_MS)).min(deadline);
        let Some(event) = parser
            .read_event(&mut server, event_deadline)
            .map_err(|_| Failure::stream())?
        else {
            if parser.events == 0 {
                return Err(Failure::stream());
            }
            return Ok(());
        };
        set_stream_deadline(client, deadline).map_err(|_| Failure::stream())?;
        client.write_all(&event).map_err(|_| Failure::stream())?;
        client.flush().map_err(|_| Failure::stream())?;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LineEnding {
    Lf,
    CrLf,
}

pub(crate) enum SseReadOutcome {
    Deliver(Vec<u8>),
    DropDuplicate,
}

pub(crate) struct SseParser<'a> {
    session_id: &'a str,
    line_ending: Option<LineEnding>,
    stream_ids: HashSet<String>,
    prior_stream_ids: HashSet<String>,
    allow_cross_stream_drop: bool,
    events: usize,
    input_bytes: usize,
    output_bytes: usize,
}
impl<'a> SseParser<'a> {
    fn new(session_id: &'a str) -> Self {
        Self::with_cross_stream_drop(session_id, false)
    }

    pub(crate) fn reconnect(session_id: &'a str) -> Self {
        Self::with_cross_stream_drop(session_id, true)
    }

    fn with_cross_stream_drop(session_id: &'a str, allow_cross_stream_drop: bool) -> Self {
        Self {
            session_id,
            line_ending: None,
            stream_ids: HashSet::new(),
            prior_stream_ids: HashSet::new(),
            allow_cross_stream_drop,
            events: 0,
            input_bytes: 0,
            output_bytes: 0,
        }
    }

    pub(crate) fn begin_reconnect_stream(&mut self) {
        self.line_ending = None;
        self.prior_stream_ids.extend(self.stream_ids.drain());
    }

    fn read_event(
        &mut self,
        reader: &mut TcpStream,
        event_deadline: Instant,
    ) -> Result<Option<Vec<u8>>, NativeSseProxyError> {
        match self.read_event_outcome(reader, event_deadline)? {
            Some(SseReadOutcome::Deliver(event)) => Ok(Some(event)),
            Some(SseReadOutcome::DropDuplicate) => Err(NativeSseProxyError),
            None => Ok(None),
        }
    }

    pub(crate) fn read_event_outcome(
        &mut self,
        reader: &mut TcpStream,
        event_deadline: Instant,
    ) -> Result<Option<SseReadOutcome>, NativeSseProxyError> {
        let Some((line, ending, raw_len)) = read_sse_line(reader, event_deadline)? else {
            return Ok(None);
        };
        self.check_ending(ending)?;
        if line.is_empty() {
            return Err(NativeSseProxyError);
        }
        if raw_len > MAX_EVENT {
            return Err(NativeSseProxyError);
        }
        self.add_input(raw_len)?;
        if matches!(line.first(), Some(b' ' | b'\t' | b':')) {
            return Err(NativeSseProxyError);
        }
        let payload = line
            .strip_prefix(b"data: ".as_slice())
            .ok_or(NativeSseProxyError)?;
        if payload.is_empty() {
            return Err(NativeSseProxyError);
        }

        let (blank, blank_ending, blank_len) =
            read_sse_line(reader, event_deadline)?.ok_or(NativeSseProxyError)?;
        self.check_ending(blank_ending)?;
        if !blank.is_empty() || raw_len + blank_len > MAX_EVENT {
            return Err(NativeSseProxyError);
        }
        self.add_input(blank_len)?;

        let value = parse_strict_json(payload)?;
        let object = value.as_object().ok_or(NativeSseProxyError)?;
        if object.len() != 3
            || !object.contains_key("id")
            || !object.contains_key("type")
            || !object.contains_key("properties")
        {
            return Err(NativeSseProxyError);
        }
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| safe_id(value))
            .ok_or(NativeSseProxyError)?;
        let event_type = object
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| safe_type(value))
            .ok_or(NativeSseProxyError)?;
        let properties = object
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(NativeSseProxyError)?;
        match properties.get("sessionID") {
            Some(Value::String(value)) if value == self.session_id => {}
            Some(_) => return Err(NativeSseProxyError),
            None if event_type == "server.connected" => {}
            None => return Err(NativeSseProxyError),
        }
        if !self.stream_ids.insert(id.into()) {
            return Err(NativeSseProxyError);
        }
        if self.allow_cross_stream_drop && self.prior_stream_ids.contains(id) {
            return Ok(Some(SseReadOutcome::DropDuplicate));
        }
        self.events = self.events.checked_add(1).ok_or(NativeSseProxyError)?;
        if self.events > MAX_EVENTS {
            return Err(NativeSseProxyError);
        }
        let canonical_json = serde_json::to_vec(&value).map_err(|_| NativeSseProxyError)?;
        let mut output = Vec::with_capacity(canonical_json.len() + 8);
        output.extend_from_slice(b"data: ");
        output.extend_from_slice(&canonical_json);
        output.extend_from_slice(b"\n\n");
        if output.len() > MAX_EVENT {
            return Err(NativeSseProxyError);
        }
        self.output_bytes = self
            .output_bytes
            .checked_add(output.len())
            .ok_or(NativeSseProxyError)?;
        if self.output_bytes > MAX_STREAM {
            return Err(NativeSseProxyError);
        }
        Ok(Some(SseReadOutcome::Deliver(output)))
    }

    fn check_ending(&mut self, ending: LineEnding) -> Result<(), NativeSseProxyError> {
        match self.line_ending {
            Some(expected) if expected != ending => Err(NativeSseProxyError),
            None => {
                self.line_ending = Some(ending);
                Ok(())
            }
            Some(_) => Ok(()),
        }
    }
    fn add_input(&mut self, count: usize) -> Result<(), NativeSseProxyError> {
        self.input_bytes = self
            .input_bytes
            .checked_add(count)
            .ok_or(NativeSseProxyError)?;
        (self.input_bytes <= MAX_STREAM)
            .then_some(())
            .ok_or(NativeSseProxyError)
    }
}

fn read_sse_line(
    reader: &mut TcpStream,
    deadline: Instant,
) -> Result<Option<(Vec<u8>, LineEnding, usize)>, NativeSseProxyError> {
    let mut line = Vec::new();
    loop {
        let timeout = remaining(deadline)?;
        reader
            .set_read_timeout(Some(timeout))
            .map_err(|_| NativeSseProxyError)?;
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) if line.is_empty() => return Ok(None),
            Ok(0) => return Err(NativeSseProxyError),
            Ok(_) => {}
            Err(_) => return Err(NativeSseProxyError),
        }
        if byte[0] == 0 || line.len() + 1 > MAX_LINE {
            return Err(NativeSseProxyError);
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            let ending = if line.len() >= 2 && line[line.len() - 2] == b'\r' {
                line.truncate(line.len() - 2);
                LineEnding::CrLf
            } else {
                line.truncate(line.len() - 1);
                LineEnding::Lf
            };
            if line.contains(&b'\r') || std::str::from_utf8(&line).is_err() {
                return Err(NativeSseProxyError);
            }
            let raw_len = line.len() + if ending == LineEnding::CrLf { 2 } else { 1 };
            return Ok(Some((line, ending, raw_len)));
        }
        if byte[0] == b'\r' {
            // A CR is accepted only when the immediately following byte is LF.
            let timeout = remaining(deadline)?;
            reader
                .set_read_timeout(Some(timeout))
                .map_err(|_| NativeSseProxyError)?;
            let mut next = [0u8; 1];
            if reader.read_exact(&mut next).is_err()
                || next[0] != b'\n'
                || line.len() + 1 > MAX_LINE
            {
                return Err(NativeSseProxyError);
            }
            line.pop();
            if line.contains(&b'\r') || std::str::from_utf8(&line).is_err() {
                return Err(NativeSseProxyError);
            }
            let raw_len = line.len() + 2;
            return Ok(Some((line, LineEnding::CrLf, raw_len)));
        }
    }
}

pub(crate) fn validate_client_request(
    raw: &[u8],
    proxy_origin: &str,
) -> Result<(), NativeSseProxyError> {
    validate_ascii_headers(raw)?;
    let text = std::str::from_utf8(raw).map_err(|_| NativeSseProxyError)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    if lines.next() != Some("GET /event HTTP/1.1") {
        return Err(NativeSseProxyError);
    }
    let expected_host = proxy_origin
        .strip_prefix("http://")
        .ok_or(NativeSseProxyError)?;
    let mut host = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = parse_header(line)?;
        let lower = name.to_ascii_lowercase();
        if lower == "host" {
            if host.replace(value).is_some() {
                return Err(NativeSseProxyError);
            }
        } else if lower == "content-length" {
            if content_length.replace(value).is_some() {
                return Err(NativeSseProxyError);
            }
        } else if lower == "transfer-encoding"
            || lower == "upgrade"
            || lower == "authorization"
            || lower == "cookie"
            || lower == "last-event-id"
            || lower.starts_with("proxy-")
        {
            return Err(NativeSseProxyError);
        }
    }
    if host != Some(expected_host) || content_length.is_some_and(|value| value != "0") {
        return Err(NativeSseProxyError);
    }
    Ok(())
}

pub(crate) fn validate_upstream_response(raw: &[u8]) -> Result<(), NativeSseProxyError> {
    validate_ascii_headers(raw)?;
    let text = std::str::from_utf8(raw).map_err(|_| NativeSseProxyError)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status = lines.next().ok_or(NativeSseProxyError)?;
    let mut parts = status.split(' ');
    if parts.next() != Some("HTTP/1.1") || parts.next() != Some("200") {
        return Err(NativeSseProxyError);
    }
    let mut content_type = None;
    let mut names = HashSet::new();
    for line in lines {
        let (name, value) = parse_header(line)?;
        let lower = name.to_ascii_lowercase();
        if !names.insert(lower.clone()) {
            return Err(NativeSseProxyError);
        }
        if lower == "content-type" {
            content_type = Some(value);
        } else if lower == "content-length"
            || lower == "transfer-encoding"
            || lower == "upgrade"
            || matches!(
                lower.as_str(),
                "authorization"
                    | "proxy-authorization"
                    | "www-authenticate"
                    | "proxy-authenticate"
                    | "cookie"
                    | "cookie2"
                    | "set-cookie"
                    | "set-cookie2"
            )
        {
            return Err(NativeSseProxyError);
        }
    }
    (content_type == Some("text/event-stream"))
        .then_some(())
        .ok_or(NativeSseProxyError)
}

fn parse_header(line: &str) -> Result<(&str, &str), NativeSseProxyError> {
    if line.is_empty() || line.starts_with([' ', '\t']) {
        return Err(NativeSseProxyError);
    }
    let (name, raw_value) = line.split_once(':').ok_or(NativeSseProxyError)?;
    if name.is_empty()
        || name.trim() != name
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(NativeSseProxyError);
    }
    let value = raw_value.trim_matches(' ');
    if value.contains(['\r', '\n']) {
        return Err(NativeSseProxyError);
    }
    Ok((name, value))
}

fn validate_ascii_headers(raw: &[u8]) -> Result<(), NativeSseProxyError> {
    if raw.len() < 4 || !raw.ends_with(b"\r\n\r\n") {
        return Err(NativeSseProxyError);
    }
    for (index, byte) in raw.iter().copied().enumerate() {
        if byte == b'\r' {
            if raw.get(index + 1) != Some(&b'\n') {
                return Err(NativeSseProxyError);
            }
        } else if byte == b'\n' {
            if index == 0 || raw[index - 1] != b'\r' {
                return Err(NativeSseProxyError);
            }
        } else if !(0x20..=0x7e).contains(&byte) {
            return Err(NativeSseProxyError);
        }
    }
    Ok(())
}

pub(crate) fn read_http_headers<R: Read>(
    reader: &mut R,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NativeSseProxyError> {
    let mut output = Vec::new();
    let mut byte = [0u8; 1];
    while output.len() < limit {
        if Instant::now() >= deadline {
            return Err(NativeSseProxyError);
        }
        match reader.read(&mut byte) {
            Ok(0) => return Err(NativeSseProxyError),
            Ok(_) => {
                output.push(byte[0]);
                if output.ends_with(b"\r\n\r\n") {
                    return Ok(output);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(NativeSseProxyError),
        }
    }
    Err(NativeSseProxyError)
}

pub(crate) fn reject_buffered_body(client: &TcpStream) -> Result<(), NativeSseProxyError> {
    let mut byte = [0u8; 1];
    // SAFETY: recv peeks at most one byte into a live one-byte buffer.
    let count = unsafe {
        libc::recv(
            client.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if count > 0 {
        return Err(NativeSseProxyError);
    }
    if count == 0 {
        return Ok(());
    }
    (std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock)
        .then_some(())
        .ok_or(NativeSseProxyError)
}

fn parse_strict_json(raw: &[u8]) -> Result<Value, NativeSseProxyError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = NoDuplicates
        .deserialize(&mut deserializer)
        .map_err(|_| NativeSseProxyError)?;
    deserializer.end().map_err(|_| NativeSseProxyError)?;
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
        formatter.write_str("one JSON value without duplicate keys")
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
    config: &SseConfig,
    secret: &[u8; 32],
    origin: &str,
    dev: u64,
    ino: u64,
) -> Result<(), NativeSseProxyError> {
    if config.schema_version != SCHEMA
        || config.route_policy != ROUTE_POLICY
        || config.limits.event_idle_ms != EVENT_IDLE_MS
        || config.limits.max_event_bytes != MAX_EVENT
        || config.limits.max_events != MAX_EVENTS
        || config.limits.max_line_bytes != MAX_LINE
        || config.limits.max_stream_bytes != MAX_STREAM
        || config.limits.total_deadline_ms != TOTAL_DEADLINE_MS
        || config.proxy_origin != origin
        || config.workspace_dev != dev
        || config.workspace_ino != ino
        || !lower_hex_64(&config.run_id)
        || !lower_hex_64(&config.nonce)
        || !lower_hex_64(&config.capability_digest)
        || !safe_id(&config.session_id)
        || parse_origin(&config.upstream_origin).is_err()
    {
        return Err(NativeSseProxyError);
    }
    let supplied = decode_hex_32(&config.config_mac).ok_or(NativeSseProxyError)?;
    constant_time_eq(&supplied, &config_mac(secret, config))
        .then_some(())
        .ok_or(NativeSseProxyError)
}
fn config_mac(secret: &[u8; 32], config: &SseConfig) -> [u8; 32] {
    hmac_sha256(
        secret,
        &canonical(&[
            b"nomad-native-sse-proxy-config-v1",
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
            config.limits.max_event_bytes.to_string().as_bytes(),
            config.limits.max_events.to_string().as_bytes(),
            config.limits.max_line_bytes.to_string().as_bytes(),
            config.limits.max_stream_bytes.to_string().as_bytes(),
            config.limits.total_deadline_ms.to_string().as_bytes(),
        ]),
    )
}
fn read_config(fd: OwnedFd, deadline: Instant) -> Result<SseConfig, NativeSseProxyError> {
    set_nonblocking(&fd)?;
    let raw = read_until_eof(File::from(fd), MAX_CONFIG + 1, deadline)?;
    if raw.is_empty() || raw.len() > MAX_CONFIG {
        return Err(NativeSseProxyError);
    }
    let config: SseConfig = serde_json::from_slice(&raw).map_err(|_| NativeSseProxyError)?;
    let value = parse_strict_json(&raw)?;
    if serde_json::to_vec(&value).map_err(|_| NativeSseProxyError)? != raw {
        return Err(NativeSseProxyError);
    }
    Ok(config)
}
fn read_secret(fd: OwnedFd, deadline: Instant) -> Result<Secret, NativeSseProxyError> {
    set_nonblocking(&fd)?;
    let mut reader = File::from(fd);
    let mut secret = Secret([0; 32]);
    let mut offset = 0;
    while offset < secret.0.len() {
        if Instant::now() >= deadline {
            return Err(NativeSseProxyError);
        }
        match reader.read(&mut secret.0[offset..]) {
            Ok(0) => return Err(NativeSseProxyError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseProxyError),
        }
    }
    let mut trailing = SecretTrailer([0]);
    loop {
        if Instant::now() >= deadline {
            return Err(NativeSseProxyError);
        }
        match reader.read(&mut trailing.0) {
            Ok(0) => break,
            Ok(_) => return Err(NativeSseProxyError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(NativeSseProxyError),
        }
    }
    if secret.0.iter().all(|byte| *byte == 0) {
        return Err(NativeSseProxyError);
    }
    Ok(secret)
}
fn read_until_eof(
    mut reader: File,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, NativeSseProxyError> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        if Instant::now() >= deadline {
            return Err(NativeSseProxyError);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) if output.len() + count <= limit => {
                output.extend_from_slice(&buffer[..count])
            }
            Ok(_) => return Err(NativeSseProxyError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => return Err(NativeSseProxyError),
        }
    }
}
fn write_ready(fd: OwnedFd, deadline: Instant) -> Result<(), NativeSseProxyError> {
    set_nonblocking(&fd)?;
    let mut writer = File::from(fd);
    let mut offset = 0;
    while offset < NATIVE_SSE_PROXY_READY.len() {
        if Instant::now() >= deadline {
            return Err(NativeSseProxyError);
        }
        match writer.write(&NATIVE_SSE_PROXY_READY[offset..]) {
            Ok(0) => return Err(NativeSseProxyError),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => return Err(NativeSseProxyError),
        }
    }
    Ok(())
}
fn write_fixed_error(
    stream: &mut TcpStream,
    status: u16,
    deadline: Instant,
) -> Result<(), NativeSseProxyError> {
    set_stream_deadline(stream, deadline)?;
    stream
        .write_all(
            format!("HTTP/1.1 {status} Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|_| NativeSseProxyError)
}
fn accept_one(listener: &TcpListener, deadline: Instant) -> Result<TcpStream, NativeSseProxyError> {
    loop {
        if Instant::now() >= deadline {
            return Err(NativeSseProxyError);
        }
        match listener.accept() {
            Ok((stream, address)) if address.ip() == Ipv4Addr::LOCALHOST => return Ok(stream),
            Ok(_) => return Err(NativeSseProxyError),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => return Err(NativeSseProxyError),
        }
    }
}
pub(crate) fn parse_origin(value: &str) -> Result<SocketAddr, NativeSseProxyError> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value != 0)
        .ok_or(NativeSseProxyError)?;
    Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
}
fn listener_origin(fd: &OwnedFd) -> Result<String, NativeSseProxyError> {
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
        return Err(NativeSseProxyError);
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
        return Err(NativeSseProxyError);
    }
    let port = u16::from_be(address.sin_port);
    if port == 0 {
        return Err(NativeSseProxyError);
    }
    Ok(format!("http://127.0.0.1:{port}"))
}
fn is_connected_unix_stream(fd: &OwnedFd) -> Result<bool, NativeSseProxyError> {
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
fn is_pipe(fd: &OwnedFd, direction: libc::c_int) -> Result<bool, NativeSseProxyError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if flags < 0 || unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeSseProxyError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFIFO && (flags & libc::O_ACCMODE) == direction)
}
fn is_directory(fd: &OwnedFd) -> Result<bool, NativeSseProxyError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(NativeSseProxyError);
    }
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}
fn set_cloexec(fd: &OwnedFd) -> Result<(), NativeSseProxyError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(NativeSseProxyError);
    }
    Ok(())
}
fn set_nonblocking(fd: &OwnedFd) -> Result<(), NativeSseProxyError> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
    {
        return Err(NativeSseProxyError);
    }
    Ok(())
}
pub(crate) fn set_send_buffer(
    stream: &TcpStream,
    size: libc::c_int,
) -> Result<(), NativeSseProxyError> {
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&size as *const libc::c_int).cast(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    } != 0
    {
        return Err(NativeSseProxyError);
    }
    Ok(())
}
fn set_stream_deadline(
    stream: &impl StreamTimeout,
    deadline: Instant,
) -> Result<(), NativeSseProxyError> {
    stream
        .set_timeouts(Some(remaining(deadline)?))
        .map_err(|_| NativeSseProxyError)
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
pub(crate) fn remaining(deadline: Instant) -> Result<Duration, NativeSseProxyError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(NativeSseProxyError)
}
fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
fn safe_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
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
