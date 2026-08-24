#![cfg(all(unix, feature = "native_sse_proxy_test_helper"))]

use nomad_connector::{native_sse_proxy_config, HostRunBinding, NATIVE_SSE_PROXY_READY};
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SECRET: [u8; 32] = [17; 32];
const CHALLENGE: [u8; 32] = [19; 32];
const SESSION: &str = "fixed_test_session-1";
const RESPONSE_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes both descriptor slots.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    for descriptor in descriptors {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            0
        );
    }
    // SAFETY: successful pipe returns two independently owned descriptors.
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}

fn clear_cloexec(descriptor: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn spawn_proxy(inherited: [RawFd; 6]) -> Child {
    let maximum = RawFd::try_from(unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(64, 65_536))
        .unwrap_or(65_536);
    let mut command = Command::new(env!("CARGO_BIN_EXE_native-sse-proxy"));
    command
        .args(inherited.map(|descriptor| descriptor.to_string()))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe fcntl calls run after fork.
    unsafe {
        command.pre_exec(move || {
            for descriptor in 3..maximum {
                let flags = libc::fcntl(descriptor, libc::F_GETFD);
                if flags < 0 {
                    continue;
                }
                if inherited.contains(&descriptor) {
                    clear_cloexec(descriptor)?;
                } else if libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

fn write_and_close(descriptor: OwnedFd, bytes: &[u8]) {
    if let Err(error) = File::from(descriptor).write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
}

struct RunningProxy {
    child: Child,
    origin: String,
}

fn start_proxy(upstream_origin: &str) -> RunningProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (child_binding, mut host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let workspace = tempfile::tempdir().unwrap();
    let workspace_fd = File::open(workspace.path()).unwrap();
    let metadata = workspace_fd.metadata().unwrap();
    let (ready_read, ready_write) = pipe_pair();
    let config = native_sse_proxy_config(
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
        &origin,
        upstream_origin,
        SESSION,
        metadata.dev(),
        metadata.ino(),
        &SECRET,
    )
    .unwrap();
    let child = spawn_proxy([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
        workspace_fd.as_raw_fd(),
        ready_write.as_raw_fd(),
    ]);
    drop((
        listener,
        child_binding,
        secret_read,
        config_read,
        workspace_fd,
        ready_write,
        workspace,
    ));
    write_and_close(secret_write, &SECRET);
    write_and_close(config_write, &config);
    host_binding
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    host_binding
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    HostRunBinding::new(CHALLENGE, SECRET)
        .unwrap()
        .handshake(&mut host_binding)
        .unwrap();
    drop(host_binding);
    let mut ready = File::from(ready_read);
    let mut marker = vec![0; NATIVE_SSE_PROXY_READY.len()];
    ready.read_exact(&mut marker).unwrap();
    assert_eq!(marker, NATIVE_SSE_PROXY_READY);
    assert_eq!(ready.read(&mut [0]).unwrap(), 0);
    RunningProxy { child, origin }
}

fn client_request(origin: &str, request: &[u8], half_close: bool) -> Vec<u8> {
    let mut stream = TcpStream::connect(origin.strip_prefix("http://").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    stream.write_all(request).unwrap();
    if half_close {
        stream.shutdown(Shutdown::Write).unwrap();
    }
    let mut response = Vec::new();
    if let Err(error) = stream.read_to_end(&mut response) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    response
}

fn event(id: &str, event_type: &str, properties: &str, ending: &str) -> Vec<u8> {
    format!(
        "data: {{\"properties\":{properties},\"type\":\"{event_type}\",\"id\":\"{id}\"}}{ending}{ending}"
    )
    .into_bytes()
}

fn wait_output(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("native SSE proxy timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_content_free(output: &Output) {
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn exact_get_forwards_two_canonical_events_with_one_hit_and_no_half_close() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let upstream_host = upstream_origin.strip_prefix("http://").unwrap().to_string();
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut raw = [0u8; 512];
        let count = stream.read(&mut raw).unwrap();
        assert_eq!(
            &raw[..count],
            format!(
                "GET /event HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                upstream_host
            )
            .as_bytes()
        );
        stream.write_all(RESPONSE_HEAD).unwrap();
        stream
            .write_all(&event("one", "server.connected", "{}", "\n"))
            .unwrap();
        stream
            .write_all(&event(
                "two",
                "unknown.observed",
                &format!("{{\"sessionID\":\"{SESSION}\",\"text\":\"雪\"}}"),
                "\n",
            ))
            .unwrap();
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let response = client_request(
        &running.origin,
        format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        false,
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"));
    let body = response
        .split(|byte| *byte == b'\r')
        .skip(4)
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let text = String::from_utf8(response).unwrap();
    assert!(
        text.contains("data: {\"id\":\"one\",\"properties\":{},\"type\":\"server.connected\"}\n\n")
    );
    assert!(text.contains(&format!("data: {{\"id\":\"two\",\"properties\":{{\"sessionID\":\"{SESSION}\",\"text\":\"雪\"}},\"type\":\"unknown.observed\"}}\n\n")));
    assert!(!body.is_empty());
    assert_eq!(peer.join().unwrap(), 1);
    let output = wait_output(running.child, Duration::from_secs(3));
    assert!(output.status.success(), "{output:?}");
    assert_content_free(&output);
}

#[test]
fn crlf_and_slow_split_utf8_are_accepted() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut raw = [0u8; 512];
        assert!(stream.read(&mut raw).unwrap() > 0);
        stream.write_all(RESPONSE_HEAD).unwrap();
        let frame = event(
            "split",
            "message.delta",
            &format!("{{\"sessionID\":\"{SESSION}\",\"text\":\"雪\"}}"),
            "\r\n",
        );
        let split = frame.iter().position(|byte| *byte == 0xe9).unwrap() + 1;
        stream.write_all(&frame[..split]).unwrap();
        thread::sleep(Duration::from_millis(30));
        stream.write_all(&frame[split..]).unwrap();
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let response = client_request(
        &running.origin,
        format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        false,
    );
    assert!(String::from_utf8(response)
        .unwrap()
        .contains("\"text\":\"雪\""));
    peer.join().unwrap();
    let output = wait_output(running.child, Duration::from_secs(3));
    assert!(output.status.success());
    assert_content_free(&output);
}

#[test]
fn invalid_client_requests_have_zero_upstream_hits() {
    let cases = [
        "POST /event HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n",
        "GET /event?after=x HTTP/1.1\r\nHost: {host}\r\n\r\n",
        "GET /event HTTP/1.1\r\nHost: {host}\r\nLast-Event-ID: x\r\n\r\n",
        "GET /event HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET /event HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n",
        "GET /session/x HTTP/1.1\r\nHost: {host}\r\n\r\n",
        "GET /event HTTP/1.1\r\nHost: {host}\r\nContent-Length: 1\r\n\r\nx",
        "GET /event HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\nx",
    ];
    for raw in cases {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let running = start_proxy(&format!("http://{}", upstream.local_addr().unwrap()));
        let host = running.origin.strip_prefix("http://").unwrap();
        let response = client_request(
            &running.origin,
            raw.replace("{host}", host).as_bytes(),
            true,
        );
        assert!(response.starts_with(b"HTTP/1.1 400 Blocked\r\n"));
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let output = wait_output(running.child, Duration::from_secs(2));
        assert!(!output.status.success());
        assert_content_free(&output);
    }
}

#[test]
fn wrong_hmac_workspace_and_fd_kind_block_before_ready() {
    for failure in ["hmac", "workspace", "fd"] {
        assert_pre_ready_block(failure);
    }
}

fn assert_pre_ready_block(failure: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let (child_binding, host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let workspace = tempfile::tempdir().unwrap();
    let workspace_fd = File::open(workspace.path()).unwrap();
    let alternate = tempfile::tempdir().unwrap();
    let metadata = if failure == "workspace" {
        File::open(alternate.path()).unwrap().metadata().unwrap()
    } else {
        workspace_fd.metadata().unwrap()
    };
    let (ready_read, ready_write) = pipe_pair();
    let mut config = native_sse_proxy_config(
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
        &origin,
        &format!("http://{}", upstream.local_addr().unwrap()),
        SESSION,
        metadata.dev(),
        metadata.ino(),
        &SECRET,
    )
    .unwrap();
    if failure == "hmac" {
        let mut value: Value = serde_json::from_slice(&config).unwrap();
        value["config_mac"] = Value::String("0".repeat(64));
        config = serde_json::to_vec(&value).unwrap();
    }
    let bad_secret = File::open("/dev/null").unwrap();
    let secret_descriptor = if failure == "fd" {
        bad_secret.as_raw_fd()
    } else {
        secret_read.as_raw_fd()
    };
    let child = spawn_proxy([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_descriptor,
        config_read.as_raw_fd(),
        workspace_fd.as_raw_fd(),
        ready_write.as_raw_fd(),
    ]);
    drop((
        listener,
        child_binding,
        host_binding,
        secret_read,
        config_read,
        workspace_fd,
        ready_write,
        workspace,
        alternate,
        bad_secret,
    ));
    write_and_close(secret_write, &SECRET);
    write_and_close(config_write, &config);
    let output = wait_output(child, Duration::from_secs(2));
    assert!(!output.status.success());
    assert_content_free(&output);
    let mut ready = File::from(ready_read);
    let mut bytes = Vec::new();
    ready.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty(), "{failure} became ready");
    assert_eq!(
        upstream.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn run_upstream_bytes(response_bytes: Vec<u8>) -> (Vec<u8>, Output, usize) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0u8; 512];
        let count = stream.read(&mut request).unwrap();
        assert!(std::str::from_utf8(&request[..count])
            .unwrap()
            .starts_with("GET /event HTTP/1.1\r\n"));
        stream.write_all(&response_bytes).unwrap();
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let response = client_request(
        &running.origin,
        format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        false,
    );
    let output = wait_output(running.child, Duration::from_secs(4));
    (response, output, peer.join().unwrap())
}

fn response_with_stream(stream: &[u8]) -> Vec<u8> {
    let mut response = RESPONSE_HEAD.to_vec();
    response.extend_from_slice(stream);
    response
}

fn response_body(response: &[u8]) -> &[u8] {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| &response[index + 4..])
        .unwrap_or_default()
}

#[test]
fn invalid_upstream_headers_never_commit_success() {
    let cases: &[(&str, &[u8])] = &[
        (
            "redirect",
            b"HTTP/1.1 302 Found\r\nContent-Type: text/event-stream\r\nLocation: http://127.0.0.1:1/event\r\n\r\n",
        ),
        (
            "wrong-content-type",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
        ),
        (
            "content-length",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "chunked",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        (
            "duplicate",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Type: text/event-stream\r\n\r\n",
        ),
        (
            "authentication",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nProxy-Authorization: secret\r\n\r\n",
        ),
    ];
    for (name, bytes) in cases {
        let (response, output, hits) = run_upstream_bytes(bytes.to_vec());
        assert!(
            response.starts_with(b"HTTP/1.1 502 Blocked\r\n"),
            "{name}: {response:?}"
        );
        assert_eq!(hits, 1, "{name}");
        assert!(!output.status.success(), "{name}");
        assert_content_free(&output);
    }
}

#[test]
fn malformed_events_close_without_forwarding_invalid_event() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("malformed-json", b"data: nope\n\n".to_vec()),
        (
            "duplicate-json-key",
            format!("data: {{\"id\":\"x\",\"id\":\"y\",\"type\":\"t\",\"properties\":{{\"sessionID\":\"{SESSION}\"}}}}\n\n").into_bytes(),
        ),
        (
            "session-mismatch",
            b"data: {\"id\":\"x\",\"type\":\"t\",\"properties\":{\"sessionID\":\"other\"}}\n\n".to_vec(),
        ),
        (
            "multiline",
            format!("data: {{\"id\":\"x\",\"type\":\"t\",\"properties\":{{\"sessionID\":\"{SESSION}\"}}}}\ndata: {{}}\n\n").into_bytes(),
        ),
        ("comment", b": keepalive\n\n".to_vec()),
        ("event-field", b"event: update\n\n".to_vec()),
        ("id-field", b"id: cursor\n\n".to_vec()),
        ("retry-field", b"retry: 1\n\n".to_vec()),
        ("bom", b"\xef\xbb\xbfdata: {}\n\n".to_vec()),
        ("nul", b"data: {\x00}\n\n".to_vec()),
        ("bare-cr", b"data: {}\rX".to_vec()),
        ("partial-eof", b"data: {\"id\":\"x\"}".to_vec()),
        (
            "trailing-json",
            format!("data: {{\"id\":\"x\",\"type\":\"t\",\"properties\":{{\"sessionID\":\"{SESSION}\"}}}} {{}}\n\n").into_bytes(),
        ),
        ("oversized-line", vec![b'x'; 8_193]),
    ];
    for (name, stream) in cases {
        let (response, output, hits) = run_upstream_bytes(response_with_stream(&stream));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"), "{name}");
        assert!(
            response_body(&response).is_empty(),
            "{name}: invalid bytes escaped"
        );
        assert_eq!(hits, 1, "{name}");
        assert!(!output.status.success(), "{name}");
        assert_content_free(&output);
    }
}

#[test]
fn duplicate_event_id_forwards_only_the_first_complete_event() {
    let first = event("same", "server.connected", "{}", "\n");
    let mut stream = first.clone();
    stream.extend_from_slice(&event(
        "same",
        "message.delta",
        &format!("{{\"sessionID\":\"{SESSION}\"}}"),
        "\n",
    ));
    let (response, output, hits) = run_upstream_bytes(response_with_stream(&stream));
    assert_eq!(
        response_body(&response),
        b"data: {\"id\":\"same\",\"properties\":{},\"type\":\"server.connected\"}\n\n"
    );
    assert_eq!(hits, 1);
    assert!(!output.status.success());
    assert_content_free(&output);
}

#[test]
fn count_and_stream_bounds_reject_the_first_excess_event() {
    let mut count_stream = Vec::new();
    for index in 0..257 {
        count_stream.extend_from_slice(&event(
            &format!("id{index}"),
            "server.connected",
            "{}",
            "\n",
        ));
    }
    let (count_response, count_output, hits) =
        run_upstream_bytes(response_with_stream(&count_stream));
    assert_eq!(hits, 1);
    assert_eq!(
        String::from_utf8_lossy(response_body(&count_response))
            .matches("data: ")
            .count(),
        256
    );
    assert!(!count_output.status.success());
    assert_content_free(&count_output);

    let padding = "x".repeat(8_000);
    let mut byte_stream = Vec::new();
    for index in 0..140 {
        byte_stream.extend_from_slice(&event(
            &format!("large{index}"),
            "message.delta",
            &format!("{{\"sessionID\":\"{SESSION}\",\"padding\":\"{padding}\"}}"),
            "\n",
        ));
    }
    let (byte_response, byte_output, hits) = run_upstream_bytes(response_with_stream(&byte_stream));
    assert_eq!(hits, 1);
    assert!(response_body(&byte_response).len() <= 1_048_576);
    assert!(!byte_output.status.success());
    assert_content_free(&byte_output);
}

#[test]
fn stalled_event_hits_two_second_idle_bound_after_one_upstream_hit() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0u8; 512];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream.write_all(RESPONSE_HEAD).unwrap();
        thread::sleep(Duration::from_secs(3));
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let started = Instant::now();
    let response = client_request(
        &running.origin,
        format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        false,
    );
    let elapsed = started.elapsed();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response_body(&response).is_empty());
    assert!(elapsed >= Duration::from_millis(1_800), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    let output = wait_output(running.child, Duration::from_secs(1));
    assert!(!output.status.success());
    assert_content_free(&output);
    assert_eq!(peer.join().unwrap(), 1);
}

#[test]
fn stalled_response_headers_hit_the_shared_total_deadline() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0u8; 512];
        assert!(stream.read(&mut request).unwrap() > 0);
        thread::sleep(Duration::from_secs(16));
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let started = Instant::now();
    let mut stream = TcpStream::connect(running.origin.strip_prefix("http://").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(17)))
        .unwrap();
    stream
        .write_all(format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = Vec::new();
    if let Err(error) = stream.read_to_end(&mut response) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(13), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(17), "{elapsed:?}");
    assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 502 Blocked\r\n"));
    let output = wait_output(running.child, Duration::from_secs(2));
    assert!(!output.status.success());
    assert_content_free(&output);
    assert_eq!(peer.join().unwrap(), 1);
}

fn connect_with_receive_buffer(origin: &str, receive_buffer: libc::c_int) -> TcpStream {
    let address: std::net::SocketAddrV4 = origin.strip_prefix("http://").unwrap().parse().unwrap();
    // SAFETY: socket creates one owned AF_INET stream descriptor. All failure
    // paths below close it before panicking or return sole ownership to TcpStream.
    let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(descriptor >= 0);
    // SAFETY: setsockopt reads one fixed integer from valid storage.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&receive_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&receive_buffer) as libc::socklen_t,
            )
        },
        0
    );
    let socket_address = libc::sockaddr_in {
        #[cfg(any(
            target_os = "aix",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "solaris",
            target_os = "visionos",
        ))]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: connect receives a correctly initialized sockaddr_in.
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&socket_address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&socket_address) as libc::socklen_t,
        )
    };
    if connected != 0 {
        // SAFETY: descriptor remains owned locally on connect failure.
        unsafe { libc::close(descriptor) };
        panic!("connect failed: {}", std::io::Error::last_os_error());
    }
    // SAFETY: successful connect leaves one live descriptor now transferred.
    unsafe { TcpStream::from_raw_fd(descriptor) }
}

#[test]
fn non_reading_client_backpressure_exits_inside_shared_deadline() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(16)))
            .unwrap();
        let mut request = [0u8; 512];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream.write_all(RESPONSE_HEAD).unwrap();
        let padding = "x".repeat(3_900);
        let mut sent = 0usize;
        for index in 0..256 {
            let frame = event(
                &format!("backpressure{index}"),
                "message.delta",
                &format!("{{\"sessionID\":\"{SESSION}\",\"padding\":\"{padding}\"}}"),
                "\n",
            );
            match stream.write_all(&frame) {
                Ok(()) => sent += frame.len(),
                Err(_) => break,
            }
        }
        upstream.set_nonblocking(true).unwrap();
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        sent
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let mut client = connect_with_receive_buffer(&running.origin, 1_024);
    client
        .write_all(format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .unwrap();
    let started = Instant::now();
    let output = wait_output(running.child, Duration::from_secs(16));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    assert!(!output.status.success());
    assert_content_free(&output);
    let sent = peer.join().unwrap();
    assert!(sent > 900_000, "upstream sent only {sent} bytes");
    drop(client);
}
