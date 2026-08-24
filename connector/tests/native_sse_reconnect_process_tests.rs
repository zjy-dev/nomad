#![cfg(all(unix, feature = "native_sse_reconnect_test_helper"))]

use nomad_connector::{native_sse_reconnect_config, HostRunBinding, NATIVE_SSE_RECONNECT_READY};
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

const SECRET: [u8; 32] = [23; 32];
const CHALLENGE: [u8; 32] = [29; 32];
const SESSION: &str = "fixed_test_session-1";
const SSE_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    for descriptor in descriptors {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            0
        );
    }
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_native-sse-reconnect"));
    command
        .args(inherited.map(|descriptor| descriptor.to_string()))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let config = native_sse_reconnect_config(
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
    let mut marker = vec![0; NATIVE_SSE_RECONNECT_READY.len()];
    ready.read_exact(&mut marker).unwrap();
    assert_eq!(marker, NATIVE_SSE_RECONNECT_READY);
    assert_eq!(ready.read(&mut [0]).unwrap(), 0);
    RunningProxy { child, origin }
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        raw.push(byte[0]);
    }
    String::from_utf8(raw).unwrap()
}

fn client_request(origin: &str) -> Vec<u8> {
    let host = origin.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(host).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(format!("GET /event HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    if let Err(error) = stream.read_to_end(&mut response) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    response
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
            panic!("native SSE reconnect timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_content_free(output: &Output) {
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn event(id: &str, event_type: &str, properties: &str) -> Vec<u8> {
    format!("data: {{\"properties\":{properties},\"type\":\"{event_type}\",\"id\":\"{id}\"}}\n\n")
        .into_bytes()
}

fn json_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
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
fn clean_first_eof_fetches_four_snapshots_then_reconnects_with_exact_six_hits() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let upstream_host = upstream_origin.strip_prefix("http://").unwrap().to_string();
    let peer = thread::spawn(move || {
        let mut requests = Vec::new();
        let expected = [
            "GET /event HTTP/1.1",
            "GET /session/fixed_test_session-1 HTTP/1.1",
            "GET /question HTTP/1.1",
            "GET /permission HTTP/1.1",
            "GET /session/fixed_test_session-1/diff HTTP/1.1",
            "GET /event HTTP/1.1",
        ];
        for (index, expected_line) in expected.iter().enumerate() {
            let (mut stream, _) = upstream.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with(&format!("{expected_line}\r\n")),
                "{request}"
            );
            assert!(request.contains(&format!("Host: {upstream_host}\r\n")));
            assert!(!request.contains("Last-Event-ID"));
            assert!(!request.contains("Authorization"));
            assert!(!request.contains("Cookie"));
            assert!(!request.starts_with("POST "));
            requests.push(request);
            match index {
                0 => {
                    stream.write_all(SSE_HEAD).unwrap();
                    stream
                        .write_all(&event("one", "server.connected", "{}"))
                        .unwrap();
                }
                1 => stream
                    .write_all(&json_response(br#"{"id":"fixed_test_session-1"}"#))
                    .unwrap(),
                2 => stream
                    .write_all(&json_response(br#"{"question":null}"#))
                    .unwrap(),
                3 => stream
                    .write_all(&json_response(br#"{"permission":"read"}"#))
                    .unwrap(),
                4 => stream.write_all(&json_response(br#"{"diff":[]}"#)).unwrap(),
                5 => {
                    stream.write_all(SSE_HEAD).unwrap();
                    stream
                        .write_all(&event("one", "server.connected", "{}"))
                        .unwrap();
                    stream
                        .write_all(&event(
                            "two",
                            "message.delta",
                            &format!("{{\"sessionID\":\"{SESSION}\",\"text\":\"new\"}}"),
                        ))
                        .unwrap();
                }
                _ => unreachable!(),
            }
        }
        upstream.set_nonblocking(true).unwrap();
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        requests
    });
    let running = start_proxy(&upstream_origin);
    let response = client_request(&running.origin);
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"));
    assert_eq!(text.matches("\"id\":\"one\"").count(), 1);
    assert_eq!(text.matches("\"id\":\"two\"").count(), 1);
    assert!(text.contains("\"text\":\"new\""));
    let requests = peer.join().unwrap();
    assert_eq!(requests.len(), 6);
    let output = wait_output(running.child, Duration::from_secs(5));
    assert!(output.status.success(), "{output:?}");
    assert_content_free(&output);
}

#[test]
fn bad_first_upstream_headers_fail_before_committing_client_success() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /event HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
            .unwrap();
        upstream.set_nonblocking(true).unwrap();
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let response = client_request(&running.origin);
    assert!(
        response.starts_with(b"HTTP/1.1 502 Blocked\r\n"),
        "{response:?}"
    );
    assert_eq!(peer.join().unwrap(), 1);
    let output = wait_output(running.child, Duration::from_secs(3));
    assert!(!output.status.success(), "{output:?}");
    assert_content_free(&output);
}

#[test]
fn bad_snapshot_stops_after_first_stream_and_never_reconnects() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let expected = [
            "GET /event HTTP/1.1",
            "GET /session/fixed_test_session-1 HTTP/1.1",
            "GET /question HTTP/1.1",
        ];
        for (index, expected_line) in expected.iter().enumerate() {
            let (mut stream, _) = upstream.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with(&format!("{expected_line}\r\n")));
            match index {
                0 => {
                    stream.write_all(SSE_HEAD).unwrap();
                    stream
                        .write_all(&event("one", "server.connected", "{}"))
                        .unwrap();
                }
                1 => stream
                    .write_all(&json_response(br#"{"id":"fixed_test_session-1"}"#))
                    .unwrap(),
                2 => stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{")
                    .unwrap(),
                _ => unreachable!(),
            }
        }
        upstream.set_nonblocking(true).unwrap();
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        expected.len()
    });
    let running = start_proxy(&upstream_origin);
    let response = client_request(&running.origin);
    let body = String::from_utf8(response_body(&response).to_vec()).unwrap();
    assert_eq!(body.matches("\"id\":\"one\"").count(), 1);
    assert_eq!(peer.join().unwrap(), 3);
    let output = wait_output(running.child, Duration::from_secs(3));
    assert!(!output.status.success(), "{output:?}");
    assert_content_free(&output);
}

#[test]
fn empty_or_malformed_first_stream_never_reconnects() {
    for stream_bytes in [
        Vec::<u8>::new(),
        b"data: nope\n\n".to_vec(),
        b": keepalive\n\n".to_vec(),
    ] {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
        let peer = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /event HTTP/1.1\r\n"));
            stream.write_all(SSE_HEAD).unwrap();
            if !stream_bytes.is_empty() {
                stream.write_all(&stream_bytes).unwrap();
            }
            upstream.set_nonblocking(true).unwrap();
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            1usize
        });
        let running = start_proxy(&upstream_origin);
        let response = client_request(&running.origin);
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response_body(&response).is_empty(), "{response:?}");
        assert_eq!(peer.join().unwrap(), 1);
        let output = wait_output(running.child, Duration::from_secs(3));
        assert!(!output.status.success(), "{output:?}");
        assert_content_free(&output);
    }
}

#[test]
fn second_stream_malformed_or_timeout_never_triggers_third_stream() {
    let timeout_case = |second_bytes: Option<Vec<u8>>, sleep_ms: u64| {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
        let peer = thread::spawn(move || {
            let expected = [
                "GET /event HTTP/1.1",
                "GET /session/fixed_test_session-1 HTTP/1.1",
                "GET /question HTTP/1.1",
                "GET /permission HTTP/1.1",
                "GET /session/fixed_test_session-1/diff HTTP/1.1",
                "GET /event HTTP/1.1",
            ];
            for (index, expected_line) in expected.iter().enumerate() {
                let (mut stream, _) = upstream.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(request.starts_with(&format!("{expected_line}\r\n")));
                match index {
                    0 => {
                        stream.write_all(SSE_HEAD).unwrap();
                        stream
                            .write_all(&event("one", "server.connected", "{}"))
                            .unwrap();
                    }
                    1 => stream
                        .write_all(&json_response(br#"{"id":"fixed_test_session-1"}"#))
                        .unwrap(),
                    2 => stream
                        .write_all(&json_response(br#"{"question":null}"#))
                        .unwrap(),
                    3 => stream
                        .write_all(&json_response(br#"{"permission":"read"}"#))
                        .unwrap(),
                    4 => stream.write_all(&json_response(br#"{"diff":[]}"#)).unwrap(),
                    5 => {
                        stream.write_all(SSE_HEAD).unwrap();
                        if let Some(bytes) = second_bytes.as_ref() {
                            stream.write_all(bytes).unwrap();
                        }
                        if sleep_ms != 0 {
                            thread::sleep(Duration::from_millis(sleep_ms));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            upstream.set_nonblocking(true).unwrap();
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            expected.len()
        });
        let running = start_proxy(&upstream_origin);
        let response = client_request(&running.origin);
        assert_eq!(
            String::from_utf8_lossy(response_body(&response))
                .matches("\"id\":\"one\"")
                .count(),
            1
        );
        assert_eq!(peer.join().unwrap(), 6);
        let output = wait_output(running.child, Duration::from_secs(5));
        assert!(!output.status.success(), "{output:?}");
        assert_content_free(&output);
    };

    timeout_case(Some(b"data: nope\n\n".to_vec()), 0);
    timeout_case(None, 2_300);
}

#[test]
fn duplicate_id_across_streams_is_dropped_while_new_ids_preserve_arrival_order() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let peer = thread::spawn(move || {
        let expected = [
            "GET /event HTTP/1.1",
            "GET /session/fixed_test_session-1 HTTP/1.1",
            "GET /question HTTP/1.1",
            "GET /permission HTTP/1.1",
            "GET /session/fixed_test_session-1/diff HTTP/1.1",
            "GET /event HTTP/1.1",
        ];
        for (index, _) in expected.iter().enumerate() {
            let (mut stream, _) = upstream.accept().unwrap();
            let _ = read_http_request(&mut stream);
            match index {
                0 => {
                    stream.write_all(SSE_HEAD).unwrap();
                    stream
                        .write_all(&event("a", "server.connected", "{}"))
                        .unwrap();
                    stream
                        .write_all(&event(
                            "b",
                            "message.delta",
                            &format!("{{\"sessionID\":\"{SESSION}\",\"text\":\"first\"}}"),
                        ))
                        .unwrap();
                }
                1 => stream
                    .write_all(&json_response(br#"{"id":"fixed_test_session-1"}"#))
                    .unwrap(),
                2 => stream
                    .write_all(&json_response(br#"{"question":null}"#))
                    .unwrap(),
                3 => stream
                    .write_all(&json_response(br#"{"permission":"read"}"#))
                    .unwrap(),
                4 => stream.write_all(&json_response(br#"{"diff":[]}"#)).unwrap(),
                5 => {
                    stream.write_all(SSE_HEAD).unwrap();
                    stream
                        .write_all(&event(
                            "b",
                            "message.delta",
                            &format!("{{\"sessionID\":\"{SESSION}\",\"text\":\"dup\"}}"),
                        ))
                        .unwrap();
                    stream
                        .write_all(&event(
                            "c",
                            "message.delta",
                            &format!("{{\"sessionID\":\"{SESSION}\",\"text\":\"second\"}}"),
                        ))
                        .unwrap();
                }
                _ => unreachable!(),
            }
        }
        6usize
    });
    let running = start_proxy(&upstream_origin);
    let response = client_request(&running.origin);
    let body = String::from_utf8(response_body(&response).to_vec()).unwrap();
    assert_eq!(body.matches("\"id\":\"a\"").count(), 1);
    assert_eq!(body.matches("\"id\":\"b\"").count(), 1);
    assert_eq!(body.matches("\"id\":\"c\"").count(), 1);
    assert!(!body.contains("\"text\":\"dup\""));
    let b_pos = body.find("\"id\":\"b\"").unwrap();
    let c_pos = body.find("\"id\":\"c\"").unwrap();
    assert!(b_pos < c_pos, "{body}");
    assert_eq!(peer.join().unwrap(), 6);
    let output = wait_output(running.child, Duration::from_secs(5));
    assert!(output.status.success(), "{output:?}");
    assert_content_free(&output);
}
