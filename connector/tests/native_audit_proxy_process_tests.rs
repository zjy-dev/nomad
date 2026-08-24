#![cfg(all(unix, feature = "native_audit_proxy_test_helper"))]

use nomad_connector::{native_audit_proxy_config, HostRunBinding, NATIVE_AUDIT_PROXY_READY};
use serde_json::Value;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SECRET: [u8; 32] = [7; 32];
const CHALLENGE: [u8; 32] = [9; 32];
const SESSION: &str = "fixed_test_session-1";

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes both descriptors.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    for descriptor in descriptors {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            0
        );
    }
    // SAFETY: successful pipe returned independently owned descriptors.
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

fn max_fd() -> RawFd {
    let value = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    RawFd::try_from(value.clamp(64, 65_536)).unwrap_or(65_536)
}

fn spawn_proxy(inherited: [RawFd; 6]) -> Child {
    assert!(inherited.iter().all(|descriptor| *descriptor > 2));
    let maximum = max_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_native-audit-proxy"));
    command
        .args(inherited.map(|descriptor| descriptor.to_string()))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the callback performs only fcntl over bounded descriptor numbers.
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
    File::from(descriptor).write_all(bytes).unwrap();
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
    let config = native_audit_proxy_config(
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
    let binding = HostRunBinding::new(CHALLENGE, SECRET)
        .unwrap()
        .handshake(&mut host_binding)
        .unwrap();
    assert_eq!(binding.proxy_origin, origin);
    drop(host_binding);
    let mut ready = File::from(ready_read);
    let mut marker = vec![0; NATIVE_AUDIT_PROXY_READY.len()];
    ready.read_exact(&mut marker).unwrap();
    assert_eq!(marker, NATIVE_AUDIT_PROXY_READY);
    let mut trailing = [0u8; 1];
    assert_eq!(ready.read(&mut trailing).unwrap(), 0);
    RunningProxy { child, origin }
}

fn request(origin: &str, raw: &[u8]) -> Vec<u8> {
    let address = origin.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(raw).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn request_without_half_close(origin: &str, raw: &[u8]) -> Vec<u8> {
    request_without_half_close_with_timeout(origin, raw, Duration::from_secs(2))
}

fn request_without_half_close_with_timeout(origin: &str, raw: &[u8], timeout: Duration) -> Vec<u8> {
    let address = origin.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(timeout)).unwrap();
    stream.write_all(raw).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn wait_output(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(7);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("native audit proxy timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_clean_success(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

fn happy_get(path: &'static str, body: &'static [u8]) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let hit = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0u8; 1024];
        let count = stream.read(&mut request).unwrap();
        let request = String::from_utf8(request[..count].to_vec()).unwrap();
        assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let response = request(
        &running.origin,
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(body));
    assert_eq!(hit.join().unwrap(), 1);
    assert_clean_success(wait_output(running.child));
}

#[test]
fn forwards_health_once_through_controlled_upstream() {
    happy_get("/global/health", br#"{"healthy":true}"#);
}

#[test]
fn forwards_fixed_session_snapshot_once() {
    happy_get(
        "/session/fixed_test_session-1",
        br#"{"id":"fixed_test_session-1"}"#,
    );
}

#[test]
fn forwards_normal_http_get_without_client_half_close() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let hit = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0u8; 1024];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"healthy\":true}",
            )
            .unwrap();
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let response = request_without_half_close(
        &running.origin,
        format!("GET /global/health HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(br#"{"healthy":true}"#));
    assert_eq!(hit.join().unwrap(), 1);
    assert_clean_success(wait_output(running.child));
}

#[test]
fn post_is_rejected_without_touching_upstream() {
    assert_request_rejected_without_upstream(
        "POST /global/health HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n",
    );
}

#[test]
fn v2_write_route_is_rejected_without_touching_upstream() {
    assert_request_rejected_without_upstream(
        "POST /api/session/fixed_test_session-1/prompt HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n",
    );
}

fn assert_request_rejected_without_upstream(template: &str) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let raw = template.replace("{host}", host);
    let response = request(&running.origin, raw.as_bytes());
    assert!(response.starts_with(b"HTTP/1.1 400 Blocked\r\n"));
    let output = wait_output(running.child);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(
        upstream.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn wrong_hmac_and_workspace_block_before_ready() {
    for failure in ["hmac", "workspace"] {
        assert_blocks_before_ready(failure);
    }
}

fn assert_blocks_before_ready(failure: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let (child_binding, host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let actual_workspace = tempfile::tempdir().unwrap();
    let actual_workspace_fd = File::open(actual_workspace.path()).unwrap();
    let expected_workspace = tempfile::tempdir().unwrap();
    let expected_metadata = if failure == "workspace" {
        File::open(expected_workspace.path())
            .unwrap()
            .metadata()
            .unwrap()
    } else {
        actual_workspace_fd.metadata().unwrap()
    };
    let (ready_read, ready_write) = pipe_pair();
    let mut config = native_audit_proxy_config(
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
        &origin,
        &upstream_origin,
        SESSION,
        expected_metadata.dev(),
        expected_metadata.ino(),
        &SECRET,
    )
    .unwrap();
    if failure == "hmac" {
        let mut value: Value = serde_json::from_slice(&config).unwrap();
        value["config_mac"] = Value::String("0".repeat(64));
        config = serde_json::to_vec(&value).unwrap();
    }
    let child = spawn_proxy([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
        actual_workspace_fd.as_raw_fd(),
        ready_write.as_raw_fd(),
    ]);
    drop((
        listener,
        child_binding,
        host_binding,
        secret_read,
        config_read,
        actual_workspace_fd,
        ready_write,
        actual_workspace,
        expected_workspace,
    ));
    write_and_close(secret_write, &SECRET);
    write_and_close(config_write, &config);
    let output = wait_output(child);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let mut ready = File::from(ready_read);
    let mut bytes = Vec::new();
    ready.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty(), "{failure} unexpectedly became ready");
}

#[test]
fn redirect_oversize_and_early_eof_are_not_forwarded_to_client() {
    let cases: &[(&str, &[u8])] = &[
        (
            "redirect",
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "oversize",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n",
        ),
        (
            "early-eof",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{}",
        ),
    ];
    for (name, upstream_response) in cases {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
        let response = upstream_response.to_vec();
        let hit = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            let mut request = [0u8; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream.write_all(&response).unwrap();
            1usize
        });
        let running = start_proxy(&upstream_origin);
        let host = running.origin.strip_prefix("http://").unwrap();
        let response = request(
            &running.origin,
            format!("GET /global/health HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        );
        assert!(
            response.starts_with(b"HTTP/1.1 502 Blocked\r\n"),
            "{name}: {response:?}"
        );
        assert_eq!(hit.join().unwrap(), 1);
        let output = wait_output(running.child);
        assert!(!output.status.success(), "{name}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn stalled_upstream_is_bounded_by_the_shared_deadline() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let hit = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(7)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"GET /global/health HTTP/1.1\r\n"));
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap();
    let started = Instant::now();
    let response = request_without_half_close_with_timeout(
        &running.origin,
        format!("GET /global/health HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        Duration::from_secs(7),
    );
    assert!(
        response.is_empty() || response.starts_with(b"HTTP/1.1 502 Blocked\r\n"),
        "timeout must fail closed: {response:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(7));
    assert_eq!(hit.join().unwrap(), 1);
    let output = wait_output(running.child);
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn delayed_pipelined_bytes_cannot_trigger_a_second_upstream_request() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_origin = format!("http://{}", upstream.local_addr().unwrap());
    let hit = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match upstream.accept() {
                Ok(value) => break value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("unexpected accept error: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0u8; 1024];
        let count = stream.read(&mut request).unwrap();
        let request = String::from_utf8(request[..count].to_vec()).unwrap();
        assert!(request.starts_with("GET /global/health HTTP/1.1\r\n"));
        assert!(!request.contains("/question"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"healthy\":true}",
            )
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        1usize
    });
    let running = start_proxy(&upstream_origin);
    let host = running.origin.strip_prefix("http://").unwrap().to_owned();
    let mut client = TcpStream::connect(&host).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .write_all(format!("GET /global/health HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    let _ = client.write_all(format!("GET /question HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes());
    let mut response = Vec::new();
    if let Err(error) = client.read_to_end(&mut response) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(hit.join().unwrap(), 1);
    assert_clean_success(wait_output(running.child));
}
