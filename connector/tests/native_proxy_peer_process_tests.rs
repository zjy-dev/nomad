#![cfg(all(unix, feature = "native_proxy_peer_test_helper"))]

use nomad_connector::HostRunBinding;
use serde_json::json;
use std::io::Write;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SECRET: [u8; 32] = [7; 32];
const CHALLENGE: [u8; 32] = [9; 32];

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes both descriptor slots.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    for descriptor in descriptors {
        // SAFETY: fcntl operates on a live descriptor.
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

fn config(origin: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "capability_digest": "c".repeat(64),
        "nonce": "b".repeat(64),
        "proxy_origin": origin,
        "run_id": "a".repeat(64),
        "schema_version": "nomad.native-proxy-peer.v1"
    }))
    .unwrap()
}

fn clear_cloexec(descriptor: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl operates on a live descriptor inherited across fork.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn max_fd() -> RawFd {
    // SAFETY: sysconf has no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    RawFd::try_from(value.clamp(64, 65_536)).unwrap_or(65_536)
}

fn spawn_peer(inherited: [RawFd; 4]) -> Child {
    assert!(inherited.iter().all(|descriptor| *descriptor > 2));
    assert!((0..4).all(|left| (left + 1..4).all(|right| inherited[left] != inherited[right])));
    let maximum = max_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_native-proxy-peer"));
    command
        .args(inherited.map(|descriptor| descriptor.to_string()))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe fcntl calls run after fork. Exactly the
    // four argv descriptors survive exec; every unrelated descriptor is CLOEXEC.
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
    let mut writer = std::fs::File::from(descriptor);
    writer.write_all(bytes).unwrap();
}

fn wait_output(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("native proxy peer timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_blocked(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"BLOCKED_NATIVE_PROXY_PEER\n");
}

#[test]
fn real_child_authenticates_prebound_listener_with_host_run_binding() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (child_binding, mut host_binding_stream) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let inherited = [
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ];
    let child = spawn_peer(inherited);
    drop((listener, child_binding, secret_read, config_read));
    write_and_close(secret_write, &SECRET);
    write_and_close(config_write, &config(&origin));

    host_binding_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    host_binding_stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let binding = HostRunBinding::new(CHALLENGE, SECRET)
        .unwrap()
        .handshake(&mut host_binding_stream)
        .unwrap();
    assert_eq!(binding.run_id, "a".repeat(64));
    assert_eq!(binding.proxy_origin, origin);
    assert_eq!(binding.capability_digest, "c".repeat(64));

    let output = wait_output(child);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"NATIVE_PROXY_PEER_READY\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn child_rejects_non_inet_listener() {
    let root = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(root.path().join("listener.sock")).unwrap();
    let (child_binding, _host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let child = spawn_peer([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ]);
    drop((listener, child_binding, secret_read, config_read));
    drop((secret_write, config_write));
    assert_blocked(&wait_output(child));
}

#[test]
fn child_rejects_short_secret() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (child_binding, _host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let child = spawn_peer([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ]);
    drop((listener, child_binding, secret_read, config_read));
    write_and_close(secret_write, &[7; 31]);
    write_and_close(config_write, &config(&origin));
    assert_blocked(&wait_output(child));
}

#[test]
fn child_rejects_config_origin_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (child_binding, _host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let child = spawn_peer([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ]);
    drop((listener, child_binding, secret_read, config_read));
    write_and_close(secret_write, &SECRET);
    write_and_close(config_write, &config("http://127.0.0.1:1"));
    assert_blocked(&wait_output(child));
}

#[test]
fn child_rejects_duplicate_config_field() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (child_binding, _host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let child = spawn_peer([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ]);
    drop((listener, child_binding, secret_read, config_read));
    write_and_close(secret_write, &SECRET);
    let duplicate = format!(
        "{{\"capability_digest\":\"{}\",\"nonce\":\"{}\",\"proxy_origin\":\"{}\",\"run_id\":\"{}\",\"run_id\":\"{}\",\"schema_version\":\"nomad.native-proxy-peer.v1\"}}",
        "c".repeat(64),
        "b".repeat(64),
        origin,
        "a".repeat(64),
        "d".repeat(64),
    );
    write_and_close(config_write, duplicate.as_bytes());
    assert_blocked(&wait_output(child));
}

#[test]
fn child_self_times_out_when_fifo_writer_holds_without_writing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (child_binding, _host_binding) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (config_read, config_write) = pipe_pair();
    let child = spawn_peer([
        listener.as_raw_fd(),
        child_binding.as_raw_fd(),
        secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ]);
    drop((listener, child_binding, secret_read, config_read));
    let started = Instant::now();
    let output = wait_output(child);
    let elapsed = started.elapsed();
    drop((secret_write, config_write));
    assert!(elapsed >= Duration::from_secs(4), "elapsed: {elapsed:?}");
    assert!(elapsed <= Duration::from_secs(6), "elapsed: {elapsed:?}");
    assert_blocked(&output);
}
