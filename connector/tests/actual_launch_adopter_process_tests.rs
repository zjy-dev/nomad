#![cfg(all(unix, feature = "actual_launch_test_helper"))]

use nomad_connector::run_binding::proxy_handshake;
use nomad_connector::RunBindingHello;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: u16 = 1;

fn canonical(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for part in parts {
        output.extend_from_slice(&(part.len() as u64).to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut normalized = [0u8; 64];
    normalized[..key.len()].copy_from_slice(key);
    let mut inner = [0u8; 64];
    let mut outer = [0u8; 64];
    for index in 0..64 {
        inner[index] = normalized[index] ^ 0x36;
        outer[index] = normalized[index] ^ 0x5c;
    }
    let inner_hash = Sha256::new()
        .chain_update(inner)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(outer)
        .chain_update(inner_hash)
        .finalize()
        .into()
}

fn payload(run_id: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "adapter_id":"opencode",
        "adapter_version":"1.18.16",
        "entrypoint_raw_digest":"1".repeat(64),
        "entrypoint_realpath":"/locked/node_modules/opencode/bin/opencode",
        "fixture_manifest_digest":"2".repeat(64),
        "full_locked_dependency_count":12,
        "full_locked_dependency_digest":"3".repeat(64),
        "installed_platform_dependency_count":3,
        "installed_platform_dependency_digest":"4".repeat(64),
        "npm_executable_realpath":"/usr/local/bin/npm",
        "npm_version":"11.12.1",
        "package_lock_raw_digest":"5".repeat(64),
        "package_name":"opencode-ai",
        "package_version":"1.18.16",
        "run_id":run_id,
        "schema_version":"nomad.actual-launch-provenance.v1",
        "task_spec_digest":"6".repeat(64)
    }))
    .unwrap()
}

fn claim(run_id: &str, digest: &[u8; 32]) -> String {
    format!(
        "{:x}",
        Sha256::digest(canonical(&[
            b"nomad-c1a-transport-claim-v1",
            &VERSION.to_be_bytes(),
            run_id.as_bytes(),
            digest,
        ]))
    )
}

fn envelope(run_id: &str, secret: &[u8; 32], corrupt_mac: bool) -> (Vec<u8>, String) {
    let payload = payload(run_id);
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut mac = hmac_sha256(
        secret,
        &canonical(&[
            b"nomad-actual-launch-provenance-v1",
            &VERSION.to_be_bytes(),
            run_id.as_bytes(),
            &digest,
        ]),
    );
    if corrupt_mac {
        mac[0] ^= 1;
    }
    let mut output = b"NOMADALP".to_vec();
    output.extend(VERSION.to_be_bytes());
    output.extend((payload.len() as u32).to_be_bytes());
    output.extend(digest);
    output.extend(mac);
    output.extend(payload);
    (output, claim(run_id, &digest))
}

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes the two-element output array. Each endpoint is
    // immediately marked CLOEXEC before it can be used to spawn a child.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    for descriptor in descriptors {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) },
            0
        );
    }
    // SAFETY: successful pipe returns two newly owned descriptors.
    unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    }
}

fn write_and_close(descriptor: OwnedFd, bytes: &[u8]) {
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes).unwrap();
}

fn clear_cloexec(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl operates on a live descriptor inherited across fork.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
            panic!("adopter timed out: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn kill_and_reap_after(mut child: Child, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            panic!("adopter exited before supervisor timeout");
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(!output.status.success());
            return output;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_adopter(inherited: [RawFd; 3], challenge: &str) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_actual-launch-adopter"));
    command
        .args([
            inherited[0].to_string(),
            inherited[1].to_string(),
            inherited[2].to_string(),
            challenge.to_string(),
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure performs only async-signal-safe fcntl calls and
    // changes exactly the three descriptors permitted for this child.
    unsafe {
        command.pre_exec(move || {
            for descriptor in inherited {
                clear_cloexec(descriptor)?;
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

fn assert_blocked(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"BLOCKED_ACTUAL_LAUNCH_ADOPTION\n");
}

fn duplicate_cloexec(descriptor: RawFd) -> OwnedFd {
    // SAFETY: F_DUPFD_CLOEXEC returns a fresh owned descriptor on success.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(duplicate >= 0);
    unsafe { OwnedFd::from_raw_fd(duplicate) }
}

fn run_child(corrupt_mac: bool) -> Output {
    let run_id = "a".repeat(64);
    let secret = [7u8; 32];
    let challenge = "09".repeat(32);
    let (frame, transport_claim) = envelope(&run_id, &secret, corrupt_mac);
    let (child_socket, mut parent_socket) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let inherited = [
        child_socket.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let child = spawn_adopter(inherited, &challenge);
    drop((child_socket, secret_read, provenance_read));
    write_and_close(secret_write, &secret);
    write_and_close(provenance_write, &frame);
    let peer = thread::spawn(move || {
        proxy_handshake(
            &mut parent_socket,
            RunBindingHello {
                run_id,
                proxy_origin: "http://127.0.0.1:43123".into(),
                nonce: "b".repeat(64),
                capability_digest: transport_claim,
            },
            secret,
        )
    });
    let output = wait_output(child);
    assert!(peer.join().unwrap().is_ok());
    output
}

#[test]
fn real_adopter_child_accepts_only_authenticated_three_fd_input() {
    let output = run_child(false);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ADOPTED_ACTUAL_LAUNCH_PROVENANCE\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn real_adopter_child_rejects_bad_mac_content_free() {
    let output = run_child(true);
    assert_blocked(&output);
}

#[test]
fn real_child_rejects_wrong_descriptor_type_and_access() {
    let challenge = "09".repeat(32);
    let (binding_read, binding_write) = pipe_pair();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let inherited = [
        binding_read.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let child = spawn_adopter(inherited, &challenge);
    drop((binding_read, secret_read, provenance_read));
    drop((binding_write, secret_write, provenance_write));
    assert_blocked(&wait_output(child));

    let (child_socket, _parent_socket) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let inherited = [
        child_socket.as_raw_fd(),
        secret_write.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let child = spawn_adopter(inherited, &challenge);
    drop((child_socket, secret_write, provenance_read));
    drop((secret_read, provenance_write));
    assert_blocked(&wait_output(child));
}

#[test]
fn real_child_rejects_short_and_long_secret() {
    for bytes in [vec![7u8; 31], vec![7u8; 33]] {
        let (child_socket, _parent_socket) = UnixStream::pair().unwrap();
        let (secret_read, secret_write) = pipe_pair();
        let (provenance_read, provenance_write) = pipe_pair();
        let inherited = [
            child_socket.as_raw_fd(),
            secret_read.as_raw_fd(),
            provenance_read.as_raw_fd(),
        ];
        let child = spawn_adopter(inherited, &"09".repeat(32));
        drop((child_socket, secret_read, provenance_read));
        write_and_close(secret_write, &bytes);
        drop(provenance_write);
        assert_blocked(&wait_output(child));
    }
}

fn run_malformed_provenance(mut frame: Vec<u8>) -> Output {
    let run_id = "a".repeat(64);
    let secret = [7u8; 32];
    let digest: [u8; 32] = Sha256::digest(payload(&run_id)).into();
    let transport_claim = claim(&run_id, &digest);
    let (child_socket, mut parent_socket) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let inherited = [
        child_socket.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let child = spawn_adopter(inherited, &"09".repeat(32));
    drop((child_socket, secret_read, provenance_read));
    write_and_close(secret_write, &secret);
    write_and_close(provenance_write, &frame);
    frame.fill(0);
    let peer = thread::spawn(move || {
        proxy_handshake(
            &mut parent_socket,
            RunBindingHello {
                run_id,
                proxy_origin: "http://127.0.0.1:43123".into(),
                nonce: "b".repeat(64),
                capability_digest: transport_claim,
            },
            secret,
        )
    });
    let output = wait_output(child);
    assert!(peer.join().unwrap().is_ok());
    output
}

#[test]
fn real_child_rejects_provenance_trailing_and_early_eof() {
    let run_id = "a".repeat(64);
    let secret = [7u8; 32];
    let (mut trailing, _) = envelope(&run_id, &secret, false);
    trailing.push(0);
    assert_blocked(&run_malformed_provenance(trailing));
    let (mut early, _) = envelope(&run_id, &secret, false);
    early.truncate(early.len() - 1);
    assert_blocked(&run_malformed_provenance(early));
}

#[test]
fn real_child_times_out_content_free_when_peer_never_handshakes() {
    let (child_socket, _parent_socket) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let inherited = [
        child_socket.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let child = spawn_adopter(inherited, &"09".repeat(32));
    drop((child_socket, secret_read, provenance_read));
    write_and_close(secret_write, &[7u8; 32]);
    drop(provenance_write);
    let started = Instant::now();
    let output = wait_output(child);
    assert!(started.elapsed() >= Duration::from_secs(4));
    assert_blocked(&output);
}

#[test]
fn supervisor_kills_and_reaps_child_blocked_on_provenance_pipe() {
    let run_id = "a".repeat(64);
    let secret = [7u8; 32];
    let payload_digest: [u8; 32] = Sha256::digest(payload(&run_id)).into();
    let (child_socket, mut parent_socket) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let inherited = [
        child_socket.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let child = spawn_adopter(inherited, &"09".repeat(32));
    drop((child_socket, secret_read, provenance_read));
    write_and_close(secret_write, &secret);
    let peer = thread::spawn(move || {
        proxy_handshake(
            &mut parent_socket,
            RunBindingHello {
                run_id: run_id.clone(),
                proxy_origin: "http://127.0.0.1:43123".into(),
                nonce: "b".repeat(64),
                capability_digest: claim(&run_id, &payload_digest),
            },
            secret,
        )
    });
    assert!(peer.join().unwrap().is_ok());
    let output = kill_and_reap_after(child, Duration::from_millis(250));
    drop(provenance_write);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn consumed_fd_streams_cannot_be_adopted_by_a_second_child() {
    let run_id = "a".repeat(64);
    let secret = [7u8; 32];
    let (frame, transport_claim) = envelope(&run_id, &secret, false);
    let (child_socket, mut parent_socket) = UnixStream::pair().unwrap();
    let (secret_read, secret_write) = pipe_pair();
    let (provenance_read, provenance_write) = pipe_pair();
    let second_socket = duplicate_cloexec(child_socket.as_raw_fd());
    let second_secret = duplicate_cloexec(secret_read.as_raw_fd());
    let second_provenance = duplicate_cloexec(provenance_read.as_raw_fd());
    let first_inherited = [
        child_socket.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let first = spawn_adopter(first_inherited, &"09".repeat(32));
    drop((child_socket, secret_read, provenance_read));
    write_and_close(secret_write, &secret);
    write_and_close(provenance_write, &frame);
    let peer = thread::spawn(move || {
        proxy_handshake(
            &mut parent_socket,
            RunBindingHello {
                run_id,
                proxy_origin: "http://127.0.0.1:43123".into(),
                nonce: "b".repeat(64),
                capability_digest: transport_claim,
            },
            secret,
        )
    });
    let first_output = wait_output(first);
    assert!(first_output.status.success());
    assert!(peer.join().unwrap().is_ok());

    let second_inherited = [
        second_socket.as_raw_fd(),
        second_secret.as_raw_fd(),
        second_provenance.as_raw_fd(),
    ];
    let second = spawn_adopter(second_inherited, &"09".repeat(32));
    drop((second_socket, second_secret, second_provenance));
    assert_blocked(&wait_output(second));
}
