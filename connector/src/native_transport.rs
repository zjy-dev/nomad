//! Test-feature-only Rust parent for the authenticated three-FD adopter wire.
//! It is not reachable from the production supervisor and creates no command capability.

use crate::actual_launch::{provenance_mac, transport_claim};
use crate::run_binding::{proxy_handshake, RunBindingHello};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: u16 = 1;
const MAX_OUTPUT: usize = 4096;
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(10);

struct Secret([u8; 32]);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct SensitiveBytes {
    bytes: Vec<u8>,
    zero_on_drop: bool,
}
impl SensitiveBytes {
    fn secret(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            zero_on_drop: true,
        }
    }
    fn plain(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            zero_on_drop: false,
        }
    }
}
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        if self.zero_on_drop {
            self.bytes.fill(0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeTransportError;

impl std::fmt::Display for NativeTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BLOCKED_NATIVE_ACTUAL_LAUNCH_TRANSPORT")
    }
}
impl std::error::Error for NativeTransportError {}

pub fn supervise_test_adopter(adopter: &Path) -> Result<(), NativeTransportError> {
    let adopter = fixed_executable(adopter)?;
    let mut random = random_material()?;
    let secret = Secret(random[0]);
    random[0].fill(0);
    let challenge = random[1];
    let run_id = hex(&random[2]);
    let nonce = hex(&random[3]);
    let payload = payload(&run_id)?;
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let claim = transport_claim(&run_id, &digest);
    let mut envelope = b"NOMADALP".to_vec();
    envelope.extend(VERSION.to_be_bytes());
    envelope.extend(
        u32::try_from(payload.len())
            .map_err(|_| NativeTransportError)?
            .to_be_bytes(),
    );
    envelope.extend(digest);
    envelope.extend(provenance_mac(&secret.0, &run_id, &digest));
    envelope.extend(payload);

    let (child_socket, mut parent_socket) = UnixStream::pair().map_err(|_| NativeTransportError)?;
    let (secret_read, secret_write) = pipe_pair()?;
    let (provenance_read, provenance_write) = pipe_pair()?;
    let inherited = [
        child_socket.as_raw_fd(),
        secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    if inherited.iter().any(|fd| *fd <= 2)
        || inherited[0] == inherited[1]
        || inherited[0] == inherited[2]
        || inherited[1] == inherited[2]
    {
        return Err(NativeTransportError);
    }
    let max_fd = max_fd();
    let mut command = Command::new(&adopter);
    command
        .args(inherited.map(|fd| fd.to_string()))
        .arg(hex(&challenge))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the callback performs only fcntl calls over bounded descriptor numbers.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            prepare_child_fds(inherited, max_fd)
        });
    }
    let mut child = command.spawn().map_err(|_| NativeTransportError)?;
    drop((child_socket, secret_read, provenance_read));
    let failed = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    if stdout.is_none() || stderr.is_none() {
        let _ = kill_reap_group(&mut child);
        drop(stdout);
        drop(stderr);
        return Err(NativeTransportError);
    }
    let stdout = stdout.expect("checked above");
    let stderr = stderr.expect("checked above");
    if set_nonblocking(stdout.as_raw_fd()).is_err()
        || set_nonblocking(stderr.as_raw_fd()).is_err()
        || set_nonblocking(secret_write.as_raw_fd()).is_err()
        || set_nonblocking(provenance_write.as_raw_fd()).is_err()
    {
        let _ = kill_reap_group(&mut child);
        drop((stdout, stderr, secret_write, provenance_write));
        return Err(NativeTransportError);
    }
    let deadline = Instant::now() + TRANSPORT_TIMEOUT;
    let stdout_failed = Arc::clone(&failed);
    let stderr_failed = Arc::clone(&failed);
    let readers = [
        thread::spawn(move || read_bounded(stdout, stdout_failed, deadline)),
        thread::spawn(move || read_bounded(stderr, stderr_failed, deadline)),
    ];
    let writer_failed = Arc::clone(&failed);
    let writer = thread::spawn(move || {
        let result = write_bounded(provenance_write, &envelope, &writer_failed, deadline);
        if !result {
            writer_failed.store(true, Ordering::SeqCst);
        }
        result
    });
    let mut protocol_ok = write_bounded(secret_write, &secret.0, &failed, deadline);
    protocol_ok = parent_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_ok()
        && parent_socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .is_ok()
        && protocol_ok;
    let handshake = if protocol_ok {
        proxy_handshake(
            &mut parent_socket,
            RunBindingHello {
                run_id,
                proxy_origin: "http://127.0.0.1:43123".into(),
                nonce,
                capability_digest: claim,
            },
            secret.0,
        )
    } else {
        Err(crate::RunBindingError::Io)
    };
    drop(secret);
    drop(parent_socket);
    let mut cleanup_ok = true;
    let mut observed_status = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                observed_status = Some(status);
                break;
            }
            Ok(None) => {}
            Err(_) => {
                cleanup_ok = false;
                break;
            }
        }
        if failed.load(Ordering::SeqCst) || Instant::now() >= deadline || handshake.is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if observed_status.is_none() || process_group_exists(child.id()) {
        cleanup_ok = kill_reap_group(&mut child) && cleanup_ok;
    }
    let status = match observed_status {
        Some(status) => status,
        None => match child.wait() {
            Ok(status) => status,
            Err(_) => {
                cleanup_ok = false;
                failed.store(true, Ordering::SeqCst);
                std::process::ExitStatus::from_raw(1)
            }
        },
    };
    let writer_ok = writer.join().is_ok_and(|ok| ok);
    let mut outputs = Vec::new();
    let readers_ok = readers.into_iter().all(|reader| match reader.join() {
        Ok(Some(bytes)) => {
            outputs.push(bytes);
            true
        }
        _ => false,
    });
    if !cleanup_ok
        || handshake.is_err()
        || !writer_ok
        || !readers_ok
        || failed.load(Ordering::SeqCst)
        || !status.success()
        || outputs.len() != 2
        || outputs[0] != b"ADOPTED_ACTUAL_LAUNCH_PROVENANCE\n"
        || !outputs[1].is_empty()
    {
        return Err(NativeTransportError);
    }
    Ok(())
}

#[cfg(feature = "native_composed_transport_test_helper")]
pub fn supervise_test_proxy_and_adopter(
    proxy: &Path,
    adopter: &Path,
) -> Result<(), NativeTransportError> {
    let proxy = fixed_executable(proxy)?;
    let adopter = fixed_executable(adopter)?;
    let mut random = random_material()?;
    let secret = Secret(random[0]);
    random[0].fill(0);
    let challenge = random[1];
    let run_id = hex(&random[2]);
    let nonce = hex(&random[3]);
    let payload = payload(&run_id)?;
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let claim = transport_claim(&run_id, &digest);
    let mut envelope = b"NOMADALP".to_vec();
    envelope.extend(VERSION.to_be_bytes());
    envelope.extend(
        u32::try_from(payload.len())
            .map_err(|_| NativeTransportError)?
            .to_be_bytes(),
    );
    envelope.extend(digest);
    envelope.extend(provenance_mac(&secret.0, &run_id, &digest));
    envelope.extend(payload);

    let listener =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(|_| NativeTransportError)?;
    let port = listener
        .local_addr()
        .map_err(|_| NativeTransportError)?
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    let config = serde_json::to_vec(&BTreeMap::from([
        ("capability_digest", Value::from(claim)),
        ("nonce", Value::from(nonce)),
        ("proxy_origin", Value::from(origin)),
        ("run_id", Value::from(run_id)),
        ("schema_version", Value::from("nomad.native-proxy-peer.v1")),
    ]))
    .map_err(|_| NativeTransportError)?;

    let (proxy_binding, adopter_binding) = UnixStream::pair().map_err(|_| NativeTransportError)?;
    let (proxy_secret_read, proxy_secret_write) = pipe_pair()?;
    let (config_read, config_write) = pipe_pair()?;
    let (adopter_secret_read, adopter_secret_write) = pipe_pair()?;
    let (provenance_read, provenance_write) = pipe_pair()?;
    let proxy_fds = [
        listener.as_raw_fd(),
        proxy_binding.as_raw_fd(),
        proxy_secret_read.as_raw_fd(),
        config_read.as_raw_fd(),
    ];
    let adopter_fds = [
        adopter_binding.as_raw_fd(),
        adopter_secret_read.as_raw_fd(),
        provenance_read.as_raw_fd(),
    ];
    let all_fds: Vec<RawFd> = proxy_fds
        .iter()
        .chain(adopter_fds.iter())
        .copied()
        .collect();
    if all_fds.len() != 7 || all_fds.iter().any(|fd| *fd <= 2) || has_duplicates(&all_fds) {
        return Err(NativeTransportError);
    }
    for fd in [
        &proxy_secret_write,
        &config_write,
        &adopter_secret_write,
        &provenance_write,
    ] {
        set_nonblocking(fd.as_raw_fd())?;
    }
    let max_fd = max_fd();
    let mut proxy_command = Command::new(&proxy);
    proxy_command
        .args(proxy_fds.map(|fd| fd.to_string()))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        proxy_command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            prepare_child_fd_slice(&proxy_fds, max_fd)
        });
    }
    let mut adopter_command = Command::new(&adopter);
    adopter_command
        .args(adopter_fds.map(|fd| fd.to_string()))
        .arg(hex(&challenge))
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        adopter_command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            prepare_child_fd_slice(&adopter_fds, max_fd)
        });
    }

    let mut proxy_child = proxy_command.spawn().map_err(|_| NativeTransportError)?;
    let mut adopter_child = match adopter_command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let _ = kill_reap_group(&mut proxy_child);
            return Err(NativeTransportError);
        }
    };
    drop((
        listener,
        proxy_binding,
        proxy_secret_read,
        config_read,
        adopter_binding,
        adopter_secret_read,
        provenance_read,
    ));
    let failed = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + TRANSPORT_TIMEOUT;
    let output_handles = match (
        proxy_child.stdout.take(),
        proxy_child.stderr.take(),
        adopter_child.stdout.take(),
        adopter_child.stderr.take(),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => {
            if [a.as_raw_fd(), b.as_raw_fd(), c.as_raw_fd(), d.as_raw_fd()]
                .into_iter()
                .any(|fd| set_nonblocking(fd).is_err())
            {
                let _ = kill_reap_group(&mut proxy_child);
                let _ = kill_reap_group(&mut adopter_child);
                return Err(NativeTransportError);
            }
            vec![
                spawn_bounded_reader(a, Arc::clone(&failed), deadline),
                spawn_bounded_reader(b, Arc::clone(&failed), deadline),
                spawn_bounded_reader(c, Arc::clone(&failed), deadline),
                spawn_bounded_reader(d, Arc::clone(&failed), deadline),
            ]
        }
        _ => {
            let _ = kill_reap_group(&mut proxy_child);
            let _ = kill_reap_group(&mut adopter_child);
            return Err(NativeTransportError);
        }
    };
    let writes = [
        (
            proxy_secret_write,
            SensitiveBytes::secret(secret.0.to_vec()),
        ),
        (config_write, SensitiveBytes::plain(config)),
        (
            adopter_secret_write,
            SensitiveBytes::secret(secret.0.to_vec()),
        ),
        (provenance_write, SensitiveBytes::plain(envelope)),
    ];
    let mut writer_handles = Vec::new();
    for (fd, bytes) in writes {
        let signal = Arc::clone(&failed);
        writer_handles.push(thread::spawn(move || {
            write_bounded(fd, &bytes.bytes, &signal, deadline)
        }));
    }
    drop(secret);

    let mut statuses = [None, None];
    while Instant::now() < deadline && !failed.load(Ordering::SeqCst) {
        if statuses[0].is_none() {
            match proxy_child.try_wait() {
                Ok(status) => statuses[0] = status,
                Err(_) => {
                    failed.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        if statuses[1].is_none() {
            match adopter_child.try_wait() {
                Ok(status) => statuses[1] = status,
                Err(_) => {
                    failed.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        if statuses.iter().all(Option::is_some) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let mut cleanup_ok = true;
    if statuses[0].is_none() || process_group_exists(proxy_child.id()) {
        cleanup_ok &= kill_reap_group(&mut proxy_child);
    }
    if statuses[1].is_none() || process_group_exists(adopter_child.id()) {
        cleanup_ok &= kill_reap_group(&mut adopter_child);
    }
    let writers_ok = writer_handles
        .into_iter()
        .all(|handle| handle.join().is_ok_and(|ok| ok));
    let outputs: Option<Vec<Vec<u8>>> = output_handles
        .into_iter()
        .map(|handle| handle.join().ok().flatten())
        .collect();
    let Some(outputs) = outputs else {
        return Err(NativeTransportError);
    };
    if !cleanup_ok
        || !writers_ok
        || failed.load(Ordering::SeqCst)
        || outputs.len() != 4
        || !statuses[0].is_some_and(|status| status.success())
        || !statuses[1].is_some_and(|status| status.success())
        || outputs[0] != b"NATIVE_PROXY_PEER_READY\n"
        || !outputs[1].is_empty()
        || outputs[2] != b"ADOPTED_ACTUAL_LAUNCH_PROVENANCE\n"
        || !outputs[3].is_empty()
    {
        return Err(NativeTransportError);
    }
    Ok(())
}

#[cfg(feature = "native_composed_transport_test_helper")]
fn has_duplicates(fds: &[RawFd]) -> bool {
    (0..fds.len()).any(|left| (left + 1..fds.len()).any(|right| fds[left] == fds[right]))
}

fn payload(run_id: &str) -> Result<Vec<u8>, NativeTransportError> {
    let fields: BTreeMap<&str, Value> = BTreeMap::from([
        ("adapter_id", Value::from("opencode")),
        ("adapter_version", Value::from("1.18.16")),
        ("entrypoint_raw_digest", Value::from("1".repeat(64))),
        (
            "entrypoint_realpath",
            Value::from("/locked/node_modules/opencode/bin/opencode"),
        ),
        ("fixture_manifest_digest", Value::from("2".repeat(64))),
        ("full_locked_dependency_count", Value::from(13)),
        ("full_locked_dependency_digest", Value::from("3".repeat(64))),
        ("installed_platform_dependency_count", Value::from(2)),
        (
            "installed_platform_dependency_digest",
            Value::from("4".repeat(64)),
        ),
        ("npm_executable_realpath", Value::from("/usr/local/bin/npm")),
        ("npm_version", Value::from("11.12.1")),
        ("package_lock_raw_digest", Value::from("5".repeat(64))),
        ("package_name", Value::from("opencode-ai")),
        ("package_version", Value::from("1.18.16")),
        ("run_id", Value::from(run_id)),
        (
            "schema_version",
            Value::from("nomad.actual-launch-provenance.v1"),
        ),
        ("task_spec_digest", Value::from("6".repeat(64))),
    ]);
    serde_json::to_vec(&fields).map_err(|_| NativeTransportError)
}

fn fixed_executable(path: &Path) -> Result<std::path::PathBuf, NativeTransportError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| NativeTransportError)?;
    let exact = std::fs::canonicalize(path).map_err(|_| NativeTransportError)?;
    if exact != path || !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 {
        Err(NativeTransportError)
    } else {
        Ok(exact)
    }
}

fn random_material() -> Result<[[u8; 32]; 4], NativeTransportError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")
        .map_err(|_| NativeTransportError)?;
    if !file
        .metadata()
        .map_err(|_| NativeTransportError)?
        .file_type()
        .is_char_device()
    {
        return Err(NativeTransportError);
    }
    let mut values = [[0_u8; 32]; 4];
    for value in &mut values {
        file.read_exact(value).map_err(|_| NativeTransportError)?;
    }
    if values
        .iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
        || (0..values.len())
            .any(|left| (left + 1..values.len()).any(|right| values[left] == values[right]))
    {
        return Err(NativeTransportError);
    }
    Ok(values)
}

fn pipe_pair() -> Result<(OwnedFd, OwnedFd), NativeTransportError> {
    let mut fds = [-1; 2];
    // SAFETY: pipe initializes both descriptor slots.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(NativeTransportError);
    }
    // SAFETY: successful pipe returns two newly owned descriptors.
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&pair.0, &pair.1] {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
        {
            return Err(NativeTransportError);
        }
    }
    Ok(pair)
}

fn max_fd() -> RawFd {
    // SAFETY: sysconf has no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    RawFd::try_from(value.clamp(64, 65_536)).unwrap_or(65_536)
}

fn prepare_child_fds(inherited: [RawFd; 3], max_fd: RawFd) -> std::io::Result<()> {
    prepare_child_fd_slice(&inherited, max_fd)
}

fn prepare_child_fd_slice(inherited: &[RawFd], max_fd: RawFd) -> std::io::Result<()> {
    for fd in 3..max_fd {
        // SAFETY: fcntl only inspects/sets descriptor flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            continue;
        }
        let wanted = if inherited.contains(&fd) {
            flags & !libc::FD_CLOEXEC
        } else {
            flags | libc::FD_CLOEXEC
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, wanted) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn write_bounded(fd: OwnedFd, bytes: &[u8], failed: &AtomicBool, deadline: Instant) -> bool {
    let mut file = File::from(fd);
    let mut offset = 0;
    while offset < bytes.len() {
        if failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return false;
        }
        match file.write(&bytes[offset..]) {
            Ok(0) => return false,
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
    true
}
fn set_nonblocking(fd: RawFd) -> Result<(), NativeTransportError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        Err(NativeTransportError)
    } else {
        Ok(())
    }
}
fn spawn_bounded_reader<R: Read + Send + 'static>(
    reader: R,
    failed: Arc<AtomicBool>,
    deadline: Instant,
) -> thread::JoinHandle<Option<Vec<u8>>> {
    thread::spawn(move || read_bounded(reader, failed, deadline))
}
fn read_bounded(
    mut reader: impl Read,
    failed: Arc<AtomicBool>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return None;
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Some(out),
            Ok(count) if out.len() + count <= MAX_OUTPUT => out.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            _ => {
                failed.store(true, Ordering::SeqCst);
                return None;
            }
        }
    }
}
fn kill_reap_group(child: &mut Child) -> bool {
    let Ok(pid) = i32::try_from(child.id()) else {
        return false;
    };
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut reaped = false;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => {
                reaped = true;
                break;
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => return false,
        }
    }
    while process_group_exists(child.id()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    reaped && !process_group_exists(child.id())
}
fn process_group_exists(id: u32) -> bool {
    let Ok(pid) = i32::try_from(id) else {
        return true;
    };
    let result = unsafe { libc::kill(-pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}
