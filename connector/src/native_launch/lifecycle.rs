//! Test-only N1 installation-stage lifecycle mechanics.
use super::inputs::{verify_stock_inputs, MaterializationRoot, VerifiedStockInputs};
use super::installed::{verify_installed_tree, VerifiedInstalledTree};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CREDENTIAL: usize = 16 * 1024;
const MAX_OUTPUT: usize = 4096;
const ALLOWED: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LifecycleError {
    Preflight,
    Npm,
    Materialize,
    Installed,
    Cleanup,
}

struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirId(u64, u64);

pub(super) struct PreparedNativeInstall {
    root: Option<tempfile::TempDir>,
    root_id: DirId,
    pub(super) home: PathBuf,
    pub(super) xdg: PathBuf,
    pub(super) workspace: PathBuf,
    pub(super) install: PathBuf,
    pub(super) inputs: VerifiedStockInputs,
    installed: Option<VerifiedInstalledTree>,
    credential_name: &'static str,
    credential: Secret,
}

impl PreparedNativeInstall {
    pub(super) fn consume_credential<R>(
        &mut self,
        use_once: impl FnOnce(&str, &str) -> R,
    ) -> Result<R, LifecycleError> {
        if self.credential.0.is_empty() {
            return Err(LifecycleError::Preflight);
        }
        let bytes = Secret(std::mem::take(&mut self.credential.0));
        let value = std::str::from_utf8(&bytes.0).map_err(|_| LifecycleError::Preflight)?;
        let result = use_once(self.credential_name, value);
        drop(bytes);
        Ok(result)
    }
    pub(super) fn root_path(&self) -> &Path {
        self.root.as_ref().expect("root").path()
    }
    pub(super) fn take_installed(&mut self) -> Result<VerifiedInstalledTree, LifecycleError> {
        self.installed.take().ok_or(LifecycleError::Installed)
    }
    pub(super) fn revalidate(&self) -> Result<VerifiedInstalledTree, LifecycleError> {
        verify_stock_inputs().map_err(|_| LifecycleError::Materialize)?;
        verify_materialized(&self.inputs, &self.install, &self.workspace)?;
        verify_installed_tree(&self.install, &self.inputs.facts)
            .map_err(|_| LifecycleError::Installed)
    }
    pub(super) fn cleanup(mut self) -> Result<(), LifecycleError> {
        let root = self.root.take().ok_or(LifecycleError::Cleanup)?;
        let path = root.path().to_path_buf();
        let actual = match dir_id(&path) {
            Ok(actual) => actual,
            Err(error) => {
                let _ = root.keep();
                return Err(error);
            }
        };
        if actual != self.root_id {
            let _ = root.keep();
            return Err(LifecycleError::Cleanup);
        }
        root.close().map_err(|_| LifecycleError::Cleanup)?;
        path_is_absent(&path)
    }

    pub(super) fn preserve(mut self) {
        if let Some(root) = self.root.take() {
            let _ = root.keep();
        }
    }
}

pub(super) fn prepare_isolated_install(
    parent: &Path,
    credential_name: &str,
    credential_value: &str,
    npm: &Path,
    timeout: Duration,
) -> Result<PreparedNativeInstall, LifecycleError> {
    let credential_name = preflight_credential(credential_name, credential_value)?;
    let npm = exact_executable(npm)?;
    if !(Duration::from_millis(100)..=Duration::from_secs(180)).contains(&timeout) {
        return Err(LifecycleError::Preflight);
    }
    let parent = exact_dir(parent)?;
    let inputs = verify_stock_inputs().map_err(|_| LifecycleError::Materialize)?;
    let credential = Secret(credential_value.as_bytes().to_vec());
    let root = tempfile::Builder::new()
        .prefix("nomad-native-launch-")
        .tempdir_in(parent)
        .map_err(|_| LifecycleError::Materialize)?;
    let root_id = dir_id(root.path())?;
    let home = root.path().join("home");
    let xdg = root.path().join("xdg");
    let workspace = root.path().join("workspace");
    let install = root.path().join("install");
    let setup = (|| {
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| LifecycleError::Materialize)?;
        for path in [&home, &xdg, &workspace, &install] {
            private_dir(path)?;
        }
        materialize(&inputs, &install, &workspace)?;
        let env = BTreeMap::from([
            ("HOME", home.as_os_str()),
            ("XDG_CONFIG_HOME", xdg.as_os_str()),
            ("XDG_DATA_HOME", xdg.as_os_str()),
            ("XDG_CACHE_HOME", xdg.as_os_str()),
            ("LANG", std::ffi::OsStr::new("C")),
            ("LC_ALL", std::ffi::OsStr::new("C")),
            ("npm_config_loglevel", std::ffi::OsStr::new("error")),
            (
                "npm_config_registry",
                std::ffi::OsStr::new("https://registry.npmjs.org"),
            ),
        ]);
        run_npm(&npm, &install, &env, timeout)?;
        verify_materialized(&inputs, &install, &workspace)?;
        verify_installed_tree(&install, &inputs.facts).map_err(|_| LifecycleError::Installed)
    })();
    let installed = match setup {
        Ok(installed) => installed,
        Err(error) => {
            cleanup_root(root, root_id)?;
            return Err(error);
        }
    };
    Ok(PreparedNativeInstall {
        root: Some(root),
        root_id,
        home,
        xdg,
        workspace,
        install,
        inputs,
        installed: Some(installed),
        credential_name,
        credential,
    })
}

fn preflight_credential(name: &str, value: &str) -> Result<&'static str, LifecycleError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL || value.contains('\0') {
        return Err(LifecycleError::Preflight);
    }
    ALLOWED
        .iter()
        .copied()
        .find(|item| *item == name)
        .ok_or(LifecycleError::Preflight)
}

fn exact_executable(path: &Path) -> Result<PathBuf, LifecycleError> {
    let meta = fs::symlink_metadata(path).map_err(|_| LifecycleError::Preflight)?;
    let exact = fs::canonicalize(path).map_err(|_| LifecycleError::Preflight)?;
    if exact != path
        || !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || meta.mode() & 0o111 == 0
    {
        Err(LifecycleError::Preflight)
    } else {
        Ok(exact)
    }
}

fn private_dir(path: &Path) -> Result<(), LifecycleError> {
    fs::create_dir(path).map_err(|_| LifecycleError::Materialize)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| LifecycleError::Materialize)
}

fn materialize(
    inputs: &VerifiedStockInputs,
    install: &Path,
    workspace: &Path,
) -> Result<(), LifecycleError> {
    for item in &inputs.materialization.files {
        let root = match item.root {
            MaterializationRoot::Install => install,
            MaterializationRoot::Workspace => workspace,
        };
        let target = root.join(item.relative_name);
        let parent = target.parent().ok_or(LifecycleError::Materialize)?;
        private_parents(root, parent)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&target)
            .map_err(|_| LifecycleError::Materialize)?;
        file.write_all(item.bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| LifecycleError::Materialize)?;
        let meta = file.metadata().map_err(|_| LifecycleError::Materialize)?;
        if meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
            return Err(LifecycleError::Materialize);
        }
    }
    Ok(())
}

fn verify_materialized(
    inputs: &VerifiedStockInputs,
    install: &Path,
    workspace: &Path,
) -> Result<(), LifecycleError> {
    for item in &inputs.materialization.files {
        let root = match item.root {
            MaterializationRoot::Install => install,
            MaterializationRoot::Workspace => workspace,
        };
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root.join(item.relative_name))
            .map_err(|_| LifecycleError::Materialize)?;
        let before = file.metadata().map_err(|_| LifecycleError::Materialize)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .map_err(|_| LifecycleError::Materialize)?;
        let after = file.metadata().map_err(|_| LifecycleError::Materialize)?;
        if raw != item.bytes
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.nlink() != 1
            || before.mode() & 0o777 != 0o600
        {
            return Err(LifecycleError::Materialize);
        }
    }
    Ok(())
}

fn private_parents(root: &Path, parent: &Path) -> Result<(), LifecycleError> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| LifecycleError::Materialize)?;
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part);
        if !current.exists() {
            private_dir(&current)?;
        }
    }
    Ok(())
}

fn run_npm(
    npm: &Path,
    install: &Path,
    env: &BTreeMap<&str, &std::ffi::OsStr>,
    timeout: Duration,
) -> Result<(), LifecycleError> {
    let mut command = Command::new(npm);
    command
        .args(["ci", "--ignore-scripts=false", "--no-audit", "--no-fund"])
        .current_dir(install)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: pre_exec performs only the async-signal-safe setpgid call.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().map_err(|_| LifecycleError::Npm)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    if stdout.is_none() || stderr.is_none() {
        let cleanup_ok = kill_and_reap_group(&mut child);
        drop(stdout);
        drop(stderr);
        return Err(if cleanup_ok {
            LifecycleError::Npm
        } else {
            LifecycleError::Cleanup
        });
    }
    let stdout = stdout.expect("checked above");
    let stderr = stderr.expect("checked above");
    if set_nonblocking(stdout.as_raw_fd()).is_err() || set_nonblocking(stderr.as_raw_fd()).is_err()
    {
        let cleanup_ok = kill_and_reap_group(&mut child);
        drop(stdout);
        drop(stderr);
        return Err(if cleanup_ok {
            LifecycleError::Npm
        } else {
            LifecycleError::Cleanup
        });
    }
    let failed = Arc::new(AtomicBool::new(false));
    let stdout_failed = Arc::clone(&failed);
    let stderr_failed = Arc::clone(&failed);
    let deadline = Instant::now() + timeout;
    let readers = [
        thread::spawn(move || read_bounded(stdout, stdout_failed, deadline)),
        thread::spawn(move || read_bounded(stderr, stderr_failed, deadline)),
    ];
    let mut cleanup_ok = true;
    let status = loop {
        if failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
            failed.store(true, Ordering::SeqCst);
            cleanup_ok = kill_and_reap_group(&mut child);
            break None;
        }
        match child.try_wait() {
            Ok(Some(value)) => break Some(value),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                failed.store(true, Ordering::SeqCst);
                cleanup_ok = kill_and_reap_group(&mut child);
                break None;
            }
        }
    };
    let descendants_remain = status.is_some() && process_group_exists(child.id());
    if descendants_remain {
        failed.store(true, Ordering::SeqCst);
        cleanup_ok = kill_and_reap_group(&mut child) && cleanup_ok;
    }
    let joined = readers
        .into_iter()
        .all(|thread| thread.join().is_ok_and(|value| value));
    if !cleanup_ok {
        Err(LifecycleError::Cleanup)
    } else if status.is_some_and(|value| value.success())
        && !descendants_remain
        && joined
        && !failed.load(Ordering::SeqCst)
    {
        Ok(())
    } else {
        Err(LifecycleError::Npm)
    }
}

fn kill_and_reap_group(child: &mut std::process::Child) -> bool {
    let pid = match i32::try_from(child.id()) {
        Ok(pid) if pid > 0 => pid,
        _ => return false,
    };
    // SAFETY: negative PID targets the dedicated npm process group only.
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => return false,
        }
    }
    while process_group_exists(child.id()) {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
    true
}

fn process_group_exists(id: u32) -> bool {
    let Ok(pid) = i32::try_from(id) else {
        return true;
    };
    // SAFETY: signal 0 probes only the dedicated child process group.
    let result = unsafe { libc::kill(-pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn set_nonblocking(fd: i32) -> Result<(), LifecycleError> {
    // SAFETY: fcntl operates on a live owned pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        Err(LifecycleError::Cleanup)
    } else {
        Ok(())
    }
}

fn read_bounded(mut stream: impl Read, failed: Arc<AtomicBool>, deadline: Instant) -> bool {
    let mut total = 0;
    let mut buffer = [0_u8; 1024];
    loop {
        if failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return false;
        }
        match stream.read(&mut buffer) {
            Ok(0) => return !failed.load(Ordering::SeqCst),
            Ok(count) => {
                total += count;
                if total > MAX_OUTPUT {
                    failed.store(true, Ordering::SeqCst);
                    return false;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                failed.store(true, Ordering::SeqCst);
                return false;
            }
        }
    }
}

fn exact_dir(path: &Path) -> Result<&Path, LifecycleError> {
    let meta = fs::symlink_metadata(path).map_err(|_| LifecycleError::Preflight)?;
    if fs::canonicalize(path).map_err(|_| LifecycleError::Preflight)? != path
        || !meta.is_dir()
        || meta.file_type().is_symlink()
    {
        Err(LifecycleError::Preflight)
    } else {
        Ok(path)
    }
}

fn dir_id(path: &Path) -> Result<DirId, LifecycleError> {
    let meta = fs::symlink_metadata(path).map_err(|_| LifecycleError::Cleanup)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        Err(LifecycleError::Cleanup)
    } else {
        Ok(DirId(meta.dev(), meta.ino()))
    }
}

fn cleanup_root(root: tempfile::TempDir, expected: DirId) -> Result<(), LifecycleError> {
    let path = root.path().to_path_buf();
    let actual = match dir_id(&path) {
        Ok(actual) => actual,
        Err(error) => {
            let _ = root.keep();
            return Err(error);
        }
    };
    if actual != expected {
        let _ = root.keep();
        return Err(LifecycleError::Cleanup);
    }
    root.close().map_err(|_| LifecycleError::Cleanup)?;
    path_is_absent(&path)
}

fn path_is_absent(path: &Path) -> Result<(), LifecycleError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(LifecycleError::Cleanup),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stub(root: &Path, behavior: &str) -> PathBuf {
        let path = root.join("npm-stub");
        let script = "#!/bin/sh\n[ \"$#\" -eq 4 ] || exit 41\n[ \"$1 $2 $3 $4\" = \"ci --ignore-scripts=false --no-audit --no-fund\" ] || exit 42\n[ -z \"${OPENAI_API_KEY+x}\" ] || exit 43\n"
            .to_owned()
            + behavior
            + "\n";
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::canonicalize(path).unwrap()
    }
    const INSTALL: &str = r#"
/bin/mkdir -p node_modules/opencode-ai node_modules/opencode-darwin-arm64 node_modules/.bin
/bin/echo '{"name":"opencode-ai","version":"1.18.16"}' > node_modules/opencode-ai/package.json
/bin/echo '{"name":"opencode-darwin-arm64","version":"1.18.16"}' > node_modules/opencode-darwin-arm64/package.json
/bin/cp /bin/sleep node_modules/opencode-darwin-arm64/opencode
/bin/chmod 700 node_modules/opencode-darwin-arm64/opencode
/bin/ln -s ../opencode-darwin-arm64/opencode node_modules/.bin/opencode
"#;
    #[test]
    fn preflight_is_resource_free() {
        let parent = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(parent.path()).unwrap();
        let npm = stub(&parent, INSTALL);
        let before = fs::read_dir(&parent).unwrap().count();
        assert!(
            prepare_isolated_install(&parent, "NOPE", "x", &npm, Duration::from_secs(2)).is_err()
        );
        assert_eq!(fs::read_dir(&parent).unwrap().count(), before);
    }
    #[test]
    fn exact_install_and_cleanup() {
        let parent = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(parent.path()).unwrap();
        let npm = stub(&parent, INSTALL);
        let prepared = prepare_isolated_install(
            &parent,
            "OPENAI_API_KEY",
            "canary",
            &npm,
            Duration::from_secs(3),
        )
        .unwrap();
        let mut prepared = prepared;
        let observed = prepared
            .consume_credential(|name, value| (name.to_owned(), value.to_owned()))
            .unwrap();
        assert_eq!(observed, ("OPENAI_API_KEY".into(), "canary".into()));
        assert!(prepared.consume_credential(|_, _| ()).is_err());
        assert_eq!(
            fs::metadata(prepared.root_path()).unwrap().mode() & 0o777,
            0o700
        );
        for path in [
            &prepared.home,
            &prepared.xdg,
            &prepared.workspace,
            &prepared.install,
        ] {
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o700);
        }
        assert_eq!(prepared.installed.as_ref().unwrap().dependency_count(), 2);
        assert_eq!(prepared.inputs.facts.darwin_arm64_dependency_count, 2);
        let root = prepared.root_path().to_path_buf();
        prepared.cleanup().unwrap();
        assert!(!root.exists());
    }
    #[test]
    fn overflow_and_timeout_cleanup() {
        for behavior in [
            "/usr/bin/yes x | /usr/bin/head -c 8192",
            "/bin/sleep 30",
            "/bin/sleep 30 & exit 0",
        ] {
            let parent = tempfile::tempdir().unwrap();
            let parent = fs::canonicalize(parent.path()).unwrap();
            let npm = stub(&parent, behavior);
            let before = fs::read_dir(&parent).unwrap().count();
            assert!(prepare_isolated_install(
                &parent,
                "OPENAI_API_KEY",
                "canary",
                &npm,
                Duration::from_millis(200)
            )
            .is_err());
            assert_eq!(fs::read_dir(&parent).unwrap().count(), before);
        }
    }

    #[test]
    fn dangling_symlink_is_not_absent() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("dangling");
        std::os::unix::fs::symlink(root.path().join("missing"), &link).unwrap();
        assert_eq!(path_is_absent(&link), Err(LifecycleError::Cleanup));
    }
}
