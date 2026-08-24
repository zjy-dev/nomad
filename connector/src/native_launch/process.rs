//! Test-only composition of an owned native child, loopback health, and Darwin proof.
use super::darwin::{verify_live_executable, VerifiedLiveExecutable};
use super::lifecycle::{LifecycleError, PreparedNativeInstall};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_HEALTH: usize = 4096;

pub(super) struct TestActualLockedLaunch {
    child: Option<Child>,
    live: Option<VerifiedLiveExecutable>,
    prepared: Option<PreparedNativeInstall>,
}

impl TestActualLockedLaunch {
    pub(super) fn pid(&self) -> u32 {
        self.live.as_ref().expect("live proof").pid()
    }
    pub(super) fn executable_path(&self) -> &std::path::Path {
        self.live.as_ref().expect("live proof").canonical_path()
    }
    pub(super) fn executable_digest(&self) -> &[u8; 32] {
        self.live.as_ref().expect("live proof").raw_digest()
    }

    pub(super) fn cleanup(mut self) -> Result<(), LifecycleError> {
        let mut child = self.child.take().ok_or(LifecycleError::Cleanup)?;
        let process_ok = terminate_group(&mut child);
        let live = self.live.take().ok_or(LifecycleError::Cleanup)?;
        let _ = live.executable_fd().as_raw_fd();
        live.retain_kernel_identity();
        drop(live);
        let prepared = self.prepared.take().ok_or(LifecycleError::Cleanup)?;
        if !process_ok {
            prepared.preserve();
            return Err(LifecycleError::Cleanup);
        }
        prepared.cleanup()
    }
}

impl Drop for TestActualLockedLaunch {
    fn drop(&mut self) {
        let process_ok = self.child.as_mut().is_none_or(terminate_group);
        self.child.take();
        self.live.take();
        if let Some(prepared) = self.prepared.take() {
            if process_ok {
                let _ = prepared.cleanup();
            } else {
                prepared.preserve();
            }
        }
    }
}

pub(super) fn launch_test_native(
    mut prepared: PreparedNativeInstall,
    timeout: Duration,
) -> Result<TestActualLockedLaunch, LifecycleError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| LifecycleError::Preflight)?;
    let port = listener
        .local_addr()
        .map_err(|_| LifecycleError::Preflight)?
        .port();
    drop(listener);
    let installed = prepared.take_installed()?;
    let executable = installed.canonical_path().to_path_buf();
    let nonce = random_nonce()?;
    let workspace = prepared.workspace.clone();
    let home = prepared.home.clone();
    let xdg = prepared.xdg.clone();
    let spawned = prepared.consume_credential(|name, value| {
        let mut command = Command::new(&executable);
        command
            .args([
                "serve",
                "--pure",
                "--hostname",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(&workspace)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", xdg.join("config"))
            .env("XDG_DATA_HOME", xdg.join("data"))
            .env("XDG_CACHE_HOME", xdg.join("cache"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("NOMAD_TEST_HEALTH_NONCE", &nonce)
            .env(name, value)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: pre_exec performs only async-signal-safe setpgid.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        command.spawn()
    })?;
    let mut child = match spawned {
        Ok(child) => child,
        Err(_) => {
            if prepared.cleanup().is_err() {
                return Err(LifecycleError::Cleanup);
            }
            return Err(LifecycleError::Npm);
        }
    };
    if !wait_health(&mut child, port, &nonce, timeout) {
        return fail_and_cleanup(child, prepared, LifecycleError::Npm);
    }
    let live =
        match verify_live_executable(&mut child, installed.into_executable(), &prepared.install) {
            Ok(live) => live,
            Err(_) => {
                return fail_and_cleanup(child, prepared, LifecycleError::Npm);
            }
        };
    let rechecked = match prepared.revalidate() {
        Ok(rechecked) => rechecked,
        Err(error) => return fail_and_cleanup(child, prepared, error),
    };
    if rechecked.canonical_path() != live.canonical_path()
        || rechecked.raw_digest() != live.raw_digest()
    {
        return fail_and_cleanup(child, prepared, LifecycleError::Installed);
    }
    Ok(TestActualLockedLaunch {
        child: Some(child),
        live: Some(live),
        prepared: Some(prepared),
    })
}

fn fail_and_cleanup(
    mut child: Child,
    prepared: PreparedNativeInstall,
    error: LifecycleError,
) -> Result<TestActualLockedLaunch, LifecycleError> {
    if !terminate_group(&mut child) {
        prepared.preserve();
        return Err(LifecycleError::Cleanup);
    }
    if prepared.cleanup().is_err() {
        return Err(LifecycleError::Cleanup);
    }
    Err(error)
}

fn wait_health(child: &mut Child, port: u16, nonce: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
            if stream
                .write_all(format!("GET /global/health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Nomad-Health-Nonce: {nonce}\r\nConnection: close\r\n\r\n").as_bytes())
                .is_ok()
            {
                let mut raw = Vec::new();
                if stream
                    .take((MAX_HEALTH + 1) as u64)
                    .read_to_end(&mut raw)
                    .is_ok()
                    && raw.len() <= MAX_HEALTH
                    && raw.starts_with(b"HTTP/1.1 200 ")
                    && raw.windows(format!("X-Nomad-Health-Nonce: {nonce}\r\n").len())
                        .any(|value| value == format!("X-Nomad-Health-Nonce: {nonce}\r\n").as_bytes())
                    && raw.windows(b"\r\n\r\n".len()).any(|v| v == b"\r\n\r\n")
                {
                    return true;
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

fn random_nonce() -> Result<String, LifecycleError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")
        .map_err(|_| LifecycleError::Preflight)?;
    if !file
        .metadata()
        .map_err(|_| LifecycleError::Preflight)?
        .file_type()
        .is_char_device()
    {
        return Err(LifecycleError::Preflight);
    }
    let mut raw = [0_u8; 32];
    file.read_exact(&mut raw)
        .map_err(|_| LifecycleError::Preflight)?;
    if raw.iter().all(|value| *value == 0) {
        return Err(LifecycleError::Preflight);
    }
    Ok(raw.iter().map(|value| format!("{value:02x}")).collect())
}

fn terminate_group(child: &mut Child) -> bool {
    let Ok(pid) = i32::try_from(child.id()) else {
        return false;
    };
    // SAFETY: negative pid targets the child-owned group.
    let _ = unsafe { libc::kill(-pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().ok().flatten().is_none() || group_exists(pid) {
        // SAFETY: negative pid targets the child-owned group.
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() && !group_exists(pid) {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

fn group_exists(pid: i32) -> bool {
    // SAFETY: signal zero probes only the child-owned group.
    let result = unsafe { libc::kill(-pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_launch::lifecycle::prepare_isolated_install;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn helper_source() -> &'static str {
        r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 7 || strcmp(argv[1],"serve") || strcmp(argv[2],"--pure") || strcmp(argv[3],"--hostname") || strcmp(argv[4],"127.0.0.1") || strcmp(argv[5],"--port")) return 31;
  if (!getenv("OPENAI_API_KEY") || getenv("PATH") || !getenv("NOMAD_TEST_HEALTH_NONCE")) return 32;
  int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons(atoi(argv[6]));
  if (bind(s,(struct sockaddr*)&a,sizeof(a)) || listen(s,2)) return 33;
  for (;;) { int c=accept(s,0,0); if(c<0) return 34; char b[1024]={0}; read(c,b,sizeof(b)-1); if(!strstr(b,getenv("NOMAD_TEST_HEALTH_NONCE"))) { close(c); continue; } char r[512]; int n=snprintf(r,sizeof(r),"HTTP/1.1 200 OK\r\nX-Nomad-Health-Nonce: %s\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",getenv("NOMAD_TEST_HEALTH_NONCE")); write(c,r,n); close(c); }
}
"#
    }

    fn npm_stub(root: &std::path::Path, native: &std::path::Path) -> std::path::PathBuf {
        let path = root.join("npm-stub");
        let body = format!(
            r#"#!/bin/sh
/bin/mkdir -p node_modules/opencode-ai node_modules/opencode-darwin-arm64 node_modules/.bin
/bin/echo '{{"name":"opencode-ai","version":"1.18.16"}}' > node_modules/opencode-ai/package.json
/bin/echo '{{"name":"opencode-darwin-arm64","version":"1.18.16"}}' > node_modules/opencode-darwin-arm64/package.json
/bin/cp '{}' node_modules/opencode-darwin-arm64/opencode
/bin/chmod 700 node_modules/opencode-darwin-arm64/opencode
/bin/ln -s ../opencode-darwin-arm64/opencode node_modules/.bin/opencode
"#,
            native.display()
        );
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::canonicalize(path).unwrap()
    }

    #[test]
    fn real_native_child_health_vnode_and_cleanup() {
        let parent = tempfile::tempdir().unwrap();
        let parent_path = fs::canonicalize(parent.path()).unwrap();
        let source = parent_path.join("helper.c");
        let native = parent_path.join("helper");
        fs::write(&source, helper_source()).unwrap();
        assert!(Command::new("/usr/bin/clang")
            .args([
                source.as_os_str(),
                "-O2".as_ref(),
                "-o".as_ref(),
                native.as_os_str()
            ])
            .status()
            .unwrap()
            .success());
        let npm = npm_stub(&parent_path, &native);
        let prepared = prepare_isolated_install(
            &parent_path,
            "OPENAI_API_KEY",
            "canary",
            &npm,
            Duration::from_secs(3),
        )
        .unwrap();
        let root = prepared.root_path().to_path_buf();
        let launch = launch_test_native(prepared, Duration::from_secs(3)).unwrap();
        assert!(launch.pid() > 0);
        assert!(launch.executable_path().ends_with("opencode"));
        assert_ne!(launch.executable_digest(), &[0; 32]);
        launch.cleanup().unwrap();
        assert!(!root.exists());
    }
}
