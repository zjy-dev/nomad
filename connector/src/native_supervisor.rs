//! Native production authority gate for the Nomad supervisor.
//!
//! N0 deliberately stops before runtime Host-publication verification.  This
//! module owns no command surface and creates no child process, socket, pipe,
//! or temporary directory.

use crate::release_bundle::{embedded_release, HistoricalReleaseEvidence};
use crate::stock_opencode::{current_release_authorization, CurrentReleaseAuthorization};
use std::fmt;
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(all(test, feature = "native_supervisor_test_helper"))]
use {
    sha2::{Digest, Sha256},
    std::fs::{self, OpenOptions},
    std::io::Read,
    std::mem::MaybeUninit,
    std::os::fd::RawFd,
    std::os::unix::fs::OpenOptionsExt,
    std::path::Path,
};

pub const NATIVE_SUPERVISOR_BLOCKED: &str = "BLOCKED_NATIVE_SUPERVISOR_AUTHORITY_UNAVAILABLE";
#[cfg(all(test, feature = "native_supervisor_test_helper"))]
const NATIVE_SUPERVISOR_AUTHORITY_READY: &str = "NATIVE_SUPERVISOR_AUTHORITY_READY";

#[cfg(all(test, feature = "native_supervisor_test_helper"))]
const MAX_HOST_BYTES: u64 = 64 * 1024 * 1024;
const PRODUCTION_ROOT: &str = "/Library/Application Support/Nomad/production";
const PRODUCTION_PROTECTED_REF: &str = "refs/heads/production/nomad-host";
const PRODUCTION_RELEASE_SOURCE: &str = "embedded:NOMADREL";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSupervisorError {
    EmbeddedRelease,
    CurrentApproval,
    NativeHostPublication,
    HostFileBinding,
}

impl fmt::Display for NativeSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(NATIVE_SUPERVISOR_BLOCKED)
    }
}

impl std::error::Error for NativeSupervisorError {}

#[derive(PartialEq, Eq)]
struct HostFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u64,
    links: u64,
    modified_seconds: i64,
    changed_seconds: i64,
}

struct BoundHostFile {
    descriptor: OwnedFd,
    identity: HostFileIdentity,
    raw_digest: [u8; 32],
}

/// The only production authority type.  It intentionally implements neither
/// `Clone` nor `Serialize`, and its fields and constructor remain private.
struct ProductionHostAuthorization {
    release: CurrentReleaseAuthorization,
    host: BoundHostFile,
}

impl ProductionHostAuthorization {
    fn retain_exact_open_host(&self) {
        let _ = (
            &self.release,
            self.host.descriptor.as_raw_fd(),
            &self.host.identity,
            &self.host.raw_digest,
        );
    }
}

/// The public production entry has no arguments: callers cannot supply a
/// Python verdict, serialized authorization, digest, path, ref, or tool.
pub fn native_supervisor_entrypoint() -> Result<(), NativeSupervisorError> {
    let authorization = production_host_authorization()?;
    authorization.retain_exact_open_host();
    drop(authorization);
    Ok(())
}

fn production_host_authorization() -> Result<ProductionHostAuthorization, NativeSupervisorError> {
    let release = embedded_release().map_err(|_| NativeSupervisorError::EmbeddedRelease)?;
    let HistoricalReleaseEvidence::Verified(evidence) = release else {
        return Err(NativeSupervisorError::EmbeddedRelease);
    };
    let release = current_release_authorization(&evidence)
        .map_err(|_| NativeSupervisorError::CurrentApproval)?;
    let host = verify_fixed_native_host_publication(&release)?;
    Ok(ProductionHostAuthorization { release, host })
}

fn verify_fixed_native_host_publication(
    _release: &CurrentReleaseAuthorization,
) -> Result<BoundHostFile, NativeSupervisorError> {
    // These inputs are deliberately fixed in the native binary.  N0 does not
    // yet contain the required native protected-ref/Git, SSHSIG/KRL, and
    // Developer ID verification, so it must not open even the fixed Host.
    let _fixed_inputs = (
        PRODUCTION_ROOT,
        PRODUCTION_PROTECTED_REF,
        PRODUCTION_RELEASE_SOURCE,
    );
    Err(NativeSupervisorError::NativeHostPublication)
}

#[cfg(all(test, feature = "native_supervisor_test_helper"))]
fn fstat_identity(descriptor: RawFd) -> Result<HostFileIdentity, NativeSupervisorError> {
    let mut raw = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `raw` points to valid writable storage and `descriptor` is owned
    // by the caller for the duration of this call.
    if unsafe { libc::fstat(descriptor, raw.as_mut_ptr()) } != 0 {
        return Err(NativeSupervisorError::HostFileBinding);
    }
    // SAFETY: successful fstat initialized the whole libc::stat value.
    let raw = unsafe { raw.assume_init() };
    if raw.st_size <= 0 {
        return Err(NativeSupervisorError::HostFileBinding);
    }
    let size = u64::try_from(raw.st_size).map_err(|_| NativeSupervisorError::HostFileBinding)?;
    Ok(HostFileIdentity {
        device: raw.st_dev as u64,
        inode: raw.st_ino,
        size,
        mode: u64::from(raw.st_mode),
        links: u64::from(raw.st_nlink),
        modified_seconds: raw.st_mtime,
        changed_seconds: raw.st_ctime,
    })
}

#[cfg(all(test, feature = "native_supervisor_test_helper"))]
fn bind_test_host(
    path: &Path,
    expected_digest: [u8; 32],
) -> Result<BoundHostFile, NativeSupervisorError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| NativeSupervisorError::HostFileBinding)?;
    let before = fstat_identity(file.as_raw_fd())?;
    if before.links != 1
        || before.size > MAX_HOST_BYTES
        || before.mode & u64::from(libc::S_IFMT) != u64::from(libc::S_IFREG)
        || before.mode & 0o111 == 0
    {
        return Err(NativeSupervisorError::HostFileBinding);
    }
    let mut raw = Vec::with_capacity(usize::try_from(before.size).unwrap_or(0));
    file.by_ref()
        .take(MAX_HOST_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| NativeSupervisorError::HostFileBinding)?;
    let after = fstat_identity(file.as_raw_fd())?;
    let path_identity = fs::symlink_metadata(path)
        .map_err(|_| NativeSupervisorError::HostFileBinding)
        .and_then(|_| {
            let reopened = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| NativeSupervisorError::HostFileBinding)?;
            fstat_identity(reopened.as_raw_fd())
        })?;
    let actual_digest: [u8; 32] = Sha256::digest(&raw).into();
    if before != after
        || before != path_identity
        || raw.len() as u64 != before.size
        || actual_digest != expected_digest
    {
        return Err(NativeSupervisorError::HostFileBinding);
    }
    Ok(BoundHostFile {
        descriptor: file.into(),
        identity: before,
        raw_digest: actual_digest,
    })
}

/// Isolated test authority.  It cannot be converted to or passed into the
/// argument-free production constructor.
#[cfg(all(test, feature = "native_supervisor_test_helper"))]
struct TestNativeAuthority {
    host: BoundHostFile,
}

#[cfg(all(test, feature = "native_supervisor_test_helper"))]
impl TestNativeAuthority {
    fn bind(path: &Path, expected_digest: [u8; 32]) -> Result<Self, NativeSupervisorError> {
        Ok(Self {
            host: bind_test_host(path, expected_digest)?,
        })
    }

    fn ready(&self) -> Result<&'static str, NativeSupervisorError> {
        if fstat_identity(self.host.descriptor.as_raw_fd())? != self.host.identity {
            return Err(NativeSupervisorError::HostFileBinding);
        }
        let _ = self.host.raw_digest;
        Ok(NATIVE_SUPERVISOR_AUTHORITY_READY)
    }
}

#[cfg(all(test, feature = "native_supervisor_test_helper"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &Path, raw: &[u8]) {
        fs::write(path, raw).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn isolated_test_authority_binds_owned_fd_identity_and_digest() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nomad-host");
        let raw = b"test-only-host-image";
        write_executable(&path, raw);
        let authority = TestNativeAuthority::bind(&path, Sha256::digest(raw).into()).unwrap();
        assert_eq!(
            authority.ready().unwrap(),
            NATIVE_SUPERVISOR_AUTHORITY_READY
        );
    }

    #[test]
    fn altered_host_and_path_replacement_cannot_be_bound() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("nomad-host");
        let expected = Sha256::digest(b"approved-host").into();
        write_executable(&path, b"replaced-host");
        assert!(matches!(
            TestNativeAuthority::bind(&path, expected),
            Err(NativeSupervisorError::HostFileBinding)
        ));

        let target = root.path().join("target-host");
        write_executable(&target, b"approved-host");
        std::os::unix::fs::symlink(&target, &path).unwrap_err();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            TestNativeAuthority::bind(&path, expected),
            Err(NativeSupervisorError::HostFileBinding)
        ));
    }
}
