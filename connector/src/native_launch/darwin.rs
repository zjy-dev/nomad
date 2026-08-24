//! Darwin-arm64 proof that an owned child is executing an exact pre-opened vnode.
//!
//! The proof stays private to `native_launch`: callers cannot deserialize or
//! construct it, and the test seam can produce only intermediate observations.

use sha2::{Digest, Sha256};
use std::fmt;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Child;

const BLOCKED: &str = "BLOCKED_DARWIN_LIVE_EXECUTABLE_UNVERIFIED";
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REGIONS: usize = 4096;
const VM_PROT_EXECUTE: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LiveExecutableError;

impl fmt::Display for LiveExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(BLOCKED)
    }
}

impl std::error::Error for LiveExecutableError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    ppid: u32,
    start_sec: u64,
    start_usec: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VnodeIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_sec: i64,
    modified_nsec: i64,
    changed_sec: i64,
    changed_nsec: i64,
    generation: u32,
    mode: u32,
    links: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Region {
    address: u64,
    size: u64,
    protection: u32,
    file_offset: u64,
    vnode: VnodeIdentity,
}

/// Non-cloneable authority retained by the future native launcher.
///
/// There is deliberately no constructor other than `verify_live_executable`.
pub(super) struct VerifiedLiveExecutable {
    descriptor: OwnedFd,
    process: ProcessIdentity,
    vnode: VnodeIdentity,
    canonical_path: PathBuf,
    raw_digest: [u8; 32],
}

impl VerifiedLiveExecutable {
    pub(super) fn pid(&self) -> u32 {
        self.process.pid
    }

    pub(super) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub(super) fn raw_digest(&self) -> &[u8; 32] {
        &self.raw_digest
    }

    pub(super) fn executable_fd(&self) -> &OwnedFd {
        &self.descriptor
    }

    pub(super) fn retain_kernel_identity(&self) {
        let _ = self.vnode;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn verify_live_executable(
    child: &mut Child,
    executable: OwnedFd,
    install_root: &Path,
) -> Result<VerifiedLiveExecutable, LiveExecutableError> {
    platform::verify(child, executable, install_root)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub(super) fn verify_live_executable(
    _child: &mut Child,
    _executable: OwnedFd,
    _install_root: &Path,
) -> Result<VerifiedLiveExecutable, LiveExecutableError> {
    Err(LiveExecutableError)
}

fn validate_observations(
    expected_pid: u32,
    expected_ppid: u32,
    target: VnodeIdentity,
    processes: [ProcessIdentity; 3],
    first: &[Region],
    second: &[Region],
) -> Result<ProcessIdentity, LiveExecutableError> {
    let process = processes[0];
    if process.pid != expected_pid
        || process.ppid != expected_ppid
        || process.start_sec == 0
        || process.start_usec >= 1_000_000
        || processes.iter().any(|candidate| *candidate != process)
        || first.is_empty()
        || first != second
        || first.iter().any(|region| region.vnode != target)
        || !first
            .iter()
            .any(|region| region.protection & VM_PROT_EXECUTE != 0)
    {
        return Err(LiveExecutableError);
    }
    Ok(process)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod platform {
    use super::*;
    use std::ffi::CStr;
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDREGIONPATHINFO: i32 = 8;
    const PROC_FLAG_INEXIT: u32 = 4;
    const SRUN: u32 = 2;
    const SSLEEP: u32 = 3;
    const MAX_PATH_LEN: usize = 1024;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
        comm: [i8; 16],
        name: [i8; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        tdev: u32,
        tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcRegionInfo {
        protection: u32,
        max_protection: u32,
        inheritance: u32,
        flags: u32,
        file_offset: u64,
        behavior: u32,
        user_wired: u32,
        user_tag: u32,
        pages_resident: u32,
        pages_shared: u32,
        pages_swapped: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u32,
        share_mode: u32,
        private_pages: u32,
        shared_pages: u32,
        object_id: u32,
        depth: u32,
        address: u64,
        size: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VinfoStat {
        device: u32,
        mode: u16,
        nlink: u16,
        inode: u64,
        uid: u32,
        gid: u32,
        atime: i64,
        atime_nsec: i64,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
        birthtime: i64,
        birthtime_nsec: i64,
        size: i64,
        blocks: i64,
        block_size: i32,
        flags: u32,
        generation: u32,
        rdev: u32,
        spare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Fsid {
        value: [i32; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VnodeInfo {
        stat: VinfoStat,
        vnode_type: i32,
        padding: i32,
        fsid: Fsid,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VnodeInfoPath {
        vnode: VnodeInfo,
        path: [i8; MAX_PATH_LEN],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcRegionWithPathInfo {
        region: ProcRegionInfo,
        vnode_path: VnodeInfoPath,
    }

    #[link(name = "proc")]
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffer_size: i32,
        ) -> i32;
    }

    pub(super) fn verify(
        child: &mut Child,
        executable: OwnedFd,
        install_root: &Path,
    ) -> Result<VerifiedLiveExecutable, LiveExecutableError> {
        assert_compiled_abi()?;
        require_live(child)?;
        let descriptor = executable.as_raw_fd();
        require_fd_flags(descriptor)?;
        let before = fstat_identity(descriptor)?;
        require_executable_file(before)?;
        let canonical_path = fd_canonical_path(descriptor, install_root)?;
        let before_digest = digest_fd(descriptor, before.size)?;
        let expected_pid = child.id();
        let expected_ppid = std::process::id();

        let first_process = process_identity(child, expected_ppid)?;
        let first = mapped_regions(child, before)?;
        let middle_process = process_identity(child, expected_ppid)?;
        let second = mapped_regions(child, before)?;
        let final_process = process_identity(child, expected_ppid)?;
        let process = validate_observations(
            expected_pid,
            expected_ppid,
            before,
            [first_process, middle_process, final_process],
            &first,
            &second,
        )?;

        require_live(child)?;
        let after = fstat_identity(descriptor)?;
        let path_after = lstat_identity(&canonical_path)?;
        let after_digest = digest_fd(descriptor, after.size)?;
        let last_process = process_identity(child, expected_ppid)?;
        if before != after
            || before != path_after
            || before_digest != after_digest
            || process != last_process
        {
            return Err(LiveExecutableError);
        }

        Ok(VerifiedLiveExecutable {
            descriptor: executable,
            process,
            vnode: before,
            canonical_path,
            raw_digest: before_digest,
        })
    }

    fn assert_compiled_abi() -> Result<(), LiveExecutableError> {
        if size_of::<ProcBsdInfo>() != 136
            || size_of::<ProcRegionInfo>() != 96
            || size_of::<VinfoStat>() != 136
            || size_of::<ProcRegionWithPathInfo>() != 1272
        {
            return Err(LiveExecutableError);
        }
        Ok(())
    }

    fn require_live(child: &mut Child) -> Result<(), LiveExecutableError> {
        if child.id() == 0 || child.try_wait().map_err(|_| LiveExecutableError)?.is_some() {
            return Err(LiveExecutableError);
        }
        Ok(())
    }

    fn require_fd_flags(fd: RawFd) -> Result<(), LiveExecutableError> {
        let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let descriptor = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if status < 0
            || descriptor < 0
            || status & libc::O_ACCMODE != libc::O_RDONLY
            || descriptor & libc::FD_CLOEXEC == 0
        {
            return Err(LiveExecutableError);
        }
        Ok(())
    }

    fn require_executable_file(vnode: VnodeIdentity) -> Result<(), LiveExecutableError> {
        if vnode.size == 0
            || vnode.size > MAX_EXECUTABLE_BYTES
            || vnode.links != 1
            || vnode.mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
            || vnode.mode & 0o111 == 0
        {
            return Err(LiveExecutableError);
        }
        Ok(())
    }

    fn fd_canonical_path(fd: RawFd, install_root: &Path) -> Result<PathBuf, LiveExecutableError> {
        let mut raw = [0_i8; MAX_PATH_LEN];
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, raw.as_mut_ptr()) } < 0 {
            return Err(LiveExecutableError);
        }
        let bytes = unsafe { CStr::from_ptr(raw.as_ptr()) }.to_bytes();
        if bytes.is_empty() {
            return Err(LiveExecutableError);
        }
        let path = PathBuf::from(std::ffi::OsStr::from_bytes(bytes));
        let canonical_path = std::fs::canonicalize(&path).map_err(|_| LiveExecutableError)?;
        let canonical_root =
            std::fs::canonicalize(install_root).map_err(|_| LiveExecutableError)?;
        let node_modules = std::fs::canonicalize(canonical_root.join("node_modules"))
            .map_err(|_| LiveExecutableError)?;
        if install_root != canonical_root
            || path != canonical_path
            || !node_modules.starts_with(&canonical_root)
            || canonical_path == node_modules
            || !canonical_path.starts_with(&node_modules)
        {
            return Err(LiveExecutableError);
        }
        Ok(canonical_path)
    }

    fn fstat_identity(fd: RawFd) -> Result<VnodeIdentity, LiveExecutableError> {
        let mut raw = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, raw.as_mut_ptr()) } != 0 {
            return Err(LiveExecutableError);
        }
        stat_identity(unsafe { raw.assume_init() })
    }

    fn lstat_identity(path: &Path) -> Result<VnodeIdentity, LiveExecutableError> {
        let path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| LiveExecutableError)?;
        let mut raw = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::lstat(path.as_ptr(), raw.as_mut_ptr()) } != 0 {
            return Err(LiveExecutableError);
        }
        stat_identity(unsafe { raw.assume_init() })
    }

    fn stat_identity(raw: libc::stat) -> Result<VnodeIdentity, LiveExecutableError> {
        Ok(VnodeIdentity {
            device: raw.st_dev as u64,
            inode: raw.st_ino,
            size: u64::try_from(raw.st_size).map_err(|_| LiveExecutableError)?,
            modified_sec: raw.st_mtime,
            modified_nsec: raw.st_mtime_nsec,
            changed_sec: raw.st_ctime,
            changed_nsec: raw.st_ctime_nsec,
            generation: raw.st_gen,
            mode: u32::from(raw.st_mode),
            links: u64::from(raw.st_nlink),
        })
    }

    fn digest_fd(fd: RawFd, size: u64) -> Result<[u8; 32], LiveExecutableError> {
        if size == 0 || size > MAX_EXECUTABLE_BYTES {
            return Err(LiveExecutableError);
        }
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut offset = 0_u64;
        while offset < size {
            let remaining = usize::try_from((size - offset).min(buffer.len() as u64))
                .map_err(|_| LiveExecutableError)?;
            let read = unsafe {
                libc::pread(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    remaining,
                    i64::try_from(offset).map_err(|_| LiveExecutableError)?,
                )
            };
            if read <= 0 {
                return Err(LiveExecutableError);
            }
            let read = usize::try_from(read).map_err(|_| LiveExecutableError)?;
            digest.update(&buffer[..read]);
            offset = offset.checked_add(read as u64).ok_or(LiveExecutableError)?;
        }
        Ok(digest.finalize().into())
    }

    fn process_identity(
        child: &mut Child,
        expected_ppid: u32,
    ) -> Result<ProcessIdentity, LiveExecutableError> {
        require_live(child)?;
        let pid = child.id();
        let mut value = MaybeUninit::<ProcBsdInfo>::zeroed();
        clear_errno();
        let result = unsafe {
            proc_pidinfo(
                i32::try_from(pid).map_err(|_| LiveExecutableError)?,
                PROC_PIDTBSDINFO,
                0,
                value.as_mut_ptr().cast(),
                size_of::<ProcBsdInfo>() as i32,
            )
        };
        if result != size_of::<ProcBsdInfo>() as i32 || errno() != 0 {
            return Err(LiveExecutableError);
        }
        let value = unsafe { value.assume_init() };
        if value.pid != pid
            || value.ppid != expected_ppid
            || !matches!(value.status, SRUN | SSLEEP)
            || value.flags & PROC_FLAG_INEXIT != 0
            || value.start_sec == 0
            || value.start_usec >= 1_000_000
        {
            return Err(LiveExecutableError);
        }
        Ok(ProcessIdentity {
            pid: value.pid,
            ppid: value.ppid,
            start_sec: value.start_sec,
            start_usec: value.start_usec,
        })
    }

    fn mapped_regions(
        child: &mut Child,
        target: VnodeIdentity,
    ) -> Result<Vec<Region>, LiveExecutableError> {
        require_live(child)?;
        let pid = i32::try_from(child.id()).map_err(|_| LiveExecutableError)?;
        let mut address = 0_u64;
        let mut matches = Vec::new();
        for _ in 0..MAX_REGIONS {
            let mut value = MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
            clear_errno();
            let result = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDREGIONPATHINFO,
                    address,
                    value.as_mut_ptr().cast(),
                    size_of::<ProcRegionWithPathInfo>() as i32,
                )
            };
            let error = errno();
            if result == 0 && matches!(error, 0 | libc::EINVAL) {
                matches.sort_unstable();
                return Ok(matches);
            }
            if result != size_of::<ProcRegionWithPathInfo>() as i32 || error != 0 {
                return Err(LiveExecutableError);
            }
            let value = unsafe { value.assume_init() };
            if value.region.size == 0 {
                return Err(LiveExecutableError);
            }
            let next = value
                .region
                .address
                .checked_add(value.region.size)
                .ok_or(LiveExecutableError)?;
            if next <= address {
                return Err(LiveExecutableError);
            }
            let vnode = vnode_identity(value.vnode_path.vnode.stat)?;
            if (vnode.device, vnode.inode) == (target.device, target.inode) {
                matches.push(Region {
                    address: value.region.address,
                    size: value.region.size,
                    protection: value.region.protection,
                    file_offset: value.region.file_offset,
                    vnode,
                });
            }
            address = next;
        }
        Err(LiveExecutableError)
    }

    fn vnode_identity(raw: VinfoStat) -> Result<VnodeIdentity, LiveExecutableError> {
        Ok(VnodeIdentity {
            device: u64::from(raw.device),
            inode: raw.inode,
            size: u64::try_from(raw.size).map_err(|_| LiveExecutableError)?,
            modified_sec: raw.mtime,
            modified_nsec: raw.mtime_nsec,
            changed_sec: raw.ctime,
            changed_nsec: raw.ctime_nsec,
            generation: raw.generation,
            mode: u32::from(raw.mode),
            links: u64::from(raw.nlink),
        })
    }

    fn clear_errno() {
        unsafe { *libc::__error() = 0 };
    }

    fn errno() -> i32 {
        unsafe { *libc::__error() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vnode(inode: u64) -> VnodeIdentity {
        VnodeIdentity {
            device: 1,
            inode,
            size: 64,
            modified_sec: 2,
            modified_nsec: 3,
            changed_sec: 4,
            changed_nsec: 5,
            generation: 6,
            mode: u32::from(libc::S_IFREG) | 0o755,
            links: 1,
        }
    }

    fn process() -> ProcessIdentity {
        ProcessIdentity {
            pid: 10,
            ppid: 9,
            start_sec: 8,
            start_usec: 7,
        }
    }

    fn region(target: VnodeIdentity, protection: u32) -> Region {
        Region {
            address: 0x1000,
            size: 0x1000,
            protection,
            file_offset: 0x4000,
            vnode: target,
        }
    }

    #[test]
    fn stable_identity_and_executable_vnode_are_required() {
        let target = vnode(11);
        let regions = vec![region(target, VM_PROT_EXECUTE)];
        assert_eq!(
            validate_observations(10, 9, target, [process(); 3], &regions, &regions),
            Ok(process())
        );

        let mut wrong = process();
        wrong.pid += 1;
        assert!(validate_observations(10, 9, target, [wrong; 3], &regions, &regions).is_err());
        wrong = process();
        wrong.ppid += 1;
        assert!(validate_observations(10, 9, target, [wrong; 3], &regions, &regions).is_err());
        wrong = process();
        wrong.start_sec = 0;
        assert!(validate_observations(10, 9, target, [wrong; 3], &regions, &regions).is_err());
    }

    #[test]
    fn unstable_noexec_and_multiple_vnode_facts_are_rejected() {
        let target = vnode(11);
        let executable = vec![region(target, VM_PROT_EXECUTE)];
        let noexec = vec![region(target, 1)];
        assert!(validate_observations(10, 9, target, [process(); 3], &noexec, &noexec).is_err());

        let mut changed = executable.clone();
        changed[0].address += 0x1000;
        assert!(
            validate_observations(10, 9, target, [process(); 3], &executable, &changed).is_err()
        );

        let multiple = vec![region(target, VM_PROT_EXECUTE), region(vnode(12), 1)];
        assert!(
            validate_observations(10, 9, target, [process(); 3], &multiple, &multiple).is_err()
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn real_child_maps_the_exact_owned_executable_vnode() {
        use std::fs::{self, OpenOptions};
        use std::os::fd::{FromRawFd, IntoRawFd};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use std::process::{Command, Stdio};
        use std::time::Duration;

        struct Reap(Child);

        impl Drop for Reap {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let root = tempfile::tempdir().unwrap();
        let requested_install = root.path().join("install");
        fs::create_dir_all(requested_install.join("node_modules/opencode/bin")).unwrap();
        let install = fs::canonicalize(requested_install).unwrap();
        let binary = install.join("node_modules/opencode/bin/opencode");
        fs::copy("/bin/sleep", &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&binary)
            .unwrap();
        let mut child = Reap(
            Command::new(&binary)
                .arg("20")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(50));

        // SAFETY: ownership of the descriptor moves from `File` exactly once.
        let owned = unsafe { OwnedFd::from_raw_fd(executable.into_raw_fd()) };
        let proof = verify_live_executable(&mut child.0, owned, &install).unwrap();
        assert_eq!(proof.pid(), child.0.id());
        assert_eq!(proof.canonical_path(), binary);
        assert_ne!(proof.raw_digest(), &[0_u8; 32]);
        let _ = proof.executable_fd();
        proof.retain_kernel_identity();
    }
}
