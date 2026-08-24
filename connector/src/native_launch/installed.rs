//! Post-install verification for the isolated native OpenCode launcher.
//!
//! This module never launches a process. It turns an already materialized npm
//! tree into one owned executable descriptor plus reviewed closure facts.

use super::inputs::{canonical_digest, strict_json, StockInputFacts};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_JSON: u64 = 64 * 1024;
const MAX_EXECUTABLE: u64 = 64 * 1024 * 1024;
const PACKAGE: &str = "opencode-ai";
const PLATFORM_PACKAGE: &str = "opencode-darwin-arm64";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InstalledTreeError;

impl fmt::Display for InstalledTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BLOCKED_NATIVE_INSTALLED_TREE_UNVERIFIED")
    }
}

impl std::error::Error for InstalledTreeError {}

pub(super) struct VerifiedInstalledTree {
    executable: OwnedFd,
    canonical_path: PathBuf,
    raw_digest: [u8; 32],
    dependency_count: usize,
    dependency_digest: String,
}

impl VerifiedInstalledTree {
    pub(super) fn into_executable(self) -> OwnedFd {
        self.executable
    }

    pub(super) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub(super) fn raw_digest(&self) -> &[u8; 32] {
        &self.raw_digest
    }

    pub(super) fn dependency_count(&self) -> usize {
        self.dependency_count
    }

    pub(super) fn dependency_digest(&self) -> &str {
        &self.dependency_digest
    }
}

pub(super) fn verify_installed_tree(
    install: &Path,
    expected: &StockInputFacts,
) -> Result<VerifiedInstalledTree, InstalledTreeError> {
    let install = exact_directory(install)?;
    let package_raw = read_regular(&install.join("package.json"), MAX_JSON)?;
    let lock_raw = read_regular(&install.join("package-lock.json"), MAX_JSON)?;
    if hex_digest(&package_raw) != expected.package_json_sha256
        || hex_digest(&lock_raw) != expected.package_lock_sha256
    {
        return Err(InstalledTreeError);
    }

    let lock = strict_json(&lock_raw, MAX_JSON as usize).map_err(|_| InstalledTreeError)?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(InstalledTreeError)?;
    let node_modules = exact_directory(&install.join("node_modules"))?;
    if !node_modules.starts_with(&install) {
        return Err(InstalledTreeError);
    }

    let actual = actual_packages(&node_modules)?;
    let wanted: BTreeSet<String> = [PACKAGE, PLATFORM_PACKAGE]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if actual != wanted {
        return Err(InstalledTreeError);
    }

    let mut tuples = Vec::new();
    for name in [PACKAGE, PLATFORM_PACKAGE] {
        let raw = read_regular(&node_modules.join(name).join("package.json"), MAX_JSON)?;
        let package = strict_json(&raw, MAX_JSON as usize).map_err(|_| InstalledTreeError)?;
        if package.get("name").and_then(Value::as_str) != Some(name)
            || package.get("version").and_then(Value::as_str) != Some("1.18.16")
        {
            return Err(InstalledTreeError);
        }
        let entry = packages
            .get(&format!("node_modules/{name}"))
            .and_then(Value::as_object)
            .ok_or(InstalledTreeError)?;
        let integrity = entry
            .get("integrity")
            .and_then(Value::as_str)
            .ok_or(InstalledTreeError)?;
        if entry.get("version").and_then(Value::as_str) != Some("1.18.16") {
            return Err(InstalledTreeError);
        }
        tuples.push(serde_json::json!([name, "1.18.16", integrity]));
    }
    tuples.sort_by_key(|value| value.to_string());
    let dependency_digest = canonical_digest(&Value::Array(tuples));
    if wanted.len() != expected.darwin_arm64_dependency_count
        || dependency_digest != expected.darwin_arm64_dependency_digest
    {
        return Err(InstalledTreeError);
    }

    let launcher = node_modules.join(".bin/opencode");
    let launcher_meta = fs::symlink_metadata(&launcher).map_err(|_| InstalledTreeError)?;
    if !launcher_meta.file_type().is_symlink() && !launcher_meta.is_file() {
        return Err(InstalledTreeError);
    }
    let canonical_path = fs::canonicalize(&launcher).map_err(|_| InstalledTreeError)?;
    if canonical_path == node_modules || !canonical_path.starts_with(&node_modules) {
        return Err(InstalledTreeError);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&canonical_path)
        .map_err(|_| InstalledTreeError)?;
    let before = file.metadata().map_err(|_| InstalledTreeError)?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_EXECUTABLE
        || before.mode() & 0o111 == 0
    {
        return Err(InstalledTreeError);
    }
    let mut raw =
        Vec::with_capacity(usize::try_from(before.len()).map_err(|_| InstalledTreeError)?);
    file.by_ref()
        .take(MAX_EXECUTABLE + 1)
        .read_to_end(&mut raw)
        .map_err(|_| InstalledTreeError)?;
    let after = file.metadata().map_err(|_| InstalledTreeError)?;
    let path_after = fs::symlink_metadata(&canonical_path).map_err(|_| InstalledTreeError)?;
    if raw.len() as u64 != before.len()
        || file_identity(&before) != file_identity(&after)
        || file_identity(&before) != file_identity(&path_after)
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC == 0
    {
        return Err(InstalledTreeError);
    }
    let raw_digest: [u8; 32] = Sha256::digest(&raw).into();
    Ok(VerifiedInstalledTree {
        executable: file.into(),
        canonical_path,
        raw_digest,
        dependency_count: wanted.len(),
        dependency_digest,
    })
}

fn exact_directory(path: &Path) -> Result<PathBuf, InstalledTreeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstalledTreeError)?;
    let canonical = fs::canonicalize(path).map_err(|_| InstalledTreeError)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical != path {
        return Err(InstalledTreeError);
    }
    Ok(canonical)
}

fn actual_packages(node_modules: &Path) -> Result<BTreeSet<String>, InstalledTreeError> {
    let mut result = BTreeSet::new();
    for entry in fs::read_dir(node_modules).map_err(|_| InstalledTreeError)? {
        let entry = entry.map_err(|_| InstalledTreeError)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| InstalledTreeError)?;
        if matches!(name.as_str(), ".bin" | ".package-lock.json") {
            continue;
        }
        let metadata = entry.metadata().map_err(|_| InstalledTreeError)?;
        if !metadata.is_dir()
            || entry
                .file_type()
                .map_err(|_| InstalledTreeError)?
                .is_symlink()
        {
            return Err(InstalledTreeError);
        }
        result.insert(name);
    }
    Ok(result)
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, InstalledTreeError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| InstalledTreeError)?;
    let before = file.metadata().map_err(|_| InstalledTreeError)?;
    if !before.is_file() || before.nlink() != 1 || before.len() == 0 || before.len() > limit {
        return Err(InstalledTreeError);
    }
    let mut raw =
        Vec::with_capacity(usize::try_from(before.len()).map_err(|_| InstalledTreeError)?);
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|_| InstalledTreeError)?;
    let after = file.metadata().map_err(|_| InstalledTreeError)?;
    let current = fs::symlink_metadata(path).map_err(|_| InstalledTreeError)?;
    if raw.len() as u64 != before.len()
        || file_identity(&before) != file_identity(&after)
        || file_identity(&before) != file_identity(&current)
    {
        return Err(InstalledTreeError);
    }
    Ok(raw)
}

fn file_identity(value: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u64) {
    (
        value.dev(),
        value.ino(),
        value.len(),
        value.mtime(),
        value.mtime_nsec(),
        value.ctime(),
        value.ctime_nsec(),
        value.nlink(),
    )
}

fn hex_digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_launch::inputs::{verify_stock_inputs, MaterializationRoot};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn tree() -> (tempfile::TempDir, StockInputFacts) {
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("install");
        fs::create_dir(&install).unwrap();
        let verified = verify_stock_inputs().unwrap();
        for item in &verified.materialization.files {
            if !matches!(item.root, MaterializationRoot::Install) {
                continue;
            }
            let target = install.join(item.relative_name);
            fs::write(target, item.bytes).unwrap();
        }
        let modules = install.join("node_modules");
        for name in [PACKAGE, PLATFORM_PACKAGE] {
            fs::create_dir_all(modules.join(name)).unwrap();
            fs::write(
                modules.join(name).join("package.json"),
                serde_json::to_vec(&serde_json::json!({
                    "name": name, "version": "1.18.16"
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let binary = modules.join(PLATFORM_PACKAGE).join("opencode");
        fs::copy("/bin/sleep", &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(modules.join(".bin")).unwrap();
        symlink(
            "../opencode-darwin-arm64/opencode",
            modules.join(".bin/opencode"),
        )
        .unwrap();
        (root, verified.facts)
    }

    #[test]
    fn exact_tree_yields_owned_native_executable() {
        let (root, facts) = tree();
        let install = fs::canonicalize(root.path().join("install")).unwrap();
        let value = verify_installed_tree(&install, &facts).unwrap();
        assert_eq!(value.dependency_count(), 2);
        assert_eq!(
            value.dependency_digest(),
            facts.darwin_arm64_dependency_digest
        );
        assert!(value
            .canonical_path()
            .starts_with(install.join("node_modules")));
        assert_ne!(value.raw_digest(), &[0_u8; 32]);
        let _owned = value.into_executable();
    }

    #[test]
    fn extra_missing_mutated_and_escaped_trees_block() {
        let (root, facts) = tree();
        let install = fs::canonicalize(root.path().join("install")).unwrap();
        fs::create_dir(install.join("node_modules/extra")).unwrap();
        assert!(verify_installed_tree(&install, &facts).is_err());

        let (root, facts) = tree();
        let install = fs::canonicalize(root.path().join("install")).unwrap();
        fs::remove_dir_all(install.join("node_modules/opencode-ai")).unwrap();
        assert!(verify_installed_tree(&install, &facts).is_err());

        let (root, facts) = tree();
        let install = fs::canonicalize(root.path().join("install")).unwrap();
        fs::write(install.join("package-lock.json"), b"{}").unwrap();
        assert!(verify_installed_tree(&install, &facts).is_err());

        let (root, facts) = tree();
        let install = fs::canonicalize(root.path().join("install")).unwrap();
        fs::remove_file(install.join("node_modules/.bin/opencode")).unwrap();
        symlink("/bin/sleep", install.join("node_modules/.bin/opencode")).unwrap();
        assert!(verify_installed_tree(&install, &facts).is_err());
    }
}
