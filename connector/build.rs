use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const ERROR: &str = "BLOCKED_RELEASE_ARTIFACT_PUBLICATION";
const MAGIC: &[u8; 8] = b"NOMADREL";
const MAX_PROCESS_OUTPUT: usize = 512 * 1024;
const MAX_ENTRY: usize = 512 * 1024;
const PYTHON_DARWIN_ARM64: &[&str] = &["/usr/bin/python3"];
const PYTHON_LINUX_X86_64: &[&str] = &["/usr/bin/python3"];
const GIT_DARWIN_ARM64: &[&str] = &["/usr/bin/git"];
const GIT_LINUX_X86_64: &[&str] = &["/usr/bin/git"];

fn fail() -> ! {
    println!("cargo:error={ERROR}");
    panic!("{ERROR}");
}

fn nonce() -> Result<[u8; 16], ()> {
    let meta = fs::symlink_metadata("/dev/urandom").map_err(|_| ())?;
    if !meta.file_type().is_char_device() || meta.file_type().is_symlink() {
        return Err(());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")
        .map_err(|_| ())?;
    let mut value = [0u8; 16];
    file.read_exact(&mut value).map_err(|_| ())?;
    Ok(value)
}

fn unavailable_container() -> Vec<u8> {
    let mut value = Vec::with_capacity(15);
    value.extend_from_slice(MAGIC);
    value.extend_from_slice(&1u16.to_be_bytes());
    value.push(0);
    value.extend_from_slice(&0u32.to_be_bytes());
    value
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn lower_hex_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn policy<'a>(darwin: &'a [&str], linux: &'a [&str]) -> &'a [&'a str] {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        darwin
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        linux
    } else {
        &[]
    }
}
fn executable(value: &str, allowed: &[&str]) -> Result<PathBuf, ()> {
    if !Path::new(value).is_absolute() || !allowed.contains(&value) {
        return Err(());
    }
    let real = fs::canonicalize(value).map_err(|_| ())?;
    if real != Path::new(value) || !real.metadata().map_err(|_| ())?.is_file() {
        return Err(());
    }
    Ok(real)
}
fn run(mut command: Command, limit: usize) -> Result<Vec<u8>, ()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| ())?;
    let stdout = child.stdout.take().ok_or(())?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take((limit + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| ())?;
        Ok::<_, ()>(output)
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| ())? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|_| ())?;
            break child.wait().map_err(|_| ())?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = reader.join().map_err(|_| ())??;
    if !status.success() || output.len() > limit {
        return Err(());
    }
    Ok(output)
}
fn git(git: &Path, repo: &Path, args: &[&str]) -> Result<Vec<u8>, ()> {
    let mut command = Command::new(git);
    command
        .args(args)
        .current_dir(repo)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("GIT_OPTIONAL_LOCKS", "0");
    run(command, MAX_PROCESS_OUTPUT)
}
fn show(git_path: &Path, repo: &Path, oid: &str, path: &str) -> Result<Vec<u8>, ()> {
    git(git_path, repo, &["show", &format!("{oid}:{path}")])
}
fn canonical(value: &Value) -> Result<String, ()> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => Ok(v.to_string()),
        Value::String(v) if v.is_ascii() => serde_json::to_string(v).map_err(|_| ()),
        Value::String(_) => Err(()),
        Value::Array(v) => Ok(format!(
            "[{}]",
            v.iter()
                .map(canonical)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(v) => {
            let mut keys: Vec<_> = v.keys().collect();
            keys.sort();
            Ok(format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|k| Ok(format!(
                        "{}:{}",
                        serde_json::to_string(k).map_err(|_| ())?,
                        canonical(&v[k])?
                    )))
                    .collect::<Result<Vec<_>, ()>>()?
                    .join(",")
            ))
        }
    }
}
fn digest_json(value: &Value) -> Result<String, ()> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(value)?.as_bytes())
    ))
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, ()> {
    value.get(name).and_then(Value::as_str).ok_or(())
}
fn encode(entries: &std::collections::BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, ()> {
    let mut out = MAGIC.to_vec();
    out.extend(1u16.to_be_bytes());
    out.push(1);
    out.extend(u32::try_from(entries.len()).map_err(|_| ())?.to_be_bytes());
    for (name, data) in entries {
        if name.is_empty()
            || name.len() > u16::MAX as usize
            || data.is_empty()
            || data.len() > MAX_ENTRY
        {
            return Err(());
        }
        out.extend((name.len() as u16).to_be_bytes());
        out.extend(name.as_bytes());
        out.extend((data.len() as u32).to_be_bytes());
        out.extend(Sha256::digest(data));
        out.extend(data);
    }
    Ok(out)
}

fn production_container(repo: &Path) -> Result<Vec<u8>, ()> {
    let source = env::var("NOMAD_SOURCE_COMMIT_OID").map_err(|_| ())?;
    let parent = env::var("NOMAD_EXPECTED_PARENT_OID").map_err(|_| ())?;
    if !lower_hex_oid(&source) || !lower_hex_oid(&parent) || source.len() != parent.len() {
        return Err(());
    }
    let py_value = env::var("NOMAD_PYTHON_REALPATH").map_err(|_| ())?;
    let python = executable(&py_value, policy(PYTHON_DARWIN_ARM64, PYTHON_LINUX_X86_64))?;
    let verifier = repo.join("testkit/agent-evidence/verify_release_bundle.py");
    if !verifier.is_file() {
        return Err(());
    }
    let mut verify = Command::new(python);
    verify
        .arg(verifier)
        .arg("--expected-parent-oid")
        .arg(&parent)
        .arg("--source-commit-oid")
        .arg(&source)
        .current_dir(repo)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .env("LC_ALL", "C")
        .env("LANG", "C");
    if run(verify, 4096)? != b"VERIFIED_RELEASE_BUNDLE\n" {
        return Err(());
    }
    let git_value = *policy(GIT_DARWIN_ARM64, GIT_LINUX_X86_64)
        .first()
        .ok_or(())?;
    let git_path = executable(git_value, policy(GIT_DARWIN_ARM64, GIT_LINUX_X86_64))?;
    let clean = || -> Result<(), ()> {
        let head =
            String::from_utf8(git(&git_path, repo, &["rev-parse", "HEAD"])?).map_err(|_| ())?;
        if head.trim() != source
            || !git(
                &git_path,
                repo,
                &["status", "--porcelain=v1", "--untracked-files=all"],
            )?
            .is_empty()
        {
            return Err(());
        }
        Ok(())
    };
    clean()?;
    let current_raw = show(
        &git_path,
        repo,
        &source,
        "evidence/agent-releases/current.json",
    )?;
    let current: Value = serde_json::from_slice(&current_raw).map_err(|_| ())?;
    let bundle_id = field(&current, "active_bundle_id")?;
    if bundle_id.len() != 71 || !bundle_id.starts_with("sha256-") {
        return Err(());
    }
    let base = format!("evidence/agent-releases/bundles/{bundle_id}");
    let manifest_raw = show(
        &git_path,
        repo,
        &source,
        &format!("{base}/bundle-manifest.json"),
    )?;
    let manifest: Value = serde_json::from_slice(&manifest_raw).map_err(|_| ())?;
    let artifacts = manifest
        .get("adapter_artifacts")
        .and_then(Value::as_object)
        .ok_or(())?;
    let mut adapter_names: Vec<_> = artifacts.keys().cloned().collect();
    adapter_names.sort();
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("outer/current.json".into(), current_raw);
    entries.insert("outer/bundle-manifest.json".into(), manifest_raw);
    for (file, name) in [
        (
            "release-approval-record.json",
            "outer/release-approval-record.json",
        ),
        (
            "release-approval-record.sshsig",
            "outer/release-approval-record.sshsig",
        ),
    ] {
        entries.insert(
            name.into(),
            show(&git_path, repo, &source, &format!("{base}/{file}"))?,
        );
    }
    for name in adapter_names {
        let bytes = show(&git_path, repo, &source, &format!("{base}/adapter/{name}"))?;
        let descriptor = artifacts.get(&name).and_then(Value::as_object).ok_or(())?;
        if descriptor.get("size_bytes").and_then(Value::as_u64) != Some(bytes.len() as u64)
            || descriptor.get("raw_sha256").and_then(Value::as_str)
                != Some(&format!("{:x}", Sha256::digest(&bytes)))
        {
            return Err(());
        }
        entries.insert(format!("adapter/{name}"), bytes);
    }
    let approval: Value = serde_json::from_slice(
        entries
            .get("outer/release-approval-record.json")
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    let mut current_core = current.clone();
    current_core
        .as_object_mut()
        .ok_or(())?
        .remove("release_index_digest");
    if field(&current, "release_index_digest")? != digest_json(&current_core)? {
        return Err(());
    }
    let meta_core = serde_json::json!({"schema_version":"nomad.agent-evidence.embedded-release.v1","source_commit_oid":source,"expected_parent_oid":parent,"release_index_digest":field(&current,"release_index_digest")?,"bundle_manifest_digest":field(&manifest,"bundle_manifest_digest")?,"adapter_id":field(&manifest,"adapter_id")?,"adapter_version":field(&manifest,"adapter_version")?,"adapter_contract_digest":field(&manifest,"adapter_contract_digest")?,"reviewed_version":field(&manifest,"reviewed_version")?,"evidence_manifest_digest":field(&manifest,"evidence_manifest_digest")?,"approval_record_digest":format!("{:x}",Sha256::digest(entries.get("outer/release-approval-record.json").unwrap())),"approval_signature_raw_digest":format!("{:x}",Sha256::digest(entries.get("outer/release-approval-record.sshsig").unwrap())),"trust_root_id":field(&approval,"trust_root_id")?});
    let mut meta = meta_core.clone();
    meta.as_object_mut().unwrap().insert(
        "metadata_digest".into(),
        Value::String(digest_json(&meta_core)?),
    );
    entries.insert(
        "outer/embedded-meta.json".into(),
        canonical(&meta)?.into_bytes(),
    );
    clean()?;
    encode(&entries)
}

fn create_container(out_dir: &Path, bytes: &[u8]) -> Result<PathBuf, ()> {
    let nonce = nonce()?;
    let path = out_dir.join(format!("nomad_agent_release-{}.container", hex(&nonce)));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&path).map_err(|_| ())?;
    let mut raw_stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), raw_stat.as_mut_ptr()) } != 0 {
        drop(file);
        return Err(());
    }
    let raw_stat = unsafe { raw_stat.assume_init() };
    let identity = (
        u64::try_from(raw_stat.st_dev).map_err(|_| ())?,
        raw_stat.st_ino,
    );
    let result = (|| {
        file.write_all(bytes).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        drop(file);
        let mut reopened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| ())?;
        let current = reopened.metadata().map_err(|_| ())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if identity != (current.dev(), current.ino()) {
                return Err(());
            }
        }
        let mut actual = Vec::new();
        reopened.read_to_end(&mut actual).map_err(|_| ())?;
        if actual != bytes {
            return Err(());
        }
        Ok(path.clone())
    })();
    if result.is_err() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(current) = fs::symlink_metadata(&path) {
                if identity == (current.dev(), current.ino()) {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }
    result
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PRODUCTION_RELEASE_BUNDLE");
    println!("cargo:rerun-if-env-changed=NOMAD_SOURCE_COMMIT_OID");
    println!("cargo:rerun-if-env-changed=NOMAD_EXPECTED_PARENT_OID");
    println!("cargo:rerun-if-env-changed=NOMAD_PYTHON_REALPATH");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_else(|| fail()));
    let bytes = if env::var_os("CARGO_FEATURE_PRODUCTION_RELEASE_BUNDLE").is_some() {
        let manifest_dir =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| fail()));
        let repo = manifest_dir.parent().unwrap_or_else(|| fail());
        production_container(repo).unwrap_or_else(|_| {
            println!("cargo:error=BLOCKED_RELEASE_BUNDLE_UNAVAILABLE");
            panic!("BLOCKED_RELEASE_BUNDLE_UNAVAILABLE");
        })
    } else {
        unavailable_container()
    };
    let path = create_container(&out, &bytes).unwrap_or_else(|_| fail());
    let absolute = fs::canonicalize(path).unwrap_or_else(|_| fail());
    println!(
        "cargo:rustc-env=NOMAD_EMBEDDED_RELEASE_PATH={}",
        absolute.display()
    );
}
