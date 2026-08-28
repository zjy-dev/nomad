"""Strictly resume a blocked M3-E evidence run from current artifacts.

Resume is a provenance check followed by a fresh, complete product-slice run.
No stage result or runtime state from the parent evidence is reused.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import fcntl
import contextlib
from typing import Any, Mapping, Sequence

from .bundle import verify_bundle


EVIDENCE_SCHEMA = "nomad.m3e.real-product-slice-evidence.v1"
PRODUCT_RUNNER_ENTRY = "testkit/remote-v2/run_m3e_product_slice.py"
BROWSER_RUNNER_ENTRY = "testkit/remote-v2/run_m3e_desktop_browser.py"
PACKAGE_INIT_ENTRY = "lib/nomad_web/__init__.py"
BUNDLE_VERIFIER_ENTRY = "lib/nomad_web/bundle.py"
RUNNER_ENTRIES = (
    PRODUCT_RUNNER_ENTRY, BROWSER_RUNNER_ENTRY, PACKAGE_INIT_ENTRY, BUNDLE_VERIFIER_ENTRY,
)
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_RUNNER_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES = 192 * 1024 * 1024
ALLOWED_PARENT_BLOCKERS = frozenset({
    "HOST_IDENTITY_AUTH_REQUIRED",
    "HOST_IDENTITY_USER_DENIED",
    "browser_join_navigation_ERR_CERT_AUTHORITY_INVALID",
})
ALLOWED_RUNNER_ARGS = frozenset({"--keep-runtime"})
SHA256 = re.compile(r"[0-9a-f]{64}")
OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
PRODUCT_EXEC_WRAPPER = """
import hashlib, os, sys
fd = int(sys.argv.pop(1))
name = sys.argv.pop(1)
chunks = []
while True:
    chunk = os.read(fd, 65536)
    if not chunk:
        break
    chunks.append(chunk)
raw = b''.join(chunks)
namespace = {
    '__name__': '__main__',
    '__file__': name,
    '__package__': None,
    '__runner_raw_sha256__': hashlib.sha256(raw).hexdigest(),
}
exec(compile(raw, name, 'exec'), namespace, namespace)
"""


class EvidenceResumeError(RuntimeError):
    """A fixed, content-free strict-resume rejection."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _read_private_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    path = path.absolute()
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceResumeError("PARENT_EVIDENCE_UNAVAILABLE") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_EVIDENCE_BYTES
    ):
        raise EvidenceResumeError("EVIDENCE_FILE_POLICY_INVALID")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceResumeError("EVIDENCE_FILE_POLICY_INVALID") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise EvidenceResumeError("EVIDENCE_FILE_CHANGED")
        raw = bytearray()
        while len(raw) <= MAX_EVIDENCE_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_EVIDENCE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_EVIDENCE_BYTES or (
        opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise EvidenceResumeError("EVIDENCE_FILE_CHANGED")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceResumeError("EVIDENCE_JSON_INVALID") from error
    if not isinstance(value, dict) or bytes(raw) != _canonical(value) + b"\n":
        raise EvidenceResumeError("EVIDENCE_NOT_CANONICAL")
    return value, bytes(raw)


def _runner_entries(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise EvidenceResumeError("RUNNER_CLOSURE_MANIFEST_INVALID")
    selected: dict[str, Mapping[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict) or item.get("path") not in RUNNER_ENTRIES:
            continue
        name = item["path"]
        if (
            name in selected
            or set(item) != {"path", "size_bytes", "raw_sha256", "mode"}
            or type(item.get("size_bytes")) is not int
            or not 0 < item["size_bytes"] <= MAX_RUNNER_BYTES
            or not isinstance(item.get("raw_sha256"), str)
            or SHA256.fullmatch(item["raw_sha256"]) is None
            or item.get("mode") != "0644"
        ):
            raise EvidenceResumeError("RUNNER_CLOSURE_MANIFEST_INVALID")
        selected[name] = item
    if set(selected) != set(RUNNER_ENTRIES):
        raise EvidenceResumeError("RUNNER_CLOSURE_MANIFEST_INVALID")
    return selected


def _manifest_source_binding(manifest: Mapping[str, Any]) -> dict[str, str]:
    entries = _runner_entries(manifest)
    return {
        "product_runner_raw_sha256": str(entries[PRODUCT_RUNNER_ENTRY]["raw_sha256"]),
        "browser_runner_raw_sha256": str(entries[BROWSER_RUNNER_ENTRY]["raw_sha256"]),
    }


def _read_manifest_file(
    root_descriptor: int, relative: str, expected: Mapping[str, Any]
) -> bytes:
    current = os.dup(root_descriptor)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            following = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = following
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(parts[-1], flags, dir_fd=current)
    except OSError as error:
        os.close(current)
        raise EvidenceResumeError("BUNDLE_SNAPSHOT_SOURCE_UNAVAILABLE") from error
    os.close(current)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or f"{stat.S_IMODE(info.st_mode):04o}" != expected["mode"]
            or info.st_size != expected["size_bytes"]
        ):
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_FILE_POLICY_INVALID")
        raw = bytearray()
        limit = MAX_BUNDLE_FILE_BYTES
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(raw) > limit
            or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or hashlib.sha256(raw).hexdigest() != expected["raw_sha256"]
        ):
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_DIGEST_MISMATCH")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _write_complete(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_WRITE_FAILED")
        offset += written


def _manifest_entries(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise EvidenceResumeError("BUNDLE_SNAPSHOT_MANIFEST_INVALID")
    entries: dict[str, Mapping[str, Any]] = {}
    for item in files:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "size_bytes", "raw_sha256", "mode"}
            or not isinstance(item.get("path"), str)
            or item["path"] in entries
            or item["path"].startswith("/")
            or ".." in Path(item["path"]).parts
            or type(item.get("size_bytes")) is not int
            or not 0 < item["size_bytes"] <= MAX_BUNDLE_FILE_BYTES
            or not isinstance(item.get("raw_sha256"), str)
            or SHA256.fullmatch(item["raw_sha256"]) is None
            or item.get("mode") not in {"0644", "0755"}
        ):
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_MANIFEST_INVALID")
        entries[item["path"]] = item
    return entries


def _directory_identity(descriptor: int) -> tuple[int, int, int, int]:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        raise EvidenceResumeError("BUNDLE_SNAPSHOT_ROOT_INVALID")
    return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns


def _path_matches_open_root(path: Path, identity: tuple[int, int, int, int]) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) == identity
    )


def _freeze_snapshot(root: Path) -> None:
    files = sorted((item for item in root.rglob("*") if item.is_file()))
    for directory in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts), reverse=True,
    ):
        descriptor = os.open(directory, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(directory, 0o755)
    for path in files:
        os.chflags(path, stat.UF_IMMUTABLE, follow_symlinks=False)
        if os.lstat(path).st_flags & stat.UF_IMMUTABLE == 0:
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_IMMUTABLE_FAILED")
    for directory in sorted(
        (item for item in root.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts), reverse=True,
    ):
        os.chflags(directory, stat.UF_IMMUTABLE, follow_symlinks=False)
        if os.lstat(directory).st_flags & stat.UF_IMMUTABLE == 0:
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_IMMUTABLE_FAILED")
    descriptor = os.open(root, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(root, 0o755)
    os.chflags(root, stat.UF_IMMUTABLE, follow_symlinks=False)
    if os.lstat(root).st_flags & stat.UF_IMMUTABLE == 0:
        raise EvidenceResumeError("BUNDLE_SNAPSHOT_IMMUTABLE_FAILED")


def _thaw_snapshot(root: Path) -> None:
    with contextlib.suppress(OSError):
        os.chflags(root, 0, follow_symlinks=False)
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
        with contextlib.suppress(OSError):
            os.chflags(path, 0, follow_symlinks=False)


class _BundleSnapshotOwner:
    def __init__(self, temporary: tempfile.TemporaryDirectory[str], root: Path):
        self._temporary = temporary
        self._root = root

    def cleanup(self) -> None:
        _thaw_snapshot(self._root)
        self._temporary.cleanup()


def _snapshot_verified_bundle(
    bundle: Path, manifest: Mapping[str, Any]
) -> tuple[tempfile.TemporaryDirectory[str], Path, Mapping[str, Any]]:
    entries = _manifest_entries(manifest)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        root_descriptor = os.open(bundle, flags)
    except OSError as error:
        raise EvidenceResumeError("BUNDLE_SNAPSHOT_SOURCE_UNAVAILABLE") from error
    source_identity = _directory_identity(root_descriptor)
    if not _path_matches_open_root(bundle, source_identity):
        os.close(root_descriptor)
        raise EvidenceResumeError("BUNDLE_SNAPSHOT_SOURCE_CHANGED")
    old_umask = os.umask(0o077)
    try:
        temporary = tempfile.TemporaryDirectory(prefix="nomad-m3e-bundle.")
    finally:
        os.umask(old_umask)
    snapshot = Path(temporary.name) / "bundle"
    snapshot.mkdir(mode=0o700)
    try:
        for name in sorted(entries):
            raw = _read_manifest_file(root_descriptor, name, entries[name])
            if (
                _directory_identity(root_descriptor) != source_identity
                or not _path_matches_open_root(bundle, source_identity)
            ):
                raise EvidenceResumeError("BUNDLE_SNAPSHOT_SOURCE_CHANGED")
            target = snapshot / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                int(str(entries[name]["mode"]), 8),
            )
            try:
                _write_complete(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        manifest_raw = _canonical(manifest) + b"\n"
        descriptor = os.open(
            snapshot / "manifest.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644,
        )
        try:
            _write_complete(descriptor, manifest_raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if (
            _directory_identity(root_descriptor) != source_identity
            or not _path_matches_open_root(bundle, source_identity)
        ):
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_SOURCE_CHANGED")
        _freeze_snapshot(snapshot)
        try:
            verified_snapshot = verify_bundle(snapshot)
        except (OSError, RuntimeError, ValueError) as error:
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_VERIFICATION_FAILED") from error
        if verified_snapshot != manifest:
            raise EvidenceResumeError("BUNDLE_SNAPSHOT_MANIFEST_MISMATCH")
        return _BundleSnapshotOwner(temporary, snapshot), snapshot, verified_snapshot
    except BaseException:
        _thaw_snapshot(snapshot)
        temporary.cleanup()
        raise
    finally:
        os.close(root_descriptor)


def _stage_runner_closure(
    bundle: Path, manifest: Mapping[str, Any]
) -> tuple[None, Path, Path]:
    """Select runner paths only from an already immutable private snapshot."""
    _runner_entries(manifest)
    return None, bundle / PRODUCT_RUNNER_ENTRY, bundle / BROWSER_RUNNER_ENTRY


def _open_staged_runner(path: Path, expected_digest: str) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        raw = bytearray()
        offset = 0
        while offset < info.st_size:
            chunk = os.pread(descriptor, min(64 * 1024, info.st_size - offset), offset)
            if not chunk:
                raise EvidenceResumeError("RUNNER_STAGING_FAILED")
            raw.extend(chunk)
            offset += len(chunk)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o644
            or hashlib.sha256(raw).hexdigest() != expected_digest
        ):
            raise EvidenceResumeError("RUNNER_STAGING_FAILED")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _validate_bundle_binding(
    evidence: Mapping[str, Any], manifest: Mapping[str, Any]
) -> None:
    binding = evidence.get("bundle")
    if not isinstance(binding, dict) or set(binding) != {
        "digest", "source_commit_oid", "launcher_version", "classification"
    }:
        raise EvidenceResumeError("PARENT_BUNDLE_BINDING_INVALID")
    if (
        not isinstance(binding.get("digest"), str)
        or SHA256.fullmatch(binding["digest"]) is None
        or not isinstance(binding.get("source_commit_oid"), str)
        or OID.fullmatch(binding["source_commit_oid"]) is None
        or binding["digest"] != manifest.get("bundle_digest")
        or binding["source_commit_oid"] != manifest.get("source_commit_oid")
        or binding["launcher_version"] != manifest.get("launcher_version")
        or binding["classification"] != manifest.get("classification")
    ):
        raise EvidenceResumeError("PARENT_BUNDLE_MISMATCH")


def _validate_common_evidence(
    evidence: Mapping[str, Any], manifest: Mapping[str, Any], source_binding: Mapping[str, str]
) -> None:
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise EvidenceResumeError("EVIDENCE_SCHEMA_INVALID")
    if (
        evidence.get("content_free") is not True
        or evidence.get("network_scope") != "lan_direct"
        or evidence.get("provider_e3") != "NOT_RUN"
        or evidence.get("physical_phone") != "NOT_RUN"
        or evidence.get("production_ready") is not False
    ):
        raise EvidenceResumeError("EVIDENCE_CLASSIFICATION_INVALID")
    if evidence.get("diagnostic_tls_bypass") is not False:
        raise EvidenceResumeError("DIAGNOSTIC_EVIDENCE_FORBIDDEN")
    tls = evidence.get("tls")
    browser = evidence.get("browser")
    if (
        isinstance(tls, dict) and tls.get("diagnostic_tls_bypass") is True
    ) or (
        isinstance(browser, dict)
        and isinstance(browser.get("https"), dict)
        and browser["https"].get("diagnostic_tls_bypass") is True
    ):
        raise EvidenceResumeError("DIAGNOSTIC_EVIDENCE_FORBIDDEN")
    _validate_bundle_binding(evidence, manifest)
    if evidence.get("source_binding") != dict(source_binding):
        raise EvidenceResumeError("RUNNER_SOURCE_MISMATCH")


def _verify_resume_parent_manifest(
    block_evidence: Path, manifest: Mapping[str, Any]
) -> str:
    evidence, raw = _read_private_canonical(block_evidence)
    source_binding = _manifest_source_binding(manifest)
    _validate_common_evidence(evidence, manifest, source_binding)
    if evidence.get("status") != "BLOCK":
        raise EvidenceResumeError("PARENT_STATUS_NOT_BLOCK")
    if evidence.get("marker") is not None:
        raise EvidenceResumeError("PARENT_PASS_MARKER_FORBIDDEN")
    if evidence.get("code") not in ALLOWED_PARENT_BLOCKERS:
        raise EvidenceResumeError("PARENT_BLOCKER_NOT_RESUMABLE")
    parent = evidence.get("parent_evidence_digest")
    if parent is not None and (not isinstance(parent, str) or SHA256.fullmatch(parent) is None):
        raise EvidenceResumeError("PARENT_LINEAGE_INVALID")
    return hashlib.sha256(raw).hexdigest()


def verify_resume_parent(block_evidence: Path, bundle: Path) -> str:
    """Verify a parent against one independently verified bundle."""
    try:
        manifest = verify_bundle(bundle)
    except (OSError, RuntimeError, ValueError) as error:
        raise EvidenceResumeError("BUNDLE_VERIFICATION_FAILED") from error
    return _verify_resume_parent_manifest(block_evidence, manifest)


def _validate_runner_args(runner_args: Sequence[str]) -> tuple[str, ...]:
    args = tuple(runner_args)
    if any(not isinstance(item, str) or item not in ALLOWED_RUNNER_ARGS for item in args):
        raise EvidenceResumeError("RUNNER_ARGUMENT_FORBIDDEN")
    if len(args) != len(set(args)):
        raise EvidenceResumeError("RUNNER_ARGUMENT_FORBIDDEN")
    return args


def resume_blocked_evidence(
    block_evidence: Path,
    bundle: Path,
    output: Path,
    runner_args: Sequence[str] = (),
    *,
    tls_ca_fd: int,
    tls_cert_fd: int,
    tls_key_fd: int,
) -> dict[str, Any]:
    """Validate lineage and execute a fresh full M3-E run.

    This API is CLI-ready but deliberately is not wired into the current CLI.
    The only optional runner argument is ``--keep-runtime``; selectors,
    preflight-only execution, diagnostic TLS, and binding overrides are banned.
    """
    block_evidence = Path(block_evidence).absolute()
    bundle = Path(bundle).absolute()
    output = Path(output).absolute()
    if block_evidence == output:
        raise EvidenceResumeError("EVIDENCE_OUTPUT_CONFLICT")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise EvidenceResumeError("EVIDENCE_OUTPUT_UNAVAILABLE") from error
    else:
        raise EvidenceResumeError("EVIDENCE_OUTPUT_EXISTS")
    args = _validate_runner_args(runner_args)
    try:
        source_manifest = verify_bundle(bundle)
    except (OSError, RuntimeError, ValueError) as error:
        raise EvidenceResumeError("BUNDLE_VERIFICATION_FAILED") from error
    snapshot_owner, snapshot, manifest = _snapshot_verified_bundle(bundle, source_manifest)
    product_descriptor: int | None = None
    owned_tls: list[int] = []
    try:
        parent_digest = _verify_resume_parent_manifest(block_evidence, manifest)
        _, product_runner, _ = _stage_runner_closure(snapshot, manifest)
        product_descriptor = _open_staged_runner(
            product_runner, _manifest_source_binding(manifest)["product_runner_raw_sha256"]
        )
        for candidate in (tls_ca_fd, tls_cert_fd, tls_key_fd):
            if type(candidate) is not int or candidate < 0:
                raise EvidenceResumeError("TLS_FD_INVALID")
            try:
                duplicate = os.dup(candidate)
                info = os.fstat(duplicate)
                access = fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE
            except OSError as error:
                raise EvidenceResumeError("TLS_FD_INVALID") from error
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or access != os.O_RDONLY:
                os.close(duplicate)
                raise EvidenceResumeError("TLS_FD_INVALID")
            owned_tls.append(duplicate)
        command = [
            sys.executable, "-I", "-B", "-c", PRODUCT_EXEC_WRAPPER,
            str(product_descriptor), str(product_runner),
            "--bundle", str(snapshot),
            "--evidence", str(output),
            "--parent-evidence-digest", parent_digest,
            *args,
        ]
        control = "NOMAD_TLS_FDS_V1 " + " ".join(str(item) for item in owned_tls) + "\n"
        try:
            completed = subprocess.run(
                command, cwd=Path.cwd(), input=control,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(product_descriptor, *owned_tls), timeout=240, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvidenceResumeError("RESUME_RUNNER_FAILED") from error
        try:
            result, _ = _read_private_canonical(output)
        except EvidenceResumeError:
            raise
        except OSError as error:
            raise EvidenceResumeError("RESUME_OUTPUT_INVALID") from error
        _validate_common_evidence(result, manifest, _manifest_source_binding(manifest))
        if result.get("parent_evidence_digest") != parent_digest:
            raise EvidenceResumeError("RESUME_LINEAGE_MISMATCH")
        status = result.get("status")
        if (
            status == "PASS"
            and completed.returncode == 0
            and result.get("marker") == "M3E_REAL_PRODUCT_SLICE_PASS"
        ):
            return result
        if status == "BLOCK" and completed.returncode == 2 and result.get("marker") is None:
            return result
        raise EvidenceResumeError("RESUME_OUTPUT_INVALID")
    finally:
        for descriptor in owned_tls:
            os.close(descriptor)
        if product_descriptor is not None:
            os.close(product_descriptor)
        snapshot_owner.cleanup()


# Short name for the future CLI integration owner.
resume = resume_blocked_evidence
