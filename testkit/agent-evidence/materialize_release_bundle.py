#!/usr/bin/env python3
"""Construct an inactive release bundle and advisory index; never publish a ref."""
from __future__ import annotations

import ctypes
import errno
import importlib.util
import json
import os
import platform
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
STOCK_ROOT = REPO_ROOT / "testkit" / "stock-opencode"
RELEASE_ROOT = REPO_ROOT / "evidence" / "agent-releases"
INPUTS = {
    "lifecycle-certificate.json": STOCK_ROOT / "real-task" / "lifecycle-certificate.json.tmp",
    "lifecycle-shape-manifest.json": STOCK_ROOT / "real-task" / "lifecycle-shape-manifest.json.tmp",
    "lifecycle-evidence-manifest.json": STOCK_ROOT / "lifecycle-evidence-manifest.json.tmp",
}
APPROVAL_PATH = STOCK_ROOT / "real-task" / "lifecycle-approval-record.json"
SIGNATURE_PATH = STOCK_ROOT / "real-task" / "release-approval-record.sshsig"
PROPOSED_NAME = "current.json.proposed"
MAX_BYTES = 512 * 1024
ZERO = "0" * 64

spec = importlib.util.spec_from_file_location("nomad_release_bundle_verifier", HERE / "verify_release_bundle.py")
if spec is None or spec.loader is None:
    raise RuntimeError("release bundle verifier unavailable")
c1 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c1
spec.loader.exec_module(c1)


@dataclass(frozen=True)
class Verdict:
    status: str
    code: str


def _verdict(code: str) -> Verdict:
    return Verdict("CANDIDATE" if code == "CANDIDATE_RELEASE_TREE" else "BLOCKED" if code.startswith("BLOCKED_") else "FAIL", code)


def _read_fixed(path: Path) -> bytes:
    return c1._read_bytes(path, MAX_BYTES)


def _read_json_bytes(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=c1._pairs)
    if not isinstance(value, dict):
        raise ValueError
    return value


def _write_exclusive(path: Path, raw: bytes) -> None:
    if not raw or len(raw) > MAX_BYTES:
        raise OSError(errno.EFBIG, "bounded")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    failure: BaseException | None = None
    try:
        os.fchmod(fd, 0o600)
        total = 0
        while total < len(raw):
            written = os.write(fd, raw[total:])
            if written <= 0:
                raise OSError(errno.EIO, "write")
            total += written
        os.fsync(fd)
    except BaseException as error:
        failure = error
    try:
        os.close(fd)
    except OSError as error:
        if failure is None:
            failure = error
    if failure is not None:
        raise failure


def _mkdir(path: Path, mode: int) -> None:
    os.mkdir(path, mode)
    os.chmod(path, mode)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or stat.S_ISLNK(info.st_mode):
        raise OSError(errno.EPERM, "directory policy")


def _safe_output_directory(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.geteuid() and not (info.st_mode & 0o022))


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _lineage(release_root: Path) -> tuple[str, int, str | None, Mapping[str, object] | None]:
    path = release_root / c1.INDEX_NAME
    try:
        index, _ = c1._read_json(path)
    except FileNotFoundError:
        return ZERO, 0, None, None
    if not c1._valid_index(index):
        raise ValueError
    return index["release_index_digest"], index["release_sequence"], index["active_bundle_id"], index


def _build_values(inputs: Mapping[str, bytes], approval_raw: bytes, signature: bytes, parent: Mapping[str, object] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = _read_json_bytes(inputs["lifecycle-evidence-manifest.json"])
    approval = _read_json_bytes(approval_raw)
    if approval.get("signature_file") != c1.SIGNATURE_NAME:
        raise ValueError
    descriptors = {name: {"raw_sha256": c1._raw_digest(raw), "size_bytes": len(raw)} for name, raw in inputs.items()}
    manifest_core = {
        "schema_version": "nomad.agent-evidence.bundle-manifest.v1",
        "adapter_id": "opencode",
        "adapter_version": "1.18.16",
        "adapter_contract_digest": c1.OPENCODE_CONTRACT_DIGEST,
        "approval_scope": c1.OPENCODE_POLICY["approval_scope"],
        "reviewed_version": evidence["reviewed_version"],
        "evidence_manifest_digest": evidence["evidence_manifest_digest"],
        "approval_record_digest": c1._digest(approval),
        "approval_signature_raw_digest": c1._raw_digest(signature),
        "trust_root_id": approval["trust_root_id"],
        "adapter_artifacts": descriptors,
    }
    manifest = {**manifest_core, "bundle_manifest_digest": c1._digest(manifest_core)}
    previous = ZERO if parent is None else parent["release_index_digest"]
    sequence = 1 if parent is None else parent["release_sequence"] + 1
    if parent is not None and parent.get("active_bundle_id") == "sha256-" + manifest["bundle_manifest_digest"]:
        raise ValueError
    index_core = {
        "schema_version": "nomad.agent-evidence.release-index.v1",
        "active_bundle_id": "sha256-" + manifest["bundle_manifest_digest"],
        "bundle_manifest_digest": manifest["bundle_manifest_digest"],
        "adapter_id": manifest["adapter_id"],
        "adapter_version": manifest["adapter_version"],
        "reviewed_version": manifest["reviewed_version"],
        "evidence_manifest_digest": manifest["evidence_manifest_digest"],
        "approval_record_digest": manifest["approval_record_digest"],
        "previous_release_index_digest": previous,
        "release_sequence": sequence,
    }
    return manifest, {**index_core, "release_index_digest": c1._digest(index_core)}


def _construct_private(candidate: Path, inputs: Mapping[str, bytes], approval: bytes, signature: bytes, manifest: Mapping[str, object], index: Mapping[str, object]) -> tuple[Path, Path]:
    bundles = candidate / c1.BUNDLES_NAME
    _mkdir(bundles, 0o700)
    bundle = bundles / ("sha256-" + str(manifest["bundle_manifest_digest"]))
    _mkdir(bundle, 0o700)
    adapter = bundle / "adapter"
    _mkdir(adapter, 0o700)
    _write_exclusive(bundle / c1.MANIFEST_NAME, c1._canonical(manifest))
    _write_exclusive(bundle / c1.APPROVAL_NAME, approval)
    _write_exclusive(bundle / c1.SIGNATURE_NAME, signature)
    for name, raw in inputs.items():
        _write_exclusive(adapter / name, raw)
    _write_exclusive(candidate / c1.INDEX_NAME, c1._canonical(index))
    for directory in (adapter, bundle, bundles, candidate):
        _fsync_dir(directory)
    return bundle, candidate / c1.INDEX_NAME


def _errno_verdict(value: int) -> Verdict:
    if value in (errno.ENOSYS, getattr(errno, "EOPNOTSUPP", errno.ENOSYS)):
        return _verdict("BLOCKED_UNSUPPORTED_NO_REPLACE")
    if value == errno.EXDEV:
        return _verdict("BLOCKED_CROSS_DEVICE")
    if value in (errno.EPERM, errno.EACCES):
        return _verdict("BLOCKED_OUTPUT_DIR_POLICY")
    if value == errno.EEXIST:
        return _verdict("BLOCKED_BUNDLE_COLLISION")
    return _verdict("BLOCKED_ATOMIC_PUBLISH")


def exclusive_dir_publish(source: Path, bundles: Path, final_basename: str, *, system: str | None = None, machine: str | None = None, library_factory: Callable[..., Any] = ctypes.CDLL) -> Verdict:
    candidate = source.parent.parent
    try:
        source_info=os.lstat(source);candidate_info=os.lstat(candidate);bundles_info=os.lstat(bundles)
    except OSError:
        return _verdict("BLOCKED_OUTPUT_DIR_POLICY")
    if (not c1.BUNDLE_ID.fullmatch(final_basename) or source.name != final_basename
            or source.parent.name != c1.BUNDLES_NAME or bundles.name != c1.BUNDLES_NAME
            or not candidate.name.startswith(".candidate-") or candidate.parent != bundles.parent
            or not all(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) for value in (source_info,candidate_info,bundles_info))):
        return _verdict("BLOCKED_OUTPUT_DIR_POLICY")
    target = bundles / final_basename
    system = system or platform.system()
    machine = machine or platform.machine()
    try:
        libc = library_factory(None, use_errno=True)
        old = os.fsencode(str(source.absolute()))
        new = os.fsencode(str(target.absolute()))
        if (os.lstat(source).st_dev,os.lstat(source).st_ino)!=(source_info.st_dev,source_info.st_ino) or (os.lstat(candidate).st_dev,os.lstat(candidate).st_ino)!=(candidate_info.st_dev,candidate_info.st_ino) or (os.lstat(bundles).st_dev,os.lstat(bundles).st_ino)!=(bundles_info.st_dev,bundles_info.st_ino):
            return _verdict("BLOCKED_ATOMIC_PUBLISH")
        ctypes.set_errno(0)
        if system == "Darwin" and machine == "arm64":
            function = libc.renamex_np
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(old, new, ctypes.c_uint(0x00000004))
        elif system == "Linux" and machine in ("x86_64", "amd64"):
            function = libc.syscall
            function.restype = ctypes.c_long
            result = function(ctypes.c_long(316), ctypes.c_int(-100), ctypes.c_char_p(old), ctypes.c_int(-100), ctypes.c_char_p(new), ctypes.c_uint(0x00000001))
        else:
            return _verdict("BLOCKED_UNSUPPORTED_NO_REPLACE")
        if result == 0:
            try:target_info=os.lstat(target)
            except OSError:return _verdict("BLOCKED_ATOMIC_PUBLISH")
            try:os.lstat(source);source_missing=False
            except FileNotFoundError:source_missing=True
            except OSError:return _verdict("BLOCKED_ATOMIC_PUBLISH")
            if not source_missing or not stat.S_ISDIR(target_info.st_mode) or stat.S_ISLNK(target_info.st_mode) or (target_info.st_dev,target_info.st_ino)!=(source_info.st_dev,source_info.st_ino):
                return _verdict("BLOCKED_ATOMIC_PUBLISH")
            if c1.compare_immutable_bundle(target, target).status != "IDENTICAL":
                return _verdict("BLOCKED_ATOMIC_PUBLISH")
            try:
                _fsync_dir(bundles)
            except OSError:
                return _verdict("BLOCKED_DIRECTORY_FSYNC")
            return Verdict("PUBLISHED_INACTIVE", "PUBLISHED_INACTIVE")
        value = ctypes.get_errno()
    except (AttributeError, OSError, TypeError, ValueError):
        return _verdict("BLOCKED_UNSUPPORTED_NO_REPLACE")
    if value == errno.EEXIST:
        comparison = c1.compare_immutable_bundle(source, target)
        return Verdict("ALREADY_IDENTICAL", "ALREADY_IDENTICAL") if comparison.status == "IDENTICAL" else _verdict("BLOCKED_BUNDLE_COLLISION")
    return _errno_verdict(value)


def _materialize(
    release_root: Path,
    input_paths: Mapping[str, Path],
    approval_path: Path,
    signature_path: Path,
    adapter_verifier: Callable[[Path, Mapping[str, object]], bool],
    approval_verifier: Callable[[Path, Mapping[str, object]], bool],
    publisher: Callable[[Path, Path, str], Verdict],
) -> Verdict:
    try:
        inputs = {name: _read_fixed(path) for name, path in input_paths.items()}
    except (FileNotFoundError, OSError, OverflowError):
        return _verdict("BLOCKED_INPUT_STAGED_MISSING")
    try:
        approval = _read_fixed(approval_path)
        signature = _read_fixed(signature_path)
    except (FileNotFoundError, OSError, OverflowError):
        return _verdict("BLOCKED_EXTERNAL_APPROVAL_VERIFICATION")
    try:
        observed_digest, observed_sequence, observed_bundle, parent = _lineage(release_root)
    except (OSError, ValueError, c1.DuplicateKey, json.JSONDecodeError, UnicodeDecodeError):
        return _verdict("BLOCKED_EXPECTED_PARENT_INDEX")
    try:
        manifest, index = _build_values(inputs, approval, signature, parent)
    except (ValueError, KeyError, TypeError, c1.DuplicateKey, json.JSONDecodeError, UnicodeDecodeError):
        return _verdict("FAIL_BUNDLE_MANIFEST")
    try:
        candidate = Path(tempfile.mkdtemp(prefix=".candidate-", dir=release_root))
        os.chmod(candidate, 0o700)
        info = os.lstat(candidate)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid()):
            return _verdict("BLOCKED_OUTPUT_DIR_POLICY")
        _fsync_dir(release_root)
        private_bundle, _ = _construct_private(candidate, inputs, approval, signature, manifest, index)
    except FileExistsError:
        return _verdict("BLOCKED_CANDIDATE_ALREADY_EXISTS")
    except OSError:
        return _verdict("BLOCKED_DIRECTORY_FSYNC")
    verification = c1._verify_release_tree(candidate, parent, adapter_verifier, approval_verifier)
    if verification.code == "BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED":
        return _verdict(verification.code)
    if verification.status != "VERIFIED":
        return _verdict("FAIL_C1_INTERNAL_VERIFICATION")
    outcome = publisher(private_bundle, release_root / c1.BUNDLES_NAME, index["active_bundle_id"])
    if outcome.status not in {"PUBLISHED_INACTIVE", "ALREADY_IDENTICAL"}:
        return outcome
    try:
        current_digest, current_sequence, current_bundle, _ = _lineage(release_root)
    except (OSError, ValueError):
        return _verdict("BLOCKED_EXPECTED_PARENT_INDEX")
    if (current_digest, current_sequence, current_bundle) != (observed_digest, observed_sequence, observed_bundle):
        return _verdict("BLOCKED_EXPECTED_PARENT_INDEX")
    try:
        _write_exclusive(release_root / PROPOSED_NAME, c1._canonical(index))
        _fsync_dir(release_root)
    except FileExistsError:
        return _verdict("BLOCKED_PROPOSED_INDEX_EXISTS")
    except OSError:
        return _verdict("BLOCKED_DIRECTORY_FSYNC")
    return Verdict("CANDIDATE", "CANDIDATE_RELEASE_TREE")


def materialize_release_bundle() -> Verdict:
    if not _safe_output_directory(RELEASE_ROOT) or not _safe_output_directory(RELEASE_ROOT / c1.BUNDLES_NAME):
        return _verdict("BLOCKED_OUTPUT_DIR_POLICY")
    return _materialize(RELEASE_ROOT, INPUTS, APPROVAL_PATH, SIGNATURE_PATH, c1._production_adapter_verifier, c1._production_approval_verifier, exclusive_dir_publish)


def main() -> int:
    if len(sys.argv) != 1:
        sys.stderr.write("BLOCKED_OUTPUT_DIR_POLICY\n")
        return 1
    verdict = materialize_release_bundle()
    stream = sys.stdout if verdict.code == "CANDIDATE_RELEASE_TREE" else sys.stderr
    stream.write(verdict.code + "\n")
    return 0 if verdict.code == "CANDIDATE_RELEASE_TREE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
