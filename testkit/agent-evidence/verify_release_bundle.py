#!/usr/bin/env python3
"""Read-only verifier for one commit-bound, agent-neutral release bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_ROOT = REPO_ROOT / "evidence" / "agent-releases"
INDEX_NAME = "current.json"
BUNDLES_NAME = "bundles"
MANIFEST_NAME = "bundle-manifest.json"
APPROVAL_NAME = "release-approval-record.json"
SIGNATURE_NAME = "release-approval-record.sshsig"
MAX_JSON = 128 * 1024
MAX_SIGNATURE = 512 * 1024
MAX_GIT_OUTPUT = 256 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
BUNDLE_ID = re.compile(r"^sha256-([0-9a-f]{64})$")
INDEX_FIELDS = frozenset({
    "schema_version", "active_bundle_id", "bundle_manifest_digest", "adapter_id",
    "adapter_version", "reviewed_version", "evidence_manifest_digest",
    "approval_record_digest", "previous_release_index_digest", "release_sequence",
    "release_index_digest",
})
MANIFEST_FIELDS = frozenset({
    "schema_version", "adapter_id", "adapter_version", "adapter_contract_digest",
    "approval_scope", "reviewed_version", "evidence_manifest_digest",
    "approval_record_digest", "approval_signature_raw_digest", "trust_root_id",
    "adapter_artifacts", "bundle_manifest_digest",
})
DESCRIPTOR_FIELDS = frozenset({"raw_sha256", "size_bytes"})
APPROVAL_FIELDS = frozenset({
    "schema_version", "evidence_manifest_digest", "reviewed_version", "scope",
    "principal", "issued_at", "expires_at", "trust_root_id", "signing_namespace",
    "signature_file",
})


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _raw_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


OPENCODE_POLICY = {
    "adapter_id": "opencode",
    "adapter_version": "1.18.16",
    "approval_scope": "nomad.m2.complete-evidence-bundle",
    "approval_schema": "nomad.stock-opencode.approval-record.v1",
    "evidence_schema": "nomad.stock-opencode.evidence-manifest.v1",
    "artifacts": (
        "lifecycle-certificate.json",
        "lifecycle-shape-manifest.json",
        "lifecycle-evidence-manifest.json",
    ),
}
OPENCODE_CONTRACT_DIGEST = _digest(OPENCODE_POLICY)
REGISTRY = {
    ("opencode", "1.18.16", OPENCODE_CONTRACT_DIGEST): OPENCODE_POLICY,
}


@dataclass(frozen=True)
class Verdict:
    status: str
    code: str


class DuplicateKey(ValueError):
    pass


class UnsafeFile(OSError):
    pass


class CleanupUnconfirmed(RuntimeError):
    pass


def _directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _open_directory(path: Path, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags, dir_fd=dir_fd)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise UnsafeFile(str(path))
    return fd


def _read_relative(directory_fd: int, name: str, limit: int) -> bytes:
    if not isinstance(name, str) or not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise UnsafeFile(name)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise UnsafeFile(name)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            piece = os.read(fd, min(65536, remaining))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        result = b"".join(chunks)
        if len(result) > limit:
            raise OverflowError(name)
        after = os.fstat(fd)
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_nlink)
        if identity(before) != identity(after) or identity(after) != identity(entry) or not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
            raise UnsafeFile(name)
        return result
    finally:
        os.close(fd)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result


def _safe_directory(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _read_bytes(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UnsafeFile(str(path))
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            piece = os.read(fd, min(65536, remaining))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        result = b"".join(chunks)
        if len(result) > limit:
            raise OverflowError(str(path))
        return result
    finally:
        os.close(fd)


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_bytes(path, MAX_JSON)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError
    return value, raw


def _valid_descriptor(value: object, raw: bytes) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == DESCRIPTOR_FIELDS
        and isinstance(value.get("raw_sha256"), str)
        and HEX64.fullmatch(value["raw_sha256"]) is not None
        and type(value.get("size_bytes")) is int
        and value["size_bytes"] == len(raw)
        and value["raw_sha256"] == _raw_digest(raw)
    )


def _immutable_bundle_snapshot(bundle_root: Path) -> dict[str, bytes] | None:
    """Read one exact immutable bundle without invoking adapter/approval authority."""
    root = Path(bundle_root)
    before = _directory_identity(root)
    adapter_root = root / "adapter"
    if before is None:
        return None
    root_fd = adapter_fd = None
    try:
        root_fd = _open_directory(root)
        root_info = os.fstat(root_fd)
        if (root_info.st_dev, root_info.st_ino) != before:
            return None
        adapter_fd = _open_directory(Path("adapter"), dir_fd=root_fd)
        adapter_info = os.fstat(adapter_fd)
        outer_names = set(os.listdir(root_fd))
        if outer_names != {MANIFEST_NAME, APPROVAL_NAME, SIGNATURE_NAME, "adapter"}:
            return None
        adapter_entry = os.stat("adapter", dir_fd=root_fd, follow_symlinks=False)
        if (adapter_info.st_dev, adapter_info.st_ino, stat.S_IFMT(adapter_info.st_mode)) != (adapter_entry.st_dev, adapter_entry.st_ino, stat.S_IFMT(adapter_entry.st_mode)):
            return None
        manifest_raw = _read_relative(root_fd, MANIFEST_NAME, MAX_JSON)
        manifest = json.loads(manifest_raw.decode("utf-8"), object_pairs_hook=_pairs)
        if not isinstance(manifest, dict):
            return None
        if set(manifest) != MANIFEST_FIELDS or manifest.get("schema_version") != "nomad.agent-evidence.bundle-manifest.v1":
            return None
        core = {key: value for key, value in manifest.items() if key != "bundle_manifest_digest"}
        digest = manifest.get("bundle_manifest_digest")
        if not isinstance(digest, str) or digest != _digest(core) or root.name != "sha256-" + digest:
            return None
        policy = REGISTRY.get((manifest.get("adapter_id"), manifest.get("adapter_version"), manifest.get("adapter_contract_digest")))
        artifacts = manifest.get("adapter_artifacts")
        if policy is None or not isinstance(artifacts, dict) or set(artifacts) != set(policy["artifacts"]):
            return None
        if set(os.listdir(adapter_fd)) != set(policy["artifacts"]):
            return None
        snapshot = {
            MANIFEST_NAME: manifest_raw,
            APPROVAL_NAME: _read_relative(root_fd, APPROVAL_NAME, MAX_JSON),
            SIGNATURE_NAME: _read_relative(root_fd, SIGNATURE_NAME, MAX_SIGNATURE),
        }
        approval = json.loads(snapshot[APPROVAL_NAME].decode("utf-8"), object_pairs_hook=_pairs)
        if not isinstance(approval, dict) or set(approval) != APPROVAL_FIELDS or approval.get("signature_file") != SIGNATURE_NAME:
            return None
        if _digest(approval) != manifest.get("approval_record_digest") or _raw_digest(snapshot[SIGNATURE_NAME]) != manifest.get("approval_signature_raw_digest"):
            return None
        for name in policy["artifacts"]:
            raw = _read_relative(adapter_fd, name, MAX_JSON)
            if not _valid_descriptor(artifacts[name], raw):
                return None
            snapshot["adapter/" + name] = raw
        adapter_after = os.fstat(adapter_fd)
        adapter_entry_after = os.stat("adapter", dir_fd=root_fd, follow_symlinks=False)
        if (adapter_after.st_dev, adapter_after.st_ino) != (adapter_entry_after.st_dev, adapter_entry_after.st_ino):
            return None
    except (FileNotFoundError, UnsafeFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError, ValueError, TypeError, KeyError):
        return None
    finally:
        if adapter_fd is not None:
            os.close(adapter_fd)
        if root_fd is not None:
            os.close(root_fd)
    return snapshot if _directory_identity(root) == before else None


def compare_immutable_bundle(expected_bundle: Path, existing_bundle: Path) -> Verdict:
    """Compare complete immutable bundle bytes; grants no verification authority."""
    expected = _immutable_bundle_snapshot(Path(expected_bundle))
    existing = _immutable_bundle_snapshot(Path(existing_bundle))
    if expected is None or existing is None:
        return Verdict("DIFFERENT", "DIFFERENT")
    return Verdict("IDENTICAL", "IDENTICAL") if expected == existing else Verdict("DIFFERENT", "DIFFERENT")


def _failure(code: str) -> Verdict:
    return Verdict("BLOCKED" if code.startswith("BLOCKED_") else "FAIL", code)


def _valid_index(index: object) -> bool:
    if not isinstance(index, dict) or set(index) != INDEX_FIELDS or index.get("schema_version") != "nomad.agent-evidence.release-index.v1":
        return False
    if (type(index.get("release_sequence")) is not int or index["release_sequence"] < 1
            or not isinstance(index.get("previous_release_index_digest"), str)
            or HEX64.fullmatch(index["previous_release_index_digest"]) is None
            or any(not isinstance(index.get(key), str) for key in INDEX_FIELDS - {"release_sequence"})):
        return False
    core = {key: value for key, value in index.items() if key != "release_index_digest"}
    return index.get("release_index_digest") == _digest(core)


def _verify_release_tree(
    tree_root: Path,
    expected_parent_index: Mapping[str, object] | None,
    adapter_verifier: Callable[[Path, Mapping[str, object]], bool],
    approval_verifier: Callable[[Path, Mapping[str, object]], bool],
) -> Verdict:
    """Internal test/materializer seam. Production CLI never exposes these inputs."""
    try:
        root = Path(tree_root)
        if not _safe_directory(root) or not _safe_directory(root / BUNDLES_NAME):
            return _failure("FAIL_RELEASE_BUNDLE_FILE_POLICY")
        index, _ = _read_json(root / INDEX_NAME)
        if not _valid_index(index):
            return _failure("FAIL_RELEASE_INDEX_SCHEMA")
        bundle_id = index.get("active_bundle_id")
        match = BUNDLE_ID.fullmatch(bundle_id) if isinstance(bundle_id, str) else None
        if match is None:
            return _failure("FAIL_RELEASE_INDEX_BUNDLE")
        bundle_root = root / BUNDLES_NAME / bundle_id
        adapter_root = bundle_root / "adapter"
        if not _safe_directory(bundle_root) or not _safe_directory(adapter_root):
            return _failure("FAIL_RELEASE_BUNDLE_FILE_POLICY")
        outer_names = {entry.name for entry in os.scandir(bundle_root)}
        if outer_names != {MANIFEST_NAME, APPROVAL_NAME, SIGNATURE_NAME, "adapter"}:
            return _failure("FAIL_RELEASE_BUNDLE_LAYOUT")
        manifest, _ = _read_json(bundle_root / MANIFEST_NAME)
        if set(manifest) != MANIFEST_FIELDS or manifest.get("schema_version") != "nomad.agent-evidence.bundle-manifest.v1":
            return _failure("FAIL_RELEASE_BUNDLE_SCHEMA")
        if (any(not isinstance(manifest.get(key), str) for key in MANIFEST_FIELDS - {"adapter_artifacts"})
                or any(HEX64.fullmatch(manifest[key]) is None for key in ("adapter_contract_digest", "evidence_manifest_digest", "approval_record_digest", "approval_signature_raw_digest", "bundle_manifest_digest"))):
            return _failure("FAIL_RELEASE_BUNDLE_SCHEMA")
        manifest_core = {key: value for key, value in manifest.items() if key != "bundle_manifest_digest"}
        if not isinstance(manifest.get("bundle_manifest_digest"), str) or manifest["bundle_manifest_digest"] != _digest(manifest_core) or match.group(1) != manifest["bundle_manifest_digest"]:
            return _failure("FAIL_RELEASE_BUNDLE_DIGEST")
        policy = REGISTRY.get((manifest.get("adapter_id"), manifest.get("adapter_version"), manifest.get("adapter_contract_digest")))
        if policy is None or manifest.get("approval_scope") != policy["approval_scope"]:
            return _failure("FAIL_RELEASE_ADAPTER_POLICY")
        artifacts = manifest.get("adapter_artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != set(policy["artifacts"]):
            return _failure("FAIL_RELEASE_ADAPTER_LAYOUT")
        adapter_names = {entry.name for entry in os.scandir(adapter_root)}
        if adapter_names != set(policy["artifacts"]):
            return _failure("FAIL_RELEASE_ADAPTER_LAYOUT")
        artifact_values: dict[str, dict[str, Any]] = {}
        for name in policy["artifacts"]:
            path = adapter_root / name
            raw = _read_bytes(path, MAX_JSON)
            if not _valid_descriptor(artifacts[name], raw):
                return _failure("FAIL_RELEASE_ARTIFACT_BINDING")
            if name.endswith("evidence-manifest.json"):
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
                if not isinstance(value, dict):
                    return _failure("FAIL_RELEASE_ARTIFACT_BINDING")
                artifact_values[name] = value
        evidence = artifact_values["lifecycle-evidence-manifest.json"]
        if evidence.get("schema_version") != policy["evidence_schema"] or evidence.get("evidence_manifest_digest") != manifest.get("evidence_manifest_digest") or evidence.get("reviewed_version") != manifest.get("reviewed_version"):
            return _failure("FAIL_RELEASE_EVIDENCE_BINDING")
        approval, _ = _read_json(bundle_root / APPROVAL_NAME)
        signature = _read_bytes(bundle_root / SIGNATURE_NAME, MAX_SIGNATURE)
        if set(approval) != APPROVAL_FIELDS or approval.get("schema_version") != policy["approval_schema"] or approval.get("signature_file") != SIGNATURE_NAME:
            return _failure("FAIL_RELEASE_APPROVAL_BINDING")
        if (
            _digest(approval) != manifest.get("approval_record_digest")
            or _raw_digest(signature) != manifest.get("approval_signature_raw_digest")
            or approval.get("evidence_manifest_digest") != manifest.get("evidence_manifest_digest")
            or approval.get("reviewed_version") != manifest.get("reviewed_version")
            or approval.get("scope") != manifest.get("approval_scope")
            or approval.get("trust_root_id") != manifest.get("trust_root_id")
        ):
            return _failure("FAIL_RELEASE_APPROVAL_BINDING")
        repeated = ("bundle_manifest_digest", "adapter_id", "adapter_version", "reviewed_version", "evidence_manifest_digest", "approval_record_digest")
        if any(index.get(key) != manifest.get(key) for key in repeated) or index.get("active_bundle_id") != "sha256-" + manifest["bundle_manifest_digest"]:
            return _failure("FAIL_RELEASE_INDEX_BINDING")
        if expected_parent_index is None:
            if index.get("previous_release_index_digest") != "0" * 64 or index.get("release_sequence") != 1:
                return _failure("BLOCKED_EXPECTED_PARENT_INDEX")
        else:
            parent = dict(expected_parent_index)
            if not _valid_index(parent):
                return _failure("BLOCKED_EXPECTED_PARENT_INDEX")
            if (
                index.get("previous_release_index_digest") != parent["release_index_digest"]
                or type(index.get("release_sequence")) is not int
                or type(parent.get("release_sequence")) is not int
                or index["release_sequence"] != parent["release_sequence"] + 1
                or index.get("active_bundle_id") == parent.get("active_bundle_id")
            ):
                return _failure("BLOCKED_EXPECTED_PARENT_INDEX")
        try:
            if not adapter_verifier(adapter_root, manifest):
                return _failure("FAIL_RELEASE_ADAPTER_VERIFICATION")
            if not approval_verifier(bundle_root, manifest):
                return _failure("BLOCKED_EXTERNAL_APPROVAL_VERIFICATION")
        except CleanupUnconfirmed:
            return _failure("BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED")
        return Verdict("VERIFIED", "VERIFIED_RELEASE_BUNDLE")
    except (FileNotFoundError, UnsafeFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError, ValueError, TypeError, KeyError):
        return _failure("FAIL_RELEASE_BUNDLE_FILE_POLICY")


def _terminate_and_reap(process: subprocess.Popen[bytes], wait_seconds: float = 1.0) -> bool:
    if process.poll() is not None:
        try:
            process.wait(timeout=wait_seconds)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return process.poll() is not None
    try:
        process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        pid = getattr(process, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            return False
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            return False
    try:
        process.wait(timeout=wait_seconds)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.poll() is not None


def _bounded_process(argv: list[str], cwd: Path, limit: int = MAX_GIT_OUTPUT, env: Mapping[str, str] | None = None, timeout_seconds: float = 10) -> tuple[int, bytes]:
    try:
        process = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False, close_fds=True, env=dict(env or {"LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0"}))
    except OSError:
        return 127, b""
    if process.stdout is None:
        return (127 if _terminate_and_reap(process) else 126), b""
    output = bytearray()
    failed = False
    eof = False
    cleanup_ok = True
    result_code = 125
    selector: selectors.BaseSelector | None = None
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while not eof and not failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            events = selector.select(min(0.1, remaining))
            if not events:
                if process.poll() is not None:
                    # A closed child pipe will become readable for EOF.
                    continue
                continue
            try:
                part = os.read(process.stdout.fileno(), min(4096, limit + 1 - len(output)))
            except OSError:
                failed = True
                break
            if not part:
                eof = True
                break
            output.extend(part)
            if len(output) > limit:
                failed = True
        if failed:
            cleanup_ok = _terminate_and_reap(process)
            result_code = 125
        else:
            remaining = max(0.001, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
                result_code = process.returncode
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = _terminate_and_reap(process)
                result_code = 125
    except (OSError, ValueError):
        cleanup_ok = _terminate_and_reap(process)
        result_code = 125
    finally:
        if selector is not None:
            try:
                selector.close()
            except OSError:
                cleanup_ok = False
        try:
            process.stdout.close()
        except OSError:
            cleanup_ok = False
    if process.poll() is None:
        cleanup_ok = _terminate_and_reap(process) and cleanup_ok
    return (result_code if cleanup_ok else 126), bytes(output)


GIT_POLICY = {
    "Darwin": ("/usr/bin/git",),
    "Linux": ("/usr/bin/git",),
}


def _git_executable() -> Path | None:
    for candidate in GIT_POLICY.get(platform.system(), ()):
        path = Path(candidate)
        try:
            resolved = path.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if resolved == path and stat.S_ISREG(info.st_mode) and os.access(resolved, os.X_OK):
            return resolved
    return None


def _git(git: Path, *args: str) -> tuple[int, bytes]:
    code, output = _bounded_process([str(git), *args], REPO_ROOT)
    if code == 126:
        raise CleanupUnconfirmed
    return code, output


def _production_adapter_verifier(adapter_root: Path, manifest: Mapping[str, object]) -> bool:
    python = str(Path(sys.executable).resolve())
    stock = REPO_ROOT / "testkit" / "stock-opencode"
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "LC_ALL": "C", "LANG": "C"}
    commands = (
        [python, str(stock / "verify_certificate.py"), str(adapter_root / "lifecycle-certificate.json")],
        [python, str(stock / "verify_shape_manifest.py"), str(adapter_root / "lifecycle-shape-manifest.json"), str(adapter_root / "lifecycle-certificate.json")],
        [python, str(stock / "verify_evidence_manifest.py"), str(adapter_root / "lifecycle-evidence-manifest.json"), str(adapter_root / "lifecycle-certificate.json"), str(adapter_root / "lifecycle-shape-manifest.json")],
    )
    for command in commands:
        code, output = _bounded_process(command, REPO_ROOT, 4096, env)
        if code == 126:
            raise CleanupUnconfirmed
        if code != 0 or output != b"VERIFIED\n":
            return False
    return True


def _production_approval_verifier(bundle_root: Path, manifest: Mapping[str, object]) -> bool:
    python = str(Path(sys.executable).resolve())
    script = REPO_ROOT / "testkit" / "stock-opencode" / "verify_approval_record.py"
    command = [python, str(script), str(bundle_root / APPROVAL_NAME), str(manifest["evidence_manifest_digest"]), str(manifest["reviewed_version"])]
    code, output = _bounded_process(command, REPO_ROOT, 4096, {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "LC_ALL": "C", "LANG": "C"})
    if code == 126:
        raise CleanupUnconfirmed
    return code == 0 and output == b"VERIFIED\n"


def _load_parent_index(git: Path, parent_oid: str) -> tuple[Verdict | None, Mapping[str, object] | None]:
    object_name = f"{parent_oid}:evidence/agent-releases/{INDEX_NAME}"
    relative = f"evidence/agent-releases/{INDEX_NAME}"
    code, names = _git(git, "ls-tree", "--name-only", parent_oid, "--", relative)
    if code != 0:
        return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), None
    if not names.strip():
        return None, None
    if names.strip() != relative.encode("ascii"):
        return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), None
    code, raw = _git(git, "show", object_name)
    if code != 0:
        return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, DuplicateKey, json.JSONDecodeError):
        return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), None
    return (None, value) if isinstance(value, dict) else (_failure("BLOCKED_EXPECTED_PARENT_INDEX"), None)


def _historical_active_bundles(git: Path, parent_oid: str) -> tuple[Verdict | None, set[str]]:
    relative = f"evidence/agent-releases/{INDEX_NAME}"
    code, commits = _git(git, "log", "--first-parent", "--format=%H", parent_oid, "--", relative)
    if code != 0:
        return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), set()
    result: set[str] = set()
    for raw_oid in commits.splitlines():
        try:
            oid = raw_oid.decode("ascii", "strict")
        except UnicodeDecodeError:
            return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), set()
        if OID.fullmatch(oid) is None:
            return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), set()
        code, raw = _git(git, "show", f"{oid}:{relative}")
        if code != 0:
            return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), set()
        try:
            index = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, DuplicateKey, json.JSONDecodeError):
            return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), set()
        if not _valid_index(index):
            return _failure("BLOCKED_EXPECTED_PARENT_INDEX"), set()
        result.add(index["active_bundle_id"])
    return None, result


def _source_tree_matches(git: Path, source_commit_oid: str) -> bool:
    code, head = _git(git, "rev-parse", "HEAD")
    if code != 0 or head.strip().decode("ascii", "ignore") != source_commit_oid:
        return False
    code, dirty = _git(git, "status", "--porcelain=v1", "--untracked-files=all")
    return code == 0 and not dirty


def _verify_production(expected_parent_oid: str, source_commit_oid: str) -> Verdict:
    if not isinstance(expected_parent_oid, str) or not OID.fullmatch(expected_parent_oid) or not isinstance(source_commit_oid, str) or not OID.fullmatch(source_commit_oid):
        return _failure("BLOCKED_SOURCE_COMMIT_OID")
    git = _git_executable()
    if git is None:
        return _failure("BLOCKED_SOURCE_COMMIT_OID")
    code, fmt = _git(git, "rev-parse", "--show-object-format")
    object_format = fmt.strip()
    wanted_length = 40 if object_format == b"sha1" else 64 if object_format == b"sha256" else 0
    if wanted_length == 0 or len(expected_parent_oid) != wanted_length or len(source_commit_oid) != wanted_length:
        return _failure("BLOCKED_SOURCE_COMMIT_OID")
    for oid in (expected_parent_oid, source_commit_oid):
        code, kind = _git(git, "cat-file", "-t", oid)
        if code != 0 or kind.strip() != b"commit":
            return _failure("BLOCKED_SOURCE_COMMIT_OID")
    if not _source_tree_matches(git, source_commit_oid):
        return _failure("BLOCKED_SOURCE_COMMIT_OID")
    code, parents = _git(git, "rev-list", "--parents", "-n", "1", source_commit_oid)
    if code != 0 or parents.decode("ascii", "ignore").strip().split() != [source_commit_oid, expected_parent_oid]:
        return _failure("BLOCKED_SOURCE_COMMIT_OID")
    parent_error, parent = _load_parent_index(git, expected_parent_oid)
    if parent_error is not None:
        return parent_error
    try:
        proposed, _ = _read_json(RELEASE_ROOT / INDEX_NAME)
    except (FileNotFoundError, UnsafeFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError, ValueError):
        return _failure("FAIL_RELEASE_BUNDLE_FILE_POLICY")
    history_error, historical = _historical_active_bundles(git, expected_parent_oid)
    if history_error is not None:
        return history_error
    if proposed.get("active_bundle_id") in historical:
        return _failure("BLOCKED_EXPECTED_PARENT_INDEX")
    verdict = _verify_release_tree(RELEASE_ROOT, parent, _production_adapter_verifier, _production_approval_verifier)
    if not _source_tree_matches(git, source_commit_oid):
        return _failure("BLOCKED_SOURCE_COMMIT_OID")
    return verdict


def verify_production(expected_parent_oid: str, source_commit_oid: str) -> Verdict:
    try:
        return _verify_production(expected_parent_oid, source_commit_oid)
    except CleanupUnconfirmed:
        return _failure("BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-parent-oid", required=True)
    parser.add_argument("--source-commit-oid", required=True)
    args = parser.parse_args()
    verdict = verify_production(args.expected_parent_oid, args.source_commit_oid)
    stream = sys.stdout if verdict.status == "VERIFIED" else sys.stderr
    stream.write(verdict.code + "\n")
    return 0 if verdict.status == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
