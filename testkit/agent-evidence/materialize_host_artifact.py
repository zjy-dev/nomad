#!/usr/bin/env python3
"""Materialize an immutable, inactive Nomad Host artifact candidate."""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import platform
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
SUCCESS = "CANDIDATE_HOST_ARTIFACT_TREE"
BLOCKED = "BLOCKED_HOST_ARTIFACT_CANDIDATE"
PROPOSAL_INCOMPLETE = "BLOCKED_HOST_PROPOSAL_INCOMPLETE"
REFERENCE_SCHEMA = "nomad.host-evidence-release-reference.v1"
PROPOSAL_SCHEMA = "nomad.host-artifact-proposed-index.v1"
MAX_BINARY = 64 * 1024 * 1024
MAX_JSON = 256 * 1024
ZERO = "0" * 64


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load("nomad_host_artifact_verifier_for_materializer", HERE / "verify_host_artifact.py")
artifact_fs = _load("nomad_artifact_fs_primitives", HERE / "artifact_fs.py")


class MaterializeError(Exception):
    pass


@dataclass(frozen=True)
class MaterializeResult:
    status: str
    code: str


def _blocked() -> MaterializeResult:
    return MaterializeResult("BLOCKED", BLOCKED)


def _canonical(value: object) -> bytes:
    return verifier._canonical(value)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_input(path: Path, limit: int, mode: int | None = None) -> tuple[bytes, os.stat_result]:
    file, before = verifier._open_regular(path, limit, require_single_link=True)
    try:
        raw = file.read(limit + 1)
        after = os.fstat(file.fileno())
        current = os.stat(path, follow_symlinks=False)
        if (len(raw) != before.st_size or len(raw) > limit
                or verifier._identity(before) != verifier._identity(after)
                or verifier._identity(before) != verifier._identity(current)):
            raise MaterializeError
        if mode is not None and stat.S_IMODE(before.st_mode) != mode:
            raise MaterializeError
        return raw, before
    except MaterializeError:
        raise
    except Exception:
        raise MaterializeError from None
    finally:
        file.close()


def _json_exact(path: Path) -> tuple[dict[str, object], bytes]:
    value, raw = verifier._read_json(path)
    if raw != _canonical(value):
        raise MaterializeError
    return value, raw


def _reference(path: Path) -> tuple[dict[str, object], bytes]:
    value, raw = _json_exact(path)
    if set(value) != {"schema_version", "availability"} or value != {
        "schema_version": REFERENCE_SCHEMA, "availability": "unavailable"
    }:
        raise MaterializeError
    return value, raw


def _safe_directory(path: Path) -> bool:
    try:
        info = os.lstat(path)
        return (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid == os.geteuid() and not info.st_mode & 0o022)
    except OSError:
        return False


def _write_binary(path: Path, raw: bytes) -> None:
    artifact_fs.write_exclusive(path, raw, mode=0o700, limit=MAX_BINARY)


def _tree_bytes(directory: Path) -> dict[str, tuple[bytes, int]]:
    expected = {"nomad-host", "host-manifest.json", "expected-build.json", "evidence-release-reference.json"}
    directory_info = os.lstat(directory)
    if (not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode)
            or stat.S_IMODE(directory_info.st_mode) != 0o700
            or directory_info.st_uid != os.geteuid()):
        raise MaterializeError
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        names = set(os.listdir(descriptor))
        if names != expected:
            raise MaterializeError
        result = {}
        for name in sorted(names):
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise MaterializeError
                raw = os.read(fd, MAX_BINARY + 1)
                if os.read(fd, 1) or len(raw) != info.st_size:
                    raise MaterializeError
                result[name] = (raw, stat.S_IMODE(info.st_mode))
            finally:
                os.close(fd)
        return result
    finally:
        os.close(descriptor)


def _same_tree(left: Path, right: Path) -> bool:
    try:
        return _tree_bytes(left) == _tree_bytes(right)
    except (OSError, MaterializeError):
        return False


def _publish_no_replace(
    source: Path, target: Path, *, system: str | None = None, machine: str | None = None,
    library_factory: Callable[..., Any] = ctypes.CDLL,
) -> str:
    system, machine = system or platform.system(), machine or platform.machine()
    source_info = os.lstat(source)
    if not stat.S_ISDIR(source_info.st_mode) or stat.S_ISLNK(source_info.st_mode):
        raise MaterializeError
    try:
        library = library_factory(None, use_errno=True)
        ctypes.set_errno(0)
        old, new = os.fsencode(source.absolute()), os.fsencode(target.absolute())
        if system == "Darwin" and machine == "arm64":
            function = library.renamex_np
            function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(old, new, ctypes.c_uint(0x4))
        elif system == "Linux" and machine in ("x86_64", "amd64"):
            function = library.syscall; function.restype = ctypes.c_long
            result = function(316, -100, old, -100, new, 1)
        else:
            raise MaterializeError
        error = ctypes.get_errno()
    except (AttributeError, OSError, TypeError, ValueError):
        raise MaterializeError from None
    if result == 0:
        current = os.lstat(target)
        if ((current.st_dev, current.st_ino) != (source_info.st_dev, source_info.st_ino)
                or not stat.S_ISDIR(current.st_mode) or source.exists()):
            raise MaterializeError
        artifact_fs.fsync_dir(target.parent)
        return "PUBLISHED_INACTIVE"
    if error == errno.EEXIST and _same_tree(source, target):
        return "ALREADY_IDENTICAL"
    raise MaterializeError


def _proposal(manifest: dict[str, object], reference_raw: bytes) -> dict[str, object]:
    digest = manifest["host_manifest_digest"]
    core = {
        "schema_version": PROPOSAL_SCHEMA,
        "candidate_id": "sha256-" + str(digest),
        "host_manifest_digest": digest,
        "host_artifact_sequence": manifest["host_artifact_sequence"],
        "previous_host_manifest_digest": manifest["previous_host_manifest_digest"],
        "evidence_release_reference_digest": _digest(reference_raw),
    }
    return {**core, "proposal_digest": _digest(_canonical(core))}


def _write_or_compare(path: Path, raw: bytes, mode: int) -> None:
    try:
        if mode == 0o700:
            _write_binary(path, raw)
        else:
            artifact_fs.write_exclusive(path, raw, mode=0o600, limit=MAX_JSON)
    except FileExistsError:
        existing, info = _read_input(path, max(MAX_BINARY, MAX_JSON), mode)
        if existing != raw or stat.S_IMODE(info.st_mode) != mode:
            raise MaterializeError


def materialize_host_candidate(
    binary: Path, manifest_path: Path, expected_path: Path, reference_path: Path, root: Path,
    *, publisher: Callable[[Path, Path], str] | None = None,
) -> MaterializeResult:
    try:
        if not _safe_directory(root) or not _safe_directory(root / "candidates"):
            raise MaterializeError
        verifier.verify_host_artifact(binary, manifest_path, expected_path)
        manifest, manifest_raw = _json_exact(manifest_path)
        _, expected_raw = _json_exact(expected_path)
        _, reference_raw = _reference(reference_path)
        binary_raw, binary_info = _read_input(binary, MAX_BINARY)
        if not binary_info.st_mode & stat.S_IXUSR or binary_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise MaterializeError
        if (manifest.get("artifact_class") != "candidate-adhoc"
                or manifest.get("embedded_release", {}).get("availability") != "unavailable"
                or manifest.get("artifact_raw_sha256") != _digest(binary_raw)):
            raise MaterializeError
        candidate_id = "sha256-" + str(manifest["host_manifest_digest"])
        if len(candidate_id) != 71 or any(character not in "0123456789abcdef" for character in candidate_id[7:]):
            raise MaterializeError
        staging = Path(tempfile.mkdtemp(prefix=".candidate-", dir=root))
        os.chmod(staging, 0o700)
        artifact_fs.write_exclusive(staging / "host-manifest.json", manifest_raw, mode=0o600, limit=MAX_JSON)
        artifact_fs.write_exclusive(staging / "expected-build.json", expected_raw, mode=0o600, limit=MAX_JSON)
        artifact_fs.write_exclusive(staging / "evidence-release-reference.json", reference_raw, mode=0o600, limit=MAX_JSON)
        _write_binary(staging / "nomad-host", binary_raw)
        artifact_fs.fsync_dir(staging)
        target = root / "candidates" / candidate_id
        publish = publisher or (lambda source, destination: _publish_no_replace(source, destination))
        outcome = publish(staging, target)
        if outcome not in ("PUBLISHED_INACTIVE", "ALREADY_IDENTICAL"):
            raise MaterializeError
        proposal_raw = _canonical(_proposal(manifest, reference_raw))
        try:
            _write_or_compare(root / "current.json.proposed", proposal_raw, 0o600)
            artifact_fs.fsync_dir(root)
        except Exception:
            return MaterializeResult("BLOCKED", PROPOSAL_INCOMPLETE)
        return MaterializeResult("CANDIDATE", SUCCESS)
    except Exception:
        return _blocked()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("binary", type=Path); parser.add_argument("manifest", type=Path)
    parser.add_argument("expected", type=Path); parser.add_argument("reference", type=Path)
    parser.add_argument("root", type=Path)
    try:
        values = parser.parse_args()
        result = materialize_host_candidate(*(
            (path if path.is_absolute() else (Path.cwd() / path)).absolute()
            for path in (values.binary, values.manifest, values.expected, values.reference, values.root)
        ))
    except SystemExit:
        result = _blocked()
    stream = sys.stdout if result.code == SUCCESS else sys.stderr
    stream.write(result.code + "\n")
    return 0 if result.code == SUCCESS else 1


if __name__ == "__main__":
    raise SystemExit(main())
