#!/usr/bin/env python3
"""Read-only B0c-4 local checkout-after-CAS mechanics verifier."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import selectors
import signal
import stat
import subprocess
import sys
import time
import weakref
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1].resolve()
SUCCESS = "VERIFIED_HOST_POST_CAS_CHECKOUT_MECHANICS"
BLOCKED = "BLOCKED_HOST_POST_CAS_CHECKOUT_MECHANICS"
REF = "refs/heads/production/nomad-host"
MAX_JSON = 512 * 1024
MAX_BINARY = 64 * 1024 * 1024
MAX_GIT = 1024 * 1024
HOST_SCHEMA = "nomad.nomad-host-artifact.v1"
HOST_FIELDS = {
    "schema_version", "artifact_class", "artifact_basename",
    "artifact_size_bytes", "artifact_raw_sha256", "platform",
    "target_triple", "source_commit_oid", "cargo_lock_raw_sha256",
    "build_profile", "rustc_release", "rustc_commit_hash",
    "rustc_host", "llvm_version", "actual_launch_protocol_version",
    "embedded_release", "macos_codesign", "host_artifact_sequence",
    "previous_host_manifest_digest", "host_manifest_digest",
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


publication = _load("nomad_b0c3_for_post_cas", HERE / "verify_host_publication_request.py")
lineage_contract = _load("nomad_b0c2_for_post_cas", HERE / "verify_host_lineage.py")


class Error(Exception):
    pass


class CleanupUnconfirmed(Error):
    pass


class _OpaquePostCasCheckout:
    __slots__ = (
        "host_manifest_digest", "artifact_raw_sha256", "release_index_digest",
        "bundle_manifest_digest", "evidence_manifest_digest",
        "host_approval_digest", "candidate_id", "host_artifact_sequence",
        "publication_sequence", "operation",
        "source_commit_oid", "proposed_commit_oid", "protected_ref",
        "active_index_digest", "binary_path", "__weakref__",
    )
    def __init__(self, *_: object) -> None:
        raise TypeError("private verified checkout")
    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("frozen verified checkout")
    def __reduce__(self) -> object:
        raise TypeError("private verified checkout")
    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


class _VerifiedPostCasCheckout(_OpaquePostCasCheckout):
    __slots__ = ()


class _TestPostCasCheckout(_OpaquePostCasCheckout):
    __slots__ = ()


_PRODUCTION_RESULTS = weakref.WeakKeyDictionary()
_TEST_RESULTS = weakref.WeakKeyDictionary()


def _snapshot(value):
    return tuple(getattr(value, name) for name in _OpaquePostCasCheckout.__slots__
                 if name != "__weakref__")
def _test_checkout_result(values):
    result = object.__new__(_TestPostCasCheckout)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    _TEST_RESULTS[result] = _snapshot(result)
    return result


def _is_verified_production(value) -> bool:
    return (type(value) is _VerifiedPostCasCheckout
            and _PRODUCTION_RESULTS.get(value) is not None
            and _PRODUCTION_RESULTS.get(value) == _snapshot(value))


def _is_verified_test(value) -> bool:
    return (type(value) is _TestPostCasCheckout and _TEST_RESULTS.get(value) is not None
            and _TEST_RESULTS.get(value) == _snapshot(value))


def _issue_test_checkout(values):
    return _test_checkout_result(values)


def _terminate(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except (OSError, TypeError):
                return False
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.poll() is not None


def _bounded(argv: tuple[str, ...], cwd: Path, limit: int) -> tuple[int, bytes]:
    env = {"LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        process = subprocess.Popen(list(argv), cwd=str(cwd), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   shell=False, close_fds=True, env=env)
    except OSError:
        return 127, b""
    if process.stdout is None:
        if not _terminate(process):
            raise CleanupUnconfirmed
        return 127, b""
    output = bytearray()
    selector = None
    failed = False
    cleanup = True
    code = 125
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10
        while not failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            events = selector.select(min(0.1, remaining))
            if not events:
                continue
            part = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(output)))
            if not part:
                break
            output.extend(part)
            if len(output) > limit:
                failed = True
        if failed:
            cleanup = _terminate(process)
        else:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                code = process.returncode
            except (OSError, subprocess.TimeoutExpired):
                cleanup = _terminate(process)
    except (OSError, ValueError):
        cleanup = _terminate(process)
    finally:
        if selector is not None:
            try:
                selector.close()
            except OSError:
                cleanup = False
        try:
            process.stdout.close()
        except OSError:
            cleanup = False
    if process.poll() is None:
        cleanup = _terminate(process) and cleanup
    if not cleanup:
        raise CleanupUnconfirmed
    return code, bytes(output)


def _git_path() -> Path:
    if platform.system() not in ("Darwin", "Linux"):
        raise Error
    path = Path("/usr/bin/git")
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError:
        raise Error from None
    if resolved != path or not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise Error
    return path


def _root_identity(root: Path) -> tuple[int, int]:
    try:
        if root.resolve(strict=True) != root:
            raise Error
        info = os.stat(root, follow_symlinks=False)
    except OSError:
        raise Error from None
    if not stat.S_ISDIR(info.st_mode):
        raise Error
    return info.st_dev, info.st_ino


def _one_line(raw: bytes, value: str) -> bool:
    return raw == value.encode("ascii") + b"\n"


def _allowed(args: tuple[str, ...], request) -> bool:
    proposed = request["proposed_commit_oid"]
    source = request["source_commit_oid"]
    parent = request["expected_parent_oid"]
    candidate_root = f"evidence/host-artifacts/candidates/{request['candidate_id']}"
    fixed = {
        ("rev-parse", "--show-toplevel"),
        ("rev-parse", "--show-object-format"),
        ("show-ref", "--verify", "--hash", REF),
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
        ("cat-file", "-t", proposed),
        ("cat-file", "-t", parent),
        ("cat-file", "-t", source),
        ("rev-list", "--parents", "-n", "1", proposed),
        ("diff-tree", "--no-commit-id", "--name-only", "-r", "-z", parent, proposed),
        ("ls-tree", "-r", "-z", "--full-tree", proposed, "--",
         "evidence/host-artifacts/current.json", candidate_root),
    }
    if args in fixed:
        return True
    blob_objects = {f"{proposed}:evidence/host-artifacts/current.json"}
    blob_objects.update(f"{proposed}:{candidate_root}/{name}" for name in (
        "nomad-host", "host-manifest.json", "expected-build.json",
        "evidence-release-reference.json",
    ))
    return len(args) == 3 and args[:2] == ("cat-file", "blob") and args[2] in blob_objects


def _call(git: Path, root: Path, request, runner, args: tuple[str, ...], limit: int = MAX_GIT) -> bytes:
    if not _allowed(args, request):
        raise Error
    code, output = runner((str(git), "-C", str(root), *args), root, limit)
    if code != 0:
        raise Error
    return output


def _observe(git: Path, root: Path, request, runner) -> tuple[int, int]:
    identity = _root_identity(root)
    if _call(git, root, request, runner, ("rev-parse", "--show-toplevel")) != os.fsencode(root) + b"\n":
        raise Error
    if _call(git, root, request, runner, ("rev-parse", "--show-object-format")) != request["repository_object_format"].encode() + b"\n":
        raise Error
    proposed = request["proposed_commit_oid"]
    if not _one_line(_call(git, root, request, runner, ("show-ref", "--verify", "--hash", REF)), proposed):
        raise Error
    if not _one_line(_call(git, root, request, runner, ("rev-parse", "HEAD")), proposed):
        raise Error
    if _call(git, root, request, runner, ("status", "--porcelain=v1", "--untracked-files=all")):
        raise Error
    for oid in (request["expected_parent_oid"], proposed, request["source_commit_oid"]):
        if _call(git, root, request, runner, ("cat-file", "-t", oid)) != b"commit\n":
            raise Error
    parents = f"{proposed} {request['expected_parent_oid']}"
    if not _one_line(_call(git, root, request, runner, ("rev-list", "--parents", "-n", "1", proposed)), parents):
        raise Error
    return identity


def _tree_records(raw: bytes, fmt: str, expected: dict[str, str]) -> dict[str, str]:
    if not raw.endswith(b"\0"):
        raise Error
    records = raw[:-1].split(b"\0")
    if len(records) != len(expected):
        raise Error
    result = {}
    oid_len = 40 if fmt == "sha1" else 64
    for record in records:
        if record.count(b"\t") != 1:
            raise Error
        header, raw_path = record.split(b"\t")
        parts = header.split(b" ")
        if len(parts) != 3:
            raise Error
        try:
            mode, kind, oid = (part.decode("ascii", "strict") for part in parts)
            path = raw_path.decode("ascii", "strict")
        except UnicodeDecodeError:
            raise Error from None
        if (kind != "blob" or path in result or path not in expected
                or mode != expected[path] or len(oid) != oid_len
                or any(c not in "0123456789abcdef" for c in oid)):
            raise Error
        result[path] = oid
    if set(result) != set(expected):
        raise Error
    return result


def _changed_paths(raw: bytes, expected: set[str]) -> None:
    if not raw.endswith(b"\0"):
        raise Error
    try:
        paths = [item.decode("ascii", "strict") for item in raw[:-1].split(b"\0")]
    except UnicodeDecodeError:
        raise Error from None
    if len(paths) != len(set(paths)) or set(paths) != expected:
        raise Error


def _blob_oid(raw: bytes, fmt: str) -> str:
    algorithm = hashlib.sha1 if fmt == "sha1" else hashlib.sha256
    return algorithm(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _json(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=publication.pairs)
        if not isinstance(value, dict) or raw != publication.canonical(value):
            raise Error
    except Error:
        raise
    except Exception:
        raise Error
    return value


def _verify_semantics(blobs: dict[str, bytes], request, lineage) -> tuple[dict, dict]:
    candidate_root = f"evidence/host-artifacts/candidates/{request['candidate_id']}"
    active = _json(blobs["evidence/host-artifacts/current.json"])
    if set(active) != lineage_contract.ACTIVE_FIELDS or active.get("schema_version") != lineage_contract.ACTIVE_SCHEMA:
        raise Error
    active_core = dict(active)
    active_digest = active_core.pop("active_index_digest", None)
    if not publication.hex64(active_digest) or active_digest != lineage_contract._digest(active_core):
        raise Error
    binary = blobs[f"{candidate_root}/nomad-host"]
    expected_active = {
        "operation": request["operation"],
        "active_candidate_id": request["candidate_id"],
        "host_manifest_digest": request["host_manifest_digest"],
        "artifact_raw_sha256": hashlib.sha256(binary).hexdigest(),
        "host_artifact_sequence": lineage["host_artifact_sequence"],
        "source_commit_oid": request["source_commit_oid"],
        "expected_parent_oid": request["expected_parent_oid"],
        "active_index_digest": lineage["active_index_digest"],
    }
    if any(active.get(key) != value for key, value in expected_active.items()):
        raise Error
    host = _json(blobs[f"{candidate_root}/host-manifest.json"])
    if set(host) != HOST_FIELDS or host.get("schema_version") != HOST_SCHEMA:
        raise Error
    host_core = dict(host)
    host_digest = host_core.pop("host_manifest_digest", None)
    if not publication.hex64(host_digest) or host_digest != hashlib.sha256(publication.canonical(host_core)).hexdigest():
        raise Error
    expected_host = {
        "artifact_class": "production-developer-id",
        "artifact_basename": "nomad-host",
        "artifact_size_bytes": len(binary),
        "artifact_raw_sha256": hashlib.sha256(binary).hexdigest(),
        "source_commit_oid": request["source_commit_oid"],
        "host_manifest_digest": request["host_manifest_digest"],
    }
    if any(host.get(key) != value for key, value in expected_host.items()):
        raise Error
    host_sequence = host.get("host_artifact_sequence")
    active_sequence = lineage["host_artifact_sequence"]
    if (type(host_sequence) is not int or host_sequence <= 0
            or (request["operation"] == "forward" and host_sequence != active_sequence)
            or (request["operation"] == "rollback" and host_sequence >= active_sequence)):
        raise Error
    embedded = host.get("embedded_release")
    if (not isinstance(embedded, dict) or embedded.get("availability") != "verified"
            or active.get("embedded_release_index_digest") != embedded.get("release_index_digest")
            or active.get("bundle_manifest_digest") != embedded.get("bundle_manifest_digest")
            or active.get("evidence_manifest_digest") != embedded.get("evidence_manifest_digest")):
        raise Error
    return active, host


def _verify_checkout_values(paths, root: Path, git: Path, runner):
    try:
        snapshots = publication._read_and_verify(*paths)
        request, tree, lineage = snapshots.request, snapshots.tree, snapshots.lineage
        if request["protected_ref"] != REF or root.resolve(strict=True) != root:
            raise Error
        before = _observe(git, root, request, runner)
        candidate_root = f"evidence/host-artifacts/candidates/{request['candidate_id']}"
        expected = {
            "evidence/host-artifacts/current.json": "100644",
            f"{candidate_root}/nomad-host": "100755",
            f"{candidate_root}/host-manifest.json": "100644",
            f"{candidate_root}/expected-build.json": "100644",
            f"{candidate_root}/evidence-release-reference.json": "100644",
        }
        changed = (set(expected) if request["operation"] == "forward"
                   else {"evidence/host-artifacts/current.json"})
        diff_args = (
            "diff-tree", "--no-commit-id", "--name-only", "-r", "-z",
            request["expected_parent_oid"], request["proposed_commit_oid"],
        )
        _changed_paths(_call(git, root, request, runner, diff_args), changed)
        args = ("ls-tree", "-r", "-z", "--full-tree", request["proposed_commit_oid"], "--",
                "evidence/host-artifacts/current.json", candidate_root)
        records = _tree_records(_call(git, root, request, runner, args), request["repository_object_format"], expected)
        blobs = {}
        entries = []
        for path in sorted(expected):
            limit = MAX_BINARY if path.endswith("/nomad-host") else MAX_JSON
            raw = _call(git, root, request, runner, ("cat-file", "blob", f"{request['proposed_commit_oid']}:{path}"), limit)
            if not raw or _blob_oid(raw, request["repository_object_format"]) != records[path]:
                raise Error
            blobs[path] = raw
            entries.append({"path": path, "kind": "regular", "mode": expected[path],
                            "size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest()})
        expected_entries = [{key: entry[key] for key in sorted(publication.ENTRY_FIELDS)} for entry in tree["tree_entries"]]
        observed_entries = [{key: entry[key] for key in sorted(publication.ENTRY_FIELDS)} for entry in entries]
        if observed_entries != expected_entries:
            raise Error
        paths_only = [entry["path"] for entry in entries]
        if (publication.digest(observed_entries) != request["proposed_tree_digest"]
                or publication.digest(paths_only) != request["proposed_tree_paths_digest"]
                or publication.digest([entry for entry in observed_entries if entry["path"].startswith(candidate_root + "/")]) != lineage["candidate_tree_digest"]):
            raise Error
        raw_bindings = {
            "active_index": "evidence/host-artifacts/current.json",
            "candidate_manifest": f"{candidate_root}/host-manifest.json",
            "expected_build": f"{candidate_root}/expected-build.json",
            "binary": f"{candidate_root}/nomad-host",
            "reference": f"{candidate_root}/evidence-release-reference.json",
        }
        for prefix, path in raw_bindings.items():
            size_name = "active_index_raw_size_bytes" if prefix == "active_index" else f"{prefix}_size_bytes"
            if hashlib.sha256(blobs[path]).hexdigest() != lineage[f"{prefix}_raw_sha256"] or len(blobs[path]) != lineage[size_name]:
                raise Error
        active, host = _verify_semantics(blobs, request, lineage)
        if _observe(git, root, request, runner) != before:
            raise Error
        embedded = host["embedded_release"]
        return {
            "host_manifest_digest": host["host_manifest_digest"],
            "artifact_raw_sha256": host["artifact_raw_sha256"],
            "release_index_digest": embedded["release_index_digest"],
            "bundle_manifest_digest": embedded["bundle_manifest_digest"],
            "evidence_manifest_digest": embedded["evidence_manifest_digest"],
            "host_approval_digest": active["host_approval_digest"],
            "candidate_id": request["candidate_id"],
            "host_artifact_sequence": host["host_artifact_sequence"],
            "publication_sequence": lineage["host_artifact_sequence"],
            "operation": request["operation"],
            "source_commit_oid": request["source_commit_oid"],
            "proposed_commit_oid": request["proposed_commit_oid"],
            "protected_ref": request["protected_ref"],
            "active_index_digest": lineage["active_index_digest"],
            "binary_path": root / candidate_root / "nomad-host",
        }
    except publication.Error:
        raise Error from None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        raise Error from None


def _verify_with_environment(paths, root: Path, git: Path, runner=_bounded):
    return _test_checkout_result(_verify_checkout_values(paths, root, git, runner))


def verify(*paths: Path):
    values = _verify_checkout_values(paths, REPO_ROOT, _git_path(), _bounded)
    result = object.__new__(_VerifiedPostCasCheckout)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    _PRODUCTION_RESULTS[result] = _snapshot(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    for name in ("request", "tree", "source", "lineage"):
        parser.add_argument(name, type=Path)
    try:
        values = parser.parse_args()
        paths = [(path if path.is_absolute() else Path.cwd() / path).absolute()
                 for path in (values.request, values.tree, values.source, values.lineage)]
        verify(*paths)
        print(SUCCESS)
        return 0
    except (Error, CleanupUnconfirmed, SystemExit):
        print(BLOCKED, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
