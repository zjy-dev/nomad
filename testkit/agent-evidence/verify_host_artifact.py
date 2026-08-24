#!/usr/bin/env python3
"""Read-only post-link verifier for a candidate Nomad Host artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import threading
import importlib.util
from pathlib import Path
from typing import BinaryIO

SUCCESS = "VERIFIED_HOST_ARTIFACT_SHAPE"
BLOCKED = "BLOCKED_HOST_ARTIFACT_UNVERIFIED"
MANIFEST_SCHEMA = "nomad.nomad-host-artifact.v1"
EXPECTED_SCHEMA = "nomad.nomad-host-expected-build.v1"
MAX_BINARY = 64 * 1024 * 1024
MAX_JSON = 256 * 1024
MAX_TOOL_OUTPUT = 64 * 1024
MANIFEST_FIELDS = {
    "schema_version", "artifact_class", "artifact_basename",
    "artifact_size_bytes", "artifact_raw_sha256", "platform",
    "target_triple", "source_commit_oid", "cargo_lock_raw_sha256",
    "build_profile", "rustc_release", "rustc_commit_hash", "rustc_host",
    "llvm_version", "actual_launch_protocol_version", "embedded_release",
    "macos_codesign", "host_artifact_sequence",
    "previous_host_manifest_digest", "host_manifest_digest",
}
EXPECTED_FIELDS = {
    "schema_version", "source_commit_oid", "cargo_lock_raw_sha256",
    "build_profile", "target_triple", "rustc_release",
    "rustc_commit_hash", "rustc_host", "llvm_version",
    "actual_launch_protocol_version",
}
ADHOC_CODESIGN_FIELDS = {
    "mode", "format", "identifier", "cdhash", "full_cdhash",
    "team_id", "signing_identity",
}
UNAVAILABLE_FIELDS = {"availability", "container_raw_sha256"}

def _load_nomadrel():
    path=Path(__file__).with_name("nomadrel.py");spec=importlib.util.spec_from_file_location("nomad_shared_nomadrel",path)
    if spec is None or spec.loader is None:raise RuntimeError
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module
nomadrel=_load_nomadrel()


class VerifyError(Exception):
    pass


class DuplicateKey(ValueError):
    pass


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise DuplicateKey
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, object], bytes]:
    raw = _read_regular(path, MAX_JSON, require_single_link=True)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except Exception:
        raise VerifyError from None
    if not isinstance(value, dict):
        raise VerifyError
    return value, raw


def _open_regular(path: Path, limit: int, *, require_single_link: bool) -> tuple[BinaryIO, os.stat_result]:
    try:
        if not path.is_absolute() or path.name in ("", ".", ".."):
            raise VerifyError
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        file = os.fdopen(descriptor, "rb", closefd=True)
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_size <= 0
                or details.st_size > limit or (require_single_link and details.st_nlink != 1)):
            file.close()
            raise VerifyError
        return file, details
    except VerifyError:
        raise
    except Exception:
        raise VerifyError from None


def _read_regular(path: Path, limit: int, *, require_single_link: bool) -> bytes:
    file, before = _open_regular(path, limit, require_single_link=require_single_link)
    try:
        raw = file.read(limit + 1)
        after = os.fstat(file.fileno())
        if len(raw) != before.st_size or len(raw) > limit or _identity(before) != _identity(after):
            raise VerifyError
        return raw
    finally:
        file.close()


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _oid(value: object) -> bool:
    return isinstance(value, str) and len(value) in (40, 64) and all(character in "0123456789abcdef" for character in value)


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if json.loads(raw, object_pairs_hook=_pairs) != value:
            raise VerifyError
        return raw
    except VerifyError:
        raise
    except Exception:
        raise VerifyError from None


def _validate_expected(value: dict[str, object]) -> None:
    if (set(value) != EXPECTED_FIELDS or value.get("schema_version") != EXPECTED_SCHEMA
            or not _oid(value.get("source_commit_oid"))
            or not _hex64(value.get("cargo_lock_raw_sha256"))
            or value.get("build_profile") != "release"
            or value.get("target_triple") != "aarch64-apple-darwin"
            or value.get("rustc_host") != "aarch64-apple-darwin"
            or not isinstance(value.get("rustc_release"), str)
            or not _oid(value.get("rustc_commit_hash"))
            or not isinstance(value.get("llvm_version"), str)
            or value.get("actual_launch_protocol_version") != 1):
        raise VerifyError


def _extract_container(binary: bytes):
    try:return nomadrel.extract(binary)
    except nomadrel.ParseError:raise VerifyError from None


def _bounded_tool(argv: list[str], *, timeout: float = 5.0) -> bytes:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={"LC_ALL":"C","LANG":"C"}, close_fds=True)
    output = bytearray()
    failed = False
    def read() -> None:
        nonlocal failed
        stream = process.stdout
        try:
            assert stream is not None
            while True:
                block = stream.read(4096)
                if not block: break
                if len(output) + len(block) > MAX_TOOL_OUTPUT:
                    failed = True; return
                output.extend(block)
        except Exception:
            failed = True
        finally:
            if stream is not None:
                stream.close()
    thread = threading.Thread(target=read); thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=2); failed = True
    thread.join(timeout=2)
    if thread.is_alive():
        process.kill(); process.wait(timeout=2); raise VerifyError
    if failed or process.returncode != 0:
        raise VerifyError
    return bytes(output)


def _codesign(binary_path: Path) -> dict[str, object]:
    tool = Path("/usr/bin/codesign")
    if tool.resolve(strict=True) != tool:
        raise VerifyError
    _bounded_tool([str(tool), "--verify", "--strict", "--verbose=4", str(binary_path)])
    raw = _bounded_tool([str(tool), "-d", "--verbose=4", str(binary_path)])
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise VerifyError from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            raise VerifyError
        values[key] = value
    allowed = {
        "Executable", "Identifier", "Format", "CodeDirectory v",
        "VersionPlatform", "VersionMin", "VersionSDK", "Hash type",
        "CandidateCDHash sha256", "CandidateCDHashFull sha256",
        "Hash choices", "CMSDigest", "CMSDigestType",
        "Executable Segment base", "Executable Segment limit",
        "Executable Segment flags", "Page size", "CDHash",
        "Signature", "Info.plist", "TeamIdentifier",
        "Sealed Resources", "Internal requirements",
    }
    if (set(values) != allowed
            or values["Hash type"] != "sha256 size=32"
            or values["Hash choices"] != "sha256"):
        raise VerifyError
    cdhash, full = values["CandidateCDHash sha256"], values["CandidateCDHashFull sha256"]
    if len(cdhash) != 40 or not all(c in "0123456789abcdef" for c in cdhash) or not _hex64(full):
        raise VerifyError
    reported = Path(values["Executable"])
    try:
        same_executable = (
            reported.is_absolute()
            and reported.name == binary_path.name
            and reported.resolve(strict=True) == binary_path.resolve(strict=True)
            and _identity(os.stat(reported, follow_symlinks=False))
                == _identity(os.stat(binary_path, follow_symlinks=False))
        )
    except OSError:
        raise VerifyError from None
    if (values["Format"] != "Mach-O thin (arm64)"
            or "flags=0x20002(adhoc,linker-signed)" not in values["CodeDirectory v"]
            or values["Signature"] != "adhoc"
            or values["TeamIdentifier"] != "not set"
            or values["Info.plist"] != "not bound"
            or values["Sealed Resources"] != "none"
            or values["Internal requirements"] != "none"
            or values["CDHash"] != cdhash
            or values["CMSDigest"] != full
            or values["CMSDigestType"] != "2"
            or not same_executable):
        raise VerifyError
    return {"mode":"adhoc","format":values["Format"],"identifier":values["Identifier"],"cdhash":cdhash,"full_cdhash":full,"team_id":None,"signing_identity":None}


def verify_host_artifact(binary_path: Path, manifest_path: Path, expected_path: Path) -> None:
    manifest, manifest_raw = _read_json(manifest_path)
    expected, expected_raw = _read_json(expected_path)
    if manifest_raw != _canonical(manifest) or expected_raw != _canonical(expected):
        raise VerifyError
    _validate_expected(expected)
    if (set(manifest) != MANIFEST_FIELDS or manifest.get("schema_version") != MANIFEST_SCHEMA
            or manifest.get("artifact_class") != "candidate-adhoc"):
        raise VerifyError
    core = dict(manifest); digest = core.pop("host_manifest_digest", None)
    if not _hex64(digest) or _sha256(_canonical(core)) != digest:
        raise VerifyError
    binary_file, before = _open_regular(binary_path, MAX_BINARY, require_single_link=True)
    try:
        binary = binary_file.read(MAX_BINARY + 1)
        if len(binary) != before.st_size or len(binary) > MAX_BINARY:
            raise VerifyError
        container = _extract_container(binary)
        if container.availability != "unavailable":
            # Verified embedded-release relation parsing belongs to the later
            # production-developer-id package and is deliberately unreachable
            # from this candidate-only verifier.
            raise VerifyError
        if (manifest.get("artifact_class") != "candidate-adhoc"
                or manifest.get("artifact_basename") != "nomad-host"
                or binary_path.name != "nomad-host"
                or manifest.get("artifact_size_bytes") != len(binary)
                or manifest.get("artifact_raw_sha256") != _sha256(binary)
                or manifest.get("platform") != "darwin-arm64"
                or manifest.get("target_triple") != expected["target_triple"]
                or manifest.get("source_commit_oid") != expected["source_commit_oid"]
                or manifest.get("cargo_lock_raw_sha256") != expected["cargo_lock_raw_sha256"]
                or manifest.get("build_profile") != expected["build_profile"]
                or any(manifest.get(field) != expected[field] for field in ("rustc_release","rustc_commit_hash","rustc_host","llvm_version","actual_launch_protocol_version"))):
            raise VerifyError
        embedded = manifest.get("embedded_release")
        if not isinstance(embedded, dict) or set(embedded) != UNAVAILABLE_FIELDS or embedded.get("availability") != "unavailable" or embedded.get("container_raw_sha256") != _sha256(container.raw):
            raise VerifyError
        if manifest.get("macos_codesign") != _codesign(binary_path):
            raise VerifyError
        sequence = manifest.get("host_artifact_sequence")
        previous = manifest.get("previous_host_manifest_digest")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence != 1 or previous != "0" * 64:
            raise VerifyError
        after = os.fstat(binary_file.fileno())
        current = os.stat(binary_path, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(before) != _identity(current):
            raise VerifyError
    finally:
        binary_file.close()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("binary", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("expected", type=Path)
    try:
        arguments = parser.parse_args()
        paths = []
        for supplied in (arguments.binary, arguments.manifest, arguments.expected):
            path = supplied if supplied.is_absolute() else Path.cwd() / supplied
            paths.append(path.absolute())
        verify_host_artifact(*paths)
        print(SUCCESS)
        return 0
    except (VerifyError, OSError, SystemExit):
        print(BLOCKED, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
