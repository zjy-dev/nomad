#!/usr/bin/env python3
"""Installed, loopback-only paired-browser diagnostic.

This runner is deliberately not an acceptance runner. It starts the exact
installed bundle through the launcher's diagnostic-only API, exercises the
real Chrome Pair/View/Refresh/Revoke journey with a page-scoped phone
emulation, and emits content-free mechanical evidence.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid


SCHEMA = "nomad.installed-loopback.paired-browser-diagnostic.v1"
BROWSER_SCHEMA = "nomad.installed-loopback.browser-diagnostic.v1"
MODE = "installed-loopback-diagnostic"
LAUNCHER_MODE = "remote-loopback-diagnostic"
EVIDENCE_NAME = "installed-loopback-diagnostic.json"
EXPECTED_ROLES = [
    "relay-host", "relay-device", "opencode", "product-host",
    "desktop-gateway", "join-gateway", "https-ingress",
]
PROVIDER_NAMES = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY",
}
FORBIDDEN_SUCCESS_VALUE = re.compile(r"PASS|READY|ACCEPTED", re.IGNORECASE)
MAX_BROWSER_RUNNER_BYTES = 2 * 1024 * 1024
MAX_LAUNCHER_OUTPUT_BYTES = 256 * 1024
MAX_UV_BYTES = 64 * 1024 * 1024
CANARY = b"TEST_ONLY_INSTALLED_LOOPBACK_NO_PROVIDER_CALLS"
INSTALL_STATUS_SCHEMA = "nomad.web-companion.install-status.v1"
DIAGNOSTIC_STATE_SCHEMA = "nomad.web-companion.diagnostic-state.v1"
SUPPORTED_BUNDLE_SCHEMAS = {
    "nomad.web-companion.prebuilt.v1",
    "nomad.web-companion.prebuilt.v2",
}
ALLOWED_TOOL_CANDIDATES = {
    "openssl": (Path("/usr/bin/openssl"), Path("/opt/homebrew/bin/openssl")),
}
PINNED_UV_CANDIDATE = Path("/opt/homebrew/bin/uv")
PINNED_UV_RESOLVED = Path("/opt/homebrew/Cellar/uv/0.11.14/bin/uv")
PINNED_UV_SHA256 = "61309a24163341fb1ed68845a041f8764b91ecd41b516704b935ad76e2a8db62"
PINNED_UV_VERSION = "uv 0.11.14 (Homebrew 2026-05-12 aarch64-apple-darwin)"
EXPECTED_GOOGLE_CHROME_EXECUTABLE = Path(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
DEFAULT_STABLE_PORTS = [18089, 14173, 4096, 14174, 18090, 18091, 18092, 18093]
SAFE_STABLE_ERROR_CODES = frozenset("""
AGENT_HEALTH_TIMEOUT AGENT_LOOPBACK_PORT_UNAVAILABLE AGENT_START_FAILED
BUNDLE_DIGEST_MISMATCH CLI_ARGUMENT_INVALID DIAGNOSTIC_BUNDLE_BINDING_MISMATCH
DIAGNOSTIC_CLEANUP_INCOMPLETE DIAGNOSTIC_IDENTITY_ROOT_EXISTS
DIAGNOSTIC_PUBLIC_ORIGIN_NOT_LOOPBACK DIAGNOSTIC_START_INPUTS_INCOMPLETE
DUPLICATE_LOOPBACK_PORT DESKTOP_GATEWAY_NOT_READY HOST_BOOTSTRAP_INVALID HOST_READY_INVALID
INGRESS_READY_INVALID JOIN_GATEWAY_NOT_READY OFFICIAL_SESSION_NOT_READY
RELAY_ROLE_INVALID RELAY_ROLE_LIVE_PROBE_FAILED RELAY_ROLE_TIMEOUT RELAY_NOT_READY
SERVICE_TIMEOUT HOST_IDENTITY_AUTH_REQUIRED HOST_IDENTITY_CORRUPT
HOST_IDENTITY_KEYCHAIN_LOCKED HOST_IDENTITY_UNAVAILABLE HOST_IDENTITY_USER_DENIED
HTTPS_LISTEN_RELEASE_TIMEOUT INVALID_FD_SECRET INVALID_INHERITED_FD
INVALID_PROVIDER_CREDENTIAL LOOPBACK_PORT_IN_USE REMOTE_HTTPS_LISTEN_IN_USE
REMOTE_HTTPS_LISTEN_INVALID REMOTE_PORT_INVALID REMOTE_PUBLIC_ORIGIN_INVALID
REMOTE_TLS_CERT_FD_INVALID REMOTE_TLS_CERT_INVALID REMOTE_TLS_KEY_FD_INVALID
RUNNING_BUNDLE_BINDING_MISMATCH RUNTIME_PORT_IN_USE SELECTED_BUNDLE_BINDING_INVALID
TLS_FD_INVALID UNSAFE_COMMAND_JOURNAL UNSAFE_DIAGNOSTIC_IDENTITY_ROOT
UNSAFE_DIAGNOSTIC_LOG_PATH UNSAFE_PRODUCT_HOST_SOCKET
UNSAFE_PRODUCT_HOST_SOCKET_DIRECTORY
""".split())


class DiagnosticError(RuntimeError):
    pass


class StableCliError(DiagnosticError):
    def __init__(self, operation_code: str, safe_code: str) -> None:
        self.operation_code = operation_code
        self.safe_code = safe_code
        super().__init__(f"{operation_code}_{safe_code}")


def _mode(value: str) -> str:
    if value != MODE:
        raise argparse.ArgumentTypeError(f"mode must be {MODE}")
    return value


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, type=_mode)
    parser.add_argument("--installed-bundle", required=True, type=Path)
    parser.add_argument("--chrome", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    return parser.parse_args(arguments)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def canonical_manifest_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _strict_json(raw: bytes, code: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DiagnosticError(code) from error


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode),
        info.st_size, info.st_mtime_ns,
    )


def verify_installed_bundle(bundle: Path) -> tuple[Path, Path]:
    lexical = bundle.absolute()
    try:
        resolved = bundle.resolve(strict=True)
        bundle_info = lexical.lstat()
    except OSError as error:
        raise DiagnosticError("INSTALLED_BUNDLE_PATH_INVALID") from error
    if (
        lexical != resolved or stat.S_ISLNK(bundle_info.st_mode)
        or not stat.S_ISDIR(bundle_info.st_mode)
        or bundle_info.st_uid != os.geteuid()
        or stat.S_IMODE(bundle_info.st_mode) != 0o755
    ):
        raise DiagnosticError("INSTALLED_BUNDLE_PATH_NOT_EXACT")
    if re.fullmatch(r"[0-9a-f]{64}", resolved.name) is None:
        raise DiagnosticError("INSTALLED_BUNDLE_PATH_NOT_DIGEST_ADDRESSED")
    if resolved.parent.name != "bundles":
        raise DiagnosticError("INSTALLED_BUNDLE_PATH_INVALID")
    home = resolved.parent.parent
    launcher = home / "bin" / "nomad-web"
    try:
        launcher_resolved = launcher.resolve(strict=True)
        launcher_info = launcher.lstat()
    except OSError as error:
        raise DiagnosticError("INSTALLED_STABLE_LAUNCHER_MISSING") from error
    if (
        not launcher.is_absolute() or launcher_resolved != launcher
        or launcher.parent != home / "bin"
        or not stat.S_ISREG(launcher_info.st_mode)
        or stat.S_ISLNK(launcher_info.st_mode)
        or launcher_info.st_uid != os.geteuid()
        or stat.S_IMODE(launcher_info.st_mode) != 0o755
    ):
        raise DiagnosticError("INSTALLED_STABLE_LAUNCHER_UNSAFE")
    return resolved, launcher


def clean_launcher_env() -> dict[str, str]:
    return {
        "HOME": os.fspath(Path.home()),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "NO_PROXY": "127.0.0.1",
        "no_proxy": "127.0.0.1",
    }


def verify_google_chrome_executable(chrome: Path) -> Path:
    lexical = chrome.absolute()
    try:
        resolved = chrome.resolve(strict=True)
        info = lexical.lstat()
    except OSError as error:
        raise DiagnosticError("GOOGLE_CHROME_MISSING") from error
    mode = stat.S_IMODE(info.st_mode)
    if (
        not chrome.is_absolute()
        or lexical != resolved
        or resolved != EXPECTED_GOOGLE_CHROME_EXECUTABLE.resolve(strict=True)
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or not mode & 0o111
        or mode & 0o022
    ):
        raise DiagnosticError("GOOGLE_CHROME_UNSAFE")
    return resolved


def resolve_allowed_tool(name: str) -> Path:
    candidates = ALLOWED_TOOL_CANDIDATES.get(name)
    if candidates is None:
        raise DiagnosticError("TOOL_NOT_ALLOWLISTED")
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.lstat()
            ancestors = (resolved.parent, *resolved.parent.parents)
            ancestor_info = [ancestor.lstat() for ancestor in ancestors]
        except OSError:
            continue
        if (
            not resolved.is_absolute() or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or bool(stat.S_IMODE(info.st_mode) & 0o022)
            or not os.access(resolved, os.X_OK)
            or any(
                not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                or item.st_uid not in {0, os.geteuid()}
                or bool(stat.S_IMODE(item.st_mode) & 0o022)
                for item in ancestor_info
            )
        ):
            continue
        return resolved
    raise DiagnosticError(f"{name.upper()}_TOOL_UNSAFE_OR_MISSING")


def _uv_source_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def snapshot_pinned_uv(root: Path, env: Mapping[str, str]) -> Path:
    try:
        root_info = root.lstat()
        if (
            not root.is_absolute()
            or not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise DiagnosticError("UV_TOOL_SNAPSHOT_ROOT_UNSAFE")
        if PINNED_UV_CANDIDATE.resolve(strict=True) != PINNED_UV_RESOLVED:
            raise DiagnosticError("UV_TOOL_UNSAFE_OR_MISSING")
        source_fd = os.open(
            PINNED_UV_RESOLVED,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, RuntimeError) as error:
        raise DiagnosticError("UV_TOOL_UNSAFE_OR_MISSING") from error
    try:
        before = os.fstat(source_fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or not mode & 0o111 or mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_UV_BYTES
        ):
            raise DiagnosticError("UV_TOOL_UNSAFE_OR_MISSING")
        chunks: list[bytes] = []
        remaining = MAX_UV_BYTES + 1
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(source_fd)
        if (
            len(raw) != before.st_size
            or len(raw) > MAX_UV_BYTES
            or _uv_source_identity(before) != _uv_source_identity(after)
            or hashlib.sha256(raw).hexdigest() != PINNED_UV_SHA256
        ):
            raise DiagnosticError("UV_TOOL_IDENTITY_MISMATCH")
    finally:
        os.close(source_fd)

    snapshot = root / "uv-pinned"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        snapshot_fd = os.open(snapshot, flags, 0o500)
        try:
            os.fchmod(snapshot_fd, 0o500)
            offset = 0
            while offset < len(raw):
                written = os.write(snapshot_fd, raw[offset:])
                if written <= 0:
                    raise DiagnosticError("UV_TOOL_SNAPSHOT_FAILED")
                offset += written
            os.fsync(snapshot_fd)
        finally:
            os.close(snapshot_fd)
        snapshot_info = snapshot.lstat()
        if (
            not stat.S_ISREG(snapshot_info.st_mode)
            or stat.S_ISLNK(snapshot_info.st_mode)
            or snapshot_info.st_uid != os.geteuid()
            or snapshot_info.st_nlink != 1
            or stat.S_IMODE(snapshot_info.st_mode) != 0o500
            or snapshot_info.st_size != len(raw)
        ):
            raise DiagnosticError("UV_TOOL_SNAPSHOT_FAILED")
        version = subprocess.run(
            [str(snapshot), "--no-config", "--no-python-downloads", "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(env),
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiagnosticError("UV_TOOL_SNAPSHOT_FAILED") from error
    if (
        version.returncode != 0 or version.stderr != b""
        or version.stdout != PINNED_UV_VERSION.encode("ascii") + b"\n"
    ):
        raise DiagnosticError("UV_TOOL_VERSION_MISMATCH")
    return snapshot


def _run_stable_json(
    command: list[str], code: str, *, env: Mapping[str, str],
    input_bytes: bytes | None = None, pass_fds: tuple[int, ...] = (),
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command, input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=dict(env), pass_fds=pass_fds,
            timeout=timeout_seconds, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiagnosticError(code) from error
    if result.returncode != 0:
        raise StableCliError(code, _safe_stable_error_code(result.stdout))
    if (
        result.stderr != b"" or not 0 < len(result.stdout) <= MAX_LAUNCHER_OUTPUT_BYTES
    ):
        raise DiagnosticError(code)
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError(code) from error
    if (
        not isinstance(value, dict)
        or result.stdout != canonical_json(value) + b"\n"
    ):
        raise DiagnosticError(code)
    return value


def _safe_stable_error_code(raw: bytes) -> str:
    if not 0 < len(raw) <= MAX_LAUNCHER_OUTPUT_BYTES:
        return "UNKNOWN"
    try:
        value = _strict_json(raw, "STABLE_ERROR_INVALID")
    except DiagnosticError:
        return "UNKNOWN"
    if not isinstance(value, dict) or raw != canonical_json(value) + b"\n":
        return "UNKNOWN"
    allowed_key_sets = (
        {"schema", "state", "production_ready", "error"},
        {"schema", "state", "production_ready", "code"},
        {"schema", "state", "production_ready", "error", "next_step"},
        {"schema", "state", "production_ready", "code", "next_step"},
    )
    if (
        set(value) not in allowed_key_sets
        or value.get("schema") != "nomad.web-companion.error.v1"
        or value.get("state") != "BLOCKED"
        or value.get("production_ready") is not False
    ):
        return "UNKNOWN"
    candidate = value.get("error", value.get("code"))
    if (
        not isinstance(candidate, str) or len(candidate) > 128
        or re.fullmatch(r"[A-Z0-9_]+", candidate) is None
        or candidate not in SAFE_STABLE_ERROR_CODES
    ):
        return "UNKNOWN"
    return candidate


def ensure_stopped_status(launcher: Path, env: Mapping[str, str]) -> None:
    status = _run_stable_json(
        [str(launcher), "--json", "status"],
        "LAUNCHER_DIAGNOSTIC_STATUS_FAILED", env=env,
    )
    if status.get("state") != "STOPPED":
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_NOT_STOPPED")


def ensure_exact_current_install(
    bundle: Path, launcher: Path, env: Mapping[str, str],
) -> None:
    installed = _run_stable_json(
        [str(launcher), "--json", "install-status"],
        "INSTALLED_SELECTOR_VERIFICATION_FAILED", env=env,
    )
    if (
        installed.get("schema") != INSTALL_STATUS_SCHEMA
        or installed.get("state") != "INSTALLED"
        or installed.get("current_bundle_digest") != bundle.name
    ):
        raise DiagnosticError("INSTALLED_BUNDLE_NOT_CURRENT")


def reserve_loopback_ports(count: int) -> list[int]:
    listeners: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        ports = [int(listener.getsockname()[1]) for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()
    if len(ports) != count or len(set(ports)) != count:
        raise DiagnosticError("LOOPBACK_PORT_RESERVATION_FAILED")
    return ports


def ensure_artifact_dir(path: Path) -> Path:
    if not path.is_absolute():
        raise DiagnosticError("ARTIFACT_DIRECTORY_MUST_BE_ABSOLUTE")
    absolute = path
    if absolute == Path("/"):
        raise DiagnosticError("ARTIFACT_DIRECTORY_UNSAFE")

    try:
        target_info = absolute.lstat()
    except FileNotFoundError:
        target_info = None
    if target_info is not None and (
        not stat.S_ISDIR(target_info.st_mode)
        or stat.S_ISLNK(target_info.st_mode)
        or target_info.st_uid != os.geteuid()
        or stat.S_IMODE(target_info.st_mode) != 0o700
    ):
        raise DiagnosticError("ARTIFACT_DIRECTORY_UNSAFE")

    try:
        parent = absolute.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise DiagnosticError("ARTIFACT_DIRECTORY_PARENT_MISSING") from error
    for ancestor in (parent, *parent.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError as error:
            raise DiagnosticError("ARTIFACT_DIRECTORY_PARENT_MISSING") from error
        mode = stat.S_IMODE(info.st_mode)
        writable = mode & 0o022
        root_owned_sticky = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or (writable and not root_owned_sticky)
        ):
            raise DiagnosticError("ARTIFACT_DIRECTORY_ANCESTOR_UNSAFE")

    resolved = parent / absolute.name
    if target_info is None:
        os.mkdir(resolved, 0o700)
    info = resolved.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DiagnosticError("ARTIFACT_DIRECTORY_UNSAFE")
    return resolved


def _run_checked(command: list[str], code: str, *, input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            command, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiagnosticError(code) from error
    if result.returncode != 0:
        raise DiagnosticError(code)
    return result.stdout


def generate_loopback_tls(root: Path, openssl: Path) -> tuple[Path, Path, str]:
    cert, key = root / "leaf.pem", root / "leaf-key.pem"
    _run_checked(
        [
            str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        "LOOPBACK_TLS_GENERATION_FAILED",
    )
    os.chmod(cert, 0o600); os.chmod(key, 0o600)
    san = _run_checked(
        [str(openssl), "x509", "-in", str(cert), "-noout", "-text"],
        "LOOPBACK_TLS_SAN_INVALID",
    ).decode("ascii", "strict")
    lines = san.splitlines()
    headings = [index for index, line in enumerate(lines) if "X509v3 Subject Alternative Name:" in line]
    if len(headings) != 1 or headings[0] + 1 >= len(lines):
        raise DiagnosticError("LOOPBACK_TLS_SAN_INVALID")
    san_entries = [item.strip() for item in lines[headings[0] + 1].split(",") if item.strip()]
    if san_entries != ["IP Address:127.0.0.1"]:
        raise DiagnosticError("LOOPBACK_TLS_SAN_INVALID")
    public = _run_checked(
        [str(openssl), "x509", "-in", str(cert), "-pubkey", "-noout"],
        "LOOPBACK_TLS_PUBLIC_KEY_FAILED",
    )
    key_public = _run_checked(
        [str(openssl), "pkey", "-in", str(key), "-pubout"],
        "LOOPBACK_TLS_KEY_INVALID",
    )
    if public != key_public:
        raise DiagnosticError("LOOPBACK_TLS_KEY_MISMATCH")
    der = _run_checked(
        [str(openssl), "pkey", "-pubin", "-outform", "DER"],
        "LOOPBACK_TLS_SPKI_FAILED", input_bytes=public,
    )
    pin = base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")
    if len(base64.b64decode(pin, validate=True)) != 32:
        raise DiagnosticError("LOOPBACK_TLS_SPKI_INVALID")
    return cert, key, pin


def _literal_loopback_url(value: Any, *, https: bool | None = None) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    expected_scheme = "https" if https else "http" if https is False else parsed.scheme
    return (
        parsed.scheme == expected_scheme and parsed.hostname == "127.0.0.1"
        and parsed.username is None and parsed.password is None and port is not None
        and parsed.netloc == f"127.0.0.1:{port}"
    )


def validate_launcher_state(
    state: Mapping[str, Any], bundle_digest: str, public_port: int,
) -> None:
    if (
        state.get("schema") != DIAGNOSTIC_STATE_SCHEMA
        or state.get("mode") != LAUNCHER_MODE
        or state.get("diagnostic_only") is not True
        or state.get("accepted_eligible") is not False
        or state.get("identity_scope") != "diagnostic-ephemeral-local"
        or state.get("tls_scope") != "self-signed-spki-diagnostic"
        or state.get("network_scope") != "loopback_diagnostic"
        or state.get("production_external") is not False
        or state.get("pairing_ready") is not True
        or state.get("remote_mailbox_ready") is not True
        or state.get("bundle_digest") != bundle_digest
        or not _literal_loopback_url(state.get("desktop_url"), https=False)
        or not _literal_loopback_url(state.get("pairing_public_origin"), https=True)
        or not _literal_loopback_url(state.get("agent_origin"), https=False)
        or re.fullmatch(r"[0-9a-f]{64}", str(state.get("run_id"))) is None
        or not isinstance(state.get("logs_dir"), str)
    ):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_STATE_INVALID")
    state_ports = [
        state.get(name) for name in (
            "relay_port", "gateway_port", "agent_port",
            "join_gateway_port", "relay_host_v2_port",
            "relay_device_v2_port", "relay_admin_port",
            "relay_device_v1_port",
        )
    ]
    if (
        any(type(port) is not int or not 1024 <= port <= 65535 for port in state_ports)
        or len(set(state_ports + [public_port])) != 9
        or urlsplit(str(state["pairing_public_origin"])).port != public_port
    ):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PORTS_INVALID")
    processes = state.get("processes")
    if not isinstance(processes, list) or [item.get("name") for item in processes] != EXPECTED_ROLES:
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_TOPOLOGY_INVALID")
    if any(
        not isinstance(item.get("pid"), int) or item["pid"] <= 1
        or not isinstance(item.get("identity"), str) or not item["identity"]
        for item in processes
    ):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PROCESS_INVALID")
    gates = state.get("external_gates")
    expected_gates = {"external_topology", "provider_e3", "physical_phone", "writes"}
    if (
        not isinstance(gates, list) or len(gates) != len(expected_gates)
        or {item.get("gate") for item in gates if isinstance(item, dict)} != expected_gates
        or any(not isinstance(item, dict) or item.get("status") != "NOT_RUN" for item in gates)
    ):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_GATES_INVALID")
    if "_initial_prompt_dispatch" in state:
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PROVIDER_DISPATCH_INVALID")


def launcher_ports(state: Mapping[str, Any], public_port: int) -> list[int]:
    return [
        int(state[name]) for name in (
            "relay_port", "gateway_port", "agent_port",
            "join_gateway_port", "relay_host_v2_port",
            "relay_device_v2_port", "relay_admin_port",
            "relay_device_v1_port",
        )
    ] + [public_port]


def validate_running_status(
    status: Mapping[str, Any], bundle_digest: str, public_port: int,
) -> None:
    if (
        status.get("schema") != DIAGNOSTIC_STATE_SCHEMA
        or status.get("mode") != LAUNCHER_MODE
        or status.get("state") != "RUNNING"
        or status.get("diagnostic_only") is not True
        or status.get("accepted_eligible") is not False
        or status.get("identity_scope") != "diagnostic-ephemeral-local"
        or status.get("tls_scope") != "self-signed-spki-diagnostic"
        or status.get("network_scope") != "loopback_diagnostic"
        or status.get("production_external") is not False
        or status.get("pairing_ready") is not True
        or status.get("remote_mailbox_ready") is not True
        or status.get("bundle_digest") != bundle_digest
        or not _literal_loopback_url(status.get("desktop_url"), https=False)
        or not _literal_loopback_url(status.get("pairing_public_origin"), https=True)
        or not _literal_loopback_url(status.get("agent_origin"), https=False)
        or status.get("lifecycle_coordinator") is not None
    ):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNNING_STATUS_INVALID")
    if urlsplit(str(status["pairing_public_origin"])).port != public_port:
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNNING_STATUS_INVALID")
    processes = status.get("processes")
    if (
        not isinstance(processes, list)
        or [item.get("name") for item in processes] != EXPECTED_ROLES
    ):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNNING_STATUS_INVALID")
    pids: list[int] = []
    for item in processes:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "pid", "alive"}
            or not isinstance(item.get("pid"), int)
            or item["pid"] <= 1
            or item.get("alive") is not True
        ):
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNNING_STATUS_INVALID")
        pids.append(item["pid"])
    if len(set(pids)) != len(EXPECTED_ROLES):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNNING_STATUS_INVALID")


def ensure_running_status(
    launcher: Path, env: Mapping[str, str], bundle_digest: str, public_port: int,
) -> None:
    status = _run_stable_json(
        [str(launcher), "--json", "status"],
        "LAUNCHER_DIAGNOSTIC_STATUS_FAILED", env=env,
    )
    validate_running_status(status, bundle_digest, public_port)


def _read_browser_runner(
    bundle: Path, expected_root_identity: tuple[int, int, int, int, int, int] | None = None,
) -> tuple[bytes, str]:
    relative = "testkit/remote-v2/run_m3e_desktop_browser.py"
    path = bundle / relative
    manifest_path = bundle / "manifest.json"
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    root_before = bundle.lstat()
    if expected_root_identity is not None and _file_identity(root_before) != expected_root_identity:
        raise DiagnosticError("INSTALLED_BUNDLE_REPLACED")
    manifest_fd = os.open(manifest_path, flags)
    descriptor = os.open(path, flags)
    try:
        manifest_before = os.fstat(manifest_fd)
        runner_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(manifest_before.st_mode)
            or manifest_before.st_size <= 0 or manifest_before.st_size > 256 * 1024
            or not stat.S_ISREG(runner_before.st_mode)
            or not 0 < runner_before.st_size <= MAX_BROWSER_RUNNER_BYTES
            or manifest_before.st_uid != os.geteuid() or manifest_before.st_nlink != 1
            or stat.S_IMODE(manifest_before.st_mode) != 0o644
            or runner_before.st_uid != os.geteuid() or runner_before.st_nlink != 1
        ):
            raise DiagnosticError("BROWSER_RUNNER_FILE_POLICY_INVALID")
        manifest_raw = os.read(manifest_fd, manifest_before.st_size + 1)
        raw = os.read(descriptor, runner_before.st_size + 1)
        manifest_after = os.fstat(manifest_fd)
        runner_after = os.fstat(descriptor)
    finally:
        os.close(manifest_fd)
        os.close(descriptor)
    root_after = bundle.lstat()
    if (
        _file_identity(root_before) != _file_identity(root_after)
        or _file_identity(manifest_before) != _file_identity(manifest_after)
        or _file_identity(runner_before) != _file_identity(runner_after)
        or _file_identity(manifest_after) != _file_identity(manifest_path.lstat())
        or _file_identity(runner_after) != _file_identity(path.lstat())
    ):
        raise DiagnosticError("BROWSER_RUNNER_READ_RACE")
    if len(raw) != runner_before.st_size or len(manifest_raw) != manifest_before.st_size:
        raise DiagnosticError("BROWSER_RUNNER_READ_INVALID")
    manifest = _strict_json(manifest_raw, "BROWSER_RUNNER_MANIFEST_INVALID")
    if not isinstance(manifest, dict) or manifest_raw != canonical_manifest_json(manifest) + b"\n":
        raise DiagnosticError("BROWSER_RUNNER_MANIFEST_INVALID")
    digest = manifest.get("bundle_digest")
    core = dict(manifest); core.pop("bundle_digest", None)
    if (
        manifest.get("schema") not in SUPPORTED_BUNDLE_SCHEMAS
        or digest != bundle.name
        or re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
        or hashlib.sha256(canonical_manifest_json(core)).hexdigest() != digest
    ):
        raise DiagnosticError("BROWSER_RUNNER_MANIFEST_DIGEST_INVALID")
    entries = manifest.get("files")
    matching = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == relative] if isinstance(entries, list) else []
    raw_digest = hashlib.sha256(raw).hexdigest()
    if (
        len(matching) != 1 or set(matching[0]) != {"path", "size_bytes", "raw_sha256", "mode"}
        or matching[0].get("size_bytes") != len(raw)
        or matching[0].get("raw_sha256") != raw_digest
        or matching[0].get("mode") != f"{stat.S_IMODE(runner_before.st_mode):04o}"
    ):
        raise DiagnosticError("BROWSER_RUNNER_MANIFEST_MISMATCH")
    return raw, raw_digest


def run_browser(
    bundle: Path, chrome: Path, desktop_url: str, public_origin: str,
    profile: Path, spki_pin: str, env: Mapping[str, str], uv: Path,
    expected_bundle_identity: tuple[int, int, int, int, int, int] | None = None,
) -> dict[str, Any]:
    raw, digest = _read_browser_runner(bundle, expected_bundle_identity)
    wrapper = (
        "import hashlib,json,sys;raw=sys.stdin.buffer.read();"
        "ns={'__name__':'installed_loopback_embedded','__file__':'<installed-browser-runner>',"
        "'__package__':None,'__runner_raw_sha256__':hashlib.sha256(raw).hexdigest()};"
        "exec(compile(raw,'<installed-browser-runner>','exec'),ns,ns);"
        "args=ns['parse_args']();error_type=ns['BrowserEvidenceError'];\n"
        "try:\n value=ns['run'](args,_installed_loopback_phone_emulation=True)\n"
        "except Exception as error:\n"
        " value={'schema':ns['LOOPBACK_DIAGNOSTIC_SCHEMA'],"
        "'runner_raw_sha256':ns['_runner_source_digest'](),'status':'BLOCK',"
        "'code':str(error) if isinstance(error,error_type) else type(error).__name__,"
        "'diagnostics':error.diagnostics if isinstance(error,error_type) else {},"
        "'content_free':True};exit_code=2\n"
        "else:\n exit_code=0\n"
        "print(json.dumps(value,sort_keys=True,separators=(',',':')));"
        "raise SystemExit(exit_code)"
    )
    command = [
        str(uv), "--no-config", "--no-python-downloads",
        "run", "--isolated", "--no-project", "--no-env-file",
        "--with", "playwright==1.62.0", "python", "-I", "-B",
        "-c", wrapper, "--desktop-url", desktop_url, "--public-origin", public_origin,
        "--profile", str(profile), "--chrome", str(chrome),
        "--timeout-ms", "20000", "--diagnostic-spki-sha256", spki_pin,
    ]
    process: subprocess.Popen[bytes] | None = None
    stdout = b""
    stderr = b""
    execution_error: DiagnosticError | None = None
    cleanup_error: DiagnosticError | None = None
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=dict(env), start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(raw, timeout=150)
        except subprocess.TimeoutExpired as error:
            execution_error = DiagnosticError("BROWSER_DIAGNOSTIC_EXECUTION_FAILED")
            execution_error.__cause__ = error
    except OSError as error:
        execution_error = DiagnosticError("BROWSER_DIAGNOSTIC_EXECUTION_FAILED")
        execution_error.__cause__ = error
    finally:
        if process is not None:
            try:
                cleanup_browser_process(process, profile)
            except DiagnosticError as error:
                cleanup_error = error
    if cleanup_error is not None:
        raise cleanup_error from execution_error
    if execution_error is not None:
        raise execution_error
    if process is None:
        raise DiagnosticError("BROWSER_DIAGNOSTIC_EXECUTION_FAILED")
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    scan_content_free(result.stdout + result.stderr)
    try:
        value = json.loads(result.stdout.decode("utf-8").strip().splitlines()[-1])
    except (UnicodeDecodeError, json.JSONDecodeError, IndexError) as error:
        raise DiagnosticError("BROWSER_DIAGNOSTIC_OUTPUT_INVALID") from error
    if result.returncode != 0:
        browser_code = value.get("code") if isinstance(value, dict) else None
        if (
            value.get("schema") == BROWSER_SCHEMA
            and value.get("status") == "BLOCK"
            and value.get("runner_raw_sha256") == digest
            and value.get("content_free") is True
            and isinstance(browser_code, str)
            and re.fullmatch(r"[a-z][a-z0-9_]{0,127}", browser_code)
        ):
            raise DiagnosticError(
                f"BROWSER_DIAGNOSTIC_BLOCK_{browser_code.upper()}"
            )
        raise DiagnosticError("BROWSER_DIAGNOSTIC_CONTRACT_INVALID")
    if (
        value.get("schema") != BROWSER_SCHEMA
        or value.get("runner_raw_sha256") != digest
        or value.get("status") != "DIAGNOSTIC_COMPLETE"
        or value.get("content_free") is not True
        or value.get("https", {}).get("ignore_https_errors") is not False
        or value.get("https", {}).get("spki_allowlist_count") != 1
        or value.get("browser", {}).get("page_modes") != ["desktop", "phone-emulation"]
        or value.get("write_command_post_count") != 0
    ):
        raise DiagnosticError("BROWSER_DIAGNOSTIC_CONTRACT_INVALID")
    actions = value.get("journey", {}).get("actions")
    if not isinstance(actions, dict) or any(actions.get(name) != "NOT_RUN" for name in ("reply", "deny", "stop")):
        raise DiagnosticError("BROWSER_DIAGNOSTIC_WRITES_INVALID")
    return value


def _profile_process_lines(profile: Path) -> list[bytes]:
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,command="], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_SCAN_FAILED") from error
    if result.returncode != 0 or result.stderr != b"":
        raise DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_SCAN_FAILED")
    marker = os.fsencode(str(profile))
    return [line for line in result.stdout.splitlines() if marker in line]


def cleanup_browser_process(process: subprocess.Popen[bytes], profile: Path) -> None:
    if not isinstance(process.pid, int) or process.pid <= 1:
        raise DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_GROUP_INVALID")

    def _kill_group(signum: signal.Signals) -> None:
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        except PermissionError as error:
            raise DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_GROUP_INVALID") from error

    _kill_group(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill_group(signal.SIGKILL)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_LEAK") from error
    leaks = _profile_process_lines(profile)
    if leaks:
        _kill_group(signal.SIGKILL)
        for _ in range(20):
            time.sleep(0.1)
            leaks = _profile_process_lines(profile)
            if not leaks:
                break
        if leaks:
            raise DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_LEAK")


def command_journal_path(home: Path, run_id: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
        raise DiagnosticError("COMMAND_JOURNAL_PATH_INVALID")
    alias = hashlib.sha256(f"journal:{run_id}".encode()).hexdigest()[:24]
    return home / "run" / f"command-{alias}.sqlite3"


def assert_command_journal_empty(home: Path, state: Mapping[str, Any]) -> None:
    run_id = state.get("run_id")
    if not isinstance(run_id, str):
        raise DiagnosticError("COMMAND_JOURNAL_PATH_INVALID")
    path = command_journal_path(home, run_id)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DiagnosticError("COMMAND_JOURNAL_READ_FAILED") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise DiagnosticError("COMMAND_JOURNAL_FILE_POLICY_INVALID")
        sidecars: list[tuple[Path, tuple[int, int, int, int, int, int]]] = []
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if os.path.lexists(sidecar):
                sidecar_info = sidecar.lstat()
                if (
                    not stat.S_ISREG(sidecar_info.st_mode) or stat.S_ISLNK(sidecar_info.st_mode)
                    or sidecar_info.st_uid != os.geteuid()
                    or stat.S_IMODE(sidecar_info.st_mode) != 0o600
                ):
                    raise DiagnosticError("COMMAND_JOURNAL_FILE_POLICY_INVALID")
                sidecars.append((sidecar, _file_identity(sidecar_info)))
        uri = path.as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            row = connection.execute("SELECT COUNT(*) FROM commands").fetchone()
        finally:
            connection.close()
        after = os.fstat(descriptor)
    except (sqlite3.Error, OSError) as error:
        raise DiagnosticError("COMMAND_JOURNAL_READ_FAILED") from error
    finally:
        os.close(descriptor)
    if (
        _file_identity(before) != _file_identity(after)
        or _file_identity(after) != _file_identity(path.lstat())
        or any(
            not os.path.lexists(sidecar)
            or _file_identity(sidecar.lstat()) != identity
            for sidecar, identity in sidecars
        )
        or row != (0,)
    ):
        raise DiagnosticError("HOST_WRITE_COMMAND_DETECTED")


def assert_processes_stopped(state: Mapping[str, Any]) -> None:
    processes = state.get("processes")
    if not isinstance(processes, list):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
    for item in processes:
        pid = item.get("pid") if isinstance(item, dict) else None
        if not isinstance(pid, int):
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        except PermissionError as error:
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID") from error
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PROCESS_LEAK")


def _product_socket_path(home: Path, run_id: str) -> Path:
    suffix = hashlib.sha256(
        f"{home.resolve(strict=True)}:{os.geteuid()}".encode()
    ).hexdigest()[:16]
    return Path("/private/tmp") / f"nomad-web-{suffix}-{run_id[:16]}" / "product-host.sock"


def assert_no_product_socket_roots(home: Path) -> None:
    suffix = hashlib.sha256(
        f"{home.resolve(strict=True)}:{os.geteuid()}".encode()
    ).hexdigest()[:16]
    if any(Path("/private/tmp").glob(f"nomad-web-{suffix}-*")):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_SOCKET_LEAK")


def assert_no_bundle_processes(bundle: Path) -> None:
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,command="], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PROCESS_SCAN_FAILED") from error
    if result.returncode != 0 or result.stderr != b"":
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PROCESS_SCAN_FAILED")
    prefixes = tuple(
        os.fsencode(str(bundle / name) + "/")
        for name in ("bin", "runtime", "agent", "gateway")
    )
    if any(any(prefix in line for prefix in prefixes) for line in result.stdout.splitlines()):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PROCESS_LEAK")


def snapshot_runtime_entries(home: Path) -> dict[str, frozenset[str] | None]:
    snapshot: dict[str, frozenset[str] | None] = {}
    for name in ("run", "logs"):
        directory = home / name
        if not os.path.lexists(directory):
            snapshot[name] = None
            continue
        try:
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or bool(stat.S_IMODE(info.st_mode) & 0o022)
            ):
                raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNTIME_ROOT_UNSAFE")
            snapshot[name] = frozenset(entry.name for entry in directory.iterdir())
        except OSError as error:
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_RUNTIME_ROOT_UNSAFE") from error
    return snapshot


def assert_no_new_owned_runtime_entries(
    home: Path, before: Mapping[str, frozenset[str] | None],
) -> None:
    if set(before) != {"run", "logs"}:
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED")
    for name in ("run", "logs"):
        directory = home / name
        if not os.path.lexists(directory):
            continue
        try:
            info = directory.lstat()
            prior = before[name]
            if (
                not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or bool(stat.S_IMODE(info.st_mode) & 0o022)
                or prior is None and stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise DiagnosticError("LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED")
            current = {entry.name: entry for entry in directory.iterdir()}
        except OSError as error:
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED") from error
        for entry_name in set(current) - set(() if prior is None else prior):
            try:
                info = current[entry_name].lstat()
            except OSError as error:
                raise DiagnosticError("LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED") from error
            if info.st_uid == os.geteuid():
                raise DiagnosticError("LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED")


def assert_ports_released(ports: list[int], timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        listening = False
        for port in ports:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.2)
            try:
                result = probe.connect_ex(("127.0.0.1", port))
            finally:
                probe.close()
            if result == 0:
                listening = True
                break
            if result != errno.ECONNREFUSED:
                raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PORT_PROBE_FAILED")
        if not listening:
            return
        if time.monotonic() >= deadline:
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_PORT_LEAK")
        time.sleep(0.05)


def assert_cleanup_verified(
    home: Path, state: Mapping[str, Any], ports: list[int],
    temporary_root: Path, artifact_dir: Path,
) -> None:
    run_id = state.get("run_id")
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
    if os.path.lexists(home / "run" / "status.json"):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_STATE_LEAK")
    socket_path = _product_socket_path(home, run_id)
    if os.path.lexists(socket_path) or os.path.lexists(socket_path.parent):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_SOCKET_LEAK")
    run_root = home / "run"
    residue = [
        run_root / f"diagnostic-host-identity-{run_id}",
        run_root / f"agent-runtime-{run_id}",
    ]
    logs_dir = Path(str(state.get("logs_dir", "")))
    if logs_dir != home / "logs":
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
    processes = state.get("processes")
    if not isinstance(processes, list):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
    for item in processes:
        if not isinstance(item, dict) or not isinstance(item.get("log"), str):
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
        log = Path(item["log"])
        if log.parent != logs_dir or run_id not in log.name:
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_INVALID")
        residue.append(log)
    if any(os.path.lexists(path) for path in residue):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_FILE_LEAK")
    if logs_dir.is_dir() and any(run_id in path.name for path in logs_dir.iterdir()):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_LOG_LEAK")
    if os.path.lexists(temporary_root):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_TLS_PROFILE_LEAK")
    if list(artifact_dir.iterdir()):
        raise DiagnosticError("ARTIFACT_DIRECTORY_NOT_EMPTY")
    assert_processes_stopped(state)
    assert_no_bundle_processes(home / "bundles" / str(state.get("bundle_digest")))
    assert_ports_released(ports)


def assert_failed_start_cleanup(
    home: Path, bundle: Path, ports: list[int], temporary_root: Path,
    artifact_dir: Path,
    runtime_entries_before: Mapping[str, frozenset[str] | None],
) -> None:
    if os.path.lexists(home / "run" / "status.json"):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_STATE_LEAK")
    assert_no_product_socket_roots(home)
    if os.path.lexists(temporary_root):
        raise DiagnosticError("LAUNCHER_DIAGNOSTIC_TLS_PROFILE_LEAK")
    if list(artifact_dir.iterdir()):
        raise DiagnosticError("ARTIFACT_DIRECTORY_NOT_EMPTY")
    assert_no_new_owned_runtime_entries(home, runtime_entries_before)
    assert_no_bundle_processes(bundle)
    assert_ports_released(ports)


def _success_value_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _success_value_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _success_value_strings(child)]
    return []


def validate_success_evidence(value: Mapping[str, Any]) -> None:
    if (
        value.get("schema") != SCHEMA
        or value.get("status") != "DIAGNOSTIC_COMPLETE"
        or value.get("repo_owned") != "mechanical"
        or value.get("tls_verified") is not False
        or value.get("content_free") is not True
        or any(value.get(name) != "NOT_RUN" for name in (
            "remote_local_evidence", "external", "physical", "provider",
        ))
        or value.get("writes") != {"reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN"}
    ):
        raise DiagnosticError("SUCCESS_EVIDENCE_CONTRACT_INVALID")
    if any(FORBIDDEN_SUCCESS_VALUE.search(item) for item in _success_value_strings(value)):
        raise DiagnosticError("SUCCESS_EVIDENCE_FORBIDDEN_CLAIM")


def scan_content_free(raw: bytes) -> None:
    forbidden = (
        CANARY, b"BEGIN PRIVATE KEY", b"BEGIN RSA PRIVATE KEY",
        b"OPENAI_API_KEY", b"ANTHROPIC_API_KEY", b"#access_token=",
        b"#token=",
    )
    if any(token in raw for token in forbidden):
        raise DiagnosticError("ARTIFACT_SECRET_SCAN_FAILED")


def write_atomic_nonoverwrite(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_json(value) + b"\n"
    scan_content_free(raw)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise DiagnosticError("EVIDENCE_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as error:
        raise DiagnosticError("EVIDENCE_ALREADY_EXISTS") from error
    finally:
        temporary.unlink(missing_ok=True)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise DiagnosticError("EVIDENCE_FILE_POLICY_INVALID")
    scan_content_free(path.read_bytes())


def _browser_summary(browser: Mapping[str, Any]) -> dict[str, Any]:
    journey = browser["journey"]
    return {
        "product": "Google Chrome",
        "executable_sha256": browser["browser"]["executable_sha256"],
        "page_modes": ["desktop", "phone-emulation"],
        "pairing": journey["pairing"],
        "view": journey["actions"]["view"],
        "refresh": journey["refresh_recovery"],
        "revoke": journey["revoke"],
        "revoked_browser_blocked": journey["revoked_browser_blocked"],
    }


def run_diagnostic(args: argparse.Namespace) -> dict[str, Any]:
    if args.mode != MODE:
        raise DiagnosticError("DIAGNOSTIC_MODE_INVALID")
    chrome = verify_google_chrome_executable(args.chrome)
    artifact_dir = ensure_artifact_dir(args.artifact_dir)
    evidence_path = artifact_dir / EVIDENCE_NAME
    if os.path.lexists(evidence_path):
        raise DiagnosticError("EVIDENCE_ALREADY_EXISTS")
    bundle, launcher = verify_installed_bundle(args.installed_bundle)
    bundle_identity = _file_identity(bundle.lstat())
    env = clean_launcher_env()
    openssl = resolve_allowed_tool("openssl")
    ensure_exact_current_install(bundle, launcher, env)
    runtime_entries_before = snapshot_runtime_entries(bundle.parent.parent)
    public_port = reserve_loopback_ports(1)[0]
    public_origin = f"https://127.0.0.1:{public_port}"
    https_listen = f"127.0.0.1:{public_port}"
    start_attempted = False
    state: Mapping[str, Any] | None = None
    browser: Mapping[str, Any] | None = None
    primary_error: Exception | None = None
    cleanup_error: DiagnosticError | None = None
    temporary_root: Path | None = None
    with tempfile.TemporaryDirectory(prefix="nomad-installed-loopback.") as raw_root:
        try:
            root = Path(raw_root); temporary_root = root; os.chmod(root, 0o700)
            uv = snapshot_pinned_uv(root, env)
            cert, key, pin = generate_loopback_tls(root, openssl)
            profile = root / "chrome-profile"; profile.mkdir(mode=0o700)
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            cert_fd = os.open(cert, flags)
            key_fd = os.open(key, flags)
            try:
                start_attempted = True
                state = _run_stable_json(
                    [
                        str(launcher), "--json", "start-loopback-diagnostic",
                        "--provider", "OPENAI_API_KEY", "--credential-stdin",
                        "--workspace", str(Path.cwd().resolve()),
                        "--public-origin", public_origin,
                        "--https-listen", https_listen,
                        "--tls-cert-fd", str(cert_fd),
                        "--tls-key-fd", str(key_fd),
                    ],
                    "LAUNCHER_DIAGNOSTIC_START_BLOCKED", env=env,
                    input_bytes=CANARY, pass_fds=(cert_fd, key_fd),
                    timeout_seconds=120,
                )
            except Exception as error:
                safe_code = error.safe_code if isinstance(error, StableCliError) else "UNKNOWN"
                primary_error = DiagnosticError(
                    f"LAUNCHER_DIAGNOSTIC_START_BLOCKED_{safe_code}"
                )
                primary_error.__cause__ = error
            finally:
                os.close(cert_fd); os.close(key_fd)
            if primary_error is None and state is not None:
                try:
                    validate_launcher_state(state, bundle.name, public_port)
                    ensure_running_status(launcher, env, bundle.name, public_port)
                    browser = run_browser(
                        bundle, chrome, str(state["desktop_url"]), public_origin,
                        profile, pin, env, uv, bundle_identity,
                    )
                    ensure_running_status(launcher, env, bundle.name, public_port)
                    assert_command_journal_empty(bundle.parent.parent, state)
                except Exception as error:
                    primary_error = error
        finally:
            if start_attempted:
                try:
                    _run_stable_json(
                        [str(launcher), "--json", "stop"],
                        "LAUNCHER_DIAGNOSTIC_CLEANUP_FAILED", env=env,
                        timeout_seconds=30,
                    )
                except Exception as error:
                    cleanup_error = DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_FAILED")
                    cleanup_error.__cause__ = error
    if start_attempted:
        try:
            ensure_stopped_status(launcher, env)
            if temporary_root is None:
                raise DiagnosticError("DIAGNOSTIC_INCOMPLETE")
            if state is None:
                assert_failed_start_cleanup(
                    bundle.parent.parent, bundle, DEFAULT_STABLE_PORTS + [public_port],
                    temporary_root, artifact_dir, runtime_entries_before,
                )
            else:
                assert_cleanup_verified(
                    bundle.parent.parent, state, launcher_ports(state, public_port),
                    temporary_root, artifact_dir,
                )
        except Exception as error:
            if cleanup_error is None:
                cleanup_error = DiagnosticError("LAUNCHER_DIAGNOSTIC_CLEANUP_FAILED")
                cleanup_error.__cause__ = error
    if cleanup_error is not None:
        if state is None and primary_error is not None:
            raise DiagnosticError("LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED") from cleanup_error
        raise cleanup_error from primary_error
    if primary_error is not None:
        raise primary_error
    if state is None or browser is None or temporary_root is None:
        raise DiagnosticError("DIAGNOSTIC_INCOMPLETE")
    value = {
        "schema": SCHEMA,
        "status": "DIAGNOSTIC_COMPLETE",
        "repo_owned": "mechanical",
        "bundle_digest": bundle.name,
        "launcher_mode": LAUNCHER_MODE,
        "topology": {"scope": "loopback_only", "process_count": 7, "roles": EXPECTED_ROLES},
        "tls": {"san": "IP:127.0.0.1", "policy": "single_leaf_spki_pin"},
        "tls_verified": False,
        "browser": _browser_summary(browser),
        "remote_local_evidence": "NOT_RUN",
        "external": "NOT_RUN",
        "physical": "NOT_RUN",
        "provider": "NOT_RUN",
        "writes": {"reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN"},
        "content_free": True,
        "cleanup": "VERIFIED",
    }
    validate_success_evidence(value)
    write_atomic_nonoverwrite(evidence_path, value)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parse_args(arguments)
    try:
        value = run_diagnostic(args)
    except Exception as error:
        code = str(error) if isinstance(error, DiagnosticError) else "DIAGNOSTIC_INTERNAL_ERROR"
        print(canonical_json({
            "schema": SCHEMA, "status": "BLOCK", "code": code,
            "repo_owned": "mechanical", "remote_local_evidence": "NOT_RUN",
            "external": "NOT_RUN", "physical": "NOT_RUN",
            "provider": "NOT_RUN",
            "writes": {"reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN"},
            "tls_verified": False, "content_free": True,
        }).decode("ascii"))
        return 2
    print(canonical_json(value).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
