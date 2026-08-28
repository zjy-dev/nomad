"""Repo-local read-only Relay and Gateway launcher. No Agent authority."""

from __future__ import annotations

import os
import base64
import fcntl
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any

from . import processes
from .agent_runtime import _validate_credential_source, _verified_workspace, start_agent
from .bundle import verify_bundle
from .install_lifecycle import select_bundle_for_start
from .state import HOME_MARKER, REMOTE_STATE_SCHEMA, STATE_SCHEMA, initialize_home, lifecycle_lock, read_run_state, state_path, validate_home, validate_runtime_dirs, write_run_state

TOKEN_ENV = "NOMAD_ALPHA_RELAY_TOKEN"
BLOCKERS = ["B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY"]
HOST_READY_SCHEMA = "nomad.product-host.ready.v1"
REMOTE_HOST_READY_SCHEMA = "nomad.product-host.ready.v2"
INGRESS_READY_SCHEMA = "nomad.https-ingress.ready.v1"
MAX_HOST_READY_BYTES = 4096
COMMAND_KEY_BYTES = 32
COMMAND_KEY_B64_BYTES = 44
DEVICE_REGISTRY_DIRNAME = "private"
DEVICE_REGISTRY_BASENAME = "host-device-registry.sqlite3"
PAIRING_STORE_BASENAME = "pairing-coordinator.sqlite3"
REMOTE_MAILBOX_STATE_BASENAME = "remote-mailbox.sqlite3"
RELAY_V2_BASENAME = "relay-v2.sqlite3"
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
SESSION_ALLOWED = {"id","slug","projectID","workspaceID","directory","path","parentID","summary","cost","tokens","share","title","agent","model","version","metadata","time","permission","revert"}
SESSION_REQUIRED = {"id","slug","projectID","directory","title","version","time"}
HOST_IDENTITY_PREFLIGHT_TIMEOUT = 5.0
HOST_IDENTITY_AUTHORIZATION_TIMEOUT = 120.0
HOST_IDENTITY_RESULTS = {
    "READY": (0, None),
    "AUTH_REQUIRED": (1, "HOST_IDENTITY_AUTH_REQUIRED"),
    "USER_DENIED": (1, "HOST_IDENTITY_USER_DENIED"),
    "KEYCHAIN_LOCKED": (1, "HOST_IDENTITY_KEYCHAIN_LOCKED"),
    "CORRUPT": (1, "HOST_IDENTITY_CORRUPT"),
    "UNAVAILABLE": (1, "HOST_IDENTITY_UNAVAILABLE"),
}


class HostIdentityError(RuntimeError):
    def __init__(self, code: str, *, next_step: str | None = None):
        super().__init__(code)
        self.code = code
        self.next_step = next_step


def _get(config: Any, name: str) -> Any:
    if hasattr(config, name):
        return getattr(config, name)
    if isinstance(config, dict):
        return config[name]
    raise RuntimeError(f"CONFIG_{name.upper()}_MISSING")


def _selected_bundle_digest(config: Any, bundle: Path | None) -> str | None:
    if bundle is None:
        return None
    canonical_home = Path(_get(config, "home")).resolve(strict=True)
    canonical_bundle = Path(bundle).resolve(strict=True)
    manifest = verify_bundle(canonical_bundle)
    digest = manifest.get("bundle_digest")
    if (
        not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or canonical_bundle != (canonical_home / "bundles" / digest).resolve(strict=True)
    ):
        raise RuntimeError("SELECTED_BUNDLE_BINDING_INVALID")
    return digest


def _run_host_identity_command(binary: Path, arguments: list[str], *, interactive: bool = False) -> str:
    timeout = HOST_IDENTITY_AUTHORIZATION_TIMEOUT if interactive else HOST_IDENTITY_PREFLIGHT_TIMEOUT
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            cwd=binary.parent.parent,
            env=processes.minimal_env(),
            stdin=None if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        code = "HOST_IDENTITY_AUTHORIZATION_TIMEOUT" if interactive else "HOST_IDENTITY_PREFLIGHT_FAILED"
        raise HostIdentityError(code) from error
    except OSError as error:
        code = "HOST_IDENTITY_AUTHORIZATION_FAILED" if interactive else "HOST_IDENTITY_PREFLIGHT_FAILED"
        raise HostIdentityError(code) from error
    invalid = "HOST_IDENTITY_AUTHORIZATION_INVALID" if interactive else "HOST_IDENTITY_PREFLIGHT_INVALID"
    if result.stderr != b"":
        raise HostIdentityError(invalid)
    matched = None
    for status, (returncode, _) in HOST_IDENTITY_RESULTS.items():
        if result.stdout == f'{{"status":"{status}"}}\n'.encode("ascii"):
            matched = status
            if result.returncode != returncode:
                raise HostIdentityError(invalid)
            break
    if matched is None:
        raise HostIdentityError(invalid)
    return matched


def _require_host_identity_ready(binary: Path) -> None:
    status = _run_host_identity_command(binary, ["identity-preflight", "--non-interactive"])
    error = HOST_IDENTITY_RESULTS[status][1]
    if error is not None:
        next_step = "nomad-web authorize-host-identity" if status in {"AUTH_REQUIRED", "USER_DENIED"} else None
        raise HostIdentityError(error, next_step=next_step)


def authorize_host_identity(config: Any) -> dict[str, Any]:
    initialize_home(config)
    with lifecycle_lock(config, create=True):
        if read_run_state(config) is not None:
            raise HostIdentityError("HOST_IDENTITY_AUTHORIZATION_REQUIRES_STOP")
        bundle = select_bundle_for_start(config, getattr(config, "bundle_root", None))
        if bundle is None:
            raise RuntimeError("PREBUILT_BUNDLE_REQUIRED")
        binary = bundle / "bin" / "nomad-product-host"
        status = _run_host_identity_command(binary, ["authorize-host-identity"], interactive=True)
        error = HOST_IDENTITY_RESULTS[status][1]
        if error is not None:
            next_step = "nomad-web authorize-host-identity" if status in {"AUTH_REQUIRED", "USER_DENIED"} else None
            raise HostIdentityError(error, next_step=next_step)
        return {
            "schema": "nomad.web-companion.host-identity.v1",
            "state": "READY",
            "status": "READY",
            "production_ready": False,
        }


def _port_free(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.1)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            return False
    with socket.socket() as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _remote_port(config: Any, name: str) -> int:
    try:
        value = int(_get(config, name))
    except (TypeError, ValueError) as error:
        raise RuntimeError("REMOTE_PORT_INVALID") from error
    if not 1024 <= value <= 65535:
        raise RuntimeError("REMOTE_PORT_INVALID")
    return value


def _validate_public_origin(origin: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(origin)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise RuntimeError("REMOTE_PUBLIC_ORIGIN_INVALID") from error
    if (
        parsed.scheme != "https" or not parsed.hostname or port is None
        or parsed.username is not None or parsed.password is not None
        or parsed.path or parsed.query or parsed.fragment
    ):
        raise RuntimeError("REMOTE_PUBLIC_ORIGIN_INVALID")
    return origin


def _validate_https_listen(value: str, public_origin: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(f"//{value}")
        host, port = parsed.hostname, parsed.port
        address = ipaddress.ip_address(host)
        public_port = urllib.parse.urlsplit(public_origin).port
    except (AttributeError, TypeError, ValueError) as error:
        raise RuntimeError("REMOTE_HTTPS_LISTEN_INVALID") from error
    canonical = f"[{address.compressed}]:{port}" if address.version == 6 else f"{address.compressed}:{port}"
    if value != canonical or address.is_unspecified or address.is_loopback or address.is_multicast or not 1024 <= port <= 65535 or port != public_port:
        raise RuntimeError("REMOTE_HTTPS_LISTEN_INVALID")
    return value


def _listen_address_free(value: str) -> bool:
    parsed = urllib.parse.urlsplit(f"//{value}")
    family = socket.AF_INET6 if ipaddress.ip_address(parsed.hostname).version == 6 else socket.AF_INET
    with socket.socket(family) as listener:
        try:
            listener.bind((parsed.hostname, parsed.port))
            return True
        except OSError:
            return False


def _validate_operator_fd(descriptor: int | None, error_code: str) -> int:
    if type(descriptor) is not int or descriptor < 3:
        raise RuntimeError(error_code)
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise RuntimeError(error_code) from error
    if stat.S_ISDIR(info.st_mode):
        raise RuntimeError(error_code)
    os.set_inheritable(descriptor, False)
    return descriptor


def _validate_remote_inputs(
    config: Any, *, public_origin: str | None, https_listen: str | None,
    tls_cert_fd: int | None, tls_key_fd: int | None,
    check_availability: bool = True,
) -> tuple[str, str, list[int]]:
    if public_origin is None or https_listen is None or tls_cert_fd is None or tls_key_fd is None:
        raise RuntimeError("REMOTE_START_INPUTS_INCOMPLETE")
    public_origin = _validate_public_origin(public_origin)
    https_listen = _validate_https_listen(https_listen, public_origin)
    _validate_operator_fd(tls_cert_fd, "REMOTE_TLS_CERT_FD_INVALID")
    _validate_operator_fd(tls_key_fd, "REMOTE_TLS_KEY_FD_INVALID")
    _tls_probe_context(tls_cert_fd)
    ports = [
        _remote_port(config, "relay_port"), _remote_port(config, "relay_device_v1_port"),
        _remote_port(config, "relay_host_v2_port"), _remote_port(config, "relay_device_v2_port"),
        _remote_port(config, "relay_admin_port"), _remote_port(config, "gateway_port"),
        _remote_port(config, "join_gateway_port"), _remote_port(config, "agent_port"),
        int(urllib.parse.urlsplit(f"//{https_listen}").port),
    ]
    if len(set(ports)) != len(ports):
        raise RuntimeError("DUPLICATE_RUNTIME_PORT")
    if check_availability:
        if any(not _port_free(port) for port in ports):
            raise RuntimeError("RUNTIME_PORT_IN_USE")
        if not _listen_address_free(https_listen):
            raise RuntimeError("REMOTE_HTTPS_LISTEN_IN_USE")
    return public_origin, https_listen, ports


def _tls_probe_context(certificate_fd: int) -> ssl.SSLContext:
    try:
        info = os.fstat(certificate_fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("REMOTE_TLS_CERT_FD_INVALID")
        raw = os.pread(certificate_fd, 1024 * 1024 + 1, 0)
        if not raw or len(raw) > 1024 * 1024:
            raise RuntimeError("REMOTE_TLS_CERT_INVALID")
        pem = raw.decode("ascii")
        context = ssl.create_default_context()
        context.load_verify_locations(cadata=pem)
        return context
    except (OSError, UnicodeDecodeError, ssl.SSLError) as error:
        raise RuntimeError("REMOTE_TLS_CERT_INVALID") from error


def _wait(url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise RuntimeError("SERVICE_TIMEOUT")


def _wait_official_session(url: str, timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with _NO_PROXY_OPENER.open(url, timeout=1) as response:
                raw = response.read(64 * 1024 + 1)
                if response.status != 200 or len(raw) > 64 * 1024:
                    raise RuntimeError("OFFICIAL_SESSION_NOT_READY")
            _bounded_json_depth(raw)
            value = json.loads(raw, object_pairs_hook=_unique_object)
            session = value.get("session") if type(value) is dict else None
            if (
                type(value) is dict
                and set(value)
                == {"schema", "status", "session", "last_applied_seq", "digest", "events", "changes", "provenance"}
                and value.get("schema") == "nomad.alpha.readonly.v1"
                and value.get("status") == "available"
                and type(session) is dict
                and type(session.get("session_id")) is str
                and re.fullmatch(r"sess-[0-9a-f]{32}", session["session_id"])
            ):
                return session["session_id"]
        except (OSError, urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RuntimeError, RecursionError):
            time.sleep(0.05)
    raise RuntimeError("OFFICIAL_SESSION_NOT_READY")


def _wait_gateway_route(port: int, route_table: str, timeout: float = 20.0) -> None:
    targets = {
        "desktop": "/api/desktop/pairing/create",
        "join": "/api/pairing/join/start",
    }
    if route_table not in targets:
        raise RuntimeError("GATEWAY_ROUTE_TABLE_INVALID")
    expected = b'{"error":"METHOD_NOT_ALLOWED"}'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}{targets[route_table]}", method="GET"
            )
            try:
                response = _NO_PROXY_OPENER.open(request, timeout=1)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(len(expected) + 1)
                content_type = response.headers.get_content_type()
                if response.status == 405 and raw == expected and content_type == "application/json":
                    return
            time.sleep(0.05)
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise RuntimeError(f"{route_table.upper()}_GATEWAY_NOT_READY")


def _wait_ports_free(ports: list[int], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(_port_free(port) for port in ports):
            return
        time.sleep(0.05)
    raise RuntimeError("LOOPBACK_PORT_RELEASE_TIMEOUT")


def _preflight_remote_agent(provider_name: str | None, credential_fd: int | None, workspace: Path | None) -> None:
    if provider_name is None or credential_fd is None or workspace is None:
        raise RuntimeError("REMOTE_START_INPUTS_INCOMPLETE")
    _validate_credential_source(provider_name, credential_fd)
    os.set_inheritable(credential_fd, False)
    _, _, workspace_fd = _verified_workspace(Path(workspace))
    os.close(workspace_fd)


def _wait_relay_role(port: int, *, role: str, timeout: float = 20.0) -> None:
    if role not in ("host", "device"):
        raise RuntimeError("RELAY_ROLE_INVALID")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("RELAY_ROLE_TIMEOUT")


class _PinnedAddressHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, port: int, context: ssl.SSLContext):
        super().__init__(hostname, port=port, timeout=3, context=context)
        self._nomad_address = address

    def connect(self) -> None:
        raw = self._create_connection((self._nomad_address, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _probe_public_negative_routes(
    public_origin: str, https_listen: str, context: ssl.SSLContext,
) -> None:
    parsed_listen = urllib.parse.urlsplit(f"//{https_listen}")
    parsed_origin = urllib.parse.urlsplit(public_origin)
    address, port = parsed_listen.hostname, int(parsed_listen.port)
    hostname, authority = parsed_origin.hostname, parsed_origin.netloc
    for method, path in (("GET", "/api/desktop/pairing/create"), ("GET", "/internal/session/current"), ("GET", "/v2/admin/mailboxes/provision"), ("GET", "/v1/frame"), ("POST", "/j/join-" + "0" * 32), ("GET", "/%2e%2e/internal/session/current")):
        connection = _PinnedAddressHTTPSConnection(hostname, address, port, context)
        try:
            connection.request(method, path, headers={"Host": authority})
            response = connection.getresponse()
            raw = response.read(4097)
            if response.status != 404 or raw != b"not found\n":
                raise RuntimeError("INGRESS_NEGATIVE_ROUTE_ACCEPTED")
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise RuntimeError("INGRESS_TLS_PROBE_FAILED") from error
        finally:
            connection.close()


def _spawn_product_host(binary: Path, cwd: Path, log_path: Path, bootstrap_child: socket.socket) -> dict[str, Any]:
    return _spawn_product_host_with_fds(binary, cwd, log_path, bootstrap_child)


def _spawn_product_host_with_fds(
    binary: Path, cwd: Path, log_path: Path, bootstrap_child: socket.socket,
    *, admin_bearer_fd: int | None = None,
) -> dict[str, Any]:
    devnull = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    safe_devnull = fcntl.fcntl(devnull, fcntl.F_DUPFD_CLOEXEC, 20)
    safe_log = fcntl.fcntl(log_fd, fcntl.F_DUPFD_CLOEXEC, 20)
    safe_bootstrap = fcntl.fcntl(bootstrap_child.fileno(), fcntl.F_DUPFD_CLOEXEC, 20)
    safe_admin = fcntl.fcntl(admin_bearer_fd, fcntl.F_DUPFD_CLOEXEC, 20) if admin_bearer_fd is not None else None
    try:
        actions = [
            (os.POSIX_SPAWN_DUP2, safe_devnull, 0), (os.POSIX_SPAWN_DUP2, safe_log, 1),
            (os.POSIX_SPAWN_DUP2, safe_log, 2), (os.POSIX_SPAWN_DUP2, safe_bootstrap, 10),
            (os.POSIX_SPAWN_CLOSE, safe_devnull), (os.POSIX_SPAWN_CLOSE, safe_log),
            (os.POSIX_SPAWN_CLOSE, safe_bootstrap),
        ]
        if safe_admin is not None:
            actions.extend([(os.POSIX_SPAWN_DUP2, safe_admin, 11), (os.POSIX_SPAWN_CLOSE, safe_admin)])
        pid = os.posix_spawn(
            str(binary), [str(binary)], processes.minimal_env({}),
            file_actions=actions, setsid=True,
        )
    finally:
        os.close(devnull); os.close(log_fd)
        os.close(safe_devnull); os.close(safe_log); os.close(safe_bootstrap)
        if safe_admin is not None:
            os.close(safe_admin)
    try: identity = processes.process_identity(pid)
    except Exception:
        _terminate_reap(pid)
        raise
    return {"name":"product-host","pid":pid,"process_group":pid,"identity":identity,"log":str(log_path)}


def _random_command_key() -> str:
    return base64.b64encode(secrets.token_bytes(COMMAND_KEY_BYTES)).decode("ascii")


def _make_command_journal_path(run_dir: Path, run_state_alias: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{64}", run_state_alias) is None:
        raise RuntimeError("INVALID_RUN_ALIAS")
    return run_dir / f"command-{hashlib.sha256(f'journal:{run_state_alias}'.encode()).hexdigest()[:24]}.sqlite3"


def _prepare_command_journal(path: Path, run_dir: Path) -> Path:
    run_root = run_dir.resolve(strict=True)
    candidate = path.absolute()
    if candidate.parent.resolve(strict=True) != run_root or candidate.is_symlink() or os.path.lexists(candidate):
        raise RuntimeError("UNSAFE_COMMAND_JOURNAL")
    return candidate


def _device_registry_dir(home: Path) -> Path:
    return _normalize_system_alias_path(home) / DEVICE_REGISTRY_DIRNAME


def _device_registry_path(home: Path) -> Path:
    return _device_registry_dir(home) / DEVICE_REGISTRY_BASENAME


def _normalize_system_alias_path(path: Path) -> Path:
    aliases = {
        Path("/var"): Path("/private/var"),
        Path("/tmp"): Path("/private/tmp"),
    }
    for lexical, physical in aliases.items():
        if path == lexical or lexical in path.parents:
            return physical / path.relative_to(lexical)
    return path


def _validate_canonical_private_dir(path: Path, error_code: str) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError(error_code) from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError(error_code)
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(error_code) from error
    normalized = _normalize_system_alias_path(path)
    if canonical != normalized:
        raise RuntimeError(error_code)
    return canonical


def _validate_private_regular_file(path: Path, directory: Path, *, mode: int, error_code: str) -> None:
    if path.parent != directory or path.is_symlink():
        raise RuntimeError(error_code)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
        raise RuntimeError(error_code)


def _validate_device_registry_artifacts(path: Path, *, require_main: bool) -> None:
    directory = _validate_canonical_private_dir(path.parent, "UNSAFE_DEVICE_REGISTRY_DIRECTORY")
    normalized = _normalize_system_alias_path(path)
    if normalized != directory / DEVICE_REGISTRY_BASENAME or not normalized.is_absolute() or not os.fspath(normalized).isascii():
        raise RuntimeError("UNSAFE_DEVICE_REGISTRY")
    allowed = {
        DEVICE_REGISTRY_BASENAME,
        f"{DEVICE_REGISTRY_BASENAME}-wal",
        f"{DEVICE_REGISTRY_BASENAME}-shm",
    }
    for basename in (PAIRING_STORE_BASENAME, REMOTE_MAILBOX_STATE_BASENAME, RELAY_V2_BASENAME):
        allowed.update({basename, f"{basename}-wal", f"{basename}-shm"})
    if not {entry.name for entry in directory.iterdir()}.issubset(allowed):
        raise RuntimeError("UNSAFE_DEVICE_REGISTRY_DIRECTORY")
    present_main = False
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if not os.path.lexists(candidate):
            continue
        present_main = present_main or candidate == path
        _validate_private_regular_file(candidate, directory, mode=0o600, error_code="UNSAFE_DEVICE_REGISTRY")
    if require_main and not present_main:
        raise RuntimeError("DEVICE_REGISTRY_MISSING")


def _prepare_device_registry_path(home: Path) -> Path:
    directory = _device_registry_dir(home)
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    _validate_canonical_private_dir(directory, "UNSAFE_DEVICE_REGISTRY_DIRECTORY")
    path = _device_registry_path(home)
    _validate_device_registry_artifacts(path, require_main=False)
    return path


def _persistent_remote_paths(home: Path) -> dict[str, Path]:
    directory = _device_registry_dir(home)
    _validate_canonical_private_dir(directory, "UNSAFE_REMOTE_STATE_DIRECTORY")
    paths = {
        "pairing_store_path": directory / PAIRING_STORE_BASENAME,
        "remote_mailbox_state_path": directory / REMOTE_MAILBOX_STATE_BASENAME,
        "relay_v2_db_path": directory / RELAY_V2_BASENAME,
    }
    for path in paths.values():
        if os.path.lexists(path):
            _validate_private_regular_file(path, directory, mode=0o600, error_code="UNSAFE_REMOTE_STATE")
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if os.path.lexists(sidecar):
                _validate_private_regular_file(sidecar, directory, mode=0o600, error_code="UNSAFE_REMOTE_STATE")
    return paths


def _remote_persistent_state_present(home: Path) -> bool:
    directory = _device_registry_dir(home)
    if not os.path.lexists(directory):
        return False
    _validate_canonical_private_dir(directory, "UNSAFE_REMOTE_STATE_DIRECTORY")
    names = {entry.name for entry in directory.iterdir()}
    remote = {PAIRING_STORE_BASENAME, REMOTE_MAILBOX_STATE_BASENAME, RELAY_V2_BASENAME}
    return any(name == basename or name in {f"{basename}-wal", f"{basename}-shm"} for basename in remote for name in names)


def _cleanup_command_journal(path: Path | None, run_dir: Path) -> None:
    if path is None:
        return
    run_root = run_dir.resolve(strict=True)
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if not os.path.lexists(candidate):
            continue
        if candidate.parent.resolve(strict=True) != run_root or candidate.is_symlink():
            raise RuntimeError("UNSAFE_COMMAND_JOURNAL")
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("UNSAFE_COMMAND_JOURNAL")
        candidate.unlink()


def _write_fd_secret(fd: int, value: str) -> None:
    if len(value) != COMMAND_KEY_B64_BYTES or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
        raise RuntimeError("INVALID_COMMAND_KEY")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise RuntimeError("INVALID_COMMAND_KEY") from error
    if len(raw) != COMMAND_KEY_BYTES:
        raise RuntimeError("INVALID_COMMAND_KEY")
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise RuntimeError("COMMAND_KEY_WRITE_FAILED")
            view = view[written:]
    finally:
        os.close(fd)


def _create_run_session(origin: str, password: str) -> str:
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or parsed.port is None:
        raise RuntimeError("AGENT_LOOPBACK_URL_INVALID")
    url = f"http://127.0.0.1:{parsed.port}/session"
    token = base64.b64encode(f"opencode:{password}".encode()).decode()
    request = urllib.request.Request(url, data=b"{}", method="POST", headers={"Authorization":f"Basic {token}","Content-Type":"application/json"})
    try:
        _validate_session_url(request.full_url, parsed.port)
        with _NO_PROXY_OPENER.open(request, timeout=10) as response:
            raw = response.read(4097)
            if response.status < 200 or response.status >= 300 or len(raw) > 4096: raise RuntimeError("SESSION_CREATE_REJECTED")
    except (OSError, urllib.error.URLError) as error: raise RuntimeError("SESSION_CREATE_REJECTED") from error
    try:
        _bounded_json_depth(raw)
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error: raise RuntimeError("SESSION_CREATE_INVALID") from error
    if type(value) is not dict or not SESSION_REQUIRED.issubset(value) or not set(value).issubset(SESSION_ALLOWED): raise RuntimeError("SESSION_CREATE_INVALID")
    session_id = value.get("id")
    time_value = value.get("time")
    if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id) or value.get("version") != "1.18.16" or any(type(value.get(key)) is not str for key in ("slug","projectID","directory","title")) or type(time_value) is not dict or not {"created","updated"}.issubset(time_value) or not set(time_value).issubset({"created","updated","archived","compacting"}) or any(type(time_value[key]) is not int or time_value[key] < 0 for key in ("created","updated")):
        raise RuntimeError("SESSION_CREATE_INVALID")
    return session_id

def _unique_object(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError("duplicate")
        value[key]=item
    return value

def _bounded_json_depth(raw: bytes, maximum: int = 32) -> None:
    depth=0; quoted=False; escaped=False
    for byte in raw:
        if quoted:
            if escaped: escaped=False
            elif byte==92: escaped=True
            elif byte==34: quoted=False
        elif byte==34: quoted=True
        elif byte in (91,123):
            depth+=1
            if depth>maximum: raise ValueError("depth")
        elif byte in (93,125):
            depth-=1
            if depth<0: raise ValueError("depth")
    if quoted or depth!=0: raise ValueError("depth")

def _validate_session_url(url: str, port: int) -> None:
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!="http" or parsed.hostname!="127.0.0.1" or parsed.port!=port or parsed.username is not None or parsed.password is not None or parsed.path!="/session" or parsed.query or parsed.fragment:
        raise RuntimeError("AGENT_LOOPBACK_URL_INVALID")

def _terminate_reap(pid: int) -> None:
    try: os.killpg(pid, 9)
    except ProcessLookupError: pass
    try: os.waitpid(pid, 0)
    except ChildProcessError: pass


def _product_host_socket_path(home: Path, run_state_alias: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{64}", run_state_alias) is None:
        raise RuntimeError("INVALID_RUN_ALIAS")
    canonical_home = home.resolve(strict=True)
    suffix = hashlib.sha256(f"{canonical_home}:{os.geteuid()}".encode()).hexdigest()[:16]
    return Path("/private/tmp") / f"nomad-web-{suffix}-{run_state_alias[:16]}" / "product-host.sock"


def _prepare_product_host_socket(home: Path, run_state_alias: str) -> Path:
    socket_path = _product_host_socket_path(home, run_state_alias)
    directory = socket_path.parent
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("UNSAFE_PRODUCT_HOST_SOCKET_DIRECTORY")
    if os.path.lexists(socket_path):
        raise RuntimeError("PRODUCT_HOST_SOCKET_ALREADY_EXISTS")
    return socket_path


def _socket_parent_identity(socket_path: Path) -> dict[str, int]:
    info = socket_path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("UNSAFE_PRODUCT_HOST_SOCKET_DIRECTORY")
    return {"parent_dev": info.st_dev, "parent_ino": info.st_ino, "parent_uid": info.st_uid, "parent_mode": stat.S_IMODE(info.st_mode)}


def _socket_identity(socket_path: Path, parent: dict[str, int]) -> dict[str, int]:
    current = _socket_parent_identity(socket_path)
    if current != parent:
        raise RuntimeError("PRODUCT_HOST_SOCKET_IDENTITY_MISMATCH")
    leaf = socket_path.lstat()
    if not stat.S_ISSOCK(leaf.st_mode) or stat.S_ISLNK(leaf.st_mode) or leaf.st_uid != os.geteuid() or stat.S_IMODE(leaf.st_mode) != 0o600:
        raise RuntimeError("UNSAFE_PRODUCT_HOST_SOCKET")
    return {**parent, "socket_dev": leaf.st_dev, "socket_ino": leaf.st_ino, "socket_uid": leaf.st_uid, "socket_mode": stat.S_IMODE(leaf.st_mode)}


def _cleanup_product_host_socket(socket_path: Path | None, expected: dict[str, int] | None = None) -> None:
    if socket_path is None:
        return
    directory = socket_path.parent
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return
    parent = {"parent_dev": info.st_dev, "parent_ino": info.st_ino, "parent_uid": info.st_uid, "parent_mode": stat.S_IMODE(info.st_mode)}
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or expected is not None and any(parent[name] != expected[name] for name in parent):
        raise RuntimeError("UNSAFE_PRODUCT_HOST_SOCKET_DIRECTORY")
    try:
        leaf = socket_path.lstat()
    except FileNotFoundError:
        leaf = None
    if leaf is not None:
        actual = {"socket_dev": leaf.st_dev, "socket_ino": leaf.st_ino, "socket_uid": leaf.st_uid, "socket_mode": stat.S_IMODE(leaf.st_mode)}
        if not stat.S_ISSOCK(leaf.st_mode) or stat.S_ISLNK(leaf.st_mode) or leaf.st_uid != os.geteuid() or stat.S_IMODE(leaf.st_mode) != 0o600:
            raise RuntimeError("UNSAFE_PRODUCT_HOST_SOCKET")
        # A Host that failed before the authenticated ready frame may have
        # created a valid socket, but the launcher never received its inode
        # capability. Preserve it; the next run uses a distinct run-scoped path.
        if expected is None or not all(name in expected for name in actual):
            return
        if any(actual[name] != expected[name] for name in actual):
            raise RuntimeError("UNSAFE_PRODUCT_HOST_SOCKET")
        socket_path.unlink()
    try:
        directory.rmdir()
    except OSError as error:
        raise RuntimeError("PRODUCT_HOST_SOCKET_DIRECTORY_NOT_EMPTY") from error


def _cleanup_gateway_db(path: Path | None, run_dir: Path) -> None:
    if path is None:
        return
    run_root = run_dir.resolve(strict=True)
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if not os.path.lexists(candidate):
            continue
        if candidate.parent.resolve(strict=True) != run_root or candidate.is_symlink():
            raise RuntimeError("UNSAFE_GATEWAY_STATE")
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError("UNSAFE_GATEWAY_STATE")
        candidate.unlink()


def _validate_run_sqlite(path: Path, run_dir: Path, *, require_main: bool) -> None:
    run_root = run_dir.resolve(strict=True)
    present_main = False
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        if not os.path.lexists(candidate):
            continue
        if candidate.parent.resolve(strict=True) != run_root or candidate.is_symlink():
            raise RuntimeError("UNSAFE_RELAY_V1_STATE")
        info = candidate.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise RuntimeError("UNSAFE_RELAY_V1_STATE")
        present_main = present_main or candidate == path
    if require_main and not present_main:
        raise RuntimeError("RELAY_V1_STATE_MISSING")


def _prepare_run_sqlite(path: Path, run_dir: Path) -> Path:
    if path.parent.resolve(strict=True) != run_dir.resolve(strict=True) or path.is_symlink() or os.path.lexists(path):
        raise RuntimeError("UNSAFE_RELAY_V1_STATE")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise RuntimeError("UNSAFE_RELAY_V1_STATE")
    finally:
        os.close(descriptor)
    _validate_run_sqlite(path, run_dir, require_main=True)
    return path


def _safe_error_code(error: BaseException) -> str:
    value = str(error)
    return value if re.fullmatch(r"[A-Z][A-Z0-9_]*", value) else "LAUNCHER_FAILURE"


def _rollback_remote_start(
    primary: BaseException, children: list[dict[str, Any]], *,
    product_host_socket_path: Path | None, product_host_socket_identity: dict[str, int] | None,
    desktop_db_path: Path | None, command_journal_path: Path | None,
    relay_v1_paths: tuple[Path, Path], run_dir: Path,
) -> None:
    cleanup_failed = False
    for child in reversed(children):
        try:
            if not processes.stop(child):
                cleanup_failed = True
        except Exception:
            cleanup_failed = True
    cleanup_steps = [
        lambda: _cleanup_product_host_socket(product_host_socket_path, product_host_socket_identity),
        lambda: _cleanup_gateway_db(desktop_db_path, run_dir),
        lambda: _cleanup_command_journal(command_journal_path, run_dir),
        *(lambda path=path: _cleanup_gateway_db(path, run_dir) for path in relay_v1_paths),
    ]
    for cleanup in cleanup_steps:
        try:
            cleanup()
        except Exception:
            cleanup_failed = True
    if cleanup_failed:
        raise RuntimeError(f"{_safe_error_code(primary)};ROLLBACK_CLEANUP_FAILED") from primary
    raise primary


def _cleanup_device_registry(path: Path | None) -> None:
    if path is None:
        return
    directory = path.parent
    if not os.path.lexists(directory):
        return
    _validate_device_registry_artifacts(path, require_main=False)
    basenames = (DEVICE_REGISTRY_BASENAME, PAIRING_STORE_BASENAME, REMOTE_MAILBOX_STATE_BASENAME, RELAY_V2_BASENAME)
    allowed = {candidate for basename in basenames for candidate in (basename, f"{basename}-wal", f"{basename}-shm")}
    if not {entry.name for entry in directory.iterdir()}.issubset(allowed):
        raise RuntimeError("UNSAFE_REMOTE_STATE_DIRECTORY")
    for basename in basenames:
        main = directory / basename
        for candidate in (Path(str(main) + "-shm"), Path(str(main) + "-wal"), main):
            if not os.path.lexists(candidate):
                continue
            _validate_private_regular_file(candidate, directory, mode=0o600, error_code="UNSAFE_REMOTE_STATE")
            candidate.unlink()
    try:
        directory.rmdir()
    except OSError as error:
        raise RuntimeError("DEVICE_REGISTRY_DIRECTORY_NOT_EMPTY") from error


def _safe_remove_tree(path: Path, *, root: Path) -> None:
    if not os.path.lexists(path):
        return
    info = path.lstat()
    if info.st_uid != os.geteuid() or stat.S_ISLNK(info.st_mode):
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME_CONTENTS")
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME_CONTENTS") from error
    if not canonical.is_relative_to(root):
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME_CONTENTS")
    if stat.S_ISDIR(info.st_mode):
        for entry in sorted(path.iterdir(), key=lambda item: item.name):
            _safe_remove_tree(entry, root=root)
        path.rmdir()
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME_CONTENTS")
    path.unlink()


def _bootstrap_host(channel: socket.socket, *, run_id: str, origin: str, session_id: str, password: str, workspace_digest: str, product_host_socket_path: Path, device_registry_path: Path, agent_pid: int, agent_process_group: int, agent_process_identity: str, command_transport_key: str, command_authority_key: str, command_journal_path: Path, join_transport_key: str | None = None, remote: dict[str, Any] | None = None) -> dict[str, int]:
    parent = _socket_parent_identity(product_host_socket_path)
    value = {"schema":"nomad.product-host.bootstrap.v2" if remote is not None else "nomad.product-host.bootstrap.v1","run_id":run_id,"origin":origin,"session_id":session_id,"server_password":password,"workspace_binding_digest":workspace_digest,"product_host_socket_path":str(product_host_socket_path),"device_registry_path":str(device_registry_path),"agent_pid":agent_pid,"agent_process_group":agent_process_group,"agent_process_identity":agent_process_identity,"product_host_socket_parent_dev":parent["parent_dev"],"product_host_socket_parent_ino":parent["parent_ino"],"command_transport_key":command_transport_key,"command_authority_key":command_authority_key,"command_journal_path":str(command_journal_path)}
    if remote is not None:
        if join_transport_key is None:
            raise RuntimeError("HOST_BOOTSTRAP_INVALID")
        value.update({"join_transport_key": join_transport_key, "remote": remote})
    raw = json.dumps(value, sort_keys=True, separators=(",",":")).encode()
    if not 0 < len(raw) <= 16 * 1024: raise RuntimeError("HOST_BOOTSTRAP_INVALID")
    try:
        channel.settimeout(70); channel.sendall(len(raw).to_bytes(4, "big") + raw); channel.shutdown(socket.SHUT_WR)
        length_raw = _recv_exact(channel, 4); length = int.from_bytes(length_raw, "big")
        if not 0 < length <= MAX_HOST_READY_BYTES: raise RuntimeError("HOST_READY_INVALID")
        ready_raw = _recv_exact(channel, length)
        if channel.recv(1) != b"": raise RuntimeError("HOST_READY_INVALID")
        _bounded_json_depth(ready_raw)
        ready = json.loads(ready_raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise RuntimeError("HOST_READY_INVALID") from error
    keys = {"schema","parent_dev","parent_ino","socket_dev","socket_ino","snapshot_seq"}
    expected_schema = HOST_READY_SCHEMA
    if remote is not None:
        keys |= {"pairing_ready", "remote_mailbox_ready"}
        expected_schema = REMOTE_HOST_READY_SCHEMA
    if type(ready) is not dict or set(ready) != keys or ready.get("schema") != expected_schema or ready.get("snapshot_seq") != 1 or any(type(ready.get(name)) is not int or ready[name] <= 0 for name in ("parent_dev","parent_ino","socket_dev","socket_ino")) or remote is not None and (ready.get("pairing_ready") is not True or ready.get("remote_mailbox_ready") is not True) or ready_raw != json.dumps(ready,separators=(",",":")).encode():
        raise RuntimeError("HOST_READY_INVALID")
    observed = _socket_identity(product_host_socket_path, parent)
    if any(ready[name] != observed[name] for name in ("parent_dev","parent_ino","socket_dev","socket_ino")):
        raise RuntimeError("HOST_READY_IDENTITY_MISMATCH")
    return observed


def _wait_ingress_ready(channel: socket.socket, record: dict[str, Any], timeout: float = 20.0) -> None:
    if processes.ownership(record) != "owned":
        raise RuntimeError("INGRESS_PROCESS_NOT_OWNED")
    channel.settimeout(timeout)
    expected = b'{"schema":"nomad.https-ingress.ready.v1","ready":true}'
    try:
        length = int.from_bytes(_recv_exact(channel, 4), "big")
        if length != len(expected):
            raise RuntimeError("INGRESS_READY_INVALID")
        raw = _recv_exact(channel, length)
        if raw != expected or channel.recv(1) != b"":
            raise RuntimeError("INGRESS_READY_INVALID")
    except (OSError, socket.timeout, RuntimeError) as error:
        if isinstance(error, RuntimeError) and str(error) == "INGRESS_PROCESS_NOT_OWNED":
            raise
        raise RuntimeError("INGRESS_READY_INVALID") from error
    if processes.ownership(record) != "owned":
        raise RuntimeError("INGRESS_PROCESS_NOT_OWNED")


def _recv_exact(channel: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = channel.recv(length - len(chunks))
        if not chunk: raise RuntimeError("HOST_READY_INVALID")
        chunks.extend(chunk)
    return bytes(chunks)


def start_foundation(
    config: Any,
    *,
    provider_name: str | None = None,
    credential_fd: int | None = None,
    workspace: Path | None = None,
    remote_local_evidence: bool = False,
    public_origin: str | None = None,
    https_listen: str | None = None,
    tls_cert_fd: int | None = None,
    tls_key_fd: int | None = None,
) -> dict[str, Any]:
    if remote_local_evidence:
        return start_remote_local_evidence(
            config, provider_name=provider_name, credential_fd=credential_fd,
            workspace=workspace, public_origin=public_origin, https_listen=https_listen,
            tls_cert_fd=tls_cert_fd, tls_key_fd=tls_key_fd,
        )
    if any(value is not None for value in (public_origin, https_listen, tls_cert_fd, tls_key_fd)):
        raise RuntimeError("REMOTE_MODE_REQUIRED")
    initialize_home(config)
    with lifecycle_lock(config, create=True):
        return _start_unlocked(
            config,
            provider_name=provider_name,
            credential_fd=credential_fd,
            workspace=workspace,
        )


def start_remote_local_evidence(
    config: Any, *, provider_name: str | None, credential_fd: int | None,
    workspace: Path | None, public_origin: str | None, https_listen: str | None,
    tls_cert_fd: int | None, tls_key_fd: int | None,
) -> dict[str, Any]:
    owned_fds = [fd for fd in (credential_fd, tls_cert_fd, tls_key_fd) if type(fd) is int]
    try:
        # Every caller-controlled value is checked before home creation, bundle
        # installation, builds, or process creation. This is the zero-spawn gate.
        _preflight_remote_agent(provider_name, credential_fd, workspace)
        public_origin, https_listen, _ = _validate_remote_inputs(
            config, public_origin=public_origin, https_listen=https_listen,
            tls_cert_fd=tls_cert_fd, tls_key_fd=tls_key_fd,
        )
        initialize_home(config)
        with lifecycle_lock(config, create=True):
            return _start_remote_unlocked(
                config, provider_name=str(provider_name), credential_fd=int(credential_fd),
                workspace=Path(workspace), public_origin=public_origin, https_listen=https_listen,
                tls_cert_fd=int(tls_cert_fd), tls_key_fd=int(tls_key_fd),
            )
    except Exception:
        for descriptor in owned_fds:
            processes.close_fd(descriptor)
        raise


def _start_unlocked(
    config: Any,
    *,
    provider_name: str | None = None,
    credential_fd: int | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    agent_requested = any(value is not None for value in (provider_name, credential_fd, workspace))
    if agent_requested and not all(value is not None for value in (provider_name, credential_fd, workspace)):
        if credential_fd is not None:
            try:
                os.close(int(credential_fd))
            except OSError:
                pass
        raise RuntimeError("AGENT_START_INPUTS_INCOMPLETE")
    bundle = select_bundle_for_start(config, getattr(config, "bundle_root", None))
    bundle_digest = _selected_bundle_digest(config, bundle)
    existing = read_run_state(config)
    if existing:
        if existing["bundle_digest"] != bundle_digest:
            raise RuntimeError("RUNNING_BUNDLE_BINDING_MISMATCH")
        ownership = [processes.ownership(item) for item in existing["processes"]]
        if "mismatch" in ownership:
            raise RuntimeError("PROCESS_IDENTITY_MISMATCH")
        lives = [state == "owned" for state in ownership]
        if all(lives):
            if credential_fd is not None:
                try:
                    os.close(int(credential_fd))
                except OSError:
                    pass
            if agent_requested and existing["mode"] != "official-agent-local":
                raise RuntimeError("MODE_CHANGE_REQUIRES_STOP")
            return _status_unlocked(config)
        for child, is_alive in reversed(list(zip(existing["processes"], lives))):
            if is_alive and not processes.stop(child):
                raise RuntimeError("DEGRADED_RECONCILE_FAILED")
        released_ports = [int(_get(config, "gateway_port")), int(_get(config, "agent_port"))]
        if existing["mode"] == "foundation-readonly":
            released_ports.append(int(_get(config, "relay_port")))
        _wait_ports_free(released_ports)
        _cleanup_run_artifacts(config, existing)
        state_path(config).unlink(missing_ok=True)
    repo = Path(_get(config, "repo_root")).resolve()
    home = Path(_get(config, "home")).resolve()
    relay_port = int(_get(config, "relay_port"))
    gateway_port = int(_get(config, "gateway_port"))
    if not _port_free(gateway_port) or not agent_requested and not _port_free(relay_port):
        raise RuntimeError("LOOPBACK_PORT_IN_USE")
    bin_dir, run_dir, log_dir = home / "bin", home / "run", home / "logs"
    for directory in (bin_dir, run_dir, log_dir):
        if directory.exists() and (not directory.is_dir() or directory.is_symlink()):
            raise RuntimeError("UNSAFE_LAUNCHER_DIRECTORY")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    validate_runtime_dirs(config)
    if bundle is not None:
        relay_binary = bundle / "bin" / "nomad-relay"
        relay_cwd = bundle
        gateway_dir = bundle / "gateway"
        web_dir = bundle / "web"
    else:
        if os.environ.get("NOMAD_WEB_ALLOW_SOURCE_BUILD") != "1":
            raise RuntimeError("PREBUILT_BUNDLE_REQUIRED")
        relay_binary = bin_dir / "nomad-relay"
        if not agent_requested:
            processes.run_checked(["go", "build", "-o", str(relay_binary), "./cmd/relay"], repo / "relay")
        processes.run_checked(["npm", "run", "build"], repo / "mobile-reference")
        relay_cwd = repo / "relay"
        gateway_dir = repo / "mobile-reference" / "pilot-gateway"
        web_dir = repo / "mobile-reference" / "dist"
    node = shutil.which("node")
    if not node:
        raise RuntimeError("NODE_UNAVAILABLE")
    token = secrets.token_urlsafe(32) if not agent_requested else None
    run_id = secrets.token_hex(32) if agent_requested else None
    run_state_alias = hashlib.sha256(f"state:{run_id}".encode()).hexdigest() if agent_requested else None
    children: list[dict[str, Any]] = []
    bootstrap_parent = bootstrap_child = None
    command_gateway_read = command_gateway_write = None
    product_host_socket_path = None
    product_host_socket_identity = None
    device_registry_path = None
    gateway_db_path = None
    command_journal_path = None
    try:
        if agent_requested:
            if bundle is None:
                raise RuntimeError("PREBUILT_AGENT_RUNTIME_REQUIRED")
            product_host_socket_path = _prepare_product_host_socket(home, run_state_alias)
            product_host_socket_identity = _socket_parent_identity(product_host_socket_path)
            device_registry_path = _prepare_device_registry_path(home)
            command_journal_path = _prepare_command_journal(
                _make_command_journal_path(run_dir, run_state_alias),
                run_dir,
            )
            bootstrap_parent, bootstrap_child = socket.socketpair()
            command_transport_key = _random_command_key()
            command_authority_key = _random_command_key()
            command_gateway_read, command_gateway_write = os.pipe()
            for fd in (command_gateway_read, command_gateway_write):
                os.set_inheritable(fd, False)
            host = _spawn_product_host(bundle / "bin" / "nomad-product-host", bundle, log_dir / f"product-host-{run_state_alias}.log", bootstrap_child)
            children.append(host)
            bootstrap_child.close(); bootstrap_child = None
            agent = start_agent(
                bundle,
                Path(workspace),
                run_dir / f"agent-runtime-{run_state_alias}",
                int(_get(config, "agent_port")),
                str(provider_name),
                int(credential_fd),
                log_dir / f"agent-{run_state_alias}.log",
            )
            password = agent.pop("_server_password")
            children.insert(0, {key: agent[key] for key in ("name", "pid", "process_group", "identity", "log")})
            workspace_digest = str(agent.pop("_workspace_binding_digest"))
            session_id = _create_run_session(str(agent["origin"]), password)
            product_host_socket_identity = _bootstrap_host(bootstrap_parent, run_id=run_id, origin=str(agent["origin"]), session_id=session_id, password=password, workspace_digest=workspace_digest, product_host_socket_path=product_host_socket_path, device_registry_path=device_registry_path, agent_pid=int(agent["pid"]), agent_process_group=int(agent["process_group"]), agent_process_identity=str(agent["identity"]), command_transport_key=command_transport_key, command_authority_key=command_authority_key, command_journal_path=command_journal_path)
            password = ""
            bootstrap_parent.close(); bootstrap_parent = None
        if not agent_requested:
            relay = processes.spawn(
                "relay",
                [str(relay_binary), "-addr", f"127.0.0.1:{relay_port}", "-db", str(run_dir / "relay.sqlite3"), "-alpha-local", "-alpha-token-env", TOKEN_ENV],
                relay_cwd,
                processes.minimal_env({TOKEN_ENV: str(token)}),
                log_dir / "relay.log",
            )
            children.append(relay)
            _wait(f"http://127.0.0.1:{relay_port}/health")
        gateway_db_path = run_dir / (f"gateway-{run_state_alias}.sqlite3" if agent_requested else "gateway.sqlite3")
        gateway_args = [node, str(gateway_dir / "server.mjs"), "--mode", "official-agent-local" if agent_requested else "foundation-readonly", "--host", "127.0.0.1", "--port", str(gateway_port), "--state-db", str(gateway_db_path), "--dist-dir", str(web_dir)]
        gateway_env: dict[str, str] = {}
        gateway_extra_fds: list[tuple[int, int]] = []
        if agent_requested:
            gateway_args.extend(["--product-host-socket", str(product_host_socket_path)])
            gateway_args.extend(["--product-host-socket-parent-dev", str(product_host_socket_identity["parent_dev"]), "--product-host-socket-parent-ino", str(product_host_socket_identity["parent_ino"]), "--product-host-socket-dev", str(product_host_socket_identity["socket_dev"]), "--product-host-socket-ino", str(product_host_socket_identity["socket_ino"])])
            gateway_args.extend(["--command-key-fd", "11"])
            gateway_extra_fds.append((command_gateway_read, 11))
        else:
            gateway_args.extend(["--relay-url", f"http://127.0.0.1:{relay_port}"])
            gateway_env[TOKEN_ENV] = token
        if agent_requested:
            # Fill and close the pipe before spawning. The 32-byte key fits in
            # the pipe atomically, and the child observes EOF without a
            # parent/child startup dependency or a synchronous-spawn deadlock.
            _write_fd_secret(command_gateway_write, command_transport_key)
            command_gateway_write = None
        gateway = processes.spawn(
            "gateway",
            gateway_args,
            gateway_dir,
            processes.minimal_env(gateway_env),
            log_dir / (f"gateway-{run_state_alias}.log" if agent_requested else "gateway.log"),
            extra_fd_actions=gateway_extra_fds,
            close_fds=(command_gateway_read,) if agent_requested else (),
        )
        children.append(gateway)
        if agent_requested:
            os.close(command_gateway_read)
            command_gateway_read = None
        _wait(f"http://127.0.0.1:{gateway_port}/")
        if agent_requested:
            session_alias = _wait_official_session(
                f"http://127.0.0.1:{gateway_port}/api/alpha/session"
            )
        agent_enabled = bool(agent_requested)
        state = {
            "schema": STATE_SCHEMA,
            "mode": "official-agent-local" if agent_enabled else "foundation-readonly",
            "real_agent_enabled": agent_enabled,
            "bundle_digest": bundle_digest,
            "blocked_on": (["PRODUCTION_DEVICE_IDENTITY"] if agent_enabled else BLOCKERS),
            "web_url": f"http://127.0.0.1:{gateway_port}/",
            "agent_origin": f"http://127.0.0.1:{_get(config, 'agent_port')}" if agent_enabled else None,
            "agent_version": "1.18.16" if agent_enabled else None,
            "logs_dir": str(log_dir),
            "relay_port": relay_port,
            "gateway_port": gateway_port,
            "agent_port": int(_get(config, "agent_port")),
            # Preserve the state schema without persisting the raw Host run ID.
            "run_id": run_state_alias if agent_enabled else None,
            "session_alias": session_alias if agent_enabled else None,
            "workspace_binding_digest": workspace_digest if agent_enabled else None,
            "product_host_socket_identity": product_host_socket_identity if agent_enabled else None,
            "processes": children,
        }
        write_run_state(config, state)
        return {**state, "state": "RUNNING"}
    except Exception:
        for child in reversed(children):
            processes.stop(child)
        _cleanup_product_host_socket(product_host_socket_path, product_host_socket_identity)
        _cleanup_gateway_db(gateway_db_path, run_dir)
        _cleanup_command_journal(command_journal_path, run_dir)
        raise
    finally:
        if bootstrap_parent is not None: bootstrap_parent.close()
        if bootstrap_child is not None: bootstrap_child.close()
        if command_gateway_read is not None:
            os.close(command_gateway_read)
        if command_gateway_write is not None:
            os.close(command_gateway_write)


def _start_remote_unlocked(
    config: Any, *, provider_name: str, credential_fd: int, workspace: Path,
    public_origin: str, https_listen: str, tls_cert_fd: int, tls_key_fd: int,
) -> dict[str, Any]:
    bundle = select_bundle_for_start(config, getattr(config, "bundle_root", None))
    if bundle is None:
        raise RuntimeError("PREBUILT_BUNDLE_REQUIRED")
    bundle_digest = _selected_bundle_digest(config, bundle)
    existing = read_run_state(config)
    if existing:
        if existing["bundle_digest"] != bundle_digest:
            raise RuntimeError("RUNNING_BUNDLE_BINDING_MISMATCH")
        ownership = [processes.ownership(item) for item in existing["processes"]]
        if "mismatch" in ownership:
            raise RuntimeError("PROCESS_IDENTITY_MISMATCH")
        if all(item == "owned" for item in ownership):
            for descriptor in (credential_fd, tls_cert_fd, tls_key_fd):
                processes.close_fd(descriptor)
            if existing["mode"] != "remote-local-evidence" or existing["pairing_public_origin"] != public_origin:
                raise RuntimeError("MODE_CHANGE_REQUIRES_STOP")
            return _status_unlocked(config)
        for child, ownership_state in reversed(list(zip(existing["processes"], ownership))):
            if ownership_state == "owned" and not processes.stop(child):
                raise RuntimeError("DEGRADED_RECONCILE_FAILED")
        _cleanup_run_artifacts(config, existing)
        state_path(config).unlink(missing_ok=True)

    # Recheck immediately before any child is created. The CLI preflight did
    # not reserve ports, so a racing listener must fail closed.
    if any(not _port_free(_remote_port(config, name)) for name in (
        "relay_port", "relay_device_v1_port", "relay_host_v2_port",
        "relay_device_v2_port", "relay_admin_port", "gateway_port",
        "join_gateway_port", "agent_port",
    )):
        raise RuntimeError("RUNTIME_PORT_IN_USE")
    if not _listen_address_free(https_listen):
        raise RuntimeError("REMOTE_HTTPS_LISTEN_IN_USE")
    repo = Path(_get(config, "repo_root")).resolve()
    home = Path(_get(config, "home")).resolve()
    bin_dir, run_dir, log_dir = home / "bin", home / "run", home / "logs"
    for directory in (bin_dir, run_dir, log_dir):
        if directory.exists() and (not directory.is_dir() or directory.is_symlink()):
            raise RuntimeError("UNSAFE_LAUNCHER_DIRECTORY")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    validate_runtime_dirs(config)
    relay_binary = bundle / "bin" / "nomad-relay"
    host_binary = bundle / "bin" / "nomad-product-host"
    ingress_binary = bundle / "bin" / "nomad-ingress"
    gateway_dir, web_dir = bundle / "gateway", bundle / "web"
    _require_host_identity_ready(host_binary)
    node = shutil.which("node")
    if not node:
        raise RuntimeError("NODE_UNAVAILABLE")

    relay_host_v1_port = _remote_port(config, "relay_port")
    relay_device_v1_port = _remote_port(config, "relay_device_v1_port")
    relay_host_v2_port = _remote_port(config, "relay_host_v2_port")
    relay_device_v2_port = _remote_port(config, "relay_device_v2_port")
    relay_admin_port = _remote_port(config, "relay_admin_port")
    desktop_port = _remote_port(config, "gateway_port")
    join_port = _remote_port(config, "join_gateway_port")
    run_id = secrets.token_hex(32)
    run_state_alias = hashlib.sha256(f"state:{run_id}".encode()).hexdigest()
    device_registry_path = _prepare_device_registry_path(home)
    persistent = _persistent_remote_paths(home)
    command_journal_path = _prepare_command_journal(_make_command_journal_path(run_dir, run_state_alias), run_dir)
    product_host_socket_path = _prepare_product_host_socket(home, run_state_alias)
    product_host_socket_identity: dict[str, int] | None = _socket_parent_identity(product_host_socket_path)
    desktop_db_path = run_dir / f"desktop-gateway-{run_state_alias}.sqlite3"
    relay_host_v1_db = run_dir / "relay-host-v1.sqlite3"
    relay_device_v1_db = run_dir / "relay-device-v1.sqlite3"
    children: list[dict[str, Any]] = []
    opened: list[int] = []
    sockets: list[socket.socket] = []
    try:
        _prepare_run_sqlite(relay_host_v1_db, run_dir)
        _prepare_run_sqlite(relay_device_v1_db, run_dir)
        tls_probe_context = _tls_probe_context(tls_cert_fd)
    except Exception as primary:
        _rollback_remote_start(
            primary, children, product_host_socket_path=product_host_socket_path,
            product_host_socket_identity=product_host_socket_identity,
            desktop_db_path=desktop_db_path, command_journal_path=command_journal_path,
            relay_v1_paths=(relay_host_v1_db, relay_device_v1_db), run_dir=run_dir,
        )

    command_transport_raw = secrets.token_bytes(32)
    join_transport_raw = secrets.token_bytes(32)
    command_authority_raw = secrets.token_bytes(32)
    relay_admin_raw = secrets.token_urlsafe(32).encode("ascii")
    trusted_ingress_raw = secrets.token_bytes(32)
    if len({command_transport_raw, join_transport_raw, command_authority_raw}) != 3:
        raise RuntimeError("REMOTE_KEY_COLLISION")
    command_transport_key = base64.b64encode(command_transport_raw).decode("ascii")
    join_transport_key = base64.b64encode(join_transport_raw).decode("ascii")
    command_authority_key = base64.b64encode(command_authority_raw).decode("ascii")
    try:
        relay_admin_relay_fd = processes.secret_pipe(relay_admin_raw); opened.append(relay_admin_relay_fd)
        relay_host = processes.spawn(
            "relay-host",
            [str(relay_binary), "--addr", f"127.0.0.1:{relay_host_v1_port}", "--db", str(relay_host_v1_db),
             "--v2-enable", "--v2-addr", f"127.0.0.1:{relay_host_v2_port}", "--v2-role", "host",
             "--v2-db", str(persistent["relay_v2_db_path"]), "--v2-loopback-test-http",
             "--v2-admin-addr", f"127.0.0.1:{relay_admin_port}", "--v2-admin-credential-fd", "11"],
            bundle, processes.minimal_env(), log_dir / f"relay-host-{run_state_alias}.log",
            extra_fd_actions=((relay_admin_relay_fd, 11),), close_fds=(relay_admin_relay_fd,),
        )
        children.append(relay_host); processes.close_fd(relay_admin_relay_fd); opened.remove(relay_admin_relay_fd)
        _validate_run_sqlite(relay_host_v1_db, run_dir, require_main=True)
        _wait_relay_role(relay_host_v2_port, role="host")
        _wait_relay_role(relay_admin_port, role="host")

        relay_device = processes.spawn(
            "relay-device",
            [str(relay_binary), "--addr", f"127.0.0.1:{relay_device_v1_port}", "--db", str(relay_device_v1_db),
             "--v2-enable", "--v2-addr", f"127.0.0.1:{relay_device_v2_port}", "--v2-role", "device",
             "--v2-db", str(persistent["relay_v2_db_path"]), "--v2-loopback-test-http",
             "--v2-trusted-tls-terminator-peer", "127.0.0.1"],
            bundle, processes.minimal_env(), log_dir / f"relay-device-{run_state_alias}.log",
        )
        children.append(relay_device)
        _validate_run_sqlite(relay_device_v1_db, run_dir, require_main=True)
        _wait_relay_role(relay_device_v2_port, role="device")

        bootstrap_parent, bootstrap_child = socket.socketpair(); sockets.extend((bootstrap_parent, bootstrap_child))
        relay_admin_host_fd = processes.secret_pipe(relay_admin_raw); opened.append(relay_admin_host_fd)
        host = _spawn_product_host_with_fds(
            host_binary, bundle, log_dir / f"product-host-{run_state_alias}.log", bootstrap_child,
            admin_bearer_fd=relay_admin_host_fd,
        )
        bootstrap_child.close(); sockets.remove(bootstrap_child)
        processes.close_fd(relay_admin_host_fd); opened.remove(relay_admin_host_fd)
        children.append(host)
        agent = start_agent(
            bundle, workspace, run_dir / f"agent-runtime-{run_state_alias}",
            _remote_port(config, "agent_port"), provider_name, credential_fd,
            log_dir / f"agent-{run_state_alias}.log",
        )
        password = agent.pop("_server_password")
        workspace_digest = str(agent.pop("_workspace_binding_digest"))
        agent_record = {key: agent[key] for key in ("name", "pid", "process_group", "identity", "log")}
        children.insert(2, agent_record)
        session_id = _create_run_session(str(agent["origin"]), password)
        remote = {
            "schema": "nomad.product-host.remote-bootstrap.v1",
            "relay_admin_base_url": f"http://127.0.0.1:{relay_admin_port}",
            "relay_host_base_url": f"http://127.0.0.1:{relay_host_v2_port}",
            "relay_device_public_base_url": public_origin,
            "allow_loopback_test_http": True,
            "pairing_store_path": str(persistent["pairing_store_path"]),
            "remote_mailbox_state_path": str(persistent["remote_mailbox_state_path"]),
        }
        product_host_socket_identity = _bootstrap_host(
            bootstrap_parent, run_id=run_id, origin=str(agent["origin"]), session_id=session_id,
            password=password, workspace_digest=workspace_digest, product_host_socket_path=product_host_socket_path,
            device_registry_path=device_registry_path, agent_pid=int(agent["pid"]),
            agent_process_group=int(agent["process_group"]), agent_process_identity=str(agent["identity"]),
            command_transport_key=command_transport_key, join_transport_key=join_transport_key,
            command_authority_key=command_authority_key, command_journal_path=command_journal_path, remote=remote,
        )
        password = ""; bootstrap_parent.close(); sockets.remove(bootstrap_parent)

        socket_args = [
            "--product-host-socket", str(product_host_socket_path),
            "--product-host-socket-parent-dev", str(product_host_socket_identity["parent_dev"]),
            "--product-host-socket-parent-ino", str(product_host_socket_identity["parent_ino"]),
            "--product-host-socket-dev", str(product_host_socket_identity["socket_dev"]),
            "--product-host-socket-ino", str(product_host_socket_identity["socket_ino"]),
        ]
        desktop_key_fd = processes.secret_pipe(command_transport_raw); opened.append(desktop_key_fd)
        desktop = processes.spawn(
            "desktop-gateway",
            [node, str(gateway_dir / "server.mjs"), "--mode", "official-agent-local", "--route-table", "desktop",
             "--host", "127.0.0.1", "--port", str(desktop_port), "--state-db", str(desktop_db_path),
             "--dist-dir", str(web_dir), *socket_args, "--command-key-fd", "11", "--public-origin", public_origin],
            gateway_dir, processes.minimal_env(), log_dir / f"desktop-gateway-{run_state_alias}.log",
            extra_fd_actions=((desktop_key_fd, 11),), close_fds=(desktop_key_fd,),
        )
        children.append(desktop); processes.close_fd(desktop_key_fd); opened.remove(desktop_key_fd)
        _wait_gateway_route(desktop_port, "desktop")

        join_key_fd = processes.secret_pipe(join_transport_raw); trusted_join_fd = processes.secret_pipe(trusted_ingress_raw)
        opened.extend((join_key_fd, trusted_join_fd))
        join_gateway = processes.spawn(
            "join-gateway",
            [node, str(gateway_dir / "server.mjs"), "--mode", "official-agent-local", "--route-table", "join",
             "--host", "127.0.0.1", "--port", str(join_port), "--dist-dir", str(web_dir),
             *socket_args, "--command-key-fd", "11", "--public-origin", public_origin, "--trusted-ingress-fd", "12"],
            gateway_dir, processes.minimal_env(), log_dir / f"join-gateway-{run_state_alias}.log",
            extra_fd_actions=((join_key_fd, 11), (trusted_join_fd, 12)), close_fds=(join_key_fd, trusted_join_fd),
        )
        children.append(join_gateway)
        for descriptor in (join_key_fd, trusted_join_fd):
            processes.close_fd(descriptor); opened.remove(descriptor)
        _wait_gateway_route(join_port, "join")

        trusted_ingress_fd = processes.secret_pipe(trusted_ingress_raw); opened.append(trusted_ingress_fd)
        ready_parent, ready_child = socket.socketpair(); sockets.extend((ready_parent, ready_child))
        ingress = processes.spawn(
            "https-ingress",
            [str(ingress_binary), "--listen", https_listen, "--public-origin", public_origin,
             "--join-upstream", f"http://127.0.0.1:{join_port}",
             "--device-relay-upstream", f"http://127.0.0.1:{relay_device_v2_port}",
             "--tls-cert-fd", "10", "--tls-key-fd", "11",
             "--trusted-join-token-fd", "12", "--ready-fd", "13"],
            bundle, processes.minimal_env(), log_dir / f"https-ingress-{run_state_alias}.log",
            extra_fd_actions=((tls_cert_fd, 10), (tls_key_fd, 11), (trusted_ingress_fd, 12), (ready_child.fileno(), 13)),
            close_fds=(tls_cert_fd, tls_key_fd, trusted_ingress_fd, ready_child.fileno()),
        )
        children.append(ingress)
        ready_child.close(); sockets.remove(ready_child)
        for descriptor in (tls_cert_fd, tls_key_fd, trusted_ingress_fd):
            processes.close_fd(descriptor)
            if descriptor in opened: opened.remove(descriptor)
        _wait_ingress_ready(ready_parent, ingress)
        ready_parent.close(); sockets.remove(ready_parent)
        _probe_public_negative_routes(public_origin, https_listen, tls_probe_context)
        session_alias = "sess-" + hashlib.sha256(f"session:{session_id}".encode()).hexdigest()[:32]

        state = {
            "schema": REMOTE_STATE_SCHEMA, "mode": "remote-local-evidence",
            "real_agent_enabled": True, "remote_enabled": True,
            "bundle_digest": bundle_digest,
            "blocked_on": ["PRODUCTION_EXTERNAL_TOPOLOGY", "PHYSICAL_PHONE_EVIDENCE", "PROVIDER_E3_EVIDENCE"],
            "desktop_url": f"http://127.0.0.1:{desktop_port}/", "pairing_public_origin": public_origin,
            "pairing_ready": True, "remote_mailbox_ready": True, "network_scope": "lan_direct",
            "production_external": False, "agent_origin": f"http://127.0.0.1:{_remote_port(config, 'agent_port')}",
            "agent_version": "1.18.16", "logs_dir": str(log_dir),
            "relay_port": relay_host_v1_port, "relay_device_v1_port": relay_device_v1_port,
            "relay_host_v2_port": relay_host_v2_port, "relay_device_v2_port": relay_device_v2_port,
            "relay_admin_port": relay_admin_port, "gateway_port": desktop_port,
            "join_gateway_port": join_port, "agent_port": _remote_port(config, "agent_port"),
            "run_id": run_state_alias, "session_alias": session_alias,
            "workspace_binding_digest": workspace_digest,
            "product_host_socket_identity": product_host_socket_identity, "processes": children,
        }
        write_run_state(config, state)
        return {**state, "state": "RUNNING"}
    except Exception as primary:
        _rollback_remote_start(
            primary, children, product_host_socket_path=product_host_socket_path,
            product_host_socket_identity=product_host_socket_identity,
            desktop_db_path=desktop_db_path, command_journal_path=command_journal_path,
            relay_v1_paths=(relay_host_v1_db, relay_device_v1_db), run_dir=run_dir,
        )
    finally:
        for descriptor in opened:
            processes.close_fd(descriptor)
        for descriptor in (credential_fd, tls_cert_fd, tls_key_fd):
            processes.close_fd(descriptor)
        for channel in sockets:
            channel.close()


def status_foundation(config: Any) -> dict[str, Any]:
    with lifecycle_lock(config, create=False) as owned:
        return _status_unlocked(config) if owned else _stopped()


def restart_foundation(
    config: Any, *, provider_name: str | None = None, credential_fd: int | None = None,
    workspace: Path | None = None, remote_local_evidence: bool = False,
    public_origin: str | None = None, https_listen: str | None = None,
    tls_cert_fd: int | None = None, tls_key_fd: int | None = None,
) -> dict[str, Any]:
    if remote_local_evidence:
        _preflight_remote_agent(provider_name, credential_fd, workspace)
        public_origin, https_listen, _ = _validate_remote_inputs(
            config, public_origin=public_origin, https_listen=https_listen,
            tls_cert_fd=tls_cert_fd, tls_key_fd=tls_key_fd, check_availability=False,
        )
    initialize_home(config)
    try:
        with lifecycle_lock(config, create=True):
            _stop_unlocked(config)
            if remote_local_evidence:
                _wait_ports_free([
                    _remote_port(config, name) for name in (
                        "relay_port", "relay_device_v1_port", "relay_host_v2_port",
                        "relay_device_v2_port", "relay_admin_port", "gateway_port",
                        "join_gateway_port", "agent_port",
                    )
                ])
                deadline = time.monotonic() + 10.0
                while not _listen_address_free(str(https_listen)):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("HTTPS_LISTEN_RELEASE_TIMEOUT")
                    time.sleep(0.05)
                return _start_remote_unlocked(
                    config, provider_name=str(provider_name), credential_fd=int(credential_fd),
                    workspace=Path(workspace), public_origin=str(public_origin), https_listen=str(https_listen),
                    tls_cert_fd=int(tls_cert_fd), tls_key_fd=int(tls_key_fd),
                )
            return _start_unlocked(
                config, provider_name=provider_name, credential_fd=credential_fd, workspace=workspace,
            )
    except Exception:
        for descriptor in (credential_fd, tls_cert_fd, tls_key_fd):
            processes.close_fd(descriptor)
        raise


def _stopped() -> dict[str, Any]:
    return {"schema": STATE_SCHEMA, "state": "STOPPED", "mode": "foundation-readonly", "real_agent_enabled": False, "blocked_on": BLOCKERS}


def _status_unlocked(config: Any) -> dict[str, Any]:
    state = read_run_state(config)
    if not state:
        return _stopped()
    process_state = [{"name": item["name"], "pid": item["pid"], "alive": processes.alive(item)} for item in state["processes"]]
    return {**state, "state": "RUNNING" if all(item["alive"] for item in process_state) else "DEGRADED", "processes": process_state}


def stop_foundation(config: Any) -> dict[str, Any]:
    with lifecycle_lock(config, create=False) as owned:
        return _stop_unlocked(config) if owned else _stopped()


def _stop_unlocked(config: Any) -> dict[str, Any]:
    state = read_run_state(config)
    if state:
        ownership = [processes.ownership(child) for child in state["processes"]]
        if "mismatch" in ownership:
            raise RuntimeError("PROCESS_IDENTITY_MISMATCH")
        for child in reversed(state["processes"]):
            if processes.ownership(child) == "owned" and not processes.stop(child):
                raise RuntimeError("PROCESS_STOP_FAILED")
        _cleanup_run_artifacts(config, state)
        state_path(config).unlink(missing_ok=True)
    return _stopped()


def _cleanup_run_artifacts(config: Any, state: dict[str, Any]) -> None:
    home = Path(_get(config, "home")).resolve()
    run_dir = home / "run"
    if state["mode"] in ("official-agent-local", "remote-local-evidence"):
        _cleanup_product_host_socket(_product_host_socket_path(home, state["run_id"]), state["product_host_socket_identity"])
        _cleanup_command_journal(_make_command_journal_path(run_dir, state["run_id"]), run_dir)
        database = run_dir / (f"desktop-gateway-{state['run_id']}.sqlite3" if state["mode"] == "remote-local-evidence" else f"gateway-{state['run_id']}.sqlite3")
        if state["mode"] == "remote-local-evidence":
            for relay_db in (run_dir / "relay-host-v1.sqlite3", run_dir / "relay-device-v1.sqlite3"):
                _cleanup_gateway_db(relay_db, run_dir)
    else:
        database = run_dir / "gateway.sqlite3"
    _cleanup_gateway_db(database, run_dir)


def uninstall_foundation(config: Any) -> dict[str, Any]:
    with lifecycle_lock(config, create=False) as owned:
        if not owned:
            return {"schema": STATE_SCHEMA, "state": "UNINSTALLED", "mode": "foundation-readonly", "real_agent_enabled": False, "blocked_on": BLOCKERS}
        current = read_run_state(config)
        home = Path(_get(config, "home")).absolute()
        if (current is not None and current["mode"] == "remote-local-evidence") or _remote_persistent_state_present(home):
            raise RuntimeError("REMOTE_UNINSTALL_REVOKE_REQUIRED")
        _stop_unlocked(config)
        if home == Path.home().resolve() or home == Path("/"):
            raise RuntimeError("UNSAFE_UNINSTALL_ROOT")
        validate_home(config)
        allowed = {HOME_MARKER, "bin", "run", "logs", "bundles", "install", DEVICE_REGISTRY_DIRNAME}
        if not {entry.name for entry in home.iterdir()}.issubset(allowed):
            raise RuntimeError("UNSAFE_NOMAD_WEB_HOME_CONTENTS")
        validate_runtime_dirs(config)
        root = home.resolve(strict=True)
        _cleanup_device_registry(_device_registry_path(home))
        for name in ("run", "logs", "bin", "bundles", "install", HOME_MARKER):
            _safe_remove_tree(home / name, root=root)
        home.rmdir()
    return {"schema": STATE_SCHEMA, "state": "UNINSTALLED", "mode": "foundation-readonly", "real_agent_enabled": False, "blocked_on": BLOCKERS}
