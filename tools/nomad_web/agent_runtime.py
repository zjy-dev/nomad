"""Owned lifecycle for the verified OpenCode binary in a Nomad bundle.

Provider credentials are copied only into the Agent child's environment. They
are never placed in argv, state, receipts, or logs. Agent output is discarded
until a separately reviewed redaction boundary exists.
"""

from __future__ import annotations

import hashlib
import array
import base64
import fcntl
import json
import os
import socket
import secrets
import stat
import sys
import termios
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Mapping

from . import processes
from .bundle import AGENT_ENTRYPOINT_SHA256, AGENT_RUNTIME, verify_bundle

PROVIDER_ENV_NAMES = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
)
MAX_HEALTH_BYTES = 4096
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
BOOTSTRAP = """
import os
import sys

fd = int(sys.argv[1])
name = sys.argv[2]
server_fd = int(sys.argv[3])
workspace_fd = int(sys.argv[4])
executable = sys.argv[5]
port = sys.argv[6]
def read_secret(descriptor):
    data = bytearray()
    while len(data) <= 16384:
        part = os.read(descriptor, min(4096, 16385 - len(data)))
        if not part: break
        data.extend(part)
    os.close(descriptor)
    if not 0 < len(data) <= 16384 or any(byte in data for byte in (0, 10, 13)): sys.exit(70)
    try: value = data.decode("utf-8")
    except UnicodeDecodeError: sys.exit(70)
    data[:] = bytes([0]) * len(data)
    return value
secret = read_secret(fd)
server_password = read_secret(server_fd)
try:
    os.fchdir(workspace_fd)
finally:
    os.close(workspace_fd)
environment = dict(os.environ)
environment[name] = secret
environment["OPENCODE_SERVER_PASSWORD"] = server_password
os.execve(
    executable,
    [executable, "serve", "--pure", "--hostname", "127.0.0.1", "--port", port],
    environment,
)
"""


def start_agent(
    bundle: Path,
    workspace: Path,
    runtime_root: Path,
    port: int,
    provider_name: str,
    credential_fd: int,
    log_path: Path | None = None,
) -> dict[str, object]:
    """Start one verified Agent or fail before spawning any child."""
    credential_owned = True
    workspace_fd = None
    try:
        manifest = verify_bundle(bundle)
        if manifest.get("agent_runtime") != AGENT_RUNTIME:
            raise RuntimeError("AGENT_RUNTIME_UNVERIFIED")
        executable = bundle.resolve(strict=True) / str(AGENT_RUNTIME["entrypoint"])
        _verify_executable(executable)
        workspace, workspace_binding_digest, workspace_fd = _verified_workspace(workspace)
        runtime_root = _owned_directory(runtime_root, create=True)
        home = _owned_directory(runtime_root / "home", create=True)
        xdg = _owned_directory(runtime_root / "xdg", create=True)
        if not 1024 <= port <= 65535 or not _port_free(port):
            raise RuntimeError("AGENT_LOOPBACK_PORT_UNAVAILABLE")
        _validate_credential_source(provider_name, credential_fd)
        server_password = secrets.token_urlsafe(32)

        child_env = {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(xdg / "config"),
            "XDG_DATA_HOME": str(xdg / "data"),
            "XDG_CACHE_HOME": str(xdg / "cache"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
        for path in (xdg / "config", xdg / "data", xdg / "cache"):
            _owned_directory(path, create=True)
        argv = [str(executable), str(port)]
        if log_path is None:
            log_path = runtime_root / "agent.log"
        log_path = log_path.absolute()
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        pid = _spawn_with_credential_fd(argv, child_env, provider_name, credential_fd, server_password, workspace_fd)
        credential_owned = False
    except Exception:
        raise
    finally:
        if credential_owned:
            try:
                os.close(credential_fd)
            except OSError:
                pass
        if workspace_fd is not None:
            try:
                os.close(workspace_fd)
            except OSError:
                pass
    try:
        _wait_health(port, server_password, pid)
    except Exception:
        _terminate_group(pid)
        raise
    try:
        identity = processes.process_identity(pid)
    except Exception:
        _terminate_group(pid)
        raise
    record = {
        "name": "opencode",
        "pid": pid,
        "process_group": pid,
        "identity": identity,
        "log": str(log_path),
    }
    return {
        **record,
        "origin": f"http://127.0.0.1:{port}",
        "package": "opencode-ai",
        "version": "1.18.16",
        "classification": "verified-bundle-runtime-not-provider-evidence",
        "_server_password": server_password,
        "_workspace_binding_digest": workspace_binding_digest,
    }


def stop_agent(record: Mapping[str, object]) -> None:
    if not processes.stop(record):
        raise RuntimeError("AGENT_PROCESS_STOP_FAILED")


def _validate_credential_source(provider_name: str, descriptor: int) -> None:
    if type(descriptor) is not int or descriptor < 3:
        raise RuntimeError("EXACTLY_ONE_PROVIDER_CREDENTIAL_REQUIRED")
    if provider_name not in PROVIDER_ENV_NAMES:
        raise RuntimeError("EXACTLY_ONE_PROVIDER_CREDENTIAL_REQUIRED")
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        raise RuntimeError("INVALID_PROVIDER_CREDENTIAL") from error
    if not (stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode)):
        raise RuntimeError("INVALID_PROVIDER_CREDENTIAL")
    # Query only the byte count. The launcher never reads credential bytes;
    # the exec bootstrap is their sole consumer. CLI stdin must already be a
    # closed, fully buffered pipe rather than an interactive terminal.
    available = array.array("i", [0])
    try:
        fcntl.ioctl(descriptor, termios.FIONREAD, available, True)
    except OSError as error:
        raise RuntimeError("INVALID_PROVIDER_CREDENTIAL") from error
    if not 0 < available[0] <= 16 * 1024:
        raise RuntimeError("INVALID_PROVIDER_CREDENTIAL")


def _owned_directory(path: Path, *, create: bool) -> Path:
    path = path.absolute()
    _reject_symlink_components(path)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    info = path.lstat()
    resolved = path.resolve(strict=True)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o022
    ):
        raise RuntimeError("UNSAFE_AGENT_DIRECTORY")
    return resolved

def _verified_workspace(path: Path) -> tuple[Path, str, int]:
    path = path.absolute(); _reject_symlink_components(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor); resolved = path.resolve(strict=True); observed = resolved.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or (info.st_dev,info.st_ino)!=(observed.st_dev,observed.st_ino):
            raise RuntimeError("UNSAFE_AGENT_DIRECTORY")
        digest=hashlib.sha256(f"{resolved}:{info.st_dev}:{info.st_ino}".encode()).hexdigest()
        return resolved,digest,descriptor
    except Exception:
        os.close(descriptor)
        raise


def _reject_symlink_components(path: Path) -> None:
    system_aliases = {Path("/var"): Path("/private/var"), Path("/tmp"): Path("/private/tmp")}
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            continue
        if stat.S_ISLNK(current.lstat().st_mode):
            expected = system_aliases.get(current)
            if expected is None or current.resolve() != expected:
                raise RuntimeError("UNSAFE_AGENT_DIRECTORY")


def _verify_executable(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o111 == 0:
            raise RuntimeError("AGENT_ENTRYPOINT_UNSAFE")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    if digest.hexdigest() != AGENT_ENTRYPOINT_SHA256:
        raise RuntimeError("AGENT_ENTRYPOINT_MISMATCH")


def _spawn_with_credential_fd(
    agent_argv: list[str],
    environment: Mapping[str, str],
    provider_name: str,
    credential_fd: int,
    server_password: str,
    workspace_fd: int,
) -> int:
    devnull = os.open(os.devnull, os.O_RDWR | os.O_CLOEXEC)
    child_secret_fd = 9
    child_server_fd = 8
    child_workspace_fd = 7
    executable, port = agent_argv
    server_read, server_write = socket.socketpair()
    server_write.sendall(server_password.encode())
    server_write.shutdown(socket.SHUT_WR)
    safe_devnull = fcntl.fcntl(devnull, fcntl.F_DUPFD_CLOEXEC, 20)
    safe_credential = fcntl.fcntl(credential_fd, fcntl.F_DUPFD_CLOEXEC, 20)
    safe_server = fcntl.fcntl(server_read.fileno(), fcntl.F_DUPFD_CLOEXEC, 20)
    safe_workspace = fcntl.fcntl(workspace_fd, fcntl.F_DUPFD_CLOEXEC, 20)
    argv = [sys.executable, "-I", "-B", "-c", BOOTSTRAP, str(child_secret_fd), provider_name, str(child_server_fd), str(child_workspace_fd), executable, port]
    try:
        pid = os.posix_spawn(
            sys.executable,
            argv,
            dict(environment),
            file_actions=[
                (os.POSIX_SPAWN_DUP2, safe_devnull, 0),
                (os.POSIX_SPAWN_DUP2, safe_devnull, 1),
                (os.POSIX_SPAWN_DUP2, safe_devnull, 2),
                (os.POSIX_SPAWN_DUP2, safe_credential, child_secret_fd),
                (os.POSIX_SPAWN_DUP2, safe_server, child_server_fd),
                (os.POSIX_SPAWN_DUP2, safe_workspace, child_workspace_fd),
                (os.POSIX_SPAWN_CLOSE, safe_devnull),
            ],
            setsid=True,
        )
    finally:
        os.close(devnull)
        server_read.close()
        server_write.close()
        for descriptor in (safe_devnull, safe_credential, safe_server, safe_workspace):
            os.close(descriptor)
        try:
            os.close(credential_fd)
        except OSError:
            pass
    return pid


def _terminate_group(pid: int) -> None:
    try:
        os.killpg(pid, 9)
    except ProcessLookupError:
        return
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _wait_health(
    port: int, server_password: str, pid: int | None = None, timeout: float = 20.0
) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/global/health"
    _validate_loopback_url(url, port, "/global/health")
    while time.monotonic() < deadline:
        if pid is not None:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                raise RuntimeError("AGENT_START_FAILED")
        try:
            token = base64.b64encode(f"opencode:{server_password}".encode()).decode()
            request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
            _validate_loopback_url(request.full_url, port, "/global/health")
            with _NO_PROXY_OPENER.open(request, timeout=1) as response:
                raw = response.read(MAX_HEALTH_BYTES + 1)
            value = json.loads(raw, object_pairs_hook=_unique_object)
            if (
                len(raw) <= MAX_HEALTH_BYTES
                and type(value) is dict and set(value) == {"healthy", "version"}
                and type(value["healthy"]) is bool and value["healthy"] is True
                and type(value["version"]) is str and value["version"] == "1.18.16"
            ):
                return
        except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
            time.sleep(0.05)
    raise RuntimeError("AGENT_HEALTH_TIMEOUT")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError("duplicate")
        value[key] = item
    return value


def _validate_loopback_url(url: str, port: int, path: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != port or parsed.username is not None or parsed.password is not None or parsed.path != path or parsed.query or parsed.fragment:
        raise RuntimeError("AGENT_LOOPBACK_URL_INVALID")


def _port_free(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.1)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            return False
    with socket.socket() as listener:
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
