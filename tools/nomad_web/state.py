from __future__ import annotations

import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

MAX_STATE_BYTES = 64 * 1024
STATE_SCHEMA = "nomad.web-companion.state.v1"
REMOTE_STATE_SCHEMA = "nomad.web-companion.state.v2"
HOME_SCHEMA = "nomad.web-companion.home.v1"
HOME_MARKER = ".nomad-web-home.json"
RUN_KEYS = {
    "schema", "mode", "real_agent_enabled", "blocked_on",
    "bundle_digest",
    "web_url", "agent_origin", "agent_version", "logs_dir", "relay_port", "gateway_port", "agent_port", "processes",
    "run_id", "session_alias", "workspace_binding_digest", "product_host_socket_identity",
}
PROCESS_KEYS = {"name", "pid", "process_group", "identity", "log"}
SOCKET_IDENTITY_KEYS = {"parent_dev", "parent_ino", "parent_uid", "parent_mode", "socket_dev", "socket_ino", "socket_uid", "socket_mode"}
REMOTE_RUN_KEYS = {
    "schema", "mode", "real_agent_enabled", "remote_enabled",
    "bundle_digest",
    "blocked_on", "desktop_url", "pairing_public_origin",
    "pairing_ready", "remote_mailbox_ready", "network_scope",
    "production_external", "agent_origin", "agent_version",
    "logs_dir", "relay_port", "gateway_port", "agent_port",
    "join_gateway_port", "relay_host_v2_port",
    "relay_device_v2_port", "relay_admin_port",
    "relay_device_v1_port", "processes", "run_id",
    "session_alias", "workspace_binding_digest",
    "product_host_socket_identity",
}


def state_path(config: Any) -> Path:
    return Path(config.home) / "run" / "status.json"


def initialize_home(config: Any) -> None:
    home = Path(config.home)
    _reject_symlink_components(home)
    if os.path.lexists(home):
        info = home.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("UNSAFE_NOMAD_WEB_HOME")
        entries = list(home.iterdir())
        if entries and not (home / HOME_MARKER).exists():
            raise RuntimeError("UNOWNED_NOMAD_WEB_HOME")
    else:
        home.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(home, 0o700)
    marker = home / HOME_MARKER
    if marker.exists():
        validate_home(config)
        return
    value = {"schema": HOME_SCHEMA, "classification": "repo-local-foundation"}
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        validate_home(config)
        return
    try:
        os.write(fd, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_home(config: Any) -> None:
    home = Path(config.home)
    _reject_symlink_components(home)
    try:
        info = home.lstat()
    except OSError as error:
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("UNSAFE_NOMAD_WEB_HOME")
    marker = home / HOME_MARKER
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise RuntimeError("UNOWNED_NOMAD_WEB_HOME") from error
    try:
        info = os.fstat(fd)
        raw = os.read(fd, 1025)
    finally:
        os.close(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or len(raw) > 1024:
        raise RuntimeError("UNSAFE_HOME_MARKER")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("UNSAFE_HOME_MARKER") from error
    if value != {"schema": HOME_SCHEMA, "classification": "repo-local-foundation"}:
        raise RuntimeError("UNSAFE_HOME_MARKER")


def validate_runtime_dirs(config: Any) -> None:
    validate_home(config)
    home = Path(config.home)
    for name in ("bin", "run", "logs"):
        path = home / name
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise RuntimeError("UNSAFE_LAUNCHER_DIRECTORY") from error
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
        ):
            raise RuntimeError("UNSAFE_LAUNCHER_DIRECTORY")


def _reject_symlink_components(path: Path) -> None:
    macos_system_aliases = {
        Path("/var"): Path("/private/var"),
        Path("/tmp"): Path("/private/tmp"),
    }
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            continue
        if stat.S_ISLNK(current.lstat().st_mode):
            expected = macos_system_aliases.get(current)
            if expected is not None and current.resolve() == expected:
                continue
            raise RuntimeError("UNSAFE_NOMAD_WEB_HOME")


@contextmanager
def lifecycle_lock(config: Any, *, create: bool):
    home = Path(config.home)
    if not os.path.lexists(home):
        if not create:
            yield False
            return
        initialize_home(config)
    validate_home(config)
    marker = home / HOME_MARKER
    fd = os.open(marker, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        validate_home(config)
        yield True
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def read_run_state(config: Any) -> dict[str, Any] | None:
    if Path(config.home).exists():
        validate_home(config)
        run_dir = Path(config.home) / "run"
        if run_dir.exists() or run_dir.is_symlink():
            validate_runtime_dirs(config)
    path = state_path(config)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise RuntimeError("UNSAFE_STATE_FILE")
        raw = os.read(fd, MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise RuntimeError("STATE_FILE_TOO_LARGE")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("INVALID_STATE") from error
    validate_run_state(config, value)
    return value


def write_run_state(config: Any, value: dict[str, Any]) -> None:
    validate_runtime_dirs(config)
    validate_run_state(config, value)
    path = state_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.parent / f".status-{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > MAX_STATE_BYTES:
            raise RuntimeError("STATE_FILE_TOO_LARGE")
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def validate_run_state(config: Any, value: Any) -> None:
    if not isinstance(value, dict):
        raise RuntimeError("INVALID_STATE")
    if value.get("schema") == REMOTE_STATE_SCHEMA:
        _validate_remote_run_state(config, value)
        return
    if set(value) != RUN_KEYS:
        raise RuntimeError("INVALID_STATE")
    if value["schema"] != STATE_SCHEMA or value["mode"] not in ("foundation-readonly", "official-agent-local"):
        raise RuntimeError("INVALID_STATE")
    agent_enabled = value["mode"] == "official-agent-local"
    if value["real_agent_enabled"] is not agent_enabled:
        raise RuntimeError("INVALID_STATE")
    expected_blockers = (["PRODUCTION_DEVICE_IDENTITY"] if agent_enabled else ["B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY"])
    if value["blocked_on"] != expected_blockers:
        raise RuntimeError("INVALID_STATE")
    if value["bundle_digest"] is not None and (
        not isinstance(value["bundle_digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["bundle_digest"]) is None
    ):
        raise RuntimeError("INVALID_STATE")
    if agent_enabled and value["bundle_digest"] is None:
        raise RuntimeError("INVALID_STATE")
    if value["relay_port"] != config.relay_port or value["gateway_port"] != config.gateway_port or value["agent_port"] != config.agent_port:
        raise RuntimeError("INVALID_STATE")
    if value["web_url"] != f"http://127.0.0.1:{config.gateway_port}/":
        raise RuntimeError("INVALID_STATE")
    if Path(value["logs_dir"]).resolve(strict=False) != (Path(config.home) / "logs").resolve(strict=False):
        raise RuntimeError("INVALID_STATE")
    processes = value["processes"]
    expected_processes = ["opencode", "product-host", "gateway"] if agent_enabled else ["relay", "gateway"]
    if not isinstance(processes, list) or [item.get("name") for item in processes if isinstance(item, dict)] != expected_processes:
        raise RuntimeError("INVALID_STATE")
    if agent_enabled:
        if value["agent_origin"] != f"http://127.0.0.1:{config.agent_port}" or value["agent_version"] != "1.18.16":
            raise RuntimeError("INVALID_STATE")
        if not all(isinstance(value[name], str) and len(value[name]) == 64 and all(c in "0123456789abcdef" for c in value[name]) for name in ("run_id", "workspace_binding_digest")):
            raise RuntimeError("INVALID_STATE")
        if not isinstance(value["session_alias"], str) or re.fullmatch(r"sess-[0-9a-f]{32}", value["session_alias"]) is None:
            raise RuntimeError("INVALID_STATE")
        socket_identity = value["product_host_socket_identity"]
        if not isinstance(socket_identity, dict) or set(socket_identity) != SOCKET_IDENTITY_KEYS:
            raise RuntimeError("INVALID_STATE")
        if any(type(socket_identity[name]) is not int or socket_identity[name] <= 0 for name in ("parent_dev", "parent_ino", "socket_dev", "socket_ino")):
            raise RuntimeError("INVALID_STATE")
        if socket_identity["parent_uid"] != os.geteuid() or socket_identity["socket_uid"] != os.geteuid() or socket_identity["parent_mode"] != 0o700 or socket_identity["socket_mode"] != 0o600:
            raise RuntimeError("INVALID_STATE")
    elif value["agent_origin"] is not None or value["agent_version"] is not None:
        raise RuntimeError("INVALID_STATE")
    elif any(value[name] is not None for name in ("run_id", "session_alias", "workspace_binding_digest", "product_host_socket_identity")):
        raise RuntimeError("INVALID_STATE")
    home = Path(config.home).resolve()
    for item in processes:
        if set(item) != PROCESS_KEYS or type(item["pid"]) is not int or item["pid"] <= 1 or item["process_group"] != item["pid"]:
            raise RuntimeError("INVALID_STATE")
        if not isinstance(item["identity"], str) or len(item["identity"]) != 64:
            raise RuntimeError("INVALID_STATE")
        log = Path(item["log"]).resolve(strict=False)
        if not log.is_relative_to(home / "logs"):
            raise RuntimeError("INVALID_STATE")


def _config_port(config: Any, name: str) -> int:
    try:
        return int(getattr(config, name))
    except (AttributeError, TypeError, ValueError) as error:
        raise RuntimeError("INVALID_STATE") from error


def _validate_remote_run_state(config: Any, value: dict[str, Any]) -> None:
    if set(value) != REMOTE_RUN_KEYS:
        raise RuntimeError("INVALID_STATE")
    if (
        value["mode"] != "remote-local-evidence"
        or value["real_agent_enabled"] is not True
        or value["remote_enabled"] is not True
        or value["pairing_ready"] is not True
        or value["remote_mailbox_ready"] is not True
        or value["network_scope"] != "lan_direct"
        or value["production_external"] is not False
        or not isinstance(value["bundle_digest"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["bundle_digest"]) is None
        or not isinstance(value["blocked_on"], list)
        or not all(isinstance(item, str) and item for item in value["blocked_on"])
    ):
        raise RuntimeError("INVALID_STATE")
    expected_ports = {
        "relay_port": "relay_port",
        "gateway_port": "gateway_port",
        "agent_port": "agent_port",
        "join_gateway_port": "join_gateway_port",
        "relay_host_v2_port": "relay_host_v2_port",
        "relay_device_v2_port": "relay_device_v2_port",
        "relay_admin_port": "relay_admin_port",
        "relay_device_v1_port": "relay_device_v1_port",
    }
    if any(value[field] != _config_port(config, attribute) for field, attribute in expected_ports.items()):
        raise RuntimeError("INVALID_STATE")
    if value["desktop_url"] != f"http://127.0.0.1:{_config_port(config, 'gateway_port')}/":
        raise RuntimeError("INVALID_STATE")
    if (
        not isinstance(value["pairing_public_origin"], str)
        or not value["pairing_public_origin"].startswith("https://")
        or value["agent_origin"] != f"http://127.0.0.1:{_config_port(config, 'agent_port')}"
        or value["agent_version"] != "1.18.16"
        or Path(value["logs_dir"]).resolve(strict=False) != (Path(config.home) / "logs").resolve(strict=False)
    ):
        raise RuntimeError("INVALID_STATE")
    for name in ("run_id", "workspace_binding_digest"):
        if not isinstance(value[name], str) or re.fullmatch(r"[0-9a-f]{64}", value[name]) is None:
            raise RuntimeError("INVALID_STATE")
    if not isinstance(value["session_alias"], str) or re.fullmatch(r"sess-[0-9a-f]{32}", value["session_alias"]) is None:
        raise RuntimeError("INVALID_STATE")
    socket_identity = value["product_host_socket_identity"]
    if not isinstance(socket_identity, dict) or set(socket_identity) != SOCKET_IDENTITY_KEYS:
        raise RuntimeError("INVALID_STATE")
    if any(type(socket_identity[name]) is not int or socket_identity[name] <= 0 for name in ("parent_dev", "parent_ino", "socket_dev", "socket_ino")):
        raise RuntimeError("INVALID_STATE")
    if socket_identity["parent_uid"] != os.geteuid() or socket_identity["socket_uid"] != os.geteuid() or socket_identity["parent_mode"] != 0o700 or socket_identity["socket_mode"] != 0o600:
        raise RuntimeError("INVALID_STATE")
    expected_names = [
        "relay-host", "relay-device", "opencode", "product-host",
        "desktop-gateway", "join-gateway", "https-ingress",
    ]
    processes = value["processes"]
    if not isinstance(processes, list) or [item.get("name") for item in processes if isinstance(item, dict)] != expected_names:
        raise RuntimeError("INVALID_STATE")
    home = Path(config.home).resolve()
    for item in processes:
        if set(item) != PROCESS_KEYS or type(item["pid"]) is not int or item["pid"] <= 1 or item["process_group"] != item["pid"]:
            raise RuntimeError("INVALID_STATE")
        if not isinstance(item["identity"], str) or re.fullmatch(r"[0-9a-f]{64}", item["identity"]) is None:
            raise RuntimeError("INVALID_STATE")
        if not Path(item["log"]).resolve(strict=False).is_relative_to(home / "logs"):
            raise RuntimeError("INVALID_STATE")
