from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

HOST_IDENTITY_ROOT_ENV = "NOMAD_HOST_IDENTITY_ROOT"


@dataclass(frozen=True)
class Config:
    repo_root: Path
    home: Path
    relay_port: int
    gateway_port: int
    agent_port: int
    bundle_root: Path | None = None
    join_gateway_port: int = 14174
    relay_host_v2_port: int = 18090
    relay_device_v2_port: int = 18091
    relay_admin_port: int = 18092
    relay_device_v1_port: int = 18093

    @property
    def desktop_gateway_port(self) -> int:
        return self.gateway_port

    @property
    def relay_host_v1_port(self) -> int:
        return self.relay_port

    @classmethod
    def load(cls, repo_root: Path | None = None) -> "Config":
        root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        configured_home = os.environ.get("NOMAD_WEB_HOME")
        home = Path(configured_home).expanduser() if configured_home else Path.home() / ".nomad" / "web-companion"
        if not home.is_absolute():
            raise RuntimeError("NOMAD_WEB_HOME_MUST_BE_ABSOLUTE")
        # Keep the lexical path. Resolving here would hide a symlink root and
        # could turn uninstall into deletion of the symlink target.
        home = Path(os.path.abspath(os.fspath(home)))
        resolved_for_comparison = home.resolve(strict=False)
        if resolved_for_comparison == Path("/") or resolved_for_comparison == Path.home().resolve():
            raise RuntimeError("UNSAFE_NOMAD_WEB_HOME")
        relay_port = _port("NOMAD_WEB_RELAY_PORT", 18089)
        gateway_port = _port("NOMAD_WEB_GATEWAY_PORT", 14173)
        agent_port = _port("NOMAD_WEB_AGENT_PORT", 4096)
        join_gateway_port = _port("NOMAD_WEB_JOIN_GATEWAY_PORT", 14174)
        relay_host_v2_port = _port("NOMAD_WEB_RELAY_HOST_V2_PORT", 18090)
        relay_device_v2_port = _port("NOMAD_WEB_RELAY_DEVICE_V2_PORT", 18091)
        relay_admin_port = _port("NOMAD_WEB_RELAY_ADMIN_PORT", 18092)
        relay_device_v1_port = _port("NOMAD_WEB_RELAY_DEVICE_V1_PORT", 18093)
        ports = {
            relay_port, gateway_port, agent_port, join_gateway_port,
            relay_host_v2_port, relay_device_v2_port, relay_admin_port,
            relay_device_v1_port,
        }
        if len(ports) != 8:
            raise RuntimeError("DUPLICATE_LOOPBACK_PORT")
        bundle_value = os.environ.get("NOMAD_WEB_BUNDLE")
        bundle_root = Path(bundle_value).absolute() if bundle_value else None
        return cls(
            root, home, relay_port, gateway_port, agent_port, bundle_root,
            join_gateway_port, relay_host_v2_port, relay_device_v2_port,
            relay_admin_port, relay_device_v1_port,
        )


def host_identity_root(config: object | None = None) -> Path:
    if isinstance(config, Config):
        root = Path.home() / "Library" / "Application Support" / "Nomad" / "host-identity"
    else:
        override = getattr(config, "_test_host_identity_root", None) if config is not None else None
        root = Path(override).expanduser() if override is not None else Path.home() / "Library" / "Application Support" / "Nomad" / "host-identity"
    if not root.is_absolute():
        raise RuntimeError("HOST_IDENTITY_ROOT_INVALID")
    return root.resolve(strict=False)


def ensure_host_identity_root(config: object | None = None) -> Path:
    root = host_identity_root(config)
    parents = list(reversed(root.parents))
    if not parents or parents[0] != Path("/"):
        raise RuntimeError("HOST_IDENTITY_ROOT_INVALID")
    target_chain = [path for path in parents if path != Path("/")] + [root]
    for path in target_chain:
        if os.path.lexists(path):
            info = path.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
            ):
                raise RuntimeError("HOST_IDENTITY_ROOT_INVALID")
            mode = stat.S_IMODE(info.st_mode)
            if path == root:
                if info.st_uid != os.geteuid() or mode != 0o700:
                    raise RuntimeError("HOST_IDENTITY_ROOT_INVALID")
            else:
                if info.st_uid not in {0, os.geteuid()} or mode & 0o022:
                    raise RuntimeError("HOST_IDENTITY_ROOT_INVALID")
            continue
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RuntimeError("HOST_IDENTITY_ROOT_INVALID")
    return root


def _port(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as error:
        raise RuntimeError(f"INVALID_{name}") from error
    if not 1024 <= value <= 65535:
        raise RuntimeError(f"INVALID_{name}")
    return value
