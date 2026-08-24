"""A2 audit-only integration harness; it cannot certify or enable M2."""

from __future__ import annotations

import json
import importlib.util
import os
import secrets
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from testkit.pilot.observing_proxy import ObservingProxy

_CHILD_PROBE = (
    "import json,os,socket,sys; s=socket.socket(fileno=int(sys.argv[1])); "
    "data=os.read(int(sys.argv[2]),32); s.sendall(b'P'); "
    "print(json.dumps({'kind':'TEST_PEER_ONLY_FD_DELIVERY','secret_bytes':len(data),'socket_ok':True},sort_keys=True))"
)


@dataclass(frozen=True)
class IntegrationResult:
    """Content-free public outcome."""

    status: str
    reason: str


class Launch(Protocol):
    root: Path
    install: Path
    workspace: Path
    port: int
    process: object

    def cleanup(self) -> None: ...


def _load_wp1_capture():
    """Load WP1 without importing its hyphenated directory as a package."""
    path = Path(__file__).resolve().parents[1] / "stock-opencode" / "real_task_capture.py"
    spec = importlib.util.spec_from_file_location("nomad_wp1_real_task_capture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("wp1")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def production_harness() -> "M2IntegrationHarness":
    """Build the real WP1-backed harness without reading credentials itself."""
    wp1 = _load_wp1_capture()

    def launch(*, provider_credential_env: str, environment: Mapping[str, str] | None) -> Launch:
        task_spec = wp1.load_task_spec()
        return wp1.launch_locked_opencode(
            provider_credential_env=provider_credential_env, task_spec=task_spec, environment=environment
        )

    return M2IntegrationHarness(credential_present=wp1.credential_present, launcher=launch)


class M2IntegrationHarness:
    """Owns A2 resources and reports audit-only, permanently blocked results."""

    def __init__(self, *, credential_present: Callable[[str, Mapping[str, str] | None], bool],
                 launcher: Callable[..., Launch], proxy_factory: Callable[[str, Path, str], ObservingProxy] = ObservingProxy):
        self._credential_present = credential_present
        self._launcher = launcher
        self._proxy_factory = proxy_factory
        self._root: tempfile.TemporaryDirectory[str] | None = None
        self._launch: Launch | None = None
        self._launch_binding: tuple[object, int, Path, Path, Path] | None = None
        self._proxy: ObservingProxy | None = None
        self._parent_socket: socket.socket | None = None
        self._child_socket: socket.socket | None = None
        self._secret_read: int | None = None
        self._secret_write: int | None = None
        self._closed = False

    def __enter__(self) -> "M2IntegrationHarness":
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()

    @property
    def temp_root(self) -> Path | None:
        return Path(self._root.name) if self._root else None

    def run(self, *, provider_credential_env: str, environment: Mapping[str, str] | None = None, dry_run: bool = False) -> IntegrationResult:
        # Environment is consulted only in this expression and passed straight to launcher.
        if self._closed or self._root is not None or self._launch is not None or self._proxy is not None:
            return IntegrationResult("BLOCKED", "BLOCKED_A2_HARNESS_ALREADY_USED")
        if dry_run:
            return IntegrationResult("BLOCKED", "BLOCKED_DRY_RUN")
        if not self._credential_present(provider_credential_env, environment):
            return IntegrationResult("BLOCKED", "BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
        try:
            self._setup(provider_credential_env, environment)
            return IntegrationResult("BLOCKED", "BLOCKED_A0_CERTIFICATE_REQUIRED")
        except Exception:
            self.cleanup()
            return IntegrationResult("BLOCKED", "BLOCKED_A2_SETUP_FAILED")

    def _setup(self, provider_credential_env: str, environment: Mapping[str, str] | None) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="nomad-m2-a2-")
        # launcher gets the mapping transiently; neither it nor any secret is retained.
        launch = self._launcher(provider_credential_env=provider_credential_env, environment=environment)
        self._launch = launch
        workspace = Path(launch.workspace).resolve(strict=True)
        root = Path(launch.root).resolve(strict=True)
        install = Path(launch.install).resolve(strict=True)
        process = getattr(launch, "process", None); pid = getattr(process, "pid", None)
        if (
            not workspace.is_relative_to(root) or not install.is_relative_to(root)
            or workspace == root or install == root or workspace == install
            or process is None or not isinstance(pid, int) or pid <= 0 or process.poll() is not None
        ):
            raise ValueError("launch")
        self._launch_binding = (process, pid, root, install, workspace)
        run_id = secrets.token_hex(32)
        self._proxy = self._proxy_factory(f"http://127.0.0.1:{int(launch.port)}", workspace, run_id)
        self._proxy.start()
        self._parent_socket, self._child_socket = socket.socketpair()
        self._secret_read, self._secret_write = os.pipe()
        for fd in (self._parent_socket.fileno(), self._child_socket.fileno(), self._secret_read, self._secret_write):
            os.set_inheritable(fd, False)

    def run_fd_probe(self) -> dict[str, object]:
        if not all((self._parent_socket, self._child_socket, self._secret_read is not None, self._secret_write is not None)):
            raise RuntimeError("not_setup")
        try:
            child_fd, secret_fd = self._child_socket.fileno(), self._secret_read
            secret = secrets.token_bytes(32)
            process: subprocess.Popen[bytes] | None = None
            os.set_inheritable(child_fd, True); os.set_inheritable(secret_fd, True)
            try:
                process = subprocess.Popen([sys.executable, "-c", _CHILD_PROBE, str(child_fd), str(secret_fd)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(child_fd, secret_fd))
            finally:
                os.set_inheritable(child_fd, False); os.set_inheritable(secret_fd, False)
            if process is None:
                raise RuntimeError("probe")
            os.close(self._secret_read); self._secret_read = None
            sent = 0
            while sent < len(secret):
                wrote = os.write(self._secret_write, secret[sent:])
                if wrote <= 0:
                    raise RuntimeError("probe")
                sent += wrote
            os.close(self._secret_write); self._secret_write = None
            self._child_socket.close(); self._child_socket = None
            self._parent_socket.settimeout(2)
            marker = self._parent_socket.recv(1)
            stdout, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=3)
            self.cleanup()
            raise RuntimeError("probe") from None
        except Exception:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=3)
            self.cleanup()
            raise RuntimeError("probe") from None
        try:
            if process.returncode or marker != b"P":
                raise RuntimeError("probe")
            result = json.loads(stdout)
            if result != {"kind": "TEST_PEER_ONLY_FD_DELIVERY", "secret_bytes": 32, "socket_ok": True}:
                raise RuntimeError("probe")
        except Exception:
            self.cleanup()
            raise
        return result

    def cleanup(self) -> IntegrationResult:
        if self._closed:
            return IntegrationResult("BLOCKED", "BLOCKED_A2_CLEANUP_INCOMPLETE") if self._launch_binding is not None else IntegrationResult("CLEANED", "CLEANED")
        self._closed = True
        for sock_name in ("_parent_socket", "_child_socket"):
            sock = getattr(self, sock_name)
            if sock is not None:
                try: sock.close()
                except OSError: pass
                setattr(self, sock_name, None)
        for fd_name in ("_secret_read", "_secret_write"):
            fd = getattr(self, fd_name)
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
                setattr(self, fd_name, None)
        if self._proxy is not None:
            try: self._proxy.shutdown()
            finally: self._proxy = None
        if self._launch is not None:
            launch = self._launch
            try:
                launch.cleanup()
            except Exception:
                pass
            binding = self._launch_binding
            complete = False
            if binding is not None:
                process, pid, root, install, workspace = binding
                complete = (
                    getattr(launch, "process", None) is process
                    and getattr(process, "pid", None) == pid
                    and process.poll() is not None
                    and not any(path.exists() for path in (root, install, workspace))
                )
            if complete:
                self._launch = None; self._launch_binding = None
        if self._root is not None:
            self._root.cleanup(); self._root = None
        if self._launch_binding is not None:
            return IntegrationResult("BLOCKED", "BLOCKED_A2_CLEANUP_INCOMPLETE")
        return IntegrationResult("CLEANED", "CLEANED")
