"""Content-free process lifecycle helpers for the repo-local Web Companion."""

from __future__ import annotations

import hashlib
import fcntl
import os
import signal
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


class ProcessError(RuntimeError):
    pass


def minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if extra:
        env.update(extra)
    return env


def run_checked(command: Sequence[str], cwd: Path, timeout: float = 180.0) -> None:
    build_env = minimal_env()
    build_env["HOME"] = str(Path.home())
    for name in ("HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "npm_config_cache"):
        value = os.environ.get(name)
        if value:
            build_env[name] = value
    result = subprocess.run(
        [str(item) for item in command],
        cwd=cwd,
        env=build_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise ProcessError("BUILD_FAILED")


def spawn(
    name: str,
    command: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    log_path: Path,
    *,
    extra_fd_actions: Sequence[tuple[int, int]] = (),
    close_fds: Sequence[int] = (),
) -> dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    argv = [str(item) for item in command]
    executable = argv[0]
    if not Path(executable).is_absolute():
        resolved = shutil.which(executable, path=env.get("PATH"))
        if not resolved:
            os.close(descriptor)
            raise ProcessError("PROCESS_EXECUTABLE_UNAVAILABLE")
        executable = resolved
        argv[0] = resolved
    safe_extra_fds: list[int] = []
    previous = Path.cwd()
    try:
        safe_actions: list[tuple[int, int]] = []
        for source_fd, target_fd in extra_fd_actions:
            if source_fd < 0 or target_fd < 3:
                raise ProcessError("INVALID_INHERITED_FD")
            safe_fd = fcntl.fcntl(source_fd, fcntl.F_DUPFD_CLOEXEC, 20)
            safe_extra_fds.append(safe_fd)
            safe_actions.append((safe_fd, target_fd))
        file_actions = [
            (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0),
            (os.POSIX_SPAWN_DUP2, descriptor, 1),
            (os.POSIX_SPAWN_DUP2, descriptor, 2),
            (os.POSIX_SPAWN_CLOSE, descriptor),
        ]
        file_actions.extend(
            (os.POSIX_SPAWN_DUP2, source_fd, target_fd)
            for source_fd, target_fd in safe_actions
        )
        file_actions.extend((os.POSIX_SPAWN_CLOSE, fd) for fd in safe_extra_fds)
        target_fds = {target_fd for _, target_fd in safe_actions}
        file_actions.extend((os.POSIX_SPAWN_CLOSE, fd) for fd in close_fds if fd not in target_fds)
        os.chdir(cwd)
        process_id = os.posix_spawn(
            executable, argv, dict(env),
            file_actions=file_actions,
            setsid=True,
        )
    finally:
        os.chdir(previous)
        os.close(descriptor)
        for safe_fd in safe_extra_fds:
            os.close(safe_fd)
    try:
        identity = process_identity(process_id)
    except Exception:
        try:
            os.killpg(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _reap(process_id)
        raise
    return {
        "name": name,
        "pid": process_id,
        "process_group": os.getpgid(process_id),
        "identity": identity,
        "log": str(log_path),
    }


def secret_pipe(value: bytes) -> int:
    """Return a non-inheritable pipe containing one bounded secret and EOF."""
    if not isinstance(value, bytes) or not value or len(value) > 4096:
        raise ProcessError("INVALID_FD_SECRET")
    read_fd, write_fd = os.pipe()
    try:
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, False)
        view = memoryview(value)
        while view:
            written = os.write(write_fd, view)
            if written <= 0:
                raise ProcessError("FD_SECRET_WRITE_FAILED")
            view = view[written:]
    except Exception:
        os.close(read_fd)
        os.close(write_fd)
        raise
    os.close(write_fd)
    return read_fd


def close_fd(descriptor: int | None) -> None:
    if descriptor is None or descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def process_identity(pid: int) -> str:
    identity_env = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
        env=identity_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=2,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise ProcessError("PROCESS_IDENTITY_UNAVAILABLE")
    return hashlib.sha256(result.stdout).hexdigest()


def alive(record: Mapping[str, Any]) -> bool:
    return ownership(record) == "owned"


def ownership(record: Mapping[str, Any]) -> str:
    try:
        pid = int(record["pid"])
        os.kill(pid, 0)
        if int(record.get("process_group", -1)) != pid or os.getpgid(pid) != pid:
            return "mismatch"
        return "owned" if process_identity(pid) == record["identity"] else "mismatch"
    except ProcessLookupError:
        return "absent"
    except (KeyError, TypeError, ValueError, PermissionError, ProcessError):
        return "mismatch"


def stop(record: Mapping[str, Any], timeout: float = 8.0) -> bool:
    if ownership(record) != "owned":
        return False
    pid = int(record["pid"])
    # Re-measure immediately before signalling. If identity cannot be proved,
    # do not signal an unrelated or PID-reused process.
    if ownership(record) != "owned":
        return False
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _reap(pid):
            return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    if alive(record):
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True
    _reap(pid)
    return True


def _reap(pid: int) -> bool:
    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        return waited == pid
    except ChildProcessError:
        return False
