"""C1a2b locked Host transport supervisor.

This module creates no command capability.  The only currently constructible
authorization is test-only; the production entry point therefore fails closed
until the B0c production typed-fact join is installed.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import select
import socket
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from testkit.pilot.observing_proxy import ObservingProxy, ProxyError, proxy_handshake

BLOCKED = "BLOCKED_LOCKED_HOST_SUPERVISOR"
CLEANUP_UNCONFIRMED = "BLOCKED_LOCKED_HOST_CLEANUP_UNCONFIRMED"
HOST_VERIFIED = b"HOST_PREREQUISITES_VERIFIED\n"
ADOPTER_VERIFIED = b"ADOPTED_ACTUAL_LAUNCH_PROVENANCE\n"
MAX_OUTPUT = 4096
MAX_PAYLOAD = 65_536
_PAYLOAD_FIELDS = frozenset({
    "schema_version", "run_id", "package_name", "package_version",
    "package_lock_raw_digest", "full_locked_dependency_count",
    "full_locked_dependency_digest", "installed_platform_dependency_count",
    "installed_platform_dependency_digest", "entrypoint_realpath",
    "entrypoint_raw_digest", "npm_executable_realpath", "npm_version",
    "task_spec_digest", "fixture_manifest_digest", "adapter_id",
    "adapter_version",
})


@dataclass(frozen=True)
class SupervisorResult:
    status: str
    reason: str


class _TestPublishedHostAuthorization:
    __slots__ = ("_path", "_digest", "_marker")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("private test Host authorization")

    def __reduce__(self) -> object:
        raise TypeError("nonserializable test Host authorization")

    def __repr__(self) -> str:
        return "TestPublishedHostAuthorization(<redacted>)"


class _PublishedHostAuthorization:
    """Exact production integration type; no constructor exists in B2."""
    __slots__ = ("_path", "_digest", "_marker")

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("private production Host authorization")


class _TestLockedLaunchMeasurement:
    __slots__ = ("_facts",)

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("private test locked launch measurement")

    def __reduce__(self) -> object:
        raise TypeError("nonserializable test locked launch measurement")


class _TestLockedLaunch:
    __slots__ = ("_measurement",)

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("private test locked launch")

    def __reduce__(self) -> object:
        raise TypeError("nonserializable test locked launch")


def _load_package_a():
    path = Path(__file__).resolve().parents[1] / "stock-opencode" / "real_task_capture.py"
    spec = importlib.util.spec_from_file_location("nomad_c1a2b_package_a", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("package_a")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_PACKAGE_A = _load_package_a()


def _issue_test_locked_launch(facts: dict[str, object]) -> _TestLockedLaunch:
    if set(facts) != _PAYLOAD_FIELDS - {"schema_version", "run_id"}:
        raise ValueError("facts")
    measurement = object.__new__(_TestLockedLaunchMeasurement)
    object.__setattr__(measurement, "_facts", dict(facts))
    launch = object.__new__(_TestLockedLaunch)
    object.__setattr__(launch, "_measurement", measurement)
    return launch


def _read_regular_nofollow(path: Path, limit: int = 64 * 1024 * 1024) -> tuple[bytes, tuple[int, int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError("host")
        chunks = bytearray()
        while len(chunks) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    current = os.stat(path, follow_symlinks=False)
    if len(chunks) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
        raise ValueError("host")
    return bytes(chunks), identity(before)


def _issue_test_host_authorization(host_path: Path, *, adopter: bool = True) -> _TestPublishedHostAuthorization:
    """Private transport-test seam; it cannot enter the production path."""
    path = Path(host_path).resolve(strict=True)
    raw, _ = _read_regular_nofollow(path)
    value = object.__new__(_TestPublishedHostAuthorization)
    object.__setattr__(value, "_path", path)
    object.__setattr__(value, "_digest", hashlib.sha256(raw).hexdigest())
    object.__setattr__(value, "_marker", ADOPTER_VERIFIED if adopter else HOST_VERIFIED)
    return value


def _canonical(parts: list[bytes]) -> bytes:
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def _payload_and_envelope_values(payload_value: dict[str, object], run_id: str, secret: bytearray) -> tuple[bytes, str]:
    payload_value = dict(payload_value)
    payload_value["run_id"] = run_id
    payload_value["schema_version"] = "nomad.actual-launch-provenance.v1"
    if set(payload_value) != _PAYLOAD_FIELDS:
        raise ValueError("payload")
    payload = json.dumps(payload_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if not 0 < len(payload) <= MAX_PAYLOAD:
        raise ValueError("payload")
    digest = hashlib.sha256(payload).digest()
    version = struct.pack("!H", 1)
    mac = hmac.new(bytes(secret), _canonical([b"nomad-actual-launch-provenance-v1", version, run_id.encode("ascii"), digest]), hashlib.sha256).digest()
    claim = hashlib.sha256(_canonical([b"nomad-c1a-transport-claim-v1", version, run_id.encode("ascii"), digest])).hexdigest()
    return b"NOMADALP" + version + struct.pack("!I", len(payload)) + digest + mac + payload, claim


def _test_payload_and_envelope(launch: _TestLockedLaunch, run_id: str, secret: bytearray) -> tuple[bytes, str]:
    if type(launch) is not _TestLockedLaunch or type(launch._measurement) is not _TestLockedLaunchMeasurement:
        raise TypeError("test locked launch")
    return _payload_and_envelope_values(launch._measurement._facts, run_id, secret)


def _production_payload_and_envelope(launch: object, run_id: str, secret: bytearray) -> tuple[bytes, str]:
    if type(launch) is not _PACKAGE_A.LockedOpenCodeLaunch:
        raise TypeError("production locked launch")
    return _payload_and_envelope_values(_PACKAGE_A._measurement_facts(launch), run_id, secret)


class _SharedFailure:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.failed = False

    def set(self) -> None:
        with self.lock:
            self.failed = True
            self.event.set()


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _actual_proxy_origin(proxy: ObservingProxy) -> str:
    if type(proxy) is not ObservingProxy or proxy._server is None or proxy._closed:
        raise ValueError("proxy")
    host, port = proxy._server.server_address
    if host != "127.0.0.1" or type(port) is not int or not 0 < port <= 65535:
        raise ValueError("proxy")
    return f"http://127.0.0.1:{port}"


def _bounded_reader(stream, output: bytearray, deadline: float, failure: _SharedFailure) -> None:
    try:
        fd = stream.fileno()
        while True:
            if failure.event.is_set():
                return
            remaining = _remaining(deadline)
            if remaining <= 0:
                failure.set(); return
            ready, _, _ = select.select([fd], [], [], min(0.1, remaining))
            if not ready:
                continue
            part = os.read(fd, min(1024, MAX_OUTPUT + 1 - len(output)))
            if not part:
                return
            output.extend(part)
            if len(output) > MAX_OUTPUT:
                failure.set(); return
    except (OSError, ValueError):
        failure.set()


def _bounded_writer(fd: int, payload: bytes, start: threading.Event, deadline: float, failure: _SharedFailure) -> None:
    try:
        if not start.wait(_remaining(deadline)):
            failure.set(); return
        os.set_blocking(fd, False)
        offset = 0
        while offset < len(payload):
            if failure.event.is_set():
                return
            remaining = _remaining(deadline)
            if remaining <= 0:
                failure.set(); return
            _, ready, _ = select.select([], [fd], [], min(0.1, remaining))
            if not ready:
                continue
            offset += os.write(fd, payload[offset:])
    except (BrokenPipeError, OSError, ValueError):
        failure.set()
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _close(value: object | None) -> None:
    if value is None:
        return
    try:
        value.close() if hasattr(value, "close") else os.close(int(value))
    except (OSError, ValueError):
        pass


def _supervise_test_host(authorization: _TestPublishedHostAuthorization, launch: object, proxy: ObservingProxy, *, timeout: float = 10.0) -> SupervisorResult:
    if type(authorization) is not _TestPublishedHostAuthorization or type(launch) is not _TestLockedLaunch or timeout <= 6:
        return SupervisorResult("BLOCKED", BLOCKED)
    process = None
    parent_socket = child_socket = None
    secret_read = secret_write = provenance_read = provenance_write = None
    threads: list[threading.Thread] = []
    stdout = bytearray(); stderr = bytearray(); failure = _SharedFailure()
    writer_start = threading.Event()
    random_values = [secrets.token_bytes(32) for _ in range(4)]
    secret = bytearray(random_values[0]); challenge = random_values[1]
    run_id = random_values[2].hex(); nonce = random_values[3].hex()
    deadline = time.monotonic() + timeout
    cleanup_ok = True
    result = SupervisorResult("BLOCKED", BLOCKED)
    try:
        if any(not any(value) for value in random_values) or len(set(random_values)) != 4:
            raise ValueError("random")
        proxy_origin = _actual_proxy_origin(proxy)
        raw, identity = _read_regular_nofollow(authorization._path)
        if hashlib.sha256(raw).hexdigest() != authorization._digest:
            raise ValueError("host")
        envelope, claim = _test_payload_and_envelope(launch, run_id, secret)
        parent_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        secret_read, secret_write = os.pipe()
        provenance_read, provenance_write = os.pipe()
        inherited = (child_socket.fileno(), secret_read, provenance_read)
        if len(set(inherited)) != 3 or any(fd <= 2 for fd in inherited):
            raise ValueError("fd")
        for fd in (parent_socket.fileno(), *inherited, secret_write, provenance_write):
            os.set_inheritable(fd, False)
        env = {"LC_ALL": "C", "LANG": "C", "RUST_BACKTRACE": "0"}
        process = subprocess.Popen(
            [str(authorization._path), *(str(fd) for fd in inherited), challenge.hex()],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, close_fds=True, pass_fds=inherited, env=env,
        )
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("stdio")
        # The path must still name the exact bytes and identity authorized at spawn.
        after, after_identity = _read_regular_nofollow(authorization._path)
        if after_identity != identity or hashlib.sha256(after).hexdigest() != authorization._digest:
            raise ValueError("host")
        child_socket.close(); child_socket = None
        os.close(secret_read); secret_read = None
        os.close(provenance_read); provenance_read = None
        for stream, target, name in ((process.stdout, stdout, "host-stdout"), (process.stderr, stderr, "host-stderr")):
            thread = threading.Thread(target=_bounded_reader, args=(stream, target, deadline, failure), name=name)
            thread.start(); threads.append(thread)
        writer = threading.Thread(target=_bounded_writer, args=(provenance_write, envelope, writer_start, deadline, failure), name="host-provenance")
        writer.start(); threads.append(writer); provenance_write = None
        secret_offset = 0
        while secret_offset < len(secret):
            wrote = os.write(secret_write, secret[secret_offset:])
            if wrote <= 0:
                raise OSError("secret")
            secret_offset += wrote
        os.close(secret_write); secret_write = None
        parent_socket.settimeout(max(0.001, min(2.0, _remaining(deadline))))
        proxy_handshake(parent_socket, bytes(secret), {"run_id": run_id, "origin": proxy_origin, "nonce": nonce, "digest": claim})
        parent_socket.close(); parent_socket = None
        writer_start.set()
        while process.poll() is None:
            if failure.event.is_set() or _remaining(deadline) <= 0:
                raise RuntimeError("worker")
            time.sleep(min(0.01, _remaining(deadline)))
        process.wait(timeout=max(0.001, _remaining(deadline)))
        for thread in threads:
            thread.join(_remaining(deadline))
        if any(thread.is_alive() for thread in threads) or failure.failed:
            raise RuntimeError("worker")
        if process.returncode != 0 or bytes(stdout) != authorization._marker or stderr:
            raise RuntimeError("host")
        result = SupervisorResult("VERIFIED", authorization._marker.rstrip().decode("ascii"))
    except (OSError, ValueError, TypeError, RuntimeError, ProxyError, subprocess.TimeoutExpired):
        result = SupervisorResult("BLOCKED", BLOCKED)
    finally:
        writer_start.set()
        failure.set()
        for endpoint in (parent_socket, child_socket, secret_read, secret_write, provenance_read, provenance_write):
            _close(endpoint)
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                cleanup_ok = False
        if process is not None:
            try:
                process.wait(timeout=max(0.1, min(2.0, _remaining(deadline) or 2.0)))
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
            for stream in (process.stdout, process.stderr):
                _close(stream)
        for thread in threads:
            thread.join(max(0.0, min(2.0, _remaining(deadline) or 2.0)))
            if thread.is_alive():
                cleanup_ok = False
        secret[:] = b"\0" * len(secret)
        # Cleanup uncertainty is intentionally not raised: callers receive only a
        # content-free result. Tests can inspect that no supervisor threads remain.
        if not cleanup_ok:
            failure.set()
            result = SupervisorResult("BLOCKED", CLEANUP_UNCONFIRMED)
    return result


def supervise_locked_host(authorization: object, _launch: object, _proxy: object) -> SupervisorResult:
    """Production path remains blocked until exact B0c typed facts exist."""
    if type(authorization) is not _PublishedHostAuthorization:
        return SupervisorResult("BLOCKED", BLOCKED)
    return SupervisorResult("BLOCKED", BLOCKED)
