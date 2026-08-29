"""Crash-safe fixed-protocol coordinator for destructive desktop lifecycle work.

The coordinator is intentionally not an arbitrary command runner.  A caller
may prepare and then commit exactly one of two operations, bound to the
currently verified launcher run and install identities.  No credential or
other secret is accepted by this protocol.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import secrets
import socket
import stat
import sys
import threading
import uuid
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from . import processes
from .install_lifecycle import status_unlocked as install_status_unlocked
from .state import lifecycle_lock, read_run_state

MAX_FRAME_BYTES = 4096
REQUEST_SCHEMA = "nomad.web-companion.lifecycle-request.v1"
COMMIT_SCHEMA = "nomad.web-companion.lifecycle-commit.v1"
RESPONSE_SCHEMA = "nomad.web-companion.lifecycle-response.v1"
JOURNAL_SCHEMA = "nomad.web-companion.lifecycle-journal.v1"
MARKER_SCHEMA = "nomad.web-companion.lifecycle-journal-root.v1"
OPERATIONS = {"reset_remote_access", "uninstall"}
JOURNAL_STATES = {"ACCEPTED", "COMMITTED", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN"}
JOURNAL_ERRORS = {
    "LIFECYCLE_COMMIT_NOT_OBSERVED",
    "LIFECYCLE_OPERATION_FAILED",
    "LIFECYCLE_OUTCOME_UNKNOWN",
}
REQUEST_KEYS = {
    "schema", "operation", "confirm", "request_id", "run_id",
    "bundle_digest", "install_sequence", "gateway_identity",
    "coordinator_identity",
}
COMMIT_KEYS = REQUEST_KEYS | {"commit_challenge"}
PROCESS_BINDING_KEYS = {"pid", "process_group", "identity"}
WORKER_CONFIG_KEYS = {
    "home", "relay_port", "gateway_port", "agent_port", "join_gateway_port",
    "relay_host_v2_port", "relay_device_v2_port", "relay_admin_port",
    "relay_device_v1_port",
}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{16,128}")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def decode_message(raw: bytes, *, schema: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FRAME_BYTES:
        raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError("LIFECYCLE_MESSAGE_DUPLICATE_KEY")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate)
    except RuntimeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("LIFECYCLE_MESSAGE_INVALID") from error
    expected_keys = COMMIT_KEYS if schema == COMMIT_SCHEMA else REQUEST_KEYS
    if not isinstance(value, dict) or set(value) != expected_keys or value.get("schema") != schema:
        raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")
    if raw != canonical_json(value):
        raise RuntimeError("LIFECYCLE_MESSAGE_NONCANONICAL")
    _validate_request_fields(value, commit=schema == COMMIT_SCHEMA)
    return value


def _validate_request_fields(value: Mapping[str, Any], *, commit: bool = False) -> None:
    expected_keys = COMMIT_KEYS if commit else REQUEST_KEYS
    if (
        set(value) != expected_keys
        or value.get("schema") not in {REQUEST_SCHEMA, COMMIT_SCHEMA}
        or value.get("operation") not in OPERATIONS
        or value.get("confirm") is not True
        or not isinstance(value.get("request_id"), str)
        or _REQUEST_ID.fullmatch(value["request_id"]) is None
        or any(
            not isinstance(value.get(name), str)
            or _HEX64.fullmatch(value[name]) is None
            for name in (
                "run_id", "bundle_digest", "gateway_identity",
                "coordinator_identity",
            )
        )
        or type(value.get("install_sequence")) is not int
        or value["install_sequence"] <= 0
        or commit and (
            not isinstance(value.get("commit_challenge"), str)
            or _HEX64.fullmatch(value["commit_challenge"]) is None
        )
    ):
        raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")


def request_from_commit(value: Mapping[str, Any]) -> dict[str, Any]:
    request = dict(value)
    request.pop("commit_challenge", None)
    request["schema"] = REQUEST_SCHEMA
    return request


def send_message(channel: socket.socket, value: Mapping[str, Any]) -> None:
    raw = canonical_json(dict(value))
    if not raw or len(raw) > MAX_FRAME_BYTES:
        raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")
    channel.sendall(len(raw).to_bytes(4, "big") + raw)


def receive_message(channel: socket.socket, *, schema: str) -> dict[str, Any]:
    size = int.from_bytes(_recv_exact(channel, 4), "big")
    if not 0 < size <= MAX_FRAME_BYTES:
        raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")
    return decode_message(_recv_exact(channel, size), schema=schema)


def _recv_exact(channel: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = channel.recv(size - len(value))
        if not chunk:
            raise RuntimeError("LIFECYCLE_CHANNEL_CLOSED")
        value.extend(chunk)
    return bytes(value)


def process_binding(record: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value = {name: record[name] for name in PROCESS_BINDING_KEYS}
    except KeyError as error:
        raise RuntimeError("LIFECYCLE_PROCESS_BINDING_INVALID") from error
    if (
        type(value["pid"]) is not int or value["pid"] <= 1
        or type(value["process_group"]) is not int
        or value["process_group"] != value["pid"]
        or not isinstance(value["identity"], str)
        or _HEX64.fullmatch(value["identity"]) is None
    ):
        raise RuntimeError("LIFECYCLE_PROCESS_BINDING_INVALID")
    return value


def make_request(
    operation: str, request_id: str, *, run_id: str, bundle_digest: str,
    install_sequence: int, gateway: Mapping[str, Any],
    coordinator: Mapping[str, Any], schema: str = REQUEST_SCHEMA,
) -> dict[str, Any]:
    value = {
        "schema": schema, "operation": operation, "confirm": True,
        "request_id": request_id, "run_id": run_id,
        "bundle_digest": bundle_digest,
        "install_sequence": install_sequence,
        "gateway_identity": process_binding(gateway)["identity"],
        "coordinator_identity": process_binding(coordinator)["identity"],
    }
    _validate_request_fields(value)
    return value


def verify_binding(
    config: Any, request: Mapping[str, Any], *, gateway: Mapping[str, Any],
    coordinator: Mapping[str, Any],
) -> None:
    gateway_binding = process_binding(gateway)
    coordinator_binding = process_binding(coordinator)
    if (
        request["gateway_identity"] != gateway_binding["identity"]
        or request["coordinator_identity"] != coordinator_binding["identity"]
        or coordinator_binding["pid"] != os.getpid()
        or processes.ownership(coordinator_binding) != "owned"
        or processes.ownership(gateway_binding) != "owned"
    ):
        raise RuntimeError("LIFECYCLE_PROCESS_BINDING_MISMATCH")
    with lifecycle_lock(config, create=False) as owned:
        if not owned:
            raise RuntimeError("LIFECYCLE_RUNTIME_BINDING_MISMATCH")
        _verify_runtime_binding_unlocked(config, request, gateway_binding)


def _verify_runtime_binding_unlocked(
    config: Any, request: Mapping[str, Any], gateway_binding: Mapping[str, Any],
) -> list[dict[str, Any]]:
    running = read_run_state(config)
    installed = install_status_unlocked(config)
    if (
        running is None
        or running.get("run_id") != request["run_id"]
        or running.get("bundle_digest") != request["bundle_digest"]
        or installed.get("state") != "INSTALLED"
        or installed.get("current_bundle_digest") != request["bundle_digest"]
        or not installed.get("history")
        or installed["history"][-1].get("sequence") != request["install_sequence"]
    ):
        raise RuntimeError("LIFECYCLE_RUNTIME_BINDING_MISMATCH")
    workload = running.get("processes", [])
    matches = [item for item in workload if item.get("name") == "desktop-gateway"]
    if len(matches) != 1 or process_binding(matches[0]) != dict(gateway_binding):
        raise RuntimeError("LIFECYCLE_GATEWAY_BINDING_MISMATCH")
    return workload


class OperationJournal:
    """Exact-owned journal pinned to one opened directory identity."""

    def __init__(self, root: Path, *, home_commitment: str):
        if _HEX64.fullmatch(home_commitment) is None:
            raise RuntimeError("LIFECYCLE_HOME_COMMITMENT_INVALID")
        self.root = root
        self.home_commitment = home_commitment
        self._dir_fd = -1
        self._root_identity: tuple[int, int] | None = None
        self._thread_lock = threading.Lock()
        self._ensure_root()

    def close(self) -> None:
        if self._dir_fd >= 0:
            os.close(self._dir_fd)
            self._dir_fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def accept(self, request: Mapping[str, Any]) -> dict[str, Any]:
        _validate_request_fields(request)
        if request["schema"] != REQUEST_SCHEMA:
            raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")
        with self._locked():
            existing = self._read(request["request_id"])
            if existing is not None:
                if existing["request"] != dict(request):
                    raise RuntimeError("LIFECYCLE_REQUEST_ID_CONFLICT")
                return existing
            if any(item["state"] in {"ACCEPTED", "COMMITTED"} for item in self._records_unlocked()):
                raise RuntimeError("LIFECYCLE_OPERATION_IN_PROGRESS")
            value = self._record(dict(request), "ACCEPTED", secrets.token_hex(32), None, None)
            self._create(self._name(request["request_id"]), canonical_json(value) + b"\n")
            return value

    def commit(self, request: Mapping[str, Any], challenge: str) -> dict[str, Any]:
        _validate_request_fields(request)
        if request["schema"] != REQUEST_SCHEMA:
            raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")
        with self._locked():
            current = self._read(request["request_id"])
            if current is None or current["request"] != dict(request):
                raise RuntimeError("LIFECYCLE_REQUEST_ID_CONFLICT")
            if current["state"] != "ACCEPTED" or challenge != current["commit_challenge"]:
                raise RuntimeError("LIFECYCLE_COMMIT_MISMATCH")
            value = self._record(dict(request), "COMMITTED", challenge, None, None)
            self._replace(self._name(request["request_id"]), canonical_json(value) + b"\n")
            return value

    def complete(self, request: Mapping[str, Any], *, result: Mapping[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
        if error is None:
            _validate_result(request["operation"], result)
        elif error not in JOURNAL_ERRORS or result is not None:
            raise RuntimeError("LIFECYCLE_JOURNAL_STATE_INVALID")
        with self._locked():
            current = self._read(request["request_id"])
            if current is None or current["request"] != dict(request) or current["state"] != "COMMITTED":
                raise RuntimeError("LIFECYCLE_JOURNAL_STATE_INVALID")
            state = "COMPLETED" if error is None else "FAILED"
            value = self._record(dict(request), state, current["commit_challenge"], dict(result) if result is not None else None, error)
            self._replace(self._name(request["request_id"]), canonical_json(value) + b"\n")
            return value

    def require_committed(self, request: Mapping[str, Any]) -> None:
        with self._locked():
            current = self._read(request["request_id"])
            if current is None or current["request"] != dict(request) or current["state"] != "COMMITTED":
                raise RuntimeError("LIFECYCLE_OPERATION_NOT_COMMITTED")

    def reconcile(self, config: Any) -> list[dict[str, Any]]:
        from . import launcher
        resolved: list[dict[str, Any]] = []
        with self._locked():
            for current in self._records_unlocked():
                request = current["request"]
                if current["state"] == "ACCEPTED":
                    value = self._record(request, "FAILED", current["commit_challenge"], None, "LIFECYCLE_COMMIT_NOT_OBSERVED")
                elif current["state"] == "COMMITTED":
                    result = None
                    try:
                        if request["operation"] == "uninstall" and not os.path.lexists(Path(config.home)):
                            result = launcher._uninstall_result()
                        elif request["operation"] == "reset_remote_access":
                            with lifecycle_lock(config, create=False) as owned:
                                if owned and read_run_state(config) is None and not launcher._remote_persistent_state_present(Path(config.home)):
                                    installed = install_status_unlocked(config)
                                    if installed.get("state") == "INSTALLED" and installed.get("current_bundle_digest") == request["bundle_digest"] and installed.get("history") and installed["history"][-1].get("sequence") == request["install_sequence"]:
                                        result = launcher._reset_result()
                    except (OSError, RuntimeError):
                        result = None
                    value = self._record(request, "COMPLETED" if result is not None else "OUTCOME_UNKNOWN", current["commit_challenge"], result, None if result is not None else "LIFECYCLE_OUTCOME_UNKNOWN")
                else:
                    continue
                self._replace(self._name(request["request_id"]), canonical_json(value) + b"\n")
                resolved.append(value)
        return resolved

    def records(self) -> list[dict[str, Any]]:
        with self._locked():
            return self._records_unlocked()

    @contextmanager
    def _locked(self):
        with self._thread_lock:
            self._verify_root()
            fcntl.flock(self._dir_fd, fcntl.LOCK_EX)
            try:
                self._verify_root()
                yield
                self._verify_root()
            finally:
                fcntl.flock(self._dir_fd, fcntl.LOCK_UN)

    def _records_unlocked(self) -> list[dict[str, Any]]:
        self._verify_root()
        names = sorted(name for name in os.listdir(self._dir_fd) if re.fullmatch(r"operation-[A-Za-z0-9_-]{16,128}\.json", name))
        self._verify_root()
        return [self._read_name(name) for name in names]

    @staticmethod
    def _record(request: dict[str, Any], state: str, challenge: str, result: dict[str, Any] | None, error: str | None) -> dict[str, Any]:
        return {"schema": JOURNAL_SCHEMA, "request": request, "state": state, "commit_challenge": challenge, "result": result, "error": error}

    @staticmethod
    def _name(request_id: str) -> str:
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise RuntimeError("LIFECYCLE_MESSAGE_INVALID")
        return f"operation-{request_id}.json"

    def _read(self, request_id: str) -> dict[str, Any] | None:
        try:
            return self._read_name(self._name(request_id))
        except FileNotFoundError:
            return None

    def _read_name(self, name: str) -> dict[str, Any]:
        self._verify_root()
        raw = _read_owned_at(self._dir_fd, name, MAX_FRAME_BYTES * 4, 0o600)
        self._verify_root()
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("LIFECYCLE_JOURNAL_INVALID") from error
        keys = {"schema", "request", "state", "commit_challenge", "result", "error"}
        if raw != canonical_json(value) + b"\n" or not isinstance(value, dict) or set(value) != keys or value["schema"] != JOURNAL_SCHEMA or value["state"] not in JOURNAL_STATES or not isinstance(value["commit_challenge"], str) or _HEX64.fullmatch(value["commit_challenge"]) is None:
            raise RuntimeError("LIFECYCLE_JOURNAL_INVALID")
        _validate_request_fields(value["request"] if isinstance(value["request"], dict) else {})
        if value["request"]["schema"] != REQUEST_SCHEMA:
            raise RuntimeError("LIFECYCLE_JOURNAL_INVALID")
        if value["state"] in {"ACCEPTED", "COMMITTED"} and (value["result"] is not None or value["error"] is not None):
            raise RuntimeError("LIFECYCLE_JOURNAL_INVALID")
        if value["state"] == "COMPLETED":
            if value["error"] is not None:
                raise RuntimeError("LIFECYCLE_JOURNAL_INVALID")
            _validate_result(value["request"]["operation"], value["result"])
        if value["state"] in {"FAILED", "OUTCOME_UNKNOWN"} and (value["result"] is not None or value["error"] not in JOURNAL_ERRORS):
            raise RuntimeError("LIFECYCLE_JOURNAL_INVALID")
        return value

    def _ensure_root(self) -> None:
        try:
            os.mkdir(self.root, 0o700)
        except FileExistsError:
            pass
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("UNSAFE_LIFECYCLE_JOURNAL_ROOT")
        self._dir_fd = os.open(self.root, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0))
        opened = os.fstat(self._dir_fd)
        self._root_identity = (opened.st_dev, opened.st_ino)
        self._verify_root()
        expected = canonical_json({"schema": MARKER_SCHEMA, "home_commitment": self.home_commitment}) + b"\n"
        try:
            observed = _read_owned_at(self._dir_fd, "marker.json", MAX_FRAME_BYTES, 0o600)
        except FileNotFoundError:
            try:
                self._create("marker.json", expected)
            except FileExistsError:
                pass
            observed = _read_owned_at(self._dir_fd, "marker.json", MAX_FRAME_BYTES, 0o600)
        if observed != expected:
            raise RuntimeError("UNSAFE_LIFECYCLE_JOURNAL_MARKER")
        for name in os.listdir(self._dir_fd):
            if name == "marker.json" or re.fullmatch(r"operation-[A-Za-z0-9_-]{16,128}\.json", name):
                continue
            if re.fullmatch(r"\.operation-[0-9a-f]{32}\.tmp", name):
                os.unlink(name, dir_fd=self._dir_fd)
                continue
            raise RuntimeError("UNSAFE_LIFECYCLE_JOURNAL_ROOT")
        os.fsync(self._dir_fd)
        self._verify_root()

    def _verify_root(self) -> None:
        try:
            opened, named = os.fstat(self._dir_fd), self.root.lstat()
        except OSError as error:
            raise RuntimeError("UNSAFE_LIFECYCLE_JOURNAL_ROOT") from error
        if self._root_identity is None or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700 or stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid() or stat.S_IMODE(named.st_mode) != 0o700 or (opened.st_dev, opened.st_ino) != self._root_identity or (named.st_dev, named.st_ino) != self._root_identity:
            raise RuntimeError("UNSAFE_LIFECYCLE_JOURNAL_ROOT")

    def _create(self, name: str, raw: bytes) -> None:
        self._verify_root()
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self._dir_fd)
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self._dir_fd)
        self._verify_root()

    def _replace(self, name: str, raw: bytes) -> None:
        temporary = f".operation-{uuid.uuid4().hex}.tmp"
        self._create(temporary, raw)
        try:
            self._verify_root()
            os.rename(temporary, name, src_dir_fd=self._dir_fd, dst_dir_fd=self._dir_fd)
            os.fsync(self._dir_fd)
            self._verify_root()
        finally:
            try:
                os.unlink(temporary, dir_fd=self._dir_fd)
            except FileNotFoundError:
                pass


def home_commitment(home: Path) -> str:
    canonical = Path(os.path.abspath(os.fspath(home))).resolve(strict=False)
    return hashlib.sha256(
        f"nomad.web.lifecycle-home.v1\n{os.geteuid()}\n{canonical}".encode("utf-8")
    ).hexdigest()


def _validate_result(operation: str, result: Any) -> None:
    if not isinstance(result, dict) or set(result) != {
        "schema", "state", "mode", "remote_access", "install_state",
        "host_identity_disposition", "production_ready",
    }:
        raise RuntimeError("LIFECYCLE_RESULT_INVALID")
    expected = (
        ("nomad.web-companion.remote-access-reset.v1", "STOPPED", "PRESERVED")
        if operation == "reset_remote_access"
        else ("nomad.web-companion.uninstall-result.v1", "UNINSTALLED", "REMOVED")
    )
    if (
        result["schema"] != expected[0] or result["state"] != expected[1]
        or result["mode"] != "foundation-readonly"
        or result["remote_access"] != "CLEARED"
        or result["install_state"] != expected[2]
        or result["host_identity_disposition"] != "retained"
        or result["production_ready"] is not False
    ):
        raise RuntimeError("LIFECYCLE_RESULT_INVALID")


def journal_root(home: Path, operation: str) -> Path:
    if operation not in OPERATIONS:
        raise RuntimeError("LIFECYCLE_OPERATION_INVALID")
    # One exact-owned root provides cross-operation single-flight and remains
    # available for the final uninstall receipt after Nomad home is removed.
    return Path("/private/tmp") / f"nomad-web-lifecycle-{home_commitment(home)}"


def execute_operation(
    config: Any, operation: str, *, request: Mapping[str, Any],
    gateway: Mapping[str, Any], journal: OperationJournal,
) -> dict[str, Any]:
    from . import launcher

    if request["operation"] != operation:
        raise RuntimeError("LIFECYCLE_COMMIT_MISMATCH")
    journal.require_committed(request)
    with lifecycle_lock(config, create=False) as owned:
        if not owned:
            raise RuntimeError("LIFECYCLE_RUNTIME_BINDING_MISMATCH")
        workload = _verify_runtime_binding_unlocked(
            config, request, process_binding(gateway),
        )
        if operation == "reset_remote_access":
            result = launcher._reset_remote_access_unlocked(config)
        elif operation == "uninstall":
            launcher._reset_remote_access_unlocked(config)
            result = launcher._uninstall_lifecycle_unlocked(config)
        else:
            raise RuntimeError("LIFECYCLE_OPERATION_INVALID")
        if any(processes.ownership(item) != "absent" for item in workload):
            raise RuntimeError("LIFECYCLE_WORKLOAD_STILL_PRESENT")
        if operation == "reset_remote_access":
            installed = install_status_unlocked(config)
            if (
                read_run_state(config) is not None
                or launcher._remote_persistent_state_present(Path(config.home))
                or installed.get("state") != "INSTALLED"
                or installed.get("current_bundle_digest") != request["bundle_digest"]
                or not installed.get("history")
                or installed["history"][-1].get("sequence") != request["install_sequence"]
            ):
                raise RuntimeError("LIFECYCLE_RESET_POSTCONDITION_FAILED")
        elif os.path.lexists(Path(config.home)):
            raise RuntimeError("LIFECYCLE_UNINSTALL_POSTCONDITION_FAILED")
        return result


def spawn_worker(
    config: Any, *, gateway: Mapping[str, Any],
) -> tuple[dict[str, Any], socket.socket]:
    """Spawn one fresh-interpreter coordinator outside the workload.

    The returned socket is intended to be inherited by the desktop Gateway on
    a fixed descriptor.  The coordinator record must be kept separately from
    the launcher's workload ``processes`` array, because reset/uninstall stops
    every process in that array before performing destructive cleanup.
    """
    process_binding(gateway)
    parent, child = socket.socketpair()
    bootstrap_read, bootstrap_write = os.pipe()
    try:
        worker_fd = fcntl.fcntl(child.fileno(), fcntl.F_DUPFD_CLOEXEC, 20)
        bootstrap_fd = fcntl.fcntl(bootstrap_read, fcntl.F_DUPFD_CLOEXEC, 20)
        bootstrap = canonical_json({
            "config": _worker_config(config),
            "gateway_binding": process_binding(gateway),
        })
        if len(bootstrap) > MAX_FRAME_BYTES:
            raise RuntimeError("LIFECYCLE_WORKER_BOOTSTRAP_INVALID")
        _write_all(bootstrap_write, bootstrap)
        os.close(bootstrap_write)
        bootstrap_write = -1
        module_name = __package__ + ".lifecycle_coordinator"
        import_root = Path(__file__).resolve().parents[2] if __package__.startswith("tools.") else Path(__file__).resolve().parents[1]
        code = (
            "import importlib,sys;sys.path.insert(0,sys.argv.pop(1));"
            "module=importlib.import_module(sys.argv.pop(1));"
            "raise SystemExit(module._worker_main())"
        )
        actions = [
            (os.POSIX_SPAWN_DUP2, worker_fd, 10),
            (os.POSIX_SPAWN_CLOSE, worker_fd),
            (os.POSIX_SPAWN_DUP2, bootstrap_fd, 11),
            (os.POSIX_SPAWN_CLOSE, bootstrap_fd),
        ]
        pid = os.posix_spawn(
            sys.executable,
            [
                sys.executable, "-I", "-B", "-c", code,
                str(import_root), module_name,
                "--channel-fd", "10", "--bootstrap-fd", "11",
            ],
            processes.minimal_env(),
            file_actions=actions, setsid=True,
        )
    finally:
        child.close()
        os.close(bootstrap_read)
        if bootstrap_write >= 0:
            os.close(bootstrap_write)
        if "worker_fd" in locals():
            os.close(worker_fd)
        if "bootstrap_fd" in locals():
            os.close(bootstrap_fd)
    try:
        record = {
            "name": "lifecycle-coordinator", "pid": pid,
            "process_group": pid, "identity": processes.process_identity(pid),
        }
        if processes.ownership(record) != "owned":
            raise RuntimeError("LIFECYCLE_COORDINATOR_IDENTITY_UNAVAILABLE")
        return record, parent
    except Exception:
        parent.close()
        try:
            os.killpg(pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        raise


def _worker_main() -> int:
    try:
        arguments = sys.argv[1:]
        if arguments != ["--channel-fd", "10", "--bootstrap-fd", "11"]:
            raise RuntimeError("LIFECYCLE_WORKER_ARGUMENTS_INVALID")
        raw = os.read(11, MAX_FRAME_BYTES + 1)
        if not raw or len(raw) > MAX_FRAME_BYTES or os.read(11, 1):
            raise RuntimeError("LIFECYCLE_WORKER_BOOTSTRAP_INVALID")
        bootstrap = json.loads(raw)
        if not isinstance(bootstrap, dict) or set(bootstrap) != {"config", "gateway_binding"} or raw != canonical_json(bootstrap):
            raise RuntimeError("LIFECYCLE_WORKER_BOOTSTRAP_INVALID")
        config_values = bootstrap["config"]
        if not isinstance(config_values, dict) or set(config_values) != WORKER_CONFIG_KEYS:
            raise RuntimeError("LIFECYCLE_WORKER_BOOTSTRAP_INVALID")
        config = SimpleNamespace(**config_values)
        config.home = Path(config.home)
        gateway = process_binding(bootstrap["gateway_binding"])
        channel = socket.socket(fileno=10)
        coordinator = {"pid": os.getpid(), "process_group": os.getpgrp(), "identity": processes.process_identity(os.getpid())}
        serve_once(config, channel, gateway=gateway, coordinator=coordinator)
        return 0
    except BaseException:
        return 1


def serve_once(
    config: Any, channel: socket.socket, *, gateway: Mapping[str, Any],
    coordinator: Mapping[str, Any], journal: OperationJournal | None = None,
    verifier: Callable[..., None] = verify_binding,
    executor: Callable[[Any, str], dict[str, Any]] = execute_operation,
) -> dict[str, Any]:
    channel.settimeout(30.0)
    journal = journal or OperationJournal(
        journal_root(Path(config.home), "reset_remote_access"),
        home_commitment=home_commitment(Path(config.home)),
    )
    journal.reconcile(config)
    request = receive_message(channel, schema=REQUEST_SCHEMA)
    verifier(config, request, gateway=gateway, coordinator=coordinator)
    accepted = journal.accept(request)
    _checkpoint("after_accept")
    send_message(channel, _response(request, accepted["state"], accepted.get("result"), accepted.get("error"), accepted.get("commit_challenge")))
    if accepted["state"] in {"COMPLETED", "FAILED", "OUTCOME_UNKNOWN"}:
        return accepted
    commit_message = receive_message(channel, schema=COMMIT_SCHEMA)
    committed_request = request_from_commit(commit_message)
    if committed_request != request or commit_message["commit_challenge"] != accepted["commit_challenge"]:
        raise RuntimeError("LIFECYCLE_COMMIT_MISMATCH")
    verifier(config, request, gateway=gateway, coordinator=coordinator)
    journal.commit(request, commit_message["commit_challenge"])
    _checkpoint("after_commit")
    try:
        if executor is execute_operation:
            result = executor(
                config, request["operation"], request=request, gateway=gateway,
                journal=journal,
            )
        else:
            result = executor(config, request["operation"])
    except Exception as error:
        code = str(error) if str(error) in JOURNAL_ERRORS else "LIFECYCLE_OPERATION_FAILED"
        completed = journal.complete(request, error=code)
    else:
        _checkpoint("after_execute")
        completed = journal.complete(request, result=result)
    send_message(channel, _response(request, completed["state"], completed["result"], completed["error"], None))
    return completed


def _worker_config(config: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"home": str(Path(config.home))}
    if not Path(value["home"]).is_absolute() or len(value["home"].encode("utf-8")) > 1024:
        raise RuntimeError("LIFECYCLE_WORKER_BOOTSTRAP_INVALID")
    for name in WORKER_CONFIG_KEYS - {"home"}:
        item = getattr(config, name, None)
        if type(item) is not int or not 1024 <= item <= 65535:
            raise RuntimeError("LIFECYCLE_WORKER_BOOTSTRAP_INVALID")
        value[name] = item
    return value


def _checkpoint(_stage: str) -> None:
    """Patchable crash-injection boundary used by focused tests."""


def _response(request: Mapping[str, Any], state: str, result: Any, error: Any, challenge: str | None) -> dict[str, Any]:
    return {
        "schema": RESPONSE_SCHEMA, "request_id": request["request_id"],
        "operation": request["operation"], "state": state,
        "result": result, "error": error, "commit_challenge": challenge,
    }


def _validate_owned_fd(descriptor: int, mode: int, code: str) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode:
        raise RuntimeError(code)


def _read_owned_at(directory_fd: int, name: str, limit: int, mode: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        _validate_owned_fd(descriptor, mode, "UNSAFE_LIFECYCLE_JOURNAL_FILE")
        raw = os.read(descriptor, limit + 1)
        if len(raw) > limit or os.read(descriptor, 1):
            raise RuntimeError("LIFECYCLE_JOURNAL_TOO_LARGE")
        return raw
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeError("LIFECYCLE_JOURNAL_WRITE_FAILED")
        view = view[written:]
