#!/usr/bin/env python3
"""Real-process Relay v2 mechanical acceptance harness.

This harness deliberately has no synthetic endpoint fallback.  It starts the
real Go relay and requires the repository-owned Rust and Node helpers before a
run can be accepted.  Provider and physical-phone evidence remain out of scope.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping


MARKER = "REMOTE_V2_MECHANICAL_PASS"
SCHEMA = "nomad.remote-v2.mechanical-evidence.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
RELAY_DIR = REPO_ROOT / "relay"
RUST_SOURCE = REPO_ROOT / "connector" / "src" / "bin" / "nomad_remote_v2_mechanical.rs"
NODE_HELPER = REPO_ROOT / "testkit" / "remote-v2" / "device.mts"
RUST_BIN_NAME = "nomad-remote-v2-mechanical"
VECTOR_PATH = REPO_ROOT / "contracts" / "vectors" / "remote-envelope-v2.json"
PROVIDER_ENV_NAMES = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_GENERATIVE_AI_API_KEY",
        "OPENROUTER_API_KEY",
        "DEEPSEEK_API_KEY",
    }
)


class HarnessError(RuntimeError):
    """Content-free harness failure."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _private_root() -> Path:
    old_umask = os.umask(0o077)
    try:
        root = Path(tempfile.mkdtemp(prefix="nomad-remote-v2-"))
    finally:
        os.umask(old_umask)
    os.chmod(root, 0o700)
    return root.resolve(strict=True)


def _exclusive_private_json(path: Path, value: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        raw = canonical_json(value)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise HarnessError("private_file_write_failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o600:
        raise HarnessError("private_file_mode_failed")


def _exclusive_private_copy(source: Path, destination: Path) -> None:
    raw = source.read_bytes()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise HarnessError("private_file_write_failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def make_provision(root: Path) -> tuple[Path, dict[str, str]]:
    """Create the fixed-shape relay provisioning file and child-only secrets."""
    host_bearer = secrets.token_urlsafe(48)
    device_bearer = secrets.token_urlsafe(48)
    vector = json.loads(VECTOR_PATH.read_bytes())
    mailbox_id = vector["frame"]["mailbox_id"]
    provision = {
        "device_key_commitment": vector["device_signing_commitment"],
        "device_token_digest": _digest(device_bearer),
        "epoch": vector["frame"]["epoch"],
        "host_identity_commitment": vector["host_signing_commitment"],
        "host_token_digest": _digest(host_bearer),
        "mailbox_id": mailbox_id,
    }
    path = root / "provision.json"
    _exclusive_private_json(path, provision)
    return path, {
        "mailbox_id": mailbox_id,
        "epoch": str(provision["epoch"]),
        "host_bearer": host_bearer,
        "device_bearer": device_bearer,
    }


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def sanitized_child_env(extra: Mapping[str, str]) -> dict[str, str]:
    """Build a child env that never inherits Provider credentials."""
    # Iterate names first so allowlisted Provider values are never fetched into
    # this process merely to discard them.
    env = {
        key: os.environ[key]
        for key in os.environ
        if key not in PROVIDER_ENV_NAMES
    }
    env.update(extra)
    return env


def helper_preflight() -> dict[str, Any]:
    rust_present = RUST_SOURCE.is_file()
    node_present = NODE_HELPER.is_file()
    return {
        "node_helper": node_present,
        "provider": "NOT_RUN",
        "physical_phone": "NOT_RUN",
        "relay_source": (RELAY_DIR / "cmd" / "relay" / "main.go").is_file(),
        "rust_helper": rust_present,
        "status": "READY" if rust_present and node_present else "BLOCKED_HELPERS_REQUIRED",
    }


def relay_command(
    binary: Path,
    *,
    role: str,
    legacy_port: int,
    v2_port: int,
    legacy_db: Path,
    v2_db: Path,
    provision_file: Path | None,
) -> list[str]:
    if role not in {"host", "device"}:
        raise HarnessError("invalid_relay_role")
    command = [
        str(binary),
        "--addr",
        f"127.0.0.1:{legacy_port}",
        "--db",
        str(legacy_db),
        "--v2-enable",
        "--v2-addr",
        f"127.0.0.1:{v2_port}",
        "--v2-role",
        role,
        "--v2-db",
        str(v2_db),
        "--v2-loopback-test-http",
    ]
    if provision_file is not None:
        command.extend(["--v2-provision-file", str(provision_file)])
    return command


def build_relay(root: Path) -> Path:
    binary = root / "nomad-relay"
    result = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/relay"],
        cwd=RELAY_DIR,
        env=sanitized_child_env({}),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if result.returncode != 0 or not binary.is_file():
        raise HarnessError("relay_build_failed")
    return binary


def build_rust_helper() -> Path:
    result = subprocess.run(
        [
            "cargo", "build", "--manifest-path", str(REPO_ROOT / "connector" / "Cargo.toml"),
            "--features", "remote_v2_test_helper", "--bin", RUST_BIN_NAME,
        ],
        cwd=REPO_ROOT, env=sanitized_child_env({}), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False,
    )
    binary = REPO_ROOT / "connector" / "target" / "debug" / RUST_BIN_NAME
    if result.returncode != 0 or not binary.is_file():
        raise HarnessError("rust_helper_build_failed")
    return binary


def start_relay(command: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        command,
        cwd=RELAY_DIR,
        env=sanitized_child_env({}),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def wait_relay(
    process: subprocess.Popen[bytes],
    *,
    base_url: str,
    mailbox_id: str,
    bearer: str,
    direction: str,
    timeout: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout
    del mailbox_id, bearer, direction
    if not base_url.startswith("http://127.0.0.1:"):
        raise HarnessError("relay_readiness_origin_invalid")
    port = int(base_url.rsplit(":", 1)[1])
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read(4096) if process.stderr is not None else b""
            category = "unknown"
            if b"provision" in stderr.lower():
                category = "provision"
            elif b"database" in stderr.lower() or b"sqlite" in stderr.lower():
                category = "database"
            elif b"listen" in stderr.lower() or b"address" in stderr.lower():
                category = "listen"
            raise HarnessError(f"relay_exited_before_ready_{category}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise HarnessError("relay_readiness_timeout")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        process.communicate(timeout=1)
        return
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def _run_json_child(
    command: list[str], *, env: Mapping[str, str], cwd: Path, expect_success: bool = True
) -> dict[str, Any]:
    result = subprocess.run(
        command, cwd=cwd, env=sanitized_child_env(env), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
    )
    combined = result.stdout + result.stderr
    for value in env.values():
        if value.encode("utf-8") in combined:
            raise HarnessError("child_output_secret_leak")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1 or len(lines[0]) > 16 * 1024:
        raise HarnessError("helper_output_invalid")
    try:
        output = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessError("helper_output_invalid") from exc
    if not isinstance(output, dict):
        raise HarnessError("helper_output_invalid")
    succeeded = result.returncode == 0
    if succeeded != expect_success:
        phase = command[command.index("--phase") + 1] if "--phase" in command else "unknown"
        error = output.get("error_code", output.get("error", "unknown"))
        safe_error = error if isinstance(error, str) and error.replace("_", "").isalnum() else "unknown"
        raise HarnessError(f"helper_exit_unexpected_{phase}_{safe_error}")
    return output


def run_host_phase(binary: Path, phase: str, url: str, state: Path, token: str, *, expect_success: bool = True) -> dict[str, Any]:
    return _run_json_child(
        [str(binary), "--phase", phase, "--relay-url", url, "--state", str(state)],
        env={"NOMAD_REMOTE_V2_HOST_TOKEN": token}, cwd=REPO_ROOT, expect_success=expect_success,
    )


def run_device_phase(phase: str, url: str, state: Path, token: str, *, expect_success: bool = True) -> dict[str, Any]:
    return _run_json_child(
        [
            "node", "--no-warnings", "--experimental-transform-types",
            str(NODE_HELPER), "--phase", phase, "--relay-url", url, "--state", str(state),
        ],
        env={"NOMAD_REMOTE_V2_DEVICE_TOKEN": token}, cwd=REPO_ROOT, expect_success=expect_success,
    )


def run_slice() -> dict[str, Any]:
    preflight = helper_preflight()
    if preflight["status"] != "READY":
        raise HarnessError("required_real_process_helpers_missing")
    root = _private_root()
    processes: list[subprocess.Popen[bytes]] = []
    try:
        provision_path, secret = make_provision(root)
        relay_binary = build_relay(root)
        host_binary = build_rust_helper()
        v2_db = root / "relay-v2.sqlite"
        host_v2_port = reserve_loopback_port()
        device_v2_port = reserve_loopback_port()
        host_legacy_port = reserve_loopback_port()
        device_legacy_port = reserve_loopback_port()
        host_url = f"http://127.0.0.1:{host_v2_port}"
        device_url = f"http://127.0.0.1:{device_v2_port}"
        host_state = root / "host-state.sqlite"
        device_state = root / "device-state" / "state.json"

        pending_host = run_host_phase(
            host_binary, "publish-projection", host_url, host_state,
            secret["host_bearer"], expect_success=False,
        )
        if pending_host.get("ok") is not False:
            raise HarnessError("host_pending_setup_invalid")
        host_relay = start_relay(relay_command(
            relay_binary, role="host", legacy_port=host_legacy_port,
            v2_port=host_v2_port, legacy_db=root / "host-v1.sqlite",
            v2_db=v2_db, provision_file=provision_path,
        ))
        processes.append(host_relay)
        wait_relay(
            host_relay, base_url=host_url, mailbox_id=secret["mailbox_id"],
            bearer=secret["host_bearer"], direction="device_to_host",
        )
        device_relay = start_relay(relay_command(
            relay_binary, role="device", legacy_port=device_legacy_port,
            v2_port=device_v2_port, legacy_db=root / "device-v1.sqlite",
            v2_db=v2_db, provision_file=None,
        ))
        processes.append(device_relay)
        wait_relay(
            device_relay, base_url=device_url, mailbox_id=secret["mailbox_id"],
            bearer=secret["device_bearer"], direction="host_to_device",
        )

        wrong_role = run_host_phase(
            host_binary, "publish-projection", device_url,
            root / "wrong-role-host-state.sqlite", secret["device_bearer"],
            expect_success=False,
        )
        if wrong_role.get("ok") is not False:
            raise HarnessError("wrong_role_was_accepted")

        projection = run_host_phase(
            host_binary, "publish-projection", host_url, host_state, secret["host_bearer"]
        )
        if projection.get("ok") is not True or projection.get("status") != "republished_pending_frame":
            raise HarnessError("projection_publish_invalid")
        consumed_projection = run_device_phase(
            "consume-projection", device_url, device_state, secret["device_bearer"]
        )
        if consumed_projection.get("status") != "OK":
            raise HarnessError("projection_consume_invalid")
        revoked_publish_state = root / "device-state" / "pre-revoke-state.json"
        _exclusive_private_copy(device_state, revoked_publish_state)

        stop_process(device_relay)
        pending_device = run_device_phase(
            "publish-command", device_url, device_state, secret["device_bearer"]
            , expect_success=False
        )
        if pending_device.get("status") != "ERROR" or pending_device.get("error") != "PUBLISH_FAILED":
            raise HarnessError("device_pending_setup_invalid")
        device_relay = start_relay(relay_command(
            relay_binary, role="device", legacy_port=device_legacy_port,
            v2_port=device_v2_port, legacy_db=root / "device-v1.sqlite",
            v2_db=v2_db, provision_file=None,
        ))
        processes.append(device_relay)
        wait_relay(
            device_relay, base_url=device_url, mailbox_id=secret["mailbox_id"],
            bearer=secret["device_bearer"], direction="host_to_device",
        )
        command = run_device_phase(
            "publish-command", device_url, device_state, secret["device_bearer"]
        )
        if command.get("status") != "OK":
            raise HarnessError("command_publish_invalid")
        receipt = run_host_phase(
            host_binary, "consume-command", host_url, host_state, secret["host_bearer"]
        )
        if (
            receipt.get("ok") is not True
            or receipt.get("status") != "rejected_safety_blocked"
            or receipt.get("read_sequence") != receipt.get("applied_through_sequence")
            or receipt.get("read_sequence") != receipt.get("acked_through_sequence")
        ):
            raise HarnessError("rejected_receipt_invalid")
        consumed_receipt = run_device_phase(
            "consume-receipt", device_url, device_state, secret["device_bearer"]
        )
        if consumed_receipt.get("status") != "OK":
            raise HarnessError("receipt_consume_invalid")

        # Every phase is a fresh endpoint process.  These repeat phases prove
        # that durable cursors survive process restart.
        host_restart = run_host_phase(
            host_binary, "consume-command", host_url, host_state, secret["host_bearer"]
        )
        if host_restart.get("status") != "idle" or host_restart.get("acked_through_sequence") != receipt.get("acked_through_sequence"):
            raise HarnessError("host_restart_cursor_invalid")
        device_restart = run_device_phase(
            "consume-receipt", device_url, device_state, secret["device_bearer"]
        )
        if device_restart.get("status") != "OK":
            raise HarnessError("device_restart_cursor_invalid")

        revoked = run_host_phase(
            host_binary, "revoke", host_url, host_state, secret["host_bearer"]
        )
        if revoked.get("status") != "revoked":
            raise HarnessError("revoke_invalid")
        denied_publish = run_device_phase(
            "publish-command", device_url, revoked_publish_state, secret["device_bearer"],
            expect_success=False,
        )
        denied_read = run_device_phase(
            "consume-receipt", device_url, device_state, secret["device_bearer"],
            expect_success=False,
        )
        if (
            denied_publish.get("status") != "ERROR"
            or denied_publish.get("error") != "PUBLISH_FAILED"
            or denied_read.get("status") != "ERROR"
            or denied_read.get("error") != "READ_FAILED"
        ):
            publish_code = denied_publish.get("error", "unknown")
            read_code = denied_read.get("error", "unknown")
            raise HarnessError(f"revoke_did_not_block_device_{publish_code}_{read_code}")

        return {
            "marker": MARKER,
            "mechanical": True,
            "physical_phone": "NOT_RUN",
            "production_ready": False,
            "provider": "NOT_RUN",
            "pending_restart": "VERIFIED",
            "relay_processes": 2,
            "restart_cursor": "VERIFIED",
            "schema": SCHEMA,
            "status": "PASS",
            "wrong_role": "VERIFIED",
        }
    finally:
        for process in reversed(processes):
            stop_process(process)
        shutil.rmtree(root)


def main() -> int:
    try:
        evidence = run_slice()
    except HarnessError as exc:
        print(canonical_json({
            "error": str(exc),
            "preflight": helper_preflight(),
            "production_ready": False,
            "provider": "NOT_RUN",
            "physical_phone": "NOT_RUN",
            "schema": SCHEMA,
            "status": "BLOCKED",
        }).decode("ascii"))
        return 1
    print(canonical_json(evidence).decode("ascii"))
    print(MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
