#!/usr/bin/env python3
"""Run the local-only Alpha read-only mechanics slice with real processes.

The OpenCode source is a deterministic interface substitute and is always
reported as SYNTHETIC_SOURCE. This runner is not Pilot or production evidence.
It writes no durable evidence; all databases and logs live in a temporary tree.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

PASS_MARKER = "LOCAL_ALPHA_READONLY_MECHANICS_PASS"
SOURCE = "SYNTHETIC_SOURCE"
TOKEN_ENV = "NOMAD_ALPHA_RELAY_TOKEN"
KEY_ENV = "NOMAD_ALPHA_DEVICE_PRIVATE_KEY_HEX"
LOCAL_TEST_PRIVATE_KEY = (
    "8cd8ac5b730d8f625d9631bb0a6cd7e7d66f6bde56d356b8af602534fe7fc54b"
    "91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864"
)
DEVICE_ID = "00112233445566778899aabbccddeeff"


class SliceFailure(RuntimeError):
    pass


def fail(code: str) -> None:
    raise SliceFailure(code)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if os.environ.get("HOME"):
        environment["HOME"] = os.environ["HOME"]
    if extra:
        environment.update(extra)
    return environment


def run_build(command: Sequence[str], cwd: Path, timeout: float) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=minimal_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        fail("BUILD_FAILED")


class ManagedProcess:
    def __init__(
        self, name: str, command: Sequence[str], cwd: Path, environment: Mapping[str, str]
    ) -> None:
        self.name = name
        self.command = tuple(str(item) for item in command)
        self.process = subprocess.Popen(
            self.command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.output = b""

    def stop(self) -> None:
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
        if self.process.stdout is not None:
            self.output += self.process.stdout.read(64 * 1024 + 1)
            self.process.stdout.close()
        if len(self.output) > 64 * 1024:
            fail("CHILD_LOG_OVERFLOW")


class RouteRecorder:
    def __init__(self, target_port: int) -> None:
        self.target_port = target_port
        self.lock = threading.Lock()
        self.routes: Counter[tuple[str, str]] = Counter()
        self.frame_list_lengths: list[int] = []
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                self.forward()

            def do_POST(self) -> None:  # noqa: N802
                self.forward()

            def forward(self) -> None:
                parsed = urlsplit(self.path)
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 128 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else None
                with recorder.lock:
                    recorder.routes[(self.command, parsed.path)] += 1
                connection = http.client.HTTPConnection(
                    "127.0.0.1", recorder.target_port, timeout=5
                )
                headers = {
                    name: value
                    for name, value in self.headers.items()
                    if name.lower() in {"authorization", "content-type"}
                }
                try:
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    payload = response.read(16 * 1024 * 1024 + 1)
                    if len(payload) > 16 * 1024 * 1024:
                        raise OSError("response bound")
                    if parsed.path == "/v1/frames" and response.status == 200:
                        value = json.loads(payload)
                        if not isinstance(value, list):
                            raise ValueError("frame list")
                        with recorder.lock:
                            recorder.frame_list_lengths.append(len(value))
                    self.send_response(response.status)
                    self.send_header(
                        "Content-Type", response.getheader("Content-Type") or "application/json"
                    )
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                except Exception:
                    self.send_error(502)
                finally:
                    connection.close()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def wait_http(url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    fail("SERVICE_TIMEOUT")


def request_json(
    url: str, *, method: str = "GET", body: Mapping[str, Any] | None = None
) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_browser_projection(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "session",
        "last_applied_seq",
        "digest",
        "events",
        "changes",
        "provenance",
    }:
        fail("BROWSER_SCHEMA")
    if value["schema"] != "nomad.alpha.readonly.v1" or value["status"] != "available":
        fail("BROWSER_SCHEMA")
    session = value.get("session")
    if not isinstance(session, dict):
        fail("BROWSER_SESSION")
    session_id = session.get("session_id")
    turn_id = session.get("turn_id")
    if not safe_alias(session_id, "sess") or (turn_id is not None and not safe_alias(turn_id, "turn")):
        fail("BROWSER_ALIAS")
    events = value.get("events")
    if not isinstance(events, list) or len(events) > 32:
        fail("BROWSER_EVENTS")
    for event in events:
        if (
            not isinstance(event, dict)
            or event.get("session_id") != session_id
            or not safe_alias(event.get("event_id"), "evt")
            or (event.get("turn_id") is not None and not safe_alias(event.get("turn_id"), "turn"))
        ):
            fail("BROWSER_ALIAS")
    if value.get("changes") != {"status": "unavailable", "files": []}:
        fail("BROWSER_READONLY")
    if value.get("provenance") != {
        "source": "local-alpha-projector",
        "relay_ingress_verified": True,
        "gateway_schema_verified": True,
    }:
        fail("BROWSER_PROVENANCE")
    digest = value.get("digest")
    without_digest = dict(value)
    without_digest.pop("digest", None)
    expected = "sha256:" + hashlib.sha256(canonical_json(without_digest).encode()).hexdigest()
    if digest != expected:
        fail("BROWSER_DIGEST")
    forbidden = {"command", "reply", "stop", "permission_decision", "allow_once"}
    if forbidden & recursive_keys(value):
        fail("BROWSER_READONLY")


def safe_alias(value: Any, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(prefix + "-"):
        return False
    suffix = value[len(prefix) + 1 :]
    return len(suffix) == 32 and all(character in "0123456789abcdef" for character in suffix)


def recursive_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = {str(key) for key in value}
        for item in value.values():
            keys.update(recursive_keys(item))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(recursive_keys(item))
        return keys
    return set()


def scan_mobile_build(dist: Path, secrets_to_reject: Sequence[str]) -> None:
    files = [path for path in dist.rglob("*") if path.is_file()]
    if not files:
        fail("MOBILE_BUILD_EMPTY")
    raw = b"".join(path.read_bytes() for path in files)
    if b"/api/alpha/session" not in raw or b"/api/pilot/session" in raw:
        fail("MOBILE_DEFAULT_ROUTE")
    for secret_value in secrets_to_reject:
        if secret_value.encode() in raw:
            fail("MOBILE_SECRET_EXPOSURE")


def run_slice(repo: Path, timeout: float) -> dict[str, Any]:
    relay_port, gateway_port = free_port(), free_port()
    token = "alpha-token-" + secrets.token_hex(24)
    processes: list[ManagedProcess] = []
    stopped: list[ManagedProcess] = []
    gateway_routes: Counter[tuple[str, str]] = Counter()
    recorder: RouteRecorder | None = None

    with tempfile.TemporaryDirectory(prefix="nomad-alpha-readonly-") as temporary:
        temp = Path(temporary)
        relay_binary = temp / "nomad-relay"
        relay_db = temp / "relay.sqlite3"
        gateway_db = temp / "gateway.sqlite3"
        run_build(["go", "build", "-o", str(relay_binary), "./cmd/relay"], repo / "relay", timeout)
        run_build(["cargo", "build", "--quiet", "--bin", "alpha-projector"], repo / "connector", timeout)
        run_build(["npm", "run", "build"], repo / "mobile-reference", timeout)
        projector_binary = repo / "connector" / "target" / "debug" / "alpha-projector"
        node = shutil.which("node")
        if not projector_binary.is_file() or not node:
            fail("BUILD_OUTPUT_MISSING")
        scan_mobile_build(repo / "mobile-reference" / "dist", (token, LOCAL_TEST_PRIVATE_KEY))

        def launch(name: str, command: Sequence[str], cwd: Path, env: Mapping[str, str]) -> ManagedProcess:
            process = ManagedProcess(name, command, cwd, env)
            processes.append(process)
            return process

        def start_relay() -> ManagedProcess:
            return launch(
                "relay",
                [
                    str(relay_binary),
                    "-addr",
                    f"127.0.0.1:{relay_port}",
                    "-db",
                    str(relay_db),
                    "-alpha-local",
                    "-alpha-token-env",
                    TOKEN_ENV,
                ],
                repo / "relay",
                minimal_env({TOKEN_ENV: token}),
            )

        def start_gateway(relay_origin: str) -> ManagedProcess:
            return launch(
                "gateway",
                [
                    node,
                    "pilot-gateway/server.mjs",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(gateway_port),
                    "--relay-url",
                    relay_origin,
                    "--state-db",
                    str(gateway_db),
                    "--dist-dir",
                    str(repo / "mobile-reference" / "dist"),
                ],
                repo / "mobile-reference",
                minimal_env({TOKEN_ENV: token}),
            )

        try:
            fake = launch(
                "synthetic-opencode",
                [
                    sys.executable,
                    "testkit/fake-opencode/server.py",
                    "--scenario",
                    "happy",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "4096",
                ],
                repo,
                minimal_env({"PYTHONDONTWRITEBYTECODE": "1"}),
            )
            wait_http("http://127.0.0.1:4096/global/health", timeout)
            if fake.process.poll() is not None:
                fail("SYNTHETIC_SOURCE_NOT_OWNED")

            relay = start_relay()
            wait_http(f"http://127.0.0.1:{relay_port}/health", timeout)
            recorder = RouteRecorder(relay_port)
            recorder.start()

            projector_command = [
                str(projector_binary),
                "--relay-url",
                recorder.origin,
                "--session-id",
                "pilot-session",
            ]
            projector = subprocess.run(
                projector_command,
                cwd=repo / "connector",
                env=minimal_env({KEY_ENV: LOCAL_TEST_PRIVATE_KEY}),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            projector_surface = b"\0".join(
                item.encode() for item in projector_command
            ) + projector.stdout + projector.stderr
            if token.encode() in projector_surface or LOCAL_TEST_PRIVATE_KEY.encode() in projector_surface:
                fail("PROJECTOR_SECRET_EXPOSURE")
            if projector.returncode != 0 or projector.stderr or len(projector.stdout) > 8 * 1024:
                fail("PROJECTOR_FAILED")
            receipt = json.loads(projector.stdout)
            if receipt.get("status") != "accepted" or not str(receipt.get("digest", "")).startswith("sha256:"):
                fail("PROJECTOR_RECEIPT")

            gateway = start_gateway(recorder.origin)
            gateway_base = f"http://127.0.0.1:{gateway_port}"
            wait_http(gateway_base + "/", timeout)
            gateway_routes[("GET", "/api/alpha/session")] += 1
            status, first = request_json(gateway_base + "/api/alpha/session")
            if status != 200:
                fail("ALPHA_SESSION_UNAVAILABLE")
            validate_browser_projection(first)

            before = recorder.routes.copy()
            gateway_routes[("POST", "/api/pilot/commands")] += 1
            command_status, command_body = request_json(
                gateway_base + "/api/pilot/commands",
                method="POST",
                body={"command_type": "stop"},
            )
            if command_status != 403 or command_body != {"error": "READ_ONLY_ALPHA"}:
                fail("COMMAND_NOT_BLOCKED")
            if recorder.routes != before:
                fail("COMMAND_TOUCHED_RELAY")

            gateway.stop()
            stopped.append(gateway)
            relay.stop()
            stopped.append(relay)
            relay = start_relay()
            wait_http(f"http://127.0.0.1:{relay_port}/health", timeout)
            gateway = start_gateway(recorder.origin)
            wait_http(gateway_base + "/", timeout)
            gateway_routes[("GET", "/api/alpha/session")] += 1
            status, restarted = request_json(gateway_base + "/api/alpha/session")
            if status != 200 or restarted != first:
                fail("RESTART_STATE_CONTINUITY")
            validate_browser_projection(restarted)

            expected_relay_routes = Counter(
                {
                    ("POST", "/v1/frame"): 1,
                    ("GET", "/v1/frames"): 2,
                    ("POST", "/v1/ack"): 1,
                }
            )
            if recorder.routes != expected_relay_routes or recorder.frame_list_lengths != [1, 0]:
                fail("RELAY_ROUTE_OR_ACK_CONTINUITY")
            if any(path.startswith("/v1/test/") for _, path in recorder.routes):
                fail("TEST_ROUTE_USED")
            if gateway_routes[("GET", "/api/pilot/session")] != 0:
                fail("DEFAULT_PILOT_ROUTE_USED")
            if not relay_db.is_file() or not gateway_db.is_file():
                fail("PERSISTENT_DB_MISSING")

            result = {
                "marker": PASS_MARKER,
                "source": SOURCE,
                "production_ready": False,
                "pilot_ready": False,
                "evidence": {
                    "real_processes": {
                        "relay_starts": 2,
                        "projector_runs": 1,
                        "gateway_starts": 2,
                        "mobile_built": True,
                    },
                    "relay_routes": {
                        "frame": 1,
                        "frames": 2,
                        "ack": 1,
                        "test_routes": 0,
                    },
                    "gateway_routes": {
                        "alpha_session": 2,
                        "pilot_commands_blocked": 1,
                        "default_pilot_session": 0,
                    },
                    "restart": {
                        "state_continuous": True,
                        "ack_continuous": True,
                    },
                    "secret_hygiene": {
                        "argv_clean": True,
                        "logs_clean": True,
                        "browser_bundle_clean": True,
                    },
                    "projection_digest": first["digest"],
                },
            }
            return result
        finally:
            if recorder is not None:
                recorder.close()
            for process in reversed(processes):
                if process not in stopped:
                    process.stop()
                    stopped.append(process)
            secret_values = (token.encode(), LOCAL_TEST_PRIVATE_KEY.encode())
            for process in stopped:
                command_bytes = "\0".join(process.command).encode()
                if any(secret in command_bytes or secret in process.output for secret in secret_values):
                    fail("CHILD_SECRET_EXPOSURE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()
    try:
        result = run_slice(args.repo.resolve(), args.timeout)
    except Exception as error:
        code = str(error) if isinstance(error, SliceFailure) else "INTERNAL_FAILURE"
        print(
            json.dumps(
                {
                    "marker": "LOCAL_ALPHA_READONLY_MECHANICS_FAIL",
                    "source": SOURCE,
                    "production_ready": False,
                    "pilot_ready": False,
                    "error": code,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
