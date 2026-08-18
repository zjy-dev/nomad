#!/usr/bin/env python3
"""Run Fake OpenCode -> Rust Host -> persistent Relay -> consumer gates."""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from testkit.pilot.acceptance import validate_result
from testkit.pilot.telemetry import alias_identifier, validate_event


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError(f"service did not become ready: {url}")


def request_json(url: str, token: str | None = None, body: dict[str, Any] | None = None) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(request, timeout=5.0) as response:
        return json.load(response)


def stop(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)


def run_json(command: list[str], cwd: Path, timeout: float) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout)
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"command emitted no JSON: {' '.join(command)}")
    result = json.loads(lines[-1])
    if result.get("ok") is not True:
        raise RuntimeError(f"command failed: {result}")
    return result


def relay_command(repo: Path, port: int, db_path: Path, token: str) -> list[str]:
    return [
        "go", "run", "./cmd/relay",
        "-addr", f"127.0.0.1:{port}",
        "-db", str(db_path),
        "-enable-test-bridge",
        "-test-token", token,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    repo = args.repo.resolve()
    relay_port = free_port()
    relay_url = f"http://127.0.0.1:{relay_port}"
    token = secrets.token_urlsafe(24)
    channel = "pilot-vertical-slice"
    salt = secrets.token_hex(16)

    fake: subprocess.Popen[str] | None = None
    relay: subprocess.Popen[str] | None = None
    with tempfile.TemporaryDirectory(prefix="nomad-pilot-slice-") as temp_dir:
        temp = Path(temp_dir)
        relay_db = temp / "relay.sqlite3"
        journal = temp / "host-journal.sqlite3"
        log_handles = {name: (temp / f"{name}.log").open("w+", encoding="utf-8") for name in ("fake", "relay")}
        try:
            fake = subprocess.Popen(
                ["python3", "testkit/fake-opencode/server.py", "--scenario", "happy"],
                cwd=repo, stdout=log_handles["fake"], stderr=subprocess.STDOUT, text=True,
            )
            wait_http("http://127.0.0.1:4096/global/health", args.timeout)

            relay = subprocess.Popen(
                relay_command(repo, relay_port, relay_db, token), cwd=repo / "relay",
                stdout=log_handles["relay"], stderr=subprocess.STDOUT, text=True,
            )
            wait_http(f"{relay_url}/health", args.timeout)

            challenge = request_json(f"{relay_url}/v1/test/pairing/challenges", token, {"channel": channel})
            for side in ("host", "mobile"):
                request_json(
                    f"{relay_url}/v1/test/pairing/confirm", token,
                    {"channel": channel, "challenge_id": challenge["challenge_id"], "side": side, "comparison_code": challenge["comparison_code"]},
                )

            adapter = ["cargo", "run", "--quiet", "--bin", "pilot-adapter", "--"]
            capture = run_json(
                adapter + [
                    "capture", "--session-id", "pilot-session",
                    "--relay-url", relay_url, "--relay-token", token, "--relay-channel", channel,
                ], repo / "connector", args.timeout,
            )
            snapshot = capture["capture"]["snapshot"]
            if snapshot["turn_state"] != "NeedsPermission" or snapshot["state_summary"]["diff_file_count"] != 1:
                raise RuntimeError("captured snapshot lacks permission or authoritative diff facts")

            stop(relay)
            relay = subprocess.Popen(
                relay_command(repo, relay_port, relay_db, token), cwd=repo / "relay",
                stdout=log_handles["relay"], stderr=subprocess.STDOUT, text=True,
            )
            wait_http(f"{relay_url}/health", args.timeout)

            consumed = request_json(
                f"{relay_url}/v1/test/pairing/consume", token,
                {"channel": channel, "challenge_id": challenge["challenge_id"]},
            )
            if consumed.get("consumed") is not True:
                raise RuntimeError("pairing did not survive Relay restart")

            messages = request_json(f"{relay_url}/v1/test/messages?channel={channel}&target=mobile", token)
            checkpoints = [item for item in messages if item.get("payload", {}).get("type") == "session.checkpoint"]
            if len(checkpoints) != 1 or checkpoints[0]["payload"].get("state") != "NeedsPermission":
                raise RuntimeError("persistent Relay checkpoint recovery failed")
            request_json(
                f"{relay_url}/v1/test/ack", token,
                {"channel": channel, "target": "mobile", "message_ids": [checkpoints[0]["message_id"]]},
            )

            def host_command(payload: dict[str, Any]) -> dict[str, Any]:
                return run_json(
                    adapter + ["command", "--journal", str(journal), "--command-json", json.dumps(payload, separators=(",", ":"))],
                    repo / "connector", args.timeout,
                )["result"]

            reply_payload = {"command_type": "reply", "request_id": "req-reply", "session_id": "pilot-session", "seq": 7, "content": "Run the focused test"}
            reply = host_command(reply_payload)
            reply_replay = host_command(reply_payload)
            deny = host_command({"command_type": "permission_decision", "request_id": "req-deny", "session_id": "pilot-session", "seq": 7, "permission_id": "perm-1", "decision": "deny", "action_hash": "sha256:test", "expires_at": "2026-08-18T18:00:00Z"})
            stop_result = host_command({"command_type": "stop", "request_id": "req-stop", "session_id": "pilot-session", "seq": 7, "target_turn_id": "turn-1"})
            allow = host_command({"command_type": "permission_decision", "request_id": "req-allow", "session_id": "pilot-session", "seq": 7, "permission_id": "perm-1", "decision": "allow_once", "action_hash": "sha256:test", "expires_at": "2026-08-18T18:00:00Z"})

            if reply["status"] != "HostAccepted" or reply_replay.get("idempotent_replay") is not True:
                raise RuntimeError("Host reply idempotency failed")
            if deny.get("upstream_pending_bound") is not True or stop_result["status"] != "HostAccepted":
                raise RuntimeError("deny or Stop was not Host accepted")
            if allow["status"] != "Rejected" or allow["error_code"] != "ERR_SAFETY_BLOCKED":
                raise RuntimeError("allow_once was not blocked")

            telemetry = {
                "name": "pilot.command_stage",
                "fields": {"action_type": "stop", "request_alias": alias_identifier("req-stop", salt), "stage": "HostAccepted", "error_code": "OK"},
            }
            validate_event(telemetry["name"], telemetry["fields"])
            acceptance = {
                "allow_once": False, "duplicate_host_acceptance": 0, "unknown_gap": 0,
                "command_stages": [reply["status"], deny["status"], stop_result["status"]],
                "telemetry": [telemetry],
            }
            validate_result(acceptance)
            cleanup = request_json(f"{relay_url}/v1/test/cleanup", token, {"channel": channel})

            print(json.dumps({
                "ok": True, "gate": "ITER2_VERTICAL_SLICE",
                "capture": {"snapshot_seq": snapshot["snapshot_seq"], "state": snapshot["turn_state"], "diff_files": snapshot["state_summary"]["diff_file_count"]},
                "relay": {"restart_recovered": True, "checkpoint_acked": True, "cleanup": cleanup},
                "commands": {"reply": reply["status"], "reply_replay": reply_replay["idempotent_replay"], "deny": deny["status"], "stop": stop_result["status"], "allow_once": allow["status"]},
                "acceptance": "PASS",
            }, sort_keys=True))
            return 0
        except Exception:
            for handle in log_handles.values():
                handle.flush()
                handle.seek(0)
                print(handle.read())
            raise
        finally:
            stop(relay)
            stop(fake)
            for handle in log_handles.values():
                handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
