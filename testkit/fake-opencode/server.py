#!/usr/bin/env python3
"""Deterministic stdlib-only OpenCode HTTP substitute for Pilot tests.

This process implements the fixed interface consumed by pilot-adapter. It is an
interface substitute, not evidence that an upstream OpenCode build implements
the Nomad durable-event extension or pending-permission guarantees.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

EXPECTED_VERSION = "1.18.16"
SESSION_ID = "pilot-session"
TURN_ID = "turn-1"
PERMISSION_ID = "perm-1"
TIMESTAMPS = [f"2026-08-18T08:00:{second:02d}Z" for second in range(30)]


def base_events() -> list[dict[str, Any]]:
    raw = [
        ("session.created", {}, None),
        ("session.status", {"status": "running", "transition": "turn_started"}, TURN_ID),
        ("message.updated", {"kind": "question", "id": "question-1", "summary": "Choose a test target"}, TURN_ID),
        ("permission.updated", {"id": PERMISSION_ID, "status": "pending", "toolName": "Bash", "action": "run tests"}, TURN_ID),
        ("session.diff", {"summary": "1 file changed"}, TURN_ID),
        ("session.status", {"status": "reconnecting"}, TURN_ID),
        ("session.status", {"status": "connected"}, TURN_ID),
    ]
    return [
        {
            "id": f"{SESSION_ID}:{seq}",
            "seq": seq,
            "timestamp": TIMESTAMPS[seq],
            "durable": True,
            "type": event_type,
            "sessionID": SESSION_ID,
            "turnID": turn_id,
            "data": data,
        }
        for seq, (event_type, data, turn_id) in enumerate(raw, start=1)
    ]


class State:
    def __init__(self, scenario: str) -> None:
        self.lock = threading.Lock()
        self.scenario = scenario
        self.commands: dict[str, dict[str, Any]] = {}
        self.command_counts = {"reply": 0, "deny": 0, "stop": 0}
        self.permission_pending = True

    def reset(self, scenario: str | None = None) -> None:
        with self.lock:
            if scenario is not None:
                self.scenario = scenario
            self.commands.clear()
            self.command_counts = {"reply": 0, "deny": 0, "stop": 0}
            self.permission_pending = True

    def execute(
        self, request_id: str, kind: str, permission_id: str | None = None
    ) -> tuple[int, dict[str, Any]]:
        with self.lock:
            if request_id in self.commands:
                result = dict(self.commands[request_id])
                result["duplicate"] = True
                return 200, result
            if kind == "deny" and (
                permission_id != PERMISSION_ID or not self.permission_pending
            ):
                result = {
                    "request_id": request_id,
                    "status": "Stale",
                    "error_code": "ERR_REQUEST_STALE",
                    "error_message": "permission is not pending",
                    "upstream_pending_bound": False,
                }
                self.commands[request_id] = result
                return 409, result
            self.command_counts[kind] += 1
            if kind == "deny":
                self.permission_pending = False
            accepted_seq = 8 + sum(self.command_counts.values())
            result = {
                "request_id": request_id,
                "status": "HostAccepted",
                "accepted_at_seq": accepted_seq,
                "event_id": f"{SESSION_ID}:{accepted_seq}",
                "error_code": "OK",
                "duplicate": False,
            }
            if kind == "deny":
                result["upstream_pending_bound"] = True
            self.commands[request_id] = result
            return 200, result


class Handler(BaseHTTPRequestHandler):
    server: "FakeServer"

    def log_message(self, format_string: str, *args: object) -> None:
        if self.server.verbose:
            super().log_message(format_string, *args)

    def send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1024 * 1024:
            raise ValueError("request too large")
        value = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path
        scenario = self.server.state.scenario
        if path == "/global/health":
            version = "0.0.0" if scenario == "version-mismatch" else EXPECTED_VERSION
            self.send_json(200, {"healthy": True, "version": version})
        elif path == f"/session/{SESSION_ID}":
            self.send_json(
                200,
                {
                    "id": SESSION_ID,
                    "version": EXPECTED_VERSION,
                    "status": "running",
                    "turnID": TURN_ID,
                    "updatedAt": TIMESTAMPS[7],
                },
            )
        elif path == "/event":
            session_id = parse_qs(parsed.query).get("sessionID", [""])[0]
            if session_id != SESSION_ID:
                self.send_json(404, {"error": "session not found"})
                return
            events = base_events()
            if scenario == "unknown-event":
                events[3]["type"] = "future.permission.v2"
            elif scenario == "event-gap":
                events.pop(3)
            self.send_json(200, events)
        elif path == f"/session/{SESSION_ID}/diff":
            self.send_json(
                200,
                [
                    {
                        "file": "src/pilot.txt",
                        "before": "before\n",
                        "after": "after\n",
                        "additions": 1,
                        "deletions": 1,
                        "patch": "@@ -1 +1 @@\n-before\n+after\n",
                    }
                ],
            )
        elif path == "/__test__/stats":
            with self.server.state.lock:
                self.send_json(
                    200,
                    {
                        "scenario": scenario,
                        "command_counts": self.server.state.command_counts,
                        "permission_pending": self.server.state.permission_pending,
                    },
                )
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
            return
        path = urlparse(self.path).path
        request_id = self.headers.get("Idempotency-Key") or body.get("request_id", "")
        if path == "/__test__/reset":
            scenario = body.get("scenario")
            if scenario not in (None, "happy", "version-mismatch", "unknown-event", "event-gap"):
                self.send_json(400, {"error": "unknown scenario"})
                return
            self.server.state.reset(scenario)
            self.send_json(200, {"ok": True, "scenario": self.server.state.scenario})
        elif path == f"/session/{SESSION_ID}/prompt_async":
            if not request_id or not str(body.get("content", "")).strip():
                self.send_json(400, {"error": "request_id and content required"})
                return
            status, result = self.server.state.execute(request_id, "reply")
            self.send_json(status, result)
        elif path == f"/session/{SESSION_ID}/permissions/{PERMISSION_ID}":
            if body.get("allow") is not False:
                self.send_json(403, {"error": "fake pilot interface only accepts deny"})
                return
            status, result = self.server.state.execute(
                request_id, "deny", PERMISSION_ID
            )
            self.send_json(status, result)
        elif path == f"/session/{SESSION_ID}/abort":
            status, result = self.server.state.execute(request_id, "stop")
            self.send_json(status, result)
        else:
            self.send_json(404, {"error": "not found"})


class FakeServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], scenario: str, verbose: bool):
        super().__init__(address, Handler)
        self.state = State(scenario)
        self.verbose = verbose


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4096)
    parser.add_argument(
        "--scenario",
        choices=("happy", "version-mismatch", "unknown-event", "event-gap"),
        default="happy",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "localhost"):
        parser.error("fake server must bind loopback only")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    return args


def main() -> None:
    args = parse_args()
    server = FakeServer((args.host, args.port), args.scenario, args.verbose)
    print(
        json.dumps(
            {"ready": True, "url": f"http://{args.host}:{args.port}", "scenario": args.scenario}
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
