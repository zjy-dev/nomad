#!/usr/bin/env python3
"""Deterministic browser-to-OpenCode C3 mechanical acceptance.

This is E2 mechanical evidence only.  The upstream process in this file speaks
the locked OpenCode 1.18.16 HTTP shapes, but it is neither OpenCode nor a
Provider-backed Agent.  Product Host, Gateway, Web assets, SQLite journals,
FD bootstrap, UDS transport, and Chrome are the real materialized components.

The child mode is intentionally in this file so the fake remains an external
process without adding a reusable production substitute.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(REPO))

from tools.nomad_web import processes
from tools.nomad_web.launcher import (
    _bootstrap_host,
    _cleanup_product_host_socket,
    _random_command_key,
    _spawn_product_host,
    _write_fd_secret,
)
from tools.nomad_web.materialize import materialize


MARKER = "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS"
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
READ_LIMIT = 64 * 1024
COMMAND_TIMEOUT = 20.0


class SmokeFailure(RuntimeError):
    pass


def fail(code: str) -> None:
    raise SmokeFailure(code)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def frame_send(channel: socket.socket, value: Any) -> None:
    raw = canonical(value)
    channel.sendall(len(raw).to_bytes(4, "big") + raw)


def recv_exact(channel: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = channel.recv(length - len(output))
        if not chunk:
            fail("CONTROL_CHANNEL_CLOSED")
        output.extend(chunk)
    return bytes(output)


def frame_recv(channel: socket.socket) -> Any:
    length = int.from_bytes(recv_exact(channel, 4), "big")
    if length <= 0 or length > 1024 * 1024:
        fail("CONTROL_FRAME_INVALID")
    return json.loads(recv_exact(channel, length))


class FakeState:
    def __init__(self, config: dict[str, Any]):
        self.lock = threading.Lock()
        self.session = config["session"]
        self.question = config["question"]
        self.unknown_question = config["unknown_question"]
        self.permission = config["permission"]
        self.message = config["message"]
        self.call = config["call"]
        self.workspace = config["workspace"]
        self.password = config["password"]
        self.phase = "reply"
        self.revision = 0
        self.drop_action: str | None = None
        self.ledger: list[dict[str, Any]] = []
        self.reads: Counter[str] = Counter()
        self.get_attempts = 0
        self.authorization_failures = 0

    def route_body(self, path: str) -> Any | None:
        with self.lock:
            self.reads[path] += 1
            phase = self.phase
            revision = self.revision
        if path == f"/session/{self.session}":
            return {
                "id": self.session,
                "slug": "c3-mechanical",
                "projectID": "project-c3",
                "directory": self.workspace,
                "title": "upstream-content-canary-c3",
                "version": "1.18.16",
                "time": {"created": 1787650000000, "updated": 1787650000000 + revision},
            }
        if path == "/session/status":
            return {self.session: {"type": "busy"}}
        if path == "/question":
            question = self.unknown_question if phase == "unknown" else self.question
            if phase not in ("reply", "unknown"):
                return []
            return [{
                "id": question,
                "sessionID": self.session,
                "questions": [{
                    "question": "Please provide deployment region?",
                    "header": "private-question-header-c3",
                    "options": [],
                    "multiple": False,
                    "custom": True,
                }],
                "tool": {"messageID": self.message, "callID": self.call},
            }]
        if path == "/permission":
            if phase != "deny":
                return []
            return [{
                "id": self.permission,
                "sessionID": self.session,
                "permission": "bash-private-content-c3",
                "patterns": ["private-command-pattern-c3"],
                "metadata": {"private": "metadata-content-c3"},
                "always": False,
                "tool": {"messageID": self.message, "callID": self.call},
            }]
        if path == f"/session/{self.session}/diff":
            return []
        return None

    def record_post(self, path: str, body: bytes, authorization: str) -> bool:
        with self.lock:
            action = self.action_for(path)
            self.ledger.append({
                "method": "POST",
                "path": path,
                "body_b64": base64.b64encode(body).decode(),
                "authorization_ok": authorization == self.expected_authorization(),
                "action": action,
            })
            drop = action is not None and self.drop_action == action
            if drop:
                self.drop_action = None
            return drop

    def expected_authorization(self) -> str:
        raw = f"opencode:{self.password}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    def action_for(self, path: str) -> str | None:
        if path == f"/api/session/{self.session}/question/{self.question}/reply":
            return "reply"
        if path == f"/api/session/{self.session}/question/{self.unknown_question}/reply":
            return "unknown"
        if path == f"/api/session/{self.session}/permission/{self.permission}/reply":
            return "deny"
        if path == f"/api/session/{self.session}/interrupt":
            return "stop"
        return None


def fake_main(port: int, control_fd: int) -> int:
    channel = socket.socket(fileno=control_fd)
    config = frame_recv(channel)
    state = FakeState(config)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _authorized(self) -> bool:
            return self.headers.get("Authorization") == state.expected_authorization()

        def _json(self, status_code: int, value: Any) -> None:
            raw = canonical(value)
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            with state.lock:
                state.get_attempts += 1
            if not self._authorized():
                with state.lock:
                    state.authorization_failures += 1
                self._json(401, {"error": "unauthorized"})
                return
            body = state.route_body(urllib.parse.urlsplit(self.path).path)
            self._json(200, body) if body is not None else self._json(404, {"error": "not-found"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > 16 * 1024:
                self._json(400, {"error": "framing"})
                return
            body = self.rfile.read(length)
            path = urllib.parse.urlsplit(self.path).path
            drop = state.record_post(path, body, self.headers.get("Authorization", ""))
            if drop:
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
            elif state.action_for(path) is None:
                self._json(404, {"error": "not-found"})
            else:
                self._json(200, {})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="c3-fake-http", daemon=True)
    thread.start()
    frame_send(channel, {"ready": True})
    try:
        while True:
            request = frame_recv(channel)
            operation = request.get("op")
            if operation == "phase":
                phase = request.get("phase")
                if phase not in ("reply", "deny", "running", "unknown"):
                    fail("FAKE_PHASE_INVALID")
                with state.lock:
                    state.phase = phase
                    state.revision += 1
                frame_send(channel, {"ok": True})
            elif operation == "drop":
                with state.lock:
                    state.drop_action = request.get("action")
                frame_send(channel, {"ok": True})
            elif operation == "inspect":
                with state.lock:
                    response = {"ledger": list(state.ledger), "reads": dict(state.reads), "phase": state.phase, "get_attempts": state.get_attempts, "authorization_failures": state.authorization_failures}
                frame_send(channel, response)
            elif operation == "stop":
                frame_send(channel, {"ok": True})
                break
            else:
                fail("FAKE_CONTROL_INVALID")
    finally:
        server.shutdown()
        server.server_close()
        channel.close()
    return 0


class FakeController:
    def __init__(self, executable: Path, port: int, config: dict[str, Any], log_path: Path):
        parent, child = socket.socketpair()
        self.channel = parent
        self.log_handle = log_path.open("xb")
        try:
            self.process = subprocess.Popen(
                [sys.executable, str(executable), "--fake", "--port", str(port), "--control-fd", str(child.fileno())],
                cwd=REPO,
                env=processes.minimal_env({"PYTHONDONTWRITEBYTECODE": "1"}),
                stdin=subprocess.DEVNULL,
                stdout=self.log_handle,
                stderr=subprocess.STDOUT,
                pass_fds=(child.fileno(),),
                start_new_session=True,
            )
        except Exception:
            self.log_handle.close()
            child.close()
            self.channel.close()
            raise
        child.close()
        self.record = {
            "name": "fake-opencode-shape",
            "pid": self.process.pid,
            "process_group": self.process.pid,
            "identity": processes.process_identity(self.process.pid),
            "log": str(log_path),
        }
        frame_send(self.channel, config)
        if frame_recv(self.channel) != {"ready": True}:
            fail("FAKE_NOT_READY")

    def call(self, value: dict[str, Any]) -> Any:
        frame_send(self.channel, value)
        return frame_recv(self.channel)

    def phase(self, value: str) -> None:
        if self.call({"op": "phase", "phase": value}) != {"ok": True}:
            fail("FAKE_PHASE_FAILED")

    def drop(self, action: str) -> None:
        if self.call({"op": "drop", "action": action}) != {"ok": True}:
            fail("FAKE_DROP_FAILED")

    def inspect(self) -> dict[str, Any]:
        return self.call({"op": "inspect"})

    def stop(self) -> None:
        try:
            if self.process.poll() is None:
                try:
                    self.call({"op": "stop"})
                except (OSError, SmokeFailure):
                    pass
            self.channel.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, 9)
                self.process.wait(timeout=5)
        finally:
            self.log_handle.close()


class CDP:
    """Minimal RFC6455 client for Chrome DevTools Protocol."""

    def __init__(self, websocket_url: str):
        parsed = urllib.parse.urlsplit(websocket_url)
        self.socket = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (
            f"GET {parsed.path}?{parsed.query} HTTP/1.1\r\n" if parsed.query else f"GET {parsed.path} HTTP/1.1\r\n"
        ) + (
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode())
        head = bytearray()
        while b"\r\n\r\n" not in head:
            head.extend(self.socket.recv(4096))
        if not head.startswith(b"HTTP/1.1 101"):
            fail("CHROME_WEBSOCKET_REJECTED")
        self.next_id = 0
        self.events: list[dict[str, Any]] = []

    def close(self) -> None:
        try:
            self.call("Page.close", timeout=2)
        except (OSError, SmokeFailure, socket.timeout):
            pass
        finally:
            self.socket.close()

    def _send_frame(self, payload: bytes, opcode: int = 1) -> None:
        mask = secrets.token_bytes(4)
        length = len(payload)
        head = bytearray([0x80 | opcode])
        if length < 126:
            head.append(0x80 | length)
        elif length < 65536:
            head.extend([0x80 | 126]); head.extend(struct.pack("!H", length))
        else:
            head.extend([0x80 | 127]); head.extend(struct.pack("!Q", length))
        head.extend(mask)
        head.extend(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(head)

    def _recv_frame(self) -> bytes:
        first, second = recv_exact(self.socket, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", recv_exact(self.socket, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", recv_exact(self.socket, 8))[0]
        mask = recv_exact(self.socket, 4) if second & 0x80 else None
        payload = recv_exact(self.socket, length)
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == 9:
            self._send_frame(payload, opcode=10)
            return self._recv_frame()
        if opcode == 8:
            fail("CHROME_WEBSOCKET_CLOSED")
        if opcode not in (1, 2):
            return self._recv_frame()
        return payload

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 15.0) -> dict[str, Any]:
        self.next_id += 1
        request_id = self.next_id
        self._send_frame(canonical({"id": request_id, "method": method, "params": params or {}}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.socket.settimeout(max(0.1, deadline - time.monotonic()))
            message = json.loads(self._recv_frame())
            if message.get("id") == request_id:
                if "error" in message:
                    fail("CHROME_CDP_ERROR_" + method.replace(".", "_"))
                return message.get("result", {})
            self.events.append(message)
        fail("CHROME_CDP_TIMEOUT")

    def evaluate(self, expression: str, timeout: float = 20.0) -> Any:
        result = self.call(
            "Runtime.evaluate",
            {"expression": expression, "awaitPromise": True, "returnByValue": True},
            timeout=timeout,
        ).get("result", {})
        if result.get("subtype") == "error":
            fail("BROWSER_JAVASCRIPT_FAILED")
        return result.get("value")

    def first_session_response(self) -> dict[str, Any] | None:
        for event in self.events:
            if event.get("method") != "Network.responseReceived":
                continue
            response = event.get("params", {}).get("response", {})
            if urllib.parse.urlsplit(response.get("url", "")).path != "/api/alpha/session" or response.get("status") != 200:
                continue
            request_id = event.get("params", {}).get("requestId")
            if not request_id:
                continue
            try:
                body = read_response_body(cdp=self, request_id=request_id, timeout=1.0)
                if body is None:
                    continue
                parsed = json.loads(body)
                return {
                    "session_id": parsed.get("session", {}).get("session_id"),
                    "snapshot_seq": parsed.get("last_applied_seq"),
                    "snapshot_digest": parsed.get("digest"),
                }
            except (SmokeFailure, UnicodeDecodeError, json.JSONDecodeError):
                continue
        return None


class Chrome:
    def __init__(self, root: Path, log_path: Path, executable: Path):
        if not executable.is_file():
            fail("CHROME_MISSING")
        self.port = free_port()
        self.log_handle = log_path.open("xb")
        try:
            self.process = subprocess.Popen(
                [
                    str(executable), "--headless=new", "--disable-gpu", "--no-first-run",
                    "--no-default-browser-check", "--disable-background-networking",
                    "--disable-component-update", "--disable-default-apps", "--disable-extensions",
                    "--disable-sync", "--metrics-recording-only", "--no-proxy-server",
                    f"--remote-debugging-port={self.port}", f"--user-data-dir={root / 'chrome-profile'}",
                    "--remote-allow-origins=*", "about:blank",
                ],
                cwd=REPO, env=processes.minimal_env({}), stdin=subprocess.DEVNULL,
                stdout=self.log_handle, stderr=subprocess.STDOUT, start_new_session=True,
            )
        except Exception:
            self.log_handle.close()
            raise
        self.record = {
            "name": "chrome", "pid": self.process.pid, "process_group": self.process.pid,
            "identity": processes.process_identity(self.process.pid), "log": str(log_path),
        }
        wait_json(f"http://127.0.0.1:{self.port}/json/version", 15)

    def page(self, url: str, width: int, height: int, mobile: bool) -> CDP:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/json/new?about:blank", method="PUT"
        )
        with NO_PROXY.open(request, timeout=5) as response:
            target = json.load(response)
        cdp = CDP(target["webSocketDebuggerUrl"])
        for method in ("Page.enable", "Runtime.enable", "Network.enable"):
            cdp.call(method)
        cdp.call("Emulation.setDeviceMetricsOverride", {
            "width": width, "height": height, "deviceScaleFactor": 1, "mobile": mobile,
        })
        cdp.call("Page.navigate", {"url": url})
        wait_eval(cdp, "document.readyState === 'complete'", 15)
        return cdp

    def stop(self) -> None:
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid, 15)
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, 9)
                    self.process.wait(timeout=5)
        finally:
            self.log_handle.close()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def port_available(port: int) -> bool:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def wait_json(url: str, timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with NO_PROXY.open(url, timeout=1) as response:
                return json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.05)
    fail("HTTP_SERVICE_TIMEOUT")


def wait_eval(cdp: CDP, expression: str, timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = cdp.evaluate(expression, timeout=min(5, timeout))
            if value:
                return value
        except SmokeFailure:
            pass
        time.sleep(0.05)
    fail("BROWSER_STATE_TIMEOUT")


def _legacy_command_observer_install_script() -> str:
    key = json.dumps(COMMAND_OBSERVER_KEY)
    return f"""(() => {{
      const __nomadC3ObserverPhase = "install";
      const key = {key};
      const state = window[key] || (window[key] = {{}});
      const observe = async (input, init, invoke) => {{
        let request;
        try {{
          request = input instanceof Request ? input : new Request(input, init);
        }} catch {{
          return await invoke();
        }}
        const token = state.active_token;
        let url;
        try {{
          url = new URL(request.url, window.location.href);
        }} catch {{
          return await invoke();
        }}
        const isTarget = Boolean(
          token &&
          url.origin === window.location.origin &&
          url.pathname === "/api/commands" &&
          request.method.toUpperCase() === "POST"
        );
        const isCapability = Boolean(
          url.origin === window.location.origin &&
          url.pathname === "/api/commands/capability" &&
          request.method.toUpperCase() === "GET"
        );
        if (isCapability) {{
          const response = await invoke();
          state.capability_response_count += 1;
          return response;
        }}
        if (!isTarget) {{
          return await invoke();
        }}
        const headers = {{}};
        for (const [raw, canonical] of [["accept", "Accept"], ["content-type", "Content-Type"], ["x-nomad-csrf", "X-Nomad-CSRF"]]) {{
          const value = request.headers.get(raw);
          if (value !== null) {{
            headers[canonical] = value;
          }}
        }}
        // Start body capture without delaying the original request.  The Host
        // capability is snapshot-bound, so even an observer must not insert an
        // avoidable scheduling point before dispatch.
        const requestBodyPromise = request.clone().text().catch(() => "");
        state.request_count += 1;
        try {{
          const responsePromise = invoke();
          const requestBody = await requestBodyPromise;
          const response = await responsePromise;
          state.response_count += 1;
          let responseBody = "";
          try {{
            responseBody = await response.clone().text();
          }} catch {{}}
          if (state.active_token === token && state.capture === null && state.error === null) {{
            state.capture = {{
              request_body: requestBody,
              headers,
              status: Number(response.status || 0),
              response_body: responseBody,
            }};
          }}
          return response;
        }} catch (error) {{
          if (state.active_token === token && state.capture === null && state.error === null) {{
            state.error = String(error && error.message ? error.message : error);
          }}
          throw error;
        }}
      }};
      if (state.installed === true) {{
        state.capture = null;
        state.error = null;
        state.request_count = 0;
        state.response_count = 0;
        return true;
      }}
      const originalFetch = window.fetch.bind(window);
      state.installed = true;
      state.active_token = null;
      state.capture = null;
      state.error = null;
      state.request_count = 0;
      state.response_count = 0;
      state.capability_response_count = Number(state.capability_response_count || 0);
      window.fetch = async function(input, init) {{
        return await observe(input, init, () => originalFetch(input, init));
      }};
      return true;
    }})()"""


def _command_observer_begin_script(token: str) -> str:
    key = json.dumps(COMMAND_OBSERVER_KEY)
    return f"""(() => {{
      const __nomadC3ObserverPhase = "begin";
      const state = window[{key}];
      if (!state || state.installed !== true) return false;
      state.active_token = {json.dumps(token)};
      state.capture = null;
      state.error = null;
      state.request_count = 0;
      state.response_count = 0;
      return true;
    }})()"""


def _command_observer_peek_script(token: str) -> str:
    key = json.dumps(COMMAND_OBSERVER_KEY)
    return f"""(() => {{
      const __nomadC3ObserverPhase = "peek";
      const state = window[{key}];
      if (!state || state.installed !== true) {{
        return {{active:false,capture:null,error:null,request_count:0,response_count:0}};
      }}
      if (state.active_token !== {json.dumps(token)}) {{
        return {{active:false,capture:null,error:null,request_count:0,response_count:0}};
      }}
      return {{
        active:true,
        capture:state.capture,
        error:state.error,
        request_count:Number(state.request_count || 0),
        response_count:Number(state.response_count || 0),
      }};
    }})()"""


def _command_observer_take_script(token: str) -> str:
    key = json.dumps(COMMAND_OBSERVER_KEY)
    return f"""(() => {{
      const __nomadC3ObserverPhase = "take";
      const state = window[{key}];
      if (!state || state.installed !== true || state.active_token !== {json.dumps(token)}) {{
        return {{active:false,capture:null,error:null,request_count:0,response_count:0}};
      }}
      const snapshot = {{
        active:true,
        capture:state.capture,
        error:state.error,
        request_count:Number(state.request_count || 0),
        response_count:Number(state.response_count || 0),
      }};
      state.active_token = null;
      state.capture = null;
      state.error = null;
      state.request_count = 0;
      state.response_count = 0;
      return snapshot;
    }})()"""


def install_command_observer(cdp: CDP) -> None:
    if cdp.evaluate(_command_observer_install_script(), timeout=5) is not True:
        fail("VISIBLE_COMMAND_OBSERVER_INSTALL_FAILED")


def begin_command_observer(cdp: CDP, token: str) -> None:
    if cdp.evaluate(_command_observer_begin_script(token), timeout=5) is not True:
        fail("VISIBLE_COMMAND_OBSERVER_BEGIN_FAILED")


def peek_command_observer(cdp: CDP, token: str) -> dict[str, Any]:
    observed = cdp.evaluate(_command_observer_peek_script(token), timeout=5)
    return observed if isinstance(observed, dict) else {}


def take_command_observer(cdp: CDP, token: str) -> dict[str, Any]:
    observed = cdp.evaluate(_command_observer_take_script(token), timeout=5)
    return observed if isinstance(observed, dict) else {}


def refresh_visible_capability(cdp: CDP) -> None:
    key = json.dumps(COMMAND_OBSERVER_KEY)
    before = cdp.evaluate(
        f"Number((window[{key}] && window[{key}].capability_response_count) || 0)"
    )
    if not isinstance(before, int):
        fail("VISIBLE_CAPABILITY_OBSERVER_INVALID")
    clicked = cdp.evaluate("""(() => {
      const button=Array.from(document.querySelectorAll('button')).find(
        candidate => candidate.querySelector('span')?.textContent?.trim()==='Refresh' && !candidate.disabled
      );
      if (!button) return false;
      button.click();
      return true;
    })()""")
    if clicked is not True:
        fail("VISIBLE_REFRESH_CONTROL_MISSING")
    wait_eval(
        cdp,
        f"Number((window[{key}] && window[{key}].capability_response_count) || 0) > {before}",
        40,
    )


def decode_response_body(raw: dict[str, Any]) -> str:
    body = raw.get("body", "")
    if raw.get("base64Encoded"):
        body = base64.b64decode(body).decode()
    return body


def read_response_body(cdp: CDP, request_id: str, timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        loading_finished = False
        loading_failed = False
        for event in cdp.events:
            params = event.get("params", {})
            if params.get("requestId") != request_id:
                continue
            if event.get("method") == "Network.loadingFinished":
                loading_finished = True
            elif event.get("method") == "Network.loadingFailed":
                loading_failed = True
        if loading_failed:
            return None
        if loading_finished:
            try:
                raw = cdp.call(
                    "Network.getResponseBody",
                    {"requestId": request_id},
                    timeout=max(0.1, min(2.0, deadline - time.monotonic())),
                )
            except SmokeFailure as error:
                if str(error) != "CHROME_CDP_ERROR_Network_getResponseBody":
                    raise
            else:
                return decode_response_body(raw)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            cdp.evaluate("true", timeout=max(0.1, min(1.0, remaining)))
        except SmokeFailure:
            pass
        time.sleep(0.05)
    return None


def wait_session_response(cdp: CDP, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = cdp.first_session_response()
        if observed is not None:
            return observed
        # A harmless expression drains pending CDP Network events without
        # starting another Gateway long poll.
        cdp.evaluate("true", timeout=2)
        time.sleep(0.05)
    fail("BROWSER_SESSION_RESPONSE_MISSING")


def screenshot_digest(cdp: CDP) -> str:
    encoded = cdp.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})["data"]
    return hashlib.sha256(base64.b64decode(encoded)).hexdigest()


def browser_private_surface(cdp: CDP) -> bytes:
    visible = cdp.evaluate("""(() => ({
      text:document.body.innerText, html:document.documentElement.outerHTML, url:location.href,
      local:Object.entries(localStorage), session:Object.entries(sessionStorage), cookie:document.cookie,
      resources:performance.getEntriesByType('resource').map(x=>x.name)
    }))()""")
    return canonical(visible) + canonical(cdp.events)


def browser_command(cdp: CDP, action: str, content: str | None = None) -> dict[str, Any]:
    content_value = json.dumps(content) if content is not None else "null"
    action_value = json.dumps(action)
    script = f"""
      (async () => {{
        const action = {action_value};
        const content = {content_value};
        const capResponse = await fetch('/api/commands/capability', {{headers: {{accept:'application/json'}}}});
        const wrapper = await capResponse.json();
        if (!capResponse.ok) return {{stage:'capability', status:capResponse.status, wrapper}};
        const cap = wrapper.capability;
        const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
        const opaque = (prefix) => prefix + '_' + Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
        const common = {{
          schema:'nomad.gateway.command.v1', capability_id:cap.capability_id, request_id:opaque('req'),
          nonce:opaque('nonce'), command_seq:cap.next_command_seq, expected_snapshot_seq:cap.snapshot_seq,
          expected_snapshot_digest:cap.snapshot_digest, issued_at:new Date().toISOString(), expires_at:cap.expires_at, action
        }};
        const bodyObject = action === 'reply'
          ? {{...common, turn_alias:cap.reply?.turn_alias, input_alias:cap.reply?.input_alias, content}}
          : action === 'deny'
            ? {{...common, permission_alias:cap.deny?.permission_alias, action_hash:cap.deny?.action_hash, permission_expires_at:cap.deny?.expires_at}}
            : {{...common, turn_alias:cap.stop?.turn_alias}};
        const body = JSON.stringify(bodyObject);
        const send = async () => {{
          const response = await fetch('/api/commands', {{method:'POST', headers:{{accept:'application/json','content-type':'application/json','X-Nomad-CSRF':wrapper.csrf_token}}, body}});
          let payload; try {{ payload = await response.json(); }} catch {{ payload = null; }}
          return {{status:response.status, payload}};
        }};
        const first = await send();
        const replay = await Promise.all([send(), send()]);
        return {{stage:'complete', action, body, capability:cap, first, replay}};
      }})()
    """
    result = cdp.evaluate(script, timeout=COMMAND_TIMEOUT)
    if not isinstance(result, dict) or result.get("stage") != "complete":
        fail(f"BROWSER_{action.upper()}_FAILED")
    return result


def try_visible_reply(cdp: CDP, content: str) -> dict[str, Any] | None:
    try:
        wait_eval(cdp, """(() => {
          const input=document.querySelector('[aria-label=\"Reply to agent\"]');
          const button=document.querySelector('[aria-label=\"Send reply\"]');
          return Boolean(input && button && !input.disabled);
        })()""", 5)
    except SmokeFailure:
        return None
    if cdp.evaluate("""(() => {
      const input=document.querySelector('[aria-label=\"Reply to agent\"]');
      if (!input || input.disabled) return false; input.focus(); return document.activeElement===input;
    })()""") is not True:
        return None
    cdp.call("Input.insertText", {"text": content})
    wait_eval(cdp, "!document.querySelector('[aria-label=\"Send reply\"]').disabled", 5)
    click_script = """(async () => {
      const button=document.querySelector('[aria-label=\"Send reply\"]');
      if (!button || button.disabled) return 'send';
      button.click(); return true;
    })()"""
    return capture_visible_command(cdp, "reply", click_script)


def capture_visible_command(cdp: CDP, action: str, click_script: str) -> dict[str, Any]:
    prior = {
        event.get("params", {}).get("requestId")
        for event in cdp.events
        if event.get("method") == "Network.requestWillBeSent"
    }
    click_result = cdp.evaluate(click_script)
    if click_result is not True:
        fail(f"VISIBLE_{action.upper()}_CONTROL_MISSING_{click_result}")
    deadline = time.monotonic() + COMMAND_TIMEOUT
    captured = None
    browser_request_count = 0
    browser_response_count = 0
    requests: dict[str, dict[str, Any]] = {}
    responses: dict[str, dict[str, Any]] = {}
    while time.monotonic() < deadline and captured is None:
        cdp.evaluate("true", timeout=2)
        requests = {}
        responses = {}
        finished: set[str] = set()
        for event in cdp.events:
            params = event.get("params", {})
            request_id = params.get("requestId")
            if not request_id or request_id in prior:
                continue
            if event.get("method") == "Network.requestWillBeSent":
                request = params.get("request", {})
                if request.get("method") == "POST" and urllib.parse.urlsplit(request.get("url", "")).path == "/api/commands":
                    requests[request_id] = request
            elif event.get("method") == "Network.responseReceived":
                responses[request_id] = params.get("response", {})
            elif event.get("method") == "Network.loadingFinished":
                finished.add(request_id)
        browser_request_count = len(requests)
        browser_response_count = sum(1 for request_id in requests if request_id in responses)
        if browser_request_count > 1 or browser_response_count > 1:
            fail(f"VISIBLE_{action.upper()}_BROWSER_POST_COUNT_INVALID")
        if browser_request_count == 1:
            request_id, request = next(iter(requests.items()))
            response = responses.get(request_id)
            if response is not None and request_id in finished:
                body = read_response_body(cdp, request_id, 2.0)
                if body is not None:
                    captured = {
                        "body": request.get("postData", ""),
                        "headers": request.get("headers", {}),
                        "status": int(response.get("status", 0)),
                        "payload": json.loads(body),
                    }
                    break
        time.sleep(0.05)
    if captured is None:
        paths = [
            urllib.parse.urlsplit(event.get("params", {}).get("request", {}).get("url", "")).path
            for event in cdp.events
            if event.get("method") == "Network.requestWillBeSent"
            and event.get("params", {}).get("requestId") not in prior
        ]
        text = cdp.evaluate("document.body.innerText")
        reason = "unclassified"
        for marker, code in (("expired", "expired"), ("result unknown", "unknown"), ("not valid", "invalid"), ("not accepted", "rejected"), ("not sent", "not_sent"), ("commands are disabled", "disabled"), ("reply is not enabled", "reply_disabled"), ("sending your denial", "sending"), ("host accepted", "host_accepted"), ("endpoint acknowledged", "acknowledged")):
            if marker in text.lower():
                reason = code
                break
        fail(f"VISIBLE_{action.upper()}_POST_NOT_OBSERVED_{reason}_{len(paths)}")
    # Drain a bounded quiet window before issuing the explicit replay probes.
    # This catches a delayed duplicate emitted by the original UI action; Host
    # idempotency must not be allowed to hide duplicate browser submissions.
    quiet_deadline = time.monotonic() + 0.5
    while time.monotonic() < quiet_deadline:
        cdp.evaluate("true", timeout=1)
        time.sleep(0.05)
    final_requests = {
        event.get("params", {}).get("requestId")
        for event in cdp.events
        if event.get("method") == "Network.requestWillBeSent"
        and event.get("params", {}).get("requestId") not in prior
        and event.get("params", {}).get("request", {}).get("method") == "POST"
        and urllib.parse.urlsplit(event.get("params", {}).get("request", {}).get("url", "")).path == "/api/commands"
    }
    final_responses = {
        event.get("params", {}).get("requestId")
        for event in cdp.events
        if event.get("method") == "Network.responseReceived"
        and event.get("params", {}).get("requestId") in final_requests
    }
    browser_request_count = len(final_requests)
    browser_response_count = len(final_responses)
    if browser_request_count != 1 or browser_response_count != 1:
        fail(f"VISIBLE_{action.upper()}_BROWSER_POST_COUNT_INVALID")
    browser_headers = {
        key: value
        for key, value in captured["headers"].items()
        if key.lower() in ("accept", "content-type", "x-nomad-csrf")
    }
    replay_script = f"""(async()=>{{
      const captured={json.dumps(captured)}; const headers={json.dumps(browser_headers)}; const send=async()=>{{const r=await fetch('/api/commands',{{method:'POST',headers,body:captured.body}});return {{status:r.status,payload:await r.json()}};}};
      return {{stage:'complete',action:{json.dumps(action)},body:captured.body,capability:null,first:{{status:captured.status,payload:captured.payload}},replay:await Promise.all([send(),send()])}};
    }})()"""
    result = cdp.evaluate(replay_script, timeout=COMMAND_TIMEOUT)
    if not isinstance(result, dict) or result.get("stage") != "complete":
        fail(f"VISIBLE_{action.upper()}_FAILED")
    result["browser_request_count"] = browser_request_count
    result["browser_response_count"] = browser_response_count
    return result


def visible_deny(cdp: CDP) -> dict[str, Any]:
    return capture_visible_command(cdp, "deny", """(async () => {
      const review=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Review request'&&!b.disabled);
      if (!review) return 'review'; review.click();
      let deny=null;
      for (let attempt=0; attempt<50 && !deny; attempt+=1) {
        await new Promise(resolve => setTimeout(resolve, 100));
        deny=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Deny request'&&!b.disabled);
      }
      if (!deny) {
        const any=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Deny request');
        const text=document.body.innerText;
        if (!any) return 'deny_absent';
        if (text.includes('displayed snapshot changed')) return 'deny_display_binding';
        if (text.includes('capability expired')) return 'deny_expired';
        if (text.includes('No live command capability')) return 'deny_no_capability';
        if (text.includes('Refreshing')) return 'deny_refreshing';
        return 'deny_disabled';
      }
      deny.click(); return true;
    })()""")


def visible_stop(cdp: CDP) -> dict[str, Any]:
    return capture_visible_command(cdp, "stop", """(async () => {
      let open=null;
      for (let attempt=0; attempt<50 && !open; attempt+=1) {
        await new Promise(resolve => setTimeout(resolve, 100));
        open=Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim()==='Stop task'&&!b.disabled);
      }
      if (!open) return 'open'; open.click();
      let confirm=null;
      for (let attempt=0; attempt<50 && !confirm; attempt+=1) {
        await new Promise(resolve => setTimeout(resolve, 100));
        const dialog=document.querySelector('[role=dialog]');
        confirm=dialog&&Array.from(dialog.querySelectorAll('button')).find(b=>b.textContent.trim()==='Stop task'&&!b.disabled);
      }
      if (!confirm) return 'confirm'; confirm.click(); return true;
    })()""")


def assert_receipts(result: dict[str, Any], expected: str) -> None:
    first = result["first"]
    if first.get("status") != 200 or first.get("payload", {}).get("status") != expected:
        fail(f"COMMAND_{result['action'].upper()}_{expected.upper()}_MISSING")
    receipt = first["payload"].get("receipt_id")
    for replay in result["replay"]:
        payload = replay.get("payload") or {}
        if replay.get("status") != 200 or payload.get("receipt_id") != receipt or payload.get("status") != expected or payload.get("idempotent_replay") is not True:
            fail(f"COMMAND_{result['action'].upper()}_REPLAY_FAILED")


def expected_journal(run_id: str, run_dir: Path) -> Path:
    alias = hashlib.sha256(f"state:{run_id}".encode()).hexdigest()
    name = hashlib.sha256(f"journal:{alias}".encode()).hexdigest()[:24]
    return run_dir / f"command-{name}.sqlite3"


def workspace_digest(path: Path) -> str:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    return hashlib.sha256(f"{resolved}:{info.st_dev}:{info.st_ino}".encode()).hexdigest()


def scan_paths(paths: list[Path], needles: list[bytes]) -> None:
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        raw = path.read_bytes()
        if any(needle and needle in raw for needle in needles):
            fail("PRIVATE_CANARY_PERSISTED_" + path.name.upper().replace(".", "_"))


def private_modes(paths: list[Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in paths:
        if path.exists():
            mode = stat.S_IMODE(path.lstat().st_mode)
            result[path.name] = f"{mode:04o}"
            if mode != 0o600:
                fail("PRIVATE_FILE_MODE_INVALID")
    return result


def lsof(pid: int) -> str:
    result = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-p", str(pid)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=False,
    )
    return result.stdout


def assert_process_gone(pid: int) -> None:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    status = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "stat="],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, timeout=2, check=False,
    ).stdout.strip()
    if status.startswith("Z"):
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        return
    fail(f"PROCESS_SURVIVED_CLEANUP_{pid}_{status}")


def remove_file(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def run_smoke(timeout: float, chrome_path: Path, keep_bundle: Path | None) -> dict[str, Any]:
    started = time.monotonic()
    processes_owned: list[dict[str, Any]] = []
    fake: FakeController | None = None
    chrome: Chrome | None = None
    pages: list[CDP] = []
    socket_path: Path | None = None
    socket_identity: dict[str, int] | None = None
    journal: Path | None = None
    device_registry: Path | None = None
    gateway_db: Path | None = None
    cleanup_pids: list[int] = []
    browser_surfaces: list[bytes] = []

    with tempfile.TemporaryDirectory(prefix="nomad-c3-e2-") as temporary:
        # macOS exposes /var through /private/var.  Product Host deliberately
        # requires a canonical journal parent, so never put the bootstrap path
        # through the lexical alias returned by tempfile.
        root = Path(temporary).resolve(strict=True)
        os.chmod(root, 0o700)
        bundle = keep_bundle or root / "bundle"
        if keep_bundle is None:
            materialize(REPO, bundle)
        host_binary = bundle / "bin" / "nomad-product-host"
        gateway_script = bundle / "gateway" / "server.mjs"
        web = bundle / "web"
        if not host_binary.is_file() or not gateway_script.is_file() or not (web / "index.html").is_file():
            fail("MATERIALIZED_COMPONENT_MISSING")

        runtime = root / "run"
        logs = root / "logs"
        workspace = root / "workspace"
        for directory in (runtime, logs, workspace):
            directory.mkdir(mode=0o700)
        run_id = secrets.token_hex(32)
        session = "ses_c3_" + secrets.token_hex(12)
        question = "que_c3_" + secrets.token_hex(12)
        unknown_question = "que_unknown_" + secrets.token_hex(10)
        permission = "per_c3_" + secrets.token_hex(12)
        message = "msg_c3_" + secrets.token_hex(12)
        call = "call_c3_" + secrets.token_hex(12)
        password = "password-c3-" + secrets.token_urlsafe(24)
        reply_content = "reply-content-c3-" + secrets.token_hex(16)
        unknown_content = "unknown-content-c3-" + secrets.token_hex(16)
        transport_key = _random_command_key()
        authority_key = _random_command_key()
        if transport_key == authority_key:
            fail("COMMAND_KEYS_NOT_INDEPENDENT")
        fake_port, gateway_port = free_port(), free_port()
        if fake_port == gateway_port:
            fail("PORT_COLLISION")

        socket_root = Path("/private/tmp") / ("nomad-c3-" + secrets.token_hex(6))
        socket_root.mkdir(mode=0o700)
        os.chmod(socket_root, 0o700)
        socket_path = socket_root / "product-host.sock"
        journal = expected_journal(run_id, runtime)
        device_registry_root = root / "device-state"
        device_registry_root.mkdir(mode=0o700)
        device_registry = device_registry_root / "host-device-registry.sqlite3"
        gateway_db = runtime / "gateway.sqlite3"

        sensitive_text = [
            session, question, unknown_question, permission, message, call, password,
            transport_key, authority_key, str(workspace), "upstream-content-canary-c3",
            "Please provide deployment region?", "private-question-header-c3",
            "private-option-c3", "private-description-c3",
            "bash-private-content-c3", "private-command-pattern-c3", "metadata-content-c3",
        ]
        sensitive = [value.encode() for value in sensitive_text]
        sensitive.extend([base64.b64decode(transport_key), base64.b64decode(authority_key)])

        try:
            fake = FakeController(
                Path(__file__).resolve(), fake_port,
                {
                    "session": session, "question": question, "unknown_question": unknown_question,
                    "permission": permission, "message": message, "call": call,
                    "workspace": str(workspace.resolve()), "password": password,
                },
                logs / "fake.log",
            )
            cleanup_pids.append(fake.process.pid)

            bootstrap_parent, bootstrap_child = socket.socketpair()
            host = _spawn_product_host(host_binary, bundle, logs / "product-host.log", bootstrap_child)
            processes_owned.append(host); cleanup_pids.append(int(host["pid"]))
            bootstrap_child.close()
            try:
                socket_identity = _bootstrap_host(
                    bootstrap_parent, run_id=run_id, origin=f"http://127.0.0.1:{fake_port}",
                    session_id=session, password=password, workspace_digest=workspace_digest(workspace),
                    product_host_socket_path=socket_path, agent_pid=fake.process.pid,
                    agent_process_group=fake.process.pid, agent_process_identity=fake.record["identity"],
                    command_transport_key=transport_key, command_authority_key=authority_key,
                    command_journal_path=journal, device_registry_path=device_registry,
                )
            except RuntimeError as error:
                observed = fake.inspect() if fake.process.poll() is None else {}
                fail(f"HOST_BOOTSTRAP_FAILED_RC_{processes.ownership(host)}_GETS_{observed.get('get_attempts', 0)}_AUTH_{observed.get('authorization_failures', 0)}_{error}")
            bootstrap_parent.close()
            password = ""

            key_read, key_write = os.pipe()
            for descriptor in (key_read, key_write):
                os.set_inheritable(descriptor, False)
            _write_fd_secret(key_write, transport_key)
            key_write = -1
            node = shutil.which("node")
            if not node:
                fail("NODE_MISSING")
            gateway = processes.spawn(
                "gateway",
                [
                    node, str(gateway_script), "--mode", "official-agent-local",
                    "--host", "127.0.0.1", "--port", str(gateway_port),
                    "--state-db", str(gateway_db), "--dist-dir", str(web),
                    "--product-host-socket", str(socket_path),
                    "--product-host-socket-parent-dev", str(socket_identity["parent_dev"]),
                    "--product-host-socket-parent-ino", str(socket_identity["parent_ino"]),
                    "--product-host-socket-dev", str(socket_identity["socket_dev"]),
                    "--product-host-socket-ino", str(socket_identity["socket_ino"]),
                    "--command-key-fd", "11",
                ],
                bundle / "gateway", processes.minimal_env({}), logs / "gateway.log",
                extra_fd_actions=((key_read, 11),), close_fds=(key_read,),
            )
            os.close(key_read)
            processes_owned.append(gateway); cleanup_pids.append(int(gateway["pid"]))
            base = f"http://127.0.0.1:{gateway_port}"
            wait_json(base + "/api/alpha/session", timeout)

            chrome = Chrome(root, logs / "chrome.log", chrome_path)
            cleanup_pids.append(chrome.process.pid)

            desktop = chrome.page(base + "/", 1440, 900, False)
            pages.append(desktop)
            wait_eval(desktop, "document.body.innerText.includes('Provide a short reply for: deployment region.')", timeout)
            if not desktop.evaluate("document.body.innerText.includes('Provide a short reply for: deployment region.')"):
                text = desktop.evaluate("document.body.innerText")
                shape = desktop.evaluate("fetch('/api/commands/capability').then(async r=>{const x=await r.json();return {status:r.status,reply:Boolean(x.capability&&x.capability.reply),summary:Boolean(x.capability&&x.capability.reply&&x.capability.reply.summary),schema:x.capability&&x.capability.reply&&x.capability.reply.summary&&x.capability.reply.summary.schema==='nomad.product-host.pending-question-summary.v1'}})")
                reason = "summary_absent"
                for marker, code in (("capability is unavailable", "capability_unavailable"), ("capability expired", "expired"), ("displayed snapshot changed", "display_binding"), ("no live command capability", "no_capability"), ("checking command capability", "checking"), ("refreshing command capability", "refreshing"), ("reviewable question context is not yet available", "summary_absent")):
                    if marker in text.lower():
                        reason = code
                        break
                fail("VISIBLE_REPLY_" + reason.upper() + f"_CAP_{shape.get('status')}_{int(bool(shape.get('reply')))}_{int(bool(shape.get('summary')))}_{int(bool(shape.get('schema')))}")
            desktop_projection = wait_session_response(desktop, timeout)
            desktop_shot = screenshot_digest(desktop)

            mobile_baseline = chrome.page(base + "/", 390, 844, True)
            pages.append(mobile_baseline)
            wait_eval(mobile_baseline, "document.body.innerText.includes('Provide a short reply for: deployment region.')", timeout)
            mobile_projection = wait_session_response(mobile_baseline, timeout)
            if desktop_projection != mobile_projection:
                fail("DESKTOP_MOBILE_PROJECTION_MISMATCH")
            mobile_shot = screenshot_digest(mobile_baseline)
            browser_surfaces.append(browser_private_surface(mobile_baseline))
            mobile_baseline.close(); pages.remove(mobile_baseline)
            browser_surfaces.append(browser_private_surface(desktop))
            desktop.close(); pages.remove(desktop)

            # The capability is intentionally short-lived.  The desktop/mobile
            # comparison above can outlive it, so acquire a fresh browser page
            # and exercise the visible control immediately; never extend the
            # product TTL or retry the original action.
            reply_page = chrome.page(base + "/", 1440, 900, False)
            pages.append(reply_page)
            wait_eval(reply_page, "document.body.innerText.includes('Provide a short reply for: deployment region.')", timeout)
            reply_result = try_visible_reply(reply_page, reply_content)
            if reply_result is None:
                fail("VISIBLE_REPLY_CONTROL_MISSING")
            reply_mode = "visible_control"
            assert_receipts(reply_result, "DispatchAcknowledged")
            browser_surfaces.append(browser_private_surface(reply_page))
            reply_page.close(); pages.remove(reply_page)

            fake.phase("deny")
            mobile = chrome.page(base + "/", 390, 844, True)
            pages.append(mobile)
            wait_eval(mobile, "document.body.innerText.includes('The agent is waiting before a change')", timeout)
            deny_result = visible_deny(mobile)
            assert_receipts(deny_result, "DispatchAcknowledged")
            browser_surfaces.append(browser_private_surface(mobile))
            mobile.close(); pages.remove(mobile)

            fake.phase("running")
            stop_page = chrome.page(base + "/", 390, 844, True)
            pages.append(stop_page)
            wait_eval(stop_page, "document.body.innerText.includes('No action needed')", timeout)
            stop_result = visible_stop(stop_page)
            assert_receipts(stop_result, "DispatchAcknowledged")
            browser_surfaces.append(browser_private_surface(stop_page))
            stop_page.close(); pages.remove(stop_page)

            fake.phase("unknown")
            unknown_page = chrome.page(base + "/", 1440, 900, False)
            pages.append(unknown_page)
            wait_eval(unknown_page, "document.body.innerText.includes('Provide a short reply for: deployment region.')", timeout)
            fake.drop("unknown")
            unknown_result = browser_command(unknown_page, "reply", unknown_content)
            assert_receipts(unknown_result, "OutcomeUnknown")
            wait_eval(unknown_page, "true", 0.1)

            browser_surfaces.append(browser_private_surface(unknown_page))
            browser_raw = b"".join(browser_surfaces)
            if any(value.encode() in browser_raw for value in sensitive_text):
                fail("PRIVATE_CANARY_REACHED_BROWSER")
            unknown_page.close(); pages.remove(unknown_page)

            inspection = fake.inspect()
            ledger = inspection["ledger"]
            actions = Counter(entry.get("action") for entry in ledger)
            if actions != Counter({"reply": 1, "deny": 1, "stop": 1, "unknown": 1}):
                fail("UPSTREAM_SIDE_EFFECT_COUNT_INVALID")
            expected_bodies = {
                "reply": canonical({"answers": [[reply_content]]}),
                "deny": b'{"reply":"reject"}',
                "stop": b"",
                "unknown": canonical({"answers": [[unknown_content]]}),
            }
            for entry in ledger:
                body = base64.b64decode(entry["body_b64"])
                if entry.get("authorization_ok") is not True or entry.get("action") not in expected_bodies or body != expected_bodies[entry["action"]]:
                    fail("UPSTREAM_ROUTE_OR_BODY_INVALID")
            five_routes = [f"/session/{session}", "/session/status", "/question", "/permission", f"/session/{session}/diff"]
            if any(inspection["reads"].get(route, 0) < 2 for route in five_routes):
                fail("FIVE_ROUTE_FRESHNESS_NOT_PROVED")

            sqlite_paths = [journal, Path(str(journal) + "-wal"), Path(str(journal) + "-shm"), gateway_db, Path(str(gateway_db) + "-wal"), Path(str(gateway_db) + "-shm")]
            modes = private_modes(sqlite_paths)
            scan_paths(sqlite_paths + list(logs.glob("*.log")), sensitive + [reply_content.encode(), unknown_content.encode()])
            command_rows = subprocess.run(
                [
                    sys.executable, "-c",
                    "import sqlite3,sys,json;c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);print(json.dumps({'journal_mode':c.execute('pragma journal_mode').fetchone()[0],'synchronous':c.execute('pragma synchronous').fetchone()[0],'rows':c.execute('select command_type,status from commands order by seq').fetchall()}))",
                    str(journal),
                ],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10, check=True,
            )
            journal_proof = json.loads(command_rows.stdout)
            if journal_proof["journal_mode"].lower() != "wal" or journal_proof["synchronous"] != 2:
                fail("JOURNAL_DURABILITY_INVALID")
            if Counter(map(tuple, journal_proof["rows"])) != Counter({("reply", "DispatchAcknowledged"): 1, ("deny", "DispatchAcknowledged"): 1, ("stop", "DispatchAcknowledged"): 1, ("reply", "OutcomeUnknown"): 1}):
                fail("JOURNAL_RECEIPTS_INVALID")

            gateway_lsof = lsof(int(gateway["pid"]))
            host_lsof = lsof(int(host["pid"]))
            browser_lsof = lsof(chrome.process.pid)
            if str(journal) in gateway_lsof or str(journal) in browser_lsof or str(socket_path) in browser_lsof:
                fail("FD_CONTAINMENT_INVALID")
            if str(journal) not in host_lsof:
                fail("HOST_JOURNAL_OWNERSHIP_MISSING")
            upstream_endpoint = f"127.0.0.1:{fake_port}"
            if upstream_endpoint in gateway_lsof or upstream_endpoint in browser_lsof:
                fail("UPSTREAM_CONNECTION_CONTAINMENT_INVALID")
            argv_surface = b"".join(
                subprocess.run(["/bin/ps", "-p", str(pid), "-o", "command="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout
                for pid in cleanup_pids
            )
            if any(needle in argv_surface for needle in sensitive):
                fail("SECRET_OR_RAW_ID_IN_ARGV")

            result = {
                "marker": MARKER, "mechanical_e2": True, "provider_e3": False,
                "production_ready": False, "run_binding": hashlib.sha256(run_id.encode()).hexdigest(),
                "materialized_product_host": True, "materialized_gateway": True,
                "materialized_web": True, "fake_boundary": "external_loopback_opencode_shape",
                "browser": {"engine": "Google Chrome headless via CDP", "desktop": "1440x900", "mobile": "390x844", "same_projection": True, "desktop_screenshot_sha256": desktop_shot, "mobile_screenshot_sha256": mobile_shot},
                "actions": {
                    "reply": {"browser_path": reply_mode, "browser_requests": reply_result["browser_request_count"], "browser_responses": reply_result["browser_response_count"], "posts": actions["reply"], "replay_side_effects": 0},
                    "deny": {"browser_path": "visible_control", "browser_requests": deny_result["browser_request_count"], "browser_responses": deny_result["browser_response_count"], "posts": actions["deny"], "replay_side_effects": 0},
                    "stop": {"browser_path": "visible_control", "browser_requests": stop_result["browser_request_count"], "browser_responses": stop_result["browser_response_count"], "posts": actions["stop"], "replay_side_effects": 0},
                    "uncertainty": {"status": "OutcomeUnknown", "posts": actions["unknown"], "automatic_retries": 0},
                },
                "fresh_five_route_reads": {"minimum_per_route": min(inspection["reads"].get(route, 0) for route in five_routes)},
                "privacy": {"browser": True, "logs": True, "persistent_sqlite": True, "argv": True},
                "containment": {"fd_10_bootstrap": True, "fd_11_transport_key": True, "independent_keys": True, "browser_has_no_uds": True, "gateway_browser_have_no_upstream_connection": True, "uds_mode": "0600", "uds_parent_mode": "0700", "sqlite_modes": modes},
                "journal": {"mode": "wal", "synchronous": "FULL", "rows": len(journal_proof["rows"])},
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        finally:
            for page in pages:
                try:
                    page.close()
                except Exception:
                    pass
            if chrome is not None:
                chrome.stop()
            for owned in reversed(processes_owned):
                processes.stop(owned)
            if fake is not None:
                fake.stop()
            if socket_path is not None:
                try:
                    _cleanup_product_host_socket(socket_path, socket_identity)
                except RuntimeError:
                    remove_file(socket_path)
                    try:
                        socket_path.parent.rmdir()
                    except OSError:
                        pass
            for database in (journal, gateway_db, device_registry):
                if database is not None:
                    for candidate in (database, Path(str(database) + "-wal"), Path(str(database) + "-shm")):
                        remove_file(candidate)
            if device_registry is not None:
                try:
                    device_registry.parent.rmdir()
                except OSError:
                    pass
            for pid in cleanup_pids:
                assert_process_gone(pid)
            released_ports = [port for port in (fake_port, gateway_port, chrome.port if chrome is not None else 0) if port]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if all(port_available(port) for port in released_ports):
                    break
                time.sleep(0.05)
            else:
                fail("PORT_CLEANUP_FAILED")
            if socket_path is not None and (socket_path.exists() or socket_path.parent.exists()):
                fail("UDS_CLEANUP_FAILED")
            if journal is not None and any(path.exists() for path in (journal, Path(str(journal) + "-wal"), Path(str(journal) + "-shm"))):
                fail("JOURNAL_CLEANUP_FAILED")
            if device_registry is not None and (device_registry.exists() or device_registry.parent.exists()):
                fail("DEVICE_REGISTRY_CLEANUP_FAILED")

        result["cleanup"] = {"processes": True, "ports": True, "uds": True, "journal": True, "gateway_db": True, "device_registry": True}
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--chrome", type=Path, default=CHROME)
    parser.add_argument("--bundle", type=Path, help="Reuse an already materialized verified bundle")
    parser.add_argument("--fake", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--control-fd", type=int, help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.fake:
        if args.port is None or args.control_fd is None:
            return 70
        return fake_main(args.port, args.control_fd)
    try:
        result = run_smoke(args.timeout, args.chrome, args.bundle)
    except Exception as error:
        text = str(error)
        code = text if isinstance(error, SmokeFailure) or text.replace("_", "").isalnum() and text.upper() == text else error.__class__.__name__
        print(json.dumps({"marker": "C3_LOCAL_COMMAND_MECHANICAL_E2_FAIL", "mechanical_e2": False, "provider_e3": False, "production_ready": False, "error": code}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
