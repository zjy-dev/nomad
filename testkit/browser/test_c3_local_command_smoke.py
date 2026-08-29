#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "c3_local_command_smoke.py"
SPEC = importlib.util.spec_from_file_location("nomad_c3_local_command_smoke", MODULE_PATH)
smoke = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)


def command_request(action: str = "reply", request_id: str = "request-00000001") -> dict:
    value = {
        "schema": "nomad.gateway.command.v1",
        "capability_id": "capability-00000001",
        "request_id": request_id,
        "nonce": "nonce-000000000001",
        "command_seq": 1,
        "expected_snapshot_seq": 7,
        "expected_snapshot_digest": "sha256:" + "a" * 64,
        "issued_at": "2026-08-30T00:00:00Z",
        "expires_at": "2026-08-30T00:00:30Z",
        "action": action,
    }
    if action == "reply":
        value.update(turn_alias="turn-" + "1" * 32, input_alias="input-" + "2" * 32, content="reply")
    elif action == "deny":
        value.update(permission_alias="permission-" + "3" * 32, action_hash="sha256:" + "b" * 64, permission_expires_at="2026-08-30T00:00:30Z")
    else:
        value.update(turn_alias="turn-" + "1" * 32)
    return value


def command_receipt(action: str = "reply", request_id: str = "request-00000001") -> dict:
    return {
        "schema": "nomad.gateway.command-receipt.v1",
        "receipt_id": "receipt-00000001",
        "request_id": request_id,
        "action": action,
        "snapshot_seq": 7,
        "snapshot_digest": "sha256:" + "a" * 64,
        "accepted_at": "2026-08-30T00:00:01Z",
        "status": "DispatchAcknowledged",
        "error_code": "OK",
        "idempotent_replay": False,
    }


class FakeCDP:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.get_response_body_calls = 0
        self.loading_finished_seen_at_get = False
        self.drain_calls = 0
        self.response_body = '{"status":"DispatchAcknowledged","receipt_id":"rcpt-1"}'
        self.observer_token: str | None = None
        self.observer: dict = {
            "active": True, "capture": None, "error": None,
            "request_count": 0, "response_count": 0,
        }
        self.evaluate_log: list[str] = []

    def call(self, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
        if method != "Network.getResponseBody":
            raise AssertionError(f"unexpected method {method}")
        self.get_response_body_calls += 1
        request_id = (params or {}).get("requestId")
        finished = any(
            event.get("method") == "Network.loadingFinished"
            and event.get("params", {}).get("requestId") == request_id
            for event in self.events
        )
        self.loading_finished_seen_at_get = finished
        if not finished:
            raise AssertionError("getResponseBody called before Network.loadingFinished")
        if self.get_response_body_calls == 1:
            raise smoke.SmokeFailure("CHROME_CDP_ERROR_Network_getResponseBody")
        return {"body": self.response_body}

    def evaluate(self, expression: str, timeout: float = 20.0):
        self.evaluate_log.append(expression)
        if "Boolean(window[" in expression and "installed === true" in expression:
            return True
        if '__nomadC3ObserverPhase = "begin"' in expression:
            self.observer_token = expression
            return True
        if '__nomadC3ObserverPhase = "peek"' in expression:
            return dict(self.observer)
        if '__nomadC3ObserverPhase = "take"' in expression:
            result = dict(self.observer)
            self.observer = {
                "active": False, "capture": None, "error": None,
                "request_count": 0, "response_count": 0,
            }
            return result
        if expression == "true":
            self.drain_calls += 1
            return True
        return True


class VisibleCDP(FakeCDP):
    def __init__(self, *, duplicate: bool = False, body_available: bool = True) -> None:
        super().__init__()
        self.duplicate = duplicate
        self.body_available = body_available
        self.emitted = False
        self.events = [{
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "old-req",
                "request": {"method": "POST", "url": "http://127.0.0.1/api/commands"},
            },
        }]
        self.replay_script: str | None = None
        request = command_request()
        receipt = command_receipt()
        self.response_body = json.dumps(receipt)
        self.observer = {
            "active": True, "error": None, "request_count": 1,
            "response_count": 1,
            "capture": {
                "request_body": json.dumps(request),
                "headers": {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Nomad-CSRF": "csrf-token",
                },
                "status": 200, "response_body": json.dumps(receipt),
            },
        }

    def call(self, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
        result = super().call(method, params, timeout)
        if not self.body_available:
            raise smoke.SmokeFailure("CHROME_CDP_ERROR_Network_getResponseBody")
        return result

    def evaluate(self, expression: str, timeout: float = 20.0):
        common = super().evaluate(expression, timeout)
        if expression != "true" and (
            "Boolean(window[" in expression or "__nomadC3ObserverPhase" in expression
        ):
            return common
        if "button.click()" in expression:
            return True
        if expression == "true":
            self.drain_calls += 1
            if not self.emitted:
                self.emitted = True
                request_ids = ["req-1", "req-2"] if self.duplicate else ["req-1"]
                for request_id in request_ids:
                    self.events.extend([
                        {
                            "method": "Network.requestWillBeSent",
                            "params": {
                                "requestId": request_id,
                                "request": {
                                    "method": "POST",
                                    "url": "http://127.0.0.1/api/commands",
                                    "postData": json.dumps(command_request()),
                                    "headers": {
                                        "Accept": "application/json",
                                        "Content-Type": "application/json",
                                        "X-Nomad-CSRF": "csrf-token",
                                        "Ignored": "value",
                                    },
                                },
                            },
                        },
                        {
                            "method": "Network.responseReceived",
                            "params": {
                                "requestId": request_id,
                                "response": {
                                    "url": "http://127.0.0.1/api/commands",
                                    "status": 200,
                                    "headers": {"Content-Type": "application/json"},
                                },
                            },
                        },
                        {"method": "Network.loadingFinished", "params": {"requestId": request_id}},
                    ])
            return True
        if "captured=" in expression and "Promise.all([send(),send()])" in expression:
            self.replay_script = expression
            return {
                "stage": "complete",
                "action": "reply",
                "body": '{"action":"reply"}',
                "capability": None,
                "first": {"status": 200, "payload": command_receipt()},
                "replay": [
                    {"status": 200, "payload": {"status": "DispatchAcknowledged", "receipt_id": "rcpt-1", "idempotent_replay": True}},
                    {"status": 200, "payload": {"status": "DispatchAcknowledged", "receipt_id": "rcpt-1", "idempotent_replay": True}},
                ],
            }
        raise AssertionError(f"unexpected evaluate {expression[:80]!r}")


class IncompleteVisibleCDP(FakeCDP):
    def __init__(
        self, events: list[dict], *, direct_body: dict | None = None,
        late_failed: bool = False, ui_acknowledged: bool = False,
    ) -> None:
        super().__init__()
        self.events = [
            {
                "method": "Network.requestWillBeSent",
                "params": {
                    "requestId": "old-req",
                    "request": {"method": "POST", "url": "http://127.0.0.1/api/commands"},
                },
            }
        ]
        self.pending = events
        self.emitted = False
        self.direct_body = direct_body
        self.late_failed = late_failed
        self.ui_acknowledged = ui_acknowledged
        self.replay_evaluated = False

    def call(self, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
        if method != "Network.getResponseBody":
            return super().call(method, params, timeout)
        if self.late_failed:
            self.events.append({
                "method": "Network.loadingFailed",
                "params": {
                    "requestId": (params or {}).get("requestId"),
                    "errorText": "private late failure",
                },
            })
        if self.direct_body is None:
            raise smoke.SmokeFailure("CHROME_CDP_ERROR_Network_getResponseBody")
        return self.direct_body

    def evaluate(self, expression: str, timeout: float = 20.0):
        common = super().evaluate(expression, timeout)
        if expression != "true" and (
            "Boolean(window[" in expression or "__nomadC3ObserverPhase" in expression
        ):
            return common
        if "Promise.all([send(),send()])" in expression:
            self.replay_evaluated = True
            raise AssertionError("diagnostic branch reached replay")
        if "button.click()" in expression:
            return True
        if expression == "true":
            if not self.emitted:
                self.events.extend(self.pending)
                self.emitted = True
            return True
        if expression == "document.body.innerText":
            return ""
        if expression == "document.body.innerText.includes('The Agent endpoint acknowledged Stop')":
            return self.ui_acknowledged
        raise AssertionError(f"unexpected evaluate {expression[:80]!r}")


class FallbackVisibleCDP(FakeCDP):
    def __init__(self, action: str) -> None:
        super().__init__()
        self.action = action
        self.request = command_request(action)
        self.receipt = command_receipt(action)
        self.emitted = False
        self.replay_evaluated = False
        self.transport_mutator = None
        self.observer = {
            "active": True, "error": None, "request_count": 1,
            "response_count": 1,
            "capture": {
                "request_body": json.dumps(self.request),
                "headers": {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Nomad-CSRF": "csrf-token",
                },
                "status": 200, "response_body": json.dumps(self.receipt),
            },
        }

    def evaluate(self, expression: str, timeout: float = 20.0):
        common = super().evaluate(expression, timeout)
        if expression != "true" and (
            "Boolean(window[" in expression or "__nomadC3ObserverPhase" in expression
        ):
            return common
        if "button.click()" in expression:
            return True
        if expression == "true":
            if not self.emitted:
                self.emitted = True
                body_length = len(json.dumps(self.receipt).encode())
                self.events.extend([
                    {
                        "method": "Network.requestWillBeSent",
                        "params": {
                            "requestId": "req-fallback",
                            "request": {
                                "method": "POST",
                                "url": "http://127.0.0.1/api/commands",
                                "postData": json.dumps(self.request),
                                "headers": {
                                    "Accept": "application/json",
                                    "Content-Type": "application/json",
                                    "X-Nomad-CSRF": "csrf-token",
                                },
                            },
                        },
                    },
                    {
                        "method": "Network.responseReceived",
                        "params": {
                            "requestId": "req-fallback",
                            "response": {
                                "url": "http://127.0.0.1/api/commands",
                                "status": 200,
                                "headers": {
                                    "Content-Type": "application/json; charset=utf-8",
                                    "Content-Length": str(body_length),
                                },
                            },
                        },
                    },
                    {
                        "method": "Network.dataReceived",
                        "params": {
                            "requestId": "req-fallback",
                            "dataLength": body_length, "encodedDataLength": 1,
                        },
                    },
                ])
                if self.transport_mutator is not None:
                    response = next(
                        event["params"]["response"] for event in self.events
                        if event["method"] == "Network.responseReceived"
                    )
                    self.transport_mutator(response, self.events)
            return True
        if "Promise.all([send(),send()])" in expression:
            self.replay_evaluated = True
            return {
                "stage": "complete", "action": self.action,
                "body": json.dumps(self.request), "capability": None,
                "first": {"status": 200, "payload": self.receipt},
                "replay": [
                    {"status": 200, "payload": {**self.receipt, "idempotent_replay": True}},
                    {"status": 200, "payload": {**self.receipt, "idempotent_replay": True}},
                ],
            }
        raise AssertionError(f"unexpected evaluate {expression[:80]!r}")


class C3LocalCommandSmokeTests(unittest.TestCase):
    def make_journal(
        self, root: Path, request: dict, receipt: dict,
        *, mode: int = 0o600, overrides: dict | None = None,
    ) -> Path:
        path = root / "command-test.sqlite3"
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE commands (request_id TEXT, command_type TEXT, seq INTEGER,
              status TEXT, accepted_at_seq INTEGER, result_json TEXT);
            CREATE TABLE host_authority_bindings (request_id TEXT, binding_digest TEXT,
              receipt_id TEXT, authority_scope TEXT, command_seq INTEGER, nonce_digest TEXT);
            CREATE TABLE host_authority_scopes (authority_scope TEXT,
              reconciliation_required INTEGER, active_request_id TEXT);
            """
        )
        values = {
            "command_type": request["action"], "seq": request["command_seq"],
            "status": "DispatchAcknowledged", "accepted_at_seq": 9,
            "binding_digest": "1" * 64, "receipt_id": receipt["receipt_id"],
            "authority_scope": "2" * 64, "command_seq": request["command_seq"],
            "nonce_digest": "3" * 64, "reconciliation_required": 0,
            "active_request_id": None,
        }
        values.update(overrides or {})
        host_receipt = {
            "receipt_id": receipt["receipt_id"],
            "request_id": receipt["request_id"],
            "kind": receipt["action"],
            "accepted_at": receipt["accepted_at"],
            "status": receipt["status"],
            "error_code": None, "accepted_at_seq": values["accepted_at_seq"],
            "idempotent_replay": False,
        }
        if "result_json" in values:
            result_json = values["result_json"]
        else:
            result_json = json.dumps(host_receipt)
        connection.execute(
            "INSERT INTO commands VALUES (?,?,?,?,?,?)",
            (request["request_id"], values["command_type"], values["seq"],
             values["status"], values["accepted_at_seq"], result_json),
        )
        connection.execute(
            "INSERT INTO host_authority_bindings VALUES (?,?,?,?,?,?)",
            (request["request_id"], values["binding_digest"], values["receipt_id"],
             values["authority_scope"], values["command_seq"], values["nonce_digest"]),
        )
        connection.execute(
            "INSERT INTO host_authority_scopes VALUES (?,?,?)",
            (values["authority_scope"], values["reconciliation_required"],
             values["active_request_id"]),
        )
        connection.commit()
        connection.close()
        os.chmod(path, mode)
        return path

    def test_heartbeat_is_fixed_content_free_and_flushes_each_line(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.parts: list[str] = []
                self.flushes = 0

            def write(self, value: str) -> int:
                self.parts.append(value)
                return len(value)

            def flush(self) -> None:
                self.flushes += 1

        sink = Sink()
        with mock.patch.object(smoke.sys, "stderr", sink):
            for stage in smoke.HEARTBEATS:
                smoke.heartbeat(stage)
            with self.assertRaisesRegex(ValueError, "^INVALID_C3_HEARTBEAT$"):
                smoke.heartbeat("PRIVATE_DYNAMIC_VALUE")
        lines = "".join(sink.parts).splitlines()
        self.assertEqual(tuple(lines), smoke.HEARTBEATS)
        self.assertTrue(set(lines).issubset(set(smoke.HEARTBEATS)))
        self.assertEqual(sink.flushes, len(smoke.HEARTBEATS))

    @staticmethod
    def receipt(
        *, request_id: str = "request-1", receipt_id: str = "receipt-1",
        action: str = "reply", status: str = "DispatchAcknowledged",
        error_code: str = "OK", replay: bool = False,
    ) -> dict:
        return {
            "schema": "nomad.gateway.command-receipt.v1",
            "receipt_id": receipt_id,
            "request_id": request_id,
            "action": action,
            "snapshot_seq": 7,
            "snapshot_digest": "sha256:" + "a" * 64,
            "accepted_at": "2026-08-30T00:00:00Z",
            "status": status,
            "error_code": error_code,
            "idempotent_replay": replay,
        }

    def replay_result(self, *, action: str = "reply") -> dict:
        first = self.receipt(action=action)
        return {
            "action": action,
            "first": {"status": 200, "payload": first},
            "replay": [
                {"status": 200, "payload": {**first, "idempotent_replay": True}},
                {"status": 200, "payload": {**first, "idempotent_replay": True}},
            ],
        }

    def test_replay_receipts_accept_two_valid_replays(self) -> None:
        smoke.assert_receipts(self.replay_result(), "DispatchAcknowledged")

    def test_replay_receipt_http_409_outcome_unknown_is_precise(self) -> None:
        result = self.replay_result()
        result["replay"][0] = {
            "status": 409,
            "payload": {"error": "ERR_OUTCOME_UNKNOWN"},
        }
        with self.assertRaisesRegex(
            smoke.SmokeFailure,
            "^COMMAND_REPLY_REPLAY_A_HTTP_409_ERR_OUTCOME_UNKNOWN$",
        ):
            smoke.assert_receipts(result, "DispatchAcknowledged")

    def test_replay_receipt_mismatch_is_precise_and_content_free(self) -> None:
        result = self.replay_result()
        private = "private-receipt-id"
        result["replay"][0]["payload"]["receipt_id"] = private
        with self.assertRaises(smoke.SmokeFailure) as raised:
            smoke.assert_receipts(result, "DispatchAcknowledged")
        self.assertEqual(
            str(raised.exception),
            "COMMAND_REPLY_REPLAY_A_RECEIPT_MISMATCH",
        )
        self.assertNotIn(private, str(raised.exception))

    def test_replay_idempotent_false_reports_replay_index(self) -> None:
        result = self.replay_result(action="stop")
        result["replay"][1]["payload"]["idempotent_replay"] = False
        with self.assertRaisesRegex(
            smoke.SmokeFailure,
            "^COMMAND_STOP_REPLAY_B_IDEMPOTENT_FALSE$",
        ):
            smoke.assert_receipts(result, "DispatchAcknowledged")

    def test_replay_structural_and_enum_failures_are_precise(self) -> None:
        private = "private-request-id-do-not-emit"
        cases = (
            ("BODY_INVALID", lambda result: result["replay"][0].update(payload={})),
            ("SCHEMA_INVALID", lambda result: result["replay"][0]["payload"].update(schema="wrong")),
            ("REQUEST_MISMATCH", lambda result: result["replay"][0]["payload"].update(request_id=private)),
            ("ACTION_MISMATCH", lambda result: result["replay"][0]["payload"].update(action="deny")),
            ("STATUS_REJECTED", lambda result: result["replay"][0]["payload"].update(status="Rejected")),
            ("ERROR_ERR_HOST_OFFLINE", lambda result: result["replay"][0]["payload"].update(error_code="ERR_HOST_OFFLINE")),
        )
        for suffix, mutate in cases:
            result = self.replay_result()
            mutate(result)
            with self.subTest(suffix=suffix), self.assertRaises(smoke.SmokeFailure) as raised:
                smoke.assert_receipts(result, "DispatchAcknowledged")
            self.assertEqual(str(raised.exception), "COMMAND_REPLY_REPLAY_A_" + suffix)
            self.assertNotIn(private, str(raised.exception))

    def test_gateway_and_chrome_timeout_codes_are_service_specific(self) -> None:
        for code in ("GATEWAY_HTTP_SERVICE_TIMEOUT", "CHROME_DEVTOOLS_TIMEOUT"):
            with self.subTest(code=code), mock.patch.object(
                smoke.NO_PROXY, "open", side_effect=OSError("unavailable")
            ), mock.patch.object(smoke.time, "sleep"), mock.patch.object(
                smoke.time, "monotonic", side_effect=[0.0, 0.5, 1.1]
            ):
                with self.assertRaisesRegex(smoke.SmokeFailure, f"^{code}_OTHER_OSError$"):
                    smoke.wait_json("http://127.0.0.1:1/ignored", 1.0, code)

    def test_chrome_wait_reports_early_exit_without_polling_http(self) -> None:
        process = mock.Mock()
        process.poll.return_value = 23
        with mock.patch.object(smoke.NO_PROXY, "open") as opened, mock.patch.object(
            smoke.time, "monotonic", side_effect=[0.0, 0.1]
        ):
            with self.assertRaisesRegex(smoke.SmokeFailure, "^CHROME_DEVTOOLS_EARLY_EXIT$"):
                smoke.wait_json(
                    "http://127.0.0.1:1/ignored", 1.0,
                    "CHROME_DEVTOOLS_TIMEOUT", child=process,
                    early_exit_code="CHROME_DEVTOOLS_EARLY_EXIT",
                )
        opened.assert_not_called()

    def test_wait_json_reports_content_free_failure_categories(self) -> None:
        cases = (
            (
                urllib.error.HTTPError("http://ignored", 503, "private", {}, None),
                "HTTP_503",
            ),
            (urllib.error.URLError(socket.timeout("private")), "REQUEST_TIMEOUT"),
            (urllib.error.URLError(ConnectionRefusedError("private")), "CONNECTION_REFUSED"),
            (json.JSONDecodeError("private", "x", 0), "INVALID_JSON"),
        )
        for error, suffix in cases:
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            side_effect = error
            if isinstance(error, json.JSONDecodeError):
                response.read.return_value = b"invalid"
                side_effect = None
            with self.subTest(suffix=suffix), mock.patch.object(
                smoke.NO_PROXY, "open",
                side_effect=side_effect,
                return_value=response,
            ), mock.patch.object(smoke.json, "load", side_effect=error if suffix == "INVALID_JSON" else None), mock.patch.object(
                smoke.time, "sleep"
            ), mock.patch.object(smoke.time, "monotonic", side_effect=[0.0, 0.5, 1.1]):
                with self.assertRaisesRegex(
                    smoke.SmokeFailure,
                    f"^GATEWAY_HTTP_SERVICE_TIMEOUT_{suffix}$",
                ):
                    smoke.wait_json(
                        "http://127.0.0.1:1/ignored", 1.0,
                        "GATEWAY_HTTP_SERVICE_TIMEOUT",
                    )

    def test_gateway_process_record_early_exit_is_reported_before_http(self) -> None:
        record = {"pid": 123, "process_group": 123, "identity": "a" * 64}
        with mock.patch.object(smoke.processes, "ownership", return_value="absent"), mock.patch.object(
            smoke.NO_PROXY, "open"
        ) as opened, mock.patch.object(smoke.time, "monotonic", side_effect=[0.0, 0.1]):
            with self.assertRaisesRegex(smoke.SmokeFailure, "^GATEWAY_HTTP_EARLY_EXIT$"):
                smoke.wait_json(
                    "http://127.0.0.1:1/ignored", 1.0,
                    "GATEWAY_HTTP_SERVICE_TIMEOUT", child=record,
                    early_exit_code="GATEWAY_HTTP_EARLY_EXIT",
                )
        opened.assert_not_called()

    def test_chrome_constructor_timeout_terminates_kills_reaps_and_closes_once(self) -> None:
        process = mock.Mock()
        process.pid = 43210
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired(["chrome"], 8), None]
        log_handle = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "chrome"
            executable.write_bytes(b"chrome")
            with mock.patch.object(smoke, "free_port", return_value=9222), mock.patch.object(
                smoke.Path, "open", return_value=log_handle
            ), mock.patch.object(smoke.subprocess, "Popen", return_value=process), mock.patch.object(
                smoke.processes, "process_identity", return_value="a" * 64
            ), mock.patch.object(
                smoke, "wait_json", side_effect=smoke.SmokeFailure("CHROME_DEVTOOLS_TIMEOUT")
            ), mock.patch.object(smoke.os, "killpg") as killpg:
                with self.assertRaisesRegex(smoke.SmokeFailure, "^CHROME_DEVTOOLS_TIMEOUT$"):
                    smoke.Chrome(root, root / "chrome.log", executable)
        self.assertEqual(
            killpg.call_args_list,
            [mock.call(process.pid, 15), mock.call(process.pid, 9)],
        )
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=8), mock.call(timeout=5)])
        log_handle.close.assert_called_once_with()

    def test_gateway_early_exit_classification_is_allowlisted_and_content_free(self) -> None:
        record = {"pid": 123, "process_group": 123, "identity": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "gateway.log"
            private = "private-path-token-do-not-emit"
            log.write_text("Error: listen EADDRINUSE " + private + "\n", encoding="utf-8")
            log.chmod(0o600)
            with mock.patch.object(
                smoke.processes, "ownership", return_value="absent"
            ), mock.patch.object(
                smoke, "child_exit_fact", return_value="EXIT_1"
            ), mock.patch.object(smoke.NO_PROXY, "open") as opened, mock.patch.object(
                smoke.time, "monotonic", side_effect=[0.0, 0.1]
            ):
                with self.assertRaises(smoke.SmokeFailure) as raised:
                    smoke.wait_json(
                        "http://127.0.0.1:1/ignored", 1.0,
                        "GATEWAY_HTTP_SERVICE_TIMEOUT", child=record,
                        early_exit_code="GATEWAY_HTTP_EARLY_EXIT",
                        early_exit_log=log,
                    )
            self.assertEqual(
                str(raised.exception),
                "GATEWAY_HTTP_EARLY_EXIT_EADDRINUSE_EXIT_1",
            )
            self.assertNotIn(private, str(raised.exception))
            opened.assert_not_called()

            log.write_text("unexpected failure " + private + "\n", encoding="utf-8")
            log.chmod(0o600)
            self.assertEqual(smoke.classify_gateway_log(log), "OTHER")

    def test_verified_bundle_runtime_ignores_ambient_path_node(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bundle"
            runtime = root / "runtime"
            runtime.mkdir(parents=True)
            bundled = runtime / "node"
            bundled.write_bytes(b"bundled")
            bundled.chmod(0o755)
            fake_bin = Path(temporary) / "ambient"
            fake_bin.mkdir()
            ambient = fake_bin / "node"
            ambient.write_bytes(b"ambient")
            ambient.chmod(0o755)
            with mock.patch.object(
                smoke, "verify_bundle", return_value={}
            ) as verify, mock.patch.dict(
                smoke.os.environ, {"PATH": str(fake_bin)}, clear=False
            ):
                verified_root, selected = smoke.verified_bundle_runtime(root)
            verify.assert_called_once_with(root)
            self.assertEqual(verified_root, root.resolve())
            self.assertEqual(selected, bundled.resolve())
            self.assertNotEqual(selected, ambient)

    def test_chrome_page_uses_passive_cdp_observation(self) -> None:
        class PageCDP:
            def __init__(self, _websocket_url: str) -> None:
                self.calls: list[tuple[str, dict | None]] = []

            def call(self, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
                self.calls.append((method, params))
                return {}

        chrome = object.__new__(smoke.Chrome)
        chrome.port = 9222
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.read.return_value = json.dumps({"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/1"}).encode()
        with mock.patch.object(smoke, "CDP", PageCDP), mock.patch.object(
            smoke.NO_PROXY, "open", return_value=response
        ), mock.patch.object(smoke, "wait_eval", return_value=True):
            cdp = chrome.page("http://127.0.0.1:14173/", 1440, 900, False)

        methods = [method for method, _params in cdp.calls]
        self.assertNotIn("Page.addScriptToEvaluateOnNewDocument", methods)
        self.assertEqual(cdp.calls[-1], ("Page.navigate", {"url": "http://127.0.0.1:14173/"}))

    def test_chrome_action_page_installs_observer_before_navigation(self) -> None:
        class PageCDP:
            def __init__(self, _websocket_url: str) -> None:
                self.calls: list[tuple[str, dict | None]] = []

            def call(self, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
                self.calls.append((method, params))
                return {}

        chrome = object.__new__(smoke.Chrome)
        chrome.port = 9222
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.read.return_value = json.dumps({"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/1"}).encode()
        with mock.patch.object(smoke, "CDP", PageCDP), mock.patch.object(
            smoke.NO_PROXY, "open", return_value=response
        ), mock.patch.object(smoke, "wait_eval", return_value=True):
            cdp = chrome.page(
                "http://127.0.0.1:14173/", 390, 844, True, action_observer=True
            )
        methods = [method for method, _params in cdp.calls]
        self.assertLess(
            methods.index("Page.addScriptToEvaluateOnNewDocument"),
            methods.index("Page.navigate"),
        )
        source = dict(cdp.calls[methods.index("Page.addScriptToEvaluateOnNewDocument")][1])["source"]
        self.assertIn("originalFetch(input, init)", source)
        self.assertIn("request.clone().text()", source)
        self.assertIn("response.clone().text()", source)

    def test_read_response_body_waits_for_loading_finished_and_retries_read_only(self) -> None:
        cdp = FakeCDP()
        cdp.events = [
            {"method": "Network.responseReceived", "params": {"requestId": "req-1", "response": {"url": "http://127.0.0.1/api/commands", "status": 200}}},
            {"method": "Network.loadingFinished", "params": {"requestId": "req-1"}},
        ]
        with mock.patch.object(smoke.time, "sleep", lambda _seconds: None):
            body = smoke.read_response_body(cdp, "req-1", timeout=0.5)
        self.assertEqual(body, '{"status":"DispatchAcknowledged","receipt_id":"rcpt-1"}')
        self.assertTrue(cdp.loading_finished_seen_at_get)
        self.assertEqual(cdp.get_response_body_calls, 2)

    def test_capture_uses_passive_cdp_and_counts_one_original_post(self) -> None:
        cdp = VisibleCDP()
        with mock.patch.object(smoke.time, "sleep", lambda _seconds: None):
            result = smoke.capture_visible_command(cdp, "reply", "(async()=>{const button={click(){}};button.click();return true})()")
        self.assertEqual(result["first"]["payload"]["status"], "DispatchAcknowledged")
        self.assertEqual(result["browser_request_count"], 1)
        self.assertEqual(result["browser_response_count"], 1)
        self.assertIsNotNone(cdp.replay_script)
        take_index = next(i for i, expression in enumerate(cdp.evaluate_log) if '__nomadC3ObserverPhase = "take"' in expression)
        replay_index = next(i for i, expression in enumerate(cdp.evaluate_log) if "Promise.all([send(),send()])" in expression)
        self.assertLess(take_index, replay_index)
        begin = next(expression for expression in cdp.evaluate_log if '__nomadC3ObserverPhase = "begin"' in expression)
        peek = next(expression for expression in cdp.evaluate_log if '__nomadC3ObserverPhase = "peek"' in expression)
        take = next(expression for expression in cdp.evaluate_log if '__nomadC3ObserverPhase = "take"' in expression)
        token = next(part for part in begin.split('\"') if len(part) == 64 and all(c in "0123456789abcdef" for c in part))
        self.assertIn(token, peek)
        self.assertIn(token, take)

    def test_capture_rejects_duplicate_original_browser_posts_before_replay(self) -> None:
        cdp = VisibleCDP(duplicate=True)
        with mock.patch.object(smoke.time, "sleep", lambda _seconds: None):
            with self.assertRaisesRegex(smoke.SmokeFailure, "VISIBLE_REPLY_BROWSER_POST_COUNT_INVALID"):
                smoke.capture_visible_command(cdp, "reply", "(async()=>{const button={click(){}};button.click();return true})()")
        self.assertIsNone(cdp.replay_script)

    def test_capture_reports_response_body_unavailable_after_single_observed_post(self) -> None:
        cdp = VisibleCDP(body_available=False)
        with mock.patch.object(smoke.time, "sleep", lambda _seconds: None):
            with self.assertRaisesRegex(smoke.SmokeFailure, "VISIBLE_REPLY_RESPONSE_BODY_UNAVAILABLE"):
                smoke.capture_visible_command(cdp, "reply", "(async()=>{const button={click(){}};button.click();return true})()")
        self.assertIsNone(cdp.replay_script)

    def test_strict_observer_fallback_reply_and_stop(self) -> None:
        for action in ("reply", "stop"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                os.chmod(root, 0o700)
                cdp = FallbackVisibleCDP(action)
                journal = self.make_journal(root, cdp.request, cdp.receipt)
                result = smoke.capture_visible_command(
                    cdp, action,
                    "(async()=>{const button={click(){}};button.click();return true})()",
                    journal,
                )
                smoke.assert_receipts(result, "DispatchAcknowledged")
                self.assertTrue(cdp.replay_evaluated)

    def test_fallback_transport_guards_fail_closed_before_replay(self) -> None:
        cases = {
            "partial": lambda response, events: events[-1]["params"].update(dataLength=1),
            "transfer_encoding": lambda response, events: response["headers"].update({"Transfer-Encoding": "chunked"}),
            "content_length": lambda response, events: response["headers"].update({"Content-Length": "bad"}),
            "encoding": lambda response, events: response["headers"].update({"Content-Encoding": "gzip"}),
            "content_type": lambda response, events: response["headers"].update({"Content-Type": "text/plain"}),
            "failed": lambda response, events: events.append({"method": "Network.loadingFailed", "params": {"requestId": "req-fallback", "errorText": "private transport detail"}}),
        }
        for name, mutate in cases.items():
            cdp = FallbackVisibleCDP("stop")
            cdp.transport_mutator = mutate
            with self.subTest(name=name), self.assertRaises(smoke.SmokeFailure) as raised:
                with mock.patch.object(
                    smoke.time, "monotonic", side_effect=[0.0, 0.1, 21.0]
                ), mock.patch.object(smoke.time, "sleep"):
                    smoke.capture_visible_command(
                        cdp, "stop",
                        "(async()=>{const button={click(){}};button.click();return true})()",
                    )
            self.assertFalse(cdp.replay_evaluated)
            self.assertNotIn("private transport detail", str(raised.exception))

    def test_observer_failures_have_fixed_content_free_subcodes(self) -> None:
        private = "private-observer-content"
        def material() -> tuple[dict, dict, dict, dict]:
            request_object = command_request("reply")
            receipt = command_receipt("reply")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Nomad-CSRF": "csrf-token",
            }
            observer = {
                "active": True, "error": None, "request_count": 1,
                "response_count": 1,
                "capture": {
                    "request_body": json.dumps(request_object),
                    "headers": dict(headers), "status": 200,
                    "response_body": json.dumps(receipt),
                },
            }
            request = {"postData": json.dumps(request_object), "headers": dict(headers)}
            return observer, request, {"status": 200}, receipt

        def state_invalid(observer, _request, _response, _receipt):
            observer["error"] = private

        def observer_request_invalid(observer, _request, _response, _receipt):
            observer["capture"]["request_body"] = '{"schema":"x","schema":"y"}'

        def cdp_request_invalid(_observer, request, _response, _receipt):
            request["postData"] = '{"schema":"x","schema":"y"}'

        def request_mismatch(observer, _request, _response, _receipt):
            value = command_request("reply")
            value["content"] = private
            observer["capture"]["request_body"] = json.dumps(value)

        def observer_headers_invalid(observer, _request, _response, _receipt):
            del observer["capture"]["headers"]["Accept"]

        def cdp_headers_invalid(_observer, request, _response, _receipt):
            del request["headers"]["Accept"]

        def headers_mismatch(observer, _request, _response, _receipt):
            observer["capture"]["headers"]["X-Nomad-CSRF"] = private

        def status_mismatch(observer, _request, _response, _receipt):
            _response["status"] = 503

        def observer_status_invalid(observer, _request, _response, _receipt):
            observer["capture"]["status"] = private

        def cdp_status_invalid(_observer, _request, response, _receipt):
            response["status"] = private

        def observer_receipt_invalid(observer, _request, _response, _receipt):
            observer["capture"]["response_body"] = '{"schema":"x","schema":"y"}'

        def cdp_receipt_invalid(_observer, _request, _response, receipt):
            receipt["receipt_id"] = "x"

        def receipt_mismatch(observer, _request, _response, _receipt):
            value = command_receipt("reply")
            value["accepted_at"] = "2026-08-30T00:00:02Z"
            observer["capture"]["response_body"] = json.dumps(value)

        cases = (
            ("STATE_INVALID", state_invalid),
            ("OBSERVER_REQUEST_INVALID", observer_request_invalid),
            ("CDP_REQUEST_INVALID", cdp_request_invalid),
            ("REQUEST_MISMATCH", request_mismatch),
            ("OBSERVER_HEADERS_INVALID", observer_headers_invalid),
            ("CDP_HEADERS_INVALID", cdp_headers_invalid),
            ("HEADERS_MISMATCH", headers_mismatch),
            ("STATUS_MISMATCH_OBSERVER_200_CDP_503", status_mismatch),
            ("OBSERVER_STATUS_INVALID", observer_status_invalid),
            ("CDP_STATUS_INVALID", cdp_status_invalid),
            ("OBSERVER_RECEIPT_INVALID", observer_receipt_invalid),
            ("CDP_RECEIPT_INVALID", cdp_receipt_invalid),
            ("RECEIPT_MISMATCH", receipt_mismatch),
        )
        for suffix, mutate in cases:
            observer, request, response, receipt = material()
            mutate(observer, request, response, receipt)
            with self.subTest(suffix=suffix), self.assertRaises(smoke.SmokeFailure) as raised:
                smoke.observer_captured(
                    "reply", observer, request, response, cdp_payload=receipt,
                )
            self.assertEqual(str(raised.exception), "VISIBLE_REPLY_OBSERVER_" + suffix)
            self.assertNotIn(private, str(raised.exception))

    def test_equal_non_200_status_reports_gateway_error_and_journal_state(self) -> None:
        request_object = command_request("deny")
        receipt = command_receipt("deny")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Nomad-CSRF": "csrf-token",
        }
        observer = {
            "active": True, "error": None, "request_count": 1,
            "response_count": 1,
            "capture": {
                "request_body": json.dumps(request_object),
                "headers": dict(headers), "status": 503,
                "response_body": json.dumps({"error": "COMMAND_OUTCOME_UNAVAILABLE"}),
            },
        }
        cdp_request = {"postData": json.dumps(request_object), "headers": headers}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            journal = self.make_journal(
                root, request_object, receipt, overrides={"status": "Dispatching"},
            )
            with self.assertRaisesRegex(
                smoke.SmokeFailure,
                "^VISIBLE_DENY_HTTP_503_COMMAND_OUTCOME_UNAVAILABLE_"
                "JOURNAL_DISPATCHING_BOUND$",
            ):
                smoke.observer_captured(
                    "deny", observer, cdp_request, {"status": 503},
                    journal_path=journal,
                )

    def test_equal_non_200_unknown_error_with_no_journal_row_is_safe(self) -> None:
        private = "private-unknown-gateway-error"
        request_object = command_request("stop")
        other_request = command_request("stop", "request-00000002")
        receipt = command_receipt("stop", "request-00000002")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Nomad-CSRF": "csrf-token",
        }
        observer = {
            "active": True, "error": None, "request_count": 1,
            "response_count": 1,
            "capture": {
                "request_body": json.dumps(request_object),
                "headers": dict(headers), "status": 503,
                "response_body": json.dumps({"error": private}),
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            journal = self.make_journal(root, other_request, receipt)
            with self.assertRaises(smoke.SmokeFailure) as raised:
                smoke.observer_captured(
                    "stop", observer,
                    {"postData": json.dumps(request_object), "headers": headers},
                    {"status": 503}, journal_path=journal,
                )
            self.assertEqual(
                str(raised.exception),
                "VISIBLE_STOP_HTTP_503_UNKNOWN_JOURNAL_NO_ROW_UNBOUND",
            )
            self.assertNotIn(private, str(raised.exception))

    def test_journal_validation_failures_are_fixed_and_content_free(self) -> None:
        private = "private-journal-content"
        cases = {
            "status": {"status": "Rejected"},
            "join": {"authority_scope": private},
            "result": {"result_json": '{"private":"' + private + '"}'},
            "binding": {"binding_digest": "0" * 64},
            "scope": {"reconciliation_required": 1},
        }
        request = command_request("stop")
        receipt = command_receipt("stop")
        for name, overrides in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                os.chmod(root, 0o700)
                path = self.make_journal(root, request, receipt, overrides=overrides)
                with self.assertRaises(smoke.SmokeFailure) as raised:
                    smoke.validate_journal_receipt(path, request, receipt)
                self.assertEqual(str(raised.exception), "VISIBLE_COMMAND_JOURNAL_VALIDATION_FAILED")
                self.assertNotIn(private, str(raised.exception))

    def test_journal_rejects_permission_symlink_and_invalid_sidecar(self) -> None:
        request = command_request("stop")
        receipt = command_receipt("stop")
        for name in ("permission", "symlink", "sidecar"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                os.chmod(root, 0o700)
                path = self.make_journal(root, request, receipt)
                target = path
                if name == "permission":
                    os.chmod(path, 0o644)
                elif name == "symlink":
                    link = root / "linked.sqlite3"
                    link.symlink_to(path)
                    target = link
                else:
                    sidecar = Path(str(path) + "-wal")
                    sidecar.write_bytes(b"invalid")
                    os.chmod(sidecar, 0o644)
                with self.assertRaisesRegex(
                    smoke.SmokeFailure, "^VISIBLE_COMMAND_JOURNAL_VALIDATION_FAILED$"
                ):
                    smoke.validate_journal_receipt(target, request, receipt)

    def test_journal_rejects_missing_join_and_receipt_mismatch(self) -> None:
        request = command_request("stop")
        receipt = command_receipt("stop")
        for name in ("missing_scope_join", "receipt_mismatch"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                os.chmod(root, 0o700)
                overrides = {"receipt_id": "different-receipt-0001"} if name == "receipt_mismatch" else {}
                path = self.make_journal(root, request, receipt, overrides=overrides)
                if name == "missing_scope_join":
                    connection = sqlite3.connect(path)
                    connection.execute("DELETE FROM host_authority_scopes")
                    connection.commit()
                    connection.close()
                with self.assertRaisesRegex(
                    smoke.SmokeFailure, "^VISIBLE_COMMAND_JOURNAL_VALIDATION_FAILED$"
                ):
                    smoke.validate_journal_receipt(path, request, receipt)

    def test_visible_command_deadline_classifies_matching_request_lifecycle(self) -> None:
        request = {
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "req-1",
                "request": {
                    "method": "POST", "url": "http://127.0.0.1/api/commands",
                    "postData": '{"action":"stop"}', "headers": {},
                },
            },
        }
        response = {
            "method": "Network.responseReceived",
            "params": {
                "requestId": "req-1",
                "response": {"url": "http://127.0.0.1/api/commands", "status": 200},
            },
        }
        failed = {
            "method": "Network.loadingFailed",
            "params": {"requestId": "req-1", "errorText": "private detail"},
        }
        cases = (
            ([request], "VISIBLE_STOP_RESPONSE_NOT_OBSERVED"),
            ([request, response], "VISIBLE_STOP_LOADING_NOT_FINISHED_BODY_UNAVAILABLE_CL_INVALID_DATA_NONE"),
            ([request, response, failed], "VISIBLE_STOP_NETWORK_LOADING_FAILED"),
        )
        for events, code in cases:
            cdp = IncompleteVisibleCDP(events)
            with self.subTest(code=code), mock.patch.object(
                smoke.time, "monotonic", side_effect=[0.0, 0.1, 21.0]
            ), mock.patch.object(smoke.time, "sleep"):
                with self.assertRaisesRegex(smoke.SmokeFailure, f"^{code}$") as raised:
                    smoke.capture_visible_command(
                        cdp, "stop",
                        "(async()=>{const button={click(){}};button.click();return true})()",
                    )
            self.assertNotIn("private detail", str(raised.exception))

    def test_unfinished_response_diagnostic_valid_invalid_and_late_failed_never_replay(self) -> None:
        request_id = "request-id-0001"
        request = {
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "req-1",
                "request": {
                    "method": "POST", "url": "http://127.0.0.1/api/commands",
                    "postData": json.dumps({"action": "stop", "request_id": request_id}),
                    "headers": {},
                },
            },
        }
        response = {
            "method": "Network.responseReceived",
            "params": {
                "requestId": "req-1",
                "response": {"url": "http://127.0.0.1/api/commands", "status": 200},
            },
        }
        receipt = self.receipt(
            request_id=request_id, receipt_id="receipt-id-0001", action="stop",
        )
        cases = (
            (
                {"body": json.dumps(receipt)}, False,
                "VISIBLE_STOP_LOADING_NOT_FINISHED_BODY_AVAILABLE_VALID_RECEIPT_CL_INVALID_DATA_NONE",
            ),
            (
                {"body": json.dumps({**receipt, "request_id": "different-request"})},
                False, "VISIBLE_STOP_LOADING_NOT_FINISHED_BODY_UNAVAILABLE_CL_INVALID_DATA_NONE",
            ),
            (
                {"body": json.dumps(receipt)}, True,
                "VISIBLE_STOP_NETWORK_LOADING_FAILED",
            ),
        )
        for direct_body, late_failed, code in cases:
            cdp = IncompleteVisibleCDP(
                [request, response], direct_body=direct_body,
                late_failed=late_failed,
            )
            with self.subTest(code=code), mock.patch.object(
                smoke.time, "monotonic", side_effect=[0.0, 0.1, 21.0]
            ), mock.patch.object(smoke.time, "sleep"):
                with self.assertRaisesRegex(smoke.SmokeFailure, f"^{code}$") as raised:
                    smoke.capture_visible_command(
                        cdp, "stop",
                        "(async()=>{const button={click(){}};button.click();return true})()",
                    )
            self.assertFalse(cdp.replay_evaluated)
            self.assertNotIn(request_id, str(raised.exception))

    def test_unfinished_response_diagnostic_rejects_duplicate_key_body(self) -> None:
        request_id = "request-id-0001"
        request = {
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "req-1",
                "request": {
                    "method": "POST", "url": "http://127.0.0.1/api/commands",
                    "postData": json.dumps({"action": "stop", "request_id": request_id}),
                    "headers": {},
                },
            },
        }
        response = {
            "method": "Network.responseReceived",
            "params": {
                "requestId": "req-1",
                "response": {"url": "http://127.0.0.1/api/commands", "status": 200},
            },
        }
        duplicate = '{"schema":"nomad.gateway.command-receipt.v1","schema":"nomad.gateway.command-receipt.v1"}'
        cdp = IncompleteVisibleCDP([request, response], direct_body={"body": duplicate})
        with mock.patch.object(
            smoke.time, "monotonic", side_effect=[0.0, 0.1, 21.0]
        ), mock.patch.object(smoke.time, "sleep"):
            with self.assertRaisesRegex(
                smoke.SmokeFailure,
                "^VISIBLE_STOP_LOADING_NOT_FINISHED_BODY_UNAVAILABLE_CL_INVALID_DATA_NONE$",
            ):
                smoke.capture_visible_command(
                    cdp, "stop",
                    "(async()=>{const button={click(){}};button.click();return true})()",
                )
        self.assertFalse(cdp.replay_evaluated)

    def test_unfinished_response_reports_ui_ack_framing_and_data_without_replay(self) -> None:
        request_id = "request-id-0001"
        request = {
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "req-1",
                "request": {
                    "method": "POST", "url": "http://127.0.0.1/api/commands",
                    "postData": json.dumps({"action": "stop", "request_id": request_id}),
                    "headers": {},
                },
            },
        }
        response = {
            "method": "Network.responseReceived",
            "params": {
                "requestId": "req-1",
                "response": {
                    "url": "http://127.0.0.1/api/commands", "status": 200,
                    "headers": {"Content-Length": "100"},
                },
            },
        }
        data = {
            "method": "Network.dataReceived",
            "params": {
                "requestId": "req-1", "dataLength": 40,
                "encodedDataLength": 40,
            },
        }
        receipt = self.receipt(
            request_id=request_id, receipt_id="receipt-id-0001", action="stop",
        )
        cdp = IncompleteVisibleCDP(
            [request, response, data], direct_body={"body": json.dumps(receipt)},
            ui_acknowledged=True,
        )
        with mock.patch.object(
            smoke.time, "monotonic", side_effect=[0.0, 0.1, 21.0]
        ), mock.patch.object(smoke.time, "sleep"):
            with self.assertRaisesRegex(
                smoke.SmokeFailure,
                "^VISIBLE_STOP_LOADING_NOT_FINISHED_UI_ACKNOWLEDGED_CL_VALID_NO_TE_DATA_PARTIAL$",
            ):
                smoke.capture_visible_command(
                    cdp, "stop",
                    "(async()=>{const button={click(){}};button.click();return true})()",
                )
        self.assertFalse(cdp.replay_evaluated)

    def test_unfinished_framing_data_enums_are_fixed(self) -> None:
        base = {
            "method": "Network.dataReceived",
            "params": {"requestId": "req-1", "dataLength": 50, "encodedDataLength": 50},
        }
        cases = (
            ({"headers": {"Content-Length": "100"}}, [base, base], ("CL_VALID_NO_TE", "DATA_COMPLETE")),
            ({"headers": {"Content-Length": "100"}}, [base], ("CL_VALID_NO_TE", "DATA_PARTIAL")),
            ({"headers": {"Transfer-Encoding": "chunked"}}, [base], ("TE_PRESENT", "DATA_UNKNOWN")),
            ({"headers": {"Content-Length": "bad"}}, [], ("CL_INVALID", "DATA_NONE")),
            ({"headers": {"Content-Length": "100"}}, [{"method": "Network.dataReceived", "params": {"requestId": "req-1", "dataLength": "private", "encodedDataLength": 1}}], ("CL_VALID_NO_TE", "DATA_UNKNOWN")),
        )
        for response, events, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    smoke.unfinished_framing_data(events, "req-1", response),
                    expected,
                )

    def test_visible_command_zero_request_retains_post_not_observed(self) -> None:
        cdp = IncompleteVisibleCDP([])
        with mock.patch.object(
            smoke.time, "monotonic", side_effect=[0.0, 0.1, 21.0]
        ), mock.patch.object(smoke.time, "sleep"):
            with self.assertRaisesRegex(
                smoke.SmokeFailure,
                "^VISIBLE_STOP_POST_NOT_OBSERVED_unclassified_0$",
            ):
                smoke.capture_visible_command(
                    cdp, "stop",
                    "(async()=>{const button={click(){}};button.click();return true})()",
                )


if __name__ == "__main__":
    unittest.main()
