#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "c3_local_command_smoke.py"
SPEC = importlib.util.spec_from_file_location("nomad_c3_local_command_smoke", MODULE_PATH)
smoke = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)


class FakeCDP:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.get_response_body_calls = 0
        self.loading_finished_seen_at_get = False
        self.drain_calls = 0

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
        return {"body": '{"status":"DispatchAcknowledged","receipt_id":"rcpt-1"}'}

    def evaluate(self, expression: str, timeout: float = 20.0):
        if expression == "true":
            self.drain_calls += 1
            return True
        return True


class VisibleCDP(FakeCDP):
    def __init__(self, *, duplicate: bool = False) -> None:
        super().__init__()
        self.duplicate = duplicate
        self.emitted = False
        self.events = [{
            "method": "Network.requestWillBeSent",
            "params": {
                "requestId": "old-req",
                "request": {"method": "POST", "url": "http://127.0.0.1/api/commands"},
            },
        }]
        self.replay_script: str | None = None

    def evaluate(self, expression: str, timeout: float = 20.0):
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
                                    "postData": '{"action":"reply"}',
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
                                "response": {"url": "http://127.0.0.1/api/commands", "status": 200},
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
                "first": {"status": 200, "payload": {"status": "DispatchAcknowledged", "receipt_id": "rcpt-1"}},
                "replay": [
                    {"status": 200, "payload": {"status": "DispatchAcknowledged", "receipt_id": "rcpt-1", "idempotent_replay": True}},
                    {"status": 200, "payload": {"status": "DispatchAcknowledged", "receipt_id": "rcpt-1", "idempotent_replay": True}},
                ],
            }
        raise AssertionError(f"unexpected evaluate {expression[:80]!r}")


class C3LocalCommandSmokeTests(unittest.TestCase):
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

    def test_capture_rejects_duplicate_original_browser_posts_before_replay(self) -> None:
        cdp = VisibleCDP(duplicate=True)
        with mock.patch.object(smoke.time, "sleep", lambda _seconds: None):
            with self.assertRaisesRegex(smoke.SmokeFailure, "VISIBLE_REPLY_BROWSER_POST_COUNT_INVALID"):
                smoke.capture_visible_command(cdp, "reply", "(async()=>{const button={click(){}};button.click();return true})()")
        self.assertIsNone(cdp.replay_script)


if __name__ == "__main__":
    unittest.main()
