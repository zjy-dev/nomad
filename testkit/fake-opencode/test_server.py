#!/usr/bin/env python3
"""Unit tests for the stdlib fake OpenCode HTTP state machine."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SERVER_PATH = Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("fake_opencode_server", SERVER_PATH)
assert SPEC is not None and SPEC.loader is not None
SERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER)


class StateTest(unittest.TestCase):
    def test_reproducible_events_cover_pilot_facts(self) -> None:
        first = SERVER.base_events()
        second = SERVER.base_events()
        self.assertEqual(first, second)
        self.assertIn("message.updated", [event["type"] for event in first])
        self.assertIn("permission.updated", [event["type"] for event in first])
        self.assertIn("session.diff", [event["type"] for event in first])
        self.assertEqual(first[-2]["data"]["status"], "reconnecting")

    def test_reply_is_deduplicated(self) -> None:
        state = SERVER.State("happy")
        status1, first = state.execute("req-1", "reply")
        status2, second = state.execute("req-1", "reply")
        self.assertEqual((status1, status2), (200, 200))
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(state.command_counts["reply"], 1)

    def test_deny_binds_pending_once(self) -> None:
        state = SERVER.State("happy")
        status, result = state.execute("deny-1", "deny", SERVER.PERMISSION_ID)
        self.assertEqual(status, 200)
        self.assertTrue(result["upstream_pending_bound"])
        stale_status, stale = state.execute(
            "deny-2", "deny", SERVER.PERMISSION_ID
        )
        self.assertEqual(stale_status, 409)
        self.assertEqual(stale["error_code"], "ERR_REQUEST_STALE")


if __name__ == "__main__":
    unittest.main()
