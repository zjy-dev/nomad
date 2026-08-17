"""Tests for the fake OpenCode session implementation.

Run via:  python3 -m unittest testkit.e2e.test_fake_opencode
Or via:   python3 -m unittest discover -s testkit -t . -p 'test_fake_opencode.py'
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from testkit.e2e.fake_opencode import OpenCodeSession, EventRecord


class OpenCodeSessionTest(unittest.TestCase):
    def test_session_created_produces_valid_event(self):
        sess = OpenCodeSession("sess_001")
        ev = sess.create_session()
        self.assertEqual(ev.event_type, "session.created")
        self.assertEqual(ev.seq, 1)
        self.assertTrue(ev.durable)

    def test_seq_strictly_increasing(self):
        sess = OpenCodeSession("sess_002")
        sess.create_session()
        sess.start_turn("t1")
        sess.accept_message("hi")
        evs = sess.get_events()
        seqs = [e["seq"] for e in evs]
        self.assertEqual(seqs, list(range(1, len(evs) + 1)))

    def test_duplicate_event_id_raises(self):
        sess = OpenCodeSession("sess_003")
        sess.create_session()
        with self.assertRaises(ValueError):
            sess._seen_event_ids.add("sess_003:2")
            sess._emit("turn.started", payload={})

    def test_valid_event_types_only(self):
        sess = OpenCodeSession("sess_004")
        sess.create_session()
        err = sess.validate_event({"event_type": "bogus", "durable": True, "seq": 2,
                                    "event_id": "x", "session_id": "sess_004"})
        self.assertIn("Unknown event_type", err)

    def test_non_durable_event_rejected(self):
        sess = OpenCodeSession("sess_005")
        sess.create_session()
        err = sess.validate_event({"event_type": "turn.started", "durable": False,
                                    "seq": 2, "event_id": "x", "session_id": "sess_005"})
        self.assertIn("Non-durable", err)

    def test_command_dedup_request_id(self):
        """INV-003-1: same request_id produces idempotent replay."""
        sess = OpenCodeSession("sess_006")
        sess.create_session()
        sess.start_turn("t1")
        result1 = sess.validate_command({
            "command_type": "reply", "request_id": "req_1",
            "session_id": "sess_006", "content": "hello",
        })
        self.assertEqual(result1["status"], "Completed")
        result2 = sess.validate_command({
            "command_type": "reply", "request_id": "req_1",
            "session_id": "sess_006", "content": "hello",
        })
        self.assertTrue(result2.get("idempotent_replay"))

    def test_outcome_unknown_no_retry(self):
        """INV-003-4: OutcomeUnknown turn must NOT auto-retry the failed tool."""
        sess = OpenCodeSession("sess_007")
        sess.create_session()
        sess.start_turn("t1")
        sess.start_tool("grep")
        sess.outcome_unknown("grep", "host crash before durable write")
        self.assertEqual(sess._turn_state, "OutcomeUnknown")
        result = sess.validate_command({
            "command_type": "stop", "request_id": "req_stop",
            "session_id": "sess_007",
        })
        self.assertEqual(result["status"], "Rejected")
        self.assertEqual(result["result"]["error_code"], "ERR_OUTCOME_UNKNOWN")

    def test_permission_first_wins_second_stale(self):
        """INV-003-5: first valid permission_decision wins, second is Stale."""
        sess = OpenCodeSession("sess_008")
        sess.create_session()
        sess.start_turn("t1")
        sess.request_permission("perm_001", "allow")
        result1 = sess.validate_command({
            "command_type": "permission_decision", "request_id": "req_A",
            "session_id": "sess_008", "permission_id": "perm_001",
            "decision": "allow_once",
        })
        self.assertEqual(result1["status"], "Completed")
        result2 = sess.validate_command({
            "command_type": "permission_decision", "request_id": "req_B",
            "session_id": "sess_008", "permission_id": "perm_001",
            "decision": "deny",
        })
        self.assertEqual(result2["status"], "Stale")
        self.assertEqual(result2["result"]["error_code"], "ERR_REQUEST_STALE")

    def test_permission_wrong_id_rejected(self):
        sess = OpenCodeSession("sess_009")
        sess.create_session()
        sess.start_turn("t1")
        sess.request_permission("perm_001", "allow")
        result = sess.validate_command({
            "command_type": "permission_decision", "request_id": "req_wrong",
            "session_id": "sess_009", "permission_id": "perm_OTHER",
            "decision": "allow_once",
        })
        self.assertEqual(result["status"], "Stale")

    def test_snapshot_digest_is_canonical(self):
        """INV-004-1: snapshot digest matches reducer output."""
        sess = OpenCodeSession("sess_010")
        sess.create_session()
        sess.start_turn("t1")
        sess.update_diff("file changed")
        snap = sess.get_snapshot()
        self.assertIn("digest", snap)
        expected = OpenCodeSession._compute_digest(snap)
        self.assertEqual(snap["digest"], expected)

    def test_snapshot_digest_tamper_evident(self):
        sess = OpenCodeSession("sess_011")
        sess.create_session()
        snap = sess.get_snapshot()
        snap_copy = json.loads(json.dumps(snap))
        snap_copy["state_summary"]["session_status"] = "corrupted"
        new_digest = OpenCodeSession._compute_digest(snap_copy)
        self.assertNotEqual(new_digest, snap["digest"])

    def test_gap_detection_marks_stale(self):
        """INV-004-3: event gap transitions to client_freshness=Stale."""
        sess = OpenCodeSession("sess_012")
        events = [
            {"event_type": "session.created", "session_id": "sess_012", "seq": 1,
             "event_id": "sess_012:1", "timestamp": "2026-08-17T10:00:00Z", "durable": True, "payload": {}},
            {"event_type": "turn.started", "session_id": "sess_012", "seq": 2,
             "event_id": "sess_012:2", "timestamp": "2026-08-17T10:00:01Z", "durable": True,
             "turn_id": "t1", "payload": {}},
            {"event_type": "tool.completed", "session_id": "sess_012", "seq": 5,
             "event_id": "sess_012:5", "timestamp": "2026-08-17T10:00:05Z", "durable": True,
             "payload": {"tool_name": "grep"}},
        ]
        applied, gap_to = sess.apply_events(events)
        self.assertIsNotNone(gap_to)
        snapshot = sess.get_snapshot()
        self.assertEqual(snapshot["client_freshness"], "Stale")

    def test_compaction_boundary(self):
        """INV-004-4: compaction boundary marker exists in stream."""
        sess = OpenCodeSession("sess_013")
        sess.create_session()
        sess.start_turn("t1")
        sess.compact()
        sess.start_turn("t2")
        evs = sess.get_events()
        boundary_seqs = [e["seq"] for e in evs if e["event_type"] == "session.compacted"]
        self.assertGreater(len(boundary_seqs), 0)

    def test_record_replay_produces_same_state(self):
        """Record/replay: replay recorded stream converges to same final state."""
        sess1 = OpenCodeSession("sess_014")
        sess1.create_session()
        sess1.start_turn("t1")
        sess1.accept_message("hello")
        sess1.start_tool("ls")
        sess1.complete_tool("ls")
        sess1.update_diff("1 file")
        sess1.complete_turn()
        recorded = sess1.get_events()

        sess2 = OpenCodeSession("sess_014")
        sess2.replay_recorded(recorded)
        self.assertEqual(sess2._turn_state, "Completed")
        self.assertEqual(sess2._seq, sess1._seq)

    def test_snapshot_to_live_after_gap_resolved(self):
        """After gap detection, once all events arrive, freshness becomes Live."""
        sess = OpenCodeSession("sess_015")
        first = [
            {"event_type": "session.created", "session_id": "sess_015", "seq": 1,
             "event_id": "sess_015:1", "timestamp": "2026-08-17T10:00:00Z", "durable": True, "payload": {}},
        ]
        sess.apply_events(first)
        # Simulate gap then replay all
        sess.apply_events([
            {"event_type": "turn.started", "session_id": "sess_015", "seq": 3,
             "event_id": "sess_015:3", "timestamp": "2026-08-17T10:00:01Z", "durable": True,
             "turn_id": "t1", "payload": {}},
        ])
        # Now send missing event 2
        sess.apply_events([
            {"event_type": "turn.started", "session_id": "sess_015", "seq": 2,
             "event_id": "sess_015:2", "timestamp": "2026-08-17T10:00:01Z", "durable": True,
             "turn_id": "t0", "payload": {}},
        ])
        snap = sess.get_snapshot()
        self.assertEqual(snap["client_freshness"], "Live")


if __name__ == "__main__":
    unittest.main()
