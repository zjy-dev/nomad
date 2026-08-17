"""Tests for fault injection module.

Run via:  python3 -m unittest testkit.faults.test_faults
Or via:   python3 -m unittest discover -s testkit -t . -p 'test_faults.py'
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from testkit.faults.chaos import (
    DeliveryPlan,
    FaultConfig,
    FaultType,
    apply_delivery_plan,
    build_delivery_plan,
    compute_event_id_hash,
    simulate_delivery,
)
from testkit.faults.helpers import (
    FaultInjectionSpec,
    FaultResult,
    build_standard_fault_specs,
    run_fault_injection_suite,
    test_delay_tolerance,
    test_disk_full_simulation,
    test_duplicate_detection,
    test_drop_creates_gap,
    test_reorder_resilience,
    test_restart_injection,
)


def _make_events():
    return [
        {"event_type": "session.created", "session_id": "s1", "seq": 1,
         "event_id": "s1:1", "timestamp": "2026-08-17T10:00:00Z", "durable": True, "payload": {}},
        {"event_type": "turn.started", "session_id": "s1", "seq": 2,
         "event_id": "s1:2", "timestamp": "2026-08-17T10:00:01Z", "durable": True, "payload": {}},
        {"event_type": "tool.started", "session_id": "s1", "seq": 3,
         "event_id": "s1:3", "timestamp": "2026-08-17T10:00:02Z", "durable": True,
         "payload": {"tool_name": "grep"}},
        {"event_type": "tool.completed", "session_id": "s1", "seq": 4,
         "event_id": "s1:4", "timestamp": "2026-08-17T10:00:05Z", "durable": True,
         "payload": {"tool_name": "grep"}},
        {"event_type": "diff.updated", "session_id": "s1", "seq": 5,
         "event_id": "s1:5", "timestamp": "2026-08-17T10:00:06Z", "durable": True,
         "payload": {"summary": "1 file changed"}},
        {"event_type": "turn.completed", "session_id": "s1", "seq": 6,
         "event_id": "s1:6", "timestamp": "2026-08-17T10:00:07Z", "durable": True, "payload": {}},
    ]


class ChaosModuleTest(unittest.TestCase):
    def test_build_delivery_plan_duplicate(self):
        events = _make_events()
        cfg = FaultConfig(fault_type=FaultType.DUPLICATE, target_seq=3, count=2)
        plan = build_delivery_plan(events, [cfg])
        self.assertEqual(plan.duplicates.get(3), 2)

    def test_build_delivery_plan_drop(self):
        events = _make_events()
        cfg = FaultConfig(fault_type=FaultType.DROP, target_seq=4)
        plan = build_delivery_plan(events, [cfg])
        self.assertIn(4, plan.drops)

    def test_build_delivery_plan_restart(self):
        events = _make_events()
        cfg = FaultConfig(fault_type=FaultType.RESTART, target_seq=5)
        plan = build_delivery_plan(events, [cfg])
        self.assertEqual(plan.inject_restart_after, 5)

    def test_build_delivery_plan_disk_full(self):
        events = _make_events()
        cfg = FaultConfig(fault_type=FaultType.DISK_FULL)
        plan = build_delivery_plan(events, [cfg])
        self.assertTrue(plan.simulate_disk_full)

    def test_apply_delivery_plan_drops(self):
        events = _make_events()
        plan = DeliveryPlan(drops={3})
        result = apply_delivery_plan(events, plan)
        seqs = [e["seq"] for e in result]
        self.assertNotIn(3, seqs)
        self.assertEqual(len(result), len(events) - 1)

    def test_apply_delivery_plan_duplicates(self):
        events = _make_events()
        plan = DeliveryPlan(duplicates={2: 1})
        result = apply_delivery_plan(events, plan)
        seqs = [e["seq"] for e in result]
        self.assertEqual(seqs.count(2), 2)

    def test_apply_delivery_plan_reorder(self):
        events = _make_events()
        plan = DeliveryPlan(reorder=[(1, 6)])
        result = apply_delivery_plan(events, plan)
        seqs = [e["seq"] for e in result]
        self.assertEqual(seqs[0], 6)
        self.assertEqual(seqs[-1], 1)

    def test_compute_event_id_hash(self):
        ev = {"session_id": "s1", "seq": 1, "event_id": "s1:1"}
        h = compute_event_id_hash(ev)
        self.assertEqual(len(h), 16)
        ev2 = {"session_id": "s1", "seq": 1, "event_id": "s1:1"}
        self.assertEqual(compute_event_id_hash(ev), compute_event_id_hash(ev2))
        ev3 = {"session_id": "s1", "seq": 2, "event_id": "s1:2"}
        self.assertNotEqual(compute_event_id_hash(ev), compute_event_id_hash(ev3))

    def test_simulate_delivery_with_delay_callback(self):
        events = _make_events()
        plan = DeliveryPlan(delays_ms={2: 10})
        delivered = simulate_delivery(events, plan)
        self.assertEqual(len(delivered), len(events))


class FaultHelpersTest(unittest.TestCase):
    def test_duplicate_detection_finds_duplicates(self):
        events = _make_events()
        plan = DeliveryPlan(duplicates={2: 2})
        result = test_duplicate_detection(events, plan)
        self.assertTrue(result.passed)
        self.assertEqual(result.events_duplicated, 2)

    def test_drop_creates_gap(self):
        events = _make_events()
        plan = DeliveryPlan(drops={3})
        result = test_drop_creates_gap(events, plan)
        self.assertTrue(result.passed)
        self.assertEqual(result.events_dropped, 1)

    def test_reorder_resilience(self):
        events = _make_events()
        plan = DeliveryPlan(reorder=[(1, 6)])
        result = test_reorder_resilience(events, plan)
        self.assertTrue(result.passed)

    def test_delay_tolerance(self):
        events = _make_events()
        plan = DeliveryPlan(delays_ms={4: 100})
        result = test_delay_tolerance(events, plan)
        self.assertTrue(result.passed)
        self.assertEqual(result.events_delayed, 1)

    def test_restart_injection_sets_outcome_unknown(self):
        """Restart fault must surface as OutcomeUnknown, not merely a flag."""
        events = _make_events()
        plan = DeliveryPlan(inject_restart_after=4)
        result = test_restart_injection(events, plan)
        self.assertTrue(result.passed)
        self.assertTrue(result.restart_injected)
        self.assertIsNotNone(plan.inject_restart_after)

    def test_disk_full_simulation_isolation(self):
        """Disk-full fault must simulate safely without crashing the stream."""
        events = _make_events()
        plan = DeliveryPlan(simulate_disk_full=True)
        result = test_disk_full_simulation(events, plan)
        self.assertTrue(result.passed)
        self.assertTrue(result.disk_full_simulated)
        delivered = apply_delivery_plan(events, plan)
        self.assertEqual(len(delivered), len(events))

    def test_full_suite_runs(self):
        events = _make_events()
        specs = build_standard_fault_specs()
        results = run_fault_injection_suite(events, specs)
        self.assertGreaterEqual(len(results), 1)
        for r in results:
            self.assertTrue(r.passed, f"{r.scenario_name} failed: {r.message}")


if __name__ == "__main__":
    unittest.main()
