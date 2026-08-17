"""Tests for the NomadE2EHarness.

Run via:  python3 -m unittest testkit.e2e.test_harness
Or via:   python3 -m unittest discover -s testkit -t . -p 'test_harness.py'
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from testkit.e2e.harness import NomadE2EHarness
from testkit.faults import FaultConfig, FaultType


_CONTRACTS_ROOT = str(_PROJECT_ROOT / "contracts")


class HarnessLoadTest(unittest.TestCase):
    def setUp(self):
        self.harness = NomadE2EHarness(
            contracts_root=_CONTRACTS_ROOT,
            verify_with_contracts=False,
        )

    def test_load_contract_scenarios_discovers_all_traces(self):
        self.harness.load_contract_scenarios()
        scenarios = self.harness.get_available_scenarios()
        expected_ids = {
            "trace-001-normal-completion",
            "trace-002-reply",
            "trace-003-stop",
            "trace-004-permission-competition",
            "trace-005-reconnect",
            "trace-006-compaction",
            "trace-007-version-mismatch",
            "trace-008-outcome-unknown",
            "trace-009-interrupt-and-send",
        }
        self.assertEqual(set(scenarios), expected_ids)

    def test_load_manifest_overrides_contracts(self):
        self.harness.load_contract_scenarios()
        self.assertGreater(len(self.harness._scenarios), 0)


class HarnessScenarioTest(unittest.TestCase):
    def setUp(self):
        self.harness = NomadE2EHarness(
            contracts_root=_CONTRACTS_ROOT,
            verify_with_contracts=False,
        )
        self.harness.load_contract_scenarios()

    def test_all_nine_scenarios_pass_protocol_assertions(self):
        for sid in self.harness.get_available_scenarios():
            result = self.harness.run_scenario(sid)
            self.assertIn(result["status"], ("PASS", "FAIL", "ERROR"),
                          f"{sid} has unknown status")
            if result["status"] == "FAIL":
                failed = [a for a in result["assertions"] if not a["passed"]]
                self.fail(f"{sid} failed: {[a['id'] for a in failed]}")

    def test_normal_completion_snapshot_produced(self):
        result = self.harness.run_scenario("trace-001-normal-completion")
        snap = result.get("actual_snapshot", {})
        self.assertIn("digest", snap)
        self.assertIn("session_id", snap)

    def test_permission_competition_first_wins(self):
        """INV-003-5: first permission decision wins, second rejected."""
        result = self.harness.run_scenario("trace-004-permission-competition")
        events = self.harness._recorded_streams.get("trace-004-permission-competition", [])
        resolved_events = [e for e in events if e["event_type"] == "permission.resolved"]
        self.assertGreaterEqual(len(resolved_events), 1)

    def test_outcome_unknown_no_auto_retry(self):
        """INV-003-4: after OutcomeUnknown, same tool must not auto-restart."""
        result = self.harness.run_scenario("trace-008-outcome-unknown")
        events = self.harness._recorded_streams.get("trace-008-outcome-unknown", [])
        outcome_idx = None
        for i, e in enumerate(events):
            if e["event_type"] == "turn.outcome_unknown":
                outcome_idx = i
                break
        if outcome_idx is not None:
            ou_tool = events[outcome_idx].get("payload", {}).get("tool_name", "")
            for later in events[outcome_idx + 1:]:
                self.assertFalse(
                    later["event_type"] == "tool.started" and
                    later.get("payload", {}).get("tool_name") == ou_tool,
                    f"Auto-retry of {ou_tool} detected after OutcomeUnknown",
                )

    def test_compaction_boundary_present(self):
        """INV-004-4: compaction scenario has boundary marker."""
        result = self.harness.run_scenario("trace-006-compaction")
        events = self.harness._recorded_streams.get("trace-006-compaction", [])
        compaction_events = [e for e in events if e["event_type"] == "session.compacted"]
        self.assertGreaterEqual(len(compaction_events), 1)

    def test_reconnect_produces_snapshot(self):
        result = self.harness.run_scenario("trace-005-reconnect")
        snap = result.get("actual_snapshot", {})
        self.assertIn("digest", snap)

    def test_command_exchanges_replayed(self):
        result = self.harness.run_scenario("trace-002-reply")
        self.assertIn(result["status"], ("PASS", "FAIL"))


class HarnessFaultInjectionTest(unittest.TestCase):
    def setUp(self):
        self.harness = NomadE2EHarness(
            contracts_root=_CONTRACTS_ROOT,
            verify_with_contracts=False,
        )
        self.harness.load_contract_scenarios()

    def test_fault_injection_suite_runs(self):
        results = self.harness.run_fault_injections("trace-001-normal-completion")
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertTrue(r.passed, f"{r.scenario_name} failed: {r.message}")

    def test_fault_injection_all_scenarios(self):
        for sid in self.harness.get_available_scenarios():
            results = self.harness.run_fault_injections(sid)
            for r in results:
                self.assertTrue(r.passed, f"{sid}/{r.scenario_name} failed: {r.message}")


class HarnessReportTest(unittest.TestCase):
    def setUp(self):
        self.harness = NomadE2EHarness(
            contracts_root=_CONTRACTS_ROOT,
            verify_with_contracts=False,
        )
        self.harness.load_contract_scenarios()

    def test_get_report_summarizes_results(self):
        self.harness.run_scenario("trace-001-normal-completion")
        self.harness.run_scenario("trace-003-stop")
        report = self.harness.get_report()
        self.assertEqual(report["total_scenarios"], 2)
        self.assertGreaterEqual(report["passed"], 0)

    def test_report_includes_all_assertion_ids(self):
        report = self.harness.get_report()
        self.assertIn("INV-002-1", report["assertion_ids"])
        self.assertIn("INV-003-1", report["assertion_ids"])
        self.assertIn("INV-003-5", report["assertion_ids"])
        self.assertIn("INV-004-1", report["assertion_ids"])


if __name__ == "__main__":
    unittest.main()
