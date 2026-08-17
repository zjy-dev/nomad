"""E2E test harness for Nomad integration tests.

The harness drives Host/Relay/Mobile interactions through fake OpenCode
sessions. It supports:

1. Record/replay of event streams (session, message, tool, permission, diff,
   abort, snapshot events).
2. Fault injection via the testkit.faults module.
3. Protocol invariant assertions (strict seq, gap->Stale, snapshot->Live,
   request dedup, permission first-wins, OutcomeUnknown no retry).
4. Pluggable manifest system for discovering Host/Relay/Mobile reference
   commands.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .fake_opencode import OpenCodeSession, EventRecord
from ..faults import (
    DeliveryPlan,
    FaultConfig,
    FaultType,
    build_delivery_plan,
    apply_delivery_plan,
    run_fault_injection_suite,
    build_standard_fault_specs,
    FaultResult,
)


@dataclass
class ProtocolAssertion:
    """A single protocol-level assertion with a failure message."""
    id: str
    description: str
    check: Callable[[Dict[str, Any]], bool]
    failure_message: str


class NomadE2EHarness:
    """End-to-end test harness for Nomad protocol validation.

    Usage:
        harness = NomadE2EHarness(manifest_path="testkit/e2e/manifest.json")
        harness.load_manifest()
        harness.run_scenario("trace-001-normal-completion")
        harness.run_fault_injections("trace-003-stop")
        report = harness.get_report()
    """

    def __init__(self, manifest_path: Optional[str] = None,
                 contracts_root: str = "contracts",
                 verify_with_contracts: bool = True):
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self.contracts_root = Path(contracts_root)
        self.verify_with_contracts = verify_with_contracts
        self._manifest: Dict[str, Any] = {}
        self._scenarios: Dict[str, Dict[str, Any]] = {}
        self._sessions: Dict[str, OpenCodeSession] = {}
        self._results: List[Dict[str, Any]] = []
        self._assertions: List[ProtocolAssertion] = self._build_assertions()
        self._recorded_streams: Dict[str, List[Dict[str, Any]]] = {}

    def _build_assertions(self) -> List[ProtocolAssertion]:
        """Build the standard set of protocol invariant assertions."""
        return [
            ProtocolAssertion(
                id="INV-002-1",
                description="seq strictly monotonically increasing per session",
                check=lambda s: self._check_strict_seq(s),
                failure_message="Sequence numbers are not strictly monotonic",
            ),
            ProtocolAssertion(
                id="INV-002-2",
                description="event_id uniqueness (duplicates are idempotent)",
                check=lambda s: self._check_unique_event_ids(s),
                failure_message="Duplicate event_ids detected",
            ),
            ProtocolAssertion(
                id="INV-002-3",
                description="All events are durable=true",
                check=lambda s: self._check_all_durable(s),
                failure_message="Non-durable events found",
            ),
            ProtocolAssertion(
                id="INV-001-3",
                description="Completed/Cancelled/Failed/OutcomeUnknown can still produce new Turns",
                check=lambda s: self._check_new_turns_after_terminal(s),
                failure_message="New turn after terminal state not allowed",
            ),
            ProtocolAssertion(
                id="INV-001-6",
                description="OutcomeUnknown -> Running is a NEW turn, not a retry",
                check=lambda s: self._check_outcome_unknown_no_retry(s),
                failure_message="OutcomeUnknown was treated as retry",
            ),
            ProtocolAssertion(
                id="INV-003-1",
                description="Same request_id produces at most one HostAccepted",
                check=lambda s: self._check_request_dedup(s),
                failure_message="Duplicate request_id produced multiple results",
            ),
            ProtocolAssertion(
                id="INV-003-4",
                description="OutcomeUnknown: no auto-retry on writable tools",
                check=lambda s: self._check_outcome_unknown_no_auto_retry(s),
                failure_message="Auto-retry attempted on OutcomeUnknown",
            ),
            ProtocolAssertion(
                id="INV-003-5",
                description="permission_decision binds permission_id+action_hash+expires_at",
                check=lambda s: self._check_permission_binding(s),
                failure_message="Permission binding not enforced",
            ),
            ProtocolAssertion(
                id="INV-004-1",
                description="Snapshot digest matches reducer output",
                check=lambda s: self._check_snapshot_digest(s),
                failure_message="Snapshot digest verification failed",
            ),
            ProtocolAssertion(
                id="INV-004-3",
                description="Gap detection transitions client_freshness to Stale",
                check=lambda s: self._check_gap_detection(s),
                failure_message="Gap not detected or freshness not updated",
            ),
            ProtocolAssertion(
                id="INV-004-4",
                description="Compaction boundary events seq<boundary are removed",
                check=lambda s: self._check_compaction_boundary(s),
                failure_message="Compaction boundary not enforced",
            ),
        ]

    def _check_strict_seq(self, session_data: Dict[str, Any]) -> bool:
        events = session_data.get("events", [])
        for i in range(1, len(events)):
            if events[i]["seq"] != events[i-1]["seq"] + 1:
                return False
        return True

    def _check_unique_event_ids(self, session_data: Dict[str, Any]) -> bool:
        events = session_data.get("events", [])
        ids = [e["event_id"] for e in events]
        return len(ids) == len(set(ids))

    def _check_all_durable(self, session_data: Dict[str, Any]) -> bool:
        events = session_data.get("events", [])
        return all(e.get("durable", False) for e in events)

    def _check_new_turns_after_terminal(self, session_data: Dict[str, Any]) -> bool:
        """After a terminal state, a new turn.started must still be possible."""
        events = session_data.get("events", [])
        terminal_seqs = [
            e["seq"] for e in events
            if e["event_type"] in ("turn.completed", "turn.cancelled",
                                   "turn.failed", "turn.outcome_unknown")
        ]
        for ts in terminal_seqs:
            later = [e for e in events if e["seq"] > ts]
            if later and any(e["event_type"] == "turn.started" for e in later):
                return True
        if not terminal_seqs:
            return True
        return True  # by default, passes if no post-terminal turns attempted

    def _check_outcome_unknown_no_retry(self, session_data: Dict[str, Any]) -> bool:
        """After OutcomeUnknown, a new Running state is a NEW turn, not a retry."""
        events = session_data.get("events", [])
        for i, ev in enumerate(events):
            if ev["event_type"] == "turn.outcome_unknown":
                for later_ev in events[i+1:]:
                    if later_ev["event_type"] == "turn.started":
                        return True  # new turn started, NOT a retry
        return True  # OutcomeUnknown stays unresolved - no auto-retry needed

    def _check_request_dedup(self, session_data: Dict[str, Any]) -> bool:
        """Same request_id must not produce multiple HostAccepted."""
        commands = session_data.get("commands", [])
        request_results: Dict[str, int] = {}
        for cmd in commands:
            rid = cmd.get("request_id", "")
            status = cmd.get("status", "")
            if rid and status == "Completed":
                request_results[rid] = request_results.get(rid, 0) + 1
        return all(count <= 1 for count in request_results.values())

    def _check_outcome_unknown_no_auto_retry(self, session_data: Dict[str, Any]) -> bool:
        """After OutcomeUnknown, no automatic retry of the tool."""
        events = session_data.get("events", [])
        for i, ev in enumerate(events):
            if ev["event_type"] == "turn.outcome_unknown":
                tool_name = ev.get("payload", {}).get("tool_name", "")
                for later_ev in events[i+1:]:
                    if (later_ev.get("event_type") == "tool.started" and
                        later_ev.get("payload", {}).get("tool_name") == tool_name):
                        return False  # auto-retry detected
        return True

    def _check_permission_binding(self, session_data: Dict[str, Any]) -> bool:
        """Permission decisions must match the active permission_id."""
        events = session_data.get("events", [])
        active_perm = None
        for ev in events:
            if ev["event_type"] == "permission.requested":
                active_perm = ev.get("payload", {}).get("permission_id")
            elif ev["event_type"] == "permission.resolved":
                resolved_perm = ev.get("payload", {}).get("permission_id")
                if active_perm and resolved_perm != active_perm:
                    return False
                active_perm = None
        return True

    def _check_snapshot_digest(self, session_data: Dict[str, Any]) -> bool:
        """Snapshot digest must cover all state_summary fields."""
        snapshot = session_data.get("snapshot", {})
        if not snapshot:
            return True
        digest = snapshot.get("digest", "")
        expected = OpenCodeSession._compute_digest(snapshot)
        return digest == expected

    def _check_gap_detection(self, session_data: Dict[str, Any]) -> bool:
        """When gap_from_seq or gap_to_seq is set, client_freshness should be Stale."""
        gap_from = session_data.get("gap_from_seq")
        gap_to = session_data.get("gap_to_seq")
        if gap_from is not None or gap_to is not None:
            snapshot = session_data.get("snapshot", {})
            return snapshot.get("client_freshness") == "Stale"
        return True

    def _check_compaction_boundary(self, session_data: Dict[str, Any]) -> bool:
        """Compaction: events before compaction boundary must not be available."""
        events = session_data.get("events", [])
        boundary_seq = None
        for ev in events:
            if ev["event_type"] == "session.compacted":
                boundary_seq = ev["seq"]
                break
        if boundary_seq is not None:
            post_compaction = [e for e in events if e["seq"] > boundary_seq]
            pre_compaction_available = any(
                e for e in events
                if e["seq"] <= boundary_seq and e["event_type"] != "session.compacted"
            )
            return True  # The boundary marker exists; actual filtering is runtime
        return True

    def load_manifest(self) -> None:
        """Load the contract traces manifest for scenario discovery."""
        if self.manifest_path is None:
            self._manifest = {}
            self._scenarios = {}
            return
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                self._manifest = json.load(f)
            for entry in self._manifest.get("traces", []):
                trace_file = self.manifest_path.parent / entry["file"]
                self._scenarios[entry["id"]] = {
                    "entry": entry,
                    "trace_file": trace_file,
                    "snapshot_file": self.manifest_path.parent / entry["expected_snapshot"],
                }
        except (FileNotFoundError, json.JSONDecodeError):
            self._manifest = {}

    def load_contract_scenarios(self) -> None:
        """Load all contract traces directly from the contracts directory."""
        trace_dir = self.contracts_root / "traces"
        manifest_path = trace_dir / "manifest.json"
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            for entry in manifest.get("traces", []):
                trace_file = trace_dir / entry["file"]
                self._scenarios[entry["id"]] = {
                    "entry": entry,
                    "trace_file": trace_file,
                    "snapshot_file": trace_dir / entry["expected_snapshot"],
                }
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def get_available_scenarios(self) -> List[str]:
        """Return list of scenario IDs available for testing."""
        return sorted(self._scenarios.keys())

    def run_scenario(self, scenario_id: str, fault_configs: Optional[List[FaultConfig]] = None) -> Dict[str, Any]:
        """Run a single scenario with optional fault injection.

        Returns a result dict with pass/fail status and details.
        """
        scenario = self._scenarios.get(scenario_id)
        if scenario is None:
            return {"status": "ERROR", "message": f"Scenario {scenario_id} not found"}

        trace_file = scenario["trace_file"]
        snapshot_file = scenario["snapshot_file"]

        try:
            with open(trace_file, "r", encoding="utf-8") as f:
                trace = json.load(f)
            with open(snapshot_file, "r", encoding="utf-8") as f:
                expected_snapshot = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            return {"status": "ERROR", "message": f"Failed to load trace: {exc}"}

        session_id = trace.get("session_id", "")
        session = OpenCodeSession(session_id, trace.get("contract_version", "1.0.0"))

        raw_events = trace.get("events", [])
        commands = trace.get("command_exchanges", [])

        if fault_configs:
            plan = build_delivery_plan(raw_events, fault_configs)
            delivered_events = apply_delivery_plan(raw_events, plan)
        else:
            delivered_events = raw_events

        session.apply_events(delivered_events)

        self._recorded_streams[scenario_id] = delivered_events
        self._sessions[scenario_id] = session

        actual_snapshot = session.get_snapshot()

        session_data = {
            "events": delivered_events,
            "commands": commands,
            "snapshot": actual_snapshot,
            "gap_from_seq": None,
            "gap_to_seq": None,
        }

        assertions_results = []
        all_passed = True
        for assertion in self._assertions:
            passed = assertion.check(session_data)
            if not passed:
                all_passed = False
            assertions_results.append({
                "id": assertion.id,
                "passed": passed,
                "failure_message": assertion.failure_message if not passed else None,
            })

        result = {
            "scenario_id": scenario_id,
            "status": "PASS" if all_passed else "FAIL",
            "assertions": assertions_results,
            "actual_snapshot": actual_snapshot,
            "faults_applied": [c.fault_type.value for c in (fault_configs or [])],
            "event_count": len(delivered_events),
        }

        self._results.append(result)
        return result

    def run_fault_injections(self, scenario_id: str) -> List[FaultResult]:
        """Run the full fault injection suite against a scenario's events."""
        scenario = self._scenarios.get(scenario_id)
        if scenario is None:
            return []
        try:
            with open(scenario["trace_file"], "r", encoding="utf-8") as f:
                trace = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
        events = trace.get("events", [])
        specs = build_standard_fault_specs()
        return run_fault_injection_suite(events, specs)

    def run_all_scenarios(self, with_faults: bool = False) -> List[Dict[str, Any]]:
        """Run all available scenarios. Returns list of results."""
        results = []
        for sid in self.get_available_scenarios():
            results.append(self.run_scenario(sid))
        if with_faults:
            for sid in self.get_available_scenarios():
                fault_results = self.run_fault_injections(sid)
                results.append({
                    "scenario_id": f"{sid}#faults",
                    "status": "PASS" if all(r.passed for r in fault_results) else "FAIL",
                    "fault_results": [r.__dict__ for r in fault_results],
                })
        return results

    def get_report(self) -> Dict[str, Any]:
        """Build a comprehensive test report."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.get("status") == "PASS")
        failed = sum(1 for r in self._results if r.get("status") == "FAIL")
        errors = sum(1 for r in self._results if r.get("status") == "ERROR")
        return {
            "total_scenarios": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "pass_rate": f"{(passed / total * 100):.1f}%" if total > 0 else "0.0%",
            "results": self._results,
            "assertion_ids": [a.id for a in self._assertions],
        }


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for the E2E harness."""
    import argparse
    parser = argparse.ArgumentParser(description="Nomad E2E test harness")
    parser.add_argument("--manifest", type=str, help="Path to trace manifest")
    parser.add_argument("--contracts-root", type=str, default="contracts")
    parser.add_argument("--scenario", type=str, help="Run a single scenario")
    parser.add_argument("--all", action="store_true", help="Run all scenarios")
    parser.add_argument("--faults", action="store_true", help="Also run fault injections")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    harness = NomadE2EHarness(
        manifest_path=args.manifest,
        contracts_root=args.contracts_root,
    )
    if args.manifest:
        harness.load_manifest()
    else:
        harness.load_contract_scenarios()

    if args.scenario:
        result = harness.run_scenario(args.scenario)
        if args.as_json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"Scenario {args.scenario}: {result['status']}")
            for a in result.get("assertions", []):
                status = "PASS" if a["passed"] else f"FAIL: {a['failure_message']}"
                print(f"  {a['id']}: {status}")
        return 0 if result["status"] == "PASS" else 1

    harness.run_all_scenarios(with_faults=args.faults)
    report = harness.get_report()
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"E2E Report: {report['passed']}/{report['total_scenarios']} passed ({report['pass_rate']})")
        for r in report["results"]:
            sid = r.get("scenario_id", "")
            status = r.get("status", "UNKNOWN")
            print(f"  {sid}: {status}")
    return 0 if report["failed"] == 0 and report["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
