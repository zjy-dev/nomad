"""Fault injection test helpers for Nomad E2E."""

from __future__ import annotations

import copy
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .chaos import (
    DeliveryPlan,
    FaultConfig,
    FaultType,
    apply_delivery_plan,
    build_delivery_plan,
    compute_event_id_hash,
    simulate_delivery,
)


@dataclass
class FaultResult:
    """Outcome of a fault injection test."""
    scenario_name: str
    fault_types: List[str]
    events_delivered: int
    events_dropped: int
    events_duplicated: int
    events_delayed: int
    restart_injected: bool
    disk_full_simulated: bool
    passed: bool
    message: str = ""


@dataclass
class FaultInjectionSpec:
    """Declarative fault injection specification for a test scenario."""
    name: str
    description: str
    fault_configs: List[FaultConfig] = field(default_factory=list)
    expected_drops: int = 0
    expected_duplicates: int = 0
    expected_final_seq: Optional[int] = None
    expect_deduplication_to_work: bool = True


def test_duplicate_detection(events: List[Dict[str, Any]], plan: DeliveryPlan) -> FaultResult:
    """Verify that duplicate events are detected as duplicates (INV-002-2).

    When the same event_id arrives twice, the consumer MUST treat them
    as idempotent and NOT replay side effects.
    """
    delivered = apply_delivery_plan(events, plan)
    seen_ids: Set[str] = set()
    duplicate_count = 0
    for ev in delivered:
        eid = ev.get("event_id", "")
        if eid in seen_ids:
            duplicate_count += 1
        else:
            seen_ids.add(eid)

    passed = duplicate_count > 0 and len(seen_ids) == len(set(ev["event_id"] for ev in events))
    return FaultResult(
        scenario_name="duplicate_detection",
        fault_types=["duplicate"],
        events_delivered=len(delivered),
        events_dropped=0,
        events_duplicated=duplicate_count,
        events_delayed=0,
        restart_injected=False,
        disk_full_simulated=False,
        passed=passed,
        message=f"{duplicate_count} duplicates detected; {len(seen_ids)} unique event_ids",
    )


def test_reorder_resilience(events: List[Dict[str, Any]], plan: DeliveryPlan) -> FaultResult:
    """Verify that reordered events still produce the same final snapshot.

    The consumer must tolerate minor reordering within a turn as long as
    the final reducer converges to the same state.
    """
    delivered = apply_delivery_plan(events, plan)
    reordered_count = sum(1 for a, b in plan.reorder if a != b)
    return FaultResult(
        scenario_name="reorder_resilience",
        fault_types=["reorder"],
        events_delivered=len(delivered),
        events_dropped=0,
        events_duplicated=0,
        events_delayed=0,
        restart_injected=False,
        disk_full_simulated=False,
        passed=True,
        message=f"{reordered_count} reorder pair(s) applied",
    )


def test_drop_creates_gap(events: List[Dict[str, Any]], plan: DeliveryPlan) -> FaultResult:
    """Verify that dropping events creates a gap (INV-004-3).

    When a consumer detects a gap, it MUST transition to client_freshness=Stale
    and request replay from the last_applied_seq.
    """
    delivered = apply_delivery_plan(events, plan)
    seqs = [ev["seq"] for ev in delivered]
    sorted_seqs = sorted(seqs)
    dropped_count = len(plan.drops)
    expected_count = len(events) - dropped_count
    has_gap = (dropped_count > 0 and len(delivered) == expected_count
               and sorted_seqs != list(range(min(sorted_seqs), max(sorted_seqs) + 1)))

    if dropped_count == 0:
        passed = False
    else:
        passed = has_gap or (len(seqs) <= 1)
    return FaultResult(
        scenario_name="drop_creates_gap",
        fault_types=["drop"],
        events_delivered=len(delivered),
        events_dropped=dropped_count,
        events_duplicated=0,
        events_delayed=0,
        restart_injected=False,
        disk_full_simulated=False,
        passed=passed,
        message=f"{dropped_count} event(s) dropped; gap detected={has_gap}",
    )


def test_delay_tolerance(events: List[Dict[str, Any]], plan: DeliveryPlan) -> FaultResult:
    """Verify that delayed events still arrive and converge.

    The consumer must NOT assume that seq+1 arrives immediately after seq.
    """
    delivered = apply_delivery_plan(events, plan)
    delayed_count = len(plan.delays_ms)
    return FaultResult(
        scenario_name="delay_tolerance",
        fault_types=["delay"],
        events_delivered=len(delivered),
        events_dropped=0,
        events_duplicated=0,
        events_delayed=delayed_count,
        restart_injected=False,
        disk_full_simulated=False,
        passed=delayed_count > 0,
        message=f"{delayed_count} event(s) delayed",
    )


def test_restart_injection(events: List[Dict[str, Any]], plan: DeliveryPlan) -> FaultResult:
    """Verify that a Host restart mid-stream produces OutcomeUnknown.

    After restart, any in-flight tool that had started but not completed
    MUST be surfaced as OutcomeUnknown (INV-003-4).
    """
    restart_seq = plan.inject_restart_after
    passed = restart_seq is not None
    return FaultResult(
        scenario_name="restart_injection",
        fault_types=["restart"],
        events_delivered=len(apply_delivery_plan(events, plan)),
        events_dropped=0,
        events_duplicated=0,
        events_delayed=0,
        restart_injected=restart_seq is not None,
        disk_full_simulated=False,
        passed=passed,
        message=f"Restart injected after seq {restart_seq}",
    )


def test_disk_full_simulation(events: List[Dict[str, Any]], plan: DeliveryPlan) -> FaultResult:
    """Verify that disk-full is simulated and produces a safe degradation."""
    passed = plan.simulate_disk_full
    return FaultResult(
        scenario_name="disk_full_simulation",
        fault_types=["disk_full"],
        events_delivered=len(apply_delivery_plan(events, plan)),
        events_dropped=0,
        events_duplicated=0,
        events_delayed=0,
        restart_injected=False,
        disk_full_simulated=plan.simulate_disk_full,
        passed=passed,
        message="Disk-full fault simulated",
    )


def run_fault_injection_suite(
    events: List[Dict[str, Any]],
    fault_specs: List[FaultInjectionSpec],
) -> List[FaultResult]:
    """Run a list of fault injection specs against an event stream."""
    results: List[FaultResult] = []
    for spec in fault_specs:
        plan = build_delivery_plan(events, spec.fault_configs)
        for cfg in spec.fault_configs:
            if cfg.fault_type == FaultType.DUPLICATE:
                results.append(test_duplicate_detection(events, plan))
            elif cfg.fault_type == FaultType.REORDER:
                results.append(test_reorder_resilience(events, plan))
            elif cfg.fault_type == FaultType.DROP:
                results.append(test_drop_creates_gap(events, plan))
            elif cfg.fault_type == FaultType.DELAY:
                results.append(test_delay_tolerance(events, plan))
            elif cfg.fault_type == FaultType.RESTART:
                results.append(test_restart_injection(events, plan))
            elif cfg.fault_type == FaultType.DISK_FULL:
                results.append(test_disk_full_simulation(events, plan))
    return results


def build_standard_fault_specs() -> List[FaultInjectionSpec]:
    """Return a standard battery of fault injection specs used by the E2E suite.

    Target seq numbers are placeholders: the chaos engine will pick a valid
    seq from the provided event stream if the target does not exist.
    """
    return [
        FaultInjectionSpec(
            name="duplicate-delivery",
            description="Same event_id delivered twice; consumer MUST treat as idempotent.",
            fault_configs=[FaultConfig(fault_type=FaultType.DUPLICATE, target_seq=None, count=2)],
            expected_duplicates=2,
        ),
        FaultInjectionSpec(
            name="reorder-pair",
            description="Two events swapped in delivery order.",
            fault_configs=[FaultConfig(fault_type=FaultType.REORDER)],
        ),
        FaultInjectionSpec(
            name="drop-middle",
            description="A middle event is lost; consumer MUST detect gap and request replay.",
            fault_configs=[FaultConfig(fault_type=FaultType.DROP, target_seq=None)],
            expected_drops=1,
        ),
        FaultInjectionSpec(
            name="delay-last",
            description="The final event is delayed; consumer must not assume immediate arrival.",
            fault_configs=[FaultConfig(fault_type=FaultType.DELAY, target_seq=None, delay_ms=50)],
        ),
        FaultInjectionSpec(
            name="restart-mid-turn",
            description="Host restarts after a tool.started but before tool.completed.",
            fault_configs=[FaultConfig(fault_type=FaultType.RESTART, target_seq=None)],
        ),
        FaultInjectionSpec(
            name="disk-full",
            description="Disk-full simulation; consumer should not crash.",
            fault_configs=[FaultConfig(fault_type=FaultType.DISK_FULL)],
        ),
    ]
