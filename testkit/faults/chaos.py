"""Chaos fault injection for Nomad E2E tests.

Faults can be applied at the transport layer (record/replay delivery)
or at the protocol layer (semantic tampering of events/commands).
All faults are deterministic and reproducible.
"""

from __future__ import annotations

import copy
import enum
import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


class FaultType(str, enum.Enum):
    """Kinds of faults the harness can inject."""
    DUPLICATE = "duplicate"
    REORDER = "reorder"
    DROP = "drop"
    DELAY = "delay"
    RESTART = "restart"
    DISK_FULL = "disk_full"


@dataclass
class FaultConfig:
    """Configuration for a single fault injection."""
    fault_type: FaultType
    target_seq: Optional[int] = None
    count: int = 1
    delay_ms: int = 0
    seed: int = 42
    description: str = ""


@dataclass
class DeliveryPlan:
    """A deterministic mutation of an event stream."""
    duplicates: Dict[int, int] = field(default_factory=dict)
    reorder: List[Tuple[int, int]] = field(default_factory=list)
    drops: set = field(default_factory=set)
    delays_ms: Dict[int, int] = field(default_factory=dict)
    inject_restart_after: Optional[int] = None
    simulate_disk_full: bool = False


def build_delivery_plan(events: List[Dict[str, Any]], configs: List[FaultConfig]) -> DeliveryPlan:
    """Apply a sequence of fault configs to produce a deterministic delivery plan.

    Each config operates on the stream in order. Earlier configs see the
    original seq numbers; the plan captures the cumulative transformation.

    When target_seq is set but the stream is too short (e.g. a 2-event
    trace requesting seq 5), the fault falls back to a valid seq from the
    stream using a deterministic rule (last applicable seq). This keeps the
    injection meaningful instead of silently failing.
    """
    rng = random.Random(42)
    plan = DeliveryPlan()
    seq_to_index: Dict[int, int] = {}
    for idx, ev in enumerate(events):
        seq = ev["seq"]
        seq_to_index[seq] = idx
    available_seqs = list(seq_to_index.keys())
    if not available_seqs:
        return plan

    def _resolve(target: Optional[int], rng: random.Random,
                 prefer_inner: bool = False) -> int:
        if target is not None and target in seq_to_index:
            return target
        if target is not None and target > max(available_seqs):
            return max(available_seqs)
        if prefer_inner and len(available_seqs) >= 3:
            return rng.choice(available_seqs[1:-1])
        if prefer_inner and len(available_seqs) >= 2:
            return available_seqs[1]
        return rng.choice(available_seqs)

    for cfg in configs:
        rng = random.Random(cfg.seed)
        if cfg.fault_type == FaultType.DUPLICATE:
            target = _resolve(cfg.target_seq, rng)
            count = cfg.count
            plan.duplicates[target] = plan.duplicates.get(target, 0) + count
        elif cfg.fault_type == FaultType.REORDER:
            indices = available_seqs
            if len(indices) >= 2:
                idx_a = rng.randrange(len(indices))
                idx_b = rng.randrange(len(indices))
                while idx_b == idx_a:
                    idx_b = rng.randrange(len(indices))
                plan.reorder.append((indices[idx_a], indices[idx_b]))
        elif cfg.fault_type == FaultType.DROP:
            target = _resolve(cfg.target_seq, rng, prefer_inner=True)
            plan.drops.add(target)
        elif cfg.fault_type == FaultType.DELAY:
            target = _resolve(cfg.target_seq, rng)
            plan.delays_ms[target] = cfg.delay_ms or rng.randint(100, 2000)
        elif cfg.fault_type == FaultType.RESTART:
            target = _resolve(cfg.target_seq, rng, prefer_inner=True)
            plan.inject_restart_after = target
        elif cfg.fault_type == FaultType.DISK_FULL:
            plan.simulate_disk_full = True
    return plan


def apply_delivery_plan(events: List[Dict[str, Any]], plan: DeliveryPlan) -> List[Dict[str, Any]]:
    """Apply a delivery plan to an event list and return the transformed stream.

    Duplicates emit the same event object at the same seq twice (simulating
    re-delivery).  Reordering swaps the delivery order of two events (the
    seq number inside the event remains unchanged).  Drops remove the event
    from the stream entirely.
    """
    result: List[Dict[str, Any]] = []
    seq_to_event: Dict[int, Dict[str, Any]] = {}
    for ev in events:
        seq_to_event[ev["seq"]] = ev

    for ev in events:
        seq = ev["seq"]
        if seq in plan.drops:
            continue
        result.append(copy.deepcopy(ev))
        dup_count = plan.duplicates.get(seq, 0)
        for _ in range(dup_count):
            dup = copy.deepcopy(ev)
            result.append(dup)

    for seq_a, seq_b in plan.reorder:
        idx_a = None
        idx_b = None
        for i, ev in enumerate(result):
            if ev["seq"] == seq_a and idx_a is None:
                idx_a = i
            if ev["seq"] == seq_b and idx_b is None:
                idx_b = i
        if idx_a is not None and idx_b is not None:
            result[idx_a], result[idx_b] = result[idx_b], result[idx_a]

    return result


def simulate_delivery(
    events: List[Dict[str, Any]],
    plan: DeliveryPlan,
    on_delivery: Optional[Callable[[Dict[str, Any], int], None]] = None,
) -> List[Dict[str, Any]]:
    """Deliver events according to plan, optionally invoking a callback per event.

    Returns the list of actually delivered events (accounting for drops).
    """
    delivered: List[Dict[str, Any]] = []
    for ev in apply_delivery_plan(events, plan):
        seq = ev["seq"]
        delay = plan.delays_ms.get(seq, 0)
        if delay:
            time.sleep(delay / 1000.0)
        delivered.append(ev)
        if on_delivery:
            on_delivery(ev, delay)
    return delivered


def compute_event_id_hash(event: Dict[str, Any]) -> str:
    """Compute a deterministic hash for duplicate detection."""
    key = f"{event.get('session_id', '')}:{event.get('seq', '')}:{event.get('event_id', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
