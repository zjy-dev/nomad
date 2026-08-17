"""testkit.faults: Chaos fault injection for Nomad E2E."""

from .chaos import (
    DeliveryPlan,
    FaultConfig,
    FaultType,
    apply_delivery_plan,
    build_delivery_plan,
    compute_event_id_hash,
    simulate_delivery,
)
from .helpers import (
    FaultInjectionSpec,
    FaultResult,
    build_standard_fault_specs,
    run_fault_injection_suite,
    test_duplicate_detection,
    test_delay_tolerance,
    test_disk_full_simulation,
    test_drop_creates_gap,
    test_reorder_resilience,
    test_restart_injection,
)

__all__ = [
    "DeliveryPlan",
    "FaultConfig",
    "FaultType",
    "FaultInjectionSpec",
    "FaultResult",
    "apply_delivery_plan",
    "build_delivery_plan",
    "build_standard_fault_specs",
    "compute_event_id_hash",
    "run_fault_injection_suite",
    "simulate_delivery",
    "test_duplicate_detection",
    "test_delay_tolerance",
    "test_disk_full_simulation",
    "test_drop_creates_gap",
    "test_reorder_resilience",
    "test_restart_injection",
]
