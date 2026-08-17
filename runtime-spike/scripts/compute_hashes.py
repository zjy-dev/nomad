#!/usr/bin/env python3
"""Compute preregistration hashes for RT-001.

This script produces the `workload_set_hash` by hashing the canonical
order of workload IDs, the baseline release, and the SQLite PRAGMA
dump. Any change to these inputs invalidates the hash and requires a
new preregistration.

Usage:
    python3 compute_hashes.py [--workloads-dir runtime-spike/workloads]
"""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path


def _load_preregistered(workloads_dir: Path) -> dict:
    import yaml
    yaml_path = workloads_dir / "preregistered.yaml"
    with open(yaml_path) as f:
        return yaml.safe_load(f)


def _canonical_inputs(prereg: dict) -> bytes:
    """Produce the canonical byte string for hashing.

    Order:
      1. number of workloads
      2. each workload ID in the order they appear in the YAML
      3. baseline opencode_release
      4. sorted key-value pairs of sqlite_pragma
    """
    parts = []
    workloads = prereg.get("workloads", [])
    parts.append(f"workload_count={len(workloads)}")
    for w in workloads:
        parts.append(f"workload_id={w['id']}")
        parts.append(f"workload_weight={w['weight']}")

    baseline = prereg.get("baseline", {})
    parts.append(f"baseline_opencode_release={baseline.get('opencode_release', '')}")

    pragma = baseline.get("sqlite_pragma", {})
    for key in sorted(pragma.keys()):
        parts.append(f"pragma_{key}={pragma[key]}")

    return "\n".join(parts).encode("utf-8")


def compute_workload_set_hash(prereg: dict) -> str:
    canonical = _canonical_inputs(prereg)
    return hashlib.sha256(canonical).hexdigest()


def write_preregistration_report(workloads_dir: Path) -> Path:
    prereg = _load_preregistered(workloads_dir)
    wsh = compute_workload_set_hash(prereg)

    # Build the report
    report = {
        "version": prereg.get("version", 1),
        "preregistered_at": prereg.get("preregistered_at", ""),
        "preregistered_by": prereg.get("preregistered_by", ""),
        "workload_set_hash": wsh,
        "workloads": [
            {
                "id": w["id"],
                "weight": w["weight"],
                "pass": w.get("pass", ""),
                "gate": w.get("gate", ""),
            }
            for w in prereg.get("workloads", [])
        ],
        "baseline": prereg.get("baseline", {}),
        "out_of_scope": prereg.get("out_of_scope", []),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_by": "scripts/compute_hashes.py",
    }

    # Include hash of the preregistered.yaml itself
    yaml_path = workloads_dir / "preregistered.yaml"
    report["preregistered_yaml_sha256"] = hashlib.sha256(yaml_path.read_bytes()).hexdigest()

    out_dir = workloads_dir.parent / ".prereports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "preregistration.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute RT-001 preregistration hashes")
    parser.add_argument("--workloads-dir", "-w", type=str,
                        default=str(Path(__file__).resolve().parent.parent / "workloads"),
                        help="Path to workloads directory")
    args = parser.parse_args()

    wd = Path(args.workloads_dir)
    report_path = write_preregistration_report(wd)

    report = json.loads(report_path.read_text())
    print(f"RT-001 preregistration report")
    print(f"  workload_set_hash: {report['workload_set_hash']}")
    print(f"  workload count:    {len(report['workloads'])}")
    print(f"  baseline:          {report['baseline']['opencode_release']}")
    print(f"  yaml sha256:       {report['preregistered_yaml_sha256']}")
    print(f"  report path:       {report_path}")
    return 0


if __name__ == "__main__":
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    sys.exit(main())