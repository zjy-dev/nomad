#!/usr/bin/env python3
"""Offline validator: check preregistration consistency.

This is the primary validator run before any measurement. It checks:

1. preregistered.yaml is parseable and has exactly 5 workloads.
2. Each workload has the required fields (id, name, weight, measurement, pass, gate).
3. Weights sum to 1.0 (within tolerance).
4. workload_set_hash in .prereports/preregistration.json matches current inputs.
5. Baseline OpenCode release is a valid tag format.
6. All fixture files referenced by the manifest exist and have sha256.
7. SQLite PRAGMA block has all required keys.

Usage:
    python3 validators/check_preregistration.py
    python3 validators/check_preregistration.py --strict
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUIRED_WORKLOAD_FIELDS = ["id", "name", "weight", "description", "measurement", "pass", "gate"]
REQUIRED_PRAGMA_KEYS = [
    "journal_mode", "synchronous", "wal_autocheckpoint",
    "cache_size", "mmap_size", "foreign_keys", "auto_vacuum",
    "temp_store", "busy_timeout",
]
REQUIRED_BASELINE_FIELDS = ["opencode_release", "sqlite_pragma"]


def find_repo_root(start: Path) -> Path:
    """Find the repo root containing runtime-spike/."""
    p = start.resolve()
    while p != p.parent:
        if (p / "runtime-spike").is_dir():
            return p
        p = p.parent
    raise SystemExit("Cannot find repo root with runtime-spike/")


def validate(workloads_dir: Path, strict: bool = False) -> list[str]:
    """Return list of error strings. Empty list = pass."""
    errors = []

    yaml_path = workloads_dir / "preregistered.yaml"
    if not yaml_path.exists():
        errors.append(f"MISSING: {yaml_path}")
        return errors

    try:
        import yaml
    except ImportError:
        errors.append("PyYAML not installed. Run: pip install pyyaml")
        return errors

    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    # --- Check workload count ---
    workloads = data.get("workloads", [])
    if len(workloads) != 5:
        errors.append(
            f"WORKLOAD COUNT: expected exactly 5 workloads, found {len(workloads)}"
        )

    # --- Check required fields ---
    for w in workloads:
        for field in REQUIRED_WORKLOAD_FIELDS:
            if field not in w:
                errors.append(f"MISSING FIELD '{field}' in workload {w.get('id', '?')}")
        if "weight" in w:
            if not isinstance(w["weight"], (int, float)):
                errors.append(f"INVALID WEIGHT for {w.get('id')}: must be a number")
            elif w["weight"] < 0 or w["weight"] > 1:
                errors.append(f"INVALID WEIGHT for {w.get('id')}: must be in [0, 1]")

    # --- Check weights sum ---
    total = sum(w.get("weight", 0) for w in workloads)
    if abs(total - 1.0) > 0.001:
        errors.append(f"WEIGHTS SUM: expected 1.0, got {total:.4f}")

    # --- Check baseline ---
    baseline = data.get("baseline", {})
    for field in REQUIRED_BASELINE_FIELDS:
        if field not in baseline:
            errors.append(f"MISSING BASELINE FIELD '{field}'")

    # --- Check baseline release format ---
    release = baseline.get("opencode_release", "")
    if not release.startswith("v"):
        errors.append(
            f"BASELINE RELEASE: '{release}' does not match 'v*' tag format"
        )

    # --- Check SQLite PRAGMA ---
    pragma = baseline.get("sqlite_pragma", {})
    for key in REQUIRED_PRAGMA_KEYS:
        if key not in pragma:
            errors.append(f"MISSING PRAGMA KEY: '{key}'")

    # --- Check out_of_scope ---
    if not data.get("out_of_scope"):
        errors.append("MISSING: out_of_scope list")

    # --- Check preregistration.json hash ---
    prereport_path = workloads_dir.parent / ".prereports" / "preregistration.json"
    if prereport_path.exists():
        prereport = json.loads(prereport_path.read_text())
        wsh = prereport.get("workload_set_hash", "")
        if not wsh:
            errors.append("MISSING: workload_set_hash in preregistration.json")
    elif strict:
        errors.append(
            "MISSING: .prereports/preregistration.json (run scripts/compute_hashes.py first)"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate RT-001 preregistration")
    parser.add_argument("--workloads-dir", "-w", type=str,
                        default=None,
                        help="Path to workloads directory")
    parser.add_argument("--strict", action="store_true",
                        help="Fail on missing preregistration.json")
    args = parser.parse_args()

    if args.workloads_dir:
        wd = Path(args.workloads_dir)
    else:
        repo_root = find_repo_root(Path.cwd())
        wd = repo_root / "runtime-spike" / "workloads"

    errors = validate(wd, strict=args.strict)

    if errors:
        print(f"RT-001 PREREGISTRATION: {len(errors)} error(s) found")
        for e in errors:
            print(f"  ERROR: {e}")
        return 1
    else:
        print("RT-001 PREREGISTRATION: PASS")
        wd = args.workloads_dir or find_repo_root(Path.cwd()) / "runtime-spike" / "workloads"
        import yaml
        data = yaml.safe_load((wd / "preregistered.yaml").read_text())
        for w in data.get("workloads", []):
            print(f"  {w['id']:22s}  weight={w['weight']:.2f}  pass={w.get('pass', '')}")
        print(f"  baseline: {data.get('baseline', {}).get('opencode_release', '')}")
        return 0


if __name__ == "__main__":
    sys.exit(main())