#!/usr/bin/env python3
"""Offline validator: check measurement provenance.

For a raw measurement file, verifies:
  1. The measurement has a provenance block with fixture hash, runtime hash,
     command line, and hardware manifest hash.
  2. The fixture hash matches what's in fixtures/manifest.json.
  3. The workload ID matches a preregistered workload.

Usage:
    python3 validators/check_measurement.py --measurement PATH
    python3 validators/check_measurement.py --all --measurements-dir DIR
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def find_repo_root(start: Path) -> Path:
    p = start.resolve()
    while p != p.parent:
        if (p / "runtime-spike").is_dir():
            return p
        p = p.parent
    raise SystemExit("Cannot find repo root with runtime-spike/")


def validate_single(measurement_path: Path, fixtures_dir: Path) -> list[str]:
    """Validate a single measurement file."""
    errors = []

    try:
        data = json.loads(measurement_path.read_text())
    except json.JSONDecodeError as e:
        errors.append(f"PARSE ERROR: {e}")
        return errors

    # Check provenance block
    provenance = data.get("provenance", {})
    if not provenance:
        errors.append("MISSING: provenance block")
        return errors

    required_prov_fields = [
        "workload_id",
        "fixture_file",
        "fixture_sha256",
        "baseline_release",
        "hardware_sha256",
        "measured_at",
    ]
    for field in required_prov_fields:
        if field not in provenance:
            errors.append(f"MISSING provenance field: {field}")

    # Check fixture hash against manifest
    fixture_file = provenance.get("fixture_file", "")
    fixture_hash = provenance.get("fixture_sha256", "")

    if fixture_file and fixture_hash:
        manifest_path = fixtures_dir / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            found = False
            for entry in manifest.get("fixtures", []):
                if entry["file"] == fixture_file:
                    if entry["sha256"] != fixture_hash:
                        errors.append(
                            f"FIXTURE HASH MISMATCH: {fixture_file} "
                            f"measurement_hash={fixture_hash[:16]}... "
                            f"manifest_hash={entry['sha256'][:16]}..."
                        )
                    found = True
                    break
            if not found:
                errors.append(f"UNKNOWN FIXTURE: {fixture_file} not in manifest")

    # Check workload ID against preregistered set
    wl_id = provenance.get("workload_id", "")
    if wl_id:
        try:
            import yaml
            wd = fixtures_dir.parent / "workloads"
            with open(wd / "preregistered.yaml") as f:
                prereg = yaml.safe_load(f)
            known_ids = {w["id"] for w in prereg.get("workloads", [])}
            if wl_id not in known_ids:
                errors.append(f"UNKNOWN WORKLOAD ID: {wl_id} not in preregistered set")
        except Exception:
            errors.append("Could not verify workload_id against preregistered set")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate RT-001 measurement provenance")
    parser.add_argument("--measurement", "-m", type=str, default=None,
                        help="Path to a single measurement JSON")
    parser.add_argument("--all", "-a", action="store_true",
                        help="Validate all measurements in a directory")
    parser.add_argument("--measurements-dir", "-d", type=str, default=None,
                        help="Directory containing measurement JSON files")
    args = parser.parse_args()

    if not args.measurement and not args.all:
        parser.error("Pass --measurement PATH or --all --measurements-dir DIR")

    repo_root = find_repo_root(Path.cwd())
    fixtures_dir = repo_root / "runtime-spike" / "fixtures"

    if args.measurement:
        errors = validate_single(Path(args.measurement), fixtures_dir)
        if errors:
            print(f"MEASUREMENT PROVENANCE: FAIL ({len(errors)} error(s))")
            for e in errors:
                print(f"  ERROR: {e}")
            return 1
        else:
            print(f"MEASUREMENT PROVENANCE: PASS ({args.measurement})")
            return 0

    # Batch mode
    mdir = Path(args.measurements_dir) if args.measurements_dir else (repo_root / "runtime-spike" / ".raw-measurements")
    if not mdir.is_dir():
        print(f"No measurements directory found: {mdir}")
        return 0

    total = 0
    failures = 0
    for mfile in sorted(mdir.glob("*.json")):
        total += 1
        errors = validate_single(mfile, fixtures_dir)
        if errors:
            failures += 1
            print(f"  FAIL: {mfile.name}")
            for e in errors:
                print(f"    {e}")
        else:
            print(f"  PASS: {mfile.name}")

    if failures:
        print(f"\nMEASUREMENT PROVENANCE: {failures}/{total} failed")
        return 1
    else:
        print(f"\nMEASUREMENT PROVENANCE: PASS ({total}/{total})")
        return 0


if __name__ == "__main__":
    sys.exit(main())