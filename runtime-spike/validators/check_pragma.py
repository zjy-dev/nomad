#!/usr/bin/env python3
"""Offline validator: check SQLite PRAGMA equality.

Verifies that the SQLite PRAGMA values from a running runtime match
the preregistered block exactly. This is a guardrail against silently
changing durability or caching settings between baseline and runtime.

Usage:
    python3 validators/check_pragma.py [--pragma-json PATH]

The --pragma-json file should contain the runtime's active PRAGMA
values in the form produced by the runtime's own PRAGMA dump. Example:
    {
        "journal_mode": "wal",
        "synchronous": "normal",
        ...
    }

If no --pragma-json is given, the validator prints the expected
PRAGMA block from preregistered.yaml so you can compare manually.
"""

import argparse
import json
import sys
from pathlib import Path


PRAGMA_KEYS = [
    "journal_mode", "synchronous", "wal_autocheckpoint",
    "cache_size", "mmap_size", "foreign_keys", "auto_vacuum",
    "temp_store", "busy_timeout",
]


def load_expected(workloads_dir: Path) -> dict:
    """Load expected PRAGMA from preregistered.yaml."""
    try:
        import yaml
    except ImportError:
        raise SystemExit("PyYAML not installed. Run: pip install pyyaml")

    yaml_path = workloads_dir / "preregistered.yaml"
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    return data.get("baseline", {}).get("sqlite_pragma", {})


def load_actual(path: Path) -> dict:
    """Load actual PRAGMA from runtime dump."""
    return json.loads(path.read_text())


def find_repo_root(start: Path) -> Path:
    p = start.resolve()
    while p != p.parent:
        if (p / "runtime-spike").is_dir():
            return p
        p = p.parent
    raise SystemExit("Cannot find repo root with runtime-spike/")


def normalize_value(key: str, value) -> str:
    """Normalize a PRAGMA value for comparison.

    SQLite PRAGMA values can come back as strings or ints. We normalize
    to a lowercase string for comparison. Booleans are converted to
    'true' or 'false'.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return str(value).lower()


def compare(expected: dict, actual: dict) -> list[str]:
    """Return list of mismatch descriptions."""
    mismatches = []

    for key in PRAGMA_KEYS:
        if key not in expected:
            mismatches.append(f"Unexpected key {key} in expected")
            continue
        if key not in actual:
            mismatches.append(f"MISSING in actual: {key}")
            continue

        exp_val = normalize_value(key, expected[key])
        act_val = normalize_value(key, actual[key])

        if exp_val != act_val:
            mismatches.append(
                f"MISMATCH {key}: expected='{exp_val}', actual='{act_val}'"
            )

    # Extra keys in actual
    for key in actual:
        if key not in PRAGMA_KEYS:
            mismatches.append(f"EXTRA key in actual: {key}")

    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SQLite PRAGMA equality")
    parser.add_argument("--pragma-json", "-p", type=str, default=None,
                        help="Path to runtime's active PRAGMA JSON dump")
    parser.add_argument("--workloads-dir", "-w", type=str, default=None,
                        help="Path to workloads directory")
    args = parser.parse_args()

    if args.workloads_dir:
        wd = Path(args.workloads_dir)
    else:
        repo_root = find_repo_root(Path.cwd())
        wd = repo_root / "runtime-spike" / "workloads"

    expected = load_expected(wd)

    if not args.pragma_json:
        print("Expected SQLite PRAGMA block (from preregistered.yaml):")
        for key in PRAGMA_KEYS:
            val = expected.get(key, "<MISSING>")
            print(f"  PRAGMA {key} = {val}")
        print()
        print("To validate a runtime's active PRAGMA, pass --pragma-json PATH")
        print("  python3 validators/check_pragma.py --pragma-json runtime-pragma.json")
        return 0

    actual = load_actual(Path(args.pragma_json))
    mismatches = compare(expected, actual)

    if mismatches:
        print(f"PRAGMA EQUALITY: FAIL ({len(mismatches)} mismatch(es))")
        for m in mismatches:
            print(f"  {m}")
        return 1
    else:
        print("PRAGMA EQUALITY: PASS")
        for key in PRAGMA_KEYS:
            print(f"  {key} = {expected[key]}")
        return 0


if __name__ == "__main__":
    sys.exit(main())