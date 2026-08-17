#!/usr/bin/env python3
"""Offline validator: check hardware manifest completeness.

Ensures that a hardware manifest captures the fields required by
RT-001's provenance rules. The validator runs on the output of
hardware_manifest.py and checks for missing or suspicious values.

Usage:
    python3 validators/check_hardware.py [--hardware-json PATH]
"""

import argparse
import json
import sys
from pathlib import Path


REQUIRED_FIELDS = [
    "hostname",
    "os",
    "cpu_model",
    "cpu_cores_logical",
    "cpu_cores_physical",
    "ram_mib",
    "storage_model",
    "storage_type",
]

VALID_OS_PREFIXES = ("Darwin", "Linux", "Windows")
VALID_STORAGE_TYPES = ("NVMe", "SATA", "USB", "SSD", "HDD")


def find_repo_root(start: Path) -> Path:
    p = start.resolve()
    while p != p.parent:
        if (p / "runtime-spike").is_dir():
            return p
        p = p.parent
    raise SystemExit("Cannot find repo root with runtime-spike/")


def validate(manifest: dict) -> list[str]:
    errors = []

    for field in REQUIRED_FIELDS:
        value = manifest.get(field)
        if value is None or value == "" or value == 0:
            errors.append(f"MISSING FIELD: {field}")

    os_str = manifest.get("os", "")
    if os_str and not any(os_str.startswith(p) for p in VALID_OS_PREFIXES):
        errors.append(f"SUSPICIOUS OS string: '{os_str}'")

    stype = manifest.get("storage_type", "")
    if stype and stype not in VALID_STORAGE_TYPES:
        errors.append(f"SUSPICIOUS storage_type: '{stype}'")

    phys = manifest.get("cpu_cores_physical", 0)
    log = manifest.get("cpu_cores_logical", 0)
    if phys and log and phys > log:
        errors.append(f"ILLOGICAL: cpu_cores_physical ({phys}) > cpu_cores_logical ({log})")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate RT-001 hardware manifest")
    parser.add_argument("--hardware-json", "-j", type=str, default=None,
                        help="Path to hardware.json (default: run hardware_manifest.py)")
    args = parser.parse_args()

    if args.hardware_json:
        manifest = json.loads(Path(args.hardware_json).read_text())
    else:
        repo_root = find_repo_root(Path.cwd())
        hw_script = repo_root / "runtime-spike" / "scripts" / "hardware_manifest.py"
        sys.path.insert(0, str(hw_script.parent))
        import importlib.util
        spec = importlib.util.spec_from_file_location("hardware_manifest", hw_script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        manifest = mod.capture()

    errors = validate(manifest)

    if errors:
        print(f"HARDWARE MANIFEST: {len(errors)} error(s) found")
        for e in errors:
            print(f"  ERROR: {e}")
        return 1
    else:
        print("HARDWARE MANIFEST: PASS")
        for field in REQUIRED_FIELDS:
            print(f"  {field}: {manifest.get(field)}")
        return 0


if __name__ == "__main__":
    sys.exit(main())