#!/usr/bin/env python3
"""Capture a hardware manifest for RT-001 measurement tagging.

Usage:
    python3 hardware_manifest.py [--output PATH]

If --output is not given, prints JSON to stdout. The manifest is
intentionally narrow: only fields that materially affect SQLite and
allocator behavior are recorded.
"""

import argparse
import json
import os
import platform
import sys
from pathlib import Path


def _cpu_model() -> str:
    if platform.system() == "Darwin":
        try:
            import subprocess
            out = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            return out
        except Exception:
            try:
                out = subprocess.check_output(
                    ["sysctl", "-n", "hw.model"],
                    stderr=subprocess.DEVNULL,
                ).decode().strip()
                return out
            except Exception:
                return "unknown"
    elif platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return "unknown"
    return "unknown"


def _cpu_cores_physical() -> int:
    if platform.system() == "Darwin":
        try:
            import subprocess
            out = subprocess.check_output(
                ["sysctl", "-n", "hw.physicalcpu"],
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            return int(out)
        except Exception:
            return 0
    elif platform.system() == "Linux":
        try:
            import subprocess
            out = subprocess.check_output(
                ["nproc", "--all"],
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            return int(out)
        except Exception:
            return os.cpu_count() or 0
    return 0


def _ram_mib() -> int:
    if platform.system() == "Darwin":
        try:
            import subprocess
            out = subprocess.check_output(
                ["sysctl", "-n", "hw.memsize"],
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            return int(out) // (1024 * 1024)
        except Exception:
            return 0
    elif platform.system() == "Linux":
        try:
            import subprocess
            out = subprocess.check_output(
                ["grep", "MemTotal", "/proc/meminfo"],
                stderr=subprocess.DEVNULL,
            ).decode()
            # MemTotal:   16384000 kB
            return int(out.split()[1]) // 1024
        except Exception:
            return 0
    return 0


def _storage_info() -> dict:
    if platform.system() == "Darwin":
        try:
            import subprocess
            out = subprocess.check_output(
                ["diskutil", "info", "/"],
                stderr=subprocess.DEVNULL,
            ).decode()
            model = "unknown"
            dtype = "unknown"
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Device / Media Name:"):
                    model = line.split(":", 1)[1].strip()
                if line.startswith("Solid State:"):
                    dtype = "NVMe" if "Yes" in line else "SATA"
            return {"model": model, "type": dtype}
        except Exception:
            return {"model": "unknown", "type": "unknown"}
    return {"model": "unknown", "type": "unknown"}


def capture() -> dict:
    storage = _storage_info()
    manifest = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "cpu_model": _cpu_model(),
        "cpu_cores_logical": os.cpu_count() or 0,
        "cpu_cores_physical": _cpu_cores_physical(),
        "ram_mib": _ram_mib(),
        "storage_model": storage["model"],
        "storage_type": storage["type"],
    }
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture RT-001 hardware manifest")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    manifest = capture()
    text = json.dumps(manifest, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())