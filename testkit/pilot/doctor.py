#!/usr/bin/env python3
"""Content-free environment checks for the disposable-data Pilot."""

from __future__ import annotations

import argparse
import json
import platform
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

EXPECTED_VERSION = "1.18.16"


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    code: str
    action: str


def check_loopback(url: str) -> Check:
    parsed = urlparse(url)
    ok = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port == 4096
    return Check("opencode_origin", ok, "OK" if ok else "ERR_NON_LOOPBACK", "Use http://127.0.0.1:4096.")


def check_platform() -> Check:
    system, machine = platform.system(), platform.machine()
    ok = system == "Darwin" and machine in {"arm64", "aarch64"}
    return Check("host_platform", ok, "OK" if ok else "ERR_UNSUPPORTED_PLATFORM", "Use an Apple Silicon Mac for this Pilot.")


def check_health(base_url: str, timeout: float) -> Check:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/global/health", timeout=timeout) as response:
            payload = json.load(response)
        version = payload.get("version")
        ok = payload.get("healthy") is True and version == EXPECTED_VERSION
        code = "OK" if ok else "ERR_INCOMPATIBLE_VERSION"
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        ok, code = False, "ERR_HOST_OFFLINE"
    return Check("opencode_health", ok, code, f"Start the fixed OpenCode {EXPECTED_VERSION} loopback server.")


def run(base_url: str, timeout: float) -> list[Check]:
    origin = check_loopback(base_url)
    checks = [check_platform(), origin]
    if origin.ok:
        checks.append(check_health(base_url, timeout))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode-url", default="http://127.0.0.1:4096")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    checks = run(args.opencode_url, args.timeout)
    output = {"ok": all(check.ok for check in checks), "checks": [asdict(check) for check in checks]}
    if args.json:
        print(json.dumps(output, sort_keys=True))
    else:
        for check in checks:
            print(f"{'PASS' if check.ok else 'FAIL'} {check.name} {check.code}: {check.action}")
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
