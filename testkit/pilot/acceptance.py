#!/usr/bin/env python3
"""Validate a machine-readable Controlled Pilot scenario result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from testkit.pilot.telemetry import TelemetryValidationError, validate_event


class AcceptanceError(ValueError):
    pass


def validate_result(result: dict[str, Any]) -> None:
    if result.get("allow_once") is not False:
        raise AcceptanceError("allow_once must be false")
    if result.get("duplicate_host_acceptance", 0) != 0:
        raise AcceptanceError("duplicate Host acceptance detected")
    if result.get("unknown_gap", 0) != 0:
        raise AcceptanceError("unknown durable-event gap detected")
    stages = result.get("command_stages")
    if not isinstance(stages, list) or not any(stage == "HostAccepted" for stage in stages):
        raise AcceptanceError("at least one HostAccepted operation is required")
    for event in result.get("telemetry", []):
        if not isinstance(event, dict) or not isinstance(event.get("name"), str) or not isinstance(event.get("fields"), dict):
            raise AcceptanceError("invalid telemetry event shape")
        try:
            validate_event(event["name"], event["fields"])
        except TelemetryValidationError as error:
            raise AcceptanceError(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    result = json.loads(args.result.read_text(encoding="utf-8"))
    try:
        validate_result(result)
    except (AcceptanceError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "gate": "CONTROLLED_PILOT_SLICE"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
