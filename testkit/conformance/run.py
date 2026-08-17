#!/usr/bin/env python3
"""Nomad language-neutral contract conformance runner.

The runner intentionally uses only the Python standard library. It validates
the portable corpus rather than importing generated types from any product
implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


REQUIRED_SCHEMAS = (
    "session.schema.json",
    "events.schema.json",
    "commands.schema.json",
    "snapshot.schema.json",
)
REQUIRED_EVENT_FIELDS = (
    "event_type",
    "session_id",
    "event_id",
    "seq",
    "timestamp",
    "durable",
)
REQUIRED_SNAPSHOT_FIELDS = (
    "session_id",
    "snapshot_seq",
    "last_applied_seq",
    "turn_state",
    "host_connectivity",
    "client_freshness",
    "version",
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str

    def render(self) -> str:
        return f"{self.code} {self.path}: {self.message}"


def load_json(path: Path, findings: List[Finding]) -> Optional[Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        findings.append(Finding("E_MISSING", str(path), "file does not exist"))
    except json.JSONDecodeError as exc:
        findings.append(
            Finding("E_JSON", str(path), f"invalid JSON at line {exc.lineno}, column {exc.colno}")
        )
    return None


def missing_fields(value: Dict[str, Any], required: Iterable[str]) -> List[str]:
    return sorted(field for field in required if field not in value)


def canonical_snapshot_digest(snapshot: Dict[str, Any]) -> str:
    """Hash canonical UTF-8 JSON for the snapshot excluding its digest field."""
    body = {key: value for key, value in snapshot.items() if key != "digest"}
    encoded = json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def semantic_diff(expected: Any, actual: Any, prefix: str = "$") -> List[str]:
    """Return a deterministic, path-sorted structural diff."""
    differences: List[str] = []
    if type(expected) is not type(actual):
        return [f"{prefix}: expected type {type(expected).__name__}, got {type(actual).__name__}"]
    if isinstance(expected, dict):
        expected_keys = set(expected)
        actual_keys = set(actual)
        for key in sorted(expected_keys - actual_keys):
            differences.append(f"{prefix}.{key}: missing")
        for key in sorted(actual_keys - expected_keys):
            differences.append(f"{prefix}.{key}: unexpected")
        for key in sorted(expected_keys & actual_keys):
            differences.extend(semantic_diff(expected[key], actual[key], f"{prefix}.{key}"))
    elif isinstance(expected, list):
        if len(expected) != len(actual):
            differences.append(f"{prefix}: expected length {len(expected)}, got {len(actual)}")
        for index, (left, right) in enumerate(zip(expected, actual)):
            differences.extend(semantic_diff(left, right, f"{prefix}[{index}]"))
    elif expected != actual:
        differences.append(
            f"{prefix}: expected {json.dumps(expected, ensure_ascii=False, sort_keys=True)}, "
            f"got {json.dumps(actual, ensure_ascii=False, sort_keys=True)}"
        )
    return differences


def validate_trace(trace_path: Path, snapshot_path: Path, findings: List[Finding]) -> None:
    trace = load_json(trace_path, findings)
    snapshot = load_json(snapshot_path, findings)
    if not isinstance(trace, dict) or not isinstance(snapshot, dict):
        return

    trace_missing = missing_fields(
        trace, ("trace_id", "scenario", "contract_version", "session_id", "events")
    )
    if trace_missing:
        findings.append(Finding("E_TRACE_FIELDS", str(trace_path), f"missing {trace_missing}"))
        return
    if not isinstance(trace["events"], list) or not trace["events"]:
        findings.append(Finding("E_TRACE_EVENTS", str(trace_path), "events must be a non-empty array"))
        return

    seen_ids = set()
    previous_seq = 0
    for index, event in enumerate(trace["events"]):
        event_path = f"{trace_path}#events[{index}]"
        if not isinstance(event, dict):
            findings.append(Finding("E_EVENT_TYPE", event_path, "event must be an object"))
            continue
        absent = missing_fields(event, REQUIRED_EVENT_FIELDS)
        if absent:
            findings.append(Finding("E_EVENT_FIELDS", event_path, f"missing {absent}"))
            continue
        seq = event["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            findings.append(Finding("E_EVENT_SEQ_TYPE", event_path, "seq must be an integer"))
        elif seq != previous_seq + 1:
            findings.append(
                Finding("E_EVENT_SEQ", event_path, f"expected seq {previous_seq + 1}, got {seq}")
            )
            previous_seq = seq
        else:
            previous_seq = seq
        if event["session_id"] != trace["session_id"]:
            findings.append(Finding("E_EVENT_SESSION", event_path, "session_id differs from trace"))
        event_id = event["event_id"]
        if event_id in seen_ids:
            findings.append(Finding("E_EVENT_ID", event_path, f"duplicate event_id {event_id}"))
        seen_ids.add(event_id)
        if event["durable"] is not True:
            findings.append(Finding("E_EVENT_DURABLE", event_path, "durable corpus event must be true"))

    snapshot_missing = missing_fields(snapshot, REQUIRED_SNAPSHOT_FIELDS)
    if snapshot_missing:
        findings.append(Finding("E_SNAPSHOT_FIELDS", str(snapshot_path), f"missing {snapshot_missing}"))
        return
    if snapshot["session_id"] != trace["session_id"]:
        findings.append(Finding("E_SNAPSHOT_SESSION", str(snapshot_path), "session_id differs from trace"))
    if snapshot["snapshot_seq"] != previous_seq:
        findings.append(
            Finding("E_SNAPSHOT_SEQ", str(snapshot_path), f"expected {previous_seq}, got {snapshot['snapshot_seq']}")
        )
    if snapshot["last_applied_seq"] != snapshot["snapshot_seq"]:
        findings.append(
            Finding("E_SNAPSHOT_CURSOR", str(snapshot_path), "last_applied_seq must equal snapshot_seq")
        )
    if snapshot["version"] != trace["contract_version"]:
        findings.append(
            Finding("E_SNAPSHOT_VERSION", str(snapshot_path), "snapshot and trace versions differ")
        )
    expected_digest = canonical_snapshot_digest(snapshot)
    if snapshot.get("digest") != expected_digest:
        findings.append(
            Finding(
                "E_SNAPSHOT_DIGEST",
                str(snapshot_path),
                f"expected {expected_digest}, got {snapshot.get('digest')}",
            )
        )


def validate_contracts(root: Path, actual_snapshots: Optional[Path] = None) -> Dict[str, Any]:
    findings: List[Finding] = []
    schema_dir = root / "schemas"
    trace_dir = root / "traces"
    schemas: Dict[str, Any] = {}
    for name in REQUIRED_SCHEMAS:
        value = load_json(schema_dir / name, findings)
        if isinstance(value, dict):
            schemas[name] = value
            if not value.get("version"):
                findings.append(Finding("E_SCHEMA_VERSION", str(schema_dir / name), "version is required"))

    manifest_path = trace_dir / "manifest.json"
    manifest = load_json(manifest_path, findings)
    trace_count = 0
    if isinstance(manifest, dict):
        if not manifest.get("corpus_version") or not manifest.get("contract_version"):
            findings.append(Finding("E_MANIFEST_VERSION", str(manifest_path), "versions are required"))
        entries = manifest.get("traces")
        if not isinstance(entries, list) or not entries:
            findings.append(Finding("E_MANIFEST_TRACES", str(manifest_path), "traces must be non-empty"))
        else:
            trace_count = len(entries)
            ids = set()
            for index, entry in enumerate(entries):
                entry_path = f"{manifest_path}#traces[{index}]"
                if not isinstance(entry, dict):
                    findings.append(Finding("E_MANIFEST_ENTRY", entry_path, "entry must be an object"))
                    continue
                absent = missing_fields(entry, ("id", "file", "expected_snapshot"))
                if absent:
                    findings.append(Finding("E_MANIFEST_ENTRY", entry_path, f"missing {absent}"))
                    continue
                if entry["id"] in ids:
                    findings.append(Finding("E_MANIFEST_ID", entry_path, f"duplicate id {entry['id']}"))
                ids.add(entry["id"])
                expected_path = trace_dir / entry["expected_snapshot"]
                validate_trace(trace_dir / entry["file"], expected_path, findings)
                if actual_snapshots is not None:
                    actual_path = actual_snapshots / entry["expected_snapshot"]
                    expected = load_json(expected_path, findings)
                    actual = load_json(actual_path, findings)
                    if expected is not None and actual is not None:
                        for difference in semantic_diff(expected, actual):
                            findings.append(Finding("E_SEMANTIC_DIFF", str(actual_path), difference))

    versions = sorted({value.get("version") for value in schemas.values() if value.get("version")})
    capabilities = {
        "schemas": sorted(schemas),
        "semantic_diff": actual_snapshots is not None,
        "trace_invariants": ["strict_seq", "unique_event_id", "durable_only", "snapshot_cursor"],
    }
    return {
        "status": "PASS" if not findings else "FAIL",
        "contract_root": str(root),
        "contract_versions": versions,
        "trace_count": trace_count,
        "capabilities": capabilities,
        "findings": [finding.__dict__ for finding in sorted(findings, key=lambda item: (item.path, item.code, item.message))],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Nomad language-neutral contract corpus")
    parser.add_argument("--contracts-root", type=Path, default=Path("contracts"))
    parser.add_argument("--actual-snapshots", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    report = validate_contracts(args.contracts_root, args.actual_snapshots)
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"CONFORMANCE {report['status']}: {report['trace_count']} trace(s), versions={report['contract_versions']}")
        for finding in report["findings"]:
            print(f"  {finding['code']} {finding['path']}: {finding['message']}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
