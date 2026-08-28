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
REQUIRED_SUPPORT_MATRIX_FIELDS = (
    "schema",
    "adapter_id",
    "adapter_version",
    "supported_versions",
    "supported_actions",
    "capability_schema",
    "capability_issuance",
    "no_capability",
    "pending_input",
    "unsupported",
    "fail_closed",
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


def validate_adapter_support_matrix(root: Path, findings: List[Finding]) -> None:
    path = root / "adapter_support_matrix.json"
    matrix = load_json(path, findings)
    if not isinstance(matrix, dict):
        return
    absent = missing_fields(matrix, REQUIRED_SUPPORT_MATRIX_FIELDS)
    if absent:
        findings.append(Finding("E_MATRIX_FIELDS", str(path), f"missing {absent}"))
        return
    if matrix["schema"] != "nomad.adapter-support-matrix.v1":
        findings.append(Finding("E_MATRIX_SCHEMA", str(path), "unexpected schema"))
    if matrix["adapter_id"] != "opencode":
        findings.append(Finding("E_MATRIX_ADAPTER", str(path), "only opencode is supported"))
    if matrix["adapter_version"] != "1.18.16":
        findings.append(Finding("E_MATRIX_VERSION", str(path), "adapter_version must be exact 1.18.16"))
    if matrix["supported_versions"] != ["1.18.16"]:
        findings.append(Finding("E_MATRIX_SUPPORTED_VERSIONS", str(path), "supported_versions must contain only the exact OpenCode version"))
    if matrix["supported_actions"] != ["view", "reply", "deny", "Stop"]:
        findings.append(Finding("E_MATRIX_ACTIONS", str(path), "supported_actions must be exactly [view, reply, deny, Stop]"))

    capability = matrix["capability_issuance"]
    if not isinstance(capability, dict):
        findings.append(Finding("E_MATRIX_CAPABILITY", str(path), "capability_issuance must be an object"))
    else:
        if capability.get("view") is not True:
            findings.append(Finding("E_MATRIX_CAPABILITY_VIEW", str(path), "view capability must remain true"))
        if capability.get("reply") != "question_only":
            findings.append(Finding("E_MATRIX_CAPABILITY_REPLY", str(path), "reply capability must be question_only"))
        if capability.get("deny") != "permission_only":
            findings.append(Finding("E_MATRIX_CAPABILITY_DENY", str(path), "deny capability must be permission_only"))
        if capability.get("stop") != "busy_session_only":
            findings.append(Finding("E_MATRIX_CAPABILITY_STOP", str(path), "stop capability must be busy_session_only"))
        if capability.get("allow_once") is not False:
            findings.append(Finding("E_MATRIX_CAPABILITY_ALLOW_ONCE", str(path), "allow_once must remain false"))

    no_capability = matrix["no_capability"]
    if not isinstance(no_capability, dict):
        findings.append(Finding("E_MATRIX_NO_CAPABILITY", str(path), "no_capability must be an object"))
    else:
        if no_capability.get("semantics") != "snapshot_with_capability_null":
            findings.append(Finding("E_MATRIX_NO_CAPABILITY_MODE", str(path), "NoCapability must map to snapshot_with_capability_null"))
        if no_capability.get("view_retained") is not True:
            findings.append(Finding("E_MATRIX_NO_CAPABILITY_VIEW", str(path), "NoCapability must retain view"))
        if no_capability.get("capability_json") != "null":
            findings.append(Finding("E_MATRIX_NO_CAPABILITY_JSON", str(path), "NoCapability capability_json must be null"))

    pending_input = matrix["pending_input"]
    if not isinstance(pending_input, dict):
        findings.append(Finding("E_MATRIX_PENDING_INPUT", str(path), "pending_input must be an object"))
    else:
        if pending_input.get("summary_behavior") != "pending_question_summary_only":
            findings.append(Finding("E_MATRIX_PENDING_SUMMARY", str(path), "pending question summary behavior is incorrect"))
        if pending_input.get("provider_text_leaks_outside_adapter") is not False:
            findings.append(Finding("E_MATRIX_PENDING_LEAK", str(path), "provider-specific text must not leak outside adapter"))

    unsupported = matrix["unsupported"]
    if not isinstance(unsupported, list):
        findings.append(Finding("E_MATRIX_UNSUPPORTED", str(path), "unsupported must be a list"))
    else:
        required = {
            "allow_once",
            "provider_passthrough",
            "non_exact_version",
            "non_exact_shape",
            "unmapped_official_lifecycle_to_durable_events",
            "multiple_simultaneous_targets",
        }
        missing = sorted(required - set(unsupported))
        if missing:
            findings.append(Finding("E_MATRIX_UNSUPPORTED", str(path), f"missing {missing}"))

    fail_closed = matrix["fail_closed"]
    if not isinstance(fail_closed, dict):
        findings.append(Finding("E_MATRIX_FAIL_CLOSED", str(path), "fail_closed must be an object"))
    else:
        if fail_closed.get("unsupported_version") != "ERR_INCOMPATIBLE_VERSION":
            findings.append(Finding("E_MATRIX_FAIL_VERSION", str(path), "unsupported_version must fail closed with ERR_INCOMPATIBLE_VERSION"))
        if fail_closed.get("unsupported_shape") != "ERR_INCOMPATIBLE_VERSION":
            findings.append(Finding("E_MATRIX_FAIL_SHAPE", str(path), "unsupported_shape must fail closed with ERR_INCOMPATIBLE_VERSION"))
        if fail_closed.get("unsupported_action_surface") != "ERR_SAFETY_BLOCKED":
            findings.append(Finding("E_MATRIX_FAIL_ACTION", str(path), "unsupported action surface must fail closed with ERR_SAFETY_BLOCKED"))


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
    validate_adapter_support_matrix(root, findings)
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
        "adapter_support_matrix": True,
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
