"""Shared, content-free Iteration 3 receipt contract for WP1 and WP4.

Receipts are NDJSON audit envelopes, never an event transport.  In particular,
no raw stock identifiers, user content, paths, credentials, argv, or payloads
are allowed in this contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

RECEIPT_SCHEMA_VERSION = 1
RECEIPT_FIELDS = frozenset({
    "schema_version", "run_id", "process_role", "stage", "sequence",
    "timestamp", "predecessor_digest", "digest", "source", "status",
    "reason_code", "subject_alias", "counts",
})
COUNT_FIELDS = frozenset({"upstream_executions", "workspace_entries_remaining", "credential_scope_violations"})
REQUIRED_STAGES = (
    "runtime_provenance_verified", "credential_scope_configured", "opencode_ready",
    "host_ready", "relay_ready", "gateway_ready", "mobile_ready", "question_observed",
    "question_reply_host_accepted", "question_reply_upstream_executed", "diff_observed",
    "permission_observed", "permission_deny_host_accepted", "permission_deny_upstream_executed",
    "stop_host_accepted", "stop_upstream_executed", "reconnect_reconciled",
    "credential_scope_audit_completed", "workspace_cleaned",
)
STAGE_BINDINGS = {
    "runtime_provenance_verified": ("harness", "wp1_harness"),
    "credential_scope_configured": ("harness", "wp1_harness"),
    "opencode_ready": ("stock_runtime", "wp1_runtime"),
    "host_ready": ("host", "wp3_process"), "relay_ready": ("relay", "wp3_process"),
    "gateway_ready": ("gateway", "wp3_process"), "mobile_ready": ("mobile", "wp3_process"),
    "question_observed": ("stock_runtime", "wp1_runtime"),
    "question_reply_host_accepted": ("host", "wp3_host"),
    "question_reply_upstream_executed": ("harness", "harness_proxy"),
    "diff_observed": ("stock_runtime", "wp1_runtime"),
    "permission_observed": ("stock_runtime", "wp1_runtime"),
    "permission_deny_host_accepted": ("host", "wp3_host"),
    "permission_deny_upstream_executed": ("harness", "harness_proxy"),
    "stop_host_accepted": ("host", "wp3_host"),
    "stop_upstream_executed": ("harness", "harness_proxy"),
    "reconnect_reconciled": ("host", "wp3_host"),
    "credential_scope_audit_completed": ("harness", "wp1_harness"),
    "workspace_cleaned": ("harness", "wp1_harness"),
}
ACTION_PAIRS = (
    ("question_reply_host_accepted", "question_reply_upstream_executed"),
    ("permission_deny_host_accepted", "permission_deny_upstream_executed"),
    ("stop_host_accepted", "stop_upstream_executed"),
)
UPSTREAM_STAGES = frozenset(proxy for _, proxy in ACTION_PAIRS)
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SUBJECT_ALIAS = re.compile(r"^(?:none|domain-[a-f0-9]{64})$")
_REQUEST_ALIAS = re.compile(r"^req-[a-f0-9]{64}$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


class ReceiptVerificationError(ValueError):
    """Stable, content-free rejection code."""


@dataclass(frozen=True)
class ReceiptRecord:
    schema_version: int
    run_id: str
    process_role: str
    stage: str
    sequence: int
    timestamp: str
    predecessor_digest: str | None
    digest: str
    source: str
    status: str
    reason_code: str
    subject_alias: str
    counts: Mapping[str, int]


@dataclass(frozen=True)
class VerifiedReceiptSet:
    run_id: str
    receipt_count: int
    checkpoint_stages: tuple[str, ...]
    source_markers: tuple[str, ...]


def canonical_digest(record: Mapping[str, Any]) -> str:
    """Hash the exact allowlisted envelope minus its self digest."""
    material = {field: record[field] for field in RECEIPT_FIELDS - {"digest"}}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def receipt_digest(record: Mapping[str, Any]) -> str:
    """Compatibility spelling for WP4 callers."""
    return canonical_digest(record)


def _fail(code: str) -> None:
    raise ReceiptVerificationError(code)


def _parse(record: Any) -> ReceiptRecord:
    if not isinstance(record, dict) or set(record) != RECEIPT_FIELDS:
        _fail("FAIL_RECEIPT_SCHEMA_FIELDS")
    if record["schema_version"] != RECEIPT_SCHEMA_VERSION:
        _fail("FAIL_RECEIPT_SCHEMA_VERSION")
    if not isinstance(record["run_id"], str) or not _RUN_ID.fullmatch(record["run_id"]):
        _fail("FAIL_RECEIPT_RUN_ID")
    if not isinstance(record["stage"], str) or record["stage"] not in STAGE_BINDINGS:
        _fail("FAIL_RECEIPT_STAGE_ALLOWLIST")
    for field in ("process_role", "source", "status", "reason_code"):
        if not isinstance(record[field], str) or not _TOKEN.fullmatch(record[field]):
            _fail("FAIL_RECEIPT_CONTENT_POLICY")
    if record["status"] != "completed":
        _fail("FAIL_RECEIPT_CHECKPOINT_STATUS")
    if (record["process_role"], record["source"]) != STAGE_BINDINGS[record["stage"]]:
        _fail("FAIL_RECEIPT_PROCESS_BINDING")
    action = record["stage"] in {stage for pair in ACTION_PAIRS for stage in pair}
    alias = record["subject_alias"]
    if not isinstance(alias, str) or (not _REQUEST_ALIAS.fullmatch(alias) if action else not _SUBJECT_ALIAS.fullmatch(alias)):
        _fail("FAIL_RECEIPT_SUBJECT_ALIAS")
    if not isinstance(record["sequence"], int) or isinstance(record["sequence"], bool) or record["sequence"] < 1:
        _fail("FAIL_RECEIPT_SEQUENCE")
    if not isinstance(record["timestamp"], str) or not _RFC3339_UTC.fullmatch(record["timestamp"]):
        _fail("FAIL_RECEIPT_TIMESTAMP")
    try:
        datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        _fail("FAIL_RECEIPT_TIMESTAMP")
    predecessor = record["predecessor_digest"]
    if predecessor is not None and (not isinstance(predecessor, str) or not _SHA256.fullmatch(predecessor)):
        _fail("FAIL_RECEIPT_PREDECESSOR")
    if not isinstance(record["digest"], str) or not _SHA256.fullmatch(record["digest"]) or record["digest"] != canonical_digest(record):
        _fail("FAIL_RECEIPT_DIGEST")
    counts = record["counts"]
    if not isinstance(counts, dict) or set(counts) - COUNT_FIELDS or any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in counts.values()):
        _fail("FAIL_RECEIPT_COUNTS")
    executions = counts.get("upstream_executions", 0)
    if (record["stage"] in UPSTREAM_STAGES and executions != 1) or (record["stage"] not in UPSTREAM_STAGES and executions != 0):
        _fail("FAIL_RECEIPT_UPSTREAM_EXECUTIONS")
    return ReceiptRecord(**record)


def read_receipt_store(store: Path, *, expected_run_id: str) -> VerifiedReceiptSet:
    try:
        lines = store.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ReceiptVerificationError("FAIL_RECEIPT_STORE_UNREADABLE") from error
    if not lines:
        _fail("FAIL_RECEIPT_STORE_EMPTY")
    try:
        records = [_parse(json.loads(line)) for line in lines]
    except json.JSONDecodeError as error:
        raise ReceiptVerificationError("FAIL_RECEIPT_NDJSON") from error
    if {record.run_id for record in records} != {expected_run_id}:
        _fail("FAIL_RECEIPT_RUN_BINDING")
    if len(records) != len(REQUIRED_STAGES) or tuple(record.stage for record in records) != REQUIRED_STAGES:
        _fail("FAIL_RECEIPT_STAGE_ORDER")
    if [record.sequence for record in records] != list(range(1, len(REQUIRED_STAGES) + 1)):
        _fail("FAIL_RECEIPT_SEQUENCE")
    if records[0].predecessor_digest is not None:
        _fail("FAIL_RECEIPT_PREDECESSOR")
    for previous, current in zip(records, records[1:]):
        if current.predecessor_digest != previous.digest:
            _fail("FAIL_RECEIPT_PREDECESSOR")
        if current.timestamp < previous.timestamp:
            _fail("FAIL_RECEIPT_TIMESTAMP_ORDER")
    aliases = []
    for host_stage, proxy_stage in ACTION_PAIRS:
        host = records[REQUIRED_STAGES.index(host_stage)]
        proxy = records[REQUIRED_STAGES.index(proxy_stage)]
        if host.subject_alias != proxy.subject_alias:
            _fail("FAIL_RECEIPT_REQUEST_PAIR")
        aliases.append(host.subject_alias)
    if len(set(aliases)) != len(aliases):
        _fail("FAIL_RECEIPT_REQUEST_ALIAS_DISTINCT")
    if records[-1].counts.get("workspace_entries_remaining") != 0:
        _fail("FAIL_RECEIPT_WORKSPACE_CLEANUP")
    audit = records[REQUIRED_STAGES.index("credential_scope_audit_completed")]
    if audit.counts.get("credential_scope_violations") != 0:
        _fail("FAIL_RECEIPT_CREDENTIAL_SCOPE")
    return VerifiedReceiptSet(expected_run_id, len(records), REQUIRED_STAGES, tuple(sorted({record.source for record in records})))


def verify_receipt_store(store: Path, *, expected_run_id: str) -> VerifiedReceiptSet:
    return read_receipt_store(store, expected_run_id=expected_run_id)


def append_receipt(store: Path, record: Mapping[str, Any]) -> ReceiptRecord:
    """Validate a new record against prior NDJSON chain, then append canonically."""
    parsed = _parse(dict(record))
    existing = store.read_text(encoding="utf-8").splitlines() if store.exists() else []
    if existing:
        try:
            prior = _parse(json.loads(existing[-1]))
        except json.JSONDecodeError as error:
            raise ReceiptVerificationError("FAIL_RECEIPT_NDJSON") from error
        if parsed.run_id != prior.run_id or parsed.sequence != prior.sequence + 1 or parsed.predecessor_digest != prior.digest:
            _fail("FAIL_RECEIPT_APPEND_CHAIN")
    elif parsed.sequence != 1 or parsed.predecessor_digest is not None:
        _fail("FAIL_RECEIPT_APPEND_CHAIN")
    with store.open("a", encoding="utf-8") as output:
        output.write(json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
    return parsed
