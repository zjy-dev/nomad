"""Deterministic, support-safe diagnostics for the Nomad Web Companion.

The collector is read-only with respect to the runtime and exports commitments,
fixed status codes, and log digests only. It never walks the repository, browser
storage, arbitrary home files, or the protected process-loop transcript.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import install_lifecycle, processes, recovery, state


SCHEMA = "nomad.web-companion.support-diagnostics.v1"
CLASSIFICATION = "support-only-not-readiness-evidence"
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,95}")
SAFE_PROCESS_NAMES = frozenset({
    "relay", "gateway", "opencode", "product-host",
    "relay-host", "relay-device", "desktop-gateway",
    "join-gateway", "https-ingress",
})
SAFE_ONBOARDING_ACTIONS = frozenset({
    "INSTALL_VERIFIED_BUNDLE", "AUTHORIZE_HOST_IDENTITY",
    "START_INSTALLED_BUNDLE", "RECOVER_RUNNING_IDENTITY",
    "PAIR_PHONE", "START_OFFICIAL_AGENT", "USE_INSTALLED_CANDIDATE",
})
SAFE_LOCAL_CODES = frozenset({
    "B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY",
    "PAIRED_DEVICE_REQUIRED", "OFFICIAL_AGENT_RUNTIME_REQUIRED",
    "PAIRED_DEVICE_IDENTITY_UNAVAILABLE", "INSTALLED_IDENTITY_INVALID",
    "RUNNING_WITHOUT_VERIFIED_INSTALL", "RUNNING_IDENTITY_MISMATCH",
    "RUNNING_PROCESS_SET_DEGRADED",
})
SAFE_BLOCKER_CODES = (
    recovery.KNOWN_RECOVERY_BLOCKER_CODES
    | SAFE_LOCAL_CODES
    | frozenset(install_lifecycle.EXTERNAL_GATES)
)
REDACTED_BLOCKER = "UNRECOGNIZED_BLOCKER_REDACTED"
RECOVERY_CODE_ALIASES = {
    "PROVIDER_E3_EVIDENCE_NOT_RUN": "PROVIDER_E3_NOT_RUN",
}
FORBIDDEN_KEYS = frozenset({
    "provider_credential", "credential", "bearer", "token",
    "prompt", "command", "agent_id", "session_alias",
    "workspace", "browser_storage", "path", "url", "pid",
    "process_group", "log_tail", "raw",
})
TOP_LEVEL_KEYS = {
    "schema", "classification", "production_ready", "readiness_evidence",
    "installed", "onboarding", "recovery", "runtime",
    "owned_processes", "logs", "bundle_install_metadata", "privacy_scan",
    "manifest_digest",
}
PRIVACY_SCAN = {
    "status": "PASS", "allowlist_only": True,
    "raw_log_content_included": False,
    "provider_credentials_included": False,
    "raw_agent_ids_included": False,
    "browser_storage_included": False,
    "protected_transcript_accessed": False,
    "unowned_files_included": False,
}


class DiagnosticsError(RuntimeError):
    """A deterministic content-free diagnostics failure."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _safe_code(value: object) -> str:
    if isinstance(value, str) and SAFE_CODE.fullmatch(value) and value in SAFE_BLOCKER_CODES:
        return value
    return REDACTED_BLOCKER


def _hex64(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise DiagnosticsError(code)
    return value


def _project_install(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        schema = value["schema"]
        install_state = value["state"]
        current = value["current_bundle_digest"]
        bundles = value["bundle_digests"]
        history = value["history"]
    except (KeyError, TypeError) as error:
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID") from error
    if (
        set(value) != {"schema", "state", "current_bundle_digest", "bundle_digests", "history"}
        or schema != install_lifecycle.STATUS_SCHEMA
        or install_state not in {"INSTALLED", "NOT_INSTALLED"}
    ):
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
    if (
        not isinstance(bundles, list) or len(bundles) > 1024
        or bundles != sorted(set(bundles))
    ):
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
    safe_bundles = [_hex64(item, "DIAGNOSTICS_INSTALL_STATE_INVALID") for item in bundles]
    if install_state == "NOT_INSTALLED":
        if current is not None or safe_bundles or history != []:
            raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
        return {
            "schema": schema, "state": install_state,
            "current_bundle_digest": None, "bundle_digests": [], "history": [],
        }
    current = _hex64(current, "DIAGNOSTICS_INSTALL_STATE_INVALID")
    if (
        current not in safe_bundles or not isinstance(history, list)
        or not history or len(history) > 4096
    ):
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
    try:
        install_lifecycle._validate_current({
            "schema": install_lifecycle.CURRENT_SCHEMA,
            "bundle_digest": current, "history": history,
        })
    except RuntimeError as error:
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID") from error
    safe_history: list[dict[str, Any]] = []
    for expected_sequence, item in enumerate(history, 1):
        if not isinstance(item, dict) or set(item) != {
            "sequence", "operation", "from_bundle_digest",
            "to_bundle_digest", "state_snapshot_digest", "rollback_of_sequence",
        }:
            raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
        if item["sequence"] != expected_sequence or item["operation"] not in {"install", "upgrade", "rollback"}:
            raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
        safe_item = dict(item)
        for field in ("from_bundle_digest", "to_bundle_digest", "state_snapshot_digest"):
            if safe_item[field] is not None:
                safe_item[field] = _hex64(safe_item[field], "DIAGNOSTICS_INSTALL_STATE_INVALID")
        rollback = safe_item["rollback_of_sequence"]
        if rollback is not None and (type(rollback) is not int or rollback <= 0):
            raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
        safe_history.append(safe_item)
    return {
        "schema": schema, "state": install_state,
        "current_bundle_digest": current, "bundle_digests": safe_bundles,
        "history": safe_history,
    }


def _project_onboarding(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        external = value["external_gates"]
        blockers = value["blockers"]
        next_action = value["next_action"]
    except (KeyError, TypeError) as error:
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID") from error
    if (
        set(value) != {
            "schema", "state", "production_ready", "external_readiness",
            "external_gates", "installed_bundle_digest", "install_sequence",
            "run_identity", "paired_device_commitment", "pairing_epoch",
            "blockers", "next_action",
        }
        or value.get("schema") != install_lifecycle.ONBOARDING_SCHEMA
        or value.get("state") not in install_lifecycle.ONBOARDING_STATES
        or value.get("production_ready") is not False
        or value.get("external_readiness") != "NOT_RUN"
        or not isinstance(external, list)
        or not isinstance(blockers, list)
        or next_action not in SAFE_ONBOARDING_ACTIONS
    ):
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    safe_external = []
    for gate in external:
        if not isinstance(gate, dict) or set(gate) != {"code", "status"} or gate.get("status") != "NOT_RUN":
            raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
        safe_external.append({"code": _safe_code(gate.get("code")), "status": "NOT_RUN"})
    expected_external = [
        {"code": code, "status": "NOT_RUN"}
        for code in install_lifecycle.EXTERNAL_GATES
    ]
    if safe_external != expected_external or len(blockers) > 16:
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    safe_blockers = [_safe_code(item) for item in blockers]
    if len(safe_blockers) != len(set(safe_blockers)):
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    result = {
        "schema": value["schema"], "state": value["state"],
        "production_ready": False, "external_readiness": "NOT_RUN",
        "external_gates": safe_external,
        "installed_bundle_digest": value.get("installed_bundle_digest"),
        "install_sequence": value.get("install_sequence"),
        "run_identity": value.get("run_identity"),
        "paired_device_commitment": value.get("paired_device_commitment"),
        "pairing_epoch": value.get("pairing_epoch"),
        "blockers": safe_blockers,
        "next_action": next_action,
    }
    for field in ("installed_bundle_digest", "run_identity", "paired_device_commitment"):
        if result[field] is not None:
            result[field] = _hex64(result[field], "DIAGNOSTICS_ONBOARDING_INVALID")
    for field in ("install_sequence", "pairing_epoch"):
        if result[field] is not None and (type(result[field]) is not int or result[field] <= 0):
            raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    state_name = result["state"]
    installed_present = result["installed_bundle_digest"] is not None and result["install_sequence"] is not None
    running_present = result["run_identity"] is not None
    paired_present = result["paired_device_commitment"] is not None and result["pairing_epoch"] is not None
    exact_shape = {
        "NOT_INSTALLED": (False, False, False, [], "INSTALL_VERIFIED_BUNDLE"),
        "INSTALLED_NEEDS_START": (True, False, False, [], "START_INSTALLED_BUNDLE"),
        "INSTALLED_BLOCKED_HOST_IDENTITY": (True, False, False, None, "AUTHORIZE_HOST_IDENTITY"),
        "RUNNING_NEEDS_PAIRING": (True, True, False, ["PAIRED_DEVICE_REQUIRED"], "PAIR_PHONE"),
        "RUNNING_PAIRED": (True, True, True, [], "USE_INSTALLED_CANDIDATE"),
        "RUNNING_DEGRADED_RECOVERY_REQUIRED": (None, None, None, None, "RECOVER_RUNNING_IDENTITY"),
    }[state_name]
    expected_installed, expected_running, expected_paired, expected_blockers, expected_action = exact_shape
    if (
        (expected_installed is not None and installed_present is not expected_installed)
        or (expected_running is not None and running_present is not expected_running)
        or (expected_paired is not None and paired_present is not expected_paired)
        or (expected_blockers is not None and result["blockers"] != expected_blockers)
        or (expected_blockers is None and not result["blockers"])
        or result["next_action"] != expected_action
    ):
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    if state_name == "INSTALLED_BLOCKED_HOST_IDENTITY" and (
        len(result["blockers"]) != 1
        or result["blockers"][0] not in install_lifecycle.HOST_IDENTITY_RESULTS.values()
        or result["blockers"][0] is None
    ):
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    return result


def _commitment(value: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"availability", *fields}:
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    result: dict[str, Any] = {"availability": value.get("availability")}
    if result["availability"] not in {"READY", "UNAVAILABLE", "UNPAIRED", "NOT_RUN"}:
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    for field in fields:
        item = value.get(field)
        if item is not None and field != "pairing_epoch" and field != "install_sequence":
            item = _hex64(item, "DIAGNOSTICS_RUNTIME_STATE_INVALID")
        if item is not None and field in {"pairing_epoch", "install_sequence"} and (type(item) is not int or item <= 0):
            raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
        result[field] = item
    available = result["availability"]
    populated = [result[field] is not None for field in fields]
    if available == "READY" and not all(populated):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    if available != "READY" and any(populated):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    return result


def _project_runtime(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"status": "NOT_RUNNING", "process_count": 0}
    identity = value.get("identity")
    process_records = value.get("processes")
    schema = value.get("schema")
    mode = value.get("mode")
    remote = schema == state.REMOTE_STATE_SCHEMA
    if (
        not isinstance(identity, dict) or set(identity) != state.IDENTITY_KEYS
        or not isinstance(process_records, list)
        or not set(value).issubset(state.REMOTE_RUN_KEYS if remote else state.RUN_KEYS)
        or schema not in {state.STATE_SCHEMA, state.REMOTE_STATE_SCHEMA}
        or mode not in {"foundation-readonly", "official-agent-local", "remote-local-evidence"}
        or type(value.get("real_agent_enabled")) is not bool
        or (remote and value.get("remote_enabled") is not True)
        or (not remote and "remote_enabled" in value)
        or value.get("network_scope", "loopback") not in {"loopback", "lan_direct"}
        or not isinstance(value.get("blocked_on"), list)
    ):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    return {
        "status": "RUNNING", "schema": schema,
        "mode": mode,
        "bundle_digest": (
            _hex64(value.get("bundle_digest"), "DIAGNOSTICS_RUNTIME_STATE_INVALID")
            if value.get("bundle_digest") is not None else None
        ),
        "real_agent_enabled": value.get("real_agent_enabled"),
        "remote_enabled": value.get("remote_enabled", False),
        "pairing_ready": value.get("pairing_ready", False),
        "remote_mailbox_ready": value.get("remote_mailbox_ready", False),
        "network_scope": value.get("network_scope", "loopback"),
        "blocked_on": [_safe_code(item) for item in value.get("blocked_on", [])],
        "process_count": len(process_records),
        "identity": {
            "installed": _commitment(identity.get("installed", {}), ("bundle_digest", "install_sequence", "install_identity")),
            "running": _commitment(identity.get("running", {}), ("bundle_digest", "process_commitment", "socket_commitment", "run_identity")),
            "host_public_commitment": _commitment(identity.get("host_public_commitment", {}), ("commitment",)),
            "paired_device": _commitment(identity.get("paired_device", {}), ("device_key_commitment", "pairing_epoch")),
        },
    }


def _validate_runtime_projection(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    if value.get("status") == "NOT_RUNNING":
        expected = {"status": "NOT_RUNNING", "process_count": 0}
        if value != expected:
            raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
        return expected
    keys = {
        "status", "schema", "mode", "bundle_digest",
        "real_agent_enabled", "remote_enabled", "pairing_ready",
        "remote_mailbox_ready", "network_scope", "blocked_on",
        "process_count", "identity",
    }
    schema = value.get("schema")
    mode = value.get("mode")
    remote = schema == state.REMOTE_STATE_SCHEMA
    blockers = value.get("blocked_on")
    if (
        set(value) != keys or value.get("status") != "RUNNING"
        or schema not in {state.STATE_SCHEMA, state.REMOTE_STATE_SCHEMA}
        or mode not in {"foundation-readonly", "official-agent-local", "remote-local-evidence"}
        or remote is not (mode == "remote-local-evidence")
        or type(value.get("real_agent_enabled")) is not bool
        or value["real_agent_enabled"] is (mode == "foundation-readonly")
        or type(value.get("remote_enabled")) is not bool
        or value["remote_enabled"] is not remote
        or type(value.get("pairing_ready")) is not bool
        or type(value.get("remote_mailbox_ready")) is not bool
        or value["pairing_ready"] is not remote
        or value["remote_mailbox_ready"] is not remote
        or value.get("network_scope") != ("lan_direct" if remote else "loopback")
        or type(value.get("process_count")) is not int
        or value["process_count"] <= 0 or value["process_count"] > 16
        or not isinstance(blockers, list) or len(blockers) > 32
    ):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    safe_blockers = [_safe_code(item) for item in blockers]
    if safe_blockers != blockers or len(blockers) != len(set(blockers)):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    bundle = value.get("bundle_digest")
    if bundle is not None:
        bundle = _hex64(bundle, "DIAGNOSTICS_RUNTIME_STATE_INVALID")
    if mode != "foundation-readonly" and bundle is None:
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    identity = value.get("identity")
    if not isinstance(identity, dict) or set(identity) != state.IDENTITY_KEYS:
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    projected = {
        "status": "RUNNING", "schema": schema, "mode": mode,
        "bundle_digest": bundle, "real_agent_enabled": value["real_agent_enabled"],
        "remote_enabled": value["remote_enabled"],
        "pairing_ready": value["pairing_ready"],
        "remote_mailbox_ready": value["remote_mailbox_ready"],
        "network_scope": value["network_scope"], "blocked_on": safe_blockers,
        "process_count": value["process_count"],
        "identity": {
            "installed": _commitment(identity["installed"], ("bundle_digest", "install_sequence", "install_identity")),
            "running": _commitment(identity["running"], ("bundle_digest", "process_commitment", "socket_commitment", "run_identity")),
            "host_public_commitment": _commitment(identity["host_public_commitment"], ("commitment",)),
            "paired_device": _commitment(identity["paired_device"], ("device_key_commitment", "pairing_epoch")),
        },
    }
    installed_identity = projected["identity"]["installed"]
    running_identity = projected["identity"]["running"]
    host_identity = projected["identity"]["host_public_commitment"]
    paired_identity = projected["identity"]["paired_device"]
    if (
        installed_identity["availability"] not in {"READY", "NOT_RUN"}
        or running_identity["availability"] not in {"READY", "NOT_RUN"}
        or host_identity["availability"] not in {"READY", "UNAVAILABLE", "NOT_RUN"}
        or paired_identity["availability"] not in {"READY", "UNPAIRED", "UNAVAILABLE", "NOT_RUN"}
        or (mode == "foundation-readonly" and (
            host_identity["availability"] != "NOT_RUN"
            or paired_identity["availability"] != "NOT_RUN"
        ))
        or (mode != "foundation-readonly" and (
            host_identity["availability"] == "NOT_RUN"
            or paired_identity["availability"] == "NOT_RUN"
        ))
        or (installed_identity["availability"] == "READY" and installed_identity["bundle_digest"] != bundle)
        or (running_identity["availability"] == "READY" and running_identity["bundle_digest"] != bundle)
    ):
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    if projected != value:
        raise DiagnosticsError("DIAGNOSTICS_RUNTIME_STATE_INVALID")
    return projected


def _read_owned_log(config: Any, process: Mapping[str, Any]) -> dict[str, Any]:
    name = process.get("name")
    if name not in SAFE_PROCESS_NAMES:
        raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
    log = Path(process.get("log", ""))
    root = Path(config.home) / "logs"
    if log.parent.resolve(strict=False) != root.resolve(strict=False):
        raise DiagnosticsError("DIAGNOSTICS_LOG_NOT_OWNED")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before_path = log.lstat()
        descriptor = os.open(log, flags)
    except OSError as error:
        raise DiagnosticsError("DIAGNOSTICS_LOG_FILE_POLICY_INVALID") from error
    try:
        before = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before_path.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > MAX_LOG_BYTES
        ):
            raise DiagnosticsError("DIAGNOSTICS_LOG_FILE_POLICY_INVALID")
        digest = hashlib.sha256()
        total = 0
        while total < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - total))
            if not chunk:
                raise DiagnosticsError("DIAGNOSTICS_LOG_CHANGED")
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise DiagnosticsError("DIAGNOSTICS_LOG_CHANGED")
    finally:
        os.close(descriptor)
    return {"process_name": name, "size_bytes": total, "raw_sha256": digest.hexdigest()}


def _process_and_log_summary(config: Any, runtime: Mapping[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if runtime is None:
        return [], []
    records = runtime.get("processes")
    if not isinstance(records, list):
        raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
    process_output, logs = [], []
    for item in records:
        if (
            not isinstance(item, dict) or set(item) != state.PROCESS_KEYS
            or item.get("name") not in SAFE_PROCESS_NAMES
        ):
            raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
        ownership = processes.ownership(item)
        if ownership not in {"owned", "absent", "mismatch"}:
            raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
        row: dict[str, Any] = {"name": item["name"], "ownership": ownership}
        if ownership == "owned":
            row["identity"] = _hex64(item.get("identity"), "DIAGNOSTICS_PROCESS_RECORD_INVALID")
            logs.append(_read_owned_log(config, item))
        else:
            row["identity"] = None
        process_output.append(row)
    return process_output, logs


def _privacy_scan(_: Mapping[str, Any]) -> dict[str, Any]:
    # Privacy follows from exact context-specific reconstruction below; this is
    # the fixed assertion recorded for support tooling, not a heuristic scan.
    return dict(PRIVACY_SCAN)


def _not_installed_inputs() -> tuple[dict[str, Any], None, dict[str, Any]]:
    installed = {
        "schema": install_lifecycle.STATUS_SCHEMA, "state": "NOT_INSTALLED",
        "current_bundle_digest": None, "bundle_digests": [], "history": [],
    }
    onboarding = install_lifecycle._classify_onboarding_unlocked(
        type("ConfigView", (), {"home": Path("/nonexistent")})(), installed, None
    )
    return installed, None, onboarding


def collect(config: Any) -> dict[str, Any]:
    """Collect one deterministic support-only manifest without runtime writes."""
    try:
        with state.lifecycle_lock(config, create=False) as owned:
            if not owned:
                installed, runtime, onboarding = _not_installed_inputs()
            else:
                installed = install_lifecycle.status_unlocked(config)
                runtime = state.read_run_state(config)
                onboarding = install_lifecycle.onboarding_status_unlocked(config)
            safe_install = _project_install(installed)
            safe_onboarding = _project_onboarding(onboarding)
            safe_runtime = _project_runtime(runtime)
            owned_processes, logs = _process_and_log_summary(config, runtime)
    except DiagnosticsError:
        raise
    except RuntimeError as error:
        raise DiagnosticsError("DIAGNOSTICS_INPUT_STATE_INVALID") from error
    gates = [
        {"status": "BLOCK", "code": RECOVERY_CODE_ALIASES.get(code, code)}
        for code in [*safe_onboarding["blockers"], *safe_runtime.get("blocked_on", [])]
    ] + [
        {**gate, "code": RECOVERY_CODE_ALIASES.get(gate["code"], gate["code"])}
        for gate in safe_onboarding["external_gates"]
    ]
    core: dict[str, Any] = {
        "schema": SCHEMA, "classification": CLASSIFICATION,
        "production_ready": False, "readiness_evidence": False,
        "installed": safe_install, "onboarding": safe_onboarding,
        "recovery": recovery.recovery_report(gates),
        "runtime": safe_runtime, "owned_processes": owned_processes,
        "logs": logs,
        "bundle_install_metadata": {
            "current_bundle_digest": safe_install["current_bundle_digest"],
            "installed_bundle_count": len(safe_install["bundle_digests"]),
            "install_history_digest": hashlib.sha256(_canonical(safe_install["history"])).hexdigest(),
        },
    }
    core["privacy_scan"] = _privacy_scan(core)
    return {**core, "manifest_digest": hashlib.sha256(_canonical(core)).hexdigest()}


def _validate_onboarding_projection(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    projected = _project_onboarding(value)
    if projected != value:
        raise DiagnosticsError("DIAGNOSTICS_ONBOARDING_INVALID")
    return projected


def _validate_processes(value: object, runtime: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != runtime["process_count"] or len(value) > 16:
        raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
    if runtime["status"] == "NOT_RUNNING":
        if value != []:
            raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
        return []
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "ownership", "identity"}:
            raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
        name, ownership, identity = item["name"], item["ownership"], item["identity"]
        if name not in SAFE_PROCESS_NAMES or name in names or ownership not in {"owned", "absent", "mismatch"}:
            raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
        names.add(name)
        if ownership == "owned":
            identity = _hex64(identity, "DIAGNOSTICS_PROCESS_RECORD_INVALID")
        elif identity is not None:
            raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
        result.append({"name": name, "ownership": ownership, "identity": identity})
    expected_names = {
        "foundation-readonly": ["relay", "gateway"],
        "official-agent-local": ["opencode", "product-host", "gateway"],
        "remote-local-evidence": [
            "relay-host", "relay-device", "opencode", "product-host",
            "desktop-gateway", "join-gateway", "https-ingress",
        ],
    }[runtime["mode"]]
    if [item["name"] for item in result] != expected_names:
        raise DiagnosticsError("DIAGNOSTICS_PROCESS_RECORD_INVALID")
    return result


def _validate_logs(value: object, owned_processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_names = [item["name"] for item in owned_processes if item["ownership"] == "owned"]
    if not isinstance(value, list) or len(value) != len(expected_names):
        raise DiagnosticsError("DIAGNOSTICS_LOG_METADATA_INVALID")
    result: list[dict[str, Any]] = []
    for expected_name, item in zip(expected_names, value, strict=True):
        if (
            not isinstance(item, dict) or set(item) != {"process_name", "size_bytes", "raw_sha256"}
            or item.get("process_name") != expected_name
            or type(item.get("size_bytes")) is not int
            or not 0 <= item["size_bytes"] <= MAX_LOG_BYTES
        ):
            raise DiagnosticsError("DIAGNOSTICS_LOG_METADATA_INVALID")
        result.append({
            "process_name": expected_name, "size_bytes": item["size_bytes"],
            "raw_sha256": _hex64(item.get("raw_sha256"), "DIAGNOSTICS_LOG_METADATA_INVALID"),
        })
    return result


def _expected_recovery(
    onboarding: Mapping[str, Any], runtime: Mapping[str, Any]
) -> dict[str, Any]:
    gates = [
        {"status": "BLOCK", "code": RECOVERY_CODE_ALIASES.get(code, code)}
        for code in [*onboarding["blockers"], *runtime.get("blocked_on", [])]
    ] + [
        {**gate, "code": RECOVERY_CODE_ALIASES.get(gate["code"], gate["code"])}
        for gate in onboarding["external_gates"]
    ]
    return recovery.recovery_report(gates)


def _reconstruct(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != TOP_LEVEL_KEYS:
        raise DiagnosticsError("DIAGNOSTICS_SCHEMA_INVALID")
    if (
        value.get("schema") != SCHEMA or value.get("classification") != CLASSIFICATION
        or value.get("production_ready") is not False
        or value.get("readiness_evidence") is not False
    ):
        raise DiagnosticsError("DIAGNOSTICS_CLASSIFICATION_INVALID")
    installed_raw = value.get("installed")
    if not isinstance(installed_raw, dict):
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
    installed = _project_install(installed_raw)
    if installed != installed_raw:
        raise DiagnosticsError("DIAGNOSTICS_INSTALL_STATE_INVALID")
    onboarding = _validate_onboarding_projection(value.get("onboarding"))
    runtime = _validate_runtime_projection(value.get("runtime"))
    owned_processes = _validate_processes(value.get("owned_processes"), runtime)
    logs = _validate_logs(value.get("logs"), owned_processes)
    expected_install_sequence = (
        installed["history"][-1]["sequence"] if installed["history"] else None
    )
    runtime_identity = runtime.get("identity", {})
    running_identity = runtime_identity.get("running", {})
    paired_identity = runtime_identity.get("paired_device", {})
    expected_run_identity = (
        running_identity.get("run_identity")
        if running_identity.get("availability") == "READY" else None
    )
    expected_device = (
        paired_identity.get("device_key_commitment")
        if paired_identity.get("availability") == "READY" else None
    )
    expected_epoch = (
        paired_identity.get("pairing_epoch")
        if paired_identity.get("availability") == "READY" else None
    )
    if (
        onboarding["installed_bundle_digest"] != installed["current_bundle_digest"]
        or onboarding["install_sequence"] != expected_install_sequence
        or onboarding["run_identity"] != expected_run_identity
        or onboarding["paired_device_commitment"] != expected_device
        or onboarding["pairing_epoch"] != expected_epoch
    ):
        raise DiagnosticsError("DIAGNOSTICS_CROSS_BINDING_INVALID")
    if runtime["status"] == "RUNNING" and runtime["bundle_digest"] != installed["current_bundle_digest"]:
        expected_drift = (
            "RUNNING_WITHOUT_VERIFIED_INSTALL"
            if installed["current_bundle_digest"] is None
            else "RUNNING_IDENTITY_MISMATCH"
        )
        if (
            onboarding["state"] != "RUNNING_DEGRADED_RECOVERY_REQUIRED"
            or expected_drift not in onboarding["blockers"]
        ):
            raise DiagnosticsError("DIAGNOSTICS_CROSS_BINDING_INVALID")
    expected_recovery = _expected_recovery(onboarding, runtime)
    if value.get("recovery") != expected_recovery:
        raise DiagnosticsError("DIAGNOSTICS_RECOVERY_INVALID")
    expected_metadata = {
        "current_bundle_digest": installed["current_bundle_digest"],
        "installed_bundle_count": len(installed["bundle_digests"]),
        "install_history_digest": hashlib.sha256(_canonical(installed["history"])).hexdigest(),
    }
    if value.get("bundle_install_metadata") != expected_metadata:
        raise DiagnosticsError("DIAGNOSTICS_BUNDLE_METADATA_INVALID")
    if value.get("privacy_scan") != PRIVACY_SCAN:
        raise DiagnosticsError("DIAGNOSTICS_PRIVACY_POLICY_FAILED")
    core = {
        "schema": SCHEMA, "classification": CLASSIFICATION,
        "production_ready": False, "readiness_evidence": False,
        "installed": installed, "onboarding": onboarding,
        "recovery": expected_recovery, "runtime": runtime,
        "owned_processes": owned_processes, "logs": logs,
        "bundle_install_metadata": expected_metadata,
        "privacy_scan": dict(PRIVACY_SCAN),
    }
    digest = value.get("manifest_digest")
    expected_digest = hashlib.sha256(_canonical(core)).hexdigest()
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise DiagnosticsError("DIAGNOSTICS_MANIFEST_DIGEST_INVALID")
    if digest != expected_digest:
        raise DiagnosticsError("DIAGNOSTICS_MANIFEST_DIGEST_MISMATCH")
    return {**core, "manifest_digest": expected_digest}


def verify(value: Mapping[str, Any]) -> None:
    if not isinstance(value, dict):
        raise DiagnosticsError("DIAGNOSTICS_SCHEMA_INVALID")
    rebuilt = _reconstruct(value)
    if rebuilt != value or _canonical(rebuilt) != _canonical(value):
        raise DiagnosticsError("DIAGNOSTICS_CANONICAL_RECONSTRUCTION_MISMATCH")


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise DiagnosticsError("DIAGNOSTICS_OUTPUT_WRITE_FAILED")
        view = view[written:]


def export(config: Any, output: Path | str) -> dict[str, Any]:
    """Collect and atomically publish one exclusive mode-0600 JSON bundle."""
    value = collect(config)
    verify(value)
    raw = _canonical(value) + b"\n"
    if len(raw) > MAX_OUTPUT_BYTES:
        raise DiagnosticsError("DIAGNOSTICS_OUTPUT_TOO_LARGE")
    output = Path(output).absolute()
    protected_suffix = ("testkit", "process-loop", "last-transcript.json")
    if tuple(output.parts[-3:]) == protected_suffix:
        raise DiagnosticsError("DIAGNOSTICS_PROTECTED_TRANSCRIPT_FORBIDDEN")
    parent = output.parent
    if output.name in {"", ".", ".."}:
        raise DiagnosticsError("DIAGNOSTICS_OUTPUT_DIRECTORY_INVALID")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory = os.open(parent, flags)
        parent_info = os.fstat(directory)
    except OSError as error:
        raise DiagnosticsError("DIAGNOSTICS_OUTPUT_DIRECTORY_INVALID") from error
    if (
        not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
        or parent_info.st_mode & 0o022
    ):
        os.close(directory)
        raise DiagnosticsError("DIAGNOSTICS_OUTPUT_DIRECTORY_INVALID")
    directory_identity = (
        parent_info.st_dev, parent_info.st_ino, parent_info.st_uid,
        stat.S_IMODE(parent_info.st_mode),
    )
    temporary = f".{output.name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    published = False
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600, dir_fd=directory,
        )
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        current = os.fstat(directory)
        if (current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode)) != directory_identity:
            raise DiagnosticsError("DIAGNOSTICS_OUTPUT_DIRECTORY_CHANGED")
        try:
            os.link(
                temporary, output.name, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise DiagnosticsError("DIAGNOSTICS_OUTPUT_EXISTS") from error
        published = True
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        current = os.fstat(directory)
        if (current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode)) != directory_identity:
            raise DiagnosticsError("DIAGNOSTICS_OUTPUT_DIRECTORY_CHANGED")
    except DiagnosticsError:
        if published:
            try:
                os.unlink(output.name, dir_fd=directory)
                published = False
                os.fsync(directory)
            except OSError as rollback_error:
                raise DiagnosticsError("DIAGNOSTICS_OUTPUT_ROLLBACK_FAILED") from rollback_error
        raise
    except OSError as error:
        if error.errno == errno.EEXIST:
            raise DiagnosticsError("DIAGNOSTICS_OUTPUT_EXISTS") from error
        raise DiagnosticsError("DIAGNOSTICS_OUTPUT_PUBLICATION_FAILED") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)
    if not published:
        raise DiagnosticsError("DIAGNOSTICS_OUTPUT_PUBLICATION_FAILED")
    return value


__all__ = ["CLASSIFICATION", "DiagnosticsError", "SCHEMA", "collect", "export", "verify"]
