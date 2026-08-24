#!/usr/bin/env python3
"""Read-only B0.1 verifier for a reviewed lifecycle evidence manifest."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Mapping

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 128 * 1024
SOURCE_MAX_BYTES = 512 * 1024
FIELDS = frozenset({
    "schema_version", "certificate_digest", "shape_manifest_digest",
    "certificate_structural_digest", "source_binding_digest",
    "historical_certified_launch_provenance_digest", "task_spec_digest",
    "fixture_manifest_digest", "command_shapes_canonical_digest",
    "rule_config_digest", "current_committed_evidence_provenance_digest",
    "reviewed_version", "evidence_manifest_digest",
})
SOURCE_BINDING_FIELDS = (
    "certificate_structural_digest", "launch_provenance_digest", "task_spec_digest",
    "fixture_manifest_digest", "command_shapes_canonical_digest", "rule_config_digest",
)
RULES = (
    {"permission": "read", "pattern": "*", "action": "allow"},
    {"permission": "edit", "pattern": "*", "action": "allow"},
    {"permission": "question", "pattern": "*", "action": "allow"},
    {"permission": "bash", "pattern": "*", "action": "deny"},
    {"permission": "bash", "pattern": "node test/arithmetic.test.js", "action": "ask"},
)
CERTIFICATE_FIELDS = frozenset({"schema_version", "expected_event_sequence", "diff_file_count", "v1_routes_verified", "v2_routes_verified", "structural_digest"})
SHAPE_FIELDS = frozenset({
    "schema_version", "certificate_structural_digest", "launch_provenance_digest", "task_spec_digest", "fixture_manifest_digest", "command_shapes_canonical_digest", "rule_config_digest", "source_binding_digest", "events", "snapshot_cardinalities", "session_id_equality", "question_snapshot_id_used_in_reply_route", "permission_snapshot_id_used_in_reply_route", "question_permission_ids_distinct", "diff_count_relation", "permission_name_is_bash", "patterns_is_single_string_list", "pattern_matches_fixed_test_command", "manifest_digest",
})
CERTIFICATE_V1_ROUTES = ["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"]
CERTIFICATE_V2_ROUTES = ["/api/session/{sessionID}/prompt", "/api/session/{sessionID}/question/{requestID}/reply", "/api/session/{sessionID}/permission/{requestID}/reply", "/api/session/{sessionID}/interrupt"]
MARKER_ORDER = ("created", "question", "diff", "permission")
MARKER_CANDIDATES = {"created": frozenset({"session.created"}), "question": frozenset({"question.asked", "question.v2.asked"}), "diff": frozenset({"session.diff"}), "permission": frozenset({"permission.asked", "permission.v2.asked"})}
RELATION_FIELDS = ("session_id_equality", "question_snapshot_id_used_in_reply_route", "permission_snapshot_id_used_in_reply_route", "question_permission_ids_distinct", "permission_name_is_bash", "patterns_is_single_string_list", "pattern_matches_fixed_test_command")
CARDINALITIES = {"/session/{id}": 1, "/question": 1, "/permission": 1, "/session/{id}/diff": 1}
SAFE_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
SECRET_NAME = re.compile(r"api_key|secret|credential|token|password|authorization|auth", re.I)
ASCII_EVENT = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
# Frozen A4.2 policy copy: this verifier must not import the discovery writer.
POLICY = {
    "session.created": {"": {"sessionID", "info"}, "info": {"id", "slug", "projectID", "directory", "title", "version", "time", "agent", "cost", "metadata", "model", "parentID", "permission", "revert", "share", "summary", "tokens", "workspaceID", "path"}, "info.time": {"created", "updated", "archived", "compacting"}, "info.model": {"id", "providerID", "variant"}, "info.tokens": {"input", "output", "reasoning", "cache"}, "info.tokens.cache": {"read", "write"}, "info.summary": {"additions", "deletions", "files", "diffs"}, "info.summary.diffs": {"file", "additions", "deletions", "status", "patch"}, "info.permission": {"permission", "pattern", "action"}, "info.revert": {"messageID", "partID", "snapshot", "diff"}, "info.share": {"url"}},
    "question.asked": {"": {"id", "sessionID", "questions", "tool"}, "questions": {"question", "header", "options", "multiple", "custom"}, "questions.options": {"label", "description"}, "tool": {"messageID", "callID"}},
    "question.v2.asked": {"": {"id", "sessionID", "questions", "tool"}, "questions": {"question", "header", "options", "multiple", "custom"}, "questions.options": {"label", "description"}, "tool": {"messageID", "callID"}},
    "session.diff": {"": {"sessionID", "diff"}, "diff": {"file", "additions", "deletions", "status", "patch"}},
    "permission.asked": {"": {"id", "sessionID", "permission", "patterns", "metadata", "always", "tool"}, "tool": {"messageID", "callID"}},
    "permission.v2.asked": {"": {"id", "sessionID", "action", "resources", "metadata", "save", "source"}, "source": {"type", "messageID", "callID"}},
}
HEX = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[\x21-\x7e]{1,128}$")
FORBIDDEN = re.compile(r"api[_-]?key|secret|credential|authorization|prompt|raw[_-]?(?:session|question|permission)?[_-]?id|command_body|diff_content|tool[_-]?output", re.I)


@dataclass(frozen=True)
class Verdict:
    status: str
    code: str


class DuplicateKey(ValueError):
    pass


class NotRegularFile(OSError):
    pass


class EvidenceDerivationError(ValueError):
    """Closed, content-free failure from evidence derivation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def raw_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bytes(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile(str(path))
        chunks: list[bytes] = []; remaining = limit + 1
        while remaining:
            piece = os.read(fd, min(65536, remaining))
            if not piece:
                break
            chunks.append(piece); remaining -= len(piece)
        result = b"".join(chunks)
        if len(result) > limit:
            raise OverflowError(str(path))
        return result
    finally:
        os.close(fd)


def _read_json(path: Path, limit: int) -> object:
    return json.loads(_read_bytes(path, limit).decode("utf-8"), object_pairs_hook=_pairs)


def _read_verdict(prefix: str, error: Exception) -> Verdict:
    if isinstance(error, (FileNotFoundError, NotRegularFile, OSError)):
        return Verdict("BLOCKED", f"BLOCKED_EVIDENCE_MANIFEST_{prefix}_MISSING")
    if isinstance(error, OverflowError):
        return Verdict("FAIL", f"FAIL_EVIDENCE_MANIFEST_{prefix}_SIZE")
    if isinstance(error, UnicodeDecodeError):
        return Verdict("FAIL", f"FAIL_EVIDENCE_MANIFEST_{prefix}_UTF8")
    if isinstance(error, DuplicateKey):
        return Verdict("FAIL", f"FAIL_EVIDENCE_MANIFEST_{prefix}_DUPLICATE")
    return Verdict("FAIL", f"FAIL_EVIDENCE_MANIFEST_{prefix}_JSON")


def _locked_closure(lock: object) -> tuple[int, str]:
    if not isinstance(lock, dict) or lock.get("lockfileVersion") not in (2, 3) or not isinstance(lock.get("packages"), dict):
        raise ValueError
    entries = []
    for location, entry in lock["packages"].items():
        if location == "":
            continue
        if not isinstance(location, str) or not isinstance(entry, dict) or entry.get("link"):
            raise ValueError
        version, integrity, resolved = entry.get("version"), entry.get("integrity"), entry.get("resolved")
        if not isinstance(version, str) or not isinstance(integrity, str) or not isinstance(resolved, str) or not resolved.startswith("https://registry.npmjs.org/"):
            raise ValueError
        name = _package_name_from_location(location)
        entries.append((name, version, integrity))
    if not entries:
        raise ValueError
    return len(entries), canonical_digest(sorted(entries))


def _package_name_from_location(location: str) -> str:
    """Mirror capture's last-node_modules package extraction with strict paths."""
    if not isinstance(location, str) or not location.startswith("node_modules/"):
        raise ValueError
    parts = location.split("/")
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules" or index + 1 >= len(parts):
            raise ValueError
        index += 1
        if parts[index].startswith("@"):
            if index + 1 >= len(parts) or len(parts[index]) == 1 or parts[index].count("@") != 1 or not parts[index + 1] or "@" in parts[index + 1]:
                raise ValueError
            name = parts[index] + "/" + parts[index + 1]; index += 2
        else:
            if not parts[index] or parts[index].startswith("@"):
                raise ValueError
            name = parts[index]; index += 1
        if index == len(parts):
            return name
    raise ValueError


def _current_sources() -> tuple[str, str, str, str]:
    task = _read_json(ROOT / "real-task/task-spec.json", SOURCE_MAX_BYTES)
    fixture = _read_json(ROOT / "real-task/fixture-manifest.json", SOURCE_MAX_BYTES)
    shapes = _read_json(ROOT / "real-task/command-shapes.json", SOURCE_MAX_BYTES)
    task_fields = {"schema", "data_boundary", "fixture_files", "task_flow", "forbidden_persisted_content"}
    if (not isinstance(task, dict) or set(task) != task_fields or task.get("schema") != "nomad.stock-opencode.disposable-task.v1"
            or not isinstance(task.get("data_boundary"), dict) or not isinstance(task.get("fixture_files"), list)
            or not isinstance(task.get("task_flow"), list) or not isinstance(task.get("forbidden_persisted_content"), list)
            or not isinstance(fixture, dict) or not isinstance(shapes, dict)):
        raise ValueError
    fixture_digest = fixture.get("digest")
    fixture_names = {"README.md", "src/arithmetic.js", "test/arithmetic.test.js"}
    files = fixture.get("files")
    if (set(fixture) != {"schema", "files", "digest"} or fixture.get("schema") != "nomad.stock-opencode.fixture-manifest.v1"
            or not isinstance(files, list) or len(files) != 3 or {item.get("relative_name") for item in files if isinstance(item, dict)} != fixture_names
            or any(not isinstance(item, dict) or set(item) != {"content_class", "relative_name", "sha256", "size"} or item.get("content_class") != "project_owned_static_fixture" or not isinstance(item.get("sha256"), str) or not HEX.fullmatch(item["sha256"]) or type(item.get("size")) is not int or item["size"] < 0 for item in files)
            or not isinstance(fixture_digest, str) or not HEX.fullmatch(fixture_digest) or fixture_digest != canonical_digest(files)):
        raise ValueError
    actions = shapes.get("actions")
    expected_actions = {"session_prompt", "question_reply", "question_reject", "permission_reply", "stop"}
    if (set(shapes) != {"schema", "classification", "runtime_provenance_digest", "actions"}
            or shapes.get("schema") != "nomad.stock-opencode.command-shapes.v1"
            or shapes.get("classification") != "official_shape_only_not_lifecycle"
            or not isinstance(shapes.get("runtime_provenance_digest"), str) or not HEX.fullmatch(shapes["runtime_provenance_digest"])
            or not isinstance(actions, dict) or set(actions) != expected_actions):
        raise ValueError
    return canonical_digest(task), fixture_digest, canonical_digest(shapes), canonical_digest(RULES)


def _valid_certificate(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != CERTIFICATE_FIELDS or value.get("schema_version") != "nomad.stock-opencode.lifecycle-certificate.v1":
        return False
    events = value.get("expected_event_sequence")
    if (not isinstance(events, list) or len(events) != len(MARKER_ORDER)
            or any(not isinstance(event, str) or not ASCII_EVENT.fullmatch(event) or event not in MARKER_CANDIDATES[marker] for event, marker in zip(events, MARKER_ORDER))):
        return False
    if type(value.get("diff_file_count")) is not int or not 1 <= value["diff_file_count"] <= 10000:
        return False
    if value.get("v1_routes_verified") != CERTIFICATE_V1_ROUTES or value.get("v2_routes_verified") != CERTIFICATE_V2_ROUTES:
        return False
    core = {key: value[key] for key in CERTIFICATE_FIELDS - {"structural_digest"}}
    return isinstance(value.get("structural_digest"), str) and HEX.fullmatch(value["structural_digest"]) and value["structural_digest"] == canonical_digest(core)


def _valid_shape_node(shape: object, policy: dict[str, set[str]], path: str = "", depth: int = 0) -> bool:
    if not isinstance(shape, dict) or set(shape) - {"type", "items", "properties", "dynamic_keys", "field_count", "count"}:
        return False
    kind = shape.get("type")
    if kind not in {"null", "bool", "int", "float", "str", "list", "dict", "mixed"}:
        return False
    if kind == "list":
        return set(shape) == {"type", "items", "count"} and type(shape.get("count")) is int and 0 <= shape["count"] <= 10000 and _valid_shape_node(shape.get("items"), policy, path, depth + 1)
    if kind == "dict":
        if shape.get("dynamic_keys") is True:
            return path.endswith("metadata") and set(shape) == {"type", "dynamic_keys", "field_count"} and type(shape.get("field_count")) is int and 0 <= shape["field_count"] <= 16
        if depth > 3:
            return set(shape) == {"type"}
        props = shape.get("properties")
        return set(shape) == {"type", "properties"} and isinstance(props, dict) and len(props) <= 16 and all(isinstance(key, str) and SAFE_NAME.fullmatch(key) and key in policy.get(path, set()) and (not SECRET_NAME.search(key) or key == "tokens") and _valid_shape_node(item, policy, key if not path else path + "." + key, depth + 1) for key, item in props.items())
    return set(shape) == {"type"}


def _valid_shape_manifest(shape: object, certificate: dict[str, Any]) -> bool:
    if not isinstance(shape, dict) or set(shape) != SHAPE_FIELDS or shape.get("schema_version") != "nomad.stock-opencode.lifecycle-shape-manifest.v1":
        return False
    digest_fields = SOURCE_BINDING_FIELDS + ("source_binding_digest", "manifest_digest")
    if any(not isinstance(shape.get(name), str) or not HEX.fullmatch(shape[name]) for name in digest_fields):
        return False
    if shape["certificate_structural_digest"] != certificate["structural_digest"]:
        return False
    source = {name: shape[name] for name in SOURCE_BINDING_FIELDS}
    if shape["source_binding_digest"] != canonical_digest(source):
        return False
    events = shape.get("events")
    if not isinstance(events, list) or len(events) != len(MARKER_ORDER):
        return False
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {"marker", "observed_event_type", "property_field_count", "property_field_names", "property_field_types"}:
            return False
        marker, names, types = MARKER_ORDER[index], event.get("property_field_names"), event.get("property_field_types")
        if (event.get("marker") != marker or event.get("observed_event_type") not in MARKER_CANDIDATES[marker] or type(event.get("property_field_count")) is not int or not isinstance(names, list) or not isinstance(types, dict) or event["property_field_count"] != len(names) == len(types) or names != sorted(names) or len(names) != len(set(names)) or set(names) != set(types) or any(not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or name not in POLICY[event["observed_event_type"]].get("", set()) or (SECRET_NAME.search(name) and name != "tokens") for name in names) or not all(_valid_shape_node(item, POLICY[event["observed_event_type"]], name, 1) for name, item in types.items())):
            return False
    if shape.get("snapshot_cardinalities") != CARDINALITIES or not all(shape.get(name) is True for name in RELATION_FIELDS) or shape.get("diff_count_relation") != "files_ge_1":
        return False
    core = {name: value for name, value in shape.items() if name != "manifest_digest"}
    return shape["manifest_digest"] == canonical_digest(core)


def _validate_pair(certificate: dict[str, Any], shape: dict[str, Any]) -> bool:
    if not _valid_certificate(certificate) or not _valid_shape_manifest(shape, certificate):
        return False
    structural = certificate["structural_digest"]
    source = {key: shape.get(key) for key in SOURCE_BINDING_FIELDS}
    return all(isinstance(value, str) and HEX.fullmatch(value) for value in source.values()) and shape["source_binding_digest"] == canonical_digest(source) and shape["certificate_structural_digest"] == structural


def _committed_provenance() -> str:
    official = _read_json(ROOT / "official-stock-contract.json", SOURCE_MAX_BYTES)
    capture = _read_json(ROOT / "capture-manifest.json", SOURCE_MAX_BYTES)
    script = _read_bytes(ROOT / "capture_contract.py", SOURCE_MAX_BYTES)
    package = _read_bytes(ROOT / "locked-runtime/package.json", SOURCE_MAX_BYTES)
    lock_bytes = _read_bytes(ROOT / "locked-runtime/package-lock.json", SOURCE_MAX_BYTES)
    lock = json.loads(lock_bytes.decode("utf-8"), object_pairs_hook=_pairs)
    package_value = json.loads(package.decode("utf-8"), object_pairs_hook=_pairs)
    if (not isinstance(official, dict) or not isinstance(capture, dict) or not isinstance(official.get("provenance"), dict)
            or official.get("schema") != "nomad.stock-opencode.contract-capture.v2"
            or capture.get("schema") != "nomad.stock-opencode.capture-manifest.v3"
            or not isinstance(package_value, dict)
            or package_value.get("name") != "nomad-stock-opencode-locked-runtime" or package_value.get("version") != "1.0.0"
            or package_value.get("private") is not True or package_value.get("packageManager") != "npm@11.12.1"
            or package_value.get("dependencies") != {"opencode-ai": "1.18.16"}):
        raise ValueError
    count, closure = _locked_closure(lock)
    provenance = official["provenance"]
    actual = {
        "fixture_canonical_sha256": canonical_digest(official),
        "capture_contract_sha256": raw_digest(script),
        "package_json_sha256": raw_digest(package),
        "package_lock_sha256": raw_digest(lock_bytes),
        "full_locked_dependency_count": count,
        "full_locked_dependency_digest": closure,
        "classification": provenance.get("classification"),
        "execution_provenance_scope": provenance.get("execution_provenance_scope"),
        "observed_installed_entrypoint_wrapper_sha256": provenance.get("observed_installed_entrypoint_wrapper_sha256"),
        "observed_installed_entrypoint_target_sha256": provenance.get("observed_installed_entrypoint_target_sha256"),
    }
    for key, value in actual.items():
        if capture.get(key) != value:
            raise ValueError
        if key in {"package_json_sha256", "package_lock_sha256", "full_locked_dependency_count", "full_locked_dependency_digest", "classification", "execution_provenance_scope", "observed_installed_entrypoint_wrapper_sha256", "observed_installed_entrypoint_target_sha256"} and provenance.get(key) != value:
            raise ValueError
    for key in ("classification", "execution_provenance_scope", "observed_installed_entrypoint_wrapper_sha256", "observed_installed_entrypoint_target_sha256", "npm_version", "os", "arch"):
        if capture.get(key) != provenance.get(key):
            raise ValueError
    if (provenance.get("classification") != "official_registry_integrity_bound_stock_contract"
            or provenance.get("npm_version") != "11.12.1" or provenance.get("os") != "darwin"
            or provenance.get("arch") != "arm64" or provenance.get("package") != "opencode-ai"
            or provenance.get("version") != "1.18.16"):
        raise ValueError
    if any(not isinstance(actual[key], str) or not HEX.fullmatch(actual[key]) for key in ("observed_installed_entrypoint_wrapper_sha256", "observed_installed_entrypoint_target_sha256")):
        raise ValueError
    return canonical_digest({
        "official_contract_canonical_digest": actual["fixture_canonical_sha256"],
        "capture_contract_raw_digest": actual["capture_contract_sha256"],
        "package_json_raw_digest": actual["package_json_sha256"],
        "package_lock_raw_digest": actual["package_lock_sha256"],
        "full_locked_dependency_digest": closure,
        "full_locked_dependency_count": count,
        "classification": actual["classification"],
        "execution_provenance_scope": actual["execution_provenance_scope"],
        "observed_installed_entrypoint_wrapper_sha256": actual["observed_installed_entrypoint_wrapper_sha256"],
        "observed_installed_entrypoint_target_sha256": actual["observed_installed_entrypoint_target_sha256"],
        "npm_version": "11.12.1", "os": "darwin", "arch": "arm64",
    })


def _content_free(value: object) -> bool:
    if isinstance(value, dict):
        return all(isinstance(key, str) and not FORBIDDEN.search(key) and _content_free(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_content_free(item) for item in value)
    return not isinstance(value, str) or not FORBIDDEN.search(value)


def derive_evidence_manifest(
    certificate: Mapping[str, object], shape_manifest: Mapping[str, object], reviewed_version: str,
) -> dict[str, str]:
    """Derive one fresh, content-free B0 manifest from a valid A3/A4 pair."""
    cert = dict(certificate)
    shape = dict(shape_manifest)
    if not _valid_certificate(cert) or not _valid_shape_manifest(shape, cert):
        raise EvidenceDerivationError("FAIL_EVIDENCE_MANIFEST_PAIR_INTEGRITY")
    if not isinstance(reviewed_version, str) or not VERSION.fullmatch(reviewed_version):
        raise EvidenceDerivationError("FAIL_EVIDENCE_MANIFEST_REVIEWED_VERSION")
    try:
        task, fixture, command_shapes, rules = _current_sources()
    except (FileNotFoundError, NotRegularFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError, ValueError):
        raise EvidenceDerivationError("FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT") from None
    try:
        provenance = _committed_provenance()
    except (FileNotFoundError, NotRegularFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError):
        raise EvidenceDerivationError("FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE") from None
    except ValueError:
        raise EvidenceDerivationError("FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE") from None
    core = {
        "schema_version": "nomad.stock-opencode.evidence-manifest.v1",
        "certificate_digest": canonical_digest(cert), "shape_manifest_digest": canonical_digest(shape),
        "certificate_structural_digest": cert["structural_digest"], "source_binding_digest": shape["source_binding_digest"],
        "historical_certified_launch_provenance_digest": shape["launch_provenance_digest"],
        "task_spec_digest": task, "fixture_manifest_digest": fixture,
        "command_shapes_canonical_digest": command_shapes, "rule_config_digest": rules,
        "current_committed_evidence_provenance_digest": provenance, "reviewed_version": reviewed_version,
    }
    return {**core, "evidence_manifest_digest": canonical_digest(core)}


def verify_evidence_manifest(evidence_path: Path, certificate_path: Path, shape_path: Path) -> Verdict:
    for prefix, path in (("CERTIFICATE", certificate_path), ("SHAPE", shape_path), ("MANIFEST", evidence_path)):
        try:
            value = _read_json(path, MAX_BYTES)
        except (FileNotFoundError, NotRegularFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError) as error:
            return _read_verdict(prefix, error)
        if prefix == "CERTIFICATE": certificate = value
        elif prefix == "SHAPE": shape = value
        else: evidence = value
    if not isinstance(certificate, dict) or not isinstance(shape, dict) or not isinstance(evidence, dict):
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_FIELDS")
    if set(evidence) != FIELDS:
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_FIELDS")
    if evidence["schema_version"] != "nomad.stock-opencode.evidence-manifest.v1":
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_SCHEMA")
    if not _content_free(list(evidence.values())):
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_CONTENT")
    if not VERSION.fullmatch(evidence["reviewed_version"]) if isinstance(evidence.get("reviewed_version"), str) else True:
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_REVIEWED_VERSION")
    digest_fields = FIELDS - {"schema_version", "reviewed_version"}
    if any(not isinstance(evidence.get(key), str) or not HEX.fullmatch(evidence[key]) for key in digest_fields):
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_DIGEST_FORMAT")
    if evidence["certificate_digest"] != canonical_digest(certificate) or evidence["shape_manifest_digest"] != canonical_digest(shape):
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_PAIR_BINDING")
    try:
        derived = derive_evidence_manifest(certificate, shape, evidence["reviewed_version"])
    except EvidenceDerivationError as error:
        return Verdict("FAIL", error.code)
    if evidence != derived:
        if evidence["certificate_digest"] != derived["certificate_digest"] or evidence["shape_manifest_digest"] != derived["shape_manifest_digest"]:
            return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_PAIR_BINDING")
        if evidence["certificate_structural_digest"] != derived["certificate_structural_digest"]:
            return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_STRUCTURAL_BINDING")
        if any(evidence[key] != derived[key] for key in ("source_binding_digest", "historical_certified_launch_provenance_digest")):
            return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_HISTORICAL_BINDING")
        if any(evidence[key] != derived[key] for key in ("task_spec_digest", "fixture_manifest_digest", "command_shapes_canonical_digest", "rule_config_digest")):
            return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT")
        if evidence["current_committed_evidence_provenance_digest"] != derived["current_committed_evidence_provenance_digest"]:
            return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE")
        return Verdict("FAIL", "FAIL_EVIDENCE_MANIFEST_DIGEST")
    return Verdict("VERIFIED", "VERIFIED")


def main() -> int:
    verdict = verify_evidence_manifest(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])) if len(sys.argv) == 4 else Verdict("BLOCKED", "BLOCKED_EVIDENCE_MANIFEST_MANIFEST_MISSING")
    (sys.stdout if verdict.status == "VERIFIED" else sys.stderr).write(verdict.code + "\n")
    return 0 if verdict.status == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
