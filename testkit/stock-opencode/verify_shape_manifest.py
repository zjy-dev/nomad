#!/usr/bin/env python3
"""Read-only verifier for A4 lifecycle shape manifests; no unlock authority."""
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

ROOT = Path(__file__).resolve().parent
MAX_MANIFEST_BYTES = 128 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 512 * 1024

FIELDS = frozenset({
    "schema_version", "certificate_structural_digest", "launch_provenance_digest",
    "task_spec_digest", "fixture_manifest_digest",
    "command_shapes_canonical_digest", "rule_config_digest",
    "source_binding_digest", "events", "snapshot_cardinalities",
    "session_id_equality", "question_snapshot_id_used_in_reply_route",
    "permission_snapshot_id_used_in_reply_route", "question_permission_ids_distinct",
    "diff_count_relation", "permission_name_is_bash",
    "patterns_is_single_string_list", "pattern_matches_fixed_test_command",
    "manifest_digest",
})
CERTIFICATE_FIELDS = frozenset({
    "schema_version", "expected_event_sequence", "diff_file_count",
    "v1_routes_verified", "v2_routes_verified", "structural_digest",
})
CERTIFICATE_V1_ROUTES = ["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"]
CERTIFICATE_V2_ROUTES = [
    "/api/session/{sessionID}/prompt",
    "/api/session/{sessionID}/question/{requestID}/reply",
    "/api/session/{sessionID}/permission/{requestID}/reply",
    "/api/session/{sessionID}/interrupt",
]
MARKER_ORDER = ("created", "question", "diff", "permission")
MARKER_CANDIDATES = {
    "created": frozenset({"session.created"}),
    "question": frozenset({"question.asked", "question.v2.asked"}),
    "diff": frozenset({"session.diff"}),
    "permission": frozenset({"permission.asked", "permission.v2.asked"}),
}
SOURCE_BINDING_FIELDS = (
    "certificate_structural_digest", "launch_provenance_digest", "task_spec_digest",
    "fixture_manifest_digest", "command_shapes_canonical_digest", "rule_config_digest",
)
RELATION_FIELDS = (
    "session_id_equality", "question_snapshot_id_used_in_reply_route",
    "permission_snapshot_id_used_in_reply_route", "question_permission_ids_distinct",
    "permission_name_is_bash", "patterns_is_single_string_list",
    "pattern_matches_fixed_test_command",
)
CARDINALITIES = {
    "/session/{id}": 1, "/question": 1, "/permission": 1, "/session/{id}/diff": 1,
}
SAFE_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
SECRET_NAME = re.compile(r"api_key|secret|credential|token|password|authorization|auth", re.I)
HEX = re.compile(r"^[0-9a-f]{64}$")
ASCII_EVENT = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")

# Frozen copies: production verification must never import the capture generator.
POLICY = {
    "session.created": {
        "": {"sessionID", "info"},
        "info": {"id", "slug", "projectID", "directory", "title", "version", "time", "agent", "cost", "metadata", "model", "parentID", "permission", "revert", "share", "summary", "tokens", "workspaceID", "path"},
        "info.time": {"created", "updated", "archived", "compacting"},
        "info.model": {"id", "providerID", "variant"},
        "info.tokens": {"input", "output", "reasoning", "cache"},
        "info.tokens.cache": {"read", "write"},
        "info.summary": {"additions", "deletions", "files", "diffs"},
        "info.summary.diffs": {"file", "additions", "deletions", "status", "patch"},
        "info.permission": {"permission", "pattern", "action"},
        "info.revert": {"messageID", "partID", "snapshot", "diff"},
        "info.share": {"url"},
    },
    "question.asked": {"": {"id", "sessionID", "questions", "tool"}, "questions": {"question", "header", "options", "multiple", "custom"}, "questions.options": {"label", "description"}, "tool": {"messageID", "callID"}},
    "question.v2.asked": {"": {"id", "sessionID", "questions", "tool"}, "questions": {"question", "header", "options", "multiple", "custom"}, "questions.options": {"label", "description"}, "tool": {"messageID", "callID"}},
    "session.diff": {"": {"sessionID", "diff"}, "diff": {"file", "additions", "deletions", "status", "patch"}},
    "permission.asked": {"": {"id", "sessionID", "permission", "patterns", "metadata", "always", "tool"}, "tool": {"messageID", "callID"}},
    "permission.v2.asked": {"": {"id", "sessionID", "action", "resources", "metadata", "save", "source"}, "source": {"type", "messageID", "callID"}},
}
RULES = (
    {"permission": "read", "pattern": "*", "action": "allow"},
    {"permission": "edit", "pattern": "*", "action": "allow"},
    {"permission": "question", "pattern": "*", "action": "allow"},
    {"permission": "bash", "pattern": "*", "action": "deny"},
    {"permission": "bash", "pattern": "node test/arithmetic.test.js", "action": "ask"},
)


@dataclass(frozen=True)
class Verdict:
    status: str
    code: str


class DuplicateKey(ValueError):
    """A JSON object contained a duplicate key."""


class NotRegularFile(OSError):
    """The supplied filesystem entry is not a regular file."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result


def digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _read_bounded_regular(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise NotRegularFile(str(path))
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            piece = os.read(fd, min(65536, remaining))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise OverflowError(str(path))
        return raw
    finally:
        os.close(fd)


def _read_json(path: Path, limit: int) -> object:
    raw = _read_bounded_regular(path, limit)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)


def _certificate_read_verdict(error: Exception) -> Verdict:
    if isinstance(error, (FileNotFoundError, NotRegularFile, OSError)):
        return Verdict("BLOCKED", "BLOCKED_CERTIFICATE_MISSING")
    if isinstance(error, OverflowError):
        return Verdict("FAIL", "FAIL_CERTIFICATE_SIZE")
    if isinstance(error, UnicodeDecodeError):
        return Verdict("FAIL", "FAIL_CERTIFICATE_UTF8")
    if isinstance(error, DuplicateKey):
        return Verdict("FAIL", "FAIL_CERTIFICATE_DUPLICATE")
    if isinstance(error, json.JSONDecodeError):
        return Verdict("FAIL", "FAIL_CERTIFICATE_JSON")
    return Verdict("FAIL", "FAIL_CERTIFICATE_READ")


def _validate_certificate(value: object) -> Verdict:
    if not isinstance(value, dict) or set(value) != CERTIFICATE_FIELDS:
        return Verdict("FAIL", "FAIL_CERTIFICATE_FIELDS")
    if value["schema_version"] != "nomad.stock-opencode.lifecycle-certificate.v1":
        return Verdict("FAIL", "FAIL_CERTIFICATE_SCHEMA")
    events = value["expected_event_sequence"]
    if (not isinstance(events, list) or len(events) != len(MARKER_ORDER)
            or any(not isinstance(event, str) or not ASCII_EVENT.fullmatch(event)
                   or event not in MARKER_CANDIDATES[marker]
                   for event, marker in zip(events, MARKER_ORDER))):
        return Verdict("FAIL", "FAIL_CERTIFICATE_EVENTS")
    count = value["diff_file_count"]
    if type(count) is not int or not 1 <= count <= 10000:
        return Verdict("FAIL", "FAIL_CERTIFICATE_DIFF")
    if value["v1_routes_verified"] != CERTIFICATE_V1_ROUTES:
        return Verdict("FAIL", "FAIL_CERTIFICATE_V1_ROUTES")
    if value["v2_routes_verified"] != CERTIFICATE_V2_ROUTES:
        return Verdict("FAIL", "FAIL_CERTIFICATE_V2_ROUTES")
    core = {name: value[name] for name in CERTIFICATE_FIELDS - {"structural_digest"}}
    structural_digest = value["structural_digest"]
    if not isinstance(structural_digest, str) or not HEX.fullmatch(structural_digest) or digest(core) != structural_digest:
        return Verdict("FAIL", "FAIL_CERTIFICATE_DIGEST")
    return Verdict("VERIFIED", "VERIFIED")


def _valid_shape(shape: object, policy: dict[str, set[str]], path: str = "", depth: int = 0) -> bool:
    if not isinstance(shape, dict) or set(shape) - {"type", "items", "properties", "dynamic_keys", "field_count", "count"}:
        return False
    value_type = shape.get("type")
    if value_type not in {"null", "bool", "int", "float", "str", "list", "dict", "mixed"}:
        return False
    if value_type == "list":
        return (set(shape) == {"type", "items", "count"} and type(shape["count"]) is int
                and 0 <= shape["count"] <= 10000 and _valid_shape(shape["items"], policy, path, depth + 1))
    if value_type == "dict":
        if shape.get("dynamic_keys") is True:
            return (path.endswith("metadata") and set(shape) == {"type", "dynamic_keys", "field_count"}
                    and type(shape["field_count"]) is int and 0 <= shape["field_count"] <= 16)
        if depth > 3:
            return set(shape) == {"type"}
        properties = shape.get("properties")
        return (set(shape) == {"type", "properties"} and isinstance(properties, dict)
                and len(properties) <= 16 and all(
                    isinstance(key, str) and SAFE_NAME.fullmatch(key) and key in policy.get(path, set())
                    and (not SECRET_NAME.search(key) or key == "tokens")
                    and _valid_shape(value, policy, key if not path else path + "." + key, depth + 1)
                    for key, value in properties.items()))
    return set(shape) == {"type"}


def _valid_fixture_manifest(value: object) -> str | None:
    if not isinstance(value, dict) or set(value) != {"schema", "files", "digest"}:
        return None
    files = value["files"]
    if value["schema"] != "nomad.stock-opencode.fixture-manifest.v1" or not isinstance(files, list):
        return None
    names = {"README.md", "src/arithmetic.js", "test/arithmetic.test.js"}
    if len(files) != len(names) or {item.get("relative_name") for item in files if isinstance(item, dict)} != names:
        return None
    if any(not isinstance(item, dict) or set(item) != {"content_class", "relative_name", "sha256", "size"}
           or item["content_class"] != "project_owned_static_fixture"
           or not isinstance(item["sha256"], str) or not HEX.fullmatch(item["sha256"])
           or type(item["size"]) is not int or item["size"] < 0 for item in files):
        return None
    manifest_digest = value["digest"]
    return manifest_digest if isinstance(manifest_digest, str) and HEX.fullmatch(manifest_digest) and manifest_digest == digest(files) else None


def _valid_task_spec(value: object) -> bool:
    return isinstance(value, dict) and value.get("schema") == "nomad.stock-opencode.disposable-task.v1" and isinstance(value.get("fixture_files"), list) and isinstance(value.get("task_flow"), list)


def current_sources() -> tuple[str, str, str, str]:
    task = _read_json(ROOT / "real-task/task-spec.json", MAX_SOURCE_BYTES)
    fixture = _read_json(ROOT / "real-task/fixture-manifest.json", MAX_SOURCE_BYTES)
    shapes = _read_json(ROOT / "real-task/command-shapes.json", MAX_SOURCE_BYTES)
    fixture_digest = _valid_fixture_manifest(fixture)
    if not _valid_task_spec(task) or fixture_digest is None or not isinstance(shapes, dict):
        raise ValueError("invalid current source artifact")
    return digest(task), fixture_digest, digest(shapes), digest(RULES)


def _manifest_read_verdict(error: Exception) -> Verdict:
    if isinstance(error, (FileNotFoundError, NotRegularFile, OSError)):
        return Verdict("BLOCKED", "BLOCKED_MANIFEST_MISSING")
    if isinstance(error, OverflowError):
        return Verdict("FAIL", "FAIL_MANIFEST_SIZE")
    if isinstance(error, UnicodeDecodeError):
        return Verdict("FAIL", "FAIL_MANIFEST_UTF8")
    if isinstance(error, DuplicateKey):
        return Verdict("FAIL", "FAIL_MANIFEST_DUPLICATE")
    if isinstance(error, json.JSONDecodeError):
        return Verdict("FAIL", "FAIL_MANIFEST_JSON")
    return Verdict("FAIL", "FAIL_MANIFEST_READ")


def verify_shape_manifest(manifest_path: Path, certificate_path: Path) -> Verdict:
    try:
        certificate = _read_json(certificate_path, MAX_CERTIFICATE_BYTES)
    except (FileNotFoundError, NotRegularFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError) as error:
        return _certificate_read_verdict(error)
    certificate_verdict = _validate_certificate(certificate)
    if certificate_verdict.status != "VERIFIED":
        return certificate_verdict
    try:
        manifest = _read_json(manifest_path, MAX_MANIFEST_BYTES)
    except (FileNotFoundError, NotRegularFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError) as error:
        return _manifest_read_verdict(error)
    if not isinstance(manifest, dict) or set(manifest) != FIELDS:
        return Verdict("FAIL", "FAIL_MANIFEST_FIELDS")
    if manifest["schema_version"] != "nomad.stock-opencode.lifecycle-shape-manifest.v1":
        return Verdict("FAIL", "FAIL_MANIFEST_SCHEMA")
    digest_fields = SOURCE_BINDING_FIELDS + ("source_binding_digest", "manifest_digest")
    if any(not isinstance(manifest[name], str) or not HEX.fullmatch(manifest[name]) for name in digest_fields):
        return Verdict("FAIL", "FAIL_MANIFEST_DIGEST_FORMAT")
    if manifest["certificate_structural_digest"] != certificate.get("structural_digest"):
        return Verdict("FAIL", "FAIL_MANIFEST_CERT_BINDING")
    source = {name: manifest[name] for name in SOURCE_BINDING_FIELDS}
    if manifest["source_binding_digest"] != digest(source):
        return Verdict("FAIL", "FAIL_MANIFEST_SOURCE_BINDING")
    try:
        source_digests = current_sources()
    except (FileNotFoundError, NotRegularFile, OSError, OverflowError, UnicodeDecodeError, DuplicateKey, json.JSONDecodeError, ValueError):
        return Verdict("FAIL", "FAIL_MANIFEST_SOURCE_ARTIFACT")
    if tuple(manifest[name] for name in ("task_spec_digest", "fixture_manifest_digest", "command_shapes_canonical_digest", "rule_config_digest")) != source_digests:
        return Verdict("FAIL", "FAIL_MANIFEST_SOURCE_ARTIFACT")
    events = manifest["events"]
    if not isinstance(events, list) or len(events) != len(MARKER_ORDER):
        return Verdict("FAIL", "FAIL_MANIFEST_EVENTS")
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {"marker", "observed_event_type", "property_field_count", "property_field_names", "property_field_types"}:
            return Verdict("FAIL", "FAIL_MANIFEST_EVENTS")
        marker = MARKER_ORDER[index]
        names = event.get("property_field_names")
        types = event.get("property_field_types")
        if (event.get("marker") != marker or event.get("observed_event_type") not in MARKER_CANDIDATES[marker]
                or type(event.get("property_field_count")) is not int or not isinstance(names, list)
                or not isinstance(types, dict) or event["property_field_count"] != len(names) == len(types)
                or names != sorted(names) or len(names) != len(set(names)) or set(names) != set(types)
                or any(not isinstance(name, str) or not SAFE_NAME.fullmatch(name)
                       or name not in POLICY[event["observed_event_type"]].get("", set())
                       or (SECRET_NAME.search(name) and name != "tokens") for name in types)
                or not all(_valid_shape(shape, POLICY[event["observed_event_type"]], name, 1) for name, shape in types.items())):
            return Verdict("FAIL", "FAIL_MANIFEST_EVENTS")
    if manifest["snapshot_cardinalities"] != CARDINALITIES:
        return Verdict("FAIL", "FAIL_MANIFEST_CARDINALITY")
    if not all(manifest[name] is True for name in RELATION_FIELDS) or manifest["diff_count_relation"] != "files_ge_1":
        return Verdict("FAIL", "FAIL_MANIFEST_RELATIONS")
    core = {name: value for name, value in manifest.items() if name != "manifest_digest"}
    if manifest["manifest_digest"] != digest(core):
        return Verdict("FAIL", "FAIL_MANIFEST_DIGEST")
    return Verdict("VERIFIED", "VERIFIED")


def main() -> int:
    verdict = verify_shape_manifest(Path(sys.argv[1]), Path(sys.argv[2])) if len(sys.argv) == 3 else Verdict("BLOCKED", "BLOCKED_MANIFEST_MISSING")
    (sys.stdout if verdict.status == "VERIFIED" else sys.stderr).write(verdict.code + "\n")
    return 0 if verdict.status == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
