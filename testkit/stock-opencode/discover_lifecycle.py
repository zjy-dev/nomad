#!/usr/bin/env python3
"""A0 real lifecycle discovery; a verified bundle is staged, never published."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import queue
import re
import sys
import threading
import time
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parent
REAL_TASK_ROOT = ROOT / "real-task"
if str(ROOT.parent.parent) not in sys.path:
    sys.path.insert(0, str(ROOT.parent.parent))
PROMPT_PATH = ROOT / "real-task" / "project-prompt.txt"
CERTIFICATE_PATH = ROOT / "real-task" / "lifecycle-certificate.json"
MANIFEST_PATH = ROOT / "real-task" / "lifecycle-shape-manifest.json"
CERTIFICATE_TMP_PATH = CERTIFICATE_PATH.with_suffix(CERTIFICATE_PATH.suffix + ".tmp")
MANIFEST_TMP_PATH = MANIFEST_PATH.with_suffix(MANIFEST_PATH.suffix + ".tmp")
EVIDENCE_PATH = ROOT / "lifecycle-evidence-manifest.json"
EVIDENCE_TMP_PATH = EVIDENCE_PATH.with_suffix(EVIDENCE_PATH.suffix + ".tmp")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
V1_ROUTES = {"session_create": ("POST", "/session"), "event_subscribe": ("GET", "/event"), "session_snapshot": ("GET", "/session/{sessionID}"), "session_diff": ("GET", "/session/{sessionID}/diff"), "question_list": ("GET", "/question"), "permission_list": ("GET", "/permission")}
MARKER_CANDIDATES = {
    "created": frozenset({"session.created"}),
    "question": frozenset({"question.v2.asked", "question.asked"}),
    "diff": frozenset({"session.diff"}),
    "permission": frozenset({"permission.v2.asked", "permission.asked"}),
}
MARKER_ORDER = ("created", "question", "diff", "permission")
CERTIFICATE_V1_ROUTES = ["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"]
TEST_COMMAND = "node test/arithmetic.test.js"
SESSION_PERMISSION_RULES = (
    {"permission": "read", "pattern": "*", "action": "allow"},
    {"permission": "edit", "pattern": "*", "action": "allow"},
    {"permission": "question", "pattern": "*", "action": "allow"},
    {"permission": "bash", "pattern": "*", "action": "deny"},
    {"permission": "bash", "pattern": TEST_COMMAND, "action": "ask"},
)
_AUTHORITY_TOKEN = object()
_COMPLETION_TOKEN = object()
_ASCII_EVENT = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_REVIEWED_VERSION = re.compile(r"^[!-~]{1,128}$")

class DiscoveryError(RuntimeError):
    def __init__(self, code: str) -> None: self.code = code; super().__init__(code)


@dataclass(frozen=True)
class StagePaths:
    root: Path
    real_task_root: Path
    certificate: Path
    shape: Path
    evidence: Path
    certificate_tmp: Path
    shape_tmp: Path
    evidence_tmp: Path

    @classmethod
    def under(cls, root: Path, real_task_root: Path) -> "StagePaths":
        certificate = real_task_root / "lifecycle-certificate.json"
        shape = real_task_root / "lifecycle-shape-manifest.json"
        evidence = root / "lifecycle-evidence-manifest.json"
        return cls(root, real_task_root, certificate, shape, evidence,
                   certificate.with_suffix(certificate.suffix + ".tmp"),
                   shape.with_suffix(shape.suffix + ".tmp"),
                   evidence.with_suffix(evidence.suffix + ".tmp"))


def _production_paths() -> StagePaths:
    return StagePaths.under(ROOT, REAL_TASK_ROOT)


def _safe_directory(path: Path) -> bool:
    try:
        info = os.lstat(path)
        return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid() and not (info.st_mode & 0o022)
    except OSError:
        return False


def _exists_no_follow(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY") from error


def _preflight(paths: StagePaths) -> None:
    for directory in (paths.root, paths.real_task_root):
        try:
            os.lstat(directory)
        except FileNotFoundError as error:
            raise DiscoveryError("BLOCKED_OUTPUT_DIR_MISSING") from error
        except OSError as error:
            raise DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY") from error
        if not _safe_directory(directory):
            raise DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY")
    if paths.real_task_root.parent != paths.root or paths != StagePaths.under(paths.root, paths.real_task_root):
        raise DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY")
    for path, code in (
        (paths.certificate, "BLOCKED_CERTIFICATE_ALREADY_EXISTS"),
        (paths.shape, "BLOCKED_SHAPE_ALREADY_EXISTS"),
        (paths.evidence, "BLOCKED_EVIDENCE_ALREADY_EXISTS"),
        (paths.certificate_tmp, "BLOCKED_CERTIFICATE_TMP_EXISTS"),
        (paths.shape_tmp, "BLOCKED_SHAPE_TMP_EXISTS"),
        (paths.evidence_tmp, "BLOCKED_EVIDENCE_TMP_EXISTS"),
    ):
        if _exists_no_follow(path):
            raise DiscoveryError(code)


def _stage_bytes(path: Path, value: object, exists_code: str) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if not raw or len(raw) > 128 * 1024:
        raise DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as error:
        raise DiscoveryError(exists_code) from error
    except OSError as error:
        raise DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY") from error
    failure: BaseException | None = None
    try:
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise OSError
        total = 0
        while total < len(raw):
            written = os.write(fd, raw[total:])
            if written <= 0:
                raise OSError
            total += written
        os.fsync(fd)
    except OSError as error:
        failure = DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY")
        failure.__cause__ = error
    except BaseException as error:
        failure = error
    try:
        os.close(fd)
    except OSError as error:
        if failure is None:
            failure = DiscoveryError("BLOCKED_OUTPUT_DIR_POLICY")
            failure.__cause__ = error
    if failure is not None:
        raise failure


def _bounded_pipe_reader(stream: Any, process: subprocess.Popen[bytes], output: bytearray, failed: threading.Event) -> None:
    try:
        while len(output) <= 4096:
            chunk = stream.read(min(1024, 4097 - len(output)))
            if not chunk:
                return
            output.extend(chunk)
            if len(output) > 4096:
                failed.set()
                try: process.kill()
                except OSError: pass
                return
    except OSError:
        failed.set()
        try: process.kill()
        except OSError: pass


def _verify_cli(script: Path, arguments: list[Path], *, timeout_seconds: float = 10) -> bool:
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8", "LC_ALL": "C", "LANG": "C"}
    try:
        process = subprocess.Popen([str(Path(sys.executable).resolve()), str(script.resolve()), *(str(path.resolve()) for path in arguments)], cwd=str(ROOT.resolve()), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, shell=False, close_fds=True)
    except OSError:
        return False
    if process.stdout is None or process.stderr is None:
        try: process.kill(); process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired): pass
        return False
    stdout, stderr, failed = bytearray(), bytearray(), threading.Event()
    readers = (threading.Thread(target=_bounded_pipe_reader, args=(process.stdout, process, stdout, failed), daemon=True), threading.Thread(target=_bounded_pipe_reader, args=(process.stderr, process, stderr, failed), daemon=True))
    for reader in readers: reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try: process.kill()
        except OSError: pass
        try: process.wait(timeout=1)
        except subprocess.TimeoutExpired: failed.set()
    for reader in readers:
        reader.join(timeout=1)
        if reader.is_alive(): failed.set()
    try:
        process.stdout.close(); process.stderr.close()
    except OSError:
        failed.set()
    return not timed_out and not failed.is_set() and process.returncode == 0 and bytes(stdout) == b"VERIFIED\n"


def _derive_evidence(certificate: Mapping[str, object], shape: Mapping[str, object], reviewed_version: str) -> dict[str, object]:
    previous = sys.dont_write_bytecode
    module_name = "nomad_b01_public"
    module: Any | None = None
    previous_module = sys.modules.get(module_name)
    try:
        try:
            sys.dont_write_bytecode = True
            target = ROOT / "verify_evidence_manifest.py"
            spec = importlib.util.spec_from_file_location(module_name, target)
            if spec is None or spec.loader is None:
                raise DiscoveryError("FAIL_B0_1_DERIVATION")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except (OSError, ImportError) as error:
            raise DiscoveryError("FAIL_B0_1_DERIVATION") from error
        try:
            result = module.derive_evidence_manifest(certificate, shape, reviewed_version)
        except module.EvidenceDerivationError as error:
            raise DiscoveryError("FAIL_B0_1_DERIVATION") from error
        if not isinstance(result, dict):
            raise DiscoveryError("FAIL_B0_1_DERIVATION")
        return result
    finally:
        if module is not None and sys.modules.get(module_name) is module:
            if previous_module is None: sys.modules.pop(module_name, None)
            else: sys.modules[module_name] = previous_module
        sys.dont_write_bytecode = previous

@dataclass(frozen=True)
class CompletedRealDiscovery:
    evidence: Mapping[str, object]
    _token: object

@dataclass(frozen=True)
class StructuralCandidate:
    evidence: Mapping[str, object]
    shape_draft: Mapping[str, object] | None = None

class RealRunAuthority:
    """Single-use authority bound to one exact locked launcher instance."""
    __slots__ = (
        "provenance_digest", "_token", "_launch", "_process",
        "_pid", "_root", "_install", "_workspace",
        "_cleanup_verified", "_used",
    )
    def __init__(self, launch: object, token: object) -> None:
        if token is not _AUTHORITY_TOKEN:
            raise DiscoveryError("SYNTHETIC_TEST_NOT_CERTIFIED")
        process = getattr(launch, "process", None)
        pid = getattr(process, "pid", None)
        provenance = getattr(launch, "provenance_digest", None)
        try:
            root = Path(getattr(launch, "root")).resolve(strict=True)
            install = Path(getattr(launch, "install")).resolve(strict=True)
            workspace = Path(getattr(launch, "workspace")).resolve(strict=True)
            contained = (
                install != root and workspace != root and install != workspace
                and install.is_relative_to(root) and workspace.is_relative_to(root)
                and root.is_dir() and install.is_dir() and workspace.is_dir()
            )
        except (OSError, TypeError, AttributeError):
            contained = False
            root = install = workspace = Path(".")
        if (
            process is None or not isinstance(pid, int) or pid <= 0
            or process.poll() is not None or not contained
            or not isinstance(provenance, str)
            or not re.fullmatch(r"[0-9a-f]{64}", provenance)
        ):
            raise DiscoveryError("BLOCKED_LOCKED_RUNTIME_UNAVAILABLE")
        self.provenance_digest = provenance
        self._token = token
        self._launch, self._process, self._pid = launch, process, pid
        self._root, self._install, self._workspace = root, install, workspace
        self._cleanup_verified = False
        self._used = False

    def verify_live(self, launch: object) -> None:
        try:
            same = (
                launch is self._launch
                and getattr(launch, "process", None) is self._process
                and getattr(self._process, "pid", None) == self._pid
                and self._process.poll() is None
                and Path(getattr(launch, "root")).resolve(strict=True) == self._root
                and Path(getattr(launch, "install")).resolve(strict=True) == self._install
                and Path(getattr(launch, "workspace")).resolve(strict=True) == self._workspace
                and getattr(launch, "provenance_digest", None) == self.provenance_digest
            )
        except (OSError, TypeError, AttributeError):
            same = False
        if not same:
            raise DiscoveryError("BLOCKED_LOCKED_RUNTIME_UNAVAILABLE")

    def verify_cleanup(self, launch: object) -> None:
        same = (
            launch is self._launch
            and getattr(launch, "process", None) is self._process
            and getattr(self._process, "pid", None) == self._pid
        )
        removed = not any(path.exists() for path in (self._root, self._install, self._workspace))
        if not same or self._process.poll() is None or not removed:
            raise DiscoveryError("BLOCKED_WORKSPACE_CLEANUP_INCOMPLETE")
        self._cleanup_verified = True

    def consume(self) -> None:
        removed = not any(path.exists() for path in (self._root, self._install, self._workspace))
        if (
            self._token is not _AUTHORITY_TOKEN or self._used
            or not self._cleanup_verified or self._process.poll() is None or not removed
        ):
            raise DiscoveryError("SYNTHETIC_TEST_NOT_CERTIFIED")
        self._used = True

class HttpSseTransport:
    def __init__(self, base: str) -> None:
        self.base = base; self.events: queue.Queue[object] = queue.Queue(); self.stop = threading.Event(); self.reader: threading.Thread | None = None
    def start(self, query: Mapping[str, str]) -> None:
        self.reader = threading.Thread(target=_sse_worker, args=(self.base, query, self.events, self.stop), daemon=True); self.reader.start()
    def next_event(self, timeout: float) -> object:
        return self.events.get(timeout=timeout)
    def request(self, method: str, route: str, *, query: Mapping[str, str] | None = None, body: object | None = None) -> tuple[int, object]:
        return _request(self.base, method, route, query=query, body=body)
    def close(self) -> None:
        self.stop.set()
        if self.reader is not None: self.reader.join(timeout=1)

class ScriptedTransport:
    """Exact protocol script for structural tests; it has no certification API."""
    def __init__(self, events: Sequence[object], requests: Sequence[tuple[str, str, Mapping[str, str] | None, object | None, int, object]]) -> None:
        self._events = list(events); self._requests = list(requests); self.calls: list[tuple[str, str, Mapping[str, str] | None, object | None]] = []
        self.started_query: Mapping[str, str] | None = None; self.stopped = False; self.joined = False
    def start(self, query: Mapping[str, str]) -> None: self.started_query = dict(query)
    def next_event(self, timeout: float) -> object:
        if not self._events: raise queue.Empty
        item = self._events.pop(0)
        if isinstance(item, Exception): raise item
        return item
    def request(self, method: str, route: str, *, query: Mapping[str, str] | None = None, body: object | None = None) -> tuple[int, object]:
        self.calls.append((method, route, query, body))
        if not self._requests: raise AssertionError("unexpected request")
        expected_method, expected_route, expected_query, expected_body, status, response = self._requests.pop(0)
        if (method, route, query, body) != (expected_method, expected_route, expected_query, expected_body): raise AssertionError("request mismatch")
        return status, response
    def close(self) -> None: self.stopped = True; self.joined = True
    def assert_consumed(self) -> None:
        if self._events or self._requests: raise AssertionError("script not consumed")

def _wp1() -> Any:
    spec = importlib.util.spec_from_file_location("nomad_real_task_capture", ROOT / "real_task_capture.py")
    if spec is None or spec.loader is None: raise DiscoveryError("BLOCKED_LOCKED_RUNTIME_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module

def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()

_SAFE_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
_SECRET_NAME = re.compile(r"api_key|secret|credential|token|password|authorization|auth", re.I)
_POLICY = {
 "session.created": {"": {"sessionID","info"}, "info": {"id","slug","projectID","directory","title","version","time","agent","cost","metadata","model","parentID","permission","revert","share","summary","tokens","workspaceID","path"}, "info.time": {"created","updated","archived","compacting"}, "info.model": {"id","providerID","variant"}, "info.tokens": {"input","output","reasoning","cache"}, "info.tokens.cache": {"read","write"}, "info.summary": {"additions","deletions","files","diffs"}, "info.summary.diffs": {"file","additions","deletions","status","patch"}, "info.permission": {"permission","pattern","action"}, "info.revert": {"messageID","partID","snapshot","diff"}, "info.share": {"url"}},
 "question.asked": {"": {"id","sessionID","questions","tool"}, "questions": {"question","header","options","multiple","custom"}, "questions.options": {"label","description"}, "tool": {"messageID","callID"}},
 "question.v2.asked": {"": {"id","sessionID","questions","tool"}, "questions": {"question","header","options","multiple","custom"}, "questions.options": {"label","description"}, "tool": {"messageID","callID"}},
 "session.diff": {"": {"sessionID","diff"}, "diff": {"file","additions","deletions","status","patch"}},
 "permission.asked": {"": {"id","sessionID","permission","patterns","metadata","always","tool"}, "tool": {"messageID","callID"}},
 "permission.v2.asked": {"": {"id","sessionID","action","resources","metadata","save","source"}, "source": {"type","messageID","callID"}},
}

def _extract_property_shape(value: object, policy: Mapping[str, set[str]], path: str = "", depth: int = 0) -> dict[str, object]:
    if value is None: return {"type": "null"}
    if type(value) is bool: return {"type": "bool"}
    if type(value) is int: return {"type": "int"}
    if type(value) is float: return {"type": "float"}
    if isinstance(value, str): return {"type": "str"}
    if isinstance(value, list):
        if len(value) > 10000: raise DiscoveryError("BLOCKED_CONTENT_POLICY")
        shapes = [_extract_property_shape(item, policy, path, depth + 1) for item in value if item is not None]
        item = {"type": "null"} if not shapes else {"type": "mixed"} if any(shape != shapes[0] for shape in shapes[1:]) else shapes[0]
        return {"type": "list", "items": item, "count": len(value)}
    if isinstance(value, Mapping):
        result: dict[str, object] = {"type": "dict"}
        if depth <= 3:
            props = {}
            if path.endswith("metadata"):
                if len(value) > 16: raise DiscoveryError("BLOCKED_CONTENT_POLICY")
                return {"type": "dict", "dynamic_keys": True, "field_count": len(value)}
            if len(value) > 16: raise DiscoveryError("BLOCKED_CONTENT_POLICY")
            allowed = policy.get(path, set())
            for key in sorted(value):
                if not isinstance(key, str) or not _SAFE_NAME.fullmatch(key) or key not in allowed or (_SECRET_NAME.search(key) and key != "tokens"): raise DiscoveryError("BLOCKED_CONTENT_POLICY")
                child = key if not path else path + "." + key
                props[key] = _extract_property_shape(value[key], policy, child, depth + 1)
            result["properties"] = props
        return result
    raise DiscoveryError("BLOCKED_CONTENT_POLICY")

def _event_shape(marker: str, event_type: str, properties: Mapping[str, object]) -> dict[str, object]:
    policy = _POLICY.get(event_type)
    if policy is None: raise DiscoveryError("BLOCKED_CONTENT_POLICY")
    shaped = _extract_property_shape(properties, policy)
    fields = sorted(shaped.get("properties", {}))
    return {"marker": marker, "observed_event_type": event_type, "property_field_count": len(fields), "property_field_names": fields, "property_field_types": shaped.get("properties", {})}

def _valid_shape(shape: object, policy: Mapping[str,set[str]], path: str = "", depth: int = 0) -> bool:
    if not isinstance(shape, Mapping) or set(shape) - {"type", "items", "properties", "dynamic_keys", "field_count", "count"}: return False
    kind = shape.get("type")
    if kind not in {"null","bool","int","float","str","list","dict","mixed"}: return False
    if "count" in shape and (type(shape["count"]) is not int or not 0 <= shape["count"] <= 10000): return False
    if kind == "list": return set(shape) <= {"type","items","count"} and _valid_shape(shape.get("items"), policy, path, depth + 1)
    if kind == "dict":
        if shape.get("dynamic_keys") is True:
            return path.endswith("metadata") and set(shape) == {"type","dynamic_keys","field_count"} and type(shape.get("field_count")) is int and 0 <= shape["field_count"] <= 16
        if depth > 3: return set(shape) == {"type"}
        props=shape.get("properties", {})
        allowed=policy.get(path,set())
        return set(shape) == {"type","properties"} and isinstance(props,Mapping) and len(props)<=16 and all(isinstance(k,str) and _SAFE_NAME.fullmatch(k) and k in allowed and (not _SECRET_NAME.search(k) or k=="tokens") and _valid_shape(v,policy,k if not path else path+"."+k,depth+1) for k,v in props.items())
    return set(shape) == {"type"}

def _hex(value: object) -> str: return canonical_digest(value)

def _build_shape_manifest(candidate: StructuralCandidate, completed: CompletedRealDiscovery, *, launch_provenance_digest: str, task_spec_digest: str, fixture_manifest_digest: str, command_shapes_canonical_digest: str, event_shapes: list[dict[str, object]], snapshot_cardinalities: Mapping[str,int], session_id: str, session_snapshot: Mapping[str, object], question_id: str, permission_id: str, question_reply_route: str, permission_reply_route: str, routes: Mapping[str, Mapping[str, str]], permission_snapshot: Mapping[str, object]) -> dict[str, object]:
    _validate_completed(completed)
    rule_config_digest = _hex(SESSION_PERMISSION_RULES)
    source = {"certificate_structural_digest": completed.evidence["structural_digest"], "launch_provenance_digest": launch_provenance_digest, "task_spec_digest": task_spec_digest, "fixture_manifest_digest": fixture_manifest_digest, "command_shapes_canonical_digest": command_shapes_canonical_digest, "rule_config_digest": rule_config_digest}
    expected_question_route = routes["question_reply"]["route"].replace("{sessionID}", session_id).replace("{requestID}", question_id)
    expected_permission_route = routes["permission_reply"]["route"].replace("{sessionID}", session_id).replace("{requestID}", permission_id)
    core = {"schema_version": "nomad.stock-opencode.lifecycle-shape-manifest.v1", **source, "source_binding_digest": _hex(source), "events": event_shapes, "snapshot_cardinalities": dict(snapshot_cardinalities), "session_id_equality": session_snapshot.get("id") == session_id, "question_snapshot_id_used_in_reply_route": question_reply_route == expected_question_route, "permission_snapshot_id_used_in_reply_route": permission_reply_route == expected_permission_route, "question_permission_ids_distinct": question_id != permission_id, "diff_count_relation": "files_ge_1", "permission_name_is_bash": permission_snapshot.get("permission") == "bash", "patterns_is_single_string_list": isinstance(permission_snapshot.get("patterns"), list) and len(permission_snapshot["patterns"]) == 1 and isinstance(permission_snapshot["patterns"][0], str), "pattern_matches_fixed_test_command": permission_snapshot.get("patterns") == [TEST_COMMAND]}
    return {**core, "manifest_digest": _hex(core)}

def verified_routes() -> dict[str, dict[str, str]]:
    fixture = _wp1().verify_command_shape_fixture()
    routes = {name: {"method": method, "route": route} for name, (method, route) in V1_ROUTES.items()}
    for name in ("session_prompt", "question_reply", "permission_reply", "stop"):
        shape = fixture["actions"][name]
        routes[name] = {"method": str(shape["method"]).upper(), "route": str(shape["route"]), "operation_id": str(shape["operation_id"])}
    return routes

def _request(base: str, method: str, route: str, *, query: Mapping[str, str] | None = None, body: object | None = None) -> tuple[int, object]:
    suffix = "?" + urllib.parse.urlencode(query) if query else ""; data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(base + route + suffix, data=data, method=method)
    if data is not None: request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(); return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        error.close()
        raise DiscoveryError("BLOCKED_UPSTREAM_HTTP_REJECTED") from None

def _require_status(status: int) -> None:
    if not 200 <= status < 300: raise DiscoveryError("BLOCKED_UPSTREAM_HTTP_REJECTED")

def _extract_id(payload: object, key: str) -> str:
    candidate = payload.get(key) if isinstance(payload, Mapping) else None
    if candidate is None and isinstance(payload, Mapping) and isinstance(payload.get("data"), Mapping): candidate = payload["data"].get(key)
    if not isinstance(candidate, str) or not _ID.fullmatch(candidate): raise DiscoveryError("BLOCKED_SESSION_RESPONSE_INVALID")
    return candidate

def _event(payload: object) -> tuple[str, Mapping[str, object]]:
    if not isinstance(payload, Mapping) or set(payload) != {"id", "type", "properties"} or not isinstance(payload["type"], str): raise DiscoveryError("BLOCKED_UNEXPECTED_EVENT_SCHEMA")
    if not isinstance(payload["properties"], Mapping): raise DiscoveryError("BLOCKED_UNEXPECTED_EVENT_SCHEMA")
    return payload["type"], payload["properties"]

def _sse_worker(base: str, query: Mapping[str, str], output: queue.Queue[object], stop: threading.Event) -> None:
    try:
        request = urllib.request.Request(base + "/event?" + urllib.parse.urlencode(query), method="GET")
        with urllib.request.urlopen(request, timeout=10) as response:
            for line in response:
                if stop.is_set(): return
                if line.startswith(b"data: "): output.put(json.loads(line[6:]))
    except Exception as error: output.put(error)

def _snapshot_id(payload: object, session_id: str, *, require_test_command: bool = False) -> str:
    values = payload if isinstance(payload, list) else payload.get("data", payload) if isinstance(payload, Mapping) else []
    if not isinstance(values, list): raise DiscoveryError("BLOCKED_SNAPSHOT_CORRELATION")
    matches = [item for item in values if isinstance(item, Mapping) and item.get("sessionID") == session_id]
    if len(matches) != 1: raise DiscoveryError("BLOCKED_SNAPSHOT_CORRELATION")
    if require_test_command:
        # Locked 1.18.16 exposes the requested command as required
        # `patterns: string[]`.  Require the exact singleton so a matching
        # command cannot hide an unrelated command in the same request.
        if matches[0].get("permission") != "bash" or matches[0].get("patterns") != [TEST_COMMAND]:
            raise DiscoveryError("BLOCKED_PERMISSION_TRIGGER_UNCERTIFIED")
    return _extract_id(matches[0], "id")

def _validate_session_snapshot(payload: object, session_id: str) -> None:
    value = payload.get("data", payload) if isinstance(payload, Mapping) else None
    if not isinstance(value, Mapping) or len(value) > 128 or _extract_id(value, "id") != session_id:
        raise DiscoveryError("BLOCKED_SNAPSHOT_CORRELATION")

def _diff_count(payload: object) -> int:
    values = payload.get("files", payload) if isinstance(payload, Mapping) else payload
    if not isinstance(values, list) or len(values) < 1: raise DiscoveryError("BLOCKED_DIFF_ZERO")
    return len(values)

def _marker(event_type: str) -> str | None:
    return next((name for name in MARKER_ORDER if event_type in MARKER_CANDIDATES[name]), None)

def _validate_permission_rule_precedence(rules: Sequence[Mapping[str, str]]) -> None:
    """Stock documentation specifies last matching rule wins: wildcard first."""
    wildcard = {"permission": "bash", "pattern": "*", "action": "deny"}
    exact = {"permission": "bash", "pattern": TEST_COMMAND, "action": "ask"}
    try:
        if rules.index(wildcard) >= rules.index(exact): raise ValueError
    except ValueError:
        raise DiscoveryError("BLOCKED_PERMISSION_TRIGGER_UNCERTIFIED") from None

def _evidence(events: list[str], diff_count: int, routes: Mapping[str, object]) -> dict[str, object]:
    if len(events) != 4 or any(events[index] not in MARKER_CANDIDATES[marker] for index, marker in enumerate(MARKER_ORDER)): raise DiscoveryError("BLOCKED_EVENT_ORDER")
    core = {"schema_version": "nomad.stock-opencode.lifecycle-certificate.v1", "expected_event_sequence": events, "diff_file_count": diff_count, "v1_routes_verified": CERTIFICATE_V1_ROUTES, "v2_routes_verified": [routes[name]["route"] for name in ("session_prompt", "question_reply", "permission_reply", "stop")]}
    return {**core, "structural_digest": canonical_digest(core)}

def _validate_completed(completed: CompletedRealDiscovery) -> None:
    if not isinstance(completed, CompletedRealDiscovery) or completed._token is not _COMPLETION_TOKEN: raise DiscoveryError("SYNTHETIC_TEST_NOT_CERTIFIED")
    evidence = completed.evidence; keys = {"schema_version", "expected_event_sequence", "diff_file_count", "v1_routes_verified", "v2_routes_verified", "structural_digest"}
    if not isinstance(evidence, Mapping) or set(evidence) != keys or evidence.get("schema_version") != "nomad.stock-opencode.lifecycle-certificate.v1": raise DiscoveryError("BLOCKED_CONTENT_POLICY")
    events = evidence["expected_event_sequence"]
    if not isinstance(events, list) or len(events) != 4 or not all(isinstance(x, str) and _ASCII_EVENT.fullmatch(x) for x in events): raise DiscoveryError("BLOCKED_CONTENT_POLICY")
    if any(events[index] not in MARKER_CANDIDATES[marker] for index, marker in enumerate(MARKER_ORDER)): raise DiscoveryError("BLOCKED_CONTENT_POLICY")
    if not isinstance(evidence["diff_file_count"], int) or not 1 <= evidence["diff_file_count"] <= 10000: raise DiscoveryError("BLOCKED_CONTENT_POLICY")
    expected_v2 = [verified_routes()[name]["route"] for name in ("session_prompt", "question_reply", "permission_reply", "stop")]
    if evidence["v1_routes_verified"] != CERTIFICATE_V1_ROUTES or evidence["v2_routes_verified"] != expected_v2: raise DiscoveryError("BLOCKED_CONTENT_POLICY")
    core = {key: evidence[key] for key in keys - {"structural_digest"}}
    if evidence["structural_digest"] != canonical_digest(core): raise DiscoveryError("BLOCKED_CONTENT_POLICY")

def _run_protocol(transport: HttpSseTransport | ScriptedTransport, workspace: Path, routes: Mapping[str, Mapping[str, str]], timeout_seconds: int) -> StructuralCandidate:
    # The stock workspace field is not a filesystem-path filter.
    filters = {"directory": str(workspace)}
    _validate_permission_rule_precedence(SESSION_PERMISSION_RULES)
    transport.start(filters)
    try:
        deadline = time.monotonic() + timeout_seconds
        # No replay is assumed: confirm the subscription before creating a session.
        while time.monotonic() < deadline:
            try: item = transport.next_event(min(0.2, max(0.01, deadline - time.monotonic())))
            except queue.Empty: continue
            except Exception as error: raise DiscoveryError("BLOCKED_SSE_TIMEOUT") from error
            if isinstance(item, Exception): raise DiscoveryError("BLOCKED_SSE_TIMEOUT") from item
            event_type, _ = _event(item)
            if event_type == "server.connected": break
        else: raise DiscoveryError("BLOCKED_SSE_TIMEOUT")
        status, created = transport.request("POST", routes["session_create"]["route"], query=filters, body={"permission": list(SESSION_PERMISSION_RULES)})
        _require_status(status); session_id = _extract_id(created, "id")
        observed: list[str] = []; shapes: list[dict[str, object]] = []; question_id = permission_id = None; question_reply_route = permission_reply_route = None; session_snapshot = question_snapshot = permission_snapshot = None; snapshot_cardinalities={"/session/{id}":0,"/question":0,"/permission":0,"/session/{id}/diff":0}; deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline and permission_id is None:
            try: item = transport.next_event(min(0.2, max(0.01, deadline - time.monotonic())))
            except queue.Empty: continue
            except Exception as error: raise DiscoveryError("BLOCKED_SSE_TIMEOUT") from error
            if isinstance(item, Exception): raise DiscoveryError("BLOCKED_SSE_TIMEOUT") from item
            event_type, properties = _event(item)
            event_session = properties.get("sessionID") or properties.get("session_id")
            if event_session != session_id: continue
            marker = _marker(event_type)
            if marker is None: continue
            expected = MARKER_ORDER[len(observed)] if len(observed) < len(MARKER_ORDER) else None
            if marker != expected: raise DiscoveryError("BLOCKED_EVENT_ORDER")
            observed.append(event_type)
            shapes.append(_event_shape(marker, event_type, properties))
            if marker == "created":
                status, snapshot = transport.request("GET", routes["session_snapshot"]["route"].replace("{sessionID}", session_id), query=filters)
                snapshot_cardinalities["/session/{id}"] += 1
                _require_status(status); _validate_session_snapshot(snapshot, session_id); session_snapshot = snapshot.get("data", snapshot)
                prompt = PROMPT_PATH.read_text(encoding="utf-8")
                status, _ = transport.request(routes["session_prompt"]["method"], routes["session_prompt"]["route"].replace("{sessionID}", session_id), body={"prompt": {"text": prompt}}); _require_status(status)
            if marker == "question":
                status, snapshot = transport.request("GET", routes["question_list"]["route"], query=filters); _require_status(status); question_id = _snapshot_id(snapshot, session_id)
                snapshot_cardinalities["/question"] += 1
                question_snapshot = next(item for item in (snapshot if isinstance(snapshot, list) else snapshot["data"]) if item.get("id") == question_id)
                question_reply_route = routes["question_reply"]["route"].replace("{sessionID}", session_id).replace("{requestID}", question_id)
                status, _ = transport.request(routes["question_reply"]["method"], question_reply_route, body={"answers": [["keep add"]]}); _require_status(status)
            if marker == "diff":
                status, diff = transport.request("GET", routes["session_diff"]["route"].replace("{sessionID}", session_id), query=filters); _require_status(status); count = _diff_count(diff)
                snapshot_cardinalities["/session/{id}/diff"] += 1
            if marker == "permission":
                status, snapshot = transport.request("GET", routes["permission_list"]["route"], query=filters); _require_status(status); permission_id = _snapshot_id(snapshot, session_id, require_test_command=True)
                snapshot_cardinalities["/permission"] += 1
                permission_snapshot = next(item for item in (snapshot if isinstance(snapshot, list) else snapshot["data"]) if item.get("id") == permission_id)
                permission_reply_route = routes["permission_reply"]["route"].replace("{sessionID}", session_id).replace("{requestID}", permission_id)
                status, _ = transport.request(routes["permission_reply"]["method"], permission_reply_route, body={"reply": "reject"}); _require_status(status)
        if question_id is None or permission_id is None: raise DiscoveryError("BLOCKED_SSE_TIMEOUT")
        if "count" not in locals(): raise DiscoveryError("BLOCKED_DIFF_ZERO")
        status, _ = transport.request(routes["stop"]["method"], routes["stop"]["route"].replace("{sessionID}", session_id)); _require_status(status)
        draft = {"events": shapes, "snapshot_cardinalities": snapshot_cardinalities, "session_id": session_id, "session_snapshot": session_snapshot, "question_id": question_id, "permission_id": permission_id, "question_reply_route": question_reply_route, "permission_reply_route": permission_reply_route, "permission_snapshot": permission_snapshot}
        return StructuralCandidate(_evidence(observed, count, routes), draft)
    finally:
        transport.close()

def _certify(authority: RealRunAuthority, candidate: StructuralCandidate) -> CompletedRealDiscovery:
    if not isinstance(authority, RealRunAuthority) or authority._token is not _AUTHORITY_TOKEN or not isinstance(candidate, StructuralCandidate):
        raise DiscoveryError("SYNTHETIC_TEST_NOT_CERTIFIED")
    authority.consume()
    return CompletedRealDiscovery(candidate.evidence, _COMPLETION_TOKEN)

def discover(provider_credential_env: str, environment: Mapping[str, str] | None = None, *, timeout_seconds: int = 90, reviewed_version: str | None = None) -> dict[str, object]:
    return _discover_staged(provider_credential_env, reviewed_version or "", environment, timeout_seconds, _production_paths())

def _discover_staged(provider_credential_env: str, reviewed_version: str, environment: Mapping[str, str] | None, timeout_seconds: int, paths: StagePaths) -> dict[str, object]:
    if not isinstance(reviewed_version, str) or not _REVIEWED_VERSION.fullmatch(reviewed_version):
        raise DiscoveryError("BLOCKED_REVIEWED_VERSION_REQUIRED")
    _preflight(paths)
    wp1 = _wp1(); env = os.environ if environment is None else environment
    if not wp1.credential_present(provider_credential_env, env):
        raise DiscoveryError("BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
    launch = None
    try:
        task_spec = wp1.load_task_spec()
        launch = wp1.launch_locked_opencode(provider_credential_env=provider_credential_env, task_spec=task_spec, environment=env)
        authority = RealRunAuthority(launch, _AUTHORITY_TOKEN)
        authority.verify_live(launch)
        candidate = _run_protocol(HttpSseTransport("http://127.0.0.1:" + str(launch.port)), launch.workspace, verified_routes(), timeout_seconds)
        authority.verify_live(launch)
        completed_launch = launch
        launch.cleanup(); authority.verify_cleanup(completed_launch); launch = None
        completed = _certify(authority, candidate)
        fixture = wp1.verify_fixture_manifest(); shapes = wp1.verify_command_shape_fixture(); draft = candidate.shape_draft or {}
        manifest = _build_shape_manifest(candidate, completed, launch_provenance_digest=authority.provenance_digest, task_spec_digest=task_spec[1], fixture_manifest_digest=fixture["digest"], command_shapes_canonical_digest=canonical_digest(shapes), event_shapes=draft["events"], snapshot_cardinalities=draft["snapshot_cardinalities"], session_id=draft["session_id"], session_snapshot=draft["session_snapshot"], question_id=draft["question_id"], permission_id=draft["permission_id"], question_reply_route=draft["question_reply_route"], permission_reply_route=draft["permission_reply_route"], routes=verified_routes(), permission_snapshot=draft["permission_snapshot"])
        _stage_bytes(paths.certificate_tmp, completed.evidence, "BLOCKED_CERTIFICATE_TMP_EXISTS")
        _stage_bytes(paths.shape_tmp, manifest, "BLOCKED_SHAPE_TMP_EXISTS")
        if not _verify_cli(ROOT / "verify_certificate.py", [paths.certificate_tmp]): raise DiscoveryError("FAIL_A3_VERIFY")
        if not _verify_cli(ROOT / "verify_shape_manifest.py", [paths.shape_tmp, paths.certificate_tmp]): raise DiscoveryError("FAIL_A4_2_VERIFY")
        evidence = _derive_evidence(completed.evidence, manifest, reviewed_version)
        _stage_bytes(paths.evidence_tmp, evidence, "BLOCKED_EVIDENCE_TMP_EXISTS")
        if not _verify_cli(ROOT / "verify_evidence_manifest.py", [paths.evidence_tmp, paths.certificate_tmp, paths.shape_tmp]): raise DiscoveryError("FAIL_B0_1_VERIFY")
        return {"status": "CANDIDATE_STAGED"}
    finally:
        if launch is not None: launch.cleanup()

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--provider-credential-env", required=True); parser.add_argument("--reviewed-version"); args = parser.parse_args()
    try: print(json.dumps(discover(args.provider_credential_env, reviewed_version=args.reviewed_version), sort_keys=True)); return 0
    except DiscoveryError as error: print(json.dumps({"status": "BLOCKED", "reason_codes": [error.code]}, sort_keys=True)); return 1
if __name__ == "__main__": raise SystemExit(main())
