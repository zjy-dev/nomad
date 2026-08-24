"""WP1 locked-runtime launcher and content-free OpenAPI shape capture."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import weakref
from datetime import datetime, timezone
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parent
if str(ROOT.parent.parent) not in sys.path:
    sys.path.insert(0, str(ROOT.parent.parent))

from testkit.iteration3_receipts import (
    STAGE_BINDINGS,
    append_receipt,
    canonical_digest,
    read_receipt_store,
)

LOCKED_RUNTIME = ROOT / "locked-runtime"
REAL_TASK_DIR = ROOT / "real-task"
DEFAULT_TASK_SPEC = REAL_TASK_DIR / "task-spec.json"
FIXTURE_MANIFEST = REAL_TASK_DIR / "fixture-manifest.json"
COMMAND_SHAPES = REAL_TASK_DIR / "command-shapes.json"
TEMPORARY_PROVIDER_ENV_NAMES = frozenset({
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY",
})
WP1_STAGES = frozenset({
    "runtime_provenance_verified", "credential_scope_configured", "opencode_ready",
    "question_observed", "diff_observed", "permission_observed",
    "credential_scope_audit_completed", "workspace_cleaned",
})
V2_ACTIONS = {
    "session_prompt": ("v2.session.prompt", "/api/session/{sessionID}/prompt"),
    "question_reply": ("v2.session.question.reply", "/api/session/{sessionID}/question/{requestID}/reply"),
    "question_reject": ("v2.session.question.reject", "/api/session/{sessionID}/question/{requestID}/reject"),
    "permission_reply": ("v2.session.permission.reply", "/api/session/{sessionID}/permission/{requestID}/reply"),
    "stop": ("v2.session.interrupt", "/api/session/{sessionID}/interrupt"),
}
FIXTURE_CONTENT = {
    "README.md": "# Disposable arithmetic fixture\n",
    "src/arithmetic.js": "export const add = (left, right) => left + right;\n",
    "test/arithmetic.test.js": "import { add } from '../src/arithmetic.js';\nif (add(1, 2) !== 3) throw new Error('arithmetic');\n",
}
TASK_SPEC_BOUNDARY = {
    "workspace": "harness_created_temporary_directory",
    "repository_source": "project_owned_generated_fixture",
    "personal_source_allowed": False,
    "ambient_opencode_auth_allowed": False,
    "provider_credential": "explicit_temporary_environment_variable_only",
    "cleanup_required": True,
}
EXPECTED_TASK_FLOW = (
    {
        "step": "question",
        "required_observation": "question.asked",
        "operator_action": "answer_with_project_owned_choice",
    },
    {
        "step": "diff",
        "required_observation": "authoritative_workspace_diff",
        "expected_file_count_min": 1,
    },
    {
        "step": "permission",
        "required_observation": "permission.asked",
        "operator_action": "reject",
    },
    {
        "step": "stop",
        "required_observation": "session_abort_or_interrupt_terminal_fact",
    },
    {
        "step": "reconnect",
        "required_observation": "snapshot_reconciliation_after_host_restart",
    },
)
FORBIDDEN_PERSISTED_CONTENT = frozenset({
    "provider_credential", "prompt", "source_text", "filesystem_path",
    "command_body", "diff_content", "raw_session_id", "raw_question_id",
    "raw_permission_id",
})
ADAPTER_ID = "opencode"


class RealTaskError(RuntimeError):
    """Stable, content-free error code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _capture_contract() -> Any:
    """Load the M1 implementation without relying on the hyphenated directory name."""
    spec = importlib.util.spec_from_file_location(
        "nomad_capture_contract", ROOT / "capture_contract.py"
    )
    if spec is None or spec.loader is None:
        raise RealTaskError("BLOCKED_LOCKED_RUNTIME_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _darwin_live_executable() -> Any:
    spec = importlib.util.spec_from_file_location(
        "nomad_darwin_live_executable_for_locked_launch",
        ROOT / "darwin_live_executable.py",
    )
    if spec is None or spec.loader is None:
        raise RealTaskError("BLOCKED_DARWIN_LIVE_EXECUTABLE_UNVERIFIED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _shape_digest(value: object) -> str:
    """Digest shape/provenance objects without treating them as receipts."""
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_task_spec_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_INVALID")
    expected_keys = {
        "schema", "data_boundary", "fixture_files", "task_flow",
        "forbidden_persisted_content",
    }
    if set(payload) != expected_keys or payload.get("schema") != "nomad.stock-opencode.disposable-task.v1":
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_INVALID")
    if payload.get("data_boundary") != TASK_SPEC_BOUNDARY:
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_INVALID")
    files = payload.get("fixture_files")
    expected_files = {
        (name, "project_owned_static_fixture") for name in FIXTURE_CONTENT
    }
    if (not isinstance(files, list) or len(files) != len(expected_files)
            or any(not isinstance(item, dict)
                   or set(item) != {"relative_name", "content_class"}
                   for item in files)
            or {(item["relative_name"], item["content_class"]) for item in files}
            != expected_files):
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_INVALID")
    flow = payload.get("task_flow")
    if (not isinstance(flow, list) or len(flow) != len(EXPECTED_TASK_FLOW)
            or any(not isinstance(item, dict) or item != expected
                   for item, expected in zip(flow, EXPECTED_TASK_FLOW))):
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_INVALID")
    if set(payload.get("forbidden_persisted_content", [])) != FORBIDDEN_PERSISTED_CONTENT:
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_INVALID")
    return payload


def load_task_spec(path: Path | None = None) -> tuple[dict[str, object], str]:
    """Load only a project-owned exact disposable-task schema."""
    selected = (path or DEFAULT_TASK_SPEC).resolve()
    try:
        selected.relative_to(ROOT.parent.parent.resolve())
        payload = json.loads(selected.read_text(encoding="utf-8"))
    except Exception as error:
        raise RealTaskError("BLOCKED_REAL_TASK_SPEC_REQUIRED") from error
    payload = _validate_task_spec_payload(payload)
    return payload, _shape_digest(payload)


def fixture_manifest() -> dict[str, object]:
    files = [
        {
            "relative_name": name,
            "sha256": _sha256_bytes(content.encode("utf-8")),
            "size": len(content.encode("utf-8")),
            "content_class": "project_owned_static_fixture",
        }
        for name, content in sorted(FIXTURE_CONTENT.items())
    ]
    return {"schema": "nomad.stock-opencode.fixture-manifest.v1", "files": files, "digest": _shape_digest(files)}


def verify_fixture_manifest(path: Path = FIXTURE_MANIFEST) -> dict[str, object]:
    try:
        actual = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise RealTaskError("BLOCKED_FIXTURE_MANIFEST_INVALID") from error
    expected = fixture_manifest()
    if actual != expected:
        raise RealTaskError("BLOCKED_FIXTURE_MANIFEST_INVALID")
    return expected


def materialize_fixture(workspace: Path, manifest: Mapping[str, object]) -> str:
    """Write only fixed project-owned bytes into a disposable workspace."""
    if manifest != fixture_manifest():
        raise RealTaskError("BLOCKED_FIXTURE_MANIFEST_INVALID")
    for name, content in FIXTURE_CONTENT.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return str(manifest["digest"])


def _fixture_matches_workspace(workspace: Path, manifest: Mapping[str, object]) -> bool:
    if manifest != fixture_manifest():
        return False
    try:
        return all(
            (workspace / name).read_bytes() == content.encode("utf-8")
            for name, content in FIXTURE_CONTENT.items()
        )
    except OSError:
        return False


def credential_present(
    provider_credential_env: str | None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Check only an allowlisted name and non-empty value; never return the value."""
    env = os.environ if environment is None else environment
    return bool(
        provider_credential_env in TEMPORARY_PROVIDER_ENV_NAMES
        and isinstance(env.get(provider_credential_env), str)
        and env[provider_credential_env].strip()
    )


def preflight(
    provider_credential_env: str | None,
    environment: Mapping[str, str] | None = None,
    task_spec: tuple[Mapping[str, object], str] | None = None,
) -> dict[str, object]:
    """Return BLOCKED until both explicit temporary inputs are available."""
    present = credential_present(provider_credential_env, environment)
    reasons: list[str] = []
    if not present:
        reasons.append("BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
    if task_spec is None:
        reasons.append("BLOCKED_REAL_TASK_SPEC_REQUIRED")
    return {"status": "READY" if not reasons else "BLOCKED", "reason_codes": reasons}


def isolated_base_env(
    *, home: Path, xdg: Path, npm_executable: Path | None = None
) -> dict[str, str]:
    """The sole environment for npm and every non-OpenCode subprocess."""
    npm = npm_executable or _canonical_npm_executable()
    node = _canonical_executable("node")
    return {
        "PATH": f"{node.parent}:{npm.parent}:{os.defpath}",
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(xdg / "config"),
        "XDG_DATA_HOME": str(xdg / "data"),
        "XDG_CACHE_HOME": str(xdg / "cache"),
        "LANG": "C",
        "LC_ALL": "C",
        "npm_config_loglevel": "error",
        "npm_config_registry": "https://registry.npmjs.org",
    }


def _canonical_executable(name: str) -> Path:
    try:
        selected = shutil.which(name)
        if not selected:
            raise OSError
        npm = Path(selected).resolve(strict=True)
        info = npm.stat()
        if (not npm.is_absolute() or not stat.S_ISREG(info.st_mode)
                or not info.st_mode & 0o111):
            raise OSError
        return npm
    except OSError:
        raise RealTaskError("BLOCKED_LOCKED_RUNTIME_UNAVAILABLE") from None


def _canonical_npm_executable() -> Path:
    return _canonical_executable("npm")


def _free_loopback_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _receipt_record(
    *,
    run_id: str,
    stage: str,
    sequence: int,
    predecessor_digest: str | None,
    reason_code: str,
    counts: Mapping[str, int] | None = None,
) -> dict[str, object]:
    if stage not in WP1_STAGES:
        raise RealTaskError("BLOCKED_WP1_STAGE_OWNERSHIP")
    process_role, source = STAGE_BINDINGS[stage]
    record = {
        "schema_version": 1,
        "run_id": run_id,
        "process_role": process_role,
        "stage": stage,
        "sequence": sequence,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "predecessor_digest": predecessor_digest,
        "digest": "0" * 64,
        "source": source,
        "status": "completed",
        "reason_code": reason_code,
        "subject_alias": "domain-" + _shape_digest({"run_id": run_id, "stage": stage}),
        "counts": dict(counts or {}),
    }
    record["digest"] = canonical_digest(record)
    return record


def append_wp1_receipt(
    store: Path,
    *,
    run_id: str,
    stage: str,
    sequence: int,
    predecessor_digest: str | None,
    reason_code: str,
    counts: Mapping[str, int] | None = None,
) -> str:
    """Append a shared-contract WP1 record; no WP3 or harness-proxy stages."""
    record = _receipt_record(
        run_id=run_id, stage=stage, sequence=sequence,
        predecessor_digest=predecessor_digest, reason_code=reason_code,
        counts=counts,
    )
    return append_receipt(store, record).digest


class _LockedOpenCodeLaunchMeasurement:
    """Frozen, private and non-serializable actual launch facts."""
    __slots__ = (
        "_package_name", "_package_version", "_package_lock_raw_digest",
        "_full_locked_dependency_count", "_full_locked_dependency_digest",
        "_installed_platform_dependency_count",
        "_installed_platform_dependency_digest", "_entrypoint_realpath",
        "_entrypoint_raw_digest", "_npm_executable_realpath", "_npm_version",
        "_task_spec_digest", "_fixture_manifest_digest", "_adapter_id",
        "_adapter_version", "_process_pid", "_root", "_install",
        "_workspace", "_port", "_sealed", "__weakref__",
    )

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("private locked launch measurement")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("frozen locked launch measurement")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("private locked launch measurement")

    def __repr__(self) -> str:
        return "LockedOpenCodeLaunchMeasurement(<redacted>)"

    def __reduce__(self) -> object:
        raise TypeError("private locked launch measurement")

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("private locked launch measurement")

    def __copy__(self) -> object:
        raise TypeError("private locked launch measurement")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("private locked launch measurement")


class LockedOpenCodeLaunch:
    __slots__ = ("root", "workspace", "home", "xdg", "install", "port",
                 "process", "__measurement", "__legacy_provenance_digest",
                 "__weakref__")

    def __init__(self, root: Path, workspace: Path, home: Path, xdg: Path,
                 install: Path, port: int, process: subprocess.Popen[bytes] | None,
                 provenance_digest: str) -> None:
        """Compatibility constructor; it deliberately cannot mint measurement."""
        self.root, self.workspace, self.home, self.xdg = root, workspace, home, xdg
        self.install, self.port, self.process = install, port, process
        self.__measurement = None
        self.__legacy_provenance_digest = provenance_digest

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("locked launch cannot be subclassed")

    def __reduce__(self) -> object:
        raise TypeError("locked launch cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("locked launch cannot be serialized")

    def __copy__(self) -> object:
        raise TypeError("locked launch cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("locked launch cannot be copied")

    @property
    def provenance_digest(self) -> str:
        return self.__legacy_provenance_digest

    def cleanup(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        shutil.rmtree(self.root, ignore_errors=True)


_MEASUREMENT_FACT_FIELDS = (
    "package_name", "package_version", "package_lock_raw_digest",
    "full_locked_dependency_count", "full_locked_dependency_digest",
    "installed_platform_dependency_count",
    "installed_platform_dependency_digest", "entrypoint_realpath",
    "entrypoint_raw_digest", "npm_executable_realpath", "npm_version",
    "task_spec_digest", "fixture_manifest_digest", "adapter_id",
    "adapter_version",
)
_PRODUCTION_LAUNCH_ISSUER = object()
_TEST_LAUNCH_ISSUER = object()
_LOCKED_LAUNCH_REGISTRY_LOCK = threading.RLock()
_ISSUED_LOCKED_MEASUREMENTS: weakref.WeakKeyDictionary[
    _LockedOpenCodeLaunchMeasurement, object
] = weakref.WeakKeyDictionary()


@dataclass(slots=True, repr=False)
class _LockedLaunchRegistryRecord:
    issuer: object
    measurement: _LockedOpenCodeLaunchMeasurement
    facts: tuple[tuple[str, object], ...]
    process: subprocess.Popen[bytes] | object
    process_pid: int
    root: Path
    workspace: Path
    home: Path
    xdg: Path
    install: Path
    port: int
    provenance_digest: str
    verify_artifacts: bool
    consumed: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class _ConsumedLockedOpenCodeLaunch:
    """Single-use handoff containing only registry snapshots and lifecycle handles."""

    facts: dict[str, object]
    process: subprocess.Popen[bytes] | object
    process_pid: int
    root: Path
    workspace: Path
    home: Path
    xdg: Path
    install: Path
    port: int


_ISSUED_LOCKED_LAUNCHES: weakref.WeakKeyDictionary[
    LockedOpenCodeLaunch, _LockedLaunchRegistryRecord
] = weakref.WeakKeyDictionary()


def _blocked_locked_launch() -> RealTaskError:
    return RealTaskError("BLOCKED_LOCKED_RUNTIME_UNAVAILABLE")


def _canonical_live_directory(path: object) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise _blocked_locked_launch()
    try:
        info = path.stat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise _blocked_locked_launch() from None
    if not stat.S_ISDIR(info.st_mode) or resolved != path:
        raise _blocked_locked_launch()
    return resolved


def _snapshot_measurement_facts(
    measurement: _LockedOpenCodeLaunchMeasurement,
) -> tuple[tuple[str, object], ...]:
    if type(measurement) is not _LockedOpenCodeLaunchMeasurement:
        raise _blocked_locked_launch()
    try:
        facts = tuple(
            (name, object.__getattribute__(measurement, "_" + name))
            for name in _MEASUREMENT_FACT_FIELDS
        )
    except (AttributeError, TypeError):
        raise _blocked_locked_launch() from None
    values = dict(facts)
    digest_fields = (
        "package_lock_raw_digest", "full_locked_dependency_digest",
        "installed_platform_dependency_digest", "entrypoint_raw_digest",
        "task_spec_digest", "fixture_manifest_digest",
    )
    count_fields = (
        "full_locked_dependency_count",
        "installed_platform_dependency_count",
    )
    if (any(not isinstance(values[name], str) or len(values[name]) != 64
            or any(character not in "0123456789abcdef" for character in values[name])
            for name in digest_fields)
            or any(type(values[name]) is not int or not 1 <= values[name] <= 65535
                   for name in count_fields)
            or any(not isinstance(values[name], str) or not values[name]
                   for name in set(_MEASUREMENT_FACT_FIELDS)
                   - set(digest_fields) - set(count_fields))):
        raise _blocked_locked_launch()
    return facts


def _issue_registered_locked_launch(
    issuer: object, *, root: Path, workspace: Path, home: Path, xdg: Path,
    install: Path, port: int, process: subprocess.Popen[bytes] | object,
    measurement: _LockedOpenCodeLaunchMeasurement, verify_artifacts: bool,
) -> LockedOpenCodeLaunch:
    """The sole exact-object issuer; the public constructor never registers."""
    if issuer not in (_PRODUCTION_LAUNCH_ISSUER, _TEST_LAUNCH_ISSUER):
        raise _blocked_locked_launch()
    if ((issuer is _PRODUCTION_LAUNCH_ISSUER) != verify_artifacts
            or type(measurement) is not _LockedOpenCodeLaunchMeasurement
            or object.__getattribute__(measurement, "_sealed") is not True
            or type(port) is not int or not 0 < port < 65536
            or (issuer is _PRODUCTION_LAUNCH_ISSUER
                and type(process) is not subprocess.Popen)):
        raise _blocked_locked_launch()
    try:
        process_pid = process.pid  # type: ignore[attr-defined]
        live = process.poll() is None  # type: ignore[attr-defined]
    except Exception:
        raise _blocked_locked_launch() from None
    if type(process_pid) is not int or process_pid <= 0 or not live:
        raise _blocked_locked_launch()
    paths = tuple(_canonical_live_directory(value) for value in (
        root, workspace, home, xdg, install,
    ))
    canonical_root, canonical_workspace, canonical_home, canonical_xdg, canonical_install = paths
    if (len(set(paths)) != len(paths)
            or any(not path.is_relative_to(canonical_root)
                   for path in paths[1:])):
        raise _blocked_locked_launch()
    facts = _snapshot_measurement_facts(measurement)
    if (object.__getattribute__(measurement, "_process_pid") != process_pid
            or object.__getattribute__(measurement, "_root") != canonical_root
            or object.__getattribute__(measurement, "_workspace") != canonical_workspace
            or object.__getattribute__(measurement, "_install") != canonical_install
            or object.__getattribute__(measurement, "_port") != port):
        raise _blocked_locked_launch()
    provenance_digest = _shape_digest(dict(facts))
    launch = LockedOpenCodeLaunch(
        canonical_root, canonical_workspace, canonical_home, canonical_xdg,
        canonical_install, port, process, provenance_digest,
    )
    object.__setattr__(
        launch, "_LockedOpenCodeLaunch__measurement", measurement
    )
    record = _LockedLaunchRegistryRecord(
        issuer=issuer, measurement=measurement, facts=facts, process=process,
        process_pid=process_pid, root=canonical_root, workspace=canonical_workspace,
        home=canonical_home, xdg=canonical_xdg, install=canonical_install,
        port=port, provenance_digest=provenance_digest,
        verify_artifacts=verify_artifacts,
    )
    with _LOCKED_LAUNCH_REGISTRY_LOCK:
        if measurement in _ISSUED_LOCKED_MEASUREMENTS:
            raise _blocked_locked_launch()
        _ISSUED_LOCKED_MEASUREMENTS[measurement] = issuer
        try:
            _ISSUED_LOCKED_LAUNCHES[launch] = record
        except Exception:
            del _ISSUED_LOCKED_MEASUREMENTS[measurement]
            raise
    return launch


def _verify_registry_artifacts(record: _LockedLaunchRegistryRecord) -> None:
    facts = dict(record.facts)
    try:
        capture = _capture_contract()
        darwin = _darwin_live_executable()
        lock_path = record.install / "package-lock.json"
        installed_package_path = (
            record.install / "node_modules" / str(facts["package_name"])
            / "package.json"
        )
        lock_raw = lock_path.read_bytes()
        installed_package = json.loads(installed_package_path.read_bytes())
        full = capture.full_locked_closure(lock_path)
        installed = capture.installed_platform_closure(lock_path, record.install)
        entrypoint = Path(str(facts["entrypoint_realpath"]))
        entrypoint_info = entrypoint.stat()
        npm = Path(str(facts["npm_executable_realpath"]))
        npm_info = npm.stat()
        base_env = isolated_base_env(
            home=record.home, xdg=record.xdg, npm_executable=npm
        )
        npm_version = capture.run(
            [str(npm), "--version"], cwd=record.install, env=base_env, timeout=10
        ).stdout.strip()
        manifest = verify_fixture_manifest()
        _task_payload, current_task_digest = load_task_spec()
        if (capture.sha256(lock_raw) != facts["package_lock_raw_digest"]
                or full["full_locked_dependency_count"]
                != facts["full_locked_dependency_count"]
                or full["full_locked_dependency_digest"]
                != facts["full_locked_dependency_digest"]
                or installed["installed_platform_dependency_count"]
                != facts["installed_platform_dependency_count"]
                or installed["installed_platform_dependency_digest"]
                != facts["installed_platform_dependency_digest"]
                or installed_package.get("name") != facts["package_name"]
                or installed_package.get("version") != facts["package_version"]
                or entrypoint.resolve(strict=True) != entrypoint
                or not stat.S_ISREG(entrypoint_info.st_mode)
                or not entrypoint_info.st_mode & 0o111
                or not entrypoint.is_relative_to(
                    record.install / "node_modules"
                )
                or capture.sha256(entrypoint.read_bytes())
                != facts["entrypoint_raw_digest"]
                or npm.resolve(strict=True) != npm
                or not stat.S_ISREG(npm_info.st_mode)
                or not npm_info.st_mode & 0o111
                or npm_version != facts["npm_version"]
                or current_task_digest != facts["task_spec_digest"]
                or manifest["digest"] != facts["fixture_manifest_digest"]
                or not _fixture_matches_workspace(record.workspace, manifest)
                or facts["adapter_id"] != ADAPTER_ID
                or facts["adapter_version"] != facts["package_version"]):
            raise _blocked_locked_launch()
        executable_fd = os.open(
            entrypoint, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        executable = os.fdopen(executable_fd, "rb", closefd=True)
        try:
            live = darwin.verify_live_executable(
                record.process, executable, record.install / "node_modules",
                os.getpid(),
            )
        finally:
            if not executable.closed:
                executable.close()
        comparison = object.__new__(_LockedOpenCodeLaunchMeasurement)
        object.__setattr__(comparison, "_sealed", False)
        sink = darwin._new_locked_launch_measurement_sink(
            darwin._SINK_TOKEN, comparison
        )
        comparison = darwin._bridge_verified_live_executable(live, sink)
        if (object.__getattribute__(comparison, "_sealed") is not True
                or object.__getattribute__(comparison, "_process_pid")
                != record.process_pid
                or object.__getattribute__(comparison, "_entrypoint_realpath")
                != facts["entrypoint_realpath"]
                or object.__getattribute__(comparison, "_entrypoint_raw_digest")
                != facts["entrypoint_raw_digest"]):
            raise _blocked_locked_launch()
    except RealTaskError:
        raise
    except Exception:
        raise _blocked_locked_launch() from None


def _verified_registry_record_locked(
    launch: object, issuer: object,
) -> _LockedLaunchRegistryRecord:
    if type(launch) is not LockedOpenCodeLaunch:
        raise _blocked_locked_launch()
    record = _ISSUED_LOCKED_LAUNCHES.get(launch)
    if (record is None or record.issuer is not issuer or record.consumed
            or _ISSUED_LOCKED_MEASUREMENTS.get(record.measurement) is not issuer):
        raise _blocked_locked_launch()
    try:
        measurement = object.__getattribute__(
            launch, "_LockedOpenCodeLaunch__measurement"
        )
        legacy_digest = object.__getattribute__(
            launch, "_LockedOpenCodeLaunch__legacy_provenance_digest"
        )
        process = object.__getattribute__(launch, "process")
        process_pid = process.pid
        process_alive = process.poll() is None
    except Exception:
        raise _blocked_locked_launch() from None
    if (measurement is not record.measurement
            or type(measurement) is not _LockedOpenCodeLaunchMeasurement
            or object.__getattribute__(measurement, "_sealed") is not True
            or _snapshot_measurement_facts(measurement) != record.facts
            or object.__getattribute__(measurement, "_process_pid")
            != record.process_pid
            or object.__getattribute__(measurement, "_root") != record.root
            or object.__getattribute__(measurement, "_workspace")
            != record.workspace
            or object.__getattribute__(measurement, "_install") != record.install
            or object.__getattribute__(measurement, "_port") != record.port
            or process is not record.process or process_pid != record.process_pid
            or not process_alive or legacy_digest != record.provenance_digest
            or object.__getattribute__(launch, "root") != record.root
            or object.__getattribute__(launch, "workspace") != record.workspace
            or object.__getattribute__(launch, "home") != record.home
            or object.__getattribute__(launch, "xdg") != record.xdg
            or object.__getattribute__(launch, "install") != record.install
            or object.__getattribute__(launch, "port") != record.port):
        raise _blocked_locked_launch()
    current_paths = tuple(_canonical_live_directory(value) for value in (
        record.root, record.workspace, record.home, record.xdg, record.install,
    ))
    if (current_paths != (record.root, record.workspace, record.home,
                          record.xdg, record.install)
            or any(not path.is_relative_to(record.root)
                   for path in current_paths[1:])):
        raise _blocked_locked_launch()
    if record.verify_artifacts:
        _verify_registry_artifacts(record)
        try:
            if (record.process.pid != record.process_pid
                    or record.process.poll() is not None):
                raise _blocked_locked_launch()
        except RealTaskError:
            raise
        except Exception:
            raise _blocked_locked_launch() from None
    return record


def _measurement_facts(launch: LockedOpenCodeLaunch) -> dict[str, object]:
    """Read an unconsumed production issuance after complete revalidation."""
    with _LOCKED_LAUNCH_REGISTRY_LOCK:
        record = _verified_registry_record_locked(
            launch, _PRODUCTION_LAUNCH_ISSUER
        )
        return dict(record.facts)


def _consume_registered_locked_launch(
    launch: LockedOpenCodeLaunch, issuer: object,
) -> _ConsumedLockedOpenCodeLaunch:
    with _LOCKED_LAUNCH_REGISTRY_LOCK:
        record = _verified_registry_record_locked(launch, issuer)
        consumed = _ConsumedLockedOpenCodeLaunch(
            facts=dict(record.facts), process=record.process,
            process_pid=record.process_pid, root=record.root,
            workspace=record.workspace, home=record.home, xdg=record.xdg,
            install=record.install, port=record.port,
        )
        record.consumed = True
        return consumed


def _consume_verified_locked_launch(
    launch: LockedOpenCodeLaunch,
) -> _ConsumedLockedOpenCodeLaunch:
    """Atomically consume one exact production launch and return snapshots."""
    return _consume_registered_locked_launch(launch, _PRODUCTION_LAUNCH_ISSUER)


def _issue_test_only_locked_launch(
    *, root: Path, workspace: Path, home: Path, xdg: Path, install: Path,
    port: int, process: object, facts: Mapping[str, object],
) -> LockedOpenCodeLaunch:
    """Exercise registry mechanics without ever minting production authority."""
    if set(facts) != set(_MEASUREMENT_FACT_FIELDS):
        raise _blocked_locked_launch()
    measurement = object.__new__(_LockedOpenCodeLaunchMeasurement)
    for name in _MEASUREMENT_FACT_FIELDS:
        object.__setattr__(measurement, "_" + name, facts[name])
    object.__setattr__(measurement, "_process_pid", process.pid)
    object.__setattr__(measurement, "_root", root)
    object.__setattr__(measurement, "_workspace", workspace)
    object.__setattr__(measurement, "_install", install)
    object.__setattr__(measurement, "_port", port)
    object.__setattr__(measurement, "_sealed", True)
    return _issue_registered_locked_launch(
        _TEST_LAUNCH_ISSUER, root=root, workspace=workspace, home=home,
        xdg=xdg, install=install, port=port, process=process,
        measurement=measurement, verify_artifacts=False,
    )


def _consume_test_only_locked_launch(
    launch: LockedOpenCodeLaunch,
) -> _ConsumedLockedOpenCodeLaunch:
    return _consume_registered_locked_launch(launch, _TEST_LAUNCH_ISSUER)


def launch_locked_opencode(
    *,
    provider_credential_env: str,
    task_spec: tuple[Mapping[str, object], str],
    environment: Mapping[str, str] | None = None,
    start: bool = True,
) -> LockedOpenCodeLaunch:
    """Create an isolated verified runtime; the secret enters only OpenCode env."""
    if not start:
        raise RealTaskError("BLOCKED_DARWIN_LIVE_EXECUTABLE_UNVERIFIED")
    source_env = os.environ if environment is None else environment
    if not credential_present(provider_credential_env, source_env):
        raise RealTaskError("BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
    capture = _capture_contract()
    artifact = capture.registry_artifact()
    locked = capture.validate_locked_runtime(artifact)
    capture.validate_registry_closure(capture.LOCKED_LOCK)
    root = Path(tempfile.mkdtemp(prefix="nomad-real-task-")).resolve(strict=True)
    home, xdg = root / "home", root / "xdg"
    workspace, install = root / "workspace", root / "locked-runtime"
    process: subprocess.Popen[bytes] | None = None
    try:
        home.mkdir()
        xdg.mkdir()
        workspace.mkdir()
        manifest = verify_fixture_manifest()
        materialize_fixture(workspace, manifest)
        shutil.copytree(LOCKED_RUNTIME, install)
        npm = _canonical_npm_executable()
        base_env = isolated_base_env(home=home, xdg=xdg, npm_executable=npm)
        capture.run(
            [str(npm), "ci", "--ignore-scripts=false", "--no-audit", "--no-fund"],
            cwd=install,
            env=base_env,
            timeout=120,
        )
        npm_version = capture.run([str(npm), "--version"], cwd=install, env=base_env).stdout.strip()
        if npm_version != capture.EXPECTED_NPM_VERSION:
            raise RealTaskError("BLOCKED_ENVIRONMENT_COMPATIBILITY_MISMATCH")
        package_path, lock_path = install / "package.json", install / "package-lock.json"
        package_raw, lock_raw = package_path.read_bytes(), lock_path.read_bytes()
        package = json.loads(package_raw)
        installed_package_path = install / "node_modules" / capture.PACKAGE / "package.json"
        installed_package_raw = installed_package_path.read_bytes()
        installed_package = json.loads(installed_package_raw)
        full = capture.full_locked_closure(lock_path)
        if (capture.sha256(package_raw) != locked["package_json_sha256"]
                or capture.sha256(lock_raw) != locked["package_lock_sha256"]
                or full != {key: locked[key] for key in full}
                or package.get("dependencies", {}).get(capture.PACKAGE) != capture.EXPECTED_VERSION
                or installed_package.get("name") != capture.PACKAGE
                or installed_package.get("version") != capture.EXPECTED_VERSION):
            raise RealTaskError("BLOCKED_DEPENDENCY_CLOSURE_MISMATCH")
        installed = capture.installed_platform_closure(lock_path, install)
        binary = install / "node_modules" / ".bin" / "opencode"
        resolved, _observed = capture.observed_installed_entrypoint(binary, install)
        if capture.run([str(resolved), "--version"], cwd=workspace, env=base_env, timeout=10).stdout.strip() != capture.EXPECTED_VERSION:
            raise RealTaskError("BINARY_VERSION_MISMATCH")
        executable_fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        executable = os.fdopen(executable_fd, "rb", closefd=True)
        port = _free_loopback_port()
        child_env = dict(base_env)
        child_env[provider_credential_env] = source_env[provider_credential_env]
        try:
            process = subprocess.Popen(
                [str(resolved), "serve", "--pure", "--hostname", "127.0.0.1", "--port", str(port)],
                cwd=workspace, env=child_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        finally:
            child_env.pop(provider_credential_env, None)
            del child_env
        try:
            capture.wait_health(f"http://127.0.0.1:{port}")
            darwin = _darwin_live_executable()
            live = darwin.verify_live_executable(
                process, executable, install / "node_modules", os.getpid()
            )
        except Exception:
            if not executable.closed:
                executable.close()
            raise

        # Mutable inputs are observed again after health/live-image proof.
        if (_canonical_npm_executable() != npm
                or package_path.read_bytes() != package_raw
                or lock_path.read_bytes() != lock_raw
                or installed_package_path.read_bytes() != installed_package_raw
                or capture.full_locked_closure(lock_path) != full
                or capture.installed_platform_closure(lock_path, install) != installed
                or _validate_task_spec_payload(task_spec[0]) != task_spec[0]
                or _shape_digest(task_spec[0]) != task_spec[1]
                or verify_fixture_manifest() != manifest
                or fixture_manifest() != manifest
                or not _fixture_matches_workspace(workspace, manifest)
                or binary.resolve(strict=True) != resolved):
            raise RealTaskError("BLOCKED_DEPENDENCY_CLOSURE_MISMATCH")
        measurement = object.__new__(_LockedOpenCodeLaunchMeasurement)
        pending_facts = {
            "package_name": installed_package["name"],
            "package_version": installed_package["version"],
            "package_lock_raw_digest": capture.sha256(lock_raw),
            "full_locked_dependency_count": full["full_locked_dependency_count"],
            "full_locked_dependency_digest": full["full_locked_dependency_digest"],
            "installed_platform_dependency_count": installed["installed_platform_dependency_count"],
            "installed_platform_dependency_digest": installed["installed_platform_dependency_digest"],
            "npm_executable_realpath": str(npm), "npm_version": npm_version,
            "task_spec_digest": task_spec[1], "fixture_manifest_digest": manifest["digest"],
            "adapter_id": ADAPTER_ID, "adapter_version": capture.EXPECTED_VERSION,
            "root": root, "install": install, "workspace": workspace, "port": port,
        }
        for name, fact in pending_facts.items():
            object.__setattr__(measurement, "_" + name, fact)
        object.__setattr__(measurement, "_sealed", False)
        sink = darwin._new_locked_launch_measurement_sink(
            darwin._SINK_TOKEN, measurement
        )
        measurement = darwin._bridge_verified_live_executable(live, sink)
        if (process.poll() is not None or process.pid != measurement._process_pid
                or str(resolved) != measurement._entrypoint_realpath
                or capture.sha256(resolved.read_bytes()) != measurement._entrypoint_raw_digest):
            raise RealTaskError("BLOCKED_DARWIN_LIVE_EXECUTABLE_UNVERIFIED")
        return _issue_registered_locked_launch(
            _PRODUCTION_LAUNCH_ISSUER, root=root, workspace=workspace,
            home=home, xdg=xdg, install=install, port=port, process=process,
            measurement=measurement, verify_artifacts=True,
        )
    except Exception:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        shutil.rmtree(root, ignore_errors=True)
        raise


def _resolve(schema: object, schemas: Mapping[str, object]) -> Mapping[str, object]:
    if isinstance(schema, Mapping) and isinstance(schema.get("$ref"), str):
        schema = schemas.get(schema["$ref"].rsplit("/", 1)[-1], {})
    return schema if isinstance(schema, Mapping) else {}


def _schema_shape(schema: object, schemas: Mapping[str, object]) -> dict[str, object]:
    resolved = _resolve(schema, schemas)
    properties = resolved.get("properties", {})
    result: dict[str, object] = {
        "type": str(resolved.get("type", "unspecified")),
        "required": sorted(resolved.get("required", [])) if isinstance(resolved.get("required"), list) else [],
        "property_names": sorted(properties) if isinstance(properties, Mapping) else [],
    }
    if isinstance(resolved.get("enum"), list):
        result["enum"] = list(resolved["enum"])
    if isinstance(properties, Mapping):
        result["properties"] = {str(name): _schema_shape(value, schemas) for name, value in sorted(properties.items())}
    if "items" in resolved:
        result["items"] = _schema_shape(resolved["items"], schemas)
    return result


def extract_command_shapes(openapi: Mapping[str, object]) -> dict[str, object]:
    """Extract only exact, separate v2 command routes and schema protocol shape."""
    paths = openapi.get("paths", {})
    components = openapi.get("components", {})
    schemas = components.get("schemas", {}) if isinstance(components, Mapping) else {}
    if not isinstance(paths, Mapping) or not isinstance(schemas, Mapping):
        raise RealTaskError("BLOCKED_OPENAPI_UNAVAILABLE")
    shapes: dict[str, object] = {}
    for action, (operation_id, route) in V2_ACTIONS.items():
        path_item = paths.get(route)
        operation = path_item.get("post") if isinstance(path_item, Mapping) else None
        if not isinstance(operation, Mapping) or operation.get("operationId") != operation_id:
            raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
        request = operation.get("requestBody", {})
        content = request.get("content", {}) if isinstance(request, Mapping) else {}
        responses = operation.get("responses", {})
        if not isinstance(content, Mapping) or not isinstance(responses, Mapping):
            raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
        request_shapes = {
            str(media): _schema_shape(value.get("schema", {}), schemas)
            for media, value in sorted(content.items()) if isinstance(value, Mapping)
        }
        response_shapes = {
            str(status): {
                str(media): _schema_shape(value.get("schema", {}), schemas)
                for media, value in sorted((response.get("content", {}) if isinstance(response, Mapping) else {}).items())
                if isinstance(value, Mapping)
            }
            for status, response in sorted(responses.items())
        }
        shape = {
            "operation_id": operation_id,
            "route": route,
            "method": "post",
            "request": request_shapes,
            "responses": response_shapes,
        }
        shapes[action] = {**shape, "digest": _shape_digest(shape)}
    return shapes


def fetch_command_shapes(base_url: str) -> dict[str, object]:
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + "/doc", timeout=5) as response:
            document = json.load(response)
        if not isinstance(document, Mapping):
            raise ValueError
        return extract_command_shapes(document)
    except RealTaskError:
        raise
    except Exception as error:
        raise RealTaskError("BLOCKED_OPENAPI_UNAVAILABLE") from error


def command_shape_fixture(
    *,
    provenance_digest: str,
    shapes: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": "nomad.stock-opencode.command-shapes.v1",
        "classification": "official_shape_only_not_lifecycle",
        "runtime_provenance_digest": provenance_digest,
        "actions": dict(shapes),
    }


def current_m1_runtime_provenance_digest() -> str:
    """Bind shape evidence to current committed M1 runtime evidence."""
    try:
        manifest = json.loads((ROOT / "capture-manifest.json").read_text(encoding="utf-8"))
        official = json.loads((ROOT / "official-stock-contract.json").read_text(encoding="utf-8"))
        provenance = official["provenance"]
        bound = {
            "manifest_fixture": manifest["fixture_canonical_sha256"],
            "manifest_script": manifest["capture_contract_sha256"],
            "package": manifest["package_json_sha256"],
            "lock": manifest["package_lock_sha256"],
            "closure": manifest["full_locked_dependency_digest"],
            "entrypoint_wrapper": manifest["observed_installed_entrypoint_wrapper_sha256"],
            "entrypoint_target": manifest["observed_installed_entrypoint_target_sha256"],
            "classification": manifest["classification"],
            "official_fixture": _shape_digest(official),
            "official_classification": provenance["classification"],
            "official_entrypoint_target": provenance["observed_installed_entrypoint_target_sha256"],
        }
    except Exception as error:
        raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING") from error
    return _shape_digest(bound)


def verify_command_shape_fixture(path: Path = COMMAND_SHAPES) -> dict[str, object]:
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING") from error
    if (not isinstance(fixture, dict) or fixture.get("schema") != "nomad.stock-opencode.command-shapes.v1"
            or fixture.get("classification") != "official_shape_only_not_lifecycle"
            or fixture.get("runtime_provenance_digest")
            != current_m1_runtime_provenance_digest()):
        raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
    actions = fixture.get("actions")
    if not isinstance(actions, dict) or set(actions) != set(V2_ACTIONS):
        raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
    for action, (operation_id, route) in V2_ACTIONS.items():
        shape = actions[action]
        if (not isinstance(shape, dict) or shape.get("operation_id") != operation_id
                or shape.get("route") != route or shape.get("method") != "post"):
            raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
        digest = shape.pop("digest", None)
        valid = isinstance(digest, str) and digest == _shape_digest(shape)
        shape["digest"] = digest
        if not valid:
            raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
    return fixture


def launch_shape_probe() -> LockedOpenCodeLaunch:
    """Launch a M1-verified locked server with no Provider environment."""
    capture = _capture_contract()
    artifact = capture.registry_artifact()
    locked = capture.validate_locked_runtime(artifact)
    capture.validate_registry_closure(capture.LOCKED_LOCK)
    root = Path(tempfile.mkdtemp(prefix="nomad-command-shape-probe-"))
    home, xdg = root / "home", root / "xdg"
    workspace, install = root / "workspace", root / "locked-runtime"
    process: subprocess.Popen[bytes] | None = None
    try:
        home.mkdir()
        xdg.mkdir()
        workspace.mkdir()
        shutil.copytree(LOCKED_RUNTIME, install)
        base_env = isolated_base_env(home=home, xdg=xdg)
        capture.run(["npm", "ci", "--ignore-scripts=false", "--no-audit", "--no-fund"], cwd=install, env=base_env, timeout=120)
        if (capture.sha256((install / "package.json").read_bytes()) != locked["package_json_sha256"]
                or capture.sha256((install / "package-lock.json").read_bytes()) != locked["package_lock_sha256"]
                or capture.full_locked_closure(install / "package-lock.json") != {key: locked[key] for key in capture.full_locked_closure(install / "package-lock.json")}):
            raise RealTaskError("BLOCKED_DEPENDENCY_CLOSURE_MISMATCH")
        resolved, observed = capture.observed_installed_entrypoint(install / "node_modules" / ".bin" / "opencode", install)
        if capture.run([str(resolved), "--version"], cwd=workspace, env=base_env, timeout=10).stdout.strip() != capture.EXPECTED_VERSION:
            raise RealTaskError("BINARY_VERSION_MISMATCH")
        port = _free_loopback_port()
        process = subprocess.Popen([str(resolved), "serve", "--pure", "--hostname", "127.0.0.1", "--port", str(port)], cwd=workspace, env=base_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        capture.wait_health("http://127.0.0.1:" + str(port))
        provenance = {"package_json_sha256": locked["package_json_sha256"], "package_lock_sha256": locked["package_lock_sha256"], "full_locked_dependency_digest": locked["full_locked_dependency_digest"], "entrypoint_target_sha256": observed["observed_installed_entrypoint_target_sha256"]}
        return LockedOpenCodeLaunch(root, workspace, home, xdg, install, port, process, _shape_digest(provenance))
    except Exception:
        if process is not None:
            process.kill()
        shutil.rmtree(root, ignore_errors=True)
        raise


def verify_live_command_shapes() -> None:
    """Compare credential-free live locked OpenAPI shapes to committed evidence."""
    fixture = verify_command_shape_fixture()
    launch = launch_shape_probe()
    try:
        actual = command_shape_fixture(provenance_digest=current_m1_runtime_provenance_digest(), shapes=fetch_command_shapes("http://127.0.0.1:" + str(launch.port)))
        if _shape_digest(actual) != _shape_digest(fixture):
            raise RealTaskError("BLOCKED_COMMAND_SHAPE_MISSING")
    finally:
        launch.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-credential-env")
    parser.add_argument("--task-spec", type=Path)
    parser.add_argument("--verify-command-shapes", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_command_shapes:
            verify_live_command_shapes()
            print(json.dumps({"status": "VERIFIED"}, sort_keys=True))
            return 0
        if not args.provider_credential_env or args.task_spec is None:
            raise RealTaskError("BLOCKED_REAL_TASK_SPEC_REQUIRED")
        task_spec = load_task_spec(args.task_spec)
        result = preflight(args.provider_credential_env, task_spec=task_spec)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "READY" else 1
    except RealTaskError as error:
        print(json.dumps({"status": "BLOCKED", "reason_codes": [error.code]}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
