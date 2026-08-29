#!/usr/bin/env python3
"""P8-G parent journey over the existing real product subjourneys."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "nomad.product-journey.evidence.v2"
EXTERNAL_GATES = (
    "PROVIDER_E3_EVIDENCE_NOT_RUN", "PHYSICAL_PHONE_SAFARI_NOT_RUN",
    "CLEAN_MACHINE_INSTALL_NOT_RUN", "DEVELOPER_ID_SIGNING_NOT_RUN",
    "APPLE_NOTARIZATION_NOT_RUN", "PUBLICATION_PROVENANCE_NOT_RUN",
)
REQUIRED = ("A_remote_local_evidence", "B_c3_local", "C_lifecycle")
MAX_CLI_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_QA_DRIVER_BYTES = 2 * 1024 * 1024
QA_DRIVER_CLASSIFICATION = "external-qa-not-shipped-product-closure"
QA_DRIVER_SOURCE_SHA256 = "f521f5b71e84b50013b98dd3010de601b79ccfecb79e73aba2a2d8e081a817b9"
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
ONBOARDING_STATES = {
    "NOT_INSTALLED", "INSTALLED_NEEDS_START",
    "INSTALLED_BLOCKED_HOST_IDENTITY", "RUNNING_NEEDS_PAIRING",
    "RUNNING_PAIRED", "RUNNING_DEGRADED_RECOVERY_REQUIRED",
}
ONBOARDING_KEYS = {
    "schema", "state", "production_ready", "external_readiness",
    "external_gates", "installed_bundle_digest", "install_sequence",
    "run_identity", "paired_device_commitment", "pairing_epoch",
    "blockers", "next_action",
}
HOST_IDENTITY_BLOCKERS = {
    "HOST_IDENTITY_AUTH_REQUIRED", "HOST_IDENTITY_USER_DENIED",
    "HOST_IDENTITY_KEYCHAIN_LOCKED", "HOST_IDENTITY_CORRUPT",
    "HOST_IDENTITY_UNAVAILABLE", "HOST_IDENTITY_PREFLIGHT_INVALID",
    "HOST_IDENTITY_PREFLIGHT_TIMEOUT", "HOST_IDENTITY_PREFLIGHT_FAILED",
}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("P8G_SUBJOURNEY_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stage(name: str, status: str, code: str, **facts: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "code": code, "facts": facts}


def _safe_work_root(work_root: Path | None) -> tuple[tempfile.TemporaryDirectory[str] | None, Path]:
    if work_root is None:
        owned = tempfile.TemporaryDirectory(prefix="nomad-p8g-")
        root = Path(owned.name)
        os.chmod(root, 0o700)
        return owned, root
    root = work_root.absolute()
    existed = root.exists()
    root.mkdir(parents=True, exist_ok=True)
    if not existed:
        os.chmod(root, 0o700)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("P8G_UNSAFE_WORK_ROOT")
    return None, root


def _bundle_digest(bundle: Path) -> str:
    try:
        package_root = str(ROOT / "tools")
        if package_root not in os.sys.path:
            os.sys.path.insert(0, package_root)
        from nomad_web.bundle import verify_bundle
        value = verify_bundle(bundle)
    except (OSError, RuntimeError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("P8G_BUNDLE_VERIFY_FAILED") from error
    item = value.get("bundle_digest")
    if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None:
        raise RuntimeError("P8G_BUNDLE_DIGEST_INVALID")
    return item


def _read_regular_file(path: Path, limit: int, code: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(code) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or not 0 < before.st_size <= limit
        ):
            raise RuntimeError(code)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RuntimeError(code)
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise RuntimeError(code)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _stage_qa_driver(
    source: Path, stage_root: Path, installed_bundle: Path,
    installed_bundle_digest: str,
) -> tuple[Path, dict[str, str]]:
    raw = _read_regular_file(source, MAX_QA_DRIVER_BYTES, "P8H_QA_DRIVER_SOURCE_INVALID")
    if hashlib.sha256(raw).hexdigest() != QA_DRIVER_SOURCE_SHA256:
        raise RuntimeError("P8H_QA_DRIVER_SOURCE_DIGEST_MISMATCH")
    if (
        re.fullmatch(r"[0-9a-f]{64}", installed_bundle_digest) is None
        or installed_bundle.resolve(strict=True).name != installed_bundle_digest
    ):
        raise RuntimeError("P8H_INSTALLED_BUNDLE_BINDING_INVALID")
    repo_binding = (
        b"REPO = Path(__file__).resolve().parents[2]\n"
        b"if __package__ in (None, \"\"):\n"
        b"    sys.path.insert(0, str(REPO))\n"
    )
    tools_import = b"from tools.nomad_web"
    if raw.count(repo_binding) != 1 or raw.count(tools_import) != 3:
        raise RuntimeError("P8H_QA_DRIVER_SOURCE_INVALID")
    stage_root = stage_root.absolute()
    installed_lib = (installed_bundle / "lib").resolve(strict=True)
    raw = raw.replace(
        repo_binding,
        (
            f"REPO = Path({json.dumps(str(stage_root))})\n"
            f"sys.path.insert(0, {json.dumps(str(installed_lib))})\n"
        ).encode("utf-8"),
    ).replace(tools_import, b"from nomad_web")
    generated_digest = hashlib.sha256(raw).hexdigest()
    binding = {
        "classification": QA_DRIVER_CLASSIFICATION,
        "trusted_source_sha256": QA_DRIVER_SOURCE_SHA256,
        "generated_sha256": generated_digest,
        "installed_bundle_digest": installed_bundle_digest,
    }
    binding["closure_digest"] = hashlib.sha256(canonical(binding)).hexdigest()
    stage_root.mkdir(mode=0o700)
    os.chmod(stage_root, 0o700)
    root_info = stage_root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != os.geteuid() or stat.S_IMODE(root_info.st_mode) != 0o700
    ):
        raise RuntimeError("P8H_QA_DRIVER_STAGE_INVALID")
    staged = stage_root / "c3_local_command_smoke.py"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(staged, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("P8H_QA_DRIVER_STAGE_FAILED")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _verified_qa_driver_bytes(staged, binding)
    return staged, binding


def _verified_qa_driver_bytes(path: Path, binding: Mapping[str, str]) -> bytes:
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise RuntimeError("P8H_QA_DRIVER_STAGE_INVALID")
    raw = _read_regular_file(path, MAX_QA_DRIVER_BYTES, "P8H_QA_DRIVER_STAGE_INVALID")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("P8H_QA_DRIVER_STAGE_INVALID")
    expected = {
        "classification": QA_DRIVER_CLASSIFICATION,
        "trusted_source_sha256": QA_DRIVER_SOURCE_SHA256,
        "generated_sha256": binding.get("generated_sha256"),
        "installed_bundle_digest": binding.get("installed_bundle_digest"),
    }
    if (
        set(binding) != {*expected, "closure_digest"}
        or any(re.fullmatch(r"[0-9a-f]{64}", str(expected[field])) is None for field in ("generated_sha256", "installed_bundle_digest"))
        or hashlib.sha256(canonical(expected)).hexdigest() != binding.get("closure_digest")
        or hashlib.sha256(raw).hexdigest() != expected["generated_sha256"]
    ):
        raise RuntimeError("P8H_QA_DRIVER_DIGEST_MISMATCH")
    return raw


class _PinnedSubprocess:
    def __init__(self, raw: bytes):
        self._encoded = base64.b64encode(raw).decode("ascii")

    def __getattr__(self, name: str) -> Any:
        return getattr(subprocess, name)

    def Popen(self, argv: Any, *args: Any, **kwargs: Any) -> Any:
        if (
            isinstance(argv, list) and len(argv) >= 3
            and argv[0] == os.sys.executable and "--fake" in argv
        ):
            bootstrap = (
                "import base64,os;"
                "raw=base64.b64decode(os.environ.pop('P8H_PINNED_QA_DRIVER'),validate=True);"
                "scope={'__name__':'__main__','__file__':'<pinned-c3-qa-driver>',"
                "'__package__':None};"
                "exec(compile(raw,'<pinned-c3-qa-driver>','exec'),scope,scope)"
            )
            environment = dict(kwargs.get("env") or {})
            environment["P8H_PINNED_QA_DRIVER"] = self._encoded
            kwargs["env"] = environment
            argv = [argv[0], "-I", "-B", "-c", bootstrap, *argv[2:]]
        return subprocess.Popen(argv, *args, **kwargs)


def _load_qa_driver(
    path: Path, binding: Mapping[str, str], installed_bundle: Path,
    expected_bundle_digest: str,
) -> Any:
    raw = _verified_qa_driver_bytes(path, binding)
    installed_bundle = installed_bundle.resolve(strict=True)
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_bundle_digest) is None
        or installed_bundle.parent.name != "bundles"
        or installed_bundle.name != expected_bundle_digest
        or binding.get("installed_bundle_digest") != expected_bundle_digest
    ):
        raise RuntimeError("P8H_INSTALLED_BUNDLE_BINDING_INVALID")
    installed_lib = (installed_bundle / "lib").resolve(strict=True)
    name = "p8g_c3_" + str(binding["closure_digest"])[:16]
    module = ModuleType(name)
    module.__file__ = "<pinned-c3-qa-driver>"
    module.__package__ = ""
    previous_path = list(os.sys.path)
    displaced = {
        key: value for key, value in tuple(os.sys.modules.items())
        if key == "nomad_web" or key.startswith("nomad_web.")
    }
    for key in displaced:
        os.sys.modules.pop(key, None)
    os.sys.path.insert(0, str(installed_lib))
    previous_dont_write_bytecode = os.sys.dont_write_bytecode
    os.sys.dont_write_bytecode = True
    try:
        exec(compile(raw, "<pinned-c3-qa-driver>", "exec"), module.__dict__, module.__dict__)
    finally:
        os.sys.dont_write_bytecode = previous_dont_write_bytecode
        for key in tuple(os.sys.modules):
            if key == "nomad_web" or key.startswith("nomad_web."):
                os.sys.modules.pop(key, None)
        os.sys.modules.update(displaced)
        os.sys.path[:] = previous_path
    module.subprocess = _PinnedSubprocess(raw)
    return module


def _facts_from_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"result_type": type(result).__name__}
    facts: dict[str, Any] = {}
    for key in ("status", "code", "production_ready", "provider_e3", "physical_phone", "content_free"):
        if key in result and isinstance(result[key], (str, bool, int, float, type(None))):
            facts[key] = result[key]
    if isinstance(result.get("journey"), dict):
        facts["journey"] = {
            key: value for key, value in result["journey"].items()
            if key in {"desktop_shell", "join_shell", "pairing", "projection", "refresh_recovery", "revoke", "revoked_browser_blocked", "actions"}
        }
    return facts


def _c3_projection(result: dict[str, Any]) -> dict[str, Any]:
    actions = result["actions"]
    return {
        "marker": result["marker"],
        "mechanical_e2": result["mechanical_e2"],
        "provider_e3": result["provider_e3"],
        "production_ready": result["production_ready"],
        "materialized_product_host": result["materialized_product_host"],
        "materialized_gateway": result["materialized_gateway"],
        "materialized_web": result["materialized_web"],
        "fake_boundary": result["fake_boundary"],
        "browser": {"engine": result["browser"]["engine"], "same_projection": result["browser"]["same_projection"]},
        "actions": {
            name: {key: actions[name][key] for key in (("browser_path", "browser_requests", "browser_responses", "posts", "replay_side_effects") if name != "uncertainty" else ("status", "posts", "automatic_retries"))}
            for name in ("reply", "deny", "stop", "uncertainty")
        },
        "privacy": result["privacy"],
        "containment": result["containment"],
        "journal": {"mode": result["journal"]["mode"], "synchronous": result["journal"]["synchronous"], "rows": result["journal"]["rows"]},
        "cleanup": result["cleanup"],
    }


def _run_a(bundle: Path, evidence: Path, parent_digest: str, tls_descriptors: tuple[int, int, int] | None = None) -> dict[str, Any]:
    if tls_descriptors is None:
        return _stage("A_remote_local_evidence", "NOT_RUN", "P8G_TLS_CONTROL_INPUT_REQUIRED", parent_evidence_digest=parent_digest)
    module = _load(ROOT / "testkit/remote-v2/run_m3e_product_slice.py", "p8g_m3e")
    try:
        result = module.run_slice(bundle, evidence, False, False, parent_digest, tls_descriptors)
    except Exception as error:
        return _stage("A_remote_local_evidence", "BLOCK", str(error) if str(error).isupper() else "P8G_M3E_RUN_FAILED", error_type=type(error).__name__)
    if not isinstance(result, dict) or result.get("marker") != "M3E_REAL_PRODUCT_SLICE_PASS" or result.get("production_ready") is not False:
        return _stage("A_remote_local_evidence", "BLOCK", "P8G_M3E_RESULT_CONTRACT_INVALID", result=_facts_from_result(result))
    return _stage("A_remote_local_evidence", "PASS", "M3E_REAL_PRODUCT_SLICE_PASS", result=_facts_from_result(result), parent_evidence_digest=parent_digest)


def _exact_int(value: Any, expected: int | None = None, *, minimum: int | None = None) -> bool:
    return (
        type(value) is int
        and (expected is None or value == expected)
        and (minimum is None or value >= minimum)
    )


def _valid_c3_browser(value: Any) -> bool:
    keys = {
        "engine", "desktop", "mobile", "same_projection",
        "desktop_screenshot_sha256", "mobile_screenshot_sha256",
    }
    return (
        isinstance(value, dict) and set(value) == keys
        and value.get("engine") == "Google Chrome headless via CDP"
        and value.get("desktop") == "1440x900"
        and value.get("mobile") == "390x844"
        and value.get("same_projection") is True
        and all(
            isinstance(value.get(field), str)
            and re.fullmatch(r"[0-9a-f]{64}", value[field]) is not None
            for field in ("desktop_screenshot_sha256", "mobile_screenshot_sha256")
        )
    )


def _valid_c3_actions(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"reply", "deny", "stop", "uncertainty"}:
        return False
    action_keys = {
        "browser_path", "browser_requests", "browser_responses",
        "posts", "replay_side_effects",
    }
    for name in ("reply", "deny", "stop"):
        item = value.get(name)
        if (
            not isinstance(item, dict) or set(item) != action_keys
            or item.get("browser_path") != "visible_control"
            or not all(_exact_int(item.get(field), 1) for field in ("browser_requests", "browser_responses", "posts"))
            or not _exact_int(item.get("replay_side_effects"), 0)
        ):
            return False
    uncertainty = value.get("uncertainty")
    return (
        isinstance(uncertainty, dict)
        and set(uncertainty) == {"status", "posts", "automatic_retries"}
        and uncertainty.get("status") == "OutcomeUnknown"
        and _exact_int(uncertainty.get("posts"), 1)
        and _exact_int(uncertainty.get("automatic_retries"), 0)
    )


def _valid_sqlite_modes(value: Any) -> bool:
    if not isinstance(value, dict) or len(value) != 6 or set(value.values()) != {"0600"}:
        return False
    command_bases = {
        match.group(1)
        for name in value
        if (match := re.fullmatch(r"(command-[0-9a-f]{24}\.sqlite3)(?:-wal|-shm)?", name)) is not None
    }
    if len(command_bases) != 1:
        return False
    command = next(iter(command_bases))
    return set(value) == {
        command, command + "-wal", command + "-shm",
        "gateway.sqlite3", "gateway.sqlite3-wal", "gateway.sqlite3-shm",
    }


def _valid_c3_containment(value: Any) -> bool:
    keys = {
        "fd_10_bootstrap", "fd_11_transport_key", "independent_keys",
        "browser_has_no_uds", "gateway_browser_have_no_upstream_connection",
        "uds_mode", "uds_parent_mode", "sqlite_modes",
    }
    return (
        isinstance(value, dict) and set(value) == keys
        and all(value.get(field) is True for field in (
            "fd_10_bootstrap", "fd_11_transport_key", "independent_keys",
            "browser_has_no_uds", "gateway_browser_have_no_upstream_connection",
        ))
        and value.get("uds_mode") == "0600"
        and value.get("uds_parent_mode") == "0700"
        and _valid_sqlite_modes(value.get("sqlite_modes"))
    )


def _valid_c3_result(result: Any) -> bool:
    required_component_keys = {"marker", "mechanical_e2", "provider_e3", "production_ready", "run_binding", "materialized_product_host", "materialized_gateway", "materialized_web", "fake_boundary", "browser", "actions", "fresh_five_route_reads", "privacy", "containment", "journal", "elapsed_seconds", "cleanup"}
    freshness = result.get("fresh_five_route_reads") if isinstance(result, dict) else None
    journal = result.get("journal") if isinstance(result, dict) else None
    elapsed = result.get("elapsed_seconds") if isinstance(result, dict) else None
    return (
        isinstance(result, dict)
        and set(result) == required_component_keys
        and result.get("marker") == "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS"
        and result.get("mechanical_e2") is True
        and result.get("provider_e3") is False
        and result.get("production_ready") is False
        and isinstance(result.get("run_binding"), str)
        and re.fullmatch(r"[0-9a-f]{64}", result["run_binding"]) is not None
        and result.get("fake_boundary") == "external_loopback_opencode_shape"
        and _valid_c3_browser(result.get("browser"))
        and _valid_c3_actions(result.get("actions"))
        and isinstance(freshness, dict)
        and set(freshness) == {"minimum_per_route"}
        and _exact_int(freshness.get("minimum_per_route"), minimum=5)
        and result.get("cleanup") == {"processes": True, "ports": True, "uds": True, "journal": True, "gateway_db": True, "device_registry": True}
        and all(type(item) is bool for item in result.get("cleanup", {}).values())
        and result.get("materialized_product_host") is True
        and result.get("materialized_gateway") is True
        and result.get("materialized_web") is True
        and result.get("privacy") == {"browser": True, "logs": True, "persistent_sqlite": True, "argv": True}
        and all(type(item) is bool for item in result.get("privacy", {}).values())
        and _valid_c3_containment(result.get("containment"))
        and isinstance(journal, dict)
        and set(journal) == {"mode", "synchronous", "rows"}
        and journal.get("mode") == "wal"
        and journal.get("synchronous") == "FULL"
        and _exact_int(journal.get("rows"), 4)
        and type(elapsed) in {int, float}
        and math.isfinite(elapsed) and elapsed >= 0
    )


def _run_b(
    bundle: Path, bundle_digest: str, qa_driver: Path,
    qa_driver_binding: Mapping[str, str], parent_digest: str,
) -> dict[str, Any]:
    try:
        module = _load_qa_driver(
            qa_driver, qa_driver_binding, bundle, bundle_digest,
        )
    except Exception as error:
        return _stage(
            "B_c3_local", "BLOCK",
            _safe_code(error, "P8H_QA_DRIVER_LOAD_FAILED"),
            error_type=type(error).__name__, parent_evidence_digest=parent_digest,
            qa_driver=dict(qa_driver_binding),
        )
    chrome = getattr(module, "CHROME", None)
    if not isinstance(chrome, Path) or not chrome.is_file():
        return _stage(
            "B_c3_local", "NOT_RUN", "P8G_CHROME_NOT_AVAILABLE",
            parent_evidence_digest=parent_digest,
            qa_driver=dict(qa_driver_binding),
        )
    try:
        result = module.run_smoke(60.0, chrome, bundle)
    except Exception as error:
        candidate = str(error).strip()
        code = candidate if re.fullmatch(r"[A-Z][A-Z0-9_]+", candidate) else "P8G_C3_SMOKE_FAILED"
        return _stage("B_c3_local", "BLOCK", code, error_type=type(error).__name__, error_message=error.args[0] if error.args and isinstance(error.args[0], str) and re.fullmatch(r"[A-Za-z0-9_ .:-]{1,160}", error.args[0]) else None, parent_evidence_digest=parent_digest, qa_driver=dict(qa_driver_binding))
    if not _valid_c3_result(result):
        return _stage("B_c3_local", "BLOCK", "P8G_C3_RESULT_CONTRACT_INVALID", qa_driver=dict(qa_driver_binding))
    return _stage("B_c3_local", "PASS", "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS", result=_c3_projection(result), parent_evidence_digest=parent_digest, qa_driver=dict(qa_driver_binding))


def _config(home: Path, repo: Path) -> Any:
    return SimpleNamespace(repo_root=repo, home=home, relay_port=18089, gateway_port=14173, agent_port=4096,
                           bundle_root=None, join_gateway_port=14174, relay_host_v2_port=18090,
                           relay_device_v2_port=18091, relay_admin_port=18092, relay_device_v1_port=18093)


def _safe_code(error: Exception, fallback: str) -> str:
    candidate = str(error).strip()
    return candidate if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", candidate) else fallback


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _clean_cli_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_process(argv: list[str], cwd: Path, *, timeout: float = 60.0) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        argv, cwd=cwd, env=_clean_cli_environment(), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise RuntimeError("P8H_INSTALLED_CLI_TIMEOUT")
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _installed_json(
    launcher: Path, cwd: Path, arguments: tuple[str, ...], *, expected_exit: int = 0,
) -> dict[str, Any]:
    result = _run_process([str(launcher), "--json", *arguments], cwd)
    if result.returncode != expected_exit:
        try:
            failure = json.loads(result.stdout, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            failure = None
        if (
            isinstance(failure, dict)
            and failure.get("schema") == "nomad.web-companion.error.v1"
            and failure.get("state") == "BLOCKED"
            and failure.get("production_ready") is False
            and isinstance(failure.get("error"), str)
            and re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", failure["error"])
        ):
            raise RuntimeError(failure["error"])
        raise RuntimeError("P8H_INSTALLED_CLI_EXIT_INVALID")
    if result.stderr != b"" or not 0 < len(result.stdout) <= MAX_CLI_OUTPUT_BYTES:
        raise RuntimeError("P8H_INSTALLED_CLI_OUTPUT_INVALID")
    try:
        value = json.loads(result.stdout, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("P8H_INSTALLED_CLI_JSON_INVALID") from error
    if not isinstance(value, dict) or result.stdout != canonical(value):
        raise RuntimeError("P8H_INSTALLED_CLI_NONCANONICAL")
    return value


def _external_gates(value: Any) -> bool:
    return value == [{"code": code, "status": "NOT_RUN"} for code in EXTERNAL_GATES]


def _fixed_external_gates() -> list[dict[str, str]]:
    return [{"code": code, "status": "NOT_RUN"} for code in EXTERNAL_GATES]


def _blocked_result(code: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": "BLOCK",
        "repo_owned_status": "BLOCK",
        "remote_local_evidence_status": "NOT_RUN",
        "external_readiness": "NOT_RUN",
        "provider_e3": {
            "status": "NOT_RUN", "code": "PROVIDER_E3_EVIDENCE_NOT_RUN",
        },
        "classification": "mechanical-local-non-provider",
        "production_ready": False, "code": code,
        "external_gates": _fixed_external_gates(),
        "privacy": {
            "content_free": True, "raw_output_included": False,
            "credential_values_inspected": False,
            "protected_transcript_accessed": False,
        },
    }


def _validate_onboarding(value: Any, installed_digest: str) -> dict[str, Any]:
    state = value.get("state") if isinstance(value, dict) else None
    blockers = value.get("blockers") if isinstance(value, dict) else None
    next_action = value.get("next_action") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict) or set(value) != ONBOARDING_KEYS
        or value.get("schema") != "nomad.web-companion.onboarding.v1"
        or state not in ONBOARDING_STATES
        or state not in {"INSTALLED_NEEDS_START", "INSTALLED_BLOCKED_HOST_IDENTITY"}
        or value.get("production_ready") is not False
        or value.get("external_readiness") != "NOT_RUN"
        or not _external_gates(value.get("external_gates"))
        or value.get("installed_bundle_digest") != installed_digest
        or value.get("install_sequence") != 1
        or any(value.get(field) is not None for field in ("run_identity", "paired_device_commitment", "pairing_epoch"))
        or not isinstance(blockers, list)
        or (state == "INSTALLED_NEEDS_START" and (blockers != [] or next_action != "START_INSTALLED_BUNDLE"))
        or (state == "INSTALLED_BLOCKED_HOST_IDENTITY" and (len(blockers) != 1 or blockers[0] not in HOST_IDENTITY_BLOCKERS or next_action != "AUTHORIZE_HOST_IDENTITY"))
    ):
        raise RuntimeError("P8H_ONBOARDING_SCHEMA_INVALID")
    return value


def _validate_install_status(value: Any, installed_digest: str) -> dict[str, Any]:
    keys = {"schema", "state", "current_bundle_digest", "bundle_digests", "history", "onboarding"}
    if (
        not isinstance(value, dict) or set(value) != keys
        or value.get("schema") != "nomad.web-companion.install-status.v1"
        or value.get("state") != "INSTALLED"
        or value.get("current_bundle_digest") != installed_digest
        or value.get("bundle_digests") != [installed_digest]
        or not isinstance(value.get("history"), list) or len(value["history"]) != 1
    ):
        raise RuntimeError("P8H_INSTALL_STATUS_SCHEMA_INVALID")
    entry = value["history"][0]
    if (
        not isinstance(entry, dict)
        or set(entry) != {"sequence", "operation", "from_bundle_digest", "to_bundle_digest", "state_snapshot_digest", "rollback_of_sequence"}
        or entry != {"sequence": 1, "operation": "install", "from_bundle_digest": None, "to_bundle_digest": installed_digest, "state_snapshot_digest": None, "rollback_of_sequence": None}
    ):
        raise RuntimeError("P8H_INSTALL_STATUS_SCHEMA_INVALID")
    _validate_onboarding(value["onboarding"], installed_digest)
    return value


def _validate_lifecycle_result(value: Any, *, uninstall: bool) -> dict[str, Any]:
    expected = {
        "schema": "nomad.web-companion.uninstall-result.v1" if uninstall else "nomad.web-companion.remote-access-reset.v1",
        "state": "UNINSTALLED" if uninstall else "STOPPED",
        "mode": "foundation-readonly", "remote_access": "CLEARED",
        "install_state": "REMOVED" if uninstall else "PRESERVED",
        "host_identity_disposition": "retained", "production_ready": False,
    }
    if value != expected:
        raise RuntimeError("P8H_UNINSTALL_SCHEMA_INVALID" if uninstall else "P8H_RESET_SCHEMA_INVALID")
    return value


def _verify_installed_diagnostics(bundle: Path, output: Path, cwd: Path) -> str:
    verifier = (
        "import json,sys;from pathlib import Path;"
        "sys.path.insert(0,sys.argv[1]);from nomad_web import diagnostics;"
        "raw=Path(sys.argv[2]).read_bytes();"
        "value=json.loads(raw);diagnostics.verify(value);"
        "assert raw==diagnostics._canonical(value)+b'\\n';"
        "print(value['manifest_digest'])"
    )
    result = _run_process([os.sys.executable, "-I", "-B", "-c", verifier, str(bundle / "lib"), str(output)], cwd)
    digest_value = result.stdout.decode("ascii", errors="ignore").strip()
    if result.returncode != 0 or result.stderr != b"" or re.fullmatch(r"[0-9a-f]{64}", digest_value) is None:
        raise RuntimeError("P8H_DIAGNOSTICS_VERIFY_FAILED")
    return digest_value


def _run_c_install(bundle: Path, home: Path, repo: Path) -> tuple[Path | None, Path | None, list[dict[str, Any]]]:
    from tools.nomad_web import install_lifecycle
    config = _config(home, repo)
    stages: list[dict[str, Any]] = []
    selected: Path | None = None
    stable: Path | None = None
    try:
        installed = install_lifecycle.install(config, bundle)
        installed_digest = installed.get("current_bundle_digest")
        if not isinstance(installed_digest, str) or len(installed_digest) != 64:
            raise RuntimeError("P8G_INSTALL_DIGEST_INVALID")
        selected = (home / "bundles" / installed_digest).resolve(strict=True)
        if selected.parent != (home / "bundles").resolve(strict=True):
            raise RuntimeError("P8G_INSTALL_PATH_INVALID")
        if _bundle_digest(selected) != installed_digest:
            raise RuntimeError("P8G_INSTALLED_BUNDLE_VERIFY_FAILED")
        stable = home / "bin" / "nomad-web"
        stable_info = stable.lstat()
        if (not stat.S_ISREG(stable_info.st_mode) or stat.S_ISLNK(stable_info.st_mode)
                or stable_info.st_uid != os.geteuid() or stat.S_IMODE(stable_info.st_mode) != 0o755):
            raise RuntimeError("P8H_CANONICAL_LAUNCHER_INVALID")
        stages.append(_stage("install", "PASS", "INSTALL_SELECTOR_COMMITTED", bundle_digest=installed_digest))
    except Exception as error:
        stages.append(_stage("install", "BLOCK", _safe_code(error, "P8G_LIFECYCLE_FAILED"), error_type=type(error).__name__))
    return selected, stable, stages


def _run_c_installed_prepare(
    launcher: Path, selected: Path, source: Path, cwd: Path, stages: list[dict[str, Any]],
) -> None:
    installed_digest = selected.name
    try:
        if source.exists():
            raise RuntimeError("P8H_SOURCE_BUNDLE_STILL_AVAILABLE")
        status = _validate_install_status(_installed_json(launcher, cwd, ("install-status",)), installed_digest)
        stages.append(_stage("install-status", "PASS", "INSTALLED_CLI_STATUS_VERIFIED", state=status["state"], bundle_digest=installed_digest, source_bundle_removed=True))
        onboarding = _validate_onboarding(_installed_json(launcher, cwd, ("onboarding",)), installed_digest)
        stages.append(_stage("onboarding", "PASS", "INSTALLED_CLI_ONBOARDING_VERIFIED", state=onboarding["state"], external_readiness="NOT_RUN"))
        missing = _installed_json(
            launcher, cwd, ("start", "--provider", "OPENAI_API_KEY", "--workspace", str(cwd)),
            expected_exit=1,
        )
        if missing != {"schema": "nomad.web-companion.error.v1", "state": "BLOCKED", "error": "AGENT_START_INPUTS_INCOMPLETE", "production_ready": False}:
            raise RuntimeError("P8H_MISSING_PROVIDER_CREDENTIAL_CONTRACT_INVALID")
        stages.append(_stage("missing-provider-credential", "PASS", "AGENT_START_INPUTS_INCOMPLETE", expected_block=True, provider_e3="NOT_RUN"))
    except Exception as error:
        stages.append(_stage("installed-prepare", "BLOCK", _safe_code(error, "P8H_INSTALLED_PREPARE_FAILED"), error_type=type(error).__name__))


def _run_c_cleanup(launcher: Path, selected: Path, home: Path, cwd: Path, root: Path, stages: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        diagnostics_root = root / "diagnostics"
        diagnostics_root.mkdir(mode=0o700)
        os.chmod(diagnostics_root, 0o700)
        diagnostic_path = diagnostics_root / "support.json"
        diagnostic = _installed_json(launcher, cwd, ("diagnostics", "--output", str(diagnostic_path)))
        if diagnostic.get("schema") != "nomad.web-companion.support-diagnostics.v1" or diagnostic.get("classification") != "support-only-not-readiness-evidence" or diagnostic.get("production_ready") is not False or diagnostic.get("readiness_evidence") is not False:
            raise RuntimeError("P8H_DIAGNOSTICS_SCHEMA_INVALID")
        if diagnostic_path.read_bytes() != canonical(diagnostic) or stat.S_IMODE(diagnostic_path.stat().st_mode) != 0o600:
            raise RuntimeError("P8H_DIAGNOSTICS_FILE_INVALID")
        manifest_digest = _verify_installed_diagnostics(selected, diagnostic_path, cwd)
        stages.append(_stage("diagnostics", "PASS", "INSTALLED_DIAGNOSTICS_VERIFIED", classification=diagnostic["classification"], manifest_digest=manifest_digest, production_ready=False))
        reset = _validate_lifecycle_result(_installed_json(launcher, cwd, ("reset-remote-access", "--confirm")), uninstall=False)
        stages.append(_stage("reset", "PASS", "REMOTE_ACCESS_RESET", state=reset["state"], install_state=reset["install_state"]))
        removed = _validate_lifecycle_result(_installed_json(launcher, cwd, ("uninstall", "--confirm")), uninstall=True)
        stages.append(_stage("uninstall", "PASS", "INSTALL_LIFECYCLE_REMOVED", state=removed["state"], install_state=removed["install_state"]))
        if launcher.exists():
            raise RuntimeError("P8H_LAUNCHER_RESIDUE_REMAINS")
    except Exception as error:
        stages.append(_stage("cleanup", "BLOCK", _safe_code(error, "P8G_CLEANUP_FAILED"), error_type=type(error).__name__))
    residue = home.exists()
    stages.append(_stage("residue", "PASS" if not residue else "BLOCK", "NO_OWNED_RESIDUE" if not residue else "OWNED_RESIDUE_REMAINS"))
    status = "PASS" if all(item["status"] == "PASS" for item in stages) else "BLOCK"
    return _stage("C_lifecycle", status, "LIFECYCLE_COMPLETE" if status == "PASS" else "P8G_LIFECYCLE_INCOMPLETE", stages=stages)


def _write_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.absolute()
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory = os.open(parent, directory_flags)
    temporary_name = "." + path.name + "." + uuid.uuid4().hex + ".tmp"
    descriptor: int | None = None
    try:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError("P8G_EVIDENCE_DIRECTORY_UNSAFE")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory)
        raw = canonical(value)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary_name, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(temporary_name, dir_fd=directory)
        os.fsync(directory)
    except FileExistsError as error:
        raise RuntimeError("P8G_EVIDENCE_EXISTS") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def run_journey(bundle: Path, *, repo: Path = ROOT, work_root: Path | None = None, evidence: Path | None = None) -> dict[str, Any]:
    owned, root = _safe_work_root(work_root)
    home = root / "home"
    bundle = bundle.absolute()
    source_bundle_digest = _bundle_digest(bundle)
    parent_digest = digest({"bundle_digest": source_bundle_digest})
    try:
        runtime_cwd = root / "installed-cwd"
        runtime_cwd.mkdir(mode=0o700)
        os.chmod(runtime_cwd, 0o700)
        if runtime_cwd.resolve().is_relative_to(repo.resolve()):
            raise RuntimeError("P8H_INSTALLED_CWD_INSIDE_REPO")
        install_source = root / "install-source"
        shutil.copytree(bundle, install_source, copy_function=shutil.copy2)
        selected_bundle, stable_launcher, lifecycle_stages = _run_c_install(install_source, home, repo)
        qa_driver: Path | None = None
        qa_driver_binding: dict[str, str] | None = None
        if selected_bundle is not None:
            if selected_bundle.name != source_bundle_digest:
                raise RuntimeError("P8H_INSTALLED_BUNDLE_BINDING_INVALID")
            qa_driver, qa_driver_binding = _stage_qa_driver(
                repo / "testkit/browser/c3_local_command_smoke.py",
                root / "qa-driver", selected_bundle, source_bundle_digest,
            )
        shutil.rmtree(install_source)
        if selected_bundle is not None and stable_launcher is not None:
            _run_c_installed_prepare(stable_launcher, selected_bundle, install_source, runtime_cwd, lifecycle_stages)
        b_stage = (_run_b(selected_bundle, source_bundle_digest, qa_driver, qa_driver_binding, parent_digest)
                   if selected_bundle is not None and qa_driver is not None and qa_driver_binding is not None
                   else _stage("B_c3_local", "NOT_RUN", "P8G_INSTALLED_BUNDLE_REQUIRED", parent_evidence_digest=parent_digest))
        a_stage = _run_a(selected_bundle or bundle, root / "a.json", parent_digest)
        c_stage = (_run_c_cleanup(stable_launcher, selected_bundle, home, runtime_cwd, root, lifecycle_stages)
                   if selected_bundle is not None and stable_launcher is not None
                   else _stage("C_lifecycle", "BLOCK", "P8G_LIFECYCLE_INCOMPLETE", stages=lifecycle_stages))
        stages = [b_stage, a_stage, c_stage]
        repo_owned_pass = b_stage["status"] == "PASS" and c_stage["status"] == "PASS"
        result = {"schema": SCHEMA, "status": "PASS" if repo_owned_pass else "BLOCK", "repo_owned_status": "PASS" if repo_owned_pass else "BLOCK", "remote_local_evidence_status": a_stage["status"], "external_readiness": "NOT_RUN", "provider_e3": {"status": "NOT_RUN", "code": "PROVIDER_E3_EVIDENCE_NOT_RUN"}, "classification": "mechanical-local-non-provider", "production_ready": False, "parent_evidence_digest": parent_digest, "bundle_digest": source_bundle_digest, "stages": stages, "external_gates": _fixed_external_gates(), "privacy":{"content_free":True,"raw_output_included":False,"credential_values_inspected":False,"protected_transcript_accessed":False}}
        if evidence is not None:
            _write_atomic(evidence, result)
        return result
    finally:
        if owned is not None:
            owned.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run_journey(args.bundle, work_root=args.work_root, evidence=args.evidence)
    except Exception as error:
        result = _blocked_result(_safe_code(error, "P8G_RUNNER_FAILED"))
        _write_atomic(args.evidence, result)
    print(json.dumps({
        "schema": SCHEMA,
        "status": result["status"],
        "repo_owned_status": result.get("repo_owned_status", result["status"]),
        "remote_local_evidence_status": result.get("remote_local_evidence_status", "NOT_RUN"),
        "external_readiness": "NOT_RUN",
        "production_ready": False,
    }, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
