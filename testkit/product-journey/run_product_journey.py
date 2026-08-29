#!/usr/bin/env python3
"""P8-G parent journey over the existing real product subjourneys."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
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
    module = _load(ROOT / "testkit/remote-v2/run_m3e_product_slice.py", "p8g_m3e")
    if tls_descriptors is None:
        return _stage("A_remote_local_evidence", "NOT_RUN", "P8G_TLS_CONTROL_INPUT_REQUIRED", parent_evidence_digest=parent_digest)
    try:
        result = module.run_slice(bundle, evidence, False, False, parent_digest, tls_descriptors)
    except Exception as error:
        return _stage("A_remote_local_evidence", "BLOCK", str(error) if str(error).isupper() else "P8G_M3E_RUN_FAILED", error_type=type(error).__name__)
    if not isinstance(result, dict) or result.get("marker") != "M3E_REAL_PRODUCT_SLICE_PASS" or result.get("production_ready") is not False:
        return _stage("A_remote_local_evidence", "BLOCK", "P8G_M3E_RESULT_CONTRACT_INVALID", result=_facts_from_result(result))
    return _stage("A_remote_local_evidence", "PASS", "M3E_REAL_PRODUCT_SLICE_PASS", result=_facts_from_result(result), parent_evidence_digest=parent_digest)


def _run_b(bundle: Path, parent_digest: str) -> dict[str, Any]:
    module = _load(ROOT / "testkit/browser/c3_local_command_smoke.py", "p8g_c3")
    chrome = getattr(module, "CHROME", None)
    if not isinstance(chrome, Path) or not chrome.is_file():
        return _stage("B_c3_local", "NOT_RUN", "P8G_CHROME_NOT_AVAILABLE", parent_evidence_digest=parent_digest)
    try:
        result = module.run_smoke(60.0, chrome, bundle)
    except Exception as error:
        candidate = str(error).strip()
        code = candidate if re.fullmatch(r"[A-Z][A-Z0-9_]+", candidate) else "P8G_C3_SMOKE_FAILED"
        return _stage("B_c3_local", "BLOCK", code, error_type=type(error).__name__, error_message=error.args[0] if error.args and isinstance(error.args[0], str) and re.fullmatch(r"[A-Za-z0-9_ .:-]{1,160}", error.args[0]) else None, parent_evidence_digest=parent_digest)
    required_actions = {"reply", "deny", "stop", "uncertainty"}
    required_component_keys = {"marker", "mechanical_e2", "provider_e3", "production_ready", "run_binding", "materialized_product_host", "materialized_gateway", "materialized_web", "fake_boundary", "browser", "actions", "fresh_five_route_reads", "privacy", "containment", "journal", "elapsed_seconds", "cleanup"}
    valid = (
        isinstance(result, dict)
        and set(result) == required_component_keys
        and result.get("marker") == "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS"
        and result.get("mechanical_e2") is True
        and result.get("provider_e3") is False
        and result.get("production_ready") is False
        and isinstance(result.get("actions"), dict)
        and set(result["actions"]) == required_actions
        and result["actions"]["uncertainty"].get("status") == "OutcomeUnknown"
        and result["actions"]["uncertainty"].get("posts") == 1
        and result["actions"]["uncertainty"].get("automatic_retries") == 0
        and all(result["actions"][name].get("browser_path") == "visible_control" for name in ("reply", "deny", "stop"))
        and all(result["actions"][name].get("browser_requests") == 1 for name in ("reply", "deny", "stop"))
        and all(result["actions"][name].get("browser_responses") == 1 for name in ("reply", "deny", "stop"))
        and all(result["actions"][name].get("posts") == 1 for name in ("reply", "deny", "stop"))
        and all(result["actions"][name].get("replay_side_effects") == 0 for name in ("reply", "deny", "stop"))
        and result.get("cleanup") == {"processes": True, "ports": True, "uds": True, "journal": True, "gateway_db": True, "device_registry": True}
        and result.get("materialized_product_host") is True and result.get("materialized_gateway") is True and result.get("materialized_web") is True
        and result.get("privacy") == {"browser": True, "logs": True, "persistent_sqlite": True, "argv": True}
        and result.get("journal", {}).get("mode") == "wal" and result.get("journal", {}).get("synchronous") == "FULL"
    )
    if not valid:
        return _stage("B_c3_local", "BLOCK", "P8G_C3_RESULT_CONTRACT_INVALID")
    return _stage("B_c3_local", "PASS", "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS", result=_c3_projection(result), parent_evidence_digest=parent_digest)


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
        shutil.rmtree(install_source)
        if selected_bundle is not None and stable_launcher is not None:
            _run_c_installed_prepare(stable_launcher, selected_bundle, install_source, runtime_cwd, lifecycle_stages)
        b_stage = (_run_b(selected_bundle, parent_digest) if selected_bundle is not None
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
