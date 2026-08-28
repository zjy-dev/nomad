#!/usr/bin/env python3
"""P8-G parent journey over the existing real product subjourneys."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
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
REQUIRED = ("A_real_product", "B_c3_local", "C_lifecycle")


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
        return _stage("A_real_product", "NOT_RUN", "P8G_TLS_CONTROL_INPUT_REQUIRED", parent_evidence_digest=parent_digest)
    try:
        result = module.run_slice(bundle, evidence, False, False, parent_digest, tls_descriptors)
    except Exception as error:
        return _stage("A_real_product", "BLOCK", str(error) if str(error).isupper() else "P8G_M3E_RUN_FAILED", error_type=type(error).__name__)
    if not isinstance(result, dict) or result.get("marker") != "M3E_REAL_PRODUCT_SLICE_PASS" or result.get("production_ready") is not False:
        return _stage("A_real_product", "BLOCK", "P8G_M3E_RESULT_CONTRACT_INVALID", result=_facts_from_result(result))
    return _stage("A_real_product", "PASS", "M3E_REAL_PRODUCT_SLICE_PASS", result=_facts_from_result(result), parent_evidence_digest=parent_digest)


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


def _run_c_prepare(bundle: Path, home: Path, repo: Path) -> tuple[Any, Path | None, list[dict[str, Any]]]:
    from tools.nomad_web import install_lifecycle
    config = _config(home, repo)
    stages: list[dict[str, Any]] = []
    selected: Path | None = None
    try:
        installed = install_lifecycle.install(config, bundle)
        installed_digest = installed.get("current_bundle_digest")
        if not isinstance(installed_digest, str) or len(installed_digest) != 64:
            raise RuntimeError("P8G_INSTALL_DIGEST_INVALID")
        selected = (home / "bundles" / installed_digest).resolve(strict=True)
        if selected.parent != (home / "bundles").resolve(strict=True):
            raise RuntimeError("P8G_INSTALL_PATH_INVALID")
        verified_digest = _bundle_digest(selected)
        if verified_digest != installed_digest:
            raise RuntimeError("P8G_INSTALLED_BUNDLE_VERIFY_FAILED")
        stages.append(_stage("install", "PASS", "INSTALL_SELECTOR_COMMITTED", bundle_digest=installed_digest))
        onboarding = install_lifecycle.onboarding_status(config)
        onboarding_install = onboarding.get("installed", onboarding) if isinstance(onboarding, dict) else {}
        onboarding_digest = onboarding_install.get("installed_bundle_digest", onboarding_install.get("current_bundle_digest")) if isinstance(onboarding_install, dict) else None
        if not isinstance(onboarding_install, dict) or onboarding_digest != installed_digest:
            raise RuntimeError("P8G_ONBOARDING_INSTALL_MISMATCH")
        stages.append(_stage("onboarding", "PASS", "ONBOARDING_CLASSIFIED", state=onboarding.get("state"), external_readiness=onboarding.get("external_readiness")))
        for directory in (home / "bin", home / "run", home / "logs"):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except Exception as error:
        stages.append(_stage("lifecycle", "BLOCK", str(error) if str(error).isupper() else "P8G_LIFECYCLE_FAILED", error_type=type(error).__name__))
    return config, selected, stages


def _run_c_cleanup(config: Any, home: Path, stages: list[dict[str, Any]]) -> dict[str, Any]:
    from tools.nomad_web import diagnostics, launcher
    try:
        diagnostic = diagnostics.collect(config)
        stages.append(_stage("diagnostics", "PASS", "DIAGNOSTICS_COLLECTED", diagnostic_status=diagnostic.get("status"), production_ready=diagnostic.get("production_ready")))
        reset = launcher.reset_remote_access(config)
        stages.append(_stage("reset", "PASS", "REMOTE_ACCESS_RESET", state=reset.get("state")))
        removed = launcher.uninstall_lifecycle(config)
        stages.append(_stage("uninstall", "PASS", "INSTALL_LIFECYCLE_REMOVED", state=removed.get("state")))
    except Exception as error:
        stages.append(_stage("cleanup", "BLOCK", str(error) if str(error).isupper() else "P8G_CLEANUP_FAILED", error_type=type(error).__name__))
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
        config, selected_bundle, lifecycle_stages = _run_c_prepare(bundle, home, repo)
        b_stage = (_run_b(selected_bundle, parent_digest) if selected_bundle is not None
                   else _stage("B_c3_local", "NOT_RUN", "P8G_INSTALLED_BUNDLE_REQUIRED", parent_evidence_digest=parent_digest))
        a_stage = _run_a(selected_bundle or bundle, root / "a.json", parent_digest)
        c_stage = _run_c_cleanup(config, home, lifecycle_stages)
        stages = [b_stage, a_stage, c_stage]
        repo_owned_pass = b_stage["status"] == "PASS" and c_stage["status"] == "PASS"
        result = {"schema": SCHEMA, "status": "PASS" if repo_owned_pass else "BLOCK", "repo_owned_status": "PASS" if repo_owned_pass else "BLOCK", "external_readiness": a_stage["status"], "classification": "mechanical-local-non-provider", "production_ready": False, "parent_evidence_digest": parent_digest, "bundle_digest": source_bundle_digest, "stages": stages, "external_gates":[{"code": code, "status":"NOT_RUN"} for code in EXTERNAL_GATES], "privacy":{"content_free":True,"raw_output_included":False,"credential_values_inspected":False,"protected_transcript_accessed":False}}
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
        result = {"schema": SCHEMA, "status":"BLOCK", "classification":"mechanical-local-non-provider", "production_ready":False, "code":str(error) if str(error).isupper() else "P8G_RUNNER_FAILED", "privacy":{"content_free":True,"protected_transcript_accessed":False}}
        _write_atomic(args.evidence, result)
    print(json.dumps({
        "schema": SCHEMA,
        "status": result["status"],
        "repo_owned_status": result.get("repo_owned_status", result["status"]),
        "external_readiness": result.get("external_readiness", "NOT_RUN"),
        "production_ready": False,
    }, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
