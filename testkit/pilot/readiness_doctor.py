#!/usr/bin/env python3
"""Read-only Phase 4 readiness doctor.

This command inspects fixed paths and environment *names* only.  It never reads
Provider values, starts a product process, contacts OpenCode, or mutates state.
Its output is diagnostic readiness, never production authorization.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[2]
STOCK = ROOT / "testkit" / "stock-opencode"
REAL_TASK = STOCK / "real-task"
ALLOWED_PROVIDER_ENV_NAMES = (
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY",
)
FIXED_VERIFIERS = {
    "certificate_verifier": STOCK / "verify_certificate.py",
    "shape_verifier": STOCK / "verify_shape_manifest.py",
    "evidence_verifier": STOCK / "verify_evidence_manifest.py",
    "command_shape_tool": STOCK / "real_task_capture.py",
}
FIXED_ARTIFACTS = {
    "lifecycle_certificate": REAL_TASK / "lifecycle-certificate.json",
    "lifecycle_certificate_tmp": REAL_TASK / "lifecycle-certificate.json.tmp",
    "lifecycle_shape_manifest": REAL_TASK / "lifecycle-shape-manifest.json",
    "lifecycle_shape_manifest_tmp": REAL_TASK / "lifecycle-shape-manifest.json.tmp",
    "lifecycle_evidence_manifest": STOCK / "lifecycle-evidence-manifest.json",
    "lifecycle_evidence_manifest_tmp": STOCK / "lifecycle-evidence-manifest.json.tmp",
}
FIXED_DIRS = {"stock_opencode": STOCK, "real_task": REAL_TASK}
SUPERVISOR_CANDIDATES = (
    ROOT / "connector" / "target" / "release" / "nomad-supervisor",
    ROOT / "connector" / "target" / "debug" / "nomad-supervisor",
)
EXTERNAL_OWNER_GATES = (
    ("developer_id_host", "EXTERNAL_OWNER_REQUIRED"),
    ("sshsig_trust_and_krl", "EXTERNAL_OWNER_REQUIRED"),
    ("protected_cas_publication", "EXTERNAL_OWNER_REQUIRED"),
)


@dataclass(frozen=True)
class Gate:
    name: str
    state: str
    code: str


def _owner_mode(path: Path, *, directory: bool) -> Gate:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return Gate(path.name, "MISSING", "MISSING_FIXED_PATH")
    except OSError:
        return Gate(path.name, "INVALID", "INVALID_FIXED_PATH")
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return Gate(path.name, "INVALID", "INVALID_TYPE_OWNER_MODE")
    return Gate(path.name, "AVAILABLE", "AVAILABLE_FIXED_PATH")


def _artifact(path: Path) -> Gate:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if path.name.endswith(".tmp"):
            return Gate(path.name, "AVAILABLE", "AVAILABLE_STAGING_SLOT")
        return Gate(path.name, "MISSING", "MISSING_REAL_EVIDENCE")
    except OSError:
        return Gate(path.name, "INVALID", "INVALID_FIXED_ARTIFACT")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return Gate(path.name, "INVALID", "INVALID_TYPE_OWNER_MODE")
    if path.name.endswith(".tmp"):
        return Gate(path.name, "INVALID", "BLOCKED_STAGED_ARTIFACT_PRESENT")
    return Gate(path.name, "INVALID", "BLOCKED_REAL_EVIDENCE_ALREADY_PRESENT")


def _verifier(path: Path) -> Gate:
    gate = _owner_mode(path, directory=False)
    if gate.state != "AVAILABLE":
        return Gate(path.name, gate.state, "MISSING_VERIFIER" if gate.state == "MISSING" else "INVALID_VERIFIER")
    return Gate(path.name, "AVAILABLE", "AVAILABLE_FIXED_VERIFIER")


def _provider_names(environment: Mapping[str, str]) -> Gate:
    # Inspect key membership only. Credential bytes, including whether a value
    # is empty, belong to the later single-use capture boundary.
    present = [name for name in ALLOWED_PROVIDER_ENV_NAMES if name in environment]
    if len(present) == 1:
        return Gate("provider_credential_name", "AVAILABLE", "AVAILABLE_ALLOWLISTED_NAME")
    if len(present) > 1:
        return Gate("provider_credential_name", "INVALID", "MULTIPLE_ALLOWLISTED_NAMES")
    return Gate("provider_credential_name", "MISSING", "MISSING_ALLOWLISTED_NAME")


def _supervisor_gate() -> Gate:
    # The doctor deliberately does not execute this binary.  Production N0 is
    # externally blocked and must remain zero-spawn until trust inputs exist.
    return Gate("default_nomad_supervisor", "EXTERNAL_OWNER_REQUIRED", "BLOCKED_NATIVE_SUPERVISOR_AUTHORITY_UNAVAILABLE")


def _external_owner_gates() -> list[Gate]:
    return [Gate(name, state, "EXTERNAL_OWNER_REQUIRED") for name, state in EXTERNAL_OWNER_GATES]


def inspect(*, environment: Mapping[str, str] | None = None) -> dict[str, object]:
    env = os.environ if environment is None else environment
    provider_gate = _provider_names(env)
    directory_gates = [_owner_mode(path, directory=True) for path in FIXED_DIRS.values()]
    artifact_gates = [_artifact(path) for path in FIXED_ARTIFACTS.values()]
    verifier_gates = [_verifier(path) for path in FIXED_VERIFIERS.values()]
    gates: list[Gate] = [provider_gate, *directory_gates, *artifact_gates, *verifier_gates]
    gates.extend(_external_owner_gates())
    gates.append(_supervisor_gate())
    # This is deliberately an operator preflight result, not production
    # authorization.  Real evidence and external-owner gates are reported
    # separately and can never turn this result into production readiness.
    artifact_ready = all(
        gate.code
        == ("AVAILABLE_STAGING_SLOT" if path.name.endswith(".tmp") else "MISSING_REAL_EVIDENCE")
        for path, gate in zip(FIXED_ARTIFACTS.values(), artifact_gates, strict=True)
    )
    local_ready = (
        provider_gate.state == "AVAILABLE"
        and all(gate.state == "AVAILABLE" for gate in directory_gates)
        and all(gate.state == "AVAILABLE" for gate in verifier_gates)
        and artifact_ready
    )
    overall = "READY_FOR_OPERATOR_PREFLIGHT" if local_ready else "BLOCKED_EXTERNAL_OR_LOCAL_GATE"
    return {"schema": "nomad.phase4.readiness-doctor.v1", "overall": overall, "gates": [asdict(g) for g in gates]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit canonical content-free JSON")
    args = parser.parse_args()
    result = inspect()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["overall"] == "READY_FOR_OPERATOR_PREFLIGHT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
