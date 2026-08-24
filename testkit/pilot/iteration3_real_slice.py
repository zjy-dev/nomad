#!/usr/bin/env python3
"""Controlled, disposable acceptance model for the Iteration 3 real slice.

This is deliberately not an adapter for the existing fake OpenCode or Relay
test bridge.  Lane B supplies the ``LaneBRealSliceDriver`` implementation that
starts Host, Relay, Gateway, and Mobile and returns content-free checkpoints.
Until then this module only plans or blocks a run.

Provider credentials are read only to establish their presence.  They are never
included in a command, result, exception, or evidence bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

if __package__ in (None, ""):
    # Direct CLI execution otherwise has only testkit/pilot on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from testkit.iteration3_receipts import (
    ReceiptVerificationError,
    VerifiedReceiptSet,
    receipt_digest,
    verify_receipt_store,
)

PINNED_OPENCODE_PACKAGE = "opencode-ai@1.18.16"
PINNED_OPENCODE_VERSION = "1.18.16"
REQUIRED_CHECKPOINTS = (
    "host_ready",
    "relay_ready",
    "gateway_ready",
    "mobile_ready",
    "question_observed",
    "permission_observed",
    "diff_observed",
    "question_reply_host_accepted",
    "question_reply_upstream_executed",
    "permission_deny_host_accepted",
    "permission_deny_upstream_executed",
    "stop_host_accepted",
    "stop_upstream_executed",
    "reconnect_reconciled",
    "workspace_cleaned",
)
_SECRET_ENV_NAME = re.compile(r"(?:TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)", re.IGNORECASE)
_VERSION_TOKEN = re.compile(r"(?<![0-9.])(\d+\.\d+\.\d+)(?![0-9.])")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_MAX_VERSION_OUTPUT_BYTES = 4096
_VERSION_TIMEOUT_SECONDS = 5.0


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    SKIP = "SKIP"


@dataclass(frozen=True)
class BinaryProvenance:
    package: str
    version_output: str
    sha256: str
    verification_method: str


@dataclass(frozen=True)
class CandidateAttestation:
    """Unverified diagnostic claims from a future Lane B integration.

    These fields are not evidence and cannot open the M1 acceptance gate.  M2
    must add a harness-owned verifier that reads a content-free receipt store,
    recomputes digests, and verifies process binding before a PASS path exists.
    """

    run_id: str
    source_kind: str
    real_provider_task: bool
    disposable_workspace: bool
    checkpoint_claims: Mapping[str, bool]


@dataclass(frozen=True)
class SliceResult:
    outcome: Outcome
    reason_codes: tuple[str, ...]
    evidence: Mapping[str, Any]


class LaneBFutureDriver(Protocol):
    """M2 integration shape only; it is not a verifier or acceptance source."""

    def run(
        self, *, run_id: str, workspace: Path, opencode_command: Sequence[str], provider_credential_env: str
    ) -> CandidateAttestation:
        """Return diagnostic claims only; never return raw DTOs or user content."""


def redact(value: Any) -> Any:
    """Remove values and secret-looking keys before an object becomes evidence."""
    if isinstance(value, Mapping):
        return {str(key): "[REDACTED]" if _SECRET_ENV_NAME.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return "[REDACTED]"
    return value


def provider_credential_available(env_name: str, environment: Mapping[str, str] | None = None) -> bool:
    if not env_name or _SECRET_ENV_NAME.search(env_name) is None:
        return False
    value = (environment or os.environ).get(env_name)
    return isinstance(value, str) and bool(value.strip())


def build_opencode_command(npx: str = "npx") -> list[str]:
    """Build the official pinned package invocation; no credential is an argument."""
    return [npx, "--yes", PINNED_OPENCODE_PACKAGE, "serve", "--hostname", "127.0.0.1"]


def verify_official_binary(binary: Path, *, package: str = PINNED_OPENCODE_PACKAGE) -> BinaryProvenance:
    """Verify a materialized official release binary before a real run."""
    if package != PINNED_OPENCODE_PACKAGE:
        raise ValueError("ERR_UNPINNED_OPENCODE_PACKAGE")
    if not binary.is_file():
        raise ValueError("ERR_OPENCODE_BINARY_MISSING")
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=_VERSION_TIMEOUT_SECONDS,
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("ERR_OPENCODE_VERSION_TIMEOUT") from error
    output = completed.stdout[:_MAX_VERSION_OUTPUT_BYTES].decode("utf-8", errors="replace")
    if len(completed.stdout) > _MAX_VERSION_OUTPUT_BYTES:
        raise ValueError("ERR_OPENCODE_VERSION_OUTPUT_TOO_LARGE")
    if completed.returncode != 0:
        raise ValueError("ERR_OPENCODE_VERSION_COMMAND_FAILED")
    if _VERSION_TOKEN.findall(output) != [PINNED_OPENCODE_VERSION]:
        raise ValueError("ERR_OPENCODE_VERSION_MISMATCH")
    return BinaryProvenance(
        package=package, version_output=PINNED_OPENCODE_VERSION,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), verification_method="executed_binary",
    )


def assess_real_slice(
    *,
    credential_available: bool,
    provenance: BinaryProvenance | None,
    candidate: CandidateAttestation | None,
    expected_run_id: str,
    receipt_store: Path | None = None,
    dry_run: bool = False,
) -> SliceResult:
    """Classify M1 diagnostics fail-closed; PASS is intentionally unreachable."""
    if dry_run:
        return SliceResult(Outcome.SKIP, ("SKIP_DRY_RUN",), {"real_provider_task": False})
    provenance_failures: list[str] = []
    if provenance is not None:
        if provenance.package != PINNED_OPENCODE_PACKAGE:
            provenance_failures.append("FAIL_BINARY_PROVENANCE_PACKAGE")
        if provenance.version_output != PINNED_OPENCODE_VERSION:
            provenance_failures.append("FAIL_BINARY_PROVENANCE_VERSION")
        if not _SHA256.fullmatch(provenance.sha256):
            provenance_failures.append("FAIL_BINARY_PROVENANCE_HASH")
        if provenance.verification_method != "executed_binary":
            provenance_failures.append("FAIL_BINARY_PROVENANCE_METHOD")
    if provenance_failures:
        return SliceResult(Outcome.FAIL, tuple(provenance_failures), {"real_provider_task": False})
    blockers: list[str] = []
    if not credential_available:
        blockers.append("BLOCKED_PROVIDER_CREDENTIAL_ABSENT")
    if provenance is None:
        blockers.append("BLOCKED_OFFICIAL_BINARY_UNVERIFIED")
    if candidate is None and receipt_store is None:
        blockers.append("BLOCKED_LANE_B_DRIVER_UNAVAILABLE")
    if blockers:
        return SliceResult(Outcome.BLOCKED, tuple(blockers), {"real_provider_task": False})

    if receipt_store is not None:
        try:
            verified = verify_receipt_store(receipt_store, expected_run_id=expected_run_id)
        except ReceiptVerificationError as error:
            return SliceResult(Outcome.FAIL, (str(error),), {"real_provider_task": False})
        # The receipt parser can establish only receipt integrity.  The product
        # still needs a non-forgeable live WP1/WP3 binding before M2 may pass.
        return SliceResult(
            Outcome.BLOCKED,
            ("BLOCKED_REAL_RECEIPT_INTEGRATION_UNAVAILABLE",),
            {"receipt_count": verified.receipt_count, "checkpoint_count": len(verified.checkpoint_stages)},
        )

    assert candidate is not None
    failures: list[str] = []
    if candidate.source_kind != "official_stock_runtime":
        failures.append("FAIL_NON_OFFICIAL_SOURCE")
    if candidate.run_id != expected_run_id:
        failures.append("FAIL_RUN_ID_MISMATCH")
    if not candidate.real_provider_task:
        failures.append("FAIL_NOT_REAL_PROVIDER_TASK")
    if not candidate.disposable_workspace:
        failures.append("FAIL_WORKSPACE_NOT_DISPOSABLE")
    failures.extend(
        f"FAIL_CHECKPOINT_{name.upper()}"
        for name in REQUIRED_CHECKPOINTS
        if candidate.checkpoint_claims.get(name) is not True
    )
    safe_evidence = {
        "official_package": provenance.package,
        "opencode_version": provenance.version_output,
        "binary_sha256": provenance.sha256,
        "verification_method": provenance.verification_method,
        "run_id": candidate.run_id,
        "source_kind": candidate.source_kind,
        "real_provider_task_claimed": candidate.real_provider_task,
        "disposable_workspace_claimed": candidate.disposable_workspace,
        "checkpoint_claims": {name: candidate.checkpoint_claims.get(name) is True for name in REQUIRED_CHECKPOINTS},
    }
    if failures:
        return SliceResult(Outcome.FAIL, tuple(failures), safe_evidence)
    return SliceResult(Outcome.BLOCKED, ("BLOCKED_VERIFIER_UNAVAILABLE",), safe_evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-credential-env", required=True, help="Name only; a secret-looking environment variable.")
    parser.add_argument("--dry-run", action="store_true", help="Plan only; always reports SKIP.")
    args = parser.parse_args()
    run_id = secrets.token_urlsafe(32)
    # No driver is linked in this scaffold.  Deliberately do not inspect or print its value.
    try:
        result = assess_real_slice(
            credential_available=provider_credential_available(args.provider_credential_env),
            provenance=None,
            candidate=None,
            expected_run_id=run_id,
            dry_run=args.dry_run,
        )
    except Exception:
        result = SliceResult(Outcome.FAIL, ("ERR_REAL_SLICE_INTERNAL",), {"real_provider_task": False})
    print(json.dumps(asdict(result), default=lambda item: item.value if isinstance(item, Enum) else item, sort_keys=True))
    return 0 if result.outcome in (Outcome.PASS, Outcome.SKIP) else 1


if __name__ == "__main__":
    raise SystemExit(main())
