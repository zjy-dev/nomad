from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Sequence

from .bundle import verify_bundle
from .config import Config
from .diagnostics import export as export_diagnostics
from .doctor import run_doctor
from .evidence_resume import resume_blocked_evidence
from .install_lifecycle import (
    ONBOARDING_STATES, install, onboarding_status, rollback,
    status as install_status, upgrade,
)
from .launcher import (
    HostIdentityError, authorize_host_identity, reset_remote_access,
    restart_foundation, start_foundation, status_foundation, stop_foundation,
    uninstall_lifecycle,
)
from .materialize import materialize
from .release_verify import collect_git_facts, verify_record


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise RuntimeError("CLI_ARGUMENT_INVALID")


def run(argv: Sequence[str] | None = None, repo_root: Path | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in arguments
    parser = _ArgumentParser(prog="nomad-web")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "command",
        choices=(
            "doctor", "start", "restart", "status", "stop",
            "uninstall", "materialize", "authorize-host-identity",
            "install", "upgrade", "rollback", "resume-evidence",
            "verify-release", "install-status", "onboarding",
            "diagnostics", "reset-remote-access",
        ),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--from", dest="from_path", type=Path)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--keep-runtime", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--tls-ca", type=Path)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--provider")
    parser.add_argument("--credential-stdin", action="store_true")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--remote-local-evidence", action="store_true")
    parser.add_argument("--public-origin")
    parser.add_argument("--https-listen")
    parser.add_argument("--tls-cert-fd", type=int)
    parser.add_argument("--tls-key-fd", type=int)
    try:
        args = parser.parse_args(arguments)
        config = Config.load(repo_root)
        if args.command == "install-status":
            result = install_status(config)
            if result.get("state") not in {"INSTALLED", "NOT_INSTALLED"}:
                raise RuntimeError("INVALID_COMMAND_STATUS")
            _emit(result, args.json)
            return 0
        if args.command == "onboarding":
            result = onboarding_status(config)
            state = result.get("state")
            if state not in ONBOARDING_STATES:
                raise RuntimeError("INVALID_COMMAND_STATUS")
            _emit(result, args.json)
            return 2 if state == "RUNNING_DEGRADED_RECOVERY_REQUIRED" else 0
        if args.command == "diagnostics":
            if args.output is None:
                raise RuntimeError("DIAGNOSTICS_OUTPUT_REQUIRED")
            result = export_diagnostics(config, args.output)
            _emit(result, args.json)
            return 0
        if args.command == "reset-remote-access":
            if not args.confirm:
                raise RuntimeError("RESET_CONFIRMATION_REQUIRED")
            result = reset_remote_access(config)
            _emit(result, args.json)
            return 0
        if args.command == "materialize":
            if args.output is None:
                raise RuntimeError("MATERIALIZE_OUTPUT_REQUIRED")
            result = materialize(config.repo_root, args.output)
            _emit(result, args.json)
            return 0
        if args.command in ("install", "upgrade"):
            if args.bundle is None:
                raise RuntimeError("INSTALL_BUNDLE_REQUIRED")
            handler = install if args.command == "install" else upgrade
            result = handler(config, args.bundle)
            _emit(result, args.json)
            return 0
        if args.command == "rollback":
            result = rollback(config)
            _emit(result, args.json)
            return 0
        if args.command == "resume-evidence":
            if args.from_path is None or args.bundle is None or args.output is None:
                raise RuntimeError("RESUME_EVIDENCE_INPUTS_REQUIRED")
            if args.tls_ca is None or args.tls_cert is None or args.tls_key is None:
                raise RuntimeError("RESUME_TLS_INPUTS_REQUIRED")
            runner_args = ("--keep-runtime",) if args.keep_runtime else ()
            descriptors: list[int] = []
            try:
                descriptors.append(_open_tls_input(args.tls_ca, private=False))
                descriptors.append(_open_tls_input(args.tls_cert, private=False))
                descriptors.append(_open_tls_input(args.tls_key, private=True))
                result = resume_blocked_evidence(
                    args.from_path, args.bundle, args.output, runner_args,
                    tls_ca_fd=descriptors[0], tls_cert_fd=descriptors[1],
                    tls_key_fd=descriptors[2],
                )
            finally:
                for descriptor in reversed(descriptors):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            _emit(result, args.json)
            return _status_exit(result.get("status"))
        if args.command == "verify-release":
            if args.record is None:
                raise RuntimeError("RELEASE_RECORD_REQUIRED")
            record = _read_release_record(args.record)
            if config.bundle_root is not None:
                manifest = verify_bundle(Path(config.bundle_root))
                source_commit = manifest["source_commit_oid"]
                dirty = manifest["source_dirty"]
            else:
                facts = collect_git_facts(config.repo_root)
                source_commit = facts["source_commit"]
                dirty = facts["dirty"]
            verdict = verify_record(
                record, actual_source_commit=str(source_commit), dirty=bool(dirty)
            )
            result = {
                "status": verdict.status,
                "code": verdict.code,
                "mechanical_checks_passed": verdict.mechanical_checks_passed,
                "production_ready": verdict.production_ready,
            }
            _emit(result, args.json)
            return _status_exit(verdict.status)
        if args.command == "authorize-host-identity":
            result = authorize_host_identity(config)
            _emit(result, args.json)
            return 0
        if args.command in ("start", "restart"):
            remote_inputs = (args.public_origin, args.https_listen, args.tls_cert_fd, args.tls_key_fd)
            if any(value is not None for value in remote_inputs) and not args.remote_local_evidence:
                raise RuntimeError("REMOTE_MODE_REQUIRED")
            if args.remote_local_evidence and not all(value is not None for value in remote_inputs):
                raise RuntimeError("REMOTE_START_INPUTS_INCOMPLETE")
            if args.provider or args.credential_stdin or args.workspace is not None or args.remote_local_evidence:
                if not args.provider or not args.credential_stdin or args.workspace is None:
                    raise RuntimeError("AGENT_START_INPUTS_INCOMPLETE")
                descriptor = os.dup(0)
                try:
                    handler = restart_foundation if args.command == "restart" else start_foundation
                    result = handler(
                        config, provider_name=args.provider, credential_fd=descriptor, workspace=args.workspace,
                        remote_local_evidence=args.remote_local_evidence, public_origin=args.public_origin,
                        https_listen=args.https_listen, tls_cert_fd=args.tls_cert_fd, tls_key_fd=args.tls_key_fd,
                    )
                finally:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            else:
                result = restart_foundation(config) if args.command == "restart" else start_foundation(config)
            _emit(result, args.json)
            return 0
        if args.command == "uninstall" and not args.confirm:
            raise RuntimeError("UNINSTALL_CONFIRMATION_REQUIRED")
        handlers = {
            "doctor": run_doctor,
            "status": status_foundation,
            "stop": stop_foundation,
            "uninstall": uninstall_lifecycle,
        }
        result = handlers[args.command](config)
        _emit(result, args.json)
        if args.command == "doctor":
            return _status_exit(result.get("release_readiness"))
        return 0
    except Exception as error:
        result = {
            "schema": "nomad.web-companion.error.v1",
            "state": "BLOCKED",
            "error": _error_code(error),
            "production_ready": False,
        }
        if (
            isinstance(error, HostIdentityError)
            and error.next_step == "nomad-web authorize-host-identity"
        ):
            result["next_step"] = error.next_step
        _emit(result, as_json)
        return 1


MAX_ERROR_CODE_LENGTH = 96
KNOWN_ERROR_CODES = frozenset("""
AGENT_BUILD_NPM_VERSION_MISMATCH AGENT_ENTRYPOINT_MISMATCH
AGENT_ENTRYPOINT_UNSAFE AGENT_HEALTH_TIMEOUT AGENT_LOCK_INPUT_MISMATCH
AGENT_LOOPBACK_PORT_UNAVAILABLE AGENT_LOOPBACK_URL_INVALID
AGENT_PROCESS_STOP_FAILED AGENT_PROVENANCE_MISMATCH AGENT_PROVENANCE_UNAVAILABLE
AGENT_RUNTIME_UNVERIFIED AGENT_START_FAILED AGENT_START_INPUTS_INCOMPLETE
BUILD_FAILED
BUNDLE_DIGEST_MISMATCH BUNDLE_FILE_MISMATCH BUNDLE_FILE_SET_MISMATCH
BUNDLE_FILE_TOO_LARGE BUNDLE_NONREGULAR_FORBIDDEN BUNDLE_OUTPUT_EXISTS
BUNDLE_SNAPSHOT_DIGEST_MISMATCH BUNDLE_SNAPSHOT_FILE_POLICY_INVALID
BUNDLE_SNAPSHOT_IMMUTABLE_FAILED BUNDLE_SNAPSHOT_MANIFEST_INVALID
BUNDLE_SNAPSHOT_MANIFEST_MISMATCH BUNDLE_SNAPSHOT_MISMATCH
BUNDLE_SNAPSHOT_ROOT_INVALID BUNDLE_SNAPSHOT_SOURCE_CHANGED
BUNDLE_SNAPSHOT_SOURCE_UNAVAILABLE BUNDLE_SNAPSHOT_VERIFICATION_FAILED
BUNDLE_SNAPSHOT_WRITE_FAILED BUNDLE_SOURCE_CHANGED BUNDLE_SYMLINK_FORBIDDEN
BUNDLE_VERIFICATION_FAILED CLI_ARGUMENT_INVALID COMMAND_KEY_WRITE_FAILED
CONFIG_AGENT_PORT_MISSING CONFIG_GATEWAY_PORT_MISSING CONFIG_HOME_MISSING
CONFIG_RELAY_PORT_MISSING CONFIG_REPO_ROOT_MISSING DEGRADED_RECONCILE_FAILED
DEVICE_REGISTRY_DIRECTORY_NOT_EMPTY DEVICE_REGISTRY_MISSING
DESKTOP_GATEWAY_NOT_READY
DIAGNOSTICS_BUNDLE_METADATA_INVALID DIAGNOSTICS_CANONICAL_RECONSTRUCTION_MISMATCH
DIAGNOSTICS_CLASSIFICATION_INVALID DIAGNOSTICS_CROSS_BINDING_INVALID
DIAGNOSTICS_INPUT_STATE_INVALID DIAGNOSTICS_INSTALL_STATE_INVALID
DIAGNOSTICS_LOG_CHANGED DIAGNOSTICS_LOG_FILE_POLICY_INVALID
DIAGNOSTICS_LOG_METADATA_INVALID DIAGNOSTICS_LOG_NOT_OWNED
DIAGNOSTICS_MANIFEST_DIGEST_INVALID DIAGNOSTICS_MANIFEST_DIGEST_MISMATCH
DIAGNOSTICS_ONBOARDING_INVALID DIAGNOSTICS_OUTPUT_DIRECTORY_CHANGED
DIAGNOSTICS_OUTPUT_DIRECTORY_INVALID DIAGNOSTICS_OUTPUT_EXISTS
DIAGNOSTICS_OUTPUT_PUBLICATION_FAILED DIAGNOSTICS_OUTPUT_REQUIRED
DIAGNOSTICS_OUTPUT_ROLLBACK_FAILED DIAGNOSTICS_OUTPUT_TOO_LARGE
DIAGNOSTICS_OUTPUT_WRITE_FAILED DIAGNOSTICS_PRIVACY_POLICY_FAILED
DIAGNOSTICS_PROCESS_RECORD_INVALID DIAGNOSTICS_PROTECTED_TRANSCRIPT_FORBIDDEN
DIAGNOSTICS_RECOVERY_INVALID DIAGNOSTICS_RUNTIME_STATE_INVALID
DIAGNOSTICS_SCHEMA_INVALID DIAGNOSTIC_EVIDENCE_FORBIDDEN
DUPLICATE_LOOPBACK_PORT DUPLICATE_RUNTIME_PORT EVIDENCE_CLASSIFICATION_INVALID
EVIDENCE_FILE_CHANGED EVIDENCE_FILE_POLICY_INVALID EVIDENCE_JSON_INVALID
EVIDENCE_NOT_CANONICAL EVIDENCE_OUTPUT_CONFLICT EVIDENCE_OUTPUT_EXISTS
EVIDENCE_OUTPUT_UNAVAILABLE EVIDENCE_SCHEMA_INVALID EXPLICIT_BUNDLE_CURRENT_CONFLICT
EXACTLY_ONE_PROVIDER_CREDENTIAL_REQUIRED FD_SECRET_WRITE_FAILED
GATEWAY_DYNAMIC_IMPORT_FORBIDDEN GATEWAY_EXTERNAL_DEPENDENCY
GATEWAY_IMPORT_SYNTAX GATEWAY_JAVASCRIPT_LEX_ERROR
GATEWAY_MODULE_ALLOWLIST_MISMATCH GATEWAY_MODULE_MISSING
GATEWAY_ROUTE_TABLE_INVALID HOST_BOOTSTRAP_INVALID
HOST_IDENTITY_AUTHORIZATION_FAILED HOST_IDENTITY_AUTHORIZATION_INVALID
HOST_IDENTITY_AUTHORIZATION_REQUIRES_STOP HOST_IDENTITY_AUTHORIZATION_TIMEOUT
HOST_IDENTITY_AUTH_REQUIRED HOST_IDENTITY_CORRUPT HOST_IDENTITY_KEYCHAIN_LOCKED
HOST_IDENTITY_PREFLIGHT_FAILED HOST_IDENTITY_PREFLIGHT_INVALID
HOST_IDENTITY_PREFLIGHT_TIMEOUT HOST_IDENTITY_UNAVAILABLE HOST_IDENTITY_USER_DENIED
HOST_READY_IDENTITY_MISMATCH HOST_READY_INVALID HTTPS_LISTEN_RELEASE_TIMEOUT
INGRESS_NEGATIVE_ROUTE_ACCEPTED INGRESS_PROCESS_NOT_OWNED INGRESS_READY_INVALID
INGRESS_SOURCE_UNAVAILABLE INGRESS_TLS_PROBE_FAILED INSTALLED_BUNDLE_DIGEST_MISMATCH
INSTALLED_BUNDLE_FILE_MISMATCH INSTALLED_BUNDLE_FILE_SET_MISMATCH
INSTALLED_LAUNCHER_INPUT_TOO_LARGE INSTALL_ALREADY_PRESENT_USE_UPGRADE
INSTALL_BUNDLE_REQUIRED INSTALL_HISTORY_TOO_LARGE INSTALL_IDENTITY_INVALID
INSTALL_LIFECYCLE_REQUIRES_STOP INSTALL_NOT_PRESENT
INSTALL_SELECTOR_INITIALIZATION_REQUIRES_STOP INVALID_AGENT_RUNTIME
INVALID_BUNDLE_DIGEST INVALID_BUNDLE_MANIFEST INVALID_BUNDLE_MODE
INVALID_BUNDLE_PATH INVALID_BUNDLE_SNAPSHOT INVALID_COMMAND_KEY
INVALID_COMMAND_STATUS INVALID_FD_SECRET INVALID_INHERITED_FD
INVALID_GATEWAY_MODULE_PATH INVALID_GATEWAY_PACKAGE INVALID_INSTALLED_BUNDLE
INVALID_INSTALL_CURRENT INVALID_INSTALL_HISTORY INVALID_NOMAD_WEB_AGENT_PORT
INVALID_NOMAD_WEB_GATEWAY_PORT INVALID_NOMAD_WEB_JOIN_GATEWAY_PORT
INVALID_NOMAD_WEB_RELAY_ADMIN_PORT INVALID_NOMAD_WEB_RELAY_DEVICE_V1_PORT
INVALID_NOMAD_WEB_RELAY_DEVICE_V2_PORT INVALID_NOMAD_WEB_RELAY_HOST_V2_PORT
INVALID_NOMAD_WEB_RELAY_PORT INVALID_ONBOARDING_STATE INVALID_RELEASE_GATE_STATUS
INVALID_PROVIDER_CREDENTIAL INVALID_RUN_ALIAS INVALID_STATE INVALID_STATE_SNAPSHOT
JOIN_GATEWAY_NOT_READY LAUNCHER_FAILURE LISTENER_PROCESS_BINDING_NOT_VERIFIED
LIFECYCLE_CHANNEL_CLOSED LIFECYCLE_COMMIT_MISMATCH
LIFECYCLE_COORDINATOR_IDENTITY_UNAVAILABLE LIFECYCLE_COORDINATOR_START_FAILED
LIFECYCLE_COORDINATOR_START_TIMEOUT LIFECYCLE_GATEWAY_BINDING_MISMATCH
LIFECYCLE_HOME_COMMITMENT_INVALID LIFECYCLE_JOURNAL_INVALID
LIFECYCLE_JOURNAL_STATE_INVALID LIFECYCLE_JOURNAL_TOO_LARGE
LIFECYCLE_JOURNAL_WRITE_FAILED LIFECYCLE_LOCK_ADOPTION_INVALID
LIFECYCLE_LOCK_ALREADY_ADOPTED LIFECYCLE_LOCK_HOME_MISMATCH
LIFECYCLE_LOCK_MARKER_CHANGED LIFECYCLE_MESSAGE_DUPLICATE_KEY
LIFECYCLE_MESSAGE_INVALID LIFECYCLE_MESSAGE_NONCANONICAL
LIFECYCLE_OPERATION_INVALID LIFECYCLE_OPERATION_IN_PROGRESS
LIFECYCLE_OPERATION_NOT_COMMITTED LIFECYCLE_PROCESS_BINDING_INVALID
LIFECYCLE_PROCESS_BINDING_MISMATCH LIFECYCLE_REQUEST_ID_CONFLICT
LIFECYCLE_REQUEST_NOT_ACCEPTED LIFECYCLE_RESET_POSTCONDITION_FAILED
LIFECYCLE_RESULT_INVALID LIFECYCLE_RUNTIME_BINDING_MISMATCH
LIFECYCLE_UNINSTALL_POSTCONDITION_FAILED LIFECYCLE_WORKER_ARGUMENTS_INVALID
LIFECYCLE_WORKER_BOOTSTRAP_INVALID
LIFECYCLE_WORKLOAD_STILL_PRESENT
LIVE_PROBE_HTTP_FRAMING_INVALID LIVE_PROBE_HTTP_SCHEMA_INVALID
LIVE_PROBE_HTTP_STATUS_INVALID LIVE_PROBE_RESPONSE_TOO_LARGE
LIVE_PROBE_TRANSPORT_FAILED LOOPBACK_PORT_IN_USE LOOPBACK_PORT_RELEASE_TIMEOUT
MATERIALIZE_OUTPUT_REQUIRED MODE_CHANGE_REQUIRES_STOP NODE_UNAVAILABLE
NOMAD_WEB_HOME_MUST_BE_ABSOLUTE NONCANONICAL_BUNDLE_MANIFEST
OFFICIAL_SESSION_NOT_READY PAIRED_DEVICE_IDENTITY_SCHEMA_MISMATCH
PAIRED_DEVICE_IDENTITY_UNAVAILABLE PARENT_BLOCKER_NOT_RESUMABLE
PARENT_BUNDLE_BINDING_INVALID PARENT_BUNDLE_MISMATCH PARENT_EVIDENCE_UNAVAILABLE
PARENT_LINEAGE_INVALID PARENT_PASS_MARKER_FORBIDDEN PARENT_STATUS_NOT_BLOCK
PERSISTENT_STATE_CHANGED PREBUILT_AGENT_RUNTIME_REQUIRED PREBUILT_BUNDLE_REQUIRED
PRIVATE_FILE_TOO_LARGE PROCESS_IDENTITY_MISMATCH PROCESS_STOP_FAILED
PROCESS_EXECUTABLE_UNAVAILABLE PROCESS_IDENTITY_UNAVAILABLE
PRODUCT_HOST_PAIRING_LIVE_PROBE_FAILED PRODUCT_HOST_SOCKET_ALREADY_EXISTS
PRODUCT_HOST_SOCKET_DIRECTORY_NOT_EMPTY PRODUCT_HOST_SOCKET_IDENTITY_MISMATCH
PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED PYTHON_EXECUTABLE_NOT_ABSOLUTE
PYTHON_EXECUTABLE_UNAVAILABLE REFUSE_UNOWNED_STAGE_REMOVAL
RELAY_ADMIN_ROLE_SCHEMA_INVALID RELAY_ROLE_INVALID RELAY_ROLE_LIVE_PROBE_FAILED
RELAY_ROLE_TIMEOUT RELAY_V1_HEALTH_SCHEMA_INVALID RELAY_V1_STATE_MISSING
RELEASE_RECORD_INVALID RELEASE_RECORD_REQUIRED REMOTE_HTTPS_LISTEN_INVALID
REMOTE_HTTPS_LISTEN_IN_USE REMOTE_KEY_COLLISION REMOTE_MODE_REQUIRED
REMOTE_PORT_INVALID REMOTE_PUBLIC_ORIGIN_INVALID REMOTE_START_INPUTS_INCOMPLETE
REMOTE_TLS_CERT_FD_INVALID REMOTE_TLS_CERT_INVALID REMOTE_TLS_KEY_FD_INVALID
REMOTE_UNINSTALL_REVOKE_REQUIRED RESET_CONFIRMATION_REQUIRED
RESUME_EVIDENCE_INPUTS_REQUIRED RESUME_LINEAGE_MISMATCH RESUME_OUTPUT_INVALID
RESUME_RUNNER_FAILED RESUME_TLS_INPUTS_REQUIRED RUNNER_ARGUMENT_FORBIDDEN
RUNNER_CLOSURE_MANIFEST_INVALID RUNNER_SOURCE_MISMATCH RUNNER_STAGING_FAILED
RUNNING_BUNDLE_BINDING_MISMATCH RUNNING_IDENTITY_MISMATCH RUNTIME_PORT_IN_USE
RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED RUNTIME_STATE_PORT_BINDING_INVALID
SELECTED_BUNDLE_BINDING_INVALID
SERVICE_TIMEOUT SESSION_CREATE_INVALID SESSION_CREATE_REJECTED SHORT_WRITE
STATE_FILE_TOO_LARGE STATE_SNAPSHOT_FILE_SET_MISMATCH STATE_SNAPSHOT_MISMATCH
STATE_SNAPSHOT_TOO_LARGE TLS_FD_INVALID TLS_INPUT_FILE_POLICY_INVALID
TLS_INPUT_OPEN_FAILED UNINSTALL_CONFIRMATION_REQUIRED UNOWNED_NOMAD_WEB_HOME
UNSAFE_BUNDLE_FILE UNSAFE_BUNDLE_ROOT UNSAFE_BUNDLE_STAGING UNSAFE_BUNDLE_STORE
UNSAFE_AGENT_DIRECTORY
UNSAFE_COMMAND_JOURNAL UNSAFE_DEVICE_REGISTRY UNSAFE_DEVICE_REGISTRY_DIRECTORY
UNSAFE_GATEWAY_STATE UNSAFE_HOME_MARKER UNSAFE_INSTALLED_BUNDLE
UNSAFE_INSTALLED_LAUNCHER_INPUT UNSAFE_INSTALL_DIRECTORY UNSAFE_LAUNCHER_DIRECTORY
UNSAFE_NOMAD_WEB_HOME UNSAFE_NOMAD_WEB_HOME_CONTENTS
UNSAFE_PERSISTENT_STATE_DIRECTORY UNSAFE_PRIVATE_FILE UNSAFE_PRODUCT_HOST_SOCKET
UNSAFE_PRODUCT_HOST_SOCKET_DIRECTORY UNSAFE_PYTHON_EXECUTABLE
UNSAFE_PYTHON_EXECUTABLE_ANCESTOR UNSAFE_RELAY_V1_STATE
UNSAFE_REMOTE_STATE UNSAFE_REMOTE_STATE_DIRECTORY UNSAFE_STATE_FILE
UNSAFE_STATE_SNAPSHOT UNSAFE_UNINSTALL_ROOT UNSAFE_LIFECYCLE_JOURNAL_FILE
UNSAFE_LIFECYCLE_JOURNAL_MARKER UNSAFE_LIFECYCLE_JOURNAL_ROOT
UNSUPPORTED_ATOMIC_RENAME_PLATFORM
UNSUPPORTED_BUNDLE_PLATFORM
""".split())
_ONBOARDING_NEXT = {
    "INSTALL_VERIFIED_BUNDLE": "Install Nomad from the release download.",
    "AUTHORIZE_HOST_IDENTITY": "Approve Nomad for this Mac when prompted.",
    "START_INSTALLED_BUNDLE": "Start the installed Nomad release.",
    "RECOVER_RUNNING_IDENTITY": "Collect diagnostics and repair the running installation.",
    "PAIR_PHONE": "Start remote access and pair your phone.",
    "START_OFFICIAL_AGENT": "Start Nomad with the official agent.",
    "USE_INSTALLED_CANDIDATE": "Continue with the installed Nomad release.",
}


def _error_code(error: Exception) -> str:
    value = str(error)
    if len(value) <= MAX_ERROR_CODE_LENGTH and value in KNOWN_ERROR_CODES:
        return value
    return "LAUNCHER_FAILURE"


def _status_exit(status: object) -> int:
    if status == "PASS":
        return 0
    if status in {"BLOCK", "BLOCKED", "NOT_RUN"}:
        return 2
    raise RuntimeError("INVALID_COMMAND_STATUS")


def _read_release_record(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("RELEASE_RECORD_INVALID") from error


def _open_tls_input(path: Path, *, private: bool) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("TLS_INPUT_OPEN_FAILED") from error
    try:
        info = os.fstat(descriptor)
        mode = stat.S_IMODE(info.st_mode)
        invalid = not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        if private:
            invalid = invalid or info.st_uid != os.geteuid() or mode != 0o600
        else:
            invalid = invalid or bool(mode & 0o022)
        if invalid:
            raise RuntimeError("TLS_INPUT_FILE_POLICY_INVALID")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _emit(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        diagnostics = result.get("schema") == "nomad.web-companion.support-diagnostics.v1"
        state = (
            result["state"] if "state" in result
            else result.get("status", "EXPORTED" if diagnostics else "READY")
        )
        print(f"State: {state}")
        print(f"Mode: {result.get('mode', result.get('classification', 'nomad-web'))}")
        if "error" in result:
            print(f"Error: {result['error']}")
        if "code" in result:
            print(f"Code: {result['code']}")
        if "mechanical_checks_passed" in result:
            print(f"Mechanical checks passed: {str(result['mechanical_checks_passed']).lower()}")
        if "production_ready" in result:
            print(f"Production ready: {str(result['production_ready']).lower()}")
        if "readiness_evidence" in result:
            print(f"Readiness evidence: {str(result['readiness_evidence']).lower()}")
        onboarding = result.get("onboarding")
        if isinstance(onboarding, dict):
            print(f"Onboarding: {onboarding.get('state', 'UNKNOWN')}")
            _emit_onboarding(onboarding, include_readiness=True)
        elif result.get("schema") == "nomad.web-companion.onboarding.v1":
            _emit_onboarding(result, include_readiness=False)
        for field, label in (
            ("remote_access", "Remote access"),
            ("install_state", "Install state"),
            ("host_identity_disposition", "Host identity"),
        ):
            if field in result:
                print(f"{label}: {result[field]}")
        if "release_readiness" in result:
            print(f"Release readiness: {result['release_readiness']}")
            print("Release blockers:")
            for blocker in result.get("release_blockers", []):
                print(f"- {blocker['gate']}: {blocker['code']}")
            if result.get("release_next_step"):
                print(f"Release next step: {result['release_next_step']}")
        if result.get("web_url") or result.get("desktop_url"):
            print(f"Web: {result.get('web_url', result.get('desktop_url'))}")
        if result.get("logs_dir"):
            print(f"Logs: {result['logs_dir']}")
        for field in ("missing_tools", "missing_paths", "occupied_ports", "blocked_on"):
            if result.get(field):
                print(f"{field}: {', '.join(result[field])}")
        if "release_readiness" not in result and result.get("next_step"):
            print(f"Next: {result['next_step']}")


def _emit_onboarding(result: dict[str, Any], *, include_readiness: bool) -> None:
    if include_readiness and "production_ready" in result:
        print(f"Production ready: {str(result['production_ready']).lower()}")
    if "external_readiness" in result:
        print(f"External readiness: {result['external_readiness']}")
    if result.get("blockers"):
        print(f"Blockers: {', '.join(result['blockers'])}")
    next_action = _ONBOARDING_NEXT.get(result.get("next_action"))
    if next_action is not None:
        print(f"Next: {next_action}")
