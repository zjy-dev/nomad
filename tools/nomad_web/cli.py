from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from typing import Any, Sequence

from .bundle import verify_bundle
from .config import Config
from .doctor import run_doctor
from .evidence_resume import resume_blocked_evidence
from .install_lifecycle import install, rollback, upgrade
from .launcher import HostIdentityError, authorize_host_identity, restart_foundation, start_foundation, status_foundation, stop_foundation, uninstall_foundation
from .materialize import materialize
from .release_verify import collect_git_facts, verify_record


def run(argv: Sequence[str] | None = None, repo_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomad-web")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "command",
        choices=(
            "doctor", "start", "restart", "status", "stop",
            "uninstall", "materialize", "authorize-host-identity",
            "install", "upgrade", "rollback", "resume-evidence",
            "verify-release",
        ),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--from", dest="from_path", type=Path)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--keep-runtime", action="store_true")
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
    args = parser.parse_args(argv)
    try:
        config = Config.load(repo_root)
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
        handlers = {
            "doctor": run_doctor,
            "status": status_foundation,
            "stop": stop_foundation,
            "uninstall": uninstall_foundation,
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
            "error": str(error) if str(error).isupper() else "LAUNCHER_FAILURE",
            "production_ready": False,
        }
        if isinstance(error, HostIdentityError) and error.next_step is not None:
            result["next_step"] = error.next_step
        _emit(result, True)
        return 1


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
        state = result["state"] if "state" in result else result.get("status", "READY")
        print(f"State: {state}")
        print(f"Mode: {result.get('mode', result.get('classification', 'nomad-web'))}")
        if "code" in result:
            print(f"Code: {result['code']}")
        if "mechanical_checks_passed" in result:
            print(f"Mechanical checks passed: {str(result['mechanical_checks_passed']).lower()}")
        if "production_ready" in result:
            print(f"Production ready: {str(result['production_ready']).lower()}")
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
