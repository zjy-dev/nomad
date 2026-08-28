from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Sequence

from .config import Config
from .doctor import run_doctor
from .launcher import HostIdentityError, authorize_host_identity, restart_foundation, start_foundation, status_foundation, stop_foundation, uninstall_foundation
from .materialize import materialize


def run(argv: Sequence[str] | None = None, repo_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomad-web")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("command", choices=("doctor", "start", "restart", "status", "stop", "uninstall", "materialize", "authorize-host-identity"))
    parser.add_argument("--output", type=Path)
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
        return 0 if args.command != "doctor" or result["foundation_ready"] else 2
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


def _emit(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"State: {result.get('state', 'READY')}")
        print(f"Mode: {result.get('mode', result.get('classification', 'nomad-web'))}")
        if result.get("web_url") or result.get("desktop_url"):
            print(f"Web: {result.get('web_url', result.get('desktop_url'))}")
        if result.get("logs_dir"):
            print(f"Logs: {result['logs_dir']}")
        for field in ("missing_tools", "missing_paths", "occupied_ports", "blocked_on"):
            if result.get(field):
                print(f"{field}: {', '.join(result[field])}")
        if result.get("next_step"):
            print(f"Next: {result['next_step']}")
