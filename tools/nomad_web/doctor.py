"""Read-only foundation and product release readiness checks.

The legacy foundation fields are intentionally retained.  Release gates are a
stricter, content-free view: they never inspect credential values, authorize a
Host identity, start a product process, or turn local/mechanical evidence into
production readiness.
"""

from __future__ import annotations

import ipaddress
import http.client
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping

from . import processes, state
from .bundle import verify_bundle
from .config import Config, HOST_IDENTITY_ROOT_ENV, host_identity_root
from .install_lifecycle import status as install_status
from .recovery import RECOVERY_SCHEMA, decorate_gate, recovery_actions

PROVIDERS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
)
RUNTIME_PORT_FIELDS = (
    "relay_port",
    "gateway_port",
    "agent_port",
    "join_gateway_port",
    "relay_host_v2_port",
    "relay_device_v2_port",
    "relay_admin_port",
    "relay_device_v1_port",
)
LEGACY_PORT_NAMES = {
    "relay": "relay_port",
    "gateway": "gateway_port",
    "agent": "agent_port",
}
REMOTE_PROCESS_NAMES = {
    "relay-host", "relay-device", "opencode", "product-host",
    "desktop-gateway", "join-gateway", "https-ingress",
}
REMOTE_ARTIFACT_PATHS = {
    "relay-host": "bin/nomad-relay",
    "relay-device": "bin/nomad-relay",
    "opencode": "agent/opencode",
    "product-host": "bin/nomad-product-host",
    "desktop-gateway": "gateway/server.mjs",
    "join-gateway": "gateway/server.mjs",
    "https-ingress": "bin/nomad-ingress",
}
NATIVE_ARTIFACT_ROLES = {"relay-host", "relay-device", "opencode", "product-host", "https-ingress"}
LISTENER_ROLE_FIELDS = {
    "relay_port": "relay-host",
    "relay_host_v2_port": "relay-host",
    "relay_admin_port": "relay-host",
    "relay_device_v1_port": "relay-device",
    "relay_device_v2_port": "relay-device",
    "gateway_port": "desktop-gateway",
    "join_gateway_port": "join-gateway",
    "agent_port": "opencode",
}
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
HOST_IDENTITY_TIMEOUT_SECONDS = 5.0
LIVE_PROBE_TIMEOUT_SECONDS = 1.0
MAX_LIVE_PROBE_BYTES = 4096
PRODUCT_HOST_PAIRING_PATH = "/internal/pairing/joins"
PRODUCT_HOST_PAIRING_PROBE_BODY = b'{"schema":"nomad.m3e.pairing.create.v1"}'
RELAY_ADMIN_PATH = "/v2/admin/mailboxes/provision"
RELAY_PROBE_BEARER = "nomad-readiness-doctor-public-probe"
HOST_IDENTITY_RESULTS = {
    "READY": (0, None),
    "AUTH_REQUIRED": (1, "HOST_IDENTITY_AUTH_REQUIRED"),
    "USER_DENIED": (1, "HOST_IDENTITY_USER_DENIED"),
    "KEYCHAIN_LOCKED": (1, "HOST_IDENTITY_KEYCHAIN_LOCKED"),
    "CORRUPT": (1, "HOST_IDENTITY_CORRUPT"),
    "UNAVAILABLE": (1, "HOST_IDENTITY_UNAVAILABLE"),
}
_IPV4 = re.compile(rb"(?:^|\s)inet\s+([0-9]+(?:\.[0-9]+){3})(?:\s|$)")
_IPV6 = re.compile(rb"(?:^|\s)inet6\s+([0-9A-Fa-f:]+)(?:%[^\s]+)?(?:\s|$)")


def run_doctor(
    config: Config, *, environment: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Return legacy foundation checks plus conservative release gates.

    ``environment`` exists for name-only testing.  Membership is the only
    operation performed on it; Provider values are never fetched.
    """

    env = os.environ if environment is None else environment
    bundle_mode = config.bundle_root is not None
    tool_names = ("python3", "node") if bundle_mode else ("python3", "go", "cargo", "node", "npm")
    tools = {name: shutil.which(name) is not None for name in tool_names}

    bundle_manifest: dict[str, Any] | None = None
    bundle_verified = False
    if bundle_mode:
        try:
            bundle_manifest = verify_bundle(Path(config.bundle_root))
            bundle_verified = True
        except Exception:
            # Verification failures are deliberately collapsed to a stable,
            # content-free code below.  Paths and exception strings may leak
            # machine-specific information.
            bundle_manifest = None
        paths = {"prebuilt_bundle": bundle_verified}
    else:
        paths = {
            "relay_source": (config.repo_root / "relay" / "cmd" / "relay").is_dir(),
            "gateway_entry": (config.repo_root / "mobile-reference" / "pilot-gateway" / "server.mjs").is_file(),
            "mobile_package": (config.repo_root / "mobile-reference" / "package.json").is_file(),
        }

    runtime_ports = {name: _free(int(getattr(config, name))) for name in RUNTIME_PORT_FIELDS}
    # Keep the original three-name foundation surface byte-for-byte compatible
    # in shape and meaning.  The release gate below covers all eight ports.
    ports = {name: runtime_ports[field] for name, field in LEGACY_PORT_NAMES.items()}
    provider_names = [name for name in PROVIDERS if name in env]
    foundation_ready = all(tools.values()) and all(paths.values()) and all(ports.values())
    missing_tools = [name for name, present in tools.items() if not present]
    missing_paths = [name for name, present in paths.items() if not present]
    occupied_ports = [name for name, available in ports.items() if not available]

    run_state, state_error = _read_runtime_state(config)
    bundle_binding_gate, bound_bundle = _runtime_bundle_binding_gate(
        config, run_state, state_error, bundle_manifest, bundle_verified,
    )
    process_gate, pairing_gate, relay_gate = _runtime_live_gates(
        config, run_state, state_error, bound_bundle, bundle_binding_gate,
    )
    network = _network_address_presence()
    release_gates = [
        _bundle_verify_gate(bundle_mode, bundle_verified),
        _bundle_digest_gate(bundle_mode, bundle_manifest),
        _host_identity_gate(
            Path(config.bundle_root),
            config=config,
            scope="local-installed",
        ) if bundle_verified else _gate(
            "host_identity", "NOT_RUN", "HOST_IDENTITY_NOT_RUN_NO_VERIFIED_BUNDLE",
            "verify the release bundle before checking Host identity",
            {"status": "NOT_RUN"},
        ),
        _runtime_ports_gate(runtime_ports, run_state, process_gate, state_error),
        _network_gate(network),
        _chrome_gate(),
        _tls_inputs_gate(run_state, state_error),
        _normal_trust_gate(),
        _provider_gate(provider_names),
        bundle_binding_gate,
        process_gate,
        pairing_gate,
        relay_gate,
        _external_gate(
            "physical_phone_safari", "PHYSICAL_PHONE_SAFARI_NOT_RUN",
            "run the accepted journey on a physical iPhone in normal Safari",
        ),
        _external_gate(
            "clean_machine_install", "CLEAN_MACHINE_INSTALL_NOT_RUN",
            "repeat the accepted journey from the exact artifact on a fresh Apple Silicon Mac",
        ),
        _external_gate(
            "developer_id_signing", "DEVELOPER_ID_SIGNING_NOT_RUN",
            "verify Developer ID signing for the exact release artifact",
        ),
        _external_gate(
            "notarization", "APPLE_NOTARIZATION_NOT_RUN",
            "verify notarization, stapling, and Gatekeeper for the exact release artifact",
        ),
        _external_gate(
            "publication_provenance", "PUBLICATION_PROVENANCE_NOT_RUN",
            "verify protected publication and downloaded-artifact digest parity",
        ),
    ]
    release_gates = [decorate_gate(gate) for gate in release_gates]
    release_blockers = [
        {
            "gate": gate["name"], "code": gate["code"],
            "recovery_code": gate["recovery_code"],
            "category": gate["category"], "scope": gate["scope"],
            "next_step": gate["next_step"],
        }
        for gate in release_gates
        if gate["status"] != "PASS"
    ]
    recoveries = recovery_actions(release_gates)
    release_readiness = (
        "BLOCK" if any(gate["status"] == "BLOCK" for gate in release_gates)
        else "NOT_RUN" if any(gate["status"] == "NOT_RUN" for gate in release_gates)
        else "PASS"
    )

    return {
        "schema": "nomad.web-companion.doctor.v1",
        "classification": "repo-local-foundation-not-production-authority",
        "runtime_mode": "prebuilt-bundle" if bundle_mode else "source-build",
        "foundation_ready": foundation_ready,
        "real_agent_enabled": False,
        "blocked_on": ["B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY"],
        "tools": tools,
        "paths": paths,
        "ports": ports,
        "provider_env_name_count": len(provider_names),
        "provider_env_names": provider_names,
        "missing_tools": missing_tools,
        "missing_paths": missing_paths,
        "occupied_ports": occupied_ports,
        "next_step": "nomad-web start" if foundation_ready else "repair failed preflight checks and rerun doctor",
        "release_schema": "nomad.web-companion.release-readiness.v1",
        "recovery_schema": RECOVERY_SCHEMA,
        "release_readiness": release_readiness,
        "release_gates": release_gates,
        "release_blockers": release_blockers,
        "recovery_actions": recoveries,
        "release_next_step": recoveries[0]["next_step"] if recoveries else None,
        # External-owner gates above are deliberately not satisfiable by this
        # local doctor, so this remains false even when every local gate passes.
        "production_ready": False,
    }


def _gate(
    name: str, status: str, code: str, next_step: str | None,
    observations: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    if status not in {"PASS", "BLOCK", "NOT_RUN"}:
        raise ValueError("INVALID_RELEASE_GATE_STATUS")
    return {
        "name": name,
        "status": status,
        "code": code,
        "next_step": next_step,
        "observations": dict(observations or {}),
    }


def _bundle_verify_gate(bundle_mode: bool, verified: bool) -> dict[str, Any]:
    if not bundle_mode:
        return _gate(
            "bundle_verify", "BLOCK", "RELEASE_BUNDLE_REQUIRED",
            "set NOMAD_WEB_BUNDLE to the exact release candidate and rerun doctor",
            {"configured": False, "verified": False},
        )
    if not verified:
        return _gate(
            "bundle_verify", "BLOCK", "RELEASE_BUNDLE_VERIFY_FAILED",
            "replace or repair the release bundle and rerun doctor",
            {"configured": True, "verified": False},
        )
    return _gate(
        "bundle_verify", "PASS", "RELEASE_BUNDLE_VERIFIED", None,
        {"configured": True, "verified": True},
    )


def _bundle_digest_gate(bundle_mode: bool, manifest: Mapping[str, Any] | None) -> dict[str, Any]:
    digest = manifest.get("bundle_digest") if manifest is not None else None
    if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None:
        return _gate(
            "bundle_digest", "PASS", "RELEASE_BUNDLE_DIGEST_VERIFIED", None,
            {"bundle_digest": digest},
        )
    return _gate(
        "bundle_digest", "NOT_RUN", "RELEASE_BUNDLE_DIGEST_NOT_VERIFIED",
        ("configure the exact release bundle and rerun doctor" if not bundle_mode
         else "repair bundle verification before checking its digest"),
        {"bundle_digest": None},
    )


def _host_identity_gate(bundle: Path, *, config: object | None = None, scope: str = "keychain") -> dict[str, Any]:
    binary = bundle / "bin" / "nomad-product-host"
    try:
        result = subprocess.run(
            [str(binary), "identity-preflight", "--non-interactive", f"--scope={scope}"],
            cwd=bundle,
            env={
                "LANG": "C", "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                **({HOST_IDENTITY_ROOT_ENV: str(host_identity_root(config))} if config is not None and scope == "local-installed" else {}),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=HOST_IDENTITY_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _gate(
            "host_identity", "BLOCK", "HOST_IDENTITY_PREFLIGHT_TIMEOUT",
            "rerun doctor after resolving the Host identity preflight timeout",
            {"status": "UNAVAILABLE"},
        )
    except OSError:
        return _gate(
            "host_identity", "BLOCK", "HOST_IDENTITY_PREFLIGHT_FAILED",
            "replace or repair the release bundle and rerun doctor",
            {"status": "UNAVAILABLE"},
        )

    for status, (returncode, blocker) in HOST_IDENTITY_RESULTS.items():
        if (
            result.returncode == returncode
            and result.stderr == b""
            and result.stdout == f'{{"status":"{status}"}}\n'.encode("ascii")
        ):
            if blocker is None:
                return _gate(
                    "host_identity", "PASS", "HOST_IDENTITY_READY", None,
                    {"status": status},
                )
            next_steps = {
                "AUTH_REQUIRED": "nomad-web authorize-host-identity",
                "USER_DENIED": "nomad-web authorize-host-identity",
                "KEYCHAIN_LOCKED": "unlock the login Keychain and rerun doctor",
                "CORRUPT": "repair the Host identity and rerun doctor",
                "UNAVAILABLE": "verify macOS Keychain availability and rerun doctor",
            }
            return _gate(
                "host_identity", "BLOCK", blocker, next_steps[status],
                {"status": status},
            )
    return _gate(
        "host_identity", "BLOCK", "HOST_IDENTITY_PREFLIGHT_INVALID",
        "replace or repair the release bundle and rerun doctor",
        {"status": "INVALID"},
    )


def _read_runtime_state(config: Config) -> tuple[dict[str, Any] | None, bool]:
    try:
        return state.read_run_state(config), False
    except Exception:
        return None, True


class _LiveProbeError(RuntimeError):
    pass


def _runtime_bundle_binding_gate(
    config: Config, run_state: Mapping[str, Any] | None, state_error: bool,
    configured_manifest: Mapping[str, Any] | None, configured_verified: bool,
) -> tuple[dict[str, Any], Path | None]:
    if state_error:
        return _gate(
            "runtime_bundle_binding", "BLOCK", "RUNTIME_STATE_INVALID",
            "repair the invalid runtime state before checking artifact binding",
        ), None
    if run_state is None:
        return _gate(
            "runtime_bundle_binding", "NOT_RUN", "RUNTIME_BUNDLE_BINDING_NOT_RUN",
            "start the exact release candidate before checking artifact binding",
        ), None

    state_digest = run_state.get("bundle_digest")
    if state_digest is None:
        if run_state.get("mode") == "foundation-readonly" and configured_manifest is None:
            return _gate(
                "runtime_bundle_binding", "NOT_RUN", "SOURCE_BUILD_RUNTIME_NOT_RELEASE_ARTIFACT",
                "install and start the exact release bundle before checking artifact binding",
                {"state_bundle_digest": None},
            ), None
        return _gate(
            "runtime_bundle_binding", "BLOCK", "RUNTIME_BUNDLE_DIGEST_MISSING",
            "stop and restart from the current verified release bundle",
        ), None
    if not isinstance(state_digest, str) or re.fullmatch(r"[0-9a-f]{64}", state_digest) is None:
        return _gate(
            "runtime_bundle_binding", "BLOCK", "RUNTIME_BUNDLE_DIGEST_INVALID",
            "stop and restart from the current verified release bundle",
        ), None
    if getattr(config, "bundle_root", None) is not None and not configured_verified:
        return _gate(
            "runtime_bundle_binding", "BLOCK", "CONFIGURED_BUNDLE_VERIFY_FAILED",
            "repair the configured release bundle and restart the release candidate",
        ), None

    try:
        selected = install_status(config)
        current_digest = selected.get("current_bundle_digest")
        bundle = (Path(config.home).resolve(strict=True) / "bundles" / state_digest).resolve(strict=True)
        manifest = verify_bundle(bundle)
    except Exception:
        return _gate(
            "runtime_bundle_binding", "BLOCK", "CURRENT_BUNDLE_VERIFY_FAILED",
            "repair the installed current bundle and restart the release candidate",
        ), None

    configured_digest = configured_manifest.get("bundle_digest") if configured_verified and configured_manifest else None
    configured_matches = configured_digest in (None, state_digest)
    if (
        selected.get("state") != "INSTALLED" or current_digest != state_digest
        or manifest.get("bundle_digest") != state_digest or bundle.name != state_digest
        or not configured_matches
    ):
        return _gate(
            "runtime_bundle_binding", "BLOCK", "CURRENT_BUNDLE_DIGEST_MISMATCH",
            "stop and restart from the current verified release bundle",
            {"configured_bundle_matches_state": configured_matches},
        ), None
    return _gate(
        "runtime_bundle_binding", "PASS", "CURRENT_RUNTIME_BUNDLE_VERIFIED", None,
        {"bundle_digest": state_digest, "configured_bundle_matches_state": True},
    ), bundle


def _runtime_live_gates(
    config: Config, run_state: Mapping[str, Any] | None, state_error: bool,
    bound_bundle: Path | None = None, bundle_gate: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if state_error:
        process_gate = _gate(
            "runtime_processes", "BLOCK", "RUNTIME_STATE_INVALID",
            "repair or remove the invalid owned runtime state and rerun doctor",
            {"running_state_present": True, "owned_process_count": 0, "live_probe_count": 0},
        )
        pairing_gate = _gate(
            "pairing", "BLOCK", "PAIRING_RUNTIME_STATE_INVALID",
            "repair the invalid runtime state before validating Product Host pairing",
        )
        relay_gate = _gate(
            "relay", "BLOCK", "RELAY_RUNTIME_STATE_INVALID",
            "repair the invalid runtime state before validating Relay roles",
        )
        return process_gate, pairing_gate, relay_gate
    if bundle_gate is not None and bundle_gate.get("status") != "PASS":
        blocked = _gate(
            "runtime_processes", "BLOCK", "RUNTIME_BUNDLE_BINDING_NOT_VERIFIED",
            "repair the runtime bundle binding before validating live roles",
            {"running_state_present": True, "owned_process_count": 0, "live_probe_count": 0},
        )
        return blocked, _probe_block("pairing", "RUNTIME_BUNDLE_BINDING_NOT_VERIFIED"), _probe_block("relay", "RUNTIME_BUNDLE_BINDING_NOT_VERIFIED")
    if run_state is None:
        process_gate = _gate(
            "runtime_processes", "NOT_RUN", "RUNTIME_PROCESSES_NOT_RUNNING",
            "start the exact release candidate before validating runtime processes",
            {"running_state_present": False, "owned_process_count": 0, "live_probe_count": 0},
        )
        pairing_gate = _gate(
            "pairing", "NOT_RUN", "PAIRING_NOT_RUN",
            "start the remote release candidate before validating Product Host pairing",
        )
        relay_gate = _gate(
            "relay", "NOT_RUN", "RELAY_NOT_RUN",
            "start the remote release candidate before validating Relay roles",
        )
        return process_gate, pairing_gate, relay_gate

    records = run_state.get("processes", [])
    before = _measure_process_ownership(records)
    owned = sum(item == "owned" for item in before)
    if not records or owned != len(records):
        blocked = _gate(
            "runtime_processes", "BLOCK", "RUNTIME_PROCESS_IDENTITY_NOT_VERIFIED",
            "stop or repair the degraded owned runtime and rerun doctor",
            {"running_state_present": True, "owned_process_count": owned, "live_probe_count": 0},
        )
        return blocked, _probe_block("pairing", "PAIRING_PROCESS_IDENTITY_NOT_VERIFIED"), _probe_block("relay", "RELAY_PROCESS_IDENTITY_NOT_VERIFIED")
    if bound_bundle is not None:
        try:
            _verify_process_executables(records, bound_bundle)
        except _LiveProbeError as error:
            blocked = _gate(
                "runtime_processes", "BLOCK", str(error),
                "stop and restart from the current verified release bundle",
                {"running_state_present": True, "owned_process_count": owned, "live_probe_count": 0},
            )
            return blocked, _probe_block("pairing", "RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED"), _probe_block("relay", "RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")

    if run_state.get("mode") != "remote-local-evidence":
        blocked = _gate(
            "runtime_processes", "BLOCK", "REMOTE_RUNTIME_LIVE_PROBES_NOT_RUN",
            "start the remote release candidate before validating release runtime roles",
            {"running_state_present": True, "owned_process_count": owned, "live_probe_count": 0},
        )
        return blocked, _gate("pairing", "NOT_RUN", "PAIRING_NOT_RUN", "start the remote release candidate before validating Product Host pairing"), _gate("relay", "NOT_RUN", "RELAY_NOT_RUN", "start the remote release candidate before validating Relay roles")

    try:
        socket_before = _measure_product_host_socket(config, run_state)
        listener_before = _measure_listener_process_bindings(config, run_state)
    except _LiveProbeError:
        blocked = _gate(
            "runtime_processes", "BLOCK", "RUNTIME_ENDPOINT_BINDING_NOT_VERIFIED",
            "stop or repair the remote runtime and rerun doctor",
            {"running_state_present": True, "owned_process_count": owned, "live_probe_count": 0},
        )
        return blocked, _probe_block("pairing", "PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED"), _probe_block("relay", "LIVE_PROBE_IDENTITY_NOT_VERIFIED")

    pairing_error = None
    relay_error = None
    try:
        try:
            _probe_product_host_pairing(config, run_state)
        except _LiveProbeError as error:
            pairing_error = str(error)
        try:
            _probe_relay_roles(config, run_state)
        except _LiveProbeError as error:
            relay_error = str(error)
    finally:
        after = _measure_process_ownership(records)
        try:
            socket_after = _measure_product_host_socket(config, run_state)
        except _LiveProbeError:
            socket_after = None
        try:
            listener_after = _measure_listener_process_bindings(config, run_state)
        except _LiveProbeError:
            listener_after = None

    if (
        before != after or any(item != "owned" for item in after)
        or socket_after != socket_before or listener_after != listener_before
    ):
        blocked = _gate(
            "runtime_processes", "BLOCK", "RUNTIME_IDENTITY_CHANGED_DURING_LIVE_PROBE",
            "stop the changed runtime and start the exact release candidate again",
            {"running_state_present": True, "owned_process_count": sum(item == "owned" for item in after), "live_probe_count": 10},
        )
        return blocked, _probe_block("pairing", "PAIRING_IDENTITY_CHANGED_DURING_LIVE_PROBE"), _probe_block("relay", "RELAY_IDENTITY_CHANGED_DURING_LIVE_PROBE")

    pairing_gate = (
        _gate("pairing", "PASS", "PRODUCT_HOST_PAIRING_ENDPOINT_VERIFIED", None, {"live_probe_verified": True})
        if pairing_error is None
        else _probe_block("pairing", pairing_error)
    )
    relay_gate = (
        _gate("relay", "PASS", "RELAY_ROLES_AND_MAILBOX_VERIFIED", None, {"live_probe_verified": True, "live_probe_count": 9})
        if relay_error is None
        else _probe_block("relay", relay_error)
    )
    probes_passed = pairing_error is None and relay_error is None
    process_gate = _gate(
        "runtime_processes", "PASS" if probes_passed else "BLOCK",
        "RUNTIME_IDENTITIES_AND_ROLES_VERIFIED" if probes_passed else "RUNTIME_ROLE_LIVE_PROBE_FAILED",
        None if probes_passed else "repair the failed runtime role and rerun doctor",
        {"running_state_present": True, "owned_process_count": owned, "live_probe_count": 10},
    )
    return process_gate, pairing_gate, relay_gate


def _probe_block(name: str, code: str) -> dict[str, Any]:
    action = (
        "repair the Product Host pairing endpoint and rerun doctor"
        if name == "pairing" else "repair the Relay runtime roles and rerun doctor"
    )
    return _gate(name, "BLOCK", code, action, {"live_probe_verified": False})


def _measure_process_ownership(records: object) -> tuple[str, ...]:
    if not isinstance(records, list):
        return ("mismatch",)
    return tuple(processes.ownership(record) if isinstance(record, Mapping) else "mismatch" for record in records)


def _verify_process_executables(records: object, bundle: Path) -> None:
    if not isinstance(records, list):
        raise _LiveProbeError("RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")
    by_name = {record.get("name"): record for record in records if isinstance(record, Mapping)}
    if set(by_name) != REMOTE_PROCESS_NAMES or len(by_name) != len(records):
        raise _LiveProbeError("RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")
    canonical_bundle = bundle.resolve(strict=True)
    for role, relative in REMOTE_ARTIFACT_PATHS.items():
        expected = (canonical_bundle / relative).resolve(strict=True)
        if not expected.is_relative_to(canonical_bundle):
            raise _LiveProbeError("RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")
        record = by_name[role]
        pid = record.get("pid")
        if type(pid) is not int or not _command_has_exact_path(pid, expected):
            raise _LiveProbeError("RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")
        text_paths = _process_text_paths(pid)
        if role in NATIVE_ARTIFACT_ROLES and expected not in text_paths:
            raise _LiveProbeError("RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")
        if role not in NATIVE_ARTIFACT_ROLES and not text_paths:
            raise _LiveProbeError("RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED")


def _command_has_exact_path(pid: int, expected: Path) -> bool:
    try:
        result = subprocess.run(
            ["/bin/ps", "-ww", "-p", str(pid), "-o", "command="],
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    command = result.stdout.strip()
    marker = os.fsencode(expected)
    if result.returncode != 0:
        return False
    first = command.split(b" ", 2)
    return command.startswith(marker + b" ") or len(first) >= 2 and first[1] == marker


def _process_text_paths(pid: int) -> tuple[Path, ...]:
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid), "-d", "txt", "-Fn"],
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    paths = []
    for line in result.stdout.splitlines():
        if line.startswith(b"n/"):
            try:
                paths.append(Path(os.fsdecode(line[1:])).resolve(strict=True))
            except (OSError, UnicodeError):
                return ()
    return tuple(paths) if result.returncode == 0 else ()


def _measure_listener_process_bindings(
    config: Config, run_state: Mapping[str, Any],
) -> tuple[tuple[str, int, int], ...]:
    records = run_state.get("processes")
    if not isinstance(records, list):
        raise _LiveProbeError("LISTENER_PROCESS_BINDING_NOT_VERIFIED")
    pids = {record.get("name"): record.get("pid") for record in records if isinstance(record, Mapping)}
    observed: list[tuple[str, int, int]] = []
    for field, role in LISTENER_ROLE_FIELDS.items():
        port = _state_port(config, run_state, field)
        expected = pids.get(role)
        if type(expected) is not int or _listener_pids(port) != {expected}:
            raise _LiveProbeError("LISTENER_PROCESS_BINDING_NOT_VERIFIED")
        observed.append((field, port, expected))
    return tuple(observed)


def _listener_pids(port: int) -> set[int]:
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-a", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"],
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _LiveProbeError("LISTENER_PROCESS_BINDING_NOT_VERIFIED") from error
    try:
        pids = {int(line[1:]) for line in result.stdout.splitlines() if line.startswith(b"p")}
    except ValueError as error:
        raise _LiveProbeError("LISTENER_PROCESS_BINDING_NOT_VERIFIED") from error
    if result.returncode != 0 or not pids:
        raise _LiveProbeError("LISTENER_PROCESS_BINDING_NOT_VERIFIED")
    return pids


def _product_host_socket_path(config: Config, run_state: Mapping[str, Any]) -> Path:
    run_id = run_state.get("run_id")
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
        raise _LiveProbeError("PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED")
    home = Path(config.home).resolve(strict=True)
    suffix = hashlib.sha256(f"{home}:{os.geteuid()}".encode()).hexdigest()[:16]
    return Path("/private/tmp") / f"nomad-web-{suffix}-{run_id[:16]}" / "product-host.sock"


def _measure_product_host_socket(
    config: Config, run_state: Mapping[str, Any],
) -> tuple[int, int, int, int, int, int, int, int]:
    try:
        path = _product_host_socket_path(config, run_state)
        parent = path.parent.lstat()
        leaf = path.lstat()
        measured = {
            "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
            "parent_uid": parent.st_uid, "parent_mode": stat.S_IMODE(parent.st_mode),
            "socket_dev": leaf.st_dev, "socket_ino": leaf.st_ino,
            "socket_uid": leaf.st_uid, "socket_mode": stat.S_IMODE(leaf.st_mode),
        }
        expected = run_state.get("product_host_socket_identity")
        if (
            not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISSOCK(leaf.st_mode) or stat.S_ISLNK(leaf.st_mode)
            or measured["parent_uid"] != os.geteuid() or measured["socket_uid"] != os.geteuid()
            or measured["parent_mode"] != 0o700 or measured["socket_mode"] != 0o600
            or not isinstance(expected, Mapping) or any(expected.get(name) != value for name, value in measured.items())
        ):
            raise _LiveProbeError("PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED")
        return tuple(measured[name] for name in (
            "parent_dev", "parent_ino", "parent_uid", "parent_mode",
            "socket_dev", "socket_ino", "socket_uid", "socket_mode",
        ))
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        if isinstance(error, _LiveProbeError):
            raise
        raise _LiveProbeError("PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED") from error


def _probe_product_host_pairing(config: Config, run_state: Mapping[str, Any]) -> None:
    body = PRODUCT_HOST_PAIRING_PROBE_BODY
    request = (
        b"POST " + PRODUCT_HOST_PAIRING_PATH.encode("ascii") + b" HTTP/1.1\r\n"
        b"Host: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n" + body
    )
    try:
        raw = _unix_exchange(_product_host_socket_path(config, run_state), request)
        _expect_json_response(
            raw, 401, "Unauthorized",
            {"schema": "nomad.product-host.error.v1", "code": "UNAUTHORIZED"},
            cache_control=True,
        )
    except (OSError, TimeoutError, ValueError, _LiveProbeError) as error:
        raise _LiveProbeError("PRODUCT_HOST_PAIRING_LIVE_PROBE_FAILED") from error


def _probe_relay_roles(config: Config, run_state: Mapping[str, Any]) -> None:
    try:
        _probe_v1_health(_state_port(config, run_state, "relay_port"))
        _probe_v1_health(_state_port(config, run_state, "relay_device_v1_port"))
        _probe_v2_role(_state_port(config, run_state, "relay_host_v2_port"), "host")
        _probe_v2_role(_state_port(config, run_state, "relay_device_v2_port"), "device")
        _probe_v2_admin(_state_port(config, run_state, "relay_admin_port"))
    except (OSError, TimeoutError, ValueError, _LiveProbeError) as error:
        raise _LiveProbeError("RELAY_ROLE_LIVE_PROBE_FAILED") from error


def _state_port(config: Config, run_state: Mapping[str, Any], name: str) -> int:
    value = run_state.get(name)
    if type(value) is not int or value != getattr(config, name) or not 1024 <= value <= 65535:
        raise _LiveProbeError("RUNTIME_STATE_PORT_BINDING_INVALID")
    return value


def _probe_v1_health(port: int) -> None:
    raw = _tcp_exchange(port, "GET", "/health")
    _, _, body = _parse_json_response(raw, 200, "OK", cache_control=False)
    value = _strict_json(body)
    if (
        set(value) != {"status", "protocol", "timestamp"}
        or value["status"] != "ok" or value["protocol"] != "TEST-ONLY/1"
        or type(value["timestamp"]) is not int or value["timestamp"] <= 0
        or body != json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    ):
        raise _LiveProbeError("RELAY_V1_HEALTH_SCHEMA_INVALID")


def _probe_v2_role(port: int, expected_role: str) -> None:
    if expected_role not in {"host", "device"}:
        raise _LiveProbeError("RELAY_ROLE_LIVE_PROBE_FAILED")
    allowed = "host_to_device" if expected_role == "host" else "device_to_host"
    _expect_json_response(
        _tcp_exchange(
            port, "POST", _relay_frame_path(), _probe_frame(allowed), _relay_probe_headers(),
        ),
        410, "Gone", {"error": "Gone"}, cache_control=True,
    )
    forbidden = "device_to_host" if expected_role == "host" else "host_to_device"
    _expect_json_response(
        _tcp_exchange(
            port, "POST", _relay_frame_path(), _probe_frame(forbidden), _relay_probe_headers(),
        ),
        403, "Forbidden", {"error": "Forbidden"}, cache_control=True,
    )
    receive = "device_to_host" if expected_role == "host" else "host_to_device"
    _expect_json_response(
        _tcp_exchange(
            port, "GET", _relay_frame_path() + f"?direction={receive}&after_sequence=0",
            headers={"Authorization": f"Bearer {RELAY_PROBE_BEARER}"},
        ),
        404, "Not Found", {"error": "Not Found"}, cache_control=True,
    )


def _probe_v2_admin(port: int) -> None:
    raw = _tcp_exchange(port, "GET", RELAY_ADMIN_PATH)
    _, headers, body = _parse_json_response(raw, 405, "Method Not Allowed", cache_control=True)
    if headers.get("allow") != "POST" or _strict_json(body) != {"error": "method not allowed"}:
        raise _LiveProbeError("RELAY_ADMIN_ROLE_SCHEMA_INVALID")
    if body != b'{"error":"method not allowed"}\n':
        raise _LiveProbeError("RELAY_ADMIN_ROLE_SCHEMA_INVALID")


def _relay_frame_path() -> str:
    return "/v2/mailboxes/mbx-" + hashlib.sha256(b"nomad-readiness-doctor-mailbox").hexdigest() + "/frames"


def _probe_frame(direction: str) -> bytes:
    return json.dumps({
        "schema": "nomad.relay.opaque-frame.v2",
        "crypto_suite": "p256-hkdf-sha256-aes256gcm-v1",
        "mailbox_id": _relay_frame_path().split("/")[3],
        # This is structurally valid but permanently expired. A role-allowed
        # publish returns 410 before opening a transaction, while a forbidden
        # direction returns 403 first. Neither probe can mutate mailbox state.
        "direction": direction, "epoch": 1, "sequence": 1,
        "message_id": "msg-00000000000000000000000000000000",
        "issued_at": 1, "expires_at": 2,
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
    }, separators=(",", ":")).encode("ascii")


def _relay_probe_headers() -> Mapping[str, str]:
    return {"Authorization": f"Bearer {RELAY_PROBE_BEARER}", "Content-Type": "application/json"}


def _unix_exchange(path: Path, request: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(LIVE_PROBE_TIMEOUT_SECONDS)
        connection.connect(str(path))
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        return _read_bounded(connection)


def _tcp_exchange(
    port: int, method: str, path: str, body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
) -> bytes:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=LIVE_PROBE_TIMEOUT_SECONDS)
    try:
        connection.request(method, path, body=body, headers=dict(headers or {"Accept": "application/json"}))
        response = connection.getresponse()
        raw_body = response.read(MAX_LIVE_PROBE_BYTES + 1)
        if len(raw_body) > MAX_LIVE_PROBE_BYTES:
            raise _LiveProbeError("LIVE_PROBE_RESPONSE_TOO_LARGE")
        head = f"HTTP/1.1 {response.status} {response.reason}\r\n".encode("ascii")
        for name, value in response.getheaders():
            head += f"{name}: {value}\r\n".encode("ascii")
        return head + b"\r\n" + raw_body
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise _LiveProbeError("LIVE_PROBE_TRANSPORT_FAILED") from error
    finally:
        connection.close()


def _read_bounded(connection: socket.socket) -> bytes:
    chunks = []
    size = 0
    while True:
        chunk = connection.recv(min(4096, MAX_LIVE_PROBE_BYTES + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_LIVE_PROBE_BYTES:
            raise _LiveProbeError("LIVE_PROBE_RESPONSE_TOO_LARGE")


def _parse_json_response(
    raw: bytes, status: int, reason: str, *, cache_control: bool,
) -> tuple[int, dict[str, str], bytes]:
    if len(raw) > MAX_LIVE_PROBE_BYTES or raw.count(b"\r\n\r\n") != 1:
        raise _LiveProbeError("LIVE_PROBE_HTTP_FRAMING_INVALID")
    head, body = raw.split(b"\r\n\r\n", 1)
    try:
        lines = head.decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise _LiveProbeError("LIVE_PROBE_HTTP_FRAMING_INVALID") from error
    if not lines or lines[0] != f"HTTP/1.1 {status} {reason}":
        raise _LiveProbeError("LIVE_PROBE_HTTP_STATUS_INVALID")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ": " not in line:
            raise _LiveProbeError("LIVE_PROBE_HTTP_FRAMING_INVALID")
        name, value = line.split(": ", 1)
        name = name.lower()
        if not name or name in headers:
            raise _LiveProbeError("LIVE_PROBE_HTTP_FRAMING_INVALID")
        headers[name] = value
    if headers.get("content-type") != "application/json" or "content-encoding" in headers:
        raise _LiveProbeError("LIVE_PROBE_HTTP_SCHEMA_INVALID")
    if cache_control and headers.get("cache-control") != "no-store":
        raise _LiveProbeError("LIVE_PROBE_HTTP_SCHEMA_INVALID")
    if headers.get("content-length") != str(len(body)) or "transfer-encoding" in headers:
        raise _LiveProbeError("LIVE_PROBE_HTTP_FRAMING_INVALID")
    return status, headers, body


def _expect_json_response(
    raw: bytes, status: int, reason: str, expected: Mapping[str, object], *, cache_control: bool,
) -> None:
    _, _, body = _parse_json_response(raw, status, reason, cache_control=cache_control)
    if _strict_json(body) != dict(expected):
        raise _LiveProbeError("LIVE_PROBE_HTTP_SCHEMA_INVALID")
    canonical = json.dumps(dict(expected), sort_keys=True, separators=(",", ":")).encode()
    if body != canonical + b"\n":
        raise _LiveProbeError("LIVE_PROBE_HTTP_SCHEMA_INVALID")


def _strict_json(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for name, item in pairs:
            if name in value:
                raise ValueError("duplicate JSON field")
            value[name] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise _LiveProbeError("LIVE_PROBE_HTTP_SCHEMA_INVALID") from error
    if not isinstance(value, dict):
        raise _LiveProbeError("LIVE_PROBE_HTTP_SCHEMA_INVALID")
    return value


def _runtime_ports_gate(
    availability: Mapping[str, bool], run_state: Mapping[str, Any] | None,
    process_gate: Mapping[str, Any], state_error: bool,
) -> dict[str, Any]:
    observations = {
        "checked_port_count": len(RUNTIME_PORT_FIELDS),
        "availability": {name: bool(availability[name]) for name in RUNTIME_PORT_FIELDS},
    }
    if state_error:
        return _gate(
            "runtime_ports", "BLOCK", "RUNTIME_PORT_STATE_INVALID",
            "repair or remove the invalid owned runtime state and rerun doctor", observations,
        )
    if run_state is None:
        if all(availability.values()):
            return _gate(
                "runtime_ports", "PASS", "ALL_RUNTIME_PORTS_AVAILABLE", None, observations,
            )
        return _gate(
            "runtime_ports", "BLOCK", "RUNTIME_PORT_IN_USE",
            "release every configured runtime port and rerun doctor", observations,
        )
    if process_gate["status"] != "PASS":
        return _gate(
            "runtime_ports", "BLOCK", "RUNTIME_PORT_LIVE_STATE_NOT_VERIFIED",
            "repair the degraded or unverified runtime before validating its ports", observations,
        )

    mode = run_state.get("mode")
    if mode == "remote-local-evidence":
        active = set(RUNTIME_PORT_FIELDS)
    elif mode == "official-agent-local":
        active = {"gateway_port", "agent_port"}
    elif mode == "foundation-readonly":
        active = {"relay_port", "gateway_port"}
    else:
        active = set()
    matches = all(not availability[name] if name in active else availability[name] for name in RUNTIME_PORT_FIELDS)
    if active and matches:
        return _gate(
            "runtime_ports", "PASS", "RUNTIME_PORTS_MATCH_RUNNING_STATE", None, observations,
        )
    return _gate(
        "runtime_ports", "BLOCK", "RUNTIME_PORTS_DO_NOT_MATCH_RUNNING_STATE",
        "stop or repair the running release candidate and rerun doctor", observations,
    )


def _network_address_presence() -> dict[str, bool]:
    try:
        result = subprocess.run(
            ["/sbin/ifconfig"],
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"lan_ip_present": False, "global_ip_present": False}
    if result.returncode != 0:
        return {"lan_ip_present": False, "global_ip_present": False}
    addresses = [match.group(1).decode("ascii") for match in _IPV4.finditer(result.stdout)]
    addresses.extend(match.group(1).decode("ascii") for match in _IPV6.finditer(result.stdout))
    lan = False
    globally_routable = False
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            continue
        lan = lan or address.is_private
        globally_routable = globally_routable or address.is_global
    return {"lan_ip_present": lan, "global_ip_present": globally_routable}


def _network_gate(observations: Mapping[str, bool]) -> dict[str, Any]:
    if observations["lan_ip_present"] or observations["global_ip_present"]:
        return _gate(
            "network_address", "PASS", "NON_LOOPBACK_NETWORK_ADDRESS_AVAILABLE", None, observations,
        )
    return _gate(
        "network_address", "BLOCK", "NON_LOOPBACK_NETWORK_ADDRESS_MISSING",
        "connect the Mac to a LAN or globally routed network and rerun doctor", observations,
    )


def _chrome_gate() -> dict[str, Any]:
    present = CHROME.is_file()
    return _gate(
        "google_chrome", "PASS" if present else "BLOCK",
        "GOOGLE_CHROME_AVAILABLE" if present else "GOOGLE_CHROME_NOT_FOUND",
        None if present else "install Google Chrome at the supported macOS application path and rerun doctor",
        {"present": present},
    )


def _tls_inputs_gate(
    run_state: Mapping[str, Any] | None, state_error: bool,
) -> dict[str, Any]:
    if state_error:
        return _gate(
            "tls_inputs", "BLOCK", "TLS_INPUTS_RUNTIME_STATE_INVALID",
            "repair the invalid runtime state before revalidating operator TLS inputs",
            {"remote_running_state_present": False},
        )
    remote = run_state is not None and run_state.get("mode") == "remote-local-evidence"
    return _gate(
        "tls_inputs", "NOT_RUN",
        "TLS_INPUTS_NOT_REVALIDATED" if remote else "TLS_INPUTS_NOT_PROVIDED_TO_DOCTOR",
        "run the strict release journey with operator-supplied TLS certificate and key inputs",
        {"remote_running_state_present": remote},
    )


def _normal_trust_gate() -> dict[str, Any]:
    return _gate(
        "normal_chrome_tls_trust", "NOT_RUN", "NORMAL_CHROME_TLS_TRUST_NOT_RUN",
        "complete the strict browser journey in a normal Chrome trust context without certificate bypass",
        {"diagnostic_bypass_accepted": False},
    )


def _provider_gate(provider_names: list[str]) -> dict[str, Any]:
    present = bool(provider_names)
    return _gate(
        "provider_e3", "NOT_RUN",
        "PROVIDER_E3_NOT_RUN" if present else "PROVIDER_CREDENTIAL_SOURCE_NAME_NOT_PRESENT",
        "run the accepted Provider E3 journey with one FD-delivered credential source",
        {
            "credential_source_name_present": present,
            "credential_source_name_count": len(provider_names),
            "credential_value_inspected": False,
        },
    )


def _external_gate(name: str, code: str, next_step: str) -> dict[str, Any]:
    return _gate(name, "NOT_RUN", code, next_step, {"external_evidence_required": True})


def _free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
