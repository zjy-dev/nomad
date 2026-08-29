#!/usr/bin/env python3
"""Live Provider E3 runner over the exact remote-local-evidence product path."""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.nomad_web.bundle import verify_bundle
from tools.nomad_web.config import Config
from tools.nomad_web.state import read_run_state

PROVIDERS = frozenset({
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY",
})
SCHEMA = "nomad.provider.e3.evidence.v1"
SECRET_RE = re.compile(r"(?i)(api[_-]?key|bearer|token|secret|password|credential)")
PROCESS_NAMES = [
    "relay-host", "relay-device", "opencode", "product-host",
    "desktop-gateway", "join-gateway", "https-ingress",
]
SCENARIO_NAMES = ("reply", "deny", "stop", "duplicate", "reconnect", "outcome_unknown")
HOST_IDENTITY_CODES = {
    "READY": None,
    "AUTH_REQUIRED": "HOST_IDENTITY_AUTH_REQUIRED",
    "USER_DENIED": "HOST_IDENTITY_USER_DENIED",
    "KEYCHAIN_LOCKED": "HOST_IDENTITY_KEYCHAIN_LOCKED",
    "CORRUPT": "HOST_IDENTITY_CORRUPT",
    "UNAVAILABLE": "HOST_IDENTITY_UNAVAILABLE",
}


class ProviderE3Error(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        status: str = "BLOCK",
        diagnostics: Mapping[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.diagnostics = dict(diagnostics or {})
        self.evidence = dict(evidence or {})


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_binding() -> dict[str, str]:
    return {"provider_e3_runner_raw_sha256": _sha256_file(Path(__file__))}


def bundle_binding(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "digest": manifest["bundle_digest"],
        "source_commit_oid": manifest["source_commit_oid"],
        "launcher_version": manifest["launcher_version"],
        "classification": manifest["classification"],
    }


def scan_text(text: str, secrets: tuple[str, ...] = ()) -> list[str]:
    findings = []
    if any(secret and secret in text for secret in secrets):
        findings.append("SECRET_VALUE_PRESENT")
    if SECRET_RE.search(text):
        findings.append("SECRET_SHAPED_TEXT_PRESENT")
    return sorted(set(findings))


def scan_argv(argv: list[str], secrets: tuple[str, ...] = ()) -> list[str]:
    text = "\n".join(argv)
    findings = []
    if any(secret and secret in text for secret in secrets):
        findings.append("SECRET_VALUE_PRESENT")
    if re.search(r"(?i)(api[_-]?key|bearer|token|secret|password|credential)=", text):
        findings.append("SECRET_SHAPED_TEXT_PRESENT")
    return sorted(set(findings))


def scan_json(value: Any) -> list[str]:
    findings: list[str] = []

    def walk(item: Any, path: str) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                child_path = f"{path}.{key}"
                if SECRET_RE.search(str(key)):
                    findings.append("SECRET_KEY:" + child_path)
                walk(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")
        elif isinstance(item, str) and SECRET_RE.search(item):
            findings.append("SECRET_SHAPED_VALUE:" + path)

    walk(value, "root")
    return sorted(set(findings))


def scan_artifacts(argv: list[str], state: Any, evidence: Any, secrets: tuple[str, ...] = ()) -> list[str]:
    findings = scan_argv(argv, secrets) + scan_json(state) + scan_json(evidence)
    return sorted(set(findings))


def _read_credential(stream: Any) -> bytearray:
    raw = stream.buffer.read(16385) if hasattr(stream, "buffer") else stream.read(16385)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not raw or len(raw) > 16384 or b"\n" in raw or b"\r" in raw:
        return bytearray()
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return bytearray()
    return bytearray(raw)


def _wipe(secret: bytearray) -> None:
    for index in range(len(secret)):
        secret[index] = 0


def _private_root() -> Path:
    old = os.umask(0o077)
    try:
        root = Path(tempfile.mkdtemp(prefix="nomad-provider-e3."))
    finally:
        os.umask(old)
    os.chmod(root, 0o700)
    return root.resolve(strict=True)


def _reserved_ports() -> tuple[int, int, int, int, int, int, int, int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(8):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
        ports = tuple(int(item.getsockname()[1]) for item in sockets)
    finally:
        for item in sockets:
            item.close()
    if len(set(ports)) != 8:
        raise ProviderE3Error("PORT_RESERVATION_COLLISION")
    return ports


def sanitized_env(extra: Mapping[str, str]) -> dict[str, str]:
    env = {name: os.environ[name] for name in os.environ if name not in PROVIDERS}
    for proxy in [name for name in env if name.lower().endswith("_proxy")]:
        env.pop(proxy, None)
    env.update(extra)
    return env


def _validate_remote_tls_inputs(
    public_origin: str | None,
    https_listen: str | None,
    tls_cert_fd: int | None,
    tls_key_fd: int | None,
) -> tuple[str, str, int, int]:
    if public_origin is None or https_listen is None or tls_cert_fd is None or tls_key_fd is None:
        raise ProviderE3Error("REMOTE_TLS_OPERATOR_INPUTS_REQUIRED", status="BLOCK")
    try:
        parsed = urllib.parse.urlsplit(public_origin)
        listen = urllib.parse.urlsplit(f"//{https_listen}")
    except ValueError as error:
        raise ProviderE3Error("REMOTE_TLS_OPERATOR_INPUTS_INVALID", status="BLOCK") from error
    if parsed.scheme != "https" or not parsed.hostname or parsed.port is None:
        raise ProviderE3Error("REMOTE_TLS_OPERATOR_INPUTS_INVALID", status="BLOCK")
    if not listen.hostname or listen.port is None:
        raise ProviderE3Error("REMOTE_TLS_OPERATOR_INPUTS_INVALID", status="BLOCK")
    if type(tls_cert_fd) is not int or type(tls_key_fd) is not int or tls_cert_fd < 3 or tls_key_fd < 3:
        raise ProviderE3Error("REMOTE_TLS_OPERATOR_INPUTS_INVALID", status="BLOCK")
    return public_origin, https_listen, tls_cert_fd, tls_key_fd


def host_identity_preflight(bundle: Path) -> dict[str, Any]:
    binary = bundle / "bin" / "nomad-product-host"
    status = "INVALID"
    code = "HOST_IDENTITY_PREFLIGHT_INVALID"
    try:
        result = subprocess.run(
            [str(binary), "identity-preflight", "--non-interactive", "--scope=keychain"],
            cwd=bundle,
            env=sanitized_env({}),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        status, code = "UNAVAILABLE", "HOST_IDENTITY_PREFLIGHT_TIMEOUT"
    except OSError:
        status, code = "UNAVAILABLE", "HOST_IDENTITY_PREFLIGHT_FAILED"
    else:
        for candidate, mapped_code in HOST_IDENTITY_CODES.items():
            expected_returncode = 0 if candidate == "READY" else 1
            if (
                result.returncode == expected_returncode
                and result.stderr == b""
                and result.stdout == f'{{"status":"{candidate}"}}\n'.encode("ascii")
            ):
                status, code = candidate, mapped_code
                break
    value: dict[str, Any] = {"status": status, "ready": status == "READY"}
    if code is not None:
        value["error_code"] = code
    if status in {"AUTH_REQUIRED", "USER_DENIED"}:
        value["next_step"] = "nomad-web authorize-host-identity"
    return value


def _capability_summary(status: int, payload: Mapping[str, Any] | None) -> dict[str, Any]:
    capability = payload.get("capability") if isinstance(payload, Mapping) else None
    return {
        "http_status": status,
        "available": status == 200 and isinstance(payload, Mapping) and payload.get("schema") == "nomad.gateway.command-capability.v1",
        "reply": isinstance(capability, Mapping) and isinstance(capability.get("reply"), Mapping),
        "deny": isinstance(capability, Mapping) and isinstance(capability.get("deny"), Mapping),
        "stop": isinstance(capability, Mapping) and isinstance(capability.get("stop"), Mapping),
    }


def _scenario(name: str, status: str, reason_code: str, *, receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"name": name, "status": status, "reason_code": reason_code}
    if receipt is not None:
        value["receipt"] = {
            "action": receipt.get("action"),
            "status": receipt.get("status"),
            "error_code": receipt.get("error_code"),
            "idempotent_replay": receipt.get("idempotent_replay"),
            "snapshot_seq": receipt.get("snapshot_seq"),
            "snapshot_digest": receipt.get("snapshot_digest"),
        }
    return value


def _not_run_matrix(reason_codes: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    reasons = dict(reason_codes or {})
    return [
        _scenario(name, "NOT_RUN", reasons.get(name, "REAL_STATE_NOT_OBSERVED"))
        for name in SCENARIO_NAMES
    ]


def _overall_status(scenarios: list[dict[str, Any]]) -> str:
    if any(item["status"] == "BLOCK" for item in scenarios):
        return "BLOCK"
    if any(item["status"] == "FAIL" for item in scenarios):
        return "FAIL"
    if len(scenarios) == len(SCENARIO_NAMES) and all(item["status"] == "PASS" for item in scenarios):
        return "PASS"
    return "NOT_RUN"


def _validate_runtime_state(state: Mapping[str, Any]) -> None:
    if state.get("schema") != "nomad.web-companion.state.v2":
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    if state.get("mode") != "remote-local-evidence":
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    if state.get("real_agent_enabled") is not True or state.get("remote_enabled") is not True:
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    if state.get("production_external") is not False or state.get("network_scope") != "lan_direct":
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    desktop_url = state.get("desktop_url")
    if not isinstance(desktop_url, str) or re.fullmatch(r"http://127\.0\.0\.1:\d+/", desktop_url) is None:
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    processes = state.get("processes")
    if not isinstance(processes, list) or len(processes) != len(PROCESS_NAMES):
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    names = [item.get("name") for item in processes if isinstance(item, Mapping)]
    if names != PROCESS_NAMES:
        raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
    seen_identities: set[str] = set()
    for item in processes:
        if not isinstance(item, Mapping):
            raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
        pid = item.get("pid")
        identity = item.get("identity")
        if not isinstance(pid, int) or pid <= 1:
            raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
        if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
        if identity in seen_identities:
            raise ProviderE3Error("LAUNCHER_STATE_INVALID", status="BLOCK")
        seen_identities.add(identity)


def _receipt_ok(receipt: Mapping[str, Any], action: str) -> bool:
    return (
        receipt.get("schema") == "nomad.gateway.command-receipt.v1"
        and receipt.get("action") == action
        and isinstance(receipt.get("receipt_id"), str)
        and receipt.get("status") == "HostAccepted"
        and receipt.get("error_code") == "OK"
        and receipt.get("idempotent_replay") is False
        and isinstance(receipt.get("snapshot_seq"), int)
        and isinstance(receipt.get("snapshot_digest"), str)
    )


def _gateway_command(action: str, capability: Mapping[str, Any], *, request_id: str) -> dict[str, Any]:
    body = {
        "schema": "nomad.gateway.command.v1",
        "capability_id": capability["capability_id"],
        "request_id": request_id,
        "nonce": base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("="),
        "command_seq": capability["next_command_seq"],
        "expected_snapshot_seq": capability["snapshot_seq"],
        "expected_snapshot_digest": capability["snapshot_digest"],
        "issued_at": capability["issued_at"],
        "expires_at": capability["expires_at"],
        "action": action,
    }
    if action == "reply":
        target = capability["reply"]
        body.update({
            "turn_alias": target["turn_alias"],
            "input_alias": target["input_alias"],
            "content": "provider-e3 reply probe",
        })
    elif action == "deny":
        target = capability["deny"]
        body.update({
            "permission_alias": target["permission_alias"],
            "action_hash": target["action_hash"],
            "permission_expires_at": target["expires_at"],
        })
    elif action == "stop":
        target = capability["stop"]
        body.update({"turn_alias": target["turn_alias"]})
    else:
        raise ProviderE3Error("UNSUPPORTED_ACTION")
    return body


def reject_direct_agent_write(target_url: str, agent_origin: str | None) -> None:
    if agent_origin and target_url.startswith(agent_origin.rstrip("/") + "/"):
        raise ProviderE3Error("DIRECT_AGENT_WRITABLE_SHORTCUT_FORBIDDEN", status="BLOCK")


class GatewayClient:
    def __init__(self, gateway_origin: str, *, agent_origin: str | None) -> None:
        self.gateway_origin = gateway_origin.rstrip("/")
        self.agent_origin = agent_origin
        parsed = re.fullmatch(r"http://127\.0\.0\.1:(\d+)", self.gateway_origin)
        if parsed is None:
            raise ProviderE3Error("GATEWAY_ORIGIN_INVALID")
        self.host = f"127.0.0.1:{parsed.group(1)}"
        self.port = int(parsed.group(1))

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        csrf_token: str | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        target_url = self.gateway_origin + path
        reject_direct_agent_write(target_url, self.agent_origin)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {
            "Accept": "application/json",
            "Host": self.host,
            "Origin": self.gateway_origin,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if csrf_token is not None:
            headers["X-Nomad-CSRF"] = csrf_token
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(65536)
        finally:
            connection.close()
        payload = None
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ProviderE3Error("GATEWAY_RESPONSE_INVALID")
        return response.status, payload if isinstance(payload, dict) else None

    def capability(self) -> tuple[int, dict[str, Any] | None]:
        return self._request("GET", "/api/commands/capability")

    def command(self, body: Mapping[str, Any], csrf_token: str) -> tuple[int, dict[str, Any] | None]:
        return self._request("POST", "/api/commands", body=json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"), csrf_token=csrf_token)


def execute_scenarios(client: GatewayClient) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    status, payload = client.capability()
    summary = _capability_summary(status, payload)
    if not summary["available"]:
        return _not_run_matrix({
            "reply": "COMMAND_CAPABILITY_UNAVAILABLE",
            "deny": "COMMAND_CAPABILITY_UNAVAILABLE",
            "stop": "COMMAND_CAPABILITY_UNAVAILABLE",
            "duplicate": "NO_ACCEPTED_COMMAND_TO_REPLAY",
            "reconnect": "NO_SAFE_RECONNECT_TRIGGER",
            "outcome_unknown": "NO_SAFE_OUTCOME_UNKNOWN_TRIGGER",
        }), summary
    assert payload is not None
    capability = payload["capability"]
    csrf_token = payload["csrf_token"]
    scenarios = [
        _scenario("reply", "NOT_RUN", "REAL_QUESTION_NOT_OBSERVED"),
        _scenario("deny", "NOT_RUN", "REAL_PERMISSION_NOT_OBSERVED"),
        _scenario("stop", "NOT_RUN", "LIVE_STOP_CAPABILITY_NOT_OBSERVED"),
        _scenario("duplicate", "NOT_RUN", "NO_ACCEPTED_COMMAND_TO_REPLAY"),
        _scenario("reconnect", "NOT_RUN", "NO_SAFE_RECONNECT_TRIGGER"),
        _scenario("outcome_unknown", "NOT_RUN", "NO_SAFE_OUTCOME_UNKNOWN_TRIGGER"),
    ]
    if isinstance(capability.get("reply"), Mapping):
        request = _gateway_command("reply", capability, request_id="provider_e3_reply_0000000000000001")
        reply_status, reply_payload = client.command(request, csrf_token)
        if reply_status == 200 and isinstance(reply_payload, Mapping) and _receipt_ok(reply_payload, "reply"):
            scenarios[0] = _scenario("reply", "PASS", "REPLY_ACCEPTED", receipt=reply_payload)
            scenarios[3] = _scenario("duplicate", "FAIL", "DUPLICATE_NOT_EVALUATED_AFTER_REPLY")
        else:
            scenarios[0] = _scenario("reply", "FAIL", "REPLY_RECEIPT_INVALID")
    if isinstance(capability.get("deny"), Mapping):
        request = _gateway_command("deny", capability, request_id="provider_e3_deny_0000000000000001")
        deny_status, deny_payload = client.command(request, csrf_token)
        scenarios[1] = _scenario(
            "deny",
            "PASS" if deny_status == 200 and isinstance(deny_payload, Mapping) and _receipt_ok(deny_payload, "deny") else "FAIL",
            "DENY_ACCEPTED" if deny_status == 200 and isinstance(deny_payload, Mapping) and _receipt_ok(deny_payload, "deny") else "DENY_RECEIPT_INVALID",
            receipt=deny_payload if isinstance(deny_payload, Mapping) else None,
        )
    if isinstance(capability.get("stop"), Mapping):
        request = _gateway_command("stop", capability, request_id="provider_e3_stop_0000000000000001")
        stop_status, stop_payload = client.command(request, csrf_token)
        if stop_status == 200 and isinstance(stop_payload, Mapping) and _receipt_ok(stop_payload, "stop"):
            scenarios[2] = _scenario("stop", "PASS", "STOP_ACCEPTED", receipt=stop_payload)
            replay_status, replay_payload = client.command(request, csrf_token)
            if (
                replay_status == 200
                and isinstance(replay_payload, Mapping)
                and replay_payload.get("schema") == "nomad.gateway.command-receipt.v1"
                and replay_payload.get("receipt_id") == stop_payload.get("receipt_id")
                and replay_payload.get("idempotent_replay") is True
            ):
                scenarios[3] = _scenario("duplicate", "PASS", "REPLAY_IDEMPOTENT", receipt=replay_payload)
            else:
                scenarios[3] = _scenario("duplicate", "FAIL", "REPLAY_IDEMPOTENCE_MISSING", receipt=replay_payload if isinstance(replay_payload, Mapping) else None)
        else:
            scenarios[2] = _scenario("stop", "FAIL", "STOP_RECEIPT_INVALID", receipt=stop_payload if isinstance(stop_payload, Mapping) else None)
    return scenarios, summary


def _start_command(
    bundle: Path, provider: str, workspace: Path, credential: bytearray,
    env: Mapping[str, str], public_origin: str, https_listen: str,
    tls_cert_fd: int, tls_key_fd: int,
) -> tuple[list[str], dict[str, Any]]:
    credential_read_fd, credential_write_fd = os.pipe()
    command = [
        str(bundle / "bin" / "nomad-web"), "--json", "start",
        "--provider", provider, "--credential-stdin",
        "--workspace", str(workspace), "--remote-local-evidence",
        "--public-origin", public_origin, "--https-listen", https_listen,
        "--tls-cert-fd", str(tls_cert_fd), "--tls-key-fd", str(tls_key_fd),
    ]
    try:
        os.write(credential_write_fd, bytes(credential))
    finally:
        os.close(credential_write_fd)
        _wipe(credential)
    try:
        result = subprocess.run(
            command,
            stdin=credential_read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(env),
            timeout=90,
            check=False,
            pass_fds=(tls_cert_fd, tls_key_fd),
        )
    except subprocess.TimeoutExpired as error:
        raise ProviderE3Error("LAUNCHER_START_TIMEOUT") from error
    finally:
        with contextlib.suppress(OSError):
            os.close(credential_read_fd)
    if result.returncode != 0:
        code = "LAUNCHER_START_FAILED"
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if lines:
            with contextlib.suppress(json.JSONDecodeError):
                payload = json.loads(lines[-1])
                candidate = payload.get("error")
                if isinstance(candidate, str):
                    code = candidate
        raise ProviderE3Error(code)
    try:
        started = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ProviderE3Error("LAUNCHER_OUTPUT_INVALID") from error
    return command, started


def _stop_runtime(bundle: Path, env: Mapping[str, str], config: Config, state: Mapping[str, Any]) -> dict[str, Any]:
    stop_result = subprocess.run(
        [str(bundle / "bin" / "nomad-web"), "--json", "stop"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(env),
        timeout=30,
        check=False,
    )
    if stop_result.returncode != 0:
        raise ProviderE3Error("LAUNCHER_STOP_FAILED")
    cleared = read_run_state(config) is None
    stopped = True
    for item in state.get("processes", []):
        pid = item.get("pid")
        if isinstance(pid, int) and pid > 1:
            try:
                os.kill(pid, 0)
            except OSError:
                continue
            stopped = False
    if not cleared or not stopped:
        raise ProviderE3Error("RUNTIME_CLEANUP_INCOMPLETE")
    return {"stop_invoked": True, "state_cleared": cleared, "owned_processes_stopped": stopped}


def write_evidence(path: Path, value: Mapping[str, Any]) -> None:
    target = path.absolute()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    try:
        raw = _canonical(value)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("EVIDENCE_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_provider_e3(
    bundle: Path,
    provider: str,
    credential: bytearray,
    workspace: Path,
    *,
    public_origin: str | None,
    https_listen: str | None,
    tls_cert_fd: int | None,
    tls_key_fd: int | None,
) -> dict[str, Any]:
    if provider not in PROVIDERS:
        return {
            "schema": SCHEMA,
            "status": "BLOCK",
            "reason": "PROVIDER_NOT_ALLOWLISTED",
            "source_binding": source_binding(),
            "scenarios": _not_run_matrix(),
        }
    if not credential:
        return {
            "schema": SCHEMA,
            "status": "NOT_RUN",
            "reason": "CREDENTIAL_MISSING_OR_INVALID",
            "source_binding": source_binding(),
            "scenarios": _not_run_matrix(),
        }
    try:
        manifest = verify_bundle(bundle)
    except Exception:
        _wipe(credential)
        return {
            "schema": SCHEMA,
            "status": "BLOCK",
            "reason": "BUNDLE_INVALID",
            "source_binding": source_binding(),
            "scenarios": _not_run_matrix(),
        }
    identity = host_identity_preflight(bundle)
    if not identity["ready"]:
        _wipe(credential)
        result = {
            "schema": SCHEMA,
            "status": "BLOCK",
            "reason": identity["error_code"],
            "source_binding": source_binding(),
            "bundle": bundle_binding(manifest),
            "scenarios": _not_run_matrix(),
            "host_identity_preflight": identity,
        }
        if "next_step" in identity:
            result["next_step"] = identity["next_step"]
        return result
    try:
        public_origin, https_listen, tls_cert_fd, tls_key_fd = _validate_remote_tls_inputs(
            public_origin, https_listen, tls_cert_fd, tls_key_fd,
        )
    except ProviderE3Error:
        _wipe(credential)
        raise

    root = _private_root()
    state: dict[str, Any] | None = None
    cleanup = {"stop_invoked": False, "state_cleared": False, "owned_processes_stopped": False}
    result: dict[str, Any] | None = None
    command: list[str] = []
    env: dict[str, str] = {}
    config: Config | None = None
    try:
        relay_port, gateway_port, agent_port, join_gateway_port, relay_host_v2_port, relay_device_v2_port, relay_admin_port, relay_device_v1_port = _reserved_ports()
        home = root / "home"
        env = sanitized_env({
            "NOMAD_WEB_HOME": str(home),
            "NOMAD_WEB_BUNDLE": str(bundle.resolve()),
            "NOMAD_WEB_RELAY_PORT": str(relay_port),
            "NOMAD_WEB_GATEWAY_PORT": str(gateway_port),
            "NOMAD_WEB_AGENT_PORT": str(agent_port),
            "NOMAD_WEB_JOIN_GATEWAY_PORT": str(join_gateway_port),
            "NOMAD_WEB_RELAY_HOST_V2_PORT": str(relay_host_v2_port),
            "NOMAD_WEB_RELAY_DEVICE_V2_PORT": str(relay_device_v2_port),
            "NOMAD_WEB_RELAY_ADMIN_PORT": str(relay_admin_port),
            "NOMAD_WEB_RELAY_DEVICE_V1_PORT": str(relay_device_v1_port),
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        command, _ = _start_command(
            bundle, provider, workspace, credential, env,
            public_origin, https_listen, tls_cert_fd, tls_key_fd,
        )
        config = Config(
            repo_root=ROOT,
            home=home,
            relay_port=relay_port,
            gateway_port=gateway_port,
            agent_port=agent_port,
            bundle_root=bundle.resolve(),
            join_gateway_port=join_gateway_port,
            relay_host_v2_port=relay_host_v2_port,
            relay_device_v2_port=relay_device_v2_port,
            relay_admin_port=relay_admin_port,
            relay_device_v1_port=relay_device_v1_port,
        )
        state = read_run_state(config)
        if state is None:
            raise ProviderE3Error("LAUNCHER_STATE_MISSING")
        _validate_runtime_state(state)
        client = GatewayClient(state["desktop_url"].rstrip("/"), agent_origin=state.get("agent_origin"))
        scenarios, capability_surface = execute_scenarios(client)
        result = {
            "schema": SCHEMA,
            "status": _overall_status(scenarios),
            "reason": "SCENARIOS_RECORDED",
            "classification": "provider-e3-live-runner",
            "source_binding": source_binding(),
            "bundle": bundle_binding(manifest),
            "launcher": {
                "mode": state["mode"],
                "run_id": state["run_id"],
                "session_alias": state["session_alias"],
                "network_scope": state["network_scope"],
            },
            "topology": {
                "process_names": [item["name"] for item in state["processes"]],
                "process_identities": [{"name": item["name"], "identity": item["identity"]} for item in state["processes"]],
                "process_count": len(state["processes"]),
            },
            "capability_surface": capability_surface,
            "scenarios": scenarios,
            "privacy_findings": scan_artifacts(command, state, {"scenarios": scenarios}, ()),
            "cleanup": cleanup,
        }
        return result
    finally:
        with contextlib.suppress(Exception):
            _wipe(credential)
        if state is not None and config is not None:
            try:
                cleanup = _stop_runtime(bundle, env, config, state)
                if result is not None:
                    result["cleanup"] = cleanup
            finally:
                shutil.rmtree(root, ignore_errors=True)
        else:
            shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--credential-stdin", action="store_true")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--public-origin")
    parser.add_argument("--https-listen")
    parser.add_argument("--tls-cert-fd", type=int)
    parser.add_argument("--tls-key-fd", type=int)
    args = parser.parse_args(argv)

    credential = _read_credential(sys.stdin) if args.credential_stdin else bytearray()
    try:
        result = run_provider_e3(
            args.bundle, args.provider, credential, args.workspace,
            public_origin=args.public_origin,
            https_listen=args.https_listen,
            tls_cert_fd=args.tls_cert_fd,
            tls_key_fd=args.tls_key_fd,
        )
    except ProviderE3Error as error:
        result = {
            "schema": SCHEMA,
            "status": error.status,
            "reason": error.code,
            "source_binding": source_binding(),
            "scenarios": _not_run_matrix(),
        }
        result.update(error.evidence)
        if error.diagnostics:
            result["diagnostics"] = error.diagnostics
    write_evidence(args.evidence, result)
    print(json.dumps({"schema": SCHEMA, "status": result["status"], "reason": result["reason"]}, sort_keys=True))
    if result["status"] in {"PASS", "NOT_RUN"}:
        return 0
    if result["status"] == "FAIL":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
