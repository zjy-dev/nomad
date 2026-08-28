#!/usr/bin/env python3
"""Run E6-D against an exact installed bundle and real desktop Chrome."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Iterator, Mapping


SCHEMA = "nomad.m3e.real-product-slice-evidence.v1"
MARKER = "M3E_REAL_PRODUCT_SLICE_PASS"
DEFAULT_BUNDLE = Path("/tmp/nomad-e6d-final7-bundle")
EXPECTED_BUNDLE_DIGEST = "683382f135833bef10ca8df700d3d06033c0663b3a0a38ff949739400d196423"
REPO_ROOT = Path(__file__).resolve().parents[2]
BROWSER_RUNNER = Path(__file__).with_name("run_m3e_desktop_browser.py")
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
LAN_ADDRESS = "192.168.100.3"
PROCESS_NAMES = [
    "relay-host", "relay-device", "opencode", "product-host",
    "desktop-gateway", "join-gateway", "https-ingress",
]
PROVIDER_NAMES = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY",
}
HOST_IDENTITY_CODES = {
    "READY": None,
    "AUTH_REQUIRED": "HOST_IDENTITY_AUTH_REQUIRED",
    "USER_DENIED": "HOST_IDENTITY_USER_DENIED",
    "KEYCHAIN_LOCKED": "HOST_IDENTITY_KEYCHAIN_LOCKED",
    "CORRUPT": "HOST_IDENTITY_CORRUPT",
    "UNAVAILABLE": "HOST_IDENTITY_UNAVAILABLE",
}


class SliceError(RuntimeError):
    def __init__(
        self, code: str, diagnostics: Mapping[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
    ):
        super().__init__(code)
        self.diagnostics = dict(diagnostics or {})
        self.evidence = dict(evidence or {})


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--keep-runtime", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--diagnostic-spki-bypass", action="store_true")
    return parser.parse_args()


def load_manifest(bundle: Path) -> dict[str, Any]:
    try:
        value = json.loads((bundle / "manifest.json").read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise SliceError("bundle_manifest_unavailable") from error
    if value.get("bundle_digest") != EXPECTED_BUNDLE_DIGEST:
        raise SliceError("bundle_digest_mismatch")
    required = [
        "bin/nomad-web", "bin/nomad-relay", "bin/nomad-product-host",
        "bin/nomad-ingress", "agent/opencode", "gateway/server.mjs",
        "web/index.html", "lib/nomad_web/launcher.py",
    ]
    if any(not (bundle / item).is_file() for item in required):
        raise SliceError("bundle_file_missing")
    if value.get("agent_runtime", {}).get("provider_backed") is not False:
        raise SliceError("bundle_agent_classification_invalid")
    return value


def _bundle_business_process_count(bundle: Path) -> int:
    result = subprocess.run(
        ["ps", "-axo", "pid=,command="], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=False,
    )
    if result.returncode != 0:
        raise SliceError("PROCESS_SCAN_FAILED")
    markers = (
        str(bundle / "bin" / "nomad-relay"),
        str(bundle / "bin" / "nomad-product-host"),
        str(bundle / "bin" / "nomad-ingress"),
        str(bundle / "agent" / "opencode"),
        str(bundle / "gateway" / "server.mjs"),
    )
    return sum(any(marker in line for marker in markers) for line in result.stdout.splitlines())


def host_identity_preflight(bundle: Path) -> dict[str, Any]:
    binary = bundle / "bin" / "nomad-product-host"
    status, code = "INVALID", "HOST_IDENTITY_PREFLIGHT_INVALID"
    try:
        result = subprocess.run(
            [str(binary), "identity-preflight", "--non-interactive"],
            cwd=bundle, env=sanitized_env({}), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
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
    process_count = _bundle_business_process_count(bundle)
    if process_count != 0:
        raise SliceError(
            "HOST_IDENTITY_PREFLIGHT_PROCESS_LEAK",
            {"host_identity_status": status, "business_process_count": process_count},
        )
    value: dict[str, Any] = {
        "status": status,
        "business_process_count": 0,
        "ready": status == "READY",
    }
    if code is not None:
        value["error_code"] = code
    if status in {"AUTH_REQUIRED", "USER_DENIED"}:
        value["next_step"] = "nomad-web authorize-host-identity"
    return value


def preflight(bundle: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    try:
        manifest = load_manifest(bundle)
        checks["exact_bundle"] = bundle.resolve() == DEFAULT_BUNDLE.resolve()
        checks["bundle_digest"] = manifest["bundle_digest"] == EXPECTED_BUNDLE_DIGEST
        identity = host_identity_preflight(bundle)
    except Exception:
        checks["exact_bundle"] = False
        checks["bundle_digest"] = False
        identity = {"status": "NOT_RUN", "business_process_count": 0, "ready": False, "error_code": "BUNDLE_PREFLIGHT_FAILED"}
    checks["lan_address"] = _lan_present(LAN_ADDRESS)
    checks["chrome"] = CHROME.is_file()
    checks["openssl"] = shutil.which("openssl") is not None
    checks["certutil"] = shutil.which("certutil") is not None
    checks["uv"] = shutil.which("uv") is not None
    checks["browser_runner"] = BROWSER_RUNNER.is_file()
    checks["host_identity_ready"] = identity["ready"]
    value: dict[str, Any] = {
        "schema": "nomad.m3e.real-product-slice-preflight.v1",
        "status": "READY" if all(checks.values()) else "BLOCKED",
        "checks": checks,
        "bundle_digest": EXPECTED_BUNDLE_DIGEST if checks["bundle_digest"] else None,
        "network_scope": "lan_direct",
        "provider_e3": "NOT_RUN",
        "physical_phone": "NOT_RUN",
        "production_ready": False,
        "content_free": True,
        "host_identity_preflight": identity,
    }
    if not identity["ready"]:
        value["code"] = identity.get("error_code", "HOST_IDENTITY_PREFLIGHT_INVALID")
        if "next_step" in identity:
            value["next_step"] = identity["next_step"]
    return value


def _lan_present(address: str) -> bool:
    result = subprocess.run(
        ["ifconfig"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False
    )
    return result.returncode == 0 and re.search(rf"\binet {re.escape(address)}\b", result.stdout) is not None


def reserve_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listener.bind((LAN_ADDRESS if not sockets else "127.0.0.1", 0))
            sockets.append(listener)
        ports = [int(item.getsockname()[1]) for item in sockets]
    finally:
        for item in sockets:
            item.close()
    if len(set(ports)) != count:
        raise SliceError("port_reservation_collision")
    return ports


def private_root() -> Path:
    old = os.umask(0o077)
    try:
        root = Path(tempfile.mkdtemp(prefix="nomad-e6d-product."))
    finally:
        os.umask(old)
    os.chmod(root, 0o700)
    return root.resolve(strict=True)


def sanitized_env(extra: Mapping[str, str]) -> dict[str, str]:
    env = {name: os.environ[name] for name in os.environ if name not in PROVIDER_NAMES}
    for proxy in [name for name in env if name.lower().endswith("_proxy")]:
        env.pop(proxy, None)
    env.update(extra)
    return env


def run_checked(
    command: list[str], *, stage: str, timeout: int = 30,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, check=False, env=None if env is None else dict(env),
        )
    except subprocess.TimeoutExpired as error:
        raise SliceError(f"{stage}_timeout") from error
    if result.returncode != 0:
        raise SliceError(f"{stage}_failed")
    return result


def create_certificates(root: Path) -> dict[str, Path]:
    ca_key, ca_cert = root / "ca.key", root / "ca.pem"
    leaf_key, leaf_csr, leaf_cert = root / "leaf.key", root / "leaf.csr", root / "leaf.pem"
    leaf_extensions = root / "leaf.ext"
    run_checked(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
                 "-subj", "/CN=Nomad E6D Ephemeral Test CA",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash"], stage="cert_ca")
    run_checked(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(leaf_key), "-out", str(leaf_csr),
                 "-subj", f"/CN={LAN_ADDRESS}",
                 "-addext", f"subjectAltName=IP:{LAN_ADDRESS},IP:127.0.0.1,DNS:localhost",
                 "-addext", "extendedKeyUsage=serverAuth",
                 "-addext", "keyUsage=critical,digitalSignature,keyEncipherment"], stage="cert_csr")
    extension_raw = (
        f"subjectAltName=IP:{LAN_ADDRESS},IP:127.0.0.1,DNS:localhost\n"
        "extendedKeyUsage=serverAuth\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "basicConstraints=critical,CA:FALSE\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    ).encode("ascii")
    extension_fd = os.open(leaf_extensions, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(extension_fd, extension_raw)
    finally:
        os.close(extension_fd)
    run_checked(["openssl", "x509", "-req", "-in", str(leaf_csr),
                 "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                 "-out", str(leaf_cert), "-days", "1",
                 "-extfile", str(leaf_extensions)], stage="cert_sign")
    for path in (ca_key, ca_cert, leaf_key, leaf_csr, leaf_cert, leaf_extensions):
        os.chmod(path, 0o600)
    verify = run_checked(["openssl", "verify", "-CAfile", str(ca_cert), str(leaf_cert)], stage="cert_verify")
    san = run_checked(["openssl", "x509", "-in", str(leaf_cert), "-noout", "-text"], stage="cert_san")
    if "192.168.100.3" not in san.stdout or "OK" not in verify.stdout:
        raise SliceError("certificate_verification_failed")
    return {"ca": ca_cert, "cert": leaf_cert, "key": leaf_key}


def leaf_spki_sha256(certificate: Path) -> str:
    public_key = run_checked(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        stage="diagnostic_spki_public_key",
    ).stdout.encode("ascii")
    try:
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=public_key, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SliceError("diagnostic_spki_der_timeout") from error
    if der.returncode != 0 or not der.stdout:
        raise SliceError("diagnostic_spki_der_failed")
    return base64.b64encode(hashlib.sha256(der.stdout).digest()).decode("ascii")


@contextlib.contextmanager
def temporary_chrome_trust(profile: Path, ca: Path) -> Iterator[None]:
    profile.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = f"sql:{profile}"
    run_checked(["certutil", "-N", "--empty-password", "-d", database], stage="trust_nss_create")
    run_checked(["certutil", "-A", "-d", database, "-n", "Nomad E6D Ephemeral Test CA", "-t", "C,,", "-i", str(ca)], stage="trust_nss_import")
    listed = run_checked(["certutil", "-L", "-d", database], stage="trust_nss_verify")
    if "Nomad E6D Ephemeral Test CA" not in listed.stdout:
        raise SliceError("chrome_nss_ca_import_failed")
    yield


def _credential_pipe() -> int:
    read_fd, write_fd = os.pipe()
    canary = b"TEST_ONLY_NOMAD_E6D_CANARY_NO_PROVIDER_CALLS"
    os.write(write_fd, canary)
    os.close(write_fd)
    return read_fd


def start_product(bundle: Path, env: Mapping[str, str], certs: Mapping[str, Path], public_origin: str, https_listen: str) -> dict[str, Any]:
    credential_fd = _credential_pipe()
    cert_fd = os.open(certs["cert"], os.O_RDONLY | os.O_CLOEXEC)
    key_fd = os.open(certs["key"], os.O_RDONLY | os.O_CLOEXEC)
    command = [
        str(bundle / "bin/nomad-web"), "--json", "start",
        "--provider", "OPENAI_API_KEY", "--credential-stdin",
        "--workspace", str(REPO_ROOT), "--remote-local-evidence",
        "--public-origin", public_origin, "--https-listen", https_listen,
        "--tls-cert-fd", str(cert_fd), "--tls-key-fd", str(key_fd),
    ]
    try:
        try:
            result = subprocess.run(
                command, stdin=credential_fd, pass_fds=(credential_fd, cert_fd, key_fd),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=dict(env),
                timeout=90, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise SliceError("launcher_start_timeout") from error
    finally:
        for descriptor in (credential_fd, cert_fd, key_fd):
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if result.returncode != 0:
        code = "LAUNCHER_FAILURE"
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if lines:
            with contextlib.suppress(json.JSONDecodeError):
                candidate = json.loads(lines[-1]).get("error")
                if isinstance(candidate, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", candidate):
                    code = candidate
        raise SliceError("launcher_start_failed", {"launcher_error_code": code})
    try:
        state = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SliceError("launcher_output_invalid") from error
    return state


def stop_product(bundle: Path, env: Mapping[str, str]) -> None:
    try:
        result = subprocess.run(
            [str(bundle / "bin/nomad-web"), "--json", "stop"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(env), timeout=30, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SliceError("launcher_stop_timeout") from error
    state_path = Path(env["NOMAD_WEB_HOME"]) / "run" / "state.json"
    if result.returncode != 0 and state_path.exists():
        raise SliceError("launcher_stop_failed")


def process_evidence(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    processes = state.get("processes")
    if not isinstance(processes, list) or [item.get("name") for item in processes] != PROCESS_NAMES:
        raise SliceError("seven_process_topology_mismatch")
    output = []
    for item in processes:
        pid, identity = item.get("pid"), item.get("identity")
        if not isinstance(pid, int) or pid <= 1 or not isinstance(identity, str) or not identity:
            raise SliceError("process_identity_invalid")
        os.kill(pid, 0)
        output.append({"name": item["name"], "pid": pid, "identity": identity})
    return output


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def public_negative_routes(public_origin: str, ca: Path) -> dict[str, int]:
    context = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    probes = {
        "desktop": ("POST", "/api/desktop/pairing/create"),
        "internal": ("GET", "/internal/session/current"),
        "admin": ("POST", "/v2/admin/mailboxes/provision"),
        "legacy": ("GET", "/v1/frames"),
        "encoded_join": ("GET", "/%6a/join-00000000000000000000000000000000"),
        "join_method": ("POST", "/j/join-00000000000000000000000000000000"),
    }
    statuses: dict[str, int] = {}
    for name, (method, path) in probes.items():
        request = urllib.request.Request(public_origin + path, method=method)
        try:
            with opener.open(request, timeout=5) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        if status != 404:
            raise SliceError(f"public_negative_route_failed_{name}")
        statuses[name] = status
    return statuses


def run_browser(
    desktop_url: str, public_origin: str, profile: Path, env: Mapping[str, str],
    diagnostic_spki_sha256: str | None = None,
) -> dict[str, Any]:
    command = [
        "uv", "run", "--with", "playwright==1.62.0", "python", str(BROWSER_RUNNER),
        "--desktop-url", desktop_url, "--public-origin", public_origin,
        "--profile", str(profile), "--chrome", str(CHROME),
        "--timeout-ms", "20000",
    ]
    if diagnostic_spki_sha256 is not None:
        command.extend(["--diagnostic-spki-sha256", diagnostic_spki_sha256])
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(env), timeout=150, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SliceError("browser_journey_timeout") from error
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as error:
        raise SliceError("browser_evidence_invalid") from error
    expected_status = "DIAGNOSTIC_COMPLETE" if diagnostic_spki_sha256 is not None else "PASS"
    if result.returncode != 0 or value.get("status") != expected_status:
        raise SliceError(
            f"browser_{value.get('code', 'failed')}",
            value.get("diagnostics") if isinstance(value.get("diagnostics"), dict) else {},
        )
    return value


def diagnostic_summary(home: Path) -> dict[str, Any]:
    logs = home / "logs"
    result: dict[str, Any] = {"log_file_count": 0, "nonempty_log_count": 0, "error_signal_count": 0}
    if not logs.is_dir():
        return result
    for path in logs.iterdir():
        if not path.is_file() or path.is_symlink():
            continue
        result["log_file_count"] += 1
        raw = path.read_bytes()[:256 * 1024]
        if raw:
            result["nonempty_log_count"] += 1
        lowered = raw.lower()
        result["error_signal_count"] += sum(lowered.count(word) for word in (b"error", b"panic", b"fatal"))
    return result


def runtime_database_summary(home: Path) -> dict[str, Any]:
    def query(database: Path, sql: str) -> list[list[Any]]:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2)
        try:
            return [list(row) for row in connection.execute(sql).fetchall()]
        finally:
            connection.close()

    private = home / "private"
    try:
        relay = private / "relay-v2.sqlite3"
        remote = private / "remote-mailbox.sqlite3"
        registry = private / "host-device-registry.sqlite3"
        pairing = private / "pairing-coordinator.sqlite3"
        return {
            "available": True,
            "relay_mailboxes": query(relay, "select state,count(*) from v2_mailboxes group by state order by state"),
            "relay_streams": query(relay, "select direction,epoch,max_sequence,max_acked_sequence,count(*) from v2_streams group by direction,epoch,max_sequence,max_acked_sequence order by direction,epoch"),
            "relay_frames": query(relay, "select direction,epoch,count(*),min(sequence),max(sequence) from v2_frames group by direction,epoch order by direction,epoch"),
            "remote_cursors": query(remote, "select direction,epoch,next_sequence,read_through_sequence,applied_through_sequence,acked_through_sequence,pending_sequence is not null,pending_inbound_sequence is not null from remote_mailbox_state order by direction,epoch"),
            "remote_poison_count": query(remote, "select count(*) from remote_mailbox_poison")[0][0],
            "device_states": query(registry, "select state,activated_epoch,revoked_epoch is not null,count(*) from device_registry group by state,activated_epoch,revoked_epoch is not null order by state,activated_epoch"),
            "pairing_challenges": query(registry, "select consumed_at_unix is not null,invalidated_at_unix is not null,count(*) from pairing_challenge group by consumed_at_unix is not null,invalidated_at_unix is not null"),
            "pairing_state_rows": query(pairing, "select count(*) from pairing_coordinator_state")[0][0],
        }
    except (OSError, sqlite3.Error):
        return {"available": False}


def write_evidence(path: Path, value: Mapping[str, Any]) -> None:
    path = path.absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, canonical_json(value) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_slice(
    bundle: Path, evidence_path: Path | None, keep_runtime: bool,
    diagnostic_spki_bypass: bool = False,
) -> dict[str, Any]:
    manifest = load_manifest(bundle)
    check = preflight(bundle)
    if check["status"] != "READY":
        identity = check["host_identity_preflight"]
        evidence = {
            "bundle_digest": check["bundle_digest"],
            "host_identity_preflight": identity,
            "processes": [], "process_count": 0,
            "network_scope": "lan_direct", "provider_e3": "NOT_RUN",
            "physical_phone": "NOT_RUN", "production_ready": False,
            "content_free": True,
        }
        if "next_step" in check:
            evidence["next_step"] = check["next_step"]
        raise SliceError(
            str(check.get("code", "PREFLIGHT_BLOCKED")),
            {"business_process_count": identity["business_process_count"]},
            evidence,
        )
    root = private_root()
    home = root / "home"
    ports = reserve_ports(9)
    public_port, relay, desktop, agent, join, host_v2, device_v2, admin, device_v1 = ports
    public_origin = f"https://{LAN_ADDRESS}:{public_port}"
    env = sanitized_env({
        "NOMAD_WEB_HOME": str(home), "NOMAD_WEB_BUNDLE": str(bundle.resolve()),
        "NOMAD_WEB_RELAY_PORT": str(relay), "NOMAD_WEB_GATEWAY_PORT": str(desktop),
        "NOMAD_WEB_AGENT_PORT": str(agent), "NOMAD_WEB_JOIN_GATEWAY_PORT": str(join),
        "NOMAD_WEB_RELAY_HOST_V2_PORT": str(host_v2),
        "NOMAD_WEB_RELAY_DEVICE_V2_PORT": str(device_v2),
        "NOMAD_WEB_RELAY_ADMIN_PORT": str(admin),
        "NOMAD_WEB_RELAY_DEVICE_V1_PORT": str(device_v1),
        "NO_PROXY": f"127.0.0.1,localhost,{LAN_ADDRESS}",
        "no_proxy": f"127.0.0.1,localhost,{LAN_ADDRESS}",
    })
    certs = create_certificates(root)
    started = False
    primary_error: BaseException | None = None
    cleanup_error: str | None = None
    partial: dict[str, Any] = {
        "bundle": {
            "digest": manifest["bundle_digest"],
            "source_commit_oid": manifest["source_commit_oid"],
            "launcher_version": manifest["launcher_version"],
            "classification": manifest["classification"],
        },
        "processes": [], "process_count": 0, "tls_verified": False,
        "diagnostic_tls_bypass": diagnostic_spki_bypass,
        "tls": {
            "ca_scope": "isolated_chrome_nss_profile", "san_lan_address": True,
            "probe_client_verified": False, "normal_chrome_verification": False,
            "ignore_https_errors": False,
        },
        "public_negative_routes": {}, "network_scope": "lan_direct",
        "browser": {
            "product": "Google Chrome", "executable_sha256": _sha256_file(CHROME),
            "headless": True, "isolated_profile": True,
        },
        "journey": {
            "desktop_shell": "NOT_RUN", "join_shell": "NOT_RUN",
            "pairing": "NOT_RUN", "projection": "NOT_RUN",
            "refresh_recovery": "NOT_RUN", "revoke": "NOT_RUN",
            "revoked_browser_blocked": "NOT_RUN",
            "actions": {"view": "NOT_RUN", "reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN"},
        },
        "provider_canary": "TEST_ONLY_AGENT_STARTUP", "provider_e3": "NOT_RUN",
        "physical_phone": "NOT_RUN", "production_external": False,
        "production_ready": False, "content_free": True,
    }
    try:
        state = start_product(bundle, env, certs, public_origin, f"{LAN_ADDRESS}:{public_port}")
        started = True
        identities = process_evidence(state)
        partial["processes"] = identities
        partial["process_count"] = len(identities)
        if state.get("network_scope") != "lan_direct" or state.get("production_external") is not False:
            raise SliceError("launcher_scope_mismatch")
        negatives = public_negative_routes(public_origin, certs["ca"])
        partial["tls"]["probe_client_verified"] = True
        partial["public_negative_routes"] = negatives
        chrome_profile = root / "chrome-profile"
        with temporary_chrome_trust(chrome_profile, certs["ca"]):
            browser = run_browser(
                state["desktop_url"], public_origin, chrome_profile, env,
                leaf_spki_sha256(certs["cert"]) if diagnostic_spki_bypass else None,
            )
        partial["tls"]["normal_chrome_verification"] = not diagnostic_spki_bypass
        partial["tls_verified"] = not diagnostic_spki_bypass
        evidence: dict[str, Any] = {
            "schema": SCHEMA,
            "status": "DIAGNOSTIC_COMPLETE" if diagnostic_spki_bypass else "PASS",
            "bundle": partial["bundle"],
            "processes": identities, "process_count": len(identities),
            "tls_verified": not diagnostic_spki_bypass, "tls": {
                "ca_scope": "isolated_chrome_nss_profile",
                "san_lan_address": True,
                "probe_client_verified": True,
                "normal_chrome_verification": not diagnostic_spki_bypass,
                "ignore_https_errors": False,
                "diagnostic_tls_bypass": diagnostic_spki_bypass,
                "spki_allowlist_count": 1 if diagnostic_spki_bypass else 0,
            },
            "public_negative_routes": negatives,
            "browser": browser, "network_scope": "lan_direct",
            "provider_canary": "TEST_ONLY_AGENT_STARTUP", "provider_e3": "NOT_RUN",
            "physical_phone": "NOT_RUN", "production_external": False,
            "production_ready": False, "content_free": True,
            "diagnostic_tls_bypass": diagnostic_spki_bypass,
        }
        if not diagnostic_spki_bypass:
            evidence["marker"] = MARKER
        if evidence_path is not None:
            write_evidence(evidence_path, evidence)
        return evidence
    except BaseException as error:
        primary_error = error
        diagnostics = dict(error.diagnostics) if isinstance(error, SliceError) else {}
        if diagnostics.get("desktop_navigation", {}).get("status") == 200:
            partial["journey"]["desktop_shell"] = "VERIFIED"
        if str(error) == "browser_desktop_pairing_blocked_command_capability_unavailable":
            partial["journey"]["pairing"] = "BLOCKED_CSRF_BOOTSTRAP"
        if diagnostic_spki_bypass and diagnostics.get("networkidle", {}).get("join") == "OBSERVED":
            partial["journey"]["join_shell"] = "VERIFIED_DIAGNOSTIC_SPKI_ONLY"
        if diagnostic_spki_bypass and diagnostics.get("paired_device_count") == 1:
            partial["journey"]["pairing"] = "VERIFIED_DIAGNOSTIC_SPKI_ONLY"
        if str(error) == "browser_remote_projection_timeout":
            partial["journey"]["projection"] = "BLOCKED_HOST_PROJECTION_UNAVAILABLE"
        diagnostics["logs"] = diagnostic_summary(home)
        diagnostics["runtime_database"] = runtime_database_summary(home)
        if started:
            diagnostics["alive_process_count_before_cleanup"] = sum(
                1 for item in partial["processes"]
                if isinstance(item.get("pid"), int) and _pid_alive(item["pid"])
            )
        raise SliceError(str(error), diagnostics, partial) from error
    finally:
        if started:
            try:
                stop_product(bundle, env)
            except SliceError as error:
                cleanup_error = str(error)
        if not keep_runtime:
            shutil.rmtree(root, ignore_errors=True)
        if primary_error is None and cleanup_error is not None:
            raise SliceError(cleanup_error)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    if args.preflight:
        result = preflight(args.bundle)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["status"] == "READY" else 2
    try:
        result = run_slice(
            args.bundle, args.evidence, args.keep_runtime, args.diagnostic_spki_bypass
        )
    except Exception as error:
        result = {
            "schema": SCHEMA, "status": "BLOCK",
            "code": str(error) if isinstance(error, SliceError) else type(error).__name__,
            "bundle_digest": EXPECTED_BUNDLE_DIGEST, "network_scope": "lan_direct",
            "provider_e3": "NOT_RUN", "physical_phone": "NOT_RUN",
            "production_ready": False, "content_free": True,
            "diagnostic_tls_bypass": args.diagnostic_spki_bypass,
        }
        if isinstance(error, SliceError):
            result.update(error.evidence)
            if error.diagnostics:
                result["diagnostics"] = error.diagnostics
        if args.evidence is not None:
            write_evidence(args.evidence, result)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
