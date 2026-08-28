"""Stable, content-safe recovery guidance for Nomad product checks.

This module is deliberately independent from CLI rendering.  P8-H and support
tools can consume the returned dictionaries without exposing blocker details,
machine paths, identifiers, credentials, or user content.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping

RECOVERY_SCHEMA = "nomad.web-companion.recovery.v1"
REPO_OWNED = "REPO_OWNED_RECOVERY"
EXTERNAL = "EXTERNAL_GATE"


@dataclass(frozen=True)
class Recovery:
    recovery_code: str
    category: str
    scope: str
    next_step: str


def _recovery(code: str, category: str, scope: str, next_step: str) -> Recovery:
    return Recovery(code, category, scope, next_step)


INSTALL_NOMAD = _recovery(
    "INSTALL_NOMAD", "INSTALL", REPO_OWNED,
    "Install Nomad from the release download, then run the check again.",
)
REINSTALL_NOMAD = _recovery(
    "REINSTALL_NOMAD", "INSTALL", REPO_OWNED,
    "Install Nomad again from the release download, then run the check again.",
)
START_NOMAD = _recovery(
    "START_NOMAD", "APP_RUNTIME", REPO_OWNED,
    "Start Nomad with remote access, then run the check again.",
)
RESTART_NOMAD = _recovery(
    "RESTART_NOMAD", "APP_RUNTIME", REPO_OWNED,
    "Stop Nomad, start it again, then run the check again.",
)
CLOSE_CONFLICTING_APP = _recovery(
    "CLOSE_CONFLICTING_APP", "APP_RUNTIME", REPO_OWNED,
    "Close the conflicting local app, then run the check again.",
)
AUTHORIZE_THIS_MAC = _recovery(
    "AUTHORIZE_THIS_MAC", "DEVICE_SECURITY", EXTERNAL,
    "Approve Nomad for this Mac when prompted, then run the check again.",
)
UNLOCK_THIS_MAC = _recovery(
    "UNLOCK_THIS_MAC", "DEVICE_SECURITY", EXTERNAL,
    "Unlock your login keychain, then run the check again.",
)
REPAIR_MAC_IDENTITY = _recovery(
    "REPAIR_MAC_IDENTITY", "DEVICE_SECURITY", REPO_OWNED,
    "Collect diagnostics and contact support to repair this Mac's identity.",
)
PAIR_PHONE = _recovery(
    "PAIR_PHONE", "PAIRING", REPO_OWNED,
    "Start remote access and pair your phone, then run the check again.",
)
REVOKE_PHONE = _recovery(
    "REVOKE_PHONE", "PAIRING", REPO_OWNED,
    "Revoke the old phone before continuing.",
)
RESET_REMOTE_ACCESS = _recovery(
    "RESET_REMOTE_ACCESS", "PAIRING", REPO_OWNED,
    "Reset remote access and pair the phone again.",
)
RESTORE_BROWSER_ACCESS = _recovery(
    "RESTORE_BROWSER_ACCESS", "BROWSER_STORAGE", REPO_OWNED,
    "Reset remote access in this browser and pair the phone again.",
)
CONNECT_NETWORK = _recovery(
    "CONNECT_NETWORK", "NETWORK", REPO_OWNED,
    "Connect this Mac to the network you will use, then run the check again.",
)
INSTALL_CHROME = _recovery(
    "INSTALL_CHROME", "BROWSER", REPO_OWNED,
    "Install Google Chrome in Applications, then run the check again.",
)
CHOOSE_CERTIFICATE = _recovery(
    "CHOOSE_CERTIFICATE", "SECURE_CONNECTION", EXTERNAL,
    "Choose the certificate and key for remote access, then run the check again.",
)
TRUST_CERTIFICATE = _recovery(
    "TRUST_CERTIFICATE", "SECURE_CONNECTION", EXTERNAL,
    "Trust the remote-access certificate in Chrome without a bypass, then run the check again.",
)
RUN_AI_SERVICE_CHECK = _recovery(
    "RUN_AI_SERVICE_CHECK", "AI_SERVICE", EXTERNAL,
    "Complete the real AI service check before release.",
)
RUN_PHONE_CHECK = _recovery(
    "RUN_PHONE_CHECK", "PHONE", EXTERNAL,
    "Complete the test on a physical iPhone using Safari.",
)
RUN_FRESH_MAC_CHECK = _recovery(
    "RUN_FRESH_MAC_CHECK", "INSTALL_TEST", EXTERNAL,
    "Repeat the full install and use test on a fresh Mac.",
)
COMPLETE_APPLE_SIGNING = _recovery(
    "COMPLETE_APPLE_SIGNING", "APPLE_RELEASE", EXTERNAL,
    "Complete Apple Developer ID signing for this release.",
)
COMPLETE_APPLE_REVIEW = _recovery(
    "COMPLETE_APPLE_REVIEW", "APPLE_RELEASE", EXTERNAL,
    "Complete Apple notarization and security checks for this release.",
)
VERIFY_RELEASE_DOWNLOAD = _recovery(
    "VERIFY_RELEASE_DOWNLOAD", "DISTRIBUTION", EXTERNAL,
    "Verify that the downloaded release exactly matches the approved release.",
)
COLLECT_DIAGNOSTICS = _recovery(
    "COLLECT_DIAGNOSTICS", "SUPPORT", REPO_OWNED,
    "Collect diagnostics so support can review this problem.",
)
CONTACT_SUPPORT = _recovery(
    "CONTACT_SUPPORT", "SUPPORT", REPO_OWNED,
    "Collect diagnostics and contact support.",
)


def _map(codes: Iterable[str], recovery: Recovery, target: dict[str, Recovery]) -> None:
    for code in codes:
        if code in target:
            raise RuntimeError("DUPLICATE_RECOVERY_CODE")
        target[code] = recovery


_RECOVERY_BY_BLOCKER: dict[str, Recovery] = {}
_map((
    "RELEASE_BUNDLE_REQUIRED", "RELEASE_BUNDLE_DIGEST_NOT_VERIFIED",
    "HOST_IDENTITY_NOT_RUN_NO_VERIFIED_BUNDLE",
), INSTALL_NOMAD, _RECOVERY_BY_BLOCKER)
_map((
    "RELEASE_BUNDLE_VERIFY_FAILED", "CURRENT_BUNDLE_VERIFY_FAILED",
    "CONFIGURED_BUNDLE_VERIFY_FAILED", "CURRENT_BUNDLE_DIGEST_MISMATCH",
    "RUNTIME_BUNDLE_DIGEST_MISSING", "RUNTIME_BUNDLE_DIGEST_INVALID",
), REINSTALL_NOMAD, _RECOVERY_BY_BLOCKER)
_map((
    "RUNTIME_BUNDLE_BINDING_NOT_RUN", "SOURCE_BUILD_RUNTIME_NOT_RELEASE_ARTIFACT",
    "RUNTIME_PROCESSES_NOT_RUNNING", "REMOTE_RUNTIME_LIVE_PROBES_NOT_RUN",
    "RELAY_NOT_RUN",
), START_NOMAD, _RECOVERY_BY_BLOCKER)
_map((
    "RUNTIME_STATE_INVALID", "RUNTIME_BUNDLE_BINDING_NOT_VERIFIED",
    "RUNTIME_PROCESS_IDENTITY_NOT_VERIFIED", "RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED",
    "RUNTIME_ENDPOINT_BINDING_NOT_VERIFIED", "RUNTIME_IDENTITY_CHANGED_DURING_LIVE_PROBE",
    "RUNTIME_PORT_STATE_INVALID", "RUNTIME_PORT_LIVE_STATE_NOT_VERIFIED",
    "RUNTIME_PORTS_DO_NOT_MATCH_RUNNING_STATE", "RUNTIME_ROLE_LIVE_PROBE_FAILED",
    "PAIRING_RUNTIME_STATE_INVALID", "PAIRING_PROCESS_IDENTITY_NOT_VERIFIED",
    "PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED", "PAIRING_IDENTITY_CHANGED_DURING_LIVE_PROBE",
    "PRODUCT_HOST_PAIRING_LIVE_PROBE_FAILED", "RELAY_RUNTIME_STATE_INVALID",
    "RELAY_PROCESS_IDENTITY_NOT_VERIFIED", "LIVE_PROBE_IDENTITY_NOT_VERIFIED",
    "RELAY_IDENTITY_CHANGED_DURING_LIVE_PROBE", "RELAY_ROLE_LIVE_PROBE_FAILED",
    "LISTENER_PROCESS_BINDING_NOT_VERIFIED", "RUNTIME_STATE_PORT_BINDING_INVALID",
    "RELAY_V1_HEALTH_SCHEMA_INVALID", "RELAY_ADMIN_ROLE_SCHEMA_INVALID",
    "LIVE_PROBE_RESPONSE_TOO_LARGE", "LIVE_PROBE_TRANSPORT_FAILED",
    "LIVE_PROBE_HTTP_FRAMING_INVALID", "LIVE_PROBE_HTTP_STATUS_INVALID",
    "LIVE_PROBE_HTTP_SCHEMA_INVALID", "TLS_INPUTS_RUNTIME_STATE_INVALID",
), RESTART_NOMAD, _RECOVERY_BY_BLOCKER)
_map(("RUNTIME_PORT_IN_USE",), CLOSE_CONFLICTING_APP, _RECOVERY_BY_BLOCKER)
_map(("HOST_IDENTITY_AUTH_REQUIRED", "HOST_IDENTITY_USER_DENIED"), AUTHORIZE_THIS_MAC, _RECOVERY_BY_BLOCKER)
_map(("HOST_IDENTITY_KEYCHAIN_LOCKED",), UNLOCK_THIS_MAC, _RECOVERY_BY_BLOCKER)
_map((
    "HOST_IDENTITY_CORRUPT", "HOST_IDENTITY_UNAVAILABLE",
    "HOST_IDENTITY_PREFLIGHT_FAILED", "HOST_IDENTITY_PREFLIGHT_INVALID",
    "HOST_IDENTITY_PREFLIGHT_TIMEOUT",
), REPAIR_MAC_IDENTITY, _RECOVERY_BY_BLOCKER)
_map(("PAIRING_NOT_RUN",), PAIR_PHONE, _RECOVERY_BY_BLOCKER)
_map(("REMOTE_UNINSTALL_REVOKE_REQUIRED", "PAIRING_REVOKE_REQUIRED"), REVOKE_PHONE, _RECOVERY_BY_BLOCKER)
_map(("RESET_REMOTE_ACCESS_REQUIRED", "PAIRING_STORAGE", "PAIRING_CRYPTO"), RESET_REMOTE_ACCESS, _RECOVERY_BY_BLOCKER)
_map((
    "BROWSER_VAULT_MISSING", "BROWSER_VAULT_UNAVAILABLE",
    "BROWSER_VAULT_LOST",
), RESTORE_BROWSER_ACCESS, _RECOVERY_BY_BLOCKER)
_map(("NON_LOOPBACK_NETWORK_ADDRESS_MISSING",), CONNECT_NETWORK, _RECOVERY_BY_BLOCKER)
_map(("GOOGLE_CHROME_NOT_FOUND",), INSTALL_CHROME, _RECOVERY_BY_BLOCKER)
_map(("TLS_INPUTS_NOT_REVALIDATED", "TLS_INPUTS_NOT_PROVIDED_TO_DOCTOR"), CHOOSE_CERTIFICATE, _RECOVERY_BY_BLOCKER)
_map(("NORMAL_CHROME_TLS_TRUST_NOT_RUN",), TRUST_CERTIFICATE, _RECOVERY_BY_BLOCKER)
_map(("PROVIDER_E3_NOT_RUN", "PROVIDER_CREDENTIAL_SOURCE_NAME_NOT_PRESENT"), RUN_AI_SERVICE_CHECK, _RECOVERY_BY_BLOCKER)
_map(("PHYSICAL_PHONE_SAFARI_NOT_RUN",), RUN_PHONE_CHECK, _RECOVERY_BY_BLOCKER)
_map(("CLEAN_MACHINE_INSTALL_NOT_RUN",), RUN_FRESH_MAC_CHECK, _RECOVERY_BY_BLOCKER)
_map(("DEVELOPER_ID_SIGNING_NOT_RUN",), COMPLETE_APPLE_SIGNING, _RECOVERY_BY_BLOCKER)
_map(("APPLE_NOTARIZATION_NOT_RUN",), COMPLETE_APPLE_REVIEW, _RECOVERY_BY_BLOCKER)
_map(("PUBLICATION_PROVENANCE_NOT_RUN",), VERIFY_RELEASE_DOWNLOAD, _RECOVERY_BY_BLOCKER)
_map(("DIAGNOSTICS_RECOMMENDED",), COLLECT_DIAGNOSTICS, _RECOVERY_BY_BLOCKER)

KNOWN_RECOVERY_BLOCKER_CODES = frozenset(_RECOVERY_BY_BLOCKER)


def recovery_for_code(blocker_code: object) -> dict[str, str]:
    """Map one blocker to a fixed safe recovery action.

    Unknown or malformed input is intentionally not echoed.
    """

    recovery = (
        _RECOVERY_BY_BLOCKER.get(blocker_code, CONTACT_SUPPORT)
        if isinstance(blocker_code, str) else CONTACT_SUPPORT
    )
    return asdict(recovery)


def decorate_gate(gate: Mapping[str, Any]) -> dict[str, Any]:
    """Attach recovery fields to a non-PASS gate without trusting its text."""

    result = dict(gate)
    if result.get("status") == "PASS":
        return result
    recovery = recovery_for_code(result.get("code"))
    result.update(recovery)
    return result


def recovery_actions(gates: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Return ordered, de-duplicated actions for P8-H and diagnostics."""

    actions: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for gate in gates:
        if gate.get("status") == "PASS":
            continue
        action = recovery_for_code(gate.get("code"))
        key = (action["recovery_code"], action["scope"])
        if key not in seen:
            seen.add(key)
            actions.append(action)
    return actions


def recovery_report(gates: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Return the stable recovery API consumed by P8-H and diagnostics."""

    actions = recovery_actions(gates)
    return {
        "schema": RECOVERY_SCHEMA,
        "actions": actions,
        "primary": actions[0] if actions else None,
    }


__all__ = [
    "EXTERNAL", "KNOWN_RECOVERY_BLOCKER_CODES", "RECOVERY_SCHEMA",
    "REPO_OWNED", "decorate_gate", "recovery_actions",
    "recovery_for_code", "recovery_report",
]
