#!/usr/bin/env python3
"""Drive the installed M3-E product journey in real Google Chrome.

The caller must establish normal Chrome-profile certificate trust before
invoking this script. This script intentionally never enables Playwright's HTTPS bypass.
Its JSON output is content-free: no join material, comparison code, bearer,
session content, page text, URL fragment, or browser storage is emitted.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any


SCHEMA = "nomad.m3e.desktop-browser-evidence.v1"
LOOPBACK_DIAGNOSTIC_SCHEMA = "nomad.installed-loopback.browser-diagnostic.v1"
EXPECTED_CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


class BrowserEvidenceError(RuntimeError):
    def __init__(self, code: str, diagnostics: dict[str, Any] | None = None):
        super().__init__(code)
        self.diagnostics = diagnostics or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--desktop-url", required=True)
    parser.add_argument("--public-origin", required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, default=EXPECTED_CHROME)
    parser.add_argument("--timeout-ms", type=int, default=60_000)
    parser.add_argument("--diagnostic-spki-sha256")
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _runner_source_digest() -> str:
    injected = globals().get("__runner_raw_sha256__")
    if isinstance(injected, str) and re.fullmatch(r"[0-9a-f]{64}", injected):
        return injected
    return _sha256(Path(__file__))


def _result_schema(installed_loopback_phone_emulation: bool) -> str:
    return (
        LOOPBACK_DIAGNOSTIC_SCHEMA
        if installed_loopback_phone_emulation else SCHEMA
    )


def _page_modes(installed_loopback_phone_emulation: bool) -> list[str]:
    return (
        ["desktop", "phone-emulation"]
        if installed_loopback_phone_emulation else ["desktop", "desktop"]
    )


def _browser_mode_evidence(installed_loopback_phone_emulation: bool) -> dict[str, Any]:
    if not installed_loopback_phone_emulation:
        return {}
    return {"page_modes": _page_modes(True)}


def _is_write_command_post(url: str, method: str) -> bool:
    from urllib.parse import urlsplit

    return method == "POST" and urlsplit(url).path == "/api/commands"


def _diagnostic_write_command_evidence(
    installed_loopback_phone_emulation: bool, count: int,
) -> dict[str, int]:
    if not installed_loopback_phone_emulation:
        return {}
    if count != 0:
        raise BrowserEvidenceError(
            "diagnostic_write_command_observed",
            {"write_command_post_count": count},
        )
    return {"write_command_post_count": 0}


def _wait_text(page: Any, text: str, timeout: int) -> None:
    page.get_by_text(text, exact=False).first.wait_for(state="visible", timeout=timeout)


def _navigate_dynamic(page: Any, url: str, timeout: int) -> bool:
    """Navigate, then attempt networkidle before using rendered DOM readiness.

    The installed product intentionally runs a 100 ms long-poll loop. A strict
    networkidle wait therefore cannot be the terminal readiness condition, but
    the attempt is still made before DOM inspection as required by the browser
    test protocol.
    """
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    page.goto(url, wait_until="domcontentloaded", timeout=timeout)
    try:
        page.wait_for_load_state("networkidle", timeout=min(timeout, 3_000))
        return True
    except PlaywrightTimeoutError:
        return False


def _safe_page_diagnostics(
    page: Any, console_errors: int, request_failures: int, networkidle: dict[str, bool],
    response_facts: dict[str, dict[str, Any]], navigation_fact: dict[str, Any],
) -> dict[str, Any]:
    diagnostics: dict[str, Any] = {
        "console_error_count": console_errors,
        "request_failure_count": request_failures,
        "networkidle": {
            name: "OBSERVED" if observed else "CONTINUOUS_OR_UNREACHED"
            for name, observed in networkidle.items()
        },
        "desktop_navigation": navigation_fact,
        "allowlisted_responses": response_facts,
    }
    try:
        raw = page.evaluate(
            """() => ({
              ready_state: document.readyState,
              title: document.title,
              body_data_mode: document.body?.getAttribute('data-mode'),
              root_present: Boolean(document.getElementById('root')),
              root_child_count: document.getElementById('root')?.childElementCount ?? 0,
              button_count: document.querySelectorAll('button').length,
              alert_count: document.querySelectorAll('[role=alert]').length,
              status_count: document.querySelectorAll('[role=status]').length,
              loading_state_present: Array.from(document.querySelectorAll('[role=status]')).some((node) => (node.textContent || '').includes('Loading')),
              session_unavailable_present: Array.from(document.querySelectorAll('[role=alert]')).some((node) => (node.textContent || '').includes('Session unavailable')),
              remote_pairing_present: Array.from(document.querySelectorAll('h2')).some((node) => (node.textContent || '').trim() === 'Remote Pairing'),
              pairing_link_count: document.querySelectorAll('[aria-label=\"Pairing link\"]').length,
              paired_device_count: document.querySelectorAll('[data-testid=\"paired-device-card\"]').length,
              buttons: {
                pair_phone: Array.from(document.querySelectorAll('button')).some((node) => (node.getAttribute('aria-label') || node.textContent || '').trim() === 'Pair phone'),
                create_pairing: Array.from(document.querySelectorAll('button')).some((node) => (node.getAttribute('aria-label') || node.textContent || '').trim() === 'Create pairing'),
                codes_match: Array.from(document.querySelectorAll('button')).some((node) => (node.getAttribute('aria-label') || node.textContent || '').trim() === 'Codes match'),
                retry: Array.from(document.querySelectorAll('button')).some((node) => (node.getAttribute('aria-label') || node.textContent || '').trim() === 'Retry'),
                retry_connect: Array.from(document.querySelectorAll('button')).some((node) => (node.getAttribute('aria-label') || node.textContent || '').trim() === 'Retry connect'),
              },
            })"""
        )
        title = raw.pop("title", None)
        mode = raw.pop("body_data_mode", None)
        raw["title"] = title if title == "Nomad · Mobile Reference" else "UNEXPECTED"
        raw["body_data_mode"] = mode if mode in {None, "official-local", "desktop", "join"} else "UNEXPECTED"
        diagnostics.update(raw)
    except Exception:
        diagnostics["page_diagnostics_available"] = False
    return diagnostics


def _safe_phone_diagnostics(page: Any) -> dict[str, Any]:
    try:
        return page.evaluate(
            """() => {
              const exact = (selector, value) => Array.from(document.querySelectorAll(selector))
                .some((node) => (node.textContent || '').trim() === value);
              return {
                ready_state: document.readyState,
                secure_context: window.isSecureContext,
                connected: exact('h1', 'Remote session connected'),
                connecting: exact('h1', 'Connecting secure session'),
                retry_connect: Array.from(document.querySelectorAll('button')).some((node) => (node.textContent || '').trim() === 'Retry connect'),
                revoked: exact('h1', 'Phone access removed'),
                key_lost: exact('h1', 'Secure keys were lost'),
                storage_unavailable: exact('h1', 'Storage unavailable'),
                paired_facts_visible: document.querySelectorAll('.pairing-facts').length > 0,
                remote_session_panel: Boolean(document.getElementById('remote-session-title')),
              };
            }"""
        )
    except Exception:
        return {"page_diagnostics_available": False}


def _relay_request_category(url: str, method: str) -> str | None:
    from urllib.parse import urlsplit

    path = urlsplit(url).path
    if re.fullmatch(r"/v2/mailboxes/mbx-[0-9a-f]{64}/frames", path):
        return "frames_get" if method == "GET" else "frames_post" if method == "POST" else "frames_other"
    if re.fullmatch(r"/v2/mailboxes/mbx-[0-9a-f]{64}/acks", path):
        return "acks_post" if method == "POST" else "acks_other"
    return None


def _safe_network_error(error_text: str | None) -> str:
    if not error_text:
        return "UNKNOWN"
    match = re.search(r"(ERR_[A-Z0-9_]+)", error_text)
    return match.group(1) if match else "OTHER"


def _safe_exception_code(stage: str, error: BaseException) -> str:
    network = _safe_network_error(str(error))
    if network != "OTHER" and network != "UNKNOWN":
        return f"{stage}_{network}"
    return f"{stage}_{type(error).__name__}"


def _connected(page: Any, timeout: int) -> None:
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        if page.get_by_role("heading", name="Remote session connected").count():
            page.get_by_role("heading", name="Remote session connected").first.wait_for(
                state="visible", timeout=2_000
            )
            return
        retry = page.get_by_role("button", name="Retry connect")
        if retry.count() and retry.first.is_visible() and retry.first.is_enabled():
            retry.first.click()
        page.wait_for_timeout(250)
    raise BrowserEvidenceError("remote_projection_timeout")


def _sample_command_capability(page: Any) -> dict[str, Any]:
    raw = page.evaluate(
        """async () => {
          const samples = [];
          for (let index = 0; index < 6; index += 1) {
            try {
              const response = await fetch('/api/commands/capability', {
                method: 'GET', credentials: 'same-origin', headers: { accept: 'application/json' },
              });
              let code = null;
              try { code = (await response.json()).error ?? null; } catch {}
              samples.push({ status: response.status, code });
            } catch {
              samples.push({ status: 0, code: 'NETWORK_FAILURE' });
            }
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
          return samples;
        }"""
    )
    allowed = {"COMMAND_CAPABILITY_UNAVAILABLE", "COMMAND_GATEWAY_UNAVAILABLE", "NETWORK_FAILURE", None}
    statuses: dict[str, int] = {}
    codes: dict[str, int] = {}
    for item in raw if isinstance(raw, list) else []:
        status = item.get("status") if isinstance(item, dict) else None
        code = item.get("code") if isinstance(item, dict) else None
        status_key = str(status) if isinstance(status, int) else "invalid"
        safe_code = code if code in allowed else "UNEXPECTED"
        statuses[status_key] = statuses.get(status_key, 0) + 1
        if safe_code is not None:
            codes[safe_code] = codes.get(safe_code, 0) + 1
    alpha = page.evaluate(
        """async () => {
          try {
            const response = await fetch('/api/alpha/session', { headers: { accept: 'application/json' } });
            let schema = null;
            try { schema = (await response.json()).schema ?? null; } catch {}
            return { status: response.status, schema };
          } catch { return { status: 0, schema: null }; }
        }"""
    )
    allowed_schemas = {"nomad.alpha.readonly.v1", None}
    alpha_schema = alpha.get("schema") if isinstance(alpha, dict) else None
    return {
        "sample_count": len(raw) if isinstance(raw, list) else 0,
        "statuses": statuses, "codes": codes,
        "alpha_session": {
            "status": alpha.get("status") if isinstance(alpha, dict) else None,
            "schema": alpha_schema if alpha_schema in allowed_schemas else "UNEXPECTED",
        },
    }


def run(
    args: argparse.Namespace, *, _installed_loopback_phone_emulation: bool = False,
) -> dict[str, Any]:
    stage = "browser_preflight"
    if not args.chrome.is_file():
        raise BrowserEvidenceError("desktop_chrome_missing")
    if not args.desktop_url.startswith("http://127.0.0.1:"):
        raise BrowserEvidenceError("desktop_origin_invalid")
    if not args.public_origin.startswith("https://"):
        raise BrowserEvidenceError("public_origin_invalid")
    if args.diagnostic_spki_sha256 is not None:
        try:
            decoded_spki = base64.b64decode(args.diagnostic_spki_sha256, validate=True)
        except ValueError as error:
            raise BrowserEvidenceError("diagnostic_spki_invalid") from error
        if len(decoded_spki) != 32:
            raise BrowserEvidenceError("diagnostic_spki_invalid")
    if _installed_loopback_phone_emulation and args.diagnostic_spki_sha256 is None:
        raise BrowserEvidenceError("installed_loopback_phone_emulation_requires_spki")
    args.profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.profile, 0o700)

    from playwright.sync_api import sync_playwright

    console_errors = 0
    request_failures = 0
    networkidle = {"desktop": False, "join": False, "refresh": False, "revoke": False}
    response_facts: dict[str, dict[str, Any]] = {}
    navigation_fact: dict[str, Any] = {}
    relay_facts: dict[str, dict[str, Any]] = {}
    network_failure_codes: dict[str, int] = {}
    write_command_post_count = 0
    with sync_playwright() as playwright:
        # Do not add ignore_https_errors here or to a page/context. A successful
        # public navigation therefore proves normal Chrome certificate checks.
        stage = "chrome_launch"
        try:
            chrome_args = ["--no-first-run", "--no-default-browser-check"]
            if args.diagnostic_spki_sha256 is not None:
                chrome_args.append(
                    f"--ignore-certificate-errors-spki-list={args.diagnostic_spki_sha256}"
                )
            context = playwright.chromium.launch_persistent_context(
                str(args.profile),
                executable_path=str(args.chrome),
                headless=True,
                args=chrome_args,
            )
        except Exception as error:
            raise BrowserEvidenceError(f"{stage}_{type(error).__name__}") from error
        try:
            desktop = context.pages[0] if context.pages else context.new_page()
            phone = context.new_page()
            if _installed_loopback_phone_emulation:
                # This private, non-CLI path is only reachable from the
                # installed-loopback diagnostic runner after the SPKI gate
                # above. The CDP session is target-scoped, leaving the first
                # page as a desktop viewport.
                phone_session = context.new_cdp_session(phone)
                phone_session.send(
                    "Emulation.setDeviceMetricsOverride",
                    {
                        "width": 390, "height": 844,
                        "deviceScaleFactor": 3, "mobile": True,
                        "screenOrientation": {"type": "portraitPrimary", "angle": 0},
                    },
                )
                phone_session.send(
                    "Emulation.setTouchEmulationEnabled",
                    {"enabled": True, "maxTouchPoints": 5},
                )

            def count_console(message: Any) -> None:
                nonlocal console_errors
                if message.type == "error":
                    console_errors += 1

            def count_request(request: Any) -> None:
                nonlocal write_command_post_count
                if (
                    _installed_loopback_phone_emulation
                    and _is_write_command_post(request.url, request.method)
                ):
                    write_command_post_count += 1
                category = _relay_request_category(request.url, request.method)
                if category is not None:
                    fact = relay_facts.setdefault(category, {"requests": 0, "responses": {}, "failures": {}})
                    fact["requests"] += 1

            def count_failed_request(request: Any) -> None:
                nonlocal request_failures
                request_failures += 1
                code = _safe_network_error(request.failure)
                network_failure_codes[code] = network_failure_codes.get(code, 0) + 1
                category = _relay_request_category(request.url, request.method)
                if category is not None:
                    fact = relay_facts.setdefault(category, {"requests": 0, "responses": {}, "failures": {}})
                    fact["failures"][code] = fact["failures"].get(code, 0) + 1

            def record_response(response: Any) -> None:
                from urllib.parse import urlsplit

                path = urlsplit(response.url).path
                allowlist = {
                    "/api/alpha/session": "alpha_session",
                    "/api/commands/capability": "command_capability",
                    "/api/desktop/devices/current": "desktop_device_current",
                    "/api/desktop/pairing/create": "desktop_pairing_create",
                    "/api/desktop/pairing/status": "desktop_pairing_status",
                    "/api/pairing/join/start": "join_start",
                    "/api/pairing/join/confirm": "join_confirm",
                    "/api/pairing/join/complete": "join_complete",
                    "/api/pairing/join/abort": "join_abort",
                }
                key = allowlist.get(path)
                if key is not None:
                    response_facts[key] = {
                        "status": response.status,
                        "content_type": (response.headers.get("content-type") or "").split(";", 1)[0],
                    }
                category = _relay_request_category(response.url, response.request.method)
                if category is not None:
                    fact = relay_facts.setdefault(category, {"requests": 0, "responses": {}, "failures": {}})
                    status_key = str(response.status)
                    fact["responses"][status_key] = fact["responses"].get(status_key, 0) + 1

            # No raw messages or URLs are retained because either may contain
            # one-time join data.
            for page in (desktop, phone):
                page.on("console", count_console)
                page.on("request", count_request)
                page.on("requestfailed", count_failed_request)
                page.on("response", record_response)

            stage = "desktop_navigation"
            response = desktop.goto(args.desktop_url, wait_until="domcontentloaded", timeout=args.timeout_ms)
            navigation_fact.update({
                "status": response.status if response is not None else None,
                "content_type": ((response.headers.get("content-type") or "").split(";", 1)[0] if response is not None else ""),
            })
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            try:
                desktop.wait_for_load_state("networkidle", timeout=min(args.timeout_ms, 3_000))
                networkidle["desktop"] = True
            except PlaywrightTimeoutError:
                networkidle["desktop"] = False
            stage = "desktop_pair_button"
            pair = desktop.get_by_role("button", name="Pair phone")
            pair.wait_for(state="visible", timeout=args.timeout_ms)
            stage = "desktop_pair_click"
            pair.click()
            stage = "desktop_pairing_link"
            pairing_link = desktop.get_by_label("Pairing link")
            try:
                pairing_link.wait_for(state="visible", timeout=min(args.timeout_ms, 5_000))
            except PlaywrightTimeoutError as error:
                diagnostics = _safe_page_diagnostics(
                    desktop, console_errors, request_failures, networkidle, response_facts, navigation_fact
                )
                diagnostics["command_capability_samples"] = _sample_command_capability(desktop)
                raise BrowserEvidenceError(
                    "desktop_pairing_blocked_command_capability_unavailable", diagnostics
                ) from error
            join_url = pairing_link.input_value()
            if not join_url.startswith(args.public_origin + "/j/join-") or "#" not in join_url:
                raise BrowserEvidenceError("desktop_join_url_invalid")

            stage = "join_navigation"
            networkidle["join"] = _navigate_dynamic(phone, join_url, args.timeout_ms)
            stage = "join_compare_control"
            _wait_text(phone, "Only confirm if this code matches your Mac", args.timeout_ms)
            secure = phone.evaluate(
                "() => ({secure: window.isSecureContext, subtle: Boolean(globalThis.crypto?.subtle), indexedDb: Boolean(globalThis.indexedDB)})"
            )
            if secure != {"secure": True, "subtle": True, "indexedDb": True}:
                raise BrowserEvidenceError("secure_browser_capabilities_missing")

            phone_code = phone.locator(".pairing-code-block--phone strong").inner_text()
            desktop_code_locator = desktop.locator(
                "[data-testid='pairing-join-card'] .pairing-code-block strong"
            )
            desktop.wait_for_function(
                "node => /^[0-9]{6}$/.test((node?.textContent || '').trim())",
                arg=desktop_code_locator.element_handle(), timeout=args.timeout_ms,
            )
            desktop_code = desktop_code_locator.inner_text().strip()
            if len(phone_code) != 6 or not phone_code.isdigit() or phone_code != desktop_code:
                raise BrowserEvidenceError("comparison_code_mismatch")

            stage = "pairing"
            desktop.get_by_role("button", name="Codes match").click()
            phone.get_by_role("button", name="Confirm").click()
            stage = "projection"
            try:
                _connected(phone, args.timeout_ms)
            except BrowserEvidenceError as error:
                diagnostics = _safe_page_diagnostics(
                    desktop, console_errors, request_failures, networkidle, response_facts, navigation_fact
                )
                diagnostics["phone_state"] = _safe_phone_diagnostics(phone)
                diagnostics["relay_requests"] = relay_facts
                raise BrowserEvidenceError(str(error), diagnostics) from error
            phone.get_by_role("heading", name="Remote Session").wait_for(
                state="visible", timeout=args.timeout_ms
            )
            phone.locator("#task-status-title").wait_for(state="visible", timeout=args.timeout_ms)
            desktop.locator("[data-testid='paired-device-card']").wait_for(
                state="visible", timeout=args.timeout_ms
            )

            # Reload the same real page/profile. The resulting projection can
            # only reconnect if the BrowserVault IndexedDB state survived.
            stage = "refresh"
            current_url = phone.url
            networkidle["refresh"] = _navigate_dynamic(phone, current_url, args.timeout_ms)
            _connected(phone, args.timeout_ms)
            phone.locator("#task-status-title").wait_for(state="visible", timeout=args.timeout_ms)

            actions: dict[str, str] = {
                "view": "VERIFIED",
                "reply": "NOT_RUN",
                "deny": "NOT_RUN",
                "stop": "NOT_RUN",
            }
            reply = phone.get_by_role("button", name="Send reply")
            deny = phone.get_by_role("button", name="Deny request")
            stop = phone.get_by_role("button", name="Stop task")
            pending = {
                "reply": bool(reply.count() and reply.first.is_visible() and reply.first.is_enabled()),
                "deny": bool(deny.count() and deny.first.is_visible() and deny.first.is_enabled()),
                "stop": bool(stop.count() and stop.first.is_visible() and stop.first.is_enabled()),
            }
            # E6-D is not allowed to manufacture Agent pending state. Presence
            # is recorded, but write actions remain NOT_RUN in this canary run.

            stage = "revoke_open"
            desktop.get_by_role("button", name="Revoke phone").click()
            stage = "revoke_confirm"
            desktop.get_by_role("button", name="Revoke now").click()
            stage = "revoke_desktop_state"
            desktop.wait_for_function(
                """() => !document.querySelector('[data-testid=\"paired-device-card\"]')
                  && Array.from(document.querySelectorAll('[role=\"status\"]')).some(
                    (node) => (node.textContent || '').includes(
                      'Phone access was removed immediately.'))""",
                timeout=args.timeout_ms,
            )
            stage = "revoke_navigation"
            current_url = phone.url
            networkidle["revoke"] = _navigate_dynamic(phone, current_url, args.timeout_ms)
            stage = "revoke_phone_state"
            phone.get_by_role("heading", name="Phone access removed").wait_for(
                state="visible", timeout=args.timeout_ms
            )

            browser = context.browser
            diagnostic_write_evidence = _diagnostic_write_command_evidence(
                _installed_loopback_phone_emulation, write_command_post_count,
            )
            return {
                "schema": _result_schema(_installed_loopback_phone_emulation),
                "runner_raw_sha256": _runner_source_digest(),
                "status": "DIAGNOSTIC_COMPLETE" if args.diagnostic_spki_sha256 else "PASS",
                "browser": {
                    "product": "Google Chrome",
                    "version": browser.version if browser is not None else "unknown",
                    "executable_sha256": _sha256(args.chrome),
                    "headless": True,
                    "isolated_profile": True,
                    **_browser_mode_evidence(_installed_loopback_phone_emulation),
                },
                "https": {
                    "normal_verification": args.diagnostic_spki_sha256 is None,
                    "ignore_https_errors": False,
                    "diagnostic_tls_bypass": args.diagnostic_spki_sha256 is not None,
                    "spki_allowlist_count": 1 if args.diagnostic_spki_sha256 else 0,
                    "secure_context": True,
                },
                "journey": {
                    "join_shell": "VERIFIED",
                    "comparison_match": "VERIFIED",
                    "pairing": "VERIFIED",
                    "projection": "VERIFIED",
                    "refresh_recovery": "VERIFIED",
                    "revoke": "VERIFIED",
                    "revoked_browser_blocked": "VERIFIED",
                    "actions": actions,
                    "pending_agent_state_observed": pending,
                },
                "diagnostics": {
                    "console_error_count": console_errors,
                    "request_failure_count": request_failures,
                    "relay_requests": relay_facts,
                    "networkidle": {
                        name: "OBSERVED" if observed else "CONTINUOUS_LONG_POLL"
                        for name, observed in networkidle.items()
                    },
                },
                "content_free": True,
                **diagnostic_write_evidence,
            }
        except BrowserEvidenceError as error:
            if error.diagnostics:
                raise
            raise BrowserEvidenceError(str(error), _safe_page_diagnostics(
                desktop, console_errors, request_failures, networkidle, response_facts, navigation_fact
            ) | {
                "phone_state": _safe_phone_diagnostics(phone),
                "relay_requests": relay_facts,
                "network_failure_codes": network_failure_codes,
            }) from error
        except Exception as error:
            raise BrowserEvidenceError(
                _safe_exception_code(stage, error),
                _safe_page_diagnostics(desktop, console_errors, request_failures, networkidle, response_facts, navigation_fact) | {
                    "phone_state": _safe_phone_diagnostics(phone),
                    "relay_requests": relay_facts,
                    "network_failure_codes": network_failure_codes,
                },
            ) from error
        finally:
            context.close()


def main() -> int:
    args = parse_args()
    try:
        result = run(args)
    except Exception as error:
        result = {
            "schema": SCHEMA,
            "runner_raw_sha256": _runner_source_digest(),
            "status": "BLOCK",
            "code": str(error) if isinstance(error, BrowserEvidenceError) else type(error).__name__,
            "diagnostics": error.diagnostics if isinstance(error, BrowserEvidenceError) else {},
            "content_free": True,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
