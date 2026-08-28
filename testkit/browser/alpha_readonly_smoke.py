#!/usr/bin/env python3
"""Headless-Chrome smoke for the real local Alpha read-only stack.

This uses the deterministic OpenCode interface substitute and proves browser
mechanics only. It is not Pilot, Provider, or production evidence.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from playwright.sync_api import Page, sync_playwright

from testkit.pilot.run_alpha_readonly_slice import (
    KEY_ENV,
    LOCAL_TEST_PRIVATE_KEY,
    SOURCE,
    TOKEN_ENV,
    ManagedProcess,
    RouteRecorder,
    fail,
    free_port,
    minimal_env,
    run_build,
    scan_mobile_build,
    wait_http,
)

MARKER = "LOCAL_ALPHA_READONLY_BROWSER_PASS"
DEFAULT_SCREENSHOT = Path("/tmp/nomad-alpha-readonly-browser.png")
DEFAULT_CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


def assert_readonly_dom(page: Page) -> None:
    page.get_by_text("READ-ONLY ALPHA", exact=True).wait_for()
    page.get_by_text("Online", exact=True).wait_for()
    page.get_by_text("Live", exact=True).wait_for()
    body = page.locator("body").inner_text()
    if "Read-only Alpha" not in body:
        fail("READONLY_LABEL_MISSING")
    labels = page.locator("button").all_inner_texts()
    if any(any(word in label for word in ("Action", "Stop", "Reply")) for label in labels):
        fail("READONLY_COMMAND_CONTROL_VISIBLE")
    if page.get_by_text("Golden traces", exact=True).count() != 0:
        fail("TRACE_LAB_VISIBLE_BY_DEFAULT")
    if page.locator('[aria-label="Reply to agent"]').count() != 0:
        fail("REPLY_CONTROL_VISIBLE")


def run_browser_smoke(
    repo: Path, timeout: float, screenshot: Path, chrome: Path
) -> dict[str, object]:
    if not chrome.is_file():
        fail("CHROME_MISSING")
    relay_port, gateway_port = free_port(), free_port()
    token = "alpha-browser-token-" + __import__("secrets").token_hex(24)
    processes: list[ManagedProcess] = []
    stopped: list[ManagedProcess] = []
    recorder: RouteRecorder | None = None

    with tempfile.TemporaryDirectory(prefix="nomad-alpha-browser-") as temporary:
        temp = Path(temporary)
        relay_binary = temp / "nomad-relay"
        relay_db = temp / "relay.sqlite3"
        gateway_db = temp / "gateway.sqlite3"
        run_build(
            ["go", "build", "-o", str(relay_binary), "./cmd/relay"],
            repo / "relay",
            timeout,
        )
        run_build(
            ["cargo", "build", "--quiet", "--bin", "alpha-projector"],
            repo / "connector",
            timeout,
        )
        run_build(["npm", "run", "build"], repo / "mobile-reference", timeout)
        projector_binary = repo / "connector" / "target" / "debug" / "alpha-projector"
        node = shutil.which("node")
        if not projector_binary.is_file() or not node:
            fail("BUILD_OUTPUT_MISSING")
        scan_mobile_build(
            repo / "mobile-reference" / "dist", (token, LOCAL_TEST_PRIVATE_KEY)
        )

        def launch(
            name: str, command: list[str], cwd: Path, environment: dict[str, str]
        ) -> ManagedProcess:
            process = ManagedProcess(name, command, cwd, environment)
            processes.append(process)
            return process

        try:
            fake = launch(
                "synthetic-opencode",
                [
                    sys.executable,
                    "testkit/fake-opencode/server.py",
                    "--scenario",
                    "happy",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "4096",
                ],
                repo,
                minimal_env({"PYTHONDONTWRITEBYTECODE": "1"}),
            )
            wait_http("http://127.0.0.1:4096/global/health", timeout)
            if fake.process.poll() is not None:
                fail("SYNTHETIC_SOURCE_NOT_OWNED")

            relay = launch(
                "relay",
                [
                    str(relay_binary),
                    "-addr",
                    f"127.0.0.1:{relay_port}",
                    "-db",
                    str(relay_db),
                    "-alpha-local",
                    "-alpha-token-env",
                    TOKEN_ENV,
                ],
                repo / "relay",
                minimal_env({TOKEN_ENV: token}),
            )
            wait_http(f"http://127.0.0.1:{relay_port}/health", timeout)
            recorder = RouteRecorder(relay_port)
            recorder.start()

            projector_command = [
                str(projector_binary),
                "--relay-url",
                recorder.origin,
                "--session-id",
                "pilot-session",
            ]
            projector = subprocess.run(
                projector_command,
                cwd=repo / "connector",
                env=minimal_env({KEY_ENV: LOCAL_TEST_PRIVATE_KEY}),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            projector_surface = (
                b"\0".join(item.encode() for item in projector_command)
                + projector.stdout
                + projector.stderr
            )
            if (
                projector.returncode != 0
                or projector.stderr
                or token.encode() in projector_surface
                or LOCAL_TEST_PRIVATE_KEY.encode() in projector_surface
            ):
                fail("PROJECTOR_FAILED")

            gateway = launch(
                "gateway",
                [
                    node,
                    "pilot-gateway/server.mjs",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(gateway_port),
                    "--relay-url",
                    recorder.origin,
                    "--state-db",
                    str(gateway_db),
                    "--dist-dir",
                    str(repo / "mobile-reference" / "dist"),
                ],
                repo / "mobile-reference",
                minimal_env({TOKEN_ENV: token}),
            )
            gateway_base = f"http://127.0.0.1:{gateway_port}"
            wait_http(gateway_base + "/", timeout)

            requests: list[tuple[str, str]] = []
            responses: Counter[tuple[str, int]] = Counter()
            console_errors: list[str] = []
            page_errors: list[str] = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True, executable_path=str(chrome)
                )
                page = browser.new_page(
                    viewport={"width": 390, "height": 844}, device_scale_factor=2
                )
                page.on(
                    "request",
                    lambda request: requests.append(
                        (request.method, urlsplit(request.url).path)
                    ),
                )
                page.on(
                    "response",
                    lambda response: responses.update(
                        [(urlsplit(response.url).path, response.status)]
                    ),
                )
                page.on(
                    "console",
                    lambda message: console_errors.append(message.text)
                    if message.type == "error"
                    else None,
                )
                page.on("pageerror", lambda error: page_errors.append(str(error)))

                try:
                    page.goto(gateway_base + "/", wait_until="networkidle")
                    assert_readonly_dom(page)
                except Exception as error:
                    if error.__class__.__name__ == "SliceFailure":
                        raise
                    alpha_statuses = sorted(
                        status
                        for (path, status), count in responses.items()
                        if path == "/api/alpha/session"
                        for _ in range(count)
                    )
                    if 200 not in alpha_statuses:
                        encoded = "_".join(str(status) for status in alpha_statuses)
                        fail(
                            f"DEFAULT_ALPHA_RESPONSES_{len(alpha_statuses)}"
                            + (f"_{encoded}" if encoded else "_NONE")
                        )
                    fail("DEFAULT_BROWSER_ASSERTION_FAILED")
                default_requests = list(requests)
                default_alpha_requests = default_requests.count(
                    ("GET", "/api/alpha/session")
                )
                if default_alpha_requests < 1:
                    fail("DEFAULT_ALPHA_ROUTE_COUNT")
                if any(path.startswith("/api/pilot") for _, path in default_requests):
                    fail("DEFAULT_PILOT_ROUTE_USED")
                if console_errors or page_errors:
                    fail("DEFAULT_BROWSER_RUNTIME_ERROR")
                screenshot.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(screenshot), full_page=True)

                relay.stop()
                stopped.append(relay)
                console_errors.clear()
                page.get_by_text("Refresh", exact=True).click()
                page.get_by_text("Session unavailable", exact=True).wait_for(timeout=10_000)
                if page.get_by_text("Online", exact=True).count() != 0:
                    fail("STALE_ONLINE_VIEW")
                if page.get_by_text("Live", exact=True).count() != 0:
                    fail("STALE_LIVE_VIEW")
                if not any(
                    path == "/api/alpha/session" and status == 503
                    for path, status in responses
                ):
                    fail("REFRESH_503_NOT_OBSERVED")
                if page_errors:
                    fail("REFRESH_PAGE_ERROR")
                # Chrome reports the deliberately injected HTTP 503 as a
                # console network error. It is expected only in this phase.
                expected_console = (
                    "Failed to load resource: the server responded with a status of 503 "
                    "(Service Unavailable)"
                )
                if console_errors != [expected_console]:
                    fail("REFRESH_CONSOLE_ERROR_SET")
                console_errors.clear()

                try:
                    page.goto(gateway_base + "/?demo=1", wait_until="networkidle")
                    page.get_by_text("DEMO DATA", exact=True).wait_for()
                    page.goto(gateway_base + "/?lab=1", wait_until="networkidle")
                    page.get_by_text("TRACE LAB", exact=True).wait_for()
                    page.get_by_text("Golden traces", exact=True).wait_for()
                except Exception:
                    fail("EXPLICIT_FIXTURE_MODE_ASSERTION_FAILED")

                if any(path.startswith("/api/pilot") for _, path in requests):
                    fail("BROWSER_PILOT_ROUTE_USED")
                total_alpha_requests = requests.count(
                    ("GET", "/api/alpha/session")
                )
                if total_alpha_requests != default_alpha_requests + 1:
                    fail("BROWSER_ALPHA_ROUTE_COUNT")
                if console_errors or page_errors:
                    fail("BROWSER_RUNTIME_ERROR")
                browser.close()

            if not screenshot.is_file() or screenshot.stat().st_size == 0:
                fail("SCREENSHOT_MISSING")
            if recorder.routes != Counter({
                ("POST", "/v1/frame"): 1,
                ("GET", "/v1/frames"): 2,
                ("POST", "/v1/ack"): 1,
            }):
                fail("RELAY_ROUTE_SET")
            if any(path.startswith("/v1/test/") for _, path in recorder.routes):
                fail("TEST_ROUTE_USED")

            return {
                "marker": MARKER,
                "source": SOURCE,
                "production_ready": False,
                "pilot_ready": False,
                "screenshot": str(screenshot),
                "evidence": {
                    "default_alpha_requests": default_alpha_requests,
                    "total_alpha_requests": total_alpha_requests,
                    "pilot_requests": 0,
                    "relay_test_routes": 0,
                    "relay_stopped_refresh_unavailable": True,
                    "readonly_controls_absent": True,
                    "demo_label": True,
                    "trace_lab_label": True,
                },
            }
        finally:
            for process in reversed(processes):
                if process not in stopped:
                    process.stop()
                    stopped.append(process)
            if recorder is not None:
                recorder.close()
            secrets_to_reject = (token.encode(), LOCAL_TEST_PRIVATE_KEY.encode())
            for process in stopped:
                surface = b"\0".join(item.encode() for item in process.command) + process.output
                if any(secret in surface for secret in secrets_to_reject):
                    fail("CHILD_SECRET_EXPOSURE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--screenshot", type=Path, default=DEFAULT_SCREENSHOT)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    args = parser.parse_args()
    try:
        result = run_browser_smoke(
            args.repo.resolve(), args.timeout, args.screenshot.resolve(), args.chrome.resolve()
        )
    except Exception as error:
        code = str(error) if error.__class__.__name__ == "SliceFailure" else "INTERNAL_FAILURE"
        print(
            json.dumps(
                {
                    "marker": "LOCAL_ALPHA_READONLY_BROWSER_FAIL",
                    "source": SOURCE,
                    "production_ready": False,
                    "pilot_ready": False,
                    "error": code,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
