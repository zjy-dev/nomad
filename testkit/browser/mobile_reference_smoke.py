#!/usr/bin/env python3
"""Browser smoke for the responsive Validation Mobile Reference."""

from pathlib import Path
from playwright.sync_api import sync_playwright


URL = "http://127.0.0.1:5173"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def main() -> None:
    console_errors = []
    page_errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=CHROME)
        page = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2)
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.goto(URL)
        page.wait_for_load_state("networkidle")

        trace_buttons = page.get_by_role("button", name=r"Load trace")
        assert trace_buttons.count() == 9, f"expected 9 traces, got {trace_buttons.count()}"
        page.get_by_role("button", name=r"Load trace trace-004-permission-competition").click()

        page.get_by_text("NEEDS PERMISSION — waiting on you").wait_for()
        page.get_by_text("HOST:ONLINE", exact=True).wait_for()
        page.get_by_text("CLIENT:LIVE", exact=True).wait_for()
        page.get_by_text("VERIFIED", exact=True).wait_for()

        page.get_by_role("button", name="Approval").click()
        page.get_by_text("`allow_once` is disabled in this build.", exact=True).wait_for()
        assert page.get_by_role("button", name="Deny permission request").is_enabled()
        assert page.get_by_role("button", name="Stop current turn instead of approving").is_enabled()
        assert page.get_by_role("button", name="Allow once", exact=True).count() == 0

        page.get_by_role("button", name="Timeline").click()
        page.get_by_text("permission.requested", exact=True).wait_for()
        assert page.locator(".t-node").count() == 3

        page.get_by_role("button", name="Changes").click()
        page.get_by_text("Changes", exact=True).first.wait_for()
        page.get_by_text("derived from diff.updated summary", exact=False).wait_for()

        screenshot = Path("/tmp/nomad-mobile-reference.png")
        page.screenshot(path=str(screenshot), full_page=True)
        assert screenshot.exists() and screenshot.stat().st_size > 0
        assert not console_errors, f"console errors: {console_errors}"
        assert not page_errors, f"page errors: {page_errors}"
        browser.close()

    print("MOBILE_REFERENCE_BROWSER_PASS traces=9 checkpoint=NeedsPermission timeline=3")
    print("screenshot=/tmp/nomad-mobile-reference.png")


if __name__ == "__main__":
    main()
