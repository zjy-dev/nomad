#!/usr/bin/env python3
"""390x844 browser smoke for the Controlled Pilot Mobile Web lane."""

from pathlib import Path
from playwright.sync_api import Page, sync_playwright


URL = "http://127.0.0.1:5173"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def assert_no_horizontal_overflow(page: Page) -> None:
    overflow = page.evaluate(
        "document.documentElement.scrollWidth - document.documentElement.clientWidth"
    )
    assert overflow == 0, f"horizontal overflow: {overflow}px"


def main() -> None:
    console_errors: list[str] = []
    page_errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=CHROME)
        page = browser.new_page(
            viewport={"width": 390, "height": 844}, device_scale_factor=2
        )
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        # Default deployment route requires the same-origin Gateway. Vite alone
        # must fail visibly instead of silently falling back to demo data.
        page.goto(URL)
        page.wait_for_load_state("networkidle")
        page.get_by_text("Session unavailable", exact=True).wait_for()
        assert page.get_by_text("The agent is waiting before a change", exact=True).count() == 0

        # Explicit demo route exercises the product UI without claiming a live
        # Gateway/Relay deployment.
        page.goto(f"{URL}/?demo=1")
        page.wait_for_load_state("networkidle")
        page.get_by_role(
            "heading", name="The agent is waiting before a change"
        ).wait_for()
        page.get_by_text("Online", exact=True).wait_for()
        page.get_by_text("Live", exact=True).wait_for()
        assert page.get_by_test_id("trace-lab").count() == 0
        assert page.get_by_role("button", name=r"Load trace").count() == 0
        assert_no_horizontal_overflow(page)

        # Pilot approval exposes Host facts and deny/Stop only.
        page.get_by_role("button", name="Action", exact=True).click()
        page.get_by_role("heading", name="Review request").wait_for()
        assert page.get_by_role("button", name="Deny request").is_enabled()
        assert page.get_by_role("button", name="Stop task instead").is_enabled()
        assert page.get_by_role("button", name=r"Allow").count() == 0
        assert "permission_id" not in page.locator("body").inner_text()
        assert "HC-" not in page.locator("body").inner_text()

        # No authoritative diff means empty — never sample files.
        page.get_by_role("button", name="Changes", exact=True).click()
        page.get_by_text("No verified changes yet", exact=True).wait_for()
        body = page.locator("body").inner_text()
        assert "src/app.tsx" not in body
        assert "derived from diff.updated" not in body
        assert_no_horizontal_overflow(page)

        product_screenshot = Path("/tmp/nomad-pilot-product.png")
        page.screenshot(path=str(product_screenshot), full_page=True)

        # Golden traces exist only at the explicit developer route.
        page.goto(f"{URL}/?lab=1")
        page.wait_for_load_state("networkidle")
        page.get_by_test_id("trace-lab").wait_for()
        trace_buttons = page.locator('[aria-label^="Load trace"]')
        assert trace_buttons.count() == 9, f"expected 9 traces, got {trace_buttons.count()}"
        page.get_by_role(
            "button", name=r"Load trace trace-007-version-mismatch"
        ).click()
        page.get_by_role("heading", name="Check this task").wait_for()
        page.get_by_text("Stale", exact=True).wait_for()
        page.get_by_role("button", name="Action", exact=True).click()
        page.get_by_text("Actions are paused", exact=True).wait_for()
        assert_no_horizontal_overflow(page)

        assert product_screenshot.exists() and product_screenshot.stat().st_size > 0
        assert not console_errors, f"console errors: {console_errors}"
        assert not page_errors, f"page errors: {page_errors}"
        browser.close()

    print("MOBILE_REFERENCE_BROWSER_PASS product=pilot lab=9 safety=stale viewport=390x844")
    print(f"screenshot={product_screenshot}")


if __name__ == "__main__":
    main()
