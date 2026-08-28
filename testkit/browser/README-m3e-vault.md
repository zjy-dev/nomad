# M3-E browser vault proof

This proof exercises the real browser IndexedDB structured-clone path. It writes
non-extractable P-256 ECDSA and ECDH keys, closes the database connection, opens
a new vault connection, signs and verifies a random challenge, derives the ECDH
secret, and unwraps the device bearer.

## Reproducible runner

Requirements: uv, pnpm, and network access on the first run.

Run both browser proofs from the repository root:

    bash testkit/browser/run_m3e_vault_browser.sh

The runner pins Python Playwright through
requirements-m3e-vault-browser.txt at version 1.62.0. It uses an isolated uv
environment, installs the Chromium and WebKit revisions associated with that
Playwright release, starts Vite, runs both proofs, and shuts the server down.
Each PASS record reports the exact browser executable path. By default the
executables are stored under HOME/.cache/nomad-playwright-1.62.0; set
PLAYWRIGHT_BROWSERS_PATH to use a clean or CI-owned cache.

Useful commands:

    bash testkit/browser/run_m3e_vault_browser.sh --prepare-only
    bash testkit/browser/run_m3e_vault_browser.sh --browser chromium
    bash testkit/browser/run_m3e_vault_browser.sh --browser webkit
    python3 testkit/browser/m3e_vault_webkit.py --help

Direct execution of the Python proof requires the pinned Playwright environment.
If it is invoked without Playwright, it returns
M3E_BROWSER_BLOCK_PLAYWRIGHT_MISSING instead of an import traceback. Runner
bootstrap failures similarly return stable M3E_BROWSER_BLOCK codes.

This is engineering evidence against Playwright Chromium and WebKit. A physical
iPhone run remains NOT_RUN.
