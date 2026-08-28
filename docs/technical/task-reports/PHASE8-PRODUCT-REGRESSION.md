# Phase 8 Product Regression (P8-G)

## Verdict

The journey harness is mechanical-local-non-provider regression coverage only. `repo_owned_status` and the compatibility `status` are PASS only when the lifecycle-owned checks and B C3 pass: install, onboarding, C3, diagnostics, reset, uninstall, and no owned residue. A is an external-readiness subjourney and is reported separately as `external_readiness` (`NOT_RUN` or `BLOCK` when TLS/identity control input is unavailable); it does not make the repo-owned status fail. The record always emits `production_ready: false`; external gates are explicitly `NOT_RUN`.

## Scope

The runner installs a verified bundle first, resolves the canonical selected path under the isolated HOME, and composes three subjourneys in order: B uses `c3_local_command_smoke.py` against that installed path and validates its exact mechanical marker/action/cleanup contract; A remains `NOT_RUN` unless the M3-E API receives operator-owned TLS descriptors in a controlled invocation; C completes diagnostics, reset, uninstall, and residue verification.

Missing Chrome/TLS/identity/helper prerequisites are BLOCK or NOT_RUN. Symbol existence and directory acceptance are never PASS. Evidence is canonical, content-free, mode 0600, atomically created with exclusive non-overwriting publication.

Provider credentials are outside this harness. Real Provider E3 remains `NOT_RUN`; no credential, session content, raw process output, or protected transcript is included in evidence.

## Executed evidence

- Focused passive-CDP browser tests: 4/4 PASS, including rejection of duplicate browser POST observations without wrapping or delaying the page's fetch implementation.
- Consecutive final passive-CDP real C3 runs: 2/2 PASS. Each run used the materialized Product Host, Gateway, Web bundle, headless Chrome, and a separate deterministic OpenCode-shape process. Each observed exactly one browser request, one browser response, and one upstream side effect for `reply`, `deny`, and `Stop`; the forced-uncertainty request had one upstream post and zero automatic retries.
- Product journey tests: 7/7 PASS, including a real verified install and complete lifecycle cleanup with no owned HOME residue.
- Launcher and C3 focused regression: 26/26 PASS.

These results are E2 mechanical evidence. They do not satisfy Provider E3, physical-phone, clean-machine, signing, notarization, or publication gates.

## Required future proof

To upgrade product readiness, execute Provider E3 against an official Agent child, physical-phone Safari, clean-machine installation, and the signed/notarized publication chain while preserving the content-free evidence contract.
