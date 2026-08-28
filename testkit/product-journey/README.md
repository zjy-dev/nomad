# P8-G product regression journey

The runner accepts a source bundle, installs and verifies it, then emits one content-free parent evidence record over the canonical installed bundle. It does not probe symbols or treat directory existence as success.

- A invokes run_m3e_product_slice.py against the exact installed bundle and requires real TLS/identity inputs.
- B invokes c3_local_command_smoke.py through its run_smoke API. It starts materialized Product Host/Gateway/Web/Chrome plus deterministic external OpenCode-shape and covers reply, deny, Stop, idempotency, and OutcomeUnknown.
- C invokes real install lifecycle and onboarding APIs in an isolated HOME, passes the selected `home/bundles/<digest>` path to B and A, then runs diagnostics, reset, uninstall, and residue verification.

Missing Chrome, TLS, identity, or helper prerequisites produce explicit BLOCK/NOT_RUN. No crypto or product startup logic is copied, and no synthetic PASS is produced.

The parent `repo_owned_status`/`status` covers only the mechanical B+C result: install, onboarding, C3, diagnostics, reset, uninstall, and no residue. A is reported separately as `external_readiness` and may be `NOT_RUN` or `BLOCK` when TLS/identity control input is unavailable. External gates remain `NOT_RUN`, and `production_ready` is always false.

Evidence is canonical JSON, content-free, mode 0600, atomically published without overwriting an existing destination.
