# Iteration 3 M2 A2 Harness Atomic Dispatch

**Sole Authority** — *One atomic package, no modifying existing files*

## Scope

One new file `testkit/pilot/m2_integration.py` and one new test file `testkit/pilot/test_m2_integration.py`. No changes to `observing_proxy.py`, `receipts.py`, any Rust, any Relay, existing verifier/transcript.

## A2: `M2IntegrationHarness` (audit-only, no certificate/capability)

### Design

`M2IntegrationHarness` is a single audit-only class that:

- **Accepts injected launcher callable and proxy factory**. The production entry uses existing `launch_locked_opencode()` only when an allowlisted temporary credential exists (checked via `credential_present()`). The proxy factory receives the upstream origin and returns a normal production `ObservingProxy` (V2 permanently blocked at `Decision(403, 'BLOCKED_A0_CERTIFICATE_REQUIRED')`).
- **Owns all temp resources** (tempdirs for proxy, launcher, logs) and implements `__enter__`/`__exit__` for exact cleanup, including on any exception during setup.
- **Does NOT spawn a real Rust Host**. Creates bidirectional `socketpair()` + one-way 32-byte secret `os.pipe()`. Sets `CLOEXEC` and/or `set_inheritable(False)` on all non-child ends. Only the explicit child-probe inherits the relevant FDs.
- **Uses a dedicated child probe** (or Python `HostRunBinding` in tests only) to prove FD delivery and framing. Labels the result `TEST_PEER_ONLY` — this is never evidence of Rust Host integration.
- **No credential value in args, results, logs, or exceptions**. The existing launcher reads the provided source env transiently; only the OpenCode subprocess environment receives the provider variable among launched product processes.

### Acceptance test shape (12 tests, stdlib `unittest` only)

| # | Test | Expected |
|---|------|----------|
| 1 | Fake launcher, no credential | `BLOCKED` |
| 2 | Injected environment, credential present, fake upstream | Launcher called, proxy created |
| 3 | Real FDs created, non-child ends CLOEXEC/non-inheritable | FDs open on parent, closed in unrelated child |
| 4 | Child probe receives inherited FDs, can read secret | `TEST_PEER_ONLY` — framing verified |
| 5 | Secret exactly 32 bytes, no frame exposure | `len(secret) == 32` |
| 6 | Normal production proxy, no credential | `BLOCKED_A0_CERTIFICATE_REQUIRED` |
| 7 | Cleanup on exception during setup | No dangling process/thread/tempdir |
| 8 | Cleanup on successful exit | No dangling process/thread/tempdir |
| 9 | Dry-run flag, no credential | `BLOCKED` |
| 10 | Credential path calls launcher but cannot PASS product | Launcher invoked, result still blocked |
| 11 | No credential value in harness args/results | Credential absent from all harness outputs |
| 12 | No credential value in logs/exceptions | Credential absent from all log output |

### Constraints

1. **NO** `_TestAuthority` in production. Harness uses normal `ObservingProxy` constructor.
2. **NO** production V2 enablement. `ObservingProxy` already permanently blocks V2.
3. **NO** certificate, capability, or official receipt fabrication.
4. **NO** credential value in args, results, logs, or exceptions.
5. `set_inheritable(True)` only on explicit child-probe FD ends.
6. `socketpair()` and `pipe()` always created with `close_fds=True` semantics on parent.

### Files owned

| File | Owner | Status |
|------|-------|--------|
| `testkit/pilot/m2_integration.py` | harness | Create |
| `testkit/pilot/test_m2_integration.py` | harness | Create |

### Acceptance

```bash
pytest testkit/pilot/test_m2_integration.py -v
# 12 tests PASS, no changes to existing files, no regressions
```

## B/C (blocked)

No code until a real A0 `lifecycle-certificate.json` exists. `connector/src/stock_opencode.rs` already returns `Err(RealLifecycleEvidence::Unavailable)` which is the correct fail-closed. No `include_str!` on a missing file. No Rust Host FD adoption, no stock-mode activation, no capability verification, no receipt emission, no end-to-end V2.