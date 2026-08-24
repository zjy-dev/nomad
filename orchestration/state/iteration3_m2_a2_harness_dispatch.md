# Iteration 3 M2 A2 Harness Integration Dispatch

**Sole Authority Dispatch** — *A2: Credential-Ready Harness Integration (No real A0 certificate required)*

## Executive Split

| Package | Scope | Requirement | Blocked Until |
|---------|-------|-------------|---------------|
| **A2** | Harness integration with locked launcher + ObservingProxy factory | Implementable/testable without credential | *Not blocked* — can ship immediately |
| **B/C** | Real capability verification and receipt emission from A0 certificate | Requires real `lifecycle-certificate.json` | **Strictly blocked** — no implementation until certificate exists |

## A2 Core Contract (6 packages, 1 new file, 3 modified files)

### Package A2.1: Harness integration with locked launcher (Python)
- **Owner**: harness (already owned by WP1)
- **New file**: `testkit/pilot/m2_integration.py`
- **Changes**:
  - Wire `launch_locked_opencode()` from `real_task_capture.py` to `ObservingProxy`
  - Create `ObservingProxy.for_locked_launch()` factory method (audit-only, uses `_TestAuthority`)
  - Add `socketpair()` anonymous pipe + secret binding (4-byte BE frame format, compat with `run_binding.rs`)
  - Prove FD creation/inheritance/close-on-exec behavior with dedicated child probe test
  - Harness-owned isolated tempdirs, FD management, process cleanup
  - Python `HostRunBinding` remains test/integration peer only — **no** real Rust Host FD adoption in A2
  - No capability unlock, no receipt emission, no certificate loading
- **Acceptance**: `pytest testkit/pilot/test_m2_integration.py -v` 12 tests PASS

### Package A2.2: No-credential test harness (Python)
- **Owner**: harness
- **New file**: `testkit/pilot/test_m2_no_credential.py`
- **Scope**:
  - Fake credential-free upstream stub for process lifecycle + FD delivery testing
  - Expected outcome: `BLOCKED_A0_CERTIFICATE_REQUIRED` from connector when it checks capabilities
  - Python peer demonstrates socket handshake but Rust Host remains blocked
  - No real OpenCode launch required for this test package
- **Acceptance**: `pytest testkit/pilot/test_m2_no_credential.py -v` 4 tests PASS

### Package A2.3: Mobile aliases environment wiring (Rust)
- **Owner**: connector
- **Changes**: `connector/src/bin/pilot_host_bridge.rs`
  - Add `--m2-stock-mode` flag to unlock command-line parsing (path still gated by capability check)
  - Wire `MobileAliases::from_environment()` to read `NOMAD_PILOT_ALIAS_KEY`
  - `run_m2_safe_mode()` **remains** `BLOCKED_A0_CERTIFICATE_REQUIRED` — no stock mode activation in A2
  - Real Rust Host FD adoption/stock mode activation is B/C and certificate-gated
- **Acceptance**: `cargo check --bin pilot-host-bridge` PASS

### Package A2.4: Harness receipt emission (Python)
- **Owner**: harness
- **Changes**: `testkit/iteration3_receipts.py`
  - Add `harness_proxy` and `harness_orchestrator` to `STAGE_BINDINGS` (already defined)
  - Append `credential_scope_violations` count receipt on leakage detection
  - No change to receipt schema — just wire harness process roles
- **Acceptance**: `pytest testkit/test_iteration3_receipts.py -v` 8 tests PASS

### Package A2.5: Credential scope audit (Python)
- **Owner**: harness
- **Changes**: `testkit/pilot/observing_proxy.py`
  - Add post-run credential absence scan — credential must not appear in:
    - Proxy memory after OpenCode launch
    - Harness logs or receipt store
  - Increment `credential_scope_violations` receipt count if found
  - Credential *only* allowed in OpenCode subprocess environment
- **Acceptance**: `pytest testkit/pilot/test_observing_proxy.py -v` 63 tests PASS (already A1-complete)

### Package A2.6: Relay readiness integration (Go)
- **Owner**: relay
- **Changes**: `relay/cmd/relay/main.go`
  - Add harness-controlled readiness handshake
  - Harness-owned log capture and cleanup
  - No envelope signing or capability verification changes
- **Acceptance**: `go build ./relay/cmd/relay` PASS

## B/C Blocked Work (Fail-closed only, no implementation until certificate)

### B1: Capability verification from A0 certificate (Rust)
- **Current state**: `connector/src/stock_opencode.rs`
  - `VerifiedM2Capabilities::from_receipts()` already returns `Err(RealLifecycleEvidence::Unavailable)`
  - `RealLifecycleEvidence` has only `Unavailable` variant
- **Constraint**: **NO** `include_str!` on missing `lifecycle-certificate.json` — compile-time fail is okay
  - Add `#[cfg(feature = "a0_certificate")]` gated implementation only
- **Unblock when**: real `lifecycle-certificate.json` exists in repository

### B2: Emission of M2 capability receipts (Rust + Python)
- **Blocked until**: B1 complete
- **Scope**: Extend `RealLifecycleEvidence` with `Captured` variant, populate capabilities from certificate

### C: End-to-end V2 verification
- **Blocked until**: B complete
- **Scope**: Full test with real credential and certificate

## Hard Constraints (All A2 packages)

1. **NO** production V2 enablement in A2
2. **NO** fabrication of certificate/capability/official receipts
3. **NO** capability unlock, receipt emission, or A0 certificate loading
4. Credential only enters OpenCode subprocess env — **NEVER** in proxy/Host/Relay/receipts/logs
5. All constrained paths must fail-closed with `BLOCKED_A0_CERTIFICATE_REQUIRED` when no credential

## Acceptance Command Sequence

```bash
# All A2 tests must pass
pytest testkit/pilot/test_observing_proxy.py -v
pytest testkit/pilot/test_m2_integration.py -v
pytest testkit/pilot/test_m2_no_credential.py -v
pytest testkit/test_iteration3_receipts.py -v
cargo check --bin pilot-host-bridge
go build ./relay/cmd/relay
```

## Line Count Target

- A2 total: ~250 lines new code, ~50 lines changes — fits in one focused worker slot

---

**Dispatch Status**: *Ready for implementation — all A2 packages unblocked*
