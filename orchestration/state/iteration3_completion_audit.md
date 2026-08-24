# Iteration 3 Completion Audit — Prompt-to-Artifact Checklist

**Audit date:** 2026-08-19
**Objective:** govern the transition from the synthetic/compatibility slice to a real-user product without treating readiness tests or fixtures as real evidence.

| Explicit requirement | Status | Current artifact/evidence | Missing proof |
| --- | --- | --- | --- |
| Product phase plan | **PASS** for governance entrance; **NO-GO** for product/Pilot/release | `iteration3_m2_entrance_gate.md` separates operator certification GO from all product work. | Same-run evidence, implementation slices, four-hop validation, and Pilot evidence. |
| Official locked OpenCode | **PARTIAL** | locked runtime, capture manifest, official contract, command-shape fixture verification | No Provider-backed lifecycle evidence pair. |
| Real lifecycle staged evidence | **NOT STARTED** | A0/A4.1/B0.1/B0.1c/B0.2a/A4.2 code and governance are independently ready | No Provider-backed same-run staged triple. |
| Temporary credential isolation | **PARTIAL** | isolated launcher and A1/A2 boundary tests | No real credential-scope audit. |
| Host → Relay → Gateway → Mobile | **NOT STARTED** | synthetic process loop and audit-only infrastructure | B0/B1/B2/C1/C2/D and a real four-hop slice remain blocked. |
| Content-free receipts | **PASS** for schema; **NOT STARTED** for real evidence | receipt schema/verifier tests | No live receipt store. |
| Controlled external user Pilot | **NOT STARTED** | Pilot planning artifacts | No approved real slice or observed user completion. |

## Verified Pre-real Gates

- A0/A4.1/B0.2a staged-bundle mechanics: 60 focused tests under ResourceWarning strict mode; staged-only, no final write or rollback; independent P0/P1/P2 zero.
- B0.1/B0.1c verifier and public derivation: 20 focused tests; renewed independent P0/P1/P2 zero.
- A4.2 shape-manifest verifier: 35 tests; read-only, pair-bound, and unable to unlock later work.
- A4.3 operator evidence governance: exact final/tmp preflight, narrow orphan rules, no glob cleanup, and local-candidate handling.
- A1 observing proxy/run-binding: 63 audit-only tests; production V2 remains blocked.
- A2 harness: 17 credential-ready tests; no Rust Host or real receipt claim.
- A3 certificate verifier: 22 read-only verifier tests.
- Full stock-opencode suite: 199 tests. `FIXTURE_LOCAL_ASSET_MISMATCH` remains fixture-local `BLOCKED`, not real lifecycle evidence.

## Current Hard Gate

The following conditions remain jointly required before B1/B2, C1/C2, D, the four-hop slice, Pilot, or release can start:

1. One real operator run creates the three staged certificate, shape, and evidence files from one authority and explicit reviewed_version; no final artifact is written.
2. A3, A4.2, and B0.1 independently verify that exact staged triple with exit 0 and stdout exactly `VERIFIED`.
3. An independent reviewer audits full pair digests, structural/source/provenance binding, current source bytes, and content-free compliance.
4. The user explicitly approves the exact complete staged triple and reviewed version.
5. Security DRI supplies externally governed B0.3b trust artifacts and signature; B0.3a verifies them.
6. B0.2c supplies a consistent immutable-bundle publication mechanism; until then publication is `BLOCKED_ATOMIC_PUBLISH`.

Fixtures, unit tests, schemas, capture manifests, official contracts, and shape fixtures cannot replace any condition above. Missing candidates and all certificate/manifest digest or binding mismatches fail closed.

## Next Executable Action

Follow `orchestration/state/iteration3_m2_operator_runbook.md` in this exact order:

1. Confirm all six fixed final/tmp paths are absent and choose explicit reviewed_version.
2. Operator performs the real temporary-credential run and obtains `CANDIDATE_STAGED`.
3. Independently run A3, A4.2, and B0.1 over the exact staged triple.
4. Perform the independent structural/source/provenance/content-free audit.
5. Obtain explicit user approval, then external B0.3b signature and B0.3a verification.
6. Keep publication and B1 blocked until B0.2c consistent-publication architecture passes.

Until then, real evidence is **NOT STARTED** and every later product gate remains fail-closed.
