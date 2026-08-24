# Iteration 3 M2 Entrance Gate

**Decision date**: 2026-08-19 | **Governance artifact** — not a product PASS

## Objective

Transition from synthetic/compatibility engineering (Stage 1 / M1) to one operator-run A0 real lifecycle certification. The only GO in this record is entry to that controlled operator action. Product implementation, the Host → Relay → Gateway → Mobile slice, Pilot, and release remain NO-GO until the complete same-run evidence bundle is independently reviewed and explicitly approved.

## Supported Runtime & Platform

| Dimension | Value |
|-----------|-------|
| OpenCode | `1.18.16` (frozen) |
| npm | `11.12.1` (exact, `EXPECTED_NPM_VERSION`) |
| OS | macOS (Darwin) |
| Arch | `arm64` |
| Locked deps | 13 (full), 2 (installed platform) |
| Provider env allowlist | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY` |

## Evidence Table

All passing test counts below are **proxy evidence**: they prove readiness and fail-closed behavior, never that a real Provider-backed session has completed.

| Gate | Status | Key Evidence | Command |
|------|--------|-------------|---------|
| **M1**: Stock facts / synthetic loop | PASS | Current Rust suite and Stage 1 acceptance | `cargo test --manifest-path connector/Cargo.toml` |
| **Pre-real**: Locked runtime, shape fixture, capture manifest | PASS | `capture-manifest.json`, `official-stock-contract.json`, locked OpenCode 1.18.16 | `python3 -W error::ResourceWarning -m unittest discover -s testkit/stock-opencode -p 'test_*capture.py'` |
| **A0/A4.1/B0.2a**: Real lifecycle staged-bundle code-ready | PASS | staged-only same-run certificate, shape, and evidence mechanics; 60 focused tests; independent P0/P1/P2 zero | `python3 -W error::ResourceWarning -m unittest testkit/stock-opencode/test_discover_lifecycle.py -v` |
| **A4.2**: Read-only shape-manifest verifier | PASS | 35 verifier tests; exact pair validation, no unlock authority | `python3 -m unittest testkit/stock-opencode/test_verify_shape_manifest.py -v` |
| **A4.3**: Operator evidence governance | PASS | exact final/tmp preflight, narrow orphan handling, same-run candidate-bundle runbook | `git diff --check -- orchestration/state/iteration3_m2_operator_runbook.md` |
| **A1**: Observing proxy (audit-only) | PASS | 63 proxy tests; production V2 remains blocked | `python3 -m unittest testkit.pilot.test_observing_proxy -v` |
| **A2**: Credential-ready harness | PASS | 17 harness tests; FD delivery, credential isolation, cleanup | `python3 -m unittest testkit.pilot.test_m2_integration -v` |
| **A3**: Certificate verifier | PASS | 22 read-only verifier tests | `python3 -m unittest testkit/stock-opencode/test_verify_certificate.py -v` |
| **B0.1/B0.1c**: Evidence verifier and public derivation | PASS | 20 focused tests; renewed independent audit P0/P1/P2 zero | `python3 -m unittest testkit/stock-opencode/test_verify_evidence_manifest.py -v` |
| **B0.3a**: External SSHSIG approval verifier | PASS | 33 focused tests; no trust-bootstrap or signing authority | `python3 -m unittest testkit/stock-opencode/test_verify_approval_record.py -v` |
| **Full stock-opencode suite** | PASS | 199 tests; fixture-local failures remain fail-closed | `python3 -m unittest discover -s testkit/stock-opencode -p 'test_*.py' -q` |
| **Real same-run evidence pair** | NOT STARTED | No production certificate, shape manifest, or temporary credential has been used | Operator-only runbook action |

`FIXTURE_LOCAL_ASSET_MISMATCH` is a fixture-local `BLOCKED` result from fixture verification. It is not real lifecycle evidence, not a product failure, and not a substitute for the controlled operator certification.

## Hard Distinction

| Decision | Scope | Condition |
|----------|-------|-----------|
| **ENTRY TO REAL STAGED CANDIDATE** | **GO** | Operator follows the runbook with explicit reviewed_version and one temporary allowlisted credential after all six final/tmp paths are absent. |
| **M2 PRODUCT / PILOT / RELEASE** | **NO-GO** | No same-run pair, no dual real verifier result, no independent binding audit, no user approval, and no B0/B1/B2/C1/C2/D or four-hop evidence. |

Fixtures, schemas, test output, `capture-manifest.json`, and `official-stock-contract.json` do not substitute for a real same-run pair.

## Required Same-Run Evidence Checklist

The operator may proceed only after preflight confirms all six exact paths are absent:

- `testkit/stock-opencode/real-task/lifecycle-certificate.json`
- `testkit/stock-opencode/real-task/lifecycle-shape-manifest.json`
- `testkit/stock-opencode/real-task/lifecycle-certificate.json.tmp`
- `testkit/stock-opencode/real-task/lifecycle-shape-manifest.json.tmp`
 - `testkit/stock-opencode/lifecycle-evidence-manifest.json`
 - `testkit/stock-opencode/lifecycle-evidence-manifest.json.tmp`

A real run may create only the three staged files from one authority. No final path is written. A separate reviewer must establish A3, A4.2, and B0.1 exact `VERIFIED`, the full structural/source/provenance binding, content-free compliance, and the explicit reviewed version.

1. A3 exact CLI result: `verify_certificate.py <certificate>` exits 0 and prints exactly `VERIFIED`.
2. A4.2 exact CLI result: `verify_shape_manifest.py <manifest> <certificate>` exits 0 and prints exactly `VERIFIED`.
3. Independent structural cross-binding audit: `shape.certificate_structural_digest == certificate.structural_digest`.
4. Independent source-binding audit over the canonical certificate structural, launch provenance, task-spec, fixture-manifest, command-shapes, and rule-config digests.
5. Explicit user approval of the complete production evidence bundle: both files, both verifier results, binding audit, and locked-runtime/source bindings.

## Fail-Closed Orphan Rules

| Code | Trigger | Recovery |
|------|---------|----------|
| `BLOCKED_CERTIFICATE_ALREADY_EXISTS` | certificate final exists | Stop; do not overwrite or automatically remove it. |
| `BLOCKED_SHAPE_ALREADY_EXISTS` / `BLOCKED_EVIDENCE_ALREADY_EXISTS` | another final exists | Stop and preserve it; no automatic or runbook deletion. |
| `BLOCKED_CERTIFICATE_TMP_EXISTS` / `BLOCKED_SHAPE_TMP_EXISTS` / `BLOCKED_EVIDENCE_TMP_EXISTS` | a staged file exists | Stop and preserve it; no cleanup or reuse. |
| `BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED` | selected env var is absent or not allowlisted | Set one temporary allowlisted variable locally; never record its value. |
| `BLOCKED_WORKSPACE_CLEANUP_INCOMPLETE` | controlled process/disposable paths remain | Stop and inspect only exact controlled paths. |
| `FAIL_CERTIFICATE_*` or `FAIL_MANIFEST_*` | A3 or A4.2 rejects the candidate | Fail closed; regenerate a new same-run pair after review. |

No glob, recursive deletion, or automatic cleanup may remove a pre-existing final or tmp artifact.

## Required Sequence After Certification

```text
six-path preflight + explicit reviewed_version
  → operator real run (same-run staged certificate + shape)
  → A3 exact VERIFIED
  → A4.2 exact VERIFIED
  → B0.1c derive staged evidence + B0.1 exact VERIFIED
  → independent structural/source-binding audit
  → explicit user approval of complete bundle
  → B0.3b external signature + B0.3a exact VERIFIED
  → B0.2c consistent-publication gate
  → B1 capability verification and B2 semantic mapper
  → C1 safe-mode bridge and C2 exact receipts
  → D real Host → Relay → Gateway → Mobile verification
  → Pilot decision
```

The sequence does not authorize the old certificate-only B2 receipt-emission interpretation. B2 is the semantic mapper and cannot begin from fixtures or a certificate alone.

## Completion Checklist

| Item | Owner | Evidence | Status |
|------|-------|----------|--------|
| A0/A4.1/B0.2a staged bundle | A0/A4.1/B0.2a | 60 focused tests, 199 full; independent PASS | DONE |
| B0.1/B0.1c evidence verification/derivation | B0.1/B0.1c | 20 focused tests; independent PASS | DONE |
| A4.2 shape verifier | A4.2 | 35 tests | DONE |
| A4.3 runbook governance | A4.3 | exact-path preflight/orphan rules and reviewed runbook | DONE |
| A1 audit-only proxy | A1 | 63 tests | DONE |
| A2 credential-ready harness | A2 | 17 tests | DONE |
| A3 certificate verifier | A3 | 22 tests | DONE |
| Full stock verification | Shared | 199 tests | DONE |
| Same-run staged candidate triple | OPERATOR | three staged files from one real run | NOT STARTED |
| Triple independent verifier pass | REVIEWER | A3 then A4.2 then B0.1 exact `VERIFIED` | NOT STARTED |
| Structural/source-binding audit | REVIEWER | audited cross-binding and source-binding | NOT STARTED |
| Complete-bundle approval | USER | explicit approval of the complete bundle | NOT STARTED |
| B0 → B1/B2 → C1/C2 → D → Pilot | Later packages | approved complete evidence and subsequent real slices | BLOCKED |
