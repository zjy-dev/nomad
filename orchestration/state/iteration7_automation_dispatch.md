# Iteration 7 Automation Dispatch

Status: REPO AUTOMATION COMPLETE / EXTERNAL GATES PENDING. P7-A through P7-F passed independent freeze review. This phase implemented every release-engineering task in scope that does not require a user approval dialog, a real Provider credential, a physical phone, a clean machine, or Apple signing credentials.

## Truth boundary

- Repo automation may PASS while product readiness remains false.
- Host Keychain authorization, normal Chrome certificate trust, Provider E3, physical iPhone Safari, clean-machine install, Developer ID signing, notarization, and publication remain independent external gates.
- Mechanical, fixture, canary, viewport, ad-hoc signature, or diagnostic-SPKI evidence never upgrades an external gate.

## Atomic packages

1. P7-A full readiness doctor: product-level PASS/BLOCK/NOT_RUN gates with content-free next actions.
2. P7-B atomic install/upgrade/rollback: content-addressed installs, stopped-state upgrades, persistent-state snapshots, failure rollback.
3. P7-C strict evidence resume: verify parent evidence and artifact/source digests, always rerun the complete journey, never splice historical evidence.
4. P7-D Provider E3 harness: FD-only credentials, two fresh sessions, real pending states only, exact-once effects, content-free evidence.
5. P7-E release trust verifier: digest provenance, Developer ID, notary, staple, Gatekeeper, publication/download parity; missing external credentials remains NOT_RUN.
6. P7-F single CLI integration owner after P7-A through P7-E freeze.

## Completion evidence

- P7-A full doctor: PASS/FREEZE after live role probes, exact bundle/run binding, and listener-to-PID binding.
- P7-B install lifecycle: PASS/FREEZE after forward-only security state, crash-atomic code selection, and canonical installed-path fixes.
- P7-C evidence resume: PASS/FREEZE after operator TLS FDs and one immutable whole-bundle snapshot bound parent, runners, product processes, and child evidence.
- P7-D Provider E3 runner: PASS/FREEZE as executable fail-closed automation; real Provider scenarios remain NOT_RUN until run with external credentials and naturally observed states.
- P7-E release trust: PASS/FREEZE as a verifier; mechanical fixtures return NOT_RUN and cannot authorize a release.
- P7-F CLI and bundle closure: PASS/FREEZE after human/JSON status parity, TLS FD lifecycle, and installed runner closure.
- Repository gates: nomad-web 117/117, remote-v2 40/40, Provider E3 20/20, release trust 3/3, Web 291/291 plus TypeScript/build, Relay test/race/vet, and Connector all-target tests/clippy.
- Product readiness remains false until the external gates in the truth boundary are actually run and pass.

## Acceptance

- Each package owns disjoint implementation/test/report files until final CLI integration.
- All failure output uses fixed, content-free codes.
- No package reads, stages, commits, or rewrites `testkit/process-loop/last-transcript.json`.
- After each coherent batch, the root orchestrator commits and pushes `feat/code-agent`.
