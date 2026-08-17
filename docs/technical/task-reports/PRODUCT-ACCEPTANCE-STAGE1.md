# Stage-1 Product Acceptance Report

- Scope: synthetic/disposable local Validation Slice
- Round 1: Rejected
- Round 2: Accepted
- Date: 2026-08-17

## Round-1 rejection

The Host, Relay and Mobile reference components were individually tested but had
not communicated across real process boundaries. The Product Manager correctly
rejected component readiness as a product closed loop. Pairing, scope boundaries
and live-data progression also lacked milestone evidence.

## Fixes

- Added an opt-in, loopback-only TEST-ONLY Relay bridge.
- Added real Rust Host and Node Mobile processes using the same JSON bridge.
- Added comparison-code pairing, NeedsPermission/diff checkpoint, deny, Stop,
  explicit Host results, ACK, and real Host rejection of allow-once.
- Added a strict process supervisor and machine-readable transcript.
- Added Stage-1 scope/deferred work and live OpenCode progression.

## Round-2 acceptance

Product Manager verdict: **ACCEPT**. The real process transcript proves the
Stage-1 closed loop. `allow_once=false` is accepted as the required fail-closed
result until D-007/HC-009 gates pass. Production pairing, E2EE, APNs, native iOS,
live OpenCode and Private Alpha evidence remain explicitly deferred.

## Evidence

- `testkit/process-loop/last-transcript.json`
- `docs/technical/task-reports/QA-PROCESS-LOOP.md`
- `docs/technical/stage1-acceptance-record.md`
- `testkit/browser/mobile_reference_smoke.py`
