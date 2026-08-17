# Stage-1 Local Validation Slice Acceptance Record

## Scope

Stage 1 proves a synthetic/disposable local bridge with real Host, Relay and
Mobile reference processes. It is a product/architecture spike, not a Private
Alpha release candidate.

Completion requires:

- a real-process Mobile → Relay → Host → Relay → Mobile loop;
- a local test pairing comparison code;
- Host checkpoint delivery with Session state and diff metadata;
- explicit Host acceptance for deny and Stop, with request deduplication;
- truthful RelayReceived versus HostAccepted states;
- `allow_once=false` and an explicit Host rejection for attempted allow;
- repeatable conformance, Host, Relay, Mobile, fault and browser checks.

## Explicitly deferred

- production pairing, device identities, revocation and key epochs (SEC-002);
- Security Envelope/E2EE and threat-model gate acceptance (SEC-003/D-005);
- APNs, native iOS, Keychain/Secure Enclave and biometric approval;
- live OpenCode pending-permission arbitration and mobile allow once (HC-009);
- external-user installation, usability, activation, retention and Private Alpha
  release evidence;
- 100k-event recovery and eight-hour workload performance gates.

## Live-data progression

The first live-data integration uses the pinned OpenCode `v1.18.16` binary on a
project-provided disposable repository and temporary Provider account. The Host
adapter must capture one real Session containing a question, a permission, a
Stop, a diff and a reconnect, then compare the projection against the same
Session Semantics conformance runner used by synthetic fixtures.

Synthetic fixtures remain the default until all of the following are true:

1. the live capture is reproducible and provenance-labeled as captured;
2. no Session content or Provider credential enters Relay/logs/diagnostics;
3. OpenCode maintains one pending permission across disconnect and desktop/mobile
   competition, and fail-closed behavior is observed;
4. the security architecture gate permits a disposable real-data run.

If condition 3 fails, view/reply/deny/Stop may proceed to the controlled pilot,
but mobile `allow_once` remains disabled per D-007 and HC-009.

## Round-1 findings and resolution

| Finding | Resolution | Retest evidence |
| --- | --- | --- |
| P0 components were not interconnected | Added real Node Mobile → Go Relay → Rust Host → Relay → Mobile process loop | `QA-PROCESS-LOOP.md`, `last-transcript.json` |
| P1 no pairing interaction | Added test-only comparison-code round trip through the real Relay/Host processes | `pair.request` and `pair.confirmed` transcript entries |
| P1 requested allow-once despite unmet safety gate | Not adopted: D-007/HC-009 require fail-closed. Real Host rejects it with `ERR_SAFETY_BLOCKED` | `command.allow_once` transcript response |
| P2 scope boundary unclear | This record and `local-validation.md` enumerate covered and deferred work | Document review |
| P2 no live-data progression | Added pinned live OpenCode progression and switch conditions above | Document review |

## Round-2 verdict

Independent Product Manager verdict: **ACCEPT** for the Stage-1
synthetic/disposable local Validation Slice. This does not accept D-005, enable
mobile allow-once, or satisfy any Private Alpha release gate.

## Stage-2 entrance criteria

Stage 2 may begin only after product, technical and security DRI roles are
assigned; SEC-002 and SEC-003 have accepted trust/key/envelope decisions; the
fixed live OpenCode adapter passes its single-pending/fail-closed experiment or
is formally limited to view/deny/Stop; the local QR/comparison-code pairing flow
has a native iOS test plan; and the real-process loop can survive one Relay
restart without duplicate Host acceptance or an unexplained event gap.
