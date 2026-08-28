# Iteration 5 C2 Acceptance Matrix

Status: DEFINED / NOT YET PASSED
Gate: continuous locked-official OpenCode snapshots -> desktop and mobile Web views

## User story and claim boundary

As a solo developer running the Host-owned, manifest-locked official OpenCode
package on an Apple Silicon Mac, I can leave the terminal open and see the same
session continue to advance in both a desktop Web layout and a mobile Web layout,
without either view inventing live state when projection is delayed or invalid.

C2 is a **local read-path integration gate**. A mobile Web layout may be a real
browser at a phone viewport on the same Mac; it is not evidence of remote-phone
reachability. C2 does not prove a Provider-backed task, browser commands, pairing,
production identity, distribution trust, or Controlled Pilot readiness.

## Acceptance matrix

| ID | Must pass in one run | Required evidence | Must fail / remain No-Go |
| --- | --- | --- | --- |
| C2-01 source | Host starts the exact bundled official OpenCode executable whose version and digest match the verified manifest. Projector reads that owned process only. | Sanitized run receipt binding bundle digest, executable identity, PID/start time, Host run ID and internal raw Session ID. | Fake/renamed binary, mock server, fixture replay, demo mode, ambient OpenCode process, unverifiable digest, or a Session discovered by listing unrelated sessions. |
| C2-02 continuity | One owned process and one exact Session produce at least **3 non-identical snapshots** across at least **2 real source-state changes**. Every accepted projection comes from two byte-identical complete five-route samples inside one process-identity-fenced bounded stable-observation window. Host-assigned projection sequence is strictly monotonic and each projected digest is unique when content changes. | Timestamped snapshot ledger binding run ID, stable internal Session ID, source observation digest, projected sequence/digest and safe state; raw user content is excluded. | One static sample polled repeatedly; snapshots spliced across processes/runs/sessions; duplicate observations advancing sequence; rollback, skipped accepted sequence, or session switch presented as continuity. The official API has no common revision, so this gate must not be described as a transactional or same-instant source snapshot. |
| C2-03 projection | Every accepted snapshot is derived from official API responses and exposes only the browser-safe subset: aliases, turn state, freshness/connectivity, update time, and aggregate change count. Upstream OpenCode is not credited with Nomad `seq` or durability. | Real-process capture plus projector/Gateway receipts showing exact-session binding and locally assigned ordering. | Synthetic event conversion presented as upstream truth; raw path, prompt, message, diff body, Provider/model name, upstream identifier, credential, or token reaches Relay, browser, logs, or evidence. |
| C2-04 transport | The run-owned Host/projector publishes through the product-intended private channel and the default same-origin Gateway route, not the legacy local-alpha fixture-signing or mock writable path. Durable last-good commit precedes acknowledgement. | Process inventory, endpoint inventory, sanitized transport receipts and Gateway persistence records for the same run. | Env fixture key, test route, mock client, argv token, direct browser-to-Relay secret, ACK-before-commit, or a legacy path is required for the demo. |
| C2-05 two Web views | A desktop browser and a mobile-width browser view are open concurrently against the same Gateway. For all 3 accepted snapshots, both expose the same session alias, projection sequence/digest, turn state and aggregate change count; each reaches the newest snapshot within **5 seconds or two projector intervals, whichever is longer**. | Browser/network capture from both viewports, viewport metadata, timestamps and sanitized screenshots tied to the same run ledger. | Only one view, two screenshots of one response, fixture-injected DOM, different sessions, divergent latest state, hidden error, or a mobile mock/component test. |
| C2-06 refresh and loss | Refreshing either view converges to the durable latest snapshot. If the source/channel becomes unavailable, the UI moves from reconnecting to stale/unavailable; an old snapshot is never labelled Live. Recovery converges without sequence rollback. | Same-run refresh plus bounded source/channel interruption and recovery trace in both layouts. | Blank infinite loading, fabricated progress, stale-last-good shown Live, rollback after refresh, silent gap, or invalid data accepted after recovery. |
| C2-07 fail closed | Malformed/oversized snapshot, wrong Session, out-of-order update, same-sequence/different-digest conflict, gap, unsupported official response shape and source-process replacement are each rejected visibly without replacing durable last-good state. | Negative real-path injections at the Host/Gateway boundary with browser-visible non-Live outcome and unchanged last-good digest. | Parser crash, partial overwrite, ACK of rejected input, automatic session adoption, or UI remains Live. |
| C2-08 repeatability | The complete C2 run passes twice from fresh run state with no owned child left after stop. No test assertion or manual database edit is needed to make the Web views converge. | Two sanitized acceptance manifests and cleanup process inventories. | A single lucky run, reuse of prior Gateway DB, manual state repair, orphan process, or cleanup of unowned state. |

All eight rows are conjunctive. Any Must-fail condition yields `FAIL`; a missing
external or implementation prerequisite yields `BLOCKED`, never a partial pass.
Unit, schema, fixture, mock, screenshot-only, and component-only evidence may
support diagnosis but cannot satisfy any C2 row by themselves.

## State semantics

Keep three independent dimensions; do not collapse them into one optimistic
"running" flag.

| Dimension | Values and meaning | UI rule |
| --- | --- | --- |
| Gate verdict | `NOT_RUN`, `RUNNING`, `PASS`, `FAIL`, `BLOCKED` | Only the acceptance runner/reviewer sets `PASS`; product runtime must not display it. |
| Projection freshness | `RECONNECTING`, `LIVE`, `STALE`, `UNKNOWN`, `UNAVAILABLE` | `LIVE` requires a validated current snapshot and intact exact-session source. Repeated observation of the same valid snapshot is still Live but does not count as continuity progress. Any conflict/shape/gap ambiguity is `UNKNOWN`; no source is `UNAVAILABLE`. |
| Agent turn | `None`, `Running`, `NeedsInput`, `NeedsPermission`, `Completed`, `Cancelled`, `Failed`, `OutcomeUnknown` | This is projected Agent state only. Terminal turn state does not imply process exit or C2 pass. `OutcomeUnknown` must never be rendered as success. |

The desktop and mobile layouts must derive all three displayed runtime fields
from the same Gateway response. UI labels such as `READ-ONLY ALPHA` are acceptable
for C2; a write-capable or remote-product label is not.

## Evidence levels

| Level | Evidence | Claim allowed |
| --- | --- | --- |
| E0 | Unit/schema/fixture/mock/golden trace | Contract or implementation support only; no product claim. |
| E1 | Locked official binary observed by one component | Official response shape/identity boundary only; no continuous Web claim. |
| E2 | Same-run official process -> continuous projector -> durable Gateway, without both browser layouts | Integrated projection mechanics only. |
| **E3 (C2)** | E2 plus concurrent desktop/mobile-layout browser convergence, negative cases, refresh/recovery, repeat run and cleanup | Local continuous official-snapshot read path. |
| E4 | Real allowlisted Provider-backed task plus authoritative `reply`, `deny`, `Stop` in desktop and real phone browsers | First-real-user journey candidate, subject to security/release review. |
| E5 | Clean-machine signed distribution, pairing/revocation, production identity/publication trust, independent security approval and Controlled Pilot evidence | Controlled Pilot Go/No-Go. |

## Current disk verdict and remaining product gap

As of 2026-08-25, disk state supports E1 foundations: the locked official
runtime launch, exact-session Host bootstrap, stock snapshot safety boundary,
Host command authority foundation and public command DTOs are recorded as
frozen. The stock snapshot adapter explicitly labels its evidence as official
registry shape only, not Provider lifecycle. The default Gateway/client still
uses the read-only local-alpha projection contract. No same-run E3 evidence is
recorded here, so C2 is `NOT_RUN`, not passed.

After C2 passes, the product still needs: real allowlisted Provider-backed task
evidence; startup/journal completion; real authoritative change-summary evidence;
Gateway/browser wiring for Host-final `reply`, `deny`, and `Stop` plus
exactly-once/reconciliation acceptance; secret/content scans; real-phone remote
access, pairing and revocation; clean-machine lifecycle; Developer ID/notarized
distribution; SSHSIG/KRL and protected CAS publication; and independent security
approval. `allow_once` remains absent and fail-closed throughout.
