# Iteration 3 Task Spec: Real Stock OpenCode Pilot Slice

## Objective

Turn the current synthetic/compatibility engineering slice into a real,
disposable Controlled Pilot slice backed by the official pinned OpenCode
release. The result must be operable by a real user through the existing
Host -> Relay -> Gateway -> Mobile path without claiming production readiness.

## Product milestones

1. **M1 Stock facts:** consume official OpenCode `id/type/properties` events and
   reconcile them with authoritative stock snapshots.
2. **M2 Real vertical slice:** drive one disposable Provider-backed task through
   Host, Relay, Gateway, and Mobile with real status, reply, Stop, question,
   permission, diff, and reconnect evidence.
3. **M3 Pilot readiness:** complete authoritative workspace baseline, onboarding,
   cleanup, real-device TLS review, and named Product/Technical/Security signoff.
4. **M4 Controlled users:** run 3 supervised-safety participants, then expand to
   10 only if the stop conditions remain clear.
5. **M5 Internal Alpha decision:** enter production identity/E2EE/native mobile
   work only when the problem, usability, technical, and safety gates pass.

## Iteration 3 P0 success criteria

- Stock OpenCode raw DTOs remain inside its adapter boundary.
- Host assigns durable, monotonic Nomad sequence numbers transactionally.
- Reconnect uses stock Session/message/permission/diff facts for reconciliation;
  it does not assume upstream replay or fabricate a pending request.
- A real disposable task records question, permission, diff, Stop, and reconnect.
- Reply and Stop reach stock OpenCode at most once per business request ID.
- Mobile `allow_once` remains absent and Host rejection remains enforced.
- Session Semantics v0 remains unchanged unless an evidence-backed ADR proves a
  missing semantic.
- Existing synthetic tests remain green, but they do not count as stock evidence.
- `testkit/process-loop/last-transcript.json` is preserved as user workspace state.

## Non-goals

- Production E2EE, account identity, native iOS, APNs, or real repositories.
- A full self-developed Agent runtime or a second Agent integration.
- Broad OpenCode version compatibility or an OpenCode fork.
- Mobile `allow_once`.

## Decision authority

- Product Owner: scope, user value, stage-gate acceptance.
- Chief Architect: package boundaries, sequencing, work assignment, technical
  acceptance recommendation.
- Workers: bounded implementation only; no stage-gate self-approval.
- Independent verifier: evidence audit; does not implement the audited work.
