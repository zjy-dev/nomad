# Iteration 5 Architecture Dispatch

## Dependency DAG

```text
A1 Web read path ──> A2 reply/deny/Stop Host authority ───────┐
A3 installable local launcher ────────────────────────────────┼─> Web Alpha
B1 temporary Provider credential -> B2 official real run ────┘

A4 pairing/revocation/security-envelope contracts
A5 release/trust plumbing skeleton
C1 official runtime provenance + C2 Developer ID
C3 SSHSIG/KRL + C4 protected CAS
A4+A5+B2+C1+C2+C3+C4 -> secure Host path
secure Host path + D1 real device + D2 APNs + D3 native commands -> native product
```

`allow_once` is outside A2 and remains fail-closed. The first command slice is
limited to reply, deny and Stop with Host-final authorization.

## First package: WP5-A3a

Implement a repo-local `nomad-web` launcher foundation without changing Phase
4 protocols. It is not a Developer ID/notarized installer and has no production
authority.

Commands: `doctor`, `start`, `status`, `stop`, `uninstall`.

The first package starts only the read-only Relay and Gateway foundation. A
real Agent is explicitly blocked until Provider evidence and a non-fixture
security identity are available. Tokens are generated in memory and passed by
environment only; no token/private key/Provider value enters argv, manifest,
state, logs or browser assets.

Owned files are limited to `tools/nomad_web/`, `testkit/nomad-web/`, and
`docs/technical/task-reports/WP5-A3-FOUNDATION.md`. Existing Relay, Gateway,
Connector and Mobile contracts are consumers and must not be changed by this
package.

## Addendum: 2026-08-25 Current-State Execution Dispatch

This addendum is the active execution contract. The skeleton DAG above remains
as audit history only. All sequencing below starts from the already-landed
repo-local launcher foundation and prebuilt web bundle on disk.

### Frozen Start

- `P5_repo_local_launcher_foundation`,
  `P5_repo_local_launcher_security_audit`,
  `P5_repo_local_launcher_product_audit`,
  `P5_prebuilt_web_bundle`, and
  `P5_prebuilt_web_bundle_security_audit` are already complete.
- `tools/nomad_web` is still `foundation-readonly`; `real_agent_enabled=false`.
- The same-origin Gateway and default browser route are still read-only today.
- `allow_once=false` remains hard-blocked at product, Host, and adapter layers.
- Local-alpha fixtures, env signing keys, and argv-token pilot paths do not
  count as product authority and stay off the shortest path.
- Prebuilt bundle materialization and verification stay frozen in this batch;
  consume the existing foundation rather than redesigning it.

### Shortest Honest DAG From Current Disk State

```text
Repo-owned path
F0 frozen prebuilt foundation [done]
  -> R1 OpenCode public surface containment
  -> R2 real Agent launcher boundary
  -> R3 continuous projector
  -> R4 secure command envelope (reply/deny/Stop only; Host-final; allow_once=false)
  -> R5 local integrated acceptance (same-host install/start/view/reply/deny/Stop)

Parallel shape
R1 -> R2
R1 -> R3
R1 -> R4a Host command authority -> [R4b same-origin Gateway write path, R4c browser writable client]
[R2, R3, R4b, R4c, E1] -> R5

External gates
E1 allowlisted Provider credential
E2 security DRI approval for controlled-pilot envelope
E3 Developer ID host / distribution trust
E4 SSHSIG/KRL + protected CAS publication
E5 real device and APNs only if native iPhone enters launch scope
```

`R5` is the honest stop line for the next batch. Pairing, revocation,
production identity publication, remote mobile acceptance, and controlled-pilot
claims stay out of scope until the local same-origin command path is proven.

### Next Batch: 10-Minute Atomic Owned-File Contracts

#### Lane 1: Real Agent Launcher

`WP5-B1a OpenCode surface containment`

- Goal: close `P5_opencode_public_surface` by forcing launcher and Gateway
  callers through product Host entrypoints only.
- Owned files:
  - `connector/src/lib.rs`
  - `connector/src/bin/nomad_host.rs`
  - `connector/src/bin/pilot_adapter.rs`
- Failure tests:
  - product path cannot require `pilot_adapter.rs` or any argv-token flow
  - `nomad_host` stays blocked until startup prerequisites are verified
  - `allow_once` remains unavailable from all product-facing surfaces
- DoD:
  - product entry surface is `nomad_host`
  - `pilot_adapter.rs` is explicitly legacy/test-only and off the product DAG
  - no launcher, Gateway, or browser code depends on direct OpenCode adapter
    internals

`WP5-B1b Child-env startup authority`

- Goal: turn the existing actual-launch and native-launch primitives into the
  only real-Agent startup path, with Provider secret present only in the Agent
  child-process environment.
- Owned files:
  - `connector/src/host_startup.rs`
  - `connector/src/actual_launch.rs`
  - `connector/src/native_launch/inputs.rs`
  - `connector/src/native_launch/lifecycle.rs`
  - `connector/src/native_launch/process.rs`
- Failure tests:
  - missing launch provenance or missing Provider credential returns blocked and
    spawns no Agent child
  - Provider secret never appears in Host env, argv, files, logs, receipts,
    browser bundles, or chat
  - child stdout/stderr remains closed or content-free for secret material
- DoD:
  - one Host-controlled start path launches real OpenCode only after
    prerequisite verification
  - Provider credential is consumed once, passed only to the Agent child env,
    then dropped or zeroized
  - Host keeps final authority over start and stop and never becomes a secret
    holder

#### Lane 2: Continuous Projector

`WP5-B2a Continuous projector`

- Goal: replace the current local-alpha projector assumption with a long-running
  projector that follows the real Agent session continuously without claiming
  production identity.
- Owned files:
  - `connector/src/alpha_projector.rs`
  - `connector/src/bin/alpha_projector.rs`
- Failure tests:
  - `NOMAD_ALPHA_DEVICE_PRIVATE_KEY_HEX` does not unlock product mode
  - projector exits blocked when Host session authority is absent
  - duplicate, gap, or stale session updates surface as explicit projector or
    store errors rather than silent data loss
- DoD:
  - projector can run continuously alongside the real Agent launcher
  - projector emits only browser-safe session projection data
  - no product claim depends on local-alpha signing fixtures

#### Lane 3: Secure Command Envelope

`WP5-B3a Host command authority`

- Goal: define the only writable command surface as Host-final `reply`,
  `deny`, and `Stop`.
- Owned files:
  - `connector/src/opencode_adapter.rs`
  - `connector/src/permission.rs`
- Failure tests:
  - `allow_once` returns `Rejected` and `ERR_SAFETY_BLOCKED`
  - stale, offline, or unauthorized session state rejects commands before
    dispatch
  - command receipts and errors contain no Provider values, relay tokens, or
    raw secret-bearing process details
- DoD:
  - Host command RPC exposes only `reply`, `deny`, and `Stop`
  - every accepted command returns a browser-safe receipt or status envelope
  - Host remains the final authorization point

`WP5-B3b Same-origin Gateway write path`

- Goal: add the secure writable envelope without exposing relay or Provider
  secrets to the browser.
- Owned files:
  - `mobile-reference/pilot-gateway/server.mjs`
  - `mobile-reference/pilot-gateway/alpha-store.mjs`
- Failure tests:
  - capability-off or read-only mode still returns blocked or `READ_ONLY_ALPHA`
  - non-loopback or non-same-origin access is rejected
  - duplicate or stale command submission is rejected with explicit status
- DoD:
  - Gateway serves `POST` and `GET` command endpoints for reply, deny, and
    `Stop` only
  - browser sees only browser-safe projection plus command receipts
  - relay token stays server-side

`WP5-B3c Browser writable client`

- Goal: switch the existing UI from mock writable paths to the real same-origin
  writable client when Host capability is present.
- Owned files:
  - `mobile-reference/src/client/http-client.ts`
  - `mobile-reference/src/client/types.ts`
  - `mobile-reference/src/main.tsx`
  - `mobile-reference/src/ui/App.tsx`
- Failure tests:
  - when capability is absent, or session is stale or offline, reply, deny, and
    `Stop` stay disabled
  - browser bundle contains no relay token, Provider env name, or secret-bearing
    Host detail
  - legacy mock writable path is not used in the default installable flow
- DoD:
  - default web UI reads and writes through the same-origin Gateway
  - writable state is capability-gated
  - `allow_once` never appears in the first action subset

#### Merge: Local Integrated Acceptance

`WP5-B4a Installable real-Agent merge`

- Goal: wire the real-Agent launcher, continuous projector, and secure command
  envelope into the existing prebuilt `nomad-web` foundation.
- Owned files:
  - `tools/nomad_web/launcher.py`
  - `tools/nomad_web/doctor.py`
  - `tools/nomad_web/processes.py`
  - `tools/nomad_web/state.py`
  - `tools/nomad_web/cli.py`
  - `tools/nomad_web/bundle_manifest.json`
  - `testkit/nomad-web/test_clean_home.py`
- Depends on:
  - `WP5-B1b`
  - `WP5-B2a`
  - `WP5-B3b`
  - `WP5-B3c`
  - external gate `E1`
- Failure tests:
  - `doctor` reports blocked cleanly when `E1` is absent
  - `start`, `status`, `stop`, and `uninstall` stay idempotent and
    secret-clean
  - launcher state, logs, argv, receipts, and browser assets contain no
    Provider secret or relay token
  - manifest capabilities become `view=true`, `reply=true`, `deny=true`,
    `stop=true`, `allow_once=false`
- DoD:
  - one clean-home install, start, and status flow launches real OpenCode plus
    the continuous projector
  - same-host browser can view and execute reply, deny, and `Stop` through the
    same-origin Gateway
  - the claim boundary remains local web alpha only; no pairing, no production
    identity, and no remote pilot claim

### Explicitly Out Of This Batch

- pairing, revocation, and published security envelope
- production identity publication and protected CAS
- Developer ID or notarized distribution
- remote phone-browser acceptance
- native iPhone app and APNs

## C2 Final Contract: Run-Owned Stable Snapshot to Local Web

Claim boundary: C2 is a same-machine, read-only `official-agent-local` path. It
does not prove Provider-backed work, remote device trust, command authority, or
an atomic upstream transaction. OpenCode 1.18.16 exposes no common revision
across the five snapshot routes, so the strongest honest source claim is a
bounded stable-observation window.

The launcher creates exactly one Session with authenticated `POST /session` and
passes the raw run ID, exact Session ID, workspace binding digest, Agent PID,
process group, launcher-observed process identity, and a run-scoped private UDS
pathname to the Product Host over bootstrap FD 10. Neither the raw identifiers
nor the Agent Basic password may enter argv, logs, state, Gateway responses, or
browser assets.

For every accepted observation the Host performs:

```text
verify Agent process -> read complete B1 (five routes) -> verify process
-> read complete B2 (same five routes) -> verify process
-> require byte-identical B1/B2 -> strict projection -> verify workspace
-> run-scope aliases -> commit last-good and sequence
```

The five routes are the exact Session, global status map, questions,
permissions, and exact Session diff. Any request, schema, session, workspace,
process, size, or equality failure rejects the whole observation. A process or
workspace binding failure is fatal to the Host. Other source failures leave the
last-good snapshot unchanged and eventually expire a 60-second monotonic health
lease. Duplicate complete observations refresh health but do not advance the
sequence. This fence reduces torn reads but cannot exclude an upstream A-B-A
transition, so it must never be described as a transactional or same-instant
snapshot. C3 must independently revalidate current raw facts before authorizing
a command.

The Host owns the private UDS listener and the only snapshot sequence. The
directory is run-scoped, canonical, owned by the effective UID, mode 0700, and
contains an initially absent `product-host.sock` with mode 0600. The Host checks
peer UID and continuously checks the bound socket identity. Bootstrap readiness
is a bounded, length-prefixed `nomad.product-host.ready.v1` receipt carrying the
verified parent/socket device and inode plus `snapshot_seq=1`. It is emitted only
after the first stable observation is committed in Host memory and the poller is
running. The Host does not wait for the Gateway.

The private HTTP surface is exact:

- `GET /internal/session/current` returns one nested
  `nomad.product-host.snapshot.v1` envelope.
- `GET /internal/session/stream?after_snapshot_seq=N` is a bounded 25-second
  long poll, not SSE: exact `N+1` returns 200, no change returns 204, and a gap,
  rollback, or cursor conflict returns 409.
- Missing baseline or expired source health returns a content-free 503.

The envelope contains only `schema`, a random `host_instance_id`,
`snapshot_seq`, `digest`, and the frozen content-safe `StockReadonlySnapshot`.
The digest is SHA-256 over canonical JSON with only the top-level digest field
removed. Rust and Node must share a golden vector. Session/input/permission
aliases are domain-separated by the run before publication.

The Gateway is a UDS client. Every request validates the expected parent and
socket device/inode supplied by the ready receipt, plus owner, exact modes,
non-symlink status, strict HTTP framing, exact JSON, schema, digest, sequence,
and restart marker. Official mode has no Relay process, token, database, or
fallback. Each run uses a separate Gateway SQLite file; the same run may restart
the Gateway against that file, while a new run cannot serve a prior run's
snapshot. SQLite `synchronous=FULL` commit precedes browser HTTP 200.

The browser keeps the existing exact `nomad.alpha.readonly.v1` response shape
with `provenance.source=local-host-direct`, recalculates its own projection
digest, and never sees `host_instance_id` or raw identifiers. It runs one
cancel-safe refresh at a time, pauses while hidden, resumes immediately, and
uses bounded retry. A failure preserves the last-good Agent turn and only
degrades connectivity/freshness; it must not synthesize `OutcomeUnknown`.

C2 implementation may freeze only after independent audit reports zero P0/P1.
C2 product acceptance remains E3 and additionally requires two clean runs, at
least three changing snapshots, desktop and mobile-width browser convergence,
negative-path recovery, and owned cleanup. Unit, fixture, schema, and screenshot
evidence alone cannot satisfy that acceptance gate.
