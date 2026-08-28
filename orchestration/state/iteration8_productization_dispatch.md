# Iteration 8 Productization Dispatch

Status: DISPATCHED FROM CURRENT-DISK REVIEW AND PM GAP REVIEW.

This phase covers only the next repo-owned productization work that can be
implemented and regression-tested without manual approval dialogs, external
Provider credentials, a physical phone, a clean machine, signing credentials,
publication infrastructure, or protected transcript access.

It exists to close the repo-owned gap between the current engineering slice and
an honest product statement of the following form:

- an ordinary user can install a repo-owned candidate;
- start the real bundled topology;
- understand why start/pair/reply/deny/Stop is blocked without reading logs;
- safely pair, revoke, reset remote access, and uninstall;
- collect a support-safe diagnostics bundle;
- see exactly what is installed and what is running;
- run product-grade automatic regressions over that journey.

This dispatch does not authorize any architectural redesign of Relay, Product
Host authority, or the OpenCode adapter boundary.

## Truth Boundary

- Repo-owned productization may PASS while product readiness remains false.
- Real Provider E3, physical iPhone Safari, clean-machine install from an exact
  release artifact, Developer ID signing, notarization, Gatekeeper, and
  publication provenance remain separate external gates.
- No package may read, export, compare against, or otherwise use
  `testkit/process-loop/last-transcript.json`.
- Provider credentials remain FD-only and Agent-child-only. They never enter
  argv, env, state, logs, browser storage, diagnostics bundles, or evidence.
- Host-final authority remains mandatory for every write.
- The allowed action subset remains exactly `view`, `reply`, `deny`, and
  `Stop`. `allow_once=false` stays absent and rejected.
- `adapters::opencode` remains the OpenCode-specific boundary. Adapter work in
  this phase is support-matrix and conformance work only, not a large refactor.
- The desktop/local Gateway is not a paired phone identity and must never be
  presented as one.

## Current-Disk Floor

- `tools/nomad_web/install_lifecycle.py` already provides stopped-only
  install/upgrade/rollback with immutable bundle selection, but the
  user-visible onboarding model is still engineering-shaped.
- `tools/nomad_web/doctor.py` already emits strict release gates and preserves
  external `NOT_RUN` rows, but the recovery surface is still code-first rather
  than ordinary-user-first.
- `tools/nomad_web/launcher.py` and `state.py` already capture bundle digest,
  run identity, process identities, Product Host socket identity, pairing
  public origin, and remote-local-evidence topology facts.
- `mobile-reference/pilot-gateway/*` and `mobile-reference/src/remote/*` already
  contain most pairing/join mechanics, but the full pair/revoke/reset/uninstall
  lifecycle is not yet productized as one ordinary-user route.
- `testkit/conformance/*` already provides a language-neutral contract runner,
  and `testkit/remote-v2/*` already covers remote-slice mechanics, but there is
  no single repo-owned product regression that exercises install -> start ->
  pair -> command -> revoke/reset -> diagnostics -> uninstall.

## Global Invariants

1. Installed identity and running identity are different facts and must stay
   different facts. A rollback may change the selected bundle, but it must
   never resurrect a revoked remote identity.
2. Any user-facing recovery surface must stay content-safe: no raw prompt
   content, no raw command content, no raw Agent IDs, no raw bearer values, no
   provider secrets, and no protected transcript references.
3. Pairing, revoke, reset, uninstall, diagnostics, and automation must all
   report stable uppercase codes before any human-readable text layer.
4. A diagnostics bundle is support material, not readiness evidence.
5. Fixture adapters, deterministic fake upstreams, same-machine join rehearsal,
   viewport simulation, or diagnostic TLS modes never upgrade an external gate.

## CLI Ownership Rule

`tools/nomad_web/cli.py` has a single owner in this phase: `P8-H`.

Every earlier package may add or freeze module-level APIs, JSON schemas, test
fixtures, and narrow user-output contracts inside its own files, but no earlier
package edits CLI command names, parser wiring, or top-level text-mode output.

## Dependency Graph

```text
P8-A installed/running identity ─┬──> P8-B install/onboarding
                                 ├──> P8-C human-readable recovery
                                 ├──> P8-D diagnostics bundle
                                 └──> P8-E pair/revoke/reset/uninstall lifecycle

P8-F adapter support matrix/conformance ───────────────────────────────────────┐
                                                                               │
P8-B install/onboarding ───────────────────────────────────────────────────────┤
P8-C human-readable recovery ──────────────────────────────────────────────────┤
P8-D diagnostics bundle ───────────────────────────────────────────────────────┼──> P8-G product regression
P8-E pair/revoke/reset/uninstall lifecycle ────────────────────────────────────┘

P8-G product regression ───────────────────────────────────────────────────────> P8-H CLI single owner integration
```

## Ownership Table

Exclusive ownership means one active package edits that file set at a time.
Sequential lease transfer is allowed only when the earlier package is frozen.

| Package | Priority | May start when | Exclusive implementation files |
| --- | --- | --- | --- |
| P8-A | P0 | immediately | `tools/nomad_web/state.py`, `tools/nomad_web/launcher.py`, `tools/nomad_web/processes.py`, focused identity tests under `testkit/nomad-web/` and `testkit/remote-v2/` |
| P8-B | P0 | after P8-A freeze | `tools/nomad_web/install_lifecycle.py`, `tools/nomad_web/materialize.py`, `tools/nomad_web/bundle_manifest.json`, new `tools/nomad_web/onboarding.py`, focused install/onboarding tests |
| P8-C | P0 | after P8-A freeze | `tools/nomad_web/doctor.py`, new `tools/nomad_web/recovery.py`, focused doctor/recovery tests |
| P8-D | P0 | after P8-A and P8-C freeze | new `tools/nomad_web/diagnostics.py`, optional narrow support manifest helper, focused diagnostics tests |
| P8-E | P0 | after P8-A freeze; may consume a later sequential lease on `tools/nomad_web/launcher.py` | `mobile-reference/pilot-gateway/server.mjs`, `mobile-reference/pilot-gateway/pairing-session.mjs`, `mobile-reference/pilot-gateway/product-host-client.mjs`, `mobile-reference/src/remote/*`, new or narrow remote-access UI files under `mobile-reference/src/ui/*`, `connector/src/device_authority.rs`, `connector/src/product_host_bootstrap.rs` only if a narrow lifecycle contract change is required, `tools/nomad_web/launcher.py` only after P8-A releases it, focused lifecycle tests |
| P8-F | P1 | immediately | `connector/src/adapters/opencode.rs`, `connector/src/stock_opencode.rs`, `testkit/conformance/*`, new adapter-conformance fixtures or contracts, optional short support-matrix doc |
| P8-G | P0 | after P8-B through P8-F freeze | `testkit/remote-v2/*`, `testkit/nomad-web/*`, optional one repo-local validation script, one task report if needed |
| P8-H | P0 | after P8-B through P8-G freeze | `tools/nomad_web/cli.py`, one CLI snapshot/golden test |

## P8-A: Installed And Running Identity Substrate

Priority: `P0`

Purpose:

- make installed bundle identity, selected install identity, running topology
  identity, Product Host socket identity, and paired-device identity explicit
  and comparable;
- give later onboarding, recovery, diagnostics, lifecycle, and regression work
  one stable identity vocabulary;
- preserve the existing rule that rollback does not own remote identity
  authority.

Scope:

- define one stable state contract that separates:
  - installed bundle digest and install-sequence facts;
  - running bundle digest and run-scoped process/socket identities;
  - Host public identity commitment;
  - paired-device commitment and epoch facts, if present;
  - degraded or mismatched identity states.
- make identity drift fail closed with deterministic codes rather than implicit
  best-effort repair.
- keep all identity material commitment-only. No private key, bearer, or raw
  credential value may appear.

Acceptance:

- starting the same installed bundle twice yields the same installed identity and
  a new run identity.
- a mismatch between selected bundle, running processes, and Product Host socket
  identity produces a deterministic block code and zero silent repair.
- stop/start preserves exactly the intended persistent remote state and never
  stores secret material in state JSON.
- the resulting identity vocabulary is sufficient for P8-B, P8-C, P8-D, P8-E,
  and P8-G without those packages inventing their own identity fields.

## P8-B: First Install And Onboarding

Priority: `P0`

Purpose:

- turn the install path into an ordinary-user journey with explicit, repo-owned
  states instead of implicit engineering assumptions;
- make the difference between source-build materialization, verified installed
  bundle, and running candidate visible and honest.

Scope:

- define a narrow onboarding state machine such as:
  - `NOT_INSTALLED`
  - `INSTALLED_NEEDS_START`
  - `INSTALLED_BLOCKED_HOST_IDENTITY`
  - `RUNNING_NEEDS_PAIRING`
  - `RUNNING_PAIRED`
  - `RUNNING_DEGRADED_RECOVERY_REQUIRED`
- preserve the current stopped-only install/upgrade/rollback safety model.
- make install state sufficiently explicit that uninstall preconditions and
  diagnostics entry points are unambiguous.
- avoid any claim that a repo-local bundle is signed, notarized, published, or
  clean-machine validated.

Acceptance:

- every install/upgrade/rollback outcome lands in one explicit onboarding state.
- a verified bundle can be reasoned about without requiring the repo checkout as
  the source of truth.
- no onboarding state claims `production_ready=true`.
- onboarding states are commitment-only and safe to include in diagnostics.

## P8-C: Human-Readable Error Recovery

Priority: `P0`

Purpose:

- convert the existing code-first gate surface into a concise, honest,
  ordinary-user recovery surface;
- keep machine-stable blocker codes while making next actions readable.

Scope:

- group the current engineering failures into short recovery classes such as:
  - install/bundle verify failure;
  - runtime identity drift;
  - Host identity authorization missing;
  - pairing required;
  - revoke or reset required;
  - browser vault/storage loss;
  - TLS/network/port block;
  - diagnostics recommended;
  - external gate not run.
- preserve current external `NOT_RUN` rows rather than turning them into fake
  local `PASS`.
- ensure that text-mode recovery stays content-safe and does not leak secret or
  machine-specific values.

Acceptance:

- every non-`PASS` doctor gate maps to one stable recovery code plus one short
  next step.
- recovery text remains safe when copied into issue trackers or support chats.
- a user can distinguish local repo-owned recovery from an external gate without
  reading source code or logs.

## P8-D: Support-Safe Diagnostics Bundle

Priority: `P0`

Purpose:

- give users and support a deterministic bundle that captures enough context to
  debug repo-owned failures without exporting secrets or transcripts.

Scope:

- export only allowlisted content:
  - installed/running identity commitments;
  - onboarding and recovery results;
  - safe state snapshots;
  - owned-process identities;
  - safe log tails or digests;
  - privacy scan results;
  - bundle/install metadata;
  - deterministic manifest digests.
- explicitly exclude:
  - provider credentials;
  - raw bearer values;
  - raw prompt or command content;
  - raw Agent IDs;
  - browser storage values;
  - protected transcript artifacts;
  - unowned files.
- keep bundle generation read-only against the running system.

Acceptance:

- identical inputs yield the same diagnostics manifest digest.
- allowlist violations fail closed with a deterministic code.
- the bundle is sufficient to explain install/runtime/pairing/identity failure
  classes without reading the protected transcript.
- diagnostics output is never labeled as readiness evidence.

## P8-E: Pair / Revoke / Reset / Uninstall Lifecycle Closure

Priority: `P0`

Purpose:

- close the user-facing lifecycle after install/start so that ordinary users can
  safely pair, revoke, recover from lost browser state, reset remote access,
  and uninstall without guessing hidden state.

Scope:

- productize the visible desktop and remote lifecycle around the already-frozen
  authority model.
- define exactly three lifecycle operations:
  - `revoke`: runtime-safe epoch advance for the active paired device while
    keeping the install and Host identity intact;
  - `reset_remote_access`: stop-only destructive clear of pairing store,
    current device registration, remote mailbox cursors, and other owned remote
    access state while preserving the installed bundle and the Host identity
    commitment unless explicit identity rotation is triggered elsewhere;
  - `uninstall`: remove owned runtime, owned install selectors, owned remote
    state, and owned bundled artifacts; never silently delete unowned data.
- make the uninstall result explicitly say what happened to Host identity:
  retained, removed, or external-manual-action-required.
- keep the current rule that the desktop/local Gateway is not itself a paired
  phone identity.

Acceptance:

- after revoke or reset, the old phone/browser path causes zero new journal
  insertions and zero upstream Agent calls.
- uninstall leaves no owned process, no owned runtime directory, no owned
  install selector, and no owned remote state database.
- lost-key, stale-cookie, replaced-device, and cancelled-pair flows end in
  explicit recoverable states rather than ambiguous failure.
- if Host identity deletion still requires external user authorization, the
  result remains an external gate and is never reported as local `PASS`.

## P8-F: Adapter Support Matrix And Conformance

Priority: `P1`

Purpose:

- make adapter support explicit without redesigning the architecture;
- freeze the current OpenCode behavior behind the existing adapter boundary.

Scope:

- publish one repo-owned support matrix covering:
  - supported adapter ids and versions;
  - supported action subset;
  - capability issuance rules;
  - `NoCapability` semantics;
  - pending-input summary behavior;
  - clearly unsupported cases.
- add conformance coverage for the behavior that productization depends on,
  including the already-frozen rule that no capability surface maps to
  `snapshot + capability=None` rather than `Unavailable`.
- keep all provider-specific logic inside the current adapter boundary.

Acceptance:

- the current adapter behavior is represented by one explicit support matrix,
  not implicit tribal knowledge.
- conformance failures yield stable diagnostics and never require the user to
  inspect provider-specific source code first.
- no package outside the adapter boundary needs provider-specific conditionals
  to understand capability or recovery behavior.

## P8-G: Product-Grade Automatic Regression

Priority: `P0`

Purpose:

- turn the repo-owned product journey into one automatic regression slice that
  ordinary engineering can rerun without external credentials or manual steps.

Scope:

- run the exact installed candidate through a deterministic product journey:
  - install;
  - doctor and onboarding classification;
  - start the real bundled topology;
  - pair/rehearse the remote journey with deterministic adapter behavior;
  - exercise `view`, `reply`, `deny`, and `Stop`;
  - revoke;
  - reset remote access;
  - collect diagnostics;
  - stop and uninstall.
- add one explicit missing-credential regression that proves the official
  provider-backed path blocks honestly instead of pretending to succeed.
- keep all success claims below the external gates listed above.

Acceptance:

- the full repo-owned slice passes from the exact installed bundle and never
  depends on a repo checkout during execution.
- a failing step returns a deterministic code and a stable recovery class.
- no regression reads the protected transcript.
- no regression claims real Provider E3, physical-phone, clean-machine,
  signing, notarization, or publication `PASS`.

## P8-H: CLI Single Owner Integration

Priority: `P0`

Purpose:

- integrate the new module surfaces into one authoritative CLI and one stable
  JSON/text contract.

Scope:

- own the final parser, command names, and top-level user output.
- wire the frozen module surfaces for:
  - onboarding and install status;
  - recovery;
  - diagnostics bundle generation;
  - lifecycle reset results;
  - regression status where appropriate.
- keep text output concise and ordinary-user readable while preserving the full
  machine-readable JSON contract.

Acceptance:

- every stable command has one authoritative JSON schema and one concise text
  rendering.
- `--json` stays complete enough for automation and support tooling.
- text output never prints secrets, raw prompt content, raw bearer values, or
  misleading `PASS` claims for external gates.
- no earlier package edits `tools/nomad_web/cli.py`.

## Recommended Execution Order

1. `P8-A` first. It is the identity vocabulary blocker for the rest of the
   phase.
2. `P8-F` may start immediately in parallel because it is boundary-local and
   does not depend on lifecycle ownership.
3. After `P8-A` freezes, run `P8-B` and `P8-C` in parallel.
4. After `P8-A` and `P8-C` freeze, run `P8-D`.
5. After `P8-A` freezes, run `P8-E`; if it needs `tools/nomad_web/launcher.py`,
   it takes that file only after the `P8-A` lease is released.
6. After `P8-B` through `P8-F` freeze, run `P8-G`.
7. Run `P8-H` last as the single CLI owner.

## External Gates That Must Not Be Faked

- Real Provider E3 with an approved external credential and authoritative
  upstream evidence.
- Physical iPhone Safari with a normal certificate path and accepted run
  evidence.
- Clean-machine install from the exact candidate artifact on a fresh Apple
  Silicon host.
- Developer ID signing, notarization, stapling, Gatekeeper, and protected
  publication/download parity.
- Any Host identity deletion or authorization flow that still depends on an OS
  approval dialog or external user action.

Nothing in this dispatch may promote those rows above `NOT_RUN` without the
required independent evidence.
