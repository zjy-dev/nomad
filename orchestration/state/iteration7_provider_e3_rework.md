# Iteration 7 Provider E3 Rework

Status: DISPATCH READY

## Why this rework exists

- Audit found `testkit/provider-e3/run_provider_e3.py` `main()` never calls `_run_official()`.
- Current E3 runner therefore never starts the real official Agent even when a valid credential is present.
- As shipped, it cannot cover real `reply`, `deny`, `stop`, `exactly-once`, `reconnect`, or `OutcomeUnknown`.
- The replacement must stay minimal and repo-owned: reuse the latest product topology instead of inventing a separate E3 runtime.

## Design goal

Define one live Provider E3 runner contract that reuses the exact installed bundle and the current product path:

`nomad-web start --remote-local-evidence`
`relay-host -> relay-device -> official opencode -> product-host -> desktop-gateway -> join-gateway -> https-ingress`

The runner must prove only what the repo already owns:

- official Agent launch via bundle launcher;
- Product Host command and receipt contract;
- Gateway command surface;
- command journal / replay / reconnect behavior;
- content-free evidence.

It must not fabricate pending state, must not open a second Agent path, and must not bypass Product Host/Gateway.

## Hard contract

### 1. Credential ownership

- Provider credential enters the system exactly once via stdin/FD supplied to `nomad-web start --credential-stdin`.
- Harness may buffer the secret only long enough to write one private pipe; harness must not place it in argv, env vars, files, logs, receipts, or evidence.
- The only consumer is the official Agent child path already owned by `tools/nomad_web/agent_runtime.py`.
- This rework must keep the existing FD-only launch contract used by `start_foundation()` / `start_remote_local_evidence()` / `start_agent()`.

### 2. Process topology

- Runner must reuse `testkit/remote-v2/run_m3e_product_slice.py` launch shape, not start ad-hoc sidecars.
- Required live roles are the existing seven-process `remote-local-evidence` topology recorded in launcher state v2:
  - `relay-host`
  - `relay-device`
  - `opencode`
  - `product-host`
  - `desktop-gateway`
  - `join-gateway`
  - `https-ingress`
- E3 runner may add harness-local observers only if they do not become business processes and do not create or mutate pending Agent state.

### 3. Product command path

- All writable actions must go through the existing Gateway and Product Host path:
  - GET `/api/commands/capability`
  - POST `/api/commands`
- Runner must not talk directly to internal Agent HTTP routes for writable actions.
- Runner must consume the existing gateway/product schemas:
  - `nomad.gateway.command-capability.v1`
  - `nomad.gateway.command-receipt.v1`
  - `nomad.product-host.command-capability.v1`
  - `nomad.product-host.command-receipt.v1`

### 4. Pending-state rule

- Harness must never synthesize `question_pending`, `permission_pending`, or any fake upstream pending row.
- If a real provider-backed session does not naturally expose the target state, that scenario result is `NOT_RUN`.
- `reply` requires a naturally observed real question/input capability.
- `deny` requires a naturally observed real permission capability.
- `stop` requires a naturally observed live turn with stop capability.
- `duplicate` requires replaying the same accepted command request through the same Gateway/Product Host path.
- `reconnect` requires a real source interruption or runner-controlled process restart that exercises current reconnection/reconciliation logic without inventing pending state.
- `OutcomeUnknown` requires a real uncertain dispatch path through Product Host command authority; if no safe repo-owned trigger exists, result is `NOT_RUN`.

### 5. Status classification

Runner output is per scenario, not one synthetic global PASS:

- `PASS`: the exact scenario executed on the real product path and all required evidence checks passed.
- `NOT_RUN`: prerequisite state never appeared naturally, or the repo does not yet own a safe real trigger.
- `BLOCK`: launcher/topology/identity/TLS/privacy/integrity precondition failed before scenario evaluation.
- `FAIL`: scenario executed on the real path but violated its contract.

No scenario may be upgraded from `NOT_RUN` by unit/fake/synthetic/manual inference.

## Required scenario matrix

The evidence document must include exactly these scenario names:

- `reply`
- `deny`
- `stop`
- `duplicate`
- `reconnect`
- `outcome_unknown`

Required interpretation:

- `reply`: PASS only if a real question capability was observed and a Gateway reply command produced an accepted terminal receipt on the live topology.
- `deny`: PASS only if a real permission capability was observed and a Gateway deny command produced an accepted terminal receipt on the live topology.
- `stop`: PASS only if a real stop capability was observed and a Gateway stop command produced an accepted terminal receipt on the live topology.
- `duplicate`: PASS only if the same request replay returns the same receipt id with `idempotent_replay=true`, and the underlying adapter path executes once.
- `reconnect`: PASS only if a real reconnect/recovery cycle re-establishes an authoritative projection from current product state without fabricating pending state.
- `outcome_unknown`: PASS only if Product Host / Gateway surfaces real `OutcomeUnknown` with `ERR_OUTCOME_UNKNOWN`, and replay of the same request returns the same receipt with `idempotent_replay=true`.

If the corresponding real state never appears, scenario status is `NOT_RUN`.

## Minimum repo-owned implementation contract

### Runner entrypoint

- Keep `testkit/provider-e3/run_provider_e3.py` as the single Provider E3 entrypoint.
- Replace the current gate-only behavior with a real orchestration path that:
  - verifies the bundle;
  - reads one stdin credential;
  - starts the exact bundle through `nomad-web --json start --remote-local-evidence`;
  - discovers current process/state from launcher state v2;
  - drives the existing Gateway command API;
  - emits canonical content-free evidence.

### Reuse requirements

- Reuse `tools/nomad_web.cli` and `tools/nomad_web.launcher` for startup/shutdown.
- Reuse `testkit/remote-v2/run_m3e_product_slice.py` for process topology, TLS, and product-runtime bring-up patterns where possible.
- Reuse existing Product Host / Gateway command contract rather than re-specifying request/receipt behavior in Python.
- Reuse current `host_command_authority` semantics for:
  - exactly-once
  - `idempotent_replay`
  - `OutcomeUnknown`
  - stale/offline/reconciliation gating

### Evidence surfaces

Allowed evidence only:

- bundle digest and source binding;
- launcher state mode / process names / process identities / session alias / run alias;
- gateway capability presence booleans;
- command receipt fields that are already content-free:
  - `action`
  - `status`
  - `error_code`
  - `idempotent_replay`
  - `snapshot_seq`
  - `snapshot_digest`
- scenario status and reason codes;
- privacy scan findings as content-free codes;
- topology and cleanup outcome.

Forbidden evidence:

- raw credential bytes;
- provider env names beyond the allowlisted selector already requested by user;
- raw Agent session ids, prompts, answers, diff contents, permission text, join secrets, comparison codes;
- protected transcript / last-transcript / browser storage / raw logs.

## Minimal work packages

### P7-D1 Runner contract rework

Owner: Python harness

Scope:

- Rework `testkit/provider-e3/run_provider_e3.py` so `main()` drives the real official path.
- Remove the dead “never-calls-`_run_official`” behavior.
- Split startup/preflight/scenario execution/evidence writing into explicit phases.
- Keep evidence canonical and content-free.

Must reuse:

- `tools.nomad_web.cli`
- existing stdin credential read and bundle verification

Must not do:

- direct writable calls to official Agent HTTP
- fake pending injection
- transcript reads

### P7-D2 Live scenario driver over current Gateway/Product Host surface

Owner: Python harness

Scope:

- Add a Gateway client inside Provider E3 harness for:
  - security/bootstrap if needed
  - `/api/commands/capability`
  - `/api/commands`
- Drive only the existing Gateway command contract.
- Record one scenario result per required scenario name.

Must reuse:

- `nomad.gateway.command-capability.v1`
- `nomad.gateway.command-receipt.v1`

Must not do:

- direct writes to Product Host socket
- ad-hoc replay semantics

### P7-D3 Outcome and reconnect classification

Owner: Python harness + product-contract reader

Scope:

- Define repo-owned, content-free rules for when a live observation counts as:
  - `PASS`
  - `NOT_RUN`
  - `FAIL`
  - `BLOCK`
- Reconnect classification must use current product behavior, not legacy alpha behavior.
- `OutcomeUnknown` must be accepted only when the live receipt path returns the existing contract result.

Must reuse:

- `connector/src/host_command_authority.rs`
- `connector/src/product_stock_projector.rs`

Must not do:

- invent a new E3-only receipt/status taxonomy

### P7-D4 Acceptance tests

Owner: focused tests

Scope:

- Update/add tests so the failure mode that triggered this rework is impossible to regress.
- Add one test that proves `main()` reaches the real official launch path when all gates are satisfied.
- Add tests that prove every scenario is `NOT_RUN` rather than fabricated when the corresponding real pending state does not naturally exist.

## Acceptance test list

Required automated tests:

1. `run_provider_e3.py main` invokes the real official launch path under satisfied gates.
2. credential stays stdin/FD-only and is absent from argv/env/evidence.
3. startup uses `nomad-web --json start --remote-local-evidence`.
4. runner rejects direct-Agent writable shortcuts.
5. missing natural question state => `reply: NOT_RUN`.
6. missing natural permission state => `deny: NOT_RUN`.
7. missing live stop capability => `stop: NOT_RUN`.
8. duplicate scenario reuses request id and requires `idempotent_replay=true`.
9. reconnect scenario requires real recovery evidence or returns `NOT_RUN`.
10. `OutcomeUnknown` requires live `ERR_OUTCOME_UNKNOWN` and replay semantics or returns `NOT_RUN`.
11. evidence writer remains canonical and content-free.
12. cleanup stops launcher-owned processes and leaves no owned E3 runtime behind.

Required manual/operator acceptance command shape:

```bash
printf '%s' "$PROVIDER_CREDENTIAL" | \
python3 testkit/provider-e3/run_provider_e3.py \
  --bundle /path/to/bundle \
  --provider OPENAI_API_KEY \
  --credential-stdin \
  --workspace /abs/disposable-workspace \
  --evidence /tmp/nomad-provider-e3-evidence.json
```

Expected result contract:

- startup is real `remote-local-evidence`, not fake/canary-only mode;
- if no natural provider pending appears, scenarios remain `NOT_RUN`;
- if natural provider pending appears, only then may `reply` / `deny` / `stop` move to `PASS` or `FAIL`;
- `duplicate` / `reconnect` / `outcome_unknown` are judged only on the same live topology.

## Non-goals

- No new Agent runtime.
- No second Host command stack.
- No protected transcript consumption.
- No production-readiness claim.
- No attempt to force a provider to emit pending state.
- No browser/mobile/physical phone expansion inside Provider E3.
- No new topology beyond the existing seven-process product slice.

## Handoff summary

This rework converts Provider E3 from a static NOT_RUN gate into a real live runner over the current product topology. The smallest correct path is:

`run_provider_e3.py -> nomad-web start --remote-local-evidence -> official opencode -> product-host -> desktop-gateway / join-gateway -> existing command/receipt contracts`

Everything else is out of scope.
