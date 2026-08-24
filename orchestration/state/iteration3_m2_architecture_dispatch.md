# Iteration 3 M2 Architecture Dispatch

## Objective

Run one Provider-backed task in a project-owned disposable workspace through
the locked OpenCode 1.18.16 runtime and the Host -> Relay -> Gateway -> Mobile
path. M2 must observe and verify real question, permission, diff, reply, Stop,
and reconnect facts without persisting user content or credentials.

## WP1: Real stock capture and credential isolation

- Ownership: new `testkit/stock-opencode/real_task_*` files and tests.
- Deliverables: content-free receipt schema/store, redactor, OpenAPI command
  request/response shape capture, locked-runtime launcher, disposable workspace
  lifecycle, and credential-scope scanner.
- Credential rule: an explicitly named temporary credential may enter only the
  OpenCode subprocess. Ambient OpenCode auth and the user's HOME/XDG state are
  forbidden. Host, Relay, Gateway, Mobile, receipts, logs, argv, and workspace
  never receive the credential.
- Real lifecycle evidence remains BLOCKED until a temporary credential is
  explicitly available. Fake and synthetic runs cannot upgrade this verdict.

## WP2: Verified stock mapper and commands

- Ownership: `connector/src/stock_opencode.rs`, required journal APIs, stock
  mapper tests, and minimal Cargo changes.
- Dependency: WP1 receipts for exact event properties and command shapes.
- Deliverables: only evidence-backed event mappings; exact Reply, deny, and Stop
  HTTP boundaries; Host durable seq; restart reconciliation; business-request
  at-most-once. Unknown types stay fail-closed. `allow_once=false`.

## WP3: Real Host-to-Mobile wiring

- Ownership: `connector/src/bin/pilot_host_bridge.rs`, new bridge tests, and new
  integration glue files.
- Dependency: WP2 API for real execution; opaque alias and leak guards may be
  scaffolded before WP2.
- Deliverables: no raw stock Session/question/permission IDs or properties cross
  the Host boundary; run-local aliases and content-free results only. Restart
  recovery uses authoritative stock snapshots rather than SSE replay.

## WP4: Harness-owned receipt verifier

- Ownership: `testkit/pilot/iteration3_*` files.
- Dependency: receipt schema can be implemented now; PASS verifier waits for
  WP1-WP3 real receipts.
- Deliverables: read and validate receipt records itself; recompute digests;
  verify process/run binding, ordering, credential scope, at-most-once, cleanup,
  and content policy. Candidate claims remain non-evidence.

## Merge order

1. WP1 schema/isolation and WP4 negative verifier tests.
2. Real Provider capture establishes lifecycle and command facts.
3. WP2 implements only captured facts.
4. WP3 connects the verified adapter to the existing product path.
5. WP4 verifies the complete receipt store and may enable PASS.

## M2 gate

PASS requires official locked provenance, project-owned disposable workspace,
temporary credential isolated to OpenCode, all required real lifecycle facts,
exact Reply/deny/Stop shapes, Host-to-Mobile operation, restart convergence,
zero duplicate upstream execution, cleanup, and content-free receipts.

No-Go: ambient/personal auth, fake lifecycle evidence, guessed request shapes,
self-asserted candidate claims, raw identifiers/content outside the adapter, or
exposed/accepted mobile `allow_once`.
