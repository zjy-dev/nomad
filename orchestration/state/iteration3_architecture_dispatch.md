# Iteration 3 Architecture Dispatch

## Decision

Iteration 3 keeps OpenCode as the only Session owner and replaces the fake
finite replay assumption with a stock anti-corruption adapter. Nomad owns its
durable sequence and reconciliation state. Session Semantics v0, Relay, Gateway,
and Mobile remain downstream of that boundary.

## Lane A: Official stock contract evidence

- Ownership: `testkit/stock-opencode/**` and new sanitized stock evidence under
  that directory only.
- Deliverable: reproducible version/OpenAPI/event/snapshot capture, content-free
  provenance, fixture validation, and an explicit evidence classification.
- Acceptance: official `opencode-ai@1.18.16`; raw `id/type/properties` verified;
  no credential, prompt, source, path, command, or diff content committed.
- Dependency: none. Its facts unblock Lane B mapping.

## Lane B: Stock adapter and Host persistence

- Ownership: `connector/src/opencode_adapter.rs`, `connector/src/journal.rs`, new
  `connector/src/stock_*.rs`, required `connector/src/lib.rs` exports, and new
  stock-focused Rust tests.
- Deliverable: stock DTO isolation, Host-owned transactional Nomad seq, restart
  persistence, snapshot reconciliation, stock reply/deny/Stop requests, and
  compatibility-path regression tests.
- Acceptance: `cargo fmt --check`, `cargo test`, and
  `cargo clippy --all-targets -- -D warnings`; no Session Semantics v0 change.
- Dependency: Lane A contract facts.

## Lane C: Official-binary real-slice harness

- Ownership: new `testkit/pilot/iteration3_*` files and an optional new
  `docs/technical/task-reports/ITER3-*` report only.
- Deliverable: orchestrate official binary, disposable workspace, Host, Relay,
  Gateway, and Mobile; distinguish PASS, FAIL, BLOCKED, and SKIP; never turn
  missing Provider credentials into a passing result.
- Acceptance: harness unit tests run without credentials; only an official
  Provider-backed disposable task may produce a stock PASS evidence bundle.
- Dependency: scaffold may proceed now; stock assertions merge after Lane B.

## Merge order and review

1. Merge/review Lane A contract facts.
2. Rebase Lane B mapping on those facts and pass Rust regression.
3. Connect Lane C to Lane B and run the content-free mechanics path.
4. Run the real disposable task only with operator-supplied credentials.
5. Independent architecture/evidence review may reject any lane; Product Owner
   alone advances M1/M2 gates.

## Invariants

- `allow_once=false`.
- Raw stock DTOs never leave the adapter.
- Upstream SSE is observation, not durable replay.
- Fake/synthetic/unit evidence never counts as stock product evidence.
- Provider credentials and user content never enter the repository.
- No production E2EE, native app, self-developed Runtime, or second Agent here.
- Preserve `testkit/process-loop/last-transcript.json`.
