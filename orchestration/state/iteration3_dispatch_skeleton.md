# Iteration 3 M1 Dispatch Skeleton

This is a Product Owner constraint skeleton, not the final technical plan. The
delivery architect must validate, adjust, and own dispatch.

## Lane A: Stock contract evidence

- Own only `testkit/stock-opencode/**` and new sanitized stock evidence fixtures.
- Capture official `id/type/properties` event and relevant OpenAPI/snapshot shapes.
- Never store Provider credentials, prompts, source, paths, or personal data.
- Deliver a reproducible local capture command and provenance manifest.

## Lane B: Host stock adapter and persistence

- Own `connector/src/opencode_adapter.rs`, stock-adapter modules approved by the
  architect, journal schema/migrations, and adapter-focused Rust tests.
- Parse stock DTOs only inside the adapter. Host assigns monotonic Nomad seq and
  reconciles stock snapshots after reconnect.
- Preserve the compatibility path until stock regression coverage exists.

## Lane C: Real-slice harness and acceptance

- Own new Iteration 3 harness/acceptance files under `testkit/pilot/**`; do not
  edit Host implementation or existing process-loop transcript.
- Orchestrate official OpenCode, disposable workspace, Host, Relay, Gateway, and
  Mobile; distinguish unavailable credentials from product failure.
- Synthetic runs may validate mechanics but cannot produce a stock PASS verdict.

## Merge dependency

Lane A contract evidence -> Lane B stock mapping/persistence -> Lane C real slice.
Lane C may scaffold in parallel, but its stock assertions merge only after Lane B.

## Product hard gates

- `allow_once=false` remains invariant.
- Session Semantics v0 does not change without an evidence-backed ADR.
- No claim of real product evidence without official binary provenance and a
  disposable Provider-backed task.
