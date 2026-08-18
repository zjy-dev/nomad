# Controlled Pilot v0.2 Engineering Integration Report

| Field | Result |
| --- | --- |
| Engineering/internal rehearsal | Accepted |
| External Controlled Product Pilot | Blocked |
| PM alignment | Engineering milestone accepted after P0 rework |
| Contract | Session Semantics v0 unchanged |
| Real repositories / Provider credentials | Not used |

## Delivered system

- Rust Nomad compatibility adapter with fixed-version preflight, capture,
  projection, reply/deny/Stop, persistent request deduplication and local
  `allow_once` rejection.
- Persistent Go TEST-ONLY Relay with one-time pairing, ACK/replay behavior,
  restart recovery and scoped cleanup.
- Persistent Rust Host bridge that consumes Relay commands, writes results
  before ACK and separates transport `message_id` from business `request_id`.
- Same-origin Node Gateway that holds the Relay token server-side, serves the
  Mobile build, distinguishes RelayReceived from HostAccepted and requires TLS
  material for non-loopback binding.
- Mobile task console with explicit demo/lab routes, user-language activity,
  deny/Stop-only Action, fail-closed state gates and no sample diff fallback.
- Content-free doctor, telemetry validation, Pilot acceptance gates and
  proposed Pilot Security Note.

## Integration evidence

`run_vertical_slice` launches the compatibility server, Rust adapter and
file-backed Go Relay. It proves capture/diff facts, Relay restart recovery,
reply idempotency, deny/Stop acceptance, `allow_once` rejection, cleanup and
content-free acceptance.

`run_gateway_slice` launches four processes: compatibility server, Go Relay,
Rust Host bridge and Node same-origin Gateway. It proves the default API Session
path, RelayReceived-to-HostAccepted transition and the same business request
after a real Host restart. The test exposed and fixed an important cross-layer
bug: a transport delivery must use a fresh `message_id`; only `request_id` is
stable across retries.

The browser smoke proves that the default route does not fall back to demo when
the Gateway is absent, `?demo=1` is the explicit local product demo and
`?lab=1` is the explicit trace lab. It also covers 390x844 layout, empty
authoritative Changes, deny/Stop-only Action and Stale version mismatch.

## PM rework completed

- Mobile no longer defaults to deterministic data in deployment composition.
- Same-origin Gateway and TLS bind guard are implemented and unit-tested.
- Relay commands now reach the persistent Host adapter and return explicit
  command results.
- Stop no longer converts RelayReceived or HostAccepted into a false Cancelled
  state. Only durable Session events may produce Cancelled.
- Official npm `opencode-ai@1.18.16` was run and captured. The result is an
  explicit adapter **NO-GO**, not a fake certification.
- PRD-to-evidence traceability is recorded in
  `docs/technical/iteration-2-traceability.md`.

## External Pilot blockers

1. Stock OpenCode events use `id/type/properties` and unbounded SSE without
   upstream Nomad seq/timestamp/durable fields. A stock event projector and
   snapshot reconciliation path must be implemented and tested.
2. A disposable real Provider task must produce authentic question, pending
   permission, permission winner, workspace diff, Stop and reconnect evidence.
3. The Host must generate a verified workspace baseline before Changes can be
   authoritative; current Gateway correctly marks baseline-less diff invalid.
4. Real non-loopback TLS/device deployment and data deletion must be reviewed
   and signed by a named Security DRI.
5. Discovery, usability and the ten-person external Pilot have not occurred.

These are real gates. They cannot be closed by fixtures, code comments, a
developer signature or another synthetic test.

## Verification summary

```text
Rust: cargo fmt --check, cargo test, cargo clippy -D warnings — PASS
Go: go vet, go test, go test -race — PASS
Mobile: 102 tests, TypeScript/Vite build, process bridge build — PASS
Gateway: 2 Node tests — PASS
Python: conformance 5, faults 16, E2E 28, fake OpenCode 3, Pilot 8 — PASS
Vertical slice: ITER2_VERTICAL_SLICE — PASS
Gateway slice: GATEWAY_HOST_RELAY_SLICE — PASS
Browser: product/demo/lab/safety at 390x844 — PASS
Official stock contract capture: version 1.18.16 — PASS, adapter verdict NO-GO
```

No commit was created. The pre-existing modified process-loop transcript was
preserved as user workspace state and is not an Iteration 2 product deliverable.
