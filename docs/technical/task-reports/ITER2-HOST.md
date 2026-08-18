# ITER2-HOST — Controlled Pilot v0.2 Host lane

| Field | Value |
| --- | --- |
| Date | 2026-08-18 |
| Scope | PRD-203, PRD-205, PRD-206, PRD-207, PRD-208, PRD-209 first HTTP vertical slice |
| Contract | Session Semantics v0 / schema version `1.0.0`, unchanged |
| Upstream gate | exact `http://127.0.0.1:4096`, OpenCode `1.18.16` |
| Result | Runnable against the deterministic fake interface; live OpenCode certification remains open |

## Outcome

The Host lane now has an executable Nomad compatibility HTTP path rather than a fixture-loading
shortcut. `pilot-adapter` performs the fixed-version preflight, obtains a
Session plus a bounded durable-event capture and authoritative diff over HTTP,
projects those facts to the existing Session Semantics v0 event/snapshot types,
and writes compact machine-readable JSON to stdout. It can optionally publish a
`session.checkpoint` using the existing `UreqRelayClient`. Stock OpenCode
certification is currently No-Go; see `ITER2-STOCK-OPENCODE.md`.

The same path submits reply, deny, and Stop over HTTP. A SQLite command journal
is the Host `request_id` idempotency boundary. An existing final result is
returned without a second upstream call; an interrupted `Executing` record is
returned as `OutcomeUnknown` and is never automatically retried. `allow_once` is
recorded and rejected locally with `ERR_SAFETY_BLOCKED` before any upstream call.

## Fixed interface contract

| Operation | HTTP interface | Host rule |
| --- | --- | --- |
| Preflight | `GET /global/health` | `healthy=true` and version exactly `1.18.16` |
| Session | `GET /session/:id` | response ID and version must match the request/gate |
| Durable events | `GET /event?sessionID=:id&after=:seq` | bounded JSON array or finite SSE capture; stable ID, positive contiguous seq, timestamp, `durable=true`; unknown events fail closed |
| Diff | `GET /session/:id/diff` | response is the authoritative current diff; empty means no Changes data |
| Reply | `POST /session/:id/prompt_async` | JSON and `Idempotency-Key` both carry `request_id` |
| Deny | `POST /session/:id/permissions/:permissionID` | sends `allow=false`; only an upstream response declaring `upstream_pending_bound=true` proves the fake pending binding |
| Stop | `POST /session/:id/abort` | stable `request_id` plus `target_turn_id`; acceptance is not presented as observed cancellation |

Supported upstream event projection is deliberately closed: session create/update
and status transitions, question messages, permission request/resolution, tool
start/completion/error, diff/file edit, and compaction. Malformed JSON/SSE, an
empty stream, a gap, a duplicate event ID, a non-durable event, cross-Session
data, an unknown type or unknown status all stop capture with an incompatible
protocol error. Network ambiguity returns `ERR_HOST_OFFLINE` for reads; a command
whose upstream outcome becomes ambiguous remains durably `OutcomeUnknown`.

## Executable paths

From the repository root:

```bash
python3 testkit/fake-opencode/server.py --scenario happy
cargo run --manifest-path connector/Cargo.toml --bin pilot-adapter -- \
  capture --session-id pilot-session
```

The capture output contains `source`, upstream Session facts, projected v0
`events`, a digest-bearing v0 `snapshot`, and authoritative `diff`. Relay
publishing is opt-in and requires all three arguments; there is no default or
embedded credential:

```bash
cargo run --manifest-path connector/Cargo.toml --bin pilot-adapter -- \
  capture --session-id pilot-session \
  --relay-url http://127.0.0.1:8080 \
  --relay-token "$NOMAD_TEST_RELAY_TOKEN" \
  --relay-channel pilot-session
```

Commands accept a JSON Session Semantics v0 command and a persistent journal:

```bash
cargo run --manifest-path connector/Cargo.toml --bin pilot-adapter -- \
  command --journal /tmp/nomad-pilot.sqlite3 --command-json \
  '{"command_type":"stop","request_id":"req-stop-1","session_id":"pilot-session","seq":7,"target_turn_id":"turn-1"}'
```

## Fake OpenCode evidence

`testkit/fake-opencode/server.py` uses only the Python standard library and
`argparse`. It refuses non-loopback binds and has no credential fields. Its
deterministic scenario includes question, pending permission, authoritative diff,
disconnect/reconnect facts, and stable durable IDs/seq. It deduplicates all
three writable operations and lets the first deny resolve the one pending
permission; a later distinct deny returns `ERR_REQUEST_STALE`. Fault scenarios
cover version mismatch, unknown event, and seq gap.

The real CLI process run produced:

- snapshot `NeedsPermission`, `snapshot_seq=7`, active turn `turn-1`, active
  permission `perm-1`, one diff file, and a SHA-256 digest;
- first reply `HostAccepted`, replay marked `idempotent_replay=true`;
- deny `HostAccepted` with `upstream_pending_bound=true`;
- Stop `HostAccepted`;
- allow_once `Rejected / ERR_SAFETY_BLOCKED`;
- fake counters `reply=1, deny=1, stop=1`, proving the reply replay and local
  allow_once rejection did not create extra upstream calls.

## Verification

Executed from `connector/` unless noted:

```text
cargo fmt --all -- --check
  PASS

cargo test
  PASS: 49 library + 40 contract integration + 2 real HTTP +
        17 process bridge tests; 0 failed

cargo clippy --all-targets -- -D warnings
  PASS

python3 -m unittest discover -s testkit/fake-opencode -p 'test_*.py' -v
  PASS: 3 tests; 0 failed

cargo run --quiet --bin pilot-adapter -- capture --session-id pilot-session
  PASS: compact JSON emitted from a real fake-server subprocess
```

The HTTP integration test starts the executable Python server and verifies
network failure, exact-origin rejection, version mismatch, event gap, unknown
event, capture/digest, reply dedup, deny pending and stale behavior, Stop, and
allow_once rejection. Existing `nomad-connector` and `process-bridge` tests remain
green.

## Deviations and unresolved risks

1. **No live OpenCode certification.** Repository provenance explicitly says
   prior fixtures were schema-derived and no live `1.18.16` server was available.
   This iteration validates real HTTP and process boundaries against a fake that
   implements the frozen interface. It does not claim that stock OpenCode
   `1.18.16` emits stable durable ID/seq/timestamp fields or finite replay on
   `/event`. A live capture must confirm or revise this boundary before Pilot.
2. **PRD-207 remains No-Go for stock OpenCode.** The fake proves binding to its
   one actual pending permission and competition behavior. It is not evidence of
   stock OpenCode's same-pending and race semantics. Until live proof exists, the
   product must not claim deny certification; Stop remains the safe fallback.
3. **Acceptance is not terminal observation.** Reply, deny, and Stop HTTP results
   report Host acceptance. Cancellation/completion must come from later durable
   events; Relay receipt or HTTP acceptance never fabricates `Cancelled`.
4. **SSE is a bounded capture, not a reconnect daemon.** The parser accepts a
   finite SSE response for capture compatibility. Continuous cursor management,
   retention/compaction recovery, and long-lived reconnect ownership are still
   required for the full PRD-215 Host responsibility.
5. **Diff baseline metadata is limited by the frozen schema.** The adapter
   forwards the upstream file diff and does not invent baseline/invalidity
   fields outside Session Semantics v0. Pilot use requires the fixed upstream
   interface to make that diff authoritative for the current workspace.
6. **Relay checkpoint publishing is compatible but optional.** It uses the
   existing test Relay endpoint/client and requires a caller-supplied token. It
   is not evidence of production identity, TLS, or E2EE.

No contract schema, product document, Mobile lane, Relay lane, process-loop
transcript, or other lane report was modified. No commit was created.
