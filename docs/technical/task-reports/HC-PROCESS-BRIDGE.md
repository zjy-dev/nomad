# HC-PROCESS-BRIDGE Completion Report

- Status: Implemented; all tests pass; clippy clean
- Owner: Host lane
- PR/Commit: uncommitted workspace
- Completed at: 2026-08-17

## Outcome

Implemented the test-only Host side of the Host → Relay → Mobile process bridge
described in `testkit/process-loop/spec.md`. The bridge:

- Publishes a synthetic `NeedsPermission` checkpoint to Mobile on startup.
- Polls Relay for host-bound messages and dispatches each through `BridgeDispatcher`.
- Handles `pair.request` (returns `pair.confirmed` with `comparison_code`).
- Handles `command` actions: `deny` and `stop` through `PermissionService` + journal,
  `allow_once` unconditionally rejected with `ERR_SAFETY_BLOCKED`.
- Posts `command.result` back to Mobile with explicit `status`, optional `error_code`,
  `error_message`, and `comparison_code`.
- ACKs every processed message (including unknown types) to the Relay.

## Files

| File | Purpose |
|---|---|
| `connector/src/process_bridge.rs` | Core module: `RelayClient` trait, `UreqRelayClient`, `BridgeDispatcher`, message types, unit tests |
| `connector/src/bin/process_bridge.rs` | CLI binary: checkpoint publish + poll/dispatch/result/ACK loop |
| `connector/tests/process_bridge_tests.rs` | Integration-level dispatch tests (deny, stop, allow_once, duplicates, unknown types, serialization) |
| `connector/Cargo.toml` | Added `ureq` dependency and `[[bin]]` entry |
| `connector/src/lib.rs` | Re-exports bridge types |

## Architecture

```
BridgeDispatcher (owns Rc<CommandJournal>)
  ├── handle_pair_request  → CommandResult { status: "HostAccepted", comparison_code }
  ├── handle_command("deny")  → PermissionService::deny() → journal → CommandResult
  ├── handle_command("stop")  → PermissionService::stop()  → journal → CommandResult
  ├── handle_command("allow_once") → CommandResult { status: "Rejected", error_code: "ERR_SAFETY_BLOCKED" }
  └── unknown types → Ok(None)  (ACK only, no reply)
```

Using `Rc<CommandJournal>` avoids lifetime-parameterized structs and eliminates
the `Box::leak` memory leak pattern that was present in earlier test helpers.

## Verification

- `cargo fmt` -> OK
- `cargo test` -> 43 (unit) + 40 (integration) + 17 (process-bridge integration) = all PASS
- `cargo clippy -- -D warnings` -> OK

## Deviations

- Spec endpoint paths match exactly: `POST /v1/test/messages`, `GET /v1/test/messages?channel=...&target=...`, `POST /v1/test/ack`.
- `allow_once` always returns `Rejected/ERR_SAFETY_BLOCKED` per spec requirement.
- No network is used in unit tests — all dispatch paths are exercised with in-memory SQLite journal and value assertions.
