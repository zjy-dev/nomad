# Iteration 4 Agent-Neutral Boundary Audit

Status: DEFER LARGE REFACTOR / DEFINE SECOND-ADAPTER GATE

## Finding

The product contracts, projection/reducer logic, and opaque Relay protocol are
largely agent-neutral. The Rust `connector` package is not yet structurally
agent-neutral: its crate root exports both neutral models and OpenCode-specific
types; its journal includes `stock_*` tables and methods; and Host startup and
native supervisor authorization are tied to `stock_opencode` release facts.

This does not block the first OpenCode Controlled Pilot. It does mean that
support for a second code agent is not yet proven and must not be described as
plug-and-play. A broad refactor is deferred until a concrete second adapter is
selected, so the boundary is extracted against real differences rather than a
speculative abstraction.

## Current neutral surface

- `contracts/schemas/`: Nomad Event, Command, Snapshot and shared protocol data.
- `connector/src/projection.rs` and `connector/src/snapshot.rs`: Nomad state and
  deterministic projection.
- `relay/protocol.go` and `relay/mailbox.go`: opaque transport and mailbox.
- `mobile-reference/src/contracts/`: consumer types, digest and reducer.

## Current OpenCode-specific surface

- `connector/src/opencode_adapter.rs` and `connector/src/stock_opencode.rs`.
- `connector/src/native_launch/`: locked OpenCode installation and process proof.
- `testkit/stock-opencode/`: fixture, lifecycle evidence and verifier suite.
- OpenCode route/event details used by the native audit and SSE helpers.
- `connector/src/journal.rs` `stock_*` storage and methods.
- `connector/src/host_startup.rs` and `connector/src/native_supervisor.rs`
  dependency on stock OpenCode release authorization.

## Gate before a second agent

Add a conformance test that fails whenever the neutral public surface exposes
adapter-specific types or route/version constants. Only then extract a minimal
`AgentAdapter` boundary with neutral inputs and outputs for preflight, session,
events, diff, reply, permission decision, and stop. Adapter-owned cursor and ID
mapping stay behind that boundary, and Host authorization becomes an
`AdapterReleaseAuthorization` rather than an OpenCode-specific type.

No second-agent implementation is dispatched in this phase. The first product
must first complete a real OpenCode Controlled Pilot.
