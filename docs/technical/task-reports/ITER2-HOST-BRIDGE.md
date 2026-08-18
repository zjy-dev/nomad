# Iteration 2 Host Relay Command Bridge Report

- Status: implemented and unit-tested against the Nomad compatibility interface
- Binary: `pilot-host-bridge`

The bridge captures and publishes a full `pilot.session` view, polls Relay
messages addressed to Host, strictly parses the `pilot.command` envelope,
executes through the persistent `PilotAdapter` journal, publishes
`pilot.command.result`, and only then ACKs the incoming Relay message. Stable
request IDs therefore survive Relay redelivery and Host restarts without a
second upstream call. `allow_once` remains locally rejected.

Invalid envelopes fail closed with a content-free Rejected result. The Relay
token is required by CLI argument and is never logged or embedded.

Verification: `cargo test` covers envelope parsing and the existing real HTTP
adapter; `cargo clippy --all-targets -- -D warnings` passes. Full stock OpenCode
use remains blocked by `ITER2-STOCK-OPENCODE.md`; the bridge is ready for the
Nomad compatibility interface, not certified against stock events.
