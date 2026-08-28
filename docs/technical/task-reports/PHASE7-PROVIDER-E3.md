# Phase 7 Provider E3

## Status

P7-D is now scoped as a live runner over the existing product topology, but it
still depends on operator TLS inputs that are being frozen separately in P7-C.
Until those inputs are provided at runtime, the harness correctly returns
`BLOCK` instead of inventing a local TLS path.

## Implemented contract

- The runner entrypoint remains `testkit/provider-e3/run_provider_e3.py`.
- Startup is the exact bundle contract:
  `bundle/bin/nomad-web --json start --remote-local-evidence`
- Shutdown is the exact bundle contract:
  `bundle/bin/nomad-web --json stop`
- Credential enters once via stdin and is written only to one private launcher
  pipe. It is not copied into argv, env, files, logs, state, or evidence.
- Writable actions are restricted to desktop Gateway:
  `GET /api/commands/capability`
  `POST /api/commands`
- The harness refuses direct-Agent writable shortcuts.
- Evidence is canonical, content-free, and written with exclusive `0600`
  semantics.

## Scenario policy

The runner records exactly these scenario names:

- `reply`
- `deny`
- `stop`
- `duplicate`
- `reconnect`
- `outcome_unknown`

Current classification rules:

- Missing natural question state keeps `reply` at `NOT_RUN`.
- Missing natural permission state keeps `deny` at `NOT_RUN`.
- Missing live stop capability keeps `stop` at `NOT_RUN`.
- `duplicate` only passes when replay returns the same receipt and
  `idempotent_replay=true`.
- `reconnect` remains `NOT_RUN` until a safe real reconnect trigger is wired.
- `outcome_unknown` remains `NOT_RUN` until a safe real
  `ERR_OUTCOME_UNKNOWN` trigger is wired.

No synthetic fixture or mock may upgrade a scenario from `NOT_RUN` to `PASS`.

## Current boundary

P7-D does not generate or trust its own TLS materials. Operator-provided
`public-origin`, `https-listen`, `tls-cert-fd`, and `tls-key-fd` are required
for the real launcher call. Missing those inputs is an expected `BLOCK`, not a
runner bug.

## Verification

Focused tests currently cover:

- real `main()` reachability into the exact `remote-local-evidence` launcher
  path
- stdin-only credential intake
- allowlist and missing-input gates
- direct-Agent writable shortcut rejection
- per-scenario `NOT_RUN` boundaries
- duplicate replay idempotence rule
- exclusive private evidence writing

These tests validate control-flow and contract boundaries only. They do not
claim live Provider E3 `PASS` evidence by themselves.
