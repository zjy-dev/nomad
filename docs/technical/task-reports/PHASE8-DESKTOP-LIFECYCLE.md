# Phase 8 Desktop Lifecycle Coordinator

## Verdict

The repo-owned Desktop Web reset and uninstall path uses a dedicated lifecycle
coordinator. It is mechanical product evidence, not production release
evidence. `production_ready` remains false; Provider E3, physical Safari,
clean-machine installation, Developer ID, notarization, and publication remain
`NOT_RUN`.

## Contract

- The coordinator runs in a session and process group separate from the remote
  workload. Normal stop and restart validate and reap its identity.
- Launcher readiness has two phases. The child first proves initialization; the
  launcher publishes the bound run state and releases it; only after journal
  reconciliation and Gateway bootstrap does the child prove it is operational.
- Gateway and coordinator communicate through fixed inherited descriptors with
  bounded, canonical, exact-key frames. No provider or TLS credential enters
  this channel, argv, environment, state, logs, or public responses.
- Browser-generated operation IDs survive a lost HTTP response. A request is
  committed only after its durable `ACCEPTED` record is returned, using an
  internal random challenge that is never exposed to the browser.
- Reset and uninstall are single-flight. Disconnect is not success; users query
  the exact operation with `nomad-web operation-status --operation-id <id>`.
- A live committed worker remains in progress. Only a proven-dead worker is
  reconciled, and uncertain post-commit state is `OUTCOME_UNKNOWN` without
  replay. Legacy v1 journals are read conservatively and migrated to v2.
- Reset clears remote state while preserving the installed bundle and Host
  identity. Coordinator-owned uninstall performs reset then removal under the
  same lifecycle lock. Direct uninstall remains fail-closed while remote state
  exists.

## Verification

- Lifecycle coordinator and CLI focused tests: 32/32 PASS.
- Launcher focused tests: 23/23 PASS, including a real Relay/Gateway/Ingress/
  coordinator start-stop-restart-stop cycle with persisted run state.
- Gateway tests: 102/102 PASS.
- Desktop/phone Web tests: 299/299 PASS.
- TypeScript check and production Vite build: PASS.
- Real Node Gateway process-group reset/uninstall harness: PASS; coordinator
  completes after the Gateway exits, reset preserves install, uninstall removes
  owned home state, and the external journal records the terminal result.

The real remote-launcher test replaces Host/Agent identity providers and the
external TLS probe because this machine's Keychain foreground authorization is
currently denied. It is not Provider E3 or physical-phone evidence.
