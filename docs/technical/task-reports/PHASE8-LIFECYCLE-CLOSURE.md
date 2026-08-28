## Background

P8-E closes the visible Pair / Revoke / Reset / Uninstall lifecycle for the
installed desktop-plus-phone flow. The required behaviors were:

- `revoke(active device)` stays runtime-safe and advances epoch through the
  existing Product Host authority path;
- `reset_remote_access` is stop-only and clears owned pairing / registry /
  mailbox state while preserving the installed bundle and Host identity;
- `uninstall` removes owned runtime and install state, but reports Host
  identity disposition explicitly rather than implying identity deletion.

The dispatch also required stable recoverable states for lost-key, stale-cookie,
replaced-device, and cancelled flows, plus restrained desktop UI that does not
push dangerous actions aggressively.

## Goal

Ship one product-facing lifecycle slice that:

- gives desktop users one state-first safety console for pair / revoke / reset /
  uninstall;
- keeps remote-phone recovery copy explicit and recoverable;
- avoids widening trust boundaries or adding arbitrary local command surfaces;
- preserves the existing zero-upstream revoke behavior by keeping active-device
  revocation on the existing Product Host path.

## Solution

### Launcher-owned lifecycle operations

`tools/nomad_web/launcher.py`

- Added `reset_remote_access(config)`:
  - acquires the lifecycle lock;
  - stops the owned runtime if present;
  - clears the private remote-state directory via existing
    `_cleanup_device_registry()` coverage, which removes:
    - `host-device-registry.sqlite3`
    - `pairing-coordinator.sqlite3`
    - `remote-mailbox.sqlite3`
    - `relay-v2.sqlite3`
    - their WAL / SHM sidecars;
  - returns schema
    `nomad.web-companion.remote-access-reset.v1` with
    `host_identity_disposition = retained`.

- Added `uninstall_lifecycle(config)`:
  - reuses existing `uninstall_foundation(config)` safety and ownership checks;
  - returns schema `nomad.web-companion.uninstall-result.v1` with explicit
    `remote_access = CLEARED`, `install_state = REMOVED`,
    `host_identity_disposition = retained`.

This keeps lifecycle ownership in launcher code and avoids inventing a new
destructive cleanup path elsewhere.

### Desktop Gateway bridge

`mobile-reference/pilot-gateway/server.mjs`

- Added desktop routes:
  - `POST /api/desktop/remote-access/reset`
  - `POST /api/desktop/install/uninstall`
- Added a fixed lifecycle bridge, not an arbitrary shell surface:
  - bridge calls `python3 -m tools.nomad_web.cli --json <command>` with only
    the reviewed fixed commands;
  - parses JSON output and narrows it into desktop-facing public schemas:
    - `nomad.desktop.remote-access-reset.v1`
    - `nomad.desktop.uninstall-result.v1`
- Kept `revoke` on the existing Product Host / pairing coordinator path.

`mobile-reference/pilot-gateway/pairing-session.mjs`

- Added strict desktop validators for:
  - `nomad.desktop.remote-access-reset.v1`
  - `nomad.desktop.uninstall.v1`

### Desktop UI

`mobile-reference/src/ui/pairing-api.ts`

- Added typed client methods:
  - `resetRemoteAccess()`
  - `uninstall()`
- Added strict decoders for the new desktop lifecycle result schemas.

`mobile-reference/src/ui/PairingConsole.tsx`

- Kept the console state-first and restrained:
  - active paired device card with explicit revoke confirmation;
  - separate “Remote Access Safety” card for:
    - reset remote access;
    - uninstall;
  - explicit copy that Host identity is retained;
  - danger actions behind a second confirmation layer.

`mobile-reference/src/ui/styles.css`

- Added narrow style support for the new danger confirmation block and screen
  reader-only labels.

### Phone recovery states

`mobile-reference/src/ui/PhonePairingScreen.tsx`

- Added explicit recoverable states and messages for:
  - `lost-key`
  - `stale-cookie`
  - `replaced-device`
  - `cancelled`
  - `revoked`
- Mapped `PAIRING_NOT_STARTED` to a stable stale-session recovery message.
- Mapped remote session failures `PAIRING_REPLACED` and `PAIRING_CANCELLED` to
  explicit user-facing recovery instructions.

## Result

Modified files:

- `tools/nomad_web/launcher.py`
- `mobile-reference/pilot-gateway/server.mjs`
- `mobile-reference/pilot-gateway/pairing-session.mjs`
- `mobile-reference/pilot-gateway/pairing-gateway.test.mjs`
- `mobile-reference/src/ui/pairing-api.ts`
- `mobile-reference/src/ui/PairingConsole.tsx`
- `mobile-reference/src/ui/PhonePairingScreen.tsx`
- `mobile-reference/src/ui/PairingUI.test.tsx`
- `mobile-reference/src/ui/styles.css`

Focused verification:

- `node --test mobile-reference/pilot-gateway/pairing-gateway.test.mjs`
- `cd mobile-reference && npm test -- --run src/ui/PairingUI.test.tsx`
- `cd mobile-reference && npm run build -- --mode test`

Notes:

- No `cli.py` changes.
- No transcript access.
- No `connector` changes were required for this slice.
- `revoke(active device)` still relies on the existing Product Host authority
  path, which preserves the previously frozen zero-upstream stale-device rule.
