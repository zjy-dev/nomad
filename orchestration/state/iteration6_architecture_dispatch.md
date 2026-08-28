# Iteration 6 Architecture Dispatch

Status: ACTIVE ATOMIC PACKAGE ONLY

This dispatch defines only the first Gate 3 atomic package:

- Host-owned persistent single-device registry
- one-time pairing challenge plus possession proof
- monotonic pairing epoch
- immediate revocation
- replacement of `ProductCommandService` hardcoded local device facts

This package does not design Relay transport, remote browser networking, or any
transcript-based flow. `command journal` semantics remain frozen.

## Frozen Premises

These facts are already established and are not redesigned here:

- `host_command_authority.rs` already binds
  `principal_id` / `device_id` / `pairing_epoch` inside
  `AuthenticatedDeviceSession` and `HostCommandEnvelope`.
- `product_stock_projector.rs` is the current gap because
  `ProductCommandService` hardcodes:
  - `local-product-user`
  - `local-gateway-device`
  - `pairing_epoch = 1`
- the command journal is already the durable replay authority and is treated as
  security-frozen in this package
- `allow_once=false` remains outside scope and stays hard-blocked

## Atomic Package

`WP6-G3a Host-owned persistent device registry`

Goal:

- remove the startup-time hardcoded local device identity from the writable Host
  path
- make current device authority persistent across Host restart
- make revocation durable and immediate
- ensure any stale capability, nonce, or prior epoch produces zero new upstream
  command dispatches

Non-goals:

- no Relay protocol or remote network path
- no browser cookie or tab identity design
- no multi-device registry
- no transcript inspection or transcript-derived authority
- no command journal redesign
- no change to browser command schemas in this package

## Design Summary

Introduce a Host-owned persistent SQLite registry with exactly one active device
slot and at most one pending pairing challenge. The registry stores only:

- device identity facts needed by Host authority
- monotonic pairing epoch
- pending one-time challenge state
- revocation history needed for restart-safe enforcement
- pending possession public key only until the challenge is terminal

It never stores:

- device private keys
- transport keys
- command authority key
- raw command content
- browser session state

`ProductCommandService` stops caching one immutable `AuthenticatedDeviceSession`
at startup. Instead:

- `capability()` reads the current active non-revoked device facts from the
  registry every time
- `execute()` reads the current registry facts every time before non-replay
  acceptance
- exact replay retrieval remains journal-owned and must produce zero additional
  upstream dispatches

The Host still constructs the final in-memory `AuthenticatedDeviceSession` for
each authority operation using:

- current registry `principal_id`
- current registry `device_id`
- current registry `pairing_epoch`
- existing Host `run_id`
- existing Host `session_id`
- existing bootstrap `command_authority_key`

The registry never persists the command key.

## File Ownership

Owned by this package:

- `connector/src/host_device_registry.rs`
  - new module for the persistent single-device registry
  - owns SQLite open policy, schema migration `v1`, challenge issue/consume,
    revocation, and current-facts reads
- `connector/src/product_stock_projector.rs`
  - replace `ProductCommandService.device` hardcoding with registry-backed
    current-device resolution on each capability and execute path
- `connector/src/product_host_bootstrap.rs`
  - extend bootstrap schema with one persistent `device_registry_path`
  - validate path policy separately from the run-scoped command journal path
- `connector/src/host_command_authority.rs`
  - keep the existing binding contract
  - add any small constructor or helper needed to create an
    `AuthenticatedDeviceSession` from freshly loaded registry facts
- `connector/src/lib.rs`
  - export the new registry module if needed by current crate layout
- `tools/nomad_web/launcher.py`
  - allocate and pass a stable Host-owned registry path under persistent Nomad
    home state, not the run directory

Explicitly not owned here:

- `connector/src/journal.rs`
- `connector/src/product_command_protocol.rs`
- Relay or browser networking files
- `testkit/process-loop/last-transcript.json`

## Persistent Path Contract

The device registry is a stable Host-owned file, not a run-scoped artifact.

Required path properties:

- absolute path
- ASCII only
- fixed basename:
  - `host-device-registry.sqlite3`
- located under persistent Nomad home state, not under the per-run directory
- parent directory owner uid equals effective uid
- parent directory mode is `0700`
- main DB file mode is `0600`
- reject symlinks for both parent traversal and final file
- reject non-owner files
- use the same restrictive umask guard pattern already used for journal
  creation so the SQLite WAL and SHM sidecars are private from first creation

SQLite open policy:

- `journal_mode = WAL`
- `synchronous = FULL`
- one process-owned connection behind the Host-owned registry object
- restart must preserve:
  - current epoch
  - active registration if not revoked
  - revoked history
- pending challenges may persist for crash consistency, but only non-expired and
  non-consumed challenges remain usable

## Registry Schema

The first schema is intentionally narrow.

```sql
CREATE TABLE registry_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL,
  current_epoch INTEGER NOT NULL CHECK (current_epoch BETWEEN 0 AND 9223372036854775807),
  active_registration_id TEXT NULL,
  pending_challenge_id TEXT NULL,
  time_floor_utc TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE device_registrations (
  registration_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  possession_key_type TEXT NOT NULL,
  possession_public_key_digest TEXT NOT NULL,
  activated_epoch INTEGER NOT NULL UNIQUE,
  paired_at TEXT NOT NULL,
  revoked_at TEXT NULL,
  revoke_reason TEXT NULL
);

CREATE TABLE pairing_challenges (
  challenge_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  possession_key_type TEXT NOT NULL,
  possession_public_key_b64 TEXT NOT NULL,
  target_epoch INTEGER NOT NULL,
  challenge_digest TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT NULL,
  invalidated_at TEXT NULL,
  invalidation_reason TEXT NULL
);
```

Registry invariants:

- `registry_state` has exactly one row with `singleton = 1`
- `current_epoch` starts at `0` and is strictly monotonic; any transition from
  `9223372036854775807` fails closed without mutation
- at most one active registration is pointed to by `active_registration_id`
- at most one pending challenge is pointed to by `pending_challenge_id`
- `activated_epoch > 0`
- `target_epoch = registry_state.current_epoch + 1` at issue time
- a challenge contains at least 32 bytes from the OS CSPRNG; only
  `SHA-256("nomad.device-authority.challenge.v1\n" || challenge_bytes)` is
  persisted
- `principal_id` is supplied by the Host, never by the remote caller
- `device_id` is `device-` plus the first 32 lower-hex characters of
  `SHA-256("nomad.device-alias.v1\n" || possession_public_key_raw)` and is
  never caller-selected; both IDs reuse the existing Host `safe_id` contract:
  ASCII `[A-Za-z0-9_-]`, max length `128`
- `possession_key_type` is fixed to `ed25519` in `v1`
- `possession_public_key_b64` must decode to exactly 32 bytes
- the raw public key exists only in the pending challenge row; completion or
  expiry deletes it, while the active registration retains only its digest

This package stores the public possession key now so later Relay work can bind a
real remote device without inventing a second registry.

## Pairing Challenge and Proof Contract

This package defines typed future interfaces only. It does not assign them to a
Relay route or public HTTP route yet.

Issue challenge request:

```json
{
  "schema": "nomad.host-device.issue-challenge.v1",
  "possession_key_type": "ed25519",
  "possession_public_key_b64": "<base64-32-byte-key>"
}
```

Issue challenge response:

```json
{
  "schema": "nomad.host-device.challenge.v1",
  "challenge_id": "challenge-<32hex>",
  "principal_id": "user_123",
  "device_id": "iphone_safari_01",
  "target_epoch": 7,
  "issued_at": "2026-08-26T10:00:00.000Z",
  "expires_at": "2026-08-26T10:02:00.000Z",
  "challenge_bytes": "<base64url-at-least-32-random-bytes>",
  "signing_payload_b64": "<canonical challenge bytes>"
}
```

Complete pairing proof request:

```json
{
  "schema": "nomad.host-device.complete-pairing.v1",
  "challenge_id": "challenge-<32hex>",
  "challenge_bytes": "<same-base64url-random-bytes>",
  "proof_signature_b64": "<base64-64-byte-ed25519-signature>"
}
```

Revoke request:

```json
{
  "schema": "nomad.host-device.revoke.v1",
  "reason": "operator_revoked"
}
```

Canonical challenge signing bytes:

```text
nomad.host-device.challenge.v1
{challenge_id}
{principal_id}
{device_id}
{challenge_bytes}
{sha256(possession_public_key_raw)}
{principal_id}
{device_id}
{target_epoch}
{issued_at_unix}
{expires_at_unix}
```

Limits and binding:

- `challenge_id` format: `challenge-<32 lower-hex>`
- one pending challenge only; issuing a new challenge invalidates the previous
  pending challenge with reason `superseded`
- challenge TTL is exactly 120 seconds in `v1`
- proof is one-time:
  - consumed challenge cannot be completed again
  - expired challenge cannot be completed
  - invalidated challenge cannot be completed
- the Host first recomputes and constant-time compares the persisted challenge
  digest, then verifies the Ed25519 signature against the pending public key and
  exact canonical signing bytes
- the Host never stores or echoes the device private key
- challenge issue/complete/revoke persist `time_floor_utc`; every state-changing
  transaction uses `effective_now = max(now, time_floor_utc)` and updates the
  floor atomically, so wall-clock rollback or restart cannot extend or resurrect
  a challenge

## State Machine

This registry is better represented as two pointers plus a monotonic counter
than as a large enum:

- `current_epoch`
- `active_registration_id | null`
- `pending_challenge_id | null`

Legal states:

- `Unpaired`
  - `active_registration_id = null`
  - `pending_challenge_id = null or one live pending challenge`
- `Paired`
  - `active_registration_id = some(active row)`
  - `pending_challenge_id = null or one live pending challenge`

Transitions:

1. `issue_challenge` under `BEGIN IMMEDIATE`
   - reads `current_epoch`
   - creates one pending challenge with `target_epoch = current_epoch + 1`
   - invalidates older pending challenge if present
   - does not disturb the current active paired device

2. `complete_pairing` under `BEGIN IMMEDIATE`
   - requires one live pending challenge
   - verifies possession proof
   - in one SQLite FULL transaction:
     - revoke current active registration if present with
       `revoke_reason = superseded_by_pairing`
     - insert new active registration with `activated_epoch = target_epoch`
     - set `current_epoch = target_epoch`
     - set `active_registration_id = new registration`
     - clear `pending_challenge_id`
     - mark the challenge consumed

3. `revoke_current(expected_epoch)` under `BEGIN IMMEDIATE`
   - in one SQLite FULL transaction:
     - revoke current active registration if present with explicit reason
     - invalidate pending challenge if present
     - increment `current_epoch` by exactly 1
     - clear `active_registration_id`
     - clear `pending_challenge_id`

Every transition reads the singleton epoch inside the write transaction,
computes exactly `current_epoch + 1`, and rejects a stale expected epoch or
concurrent loser with zero mutation.

Effects:

- revoke is immediate for future capabilities
- revoke survives restart
- re-pairing always advances epoch
- old capability and old epoch can never authorize a new upstream dispatch after
  revocation or successful re-pair

## ProductCommandService Replacement

Current anti-pattern:

- `ProductCommandService` creates one startup-time
  `AuthenticatedDeviceSession::new_local("local-product-user", "local-gateway-device", ..., 1, ...)`
  and reuses it forever

Required replacement:

- replace `device: AuthenticatedDeviceSession` with a Host-owned registry handle
- add `current_authenticated_device()`:
  - read current registry state
  - require one active non-revoked registration
  - construct a fresh `AuthenticatedDeviceSession` using:
    - registry `principal_id`
    - registry `device_id`
    - registry `activated_epoch`
    - existing authority `run_id`
    - existing authority `session_id`
    - existing bootstrap `command_authority_key`

Behavioral rules:

- `capability()`
  - must load current device facts on every call
  - if no active non-revoked device exists, fail closed and issue no capability

- `execute()`
  - must load current device facts on every call
  - exact replay lookup remains journal-owned and must return zero upstream
    dispatches
  - any new command acceptance requires current active non-revoked facts
  - if epoch changed, device changed, or device is revoked since capability
    issuance, reject before adapter dispatch

- the command transport MAC key path stays unchanged
- the command journal schema stays unchanged

Device mutation and command authorization are linearized by one process-local
serialization primitive shared by capability issue, non-replay execute, pairing
completion, replacement, and revocation. The final current device alias/epoch
comparison occurs inside this critical section immediately before the journal
claim. A revoke cannot commit in the check-to-claim gap.

## Zero-Upstream Rule

This package has one hard security requirement:

- after revoke or after a successful re-pair that changes epoch, any capability,
  nonce, or request from the older device authority may produce:
  - stale
  - unauthorized
  - exact replay receipt retrieval
- but it must produce zero new upstream adapter dispatches

The acceptance proof for this package must measure adapter call count directly.

## Implementation Sequence

1. Add persistent bootstrap path support
   - `tools/nomad_web/launcher.py`
   - `connector/src/product_host_bootstrap.rs`

2. Land the registry module
   - open policy
   - schema creation
   - issue challenge
   - complete proof
   - revoke
   - read current active facts

3. Replace hardcoded device session use in `ProductCommandService`
   - `capability()`
   - `execute()`

4. Keep `host_command_authority.rs` binding unchanged
   - only add thin helpers needed for fresh construction from registry facts

5. Add focused tests and audit gates

## Tests

Registry correctness:

- first boot creates `registry_state.current_epoch = 0`
- DB, WAL, and SHM artifacts are private to the owner
- symlink path, wrong-owner path, wrong-mode parent, or alternate basename fail
  closed
- restart preserves:
  - revoked registration rows
  - `current_epoch`
  - empty active state after revoke

Challenge and proof:

- only one pending challenge survives
- superseded pending challenge cannot complete
- expired challenge cannot complete
- rollback before expiry, rollback after expiry, and restart under a regressed
  wall clock cannot extend or resurrect a challenge
- wrong key type fails
- wrong public key length fails
- wrong signature fails
- same proof cannot consume challenge twice
- successful proof stores exactly one active registration and advances epoch once
- epoch overflow fails closed; concurrent complete/revoke has one winner and
  stale losers make no mutation

Revocation and epoch:

- pair once -> epoch `1`
- revoke -> no active device and epoch `2`
- pair again -> new active device and epoch `3`
- revocation immediately invalidates the prior active device

`ProductCommandService` behavior:

- no active device -> capability blocked
- active device -> capability succeeds
- revoke after capability issuance -> execute rejects before adapter dispatch
- re-pair after capability issuance -> execute rejects before adapter dispatch
- replay of already journaled request returns saved receipt and zero additional
  adapter calls
- hardcoded `local-product-user` / `local-gateway-device` / `epoch=1` no longer
  appear in live capability-execute behavior

Bootstrap and launcher:

- bootstrap rejects non-persistent or run-scoped registry paths
- launcher passes stable registry path under Nomad home state
- run cleanup never deletes the persistent registry

## Audit Gates

`AG1 Filesystem gate`

- registry path is owner-only, no-symlink, canonical, and persistent
- SQLite is opened with WAL plus FULL sync

`AG2 Authority gate`

- `capability()` and non-replay `execute()` both re-read current non-revoked
  device facts
- stale epoch or revoked device cannot reach adapter dispatch

`AG3 Restart gate`

- revoke survives Host restart
- Host restart does not silently reset epoch to `1`
- Host restart does not recreate the old hardcoded local device

`AG4 Privacy gate`

- no device private key in argv, env, logs, receipts, browser payloads, or
  registry
- no transport key or command authority key in registry
- no transcript file reads or transcript-derived authority

`AG5 Scope gate`

- no Relay route design in this package
- no browser/public API surface for pairing beyond typed future interfaces
- no journal schema changes

## Exit Criteria

This atomic package is complete only when all of the following are true:

- `ProductCommandService` no longer owns a hardcoded immutable device session
- the Host has one persistent single-device registry
- pairing proof can create one active device with monotonic epoch
- explicit revoke persists across restart
- old capability or old epoch causes zero new upstream dispatches
- command journal behavior remains frozen

## Critical Files for Implementation

- connector/src/host_device_registry.rs
- connector/src/product_stock_projector.rs
- connector/src/product_host_bootstrap.rs
- connector/src/host_command_authority.rs
- tools/nomad_web/launcher.py
