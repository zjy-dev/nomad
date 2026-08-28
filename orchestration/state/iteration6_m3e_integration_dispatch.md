# Iteration 6 M3-E Integration Dispatch

Status: DISPATCHABLE ARCHITECTURE / IMPLEMENTATION NOT YET ACCEPTED

## 1. Scope and current floor

This dispatch turns the landed M3-E component work into four executable,
dependency-ordered integration packages:

1. **E2b** — Product Host bootstrap v2 and inherited-secret configuration.
2. **E2c** — Product Host Relay v2 mailbox pump and remote command ingress.
3. **E6** — installed launcher, bundle, two Gateway listeners, Relay topology,
   and HTTPS ingress.
4. **E7** — real-process, desktop-browser, and physical-phone evidence.

The current floor on disk is:

- E1 pairing coordinator and E1.1 durable encrypted store exist in
  `connector/src/pairing_coordinator.rs`.
- E2 owns the exact Product Host pairing routes and is landing the composition
  seam in `product_stock_projector.rs` plus the bounded provision client in
  `relay_provisioning.rs`.
- E3 Gateway has separate `desktop` and `join` route tables. The join Gateway
  reads its trusted-ingress token from FD 12, and both Gateway processes read a
  Product Host transport key from FD 11.
- Relay can run one fixed v2 role per process and can add the admin provision
  listener to that process. The current CLI therefore needs two Relay processes
  over one file-backed v2 SQLite database for a local full slice.
- `remote_mailbox.rs`, `remote_crypto.rs`, and `remote_application.rs` provide
  the durable cursor, P-256 envelope, and strict application-envelope primitives.
  They are not yet connected to `ProductCommandService`.
- The existing launcher starts either the foundation v1 Relay/Gateway pair or
  the official Agent/Product Host/single legacy Gateway path. It does not start
  the M3-E topology.

This document authorizes planning and later implementation only. Component
tests, including E1/E3/UI green tests, are not M3-E product evidence.

## 2. Cross-package invariants

The following rules apply to every package and may not be relaxed locally:

1. There is one `Arc<DeviceCommandGate>` inside each Product Host process.
   Pairing confirm, vault complete/abort, revoke, and remote command journal
   claim all use that same object.
2. Product Host is the sole pairing and command authority. Gateway is a strict
   HTTPS/UDS controller. Relay remains content-blind.
3. The Relay admin credential, Host bearer, device bearer, Provider credential,
   Product Host transport keys, trusted-ingress token, TLS private key, and P-256
   private keys never appear in argv, environment, run-state JSON, logs, error
   strings, or evidence JSON.
4. A capability carried from Gateway to Host is an exact JSON body field and is
   covered by the existing path-plus-body transport HMAC. It is never put in a
   custom header or URL.
5. A browser is command-eligible only after the coordinator reports an `active`
   binding following vault persist-and-restore. `ProvisionedPendingVault` is not
   active.
6. Relay ACK means delivery progress only. It is never Agent acceptance or
   command success.
7. `allow_once` remains absent and rejected. The remote action set is exactly
   `view`, `reply`, `deny`, and `stop`.
8. `OutcomeUnknown` is durable and never causes a new semantic command attempt.
9. Production paths require HTTPS with normal certificate validation. Cleartext
   is available only through an explicit loopback-test flag and cannot satisfy
   physical-phone or product readiness.
10. No package may read, rewrite, delete, or use
    `testkit/process-loop/last-transcript.json` as evidence.

## 3. Dependency graph and ownership leases

```text
E1.1 durable coordinator + device public-key/remote-key binding ─┐
E2 Host pairing routes + remote command facade ──────────────────┼──> E2b bootstrap/config
E3 Gateway/UI ───────────────────────────────────────────────────┘             │
Relay v2 lifecycle/data/admin ─────────────────────────────────────────────────┤
                                                                               v
                                                                    E2c mailbox ingress
                                                                               │
                                                            v
                                                     E6 launcher/bundle
                                                            │
                                                            v
                                                      E7 evidence
```

Ownership is exclusive while a package is active. A later package may take a
new ownership lease on a file only after the earlier package is merged or its
worker is stopped. No two workers edit the same file concurrently.

| Package | May start when | Exclusive implementation files |
| --- | --- | --- |
| E2b | E1.1 and E2 dual-auth/composition interfaces frozen | `connector/src/product_host_bootstrap.rs`; focused Rust bootstrap tests |
| E2c | E2b merged; E1.1 device public-key/remote-key binding and E2 command facade frozen | new `connector/src/remote_command_ingress.rs`; `connector/src/remote_mailbox.rs` for the atomic inbound-applied/outbound-response transaction; `connector/src/product_stock_projector.rs`; `connector/src/product_command_protocol.rs` only if the E2 conversion seam needs a follow-up; `connector/src/product_host_bootstrap.rs` for the final mailbox-ready composition after E2b releases it; `connector/src/lib.rs`; focused Rust ingress tests |
| E6 | E2b + E2c pass; E3 Gateway CLI frozen | `tools/nomad_web/config.py`, `launcher.py`, `processes.py`, `state.py`, `cli.py`, `bundle.py`, `materialize.py`, `bundle_manifest.json`; new `relay/cmd/nomad-ingress/`; new launcher/ingress tests |
| E7 | E6 installed slice passes | new files under `testkit/remote-v2/m3e_*`; new `docs/technical/task-reports/M3E-*` reports only |

Files owned by E1/E1.1, E3/UI, or Relay v2 are inputs, not edit targets:

- `connector/src/pairing_coordinator.rs`
- `connector/src/host_device_identity.rs`
- `connector/src/remote_crypto.rs`
- `connector/src/remote_application.rs`
- `mobile-reference/pilot-gateway/*`
- `mobile-reference/src/remote/*`
- `mobile-reference/src/ui/*`
- `relay/v2_*.go` and `relay/cmd/relay/main.go`

If an input lacks a symbol, the package records one narrow follow-up for its
current owner instead of editing outside its lease.

## 4. E2b — Product Host bootstrap v2 and admin FD

### 4.1 Purpose

E2b carries remote configuration and the existing Host transport keys into
Product Host, supplies the Relay admin credential through a fixed inherited
descriptor, opens the durable pairing and mailbox stores, constructs the real
Host identity/coordinator, and fails closed before the Product Host ready frame
if any dependency is invalid.

E2b does not run the mailbox polling loop. E2c owns that loop. E2b freezes the
configuration that E2c consumes.

### 4.2 File ownership

Owned during E2b:

- `connector/src/product_host_bootstrap.rs`
- inline tests in that file, or new
  `connector/tests/m3e_product_host_bootstrap_tests.rs`

Read-only inputs:

- `connector/src/pairing_coordinator.rs`
- `connector/src/host_device_identity.rs`
- `connector/src/relay_provisioning.rs`
- `connector/src/product_stock_projector.rs`
- `connector/src/remote_mailbox.rs`

`connector/src/bin/nomad_product_host.rs` remains unchanged: it already calls
`run_product_host(BOOTSTRAP_FD)`. `run_product_host` selects v1 or v2 after
decoding FD 10 and consumes FD 11 only for a v2 remote bootstrap.

E2b owns `product_host_bootstrap.rs` first. After E2b is frozen, E2c receives a
new, exclusive lease on that same file solely to connect the mailbox-ready
barrier. This is sequential ownership, not concurrent editing.

### 4.3 Fixed per-process descriptors

| Product Host FD | Meaning | Encoding and lifetime |
| ---: | --- | --- |
| 0 | `/dev/null` | no user input |
| 1, 2 | private Host log | content-free errors only |
| 10 | bootstrap socket | 4-byte big-endian length plus exact JSON, then EOF; existing response channel |
| 11 | Relay admin bearer | exactly one ASCII token then EOF; consumed once and closed before ready |

FD numbers are process-local. Gateway FD 11 carries a different transport key,
and Relay FD 11 carries a separate copy of the Relay admin bearer. Reuse of the
number across processes does not mean reuse of the secret.

The Relay admin bearer is not included in bootstrap JSON. A v2 bootstrap with a
missing, short, overlong, non-ASCII, whitespace-containing, non-pipe/socket, or
non-EOF FD 11 fails before Host socket publication or ready acknowledgement.
No fallback to a file path, environment variable, or argv flag exists in Product
Host.

### 4.4 Bootstrap wire contract

`nomad.product-host.bootstrap.v1` remains byte-shape compatible and means local
C3 only. Unknown remote fields on v1 are rejected.

Remote mode uses exact top-level schema
`nomad.product-host.bootstrap.v2`. It contains every existing v1 field, one
additional `join_transport_key`, and one `remote` object:

```json
{
  "schema": "nomad.product-host.bootstrap.v2",
  "run_id": "<64 lower hex>",
  "origin": "http://127.0.0.1:4096",
  "session_id": "<official Agent session id>",
  "server_password": "<Agent child secret>",
  "workspace_binding_digest": "<64 lower hex>",
  "product_host_socket_path": "/private/tmp/.../product-host.sock",
  "agent_pid": 1234,
  "agent_process_group": 1234,
  "agent_process_identity": "<64 lower hex>",
  "product_host_socket_parent_dev": 1,
  "product_host_socket_parent_ino": 2,
  "command_transport_key": "<32 bytes, standard base64>",
  "join_transport_key": "<32 bytes, standard base64>",
  "command_authority_key": "<32 bytes, standard base64>",
  "command_journal_path": "<run-private>/command-<alias>.sqlite3",
  "device_registry_path": "<persistent-private>/host-device-registry.sqlite3",
  "remote": {
    "schema": "nomad.product-host.remote-bootstrap.v1",
    "relay_admin_base_url": "http://127.0.0.1:<admin-port>",
    "relay_host_base_url": "http://127.0.0.1:<host-v2-port>",
    "relay_device_public_base_url": "https://pair.example",
    "allow_loopback_test_http": true,
    "pairing_store_path": "<persistent-private>/pairing-coordinator.sqlite3",
    "remote_mailbox_state_path": "<persistent-private>/remote-mailbox.sqlite3"
  }
}
```

All keys are required exactly once; duplicate, unknown, missing, trailing, and
oversize input fails. The three 32-byte keys must be pairwise distinct.
`join_transport_key` authenticates only `/internal/pairing/join/*`; the existing
`command_transport_key` authenticates local command plus desktop pairing/device
administration. This prevents compromise of the public-facing join Gateway from
turning its Host transport credential into desktop create/approve/revoke or
local command authority. Both keys retain independent nonce caches.

E2 must freeze this as a path-classified Product Host API, not as two keys that
the caller can choose between. `read_product_request` first parses the request
line and classifies the exact path, then selects exactly one authenticator:

| Authenticator | Only accepted paths | Explicitly rejected paths |
| --- | --- | --- |
| desktop/command `command_transport_key` | `/internal/session/*`, `/internal/commands/*`, `/internal/pairing/joins`, `/internal/pairing/joins/{approve,cancel,status}`, `/internal/devices/*` | every `/internal/pairing/join/*` route |
| public join `join_transport_key` | `/internal/pairing/join/{start,confirm,complete,abort}` | session, command, desktop join-management, and device routes |

The selected key verifies the existing canonical
`method + path + timestamp + nonce + body_digest` material. There is no key ID,
fallback, or caller-selected auth domain. A valid MAC from the wrong key returns
`UNAUTHORIZED` before JSON parsing or coordinator mutation. Cross-key tests must
cover every route family, including an identical body and nonce authenticated
under the other key.

All Relay values are **origins**, not API-prefix URLs. They have no username,
password, path other than `/`, query, or fragment. Clients append
`/v2/mailboxes/...` or `/v2/admin/mailboxes/provision`. This corrects the older
illustrative `https://relay.example/v2` value, which would otherwise generate a
double `/v2/v2/...` path.

Validation rules:

- `relay_device_public_base_url` is always HTTPS and is the value signed into
  the browser provisioning bundle.
- `relay_host_base_url` is HTTPS, except literal loopback HTTP when
  `allow_loopback_test_http=true`.
- `relay_admin_base_url` is literal loopback HTTP only in the current
  implementation and requires `allow_loopback_test_http=true`. The current
  Relay provision server rejects TLS and non-loopback peers, so any external or
  production admin control plane remains `NO-GO` and belongs to E5.
- `pairing_store_path`, `remote_mailbox_state_path`, and
  `device_registry_path` share one canonical, owner-only `0700` persistent
  directory. Basenames are exactly `pairing-coordinator.sqlite3`,
  `remote-mailbox.sqlite3`, and `host-device-registry.sqlite3`. Existing DB files
  must be regular, owner-only `0600`, single-link, and not symlinks.
- The run-scoped command journal remains under the current run directory and is
  not moved into the persistent device directory.

### 4.5 Host construction and readiness

For v2, `run_product_host` performs this order before returning ready:

1. parse and validate all non-secret bootstrap fields;
2. consume and close FD 11 through `RelayAdminBearer`;
3. load or create `HostDeviceIdentity`;
4. open the existing `DeviceAuthority`;
5. open `SqliteJoinSessionStore` using the Host identity-derived at-rest key;
6. construct `UreqRelayProvisioner`;
7. construct one `PairingCoordinator` and run pending-candidate recovery;
8. open `RemoteMailboxState`;
9. call E2 `ProductStockHost::start_with_pairing` with that coordinator and the
   two path-bound authenticators;
10. call E2c's start function with the mailbox configuration and an owned
    readiness sender;
11. wait for exactly one content-free mailbox-ready event; only then may the
    v2 Product Host ready frame be sent.

The ready response becomes a strict schema union. V1 keeps the current exact
`nomad.product-host.ready.v1`. V2 is:

```json
{
  "schema": "nomad.product-host.ready.v2",
  "parent_dev": 1,
  "parent_ino": 2,
  "socket_dev": 3,
  "socket_ino": 4,
  "snapshot_seq": 1,
  "pairing_ready": true,
  "remote_mailbox_ready": true
}
```

`pairing_ready` means the real identity, durable coordinator store, registry,
provision client, dual-auth route table, and startup compensation are ready.
`remote_mailbox_ready` means E2c opened and validated the cursor DB, installed
its stop/health state in the Host lifecycle, and reached its polling loop. It
does not claim Relay reachability, a paired device, Provider E3, HTTPS
deployment, or product readiness.

E2b may land the v2 decoder/config types before E2c, but until E2c is linked, a
v2 bootstrap returns `BOOTSTRAP_REMOTE_INGRESS_UNAVAILABLE`, closes FD 11, emits
no `ready.v2`, and removes any newly created Host socket. A placeholder
`remote_mailbox_ready=false` ready frame is forbidden. E2c later takes the
exclusive bootstrap-file lease and replaces that fail-closed branch with the
real ready barrier.

### 4.6 E2b tests and commands

Required tests:

- v1 exact DTO still accepts and rejects the same cases;
- v1 rejects every v2-only key; v2 rejects every missing/unknown/duplicate key;
- all three Host keys are exactly 32 bytes and pairwise distinct;
- the desktop key cannot authenticate any join route, the join key cannot
  authenticate any desktop/session/command/device route, and neither route
  family falls back to the other key;
- v2 with invalid or absent FD 11 fails before Host socket/ready; tests cover
  pipe/socket acceptance and rejection of directories/devices. Private regular
  files are accepted only if the already-reviewed Relay secret reader enforces
  owner, `0600`, single-link, no-follow semantics; otherwise E2b is pipe/socket
  only;
- FD 11 requires exact token plus EOF, closes on success and every error path,
  and never appears in Debug/errors;
- URL path, credentials, query, fragment, non-HTTPS public device URL, and
  implicit non-loopback HTTP fail;
- unsafe store paths, wrong basenames, symlink/hardlink/public parents fail;
- corrupted encrypted coordinator store fails closed before ready;
- before E2c lands, every v2 bootstrap returns
  `BOOTSTRAP_REMOTE_INGRESS_UNAVAILABLE` and emits no ready frame; after E2c,
  v2 ready is impossible until pairing recovery and the mailbox-ready event;
- a v2 bootstrap failure leaves zero Host client threads and no socket artifact.

Run from `connector/`:

```sh
cargo test product_host_bootstrap --lib
cargo test pairing_coordinator --lib
cargo test relay_provisioning --lib
cargo clippy --lib --tests -- -D warnings
```

E2b exit marker: `M3E_E2B_BOOTSTRAP_PASS`. It is an engineering marker only.

## 5. E2c — Remote mailbox command ingress

### 5.1 Purpose and file ownership

E2c runs the Host side of the active device mailbox. It publishes the current
content-safe projection/capability, consumes `device_to_host` commands, enters
the existing Host-final command authority, persists a receipt outbox, and ACKs
only after durable application.

Owned during E2c, after E2 releases its lease:

- new `connector/src/remote_command_ingress.rs`
- `connector/src/product_stock_projector.rs` for the narrow remote-authority
  facade and worker lifecycle
- `connector/src/product_command_protocol.rs` only if E2 has not already landed
  `TryFrom<GatewayCommand> for ParsedProductCommand`
- `connector/src/lib.rs` for `mod remote_command_ingress;` only
- new `connector/tests/m3e_remote_command_ingress_tests.rs`, or inline focused
  tests in the new module

Read-only inputs include E1/E1.1, Host identity, crypto, application envelope,
mailbox state/client, journal, and Relay Go files.

### 5.2 Required E2 handoff seam

E2 must leave these crate-private seams before E2c begins:

- `ProductStockHost::start_with_pairing(bootstrap, Arc<PairingCoordinator>)`;
- the gate is derived only from `coordinator.device_command_gate()`, never passed
  as a second independently constructed `Arc`;
- `TryFrom<GatewayCommand> for ParsedProductCommand` performs a direct exact
  field mapping and reuses existing parsed/resolved validation; it does not
  serialize and reparse JSON;
- a `ProductRemoteCommandAuthority` facade that can issue a capability for an
  active remote device and execute one mapped command while the coordinator
  `DeviceCommandGuard` is held.

The execution seam must accept `&DeviceCommandGuard` and delegate to a private
`execute_locked` core. It must not call the local `execute()` method that acquires
the same non-reentrant mutex again. Local C3 continues to acquire the gate in
its public method; E2c acquires it once, revalidates the binding, and passes the
guard through the remote facade to the common journal/dispatch core.

E2c also has one hard E1.1 prerequisite that is not optional: the durable active
binding must return the device agreement SEC1 public key that was validated at
pairing time. The Host needs it to encrypt `host_to_device` projections and
receipts. Prefer retaining both verified device signing and agreement SEC1 keys
and recomputing their commitments whenever durable state is loaded. A raw key
learned later from an inbound frame or browser request must never replace this
pairing-time trust anchor. If this field is not present when E2c starts, E2c is
blocked and must request the narrow E1.1 addition; it must not infer or re-enrol
the key.

The remote facade must not expose `ProductCommandService`, adapter internals,
raw Agent IDs, `CommandJournal`, or the local-run `AuthenticatedDeviceSession`.
Local and remote capabilities use separate issued-state slots, principal/device
bindings, epoch, nonce space, and journal scope. A remote session is bound to the
fixed remote principal, current device alias, current epoch, current run/session,
and a Host-only derived authority key. It never reuses the local Gateway device
identity.

The remote authority key is derived, not copied, from the existing 32-byte
`command_authority_key`:

```text
salt = SHA-256("nomad.m3e.remote-command-salt.v1\n" ||
              device_alias || "\n" || decimal(pairing_epoch))
remote_command_key = HKDF-SHA256(command_authority_key, salt,
                                 info="nomad.m3e.remote-command-authority.v1",
                                 L=32)
```

This value exists only in Host memory, is zeroized on drop, and is reconstructed
after restart only after the active coordinator/registry binding matches. The
local command key is not reused. The journal's existing authority scope remains
bound to principal, device, run, session, and epoch, so old-epoch sequence and
nonce values cannot collide with a replacement device.

### 5.3 Runtime object

The new module owns a `RemoteCommandIngress` composed from:

- `Arc<PairingCoordinator>`;
- `Arc<EndpointKeys>` from the same `HostDeviceIdentity`;
- E2's `ProductRemoteCommandAuthority` facade;
- `RemoteMailboxState` opened at the E2b path;
- the validated Host Relay origin and explicit loopback-test bit;
- a stop signal and health state shared with `ProductStockHost`.

Its startup returns `(RemoteCommandIngress, RemoteMailboxReadyReceiver)` or an
equivalent one-shot barrier. The worker sends success exactly once only after
the cursor store is open, durable state is validated, the initial active
binding/registry reconciliation completed, and the polling thread is alive. A
thread spawn error, early panic/exit, corrupt cursor, or reconciliation conflict
closes the channel with no success. `run_product_host` must receive this success
before serializing `nomad.product-host.ready.v2`.

The Host identity input must expose the existing `endpoint_keys()` accessor or
an equivalent non-exporting encrypt/decrypt wrapper. E2c does not load another
Host identity and does not copy private scalar bytes.

There is no remote-command UDS or Gateway route. The only ingress is an
authenticated, decrypted `device_to_host` Relay v2 application envelope.

### 5.4 Poll and admission order

Every worker iteration uses the following order:

1. Flush any durable pending `host_to_device` frame byte-for-byte before
   creating a newer frame.
2. Briefly acquire `coordinator.command_guard()` and call
   `active_binding_locked(&guard)`. If there is no active device, stay idle.
   Copy only the redacted binding facts needed for network I/O, then release.
3. Construct/reuse `HostRelayV2Client` for the binding's Host bearer and exact
   Host-role origin. Open the cursor keyed by
   `(mailbox_id, device_to_host, epoch)`.
4. If local `applied_through_sequence > acked_through_sequence`, first recover
   and publish the durable response for that applied command, then retry the ACK
   before reading. This repairs a crash or lost response after Relay accepted an
   ACK but before local `acked_through` persistence without losing the command
   receipt.
5. Read ordered frames after durable `acked_through_sequence`. Process one frame
   at a time. Sequence gaps are allowed; regression or duplicate mutation is not.
6. Persist `read_through_sequence` after strict Relay frame validation.
7. Convert the Relay frame to the exact crypto frame and decrypt with the Host
   identity. Build `SharedContext` from the candidate binding and require all
   four commitments, mailbox ID, direction, epoch, sequence, and message ID.
8. Strictly parse `ApplicationEnvelope` against that frame binding and require
   `kind=command`, `direction=device_to_host`, and the frozen `GatewayCommand`.
9. Reacquire `coordinator.command_guard()`. Under the same guard,
   `active_binding_locked` re-reads coordinator state and `DeviceAuthority`;
   exact-match alias, epoch, mailbox, and all four commitments against the
   pre-I/O binding. A revoke or replacement that won during I/O rejects the
   frame with zero journal insertion and zero Agent call.
10. Map `GatewayCommand` directly to `ParsedProductCommand`, re-check the remote
    issued capability, then enter the existing Host authority. The same guard is
    held through the durable journal claim. Release only at the authority's safe
    point.
11. Build the exact remote receipt from the authoritative Host receipt. Persist
    its encrypted canonical `host_to_device` frame as the one pending outbox
    entry, then publish/retry that exact frame.
12. Only after the receipt frame is durably pending and Relay has accepted or
    idempotently accepted it, atomically persist inbound
    `applied_through_sequence` together with the response association.
13. Send the inbound Relay ACK; only after an accepted/idempotent ACK persist
    `acked_through_sequence`. A lost ACK response retries ACK, never command or
    receipt creation.

The remote receipt mapping is exact: schema
`nomad.gateway.command-receipt.v1`; `receipt_id`, `request_id`, action, accepted
time, status, error code, and idempotent flag come from `HostCommandReceipt`;
snapshot sequence/digest come from the accepted `ParsedProductCommand`. `None`
Host error maps to `OK`. No Relay or worker state may synthesize HostAccepted or
a terminal result.

For a crash after Host journal claim but before receipt/outbox persistence,
redelivery follows the existing exact request-id replay path and reconstructs
the stored receipt without another Agent call. A frame is not marked applied
until its response is durably recoverable. For a crash after applied but before
ACK persistence, step 4 recovers the response association and retries the ACK.

### 5.5 Projection/capability egress

E2c also owns the minimum egress needed for phone `view` and a command:

- when a new active binding appears, or the Product Host snapshot changes, build
  the strict M3 application `projection`;
- issue capability for the remote device identity and epoch, not the local
  Gateway session;
- derive snapshot and capability under the same command guard;
- reserve the Host-to-device sequence before encryption;
- persist exact encrypted frame bytes before publish;
- republish pending bytes after restart before any newer projection/receipt.

Projection coalescing may skip intermediate snapshots before sequence
reservation. It may not mutate an already persisted pending frame. Receipt
delivery takes priority over a newer projection.

### 5.6 Failure classification

| Failure | Applied? | ACK? | Receipt? | Worker action |
| --- | --- | --- | --- | --- |
| no active binding | no | no | no | idle |
| Relay unavailable/timeout | no | no | no | bounded backoff; local C3 remains available |
| frame canonical/auth/crypto/binding invalid | no | no | no | fail closed and report content-free blocked health |
| stale/revoked/replaced binding before journal claim | no | no | no | drop current client, do not call Agent |
| valid deterministic Host rejection | yes after durable rejection receipt/outbox | yes | exact rejection | continue |
| Host transient unavailable before claim | no | no | no | retry same frame later |
| dispatch outcome ambiguous | yes after durable `OutcomeUnknown` | yes | exact `OutcomeUnknown` | never semantic retry |
| receipt publish ambiguous | yes | yes | pending exact receipt | republish identical bytes |
| ACK response ambiguous | yes | local ack cursor unchanged | pending/existing | retry ACK from applied cursor |

Malformed frames deliberately remain unacked in this slice. Automatic poison
frame quarantine is a later protocol decision and must not be invented in E2c.

### 5.7 Lifecycle and tests

The worker starts before Product Host emits remote-ready. Network unavailability
is a degraded remote condition, not permission to terminate the local C3 Host.
Corrupt private cursor state, Host identity mismatch, or coordinator/registry
conflict is fatal and prevents remote-ready. Normal Product Host restart uses the
same Host identity, pairing store, device registry, and remote mailbox cursor.
The worker's unexpected exit after ready sets a fatal remote health flag, makes
future pairing/remote writes unavailable, and appears as `DEGRADED`; it does not
silently leave the Product Host advertising remote readiness.

Required tests:

- real file-backed cursor restart for pending receipt and applied-before-ACK;
- exact frame and application binding, including all four commitments;
- `TryFrom<GatewayCommand>` parity for reply/deny/stop and rejection of
  `allow_once`/unknown action before journal claim;
- revoke wins before claim: zero journal rows and zero adapter calls;
- replacement wins before claim: old epoch has zero journal/Agent effects;
- command wins before revoke: exact request may finish, every later old-epoch
  frame is blocked;
- duplicate/redelivered command produces one Agent call and the same receipt;
- `OutcomeUnknown` persists across Host restart and is never retried;
- crash matrix at claim, outbox persistence, applied cursor, Relay ACK, and
  receipt publish boundaries;
- local C3 command tests remain unchanged and green;
- a pre-held coordinator guard can call the remote locked core without
  deadlock, while calling it with a guard from another coordinator fails;
- derived remote command key differs from local and from every other epoch;
- worker network errors and Debug output contain no bearer, plaintext, prompt,
  path, or ciphertext.

Run from `connector/`:

```sh
cargo test remote_command_ingress --lib
cargo test product_stock_projector --lib
cargo test --test m3e_remote_command_ingress_tests
cargo test --test m2_stock_command_tests
cargo clippy --lib --tests -- -D warnings
```

E2c exit marker: `M3E_E2C_REMOTE_COMMAND_PASS`. It is still local engineering
evidence, not a physical-phone or Provider result.

## 6. E6 — Installed local-evidence launcher, bundle, and HTTPS ingress

E6 is split into two sequential commits under one owner because launcher flags,
bundle allowlists, child FDs, and ingress readiness form one release contract.
It starts only after E2b/E2c and the E3 Gateway CLI are frozen.

### 6.1 File ownership

Owned by E6:

- `tools/nomad_web/config.py`
- `tools/nomad_web/launcher.py`
- `tools/nomad_web/processes.py`
- `tools/nomad_web/state.py`
- `tools/nomad_web/cli.py`
- `tools/nomad_web/bundle.py`
- `tools/nomad_web/materialize.py`
- `tools/nomad_web/bundle_manifest.json`
- new `relay/cmd/nomad-ingress/main.go` and tests only; no edits to Relay v2
  data/admin implementations
- new `testkit/nomad-web/test_m3e_launcher.py`

Gateway implementation files and all connector implementation files are
read-only inputs. Existing launcher tests may be updated only by the E6 owner
after confirming no other worker holds them.

### 6.2 Launcher command and external inputs

The first executable mode is explicitly a LAN/local-evidence mode. It extends
the current installed command as follows:

```sh
nomad-web --json start \
  --provider OPENAI_API_KEY \
  --credential-stdin \
  --workspace /absolute/repository \
  --remote-local-evidence \
  --public-origin https://pair.example:8443 \
  --https-listen 192.0.2.10:8443 \
  --tls-cert-fd 3 \
  --tls-key-fd 4
```

`--credential-stdin` remains exclusively the Provider credential. TLS material
uses caller-owned descriptors; it is not accepted by path, argv content, or
environment. `--remote-local-evidence` requires every remote argument and
rejects partial or ambiguous input before spawning any process. The listen address must be one
specific non-wildcard IP and port; `0.0.0.0`, `::`, hostnames, URL syntax, and
privileged ports are rejected. `public-origin` is HTTPS, has an explicit port,
and has no credentials, path, query, or fragment. Certificate hostname validity
is proved by the real phone in E7; the launcher does not invent trust.

This mode opens one reviewed LAN HTTPS port on the Mac and is not D-005's
production outbound-only topology. The product `--remote` mode remains absent
and `NO-GO` until an externally operated Relay/HTTPS service or a reviewed
outbound tunnel connector is selected, threat-modelled, and implemented. E6
must not alias `--remote-local-evidence` to `--remote` or advertise it as a
production connection.

### 6.3 Runtime ports and child processes

`Config` adds distinct, unique ports for:

- desktop Gateway;
- join Gateway;
- Relay host-role v2;
- Relay device-role v2;
- Relay admin;
- two unused loopback v1 listeners required by the current Relay executable;
- official Agent.

The current Relay CLI fixes one v2 role per process and always starts v1. E6
therefore launches two Relay children over the same v2 DB:

```text
relay-host:
  nomad-relay --addr 127.0.0.1:<host-v1-sink>
    --db <run>/relay-host-v1.sqlite3
    --v2-enable --v2-addr 127.0.0.1:<host-v2> --v2-role host
    --v2-db <persistent-private>/relay-v2.sqlite3
    --v2-loopback-test-http
    --v2-admin-addr 127.0.0.1:<admin> --v2-admin-credential-fd 11

relay-device:
  nomad-relay --addr 127.0.0.1:<device-v1-sink>
    --db <run>/relay-device-v1.sqlite3
    --v2-enable --v2-addr 127.0.0.1:<device-v2> --v2-role device
    --v2-db <persistent-private>/relay-v2.sqlite3
    --v2-loopback-test-http
    --v2-trusted-tls-terminator-peer 127.0.0.1
```

The two unused v1 listeners are loopback-only and receive no token or routes
from the UI. Their presence is a current-CLI compatibility cost, not production
architecture. Removing them or hosting both v2 roles in one process is a future
Relay CLI package; E6 must not silently claim that has happened.

After all dependencies are running, the process set is exact:

```text
relay-host, relay-device, opencode, product-host,
desktop-gateway, join-gateway, https-ingress
```

### 6.4 Secret and FD flow

| Secret | Creator/source | Recipients | Fixed child FD | Persisted? |
| --- | --- | --- | ---: | --- |
| Provider credential | operator stdin | official Agent only | existing Agent contract | no |
| command transport key | launcher CSPRNG | Host bootstrap JSON; desktop Gateway | desktop Gateway 11 | no |
| join transport key | launcher CSPRNG | Host bootstrap JSON; join Gateway | join Gateway 11 | no |
| command authority key | launcher CSPRNG | Host bootstrap JSON only | n/a | no |
| Relay admin bearer | launcher CSPRNG | Product Host; relay-host | each child 11 | no |
| trusted-ingress token | launcher CSPRNG | join Gateway; HTTPS ingress | each child 12 | no |
| TLS certificate | operator FD | HTTPS ingress only | ingress 10 | public material is not copied by launcher |
| TLS private key | operator FD | HTTPS ingress only | ingress 11 | no |
| ingress ready channel | launcher socketpair | HTTPS ingress | ingress 13 | no |
| Host/device mailbox bearer | Product Host coordinator | Host encrypted store/browser wrapped bundle | none | encrypted/wrapped only |
| Host P-256 private keys | Product Host | macOS Keychain-backed identity only | none | Keychain |

Two children that consume the same secret get two separate pipes containing the
same bytes. They never share a single read end. Every parent and child copy is
closed on success, spawn failure, bootstrap failure, repeated start, and stop.
`processes.spawn` remains responsible for `F_DUPFD_CLOEXEC`, `dup2`, and closing
the temporary descriptors.

Because both Relay children open one SQLite database, the launcher starts them
sequentially and requires the first process to finish schema/WAL initialization
before the second opens it. Relay remains the DB owner; the launcher never opens
or edits Relay tables.

### 6.5 Gateway and HTTPS ingress topology

Desktop Gateway command:

```text
node gateway/server.mjs --mode official-agent-local --route-table desktop
  --host 127.0.0.1 --port <desktop> --state-db <run-private DB>
  --product-host-socket <UDS> <four socket identity arguments>
  --command-key-fd 11 --public-origin https://pair.example:8443
```

Join Gateway command:

```text
node gateway/server.mjs --mode official-agent-local --route-table join
  --host 127.0.0.1 --port <join> --dist-dir <verified web bundle>
  --product-host-socket <same UDS> <same socket identity arguments>
  --command-key-fd 11 --public-origin https://pair.example:8443
  --trusted-ingress-fd 12
```

The join child receives the join transport key, not the desktop command key.
The desktop child receives the desktop command key and no ingress token. The
join listener has no state DB; the desktop listener retains the current
file-backed projection store.

The new `nomad-https-ingress` command is:

```text
nomad-https-ingress --listen <specific-ip:port>
  --public-origin https://pair.example:8443
  --join-upstream http://127.0.0.1:<join-port>
  --device-relay-upstream http://127.0.0.1:<device-v2-port>
  --tls-cert-fd 10 --tls-key-fd 11
  --trusted-join-token-fd 12 --ready-fd 13
```

`nomad-https-ingress` is a deliberately narrow TLS reverse proxy. It is not a
second Relay implementation and does not open the Relay database. Its source
may reuse the Go standard library, but it cannot import or call provisioning
handlers.

Ingress routing is an exact allowlist:

- `/j/{join_id}`, `/assets/*`, and `/api/pairing/*` go to join Gateway; ingress
  strips caller forwarding/trust headers and injects the exact HTTPS authority,
  scheme, and trusted-ingress token expected by E3.
- `/v2/mailboxes/{mailbox_id}/frames` and `/acks` go to the device-role Relay;
  ingress removes cookies plus all forwarding/trust headers and does not expose
  the admin route.
- every desktop route, `/internal/*`, `/v2/admin/*`, legacy `/v1/*`, arbitrary
  path, encoded-path variant, and unsupported method is rejected locally.

Ingress uses TLS 1.3 or the repository security baseline if stricter, bounded
headers/bodies/timeouts, no redirects, and normal certificate presentation. It
writes one length-framed content-free ready DTO to FD 13 only after binding TLS
and validating both loopback upstream configurations. Certificate/key/token
bytes are zeroized and never logged.

The signed provisioning bundle's `relay_base_url` is exactly the public origin,
with no `/v2` suffix. The browser Relay client appends `/v2/mailboxes/...`.

### 6.6 Startup, ready, stop, and persistence

Startup order:

1. verify the installed bundle and every input before spawn;
2. create/validate persistent private DB paths and run-private paths;
3. allocate every secret and a separate pipe per recipient;
4. start relay-host and relay-device; wait for their listeners without treating
   a TCP connect as authenticated product readiness;
5. start Product Host blocked on FD 10, then start official Agent and create the
   session as today;
6. send bootstrap v2; require exact Product Host ready v2;
7. start desktop Gateway, then join Gateway; verify exact route-local health;
8. start HTTPS ingress and require its authenticated FD 13 ready frame;
9. run negative route probes against the public origin;
10. atomically write secret-free run state and return `RUNNING`.

Any failure stops owned children in reverse order, closes all FDs, removes only
verified run-scoped artifacts, and preserves the persistent device registry,
pairing coordinator DB, remote mailbox cursor DB, and Relay v2 DB for recovery.
Normal `stop` preserves pairing. `uninstall` must request Host-side revoke while
the Host is alive before deleting persistent identity/state; if it cannot prove
revoke, uninstall fails closed unless a separately reviewed destructive reset
flow is explicitly invoked.

Run-state v2 stores only content-free metadata:

```json
{
  "schema": "nomad.web-companion.state.v2",
  "mode": "m3e-local-evidence",
  "real_agent_enabled": true,
  "remote_enabled": true,
  "desktop_url": "http://127.0.0.1:<desktop>/",
  "pairing_public_origin": "https://pair.example:8443",
  "pairing_ready": true,
  "remote_mailbox_ready": true,
  "processes": []
}
```

The exact final key set also contains the current content-free Agent/run/socket
metadata and distinct port numbers. It never contains an admin bearer, mailbox
bearer, cookie capability, transport/authority key, ingress token, TLS material,
Provider secret, raw Agent session ID, or raw Host run ID. Existing state v1
remains readable for stop/reconciliation and cannot be silently interpreted as
remote-ready.

### 6.7 Bundle and launcher tests

The bundle allowlist adds the already-landed `gateway/pairing-session.mjs` and
the new `bin/nomad-https-ingress`. Materialization builds the ingress binary,
and verification rejects missing, extra, wrong-mode, symlinked, or digest-
mismatched files. The installed run must have no source-tree dependency.

Required commands:

```sh
python3 -m unittest discover -s testkit/nomad-web -p 'test_*.py' -v
cd mobile-reference && npm run test:gateway
cd relay && go test ./cmd/nomad-ingress
python3 -m tools.nomad_web --json materialize --output <new-empty-path>
```

Required fault tests cover zero-spawn on partial inputs, FD exact length/EOF and
closure, distinct keys, occupied ports, Relay child failure, Host bootstrap
failure, Gateway failure, ingress TLS/ready failure, process identity mismatch,
restart recovery, reverse cleanup, v1 state compatibility, and a scan of argv,
environment, logs, ready frames, and state JSON for every canary secret.

E6 exit marker: `M3E_E6_LOCAL_INSTALLED_TOPOLOGY_PASS`. It does not satisfy the
real-phone gate without E7, and the repo-local ingress/Relay test mode is not the
accepted outbound production service from D-005.

## 7. E7 — Evidence packages

E7 owns evidence only. It does not fix production code while running a proof. A
failed proof returns to the owning implementation package.

### 7.1 File ownership

New files only:

- `testkit/remote-v2/run_m3e_product_slice.py`
- `testkit/remote-v2/test_m3e_product_slice.py`
- `testkit/remote-v2/run_m3e_desktop_browser.py`
- `testkit/remote-v2/run_m3e_phone_evidence.py`
- `testkit/remote-v2/README-M3E.md`
- `docs/technical/task-reports/M3E-REAL-PROCESS.md`
- `docs/technical/task-reports/M3E-REAL-PHONE.md`

No E7 file may import a fake Host/Relay, edit application code, or touch the old
process-loop transcript. Evidence output goes to a fresh operator-selected
private directory and contains no credentials, URLs with fragments, ciphertext,
prompts, paths, or raw Agent IDs.

### 7.2 E7a real-process product slice

Run the installed bundle, actual Relay host/device/admin listeners, actual
Product Host, actual Gateway children, actual browser WebCrypto, and actual HTTPS
ingress. The Agent may use a deterministic local fixture only for this first
mechanical classification, which must report `provider_e3=NOT_RUN`.

Executable command:

```sh
python3 testkit/remote-v2/run_m3e_product_slice.py --json
python3 -m unittest discover -s testkit/remote-v2 \
  -p 'test_m3e_product_slice.py' -v
```

It proves one create/start/dual-proof/desktop-approve/confirm/vault-commit cycle,
projection view, reply, deny, stop, receipt convergence, restart cursor recovery,
explicit revoke, and zero later Agent calls from the old epoch. Inject failures
at Relay provision response, browser vault persistence, Host receipt publish,
ACK response, and Host restart. Marker: `M3E_REAL_PROCESS_PASS`.

### 7.3 E7b desktop-browser journey

Use Playwright against the installed desktop Gateway, not component mocks. Prove
the pair card initially says unpaired, shows a QR/short link and countdown after
phone start, shows the locally computed comparison code, requires desktop
approval, becomes paired only after vault commit, and returns to unpaired after
revoke. Public join origin must return 404 for desktop routes.

Executable command:

```sh
uv run --with playwright python testkit/remote-v2/run_m3e_desktop_browser.py --json
```

Marker: `M3E_DESKTOP_BROWSER_PASS`. Responsive mobile emulation in this step is
not physical-phone evidence.

### 7.4 E7c physical-phone journey

Start from a newly materialized bundle on Apple Silicon macOS with a certificate
trusted by the physical phone:

```sh
nomad-web --json start \
  --provider <approved-provider-env-name> --credential-stdin \
  --workspace <real-repository> --remote-local-evidence \
  --public-origin https://<trusted-name>:<port> \
  --https-listen <specific-lan-ip>:<port> \
  --tls-cert-fd <fd> --tls-key-fd <fd>

python3 testkit/remote-v2/run_m3e_phone_evidence.py \
  --public-origin https://<trusted-name>:<port> --json
```

The operator scans the displayed QR using physical Safari, compares both codes,
approves on desktop, completes vault restore, performs `view`, `reply`, `deny`,
and `Stop`, refreshes Safari, restarts the Mac Host, then revokes and attempts an
old-epoch command. The verifier records content-free signed observations for:

- certificate and hostname validation succeeded with no warning bypass;
- device is a physical phone, not desktop emulation;
- refresh restored only from IndexedDB/CryptoKey state;
- lost-key injection failed closed and required re-pair;
- Relay/admin/browser/Host process logs contain no canary secret;
- revoke advanced Host epoch and caused zero later journal insertion/Agent call;
- local desktop C3 remained usable during remote network loss;
- installed paths, not source-tree entrypoints, owned every process.

Marker: `M3E_REAL_PHONE_PASS`. Provider-backed Agent evidence is recorded as
`provider_e3=PASS|NOT_RUN`, and network topology is recorded as
`network_scope=lan_direct`. A physical-phone pass with `provider_e3=NOT_RUN`
does not satisfy the product G2 Provider gate, and a LAN-direct pass does not
satisfy the D-005 outbound Relay gate.

### 7.5 E7d clean-machine and outbound-service evidence

After the LAN slice is stable, repeat the exact candidate artifact on a fresh
Apple Silicon Mac with no repository checkout or development toolchain. This
run uses the reviewed external Relay/HTTPS service or outbound tunnel selected
after E6; it must not reuse `nomad-https-ingress` as a public Host listener.
Record install digest, signing/notarization state, `doctor`, Provider E3, physical
phone journey, revoke, stop/uninstall, Keychain disposition, and owned-state
cleanup. Marker: `M3E_CLEAN_OUTBOUND_PASS`. This is the first E7 marker eligible
to contribute to overall product readiness.

## 8. Merge order and gates

1. Freeze E1.1 and E2.
2. Implement and independently review E2b.
3. Implement E2c against E2b's frozen bootstrap and E2's remote command facade.
4. Re-run all Rust tests/clippy; freeze the Product Host remote surface.
5. Implement E6 launcher/ingress/bundle; re-run legacy launcher and Gateway
   suites to prove no local C3 regression.
6. Run E7a, then E7b, then E7c, then E7d. Never promote a later gate from an
   earlier synthetic, component-only, or LAN-only result.

| Gate | PASS condition | Current disposition |
| --- | --- | --- |
| E2b | exact bootstrap v1/v2, FD 11 secret, durable paths, no premature ready | NOT IMPLEMENTED |
| E2c | encrypted mailbox -> same Host authority -> durable receipt/ACK under shared gate | NOT IMPLEMENTED |
| E6 | installed seven-process local-evidence topology plus verified HTTPS ingress and secret-free recovery | NOT IMPLEMENTED |
| E7a | full real-process product slice | NOT RUN |
| E7b | installed desktop-browser journey | NOT RUN |
| E7c | physical Safari journey with revoke zero-dispatch | NOT RUN |
| E7d | clean-machine physical-phone journey through outbound Relay | NOT RUN |
| Provider E3 | real Provider lifecycle through the same installed path | NOT RUN / independent hard gate |
| Outbound Relay | reviewed external service or outbound tunnel; no public Host listener | NOT IMPLEMENTED / independent hard gate |
| Clean machine | exact candidate artifact on a fresh Apple Silicon host | NOT RUN / independent hard gate |

## 9. Explicit NO-GO conditions

M3-E remains `NO-GO` if any one of these is true:

- bootstrap v2 places Relay admin credential or TLS private material in JSON,
  argv, environment, logs, or state;
- desktop and join Gateways receive the same Host transport key or Host accepts a
  join key on desktop/command routes;
- Product Host emits ready before encrypted store recovery and mailbox worker
  initialization;
- `relay_base_url` contains `/v2`, causing the clients to append a second API
  prefix;
- a remote command reaches the journal without a same-gate active-binding and
  DeviceAuthority re-read;
- an ACK is sent before durable journal/rejection plus receipt-outbox state;
- a restart creates a new sequence or encrypted receipt while an older pending
  frame exists;
- remote network failure takes down local C3 authority or creates optimistic
  success;
- the public HTTPS listener routes desktop, internal, admin, or legacy APIs;
- HTTPS uses an untrusted certificate, user warning bypass, wildcard bind, or
  spoofable forwarding headers without the FD-delivered ingress capability;
- LAN-direct evidence is relabelled as the D-005 outbound Relay/product
  topology;
- normal stop deletes the paired identity/cursor state, or uninstall deletes it
  without a proven revoke/reset decision;
- evidence uses mocks, a source-tree-only setup, responsive emulation, or the
  old process-loop transcript to claim physical-phone/product readiness.

Until E2b, E2c, and E6 pass, the correct product status is
`M3-E INTEGRATION NO-GO`. Even after E7c, the overall status remains
`PRODUCT NO-GO` until Provider E3, the outbound Relay gate, the clean-machine
gate, and release/security review all pass on the same candidate artifact.
