# Iteration 6 M3 Remote Join Dispatch

Status: DISPATCHED

## Product boundary

M3 connects the frozen P-256 device authority, endpoint crypto, and Relay v2
mailbox. Its first acceptance is a real multi-process mechanical slice. It is
not Provider E3 and is not physical-phone G3 evidence.

The supported product actions remain `view`, safe-summary `reply`, `deny`, and
`Stop`. `allow_once` is absent and rejected everywhere. OpenCode-specific DTOs
remain below `adapters::opencode`; M3 does not introduce a generic Agent trait.

## Topology

```text
Rust Host endpoint -> host-role Relay v2 listener -> shared opaque mailbox
shared opaque mailbox -> device-role Relay v2 listener -> WebCrypto endpoint
WebCrypto endpoint -> device-role Relay v2 listener -> shared opaque mailbox
shared opaque mailbox -> host-role Relay v2 listener -> Rust Host endpoint
```

The mechanical slice uses two fixed-role loopback listeners over one
file-backed Relay v2 database. Production keeps the same role split but must
use HTTPS with normal certificate validation. Relay never receives plaintext or
private keys.

## Ownership and trust

- Host owns its P-256 signing/agreement private keys, Host bearer, device
  registry, command journal, and durable per-direction sequence/cursor state.
- Device owns its non-extractable WebCrypto signing/agreement private keys,
  Device bearer, and durable transport state. Browser key persistence is a
  later task; the mechanical process keeps keys only for its lifetime.
- Relay stores only bearer digests, public-key commitments, opaque ciphertext,
  monotonic cursors, tombstones, and revocation state.
- A pairing result binds mailbox ID, epoch, four key commitments, and the two
  role-scoped bearer credentials. A credential is never logged or placed in a
  URL, argv, frame, receipt, or evidence bundle.
- Provider credentials remain exclusive to the official Agent child process.

## Message state machine

1. Sender durably reserves the next sequence before encryption.
2. Sender encrypts once. Retry reuses the exact canonical frame bytes.
3. Receiver reads strictly after its persisted cursor, decrypts and validates
   identity commitments, then applies the application envelope.
4. Receiver persists the applied result before ACK. ACK is monotonic and may be
   retried byte-for-byte.
5. A remote command is accepted only while holding the same
   `DeviceCommandGate` used by pairing and revoke. It then enters the existing
   Host command authority. Relay receipt is never Host acceptance.
6. Ambiguous upstream Agent dispatch is `OutcomeUnknown`; neither Host nor
   Device automatically retries it.
7. Revoke wins under the shared gate, deletes the Relay mailbox best-effort,
   and prevents every later command acceptance for the old epoch.

## Atomic work packages

### M3-A: Rust Relay v2 client and durable endpoint outbox

Owner files: new `connector/src/remote_mailbox.rs`, module registration, focused
tests only. Implement strict HTTPS/explicit-loopback-test transport, role-bound
publish/read/ACK/delete, canonical response decoding, byte-stable retry, and
file-backed private state keyed by exact `(mailbox_id, direction, epoch)`: an
outbound `next_sequence` reserved and persisted before encryption, an inbound
`applied_through_sequence` persisted before ACK, and monotonic ACK/read cursors.
No state may be reused across mailbox rotation or epoch change.

Acceptance: restart does not reuse a nonce or regress a cursor; ambiguous POST
never causes re-encryption; bearer/ciphertext/plaintext are absent from errors.

### M3-B: Host remote endpoint

Owner files: new `connector/src/remote_host.rs`, new
`connector/src/bin/nomad_remote_host.rs`, focused tests. Compose device registry
facts, `remote_crypto`, M3-A, Product snapshot projection, and the shared
`DeviceCommandGate`. First slice supports encrypted projection plus a bounded
mechanical command/receipt envelope; then it is wired to existing C3 authority.

Acceptance: stale epoch, revoked device, wrong commitments, replay, and unknown
action make zero upstream calls; `OutcomeUnknown` is emitted and locked.

### M3-C: Web endpoint and Relay client

Owner files: new `mobile-reference/src/remote/relay-client.ts`,
`mobile-reference/src/remote/device-endpoint.ts`, focused tests. Use WebCrypto
keys and exact v2 frames, persist durable device-side transport state, and
expose only a strict decrypted application-envelope boundary. M3-C must not
invent typed projection/receipt DTOs before M3-B freezes that plaintext
application envelope. No raw Agent identifiers and no optimistic success.
Device state must reserve and persist `device_to_host.next_sequence` before
publish and persist `host_to_device.applied_through_sequence` before ACK, each
keyed by exact `(mailbox_id, direction, epoch)`; in-memory-only counters are
forbidden.

Acceptance: duplicate/reordered/mutated responses fail closed; reconnect resumes
from the persisted cursor; no token or key appears in UI state or logs.

### M3-D: Mechanical real-process harness

Owner files: new `testkit/remote-v2/` only. Start actual Go Relay process with
two fixed-role listeners, actual Rust Host endpoint process, and actual Node
WebCrypto endpoint process. Prove both directions, ACK cleanup, restart resume,
wrong-role rejection, and revoke stopping all later traffic.

Acceptance marker: `REMOTE_V2_MECHANICAL_PASS`. Evidence must label Provider and
physical phone as `NOT_RUN`. It must not read or overwrite
`testkit/process-loop/last-transcript.json`.

### M3-E: Official launcher and browser product join

Owner files: `tools/nomad_web/`, `mobile-reference/pilot-gateway/`, browser UI
and focused tests. Provision secrets through inherited descriptors/private files,
start remote endpoint readiness-gated, add pairing/revoke UX, and route remote
commands through the Host authority.

Acceptance: installed local user can pair one browser device, view, reply, deny,
Stop, revoke it, and observe no later accepted writes. Local C3 behavior remains
unchanged.

### M3-F: Real evidence upgrades

Owner files: new evidence harnesses/runbooks only. Run the same product path
first with the official Provider-backed Agent on one machine, then through a
physical phone browser, then from a clean Apple Silicon machine. No synthetic
input may satisfy these gates.

## Merge and audit order

`M3-A + transport-only M3-C` may proceed in parallel. `M3-B` follows M3-A and
freezes the plaintext application envelope. Typed projection/receipt exposure
in M3-C follows M3-B. `M3-D` follows M3-A/B/C. Independent security review is
required before M3-E. Product G2/G3 claims require M3-F evidence, not component
tests.
