# Iteration 6 Remote Envelope and Mailbox Dispatch

Status: V2 CONTRACT FROZEN FOR M1 IMPLEMENTATION ONLY

## Boundary

The existing Relay v1 envelope and all `/v1/*` device/mailbox routes remain
validation-only. They provide signature integrity but not E2EE and their public
registration/read/delete surfaces are not a production identity boundary. No v2
code may call or alias those handlers.

M1 builds only a separately namespaced opaque mailbox and frozen crypto wire. It
does not connect a browser, Product Host, or Agent and therefore cannot satisfy
real-phone acceptance.

## Cryptographic suite

The first Web-compatible suite is:

- device identity signature: ECDSA P-256 with SHA-256
- pair/session key agreement: ECDH P-256
- key derivation: HKDF-SHA-256
- payload encryption: AES-256-GCM
- random values: OS/WebCrypto CSPRNG only

P-256 is chosen for stable Safari/iOS WebCrypto support. X25519/Ed25519 may be
added only as a separately versioned suite after real-device compatibility
evidence. A1's current Ed25519 registry is not silently reinterpreted; M2 will
add an explicit registry schema migration for P-256 signing and agreement keys.

## V2 relay authentication

The Relay never registers a device from a public caller. A Host creates one
random 256-bit `mailbox_id`, one random 256-bit host bearer token and one random
256-bit device bearer token after local pairing. Only their SHA-256 digests are
stored by Relay. Host and device credentials have distinct route permissions.
Rotation creates a new mailbox epoch and invalidates the prior credentials.

For M1 only, `mailbox_id`, both bearer-token digests,
`host_identity_commitment`, `device_key_commitment`, and initial epoch are
provisioned out of band through an explicit local test/admin seam before Relay
serves v2. Pairing and registry mutation are outside M1 and are neither
implemented nor implied by any v2 route.

Transport TLS is mandatory outside loopback, but bearer/TLS is not E2EE and is
not command authority.
`/v2/*` rejects cleartext transport unless the peer is loopback and the server
was explicitly started in v2 test mode. An external TLS terminator is accepted
only from an explicitly configured loopback peer; Relay never trusts ambient
`Forwarded` or `X-Forwarded-Proto` headers. Production clients require HTTPS/WSS
certificate validation and never send a bearer over cleartext.

## Opaque frame v2

Canonical JSON, exact keys, no unknown/duplicate fields:

```json
{
  "schema": "nomad.relay.opaque-frame.v2",
  "crypto_suite": "p256-hkdf-sha256-aes256gcm-v1",
  "mailbox_id": "mbx-<64hex>",
  "direction": "host_to_device|device_to_host",
  "epoch": 1,
  "sequence": 1,
  "message_id": "msg-<32hex>",
  "issued_at": 0,
  "expires_at": 0,
  "nonce": "<base64url 12 bytes>",
  "ciphertext": "<base64url bounded bytes including GCM tag>"
}
```

AAD is canonical bytes of every field except `ciphertext`, including the exact
`crypto_suite`, prefixed with
`nomad.remote-envelope.v2\n`. The 96-bit nonce is unique per derived key; senders
must allocate monotonically increasing sequence numbers durably before publish.
Keys are derived per direction and epoch with HKDF salt bound to mailbox ID and
info bound to protocol version, direction, Host identity commitment, device-key
commitment and epoch.

Plaintext is one exact bounded application envelope, then padded into reviewed
buckets before encryption. M1 treats ciphertext as bytes and never parses it.
Maximum wire frame is 96 KiB; expiry is at most 10 minutes from issue; clocks may
differ by at most 60 seconds.

## M1 Relay package

Owned files:

- new `relay/v2_protocol.go`
- new `relay/v2_mailbox.go`
- new `relay/v2_server.go`
- new focused `relay/v2_*_test.go`
- `relay/cmd/relay/main.go` only for an explicit `--v2-*` configuration gate

Routes under `/v2/mailboxes/{mailbox_id}` only:

- `POST /frames` with sender-role bearer
- `GET /frames?direction=&after_sequence=` with receiver-role bearer
- `POST /acks` with receiver-role bearer
- Host-only `DELETE /` for best-effort revocation cleanup

Exact role matrix:

| Bearer | Publish | Read | ACK | Revoke |
| --- | --- | --- | --- | --- |
| Host | `host_to_device` only | `device_to_host` only | `device_to_host` only | yes |
| Device | `device_to_host` only | `host_to_device` only | `host_to_device` only | no |

Opposite-direction or same-direction read/ACK is `403` before mutation.

The Relay validates exact framing, bearer digest, mailbox, role, direction,
epoch, sequence, nonce shape, issue/expiry window and ciphertext bounds. It
does not decrypt or receive encryption keys. POST is idempotent only for the
same `(mailbox, direction, epoch, sequence, message_id, frame_digest)`; conflict
is rejected. ACK tombstones survive payload cleanup for the full replay window.
Reads use a monotonic cursor and never cross direction or epoch.
`frame_digest` is SHA-256 over the exact canonical frame bytes including
ciphertext. `GET` returns strictly ascending frames with `sequence >
after_sequence` for one exact `(mailbox_id, direction, epoch)`. `POST /acks` has
the exact body
`{"schema":"nomad.relay.opaque-ack.v2","mailbox_id":...,"direction":...,"epoch":...,"acked_through_sequence":...}`.
Relay persists `max_acked_sequence` per mailbox/direction/epoch; ACK is monotonic
and idempotent. Payloads at or below it may be deleted, but tombstones keyed by
mailbox/direction/epoch/sequence/message ID survive for 30 days. Wall-clock
checks are admission freshness only; durable tuple/tombstone checks prevent
rollback from reopening accepted, ACKed, rejected, or revoked frames. Relay also
persists `max_seen_issued_at` per mailbox/direction/epoch and never lowers it.

Host-only `DELETE /` is an irreversible transaction: mark the mailbox revoked,
record `revoked_at`, reject all later reads/writes/ACKs for every epoch, then do
best-effort ciphertext cleanup. The revoked row and replay tombstones survive
restart. Rotation is a separate operation that creates a new mailbox identity;
it never reactivates a revoked row.

SQLite uses WAL and `synchronous=FULL`. Mailbox/frame/ACK mutation is
transactional. Limits: one active epoch, 100 unacked frames per direction, 5
frames/second burst, 10-minute payload TTL, 30-day ACK/replay tombstone.

## M1 P0 tests

- Relay DB/frame/API never contain known plaintext canaries or crypto keys.
- Wrong role, token, mailbox, direction, epoch, sequence, nonce, expiry and
  frame digest fail before mutation.
- Duplicate identical publish is idempotent; changed ciphertext under the same
  tuple conflicts; ACKed or cleaned payload cannot be replayed while tombstone
  lives.
- Receiver cannot read the opposite direction; sender cannot ACK or delete.
- Mailbox delete prevents all later read/write and cannot be undone by replay.
- Restart preserves cursors, ACK tombstones and revocation.
- v1 endpoints and v2 tables/types are disjoint; v1 keys never authenticate v2.
- Golden vectors cover AAD, HKDF inputs and AES-GCM in Go, Rust and WebCrypto
  before M2 begins.

## Later joins

M2 adds an explicit device-registry schema migration for P-256 signing and ECDH
public keys, then Host and browser crypto endpoints. M3 connects encrypted
projection and command messages to the Host shared device/command lock. Only M3
may claim remote command mechanics; only a physical phone run may claim G3.
