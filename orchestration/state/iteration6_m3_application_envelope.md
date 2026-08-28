# Iteration 6 M3 Application Envelope

Status: FROZEN FOR M3-B IMPLEMENTATION

## Boundary

The decrypted value is one strict canonical JSON object. It is not a general
Agent protocol. OpenCode-specific interpretation remains in
`adapters::opencode`; this envelope carries only Nomad product facts already
accepted by the C3 Host authority. Maximum canonical plaintext is 32 KiB.
Duplicate keys, unknown keys, trailing bytes, non-canonical JSON, and a value
whose outer bindings do not exactly match the authenticated Relay frame fail
before application.

Exact common fields:

```json
{
  "schema": "nomad.remote.application-envelope.v1",
  "kind": "projection|command|receipt",
  "mailbox_id": "mbx-<64 lowercase hex>",
  "direction": "host_to_device|device_to_host",
  "epoch": 1,
  "sequence": 1,
  "message_id": "msg-<32 lowercase hex>",
  "payload": {}
}
```

`mailbox_id`, `direction`, `epoch`, `sequence`, and `message_id` must equal the
authenticated frame metadata byte-for-value. `projection` and `receipt` are
`host_to_device`; `command` is `device_to_host`.

## Projection

```json
{
  "schema": "nomad.remote.projection.v1",
  "snapshot": {"schema": "nomad.product-host.snapshot.v1"},
  "capability": null
}
```

`snapshot` is the exact content-safe `ProductSnapshotEnvelope` already served
by Product Host. `capability` is either `null` or the exact current
`OpenCodeCommandCapability`; it must contain `allow_once: false`. The Host must
derive both from the same fresh snapshot while holding `DeviceCommandGate`. No
raw Agent session, turn, question, permission, tool-call, path, or provider ID
may appear. A newer projection supersedes older display state only after frame
and plaintext verification.
The receiver recomputes the snapshot digest after removing `digest`. A non-null
capability must have `view=true`, must match that snapshot's sequence and
digest, and must use a whole-second UTC window no longer than 30 seconds.

## Command

```json
{
  "schema": "nomad.remote.command.v1",
  "command": {"schema": "nomad.gateway.command.v1", "action": "reply|deny|stop"}
}
```

`command` is byte-semantically the existing strict C3 command body, including
`capability_id`, stable `request_id`, nonce, command sequence, expected snapshot
sequence/digest, issue/expiry times, and action-specific aliases. Only
`reply`, `deny`, and `stop` exist. `allow_once` and unknown actions fail before
journal claim. Remote acceptance occurs under the same `DeviceCommandGate` as
pair/revoke and uses the active registry principal and epoch, never the
`local-run` principal. Redelivery of the exact request retrieves the stored
receipt; no layer creates a replacement request ID.
Reply content is non-blank UTF-8, at most 8 KiB; the canonical nested command is
at most 16 KiB. Command, capability, and receipt times are exact whole-second
UTC strings. Snapshot `updated_at` is exact millisecond UTC.

## Receipt

```json
{
  "schema": "nomad.remote.receipt.v1",
  "receipt": {"schema": "nomad.product-host.command-receipt.v1"}
}
```

`receipt` uses `nomad.gateway.command-receipt.v1`, the existing C3 browser-facing
receipt after the Gateway's schema-only translation of the Product Host
`WireReceipt`: receipt/request IDs, action, bound
snapshot sequence/digest, accepted time, status, safe error code, and
`idempotent_replay`. The exact status vocabulary remains owned by the existing
Host authority and its serializer; M3 must not add intermediate or optimistic
success states. Relay storage or ACK is not a success receipt.
`OutcomeUnknown` remains explicit and disables any automatic retry; exact replay
returns the same stored outcome.
The wire status set is exactly `HostAccepted`, `Dispatching`,
`DispatchAcknowledged`, `Rejected`, `Stale`, `Expired`, and `OutcomeUnknown`.
Only Host-authority receipt error codes are accepted; transport/pre-accept HTTP
errors such as `COMMAND_UNAVAILABLE` are not receipt codes.

## Processing order

Receive: frame bounds -> tuple/cursor -> cryptographic verification/decryption
-> strict canonical application envelope -> common-field equality -> kind and
payload schema -> Host shared gate or browser reducer -> durable applied cursor
-> Relay ACK.

Send: build strict payload -> reserve sequence durably -> build common envelope
with that tuple -> canonicalize/encrypt once -> persist exact canonical frame ->
publish. Transport retry reuses those exact bytes. Reserved sequence gaps caused
by a crash before encryption are allowed; receivers require strict increasing
order greater than the durable cursor, not contiguity.

## Required tests

- Every common field mismatch fails before product state or journal mutation.
- Snapshot digest is recomputed over the exact Product Host envelope with the
  `digest` field removed; capability snapshot seq/digest must equal it,
  `view=true`, `allow_once=false`, and the capability TTL is at most 30 seconds.
- Kind/direction mismatch, unknown kind/action, `allow_once`, duplicate/unknown
  fields, trailing JSON, oversize plaintext, and non-canonical JSON fail closed.
- Projection contains only the existing content-safe snapshot/capability surface.
- Exact command redelivery has at most one upstream dispatch.
- `OutcomeUnknown` survives restart and never causes a new request.
