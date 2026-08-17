# TEST-ONLY Local Process Bridge v1

This API exists only to prove a synthetic/disposable Host → Relay → Mobile
process loop. It is disabled by default, must bind to loopback, uses an explicit
test token, and is not the Security Envelope or production pairing protocol.

## Relay endpoints

All requests require `Authorization: Bearer <test-token>`.

- `POST /v1/test/messages`
  - body: `{"channel":string,"target":"host"|"mobile","message_id":string,"payload":object}`
  - idempotent on `(channel,target,message_id)`
- `GET /v1/test/messages?channel=<id>&target=<host|mobile>`
  - returns unacked messages in insertion order
- `POST /v1/test/ack`
  - body: `{"channel":string,"target":"host"|"mobile","message_ids":[string]}`

## Message payloads

- `pair.request`: Mobile sends a six-digit `comparison_code`; Host returns
  `pair.confirmed` with the same code. This is a local interaction proof, not
  SEC-002 pairing.
- `session.checkpoint`: Host publishes the synthetic NeedsPermission checkpoint
  and diff summary to Mobile on startup.
- `command`: Mobile sends a Session Semantics command (`deny` or `stop`; reply is
  supported). `allow_once` must return `Rejected/ERR_SAFETY_BLOCKED`.
- `command.result`: Host returns explicit `status` and `result`; Relay receipt is
  never displayed as Host acceptance.

## Acceptance transcript

The process-loop harness must prove, using real OS processes:

1. test-only pairing comparison code round-trips through Relay;
2. Mobile receives a Host checkpoint with `NeedsPermission` and diff metadata;
3. Mobile deny is explicitly Host-accepted and idempotently journaled;
4. Mobile Stop is explicitly Host-accepted;
5. Mobile ACK removes each Relay message;
6. `allow_once=false` throughout;
7. no production security, APNs or native-iOS claim is made.
