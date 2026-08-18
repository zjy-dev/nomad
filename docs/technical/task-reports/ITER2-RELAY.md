# Iteration 2 Relay Completion Report

| Field | Value |
| --- | --- |
| Scope | PRD-204, PRD-215, PRD-218 Relay lane |
| Boundary | Controlled Pilot TEST-ONLY bridge |
| Date | 2026-08-18 |
| Result | Implemented and relay tests pass |

## Delivered behavior

The persistent `TestBridgeStore` now owns two SQLite tables: the compatible
`test_messages` mailbox and `test_pairing_challenges`. The latter stores a
random challenge ID, channel, a random salt, a SHA-256 code hash, two-side
confirmation timestamps, expiration, and one-time consumption. The plaintext
six-digit comparison code is returned only when the challenge is created and
is not stored. The fixed challenge TTL is two minutes.

Pairing completes through three explicit stages: create, confirm independently
as `host` and `mobile` with the same code, then consume. Wrong code, expiration,
repeated confirmation by the same side, consumption before both confirmations,
and consumption or confirmation after consumption are rejected. Consumption is
persisted, so a Relay restart does not make a challenge reusable. This is a
Pilot comparison mechanism behind one shared test token; it is not device
identity, proof of possession, E2EE, key rotation, or a production pairing
protocol.

Channel cleanup deletes all ACKed and unACKed test messages and all pairing
challenges for exactly one channel in one SQLite transaction. Repeating cleanup
is safe and returns zero counts. The response contains aggregate deletion counts
only; it does not return or log message IDs, payloads, comparison codes, or
pairing hashes.

## HTTP and storage contract

All paths below exist only when `--enable-test-bridge` is supplied, require
`Authorization: Bearer <test-token>`, and are only accepted when Relay binds a
loopback address. JSON bodies are limited to 64 KiB. Channels are non-blank and
at most 128 bytes; message IDs are non-blank and at most 256 bytes; target is
`host` or `mobile`.

| Method and path | Request | Successful response |
| --- | --- | --- |
| `POST /v1/test/messages` | `{channel,target,message_id,payload}` | `202` with ID, `new`, channel, target and message ID |
| `GET /v1/test/messages?channel=...&target=host|mobile` | No body | Ordered unACKed messages with object payloads |
| `POST /v1/test/ack` | `{channel,target,message_ids}` | `200`; ACK is idempotent |
| `POST /v1/test/pairing/challenges` | `{channel}` | `201` with random `challenge_id`, six-digit `comparison_code`, `expires_at`, `test_only:true` |
| `POST /v1/test/pairing/confirm` | `{channel,challenge_id,side,comparison_code}` | `200` with confirmation booleans and no code |
| `POST /v1/test/pairing/consume` | `{channel,challenge_id}` | `200` with `consumed:true` after both confirmations |
| `POST /v1/test/cleanup` | `{channel}` | `200` with deleted unACKed, ACKed and pairing counts only |

Pairing failures return only a stable error code: `PAIRING_NOT_FOUND`,
`PAIRING_EXPIRED`, `PAIRING_CONSUMED`, `PAIRING_CODE_MISMATCH`,
`PAIRING_CONFIRMATION_REPLAY`, `PAIRING_CONFIRMATION_REQUIRED`, or
`PAIRING_INVALID_SIDE`. They do not echo the channel, challenge, submitted code,
or stored data.

The `test_messages` compatibility contract is unchanged. In particular, a Host
can publish the existing `session.checkpoint` object without a new envelope:

```json
{
  "channel": "pilot-01",
  "target": "mobile",
  "message_id": "checkpoint-pilot-01-0",
  "payload": {
    "type": "session.checkpoint"
  }
}
```

For Host publication, use `POST /v1/test/messages` with target `mobile`. A Node
consumer polls `GET /v1/test/messages?channel=pilot-01&target=mobile`, applies
its stable message-ID deduplication, and ACKs successfully applied records with
`POST /v1/test/ack`. Commands use the same paths in the opposite direction with
target `host`. Relay receipt or ACK still does not mean Host acceptance.

## Restart recovery evidence

`TestPilotSQLiteRecoveryAcrossRealReopen` uses a temporary on-disk SQLite file
and three distinct `NewMailboxDB` lifetimes:

1. Store an unACKed `session.checkpoint`, then close the database.
2. Reopen it and verify the checkpoint is listed unchanged. Re-publish the same
   `(channel,target,message_id)` and verify `new=false`, the original row ID is
   returned, and no second row is inserted. ACK it and close the database.
3. Reopen again and verify the ACKed checkpoint is not listed. Replay the same
   message ID once more and verify it remains the single ACKed row and does not
   reappear.

This proves persistent at-least-once mailbox recovery and Relay-side stable-ID
deduplication. It does not by itself prove a Host process accepted a command
only once, browser cursor convergence, snapshot digest validation, or a 30-second
end-to-end Live transition; those remain integration-gate responsibilities.

## CORS and deployment limitations

Relay currently emits no `Access-Control-Allow-*` headers and has no `OPTIONS`
handler. Therefore a same-origin consumer or Node process can use these endpoints,
but a browser page on another origin cannot send the Bearer request directly.
The test bridge also refuses non-loopback binds. An iPhone cannot connect to the
Mac's `127.0.0.1`; a controlled same-origin/TLS proxy or an explicitly reviewed
deployment change is required before real-phone integration. Broadening the bind
or adding permissive CORS in this lane would weaken the established TEST-ONLY
boundary and was not done.

The executable defaults to `:memory:`. Restart recovery requires a file path, for
example:

```sh
go run ./cmd/relay \
  -addr 127.0.0.1:8089 \
  -db /tmp/nomad-pilot-relay.sqlite \
  -enable-test-bridge \
  -test-token "$NOMAD_PILOT_TEST_TOKEN"
```

The operator must supply TLS outside this process before any non-loopback
transport is considered. The shared Bearer token is test access control only.
The Relay does not provide production identity, account cleanup, E2EE, Push,
device keys, revocation, a retention SLA, or protection suitable for real
repositories and credentials. Cleanup covers the Relay channel and pairing
state only; Host local state and temporary Provider accounts require their own
lane cleanup.

## Verification

Run from `relay/`:

```sh
gofmt -w testbridge.go server.go testbridge_test.go testbridge_pilot_test.go
go test ./...
go test -race ./...
```

Observed results on 2026-08-18:

```text
ok   github.com/nomad/relay             1.230s
?    github.com/nomad/relay/cmd/relay   [no test files]
ok   github.com/nomad/relay             2.693s
?    github.com/nomad/relay/cmd/relay   [no test files]
```

Coverage added for six-digit generation, two-minute expiration, mismatched code,
premature consumption, duplicate confirmation, consumed replay, HTTP bearer
authentication, privacy-safe errors, request-size limit, idempotent scoped
cleanup, content-free cleanup response, and real close/reopen SQLite recovery.
