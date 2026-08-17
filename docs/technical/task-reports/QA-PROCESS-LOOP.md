# QA-PROCESS-LOOP Completion Report

- Status: Done, real local processes
- Completed at: 2026-08-17

## Topology

```text
Node Mobile process
  -> Go Relay /v1/test/messages
  -> Rust Host process bridge
  -> Go Relay response mailbox
  -> Node Mobile process + transcript
```

## Outcome

Closed the Round-1 product P0: the three actual OS processes now exchange one
pair request, a Session checkpoint, deny, Stop and allow-once rejection. Relay
receipt and Host acceptance are distinct; each received message is ACKed.

## Verification

- `python3 testkit/process-loop/run_process_loop.py --timeout 60` ->
  `PROCESS_LOOP_PASS pair checkpoint deny stop ack allow_once=false`.
- Transcript: `testkit/process-loop/last-transcript.json`.
- Transcript validator checks comparison code equality, NeedsPermission and diff
  metadata, deny/Stop HostAccepted, RelayReceived separation, allow-once
  `ERR_SAFETY_BLOCKED`, and final completion.

## Scope

- Real process boundaries; synthetic/disposable data and TEST-ONLY local Relay.
- Not Private Alpha, production pairing, E2EE, APNs or live OpenCode evidence.
