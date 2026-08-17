# Local Validation Slice

This repository currently implements a synthetic/disposable validation slice.
It exercises the frozen Session Semantics across a Rust Host reference core, an
opaque Go Relay, a responsive Mobile reference client, and fault/conformance
harnesses. It is not Private Alpha evidence.

Run the reproducible non-browser checks from the repository root:

```bash
sh scripts/validate-local-slice.sh
```

Run the responsive browser smoke after installing Python Playwright and using a
local Chrome executable:

```bash
python /path/to/with_server.py \
  --server "cd mobile-reference && npm run dev -- --host 127.0.0.1" \
  --port 5173 -- \
  python testkit/browser/mobile_reference_smoke.py
```

Verified reference behavior:

- nine golden Session traces and canonical snapshot digests;
- loopback/version gate, single-writer projection and command dedup;
- Stop/interrupt ordering and mobile `allow_once=false`;
- opaque Relay mailbox with per-device ACK, TTL, capacity and rate limits;
- Mobile NeedsPermission checkpoint, deny/Stop, timeline, diff and truthful
  RelayReceived versus HostAccepted labels;
- duplicate, reorder, drop, delay, restart and disk-full synthetic faults.

Not yet proven by this slice:

- a live OpenCode v1.18.16 adapter and real pending-permission competition;
- production Security Envelope/E2EE, pairing, revocation and APNs;
- native iOS lifecycle, Keychain/Secure Enclave, biometric approval and TestFlight;
- real Host-to-Relay-to-Mobile process communication under network faults;
- 100k-event and eight-hour product workload targets;
- external-user activation, usability, retention or Private Alpha release gates.
