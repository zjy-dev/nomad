# Relay v2 mechanical real-process slice

This directory owns the M3-D acceptance harness. The accepted topology is two
actual `relay/cmd/relay` processes, because one Relay v2 listener has exactly
one fixed role. The host-role and device-role processes use different dynamic
loopback ports and the same file-backed v2 SQLite database. Only the first
process consumes the private provisioning file; the second opens the already
provisioned database.

The harness requires the actual Rust
`nomad-remote-v2-mechanical` endpoint and the actual Node WebCrypto endpoint in
`device.mts`. There is deliberately no Python HTTP, mock endpoint, or in-memory
substitute. It executes projection, Stop, rejected receipt, restart cursor,
byte-stable pending retry, wrong-role rejection, and revoke phases as separate
endpoint processes. If either helper is absent, the runner exits nonzero with
`BLOCKED_HELPERS_REQUIRED`.

Run it with:

```sh
python3 testkit/remote-v2/run_remote_v2_slice.py
```

Secrets are generated per run. Bearer values are passed only in the relevant
child environment, while the Relay provisioning file contains only SHA-256
digests and commitments. Temporary parents are mode `0700`, the canonical
provisioning file is mode `0600`, and allowlisted Provider environment names
are removed from all child environments. The harness never reads or writes
`testkit/process-loop/last-transcript.json`.

Successful evidence ends with `REMOTE_V2_MECHANICAL_PASS` and always labels
Provider execution and physical-phone execution as `NOT_RUN`. This is local
mechanical evidence, not production readiness.
