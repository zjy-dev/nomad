# Iteration 6 A2 Integration Dispatch

Status: DISPATCHABLE IN TWO JOINS

## Trust split

The frozen local command path and the future remote-phone path are different
principals. They share the Host-final command authority and Agent adapter, but
they never share a capability, nonce space, pairing epoch, or ingress key.

- `local-run-gateway`: authenticated only by the run-scoped FD11 transport key
  and private UDS. It remains available exactly as C3 froze it. It is not a
  paired phone and is destroyed with the run.
- `remote-paired-device`: authenticated by possession of the public key whose
  digest and current epoch are stored in `DeviceAuthority`. It is unavailable
  until explicit pairing succeeds and becomes unavailable immediately on
  revoke. It never falls back to FD11 identity.

## A2a: persistent registry adoption and local administration

Owned files:

- `connector/src/product_host_bootstrap.rs`
- `connector/src/product_stock_projector.rs`
- `connector/src/product_command_protocol.rs`
- `tools/nomad_web/launcher.py`
- focused Rust/Python tests

Contract:

1. Launcher owns a stable `0700` directory under Nomad home and passes the
   absolute fixed-basename `host-device-registry.sqlite3` path in FD10. Stop
   preserves it; uninstall removes it only after the same owner/path checks as
   creation. It is never run-scoped and is never included in evidence content.
2. Product Host opens `DeviceAuthority` before readiness. Failure is fatal. It
   keeps the existing local `AuthenticatedDeviceSession` for FD11 commands and
   labels that value in code as local/run-scoped. No registry row is created
   automatically for it.
3. Add four strict, FD11-authenticated, local-only UDS routes:
   - `GET /internal/devices/current`
   - `POST /internal/devices/pairing/challenge`
   - `POST /internal/devices/pairing/confirm`
   - `POST /internal/devices/revoke`
4. Request/response schemas are bounded, deny unknown/duplicate fields, and
   contain no Agent IDs, Provider facts, private key, command key, raw path, or
   reply content. The Host supplies the fixed principal alias; callers cannot.
5. Pairing completion/revocation and any future remote command acceptance share
   one process-local mutex. A2a introduces this facade now even though no remote
   command route is enabled.
6. The existing browser command capability and C3 route remain byte-compatible.
   Pairing management is not exposed to the browser in A2a.

A2a exits only when C3 local commands remain green, registry survives restart,
stop preserves it, uninstall safely deletes it, and UDS negative tests prove no
unauthenticated pairing/revoke call reaches registry mutation.

## A2b: remote authenticated Host ingress

Depends on A2a PASS/FREEZE and the separate encrypted Relay envelope contract.
It must not be implemented as a new browser-to-Host socket.

The future decryptor hands the Host exact authenticated remote request bytes
plus the presented public key. Inside the shared device/command mutex the Host:

1. hashes the presented public key and matches the current registry digest;
2. verifies the remote signature over direction, device alias, epoch, message
   nonce/sequence, expiry, and exact command bytes;
3. re-reads current non-revoked device alias/epoch;
4. derives a Host-only command key from the bootstrap authority key, device
   digest and epoch using a domain-separated KDF;
5. constructs an internal `AuthenticatedDeviceSession`;
6. re-checks the device immediately before the journal claim and calls the
   existing single Host authority.

Old epoch, revoked device, replayed remote nonce/sequence, wrong direction,
wrong key, stale capability, decrypt failure, Host offline, or registry failure
causes zero new Agent calls. Relay acknowledgement is never Host success.

## Required evidence

- local C3 capability/command golden vectors unchanged;
- no auto-pairing at startup;
- local principal cannot claim a remote device alias and remote principal cannot
  use FD11 capability state;
- pairing/revoke restart tests on the materialized Host path;
- revoke-vs-command barrier test proving the losing old remote command performs
  zero journal insertion and zero adapter calls;
- content scans cover registry, journal, browser assets, logs and argv.

This still does not prove a real phone or Provider E3.
