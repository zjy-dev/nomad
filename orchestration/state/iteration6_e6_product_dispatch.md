# Iteration 6 E6 Product Topology Dispatch

Status: IMPLEMENTATION AUTHORIZED after E1.3, E2/E2c, and Browser UI independent PASS/FREEZE.

## Product gate

E6 proves only `local_machine_usable`: a materialized bundle starts the real process topology and a real desktop browser completes the HTTPS pairing and remote-session journey. It does not prove physical-phone usability, Provider E3, clean-machine installation, signing/notarization, or public production readiness.

## Frozen topology

- `relay-host`: run-scoped v1 sink, v2 host listener, isolated loopback admin listener.
- `relay-device`: run-scoped v1 sink, v2 device listener.
- Both Relay processes share the persistent v2 mailbox database; host starts first and initializes it.
- `nomad-product-host`: private UDS; bootstrap v2 on FD 10 and Relay admin bearer on FD 11.
- official Agent: loopback-only and the only session writer; provider credential enters only this child.
- `desktop-gateway`: loopback HTTP, desktop routes only.
- `join-gateway`: loopback HTTP, join/remote routes only.
- `nomad-ingress`: explicit LAN address HTTPS; exact allowlist to join Gateway and device Relay.

Public ingress must reject `/api/desktop/*`, `/internal/*`, `/v2/admin/*`, `/v1/*`, encoded path bypasses, and unsupported methods locally. The mode name is `remote-local-evidence`; state and evidence must say `network_scope=lan_direct` and `production_external=false`.

## Secret and FD contract

- Provider credential: official Agent child only; never Host/Relay/Gateway/browser/state/logs/argv.
- Desktop and join transport keys: distinct; Host bootstrap plus the corresponding Gateway's inherited secret FD.
- Command authority key: Host bootstrap only.
- Relay admin bearer: same bytes through two independent pipes to Product Host and relay-host; never argv/env/state.
- Trusted ingress token: same bytes through two independent pipes to join Gateway and HTTPS ingress; never argv/env/state.
- TLS certificate and private key: operator-opened descriptors consumed by ingress; never bundle/state/argv.
- Mailbox bearers: Host creates them; Relay stores digests; browser receives only wrapped bearer.

## Startup and shutdown

Validate all inputs and port uniqueness before spawning. Start relay-host, relay-device, Product Host/Agent, desktop Gateway, join Gateway, and HTTPS ingress in dependency order. Accept Product Host ready v2 only after pairing and remote mailbox readiness. Probe each role-specific route plus public negative routes before atomically publishing state v2.

Shutdown order: HTTPS ingress, join Gateway, desktop Gateway, Product Host, Agent, relay-device, relay-host. Normal stop preserves device registry, pairing store, remote mailbox cursor, and Relay v2 database.

## Work packages

### E6-A Launcher composition

Owner files: `tools/nomad_web/config.py`, `launcher.py`, `processes.py`, `state.py`, `cli.py`, and `testkit/nomad-web/test_m3e_launcher.py`.

Implement the `remote-local-evidence` inputs, role-specific ports/processes, bootstrap v2/FD distribution, state v2, rollback, restart, and stop behavior.

### E6-B Narrow HTTPS ingress

Owner files: new `relay/cmd/nomad-ingress/*`.

Implement TLS from inherited descriptors, exact route/method allowlist, request/header/cookie normalization, trusted-ingress authentication to the join Gateway, device Relay proxying, bounded bodies/responses, content-free ready frame, and graceful shutdown.

### E6-C Installable bundle

Owner files: `tools/nomad_web/bundle.py`, `materialize.py`, `bundle_manifest.json`, and bundle-focused tests only.

Include the ingress binary and complete Gateway module closure including `pairing-session.mjs`; preserve strict file allowlist, modes, digests, and source-tree independence.

### E6-D Real process and desktop-browser evidence

Owner files: new files under `testkit/remote-v2/` and one task report. Start only after A-C stabilize. Run materialized binaries, real browser/WebCrypto, exact pairing and `view/reply/deny/Stop` paths, refresh recovery, revoke, and negative public-route probes. Provider E3 remains `NOT_RUN` unless real credentials and official Agent evidence exist.

## Hard non-claims

- Desktop browser is not a physical phone.
- LAN-direct HTTPS is not production external topology.
- Component, fixture, or mock tests are not real-process evidence.
- No E6 result changes Provider E3, clean-machine, physical iPhone, signing, or notarization from `NOT_RUN`.
