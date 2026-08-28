# M3-E Real Product Slice (E6-D)

Status: `BLOCK` at the final7 Host identity preflight (2026-08-28).

This gate starts the exact installed bundle at
`/tmp/nomad-e6d-final7-bundle` and requires the seven-process
`remote-local-evidence` topology. A real Google Chrome binary is driven through
Playwright without `ignoreHTTPSErrors`. TLS uses a run-scoped CA with the LAN
address `192.168.100.3` in the leaf SAN and an isolated Chrome NSS profile that
is removed after the run.

The journey covers the HTTPS join shell, two-sided comparison-code pairing,
the encrypted remote projection, browser refresh recovery, desktop revoke, the
blocked revoked browser, and public negative routes. Reply, deny, and Stop are
reported as `NOT_RUN` when the official Agent has no corresponding pending
state; the runner never manufactures that state.

Evidence is content-free. It records the bundle digest, process identities,
normal TLS verification, route status codes, and boolean journey results, but
never records join secrets, comparison codes, bearers, browser storage, page
content, Session content, or Provider credentials. The Agent receives a clear
TEST-ONLY canary solely to satisfy startup. Therefore Provider E3 and physical
phone evidence remain `NOT_RUN`, `network_scope` remains `lan_direct`, and
`production_ready` remains `false`.

## Runtime result

The current exact bundle is `/tmp/nomad-e6d-final7-bundle`, with manifest digest
`683382f135833bef10ca8df700d3d06033c0663b3a0a38ff949739400d196423`
and source commit `4e4ac68765a8c399887a15bb2452cbe22983dbd2`. The
runner would use a TEST-ONLY provider canary solely to start the official
Agent, but final7 stopped before any credential or business process was used.

## Current final7 blocker

The runner first executed the exact bundled Product Host command
`identity-preflight --non-interactive`. It returned the exact fixed result
`USER_DENIED` with exit status 1 and empty stderr. The resulting E6-D evidence
records:

- code `HOST_IDENTITY_USER_DENIED`;
- `host_identity_preflight.status=USER_DENIED`;
- `business_process_count=0` and `process_count=0`;
- next step `nomad-web authorize-host-identity`;
- Provider E3 and physical phone `NOT_RUN`;
- `production_ready=false`.

This gate runs before temporary certificate creation, Relay, Agent, Product
Host service, Gateway, ingress, or Chrome startup. No final7 business process
was spawned. The strict run therefore correctly stopped without attempting the
browser journey.

Final7 strict evidence is
`/tmp/nomad-e6d-real-product-slice-evidence-final7.json` (mode 0600), SHA-256
`82f2279b5aa0b43d8083bf65b794624d86530b3416c6789d8e73bf11cd73479b`.

The final5 bundle contains launcher SHA-256
`8b83394cd7213b46ae7a9d64a2549ca66809c0e719fd152290b0f8fc252c9b1a`,
Gateway SHA-256
`5cc8c159448f3731b08ce3e749c6e760f15d9466c28c79cbbc8b9a5593153633`,
and Product Host SHA-256
`10fee3e92c943cae6458c9900885a0139142bfc4243311a9749ed6585ca89a45`.

## Historical final5 blocker

The exclusive exact-SPKI diagnostic run stopped before browser launch.
`nomad-web start` returned `HOST_READY_INVALID` after the remote Product Host
ready interval. Only the first four roles reached log creation (`relay-host`,
`relay-device`, official Agent, and Product Host); Product Host and Agent logs
were empty, no run state was published, and no log contained an `error`,
`panic`, or `fatal` signal.

The unit-level ready contracts still pass:

- `ready_v2_is_length_prefixed_exact_json_only_after_remote_barrier`;
- `start_with_pairing_does_not_wait_or_signal_and_exposes_authority_before_worker_ready`.

The launcher and Host source agree on the ready-v2 schema, fields, and initial
`snapshot_seq=1`. This leaves a process-level ready-barrier failure not covered
by those unit tests: Product Host did not produce a launcher-acceptable remote
ready frame before timeout, or did not complete the expected framing/EOF
contract. Browser, TLS, pairing, projection, refresh, and revoke are all
`NOT_RUN` for final5.

Historical final5 diagnostic evidence is
`/tmp/nomad-e6d-real-product-slice-diagnostic-final5.json` (mode 0600), SHA-256
`e30b739ed27897aef71005a4234df8d64854d849f49cbadca454fd548df07e88`.
It is `BLOCK`, not PASS.

The following real-process checks passed in the earlier d0bc strict run; they
are historical context and are not attributed to final5:

- all seven launcher-owned roles were alive with validated process identities:
  `relay-host`, `relay-device`, official `opencode`, `product-host`,
  `desktop-gateway`, `join-gateway`, and `https-ingress`;
- the CA-signed leaf contained the LAN SAN and passed normal certificate-chain
  verification;
- all six public negative probes returned 404: desktop, internal, admin,
  legacy, encoded-join, and unsupported join method;
- real Google Chrome loaded the desktop product HTML with status 200;
- the rendered app had a mounted root, a visible Remote Pairing surface, and a
  visible `Pair phone` control;
- `/api/alpha/session` returned status 200.

The prior `f94904da...` bundle stopped at
`browser_desktop_pairing_blocked_command_capability_unavailable`. Clicking
`Pair phone` did not send `/api/desktop/pairing/create`. The browser client's
CSRF provider first requested `/api/commands/capability`; six consecutive
samples returned status 503 with the fixed error code
`COMMAND_CAPABILITY_UNAVAILABLE`. The desktop Gateway owns a separate pairing
CSRF value, but the installed UI has no independent route to obtain it and
therefore gates pairing on command-capability availability. This is a product
P1 across the UI/Gateway contract, not a selector, TLS, or harness failure. Its
evidence remains historical BLOCK at
`/tmp/nomad-e6d-real-product-slice-evidence-f94904da-historical.json`; it must
never be presented as PASS. The current `d0bc877e...` bundle fixed that seam:
desktop security, current-device, pairing-create, and pairing-status requests
all returned 200.

## Historical strict TLS blocker

The prior d0bc default runner remained strict and did not pass any certificate-error
switch. It stopped at
`browser_join_navigation_ERR_CERT_AUTHORITY_INVALID`. The temporary CA and its
LAN-SAN leaf passed normal Python/OpenSSL validation, but Google Chrome 152 on
macOS did not use the CA imported into the isolated NSS profile. A temporary
user keychain, even when made the default keychain, still required an
interactive authorization prompt for `security add-trusted-cert`. The runner
does not mutate the login or system keychain automatically.

That strict result remained `BLOCK`, with
`tls.probe_client_verified=true`, `tls_verified=false`, and
`normal_chrome_verification=false`. The historical strict evidence is
`/tmp/nomad-e6d-real-product-slice-evidence-d0bc-strict-block.json` (mode 0600), SHA-256
`93110133fb166dac1e8179d1f9987b2c273f35eb9a45dde7fe631073cf3c7ee1`.

## Historical d0bc exact-SPKI diagnostic result

The explicit `--diagnostic-spki-bypass` mode uses only Chrome's exact leaf-SPKI
allowlist. It never enables global certificate ignoring, always records
`diagnostic_tls_bypass=true` and `tls_verified=false`, emits no PASS marker,
and cannot satisfy E6-D. It exists only to expose later product failures.

That diagnostic run reached and verified the following functional stages:

- HTTPS join shell loaded in a secure context;
- join/start, join/confirm, and join/complete all returned 200;
- the desktop showed one active paired device;
- the device registry contained one active epoch-1 device and one consumed
  pairing challenge;
- the browser made 63 authenticated public Relay frame reads, all returning
  200, without key-loss or revoke state.

It then stopped at `browser_remote_projection_timeout`. Content-free database
evidence showed one active Relay mailbox and both direction streams, but zero
stored frames and `host_to_device max_sequence=0`. Host remote state contained
only the initial device-to-host cursor and no pending host frame. The phone
remained in `connecting` state. All seven processes were alive and the logs
contained no `error`, `panic`, or `fatal` signal.

The product cause is in the Host projection path: `projection_locked()` obtains
the safe snapshot but then unconditionally calls `issue_current_capability()`.
When the TEST-ONLY Agent has no available command facts,
`capability_remote_locked()` returns `Unavailable`; the mailbox worker treats
the entire projection as retryable and never publishes even a view-only
projection. This incorrectly couples read-only viewing to write-capability
availability.

Historical diagnostic evidence is
`/tmp/nomad-e6d-real-product-slice-diagnostic-d0bc-historical.json` (mode 0600), SHA-256
`be136cc1cf212e0c3bef916b86a4c6395299cc648bec22c6f7aabdde771838a8`.

The evidence files contain
no join URL, URL fragment, comparison code, bearer, browser storage, page
content, Session content, provider credential, or raw logs. Runtime logs had
zero `error`/`panic`/`fatal` signals, and all launcher-owned processes were
stopped during cleanup.

STOP SHA (repository HEAD used for this run):
`4e4ac68765a8c399887a15bb2452cbe22983dbd2`.

## Resume condition

The next product fix must make the final5 real-process Product Host reach its
remote ready-v2 barrier and expose a content-free failure classification more
specific than `HOST_READY_INVALID`. Separately, formal E6-D
still needs an operator-approved normal Chrome trust path; the exact-SPKI mode
cannot satisfy that gate. After both conditions are available in a new
same-source bundle, rerun the strict command. Acceptance still requires the
real Chrome HTTPS join, pairing, projection, refresh, and revoke path; component
tests, direct API calls, or the diagnostic bypass cannot substitute for it.

Run preflight:

```bash
python3 testkit/remote-v2/run_m3e_product_slice.py --preflight
```

Run the slice and write evidence outside the repository:

```bash
python3 testkit/remote-v2/run_m3e_product_slice.py \
  --evidence /tmp/nomad-e6d-real-product-slice-evidence.json
```

Continue functional diagnosis only:

```bash
python3 testkit/remote-v2/run_m3e_product_slice.py \
  --diagnostic-spki-bypass \
  --evidence /tmp/nomad-e6d-real-product-slice-diagnostic.json
```
