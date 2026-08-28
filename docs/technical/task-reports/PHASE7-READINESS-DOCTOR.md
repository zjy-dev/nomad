# Phase 7 Release Readiness Doctor (P7-A)

Status: COMPLETE / REPOSITORY AUTOMATION ONLY / PRODUCTION READINESS REMAINS FALSE

## Scope

P7-A extends `nomad-web doctor` with a structured, content-free release view
while preserving the existing `nomad.web-companion.doctor.v1` foundation
fields. It does not change the CLI, launcher, bundle verifier, or runtime.

The doctor is read-only. It does not authorize Host identity, start processes,
read Provider credential values, accept TLS certificate bypasses, or consume
historical acceptance transcripts.

## Release contract

`release_schema=nomad.web-companion.release-readiness.v1` adds ordered gates.
Every gate has exactly one status from `PASS`, `BLOCK`, or `NOT_RUN`, a stable
content-free code, an actionable `next_step`, and bounded observations.

The gates cover:

- strict bundle verification and the verified manifest digest;
- the exact bundled Product Host command
  `identity-preflight --non-interactive`, with a five-second timeout, fixed
  environment, null stdin, byte-exact stdout, empty stderr, and exact exit code;
- all eight configured runtime ports, interpreted against stopped or verified
  running state;
- non-loopback LAN/global IP presence and the supported Google Chrome path;
- operator TLS inputs and normal Chrome trust, which this doctor can report only
  as `NOT_RUN` or `BLOCK`;
- Provider credential-source name presence without reading a value and without
  ever treating presence as Provider E3 `PASS`;
- owned process identity plus state-bound, role-specific live probes only when a
  validated remote running state exists;
- physical iPhone Safari, clean-machine install, Developer ID signing, Apple
  notarization, and publication provenance as explicit external `NOT_RUN` gates.

`release_blockers` is an ordered list of non-PASS gate code/action pairs.
`release_next_step` points to its first action. The legacy `next_step`,
`foundation_ready`, tool/path/three-port fields, and Provider-name fields retain
their prior meanings for compatibility.

`production_ready` remains `false`. Local checks, credential-name presence,
diagnostic TLS, and runtime state cannot upgrade the external release gates.

## Artifact and listener binding

Both local and remote run-state schemas now carry `bundle_digest`. A source-only
foundation run uses `null`; official Agent and remote modes require an exact
64-character digest. While holding the existing lifecycle lock, the launcher
uses P7-B's selector, re-verifies the selected bundle, requires its canonical
path to equal `home/bundles/<digest>`, and persists that digest. A restart of an
already running process set fails closed if the selected and recorded digests
differ. The selector, lock, canonical path, and rollback mechanisms remain
owned by P7-B and are not replaced here.

For a running release gate, the doctor independently requires all of the
following before role probes can pass:

- configured bundle digest, P7-B current-selector digest, run-state digest, and
  the freshly verified installed manifest digest are identical;
- the installed bundle is the canonical `home/bundles/<digest>` directory;
- every recorded process command references its exact bundle artifact; native
  Relay, Product Host, ingress, and Agent roles also expose that artifact as a
  loaded executable through the fixed macOS `lsof` interface;
- every state-bound loopback listener maps to exactly the expected process PID.
  This covers Relay host v1/v2/admin, Relay device v1/v2, desktop Gateway, join
  Gateway, and Agent.

Listener bindings, process identities, and the Product Host socket identity are
measured before and after live probes. Any mismatch, ambiguity, unavailable
system evidence, or mid-probe change blocks readiness.

## Live runtime proof

Runtime, pairing, and Relay gates no longer trust PID presence or persisted
`pairing_ready` / `remote_mailbox_ready` booleans. Before probing, the doctor
requires every recorded process identity to be launcher-owned and independently
re-measures the state-bound Product Host Unix socket identity. It repeats both
measurements after all probes. Any PID ownership change, socket replacement,
timeout, response framing error, schema mismatch, or role mismatch blocks the
runtime gate.

The content-free probes use existing protocol contracts:

- Product Host: an unauthenticated canonical pairing-create request to the
  state-derived Unix socket must return exact HTTP 401 and
  `nomad.product-host.error.v1 / UNAUTHORIZED`. This proves the pairing route
  exists and fails closed without reading or sending a transport secret.
- Relay v1 host/device listeners: `/health` must return exact fields
  `status=ok`, `protocol=TEST-ONLY/1`, and a positive integer timestamp.
- Relay v2 host/device listeners: fixed public probe data exercises both sides
  of the role matrix without mutation. A structurally valid but permanently
  expired publish in the role-allowed direction must return 410 before opening
  a transaction, while the forbidden direction must return 403 first. A read in
  the role-allowed receive direction must reach the mailbox DB lookup and return
  404 for the fixed nonexistent mailbox.
- Relay admin: unauthenticated GET of the existing provision route must return
  exact 405 JSON plus `Allow: POST`; a data-plane or wrong-role listener returns
  a different contract and therefore blocks.

Every TCP probe uses the exact port from validated run state, verified against
the active configuration. Responses are bounded to 4 KiB with a one-second
timeout, exact status/reason, JSON content type, no compression or chunked
framing, strict duplicate-key rejection, exact fields, and canonical body. No
credential, bearer from runtime state, mailbox content, or secret enters a probe
or doctor output.

## Verification

Focused table-driven coverage validates every Host identity status, malformed
identity output and timeout, each class of runtime-port collision, zero/one/many
Provider source names, absent bundle behavior, strict bundle/digest success,
stopped-versus-running process semantics, Product Host and Relay live-probe
success, timeout/schema/role failures, PID and socket identity drift, content-free
output, and the invariant that external gates and `production_ready` cannot pass
locally.

Commands used:

```text
python3 -m unittest testkit/nomad-web/test_release_readiness_doctor.py -v
python3 -m unittest testkit/nomad-web/test_clean_home.py -v
python3 -m py_compile tools/nomad_web/doctor.py testkit/nomad-web/test_release_readiness_doctor.py
git diff --check -- tools/nomad_web/doctor.py testkit/nomad-web/test_release_readiness_doctor.py docs/technical/task-reports/PHASE7-READINESS-DOCTOR.md
```

The P7-A focused suite passes 15/15 and the clean-home compatibility suite
passes 8/8 against the integrated CLI behavior. Python compilation and diff
whitespace checks pass. Product Host bootstrap and M3-E launcher regression
suites pass 33/33 and 19/19 respectively. The prebuilt-bundle suite passes
21/21 and the P7-B install-lifecycle suite passes 12/12.

## Remaining external blockers

- operator-supplied TLS inputs must be exercised by the strict release journey;
- normal Chrome certificate trust must pass without SPKI or certificate bypass;
- Provider E3 needs authoritative real-Provider lifecycle evidence;
- pairing and Relay require a live, identity-verified remote runtime;
- physical iPhone Safari and clean-machine installed journeys are not run;
- Developer ID signing, notarization/stapling/Gatekeeper, and protected
  publication/download digest parity are not run.

STOP SHA: `35bb1ea3dd650cadbb0fc1e9c75e80368cff1238`.
