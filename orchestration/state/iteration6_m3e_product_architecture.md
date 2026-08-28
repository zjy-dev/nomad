# Iteration 6 M3-E Executable Product Architecture

Status: ARCHITECTURE FROZEN / HOST COORDINATOR IN PROGRESS / PRODUCT GATE NO-GO

## 1. Decision and current disk truth

M3-E will use the fragment plus short-lived HttpOnly join-cookie design. The
first launch remains one Mac Host, one active phone browser, and one active
pairing epoch. This document narrows the earlier pairing dispatch and product
journey into implementation boundaries that can be assigned without inventing
wire contracts in individual packages.

The repository already contains useful halves of this design:

- `connector/src/host_device_identity.rs` generates separate P-256 signing and
  agreement keys and persists them in macOS Keychain.
- `connector/src/device_authority.rs` provides a durable, single-active-device
  epoch registry and pending P-256 key material, but its old one-signature
  ceremony is not the public M3-E ceremony.
- `relay/v2_provision_server.go` provides a digest-only, authenticated,
  loopback-only provision listener. It is a valid local seam, not yet a
  production remote admin endpoint.
- `mobile-reference/src/remote/pairing-client.ts` implements the M3-E transcript
  and dual proof; `browser-vault.ts` implements an IndexedDB vault containing
  non-extractable keys and a wrapped bearer.
- `DeviceCommandGate` currently exists only as a private type inside
  `product_stock_projector.rs`. It must become a single injected Host-wide gate.
- `tools/nomad_web/launcher.py` still starts the Alpha v1 topology. It does not
  start Relay v2 role listeners, the provision seam, a join-only Gateway, or a
  reviewed HTTPS ingress.

Therefore this architecture does not declare M3-E complete. It freezes the
missing composition and the evidence required to change the gate.

## 2. Non-negotiable invariants

1. Browser-visible URLs contain only `join_id#join_secret`. They never contain a
   mailbox bearer, Host bearer, device bearer, private key, or Provider secret.
2. Browser JavaScript removes the fragment synchronously before key generation
   or network I/O, then sends the secret once in the start body.
3. The short-lived cookie is a join capability only. It is not device identity,
   command identity, a Relay credential, or a fallback after vault loss.
4. Both P-256 private keys must be proven, and the user must approve the same
   locally computed six-digit code on phone and Mac.
5. Browser code never provisions Relay. Product Host generates both bearer
   values and is the only caller of the Relay admin seam. Relay receives only
   their SHA-256 digests and the composite public-key commitments.
6. Pair confirm/provision, vault commit/abort, revoke, and remote command
   admission acquire the same `Arc<DeviceCommandGate>`. There is one instance
   per Product Host process.
7. A provisioned browser is not command-eligible until IndexedDB persist and
   restore succeeds and the browser sends the vault-commit proof.
8. Host epoch/current-binding checks are the revocation boundary. Relay delete
   is cleanup and must never be required to make an old device harmless.
9. `allow_once` is absent and rejected. Only `view`, `reply`, `deny`, and `Stop`
   remain in M3-E.
10. No M3-E test or launcher reads or regenerates
    `testkit/process-loop/last-transcript.json`.

## 3. Trust boundaries and topology

### 3.1 Process topology

```text
Mac bundle
  official Agent child
       ^ loopback HTTP, Agent credential remains child/Host only
       |
  nomad-product-host
    - Product Host UDS server (0600 socket)
    - HostDeviceIdentity / DeviceAuthority / PairingCoordinator
    - one DeviceCommandGate
    - Host Relay v2 mailbox pump (outbound HTTPS)
       ^                         |
       | signed UDS admin        +----> Relay host-role HTTPS data plane
       |
  desktop-gateway (127.0.0.1, desktop/admin routes only)
       ^
       | same local browser, CSRF + exact Origin
  desktop UI

  join-gateway (127.0.0.1, join/remote routes only)
       ^
       | reviewed outbound HTTPS ingress/tunnel, no direct Mac bind
       |
physical phone browser ---- HTTPS ---- public ingress
       |                                  |
       +---- same-origin /v2 proxy -------+----> Relay device-role HTTPS data plane

Relay service
  host-role data listener ----+
  device-role data listener --+-- one durable mailbox store
  admin provision listener ---+   (not routed to the browser/public data plane)
```

The Product Host owns the coordinator and mailbox pump in one process. Splitting
pairing and command admission into different Host processes would destroy the
shared-gate guarantee unless a new linearizable authority service were added;
that split is forbidden for M3-E.

The desktop and join Gateway listeners have different route tables. The public
ingress/tunnel may target only the join listener. Desktop create/approve/revoke
routes must not be reachable through the public listener. Host continues to
have no public inbound port.

### 3.2 Relay listener model

Relay fixes a role to a listener rather than accepting a role from a request.
The product topology therefore needs three distinct endpoints over one mailbox
store:

- host-role data plane;
- device-role data plane;
- admin-only provision plane.

For local integration they may be loopback listeners with the existing explicit
test flags. For a physical phone or product deployment, host/device endpoints
must be HTTPS with normal certificate validation. The current provision server
accepts only loopback cleartext, so it is evidence for the seam but not a
production admin deployment. Production must place it behind an authenticated
internal control plane or add mTLS without exposing the route through either
data listener.

## 4. Pairing state and authority

### 4.1 Durable states

```text
created
  -> started_awaiting_desktop_approval
  -> desktop_approved
  -> provisioned_pending_vault
  -> active
  -> consumed

created|started|desktop_approved -> cancelled|expired
provisioned_pending_vault        -> compensated|expired_compensated
active                            -> revoked
```

Only `active` produces a `CurrentRemoteBinding` accepted by the remote command
path. `DeviceAuthority::confirm_pairing_preverified` currently creates an
active registry row before Relay provisioning. The coordinator must mask that
row until vault commit. If provisioning, bundle construction, delivery commit,
or vault commit fails, it invokes `DeviceAuthority::revoke` before releasing the
gate. On startup it must scan `provisioned_pending_vault` records and compensate
them before accepting remote commands.

The durable Host pairing/binding store contains no raw join secret. It stores:

- `join_id`, `SHA-256(join_secret)`, Host-generated opaque cookie-capability
  digest, timestamps, state;
- challenge ID and digest, prospective epoch, four key commitments, temporary
  device public keys until terminal;
- desktop approval and vault-commit state;
- mailbox ID, active epoch, Relay URL, and an encrypted/Keychain-backed Host
  bearer binding;
- cleanup outcome and retry-needed marker.

Terminal rows clear the cookie digest, challenge bytes, temporary public keys,
wrapped device bearer, and volatile bearer material. A new create cancels any
unconsumed join; it does not revoke an already active device until a replacement
successfully enters the pairing commit path under the gate.

### 4.2 Shared gate contract

`DeviceCommandGate` is a crate-private type owned by
`connector/src/pairing_coordinator.rs` and constructed exactly once during
`ProductHost::start`. The same `Arc` is injected into:

- `PairingCoordinator`;
- `ProductDeviceRegistryService` revoke path;
- `ProductCommandService` local command execution where it already serializes;
- the remote mailbox command consumer before active-device validation and
  journal claim.

Gate-protected operations are deliberately coarse and synchronous for the
single-device launch. No network request may hold the gate indefinitely: Relay
provision/delete clients use bounded connect/read/write timeouts. The exact
linearized order is:

Pair confirm:

1. acquire gate;
2. re-read join, approval, challenge, expected epoch, and current device facts;
3. verify both browser proofs;
4. activate candidate in `DeviceAuthority`;
5. provision Relay;
6. create and sign bundle;
7. persist `provisioned_pending_vault`;
8. release gate and return bundle.

Vault commit:

1. acquire gate;
2. validate cookie, pending binding, deadline, epoch, and device vault proof;
3. persist active Host binding before returning success;
4. clear join capability and temporary keys;
5. release gate.

Remote command admission:

1. acquire the same gate;
2. require an `active` Host binding and re-read `DeviceAuthority::current_active`;
3. require exact device alias, epoch, and four commitments;
4. validate application command and current capability;
5. perform the existing durable journal claim before upstream execution;
6. release only at the existing authority-defined safe point.

Revoke/compensation:

1. acquire gate;
2. advance and persist the revoked epoch in `DeviceAuthority`;
3. remove command eligibility and persist binding state;
4. best-effort Relay `DELETE /v2/mailboxes/{mailbox_id}` with Host bearer;
5. persist cleanup result/retry marker, clear join cookie state, release gate.

The epoch transition and removal of command eligibility precede Relay cleanup.
Consequently an ambiguous or failed DELETE cannot reopen access.

## 5. Exact cryptographic contract

All byte strings below are concatenated exactly as shown. Integers in the M3-E
transcript are lowercase decimal ASCII. Hash commitments are lowercase hex when
included in the transcript or JSON. SEC1 keys are uncompressed 65-byte P-256
points and are base64url without padding on M3-E JSON. Signatures are 64-byte
P1363 and base64url without padding.

```text
transcript_hash = SHA-256(
  "nomad.m3e.pairing.v1\n" ||
  join_id || "\n" ||
  challenge_id || "\n" ||
  hex(SHA-256(challenge_bytes)) || "\n" ||
  decimal(prospective_epoch) || "\n" ||
  hex(SHA-256(host_signing_public_sec1)) || "\n" ||
  hex(SHA-256(host_agreement_public_sec1)) || "\n" ||
  hex(SHA-256(device_signing_public_sec1)) || "\n" ||
  hex(SHA-256(device_agreement_public_sec1))
)

signing_digest = SHA-256("nomad.m3e.signing-proof.v1\n" || transcript_hash)
signing_proof  = ECDSA-P256-P1363(device_signing_private, signing_digest)
agreement_ikm  = ECDH-P256(device_agreement_private, host_agreement_public)
agreement_key  = HKDF-SHA256(agreement_ikm, salt=empty,
                             info="nomad.m3e.agreement-proof.v1", L=32)
agreement_mac  = HMAC-SHA256(agreement_key, transcript_hash)
comparison     = zero_pad_6(first_24_bits(
                   SHA-256("nomad.m3e.compare.v1\n" || transcript_hash)
                 ) mod 1_000_000)
```

Relay composite commitments are frozen as:

```text
host_identity_commitment = SHA-256(
  "nomad.m3e.host-identity-commitment.v1\n" ||
  host_signing_commitment_bytes || host_agreement_commitment_bytes
)
device_key_commitment = SHA-256(
  "nomad.m3e.device-key-commitment.v1\n" ||
  device_signing_commitment_bytes || device_agreement_commitment_bytes
)
```

The browser vault key and vault commit are:

```text
vault_key = HKDF-SHA256(
  ECDH-P256(host_agreement_private, device_agreement_public),
  salt=empty,
  info="nomad.m3e.browser-vault.v1\n" || mailbox_id || "\n" || decimal(epoch),
  L=32
)
wrapped_device_bearer = AES-256-GCM(vault_key, random_nonce_12,
                                    plaintext=UTF8(device_bearer), aad=empty)
vault_commit_digest = SHA-256(
  "nomad.m3e.vault-commit.v1\n" ||
  SHA-256(canonical_json(signed_provisioning_bundle))
)
```

The browser signs `vault_commit_digest` with the restored device signing key.
This does not let Host prove IndexedDB internals; it makes the client ordering
testable and proves the post-restore code still possesses the paired key.

## 6. Exact DTOs and routes

Every JSON object denies unknown and duplicate keys and has a bounded canonical
encoding. Times are RFC3339 UTC. Secrets and proofs are base64url without
padding. Error bodies expose a stable safe code only.

### 6.1 Desktop-only Gateway to Host admin

These routes use the existing signed Product Host UDS transport. Gateway
desktop routes additionally require exact loopback Origin and CSRF. They are
absent on the join-only listener.

`POST /internal/pairing/joins` takes:

```json
{"schema":"nomad.m3e.pairing.create.v1"}
```

and returns only to the desktop controller:

```json
{
  "schema": "nomad.m3e.pairing.created.v1",
  "join_id": "join-<32 lowercase hex>",
  "join_secret": "<32 random bytes, base64url-no-pad>",
  "expires_at": "2026-08-27T14:00:00Z"
}
```

`POST /internal/pairing/joins/approve` takes:

```json
{
  "schema": "nomad.m3e.pairing.desktop-approve.v1",
  "join_id": "join-...",
  "challenge_id": "challenge-...",
  "expected_epoch": 1,
  "comparison_code": "042913"
}
```

Host recomputes the code; it never trusts the supplied display value. Cancel,
status, current device, and revoke are respectively:

```text
POST /internal/pairing/joins/cancel
POST /internal/pairing/joins/status
GET  /internal/devices/current
POST /internal/devices/revoke
```

Cancel is frozen as the exact body below; it is a desktop-only operation and
does not accept a join secret or cookie capability:

```json
{
  "schema": "nomad.m3e.pairing.cancel.v1",
  "join_id": "join-..."
}
```

Revoke does not introduce another M3-E DTO. It reuses the existing Product Host
request exactly, with no `schema` field:

```json
{
  "device_alias": "device-...",
  "expected_epoch": 1
}
```

Its response retains the existing `revoked|already_revoked`, prior epoch, and
revoked epoch semantics. E2 must extend the existing route rather than create a
second revoke authority.

Desktop pending-state polling is frozen as an authenticated Product Host POST,
not a browser join-cookie route. Request:

```json
{
  "schema": "nomad.m3e.pairing.status.v1",
  "join_id": "join-..."
}
```

Response has every key present; unavailable phase-dependent values are `null`:

```json
{
  "schema": "nomad.m3e.pairing.status-response.v1",
  "join_id": "join-...",
  "state": "created|started_awaiting_desktop_approval|desktop_approved|provisioned_pending_vault|active|cancelled|expired|compensated|revoked",
  "challenge_id": "challenge-... or null",
  "expected_epoch": 1,
  "comparison_code": "042913 or null",
  "expires_at": "2026-08-27T14:00:00Z"
}
```

In the actual JSON, `challenge_id`, `expected_epoch`, and `comparison_code`
are JSON `null` before they exist, not the explanatory strings shown above.
`comparison_code` becomes non-null only after phone start supplies both device
keys. This DTO contains no join secret, cookie capability, bearer, public key,
key commitment, mailbox ID, or raw device/Agent identifier. Unknown `join_id`
returns a safe not-found error rather than a synthetic state.

The desktop Gateway exposes only:

```text
POST /api/desktop/pairing/status
```

with the same exact request and response DTOs. It is available only on the
desktop listener, with the existing exact loopback Origin and CSRF checks, and
is absent from the public join listener. Gateway neither caches nor enriches
the status response.

All Gateway-to-Host pairing calls use per-route exact internal JSON bodies. The
existing Product Host transport authenticator hashes the complete body into its
HMAC, so `join_cookie_capability` is authenticated together with the route and
the remaining fields. It is never sent in a header, URL, query, or log. The four
join-listener wrappers are frozen as follows:

```json
{
  "schema": "nomad.m3e.internal.pairing-start.v1",
  "join_id": "join-...",
  "join_secret": "<base64url-no-pad>",
  "device_signing_public_key_sec1": "<65 bytes, base64url-no-pad>",
  "device_agreement_public_key_sec1": "<65 bytes, base64url-no-pad>"
}
```

```json
{
  "schema": "nomad.m3e.internal.pairing-confirm.v1",
  "join_cookie_capability": "<base64url-no-pad>",
  "challenge_id": "challenge-...",
  "expected_epoch": 1,
  "device_signing_signature_p1363": "<64 bytes, base64url-no-pad>",
  "device_agreement_mac": "<32 bytes, base64url-no-pad>"
}
```

```json
{
  "schema": "nomad.m3e.internal.pairing-complete.v1",
  "join_cookie_capability": "<base64url-no-pad>",
  "challenge_id": "challenge-...",
  "expected_epoch": 1,
  "device_vault_signature_p1363": "<64 bytes, base64url-no-pad>"
}
```

```json
{
  "schema": "nomad.m3e.internal.pairing-abort.v1",
  "join_cookie_capability": "<base64url-no-pad>",
  "challenge_id": "challenge-...",
  "expected_epoch": 1
}
```

These internal schemas are distinct from public browser DTOs (for example,
public abort is `nomad.m3e.pairing.abort.v1`). Product Host rejects an internal
schema on the wrong route, unknown/duplicate keys, an absent capability, and a
transport HMAC computed for a different path or body. Gateway reads the
HttpOnly cookie and inserts its value into only the matching internal body.
This preserves HttpOnly while preventing capability smuggling or cross-route
substitution.

### 6.2 Phone HTTPS join surface

The QR is exactly:

```text
https://<opaque-host>.pair.nomad.example/j/{join_id}#{join_secret}
```

`GET /j/{join_id}` serves only the static shell with `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, restrictive CSP, and no embedded join secret.

`POST /api/pairing/join/start` request:

```json
{
  "join_id": "join-...",
  "join_secret": "<base64url-no-pad>",
  "device_signing_public_key_sec1": "<65 bytes>",
  "device_agreement_public_key_sec1": "<65 bytes>"
}
```

Host, not Gateway, generates the cookie capability. On a valid start it creates
32 random bytes, stores only `SHA-256(raw_capability)` against the started join,
and returns the raw base64url capability exactly once to the trusted Gateway
over the authenticated Product Host UDS response. The internal response is:

```json
{
  "schema": "nomad.m3e.pairing.host-start.v1",
  "join_cookie_capability": "<32 random bytes, base64url-no-pad>",
  "join_cookie_max_age_seconds": 120,
  "browser_start": {
    "schema": "nomad.m3e.pairing.start-response.v1",
    "challenge_id": "challenge-...",
    "challenge_bytes_b64": "<32 bytes>",
    "prospective_epoch": 1,
    "host_signing_public_key_sec1": "<65 bytes>",
    "host_agreement_public_key_sec1": "<65 bytes>",
    "issued_at": "2026-08-27T13:58:00Z",
    "expires_at": "2026-08-27T14:00:00Z"
  }
}
```

Gateway must neither generate nor persist this value. It moves the raw value
directly into the response cookie, zeroes its temporary buffer, and returns only
`browser_start` as JSON. It must never forward `join_cookie_capability` to
browser JavaScript. A retry after this response is lost rotates the capability,
invalidates the prior digest, and returns one new raw capability.

Successful start sets:

```text
Set-Cookie: __Host-nomad-join=<opaque random capability>; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=<remaining <= 120>
Cache-Control: no-store
Referrer-Policy: no-referrer
```

`__Host-` cookies require `Path=/` and no `Domain`; therefore the older idea of
a join-scoped cookie path is invalid. Logical scoping is provided by the random
capability digest stored against exactly one join. Gateway also requires exact
HTTPS Origin and rejects cross-site Fetch Metadata.

Start response is exactly the existing browser contract:

```json
{
  "schema": "nomad.m3e.pairing.start-response.v1",
  "challenge_id": "challenge-...",
  "challenge_bytes_b64": "<32 bytes>",
  "prospective_epoch": 1,
  "host_signing_public_key_sec1": "<65 bytes>",
  "host_agreement_public_key_sec1": "<65 bytes>",
  "issued_at": "2026-08-27T13:58:00Z",
  "expires_at": "2026-08-27T14:00:00Z"
}
```

`POST /api/pairing/join/confirm` requires the join cookie and exactly:

```json
{
  "challenge_id": "challenge-...",
  "expected_epoch": 1,
  "device_signing_signature_p1363": "<64 bytes>",
  "device_agreement_mac": "<32 bytes>"
}
```

If desktop approval has not been recorded, it returns
`409 PAIRING_DESKTOP_APPROVAL_REQUIRED` without consuming the challenge. On
success it returns:

```json
{
  "schema": "nomad.m3e.pairing.confirm-response.v1",
  "signed_provisioning_bundle": {
    "schema": "nomad.m3e.signed-provisioning-bundle.v1",
    "bundle": {
      "schema": "nomad.m3e.provisioning-bundle.v1",
      "device_alias": "device-...",
      "pairing_epoch": 1,
      "mailbox_id": "mbx-<64 lowercase hex>",
      "relay_base_url": "https://relay.example/v2",
      "host_signing_public_key_sec1": "<65 bytes>",
      "host_agreement_public_key_sec1": "<65 bytes>",
      "wrapped_device_bearer": "<ciphertext plus GCM tag>",
      "wrap_nonce": "<12 bytes>",
      "issued_at": "2026-08-27T13:58:20Z"
    },
    "provisioning_signature_p1363": "<64 bytes>"
  }
}
```

The signature covers SHA-256 of the exact canonical `bundle` JSON. After
persist-and-restore, `POST /api/pairing/join/complete` requires the cookie and:

```json
{
  "schema": "nomad.m3e.pairing.vault-commit.v1",
  "challenge_id": "challenge-...",
  "expected_epoch": 1,
  "device_vault_signature_p1363": "<64 bytes>"
}
```

Successful completion returns
`{"schema":"nomad.m3e.pairing.complete-response.v1","device_alias":"device-...","pairing_epoch":1}`
and clears the cookie with `Max-Age=0`.

`POST /api/pairing/join/abort` requires the cookie and this exact body:

```json
{
  "schema": "nomad.m3e.pairing.abort.v1",
  "challenge_id": "challenge-...",
  "expected_epoch": 1
}
```

It compensates a provisioned candidate, is idempotent, and clears the cookie. A
browser vault failure must call abort best-effort and display a re-pair-only
state. Host timeout/startup recovery is authoritative if abort is lost. Gateway
passes the raw cookie capability only as the authenticated UDS request secret;
Host hashes it and compares the digest in constant time before cancel, confirm,
complete, or abort state transitions.

### 6.3 Relay admin seam

The already-landed local path is exactly:

```text
POST /v2/admin/mailboxes/provision
Authorization: Bearer <Host-only admin credential>
Content-Type: application/json
```

Canonical request:

```json
{
  "schema": "nomad.relay.mailbox-provision.v1",
  "mailbox_id": "mbx-<64 lowercase hex>",
  "epoch": 1,
  "host_token_digest": "<64 lowercase hex>",
  "device_token_digest": "<64 lowercase hex>",
  "host_identity_commitment": "<64 lowercase hex>",
  "device_key_commitment": "<64 lowercase hex>"
}
```

Response is `201` for create or `200` for exact idempotent replay:

```json
{
  "schema": "nomad.relay.mailbox-provision-result.v1",
  "mailbox_id": "mbx-...",
  "epoch": 1,
  "created": true,
  "idempotent": false
}
```

Any different replay for the mailbox is a conflict. The response never echoes
a bearer. Admin credentials enter Relay and Host only through inherited private
FDs or a reviewed mTLS identity, never argv, environment, Gateway, browser, or
run-state JSON. Revoke cleanup uses the existing Host-role authenticated
`DELETE /v2/mailboxes/{mailbox_id}`. The admin seam remains provision-only.

## 7. Failure matrix and compensation

| Failure point | Durable Host result before gate release | Browser result | Relay cleanup | Command eligibility |
| --- | --- | --- | --- | --- |
| invalid/expired join | unchanged or terminal expired | safe 4xx | none | unchanged |
| either key proof fails | challenge stays bounded or is invalidated by policy | `PAIRING_PROOF_INVALID` | none | unchanged |
| desktop approval missing | started, retryable until expiry | 409 | none | unchanged |
| Relay provision definite failure | candidate revoked, join terminal | 503/re-pair | delete if mailbox may exist | none |
| Relay provision ambiguous | candidate revoked, cleanup retry recorded | 503/re-pair | DELETE with generated Host bearer | none |
| bundle wrap/sign/persist fails | candidate revoked, cleanup retry recorded | 503/re-pair | best effort | none |
| response lost after provision | pending-vault until deadline, then compensated | retry same cookie returns same bundle or re-pair after deadline | on timeout | none |
| IndexedDB persist/restore fails | abort or timeout compensates | lost-key/re-pair | best effort | none |
| vault commit response lost | exact retry is idempotent | restores active session | none | active once |
| explicit revoke | epoch advanced first | revoked/re-pair | best effort | none immediately |
| Relay delete fails | cleanup retry remains | revoked/re-pair | asynchronous retry | none |

Coordinator errors and `Debug` output must not contain secrets, public keys,
proofs, bearer digests, mailbox content, or the comparison transcript.

## 8. Launcher contract

The launcher must extend its current readiness-gated child model, not bolt M3-E
onto the Alpha v1 flags. Startup order is:

1. validate installed bundle, private run directories, configured HTTPS ingress,
   and three distinct Relay endpoints;
2. create anonymous pipes for Product Host transport key and Relay admin
   credential; never persist either in run-state;
3. start official Agent and wait for authoritative readiness;
4. start `nomad-product-host`, bootstrap the UDS and load/create Host identity;
5. start or connect Relay host/device/admin endpoints and require health plus an
   authenticated admin preflight;
6. start desktop Gateway with only desktop route table;
7. start join Gateway with only join/remote route table;
8. start the reviewed outbound HTTPS ingress/tunnel to the join Gateway;
9. only then enable `Pair phone`.

In local integration mode the launcher may start two Relay processes sharing a
file-backed v2 database because the current executable fixes one role per
process; only one process receives the admin FD. A later Relay main refactor may
host two role listeners in one process, but it may not collapse their role
configuration or expose admin routes on them. In production mode Relay and TLS
ingress are external services; the Mac launcher connects outbound and must not
claim readiness from loopback test flags.

Run-state may persist endpoint origins, child PIDs/identities, mailbox alias,
device alias, epoch, and readiness states. It must not persist raw bearers, join
secret/cookie capability, admin credential, command key, private keys, Provider
credential, or signed bundle. Stop is reverse dependency order and performs
Host-local revoke/cleanup before terminating the process that owns the gate.

## 9. Atomic implementation packages

### E1 - Host pairing coordinator (current dispatched worker)

Owner: `connector/src/pairing_coordinator.rs` and inline focused tests only.

Deliver the exact transcript, dual proof, comparison code, shared gate type,
trait-based provision/delete seam, random mailbox/bearers, digest-only request,
signed/wrapped bundle, pending-vault state, compensation, and revoke. A memory
store is acceptable for focused logic tests only; E2 owns durable integration.

Gate: focused coordinator tests and connector clippy pass after module
registration.

### E2 - Product Host integration and durable binding

Owner:

- `connector/src/lib.rs` module registration;
- `connector/src/product_stock_projector.rs`;
- `connector/src/product_command_protocol.rs`;
- new `connector/src/relay_provisioning.rs`;
- focused Product Host tests.

Replace the private gate definition with the coordinator gate, construct one
`Arc`, add exact local admin routes/serializers, implement bounded Relay admin
HTTP and host-role DELETE clients, and add a private durable pairing/binding
store plus startup compensation. Remote command admission must consume only an
active coordinator binding under that same gate.

Gate: concurrent confirm/revoke/remote-command tests prove one linear order;
provision ambiguity and Host restart both compensate; stale epoch causes zero
Agent calls.

### E3 - Gateway split and join-cookie controller

Owner:

- `mobile-reference/pilot-gateway/server.mjs`;
- new `mobile-reference/pilot-gateway/pairing-session.mjs`;
- `mobile-reference/pilot-gateway/product-host-client.mjs`;
- focused Node tests.

Add separate desktop and join route tables, exact UDS methods, fragment shell
headers, strict Origin/Fetch Metadata, and `__Host-nomad-join` installation/
clearing with no-store responses. Host generates and rotates the capability;
Gateway stores no pairing truth, generates no cookie capability, and never calls
Relay admin. It forwards the raw cookie value only to Host and never exposes it
to JavaScript or logs. The desktop-only `/api/desktop/pairing/status` proxy must
preserve the exact secret-free Host status DTO and must be absent from the join
listener.

Gate: route-isolation tests prove public ingress cannot create/approve/revoke;
public ingress also cannot read desktop pairing status; cookie attributes are
exact; the desktop status DTO is exact and logs/errors contain no join secret or
bearer.

### E4 - Browser ceremony and paired UI

Owner:

- `mobile-reference/src/remote/pairing-client.ts`;
- `mobile-reference/src/remote/browser-vault.ts`;
- browser Relay client and device endpoint;
- pairing and device UI plus focused tests.

Wire the already-landed crypto/vault modules into the UI, add desktop-approval
wait state, restore-then-vault-commit, abort on persistence failure, and exact
lost-key/revoked copy. Keep bearer only in the non-extractable-key protected
vault path and volatile request scope; never local/session storage or UI state.

Gate: Safari-compatible IndexedDB integration test, refresh resume, private-mode
failure, tampered bundle/proof rejection, no duplicate command after restore.

### E5 - Relay product seam

Owner:

- `relay/v2_provision_server.go`;
- `relay/cmd/relay/main.go`;
- focused Go tests and deployment configuration.

Retain digest-only canonical provision and role-separated data listeners. Add
the production authentication/deployment seam (mTLS or internal control plane),
authenticated health/preflight, bounded audit metadata, and cleanup retry
observability. Do not add browser provisioning or a public admin route.

Gate: exact idempotent provision, conflicting replay rejection, credential
redaction, and proof that neither data listener serves the admin path.

### E6 - Launcher topology

Owner: `tools/nomad_web/config.py`, `launcher.py`, `processes.py`, state schema,
bundle manifest, and launcher tests.

Add distinct endpoints/ports, FD wiring, Host identity readiness, two Gateway
listeners, external HTTPS ingress readiness, reverse-order cleanup, and secret-
free run state. Preserve existing local C3 behavior as a separate mode.

Gate: installed-bundle clean-home process test proves topology/readiness and
checks argv, environment, logs, and state for secret absence.

### E7 - Cross-process and physical-phone evidence

Owner: new files under `testkit/remote-v2/` and a task report. Existing process
transcripts are out of scope.

First run a real-process pair/approve/provision/vault-commit/view/command/revoke
slice, including injected provision ambiguity and lost-key compensation. Then
run the same installed path with a physical Safari phone over reviewed HTTPS.
Provider E3 is reported separately; fixture Agent evidence cannot satisfy it.

Gate marker: `M3E_REAL_PHONE_PASS`, with explicit fields for `provider_e3`,
`physical_phone`, `https_certificate`, `installed_bundle`, and `security_review`.

## 10. Acceptance gates

| Gate | Required proof | Current status |
| --- | --- | --- |
| A - Contract | Exact DTO/transcript cross-language vectors | PARTIAL: browser side landed, Host coordinator pending |
| B - Linear authority | One gate for confirm, vault commit/abort, revoke, remote command | NO-GO: current gate is private in projector |
| C - Provision safety | Digest-only create, ambiguity compensation, restart recovery | PARTIAL: Relay create landed; Host owner/recovery missing |
| D - Browser vault | Non-extractable IndexedDB restore before active commit | PARTIAL: vault landed; UI/commit integration missing |
| E - Gateway boundary | Fragment clearing, exact cookie, route split, no public admin | NO-GO |
| F - Launcher | Installed topology, FD secrets, HTTPS ingress readiness | NO-GO |
| G - Product evidence | Physical Safari full journey and revoke zero-dispatch | NOT RUN |
| H - Provider readiness | Real Provider E3 on same product path | NOT RUN, independent of M3-E mechanics |

M3-E becomes engineering-complete only after A through F pass with the real
cross-process harness. It becomes the requested first real phone-browser journey
only after G passes. It does not establish overall product readiness while H or
the required security review remains open.

## 11. Merge order

1. E1 coordinator and tests.
2. E2 module/gate/durable Host integration.
3. E3 Gateway seam and E5 Relay product seam in parallel after DTO freeze.
4. E4 browser UI after E3 response/cookie contract is executable.
5. E6 launcher after Host/Gateway/Relay CLIs are stable.
6. E7 real-process fault matrix, then physical-phone evidence.

The merge owner must re-run Rust focused tests and clippy, Go tests, Gateway
tests, browser tests, installed bundle checks, and a secret scan. Component-only
green tests must remain labelled mechanical until the full product path passes.
