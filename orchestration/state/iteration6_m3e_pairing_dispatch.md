# Iteration 6 M3-E Pairing Dispatch

Status: DISPATCHED / MINIMAL PRODUCTION PAIRING-PROVISIONING

## Preconditions

- `M3 mechanical PASS` is the current floor: Relay v2 data plane, P-256 remote crypto, Host `DeviceAuthority`, and local admin routes are already frozen mechanical inputs.
- First ship remains `single Host + single active browser device + single active epoch`.
- Supported remote actions remain `view`, `reply`, `deny`, and `Stop`; `allow_once=false` stays absent and rejected.
- On first M3-E startup the Host generates two distinct P-256 signing and
  agreement private keys with the OS CSPRNG and persists them as the one Host
  remote identity in macOS Keychain. Later pairing, signed grants, bearer
  wrapping, and browser restore bind that same identity. Mechanical vector keys
  are forbidden in this path. Explicit identity rotation revokes every paired
  device and requires re-pair. Secure Enclave is a later hardening option, not
  required for this slice.
- Relay v2 still has no public provisioning route. That remains correct.

## Scope

This dispatch defines only the smallest production pairing/provisioning path for M3-E:

- one-time join URL with no long-lived bearer
- browser submission of two P-256 public keys plus possession proofs
- MITM-visible comparison code
- Host-owned Relay provisioning
- browser credential storage and refresh/lost-key policy
- revoke linearization under the shared gate

Out of scope:

- multi-device
- native app or APNs
- recovery code, export, or key escrow
- transcript-based proof
- Provider E3 or physical-phone product evidence
- redesign of Relay v2 data-plane routes

## Architecture

Actors:

- Mac Product Host: pairing authority, Relay provisioning owner, shared-gate owner
- HTTPS join controller: remote browser entry only; never command authority
- Phone browser: generates non-extractable P-256 keys and speaks Relay v2 as the device role after pairing
- Relay v2 provision seam: admin-only mailbox constructor
- Relay v2 data plane: existing host/device listeners only

## Decision 1: One-Time Join Carries No Long-Lived Bearer

- Desktop `Pair phone` creates `JoinSession {join_id, join_secret_digest, expires_at, status}` in Host-owned private state.
- QR / short link format is `https://pair.nomad.example/j/{join_id}#{join_secret}`.
- `join_secret` is 32 random bytes base64url in the fragment, so it is not sent in the initial HTTP request, referrer, or server logs.
- TTL is 120 seconds and single use.
- Browser JS posts the fragment secret exactly once to `/api/pairing/join/start`, then clears the fragment with `history.replaceState`.
- After successful `start`, the join controller sets only a short-lived `__Host-nomad-join` cookie:
  - `Secure`
  - `HttpOnly`
  - `SameSite=Strict`
  - `Max-Age<=120`
  - join-scoped path
- This cookie exists only to survive pre-confirm refresh. It is never the device bearer and is cleared on confirm, cancel, revoke, or expiry.

## Decision 2: Browser Submits Two P-256 Public Keys And Proves Both Private Keys

- The browser generates two non-extractable WebCrypto P-256 keypairs:
  - signing: ECDSA P-256
  - agreement: ECDH P-256
- The browser exports only the two public keys in uncompressed SEC1 65-byte form and posts them on `start`.
- The join controller forwards only these public keys to Product Host. Browser never talks to Relay during pairing.
- Host reuses the current `DeviceAuthority` shape: pending rows may store raw public keys until the challenge is terminal; active rows retain only digests.

Join start response from Host, via the join controller:

- `challenge_id`
- `challenge_bytes_b64`
- `prospective_epoch`
- `host_signing_public_key_sec1`
- `host_agreement_public_key_sec1`
- `issued_at`
- `expires_at`

Dual-key proof on confirm:

- `transcript_hash = SHA-256("nomad.m3e.pairing.v1\n" || join_id || challenge_id || challenge_digest || prospective_epoch || H(host_sign_pub) || H(host_agree_pub) || H(device_sign_pub) || H(device_agree_pub))`
- `signing_proof = ECDSA-P256-P1363(device_sign_priv, SHA-256("nomad.m3e.signing-proof.v1\n" || transcript_hash))`
- `agreement_secret = HKDF(ECDH(device_agree_priv, host_agree_pub), "nomad.m3e.agreement-proof.v1")`
- `agreement_proof = HMAC-SHA256(agreement_secret, transcript_hash)`

Confirm request from browser:

- `challenge_id`
- `expected_epoch`
- `device_signing_signature_p1363`
- `device_agreement_mac`
- no raw bearer
- no caller-selected `device_id`

Host verifies both proofs before any activation or provisioning.

## Decision 3: MITM Resistance Uses A Locally Computed Comparison Code

- The comparison code is not a server-authored string.
- Host desktop computes it locally from the same `transcript_hash`.
- Phone browser computes it locally from the challenge plus both keypairs' digests.
- Code formula:
  - `comparison_code = decimal6(SHA-256("nomad.m3e.compare.v1\n" || transcript_hash))`
- The user must confirm only if both screens match.
- Any MITM that swaps the Host keys, device keys, challenge, or epoch changes the code.

## Decision 4: Relay Provisioning Owner Is Product Host, Not The Browser

- Browser pairing and browser session restore never call Relay provisioning directly.
- Product Host owns:
  - `mailbox_id` generation
  - raw `host_bearer` and `device_bearer` generation
  - Relay provisioning request
  - Host-side persistence of the host bearer and mailbox binding
- Relay receives only digests and commitments, never raw bearer values.

Required seam:

- Keep the current Relay v2 data-plane listeners free of public provisioning.
- Add a separate admin-only provision seam, for example `POST /v2/provision/mailboxes`, on a provision-only server or internal RPC.
- Auth for that seam is Host-owned only: provisioning credential or mTLS, never browser, never QR, never join cookie.

Provision request fields:

- `mailbox_id`
- `epoch`
- `host_token_digest`
- `device_token_digest`
- `host_identity_commitment`
- `device_key_commitment`

Provision response:

- `201 created` or `200 idempotent_same_mailbox`
- no raw bearer echo
- no device content

## Decision 5: Host Delivers Mailbox Metadata And Device Bearer As A Signed Provisioning Bundle

Only after Host has both:

1. accepted the dual-key confirm under the shared gate
2. completed Relay provisioning

does it emit a `ProvisioningBundle`.

Bundle fields:

- `schema`
- `device_alias`
- `pairing_epoch`
- `mailbox_id`
- `relay_base_url` or equivalent role metadata
- `host_signing_public_key_sec1`
- `host_agreement_public_key_sec1`
- `wrapped_device_bearer`
- `wrap_nonce`
- `issued_at`

Bundle integrity:

- Host signs canonical JSON with the Host signing key already shown to the user via the comparison-code transcript.
- Browser must reject if the bundle Host key digests differ from the ones used to compute the comparison code.

Bearer wrapping:

- `vault_key = HKDF(ECDH(host_agree_priv, device_agree_pub), "nomad.m3e.browser-vault.v1" || mailbox_id || pairing_epoch)`
- `wrapped_device_bearer = AES-256-GCM(vault_key, device_bearer)`

This means:

- the device bearer is never in the URL
- the device bearer is never written to localStorage or sessionStorage
- Relay never learns the raw bearer
- the browser can verify both origin integrity and Host intent before unwrapping

## Decision 6: Browser Credential Storage Is IndexedDB Plus Non-Extractable CryptoKeys

Persistent browser state after a successful pair is limited to IndexedDB:

- non-extractable `CryptoKey` handles for the device signing and agreement keys
- the signed provisioning bundle
- `wrapped_device_bearer`
- mailbox metadata
- opaque read/write cursors and ACK state

Hard rules:

- no localStorage
- no sessionStorage
- no bearer in cookies
- no bearer in URL path, query, or fragment after join start
- no fallback to cookie/session identity for paired commands

Pairing completion must fail closed if:

- IndexedDB is unavailable
- non-extractable key persistence is unavailable
- a persist-and-restore self-check for the browser vault fails

## Decision 7: Refresh And Lost-Key Behavior

Before confirm:

- If the join cookie is still valid, refresh may reopen the pending pairing page.
- If the page lost the temporary browser keypair, it must restart `start`, which invalidates the previous pending challenge and produces a new code.
- If the join session expired, the browser must return to the Mac and start again.

After confirm:

- Refresh restores the paired session only from IndexedDB plus persisted CryptoKeys.
- Browser reloads the signed bundle, verifies it again, unwraps the device bearer, and resumes from persisted cursors.
- No duplicate command is created during restore.

Lost-key, private-mode, or storage failure:

- If the paired browser cannot restore the CryptoKeys or cannot unwrap the bearer, it is no longer the active device.
- The product must fail closed, clear volatile state, and require re-pair.
- Host must never silently treat an HTTP cookie, tab, or TLS session as device identity.

## Decision 8: Revoke Is Linearly Ordered By The Shared Gate

The same shared gate serializes:

- pairing confirm plus provisioning commit
- revoke
- remote command acceptance into Host authority

Required order for revoke:

1. acquire the shared gate
2. persist the new revoked epoch in `DeviceAuthority`
3. invalidate current command eligibility for the old `device_alias + epoch`
4. best-effort Relay mailbox delete or cleanup
5. release the gate

Rules:

- the security boundary is the Host epoch check, not Relay deletion
- remote command acceptance must re-read current active device facts under the gate before journal claim
- stale epoch, revoked device, or browser lost-key state must produce zero upstream Agent calls

Provisioning failure after confirm:

- If Relay provisioning fails after the new epoch was activated, Host must immediately compensating-revoke that just-activated device before releasing the gate.
- The product returns to `unpaired`; no device bearer is returned.

## Minimal State Machines

Join session:

- `new -> started -> confirmed -> consumed`
- `new|started -> expired|cancelled`

Device authority:

- `unpaired -> active(epoch n) -> revoked(epoch n+1)`
- `active(epoch n) -> replaced(epoch n+1)`

Browser vault:

- `empty -> pending_join -> paired_restorable`
- `pending_join -> empty`
- `paired_restorable -> lost_key -> empty`

## Atomic Tasks With Mutually Exclusive File Ownership

### M3-E1 Host Pairing Coordinator

Owned files:

- `connector/src/device_authority.rs`
- `connector/src/product_stock_projector.rs`
- `connector/src/product_command_protocol.rs`
- `connector/src/relay_provisioning.rs` [new]
- `connector/tests/product_host_command_process_tests.rs` [new or focused extension]

Must deliver:

- dual-key proof verification
- comparison-code transcript fields
- signed provisioning bundle creation
- compensating revoke on provision failure
- shared-gate serialization for confirm, revoke, and remote command accept

### M3-E2 Relay Provision Seam

Owned files:

- `relay/v2_mailbox.go`
- `relay/v2_protocol.go`
- `relay/v2_provision_server.go` [new]
- `relay/v2_provision_server_test.go` [new]
- `relay/v2_mailbox_test.go`

Must deliver:

- admin-only provision API or internal RPC
- digest-only provisioning
- idempotent same-mailbox replay
- no provisioning route on the public host/device data-plane listeners

### M3-E3 HTTPS Join Controller And Desktop Pair Entry

Owned files:

- `mobile-reference/pilot-gateway/server.mjs`
- `mobile-reference/pilot-gateway/pairing-session.mjs` [new]
- `mobile-reference/pilot-gateway/product-host-client.mjs`
- `mobile-reference/pilot-gateway/product-host-client.test.mjs`
- `tools/nomad_web/launcher.py`
- `tools/nomad_web/state.py`

Must deliver:

- `join_id#join_secret` entrypoint
- fragment clearing
- short-lived HttpOnly join cookie
- no-store and referrer-safe join flow
- desktop-visible comparison code and expiry UI
- remote controller calling Product Host local admin routes only, never Relay provisioning from the browser

### M3-E4 Browser Key Vault And Paired Restore

Owned files:

- `mobile-reference/src/remote/pairing-client.ts` [new]
- `mobile-reference/src/remote/browser-vault.ts` [new]
- `mobile-reference/src/remote/relay-client.ts`
- `mobile-reference/src/ui/App.tsx`
- `mobile-reference/src/ui/App.test.tsx`
- `mobile-reference/src/ui/Approval.tsx`

Must deliver:

- non-extractable P-256 key generation
- IndexedDB persistence
- wrapped bearer restore
- refresh-safe resume
- fail-closed lost-key handling
- zero localStorage or sessionStorage bearer usage

### M3-E5 Integrated Pair, Refresh, And Revoke Audit

Owned files:

- `testkit/remote-v2/test_m3e_pairing.py` [new]
- `testkit/remote-v2/test_m3e_lost_key.py` [new]
- `testkit/remote-v2/test_m3e_revoke.py` [new]
- `testkit/remote-v2/README.md` [new]

Must prove:

- one-time join URL contains no long-lived bearer
- confirm requires both P-256 proofs and matching comparison code
- browser restore works only with persisted vault state
- lost key forces re-pair
- revoke blocks all later writes from the old epoch with zero upstream call

## Exit Criteria For This Dispatch

- The only browser-held long-lived credential is the device bearer, and it exists only wrapped inside IndexedDB-backed vault state.
- Browser never provisions Relay.
- Relay provisioning is Host-owned and digest-only.
- Comparison code covers both Host and device P-256 keys plus the one-time challenge.
- Confirm, revoke, and remote command accept are serialized by the same shared gate.
- After revoke, old capability, old nonce space, and old browser state can produce no new upstream call.
