# Iteration 6 M3-E Product Gate

Status: `CURRENT-DISK PM REVIEW / ALL REAL-USER GATES NOT_RUN / OVERALL NO-GO`
Review date: 2026-08-27
Review target: dirty worktree on `feat/code-agent` at HEAD `4e4ac68765a8`

## 1. Decision

The next user-perceptible gate is one continuous **Mac install -> official Agent
start -> desktop pairing -> physical iPhone Safari attach -> same Session
view/reply/deny/Stop -> Mac revoke -> blocked old phone -> stop/uninstall** journey.

The current product verdict is **NO-GO**. No real-user acceptance run was
performed or found on current disk for desktop M3-E pairing, physical iPhone
Safari, Provider E3, or a clean Apple Silicon machine. All four remain
`NOT_RUN`; existing component tests and mechanical E2 evidence do not change
that verdict.

This review does not claim that the repository is broken. It says that useful
security and product components exist, but the shipped user route does not yet
connect them into the promised M3-E experience.

## 2. Scope and evidence rules

This is a read-only product review of:

- `orchestration/state/iteration6_m3e_product_journey.md`;
- `orchestration/state/iteration6_m3e_pairing_dispatch.md`;
- current browser UI and Gateway code under `mobile-reference/`;
- current launcher and bundle code under `tools/nomad_web/`;
- the current Product Host, device authority, Relay v2, and remote-browser
  implementation seams.

No runtime acceptance was executed as part of this review.
`testkit/process-loop/last-transcript.json` was neither read nor modified.

Verdict vocabulary is strict:

| Label | Meaning |
| --- | --- |
| `IMPLEMENTED` | Relevant code exists. It does not imply that the product route reaches it. |
| `CONNECTED` | The installed launcher/UI reaches the code through the intended production boundary. |
| `NOT_RUN` | The required real environment and evidence run have not been executed and accepted. |
| `NO-GO` | The product or next gate must not advance because a required capability or accepted proof is absent. |
| `PASS` | The exact acceptance row passed with the required evidence class. No lower evidence class can imply it. |

## 3. Current user journey audit

| User step | What exists on current disk | User-visible gap | Current verdict |
| --- | --- | --- | --- |
| Install Nomad | A verifiable repo-local prebuilt bundle can be materialized for `darwin-arm64`; it includes the locked `opencode-ai@1.18.16`, Product Host, Gateway, Web assets, and Relay binary. | This is explicitly `repo-local-prebuilt-not-production-authority`, not a signed/notarized installer or clean-machine proof. Materialization itself requires the source tree and build toolchain. | `IMPLEMENTED` foundation; clean-machine acceptance `NOT_RUN / NO-GO`. |
| Run `doctor` | It checks tools, files, and loopback ports, and reports `production_ready=false`. | It does not check pairing state, Relay v2 reachability, HTTPS/certificate readiness, browser key persistence, or real Provider lifecycle evidence. Its next step can say `nomad-web start` while real-user blockers remain. | Foundation check only; not a product Gate. |
| Start official Agent | `nomad-web start --provider ... --credential-stdin --workspace ...` can launch the locked Agent, Product Host, and Gateway from a prebuilt bundle. | The returned mode is `official-agent-local`, the Web URL is `http://127.0.0.1`, and state still blocks on `PRODUCTION_DEVICE_IDENTITY`. The official path does not start Relay v2, a remote Host endpoint, an HTTPS join controller, or TLS publication. | Local launch path `IMPLEMENTED`; M3-E start `NO-GO`. |
| See and control Session on desktop | The current React app renders `Nomad Local`, reads the local Product Host projection, and has capability-gated `reply`, `deny`, and `Stop` UI. Recorded C3 E2 evidence covers headless desktop Chrome and mobile-width Chrome against a non-Provider upstream. | There is no desktop `Pair phone`, QR/short-link, comparison code, countdown, paired-device card, or `Revoke phone` surface. E2 does not prove Provider E3 or M3-E. | Local C3 mechanical baseline only; desktop M3-E `NOT_RUN / NO-GO`. |
| Open pairing page | Browser modules exist for P-256 pairing, comparison-code computation, non-extractable keys, IndexedDB vault restore, and Relay v2 device transport. | `main.tsx` does not instantiate them. The Gateway has no `/api/pairing/*` routes, accepts only `foundation-readonly` and `official-agent-local`, binds loopback HTTP, and serves the same local app. There is no HTTPS join page reachable by a phone. | Modules `IMPLEMENTED`; product path not `CONNECTED`; `NO-GO`. |
| Confirm pairing | Product Host has FD11-authenticated local admin routes for current/challenge/confirm/revoke, backed by a durable one-active-device registry and shared gate. | These are local UDS administration routes, not the dispatched one-time `join_id#join_secret` ceremony. The current Host confirm contract verifies one signing proof; the M3-E browser client expects the newer comparison transcript, dual signing/agreement proofs, Host identity, Relay provisioning, and a signed provisioning bundle. No join controller bridges the two. | A2a local admin `IMPLEMENTED`; M3-E confirm not `CONNECTED`; `NO-GO`. |
| Provision remote transport | Relay v2 mailbox/data-plane and a dedicated loopback-only admin provision server exist with focused tests. Host/device crypto and mechanical endpoints also exist. | The official launcher does not start Relay v2 or its admin seam. Product Host does not own a live provisioning coordinator, emit a signed provisioning bundle, or run the remote endpoint in the official product path. The Host identity Keychain module is present but is not adopted by Product Host startup. | Component/mechanical foundation only; `NO-GO`. |
| View/reply/deny/Stop on phone | Local UI and Host-final authority support the intended action subset; remote envelope and device endpoint modules cover mechanics. | The physical-phone UI is not connected to pairing, vault restore, Relay v2, decrypted projections, or Host remote ingress. `host_command_authority` remains unreachable from a production-paired remote context. | Physical-phone action journey `NOT_RUN / NO-GO`. |
| Revoke phone on Mac | Device registry revoke and Relay mailbox revoke mechanics exist independently. | No desktop revoke control is wired; no live pairing binding connects Host epoch advance, remote command rejection, phone blocked state, and Relay cleanup in one product run. | Integrated revoke `NOT_RUN / NO-GO`. |
| Stop/uninstall | Launcher tracks owned processes, stops them, removes owned bundle/runtime state, and removes the current device-registry files with ownership checks. | No clean-machine install-to-uninstall run exists for the M3-E product path. Future adopted Keychain identity also requires an explicit reviewed uninstall/retain policy; its current helper is not wired into launcher uninstall. | Local mechanics exist; clean-machine lifecycle `NOT_RUN / NO-GO`. |

## 4. Pairing dispatch implementation delta

The M3-E dispatch is still a target contract, not an implemented product claim.

| Dispatch package | Current-disk assessment | Gate consequence |
| --- | --- | --- |
| M3-E1 Host Pairing Coordinator | Device registry, local challenge/confirm/revoke, and shared gate exist. Host P-256 identity support also exists as an isolated module. Missing: adopted Host identity, dispatched dual-proof transcript, Host-owned Relay provisioning, signed bundle, compensation on provisioning failure, and production remote command context. | `PARTIAL / NO-GO`. |
| M3-E2 Relay Provision Seam | Dedicated digest-only, loopback-only provision server exists with focused tests. | `IMPLEMENTED` component, but not launched or called by the official product route; cannot pass M3-E. |
| M3-E3 HTTPS Join Controller and Desktop Pair Entry | The named `pairing-session.mjs` does not exist; Gateway exposes no pairing APIs; launcher remains loopback HTTP; desktop Pair/Revoke UX is absent. | `NOT CONNECTED / NO-GO`. This is the first visible blocking package. |
| M3-E4 Browser Key Vault and Paired Restore | `pairing-client.ts`, `browser-vault.ts`, Relay client, and device endpoint exist with unit tests. | `IMPLEMENTED` modules, but unused by the shipped entrypoint/UI; Safari behavior is `NOT_RUN`. |
| M3-E5 Integrated Pair, Refresh, and Revoke Audit | The dispatched `test_m3e_pairing.py`, `test_m3e_lost_key.py`, and `test_m3e_revoke.py` files do not exist. Existing remote-v2 harness explicitly reports Provider and physical phone as `NOT_RUN`. | `NOT_RUN / NO-GO`. |

This delta also exposes a contract-join risk: the local A2a pairing protocol and
the later M3-E browser protocol are not the same wire ceremony. The next phase
must converge on one versioned contract rather than adapting the UI to two
incompatible definitions.

## 5. Next user-perceptible Gate

### Gate name

`M3-E First Remote User Journey`

### User promise

A user with one Apple Silicon Mac and one physical iPhone can install Nomad,
start one locked official Provider-backed Agent, pair Safari by comparing the
same six-digit code on both devices, control the same Session with only
`view`/`reply`/`deny`/`Stop`, revoke the phone on Mac, and observe that the old
phone can perform no further write.

### Entry conditions

Engineering may begin this gate only from the frozen scope below:

- single Host, single active browser device, single active epoch;
- `allow_once=false` everywhere;
- one versioned pairing transcript and one comparison-code formula;
- Host is the only pairing/provisioning authority;
- Relay stays ciphertext-only and never receives raw bearer values;
- remote and local principals share Host-final command authority but never
  capability, ingress identity, nonce space, or pairing epoch;
- no mock, fixture, responsive viewport, or mechanical harness can satisfy a
  real-environment row.

### Exit criteria

All of the following are conjunctive:

1. The installed launcher visibly exposes `Pair phone`, pairing progress, active
   phone identity, and `Revoke phone`; `doctor` reports actionable remote-join
   prerequisites without claiming readiness.
2. The phone enters through normal-certificate HTTPS; QR/link contains only a
   single-use 120-second join secret, which is cleared after start.
3. Mac and phone independently show the same six-digit comparison code; an
   expired, reused, mismatched, cancelled, or replaced challenge fails closed.
4. Safari persists non-extractable P-256 keys and the wrapped bearer only in the
   approved IndexedDB vault. Refresh restores safely; private mode, storage
   failure, or lost key blocks writes and requires re-pair.
5. The physical phone sees the same authoritative Session and can complete
   `reply`, `deny`, and `Stop` only when current Host capability permits them.
6. Each positive action produces exactly one upstream Agent invocation and a
   later authoritative outcome. Relay/Gateway acknowledgement is never shown as
   success; ambiguity is durable `OutcomeUnknown` with no automatic retry.
7. Mac revoke advances the Host epoch before best-effort Relay cleanup. Every
   later write from the old phone produces zero journal insertions and zero
   upstream Agent calls, including cached-page and reconnect attempts.
8. The exact journey passes in desktop Chrome, physical iPhone Safari, real
   Provider E3, and clean-machine contexts according to the matrix below.
9. Privacy evidence shows no long-lived bearer in URL/cookie/localStorage/
   sessionStorage, no Provider secret value, and no raw Agent IDs or command
   content in routine logs, screenshots, receipts, state, or exported evidence.
10. Stop and uninstall leave no owned process or owned runtime state. The
    reviewed policy explicitly decides whether uninstall deletes or retains the
    paired Host Keychain identity, and behavior matches that policy.

### Immediate NO-GO conditions

- Any pairing or remote write path bypasses Host-final authority or the shared
  pairing/revoke/command gate.
- The browser can provision Relay, or a Relay/Gateway receipt is presented as
  Agent success.
- A bearer appears in URL query/path, browser Web Storage, argv, routine logs,
  screenshot, or exported evidence.
- Safari falls back to cookie, tab, TLS session, or JS-readable ambient state as
  device identity after key loss.
- `allow_once` is visible, accepted, or forwarded.
- Revoke is UI-only, or an old epoch can cause a journal insertion or upstream
  call.
- Desktop responsive mode is substituted for a physical iPhone.
- A fake/fixture Provider, plausible text, or credential presence is substituted
  for authoritative Provider lifecycle evidence.
- A source-tree/dev-machine run is substituted for clean-machine installed
  evidence.

## 6. Acceptance matrix

Every row has an independent verdict. The overall Gate is `PASS` only when all
four rows pass on reviewed evidence; a pass in one row never upgrades another.

| Environment gate | Required setup and user actions | Required observable evidence | Current evidence | Current verdict |
| --- | --- | --- | --- | --- |
| Desktop Chrome | Use the exact candidate bundle on Apple Silicon macOS. Start the official route, open a fresh normal Chrome profile, choose `Pair phone`, inspect QR/short link, code and countdown, complete a browser pairing rehearsal, refresh, exercise visible controls against reviewed safe states, and revoke from Mac. | Desktop capture shows `Waiting to pair phone` -> pending code -> `Phone paired` -> revoked; exact HTTPS origin and secret-safe URL; same Session alias/digest; control inventory excludes allow; duplicate/stale/offline/lost-state cases fail closed; no console/network/privacy leak. | Two recorded C3 E2 headless-Chrome runs cover local same-machine controls only. Current UI has no Pair/Revoke surface and no M3-E route. No M3-E Chrome run was performed in this review. | `NOT_RUN / NO-GO` for M3-E. Prior E2 remains a mechanical baseline only. |
| Physical iPhone Safari | Record physical device model, iOS and Safari versions. In a normal Safari tab, scan the HTTPS QR, compare the six-digit code, confirm, view the same Session, perform at least one permitted remote action, refresh/reconnect, then attempt again after Mac revoke. Separately test private mode or unavailable durable storage. | Camera/device provenance; normal certificate validation; matching codes; non-extractable key + IndexedDB restore; same Session binding; authoritative action result; after revoke, blocking phone copy and zero Host journal/upstream calls; private/lost-key path requires re-pair. | No physical-phone evidence exists. Launcher is loopback HTTP and pairing UI/route is not connected. Existing remote-v2 harness labels physical phone `NOT_RUN`. | `NOT_RUN / NO-GO`. |
| Provider E3 | On Apple Silicon macOS, use the locked official `opencode-ai@1.18.16` with an allowlisted real Provider credential delivered only through the approved FD path. Complete two fresh runs as already required by C3: real task -> NeedsInput/reply -> continue; real permission/deny -> resolved; active turn/Stop -> authoritative cancellation, reversing desktop/mobile ownership between runs. | One install/executable/Session/command/cleanup lineage per run; authoritative Provider/Agent lifecycle facts; exactly one upstream call for each positive command; duplicate/reconnect and one controlled `OutcomeUnknown` case cause no redispatch; content-safe privacy scan and no credential persistence. | C3 E2 used an OpenCode-shaped loopback upstream. Current environment exposes no allowlisted Provider credential name. No accepted C3-E3 bundle exists. | `NOT_RUN / NO-GO`. |
| Clean machine | Use a fresh Apple Silicon macOS host with no repo checkout, Go, Cargo, npm, warm cache, or prior Nomad home. Install the exact candidate artifact, run `doctor`, start with the approved credential path, complete desktop plus physical-phone Provider-backed journey, revoke, stop, uninstall, and verify residue. | Machine provenance; downloaded artifact digest; installer and `doctor` capture; no source path/toolchain dependency; full same-run Provider + phone lineage; owned-process inventory before/after; no owned runtime residue; explicit Keychain identity outcome; no deletion of unowned data. | Repo-local prebuilt bundle and lifecycle tests exist, but no fresh-host installed M3-E run, production signing/notarization, or publication provenance exists. | `NOT_RUN / NO-GO`. |

## 7. Required Gate order and stop rules

1. **Join the product route.** Converge the pairing contract; connect Product
   Host identity and provisioning, Relay v2, HTTPS join controller, remote Host
   ingress, browser vault, and visible desktop/phone UI. This may reach
   `CONNECTED`, not product `PASS`.
2. **Desktop Chrome rehearsal.** Prove the exact visible ceremony and negative
   states without calling it phone or Provider evidence. Any P0/P1 or secret leak
   stops the sequence.
3. **Provider E3.** Run the existing two-run C3-E3 requirement through the
   official installed local path. If authoritative lifecycle evidence cannot be
   obtained, record `BLOCKED` and keep `NO-GO`; do not inject synthetic states.
4. **Physical iPhone Safari.** Run pairing, refresh/lost-key, remote action, and
   revoke against the same real Host authority. A desktop viewport cannot stand
   in for this step.
5. **Clean-machine repeat.** Repeat the accepted combined journey using the
   exact candidate artifact on a fresh host. This is where installability,
   actionable diagnostics, lifecycle cleanup, and Keychain policy become real.
6. **Release trust remains separate.** Signing, notarization, publication
   provenance, independent security approval, support, and rollback remain
   required before a First Real User release even after M3-E passes.

Do not continue to the next environment after a safety failure. Product or
usability failures may be fixed and the affected row rerun, but no partially
completed chain may be relabelled `PASS`.

## 8. Evidence packet and reviewer decision

One top-level index must bind the exact artifact digest to all four rows. Per-run
records should contain only privacy-safe aliases and commitments and include:

- platform/browser/device versions and run timestamps;
- artifact, executable, workspace, Session, and command lineage commitments;
- visible state captures for pairing, action lifecycle, revoke, and recovery;
- network route and field allowlist results;
- command journal and upstream invocation counts without command content;
- negative-case results and zero-call assertions;
- privacy scan counts;
- stop/uninstall process and owned-state cleanup results.

The reviewer records each row as exactly one of `NOT_RUN`, `BLOCKED`, `FAIL`, or
`PASS`, then records one overall decision:

```text
M3-E = PASS only if Desktop Chrome = PASS
                    and Physical iPhone Safari = PASS
                    and Provider E3 = PASS
                    and Clean machine = PASS
                    and no open P0/P1 exists.
Otherwise M3-E = NO-GO.
```

## 9. Current sign-off

| Decision | Verdict | Reason |
| --- | --- | --- |
| Continue implementation toward the narrowly frozen M3-E journey | `GO` | The product target and single-device scope are clear, and reusable component foundations exist. |
| Claim M3-E connected | `NO-GO` | Official launcher, Gateway, UI, Host provisioning/remote ingress, and browser pairing modules are not joined into one user route. |
| Claim Provider-backed local product acceptance | `NO-GO` | Provider E3 is `NOT_RUN`; only mechanical E2 evidence exists. |
| Claim real-phone acceptance | `NO-GO` | Physical iPhone Safari is `NOT_RUN` and no reachable HTTPS pairing route exists. |
| Claim clean-machine/installable product acceptance | `NO-GO` | Clean-machine M3-E is `NOT_RUN`; current bundle is repo-local and not production trust evidence. |
| Claim First Real User readiness | **`NO-GO`** | M3-E and release-trust gates are not passed. |
