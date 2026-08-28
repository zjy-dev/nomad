# Iteration 6 Product Brief

Status: PHASE 6 SHORTEST PRODUCT PATH / KEEP NO-GO UNTIL REAL USER GATES PASS

## Goal

The next user-visible product is only this:

- install Nomad on Apple Silicon macOS from a shipped bundle;
- start one locked real official Code Agent;
- run one real Provider-backed task;
- open the same Session from desktop Web and a real phone browser;
- safely `view`, `reply`, `deny`, and `Stop`;
- keep `allow_once=false`;
- revoke a stale or removed phone and fail closed;
- stop and uninstall without leaving owned processes or state behind.

Anything less remains foundation, freeze, or internal validation.

## Current state

- `G1` is materially ahead of the others: current disk says `C3` is `REPO CODE FROZEN / MECHANICAL E2 PASSED / PROVIDER E3 NOT RUN`.
- `doctor` still reports `repo-local-foundation-not-production-authority` and blocks on `B1_PROVIDER_CREDENTIAL` and `PRODUCTION_DEVICE_IDENTITY`.
- `launcher` can now enter `official-agent-local`, but that still leaves `PRODUCTION_DEVICE_IDENTITY` blocked.
- No current disk evidence upgrades same-machine mechanical proof into real Provider proof, real phone proof, clean-machine proof, or release-trust proof.

Overall verdict: `NO-GO`.

## Gate order

Run Phase 6 in this exact order:

1. `G1 local mechanical freeze`
2. `G2 same-machine real Provider E3`
3. `G3 real phone pairing/revocation/device identity`
4. `G4 clean-machine install`
5. `G5 production signing/notarization`

Rule:

- do not start claiming product readiness after `G1`;
- do not start clean-machine packaging work as the main story before `G2` and `G3` are real;
- do not treat `G5` paperwork as a substitute for missing real behavior.

## Gate cards

### G1. Local mechanical freeze

What it proves:

- repo-owned same-machine path is mechanically correct and fail-closed;
- installed or prebuilt local path starts the locked official Agent route;
- desktop Web plus mobile-width Web see the same Session;
- writable surface is exactly `reply`, `deny`, `Stop`;
- `allow_once=false` is enforced end to end.

Evidence owner:

- repo-owned only.

Real evidence required:

- one installed-path same-machine run through Gateway -> Host authority -> official Agent route;
- durable journal and replay behavior;
- duplicate/stale/offline/crash windows fail closed;
- privacy scan clean;
- owned cleanup clean.

Does not count:

- mock, fixture, synthetic pending state, fake Provider, screenshot-only proof,
  source audit alone.

Current verdict:

- `GO` for freeze scope only.
- not product `GO`.

NO-GO if:

- any path allows `allow_once`;
- any optimistic success appears without later authoritative Host/Agent fact;
- any raw ID or secret-bearing material leaks to browser/log/receipt/state.

### G2. Same-machine real Provider E3

What it proves:

- the locked official package actually performs one real Provider-backed task on the user's Mac;
- `reply`, `deny`, and `Stop` each succeed exactly once through the real Host authority path;
- same-machine Web control is no longer only a mechanical claim.

Evidence owner:

- repo-owned: harness, lineage, privacy scan, command truth.
- external-owned: allowlisted Provider access and real Provider service.

Real evidence required:

- one same-run install -> executable -> Session -> command -> cleanup chain;
- authoritative Provider lifecycle fact, not env-name presence;
- exactly one upstream invocation for positive `reply`, `deny`, `Stop`;
- later authoritative facts for continued turn, denied permission, and terminal stop outcome;
- negative paths remain fail-closed or `OutcomeUnknown`.

Does not count:

- credential presence alone;
- fake upstream or loopback-only server;
- plausible generated text;
- fixture-generated question/permission;
- any E2 mechanical run.

Current verdict:

- `NO-GO`.

NO-GO if:

- there is no authoritative Provider lifecycle proof;
- any positive command lacks later authoritative terminal evidence;
- any retry/reconnect duplicates an upstream side effect.

### G3. Real phone pairing, revocation, and device identity

What it proves:

- a physical phone browser, not desktop responsive mode, can safely attach and act;
- Host authority binds commands to a real paired device identity;
- revocation or epoch change immediately removes write authority.

Evidence owner:

- repo-owned: pairing flow, Host checks, revocation enforcement, browser UX.
- external-owned: trust anchors or device-trust publication if the selected design requires them.

Real evidence required:

- real physical phone browser attached to the same Session;
- device identity issuance bound to that phone;
- real phone executes positive `reply`, `deny`, or `Stop` through Host authority;
- revocation proof with zero extra upstream calls after revoke;
- reconnect proof with no optimistic success and no duplicate side effect.

Does not count:

- desktop mobile viewport;
- localhost-only same-machine session;
- browser cookie treated as device identity;
- QR demo without revocation;
- mock device IDs.

Current verdict:

- `NO-GO`.

NO-GO if:

- the phone cannot be uniquely identified and revoked;
- revocation only updates UI but does not block Host dispatch;
- remote proof is replaced by same-machine viewport proof.

### G4. Clean-machine install

What it proves:

- a fresh Apple Silicon macOS machine can install, run `doctor`, start, use, stop, and uninstall from the shipped bundle without repo assumptions.

Evidence owner:

- repo-owned: bundle, installer/uninstaller, doctor semantics, owned cleanup.
- external-owned: clean-machine environment and any org policy exceptions.

Real evidence required:

- clean-machine provenance;
- shipped-bundle install path;
- `doctor` output with actionable blockers and next step;
- `start` launches product from installed artifact, not source tree;
- one end-to-end accepted scenario using the shipped artifact;
- after uninstall, no owned child and no owned state remain.

Does not count:

- source-build launch;
- dev machine with preinstalled toolchain and warm caches;
- manual copying that bypasses product install flow.

Current verdict:

- `NO-GO`.

NO-GO if:

- the run depends on repo-local tools or source paths;
- `doctor` is not actionable for a real user;
- uninstall leaves owned processes or owned state behind.

### G5. Production signing and notarization

What it proves:

- the exact shipped artifact is trusted and distributable under the intended release chain.

Evidence owner:

- repo-owned: build inputs and published artifact digests.
- external-owned: Developer ID host, signing, notarization, protected publication, trust/KRL policy.

Real evidence required:

- exact artifact signing proof;
- notarization and stapling proof;
- publication/provenance proof for the shipped digest;
- operator verification that the downloaded artifact matches the reviewed artifact.

Does not count:

- adhoc signing;
- unsigned local build;
- local launch success;
- checklist screenshots.

Current verdict:

- `NO-GO`.

NO-GO if:

- the reviewed artifact is not the shipped artifact;
- notarization is missing;
- publication provenance is incomplete.

## Dispatchable work order

### Step 1: close G1 and stop expanding scope

Owner:

- repo team.

Deliverable:

- one short freeze note that says `G1 passed for local mechanical scope only`.

Exit rule:

- no open P0/P1 inside same-machine writable mechanics.

### Step 2: run G2 immediately

Owner:

- repo team plus external Provider access owner.

Deliverable:

- one same-run real Provider acceptance bundle on Apple Silicon macOS.

Exit rule:

- positive `reply`, `deny`, `Stop` each have exactly one upstream call and later authoritative outcome.

### Step 3: add the smallest G3 path

Owner:

- repo team plus trust/policy owner if needed.

Deliverable:

- one physical phone browser path with one pairing method and one revocation method.

Exit rule:

- revoke once, then prove zero further upstream writes from that phone identity.

### Step 4: repeat on a clean machine for G4

Owner:

- repo team plus machine/environment owner.

Deliverable:

- one clean-machine install-to-uninstall run using the shipped bundle.

Exit rule:

- no source-tree dependency and no owned residue after uninstall.

### Step 5: finish G5 on the exact artifact

Owner:

- release/trust owners.

Deliverable:

- signed, notarized, published artifact proof tied to the reviewed digest.

Exit rule:

- release reviewer can verify artifact identity and trust chain end to end.

## Product P0s

1. No accepted real Provider E3 run for official Agent + `reply` + `deny` + `Stop`.
2. No accepted real phone device identity and revocation proof.
3. No accepted clean-machine installed user journey on Apple Silicon.
4. No accepted production signing/notarization/publication proof.
5. Any path that exposes or forwards `allow_once`.
6. Any path that shows optimistic command success before authoritative outcome.
7. Any leak of Provider secret value, raw Agent IDs, or command content into Nomad-owned observable surfaces.

## Shortest product path

The shortest credible Phase 6 path is:

1. keep `G1` frozen and do not reopen command-surface scope;
2. get one real same-machine `G2` run green;
3. add one real-phone `G3` path with pairing plus revocation;
4. then prove the same path on a clean machine for `G4`;
5. only then close `G5` on the exact shipped artifact.

Why this order:

- it preserves the first-release surface at `view`/`reply`/`deny`/`Stop`;
- it separates repo-owned proof from external-owned proof;
- it avoids wasting time on mock demos, source-tree-only install stories, or release paperwork before the real product path exists.
