# Iteration 6 M3-E Product Journey

Status: FIRST REAL PHONE-BROWSER JOURNEY / PRODUCT PLAN ONLY / NO CODE CHANGE

## Scope

M3-E is the first real phone-browser product slice after `M3 mechanical PASS/FREEZE`.

It covers only this user journey:

1. User installs Nomad on Apple Silicon macOS.
2. User starts the locked official Agent on Mac.
3. Desktop shows one-time pairing information.
4. User opens an HTTPS page on a physical phone browser.
5. User compares and confirms pairing on both ends.
6. Phone can `view`, `reply`, `deny`, and `Stop`.
7. Mac can revoke that phone.

This document does not approve:

- product code changes;
- transcript mutation;
- multi-device launch;
- native mobile app;
- `allow_once`;
- generic remote shell;
- treating mock/fixture/synthetic runs as real-phone proof.

## Product decision

First launch stays `single Host + single paired browser device + single active epoch`.

Rationale:

- current `DeviceAuthority` is already shaped around one active device;
- first real-phone proof should reduce ambiguity, not introduce device fan-out;
- revoke semantics stay simple: revoke the one active phone, advance epoch, and
  block all later writes from the old phone.

## P0 user journey

### 1. Mac install and startup

User action:

- install the shipped Nomad bundle on Apple Silicon macOS;
- run `nomad doctor`;
- run `nomad start`.

P0 UX:

- `doctor` must remain explicit that it is checking local foundation plus
  remote-join prerequisites, not claiming product readiness on its own;
- if the supported official Agent or required Provider prerequisite is missing,
  the user sees one blocking reason and one next step per blocker;
- `start` must end with a clear desktop-visible state: `Waiting to pair phone`
  or `Phone paired`.

P0 API/behavior:

- installed bundle only, no source-tree dependency;
- startup creates or reuses the durable device registry path under Nomad home;
- no browser device is auto-paired during startup;
- local desktop control path remains separate from remote paired-device
  authority.

### 2. Desktop shows one-time pairing information

User action:

- user chooses `Pair phone` on Mac.

P0 UX:

- desktop shows:
  - a one-time HTTPS URL or QR entrypoint;
  - a six-digit comparison code;
  - a two-minute countdown;
  - short copy: `Scan or open on your phone. Confirm only if both codes match.`
- desktop also shows current state: `No phone paired yet`.

P0 API/behavior:

- pairing challenge is single-use and expires in 120 seconds;
- Host issues one pending challenge at a time and invalidates any previous
  unconsumed challenge;
- pairing challenge result binds `mailbox_id`, `epoch`, device key commitments,
  and device alias;
- no long-lived bearer appears in the QR, URL, browser address bar, argv,
  logs, receipts, or evidence.

### 3. Phone opens HTTPS page

User action:

- user scans the QR or types the short HTTPS URL in Safari/mobile browser.

P0 UX:

- phone first lands on a lightweight `Confirm this Mac` screen;
- the page shows:
  - Mac label;
  - six-digit comparison code;
  - short expiry text: `This code expires in about 2 minutes`;
  - buttons: `Confirm` and `Cancel`.

P0 API/behavior:

- remote product entry is HTTPS only with normal certificate validation;
- browser receives only the minimum join material needed for this single
  ceremony;
- bearer credentials stay server-side or inside protected handshake state and
  never enter URL query/fragment, localStorage, or sessionStorage;
- if browser refreshes before confirmation, the page may re-fetch the pending
  challenge view, but only while the challenge is still valid.

### 4. User compares and confirms

User action:

- user verifies both codes match;
- user confirms on phone;
- desktop updates to paired.

P0 UX:

- phone copy: `Only confirm if this code matches your Mac`;
- desktop copy after success: `Phone paired. You can revoke it anytime from this Mac.`;
- both sides show the same device alias after pairing.

P0 API/behavior:

- confirmation succeeds only if:
  - challenge is unexpired;
  - challenge is unconsumed;
  - proof matches the challenge transcript;
  - expected epoch is current;
  - Host still accepts the pairing under the shared `DeviceCommandGate`.
- pairing completion revokes any previous active device and advances epoch;
- after success, old epoch traffic is rejected even if the old browser still has
  cached page state.

### 5. Phone can view / reply / deny / Stop

User action:

- phone sees the same Session as desktop;
- user can `view`, `reply`, `deny`, `Stop`.

P0 UX:

- `view` is always the safe baseline;
- `reply`, `deny`, `Stop` appear only when live capability and current state
  permit them;
- `allow_once` is absent everywhere;
- command states remain truthful:
  - `Sent to Mac`
  - `Accepted by Mac`
  - `Waiting for Agent result`
  - `Result unknown`
  - terminal result only after authoritative Host/Agent fact

P0 API/behavior:

- phone commands are bound to the active paired device alias and epoch;
- remote command acceptance uses the same Host-final command authority as local
  C3;
- relay/mailbox acknowledgement is never command success;
- stale epoch, revoked device, stale capability, duplicate request, or transport
  ambiguity make zero new Agent calls or return durable `OutcomeUnknown`.

### 6. Mac revoke

User action:

- user clicks `Revoke phone` on Mac.

P0 UX:

- desktop shows the active paired phone and a single revoke action;
- revoke confirmation copy:
  `This removes this phone's access immediately. You can pair again later.`
- after revoke, desktop returns to `No phone paired`;
- phone shows a blocking state:
  `This phone was removed from this Mac. Pair again to continue.`

P0 API/behavior:

- revoke requires exact `device_alias + expected_epoch`;
- revoke advances epoch and blocks every later write from the old phone;
- already-revoked retries are idempotent and must not recreate access;
- best-effort relay mailbox deletion is cleanup only, not the security boundary.

## P0 UX surfaces

The following UX is P0 for first launch:

1. Mac `Waiting to pair phone` state.
2. Desktop pairing card with QR/short link, six-digit code, countdown, cancel.
3. Phone `Confirm this Mac` page.
4. Paired phone session page with truthful `view`/`reply`/`deny`/`Stop`.
5. Desktop paired-device card with revoke action.
6. User-facing blocked/error states for expired challenge, mismatch, revoked
   device, stale page, lost device key, offline Host, and `OutcomeUnknown`.

The following is not P0:

- device rename;
- multiple phones;
- remembered phone list beyond the one active device;
- phone-side settings;
- push notifications;
- native app deep-linking;
- background sync polish.

## P0 API surfaces

The following API surfaces are P0:

1. Local-only admin routes for:
   - current device;
   - pairing challenge;
   - pairing confirm;
   - revoke.
2. Remote HTTPS browser join entrypoint.
3. Remote encrypted projection flow.
4. Remote command flow for `reply`, `deny`, `Stop`.
5. Remote revoke enforcement and stale-epoch rejection.

The following API rules are mandatory:

- no bearer in URL path, query, or fragment;
- no bearer in localStorage or sessionStorage;
- no raw Agent IDs in browser-visible payloads;
- browser persistence may keep opaque durable transport state, but not long-term
  bearer secrets or extractable private keys;
- local desktop path and remote paired-device path must never share nonce space,
  capability, or ingress identity.

## Bearer and storage policy

Hard rules:

- QR and short link may contain only one-time join material, never a long-lived
  bearer credential.
- Browser must not persist bearer in:
  - URL
  - localStorage
  - sessionStorage
  - exported logs
  - screenshots generated by the product
- Browser must not rely on copying a bearer into JS-readable global state after
  initial join.

Accepted direction for first launch:

- keep remote bearer server-side where possible;
- if browser needs join-scoped secret material during the ceremony, keep it in
  ephemeral memory or protected handshake state only;
- use durable browser storage only for opaque transport recovery state and only
  after pairing succeeds.

## Safari refresh and lost-key handling

This is product-critical and must be fail-closed.

### Case A: refresh before pairing confirm

Behavior:

- phone reopens the pending confirm page if the challenge is still valid;
- if the challenge expired, phone lands on `Pairing expired`.

User copy:

- `Pairing expired. Return to your Mac and start pairing again.`

### Case B: refresh after pairing, key still available

Behavior:

- phone restores the paired session using durable device transport state;
- page resumes from persisted cursor and pending ACK/outbound recovery if needed;
- no duplicate command is created.

User copy:

- `Reconnected to your Mac.`

### Case C: Safari refresh or browser process loss causes key/state loss

Behavior:

- product must fail closed;
- phone is treated as no longer able to prove the active device identity;
- page becomes read-blocked for writes and prompts re-pair;
- Host does not silently downgrade to cookie/session identity.

User copy:

- `This browser lost its secure device keys. Pair again from your Mac to continue.`

### Case D: private mode / storage unavailable

Behavior:

- product should block pairing completion if durable device state cannot be
  established for the supported journey;
- do not allow a seemingly paired browser that cannot survive normal refresh.

User copy:

- `This browser cannot keep the secure data Nomad needs. Open in a normal Safari tab and try again.`

## Single-device launch rule

First launch supports exactly one active phone browser device per Mac.

Implications:

- new pair replaces the old active device;
- revoke returns the Mac to unpaired state;
- no second-device coexistence UX is required;
- no device chooser is needed on phone;
- desktop wording should say `your paired phone`, not `one of your devices`.

## Failure and recovery copy

The first launch must ship with explicit copy for these states.

### Pairing code mismatch

Phone:

- `Codes do not match. Do not continue. Start pairing again from your Mac.`

Desktop:

- `Pairing was cancelled because the codes did not match.`

### Pairing expired

Phone:

- `Pairing expired. Return to your Mac and start again.`

Desktop:

- `Pairing code expired. Generate a new one when you're ready.`

### Pairing already used

Phone:

- `This pairing link has already been used. Start a new one from your Mac.`

### Host offline / unreachable

Phone:

- `Your Mac is offline or unreachable. You can view the last safe state, but new actions are blocked.`

### Device revoked

Phone:

- `This phone was removed from your Mac. Pair again to continue.`

Desktop:

- `Phone access removed.`

### Stale page / stale capability

Phone:

- `This page is out of date. Refresh to get the latest state from your Mac.`

### Result unknown

Phone:

- `Your Mac may have started this action, but Nomad could not confirm the result. It will not retry automatically. Check the latest state on your Mac.`

### Browser lost key/state

Phone:

- `This browser lost its secure device keys. Pair again from your Mac to continue.`

## Acceptance for M3-E product journey

M3-E product journey is accepted only when all of the following are true in one
real product path:

1. User installs and starts from the shipped Mac bundle.
2. Desktop shows one-time pairing info with six-digit comparison code and
   two-minute expiry.
3. Physical phone browser opens over HTTPS.
4. User confirms matching code on both ends.
5. Paired phone can `view`, `reply`, `deny`, and `Stop` through Host authority.
6. `allow_once` is absent and rejected.
7. Mac revoke blocks every later write from the old phone.
8. Browser refresh either reconnects safely or fails closed and requires re-pair.
9. No bearer appears in URL or localStorage/sessionStorage.

M3-E remains `NO-GO` if any of the following are true:

- proof uses desktop responsive mode instead of a physical phone browser;
- proof uses mock, fixture, or synthetic transport as if it were real product evidence;
- revoke only changes UI and does not block Host dispatch;
- browser falls back to cookie/session identity after key loss;
- bearer appears in URL or browser storage;
- pairing success depends on source-tree-only setup rather than the shipped path.

## Dispatch order

1. Freeze the M3-E journey copy and states in this document.
2. Implement local admin pairing/revoke UX on Mac.
3. Implement phone HTTPS confirm page and paired-session shell.
4. Implement fail-closed browser persistence and Safari-loss handling.
5. Run one real physical-phone journey end to end.
6. Only after that, discuss polish, multiple devices, or push.
