# Iteration 5 C3 Safe Local Commands Acceptance Matrix

Status: REPO CODE FROZEN / MECHANICAL E2 PASSED / PROVIDER E3 NOT RUN
Gate: desktop Web and mobile-width Web control the same real, locked, official Agent run

## Product claim and boundary

C3 proves the first local writable product slice: on one Apple Silicon Mac, a
desktop browser and a mobile-width browser observe the same Host-owned official
Agent Session and can use exactly four first-release actions: `view`, `reply`,
`deny`, and `Stop`. `view` is the read path; the other three are Host-final
commands. `allow_once=false` is invariant in capability negotiation, UI,
Gateway, Host authority, adapter, tests, and evidence.

C3 is not remote-phone acceptance. The mobile-width browser may run on the same
Mac at a recorded phone viewport. It proves responsive Web behavior, not
pairing, revocation, Internet reachability, a real phone, production identity,
signed distribution, or Controlled Pilot readiness.

One C3 acceptance run means one verified install, one exact official executable,
one Host-owned Agent process, one raw Agent Session held inside the Host, one
browser-safe Session alias, one disposable workspace, and one command journal.
Neither browser may discover or switch to an ambient process or Session.

## Non-negotiable success semantics

- Every command is re-authorized against current raw Agent facts at the Host. A
  browser snapshot, cached permission, Gateway receipt, or client clock is never
  authority.
- A transport or Gateway acknowledgement means only "received".
  `HostAccepted` means only that the Host durably accepted the exact command.
  `Executing` means the side effect may have started. None of these is success.
- `reply` is successful only after authoritative Agent facts bind the reply to
  the pending input and show the Session continuing from that input.
- `deny` is successful only after authoritative Agent facts show that the exact
  pending permission was rejected/resolved.
- `Stop` is successful only after authoritative Agent facts show the target turn
  cancelled or the adapter's explicitly reviewed equivalent terminal stop fact.
  An abort HTTP success is not enough.
- `OutcomeUnknown` is a terminal user-visible uncertainty, not success or
  failure. It is never automatically retried, never relabelled after an ordinary
  refresh, and blocks new commands in the authority scope until authenticated,
  single-use reconciliation proves an authoritative terminal outcome.
- A terminal result is durably committed before a success response. Any timeout,
  disconnect, crash window, persistence failure, or ambiguous upstream response
  stays pending/unknown or fails closed. The product must never show optimistic
  false success.

## C3 acceptance matrix

All rows are conjunctive. A must-fail observation makes the run `FAIL`. A missing
Provider, product capability, or external prerequisite makes it `BLOCKED`, never
a partial pass. Component, fixture, mock, schema, and screenshot-only evidence
cannot satisfy a row that requires C3-E3.

| ID | Must pass | Required evidence | Must fail or remain No-Go |
| --- | --- | --- | --- |
| C3-01 run ownership | The installed bundle starts the manifest-locked official executable, and both browser layouts bind to the one Host-owned process and Session for the entire run. | Install, executable, process, workspace, Session-alias, and lineage attestations in one run manifest. | Source build substituted for the installed bundle; fake/renamed Agent; mock/demo/fixture mode; ambient process; Session discovered by listing; process, workspace, or Session switch. |
| C3-02 real Provider work | The official Agent performs a real Provider request and receives a real response in the same Session. The proof comes from an authoritative Agent or Provider lifecycle fact, not from credential presence or plausible generated text. | Sanitized Provider-backed attestation, time window, executable binding, and Session lineage binding. | No-provider launch, fake Provider, replay, generated fixture, credential-in-child-env alone, or a snapshot whose evidence class says it is not Provider lifecycle evidence. If authoritative proof is unavailable, result is `BLOCKED`. |
| C3-03 exact capability surface | The product advertises `view=true`, and only `reply`, `deny`, and `stop` as writable actions. `allow_once=false`. The default installed route is same-origin and uses the Host authority path. | Capability response, browser control inventory from both layouts, route inventory, and a constructed `allow_once` rejection with zero Agent calls. | Hidden legacy write route, arbitrary command, interrupt-and-send, allow control, `allow_once` accepted/forwarded, Relay token in browser, or direct browser-to-Agent access. |
| C3-04 shared view | Desktop and mobile-width browsers remain open concurrently and show the same Session alias, projection sequence/digest, turn state, pending-action alias, command state, and authoritative change summary. | Timestamped browser/network captures and viewport metadata correlated to the same run ledger. | Different Sessions, fixture-injected DOM, raw identifier in either browser, stale-last-good labelled Live, divergent command result, or client-invented state. |
| C3-05 reply | A real Provider-backed turn reaches `NeedsInput`; one browser submits one non-empty reply. The other view sees the same command lifecycle and authoritative continued-turn fact. Exactly one upstream reply occurs. | Browser gesture, content-free command ledger, Host journal transition, upstream-call count, and later bound Agent fact. | Empty/expired/stale target accepted; UI declares sent/success from HTTP 2xx, Gateway receipt, `HostAccepted`, or `Executing`; duplicate upstream prompt; reply queued while offline. |
| C3-06 deny | A real pending permission exposes browser-safe facts and expiry. One browser denies it; both views show an authoritative resolved/rejected fact. Exactly one upstream deny occurs. | Permission-alias/action-binding commitment, expiry test, Host journal, upstream-call count, and later bound Agent fact. | Raw permission ID exposed; expired, changed, resolved, cross-Session, or action-hash-mismatched permission reaches the Agent; denial is shown successful from acceptance alone; any allow control appears. |
| C3-07 Stop | During an active cancellable turn, one browser confirms `Stop`. Both views distinguish command progress from Agent turn state and eventually show authoritative cancellation. Exactly one upstream Stop occurs. | Confirmation capture, Host journal, upstream-call count, and later cancellation/approved-equivalent terminal fact. | Offline Stop queue; optimistic `Stopping`/`Cancelled` Agent state created only by the client; repeated abort; task completion race misreported as Stop success; Stop kills an unowned process. |
| C3-08 freshness and availability | Capability absent, stale projection, offline Host, reconnecting state, wrong sequence/digest, wrong target, and expired permission all disable or remove writes and are rejected again at the Host before dispatch. `view` may retain labelled last-good data. | Browser state captures plus zero-upstream-call negative receipts for every case. | CSS-only disable, forged request reaches Agent, offline command queue, stale content labelled Live, ordinary refresh clears a safety gate, or capability absence silently falls back to a mock route. |
| C3-09 duplicate and replay | Rapid duplicate taps, HTTP retry, two-tab race, and terminal replay produce at most one Host acceptance and one upstream side effect. Same bound request returns the same durable terminal result with replay marked; same request alias with changed binding is rejected. | Concurrency trace, stable public command alias, durable receipt digest, journal reopen trace, and upstream-call counters. | Each tap allocates an independently executable command, duplicate terminal side effect, changed payload accepted under an old alias, or a replay changes terminal meaning. |
| C3-10 crash, restart, reconnect | Browser, Gateway, and Host restart/reconnect preserve last-good view and durable command truth. An interrupted `Prepared`/`Executing` command becomes `OutcomeUnknown` unless authoritative reconciliation proves its terminal outcome; it is never redispatched. | Fault injection on the real path, journal reopen, browser convergence, zero redispatch count, and reconciliation proof when used. | Restart replays the side effect, blank state becomes Live, a new run consumes the old journal, refresh turns unknown into success, or a reconciliation proof can be replayed/cross-bound. |
| C3-11 privacy | Raw Agent run/Session/turn/input/permission/Provider request IDs, process credentials, Provider credential name/value, reply body, and permission arguments are absent from receipts, routine logs, browser assets, URLs, telemetry, screenshots, and exported evidence. Browsers receive aliases and minimal display facts only. | In-memory canary scans with count-only results, static bundle scan, sanitized network capture, log/receipt/evidence scan, and field allowlist report. | Secret value or raw ID appears anywhere forbidden; secret is accepted through argv; raw content is copied into a receipt/error; scanner republishes the matched secret. |
| C3-12 cleanup and repeatability | Two fresh C3-E3 runs pass, each with a separate run directory, Gateway database, command journal, aliases, browser contexts, and Provider-backed Session. `nomad stop`/uninstall leaves no owned child and removes only owned state. | Two independently indexed evidence bundles, before/after owned-process attestations, owned-path inventory, and cross-run non-reuse checks. | One lucky run, reused Session/journal/database, manual database repair, orphan child, deletion of unowned state, or cleanup evidence not bound to the run. |

## User-visible and authority states

The UI keeps projection freshness, Agent turn state, capability, and command state
separate. It must not fold them into a single green "running" or "success"
badge.

| Situation | User-visible behavior | Host/Gateway rule | Recovery |
| --- | --- | --- | --- |
| Capability absent | View remains available if safe; reply/deny/Stop are absent or disabled with an explicit read-only reason. | Constructed command and `allow_once` requests are rejected with zero Agent calls. | Re-fetch an authenticated capability document; never enable from a client flag. |
| Live and eligible | Only the action valid for the current bound turn/input/permission is enabled. | Re-read raw current facts and compare Session, target, sequence, digest, command sequence, expiry, and action hash before dispatch. | Normal command lifecycle. |
| Stale | Last-good data is labelled Stale; all writes are disabled. Draft reply may remain local only. | Reject stale sequence/digest/target before journal execution or Agent call. | Validated current snapshot may restore Live; the old command is not submitted automatically. |
| Offline or reconnecting | Last-good data is labelled Offline/Reconnecting; no command is queued. | Reject before dispatch. | User reviews the newly Live state and explicitly acts again with a new command alias. |
| Submitted/received | Show "sent to local Gateway" or equivalent, not "Host accepted" and not success. | Persist the ingress fact; do not infer Host state. | Poll/resume by the same public command alias. |
| HostAccepted | Show "Host accepted; waiting for Agent result". | The exact acceptance is durable and idempotent. | Continue observing; do not resubmit. |
| Executing | Disable repeated action and show that the outcome is not final. Do not alter Agent turn state optimistically. | Scope remains locked; restart treats an unproven execution as unknown. | Await an authoritative terminal fact or enter `OutcomeUnknown`. |
| OutcomeUnknown | Prominent "result unknown; not retried" state in both layouts. No success affordance and no new command in that scope. | No auto-retry. Ordinary snapshot refresh cannot clear the journal gate. | Only authenticated single-use reconciliation bound to principal, run, Session, request, and current snapshot may set Completed/Rejected. |
| Terminal replay | Show the original terminal meaning and that no new action ran. | Return the durable receipt with replay=true and no Agent call. Changed binding under the same alias is Stale/Rejected. | None; user may start a genuinely new action only from new current state. |
| Duplicate taps/tabs | First gesture enters progress immediately; later identical gestures converge on it. A competing distinct request says another action won/state changed. | At most one acceptance and one Agent call for the bound action. | Refresh current state; never silently generate another executable request. |
| Expired permission | Show Expired and remove/disable deny. Stop may remain available only if independently Live and valid. | Host clock and freshly read permission facts decide expiry; zero deny calls after expiry. | Wait for a new permission; an old decision is never replayed. |
| Stop in progress | Show command progress separately from the still-authoritative Agent turn. | One abort dispatch. No new reply/deny in the locked scope. | Only observed cancellation/equivalent terminal fact completes Stop; ambiguity becomes unknown. |
| Terminal Agent turn | Show Completed, Cancelled, or Failed exactly as projected; pending controls disappear. | Reject commands targeted at the terminal turn. | A new Agent turn requires new current facts and new bindings. |
| Restart/reconnect | Preserve the durable last-good view and command receipt, labelled with current freshness. | Reopen only the same run's database/journal; never dispatch an interrupted command. | Converge by validated snapshot plus command-status reconciliation. |

## Evidence classes

These labels are local to C3. In particular, C2 read-path evidence does not
become C3 command evidence merely because it was previously called E3.

| Class | Evidence | Claim allowed |
| --- | --- | --- |
| C3-E0 | Schema, type, reducer, unit, property, and golden-trace tests | Contract support only. |
| C3-E1 | Component tests against fake Agent/Gateway/Host, including negative and crash paths | Component behavior only; no official-Agent or product claim. |
| C3-E2 | Installed local cross-process integration through real browser, Gateway, Host authority, journal, and locked official API surface, but with fake/no Provider or synthetic pending states | Repo-code integration and freeze candidate only. It cannot pass C3 acceptance. |
| **C3-E3** | Two fresh runs of the installed locked official Agent with authoritative real Provider lifecycle proof, concurrent desktop/mobile-width views, real reply/deny/Stop outcomes, all negative cases, privacy scans, restart/reconnect, and owned cleanup | C3 safe local commands product acceptance. It is still not First Real User release approval. |

An E0-E2 failure blocks code freeze. An E3 failure blocks C3 product acceptance.
No volume of E0-E2 evidence upgrades itself to E3.

## Required two-run real acceptance

Both runs must start from fresh run-owned state and use the installed bundle, not
the source tree. Both must attach a desktop viewport and a recorded mobile-width
viewport concurrently to the same Session. Use a disposable repository and a
bounded harmless task designed to reach an input question, a permission request,
and a cancellable active turn. The Agent and Provider interactions must remain
real. If the supported official Agent cannot produce one of these facts
reliably, the gate is `BLOCKED`; a synthetic substitute is not allowed.

| Run | Command ownership | Required positive path | Required resilience path |
| --- | --- | --- | --- |
| A | Desktop sends reply, mobile-width sends deny, desktop sends Stop. | Provider-backed start -> shared view -> real NeedsInput/reply/continue -> real NeedsPermission/deny/resolved -> new active turn/Stop/cancelled. | Duplicate each gesture; expire a separate harmless permission before deny; restart Gateway after a terminal command; reconnect both views; reject constructed `allow_once`; clean stop/uninstall. |
| B | Mobile-width sends reply, desktop sends deny, mobile-width sends Stop. | Repeat the full positive path with new run/Session/command aliases and new Provider interaction proof. | Exercise stale snapshot and Host-offline rejection; interrupt one controlled command after durable execution begins to prove `OutcomeUnknown`, zero redispatch, authenticated reconciliation, terminal replay after Host/Gateway reopen, then clean stop/uninstall. |

Each positive command must have exactly one upstream invocation and a later
authoritative terminal fact. A correct negative result (`Expired`, `Stale`,
`Rejected`, or `OutcomeUnknown`) is evidence for its named resilience case but
does not replace the required positive reply, deny, or Stop outcome.

## Evidence bundle contract

Each run exports a content-safe bundle plus a top-level index that hashes every
file. The run-owned Host/acceptance attestor evaluates raw bindings internally
and emits domain-separated lineage attestations; it never exports the raw Agent
identifiers or credential. Every record carries the same public run alias and
lineage attestation so a reviewer can verify install -> executable -> Session ->
command -> cleanup continuity without seeing the raw values.

Required per-run records:

1. `acceptance-manifest.json`: C3 version, result, timestamps, platform/arch,
   public run alias, evidence index digest, and exact pass/fail/block reasons.
2. `install.json`: bundle/manifest versions and digests, installation mode,
   `doctor` result, capability set, and owned-path commitments.
3. `executable.json`: official package/version/raw-file digest, verified launch
   provenance, process-start and workspace commitments, and Provider-backed
   attestation class. No PID, path containing user data, Provider name, request
   ID, or credential is required in the exported record.
4. `session-ledger.ndjson`: browser-safe Session alias, projection sequence and
   digest, freshness, turn state, pending aliases, authoritative change-summary
   digest/count, and lineage attestation.
5. `command-ledger.ndjson`: public command alias, action, originating viewport,
   observed projection commitment, target/action commitment, lifecycle
   timestamps, sanitized error code, terminal receipt digest, replay flag,
   upstream invocation count, and authoritative-outcome commitment. It contains
   no reply text, permission arguments, raw target ID, or upstream body.
6. `browser-evidence.json`: viewport sizes, same-origin URL origin without query
   secrets, Session alias, network field allowlist result, accessibility-visible
   labels, and hashes of sanitized screenshots.
7. `faults-and-recovery.ndjson`: capability-absent, stale, offline, duplicate,
   expired, restart/reconnect, `OutcomeUnknown`, reconciliation, and terminal
   replay observations with zero/one-call assertions.
8. `privacy-scan.json`: scanned surfaces and boolean/count-only results for raw
   identifiers, credential value/name, relay token, reply body, and forbidden
   fields. The scanner compares secrets in memory and never prints a match.
9. `cleanup.json`: pre/post owned process and path commitments, Agent/Host/Gateway
   exit outcomes, deleted owned-state set, preserved unowned-state assertion,
   and zero-owned-child result.

The two-run index must additionally prove that run aliases, Session aliases,
command aliases, Gateway databases, journals, and process bindings were not
reused. Evidence is invalid if any receipt or routine log contains raw Agent
run/Session/turn/input/permission/Provider request identifiers, or if any browser
surface contains those identifiers, a Provider credential name/value, a Relay
token, or internal Host/socket details.

## Frozen mechanical evidence

The current-disk freeze is backed by two fresh, independent visible-control
mechanical E2 runs. Both used the materialized Product Host, Gateway, production
Web bundle, Chrome DevTools input/network capture, a private UDS, and a separate
OpenCode-shaped loopback upstream. The upstream was not Provider-backed.

- Run 1 binding: `668d121a1267eea10a7c677c0263c37900e722e7168a0936bbb10783809f1d88`
- Run 2 binding: `bfd3b427795870451fab94765bfe5580db8ff03129f47aa0b2f548e05c850d86`
- In each run, browser-visible controls sent one reply, one deny, and one Stop;
  each produced exactly one upstream POST.
- Replay produced zero additional side effects. The injected ambiguous result
  produced one upstream POST, `OutcomeUnknown`, and zero automatic retries.
- Desktop and mobile-width views bound to the same safe projection.
- Journal DB/WAL/SHM and the UDS were `0600`; the UDS parent was `0700`.
- Privacy checks for browser, logs, SQLite, and argv passed. Owned processes,
  ports, UDS, journal, and Gateway database were cleaned after each run.
- Evidence class is `C3-E2`; `provider_e3=false` and
  `production_ready=false` remain explicit.

Final frozen-disk gates on 2026-08-26: Rust 217 library tests plus all
integration targets passed; clippy passed with warnings denied; Web tests passed
185/185; Gateway tests passed 82/82; the production Web build passed; launcher
tests passed 51/51; and `git diff --check` passed. A fresh independent C3 audit
returned `PASS/FREEZE` with no P0/P1 for the local scope.

## Atomic implementation checklist

An item is complete only with its named focused tests and a content-safe task
report. Architects may assign items independently when their owned files do not
overlap; the merge and real-run items remain explicit joins.

### Contract and authority

- [x] **C3-A01 capability contract:** define the exact public capability object
  (`view`, `reply`, `deny`, `stop`, `allow_once=false`) and reject unknown or
  contradictory fields.
- [x] **C3-A02 alias boundary:** map all Agent raw identifiers to run-scoped
  browser aliases and prove raw identifiers cannot serialize through public
  projection, command, error, or receipt types.
- [x] **C3-A03 command DTOs:** keep the public writable union exactly reply,
  deny, and Stop; require current projection CAS and action-specific target
  bindings; reject polluted/legacy variants.
- [x] **C3-A04 Host state refresh:** obtain one bounded, current, process-fenced
  raw fact set immediately before authorization; reject stale, offline, switched,
  expired, conflicting, or incomplete state with zero adapter calls.
- [x] **C3-A05 single authority entrypoint:** route all product writes through
  the crate-private Host-final authority; prove legacy/test adapters cannot be
  reached from the installed route.
- [x] **C3-A06 official command adapter:** bind reply, deny, and Stop to the exact
  official Session facts and map only authoritative outcomes; treat ambiguous
  responses as `OutcomeUnknown`.
- [x] **C3-A07 durable journal:** atomically claim command alias/binding/sequence,
  persist Executing before dispatch, persist terminal before response, and reject
  changed-binding replay.
- [x] **C3-A08 reconciliation:** keep an unknown scope blocked until a
  single-use authenticated proof bound to current authoritative facts commits a
  terminal result; prove ordinary refresh and proof replay cannot clear it.

### Gateway and browser

- [x] **C3-B01 private Host command transport:** add strict bounded command and
  status endpoints over the run-owned private channel with peer/socket/process
  identity checks and no secret-bearing fallback.
- [x] **C3-B02 same-origin Gateway endpoints:** expose POST/status only for the
  three writable commands, keep Host/Provider credentials server-side, validate
  exact framing/schema/origin, and durably correlate public aliases.
- [x] **C3-B03 Gateway restart:** reopen only the same run database, preserve
  terminal receipts, classify interrupted execution unknown, and never dispatch
  during recovery.
- [x] **C3-B04 writable client:** consume server capabilities; remove mock/legacy
  writes from the default installed route; keep local drafts local while not
  Live.
- [x] **C3-B05 truthful lifecycle UI:** render received, HostAccepted, Executing,
  Completed/Rejected/Expired/Stale, and OutcomeUnknown separately; never mutate
  Agent turn state from command submission alone.
- [x] **C3-B06 duplicate gesture control:** allocate one stable public command
  alias per gesture, lock immediately, converge duplicate taps/tabs/status polls,
  and preserve terminal replay semantics.
- [x] **C3-B07 deny expiry:** update the visible expiry state from a trusted time
  policy, disable deny at expiry, and rely on Host revalidation for the race.
- [x] **C3-B08 Stop UX:** require explicit confirmation, distinguish task Stop
  from product shutdown, show waiting/unknown honestly, and complete only from an
  authoritative cancellation fact.
- [x] **C3-B09 responsive parity:** run the same production client in desktop and
  mobile-width layouts; prove action, focus, overflow, live-region, reconnect, and
  result parity without a mobile-only mock.

### Verification and evidence

- [x] **C3-Q01 component matrix:** cover every state-table row at E0/E1, including
  zero-call assertions and same-alias/different-binding attacks.
- [x] **C3-Q02 installed E2 loop:** exercise browser -> Gateway -> private Host ->
  journal -> official adapter boundary from the prebuilt bundle, including
  restart and cleanup, while lab/fake mode remains clearly non-acceptance.
- [x] **C3-Q03 evidence attestor:** emit the allowlisted evidence fields and
  domain-separated lineage attestations without exporting raw IDs, credentials,
  command content, or private socket/process details.
- [x] **C3-Q04 privacy scanner:** scan argv, inherited non-Agent env, state,
  databases, routine logs, receipts, browser bundle/cache/network capture,
  screenshots, and evidence; output counts only.
- [ ] **C3-Q05 Run A:** execute, review, and index the complete first real
  Provider-backed run exactly as specified above.
- [ ] **C3-Q06 Run B:** execute, review, and index the complete independent second
  real Provider-backed run, including unknown/reconciliation/replay.
- [ ] **C3-Q07 independent audit:** report zero open P0/P1 for command authority,
  no optimistic false success, privacy, ownership, and cleanup; record any P2 as
  an explicit release decision.

## Separate verdicts

| Verdict | Pass rule | Current verdict on 2026-08-25 |
| --- | --- | --- |
| C3 repo-code freeze | C3-A01..B09 and C3-Q01..Q04 complete; focused/full tests pass; independent code/security audit has zero P0/P1. E2 is sufficient to freeze code, but the label must remain `CODE_FROZEN`, not `C3 PASS`. | **CODE_FROZEN.** Two fresh visible-control mechanical E2 runs passed through the materialized Product Host, Gateway, browser UI, command journal, and locked OpenCode-shaped HTTP boundary. The final current-disk audit found no P0/P1. This is not Provider evidence. |
| C3 safe local commands acceptance | C3-Q05 and C3-Q06 both produce valid C3-E3 bundles and every C3-01..C3-12 row passes. | **NOT RUN / NO-GO.** No allowlisted Provider credential is present and no two-run Provider-backed command bundle is recorded. |
| First Real User release | C3-E3 passes **and** clean-machine shipped-package, real phone/remote Web, pairing/revocation, production identity/publication trust, release signing/notarization, independent security approval, support/rollback, and no-open-P0/P1 gates pass. | **NO-GO.** C3 code freeze or local E3 alone cannot approve the release. |

The verdicts may advance independently but never by implication: repo-code freeze
does not prove a Provider-backed run, C3-E3 does not prove remote-device trust,
and neither substitutes for the First Real User release decision.
