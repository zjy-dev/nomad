# Iteration 2 Mobile Web Completion Report

## Scope

Delivered the Controlled Pilot v0.2 Mobile Web lane for PRD-210 through PRD-214. The implementation remains a responsive web client; it does not claim native iOS, Push, background recovery, production identity, or production transport evidence.

## Design direction

The product surface is an industrial task console: dark, compact, high-contrast, information-first, and deliberately low on decorative chrome. A yellow-green control signal marks actionable state; danger, warning, and verified states always include words or symbols in addition to color. The 390 x 844 layout uses a fixed four-item control rail, 44 px minimum controls, compact Host/freshness status cells, and no horizontal overflow.

The default route is the Pilot product. It immediately resolves `SessionClient.loadCurrentSession()` and answers, in order:

1. Does this task need me?
2. What happened last?
3. What can I safely do now?

Golden traces are isolated behind the explicit `?lab=1` developer route.

## Client and integration boundary

`src/client/types.ts` defines the replaceable `SessionClient` boundary and client-only `SessionView` projection. UI components do not import or call `getMockHost`. The local composition root injects `PilotSessionClient`, which provides a deterministic permission checkpoint for product and browser tests.

`HttpSessionClient` is ready for Host/Relay integration, but intentionally requires routes and decoding functions at construction time. Session Semantics v0 freezes Snapshot/Event/Command shapes, not a new Mobile REST envelope; the Mobile lane therefore does not invent or freeze an HTTP schema.

Root integration steps:

1. Add a Host/Relay-owned adapter that decodes the deployed read response into `SessionView`. Start from the frozen Snapshot/Event semantics and attach Host-owned approval facts and authoritative diff projection.
2. Construct `HttpSessionClient` with the deployed current-session, refresh, command, and optional command-status routes plus those codecs.
3. Replace `new PilotSessionClient()` in `src/main.tsx` with the HTTP instance. No Home, Activity, Action, or Changes component changes are required.
4. Preserve command stages as distinct values. `RelayReceived` must not be decoded as `HostAccepted`.
5. Populate `approval.actionHash` for deny submission but do not render it. Populate Changes only from Host-authoritative `source`, `baseline`, and `files`.

## Information mapping

| Protocol or Host fact | Pilot product wording | Default visibility |
| --- | --- | --- |
| `host_connectivity=Online` | Online - Host reachable | Visible |
| `host_connectivity=Offline` | Offline - Host unreachable; actions paused | Visible |
| `client_freshness=Live` | Live - state verified | Visible |
| `Reconnecting` | Checking state; actions unlock after verification | Visible |
| `Stale` | State not verified; refresh before acting | Visible |
| `permission.requested` | Paused before a protected action | Visible |
| `tool.started/completed/failed` | Humanized workspace progress | Visible |
| seq, event ID, digest, contract version | Diagnostic details | Collapsed or absent |
| permission ID and action hash | Submission-only internal fact | Not rendered |
| Host approval facts | Tool, requested action, scope, working area, resources, expiry, source | Visible |
| `allow_once` | No product control | Absent |
| `diff_file_count` without authoritative files | No verified changes yet | Empty state |

## Safety and Changes behavior

- Reply, deny, and Stop remain gated on Online + Live + compatible version + verified snapshot.
- Offline and Stale explain recovery in user language and disable command controls.
- Action presents Host facts separately from explanatory copy. Pilot offers only deny and Stop; no Allow button or internal HC/SEC identifier appears.
- `SAMPLE_FILES` and all sample-diff fallback behavior were removed.
- Changes uses a client view model with `status`, `source`, `baseline`, and `files`. `available` data is displayed only when source and baseline are present; empty or invalid data renders an explicit empty state.
- External edits, binary files, truncation, and invalid baselines have explicit view states/labels.

## Verification

Passed:

- `cd mobile-reference && npm test -- --run` - 8 files, 99 tests.
- `cd mobile-reference && npm run build`.
- `cd mobile-reference && npm run build:process-bridge`.

Tests cover the default product route, explicit trace lab, HTTP route/codec injection, Relay receipt versus Host acceptance, authoritative empty diff, absence of Allow, and Offline/Stale command gates. `App.test.tsx` waits on a MutationObserver-backed UI readiness condition rather than a fixed timeout, removing the asynchronous load race seen under parallel runs.

The browser smoke was updated for the product route, `?lab=1`, empty diff, deny/Stop-only Action, Stale safety gate, 390 x 844 overflow, and console/page errors. In this shell it must be run with the available Playwright environment, for example:

```sh
uv run --with playwright python testkit/browser/mobile_reference_smoke.py
```

The root agent remains the owner of the final integrated browser run against the selected Host/Relay composition.

## Known limitations

- The default injected session is deterministic Pilot data, not evidence of a deployed OpenCode/Host/Relay capture.
- The HTTP envelope and authentication headers remain integration-owned because those APIs were not frozen in this lane.
- Approval fact quality depends on the Host adapter providing real tool facts and a deny-bound action hash.
- The UI supports an authoritative diff view, but the deterministic permission checkpoint intentionally supplies no diff and exercises the empty state.
- Frontground responsive Web behavior is covered; Push, background recovery, native storage, and native accessibility are outside this iteration.
