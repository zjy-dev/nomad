# Iteration 5 Product Brief

Status: FIRST REAL USER VERSION / APPLE SILICON MACOS HOST + DESKTOP/MOBILE WEB COMPANION

## Product definition

The first real user version of Nomad is:

- Apple Silicon macOS Host only.
- Desktop Web and mobile Web Companion only.
- One user, one Host, one active Session.
- One supported official Code Agent package only.
- Remote actions limited to `view`, `reply`, `deny`, and `Stop`.
- `allow_once=false` in UI, Host authority, and acceptance.
- Native iPhone, APNs, multi-device support, and broader Agent support are later packages.

The repo-local launcher foundation and prebuilt bundle are prerequisites, not
the product. The product starts only when a real Agent can be installed,
started, observed, and safely controlled.

## Target user

A solo developer using an Apple Silicon Mac as their main coding machine who
runs one supported local Code Agent and wants to leave the terminal without
losing visibility or the ability to make a small set of safe interventions.

Teams, multi-Host orchestration, hosted workspaces, arbitrary remote shell, and
native-mobile-only users are outside the first version.

## Required user journey

1. Install the prebuilt Nomad Host bundle on a clean Apple Silicon Mac.
2. Run `nomad doctor` and receive exact blockers plus recovery actions.
3. Run `nomad start`; the Host starts one locked official Code Agent package
   and the Web Companion path.
4. Start one real task and open the reported Web URL on desktop or phone.
5. Observe the same live Session, pending interaction, and authoritative diff.
6. Execute `reply`, `deny`, or `Stop` through Host-final authorization.
7. Refresh or reconnect without stale-live state or duplicate side effects.
8. End the Session and remove owned local state with an auditable outcome.

Starting only Relay and Gateway is `foundation-readonly`, not product success.

## Real Agent definition

All of the following must be true in the same run:

- The process is the locked official package, not fake-opencode, mock transport,
  synthetic trace, fixture replay, or demo mode.
- It executes a real Provider-backed task on the user's Mac.
- The Web projection is derived from that process and that Session.
- `reply`, `deny`, and `Stop` traverse the real Host authority path to that
  process and produce authoritative outcomes.
- Evidence binds install, executable identity, Session, projections, commands,
  and cleanup without persisting Provider secret values or user content.

## First-release capabilities

In scope: live Session state, pending question/permission context, authoritative
change summary, `reply`, `deny`, `Stop`, reconnect recovery, and local audit
receipts.

Out of scope: `allow_once`, arbitrary command execution, permanent permission
rules, native iPhone, APNs, multi-device, hosted execution, and a broad Provider
or Agent matrix. `allow_once=false` is a hard invariant: absent from the UI,
rejected by Host authority, and covered by negative acceptance.

## Security and release gates

- The Provider credential remains owned by the Agent process. Its value never
  enters Nomad argv, persisted state, logs, browser assets, Relay, or receipts.
- The official Agent is installed and started through an adapter-owned path.
- Pairing, client authentication, command authorization, replay protection,
  revocation, and reconnect behavior fail closed.
- `reply`, `deny`, and `Stop` receive Host-final authorization and durable,
  content-safe outcomes.
- The actual shipped Host package satisfies the required release and trust
  gates; repo-local evidence cannot substitute for them.
- Independent security review approves the limited action surface.

## Must-pass real acceptance

1. Clean-machine prebuilt install on Apple Silicon macOS.
2. Actionable `doctor` output and a one-command owned-process lifecycle.
3. Locked official OpenCode starts and completes one real Provider-backed task.
4. Desktop Web and a real phone browser attach to that same run.
5. Both show current state and the authoritative change summary.
6. `reply`, `deny`, and `Stop` each succeed exactly once end to end.
7. Refresh/reconnect does not fabricate live state or duplicate a command.
8. Constructed `allow_once` is rejected.
9. Secret/content scanners pass for argv, logs, state, browser assets, Relay, and
   evidence receipts.
10. Stop/uninstall leaves no owned process and deletes only owned local state.

Synthetic, fixture, schema-only, or demo evidence cannot pass these gates.

## Go / No-Go

Go only when every must-pass acceptance item succeeds in same-run evidence and
the security/release reviewers report no open P0/P1. Otherwise the result stays
an internal foundation, even if all component tests pass.
