# Iteration 5 C3 Command Dispatch

Status: ARCHITECTURE FROZEN / IMPLEMENTATION NOT YET ACCEPTED

Depends on: C2 accepted local official-agent read path.

Claim boundary: same-machine browser -> same-origin Gateway -> private Product Host UDS -> locked official OpenCode 1.18.16.

## Product slice

C3 adds the smallest honest writable path after C2: view remains the C2 path; commands are exactly reply, deny, and Stop; allow_once=false at every layer; Product Host is the final and only command authority. Raw OpenCode Session/question/permission IDs and the Provider credential never leave Product Host. Real Provider-backed semantic evidence is a later external gate, not something unit, mock, fixture, or fake-server tests satisfy.

C3 does not add remote access, remote pairing UI, a second Agent, Relay writes, or a generic Agent abstraction. C2 aliases and writable booleans are display data, never command authority.

## Frozen dependency DAG

    C2 accepted read path
      -> C3-A private OpenCode command facts and safe capability
           -> C3-B single HostCommandAuthority and FULL durable journal
           -> C3-C concrete OpenCode 1.18.16 dispatcher
                -> C3-D Product Host UDS command endpoint/composition
                     -> C3-E same-origin Gateway command proxy
                          -> C3-F capability-gated browser client/UI
                               -> C3-G local integrated acceptance
                                    -> E-C3 real Provider evidence [external/later]

No lane after C3-A may invent raw target facts. C3-D cannot merge before C3-A, C3-B, and C3-C independently pass. C3-F cannot enable writes without a live Host-issued capability.

## C3-A: authoritative private command facts

The OpenCode adapter owns one private current-facts object populated by a fresh process-identity-fenced read from the exact owned OpenCode process and Session. It holds raw Session ID, active raw question ID, active raw permission ID, any observed active turn, permission action hash, process/run binding, and the C2 snapshot sequence/digest. OpenCode 1.18.16 does not expose a permission expiry on `/permission`; the expiry below is therefore a Host-issued authorization expiry, not an upstream fact. Raw fields are non-serializable and Debug-redacted.

The Host may publish a content-safe nomad.product-host.command-capability.v1 containing only: opaque capability_id; snapshot_seq and snapshot_digest; next_command_seq; Host UTC issued_at and expires_at with at most 30 seconds validity and zero skew; optional `reply {turn_alias,input_alias}`, `deny {permission_alias,action_hash,expires_at}`, and `stop {turn_alias}` capabilities; `view=true`; and `allow_once=false`. The deny expiry equals the Host authorization expiry and must be rechecked together with fresh raw permission facts. For session-scoped interrupt, `turn_alias` is an opaque run/session/snapshot-bound Host capability; it is not a claim that OpenCode exposes a raw turn identifier.

It contains no raw ID, Provider/model data, credential, Agent password, command key, or upstream URL. It is live only while Agent process identity, run, source health, snapshot binding, target facts, pairing epoch, and expiry remain current and no reconciliation is pending. Alias presence alone never creates capability.

On every command the Host synchronously re-reads authoritative raw facts, resolves the safe target through its private run-scoped map, and compares fresh raw target, action hash, expiry, process identity, run, Session, snapshot sequence and digest. Failure is Stale or HostOffline before dispatch. OpenCode has no transactional precondition, so a read-to-POST race remains and must not be described as an atomic upstream transaction.

## C3-B: one Host authority and durable semantics

Product Host constructs exactly one HostCommandAuthority at startup. It owns one file-backed CommandJournal, one current-facts source, and one concrete OpenCode dispatcher for the run. UDS handlers share it and never construct per-request authorities. SQLite remains journal_mode=WAL and synchronous=FULL; failure to verify PRAGMA synchronous equals 2 prevents command readiness.

The browser request is exact-schema and content-safe: opaque capability ID, request ID, safe target alias, action, reply content only for reply, expected snapshot sequence/digest, nonce, command sequence, issued time, and expiry. Gateway never supplies raw IDs. Inside Host, authority binds command to raw run and Session, authenticated local device and pairing epoch, capability, request, nonce, sequence, expiry, snapshot, exact action hash, reply-content digest, and freshly re-read target facts.

The binding is keyed and constant-time verified. Request ID, nonce, or sequence cannot cross run, Session, device, or pairing epoch. Revocation or epoch change immediately invalidates capabilities. C3 local mode uses a Host-created run-local device session delivered to Gateway only through the private inherited bootstrap/ready channel. This is not remote-device pairing. Browser sees only opaque capability and a separate Gateway CSRF token.

The local composition uses two independent launcher-generated 32-byte keys. The Host receives both only inside the existing length-prefixed anonymous FD 10 bootstrap: a command-authority key used to construct the local authenticated device session, and a transport key used only to authenticate Gateway-to-Host command HTTP. Gateway receives only the transport key through inherited FD 11 and consumes exactly 32 bytes plus EOF before serving. Neither key may appear in argv, environment, state, files, logs, receipts, or browser data. Every command capability GET and command POST carries `X-Nomad-Transport-Time`, `X-Nomad-Transport-Nonce`, and `X-Nomad-Transport-Mac`; the Host enforces a 30-second UTC window and a bounded single-use nonce cache. The HMAC-SHA256 input is exactly `nomad.product-host.transport.v1\n{method}\n{path}\n{unix_seconds}\n{nonce}\n{lower_hex_sha256(body)}`. C2 read routes remain unauthenticated beyond their existing pinned UDS/peer contract.

### Honest command lifecycle

The guarantee is exactly-once Host acceptance plus at-most-once upstream dispatch, not exactly-once upstream effect.

1. Validate device, capability, fresh facts, action, nonce, sequence, snapshot and expiry.
2. Insert keyed binding, consumed nonce/sequence, content-free acceptance record and receipt ID in one FULL-synchronous transaction. Commit before upstream POST.
3. Mark Dispatching durably, then make at most one upstream call.
4. Persist DispatchAcknowledged, Rejected, or OutcomeUnknown and return a content-free receipt. DispatchAcknowledged means only that the exact OpenCode endpoint accepted the HTTP request, not that the Agent completed the semantic action.
5. Exact replay returns the stored receipt with idempotent_replay=true and no upstream call. Same request ID with changed binding is Stale. Accepted/Dispatching state found after crash becomes durable OutcomeUnknown and is never dispatched again.

OpenCode has no idempotency key or authoritative command receipt. Timeout, connection loss after dispatch begins, malformed success, Host crash after POST, or failure to durably record response is OutcomeUnknown. Reconciliation may later observe state, but only an authenticated single-use Host proof may update the record and it never redispatches.

Audit receipts contain only schema, receipt ID, request ID, action kind/hash, bound snapshot sequence/digest, Host acceptance time, dispatch status, sanitized error, and replay flag. They contain no command content, raw ID, credential, URL, HTTP body, or process detail.

## C3-C: exact OpenCode 1.18.16 dispatch

OpenCode-specific facts, URL construction, bodies, authentication, response classification, and re-read logic stay under adapters::opencode. Do not create a premature generic Agent command trait. Production authority uses one concrete OpenCode dispatcher; substitution is test-only.

| Action | Exact request | Exact body |
| --- | --- | --- |
| reply | POST /api/session/{raw_session}/question/{raw_question}/reply | {"answers":[[content]]} |
| deny | POST /api/session/{raw_session}/permission/{raw_permission}/reply | {"reply":"reject"} |
| Stop | POST /api/session/{raw_session}/interrupt | no body |

Raw path components come only from freshly re-read private facts and are encoded once as URL path segments. Browser or Gateway path strings are never appended upstream. Fixed loopback origin and Agent Basic credential remain Host-only. Stop sends zero body bytes. No allow, allow_once, arbitrary route, or generic action escape hatch exists. Unknown action fails before journal acceptance and network I/O.

## C3-D: private Product Host command API

The existing run-owned product-host.sock remains the sole Host surface. Add exactly:

- GET /internal/commands/capability: current safe capability or content-free 503.
- POST /internal/commands: one synchronous Host-final command receipt.

Keep C2 parent/socket dev+inode, owner, 0700 directory, 0600 socket, and peer-UID checks. Accept only exact HTTP framing and JSON, bounded Content-Length, application/json, no transfer encoding, no pipelined/trailing request, and no ambient Authorization header. Gateway-to-Host run-local capability comes through the private inherited channel and never becomes a browser bearer. Capability and command use the same single Host instance and facts store as C2. Existing C2 read schemas remain unchanged.

## C3-E: same-origin Gateway proxy

Writable routes exist only in official-agent-local mode:

- GET /api/commands/capability
- POST /api/commands

Gateway talks only to pinned Product Host UDS. Official mode never constructs or calls RelayClient, PilotSessionClient, mock Host, legacy bridge, or OpenCode. Host failure is sanitized unavailable or OutcomeUnknown; no fallback exists.

Before POST body proxy, require exact configured loopback Host header, exact same-origin Origin, Sec-Fetch-Site same-origin, Sec-Fetch-Mode cors, application/json, bounded Content-Length, no transfer encoding, and X-Nomad-CSRF constant-time equal to a random process-local token returned by capability GET. Reject wildcard, suffix, null, missing, or alternate localhost/127.0.0.1 origin. Emit no CORS headers. Use a bounded request/nonce/sequence cache only as fast rejection; Host journal remains durable replay authority. Cache-Control is no-store; CSRF, UDS capability and bodies are never logged. Gateway restart rotates CSRF and refetches Host capability.

## C3-F: browser behavior

Default installed UI uses only same-origin HTTP. Reply, deny, and Stop controls exist only when live capability matches displayed snapshot sequence/digest and enables that action. Disable immediately on expiry, refresh, offline, stale, reconciliation pending, snapshot change, or an in-flight command. Missing or true allow_once makes capability unusable.

Client submits once. Transport recovery may replay only the exact same request to retrieve a receipt; it never generates a new request ID, nonce, or sequence. OutcomeUnknown remains unknown and never triggers automatic upstream retry. RelayReceived never implies HostAccepted; DispatchAcknowledged never renders as Agent task completion.

## Non-overlapping worker packages

### WP-C3-A: OpenCode private facts and dispatcher

Owned files:

- connector/src/adapters/opencode.rs

Tests in that file: exact routes/methods/bodies including zero-byte Stop; path escaping and fixed origin; reject changed process/Session/question/permission/action hash/expiry/snapshot/run; capability secret/raw-ID absence and allow_once=false; conservative mapping for timeout/disconnect/malformed response with no second POST; secret-clean Debug/errors.

Gate: no public generic command trait, no implementation outside adapters::opencode, no Provider claim.

### WP-C3-B: Host authority and FULL journal

Depends on WP-C3-A frozen internal interface.

Owned files:

- connector/src/host_command_authority.rs
- connector/src/journal.rs

Tests: mutate every run/Session/device/pairing/capability/nonce/sequence/snapshot/expiry/action-hash binding and reject before adapter; expired/future/revoked/offline/stale/reconciliation-pending reject; exact/concurrent replay calls adapter once; DB reopen preserves replay and OutcomeUnknown; accepted/dispatching crash never redispatches; FULL and commit-before-call verified; receipt/Debug excludes content/raw IDs/keys/credential; allow and allow_once impossible or blocked.

Gate: one production authority; test adapter seam is test-only; no public caller-supplied authenticated-session constructor.

### WP-C3-C: Product Host UDS protocol and composition

Depends on WP-C3-A and WP-C3-B.

Owned files:

- connector/src/product_command_protocol.rs [new]
- connector/src/product_stock_projector.rs
- connector/src/product_host_bootstrap.rs
- connector/src/lib.rs
- connector/tests/product_host_command_process_tests.rs [new]

Tests: exact capability GET/command POST; reject all other method/path/header/body shapes, duplicate keys, trailing bytes, chunking and oversize; reject wrong peer UID/socket identity/mode/owner/run capability/restarted Host; one authority instance under concurrency; aliases cannot dispatch without fresh facts; response/ready receipt has no raw ID/password/Provider/UDS secret/content/process detail; C2 current/stream remain compatible.

Gate: one UDS, one authority, no TCP Host listener or read fallback.

### WP-C3-D: Gateway CSRF and UDS proxy

Depends on WP-C3-C.

Owned files:

- mobile-reference/pilot-gateway/product-host-client.mjs
- mobile-reference/pilot-gateway/command-security.mjs [new]
- mobile-reference/pilot-gateway/server.mjs
- mobile-reference/pilot-gateway/product-host-command.test.mjs [new]
- mobile-reference/pilot-gateway/server.test.mjs

Tests: reject missing/wrong/cross/null Origin, Host mismatch, Fetch Metadata failure, simple content types, bad CSRF, oversize/chunking; no CORS/token/body logs; CSRF rotates; duplicate/conflict fast reject and Host replay survives Gateway restart; official mode never constructs Relay and /api/pilot stays blocked; UDS failure has no fallback; raw-ID/credential canaries never reach browser.

Gate: official write path has exactly one downstream, pinned Product Host UDS.

### WP-C3-E: browser capability-gated client/UI

Depends on WP-C3-D.

Owned files:

- mobile-reference/src/client/types.ts
- mobile-reference/src/client/http-client.ts
- mobile-reference/src/client/http-client.test.ts
- mobile-reference/src/main.tsx
- mobile-reference/src/ui/App.tsx
- mobile-reference/src/ui/App.test.tsx
- mobile-reference/src/ui/Approval.tsx
- mobile-reference/src/ui/ReplyComposer.tsx
- mobile-reference/src/ui/ReplyComposer.test.ts
- mobile-reference/src/ui/StopDialog.tsx

Tests: controls disabled for missing/malformed/expired/stale/offline/reconciliation/allow_once-invalid capability; exact reply/deny/Stop and CSRF shapes with no raw IDs; double click/in-flight/stale capability sends nothing extra; OutcomeUnknown no retry; lifecycle labels remain honest; default official client imports neither pilot-client nor mock/api.

Gate: build/tests pass with no allow action in public command union.

### WP-C3-F: generated bundle and local integration

Depends on WP-C3-C, WP-C3-D, and WP-C3-E.

Owned files:

- mobile-reference/dist/** [generated only; no hand editing]
- tools/nomad_web/launcher.py
- tools/nomad_web/processes.py
- tools/nomad_web/state.py
- tools/nomad_web/bundle_manifest.json
- testkit/nomad-web/test_c3_local_commands.py [new]

Tests: clean-home official start has one Host, Gateway, journal and no Relay; mechanical reply/deny/Stop each makes one exact fake-upstream POST and one durable receipt; crash before/during/after request proves no automatic second POST and durable OutcomeUnknown; state/argv/log/bundle/receipt excludes raw-ID/credential canaries; manifest becomes view/reply/deny/stop true and allow_once false only after gates pass.

Gate: local mechanics only. Fake upstream is not official Agent semantics or Provider evidence.

## Forbidden production paths

C3 product graph must not call PilotAdapter::execute, PilotCommand, parse_pilot_command, result_payload, BridgeDispatcher::dispatch, process-bridge, Relay command polling, StockCommandTransport::execute, UreqStockCommandHttp, StockOpenCodeAdapter::execute_blocked_command, PilotSessionClient, createMockHost, or getMockHost. It must not use /api/pilot, direct browser/Gateway-to-OpenCode requests, caller-supplied raw IDs, CurrentReleaseAuthorization alone, C2 aliases, writable booleans, feature flags, or embedded evidence as command authority. Permission allow, allow_once, interrupt_and_send, prompt/send, arbitrary routes, and generic action escapes are forbidden.

Legacy code may remain for tests/history, but no C3 binary, official Gateway, default browser entrypoint, launcher, or bundle may import or invoke it.

## Gates and acceptance

Repo-local gate: all negative tests, full Connector tests/clippy, Gateway/browser tests/build, generated bundle verification, and independent security audit P0=0/P1=0. Source audit shows one production authority and no forbidden installed path.

Local integrated gate: one clean run demonstrates C2 view plus reply, deny, and Stop through same-origin Gateway and UDS. Each has FULL-durable Host acceptance and at most one exact upstream call. Replay, stale capability, revocation, snapshot change, and crash windows remain fail-closed. Fake upstream proves mechanics only.

External E-C3 gate, later: a temporary allowlisted Provider credential and locked official OpenCode 1.18.16 demonstrate the three routes in a disposable real task. Credential stays only in Agent child environment and never enters argv, Host environment, files, logs, receipts, browser assets, evidence, or chat. Independent review binds run to release/provenance. Until this and applicable security/release approvals pass, C3 is at most implementation-complete, not production command-ready or Controlled Pilot-ready.
