# Iteration 3 M2 Real Integration Dispatch (Final)

## Corrected Capability Design: Harness Proxy

### The Contradiction

Previous dispatch said:
- A1: "Python constructs `VerifiedM2Capabilities` in memory and passes to Host"
- C: "Host receives capability from environment"

Both are wrong. Python cannot call Rust `VerifiedM2Capabilities::from_live_capture()`; and env-based capability is forgeable self-attestation.

### Concrete Cross-Process Design

```
┌───────────────────────────────────────────────────────────────────────┐
│  Harness (Python)                                                    │
│  ┌─────────────┐     ┌──────────────────────────────┐                │
│  │ OpenCode    │────→│  Observing Proxy (Python)     │←──bidirectional│
│  │ (locked sub)│     │  - audit-only observation     │   socketpair   │
│  │             │     │  - SSE traffic observer       │   (e.g. FD 3)  │
│  │ port 4096   │←───│  - run-state machine          │                │
│  │             │     │  - no capability construction │  ←──one-way   │
│  │             │     │  - no receipt emission        │  pipe (FD 4)  │
│  │             │     │  - V2 blocked until later     │  32 B secret   │
│  │             │     │  - opencode traffic relay     │                │
│  └─────────────┘     └──────────────────────────────┘                │
│                                              │                       │
│                                     random TCP port                  │
│                                              │                       │
│                               ┌────────────────▼────────────────┐    │
│                               │  Host (Rust binary)             │    │
│                               │  - pilot_host_bridge            │    │
│                               │  --m2-stock-mode                │    │
│                               │  - connects to proxy HTTP port  │    │
│                               │  - handshake over socketpair    │    │
│                               │  - 32 B secret from FD 4 pipe   │    │
│                               │  - challenge-response HMAC      │    │
│                               │  - StockCommandTransport        │    │
│                               │  - aliased Relay relay          │    │
│                               └─────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────────┘
```

### Harness Proxy Responsibilities (Python, Lane A1)

**Superseded by the authoritative A1 work package below (lines 233–407).** The older design sections that follow are retained only for historical context. The corrected A1 design is:

- **Typed fixed-route observing gateway** — not a generic reverse proxy
- **Audit-only**: V2 blocked until later integration (`BLOCKED_A0_CERTIFICATE_REQUIRED`)
- **No capability construction, no receipt emission, no A0 certificate loading**
- **Two inherited channels**: bidirectional socketpair (handshake) + one-way pipe (32 B secret), exact FD numbers harness-assigned
- **No TCP control socket/capability JSON in A1 proxy**
- **See A1 Lane section below for the complete authoritative design.**

### Anonymous FD Run Binding (Host ← → Harness)

**Superseded by the authoritative A1 work package below (lines 233–407).** The corrected design uses two inherited channels:

- **Bidirectional socketpair** (e.g. FD 3) for `run_binding.rs` HELLO/CHALLENGE/RESPONSE handshake
- **One-way anonymous pipe** (e.g. FD 4) for exact 32-byte binding secret, close-on-exec for unrelated children

FD numbers are harness-assigned, not protocol constants. No TCP control socket, no capability JSON in A1 proxy. See A1 Lane section below for the authoritative specification.

### Rust/Python Responsibility Split

**Superseded by the authoritative A1 spec below.** The corrected A1 proxy is an **audit-only typed fixed-route gateway**. It does not construct capabilities, does not emit receipts, and V2 is blocked until later integration. The responsibility table below is historical only:

| Component | Language | Role | Access to credential? |
|-----------|----------|------|---------------------|
| OpenCode subprocess | stock JS | Provider-backed session | Yes (env) |
| Harness proxy | Python | Audit-only typed fixed-route gateway, SSE observation, state machine | No |
| Host | Rust | Stock adapter, journal, command transport, alias, Relay relay | No |
| Relay | Go | Message relay | No |
| Harness orchestrator | Python | Process lifecycle, receipt store, verification | No |

### A0 Certificate Role

**Superseded by the authoritative A1 spec below.** The A0 certificate is a committed structural contract. Its role in capability construction is explicitly deferred to later integration (Lane B, TBD after certificate). The A1 proxy does not load or use the A0 certificate.

---

## Architecture Decisions

### Decision 1: Harness Proxy Design

**Problem**: Python cannot construct Rust `VerifiedM2Capabilities`. Environment-based capability is forgeable.

**Solution**: Harness proxy between OpenCode and Host. Proxy owns observation and state machine. In A1, proxy is audit-only — V2 blocked, no capability construction, no receipt emission. Two inherited channels: bidirectional socketpair for handshake (frozen `run_binding.rs` protocol) + one-way pipe for 32 B binding secret. Capability unlock is later integration (B/C, TBD after A0 certificate).

### Decision 2: Integrity Hash Chain

Receipts form an integrity hash chain anchored by harness-run random nonce. Not a signature, not proof-of-work.

### Decision 3: A0 Discovery Phase

Separate credential-gated phase to discover the required event sequence and commit a structural certificate. The certificate is expected structure only — never sufficient to unlock capability by itself.

### Decision 4: Preserve `--dry-run` → SKIP

Existing frozen behavior preserved.

---

## Revised Work Packages

### Lane A0: Discovery & Structural Certification

**Known V1 route facts** (official 1.18.16, no-credential verified, directory-only):

| Route | Method | operationId | Purpose |
|-------|--------|-------------|---------|
| `/session` | POST | `session.create` | Create a new session with `directory` query filter |
| `/event` | GET | `event.subscribe` | SSE event stream, supports `directory` query filter |
| `/session/{sessionID}` | GET | session read | Get session state |
| `/session/{sessionID}/diff` | GET | `session.diff` | Get workspace diff |
| `/question` | GET | `question.list` | List questions (pending) |
| `/permission` | GET | `permission.list` | List permissions (pending) |
| `/api/session/...` | POST | v2 commands | V2 write routes (prompt, question reply, permission reply, interrupt) — per committed `command-shapes.json` |

**Key separation**: V1 read routes (`/session/{id}`, `/event`, `/question`, `/permission`, `/session/{id}/diff`) are separate from V2 write routes (`/api/session/{id}/prompt`, `/api/session/{id}/question/{rid}/reply`, etc.). The proxy must understand both layers. `/event` does not accept `sessionID` query — correlate via `properties.sessionID` in SSE. `workspace` query is rejected.

**Deliverable (already code-ready PASS, certificate pending)**:
1. `discover_lifecycle.py` — reuses WP1 isolation, triggers the required sequence with a project-owned prompt, captures content-free structural certificate. The sequence is:
   a. **GET `/event`** with `directory` query → subscribe first (before session create)
   b. **POST `/session`** with `directory` query → creates a session
   c. **POST `/api/session/{id}/prompt`** (V2) with project-owned prompt content → triggers assistant response
   d. Observe SSE events until the required lifecycle sequence is complete
   e. **GET `/session/{id}/diff`** → captures diff count
   f. **GET `/question`** → verifies question list matches expected
   g. **GET `/permission`** → verifies permission list matches expected

2. Certificate schema:
   ```json
   {
     "schema_version": "nomad.stock-opencode.lifecycle-certificate.v1",
     "expected_event_sequence": [
       "server.connected",
       "session.created",
       "turn.started",
       "message.updated(kind=question)",
       "diff.updated",
       "permission.updated(status=pending)"
     ],
     "diff_file_count": 1,
     "v1_routes_verified": ["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"],
     "v2_routes_verified": ["/api/session/{id}/prompt", "/api/session/{id}/question/{rid}/reply", "/api/session/{id}/permission/{rid}/reply", "/api/session/{id}/interrupt"],
     "structural_digest": "sha256:..."
   }
   ```

3. Project-owned prompt: a deterministic text that reliably triggers the sequence. Must be committed to `testkit/stock-opencode/real-task/project-prompt.txt`. Content is project-owned and never appears in receipts or evidence output.

**Acceptance** (requires credential):
```bash
export ANTHROPIC_API_KEY=sk-...
python3 testkit/stock-opencode/discover_lifecycle.py --provider-credential-env ANTHROPIC_API_KEY
# → {"status": "CERTIFIED", "certificate_path": "..."}
# Writes lifecycle-certificate.json to testkit/stock-opencode/real-task/
```

**Dependency**: None.

---

### Lane A1: Observing Proxy & Run Binding Peer

**Ownership**: `testkit/pilot/observing_proxy.py` (new — typed fixed-route observing gateway). `testkit/pilot/test_observing_proxy.py` (new — no-credential scripted acceptance). No changes to `testkit/pilot/iteration3_real_slice.py` (preserve as verifier scaffold). No changes to `connector/src/run_binding.rs` (already PASS, frozen). Only add Python; no Rust changes in A1.

**Design constraint**: the proxy is a **typed fixed-route gateway**, not a generic reverse proxy. Every route, method, query parameter, header, and body bound is explicitly enumerated. Unknown values reject before any network I/O. This eliminates SSRF, request smuggling, and header injection by construction.

**Invariants preserved**:
- No capability unlock until A0 certificate is observed and matches → audit-only mode by default
- Credential only in OpenCode subprocess, never in proxy/Host/receipts
- Preserve `--dry-run` → SKIP
- Preserve `testkit/process-loop/last-transcript.json`
- `allow_once=false` (still blocked capability)

**Deliverable**:

1. **Python observing proxy** (`testkit/pilot/observing_proxy.py`):

   **Constructor**:
   - `ObservingProxy(upstream_origin: str, canonical_workspace: Path, run_id: str)` — **audit-only production factory**. No capability_digest, no challenge, no binding_secret. V2 authorization is permanently blocked.
   - `upstream_origin` is fixed `http://127.0.0.1:<port>` (no path), supplied by harness
   - `canonical_workspace` is the resolved absolute disposable workspace path — every `directory` query must match exactly after canonical resolution
   - Listens on `127.0.0.1:0` (OS-assigned random port)
   - `run_id` is a harness-generated 32-byte hex string for binding correlation
   - The production factory has **no** capability_digest, challenge, or binding_secret parameters — these are supplied by the harness orchestrator via separate inherited channels, not by the proxy constructor
   - **Test-only factory**: `ObservingProxy.test_upstream(upstream_origin, canonical_workspace, run_id, test_authority: TestAuthority)` — module-private, `TestAuthority` is a module-private sentinel class with a private sentinel object. Only constructible in test/harness code. All observations/outputs from this path are labeled `SYNTHETIC_TEST_ONLY`. Cannot construct capability bundles, emit official receipts, or be serialized.

   **Exact route table** (official locked 1.18.16, corrected per product alignment):

   | Method | Path Template | Query Keys (allowlist only) | operationId | Notes |
   |--------|---------------|------------------------------|-------------|-------|
   | GET | `/global/health` | none | — | pass-through |
   | POST | `/session` | `directory` only | `session.create` | directory must match canonical_workspace exactly |
   | GET | `/session/{sessionID}` | `directory` only | — | directory must match canonical_workspace exactly |
   | GET | `/session/{sessionID}/diff` | `directory` only | `session.diff` | directory must match canonical_workspace exactly |
   | GET | `/event` | `directory` only | `event.subscribe` | official: no `sessionID` query; correlation via `properties.sessionID` in SSE |
   | GET | `/question` | `directory` only | `question.list` | directory must match canonical_workspace exactly |
   | GET | `/permission` | `directory` only | `permission.list` | directory must match canonical_workspace exactly |
   | POST | `/api/session/{sessionID}/prompt` | none | `v2.session.prompt` | allowed only after `provisioned` state |
   | POST | `/api/session/{sessionID}/question/{requestID}/reply` | none | `v2.session.question.reply` | at most one, after `question_pending` |
   | POST | `/api/session/{sessionID}/permission/{requestID}/reply` | none | `v2.session.permission.reply` | at most one, after `permission_pending` |
   | POST | `/api/session/{sessionID}/interrupt` | none | `v2.session.interrupt` | one-shot, after Stop event → `stopping` |

   **Route matching & validation rules**:
   - Path matched as literal after template expansion — no regex, no prefix match, no glob
   - Path params `sessionID`/`requestID`: must match `^[A-Za-z0-9_-]{1,256}$` → else 400
   - **Query key allowlist per route**: any extra/unknown query key → 400 before upstream I/O
   - **Canonical directory binding**:
     - `directory` query: one and only one key (reject duplicate keys → 400)
     - percent-decode exactly once, canonicalize to absolute path via `Path.canonicalize()`
     - canonical path must **equal** constructor `canonical_workspace` → else 403
     - reject percent-encoding ambiguity, `..` segments, symlinks escaping workspace, null bytes
   - `workspace` query key: **explicitly rejected** (known 500 in official) → 400
   - No redirects: proxy never follows 3xx upstream; return response as-is
   - **Header policy**:
     - `Host` header: consumed locally by the proxy HTTP server (required by HTTP/1.1). Reject duplicate/malformed `Host` headers (multiple Host headers or invalid syntax). Never forwarded to upstream.
     - Forwarded headers (allowlist only): `Content-Type`, `Content-Length`
     - All other request headers (including `User-Agent`, `Accept`, `Authorization`, cookies) are **stripped**, not rejected
     - Response headers: only `Content-Type`, `Content-Length` forwarded; all others stripped
     - `Transfer-Encoding`, `Connection`, `Upgrade` and connection-specific headers: reject on request if they indicate upgrade/chunked/smuggling patterns (e.g. `Transfer-Encoding: chunked`, `Connection: upgrade`, or multiple `Transfer-Encoding` values). Simple `Connection: keep-alive` or `Connection: close` is benign and stripped.
     - `Proxy-*` headers: rejected → 400
     - No `X-Forwarded-*` headers added (no need — proxy is transparent loopback)

   **Body bounds & JSON validation** (reject before upstream):

   | Route | Max request body (bytes) | Max response body (bytes) | JSON schema required |
   |-------|--------------------------|----------------------------|----------------------|
   | `POST /session` | 16384 | 4096 | response: `{"id": string}` |
   | `POST /api/session/{id}/prompt` | 16384 | 8192 | request: `{"prompt": {"text": string}}` |
   | `POST /api/session/{id}/question/{rid}/reply` | 16384 | 4096 | request: `{"answers": [[string]]}` |
   | `POST /api/session/{id}/permission/{rid}/reply` | 4096 | 4096 | request: `{"reply": "reject"}` (exact string) |
   | `POST /api/session/{id}/interrupt` | 0 (no body allowed) | 4096 | — |
   | All GET routes | 0 (no body allowed) | per route above | — |

   **SSE handling** (`GET /event`, `directory=<canonical>` only):
   - Protocol: subscribe before session creation (per official: SSE connects first, then create session)
   - Proxy opens upstream connection, reads line-by-line, expects `data: ` prefix
   - Each `data: ` line parsed as JSON `{"id": string, "type": string, "properties": object}`
   - Validate bounds: total observed events ≤ 1000; each SSE frame ≤ 8192 bytes
   - Raw line (including `data: ` prefix and newline) forwarded byte-for-byte to caller
   - Correlate `properties.sessionID` with session created response → proxy holds sessionID mapping
   - Backpressure: synchronous read from upstream, write to caller → no in-memory buffering beyond TCP window
   - **Malformed upstream**: if upstream sends a non-`data:` line, invalid JSON, or oversized frame, the proxy closes the upstream connection, closes the caller connection, and logs a diagnostic. The caller will see a connection close — not necessarily an HTTP 400 (headers may already be sent). The acceptance test must assert connection close + diagnostic, not an HTTP status code.
   - On disconnect: close upstream, transition to reconnect state

   **State machine** (corrected sequence, matches A0 exact frozen event candidates):
   - `audit_only` (initial): V2 commands rejected; `BLOCKED_A0_CERTIFICATE_REQUIRED`
   - After successful `GET /event` → `waiting_server_connected` (subscribe before create)
   - After SSE `server.connected` observed → `server_connected`
   - After `POST /session` returns 2xx and session ID extracted → `session_created`
   - After SSE `session.created` event with matching sessionID via `properties.sessionID` → `provisioned`; V2 prompt now allowed
   - After SSE `question.v2.asked` or `question.asked` observed → `question_pending`; **one and only one** question reply allowed; after forward → back to `provisioned`
   - After SSE `session.diff` observed → allow `GET /session/{id}/diff` (no state change)
   - After SSE `permission.v2.asked` or `permission.asked` observed → `permission_pending`; **one and only one** permission deny (`reply: "reject"`) allowed; after forward → back to `provisioned`
   - Interrupt (`v2.session.interrupt`) **is the Stop action**: allowed in `provisioned`, `question_pending`, `permission_pending`; after successful forward → `stopping`, then on upstream response → `terminal`. No separate Stop event required.
   - Reconnect: after disconnect, start fresh `GET /event` (directory-only), then reissue `GET /session/{id}`, `GET /question`, `GET /permission`, `GET /session/{id}/diff` to restore snapshot. No cursor query (stock SSE does not support it). Explicitly no replay assumption.
   - Unknown method/route given current state → 403
   - Duplicate V2 in same state → 403 (at-most-once)

   **Observations only**: in-memory diagnostic observations of events, actions, and V2 forwards. No durable receipt emission (receipts are later integration, out of A1 scope). Proxy does not load A0 certificate, does not construct `M2CapabilityReceipts`, does not emit official receipts. When A0 certificate is absent (no-credential test case), V2 remains permanently blocked (`audit_only`).

   **Test-only `TestAuthority`**: module-private sentinel class with a private sentinel object, only constructible in test/harness code. `TestAuthority` toggles synthetic V2 forwarding in-process for testing the state machine without a real handshake. It is **nonserializable**, cannot construct capability bundles, cannot emit official receipts, and cannot participate in the handshake protocol. All observations/outputs from this path are labeled `SYNTHETIC_TEST_ONLY`.

   **Run binding handshake** (exact match to frozen `run_binding.rs` protocol):
   - Harness opens bidirectional `socketpair()` before `exec` to Host child
   - Harness passes **separate one-way anonymous inherited FD 3** with 32-byte `binding_secret` (close-on-exec)
   - Proxy retains `binding_secret` in-memory; never writes to log/env/argv
   - Proxy binds `accept()` on random loopback port for control connection
   - When Host connects, proxy calls `run_binding::proxy_handshake()` from `run_binding.rs` contract:
     - Frame format: 4-byte big-endian length + payload; payload: kind(1) + version(1) + tag(1) + len(2) + value
     - Kinds: HELLO(1), HOST_CHALLENGE(2), PROXY_RESPONSE(3)
     - Version = 1, MAX_FRAME = 1024, MAX_FIELD = 256
     - HMAC-SHA256 authenticated challenge-response using `binding_secret`
   - Only after successful handshake does proxy accept V2 commands from Host
   - This matches exactly the existing Rust wire protocol — no new changes

   **Credential invariant**: proxy never reads credential environment variables. No credential handling code in proxy.

   **Shutdown cleanup**: trap SIGTERM/SIGINT, close all connections, close listening socket, exit. Host child reaping is parent/harness responsibility.

2. **No-credential acceptance test** (`testkit/pilot/test_observing_proxy.py`):

   - Uses Python `socketserver`/`http.server` for scripted upstream on random loopback port
   - Serves pre-canned responses matching official sequence:
     1. `GET /event` → SSE stream: `server.connected`, `session.created`, `turn.started`, `message.updated(kind=question)`, `diff.updated`, `permission.updated(status=pending)`
     2. `POST /session?directory=<canonical>` → 200 `{"id": "test-session-1"}`
     3. `GET /session/test-session-1` → 200 session snapshot
     4. `GET /session/test-session-1/diff` → 200 with one diff file
     5. `GET /question` → 200 with one pending question
     6. `GET /permission` → 200 with one pending permission
   - Runs full protocol with real sockets, proxy, and `TestAuthority`
   - Tests all rejection cases:
     - Unknown route → 404
     - Unknown method → 405
     - Unknown query key → 400
     - Duplicate query key → 400
     - `workspace` query → 400
     - Directory doesn't match canonical → 403
     - Percent-encoding ambiguity (`/%2573`) → 400
     - `..` path escape → 400
     - Non-allowlisted header stripped, hop header rejected → 400
     - Upstream 301 redirect returned as-is (no follow)
     - Oversized request body → 413
     - JSON schema mismatch → 400
     - Malformed SSE (no `data: `, invalid JSON, oversized frame) → 400
     - Backpressure: slow upstream, disconnect in middle of SSE → clean shutdown
     - Out-of-order V2 request (prompt before provisioned) → 403
     - Duplicate V2 in same state → 403
     - Cross-session sessionID mismatch → ignored
     - After one V2 forward, not allowed again → 403
     - Exact upstream execution count: one each of prompt/question/permission/interrupt
     - Clean shutdown: all sockets closed, no dangling threads
   - **No credential, no OpenCode, no Rust binary required** for this test

3. **No code changes** in:
   - `connector/src/run_binding.rs` — already PASS, frozen wire protocol
   - `testkit/pilot/iteration3_real_slice.py` — preserve as verifier scaffold
   - `testkit/iteration3_receipts.py` — receipt emission is later integration

**Acceptance** (no credential needed):
```bash
# Python proxy tests (no credential, no OpenCode, no Rust)
python3 -m pytest testkit/pilot/test_observing_proxy.py -v
# → all tests pass (coverage: route validation, state machine, bounds, security rejections)

# Existing Rust tests still pass (no changes)
cd connector && cargo test
# → run_binding tests unchanged, all pass

# Existing verifier scaffold unchanged
python3 testkit/pilot/iteration3_real_slice.py --provider-credential-env DOES_NOT_EXIST --dry-run
# → {"outcome": "SKIP"}
```

**Capability unlocking**: This A1 task does NOT unlock capability. Capability remains blocked until: (1) A0 committed certificate exists, (2) proxy observes live SSE sequence matches certificate, (3) capability digest computed, (4) handshake completes. For this task, proxy stays audit-only when certificate is absent.

---

### Lane B: Verified Capability & Mapper Unlock

**Ownership**: `connector/src/stock_opencode.rs` only. Add `VerifiedM2Capabilities::from_capability_json` constructor.

**Deliverable**:
1. `RealLifecycleEvidence::Captured { structural_digest: String }` — variant for live-captured evidence
2. Compile-time A0 certificate: `const CERTIFIED_LIFECYCLE: &str = include_str!("...")`
3. `VerifiedM2Capabilities::from_capability_json(json: &str) -> Result<Self>`:
   - Deserializes the JSON capability bundle
   - Validates `runtime_provenance_digest` matches M1 committed shapes
   - Validates `source_classification` is `"official_stock_runtime"`
   - Validates `real_lifecycle_evidence.structural_digest` matches the A0 certificate
   - Does NOT trust the JSON for anything else — the structural digest must match the committed certificate
4. The JSON is delivered over FD 3, not from filesystem. Even if saved to disk, it cannot unlock a different run.
5. `StockCommandTransport::execute` already takes `&VerifiedM2Capabilities` — no API change needed.

**Acceptance** (no credential needed):
```bash
cd connector && cargo test
# → all existing tests pass
# → new test: valid capability JSON from A0 certificate passes
# → new test: wrong structural digest fails closed
# → new test: forged capability JSON with wrong provenace fails closed
```

**Dependency**: A0 (certificate must be committed). A1 (run binding format must be agreed).

---

### Lane C: Host Stock Mode

**Ownership**: `connector/src/bin/pilot_host_bridge.rs` only. Add `run_m2_stock_mode`.

**Deliverable**:
1. New `--m2-stock-mode` flag (mutually exclusive with `--m2-safe-mode`):
   - Reads FD 3 for run binding (uses `run_binding.rs` from A1)
   - Challenges proxy → receives bound acknowledgment
   - Constructs `StockCommandTransport` with verified capability
   - Polls Relay for commands, dispatches through `StockCommandTransport`
   - All commands go through proxy, not directly to OpenCode
   - `allow_once` still blocked
   - All IDs aliased via `MobileAliases`
2. Key change: `StockCommandTransport` now targets the proxy port, not OpenCode directly. The proxy forwards to OpenCode.

**Acceptance** (no credential needed):
```bash
cd connector && cargo test
# → all tests pass, new m2-stock-mode arg parsing test
# → new test: challenge-response with mock proxy
```

**Dependency**: A1 (run binding + challenge-response protocol). B (VerifiedM2Capabilities).

---

### Lane D: Orchestration & Verifier

**Ownership**: `testkit/iteration3_receipts.py` (add chain verification). No other files.

**Deliverable**:
1. `verify_complete_integrity_chain` function — validates entire hash chain
2. Correct terminology: integrity hash chain
3. Harness (A1) appends all receipts; D verifies

**Acceptance** (no credential needed):
```bash
python3 -m pytest testkit/ -v
# → all receipt validation tests pass
```

**Dependency**: A1 (harness appends receipts).

---

## Merge Order

```
A0 (discovery, needs credential)
  ↓
A1 (proxy + run binding, can implement/test without credential)
  ↓
B (capability unlock, uses A0 cert, no credential needed)
  ↓
C (host stock mode, uses A1 protocol + B capability, no credential)
  ↓
D (verifier, no credential)
```

## Ownership Table

| Lane | Files | Lang |
|------|-------|------|
| A0 | `testkit/stock-opencode/discover_lifecycle.py` (new)<br>`testkit/stock-opencode/real-task/lifecycle-certificate.json` (new)<br>`testkit/stock-opencode/real-task/project-prompt.txt` (new) | Python |
| A1 | `testkit/pilot/observing_proxy.py` (new)<br>`testkit/pilot/test_observing_proxy.py` (new) | Python only |
| B | `connector/src/stock_opencode.rs` | Rust |
| C | `connector/src/bin/pilot_host_bridge.rs` | Rust |
| D | `testkit/iteration3_receipts.py` | Python |

## Invariants (Preserved)

1. Locked 1.18.16 only
2. Project-owned disposable workspace
3. Credential only in OpenCode subprocess (never in proxy, Host, Relay, receipts)
4. Content-free receipts (no raw IDs, content, credentials)
5. `allow_once=false`
6. No Session Semantics v0 changes
7. No raw upstream facts cross Host boundary (HMAC aliasing)
8. At-most-once upstream (binding digest)
9. No production E2EE/native app/second Agent
10. Preserve `testkit/process-loop/last-transcript.json`
11. Preserve `--dry-run` → SKIP
12. A0 certificate is structural contract only, never sufficient to unlock capability
13. Capability delivered over FD 3 with challenge-response, not env/file/argv

## Verification Commands

```bash
# A0 (requires credential, operator only)
export ANTHROPIC_API_KEY=sk-...
python3 testkit/stock-opencode/discover_lifecycle.py --provider-credential-env ANTHROPIC_API_KEY

# A1 (no credential needed for dry-run)
python3 testkit/pilot/iteration3_real_slice.py --provider-credential-env X --dry-run
cd connector && cargo test  # run_binding tests

# B (no credential needed)
cd connector && cargo test  # capability_from_json tests

# C (no credential needed)
cd connector && cargo test  # m2-stock-mode tests

# D (no credential needed)
python3 -m pytest testkit/ -v

# Full real run (operator only, all lanes merged)
export ANTHROPIC_API_KEY=sk-...
python3 testkit/pilot/iteration3_real_slice.py --provider-credential-env ANTHROPIC_API_KEY
# → {"outcome": "PASS", ...} if all stages complete and receipts verified
```

## Architect Verdict

The contradiction is resolved:
- ✅ Python proxy independently observes SSE, enforces state machine, generates upstream receipts
- ✅ Rust Host receives capability over FD 3 with challenge-response — not forgeable, not env-based
- ✅ A0 certificate is structural contract only, never sufficient to unlock capability
- ✅ No filesystem path trust, no env var capability
- ✅ All 6 corrections from previous rounds addressed
- ✅ Concrete cross-process design with exact Rust/Python responsibilities
