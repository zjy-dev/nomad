# Iteration 3 M2 A1 Observing Proxy Dispatch (SUPERSEDED)

**This dispatch is superseded for execution by `iteration3_m2_a1_proxy_atomic_dispatch.md`.** The new atomic dispatch splits A1 into 3 sequential bounded packages (A1.1 HTTP/V2, A1.2 SSE/reconnect, A1.3 run-binding/final audit) with exact test counts, freeze conditions, and no parallel ownership. Refer to that file for implementation.

The content below is retained for reference only.

## Purpose

This is the sole authoritative dispatch for the A1 `observing_proxy.py` implementation task. The older `iteration3_m2_real_integration_dispatch.md` contains historical context only and is non-normative for this task.

**Task**: Implement an audit-only typed fixed-route gateway in Python, can be built/tested without credential, following the exact specifications below. No capability unlock, no receipt emission, no A0 certificate loading, no Rust changes.

## Ownership

- `testkit/pilot/observing_proxy.py` (new) — Python implementation
- `testkit/pilot/test_observing_proxy.py` (new) — no-credential scripted acceptance tests
- No changes to: `testkit/pilot/iteration3_real_slice.py` (preserve as verifier scaffold), `connector/src/run_binding.rs` (already PASS/frozen), `testkit/iteration3_receipts.py` (receipt emission is later integration)

## Invariants

1. **Audit-only by default**: V2 commands permanently blocked → `BLOCKED_A0_CERTIFICATE_REQUIRED` until later integration
2. No capability construction, no receipt emission, no A0 certificate loading
3. Credential never in proxy env/argv/log/receipts — proxy never reads credential environment variables
4. Preserve `--dry-run` → SKIP
5. Preserve `testkit/process-loop/last-transcript.json`
6. `allow_once=false` (still blocked)

## Exact Route Table (official 1.18.16, corrected)

| Method | Path Template | Query Keys (allowlist only) | operationId | Notes |
|--------|---------------|------------------------------|-------------|-------|
| GET | `/global/health` | none | — | pass-through |
| POST | `/session` | `directory` only | `session.create` | directory must match constructor canonical workspace exactly |
| GET | `/session/{sessionID}` | `directory` only | — | directory must match constructor canonical workspace exactly |
| GET | `/session/{sessionID}/diff` | `directory` only | `session.diff` | directory must match constructor canonical workspace exactly |
| GET | `/event` | `directory` only | `event.subscribe` | official: no `sessionID` query; correlate via `properties.sessionID` in SSE |
| GET | `/question` | `directory` only | `question.list` | directory must match constructor canonical workspace exactly |
| GET | `/permission` | `directory` only | `permission.list` | directory must match constructor canonical workspace exactly |
| POST | `/api/session/{sessionID}/prompt` | none | `v2.session.prompt` | allowed only after `provisioned` state |
| POST | `/api/session/{sessionID}/question/{requestID}/reply` | none | `v2.session.question.reply` | at most one, after `question_pending` |
| POST | `/api/session/{sessionID}/permission/{requestID}/reply` | none | `v2.session.permission.reply` | at most one, after `permission_pending` |
| POST | `/api/session/{sessionID}/interrupt` | none | `v2.session.interrupt` | one-shot interrupt |

## Validation Rules (reject before upstream)

1. **Path**: literal after expansion; no regex/prefix/wildcard
2. **Path params**: `sessionID`/`requestID` must match `^[A-Za-z0-9_-]{1,256}$` → 400 if mismatch
3. **Query**: allowlist per route only — any extra/unknown key → 400
4. **Directory**:
   - one and only one `directory` key → reject duplicates → 400
   - percent-decode exactly once, canonicalize to absolute path → `Path.canonicalize()`
   - canonical must **equal** constructor `canonical_workspace` → 403 if mismatch
   - reject percent-encoding ambiguity, `..` segments, symlinks escaping workspace, null bytes
   - `workspace` query key → explicitly rejected → 400
5. **Headers**:
   - `Host`: consumed locally by proxy HTTP server; reject duplicate/malformed → 400; never forwarded
   - Only `Content-Type`, `Content-Length` forwarded to upstream; all others stripped
   - Response: only `Content-Type`, `Content-Length` forwarded from upstream; all others stripped
   - `Transfer-Encoding`, `Connection: upgrade`, multiple `Transfer-Encoding` → reject → 400; simple `keep-alive`/`close` stripped
   - `Proxy-*` → reject → 400; no `X-Forwarded-*` added
6. **Body bounds**:

| Route | Max request body (bytes) | Max response body (bytes) | JSON schema required |
|-------|--------------------------|----------------------------|----------------------|
| `POST /session` | 16384 | 4096 | response: `{"id": string}` |
| `POST /api/session/{id}/prompt` | 16384 | 8192 | request: `{"prompt": {"text": string}}` |
| `POST /api/session/{id}/question/{rid}/reply` | 16384 | 4096 | request: `{"answers": [[string]]}` |
| `POST /api/session/{id}/permission/{rid}/reply` | 4096 | 4096 | request: `{"reply": "reject"}` (exact string) |
| `POST /api/session/{id}/interrupt` | 0 (no body allowed) | 4096 | — |
| All GET routes | 0 (no body allowed) | per route above | — |

## SSE Handling (`GET /event`)

- Protocol: subscribe before session creation (SSE connects first, then create session)
- Each `data: ` line parsed as JSON `{"id": string, "type": string, "properties": object}`
- Validate bounds: total events ≤ 1000; each frame ≤ 8192 bytes
- Raw line forwarded byte-for-byte to caller
- Correlate `properties.sessionID` with session created response
- Synchronous read/write — no buffering beyond TCP window
- **Malformed upstream**: close connections, log diagnostic. Caller sees connection close (not necessarily HTTP 400). Test asserts this.
- On disconnect: close upstream, transition to reconnect

## State Machine (matches A0 frozen event candidates)

- `audit_only` (initial): V2 rejected → `BLOCKED_A0_CERTIFICATE_REQUIRED`
- After successful `GET /event` → `waiting_server_connected`
- After SSE `server.connected` → `server_connected`
- After `POST /session` 2xx + session ID extracted → `session_created`
- After SSE `session.created` with matching sessionID → `provisioned`; V2 prompt allowed
- After SSE `question.v2.asked` OR `question.asked` → `question_pending`; one question reply allowed; after forward → `provisioned`
- After SSE `session.diff` → allow `GET /session/{id}/diff` (no state change)
- After SSE `permission.v2.asked` OR `permission.asked` → `permission_pending`; one permission deny (`reply: "reject"`) allowed; after forward → `provisioned`
- Interrupt **is the Stop action**: allowed in `provisioned`, `question_pending`, `permission_pending`; after successful forward → `terminal`
- Reconnect: after disconnect, start fresh `GET /event` (directory-only), then reissue `GET /session/{id}`, `GET /question`, `GET /permission`, `GET /session/{id}/diff` to restore snapshot. No cursor query (stock SSE does not support it). No replay assumption.
- Unknown method/route given current state → 403
- Duplicate V2 in same state → 403 (at-most-once)

## Run Binding (exact match to frozen `run_binding.rs` protocol)

Two distinct inherited channels, both close-on-exec for unrelated children. Exact FD numbers are harness-assigned (not protocol constants). Example: bidirectional on FD 3, one-way secret on FD 4.

1. **Bidirectional socketpair** (handshake stream):
   - Harness opens `socketpair(AF_UNIX, SOCK_STREAM, 0)` before `exec`
   - Proxy holds one end, Host inherits the other
   - Protocol: `proxy_handshake()` (Python side) uses same frame format as Rust: 4-byte big-endian length + payload; payload = kind(1) + version(1) + tag(1) + len(2) + value
   - Kinds: HELLO(1), HOST_CHALLENGE(2), PROXY_RESPONSE(3)
   - Version = 1, MAX_FRAME = 1024, MAX_FIELD = 256
   - HMAC-SHA256 authenticated challenge-response using `binding_secret`

2. **Separate one-way anonymous pipe** (32-byte `binding_secret`):
   - Harness generates 32-byte from CSPRNG
   - Passes to Host via inherited pipe with exact 32-byte read
   - Proxy retains in-memory; never in env/argv/file/receipts
   - `binding_secret` never sent on bidirectional stream; only hashed into HMAC

**Sequence**:
1. Proxy listens on random TCP loopback port for HTTP
2. Harness passes the already-open bidirectional socket to Host
3. Host connects to proxy HTTP port, performs handshake on the inherited socket
4. Only after successful handshake does proxy accept V2 commands from Host

## Constructor & TestAuthority

- **Production factory**: `ObservingProxy(upstream_origin: str, canonical_workspace: Path, run_id: str)` — audit-only, V2 blocked. No capability/secret/challenge parameters — these are supplied via separate inherited channels.
- **Test-only factory**: `ObservingProxy.with_test_authority(...)` — module-private, `TestAuthority` is a module-private sentinel. Toggles synthetic V2 forwarding for testing state machine without real handshake. **Nonserializable**, cannot construct capability bundles, cannot emit official receipts. All outputs labeled `SYNTHETIC_TEST_ONLY`.

## No-credential Acceptance Test (`test_observing_proxy.py`)

- Python `socketserver`/`http.server` scripted upstream on random loopback port
- Pre-canned responses matching official sequence:
  1. `GET /event` → SSE: `server.connected`, `session.created`, `question.v2.asked`, `session.diff`, `permission.v2.asked`
  2. `POST /session?directory=<canonical>` → 200 `{"id": "test-session-1"}`
  3. `GET /session/test-session-1` → 200 snapshot
  4. `GET /session/test-session-1/diff` → 200 with one diff
  5. `GET /question` → 200 with one pending question
  6. `GET /permission` → 200 with one pending permission
- Tests all rejection cases: unknown route/method/query, duplicate query, `workspace` query, directory mismatch, percent ambiguity, `..` escape, oversized body, JSON mismatch, malformed SSE, backpressure disconnect, out-of-order V2, duplicate V2, cross-session mismatch, clean shutdown
- **No credential, no OpenCode, no Rust binary** required

## Acceptance Commands

```bash
# Run tests (no credential needed)
python3 -m pytest testkit/pilot/test_observing_proxy.py -v
# → all tests pass

# Existing Rust tests unchanged
cd connector && cargo test
# → all pass

# Existing verifier scaffold unchanged
python3 testkit/pilot/iteration3_real_slice.py --provider-credential-env DOES_NOT_EXIST --dry-run
# → {"outcome": "SKIP"}
```

## Summary

- Two new Python files, no changes to existing code
- Audit-only typed fixed-route gateway
- No capability unlock, no receipt emission, no A0 certificate usage
- Security: all validation before upstream I/O; eliminates SSRF/smuggling by construction
- Complete and testable without credential
