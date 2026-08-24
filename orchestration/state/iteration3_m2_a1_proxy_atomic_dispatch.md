# A1 Observing Proxy Atomic Dispatch (SOLE WORKER AUTHORITY)

**Supersedes**: `iteration3_m2_a1_proxy_dispatch.md` (non-normative for execution). `iteration3_m2_real_integration_dispatch.md` (historical only).

**Files**: `testkit/pilot/observing_proxy.py` + `testkit/pilot/test_observing_proxy.py`. No other files.

**Baseline**: 221-line proxy + 66-line test (26 tests). Three sequential packages below, each with a freeze condition. No parallel ownership. No capability/receipt/certificate scope.

---

## A1.1: HTTP Transport & V2 Framing (current baseline ~26 tests)

**Baseline**: routes, directory binding, header policy, body bounds, V2 prepare/commit, upstream forwarding, test\_authority toggle. Real HTTP forward exists (test26) but coverage is thin.

**Bounded changes** (both files):
- `observing_proxy.py`: add `Content-Type` enforcement on POST (not just v2), `Content-Length` parsing hardening, `Host` header validation per HTTP/1.1 spec, short-body rejection (read returns fewer bytes than Content-Length)
- `test_observing_proxy.py`: add tests for:

| # | Test | Detail |
|---|------|--------|
| 27 | real prompt forward | HTTP POST /prompt → upstream receives 1 call, proxy returns 200, state committed |
| 28 | real question forward | question_pending state → POST /question/{rid}/reply → upstream 1 call, 200 |
| 29 | real permission forward | permission_pending state → POST /permission/{rid}/reply {"reply":"reject"} → 200 |
| 30 | real interrupt forward | provisioned state → POST /interrupt → 200, state terminal |
| 31 | prepare->2xx commit | V2 forward with 2xx upstream → `_seen` includes action, state transitioned |
| 32 | duplicate block | same V2 action after first forward → 403, no upstream call |
| 33 | non-2xx no commit | upstream returns 500 → proxy returns 500, state unchanged, `_seen` empty |
| 34 | connection ambiguity | upstream unreachable → proxy returns 502, `OutcomeUnknown` semantics (no retry), state unchanged |
| 35 | CL/TE rejection | `Transfer-Encoding: chunked` → 400, no upstream; duplicate Content-Length → 400 |
| 36 | short body | Content-Length: 100, body: 10 bytes → 400 |
| 37 | response bounds | upstream response > limit → proxy closes, returns 502 |
| 38 | redirect | upstream 301 → proxy returns 301 as-is (no follow) |
| 39 | Content-Type on POST | non-JSON Content-Type on POST → 400 |
| 40 | exact forward counts | full sequence: prompt(1), question(1), permission(1), interrupt(1) → exactly 4 upstream calls |

**Freeze**: ≥35 total tests, all pass. No regressions on existing tests.

**Acceptance**: `python3 -m pytest testkit/pilot/test_observing_proxy.py -v && cd connector && cargo test`

---

## A1.2: SSE & Reconnect Convergence

**Baseline**: `observe_sse()`, `_sse()`, `reconnect_snapshot()`, state machine transitions. SSE tests (19-20) cover malformed JSON and event limit only.

**Bounded changes** (both files):
- `observing_proxy.py`: ensure `_sse` calls `observe_sse` *before* forwarding each frame (currently order unclear); ensure `reconnect_snapshot` always emits exactly 4 GETs; add `ThreadingHTTPServer` thread join in `shutdown`; refuse second `start()` call
- `test_observing_proxy.py`: add tests for:

| # | Test | Detail |
|---|------|--------|
| 41 | SSE before create | subscribe `/event` before `POST /session` → correct sequence: server.connected → session.created |
| 42 | full event flow | subscribe → server.connected → session.created → question.v2.asked → session.diff → permission.v2.asked → all V2 actions in order |
| 43 | snapshot GETs | after session.created → GET /session/{id} (200) |
| 44 | malformed SSE | upstream sends non-`data:` line → proxy closes connections, caller sees close (not 400) |
| 45 | oversized SSE frame | `data:` line > 8192 bytes → proxy closes connections |
| 46 | backpressure | slow reader on caller side → no crash, eventual clean close |
| 47 | disconnect mid-stream | upstream disconnect mid-event → proxy transitions to `reconnect` state |
| 48 | reconnect_snapshot | after disconnect → exactly 4 GETs: `/session/{id}`, `/question`, `/permission`, `/session/{id}/diff` |
| 49 | no cursor | reconnect does NOT use `Last-Event-ID` or any SSE cursor query |
| 50 | clean threads | after shutdown → no dangling threads, `is_alive()` false for all |

**Freeze**: ≥50 total tests, all pass. No regressions on A1.1 tests.

**Acceptance**: `python3 -m pytest testkit/pilot/test_observing_proxy.py -v`

---

## A1.3: Run-Binding Python Peer + Final Audit

**Baseline**: `proxy_handshake()`, `_mac()`, `_read()`, `_write()`, `_frame()` all exist. Test21 (handshake), test22 (bad MAC), test23 (compatibility vector with hardcoded HMAC).

**Bounded changes** (both files):
- `observing_proxy.py`: ensure `proxy_handshake` validates all frame fields (kind, version, field count, tag values); add `HostRunBinding`-style Python peer for future integration (struct with `challenge` + `secret` + `used` flag, `handshake()` method); ensure `_write` enforces `MAX_FRAME` before sending; ensure `_read` rejects zero-length frames
- `test_observing_proxy.py`: add tests for:

| # | Test | Detail |
|---|------|--------|
| 51 | secret absent | `proxy_handshake` with `binding_secret` length != 32 → raises `ProxyError` |
| 52 | HMAC vector | second compatibility vector with different secret/challenge → matches hardcoded Rust output |
| 53 | bad MAC (host) | host MAC wrong → `proxy_handshake` raises `authentication` |
| 54 | bad MAC (proxy) | proxy MAC wrong → `HostRunBinding.handshake` raises `Authentication` |
| 55 | duplicate handshake | second `proxy_handshake` on same socket → IO error / frame error |
| 56 | field bounds | `_frame` with value > MAX_FIELD → raises `ProxyError('field')` |
| 57 | partial IO | `_recv_exact` interrupted mid-read → raises `ProxyError('frame')` |
| 58 | zero-length frame | `_read` receives 4-byte length = 0 → raises `ProxyError('frame')` |
| 59 | production audit-only | `ObservingProxy` (no test authority) → all V2 routes return 403 `BLOCKED_A0_CERTIFICATE_REQUIRED` |
| 60 | TestAuthority non-serializable | `pickle.dumps(_AUTHORITY)` → `TypeError` |
| 61 | file ownership | `observing_proxy.py` diff: only proxy code, no receipt/capability/certificate |
| 62 | regression | all A1.1 + A1.2 tests still pass |

**Freeze**: ≥62 total tests, all pass. `cd connector && cargo test` all pass. No changes outside two files.

**Acceptance**: `python3 -m pytest testkit/pilot/test_observing_proxy.py -v && cd connector && cargo test`

---

## Notes

- No capability unlock, receipt emission, or A0 certificate loading in any package
- No Rust changes in any package
- Each package freezes before next starts; rework loops within package only
- Test numbering: start at 27 (A1.1), 41 (A1.2), 51 (A1.3) — monotonically increasing, no gaps