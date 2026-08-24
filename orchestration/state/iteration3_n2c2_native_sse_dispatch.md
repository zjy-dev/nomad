# Iteration 3 N2c2 Native SSE Dispatch

Status: N2C2A AND N2C2B FROZEN / EXTERNAL PRODUCT GATE

## Boundary

N2c2 remains a test-feature-only Rust mechanics slice. It may observe a fixed
OpenCode event stream and recover read-only snapshots. It does not add command
routes, Provider access, production release authority, Host approval, or a path
from the default `nomad-supervisor`, which remains zero-spawn. Python SSE code is
only a behavioral reference and supplies no authority.

N2c1 is frozen. Its exact six inherited descriptors, descriptor validation,
canonical authenticated config, workspace device/inode binding, run binding,
READY ordering, numeric loopback upstream, secret zeroization, and content-free
failure surface remain mandatory. Shared helpers may be extracted only without
weakening the frozen N2c1 process tests.

## Staged delivery

N2c2a is one authenticated proxy process, one accepted client, and one upstream
`GET /event` stream. There is no reconnect. N2c2b is held until N2c2a has an
independent P0/P1/P2 PASS. N2c2b permits exactly this single recovery order:
first-stream EOF, four fixed read-only snapshot requests, a fixed 100 ms local
backoff, then at most one reconnect.

## N2c2a exact contract

- Client request is exactly HTTP/1.1 `GET /event` with the exact listener Host.
  Query strings, request bodies, `Content-Length` other than `0`,
  `Transfer-Encoding`, `Upgrade`, `Authorization`, `Cookie`, proxy headers and
  `Last-Event-ID` are rejected before upstream network I/O.
- The proxy creates exactly one TCP connection to the HMAC-bound numeric
  `http://127.0.0.1:<port>` upstream and emits a reconstructed
  `GET /event HTTP/1.1` request with exact Host,
  `Accept: text/event-stream`, `Cache-Control: no-cache`, and
  `Connection: close`. It never uses DNS, redirects, caller-selected origins,
  or proxy environment variables.
- The upstream response must be HTTP/1.1 status 200, exactly one
  `Content-Type: text/event-stream` value (parameters forbidden), no
  `Content-Length`, no `Transfer-Encoding`, no redirect, no upgrade and no
  authentication/cookie headers. The proxy commits the client 200 response only
  after these headers validate. A later stream error closes the client stream;
  it cannot emit a second HTTP response.
- Only LF and CRLF line endings are accepted; one stream must use one style. A
  line is at most 8192 bytes including terminator, one event is at most 32768
  bytes, the stream is at most 256 events and 1 MiB, and one event must finish
  within a 2 second idle deadline. Total process deadline is 15 seconds. Client
  write/backpressure shares the remaining total deadline.
- Empty lines delimit events. Blank events and comment lines are rejected. BOM,
  NUL, bare CR, invalid UTF-8, unknown fields, field names without a colon, and
  whitespace before a field are rejected. Only `data:` is accepted. `event:`,
  `id:`, `retry:` and every other field are rejected, so N2c2a has no cursor or
  caller-controlled reconnect state.
- A single event contains exactly one `data: ` line. Empty data and multiline
  data are rejected. Its payload is strict UTF-8 JSON with recursive duplicate
  keys and trailing values rejected. Exact top-level schema is
  `{"id": string, "type": string, "properties": object}`. All strings and
  aggregate JSON bytes stay within the event bound.
- Event `id` is a safe ASCII identifier of 1..256 bytes and must be unique in
  the stream. `type` is nonempty safe ASCII of at most 256 bytes. If
  `properties.sessionID` exists it must equal the HMAC-bound fixed session ID;
  a missing session ID is accepted only for `server.connected`. Unknown event
  types are observed but cannot create command authority.
- The proxy forwards only fully validated, canonically reconstructed
  `data: <canonical-json>\n\n` events. It never forwards partial or invalid
  upstream bytes. Normal upstream EOF is success only after an event boundary
  and at least one valid event. Client disconnect is a bounded failure for this
  mechanics slice.
- Repeated event IDs, malformed events, partial EOF, idle timeout, total
  timeout, client backpressure and upstream errors fail closed. Exactly one
  upstream hit is permitted and the process exits after the one stream.

## N2c2b exact contract

- Activated only after N2c2a freezes. Only a clean EOF after at least one fully
  validated event may trigger at most one reconnect cycle. Empty streams,
  partial EOF, malformed frames, timeouts, authentication failures and policy
  failures terminate without reconnect. There is no unbounded retry loop and
  no server-provided `retry:`.
- `Last-Event-ID` remains forbidden. Recovery does not assume an upstream cursor.
  It performs exactly four HMAC-bound fixed GETs in order:
  `/session/<fixed>`, `/question`, `/permission`,
  `/session/<fixed>/diff`, using the frozen N2c1 JSON response policy.
- Snapshot responses are kept only in bounded in-memory observation state and
  are not authority. No POST or v2 route is issued. Recovery then creates at
  most one new `GET /event` connection. Maximum counts are six upstream hits:
  first stream + four snapshots + one reconnect.
- A duplicate event ID across the two streams is dropped without delivery. New
  event IDs preserve arrival order. There is no numeric ordering inference. A
  fixed bound of 256 total delivered events and 1 MiB total event bytes spans
  both streams. Snapshot bytes have the N2c1 per-response bounds.
- One 15 second total run deadline covers both streams, the fixed 100 ms local
  backoff, all snapshots and client writes. No individual step resets it. Any
  uncertain result closes the client and exits content-free.

## Atomic packages and ownership

### S1: N2c2a parser and single-stream process

Owner files: `connector/src/native_sse_proxy.rs`,
`connector/src/bin/native_sse_proxy.rs`, the minimal feature/export wiring in
`connector/Cargo.toml` and `connector/src/lib.rs`, and
`connector/tests/native_sse_proxy_process_tests.rs`. It may extract a small
crate-private no-policy bootstrap helper from `native_audit_proxy.rs`, but N2c1
behavior and all nine frozen process tests must remain unchanged.

Real-process acceptance matrix:

1. exact client GET produces one upstream hit and two canonical complete events;
2. ordinary client does not half-close; slow split UTF-8 and CRLF frames work;
3. wrong HMAC/workspace/FD kind blocks before READY and before upstream hit;
4. POST, query, Last-Event-ID, body, TE, duplicate Host and unknown route have
   zero upstream hits;
5. redirect/wrong content type/content length/chunked/duplicate response headers
   close without committing success;
6. oversized line/event/stream/count, duplicate ID/session mismatch, duplicate
   JSON keys, multiline data, comments/event/id/retry, BOM/NUL/bare CR, partial
   EOF and trailing JSON close without forwarding the invalid event;
7. stalled header/event and non-reading client terminate within the shared
   bound; stdout/stderr remain empty; exact one-hit semantics hold.

Independent architecture/security audit must return P0/P1/P2 zero before S2.

### S2: N2c2b one-reconnect recovery

Owner files: a new `connector/src/native_sse_reconnect.rs`, feature-gated binary
and process tests. It composes frozen S1 parsing and frozen N2c1 response parsing
through crate-private typed helpers; it does not copy permissive parsers.

Real-process acceptance matrix:

1. first EOF -> four ordered snapshots -> 100 ms backoff -> one reconnect, with
   exact six upstream hits;
2. duplicate ID across streams delivers once, new IDs preserve arrival order;
3. malformed or empty first stream, bad snapshot, second EOF, timeout and client backpressure
   stop with no third stream and no write request;
4. capture every upstream request and prove absence of POST, `Last-Event-ID`,
   credential, proxy env and caller-selected route/origin;
5. all descriptors close and child exits inside the one total deadline.

Independent architecture/security audit must return P0/P1/P2 zero before N2c2
is frozen.

## Evidence boundary after N2c2

N2c2 proves only native, bounded, read-only HTTP/SSE transport mechanics against
local deterministic peers. A real Controlled Pilot still requires externally
provided production release trust, Developer ID Host identity, SSHSIG approval
and trust root, protected-ref CAS/publication, an allowlisted temporary Provider
credential, official stock OpenCode installed from the locked package closure,
and same-run Provider-backed lifecycle evidence independently reviewed. None of
those gates may be synthesized by repository code, tests, agents, or ordinary CI.
