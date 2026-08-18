# Iteration 2 Same-Origin Pilot Gateway Report

- Status: implemented locally; non-loopback deployment still requires real TLS material and Security DRI review
- Runtime: Node standard library, no new package dependency

The Gateway serves the Mobile build and `/api/pilot/*` from one origin. The
Relay Bearer token remains server-side. A browser POST receives
`RelayReceived`; only a later Host `pilot.command.result` yields HostAccepted or
Rejected. It consumes the full `pilot.session` checkpoint and fails closed for
unknown or missing facts. A diff without verified baseline remains invalid and
is never rendered as authoritative.

Non-loopback binds are rejected unless `--tls-cert` and `--tls-key` are
provided. The server sets same-origin CSP, no-store, no-referrer and nosniff,
does not enable CORS, limits JSON to 64 KiB and never logs bodies or tokens.
The default Mobile composition now uses the same-origin `HttpSessionClient`;
deterministic data is available only through explicit `?demo=1` or `?lab=1`.

Verification: `npm run test:gateway` covers current Session decoding, invalid
baseline, RelayReceived/HostAccepted separation and the TLS bind guard. Mobile
unit/build/browser suites remain required in the root acceptance run.
