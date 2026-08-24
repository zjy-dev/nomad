# Iteration 3 N1 Rust-owned Locked OpenCode Dispatch

Status: ARCHITECTURE FROZEN / N1a AND N1b DISPATCHED / INTEGRATION HELD

## Product boundary

N1 moves locked OpenCode process ownership and live-image measurement into
Rust. It never consumes a Python measurement, registry, verdict, digest claim,
or success marker. The N0 production entry remains blocked at native Host
publication verification, so N1 is not reachable from production yet and does
not weaken N0 zero-spawn behavior.

The current machine is Darwin arm64 with npm 11.12.1, but no allowlisted
temporary Provider credential is present. Therefore N1 can prove native input,
process, OS-image, and cleanup mechanics; it cannot claim a Provider-backed
official OpenCode run in this iteration.

## N1a: immutable stock input verifier

Owner: dedicated Rust worker. Files: new `connector/src/native_launch/inputs.rs`
and focused colocated tests only. It must not edit Cargo, lib.rs, N0, Python,
Host, proxy, or transport files.

It embeds and strictly validates the reviewed OpenCode package and lock bytes,
the disposable task specification, fixture manifest, and project prompt. JSON
parsing rejects duplicate keys, trailing values, unknown fields, invalid types,
and unbounded structures. It verifies official OpenCode 1.18.16, npm 11.12.1,
registry-only dependency sources, full closure, Darwin-arm64 selected closure,
task and fixture contracts, and exact fixture content hashes. It returns only a
private Rust facts value to its parent module.

## N1b: Darwin live executable verifier

Owner: dedicated Rust worker. Files: new
`connector/src/native_launch/darwin.rs` and focused colocated tests only. It
must not edit Cargo, lib.rs, N0, Python, Host, proxy, or transport files.

On Darwin arm64 it uses libproc directly to bind the exact owned Child PID and
parent, nonzero stable start time, runnable/sleeping state, non-exiting status,
pre-open read-only CLOEXEC executable FD, canonical path, stable vnode and raw
digest, and two stable bounded executable-region enumerations. Other platforms
fail closed. Test-only seams may inject an OS reader but cannot construct or
export production launch authority.

## N1c: native launcher integration

Held until N1a/N1b focused review. Owner will receive new
`connector/src/native_launch.rs`, its process tests, and minimal private module
wiring. It will validate credential name before resources, create a 0700 owned
temporary tree, materialize only verified fixed bytes with 0600 exclusive files,
run a fixed reviewed npm executable with bounded output and cleanup, recompute
installed closure, pre-open and spawn the exact native OpenCode image, perform
bounded loopback health and N1b verification, revalidate all mutable facts, and
return a private non-cloneable Rust owner. Explicit cleanup must terminate, kill
if necessary, reap, close, delete only the owned root, and verify absence.

The production npm/node path policy is not supplied by the current fnm session.
Only a test-only path seam may be used now. A test launch marker is mechanics
evidence and cannot flow into N0 production authority. N2 proxy and Host three-FD
transport remain out of scope.

## Gates

- N1a and N1b each need focused tests, fmt, clippy, and independent review.
- N1c begins only when their facts and ownership APIs are aligned.
- Default `nomad-supervisor`, even with fake credentials, PATH, or TMPDIR, must
  still create zero children and zero temporary resources.
- A real official OpenCode launch requires an allowlisted temporary Provider
  credential and will be reported separately; stub/helper launches do not count.
- No N1 result authorizes commands, capabilities, receipts, proxy, or Host.
