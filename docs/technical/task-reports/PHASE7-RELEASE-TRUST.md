# P7-E Release Trust Scaffold

Status: NOT_RUN (PRODUCTION_RELEASE_TRUST_NOT_RUN). Mechanical checks pass,
but production readiness is false.

The new read-only verifier consumes a canonical `nomad.release-trust.v1` fact
record. It binds source commit and clean-worktree facts, canonical provenance
digest, bundle digest, nested Mach-O pre/post-sign digests, Developer ID team
and certificate facts, notarization/ticket/staple/spctl facts, and
publication/download digests. It never independently invokes or validates the
complete Developer ID, notarization, staple, Gatekeeper, publication, and
download chain. Missing credentials, ad-hoc/unsigned
facts, rejected/missing tool facts, and digest mismatches fail closed as
`NOT_RUN` or `BLOCKED`.

Fixtures under `testkit/release-trust` cover a mechanical pass plus tampered
team identity, notary/staple status, and download digest mismatch. Fixture
success is not Developer ID, notarization, publication, or production
evidence. Actual `codesign`, `xcrun`, and `spctl` integration must be a
separately authorized, read-only collection step with protected credentials.

Even when every mechanical check passes, the verifier returns NOT_RUN, reports
mechanical_checks_passed=true and production_ready=false, and exits nonzero.
PASS remains unreachable until a future real mode independently validates the
complete protected release and publication chain.
