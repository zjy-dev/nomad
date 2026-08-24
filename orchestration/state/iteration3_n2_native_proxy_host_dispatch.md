# Iteration 3 N2 Native Proxy and Host Transport Dispatch

Status: N2A, N2B AND N2C FROZEN / PRODUCTION STILL ZERO-SPAWN

N2 remains test-only while N0 production Host publication and Provider gates
are unavailable. N2a moved canonical NOMADALP construction, four independent
random values, exact three-FD inheritance, Rust proxy handshake, bounded
writers/readers and child cleanup into one Rust parent. A real
`actual-launch-adopter` accepts the transport; this does not prove OpenCode or
production Host execution.

N2b1 adds a feature-gated native proxy peer child. The parent owns a pre-bound
loopback listener and passes exactly listener, binding socket, secret reader and
canonical config reader. The child verifies descriptor types and directions,
run/nonce/claim, exact secret EOF and loopback origin, calls the existing Rust
`proxy_handshake`, and emits one exact ready marker. It does not forward HTTP or
create command authority.

N2b2 will compose that proxy child with the adopter and then exercise default
`nomad-host`, which must retain its expected production-release blocker. HTTP
audit forwarding and Provider-backed evidence remain later gates.
