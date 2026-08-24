# Iteration 3 N0 Native Supervisor Dispatch

Status: ARCHITECTURE FROZEN / IMPLEMENTATION IN PROGRESS

## Decision

Production launch authority does not live in the Python interpreter. Python
objects, module registries, private tokens, verifier exit markers, and JSON
verdicts are diagnostics or test mechanics only. They cannot authorize a child
process.

The production boundary is one native Rust `nomad-supervisor` process. It is
the only future owner of production verification, run secrets, OpenCode, the
audit-only proxy, the exact Host image, inherited descriptors, and cleanup.
N0 implements only the first gate; it launches none of those children.

## Why the previous direction failed

An independent audit demonstrated that same-interpreter Python code can create
an exact-class object with `object.__new__`, populate slots with
`object.__setattr__`, and directly alter a module-level registry. Weak
registries and immutable snapshots detect accidental substitution and
post-issuance mutation, but they are not a production security boundary. More
Python privacy conventions would not change that fact.

The corrected architecture changes the isolation boundary instead of adding
another token or registry.

## N0 scope

N0 adds a Rust `nomad-supervisor` binary and native authority module. The
production path:

1. reads only fixed production inputs;
2. reuses the strict embedded NOMADREL parser and current embedded approval
   checks;
3. independently binds the runtime Host publication, immutable release
   identity, approval, and opened Host file;
4. retains an owned Host descriptor, file identity, and raw digest in a
   private, non-cloneable and non-serializable Rust value;
5. blocks if native Git, SSHSIG, Developer ID, or fixed-path verification is
   not yet complete; and
6. returns before creating a proxy, socket, pipe, temporary runtime, OpenCode
   child, or Host child whenever any production prerequisite is unavailable.

N0 test features may exercise an isolated test authority and emit
`NATIVE_SUPERVISOR_AUTHORITY_READY`. That marker is not compiled into or
accepted by the default production path and is not product-readiness evidence.

## Forbidden inputs and effects

- no Python object, registry, object identity, digest claim, or success marker;
- no caller-selected Host, release, trust, Git ref, Python interpreter, or tool
  path;
- no environment-selected path or digest;
- no command or capability authorization;
- no Provider credential read in N0;
- no proxy, socketpair, pipe, OpenCode child, or Host child in N0;
- no modification of protected refs, trust roots, signatures, or release data.

## Acceptance

- default build with absent production release/trust returns the stable native
  blocker and creates zero children/resources;
- arbitrary Python PASS output and environment variables cannot affect it;
- caller-supplied and test-feature authority cannot enter the production
  function;
- Host verification retains the exact opened file identity and digest, with no
  verify-by-path then spawn-by-replaced-path gap;
- build, unit, integration, formatting, lint, and independent adversarial audit
  pass; and
- the result is reported as N0 authority-gate mechanics, not an OpenCode or
  Host launch and not a real product pass.

## Strict sequencing

N1 (Rust-owned official OpenCode launch and Darwin live-image binding) starts
only after N0 independent P0/P1/P2 PASS. N2 (Rust-owned proxy and authenticated
three-FD Host transport) starts only after N1 independently passes.
