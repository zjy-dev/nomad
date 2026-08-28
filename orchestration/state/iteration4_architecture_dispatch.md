# Iteration 4 Architecture Dispatch

Status: ARCHITECTURE APPROVED / EXTERNAL GATE PRESERVED

## Decision

Phase 4 separates three classes of work:

- A: repository-local work that reduces the risk of executing the real Pilot
  without fabricating trust;
- B: external-owner inputs that code, tests, agents, and ordinary CI cannot
  synthesize;
- C: production composition and four-hop validation, which start only after
  the required B inputs are independently verified.

The frozen N0/N1/N2 mechanisms remain engineering evidence. The default
`nomad-supervisor` remains zero-spawn until production release, Host identity,
SSHSIG/KRL/trust, protected CAS, and real Provider-backed evidence are present.

## Dependency DAG

```text
A0 read-only readiness doctor ───────┐
A1 agent-neutral contract audit ────┼──> A4 operator handoff
                                    │
B1 temporary Provider credential ──┤
B2 Developer ID Host/notarization ─┤
B3 SSHSIG trust/KRL/approval ──────┤──> C1 production supervisor composition
B4 protected CAS/publication ──────┤       └──> C2 real four-hop run
B5 locked official OpenCode ───────┘                └──> Pilot go/no-go
```

## Agent-neutral boundary

Core owns versioned Session, Turn, Event, Snapshot, Command and Result models;
monotonic sequence, digest, gap/replay, deduplication, `OutcomeUnknown`, security
envelope, process/FD ownership, and fail-closed authorization. Core must not
import an OpenCode route, event name, package version, credential name, or
private schema.

An adapter owns one agent implementation: installation and executable identity,
health, HTTP/SSE routes, upstream schema mapping, snapshots, permissions, and
command translation. `OpenCodeAdapter` is the first adapter, not the core. A
second agent is added only through a separately versioned and audited adapter.

## Immediate internal packages

### P4-A0: read-only readiness doctor

Owned files: a new doctor entrypoint and tests under `testkit/pilot/`, plus a
short operator document. It may inspect only existence, type, ownership, mode,
and verifier availability for the fixed external inputs. It must never read or
print Provider credential values, create/delete/rename/sign/publish anything,
or turn a test marker into readiness.

Output is canonical content-free JSON with per-gate states `AVAILABLE`,
`MISSING`, `INVALID`, or `EXTERNAL_OWNER_REQUIRED`, and an overall state that is
never production-ready unless all externally rooted gates are independently
verifiable. Tests prove no mutation, fixed paths, symlink/path rejection, secret
redaction, and default supervisor zero-spawn.

### P4-A1: core/adapter boundary audit

Owned files: an additive audit report and, only if the audit finds a concrete
violation, narrowly scoped contract/test files. First inventory imports and
types across `connector`, `contracts`, Relay, and Mobile. Report every OpenCode
specific route/type/version that crosses into agent-neutral core. No refactor is
authorized until the report supplies a failing conformance test and a minimal
migration boundary.

### P4-A4: operator handoff hardening

Owned files: additive runbook/checklist documents and tests for the read-only
doctor. It must give exact preflight, credential injection, staged evidence,
independent verification, cleanup, approval, signing, CAS, and rollback steps.
It may not generate production credentials, trust roots, signatures, approvals,
or publication state.

## External-owner packages

- B1 Provider owner: one allowlisted, temporary, revocable credential and scope.
- B2 Release/Host owner: Developer ID signed/notarized Host artifact and identity.
- B3 Security owner: signer policy, allowed-signers, KRL, and SSHSIG approval for
  the exact digest and reviewed version.
- B4 Release platform owner: immutable publication and protected-ref CAS.
- B5 Adapter owner: official locked OpenCode package/runtime provenance.

These artifacts must not be generated, inferred, copied from test fixtures, or
placed into chat by repository agents.

## Gated production packages

### P4-C1: native production composition

Starts only after B2-B5 independently verify and B1 is available for the real
run. The native supervisor remains the sole authority and owns opened-file
identity, run secrets, child creation, inherited descriptors, proxy lifecycle,
and cleanup. Every missing/invalid prerequisite must block before creating any
child, socket, pipe, proxy, or temporary runtime. Test-only features cannot be
linked or converted into a production authorization path.

### P4-C2: real four-hop Controlled Pilot

Starts only after C1. One same-run execution must cover official locked
OpenCode, native Host/Connector, Relay, Gateway, and Mobile; read-only
observation plus explicitly authorized reply/deny/Stop; reconnect, gap, ACK,
deduplication, failure recovery, deletion, revocation, and cleanup. Evidence
must bind all hops to one run and be independently reviewed.

## Dispatch order

1. Implement and audit P4-A0.
2. Run P4-A1 as an evidence-first audit; implement only proven boundary gaps.
3. Align P4-A4 with A0 output and the existing operator runbook.
4. In parallel, external owners supply B1-B5.
5. Only then implement/audit C1, followed by the real C2 run.

No current task authorizes Provider use, signing, trust bootstrap, publication,
production child launch, command capability, or a product-readiness claim.
