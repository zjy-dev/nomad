# Nomad autonomous implementation task

## Goal

Implement the Validation Companion architecture in dependency order, use independent product acceptance against `docs/product/mvp-prd.md`, fix all in-scope acceptance findings, and repeat acceptance until the implemented milestone passes.

## Current implementation milestone

Build the Dual Spike and a runnable disposable-repository vertical slice for Apple Silicon macOS/iOS-oriented development:

- Versioned Session Semantics contracts and conformance tests.
- Fixed OpenCode v1.18.16 adapter fixtures and permission feasibility evidence.
- Host/Relay/Mobile reference implementations sufficient for pair, observe, reply, deny, Stop, diff and recovery in local/disposable test mode.
- Conditional allow-once only if adapter and security gates pass.
- Rust Session/Event benchmark spike kept outside the Companion critical path.
- Privacy-safe automated tests and product acceptance evidence.

## Success criteria

1. The repository contains runnable build/test commands and a clear developer entrypoint.
2. Contract, Host, Relay, Mobile/reference client and testkit consume one versioned semantic model.
3. Durable replay, gap recovery, request deduplication, permission single-pending behavior and OutcomeUnknown have automated evidence.
4. Relay cannot inspect content in the implemented security model and content does not enter logs, Push fixtures or diagnostics.
5. An independent product-manager agent evaluates the runnable vertical slice against the PRD and records pass/fail findings.
6. All actionable acceptance findings within the milestone are fixed and revalidated.

## Constraints

- Product decisions and release gates remain authoritative.
- OpenCode is the sole Session domain writer in the Companion path.
- No task may weaken fail-closed behavior to make a test pass.
- No external real repository or real write approval before the security architecture gate is accepted.
- Do not commit automatically; preserve unrelated user files and changes.
- Each worker owns only the directories listed in its assignment.
