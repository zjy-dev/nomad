# PHASE8 Adapter Conformance

Status: implemented in repo-owned adapter boundary

## Goal

P8-F requires one explicit adapter support matrix and conformance coverage for
the current productized behavior without redesigning the adapter architecture.

## Outcome

The repo now pins one explicit support statement for the current adapter:

- adapter id `opencode`
- exact upstream version `1.18.16`
- supported action subset `view`, `reply`, `deny`, `Stop`
- `allow_once=false`
- `NoCapability => snapshot + capability=null`
- unsupported version, unsupported shape, and unsupported action surface fail closed

## Implementation scope

Changed implementation files:

- `connector/src/stock_opencode.rs`
- `connector/src/adapters/opencode.rs`
- `contracts/adapter_support_matrix.json`
- `testkit/conformance/run.py`
- `testkit/conformance/test_runner.py`
- `testkit/conformance/README.md`
- `docs/product/adapter-support-matrix.md`

No crate-root, CLI, or launcher changes were required.

## Conformance rules added

- language-neutral support-matrix fixture validation
- exact version-only support assertion
- exact action subset assertion
- `allow_once=false` assertion
- `NoCapability` maps to `snapshot_with_capability_null`
- provider-specific text must not leak outside adapter semantics
- unsupported version and unsupported shape fail with `ERR_INCOMPATIBLE_VERSION`
- unsupported action surface fails with `ERR_SAFETY_BLOCKED`

## Verification

Run from repo root:

```bash
cargo test --manifest-path connector/Cargo.toml --lib c3_facts_tests
cargo test --manifest-path connector/Cargo.toml --lib stock_opencode
python3 testkit/conformance/run.py
python3 -m unittest discover -s testkit/conformance -p 'test_*.py'
```

The final execution results are recorded in the handoff message for this task.
