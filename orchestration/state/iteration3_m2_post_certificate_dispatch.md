# Iteration 3 M2 Post-Certificate Dispatch

**Plan-only — most packages BLOCKED (see below). B0.1 and B0.3a are independently complete; only the credential-free B0.2a staged-bundle package may proceed after architecture audit.**

## Four-Layer Authorization Architecture

All four layers are independently required and mutually non-substitutable:

```
Layer 1: VerifiedHistoricalEvidence
  ── M1 committed shape fixtures, capture-manifest.json, official-stock-contract.json,
     locked-runtime package/package-lock. Compile-time evidence. No runtime credential.

Layer 2: ReleaseAuthorization
  ── User-approved evidence bundle + external approval record with trust-root
     signature. NOT self-signed by the artifact. Independent approval schema.

Layer 3: AuthenticatedCurrentRun
  ── Socketpair handshake (run_binding.rs HostRunBinding + proxy_handshake).
     Produces RunBinding { run_id, proxy_origin, capability_digest }.
     Proves the process is the same one that was launched.

Layer 4: RuntimeExecutionAuthorization
  ── Combines L1+L2+L3: VerifiedHistoricalEvidence + ReleaseAuthorization +
     AuthenticatedCurrentRun → authorization to execute stock commands.
     VerifiedM2Capabilities binds evidence_manifest_digest + capability_digest.
```

## Unblock Conditions

Six conditions are jointly required before B0.2b, B0.3b, B1, B2, C1, C2, D, Pilot. Credential-free B0.2a staging mechanics and the completed B0.3a verifier are excluded from this production gate and confer no production authority:

1. One real certification run produced both `lifecycle-shape-manifest.json` and `lifecycle-certificate.json`; fixtures cannot substitute for either same-run production candidate.
2. **A3** `verify_certificate.py` exits 0 with exact `VERIFIED` for that certificate.
3. **A4.2** `verify_shape_manifest.py` exits 0 with exact `VERIFIED` for that manifest/certificate pair.
4. An independent audit confirms content-free compliance, the certificate structural cross-binding, and the manifest source-binding against current source artifacts. Any missing candidate or digest mismatch fails closed.
5. The user explicitly approves versioning the complete production evidence bundle, not either file or a digest in isolation.
6. A Security DRI trust-root decision and provisioned production artifacts exist for the ReleaseAuthorization layer (B0.3b), and the resulting record passes B0.3a.

---

## B0.1: Evidence-Manifest Verifier + Tests (credential-free, code-ready)

**Nature**: Read-only schema definition + verifier + tests. Uses `TemporaryDirectory` temp fixtures. Does NOT generate a production manifest, does NOT contain `approval_identity`/signature/authorization, does NOT unlock any capability.

**Files**:
- `testkit/stock-opencode/verify_evidence_manifest.py` — verifier (stdlib, read-only)
- `testkit/stock-opencode/test_verify_evidence_manifest.py` — tests

**Schema** (`nomad.stock-opencode.evidence-manifest.v1`):

| Field | Type | Content | Computation |
|-------|------|---------|-------------|
| `schema_version` | str | `"nomad.stock-opencode.evidence-manifest.v1"` | Constant |
| `certificate_digest` | str | SHA256 of `lifecycle-certificate.json` canonical bytes | Canonical JSON → SHA256 |
| `shape_manifest_digest` | str | SHA256 of `lifecycle-shape-manifest.json` canonical bytes | Canonical JSON → SHA256 |
| `certificate_structural_digest` | str | From cert's `structural_digest` field | Direct copy (cross-binding) |
| `source_binding_digest` | str | From manifest's `source_binding_digest` field | Direct copy (cross-binding) |
| `historical_certified_launch_provenance_digest` | str | From manifest's `launch_provenance_digest` | Shape manifest claim, cross-binding verified |
| `task_spec_digest` | str | From manifest's `task_spec_digest` | Source artifact binding |
| `fixture_manifest_digest` | str | From manifest's `fixture_manifest_digest` | Source artifact binding |
| `command_shapes_canonical_digest` | str | From manifest's `command_shapes_canonical_digest` | Source artifact binding |
| `rule_config_digest` | str | From manifest's `rule_config_digest` | Source artifact binding |
| `current_committed_evidence_provenance_digest` | str | Independently recomputed from current committed evidence bytes and exact lock closure | See below |
| `reviewed_version` | str | e.g. `"v0.1.0"` | Governance input, non-empty ASCII |
| `evidence_manifest_digest` | str | SHA256 of all other fields (excluding this field itself) | Computed last |

**`current_committed_evidence_provenance_digest` computation** — stdlib, no import side effects, and no launch claim:

```
current_committed_evidence_provenance = canonical SHA256 of {
  "official_contract_canonical_digest": canonical SHA256 of official-stock-contract.json,
  "capture_contract_raw_digest": SHA256 of capture_contract.py raw bytes,
  "package_json_raw_digest": SHA256 of locked-runtime/package.json raw bytes,
  "package_lock_raw_digest": SHA256 of locked-runtime/package-lock.json raw bytes,
  "full_locked_dependency_digest": recomputed from exact package-lock entries,
  "full_locked_dependency_count": recomputed from exact package-lock entries,
  "classification": fixed claim after official/capture equality check,
  "entrypoint_historical_claim": fixed claim after official/capture equality check
}
```

The verifier recomputes every value from actual repository bytes. It must compare, field by field, the recomputed official canonical digest (also the fixture canonical digest because `verify_fixture` uses `official-stock-contract.json` as the fixture), capture-contract raw digest, package raw digest, lock raw digest, and recomputed full locked closure digest/count against `capture-manifest.json`. It must also compare the fixed `classification` and historical entrypoint claims between `capture-manifest.json` and `official-stock-contract.json`. Any missing value, disagreement, or non-exact package-lock parse fails closed. None of these checks is a sanity-only check.

**Exact input paths** (frozen, no fallback):
- `testkit/stock-opencode/capture-manifest.json`
- `testkit/stock-opencode/official-stock-contract.json`
- `testkit/stock-opencode/capture_contract.py`
- `testkit/stock-opencode/locked-runtime/package.json`
- `testkit/stock-opencode/locked-runtime/package-lock.json`

**Verifier rules** (17):
1. File exists, bounded (≤128KB), regular file, `os.open` with `O_RDONLY|O_CLOEXEC|O_NOFOLLOW`, no symlink follow, valid JSON, no duplicate keys (object_pairs_hook)
2. `schema_version == "nomad.stock-opencode.evidence-manifest.v1"`
3. All required fields present, no extra
4. `certificate_digest` matches `canonical_digest(certificate_file_bytes)`
5. `shape_manifest_digest` matches `canonical_digest(shape_manifest_file_bytes)`
6. `certificate_structural_digest` matches cert file's `structural_digest` field
7. `source_binding_digest` matches manifest file's `source_binding_digest` field
8. `historical_certified_launch_provenance_digest` matches manifest file's `launch_provenance_digest` field
9. All 6 source digests (`task_spec_digest`, `fixture_manifest_digest`, `command_shapes_canonical_digest`, `rule_config_digest`, `historical_certified_launch_provenance_digest`, `current_committed_evidence_provenance_digest`) are valid 64-hex
10. `current_committed_evidence_provenance_digest` matches the independent actual-byte recomputation above, and every recomputed component and fixed claim matches the corresponding capture/official provenance claim
11. `reviewed_version` is non-empty ASCII, max 128 chars
12. `evidence_manifest_digest` matches computed SHA256 of canonical core (all other fields)
13. Content-free: no forbidden content patterns (provider key, prompt, raw ID, command, diff, tool output)
14-17. (reserved for future binding rules)

**Negative tests**: missing file, wrong schema, extra field, missing field, cert digest mismatch, shape digest mismatch, structural digest mismatch, source binding mismatch, historical provenance mismatch, committed-evidence provenance mismatch, each component/claim mismatch, malformed or non-exact lock closure, source digest format, reviewed_version empty, evidence_manifest_digest mismatch, content violation, valid pair.

**Dependencies**: None. Uses temp fixtures with synthetic cert/manifest data.

**Worker**: `m2_capture_scaffold`
**Auditor**: `m1_evidence_audit`
**NO-GO**: Any rule fails → `FAIL_EVIDENCE_MANIFEST_*` exit code. B0.1 PASS does NOT imply B0.2 readiness.

---

## B0.1c: Public Evidence-Derivation API (credential-free prerequisite, architecture rework)

**Purpose**: Close the construction gap identified by independent B0.2 architecture audit. The current B0.1 CLI can verify a complete manifest but cannot provide the current-source and committed-provenance values needed to construct one. B0.2a may not copy or import B0.1 private algorithms, so B0.1c must first freeze one audited, side-effect-free public derivation API backed by the same implementation used by verification.

**Authorized files only**:
- `testkit/stock-opencode/verify_evidence_manifest.py`
- `testkit/stock-opencode/test_verify_evidence_manifest.py`

**Frozen public API**:

```python
class EvidenceDerivationError(ValueError):
    code: str

def derive_evidence_manifest(
    certificate: Mapping[str, object],
    shape_manifest: Mapping[str, object],
    reviewed_version: str,
) -> dict[str, str]: ...
```

This is a read-only deterministic derivation over the three explicit arguments plus the existing checked-in fixed `ROOT` source artifacts. It accepts no path/root/environment/credential/output/approval argument, performs no write, mkdir, rename, unlink, subprocess, network, logging, stdout, or stderr operation, and does not mutate its arguments. Production and B0.2a always use that fixed root. Tests may monkeypatch the existing module-global `ROOT` to a `TemporaryDirectory` as a non-public test seam; no function/CLI parameter, environment variable, config, or production caller may select that seam, and tests must prove it is unreachable from CLI/B0.2a inputs. It returns a fresh exact-schema `nomad.stock-opencode.evidence-manifest.v1` mapping including `evidence_manifest_digest`, or raises only `EvidenceDerivationError` with an existing `FAIL_EVIDENCE_MANIFEST_*` code. It never returns a partial mapping or an authorization decision.

**Single implementation rule**: the public function owns construction and invokes the existing private safe readers, `_current_sources()`, `_committed_provenance()`, A3/A4 pair validation, and canonical digest functions. `verify_evidence_manifest()` must call this same public function after safely reading the three input files and compare the supplied evidence mapping to the freshly derived exact mapping. There may be no second field-construction, current-source, lock-closure, provenance, or evidence-digest implementation in either B0.1c or B0.2a. Existing verifier reason-code behavior and exact CLI `(returncode, stdout, stderr)` matrices must remain backward compatible; helper exceptions are mapped to the corresponding existing verifier verdict.

**Closed exception contract**: `derive_evidence_manifest()` catches every controlled bottom-layer file/read/parse/schema/pair/source/provenance failure, including `FileNotFoundError`, `NotRegularFile`, `OSError`, `OverflowError`, `UnicodeDecodeError`, `DuplicateKey`, `json.JSONDecodeError`, and `ValueError`, and converts it to `EvidenceDerivationError` with the exact existing B0.1 failure code for that stage. Its exception message is the code only and contains no path, credential, raw ID, artifact content, or tool output. Programmer defects outside this enumerated controlled set are not converted. `verify_evidence_manifest()` maps the controlled helper code back to the pre-B0.1c `Verdict`, preserving every existing CLI tuple exactly.

**Required tests**:

- Isolated import in a fresh interpreter with `PYTHONDONTWRITEBYTECODE=1` produces no stdout/stderr and no filesystem change; importing does not read source artifacts or execute derivation.
- Calling the public function with the non-public module-global `ROOT` test seam monkeypatched to a `TemporaryDirectory` changes no file metadata/bytes, creates no file, emits no output, reads no environment/credential, and returns a fresh mapping on every call without mutating inputs. Production CLI/B0.2a cannot select this seam by argument, environment, or config.
- Every enumerated controlled bottom-layer exception is converted to the exact content-free `EvidenceDerivationError.code`; no path/message/content leaks, and verifier/CLI parity remains exact.
- Exact helper/verifier parity: a helper-produced mapping is accepted by `verify_evidence_manifest()`; every field mutation is rejected; valid and invalid certificate, shape, reviewed-version, current-source, and committed-provenance cases have the same controlled classification as the pre-B0.1c verifier.
- AST/behavioral checks forbid write-capable calls, subprocess/network/signing/approval/capability surfaces, public path parameters, and import of discovery code.
- Full existing B0.1 focused and stock-opencode suites remain green; B0.1 receives a renewed independent evidence audit because its construction boundary changed.

**Worker**: `m2_receipt_verifier`
**Architecture auditor**: `m1_architecture_audit`
**Implementation/evidence auditor**: `m1_evidence_audit`
**Status**: **COMPLETE / INDEPENDENT PASS**. Architecture and renewed B0.1 evidence audits passed with P0/P1/P2 all zero; 20 focused and 191 full stock-opencode tests passed. This freezes only the public derivation API and does not itself unlock B0.2a implementation without its separate architecture PASS.

---

## B0.2a: Same-Run Staged Evidence Bundle (credential-free mechanics, code-ready after architecture PASS)

**Nature**: A fail-closed staging and gate-orchestration change for the existing A0/A4.1 discovery flow. It prepares the certificate, shape manifest, and evidence manifest as one staged candidate bundle. It does not publish production files, create approval, provision trust, sign anything, or unlock B1. Synthetic tests prove mechanics only.

**Implementation ownership (exactly two files)**:
- `testkit/stock-opencode/discover_lifecycle.py`
- `testkit/stock-opencode/test_discover_lifecycle.py`

No new generator entrypoint is authorized. B0.2a must not modify B0.1/B0.3, trust-root files, Connector capability code, or any production evidence file. Tests use `TemporaryDirectory`; they never target the repository production directory.

### Fixed paths and preflight

There are exactly two fixed, pre-existing controlled directories resolved from the checked-in discovery entrypoint: `ROOT = testkit/stock-opencode/` and `REAL_TASK_ROOT = ROOT/real-task/`. Production CLI accepts only the allowlisted Provider credential variable plus a required `--reviewed-version`; it has no `--output`, `--output-dir`, root/path override, `--force`, or directory-creation behavior. One preflight covers both directories and all six staged/final paths. Each directory is checked with no-follow metadata as an existing non-symlink directory, owned by the effective user, with no group/other write bit; `REAL_TASK_ROOT` must be the exact direct child of `ROOT`. Missing, replaced, wrong-owner, or unsafe directories fail closed. It must never call `mkdir`. Tests may inject `TemporaryDirectory` roots only through an internal test seam that is unreachable from production CLI.

The following fixed names form the candidate bundle:

| Artifact | Staged path | Final path |
|---|---|---|
| certificate | `real-task/lifecycle-certificate.json.tmp` | `real-task/lifecycle-certificate.json` |
| shape manifest | `real-task/lifecycle-shape-manifest.json.tmp` | `real-task/lifecycle-shape-manifest.json` |
| evidence manifest | `testkit/stock-opencode/lifecycle-evidence-manifest.json.tmp` | `testkit/stock-opencode/lifecycle-evidence-manifest.json` |

Pre-existing staged or final certificate/shape/evidence files fail closed. They are never opened for truncation, reused, overwritten, renamed away, or deleted. A race after preflight is closed by exclusive creation, not by cleanup.

### Frozen staging and gate sequence

1. A0 executes one locked official OpenCode `1.18.16` real run and produces an in-memory structural candidate only. This is not certification or approval.
2. The single-use `RealRunAuthority` is consumed exactly once to freeze certificate and shape bytes from that same run. The A3 certificate six-field schema stays unchanged; it does not acquire a fictitious `shape_manifest_digest`.
3. Certificate and shape staged files are each created with `O_CREAT|O_EXCL`, mode `0600`, bounded complete writes, file `fsync`, and close. No final target is written. Any write, `fsync`, close, crash, signal, or interruption failure leaves existing staged bytes for diagnosis and leaves every final target absent. No `unlink` rollback is allowed.
4. Invoke the fixed `verify_certificate.py` with the current interpreter realpath, no shell, fixed cwd/argv, `stdin=DEVNULL`, a ten-second timeout, and the exact child environment `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, `LC_ALL=C`, `LANG=C`; inherit nothing else and require all fixed argv paths to be absolute, so `PATH` is unnecessary. This excludes every allowlisted Provider credential and alias by construction. Capture bounded stdout/stderr (maximum 4 KiB each). Continue only for normal exit code `0` and stdout byte-for-byte exactly `VERIFIED\n`. Captured stderr may be non-empty but is ignored and never exposed. Spawn error, timeout, signal, output overflow, nonzero, or wrong stdout returns `FAIL_A3_VERIFY`.
5. Invoke `verify_shape_manifest.py` under the identical subprocess policy against the staged shape/certificate pair. The same normal-exit/exact-stdout rule applies; every failure class returns `FAIL_A4_2_VERIFY`.
6. Require `reviewed_version` as an explicit, exact governance input. It may not be inferred from a package version, git ref, branch, filename, environment default, or fixture. Load only B0.1c's frozen public `derive_evidence_manifest()` from the fixed verifier module through a controlled absolute-path loader while `sys.dont_write_bytecode` is forced true; callers and environment cannot override this. Pass the in-memory certificate, shape, and explicit version, and receive the complete exact-schema candidate. The load and call must create, update, or delete no workspace file or metadata, including `__pycache__`/`.pyc`; this is asserted before/after in tests. Any controlled helper failure becomes the content-free outer code `FAIL_B0_1_DERIVATION`. Write the returned candidate to the fixed evidence staged path with the same exclusive `0600`/bounded-write/`fsync`/close policy.
7. B0.2a must not copy or import B0.1 private `_committed_provenance`, `_current_sources`, lock-closure, pair-validation, field-construction, or canonical-verification algorithms. After staging, invoke the audited `verify_evidence_manifest.py` CLI under the same bounded, scrubbed subprocess policy with fixed staged paths. Continue only for normal exit `0` plus stdout exactly `VERIFIED\n`; every failure class returns `FAIL_B0_1_VERIFY`. This CLI reopening is mandatory even though the candidate came from the public helper.
8. A successful code path returns only `CANDIDATE_STAGED`. It must not emit `CERTIFIED`, `APPROVED`, `RELEASE_AUTHORIZED`, `B1_READY`, or an unlock claim. Digests, credential material, prompts, raw IDs, commands, diffs, and verifier tool output are not printed.

The generator's assertions and its invocation of the three verifiers are not an independent audit, user approval, or release authorization. Staging is deliberately terminal in B0.2a.

### Stable reason codes

**B0.2a reachable codes**: `BLOCKED_OUTPUT_DIR_MISSING`, `BLOCKED_OUTPUT_DIR_POLICY`, `BLOCKED_CERTIFICATE_ALREADY_EXISTS`, `BLOCKED_SHAPE_ALREADY_EXISTS`, `BLOCKED_EVIDENCE_ALREADY_EXISTS`, `BLOCKED_CERTIFICATE_TMP_EXISTS`, `BLOCKED_SHAPE_TMP_EXISTS`, `BLOCKED_EVIDENCE_TMP_EXISTS`, `BLOCKED_REVIEWED_VERSION_REQUIRED`, `FAIL_A3_VERIFY`, `FAIL_A4_2_VERIFY`, `FAIL_B0_1_DERIVATION`, and `FAIL_B0_1_VERIFY`.

**B0.2b-only reserved governance codes, unreachable from B0.2a**: `BLOCKED_INDEPENDENT_AUDIT_REQUIRED`, `BLOCKED_USER_APPROVAL_REQUIRED`, `BLOCKED_B0_3B_EXTERNAL_GOVERNANCE`, and `BLOCKED_ATOMIC_PUBLISH`.

### Required test matrix

- Missing, symlink, non-directory, wrong-owner, and unsafe-permission production-directory policies; no automatic directory creation and no arbitrary output option.
- Every pre-existing final and staged path, including evidence; preservation of exact existing bytes.
- `O_EXCL` race at each staged file; bounded partial write, file `fsync`, and close ordering/failure.
- Crash/interruption after each staged write or verifier gate leaves staged files and no final file; no production path is ever unlinked.
- A3, A4.2, and B0.1 non-zero exit; zero exit with non-exact stdout; timeout/spawn/signal/output overflow; empty and non-empty stderr both remain unexposed and do not change a valid stdout verdict. Verify fixed absolute argv/cwd, no shell, bounded capture, timeout, the exact four-variable child environment, no inherited variable, and no allowlisted Provider credential. The minimal environment must preserve the valid verifier result.
- Controlled B0.1c loading forces no-bytecode mode and leaves every pre-existing workspace byte and metadata snapshot unchanged; no new `__pycache__` or `.pyc` appears.
- Certificate/shape/evidence full digest, structural, source, historical provenance, and pair-binding tamper cases, including proof that the certificate schema has no shape digest.
- Missing, inferred, malformed, or mismatched `reviewed_version`.
- Static/behavioral proof that no signing, private key, trust-root creation, approval synthesis, capability enablement, or mixed/final publication is reachable.
- Success output is exactly `CANDIDATE_STAGED`; forbidden authority statuses never appear.

**Worker**: `m2_capture_scaffold`
**Architecture auditor**: `m1_architecture_audit`
**Implementation/evidence auditor**: `m1_evidence_audit`
**Status**: **READY_FOR_ARCH_AUDIT**. B0.1c is independently frozen; no implementation dispatch before renewed B0.2 architecture PASS.

---

## B0.2b: Real Audit, Approval, and Consistent Publication (real pair required)

**Nature**: Operator/governance action over the exact staged triple produced by a real credential-backed same-run A0 execution. It is not implemented or simulated by B0.2a.

Frozen sequence after B0.2a returns `CANDIDATE_STAGED`:

1. An independent auditor reopens the staged bytes and confirms A3, A4.2, B0.1, content-free, structural, source, provenance, and full pair binding. Generator self-checks do not satisfy this gate.
2. The user explicitly approves the exact complete staged bundle and exact `reviewed_version`; approval of one file or an isolated digest is insufficient.
3. A Security DRI provisions the externally governed B0.3b policy, allowed signer, KRL, and detached SSHSIG outside repo/agent/CI/chat authority, then signs the exact B0-verified digest/version.
4. B0.3a verifies the current approval record and signature with exact `VERIFIED`.
5. B0.2b is currently fixed to preserve all staged files and return `BLOCKED_ATOMIC_PUBLISH`. Three ordinary renames cannot provide a consistent three-file commit and are never acceptable. A future, separately architected package must define a versioned immutable bundle plus a single atomic no-replace visibility pointer (including file and directory `fsync`, reader semantics, recovery, and protected-branch governance) before publication can become executable. It is forbidden to publish one final file first, delete a published file as rollback, or expose a mixed-version final bundle.

**Dependencies**: temporary Provider credential + real same-run staged triple + A3/A4.2/B0.1 exact VERIFIED + independent audit + explicit user approval + B0.3b external governance + B0.3a exact VERIFIED + a separately frozen and proven versioned-bundle/atomic-pointer publication protocol.
**Worker**: operator + Security DRI; production publication requires an independent protected-branch reviewer.
**Auditor**: `m1_evidence_audit` plus independent protected-branch security reviewer.
**Status**: **BLOCKED**. B0.2b, B0.3b, B1, B2, C1, C2, D, and Pilot remain blocked.

---

## B0.2c: Agent-Neutral Immutable Release Bundle (credential-free mechanics)

Decision: local filesystem pointers and three independent renames are not production publication. Production visibility is one compare-and-swap update of a protected Git ref. The new commit tree contains both an immutable content-addressed bundle and the release index selecting it. CI, build, and runtime consumers resolve both from the same commit OID; a dirty worktree, PR branch, uncommitted file, or unreferenced bundle is never production-visible.

The outer release envelope is Agent-neutral. OpenCode-specific verification remains inside the opencode adapter evidence set; the bundle uses adapter identity/version, content digests, approval identity, and artifact descriptors. A future Code Agent adds an adapter verifier and artifact set without changing release-index visibility semantics.

### Fixed layout

evidence/agent-releases/current.json selects exactly one evidence/agent-releases/bundles/sha256-<bundle_manifest_digest>/ directory. The outer directory always contains exactly bundle-manifest.json, release-approval-record.json, release-approval-record.sshsig, and one adapter/ directory. adapter/ contains the exact basenames declared by the registered adapter policy and bundle manifest. Initial opencode@1.18.16 policy requires lifecycle-certificate.json, lifecycle-shape-manifest.json, and lifecycle-evidence-manifest.json; those names are not part of the outer schema.

No symlink, hard link, alternate basename, extra file, traversal, mutable latest directory, or legacy scattered-file fallback is accepted. The one fixed adapter/ directory is the only allowed nested directory: it is an immediate non-symlink child with verified directory identity/link policy, contains only registry-declared regular basenames, and contains no subdirectory. Bundle files are bounded regular files. An existing bundle ID is accepted only when every byte is identical; it is never overwritten or deleted by the tool.

### Bundle manifest

Exact schema nomad.agent-evidence.bundle-manifest.v1 contains: schema_version; adapter_id; adapter_version; adapter_contract_digest; approval_scope; reviewed_version; evidence_manifest_digest; approval_record_digest; approval_signature_raw_digest; trust_root_id; an exact adapter_artifacts map from adapter-relative basename to raw_sha256 and size_bytes; and bundle_manifest_digest, the canonical SHA-256 of all preceding fields. The outer verifier has a static registry keyed by adapter_id, adapter_version, and adapter_contract_digest. It freezes exact artifact names, adapter verifier entrypoint, expected evidence schema, and approval scope. Unknown adapters fail closed. Adding an adapter is a separately reviewed registry/code change; no adapter may masquerade as OpenCode.

The directory basename is exactly sha256-<bundle_manifest_digest>. The manifest binds outer approval-record and signature bytes through approval_record_digest and approval_signature_raw_digest; they are not adapter_artifacts. Every registered adapter uses the fixed outer basenames release-approval-record.json and release-approval-record.sshsig. The registry selects the external approval verifier, approval schema, and exact scope, and requires the parsed record signature_file to equal release-approval-record.sshsig byte-for-byte. Initial OpenCode policy uses B0.3a scope nomad.m2.complete-evidence-bundle. Bundle code never signs, creates keys, provisions trust, or treats Git authorship as approval.

### Release index and rollback chain

Exact schema nomad.agent-evidence.release-index.v1 contains: schema_version; active_bundle_id; bundle_manifest_digest; adapter_id; adapter_version; reviewed_version; evidence_manifest_digest; approval_record_digest; previous_release_index_digest; release_sequence; and release_index_digest. Repeated fields exactly match the referenced manifest.

For the first release, previous_release_index_digest is 64 zeroes and sequence is 1. Later candidates must point to the exact current.json digest, active bundle ID, and sequence read from the expected protected parent commit and increment sequence by exactly one; reactivating an older bundle is forbidden. The publication request is an external governance record containing protected_ref, repository_object_format, expected_parent_oid, proposed_commit_oid, release_index_digest, and bundle_manifest_digest. Both OIDs are verified commit objects in the same repository format and proposed has expected parent as unique first parent. Only protected CI/reviewer authority may create or approve the commit and perform compare-and-swap ref update. Materializer and verifier have no git mutation capability. Dirty tree, non-protected ref, stale parent, CAS conflict, fetch failure, object-format/type mismatch, or consumer checkout OID mismatch returns BLOCKED_SOURCE_COMMIT_OID or BLOCKED_PROTECTED_REF_CAS. Git tree/ref atomicity is the only visibility boundary.

### B0.2c1: Read-only release-bundle verifier

Authorized files only: testkit/agent-evidence/verify_release_bundle.py and testkit/agent-evidence/test_verify_release_bundle.py.

The stdlib verifier has an internal _verify_release_tree(tree_root, expected_parent_index, adapter_verifier, approval_verifier) API used by unittest and later materializer tests. Those four injections are not reachable from CLI, environment, manifest, registry data, or production configuration. The production CLI accepts exactly two mandatory governance values: --expected-parent-oid and --source-commit-oid; both must be lower hex commit OIDs in the repository object format. It has no root/verifier/trust/path override. Through a platform-policy allowlisted absolute git executable, bounded no-shell subprocesses require: git rev-parse --show-object-format; cat-file -t for both OIDs equals commit; current HEAD equals source_commit_oid; source commit has expected_parent_oid as its unique first parent; the worktree/index is clean including untracked files; and the current tree root is the checked-out source commit. OID length is 40 for sha1 or 64 for sha256 and both OIDs use the same format. Any mismatch returns BLOCKED_SOURCE_COMMIT_OID.

Subprocess lifecycle has two owners. c1 owns normal spawn, bounded output, timeout, kill, PID-level SIGKILL fallback, finite wait/reap, selector close, and pipe close. If both process-handle kill and PID-level SIGKILL fail or the child cannot be confirmed reaped, c1 closes its own descriptors, returns exact BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED, and can never emit VERIFIED_RELEASE_BUNDLE. Production c1 is authorized only inside a protected-CI isolated job or container whose external supervisor owns the process domain and destroys the job on this blocker. Local/operator execution seeing this blocker must stop and terminate the containing environment; it may not retry or continue. The verifier does not claim that an unkillable kernel task was locally cleaned, and it never waits without a finite bound.

The CLI reads the expected parent current.json with bounded git show <expected_parent_oid>:evidence/agent-releases/current.json. For the first release, that exact path must be absent and the proposed index must use zero previous digest and sequence 1. Otherwise the parent file must be valid and its canonical digest, active bundle ID, and sequence must exactly drive proposed previous_release_index_digest and sequence+1. Missing/malformed parent, stale lineage, old-bundle reactivation, unreadable object, or absent required parent index returns BLOCKED_EXPECTED_PARENT_INDEX. Production CLI always uses static registry absolute adapter/approval entrypoints. Missing B0.3b trust returns BLOCKED_EXTERNAL_APPROVAL_VERIFICATION. Credential-free tests inject synthetic parent bytes and audited temporary-only B0.1/B0.3a verifier callables through the internal API; a test-only VERIFIED result proves orchestration only and never production approval. AST/behavior tests prove main/CLI cannot reference test hooks or write production trust. The verifier creates no key, signature, trust root, commit, ref, capability, or publication. Success is exactly VERIFIED_RELEASE_BUNDLE.

Worker: release_bundle_verifier. Architecture auditor: m1_architecture_audit. Implementation auditor: m1_evidence_audit. Status: COMPLETE / INDEPENDENT PASS (26 focused tests; P0/P1/P2 zero).

B0.2c1b prerequisite for materialization: add public read-only compare_immutable_bundle(expected_bundle, existing_bundle) to the same c1 verifier and tests. It accepts two paths only through Python API, is not exposed by production CLI, uses the same frozen safe readers/layout policy, returns IDENTICAL or DIFFERENT/file-policy verdict, writes nothing, invokes no adapter/approval/Git subprocess, and grants no authority. Authorized files remain the two c1 files; implementation requires renewed independent evidence audit before c2 dispatch.

### B0.2c2: Worktree bundle materializer

B0.2c2 is a proposal materializer, not a publisher and not a Git authority. It never calls c1 production CLI, accepts no commit OID, and never claims VERIFIED_RELEASE_BUNDLE. Fixed production inputs are the three B0.2a staged files, fixed B0.3b approval record/signature, and active current.json only as observed lineage. All inputs are bounded same-FD no-follow regular reads into memory before construction. Missing inputs or non-VERIFIED A3/A4.2/B0.1/B0.3a return stable blockers; no digest/signature algorithm is copied.

Construction order is frozen: read/verify inputs; read/validate active current.json or exact first-release absence; derive adapter descriptors; canonicalize bundle manifest; compute bundle_manifest_digest and sha256- directory basename; construct complete private proposal tree; construct release index with zero/1 or active index digest/sequence+1 while rejecting same active bundle; canonicalize/index digest; write proposed index inside the private tree; call c1 internal _verify_release_tree(private release root, observed parent index, production adapter verifier, production approval verifier). Success of this step is internal mechanics only.

The staging directory is a unique unpredictable .candidate-* directory created by tempfile.mkdtemp(dir=fixed_release_root, prefix=.candidate-) under the fixed, pre-existing evidence/agent-releases root, mode 0700. It is in the same filesystem as bundles and is not operator-selectable. It contains a complete release-root-shaped proposal with bundle and current index. Every file is O_EXCL 0600, bounded, complete-write, fsync, close; all adapter/bundle/candidate/release directories are fsynced. Failures preserve the candidate directory and output only a stable code; an external supervisor records the candidate basename. There is no automatic cleanup/delete.

After c1 internal verification, exactly the complete private bundle directory is connected to the inactive worktree bundles/sha256-* basename using exclusive_dir_publish(staging_bundle, bundles_dir, final_basename). Darwin arm64 loads CDLL(None,use_errno=True).renamex_np with argtypes [c_char_p,c_char_p,c_uint], restype c_int, and RENAME_EXCL=0x00000004. Linux x86_64 loads CDLL(None,use_errno=True).syscall with restype c_long; syscall is variadic so argtypes is unset, and each argument is explicitly typed: c_long(SYS_renameat2=316), c_int(AT_FDCWD=-100), c_char_p(old_abs), c_int(AT_FDCWD), c_char_p(new_abs), c_uint(RENAME_NOREPLACE=0x00000001). Only absolute encoded paths on one filesystem are accepted; return 0 is success. No other OS/arch, missing symbol, or fallback is supported. ENOSYS/EOPNOTSUPP returns BLOCKED_UNSUPPORTED_NO_REPLACE; EXDEV returns BLOCKED_CROSS_DEVICE; EPERM/EACCES returns BLOCKED_OUTPUT_DIR_POLICY; all other errno including EIO returns BLOCKED_ATOMIC_PUBLISH. Staging is preserved. Ordinary rename, os.rename, os.replace, check-then-rename, copy-over, unlink, rmtree, and fallback delete are forbidden.

EEXIST is handled only by the separately audited c1 public pure helper compare_immutable_bundle(expected_private_bundle, existing_bundle). That helper enforces the exact outer/adapter layout, rejects extra files/subdirs/symlinks/hardlinks/non-regular/oversize, reads every file bounded no-follow with link count one, verifies the expected and existing directory basename/manifest relation, and compares every raw byte. It performs no adapter/signature verification and no write. IDENTICAL permits the internal ALREADY_IDENTICAL outcome while preserving private staging; DIFFERENT or any replacement/TOCTOU/file-policy failure returns BLOCKED_BUNDLE_COLLISION. c2 may not copy this reader or implement a weaker known-file comparison.

After successful/identical inactive bundle connection, c2 re-reads active current.json. First-release absence is represented internally by the fixed sentinel 64 zeroes plus sequence zero. Absence followed by appearance, presence followed by absence/malformed bytes, or any digest change returns BLOCKED_EXPECTED_PARENT_INDEX and does not write a proposal. Otherwise it exclusively writes the canonical release index to evidence/agent-releases/current.json.proposed, fsyncs file and release root, and never modifies active current.json. The proposed index previous_release_index_digest is the lineage_observed_digest; it is advisory only. c1 production verification in the future protected candidate commit must re-bind it to expected-parent commit and CAS; any later active change makes the proposal stale and blocked. An inactive bundle connected without proposal is an auditable orphan, never success. Existing proposed index returns BLOCKED_PROPOSED_INDEX_EXISTS.

Authorized files only: testkit/agent-evidence/materialize_release_bundle.py and testkit/agent-evidence/test_materialize_release_bundle.py. Production CLI has no arguments or path/root/verifier/shim input. Internal tests may inject TemporaryDirectory roots, c1 internal verifier, adapter/approval callables, libc rename shim, and I/O failure hooks; seams are absent from CLI/environment/manifest. No git commit/push/merge/ref, key/signing/trust, cleanup/delete, capability, or receipt API exists.

Stable errors: BLOCKED_INPUT_STAGED_MISSING, BLOCKED_EXTERNAL_APPROVAL_VERIFICATION, BLOCKED_CANDIDATE_ALREADY_EXISTS, BLOCKED_BUNDLE_COLLISION, BLOCKED_PROPOSED_INDEX_EXISTS, BLOCKED_EXPECTED_PARENT_INDEX, BLOCKED_DIRECTORY_FSYNC, BLOCKED_UNSUPPORTED_NO_REPLACE, BLOCKED_CROSS_DEVICE, BLOCKED_OUTPUT_DIR_POLICY, BLOCKED_ATOMIC_PUBLISH, FAIL_BUNDLE_MANIFEST, FAIL_RELEASE_INDEX, FAIL_C1_INTERNAL_VERIFICATION, BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED. Success stdout is exactly CANDIDATE_RELEASE_TREE; ALREADY_IDENTICAL is an internal materialization outcome but still requires proposed index and final success gate. VERIFIED_RELEASE_BUNDLE, PUBLISHED, AUTHORIZED, B1_READY are forbidden. Status: COMPLETE / INDEPENDENT PASS (15 focused tests including Darwin arm64 no-replace smoke; P0/P1/P2 zero).

### B0.2d: Build and runtime consumption

Connector must stop consuming legacy scattered lifecycle files. The frozen future build entrypoint is connector/build.rs. Its only repository inputs are evidence/agent-releases/current.json and the referenced bundle from the same checked-out commit. Environment input NOMAD_SOURCE_COMMIT_OID is mandatory, exactly 40 or 64 lower hex, and must equal the protected-CI proposed_commit_oid recorded for this build; dirty or unknown OID is blocked before compilation. build.rs invokes the fixed release verifier and requires exact VERIFIED_RELEASE_BUNDLE. It writes only OUT_DIR/nomad_agent_release.bin and OUT_DIR/nomad_agent_release.meta.json; metadata binds source_commit_oid, release_index_digest, bundle_manifest_digest, adapter_id/version, reviewed_version, evidence digest, and approval digest. Build failure uses cargo:error with stable BLOCKED_RELEASE_BUNDLE_* code and emits no usable bytes. Runtime include_bytes reads only these OUT_DIR artifacts, revalidates all digests and the approval/evidence relation, and supplies those exact fields to VerifiedM2Capabilities together with RunBinding. Any legacy scattered lifecycle path or feature-only fallback returns REAL_LIFECYCLE_EVIDENCE_REQUIRED/SafetyBlocked. Status: BLOCKED pending B0.2c PASS and a separate Rust/build architecture audit; no B0.2d implementation is authorized by c1 PASS.

### B0.2d1: Commit-Bound Build Container

Normal developer/test builds never start Python or Git and generate an invocation-unique unavailable container in OUT_DIR; RealLifecycleEvidence remains Unavailable. On supported Darwin/Linux only, build.rs opens fixed /dev/urandom with O_RDONLY|O_CLOEXEC|O_NOFOLLOW, verifies the opened object is the expected character device policy, reads exactly 16 bytes with EINTR-safe read_exact, and closes it. This is the sole nonce source; rand crates, time, PID, counters and environment-derived entropy are forbidden. It creates exactly nomad_agent_release-<32 lower hex>.container with O_CREAT|O_EXCL and emits cargo:rustc-env=NOMAD_EMBEDDED_RELEASE_PATH=<absolute invocation file>. release_bundle.rs uses include_bytes!(env!(NOMAD_EMBEDDED_RELEASE_PATH)); it never discovers a fixed filename. Reused OUT_DIR stale files are unreachable because each invocation embeds only its freshly created path. Cargo feature production_release_bundle is only a build-input requirement and never runtime authority.

Feature build requires exact NOMAD_SOURCE_COMMIT_OID, NOMAD_EXPECTED_PARENT_OID, and NOMAD_PYTHON_REALPATH. Python policy is immutable source code in build.rs: exact platform map darwin-arm64 and linux-x86_64 to one or more absolute realpaths approved in code review; it is not read from env/repository evidence/config. NOMAD_PYTHON_REALPATH must resolve to exactly one compiled entry and be a regular executable. PATH lookup is forbidden. Fixed verifier path is testkit/agent-evidence/verify_release_bundle.py. argv, cwd, four-variable scrubbed env, ten-second timeout, bounded output, exact VERIFIED_RELEASE_BUNDLE and cleanup blocker mirror c1. Normal builds do not inspect these env vars.

Authorized d1 files: connector/Cargo.toml, connector/build.rs, connector/src/release_bundle.rs, connector/src/lib.rs, connector/tests/release_bundle_build_tests.rs. d1 enables no command execution or d2 types.

After c1 production verification, build.rs does not read release bytes from the mutable worktree. Through an immutable build.rs source-code allowlist for absolute Git realpaths (darwin-arm64 /usr/bin/git, linux-x86_64 /usr/bin/git) and GIT_OPTIONAL_LOCKS=0, it reads every file from NOMAD_SOURCE_COMMIT_OID using bounded git show object access. It first reads current.json, derives the content-addressed bundle path, then reads manifest, fixed outer files and registry-declared adapter files. It verifies object format/type and re-parses/re-hashes all relations. Before and after object reads it rechecks HEAD/source OID and clean worktree including untracked. Any object/checkout/digest change returns BLOCKED_RELEASE_BUNDLE_TOCTOU. No c1 pass authorizes different bytes.

OUT_DIR publication is the invocation-unique O_EXCL file itself; there is no temp/final rename and no shared final name. The same state machine is used for unavailable and verified containers: nonce read, exclusive create, record dev/inode, bounded complete writes, fsync, close, no-follow reopen, byte-for-byte parser revalidation, then and only then emit rustc-env. Random source/open/read/close, collision, short write, fsync, close, reopen, identity, or revalidation failure maps exactly to cargo:error=BLOCKED_RELEASE_ARTIFACT_PUBLICATION, emits no rustc-env and fails build. It may remove only the invocation-owned nonce file after dev/inode no-follow equality; inability to confirm or remove is the same blocker. It never deletes a pre-existing file, repository path or other Cargo output. The valid nonce file remains present for the entire rustc invocation and Cargo owns eventual OUT_DIR disposal.

Container framing is Agent-neutral: 8-byte NOMADREL magic, u16 BE version 1, one-byte availability, u32 BE entry_count, then all entries globally sorted by raw ASCII name bytes. Each entry is u16 name_len, ASCII name, u32 data_len, 32 raw SHA-256 bytes, raw data. Verified names are exactly adapter/<each registry basename>, outer/bundle-manifest.json, outer/current.json, outer/embedded-meta.json, outer/release-approval-record.json, and outer/release-approval-record.sshsig, globally bytewise sorted with no subgroup exception. entry_count equals 5 plus registry adapter artifact count (initial OpenCode count 8). Unknown/duplicate/unsorted names, traversal, zero/oversized length, count mismatch, trailing bytes, extra/missing entry, digest mismatch or total overflow fail. Unavailable has availability 0, entry_count 0 and immediate EOF.

The container includes one final metadata entry outer/embedded-meta.json before framing digest calculation. Its exact schema nomad.agent-evidence.embedded-release.v1 binds source_commit_oid, expected_parent_oid, release_index_digest, bundle_manifest_digest, adapter_id/version/contract_digest, reviewed_version, evidence_manifest_digest, approval_record_digest, approval_signature_raw_digest and trust_root_id. metadata_digest is canonical SHA-256 of preceding fields. There is no container hash inside metadata, avoiding a digest cycle; each entry has its own framing raw digest and the runtime hashes the complete container independently.

release_bundle.rs always include_bytes from env NOMAD_EMBEDDED_RELEASE_PATH, never repository lifecycle paths. EmbeddedRelease::load parses framing, rehashes entries and revalidates metadata/index/manifest/evidence/approval relations and registry names. It yields Unavailable or VerifiedHistoricalEvidence; the latter proves exact build-time embedded bytes/commit binding, not a new runtime SSHSIG verification, current validity, launch, RunBinding or command authority.

d1 tests cover normal build with no Python/Git invocation; /dev/urandom exact policy, short/EINTR/read/close failure and forbidden alternate entropy; two builds reusing OUT_DIR embed different nonce paths and second cannot consume first verified file; every exclusive-write/fsync/close/reopen/revalidate/owned-cleanup failure; direct assertion of cargo:rustc-env absolute path and lifetime; feature missing env/file/trust/interpreter; temp Git SHA-1/SHA-256; dirty/stale/wrong commit; c1 output/cleanup/TOCTOU; unavailable framing; global dynamic entry order/count/name/digest; truncation/extra/meta mutations; legacy paths ignored; no repository writes. d1a normal unavailable build and strict verified parser are COMPLETE / INDEPENDENT PASS (90 library tests including strict parser, 4 release-container integration tests, full Cargo and clippy PASS; production feature remains blocked). d1b production feature handoff is the next atomic implementation package.

### B0.2d2: Runtime Execution Authorization

d2 begins only after d1 PASS. VerifiedHistoricalEvidence is the parsed exact embedded release. ReleaseAuthorization does not claim to re-run SSH cryptography: build-time c1/B0.3a verified exact immutable approval/signature bytes hash-bound into the container. Runtime revalidates raw digests, record/evidence/version/scope/trust relations and current UTC expiry. Timestamp grammar is exactly B0.3a strict second-resolution RFC3339 Z (YYYY-MM-DDTHH:MM:SSZ); offsets, fractions and date-only forms fail. authorize_current_run receives an injected UTC now in tests and system UTC in production, with policy skew already bounded 0..300; expired/future/malformed approval is SafetyBlocked. Runtime cryptographic re-verification requires separate ADR/tool boundary.

ActualLaunchProvenance is an unforgeable type constructed only inside the locked launcher module from actual package, lock, full closure/count, installed closure, entrypoint, npm, task, fixture and adapter identity/version bytes; fields are private and no public string constructor exists. AuthenticatedCurrentRun is a borrowed RunBinding. RuntimeExecutionAuthorization is opaque, non-Clone, non-Serialize, contains the recomputed digest plus run_id scope, and is created only by authorize_current_run(VerifiedHistoricalEvidence, RunBinding, ActualLaunchProvenance, now_utc).

Expected capability digest is canonical SHA-256 of schema version, source commit OID, release index/bundle/evidence/approval digests, reviewed adapter identity/version, actual launch provenance digest, RunBinding run_id and proxy_origin. RunBinding.capability_digest is only the authenticated received claim; expected digest is independently recomputed and constant-time compared. There is no cycle because the proxy receives the reviewed release/launch facts before it forms hello; it cannot choose expected facts. Token scope must match the exact RunBinding run_id for each command and cannot cross-run/replay.

All legacy from_receipts/RealLifecycleEvidence caller-supplied paths remain compatibility blockers returning REAL_LIFECYCLE_EVIDENCE_REQUIRED. Stable runtime blockers distinguish UNAVAILABLE_RELEASE, APPROVAL_EXPIRED_OR_INVALID, ACTUAL_LAUNCH_MISMATCH, RUN_BINDING_MISMATCH, CAPABILITY_CLAIM_MISMATCH and AUTHORIZATION_SCOPE_MISMATCH. Historical evidence, approval, actual launch and RunBinding cannot substitute for one another. Stock production command methods require &RuntimeExecutionAuthorization; feature flags, embedded bytes, Git authorship, approval alone or handshake alone never authorize. Adapter-neutral release parsing stays in release_bundle.rs; stock_opencode.rs owns OpenCode Session Semantics. Status: BLOCKED_ON_B0.2d1_PASS and real external gates.

### B0.2d2a: Release Authorization Only (credential-free mechanics)

B0.2d1a/d1b are COMPLETE / INDEPENDENT PASS for normal-unavailable, strict parser and production commit-to-container handoff mechanics. Real production feature build remains externally blocked by missing evidence/trust/CAS.

d2a may modify only connector/src/release_bundle.rs, connector/src/stock_opencode.rs, connector/src/lib.rs and focused tests. VerifiedHistoricalEvidence becomes sealed: fields are private and it has no public constructor. The parser retains hash-bound approval schema, issued_at, expires_at, scope, signing_namespace, approval_signature_raw_digest and trust_root_id in addition to release/evidence fields. It also revalidates those fields against manifest/meta/approval raw bytes before constructing the sealed value.

d2a implements only current_release_authorization(&VerifiedHistoricalEvidence) -> Result<CurrentReleaseAuthorization, SafetyBlocked>. The public production entrypoint obtains system UTC internally; arbitrary clock injection and the Embedded parser seam exist only under cfg(test) and are absent from non-test symbols. It enforces exact approval schema/scope/namespace/evidence digest/reviewed version/trust root/signature raw digest, strict second-resolution UTC-Z grammar, issued_at before expires_at, maximum validity 2592000 seconds, issued_at not in the future and expires_at strictly after now. Runtime clock skew is fixed to zero and is not caller/environment input. CurrentReleaseAuthorization is opaque, non-Clone, non-Serialize and contains only release/approval digest scope; it cannot authorize commands.

No capability formula, actual_launch_digest parameter, RuntimeExecutionAuthorization, RunBinding comparison or command API change is allowed in d2a. VerifiedM2Capabilities::from_receipts and all production commands remain blocked exactly as before. Capability derivation moves entirely to d2b/C1 after authenticated ActualLaunchProvenance exists.

d2a is COMPLETE / FINAL INDEPENDENT PASS. VerifiedHistoricalEvidence is sealed and records whether it came from the compile-time embedded container or from the public diagnostic parser. Only embedded provenance can produce CurrentReleaseAuthorization; a caller-supplied but internally consistent container is SafetyBlocked with APPROVAL_EXPIRED_OR_INVALID. After architecture alignment found two P1 gaps, the production entrypoint now owns trusted system UTC and the cfg(test)-only embedded path proves both authorization success and stable failure. The approval schema/scope/namespace, raw approval/signature digests, manifest/meta/index/evidence relations, reviewed version, strict UTC-Z grammar, zero-skew time window and 30-day maximum are revalidated. CurrentReleaseAuthorization remains opaque, non-Clone, non-Serialize and is not consumed by any command API. Connector regression is 94 library tests plus 8 release-container focused tests and all existing integration targets; full Cargo, clippy and fmt pass. This gate proves current embedded approval validity mechanics only; d2b/C1 and all command authority remain blocked.

### B0.2d2b / C1: Authenticated Actual Launch Adoption and Command Gate

Python locked launcher must deliver complete ActualLaunchProvenance bytes to Rust over a separate one-way inherited FD authenticated and bound to the same RunBinding secret/run ID. Rust validates exact schema, bounded framing, HMAC domain separation, single-use FD ownership, close-on-exec isolation, package/lock/closure/entrypoint/npm/task/fixture/adapter fields and derives launch digest. Only this private path creates ActualLaunchProvenance. d2b then creates non-Clone RuntimeExecutionAuthorization and production commands require it. This C1 package remains BLOCKED pending separate architecture and real-process audit; d2a cannot simulate it with public strings.

Tests cover duplicate/extra/missing fields; invalid adapter/version; every artifact missing, symlink, hard link, non-regular, oversized, size/digest mismatch; bundle-ID collision; extra files; index/manifest and approval/evidence/trust mismatch; invalid SSHSIG/KRL; rollback/fork/sequence errors; staged but unindexed and indexed incomplete bundles; crashes before directory rename or proposed index; dirty/uncommitted tree never claimed published; and proof that no private key, signing, git mutation, capability, receipt, or legacy fallback is reachable.

B0.2c PASS proves release-tree mechanics only. Real Provider evidence, independent audit, user approval, Security DRI B0.3b, protected-branch review, commit/ref CAS, B1, and Pilot remain separate gates.

---

## B0.3a: OpenSSH SSHSIG Approval Verifier + Tests (credential-free, code-ready)

**Nature**: Read-only verifier and tests for an externally signed approval record. Its fixed `ssh-keygen` allowlist contains exactly two command shapes: `-lf <temporary expected-public-key file>` for fingerprint derivation and `-Y verify ... -r <revoked.krl>` for SSHSIG verification with mandatory KRL enforcement. It never invokes `-Q`, `-Y sign`, provisions a trust root, or adds a cryptography dependency. Tests use temporary Ed25519 keys and paths only.

**Files**:
- `testkit/stock-opencode/verify_approval_record.py`
- `testkit/stock-opencode/test_verify_approval_record.py`

**Exact approval-record schema** (`nomad.stock-opencode.approval-record.v1`; no missing or extra fields):

| Field | Contract |
|-------|----------|
| `schema_version` | exact `"nomad.stock-opencode.approval-record.v1"` |
| `evidence_manifest_digest` | exact digest of the B0-verified complete evidence bundle |
| `reviewed_version` | exact B0-verified reviewed version |
| `scope` | exact enum `"nomad.m2.complete-evidence-bundle"` |
| `principal` | exact principal from trust-root policy and allowed-signers entry |
| `issued_at` | UTC RFC 3339 timestamp |
| `expires_at` | UTC RFC 3339 timestamp |
| `trust_root_id` | exact trust-root policy identifier |
| `signing_namespace` | exact `"nomad-m2-release-authorization-v1"` |
| `signature_file` | exact basename regex `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; no `.`, `..`, slash, or backslash; detached SSHSIG file, excluded from the signed core |

**Canonical signed domain input**:

```
nomad-release-authorization
approval-record-v1
<canonical JSON core excluding signature_file>
```

The two domain lines and newlines are fixed ASCII/UTF-8 bytes. Canonical JSON is UTF-8 with no BOM, `allow_nan=false`, `sort_keys=true`, separators exactly `(',', ':')`, and no trailing bytes beyond the final newline required by the frozen domain format. The verifier bounds the record, signature, policy, allowed-signers, and KRL files before parsing or invoking the tool.

**Allowed-signers grammar**:
- Exactly one non-comment, non-blank line and exactly one principal. Principal lists, commas, whitespace ambiguity, and glob characters are forbidden.
- Options are exactly `namespaces="nomad-m2-release-authorization-v1"`; no other option is accepted. In particular, `cert-authority`, `valid-after`, and `valid-before` are forbidden.
- Key type is exactly `ssh-ed25519`; key material is strict valid base64 and decodes to a structurally valid Ed25519 SSH public key. No certificate key, unknown option/token, trailing field/comment ambiguity, or multiple key is accepted.
- The expected public key is obtained only after this mechanical parse succeeds. It is never accepted from the approval record. The verifier writes only that mechanically validated public key to its private temporary expected-key file for the two allowlisted tool calls.

**Exact trust-root-policy schema** (`nomad.stock-opencode.trust-root-policy.v1`; no missing or extra fields):

| Field | Contract |
|-------|----------|
| `schema_version` | exact `"nomad.stock-opencode.trust-root-policy.v1"` |
| `trust_root_id` | exact derived value `ssh-ed25519:<fingerprint>` |
| `fingerprint` | exact fingerprint recomputed by allowlisted `ssh-keygen -lf` over the expected public key |
| `principal` | exact single allowed-signers principal |
| `namespace` | exact `"nomad-m2-release-authorization-v1"`, equal to record and allowed-signers option |
| `key_type` | exact `"ssh-ed25519"` |
| `max_validity_seconds` | exact integer `2592000` |
| `clock_skew_seconds` | integer in `[0,300]`; the verifier hard-caps Pilot clock skew at five minutes, and production policy may choose a smaller value only |
| `ssh_keygen` | exact object with no extra fields: `platform_paths` has exactly `darwin-arm64` and `linux-x86_64`, each containing one or more absolute executable realpath allowlist entries |
| `revocation_policy` | exact policy requiring the fixed KRL through `-Y verify -r`; no separate revocation classification |

The verifier may parse only the bounded, controlled stdout of `ssh-keygen -lf`, using the frozen fingerprint output format; stderr is never exposed. The recomputed fingerprint must equal policy `fingerprint`; policy `trust_root_id` must equal `ssh-ed25519:<fingerprint>`; and record `trust_root_id` must exactly equal that derived value. Record, policy, allowed-signers, and `-Y` namespace must all be identical.

**Path and file policy**:
- Tests inject all paths and use only `TemporaryDirectory`.
- Production paths are fixed under `security/trust/b0.3/`: `allowed_signers`, `trust-root-policy.json`, and `revoked.krl`. The approval-record path is the single fixed production input path, not an alternate caller argument. The signature path is derived only as `record_path.parent / signature_file`; after resolution it must remain directly inside that fixed record directory. No alternate signature path argument is accepted.
- Record and trust-root policy are each read and parsed exactly once from the same already-open, bounded, regular, no-follow file descriptor; canonical record input is derived from those exact record bytes. Signature, allowed-signers, and KRL are likewise read once from bounded, regular, no-follow descriptors and mechanically validated before any tool call. Symlinks, non-regular files, oversized inputs, duplicate keys, invalid UTF-8, basename traversal, and file replacement inconsistencies fail closed.
- Before invoking `ssh-keygen`, create a private `TemporaryDirectory` with mode `0700`. Materialize the already-validated allowed-signers bytes, KRL bytes, signature bytes, and expected-public-key bytes into distinct snapshot files using exclusive creation (`O_CREAT|O_EXCL`), mode `0600`, complete writes, `fsync`, and close-before-use. The tool receives only these snapshot paths; it must never receive or reopen the original allowed-signers, KRL, signature, record, or policy paths. Replacement of an original file after its same-FD read cannot affect the current verification. Snapshot paths are internal and cannot be selected or replaced through a user-controlled path. Cleanup of every snapshot and the private directory is mandatory and verified on success and every failure path; incomplete cleanup fails closed.

**Verification policy**:
1. Select the exact current platform key (`darwin-arm64` or `linux-x86_64`); any other platform fails closed. Resolve the selected executable to its realpath and require that realpath to be an absolute entry in that platform's policy allowlist, a regular executable file, and not merely an arbitrary `PATH` match. A successful controlled `-lf` call confirms the selected executable for fingerprint use. No fallback verifier.
2. After exact allowed-signers parsing and snapshot creation, invoke allowlisted `ssh-keygen -lf <snapshot expected pubkey>` and accept only its bounded fixed-format fingerprint stdout. Any nonzero exit (including 255), spawn/execute error, timeout, signal, or malformed controlled output/status maps to `FAIL_APPROVAL_TOOL`.
3. Only after every record, signature, path, allowed-signers, trust-policy, namespace, time, bundle, executable, snapshot, and fingerprint check succeeds, spawn exactly one `ssh-keygen -Y verify` with the policy principal, identical record/policy/allowed-signers namespace, the allowed-signers snapshot, the signature snapshot, and mandatory `-r <KRL snapshot>`. If spawn succeeds and the process completes without timeout or signal, exit 0 means `VERIFIED` and every nonzero exit, including 255, means `FAIL_APPROVAL_SIGNATURE`. This covers revoked keys, bad signatures, unknown signers, and all other verification rejection without parsing stdout or stderr. Spawn/execute `OSError`, timeout, or signal termination maps to `FAIL_APPROVAL_TOOL`. Never invoke signing or accept a key from the approval record.
4. Except for bounded fixed-format `-lf` stdout, do not expose tool stdout; never expose stderr. Consume only controlled bounded output/status and map it to controlled verdicts.
5. Require strict UTC RFC3339 `Z` timestamps, `issued_at < expires_at`, `expires_at - issued_at <= max_validity_seconds == 2592000`, `clock_skew_seconds` in `[0,300]`, `issued_at` not later than current UTC plus policy clock skew, and `expires_at` later than current UTC minus that skew. Offset timestamps, date-only forms, and unbounded fractional forms fail closed.
6. Require exact `scope`, exact bundle `evidence_manifest_digest`, and exact `reviewed_version` from the B0-verified bundle.
7. Require exact trust-policy schema, selected-platform executable realpath, derived trust-root ID/fingerprint, principal, namespace, key type, allowed signer, signature path binding, snapshot integrity/cleanup, and KRL-enforced verification.

**Controlled errors**: `BLOCKED_APPROVAL_RECORD_MISSING`, `BLOCKED_APPROVAL_SIGNATURE_MISSING`, `BLOCKED_TRUST_POLICY_MISSING`, `BLOCKED_ALLOWED_SIGNERS_MISSING`, `BLOCKED_REVOCATION_KRL_MISSING`, `BLOCKED_SSH_KEYGEN_UNAVAILABLE`, `FAIL_APPROVAL_SCHEMA`, `FAIL_APPROVAL_DUPLICATE_KEY`, `FAIL_APPROVAL_FILE_POLICY`, `FAIL_APPROVAL_CANONICALIZATION`, `FAIL_APPROVAL_BUNDLE_BINDING`, `FAIL_APPROVAL_SCOPE`, `FAIL_APPROVAL_TIME_WINDOW`, `FAIL_APPROVAL_ALLOWED_SIGNERS`, `FAIL_APPROVAL_TRUST_POLICY`, `FAIL_APPROVAL_FINGERPRINT`, `FAIL_APPROVAL_SIGNATURE`, and `FAIL_APPROVAL_TOOL`. Classification is command-stage-specific: `-lf` nonzero (including 255) or abnormal execution returns `FAIL_APPROVAL_TOOL`; a successfully spawned, non-timeout, non-signaled formal `-Y verify` returns `VERIFIED` only on 0 and `FAIL_APPROVAL_SIGNATURE` on every nonzero exit including 255. `-Y` spawn `OSError`, timeout, or signal returns `FAIL_APPROVAL_TOOL`. No `-Y` stdout or stderr is parsed or exposed. This deliberately trades diagnostic precision for a smaller fail-closed error model.

**Tests**: valid real path must make the formal `-Y verify` exit 0; tampered digest/reviewed-version/scope/canonical bytes; signature basename boundary plus `.`, `..`, slash, backslash, traversal, alternate-path, symlink, non-regular, and oversized cases; allowed-signers blank/multiple lines, multiple/glob principal, missing/wrong/extra options, `valid-after`/`valid-before`, cert-authority, wrong key type, bad base64, trailing ambiguity, multiple keys; trust policy missing/duplicate/extra fields, wrong fingerprint/derived trust-root ID/principal/namespace/key type/max validity/skew outside `[0,300]`/revocation policy/platform paths; exact platform path accepted, wrong platform path rejected, symlink resolved to an allowlisted realpath, symlink resolving outside allowlist rejected, and other platforms rejected; strict UTC `Z` timestamp grammar, rejected offsets/date-only/unbounded fraction; record and policy same-FD single parse; original signature/allowed-signers/KRL replacement after snapshot leaves current verification bound to the validated snapshot; tool argv contains no original input paths; private directory is `0700`, snapshots are exclusive `0600`, user-path snapshot tampering is impossible, and cleanup is verified by confirming the directory and every snapshot are absent after both success and failure (including a non-cleaning context manager that does not raise); record-policy-allowed-signers namespace mismatch; real wrong signer, bad signature, KRL-revoked signer, and any mocked formal `-Y` nonzero all mapping to `FAIL_APPROVAL_SIGNATURE`; mocked `-lf` exit 255 mapping to `FAIL_APPROVAL_TOOL`; mocked successfully spawned `-Y` exit 255 mapping to `FAIL_APPROVAL_SIGNATURE`; expired, future, and over-30-day records; `-lf` tool missing/nonzero/timeout/signal/unexecutable/malformed output mapping to `FAIL_APPROVAL_TOOL`; formal `-Y` spawn `OSError`, timeout, and signal mapping to `FAIL_APPROVAL_TOOL`; and rotation with old/new allowed signers followed by old-key revocation returning `FAIL_APPROVAL_SIGNATURE`. Tests may call `ssh-keygen` to create disposable Ed25519 keys and signatures under the temporary directory only; they never create production keys, policies, records, or signatures.

**Status**: **READY** — credential-free verifier work using temporary keys only.
**Worker**: `m2_capture_scaffold`
**Auditor**: `m1_evidence_audit`
**NO-GO**: B0.3a PASS proves verifier mechanics only. Any allowed-signers ambiguity, platform executable realpath failure, trust-policy/fingerprint/derived-ID mismatch, signature path or snapshot/cleanup failure, namespace disagreement, KRL revocation, unknown signer, bad signature, nonzero formal verification, or abnormal tool execution fails closed under the controlled classifications above. It does not provision or approve a production trust root and cannot unlock B1.

---

## B0.3b: Production Trust-Root Provisioning (external governance blocked)

**Nature**: Security DRI governance and operational provisioning outside agent authority. A Security DRI must issue a signed decision outside the repository, followed by protected-branch review of the public policy artifacts. The decision freezes the public-key fingerprint, exact principal, exact namespace, maximum validity/clock-skew policy, rotation procedure, and revocation owner.

**Production artifacts**:
- `security/trust/b0.3/allowed_signers`
- `security/trust/b0.3/trust-root-policy.json`
- `security/trust/b0.3/revoked.krl`
- one valid production approval JSON and detached SSHSIG matching the B0-verified bundle

Agent, CI, chat, and the verifier cannot bootstrap, nominate, or self-approve the trust root. The private signing key must never enter the repository, workspace, CI variables/artifacts, logs, prompts, or chat. Only public policy, allowed signer material, revocation data, and the externally produced signed record may be reviewed/versioned.

**Status**: **BLOCKED_EXTERNAL_GOVERNANCE**.
**Owner**: Security DRI
**Auditor**: protected-branch security reviewer, independent of the signer and implementation worker
**NO-GO**: Until the production policy, allowed signer, KRL, and a currently valid signed record exist and B0.3a returns VERIFIED, there is no `ReleaseAuthorization`; B1 remains blocked.

---

## B1: RealLifecycleEvidence::Captured + Run-Scoped Capability (Rust, blocked)

**Files**: `connector/src/stock_opencode.rs` (extend `RealLifecycleEvidence`, `VerifiedM2Capabilities`, `from_receipts()`)

**`RealLifecycleEvidence` extension**:
```rust
pub enum RealLifecycleEvidence {
    Unavailable,
    Captured {
        evidence_manifest_digest: String,     // B0 evidence_manifest_digest
        certificate_digest: String,           // cert file canonical digest
        shape_manifest_digest: String,        // shape file canonical digest
        historical_certified_launch_provenance: String,  // from manifest
        current_committed_evidence_provenance: String,   // B0.1, actual repo bytes
        current_actual_launch_provenance: String,        // runtime launch_locked_opencode formula
        reviewed_version: String,             // from B0 manifest
    }
}
```

**`VerifiedM2Capabilities` extension**:
```rust
pub struct VerifiedM2Capabilities {
    evidence_manifest_digest: String,
    capability_digest: String,  // locally recomputed expected_capability_digest
}
```

**Three non-substitutable provenance classes**:

1. `current_committed_evidence_provenance_digest`: B0.1 recomputation from current repository evidence bytes. It is not proof of an actual launch.
2. `historical_certified_launch_provenance_digest`: the A0 shape-manifest claim computed by the historical `launch_locked_opencode` formula for the certified run.
3. `current_actual_launch_provenance_digest`: recomputed at B1 runtime with the same `launch_locked_opencode` formula over package, lock, full locked closure, installed-platform closure, entrypoint target, npm version, task digest, and fixture digest.

The current actual launch must match reviewed policy for package digest, lock digest, full closure digest/count, entrypoint target, npm version, fixture digest, and task digest. Historical provenance is retained as historical evidence, not substituted for this runtime check. Any required-policy mismatch returns `Err(SafetyBlocked)`.

**Unique capability derivation**:

```
expected_capability_digest = SHA256(canonical {
  schema_version,
  evidence_manifest_digest,
  certificate_digest,
  shape_manifest_digest,
  current_actual_launch_provenance_digest,
  reviewed_version,
  RunBinding.run_id,
  RunBinding.proxy_origin
})
```

`RunBinding.capability_digest` is an authenticated received claim only. `from_receipts()` must recompute `expected_capability_digest` from the fields above and compare it in constant time with that claim; it stores/returns only the recomputed digest. No caller-provided digest string or arbitrary authenticated claim is sufficient.

**`from_receipts()` additional validation**:
1. `evidence_manifest_digest` matches committed B0 evidence manifest canonical digest
2. `certificate_digest` matches committed cert file canonical digest
3. `shape_manifest_digest` matches committed shape manifest file canonical digest
4. `historical_certified_launch_provenance` matches manifest's `launch_provenance_digest`
5. `current_committed_evidence_provenance` matches B0.1's actual-repository-byte recomputation
6. `reviewed_version` is non-empty ASCII
7. `current_actual_launch_provenance` is recomputed with the exact `launch_locked_opencode` formula and every required component matches reviewed policy
8. The current run scope is an `&RunBinding`; `from_receipts()` recomputes the unique expected digest from `run_id` and `proxy_origin`, then compares the received `RunBinding.capability_digest` claim

**`#[cfg(feature = "a0_certificate")]`**: Compile-time gate for `include_str!` bytes availability. The file must exist in the working tree at compile time. Runtime `from_receipts()` independently validates all digests — the feature flag provides no runtime bypass.

**Negative tests**: evidence-manifest/cert/shape mismatch, historical provenance mismatch, committed-evidence provenance mismatch, each current-actual-launch policy mismatch, reviewed_version empty, missing RunBinding, arbitrary capability claim, run_id mismatch, proxy_origin mismatch, feature flag without real file, feature flag with forged JSON.

**Dependencies**: Consistently published B0.2b production bundle + B0.3a verifier PASS + B0.3b production policy/allowed signer/KRL/current valid signed record + real same-run A0 pair + A3/A4.2/B0.1 VERIFIED.
**Status**: **BLOCKED** — requires completed B0.2b consistent publication, B0.3a PASS, B0.3b production authorization, and real credential-backed evidence.

**Worker**: `m2_capture_scaffold`
**Auditor**: `m1_evidence_audit`
**NO-GO**: Any evidence, required launch-policy, or recomputed capability mismatch → `Err(SafetyBlocked)`. RunBinding absent or its capability claim arbitrary/mismatched → `Err(SafetyBlocked)`.

---

## B2: ReviewedLifecycleShapeBoundStockEventMapper (Rust, blocked)

**Files**: `connector/src/stock_opencode.rs` (extend `StockObservationOutcome`, `observe_json()`, add `ReviewedLifecycleShapeBound`)

**Design**: The mapper loads the reviewed lifecycle shape manifest and uses it to classify live events. The manifest provides historical relation facts; the mapper applies runtime relation checks.

**`ReviewedLifecycleShapeBound` struct**:
```rust
pub struct ReviewedLifecycleShapeBound {
    shape_manifest_digest: String,
    // Loaded from include_str! of lifecycle-shape-manifest.json
    known_event_types: BTreeMap<String, EventShape>,
}
pub struct EventShape {
    observed_event_type: String,
    property_field_count: u8,
    property_field_names: Vec<String>,  // sorted, content-free names
    property_field_types: BTreeMap<String, PropertyTypeShape>,
}
```

**Relation classification and required runtime context**:

| Relation | Class | Required context for runtime recheck |
|----------|-------|--------------------------------------|
| `session_id_equality` | runtime_recheckable | POST session response plus matching GET session snapshot and route session id |
| `question_snapshot_id_used_in_reply_route` | runtime_recheckable | question snapshot id plus actual question reply route |
| `permission_snapshot_id_used_in_reply_route` | runtime_recheckable | permission snapshot id plus actual permission reply route |
| `question_permission_ids_distinct` | runtime_recheckable | both question and permission snapshot ids from the same run |
| `permission_name_is_bash` | runtime_recheckable | permission snapshot permission field |
| `patterns_is_single_string_list` | runtime_recheckable | permission snapshot patterns field |
| `pattern_matches_fixed_test_command` | runtime_recheckable | permission pattern plus reviewed fixed test command |
| `diff_count_relation == "files_ge_1"` | runtime_recheckable | diff snapshot/cardinality for the same session |
| `snapshot_cardinalities` | runtime_recheckable | complete per-endpoint request accounting for the evaluated run |
| historical event/property shapes | historical_only unless the complete live event properties are present | complete live properties for a shape comparison; otherwise no runtime relation conclusion |

Historical-only evidence describes the certified run and never proves a current relation. A runtime-recheckable relation may become `Known` only when all listed same-run context is available and matches. Missing or partial context returns `UnknownRequiresReconciliation { reason: "relation_context_unavailable" }`; it must never return `Known`.

**Runtime relation checks** — applied to each live event:
- `Known { outcome: ... }` is permitted only when B1 `VerifiedM2Capabilities` is valid, the reviewed shape-manifest digest matches the verified bundle, event type/property names/bounded recursive shape all match, and every runtime-recheckable relation associated with that event has the complete same-run context listed above and revalidates successfully. Historical-only facts never count as current proof.
- Event type + property shape without all required relation context → `UnknownRequiresReconciliation { reason: "relation_context_unavailable" }`; it must not produce `Known`. An event with no runtime-recheckable relation may be shape-classified directly only if that exception is explicitly enumerated per event in the reviewed contract.
- Known event type but property shape differs → `UnknownRequiresReconciliation { reason: "property_shape_drift" }`
- Extra property field name not in manifest → `UnknownRequiresReconciliation { reason: "extra_field" }`
- Event type not in manifest → `UnknownRequiresReconciliation` (existing)
- Provenance digest mismatch → `SafetyBlocked`
- Cardinality exceeds manifest → `UnknownRequiresReconciliation { reason: "cardinality_drift" }`
- A runtime relation with complete context but a different result → `UnknownRequiresReconciliation` with a relation-specific reason code
- Required runtime relation context absent/incomplete → `UnknownRequiresReconciliation { reason: "relation_context_unavailable" }`

**Content-free constraint**: The mapper classifies by shape, not by value. Raw IDs, prompt, answer, command, diff, tool output never enter the classification outcome.

**Negative tests**: unknown event type, extra property name, property type drift, depth violation, count violation, event type + valid shape but missing relation context, each relation with missing context, each recheckable relation mismatch with complete context, historical-only fact presented as current proof, provenance mismatch, manifest digest mismatch, and valid classification only with all required context.

**Dependencies**: B1 `VerifiedM2Capabilities` + real shape manifest + real certificate.
**Status**: **BLOCKED** — requires B1 + real credential.

**Worker**: `m2_capture_scaffold`
**Auditor**: `m1_evidence_audit`
**NO-GO**: Any drift/unknown → `UnknownRequiresReconciliation` or `SafetyBlocked`. No silent fallback to known outcome.

---

## C1: pilot_host_bridge Real FD Adoption + Stock Transport (Rust, blocked)

**Files**: `connector/src/bin/pilot_host_bridge.rs`, `connector/src/run_binding.rs`

**Dependencies**: B1 `VerifiedM2Capabilities` + `ObservingProxy` HTTP endpoint.
**Status**: **BLOCKED**.
**Worker**: `m2_capture_scaffold`
**Auditor**: `m1_evidence_audit`

---

## C2: Harness-Owned Exact 19 Receipts (Python, code ready, blocked)

**Files**: `testkit/pilot/m2_integration.py` (extend `M2IntegrationHarness`), `testkit/iteration3_receipts.py` (no changes)

**Dependencies**: Real credential + `VerifiedM2Capabilities`.
**Status**: **BLOCKED**. Code schema is ready; real receipt store requires real credential.
**Worker**: code already exists
**Auditor**: `m1_evidence_audit`

---

## D: Real H→R→G→M Runner + Independent Verifier (blocked)

**Dependencies**: All previous packages.
**Status**: **BLOCKED**.

---

## Pilot Gate (governance, blocked)

**Dependencies**: D + PRD exit criteria.
**Status**: **BLOCKED**.

---

## Status Summary

| Package | Credential-free? | Dispatchable now? | Worker | Auditor | Status |
|---------|-----------------|-------------------|--------|---------|--------|
| **B0.1** evidence-manifest verifier | ✅ Yes | No further dispatch | `m2_capture_scaffold` | `m1_evidence_audit` | COMPLETE / INDEPENDENT PASS |
| **B0.1c** public evidence derivation | ✅ Yes | No further dispatch | `m2_receipt_verifier` | `m1_architecture_audit` then `m1_evidence_audit` | COMPLETE / INDEPENDENT PASS |
| **B0.2a** staged-bundle mechanics | ✅ Yes | Architecture audit first | `m2_capture_scaffold` | `m1_architecture_audit` then `m1_evidence_audit` | READY_FOR_ARCH_AUDIT |
| **B0.2c1** release-bundle verifier | ✅ Yes | No further dispatch | `release_bundle_verifier` | `m1_architecture_audit` then `m1_evidence_audit` | COMPLETE / INDEPENDENT PASS |
| **B0.2c2** worktree materializer | ✅ Yes | No further dispatch | materializer worker | `m1_architecture_audit` then `m1_evidence_audit` | COMPLETE / INDEPENDENT PASS |
| **B0.2d** build/runtime consumption | ✅ Mechanics | ❌ | Rust/build worker | independent Rust/security audit | BLOCKED_ARCHITECTURE |
| B0.2b real audit/approval/publication | No | ❌ | operator + Security DRI | independent evidence + protected-branch security reviewers | BLOCKED |
| **B0.3a** SSHSIG approval verifier | ✅ Yes | No further dispatch | `m2_capture_scaffold` | `m1_evidence_audit` | COMPLETE / INDEPENDENT PASS |
| B0.3b production trust-root provisioning | No | ❌ | Security DRI | independent protected-branch security reviewer | BLOCKED_EXTERNAL_GOVERNANCE |
| B1 Captured variant | No | ❌ | `m2_capture_scaffold` | `m1_evidence_audit` | BLOCKED |
| B2 Shape-bound mapper | No | ❌ | `m2_capture_scaffold` | `m1_evidence_audit` | BLOCKED |
| C1 FD adoption | No | ❌ | `m2_capture_scaffold` | `m1_evidence_audit` | BLOCKED |
| C2 19 receipts | No | ❌ | code ready | `m1_evidence_audit` | BLOCKED |
| D/Pilot | No | ❌ | — | — | BLOCKED |

## Cross-Cutting Constraints

| Constraint | Enforced By |
|------------|-------------|
| No `include_str!` on missing evidence | `#[cfg(feature = "a0_certificate")]` compile gate |
| No feature flag accepting forged JSON | A3 + A4.2 + B0.1 verification + runtime re-validation in `from_receipts()` |
| No `TestAuthority` in production | `run_m2_safe_mode()` uses normal `ObservingProxy` constructor |
| `allow_once=false` | `ERR_SAFETY_BLOCKED` in `pilot_host_bridge.rs`, `Decision(403, ...)` in proxy |
| `OutcomeUnknown` no retry | `existing_command_result()` returns `Err(ConnectorError::OutcomeUnknown)` |
| Credential only in OpenCode subprocess | `M2IntegrationHarness` + `credential_present()` pattern |
| B0.1 does not contain approval/signature/authorization | Schema excludes `approval_identity`; verifier is read-only |
| B0.1 `current_committed_evidence_provenance_digest` is actual-byte-derived | Verifier directly recomputes official/capture/package/lock/closure inputs and cross-checks every capture/official claim |
| B0.2a never publishes or rolls back a final file | Fixed staged paths, exclusive writes, and terminal `CANDIDATE_STAGED`; B0.2b owns any future consistent publication |
| B0.2a cannot synthesize governance authority | Independent audit, explicit user approval, external B0.3b signature, and B0.3a verification remain separate gates |
| Multi-file consistency is fail-closed | If independently reviewed no-replace publication cannot guarantee a consistent bundle, preserve staged bytes and return `BLOCKED_ATOMIC_PUBLISH` |
| Production visibility is one protected-ref CAS | External protected CI compares expected parent OID and updates one ref to a commit containing index plus immutable bundle; local materialization is not publication |
| Release envelope is adapter-neutral | Static adapter registry freezes artifact set, verifier and approval scope; unknown or masquerading adapters fail closed |
| B1 `current_run_scope` only from `&RunBinding` | `from_receipts()` accepts `&RunBinding`, not `String` |
| B2 context-insufficient → reconciliation | `UnknownRequiresReconciliation`, not `Known` |

## Evidence Chain

```
A0 real run ──▶ staged cert + staged shape ──A3/A4.2──▶ VERIFIED staged pair
                                                        │
                                explicit reviewed_version + staged evidence manifest
                                                        │
                                           B0.1 exact VERIFIED staged triple
                                                        │
                                  independent evidence/binding audit + user approval
                                                        │
                         B0.3b Security DRI trust root + signed record ──B0.3a──▶ VERIFIED
                                                        │
                     B0.2c immutable adapter bundle + release index (mechanics verified)
                                                        │
                 external protected CI/reviewer commit + expected-parent ref CAS
                                                        │
                         B0.2d same-commit build embedding + runtime revalidation
                                                        │
                                           B1 Captured + RunBinding
                                                        │
                                           B2 Shape-bound mapper
                                                        │
                                           C1 → C2 → D → Pilot
```

**B0.1, B0.1c, B0.2a, and B0.3a are independently complete mechanics. B0.2c1 is the next credential-free architecture package.** None creates real evidence, approval, protected-ref visibility, or runtime authorization. B0.2b, B0.3b, B0.2c2 production materialization, B0.2d, B1, and all later packages remain BLOCKED until their separate real-run, independent-audit, user-approval, external-governance, protected-CAS, build-binding, and runtime gates pass.
