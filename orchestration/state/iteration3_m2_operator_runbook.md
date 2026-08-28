# M2 B0.2 Staged Lifecycle Evidence - Operator Runbook

This procedure runs one real Provider-backed task with locked official OpenCode 1.18.16 and produces a local staged candidate triple. It can incur Provider usage. It does not publish evidence, create approval, unlock B1, or authorize product, Pilot, or release work.

## Security boundary

- Set one temporary and revocable Provider key locally. Never put its value in chat, argv, files, logs, receipts, or version control.
- Ambient OpenCode auth is forbidden. Allowed names: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, GOOGLE_GENERATIVE_AI_API_KEY, OPENROUTER_API_KEY, DEEPSEEK_API_KEY.
- reviewed_version is an explicit governance input. It is never inferred from git, package metadata, a filename, or an environment default.
- Success ends at CANDIDATE_STAGED. It cannot mean CERTIFIED, APPROVED, RELEASE_AUTHORIZED, or B1_READY.

## Six-path preflight

From the repository root, first run the read-only Phase 4 readiness doctor:

```bash
python3 testkit/pilot/readiness_doctor.py --json
```

Exit `0` means only `READY_FOR_OPERATOR_PREFLIGHT`; it is not production
authorization and does not satisfy Developer ID, SSHSIG, protected-CAS, or
real-evidence gates. Exit `1` reports content-free per-gate states that must be
resolved without overriding or deleting existing evidence.

Then confirm that all six evidence paths are absent:

```bash
test ! -e testkit/stock-opencode/real-task/lifecycle-certificate.json
test ! -e testkit/stock-opencode/real-task/lifecycle-shape-manifest.json
test ! -e testkit/stock-opencode/lifecycle-evidence-manifest.json
test ! -e testkit/stock-opencode/real-task/lifecycle-certificate.json.tmp
test ! -e testkit/stock-opencode/real-task/lifecycle-shape-manifest.json.tmp
test ! -e testkit/stock-opencode/lifecycle-evidence-manifest.json.tmp
python3 testkit/stock-opencode/real_task_capture.py --verify-command-shapes
```

Do not delete, reuse, truncate, or overwrite a pre-existing final or staged file. The implementation also checks both fixed directories with lstat: they must be real directories owned by the effective user, group and other non-writable, and real-task must be the direct child of testkit/stock-opencode. There is no output or root override, force option, or automatic mkdir.

## Real staged run

Example using a temporary OpenAI key and explicit reviewed version:

```bash
export OPENAI_API_KEY='set-locally-do-not-paste'
python3 testkit/stock-opencode/discover_lifecycle.py \
  --provider-credential-env OPENAI_API_KEY \
  --reviewed-version v0.1.0
```

A successful command prints a JSON object whose status is CANDIDATE_STAGED. It leaves these three content-free mode-0600 staged files and no final file:

- testkit/stock-opencode/real-task/lifecycle-certificate.json.tmp
- testkit/stock-opencode/real-task/lifecycle-shape-manifest.json.tmp
- testkit/stock-opencode/lifecycle-evidence-manifest.json.tmp

The fixed order is: freeze certificate and shape from one single-use real-run authority; exclusively stage both; require A3 exact VERIFIED; require A4.2 exact VERIFIED; derive evidence through the audited B0.1c public API with explicit reviewed_version; exclusively stage evidence; require B0.1 exact VERIFIED over the staged triple.

Every write is bounded, O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, complete-write, fsync, then close. A crash or gate failure preserves the exact staged prefix. The implementation never renames, replaces, unlinks, publishes, or rolls back a final file.

## Stable stop conditions

- BLOCKED_OUTPUT_DIR_MISSING or BLOCKED_OUTPUT_DIR_POLICY: fixed directory policy failed.
- BLOCKED_CERTIFICATE_ALREADY_EXISTS, BLOCKED_SHAPE_ALREADY_EXISTS, BLOCKED_EVIDENCE_ALREADY_EXISTS: a final target exists.
- BLOCKED_CERTIFICATE_TMP_EXISTS, BLOCKED_SHAPE_TMP_EXISTS, BLOCKED_EVIDENCE_TMP_EXISTS: a staged target exists.
- BLOCKED_REVIEWED_VERSION_REQUIRED: explicit reviewed version is absent or malformed.
- BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED: selected name is not allowlisted or has no value.
- FAIL_A3_VERIFY, FAIL_A4_2_VERIFY, FAIL_B0_1_DERIVATION, FAIL_B0_1_VERIFY: the staged evidence chain failed.

On any stop condition, preserve the exact state for independent review. Never use a glob, recursive cleanup, or automatic deletion.

## Independent verification

Unset the credential, then verify the exact staged files:

```bash
unset OPENAI_API_KEY
python3 testkit/stock-opencode/verify_certificate.py testkit/stock-opencode/real-task/lifecycle-certificate.json.tmp
python3 testkit/stock-opencode/verify_shape_manifest.py testkit/stock-opencode/real-task/lifecycle-shape-manifest.json.tmp testkit/stock-opencode/real-task/lifecycle-certificate.json.tmp
python3 testkit/stock-opencode/verify_evidence_manifest.py testkit/stock-opencode/lifecycle-evidence-manifest.json.tmp testkit/stock-opencode/real-task/lifecycle-certificate.json.tmp testkit/stock-opencode/real-task/lifecycle-shape-manifest.json.tmp
```

Each command must exit 0 and print exactly VERIFIED. The reviewer separately confirms full pair digests, structural and source binding, historical launch provenance, current committed-evidence provenance, exact reviewed version, content-free compliance, and that no final artifact exists.

## Governance after a valid candidate

1. The user explicitly approves the exact complete staged triple and reviewed version.
2. A Security DRI outside repo, agent, CI, and chat authority provisions B0.3b policy, allowed signer, KRL, and SSHSIG for the exact B0-verified digest and version.
3. B0.3a verifies that current approval with exact VERIFIED.
4. Publication remains BLOCKED_ATOMIC_PUBLISH. Three file renames are forbidden. B0.2c must first validate an immutable versioned bundle plus a single visibility point.

This runbook performs no commit, push, signing, trust bootstrap, approval synthesis, publication, or downstream unlock.
