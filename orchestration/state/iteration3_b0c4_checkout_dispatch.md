# Iteration 3 B0c-4 Checkout-After-CAS Verifier Dispatch

Status: IMPLEMENTED / FINAL INDEPENDENT P0-P1-P2 PASS

## Product boundary

B0c-4 is a credential-free, read-only verifier for local checkout-after-CAS mechanics. It observes a local protected-ref mirror and clean checkout after an external actor claims to have completed a protected-ref compare-and-swap. It never fetches, commits, checks out, signs, pushes, updates a ref, creates trust, starts OpenCode, reads Provider credentials, grants capability, or makes an artifact supervisor-consumable. Success is exactly `VERIFIED_HOST_POST_CAS_CHECKOUT_MECHANICS`; every failure is content-free `BLOCKED_HOST_POST_CAS_CHECKOUT_MECHANICS`. Success is not proof that a remote hosting service enforced branch protection or CAS.

## Public interface and fixed authority surface

The public CLI accepts exactly the same four absolute-or-cwd-resolved canonical snapshot files as B0c-3, in this order: publication request, proposed tree snapshot, clean source snapshot, and sealed lineage snapshot. It accepts no repository path, ref, Git executable, expected OID, callback, environment mapping, or alternate policy.

`repository_root` is the canonical realpath of the source checkout containing `verify_host_post_cas_checkout.py`, derived from the module location; the public CLI cannot override it. The root directory's device/inode and canonical path are captured before verification and must be unchanged afterward. The protected ref is fixed to `refs/heads/production/nomad-host`.

The production path resolves only the compiled platform allowlist entry `/usr/bin/git`, requires exact canonical realpath plus regular executable identity, invokes with `shell=False`, `close_fds=True`, null stdin/stderr, bounded stdout and timeout, and an environment containing only `LC_ALL=C`, `LANG=C`, and `GIT_OPTIONAL_LOCKS=0`. Timeout, overflow, spawn/read/wait/kill failure, signal exit, or unconfirmed cleanup blocks. Test injection of a repository root or Git runner is private/internal and unreachable from the public CLI.

## B0c-3 same-read reuse

B0c-4 validates B0c-3 on the exact in-memory values it later consumes. Refactor B0c-3 only as needed to provide one private read-and-verify helper that performs its existing no-follow, single-link, bounded, identity-stable reads and returns one private frozen `_VerifiedPublicationSnapshots` value. That value contains recursively immutable request, tree, source, and lineage mappings only after all existing exact schemas and relations pass. B0c-4 consumes only that returned value and never rereads any of the four snapshot paths. The B0c-3 public CLI, marker, blocker, field constants, validation semantics, and tests remain behaviorally identical. Calling the B0c-3 path verifier and then independently rereading mutable snapshot paths is forbidden.

## Required Git observations

The verified request supplies `repository_object_format`, `expected_parent_oid`, `proposed_commit_oid`, `source_commit_oid`, `candidate_id`, and the fixed five paths. B0c-4 performs a before observation, immutable-object verification, and an after observation. Both before and after independently establish:

- `git rev-parse --show-toplevel` returns exactly the canonical `repository_root`;
- `git rev-parse --show-object-format` equals request format `sha1` or `sha256`, and all OID lengths match it;
- `git show-ref --verify --hash refs/heads/production/nomad-host` returns exactly one line equal to the proposed OID;
- `git rev-parse HEAD` returns exactly one line equal to the proposed OID;
- `git status --porcelain=v1 --untracked-files=all` succeeds with empty output, proving clean tracked state and an empty untracked set;
- repository-root device/inode/canonical identity is unchanged.

The immutable-object phase requires expected parent, proposed, and B0c-3 source OIDs to resolve as commit objects. `git rev-list --parents -n 1 <proposed>` must return exactly `<proposed> <expected-parent>`, with no second parent, extra token, leading/trailing whitespace ambiguity, or malformed OID. Applicable outputs are strict ASCII.

The publication commit is dedicated: `/usr/bin/git -C <fixed-root> diff-tree --no-commit-id --name-only -r -z <expected-parent> <proposed>` returns, with no duplicate or unrelated path, exactly the five paths below for a forward publication, or only `evidence/host-artifacts/current.json` for rollback because the historical immutable candidate already exists in the parent tree. The verifier compares the parsed path set and does not trust Git output order. A Host publication commit may not carry unrelated source, documentation, workflow, or evidence changes. Both operations still read and verify the same five blobs from the proposed commit tree.

The B0c-3 source snapshot records the earlier clean source checkout at `source_commit_oid`; it does not claim the present checkout remains at that OID. B0c-4's present checkout is at `proposed_commit_oid`. Source provenance and post-CAS observation are distinct roles.

## Exact Git tree contract

Run exactly:

```text
/usr/bin/git -C <fixed-root> ls-tree -r -z --full-tree <proposed-commit> -- \
  evidence/host-artifacts/current.json \
  evidence/host-artifacts/candidates/<candidate-id>
```

Parse every record only as `<mode> SP <type> SP <object-oid> TAB <raw-path-bytes> NUL`. Mode, type, and object OID are strict ASCII. Path is compared as exact ASCII bytes with no Git quoting or escape decoding. Object OID length matches repository format. Require exactly five blob records, with no duplicate, malformed, directory, symlink, submodule, or extra record:

- `evidence/host-artifacts/current.json`, Git mode `100644`;
- candidate `nomad-host`, Git mode `100755`;
- candidate `host-manifest.json`, Git mode `100644`;
- candidate `expected-build.json`, Git mode `100644`;
- candidate `evidence-release-reference.json`, Git mode `100644`.

These are Git tree modes and are independent of B0b candidate filesystem modes (`0700` binary and `0600` JSON).

## Immutable blob reads and B0c-3 parity

Read each blob only with `/usr/bin/git -C <fixed-root> cat-file blob <proposed-commit>:<exact-path>`. The returned stream is raw bytes and is independently bounded at 512 KiB for JSON and 64 MiB for `nomad-host`. Overflow, truncation, timeout, nonzero or signal exit, read failure, or unconfirmed cleanup blocks. Hash and size the bytes and require the tree-record blob OID to equal the repository-format Git object hash of the exact blob bytes.

Reconstruct the five B0c-3 entry objects from observed path, `kind=regular`, observed Git mode, raw size, and raw SHA-256. Using B0c-3's exact canonicalization, reconstruct sorted entries, path digest, full proposed-tree digest, and candidate-tree digest. They must equal the same verified B0c-3 tree/request/lineage fields. Every observed SHA-256 and size must equal the corresponding ten sealed lineage raw facts. Caller tree-entry metadata never establishes the observed bytes.

## Exact active-index and Host-manifest semantics

The actual `current.json` bytes must be canonical JSON with schema `nomad.host-artifact-active-index.v1`, valid `active_index_digest` using `verify_host_lineage.py` canonicalization, and exactly these fields: `schema_version`, `operation`, `active_candidate_id`, `host_manifest_digest`, `artifact_raw_sha256`, `embedded_release_index_digest`, `bundle_manifest_digest`, `evidence_manifest_digest`, `host_approval_digest`, `host_artifact_sequence`, `previous_host_active_index_digest`, `source_commit_oid`, `expected_parent_oid`, `rollback_from_active_index_digest`, `rollback_target_candidate_id`, and `active_index_digest`. Its active candidate, host manifest digest, artifact digest, sequence, source commit, expected parent, operation, and semantic digest equal B0c-3 lineage/request facts and the observed binary. Forward/rollback authorization and lineage are delegated to the already verified B0c-2/B0c-3 inputs; B0c-4 creates neither.

The actual `host-manifest.json` bytes must be canonical JSON with schema `nomad.nomad-host-artifact.v1`, valid `host_manifest_digest`, and exactly these fields: `schema_version`, `artifact_class`, `artifact_basename`, `artifact_size_bytes`, `artifact_raw_sha256`, `platform`, `target_triple`, `source_commit_oid`, `cargo_lock_raw_sha256`, `build_profile`, `rustc_release`, `rustc_commit_hash`, `rustc_host`, `llvm_version`, `actual_launch_protocol_version`, `embedded_release`, `macos_codesign`, `host_artifact_sequence`, `previous_host_manifest_digest`, and `host_manifest_digest`. B0c-1a alone accepts production class `production-developer-id` and proves Developer ID plus verified embedded-release relations. B0c-4 requires that class and joins manifest digest, observed binary digest/size, source commit, and active-index fields, but does not repeat or replace B0c-1a, B0c-1b SSHSIG, or their combiner. On forward publication the immutable candidate manifest sequence equals the new active-index sequence. On rollback the historical candidate manifest is not rewritten: its positive sequence is strictly less than the new active-index sequence.

After the five reads and semantic checks, repeat the full root identity, `--show-toplevel`, object format, protected ref, HEAD, clean tracked/untracked status, and required source/OID relations. Any change or ambiguity blocks. Immutable commit objects plus the double observation close movement of the mutable local ref and checkout around the reads. This proves only local checkout/ref stability, not remote branch protection, remote CAS, remote ref state, or external-actor authority.

## Owner files

- new `testkit/agent-evidence/verify_host_post_cas_checkout.py`;
- new `testkit/agent-evidence/test_verify_host_post_cas_checkout.py`;
- minimal same-read helper refactor in `verify_host_publication_request.py` and its existing focused test only if required.

No connector, launcher, command, release trust, production key, ref, or `testkit/process-loop/last-transcript.json` file may be modified.

## Focused acceptance matrix

Positive mechanics cases cover SHA-1 and SHA-256 repositories, one exact parent, fixed ref, clean matching HEAD, a dedicated five-path publication diff, five exact blobs, and forward/rollback inputs. Negative cases cover wrong/moving/multiline ref; wrong/moving HEAD; wrong toplevel; root identity change; dirty/untracked checkout before or after; object-format/OID mismatch; missing/non-commit source, parent, or proposed object; zero/two/wrong parent; missing/duplicate/unsorted/extra diff path; malformed/duplicate/extra tree records; wrong Git mode/type/path/OID; extra candidate file; Git overflow, timeout, nonzero, signal, and cleanup failure; missing/oversize blob; every raw digest/size mismatch; Git blob-object hash mismatch; aggregate tree/path/candidate digest mismatch; noncanonical or semantically mismatched active index and host manifest; B0c-3 failure; and snapshot substitution around validation.

Static tests prove public CLI has no repository/ref/tool/callback override and inspect the exact executable Git argv allowlist. Only `rev-parse --show-toplevel`, `rev-parse --show-object-format`, `show-ref --verify --hash`, `status --porcelain=v1 --untracked-files=all`, `cat-file -t`, `rev-list --parents -n 1`, `diff-tree --no-commit-id --name-only -r -z`, `ls-tree -r -z --full-tree`, and `cat-file blob` are permitted. Mutation commands including `commit`, `update-ref`, `checkout`, `switch`, `reset`, `push`, `fetch`, `merge`, `rebase`, `tag`, `add`, and `rm` are forbidden. The exact-command check does not reject read-only `show-ref` merely because its name contains `ref`. Focused tests and full `testkit/agent-evidence` must pass before implementation audit.

## Freeze rule

B0c-3 request/tree/source/lineage snapshots remain caller-supplied mechanics inputs. They do not authenticate Git objects, checkout state, remote refs, branch protection, or CAS. Protected CI or the reviewer must independently regenerate and authenticate Git-object, clean-checkout, parent, and local-CAS observations before production use.

Implementation may start only after independent architecture re-audit reports no P0/P1. B0c-4 freezes only local post-CAS observation mechanics. Real production release bytes, Developer ID signing, external Host SSHSIG/trust/KRL, independently enforced protected-ref CAS, remote ref evidence, Provider-backed same-run evidence, supervisor integration, capability, commands, and product readiness remain blocked.

## Implementation record

The implementation uses a B0c-3 frozen same-read value, fixed-root and fixed-Git read-only commands, two complete local ref/HEAD/root/object-format/clean observations, exact parent and dedicated-diff checks, strict NUL-delimited tree parsing, and five bounded immutable blob reads with SHA-1/SHA-256 Git-object verification. Forward publication changes exactly five paths; rollback changes only current.json while reusing a historical candidate whose manifest sequence is lower than the new active-index sequence. Focused tests execute real SHA-1 and SHA-256 repositories for both forward and rollback. Final evidence is focused 26/26 and sequential full agent-evidence 123/123, plus py_compile and git diff --check. Independent implementation audit reports P0/P1/P2 PASS. This is local post-CAS mechanics only.
