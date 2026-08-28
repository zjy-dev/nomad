# Phase 7 Strict Evidence Resume

Status: P7-C core and the P0/P1 audit rework are implemented. CLI integration is
owned separately and is not claimed by this report.

## Scope

P7-C resumes only a strict M3-E `BLOCK` caused by an operator-remediable Host
identity authorization or normal Chrome certificate-trust gate. Resume does not
reuse a runtime directory, browser profile, process, port, certificate, pairing
record, database, journey stage, or prior assertion. It verifies provenance and
then starts the existing complete product-slice runner from its first preflight.

Provider E3 and physical-phone evidence remain `NOT_RUN`; this lane cannot
upgrade either gate or set `production_ready=true`.

## Input and provenance contract

`tools.nomad_web.evidence_resume.resume_blocked_evidence` accepts:

- a parent evidence path;
- an explicit installed bundle path;
- a new output path;
- optional runner arguments, currently limited to `--keep-runtime`.
- three required keyword-only integers: `tls_ca_fd`, `tls_cert_fd`, and
  `tls_key_fd`. These descriptors must already be opened read-only by the
  operator-facing caller.

TLS bytes are never accepted through a pathname, command argument, environment
variable, state file, or evidence field. Resume duplicates the already-opened
descriptors and transfers only the inherited FD numbers over the runner's
bounded stdin control record. The runner snapshots bytes with `pread` into its
new private runtime directory, checks stable FD identity and size, verifies the
leaf against the supplied CA, checks current validity, requires the exact LAN IP
SAN, and compares the certificate public key to the private-key public key
before Host preflight or any business-process launch.

The supplied CA is not installed by the runner. Chrome uses a fresh profile and
normal platform certificate verification. Therefore the operator must separately
establish normal Chrome trust for that CA; the CA FD proves which chain the
runner serves and probes, but does not bypass or manufacture browser trust.

The parent file must be a single-link regular file with exact mode `0600`, no
symlink traversal, bounded size, and canonical newline-terminated JSON. P7-C
requires the exact M3-E evidence schema, `status=BLOCK`, no PASS marker,
`diagnostic_tls_bypass=false`, content-free classification, LAN-direct scope,
Provider E3 and physical phone `NOT_RUN`, and `production_ready=false`.

The resumable blocker allowlist is deliberately narrow:

- `HOST_IDENTITY_AUTH_REQUIRED`;
- `HOST_IDENTITY_USER_DENIED`;
- `browser_join_navigation_ERR_CERT_AUTHORITY_INVALID`.

The bundle is verified through the existing strict bundle verifier. The parent
must bind the verified manifest's bundle digest, source commit, launcher version,
and classification. It must also bind the manifest SHA-256 of both runner-closure
entries. A changed bundle, source commit, runner, or browser runner rejects
resume before a product process is started.

To close bundle and runner hash-to-use TOCTOU, resume verifies the source bundle
once, opens its root directory, and copies every manifest-declared file through
directory-relative `open` plus `O_NOFOLLOW`. Every source file is checked against
the verified manifest from that same opened FD. Root device/inode and mutation
timestamps are checked throughout the copy, and the source pathname must still
refer to that root before snapshot acceptance. A rename-swap or mutation during
the snapshot therefore returns `BUNDLE_SNAPSHOT_SOURCE_CHANGED` before parent
validation, TLS handling, or any product spawn.

The complete private snapshot is fsynced, marked immutable with the platform
immutable flag, and reverified through the strict bundle verifier. Parent binding,
runner closure, `nomad-web`, Host, Relay, Agent, Gateway, Web assets, and child
evidence validation then use only this snapshot. The original bundle pathname is
never opened again. Replacing it after snapshot acceptance cannot change which
bytes run or which manifest validates the child.

Within the snapshot, resume opens the product runner, rechecks its digest, and
passes that same FD to isolated Python; Python reads and compiles the exact FD
bytes rather than reopening a pathname. The product runner verifies its running
digest and browser sibling digest against the snapshot manifest before TLS work
or product launch, then snapshots the browser sibling once and sends those exact
bytes to an isolated Playwright Python subprocess over stdin.

The raw SHA-256 of the verified parent file becomes
`parent_evidence_digest` in the new evidence. This is lineage only: no parent
stage result is copied into the new run. The child browser evidence also records
its own runner digest, and the product runner verifies it before accepting the
browser result.

## Full-run and publication guarantees

Resume invokes the staged `run_m3e_product_slice.py` with explicit `--bundle`,
`--evidence`, and `--parent-evidence-digest`. Preflight-only and diagnostic-SPKI
arguments are not accepted by the resume API. TLS FD numbers are not placed in
argv. The product runner creates a new private runtime root and executes its
normal complete sequence. It no longer generates a per-run CA and no longer
imports a CA into an NSS profile.

Evidence output uses `O_CREAT|O_EXCL` with mode `0600`, complete-write handling,
and `fsync`. An existing path is rejected before runner launch and is never
truncated or replaced. Both PASS and BLOCK results retain the parent digest and
current bundle/source bindings. Diagnostic evidence is never eligible as a
parent and can never be upgraded to PASS through resume.

## Verification

Focused suite after the audit rework:

```text
python3 -m unittest testkit/remote-v2/test_m3e_product_slice.py
Ran 28 tests ... OK
```

Remote-v2 regression suite:

```text
python3 -m unittest discover -s testkit/remote-v2 -p 'test_*.py'
Ran 40 tests ... OK
```

The adversarial cases cover noncanonical/tampered parent bytes, wrong bundle,
stale runner source, diagnostic evidence, non-allowlisted blockers, non-BLOCK or
non-private evidence, forbidden partial/diagnostic runner arguments, and an
already existing output path. A command-shape test proves that resume launches
the full staged runner and propagates only the parent digest, not historical
stages. Additional cases prove exact stdin FD control, certificate/key mismatch
rejection before launch, CA/expiry/SAN/key validation calls, absence of TLS path
or environment inputs, manifest-bound runner staging, exact browser-runner byte
execution, runner digest-tamper rejection, and pre-launch product/browser source
binding failure.
The second audit cases additionally replace the original bundle pathname after
parent-ready snapshot construction and assert that the child receives only the
snapshot path, with no later source verification call. A separate mid-copy
rename-swap case asserts `BUNDLE_SNAPSHOT_SOURCE_CHANGED` and zero subprocess
spawn.

## Deferred integration and external gates

P7-C does not modify `tools/nomad_web/cli.py`, `bundle.py`, or `materialize.py`.
The integration owner must open the operator-selected CA/certificate/private-key
files itself and call `resume_blocked_evidence(..., tls_ca_fd=...,
tls_cert_fd=..., tls_key_fd=...)`. It must not translate those descriptors back
into TLS path flags, environment variables, state, or evidence. User-facing CLI
path selection may exist only at that outer operator boundary; the resume API
and runner contract remain FD-only.

No strict real-browser PASS was attempted. Host Keychain authorization and
normal Chrome trust remain user-mediated external blockers. Provider E3 and a
physical phone remain `NOT_RUN`.

Implementation base commit at task start:
`0eeef7db45e5f804ddfb9f3f5b89e672270e9451`. This is not a post-change STOP SHA;
the integration owner/orchestrator assigns that only after the combined commit.
