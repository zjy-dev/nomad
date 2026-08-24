# Iteration 3 C1a: Authenticated Actual Launch Adoption

Status: C1a1, C1a2a, minimal `nomad-host`, C1a2b0a candidate verifier and C1a2b0b immutable candidate COMPLETE / FINAL INDEPENDENT PASS; B0c publication, supervisor and C1a3 remain BLOCKED.

## Product boundary

C1a proves that the real Rust Host process adopted one exact, actual locked-launch measurement from its credential-aware Python supervisor. It does not derive a runtime capability, does not create RuntimeExecutionAuthorization, and does not change any command API or VerifiedM2Capabilities::from_receipts. C1b remains blocked until C1a has real-process evidence and independent PASS.

## Current topology evidence and gap

- `real_task_capture.launch_locked_opencode` is the only locked launcher. It verifies the registry/lock/install/entrypoint/npm/task/fixture facts and directly starts official OpenCode 1.18.16. It does not start Rust Host.
- `m2_integration.M2IntegrationHarness` creates a run ID, ObservingProxy, socketpair and 32-byte secret pipe, but `run_fd_probe` starts `python -c`; no Rust process reads these inherited FDs. The result is explicitly `TEST_PEER_ONLY_FD_DELIVERY`.
- `run_gateway_slice.py` starts real `pilot-host-bridge`, but uses a compatibility OpenCode server and has no locked launch, RunBinding, actual provenance or credential isolation.
- Rust `HostRunBinding` is complete in-process code and tests, but no Python supervisor has delivered its socket and secret FDs to a real Rust child.

The two existing slices cannot be composed by assertion. C1a must create one new real process slice.

## Frozen process ownership

Python remains the top-level supervisor because it is the only process allowed to receive the explicitly selected Provider credential mapping. It launches:

1. official locked OpenCode child with only the selected allowlisted Provider credential;
2. ObservingProxy in supervisor memory;
3. a fixed, canonical Rust Host/adopter binary with a scrubbed environment containing no Provider credential.

Before child creation, the supervisor creates one `AF_UNIX`, `SOCK_STREAM` socketpair and two one-way pipes. It generates both the 64-lower-hex run ID and the independent 32-byte Host challenge with Python `secrets` backed by the OS CSPRNG; challenge, secret, time, PID, counters and run ID may not derive from one another. Rust continues rejecting an all-zero challenge/secret, and fixed/repeated challenge values exist only as negative test fixtures.

Every endpoint is non-inheritable by default. The three Rust child descriptors are pairwise different descriptor numbers and pairwise different `(st_dev, st_ino)` identities; aliases, duped identities and descriptor reuse fail before spawn. `binding_child_socket` is validated as connected `AF_UNIX/SOCK_STREAM`. `secret_read` and `provenance_read` are distinct FIFO read-only ends by `fstat` and `F_GETFL & O_ACCMODE`; swapping a socket/pipe or a pipe/write endpoint fails. For the Rust child only, `close_fds=True` and `pass_fds=(binding_child_socket, secret_read, provenance_read)` form the exact allowlist. FD numbers and the 32-byte challenge may be argv metadata; secret, payload, run ID, digests and credentials may not be argv or environment.

Immediately after spawn, the parent restores non-inheritable state and closes its copies of `binding_child_socket`, `secret_read` and `provenance_read`; after complete writes it closes `secret_write` and `provenance_write`. The parent retains only its binding socket endpoint. Rust repeats descriptor number/identity/type/access checks, requires the inherited descriptors to be open for this adoption only, sets `FD_CLOEXEC` immediately, and closes all three on every success/failure path. An unrelated child spawned before, during and after adoption inherits none.

The Rust child environment is exactly the immutable allowlist `LC_ALL=C`, `LANG=C`, `RUST_BACKTRACE=0`; no ambient variable is copied. Tests enumerate every allowlisted Provider credential name and a canary value and prove names/values are absent from Rust env, argv, stdout/stderr, payload, errors and unrelated children.

The Rust binary path in C1a tests is an explicit canonical test seam. It is not production authority. Product integration into a packaged `pilot-host-bridge` path is a separate C1a2 acceptance condition; C1a tests may not claim production readiness from `target/debug` or `cargo run`.

## Exact actual-launch payload

Schema: `nomad.actual-launch-provenance.v1`. Exact fields, no extras or duplicates:

- `schema_version`
- `run_id` — 64 lower hex, identical to RunBinding hello
- `package_name` — `opencode-ai`
- `package_version` — `1.18.16`
- `package_lock_raw_digest` — lower-hex SHA-256 of the installed exact lock bytes
- `full_locked_dependency_count` — positive bounded integer
- `full_locked_dependency_digest` — existing canonical full locked closure digest
- `installed_platform_dependency_count` — positive bounded integer
- `installed_platform_dependency_digest` — existing canonical installed closure digest
- `entrypoint_realpath` — canonical absolute resolved target proven to be the running OpenCode executable image
- `entrypoint_raw_digest` — lower-hex SHA-256 of that resolved target bytes
- `npm_executable_realpath` — canonical absolute executable used for `npm ci` and version check
- `npm_version` — `11.12.1`
- `task_spec_digest`
- `fixture_manifest_digest`
- `adapter_id` — `opencode`
- `adapter_version` — `1.18.16`

The locked launcher re-measures these fields after OpenCode health succeeds and immediately before Rust spawn. It accepts no caller-provided facts. `LockedOpenCodeLaunch` retains the complete typed measurement plus exact process object/PID, canonical root/install/workspace, and pre-spawn entrypoint `(st_dev, st_ino, size, raw digest)` identity; a single historical aggregate digest is insufficient. Existing `full_locked_closure`, `installed_platform_closure`, `observed_installed_entrypoint`, task-spec and fixture-manifest functions are reused; historical certificate/provenance claims are not substitutes.

Entrypoint execution identity is fail-closed, platform-specific and mandatory before C1a2/C1a3. Pre-spawn the launcher opens the resolved target with no-follow/read-only/CLOEXEC, verifies a regular executable within the locked install, records `fstat` device, inode, size, mtime, ctime and generation where available, and hashes from that opened FD. It starts OpenCode, waits for health, and proves the actual executable image for the exact process object/PID.

Linux uses a no-follow open of `/proc/<pid>/exe`, then `fstat` and FD hashing. Darwin uses `libproc.proc_pidpath` only as auxiliary process-path evidence and enumerates the same live PID with `proc_pidinfo(PROC_PIDREGIONPATHINFO)`. Authority selection is by equality with the pre-open FD vnode `(device, inode)`, not by path text. It requires one or more mapped regions for that vnode, at least one region with `VM_PROT_EXECUTE`, and every matching region to report the same `vnode_info_path.vi_stat` identity. The mapped vnode device, inode, size, mtime, ctime and generation must equal the pre-open FD identity. No file-offset-zero requirement exists: a local Darwin arm64 probe showed the legitimate `/bin/sleep` executable mapping beginning at a nonzero Mach-O file offset. The same probe demonstrated matching device/inode/size and an executable region; `/dev/fd/<n>` execution was separately rejected by the kernel with EACCES and is not an allowed design.

Darwin ABI is compiled policy, not inferred at runtime. C1a2a supports only `darwin-arm64` with the audited SDK layout: `PROC_PIDTBSDINFO=3`, `PROC_PIDREGIONPATHINFO=8`, `VM_PROT_EXECUTE=4`, `MAXPATHLEN=1024`; process states `SIDL/SRUN/SSLEEP/SSTOP/SZOMB=1/2/3/4/5` and `PROC_FLAG_INEXIT=4`; `sizeof(proc_bsdinfo)=136` with flags/status/PID/PPID/start-sec/start-usec offsets `0/4/12/16/120/128`; `sizeof(proc_regioninfo)=96` with protection/file-offset/address/size offsets `0/16/80/88`; `sizeof(vinfo_stat)=136` with device/inode/size/mtime/mtime-nsec/ctime/ctime-nsec/generation/mode offsets `0/8/88/40/48/56/64/112/4`; `sizeof(proc_regionwithpathinfo)=1272` with region/vnode/path/stat offsets `0/96/248/96`. These constants come from a reviewed C generator compiled against the named platform SDK and are committed as an exact JSON artifact; production verification never invokes clang or derives offsets from ctypes. The ctypes module loads the artifact, asserts every size/offset and platform/architecture before loading libproc, and rejects unknown/missing/extra artifact fields. `proc_pidinfo` must return the exact requested structure size; partial, negative, unexpected errno, iteration overflow, non-progressing addresses or layout mismatch fail closed. A later SDK layout requires a regenerated artifact and explicit review, not fallback parsing.

PID reuse is closed with `proc_pidinfo(PROC_PIDTBSDINFO)`: immediately after `Popen`, after health, before and after each region proof, and immediately before Rust spawn, the same `Popen` object must remain live and its PID, parent PID, `pbi_start_tvsec` and `pbi_start_tvusec` must equal the first captured kernel identity. The parent PID must equal the supervisor PID. Each check requires `pbi_status` to be exactly `SRUN=2` or `SSLEEP=3` and `(pbi_flags & PROC_FLAG_INEXIT) == 0`; `SIDL`, `SSTOP`, `SZOMB`, an unknown/changing status, `Popen.poll() != None`, identity change or query failure blocks. `Popen.poll()` and `proc_pidpath` are supplemental and never substitute for kernel PID/start-time/status identity.

Region proof is two complete consecutive enumerations in a bounded short window. Each call uses the prior region end address as the next argument. An exact structure-size return advances to `address + size`; zero alone terminates one complete enumeration. A negative result, short/oversized return, zero-sized region, integer overflow, non-increasing next address, unexpected errno, or reaching 4096 regions before a terminating zero blocks. Each enumeration derives only the matching-vnode tuple set `(address,size,protection,file_offset,device,inode,file-size,mtime,mtime-nsec,ctime,ctime-nsec,generation,mode)`. Both sets must be nonempty and exactly equal, use one vnode identity and contain an executable region. Any transient difference, multiple vnode identity, disappearance or query anomaly blocks. The proof makes no claim about selected Universal Mach-O slice or code-signing identity; it proves only that the exact complete file vnode/bytes measured from the pre-open FD has executable mappings in the bound live process. Slice/signature policy, if required later, is a separate reviewed gate.

After live-image proof, the supervisor re-hashes the original pre-open FD from offset zero and re-fstats both that FD and the path; all retained identities/digests must remain equal immediately before Rust spawn. The post-start mapped vnode is the actual-image authority; `proc_pidpath`, path equality, `argv[0]`, process name and a pre-spawn hash alone are never evidence. If the platform API is unavailable, struct sizes/constants mismatch the compiled policy, no executable region is found, more than one vnode identity appears, the PID/process object changes or exits, or any identity/digest changes, C1a2 fails closed.

## Framing and authentication

Provenance pipe framing is bounded and single-use:

```text
8 bytes  magic = NOMADALP
2 bytes  version = 1, big endian
4 bytes  payload_len, big endian, 1..65536
32 bytes payload_sha256
32 bytes HMAC-SHA256
N bytes  canonical UTF-8 JSON payload
EOF      mandatory; trailing bytes fail
```

HMAC input is a length-delimited canonical transcript with domain `nomad-actual-launch-provenance-v1`, protocol version, RunBinding run ID and raw payload SHA-256. The same 32-byte binding secret is delivered through the separate secret pipe. Rust reads exactly 32 bytes and requires EOF; zero/short/long secret fails.

The RunBinding hello tag currently named `capability_digest` carries a C1a transport claim only:

```text
SHA256(domain=nomad-c1a-transport-claim-v1, version, run_id, payload_sha256)
```

This value is not a capability and is consumed by no command. C1b must independently replace/derive the final capability formula; C1a may not reuse this transport claim as command authority.

Rust order is: validate and adopt the three descriptors; bounded read secret; complete authenticated RunBinding handshake; bounded read envelope; verify raw payload digest; verify HMAC before JSON interpretation; recompute and constant-time compare the transport claim; strict parse/canonical round-trip; require payload run ID equals RunBinding run ID; validate every field; construct opaque `ActualLaunchProvenance`; zero the secret and HMAC key material on every exit, then close descriptors. The payload contains content-free provenance facts and is not described as zeroized: temporary payload/envelope buffers are bounded, not logged or serialized after validation, and are ordinarily dropped. External Python supervision owns timeout, kill, wait and cleanup for a child blocked on a pipe.

`ActualLaunchProvenance` has private fields, no public constructor, no `Clone`, `Copy`, `Serialize`, `Deserialize`, `Default` or `From`. The only authority constructor is private adoption from the three inherited FDs. C1a's executable consumes and drops it after printing exact content-free stdout `ADOPTED_ACTUAL_LAUNCH_PROVENANCE`; it exposes no digest or fact.

## Atomic dispatch cards

### C1a1 — Rust bounded adoption core

Owner files: `connector/Cargo.toml`, `connector/Cargo.lock` only if dependency metadata changes, `connector/src/actual_launch.rs`, `connector/src/run_binding.rs` only for frozen crate-private HMAC/constant-time helpers, `connector/src/lib.rs`, `connector/src/bin/actual_launch_adopter.rs`, and focused Rust tests. `libc` must be a normal dependency because FD validation is runtime code; build-dependency-only `libc` is insufficient. The existing audited HMAC-SHA256 and constant-time equality implementation is exposed `pub(crate)` or moved once into a crate-private crypto helper. A second copied implementation is forbidden.

Acceptance: exact framing/schema/canonicalization, secret exact-read+EOF, HMAC/run/claim binding, descriptor type/access/identity/CLOEXEC validation, opaque type, single-use state, redacted errors/debug, partial read, short/long/trailing/bad MAC/wrong run/wrong claim/replay/aliased/swapped-FD vectors. C1a1 receives the supervisor challenge as fixed-format non-secret argv metadata, validates exact 64 lower hex / 32 nonzero bytes, and binds it through the existing HostRunBinding transcript. C1a1 does not generate the challenge and makes no CSPRNG claim; Python C1a2/C1a3 owns and proves independent OS-CSPRNG generation. Secret, payload, run ID, digest and credential remain forbidden in argv. No Python, credential, release, formula or command changes. This card is mechanically dispatchable after architecture PASS, but proves only Rust adoption mechanics.

### C1a2 — Locked launcher fact materialization and supervisor

Owner files: `testkit/stock-opencode/real_task_capture.py`, a production-candidate supervisor module, `m2_integration.py` only as migration/compatibility glue, and focused Python tests.

Acceptance: actual facts are re-measured from the live `LockedOpenCodeLaunch`; pre-spawn entrypoint FD and post-health actual executable-image FD identities/digests match; exact canonical payload/frame matches Rust vectors; Host challenge comes from the OS CSPRNG; Provider credential appears only in OpenCode child environment; Rust gets the exact three-variable environment allowlist; three-FD type/access/identity allowlist and endpoint closure pass; same run ID/secret binds proxy handshake and provenance; complete cleanup. No fake launch may satisfy the authority path.

C1a1 implementation record: the Rust core now has one opaque `ActualLaunchProvenance`, one authenticated canonical envelope parser, one shared crate-private HMAC/constant-time implementation, `OwnedFd` validation for a connected AF_UNIX stream plus two distinct read-only FIFO pipes, exact secret read/EOF, FD_CLOEXEC, RunBinding handshake, and a dedicated content-free adopter binary. Independent audit reached P0/P1/P2 zero after secret-zeroization, dead-code, and real-child negative-matrix rework. Evidence is 102 library tests, 8 actual-launch library/Unix-FD tests, 8 dedicated real-child process tests, all pre-existing integration targets, clippy and fmt PASS. This proves Rust adoption/FD mechanics only and is not Python locked-launch, Provider isolation, C1a2/C1a3 or product evidence.

### C1a2a — Credential-Free Darwin Live-Executable Verifier

Owner files: one reviewed SDK C ABI generator source, committed exact `darwin-arm64` ABI JSON artifact, `testkit/stock-opencode/darwin_live_executable.py`, and focused tests only. The generator is a review/build-time maintenance tool and is never invoked by production verification.

Inputs are an already-running controlled `subprocess.Popen` object, an already-open no-follow regular executable FD and its canonical locked-install containment root, plus the expected supervisor PID. The verifier accepts no arbitrary PID without the exact `Popen` object, no path-only identity, no caller-supplied stat/digest facts, and no credential/environment mapping. It does not start OpenCode, Rust or any process; it reads no Provider credential; it creates no launch provenance, authority, capability, receipt or artifact.

The verifier owns the pre-open FD for the call, computes its raw SHA-256 and `fstat` identity itself, captures and repeatedly verifies the exact kernel `proc_bsdinfo` identity/status, performs the two stable mapped-vnode enumerations above, then re-hashes/re-fstats the same FD and no-follow re-stats the canonical path. Success returns only an opaque/private verified measurement to its future C1a2b caller and a content-free test verdict; failure exposes one stable blocker with no path, PID, identity or digest. The type is not serializable and has no public fact constructor.

Acceptance includes exact ABI artifact/schema/platform/arch/libproc-symbol checks; live `/bin/sleep` positive proof on Darwin; wrong pre-FD, exited/zombie/stopped/identity mutation, wrong parent, short ABI return, errno, unstable/overflowing/non-progressing/over-4096 region enumeration, zero/multiple/non-executable vnode matches, path replacement, FD mutation and unsupported-platform blockers. Tests use controlled temporary executables or system binaries and never Provider credentials. C1a2a proves only the Darwin kernel verifier and cannot satisfy C1a2b/C1a3.

### C1a2b — Locked Launcher and Supervisor Integration

BLOCKED. Begins only after C1a2a independent PASS and after the packaged canonical Rust Host binary location/identity plus complete typed `LockedOpenCodeLaunch` measurement are separately frozen. It owns Provider isolation, actual OpenCode launch, Rust child spawn, payload materialization and the C1a1 three-FD protocol.

C1a2a implementation record: the credential-free Darwin verifier consumes a fixed raw-digest-bound `darwin-arm64` ABI JSON artifact generated by reviewed C source, validates exact ctypes layout and libproc symbols, binds a real `subprocess.Popen` through PID/PPID/start-time/status, and proves the pre-open executable FD vnode is stably mapped with execute protection in the live process. It re-hashes/re-fstats the FD, re-stats its contained path, rejects replacement and closes the owned FD. Focused 8 and full stock-opencode 207 tests pass; final independent audit reports P0/P1/P2 zero. This is Darwin kernel verifier evidence only.

C1a2b is split further: C1a2b0 freezes post-link Rust binary artifact authority without credentials; C1a2b1 may then integrate the credential-aware Python supervisor. A test binary under `target/`, Cargo environment, build.rs output, path ownership or a self-written adjacent hash file is never packaged authority.

### C1a2b0a — Credential-Free Post-Link Host Artifact Verifier

This is the only currently implementable C1a2b0 package. It is read-only and creates no publication or authority. Exact host manifest schema `nomad.nomad-host-artifact.v1` has these top-level fields and no others:

- `schema_version`
- `artifact_class`: `candidate-adhoc` or `production-developer-id`
- `artifact_basename`: exactly `nomad-host`
- `artifact_size_bytes` and `artifact_raw_sha256`
- `platform`: initial policy only `darwin-arm64`
- `target_triple`: exactly `aarch64-apple-darwin`
- `source_commit_oid` and `cargo_lock_raw_sha256`
- `build_profile`: exactly `release`
- `rustc_release`, `rustc_commit_hash`, `rustc_host`, `llvm_version`
- `actual_launch_protocol_version`: exactly `1`
- `embedded_release`: exact nested variant described below
- `macos_codesign`: exact nested variant described below
- `host_artifact_sequence`: positive integer
- `previous_host_manifest_digest`: 64 lower hex, zero only for sequence 1
- `host_manifest_digest`: canonical SHA-256 of all preceding fields

`embedded_release` is parsed from the final binary bytes, never trusted from the manifest alone. The verifier scans bounded binary bytes for `NOMADREL`, applies the C1a/d1 exact framing/count/name/entry-digest parser to every occurrence and requires exactly one complete valid container candidate. It revalidates outer current/manifest/meta/approval/evidence relations. The nested manifest value is one exact variant:

- unavailable candidate: `availability=unavailable`, `container_raw_sha256`; no release digest fields. This is allowed only for `candidate-adhoc` and can never be supervisor-consumable.
- verified candidate: `availability=verified`, `container_raw_sha256`, `source_commit_oid`, `release_index_digest`, `bundle_manifest_digest`, `evidence_manifest_digest`, `approval_record_digest`, `approval_signature_raw_digest`, `trust_root_id`, `adapter_id`, `adapter_version`, `reviewed_version`. This variant is mandatory for `production-developer-id`.

For `source_commit_oid`, Cargo.lock and toolchain facts, B0a accepts an independent exact expected-build statement as a separate read-only input. That statement is not artifact authority and cannot be taken from the host manifest: it supplies the expected source commit, expected raw Cargo.lock bytes/digest, exact release profile/target and exact reviewed rustc/LLVM fields. B0a compares the manifest and binary against it. Production publication later binds the same statement into signed approval/protected CAS. A caller may not omit it or ask the verifier to infer expected values from the candidate manifest.

`macos_codesign` exact variants:

- candidate ad-hoc: `mode=adhoc`, `format=Mach-O thin (arm64)`, actual identifier, actual 40-lower-hex CDHash and 64-lower-hex full CDHash, `team_id=null`, `signing_identity=null`. This is permitted only for `candidate-adhoc`.
- production Developer ID: `mode=developer-id`, exact reviewed thin-arm64 format, fixed external expected identifier, Team ID, signing identity, CDHash/full CDHash and designated-requirement digest. These expected identity fields come from compiled release policy, not the manifest. No production Team ID/signing identity is currently provisioned, so this variant remains blocked.

On Darwin, fixed `/usr/bin/codesign` realpath is invoked with exact bounded commands for strict verification and display. Output is bounded, timeout/kill/wait supervised, parsed as an exact allowlisted field set and compared to the binary and manifest. `candidate-adhoc` must report ad-hoc/linker-signed, no TeamIdentifier and a single arm64 Mach-O. Universal/fat binaries, unknown hash algorithms, multiple CodeDirectories, missing CDHash or unexpected fields fail. Production additionally requires Developer ID policy and cannot accept ad-hoc output.

The verifier opens the binary and manifest no-follow, regular, bounded and identity-stable; hard links (`st_nlink != 1`), symlinks, mutation before/after tool calls, basename mismatch and path traversal fail. It writes nothing, signs nothing, invokes no Cargo/Git/compiler, reads no Provider credential, starts no OpenCode/Rust/supervisor, and cannot create approval/trust/publication. Candidate success is exactly `VERIFIED_HOST_ARTIFACT_SHAPE`; production-shaped success without external approval remains non-published and non-supervisor-consumable.

Owner files: `testkit/agent-evidence/verify_host_artifact.py`, focused tests and fixed schema/policy fixtures. Connector, launcher, commands and release trees are forbidden.

### C1a2b0b — Immutable Host Artifact Candidate

BLOCKED until b0a independent PASS and exact candidate directory/index binding is audited. It reuses private candidate, O_EXCL/fsync/no-replace mechanics, but does not sign, publish or mutate Git. Success is only `CANDIDATE_HOST_ARTIFACT_TREE`. Agent-neutral evidence release approval and host binary approval remain separate scopes joined by explicit digests.

Implementation record before b0b architecture: a new default-product `nomad-host` binary now links the embedded release and enforces startup order `embedded release -> current approval -> inherited-FD actual launch`. It holds both opaque values in a private aggregate, creates no command authority, and normal builds fail closed before touching FDs. The standalone adopter is isolated behind a non-default test-helper feature. A candidate-only post-link verifier binds the real `nomad-host` bytes to canonical manifest and independent expected-build statement, requires a unique complete unavailable container plus exact ad-hoc thin-arm64 codesign metadata, and emits only `VERIFIED_HOST_ARTIFACT_SHAPE`. Final independent audit reports P0/P1/P2 zero. Regression evidence: connector 102, helper real-child 8, agent-evidence 53 including host focused 7, stock 207, clippy and fmt PASS. Production verified-container relation parsing, Developer ID, approval, publication and supervisor consumption remain unimplemented and blocked.

### C1a2b0c — Protected Host Artifact Publication

BLOCKED on external release trust, SSHSIG approval, macOS production signing policy and protected ref CAS. Host binary -> host manifest digest -> external approval -> trust policy -> protected publication is mandatory. Rollback publishes a new monotonic sequence and never rewrites prior artifact bytes. Only b0c may make an artifact supervisor-consumable.

B0c is split into four read-only verifier mechanics before any external action: production host relation verification; active-index/lineage verification; protected publication request verification; checkout-after-CAS verification. Local tools never sign, codesign, create trust, mutate Git or refs, build, launch Provider/OpenCode/supervisor, or authorize commands. Synthetic success proves mechanics only.

The exact active index schema is `nomad.host-artifact-active-index.v1` with: `schema_version`, `active_candidate_id`, `host_manifest_digest`, `artifact_raw_sha256`, `embedded_release_index_digest`, `bundle_manifest_digest`, `evidence_manifest_digest`, `host_approval_digest`, `host_artifact_sequence`, `previous_host_active_index_digest`, `source_commit_oid`, `expected_parent_oid`, and `active_index_digest`. The final digest is canonical SHA-256 of all preceding fields. First publication uses sequence 1 and zero previous digest. Later publication uses prior sequence + 1, prior active index digest and expected parent supplied by an independently verified parent snapshot. Candidate ID must equal `sha256-<host_manifest_digest>`. Same candidate at a later sequence, sequence rollback, digest fork and reactivation of any previously used candidate are rejected. Rollback is represented only as a new sequence to a previously published immutable candidate when an explicit external rollback policy supplies that candidate in an allowlisted rollback set; B0c-2 validates the rule but creates no policy or publication.

B0c-2 implementation record: the read-only lineage verifier uses the reviewed schema revision with explicit `operation=forward|rollback`, nullable rollback provenance on forward and mandatory rollback provenance/request/allowlist relations on rollback. It verifies canonical active index, parent snapshot, history snapshot, candidate binding, publication request and rollback allowlist; enforces monotonic sequence, parent digest, SHA-1/SHA-256 OID format, forward old-candidate rejection, rollback-as-new-sequence and fork/replay blockers. It creates no rollback authorization. Final independent audit reports P0/P1/P2 zero after FD ownership and symlink/hardlink/history/OID test rework. Evidence: focused 7 and agent-evidence 72 PASS; production publication remains blocked.

B0b implementation record: the candidate-only materializer re-verifies B0a inputs, snapshots `nomad-host`, constructs an exact four-file 0700 immutable tree, and publishes it through Darwin/Linux no-replace directory operations. EEXIST requires exact bytes, file modes, single links, entry set and candidate directory owner/mode. A canonical `current.json.proposed` is O_EXCL-written or exact-compared; candidate-published/proposal-failed state returns `BLOCKED_HOST_PROPOSAL_INCOMPLETE`, preserves the orphan and can be recovered by same-input retry. Pure `artifact_fs` primitives have side-effect-free import evidence. Final independent audit reports P0/P1/P2 zero after proposal, import, directory-mode and Linux syscall matrix rework. Evidence: focused 12, agent-evidence 65, stock 207, connector 102, helper real-child 8, clippy and fmt PASS. This remains inactive unavailable/ad-hoc candidate mechanics only.

B0c-3 implementation record: the read-only protected-publication request verifier now seals five independent raw-file facts in its lineage snapshot: the proposed `current.json` plus candidate `host-manifest.json`, `expected-build.json`, `nomad-host`, and `evidence-release-reference.json`. Each file has an exact lower-hex raw SHA-256 and positive non-boolean byte size, and both facts must equal the corresponding fixed proposed-tree entry. This closes the prior gap where a semantic active-index digest or aggregate candidate-tree digest could remain unchanged while a file's raw representation changed. Exact schemas, canonical JSON, no-follow/single-link/identity-stable reads, fixed paths and Git modes, clean-source claims, and no-Git/no-write mechanics remain unchanged. Focused 9 and full agent-evidence 96 tests pass. Independent re-audit reports P0/P1/P2 zero and freezes B0c-3. These inputs remain caller-supplied mechanics snapshots, not trusted Git attestations, proof of protected-ref CAS, or publication authority. B0c-4 may start only as a credential-free checkout-after-CAS verifier mechanics card.

B0c-4 implementation record: the read-only local checkout-after-CAS verifier consumes the exact frozen B0c-3 in-memory snapshots, fixes the repository root, protected ref and /usr/bin/git, and observes root/object-format/ref/HEAD/clean state before and after immutable-object checks. It requires a dedicated forward five-path diff or rollback-only current.json diff, exact tree records and Git modes, and independently reads and hashes all five blobs from proposed_commit_oid. It validates Git blob OIDs for SHA-1 and SHA-256 and joins actual active-index and production Host-manifest semantics without re-performing B0c-1 signing/trust verification. Real Git forward and rollback tests pass for both object formats. Final evidence: focused 26 and full agent-evidence 123 PASS; independent audit reports P0/P1/P2 zero. This proves local checkout/ref observation mechanics only, not remote CAS, branch protection, signing/trust, or product readiness.

### C1a3 — Real Rust child interconnection

Owner files: one new bounded E2E runner/test and C1a evidence transcript location; no command modules.

Acceptance: direct execution of the real Rust adopter/Host binary, not `python -c`; actual locked OpenCode process is alive; successful exact marker; bad MAC/wrong run/partial/trailing/replay/timeout/early exit all fail content-free and are reaped; unrelated child proves no FD inheritance; credential canary absent. A test-built binary and non-Provider health run are transport evidence only, never production evidence.

### C1b — Capability formula and command gate

Blocked. Begins only after C1a1–C1a3 independent PASS, production binary packaging path is fixed, real release/trust/CAS exist, and the real Provider-backed same-run evidence gate is satisfied.

## Independent audit checklist

- Python credential isolation and Rust exact three-variable environment allowlist.
- Exact process identity and actual fact re-measurement; no committed/historical claim substitution.
- Only three pairwise non-aliased and type/access-validated FDs inherited by Rust; child immediately applies CLOEXEC; all other endpoints close in the frozen order; unrelated child none.
- One secret binds both RunBinding and provenance HMAC; run ID and payload digest cannot be substituted.
- Host challenge and run ID use independent OS-CSPRNG values; authentication precedes JSON semantic acceptance; bounded reads, EOF, timeout/kill/wait and secret/HMAC key zeroization hold.
- Opaque ActualLaunchProvenance cannot be built from public strings/raw parser.
- Transport claim cannot reach command APIs or be mislabeled final capability.
- Real Rust child evidence is not confused with Python probe or mocked launch.
- No production trust, signing, Provider evidence or command authority is claimed.

## Unresolved before production C1a freeze

- P1: packaged canonical Rust Host binary location/identity is not yet defined; `target/debug` is test-only. This blocks C1a2/C1a3 production claims, not the isolated C1a1 Rust core.
- P1: the Darwin `libproc` mapped-vnode policy has successful local kernel and SDK ABI probes but is not yet independently re-audited or implemented. This blocks C1a2/C1a3 dispatch; only credential-free C1a2a verifier work may be authorized after architecture PASS.
- P1: current `LockedOpenCodeLaunch` retains only an incomplete provenance digest and must retain/re-measure the exact field set without exposing a caller fact constructor. This blocks C1a2/C1a3, not C1a1.
- P2: legacy RunBinding field name `capability_digest` is semantically misleading for the C1a transport claim and must be explicitly isolated from C1b authority.
