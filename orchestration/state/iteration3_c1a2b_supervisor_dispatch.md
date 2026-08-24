# Iteration 3 C1a2b Locked Launcher and Host Supervisor Dispatch

Status: ARCHITECTURE AMENDED / B1 AND PACKAGE A REGISTRY HARDENING IN PROGRESS / B2 HELD

## Goal and authority boundary

C1a2b joins three separated facts in one Python supervisor: an externally authorized exact published nomad-host, one registered and single-use actual locked OpenCode 1.18.16 process, and the Rust C1a1 authenticated three-FD adoption protocol. It creates no command capability and cannot make an unavailable or ad-hoc Host production-authorized.

Production order is fixed: B0c-1a relation, B0c-1b approval, B0c-4 post-CAS checkout, no-follow re-open/re-hash of the same published Host, launch and measure official OpenCode, then spawn the exact Host and complete C1a1 adoption. Missing production release policy, Host trust, approval, protected-ref match, Provider credential, or any join blocks before Host spawn.

B0c-1a production verification returns a private non-constructible `_VerifiedProductionHostRelation`, not the current caller-constructible `RelationFacts`; B0c-1b production verification returns a private non-constructible `_VerifiedProductionHostApproval`; and B0c-4 production verification returns a private non-constructible `_VerifiedPostCasCheckout`. Their constructors reject direct calls and are reachable only from the respective public production verifier after its complete checks. The private production combiner requires `type(value) is ExactPrivateType` for all three results and exact field equality before constructing `_PublishedHostAuthorization`. It does not accept subclassing or duck typing. The existing `_verify_with_policy`, `_verify_with_environment`, injected trust and runner seams return parallel `_Test...` result classes that cannot reach the production combiner.

Private tests may combine only `_TestPublishedHostAuthorization` for transport tests. Production entry accepts only the exact private production authorization type. No current public `RelationFacts`, dict, serialized verdict, `None`, boolean success, caller digest, target binary, adjacent hash, or synthetic verifier result constructs production authorization. Public B0c CLI markers remain content-free and are not parseable authority tokens.

## Package A: complete locked OpenCode measurement

Owner files are real_task_capture.py and its tests, plus only a private extraction bridge in darwin_live_executable.py if needed.

LockedOpenCodeLaunch retains lifecycle handles plus a private frozen, non-serializable LockedOpenCodeLaunchMeasurement instead of only provenance_digest. The production launcher is its only constructor. After fresh npm ci, fixture materialization, exact version check, process health, and Darwin live-image verification it retains typed raw facts:

- package_name opencode-ai and actual installed package_version 1.18.16;
- actual temporary install package-lock raw SHA-256;
- full locked dependency count and canonical digest;
- installed platform dependency count and canonical digest;
- live native executable canonical realpath and raw SHA-256 from the owned FD that darwin_live_executable verifies against the mapped vnode of the actual Popen process;
- exact npm executable canonical realpath and version 11.12.1 from invoking that same path;
- exact task-spec and fixture-manifest digests;
- adapter_id opencode and adapter_version 1.18.16;
- exact process object/PID, root/install/workspace and port retained for remeasurement and cleanup.

The npm .bin/opencode path is a launcher reference. On reviewed Darwin arm64 OpenCode 1.18.16 it resolves to the native Mach-O. The launcher opens the resolved target O_RDONLY, O_CLOEXEC and O_NOFOLLOW before spawn, launches that canonical path, and hands the owned FD to the Darwin verifier. Payload entrypoint_realpath and entrypoint_raw_digest mean the verified live native image, not wrapper bytes. Wrapper facts may remain diagnostic only.

Resolve npm once to a canonical regular executable and invoke that exact path for npm ci and npm --version. Recheck mutable lock, package, task, fixture and entrypoint facts after health and immediately before Host spawn. Provider credential is read only by launch_locked_opencode from an allowlisted environment name and added only to the OpenCode child environment. It is absent from npm, Git, verifier, Host and unrelated-child environments, argv, payload, files, receipts, errors, stdout/stderr and repr. Discard the transient child environment immediately after spawn.

Package A success proves an actual live OpenCode process measurement only. It neither authorizes Host launch nor persists credentials.

## Package B: published Host authorization and real three-FD supervisor

Owner files are a new locked_host_supervisor.py and focused tests, plus minimal typed-result returns in B0c-1/B0c-4 modules. m2_integration.py may receive narrow migration glue only after the new path passes independently.

Private PublishedHostAuthorization retains matching Host manifest and binary digests from B0c-1 and B0c-4, embedded release index/bundle/evidence/approval digests from B0c-1, and B0c-4 active-index digest, candidate, operation, artifact sequence, publication sequence, proposed commit and source commit. It is non-serializable, privately issued, registered, and grants only permission to spawn the exact opened Host image. The production constructor calls only production B0c verifiers and requires exact typed results that remain members of their originating registries. Approval must retain the identical originating relation object. Injected policy, trust, runner or fake CAS paths return only distinct test values that cannot enter the production registry. Forward publication requires artifact and publication sequences to be equal. Rollback preserves the historical artifact sequence and requires a strictly newer publication sequence.

Package A production launch and measurement are also privately issued and registered with their exact object-identity relationship. `_measurement_facts` checks both registry membership and the relationship rather than exact Python class alone. The production supervisor atomically consumes the launch once; a legacy launch, shape-probe launch, copied value, forged exact-class object, replaced measurement, or replay cannot cross this boundary. Consumption transfers cleanup ownership to the supervisor.

The production supervisor accepts only an authorization and the complete live OpenCode launch. It does not accept a caller-created proxy, proxy factory, or run ID. After validating the registered authorization and atomically consuming the registered launch, it independently creates run_id=32 random bytes encoded lower hex, nonce=32 random bytes encoded lower hex, binding secret=32 raw bytes, and Host challenge=32 raw bytes from the OS CSPRNG. All are nonzero and independent. The supervisor creates and starts the exact ObservingProxy for `http://127.0.0.1:<launch.port>`, the exact canonical launch workspace, and that same run ID before creating transport descriptors or spawning Host. The secret uses mutable storage and is overwritten in finally.

The canonical ASCII JSON NOMADALP payload contains exactly these Rust fields: schema_version, run_id, package_name, package_version, package_lock_raw_digest, full_locked_dependency_count, full_locked_dependency_digest, installed_platform_dependency_count, installed_platform_dependency_digest, entrypoint_realpath, entrypoint_raw_digest, npm_executable_realpath, npm_version, task_spec_digest, fixture_manifest_digest, adapter_id, adapter_version. No caller mapping supplies these facts.

The envelope is magic NOMADALP, u16 big-endian version 1, u32 big-endian payload length, raw SHA-256 payload digest, HMAC-SHA256 over the Rust canonical domain/run/digest tuple, then the payload with no trailing bytes. The transport claim is lower-hex SHA-256 of the Rust canonical claim-domain/version/run/digest tuple. Every canonical tuple part is u64 big-endian length followed by bytes.

Create one connected AF_UNIX SOCK_STREAM pair, one secret pipe, and one provenance pipe. All endpoints start non-inheritable. Spawn exactly authorization-bound nomad-host with argv host_path, binding_child_fd, secret_read_fd, provenance_read_fd, challenge_hex; pass_fds contains exactly those three distinct descriptors; close_fds is true; stdin is null; stdout/stderr are pipes; shell is false; env is exactly LC_ALL=C, LANG=C, RUST_BACKTRACE=0. Provider credential, run ID, secret, payload and authorization are absent from Host env.

After spawn, parent closes child socket and both read ends. It writes exactly 32 secret bytes and closes that writer. It runs the existing Rust-compatible proxy handshake using actual proxy origin and transport claim. After handshake it writes and closes the bounded provenance envelope.

Host stdout and stderr are drained continuously by two concurrent bounded readers from immediately after spawn until EOF. The provenance writer, both output readers, socket handshake, and Host exit share one monotonic hard deadline longer than the Rust five-second socket timeout. Each reader accepts at most 4096 bytes; the first overflow, read error, missed deadline, or unjoined reader/writer thread fails closed. The supervisor never waits for Host exit while leaving either output pipe undrained, and never synchronously writes a potentially 65,614-byte envelope into a pipe before the Host can read it. Success is evaluated only after both readers and any writer reach EOF/completion and join, the Host is reaped, and it has return code zero, stdout exactly HOST_PREREQUISITES_VERIFIED plus newline, and empty stderr.

On success or failure, close every remaining endpoint first, kill Host if live, wait/reap with a hard deadline, join all output and writer threads, shut down the supervisor-owned proxy exactly once, terminate/reap the consumed OpenCode launch exactly once, verify process exit and disposable root/install/workspace deletion, and return only a content-free result. Cleanup uncertainty or an unjoined thread is distinct and never success. Before successful Package A consumption the caller remains the launch owner; after consumption the supervisor is the sole cleanup owner. A sentinel test proves no unrelated descriptor, including an explicitly inheritable sentinel writer, reaches Host.

## Atomic dispatch and tests

Package A must independently pass before Package B starts. Package A tests cover typed-field completeness, non-serializability, native-image versus wrapper identity, lock raw bytes with unchanged semantic closure, installed/full counts, npm path replacement, process/path/FD mutation, task/fixture mutation, credential non-retention and cleanup.

Package B first uses the feature-gated actual-launch-adopter for byte parity and failure vectors, then runs the real default nomad-host. One shared transport core serves test and production wrappers. Tests cover one supervisor-owned run ID across proxy, payload, claim and handshake; exact happy marker; stdout/stderr larger than pipe capacity and output overflow; concurrent reader/writer shared-deadline behavior; all FD type/direction/alias failures; 31/33/zero/non-EOF secret; wrong challenge/run/claim/MAC; malformed/partial/trailing payload; silent peer/full pipe timeout; early Host/OpenCode exit; sentinel noninheritance; replay; and complete proxy/Host/OpenCode cleanup. Forged authorization or launch, missing trust or credential, legacy or consumed launch, and proxy construction/start failure must block before Host spawn. A test-only production-release build seam may prove orchestration but cannot construct production PublishedHostAuthorization.

Public production invocation remains fail closed in this repository while Developer ID policy, verified embedded release, Host SSHSIG/trust/KRL, protected-ref CAS and temporary Provider credential are absent. No C1b capability or command API may consume these values.

## Package A implementation record

LockedOpenCodeLaunch now carries a private, frozen, non-serializable complete measurement while preserving the historical provenance_digest as a read-only compatibility projection. A legacy caller-created launch cannot yield measurement facts. npm is resolved once to a canonical executable and the same absolute path runs install and version checks. The fresh lock/package/installed closure and task/fixture material are re-read after health; the resolved native OpenCode image is pre-opened and verified against the live Darwin mapped vnode. The live verifier exposes no generic facts callback: an exact, single-use private sink joins verified image facts into the launch measurement. Credentials enter only the OpenCode child environment and the transient mapping is discarded after spawn. Focused real-task plus Darwin suites pass 20/20 and full stock-opencode passes 210/210; the trailing fixture-local mismatch is an expected content-free diagnostic, not a test failure. No Provider credential was available, so no Provider-backed launch is claimed. Independent audit reports P0/P1/P2 zero. Package B may now start.
