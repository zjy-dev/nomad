# Phase 8 P8-D: Support-Safe Diagnostics Bundle

Status: COMPLETE / MODULE API FROZEN / CLI AND PACKAGE INTEGRATION DEFERRED

## Outcome

P8-D adds a deterministic, support-safe diagnostics exporter in
`tools/nomad_web/diagnostics.py`. Its output is canonical JSON with schema
`nomad.web-companion.support-diagnostics.v1` and the literal classification
`support-only-not-readiness-evidence`. It always records
`production_ready=false` and `readiness_evidence=false`.

The module API for the later CLI owner is:

```text
collect(config) -> diagnostics manifest
verify(manifest) -> None or deterministic DiagnosticsError
export(config, output) -> diagnostics manifest
```

No CLI, bundle verifier, materializer, launcher, or doctor change is part of
this package.

## Allowlisted contents

The diagnostics manifest contains only projections constructed by this module:

- verified installed bundle digests and digest-only install history;
- onboarding state, fixed blockers, external `NOT_RUN` gates, and commitments;
- P8-C recovery actions generated from fixed blocker codes;
- safe running mode and status booleans;
- installed, running, Host-public, and paired-device commitments;
- owned process role, ownership result, and process identity commitment;
- owned log size and SHA-256 only;
- bundle/install counts and history digest;
- a fixed privacy-scan result.

No raw log bytes or tails are exported. Log contents are read only to calculate
size and SHA-256 from a stable, owned, mode-0600 regular file. This permits
support to compare logs without exposing their contents.

Verification is context-specific rather than a recursive key-name scan. It
reconstructs the one valid canonical object for each section and requires the
entire supplied manifest to equal that reconstruction. Exact schemas, field
sets, enum values, nullable relationships, commitment formats, list lengths,
process topology, owned-log metadata, install/onboarding/runtime cross-bindings,
privacy assertions, bounded list lengths, and derived digests are all validated. An allowed field
name therefore cannot carry an arbitrary prompt, command, Agent ID, or other
string. Unknown blocker input is either rejected by the state-specific relation
or normalized to the single fixed redacted blocker before export; it is never
echoed.

Recovery is not trusted as supplied content. The verifier rebuilds its gates
from the validated onboarding and runtime codes, calls the P8-C authoritative
`recovery.recovery_report` mapping, and requires exact equality of every action's
`recovery_code`, `category`, `scope`, and `next_step`, including ordering,
deduplication, and `primary`. Recomputing the outer manifest digest cannot make a
mutated recovery sentence valid.

## Runtime read-only boundary

Collection uses existing read-only state/install/recovery contracts while
holding the existing lifecycle lock with `create=false`:

- `install_lifecycle.status_unlocked`;
- `state.read_run_state`;
- `install_lifecycle.onboarding_status_unlocked`;
- `recovery.recovery_report`;
- `processes.ownership`.

The collector does not write runtime state. If the home does not exist, it
returns deterministic `NOT_INSTALLED` and `NOT_RUNNING` projections without
creating the home.

Only log paths already present in a validated process state are eligible. Each
must be a direct child of the configured owned logs directory. Symlinks, hard
links, non-owner files, non-0600 files, oversized files, identity changes, and
paths outside that directory fail closed. Other files in the logs directory are
not enumerated or opened.

## Explicit exclusions

The diagnostics bundle never contains:

- Provider credentials or bearer values;
- raw prompts or commands;
- raw Agent IDs or session aliases;
- browser storage;
- socket or filesystem paths;
- raw log content;
- unowned process or file data;
- readiness evidence;
- `testkit/process-loop/last-transcript.json`.

The collector has no repository walk. The protected transcript is neither
opened nor named in output, and `export` explicitly rejects that protected path
as an output target.

## Determinism and publication

All lists retain contract-defined order or are explicitly sorted. No timestamp,
hostname, random run value, output path, or collection time enters the manifest.
The `manifest_digest` is SHA-256 over canonical JSON of every preceding field.
Identical accepted inputs therefore produce identical manifest bytes and digest.

`export` first collects and verifies the complete in-memory manifest. It then:

1. opens the parent once with `O_DIRECTORY|O_NOFOLLOW`, then validates owner and
   mode using `fstat` on that descriptor;
2. creates a mode-0600 temporary file with `O_EXCL` relative to the directory FD;
3. writes canonical newline-terminated JSON and fsyncs it;
4. revalidates the same directory FD and publishes with `linkat`-equivalent
   `dir_fd` arguments, so an existing path or symlink is never overwritten;
5. removes the temporary name with `unlinkat`-equivalent `dir_fd` handling,
   fsyncs and revalidates that same directory FD. If the opened directory's
   identity or security mode changes, the just-published name is removed through
   the same FD and the operation fails closed.

No publish operation reopens or resolves the parent pathname. If an attacker
renames the parent and creates a replacement directory after it is opened, the
bundle is published only into the original opened directory, never the
replacement.

## Focused verification

```text
python3 -m py_compile \
  tools/nomad_web/diagnostics.py \
  testkit/nomad-web/test_diagnostics.py

python3 -m unittest -v testkit/nomad-web/test_diagnostics.py
Ran 15 tests ... OK
```

The focused suite covers deterministic bytes and digest, manifest tampering,
symlinked logs, unowned paths/processes, secret canaries in raw logs and unknown
codes, protected transcript non-access and output rejection, unowned extra-file
non-access, unknown input fields, absent-home read-only behavior, and canonical
0600 exclusive publication without overwrite. The audit regression cases also
cover an incomplete manifest made only of otherwise allowed field names, a
mutated recovery `next_step` with a recomputed outer digest, and deterministic
parent-directory rename/swap publication through the original directory FD. A
separate simulated opened-directory identity change verifies rollback of the
just-published output.

## Deferred integration

P8-H owns CLI wiring and package integration. It should expose a single output
path to `export(config, output)` and preserve the module's existing-path failure.
It must not add broad directory inputs, raw-log options, transcript flags, or a
readiness-evidence label.
