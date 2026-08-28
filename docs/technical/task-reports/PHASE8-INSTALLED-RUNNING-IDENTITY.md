# Phase 8 P8-A: Installed And Running Identity

## Scope

Implemented the P8-A installed/running identity substrate in the owned Python
surface:

- `tools/nomad_web/state.py`
- `tools/nomad_web/launcher.py`
- `tools/nomad_web/install_lifecycle.py`
- focused tests under `testkit/nomad-web/`

`tools/nomad_web/processes.py` was reviewed and left unchanged. Its existing
`process_identity(pid)` commitment already satisfies the running-process
primitive P8-A needs.

This work does not edit `tools/nomad_web/cli.py`, does not read protected
transcript artifacts, and does not invent host or device authority that the
owned Python surface does not possess.

## Contract Added

State now persists one top-level `identity` object in both local and remote
schemas. The contract is commitment-only:

- `installed`
  - `availability`
  - `bundle_digest`
  - `install_sequence`
  - `install_identity`
- `running`
  - `availability`
  - `bundle_digest`
  - `run_id`
  - `process_commitment`
  - `socket_commitment`
  - `run_identity`
- `host_public_commitment`
  - `availability`
  - `commitment`
- `paired_device`
  - `availability`
  - `device_key_commitment`
  - `pairing_epoch`

Separation is deliberate:

- installed identity is stable across repeated starts of the same installed
  bundle and changes only when the selected install record changes;
- running identity changes per run and binds the process set plus Product Host
  socket identity;
- host public commitment remains availability-only because this surface does
  not own authoritative public commitment material;
- paired-device identity is read-only from the authoritative registry DB and is
  never synthesized.

## Final Root Cause And Fix

The real P8-A E2E regression was not the authority DB read path. It was a
self-deadlock in launcher identity composition:

- launcher `start` and `status` already execute under `lifecycle_lock`;
- `_compose_identity()` called `_installed_identity()`;
- `_installed_identity()` called the public `install_lifecycle.status(config)`;
- public `status(config)` attempted to acquire `lifecycle_lock` again;
- result: self-deadlock while Product Host, gateway, and opencode had already
  been spawned, so the CLI never returned and timeout paths could strand
  children.

The required fix was the explicit private seam in install lifecycle:

- `tools/nomad_web/install_lifecycle.py`
  - added `status_unlocked(config)` for callers that already hold
    `lifecycle_lock`;
  - public `status(config)` still acquires the lock itself and then delegates to
    `status_unlocked(config)`.
- `tools/nomad_web/launcher.py`
  - imports and uses only `install_lifecycle.status_unlocked` for installed
    identity composition while already under the held lifecycle lock.

This keeps the public lock semantics intact and removes the re-lock path
without making the lock reentrant or weakening fail-closed behavior.

## Implementation Notes

### `tools/nomad_web/state.py`

- Added `identity` to both local and remote run-state keysets.
- Added strict validators for the four identity sub-objects.
- Enforced mode-specific availability rules:
  - `foundation-readonly` requires `NOT_RUN` for host and paired-device rows.
  - non-foundation modes reject `NOT_RUN` for those rows.
- Validated commitment fields as canonical lowercase hex digests.
- Bound `running.socket_commitment` to the persisted
  `product_host_socket_identity`.

### `tools/nomad_web/launcher.py`

- Added identity helpers:
  - `_sha256_json`
  - `_installed_identity`
  - `_running_identity`
  - `_host_public_commitment`
  - `_paired_device_identity`
  - `_compose_identity`
  - `_assert_identity_match`
- `installed` identity now uses the private `install_lifecycle.status_unlocked`
  seam while the caller already holds `lifecycle_lock`.
- `running` identity commits only:
  - selected bundle digest
  - persisted run ID
  - process identity projection
  - Product Host socket identity
- host public commitment is fail-closed on authority:
  - `foundation-readonly` => `NOT_RUN`
  - other modes => `UNAVAILABLE`
- paired-device identity is read only from
  `/home/private/host-device-registry.sqlite3` under secure path/artifact
  validation and strict schema validation.
- identity mismatches fail closed with `RUNNING_IDENTITY_MISMATCH`.
- start paths and status now recompute identity and compare it to persisted
  state instead of silently trusting stored values.

### Paired-device authority schema correction

The initial launcher query assumed an outdated `device_registry` layout. Real
official-agent-local E2E then failed with
`PAIRED_DEVICE_IDENTITY_SCHEMA_MISMATCH`.

The launcher and fixtures were corrected to the authoritative schema in
`connector/src/device_authority.rs`:

- columns:
  - `row_id`
  - `device_alias`
  - `principal_alias`
  - `signing_key_digest`
  - `agreement_key_digest`
  - `state`
  - `activated_epoch`
  - `revoked_epoch`
  - `created_at`
  - `updated_at`
- active-row query remains a strict read-only projection over the authoritative
  table and does not fabricate any host/device commitment.

### `tools/nomad_web/processes.py`

No code change. Existing `process_identity(pid)` already provides the process
commitment primitive required by P8-A.

## Safety Properties Preserved

- No provider credential, bearer, session raw ID, agent raw ID, or socket
  secret is written into the identity contract.
- No host public commitment is fabricated.
- No paired-device commitment is fabricated.
- No silent repair path was added for drift between persisted and recomputed
  identity.
- Locking semantics remain unchanged for public install lifecycle APIs.
- Stop/start persistence remains scoped to intended run artifacts only.

## Tests Added Or Updated

### Added

- `testkit/nomad-web/test_phase8_identity.py`
  - foundation identity shape and availability rules
  - paired-device authority DB read path
  - paired-device schema mismatch fail-closed
  - explicit confirmation that `processes.py` did not require P8-A edits

- `testkit/nomad-web/test_install_lifecycle.py`
  - `test_status_unlocked_reads_current_without_relocking_marker`
  - verifies `status_unlocked(config)` can read current install state while the
    caller already holds `lifecycle_lock`, and would fail if it tried to
    re-lock

### Updated

- `testkit/nomad-web/test_m3e_launcher.py`
  - remote identity assertions for the new state contract
  - mismatch assertion for `RUNNING_IDENTITY_MISMATCH`
  - fixtures updated so installed identity uses the unlocked seam and the
    mismatch path reaches identity validation instead of real bundle
    verification

- `testkit/nomad-web/test_prebuilt_bundle.py`
  - official-agent-local start/status/restart assertions for the new identity
    payload
  - helper `run_cli(...)` now launches with `start_new_session=True`
  - on `TimeoutExpired`, helper kills the child process group with
    `os.killpg(process.pid, signal.SIGKILL)` before collecting output

The helper cleanup change is intentionally narrow: it proves cleanup at the
test-helper boundary for future timeout cases, but it does not claim to be a
general runtime supervisor change.

## Verification Run

Verified from current disk state:

```text
python3 -m unittest -v testkit.nomad-web.test_phase8_identity
python3 -m unittest -v \
  testkit.nomad-web.test_install_lifecycle.InstallLifecycleTests.test_status_unlocked_reads_current_without_relocking_marker \
  testkit.nomad-web.test_phase8_identity \
  testkit.nomad-web.test_m3e_launcher
python3 -m unittest -v \
  testkit.nomad-web.test_prebuilt_bundle.PrebuiltBundleTests.test_cli_starts_owned_official_agent_with_connected_local_web \
  testkit.nomad-web.test_prebuilt_bundle.PrebuiltBundleTests.test_product_host_death_is_degraded_then_owned_crash_recovery_starts_fresh_run
python3 -m unittest -v testkit.nomad-web.test_prebuilt_bundle
```

Observed result:

- `test_phase8_identity`: PASS
- seam regression plus focused launcher tests: PASS
  - `Ran 25 tests ... OK`
- targeted official-agent-local prebuilt regressions: PASS
  - `Ran 2 tests in 69.229s OK`
- full `test_prebuilt_bundle`: PASS
  - `Ran 21 tests in 79.248s OK`

## Cleanup Status

The earlier timeout-era orphan risk was reproduced before the seam fix and was
the direct symptom of the launcher self-deadlock.

After the seam fix and helper cleanup hardening:

- a final process sweep for stale `nomad-prebuilt-run-*`,
  `nomad-prebuilt-h*`, `nomad-product-host`,
  `gateway/server.mjs --mode official-agent-local`, and
  `agent/opencode serve --pure` matches returned no remaining stale processes;
- no broad kill step was required in the final state because the inventory was
  already clean.

## Files In Scope

- `tools/nomad_web/state.py`
- `tools/nomad_web/launcher.py`
- `tools/nomad_web/install_lifecycle.py`
- `testkit/nomad-web/test_install_lifecycle.py`
- `testkit/nomad-web/test_phase8_identity.py`
- `testkit/nomad-web/test_m3e_launcher.py`
- `testkit/nomad-web/test_prebuilt_bundle.py`
- `docs/technical/task-reports/PHASE8-INSTALLED-RUNNING-IDENTITY.md`
