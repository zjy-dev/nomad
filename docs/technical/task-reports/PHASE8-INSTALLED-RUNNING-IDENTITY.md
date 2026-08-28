# Phase 8 P8-A: Installed And Running Identity

## Scope

Implemented the P8-A identity substrate in the owned Python surface:

- `tools/nomad_web/state.py`
- `tools/nomad_web/launcher.py`
- focused tests under `testkit/nomad-web/`

`tools/nomad_web/processes.py` was reviewed and left unchanged. Its existing
`process_identity(pid)` SHA-256 commitment already satisfies the P8-A running
process commitment requirement.

This package does not edit `tools/nomad_web/cli.py`, does not read protected
transcript artifacts, and does not introduce any host-side invented authority.

## Contract Added

State now persists one top-level `identity` object for both local and remote
run schemas. The vocabulary is intentionally commitment-only:

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

The separation is deliberate:

- installed identity is stable across repeated starts of the same installed
  bundle;
- running identity changes per run and binds the current process set plus the
  Product Host socket identity;
- host public commitment is surfaced only as availability because the owned
  Python surface does not have authoritative commitment material yet;
- paired-device identity is read-only from the authoritative registry DB and
  never synthesized.

## Implementation Notes

### `tools/nomad_web/state.py`

- Added `identity` to both local and remote run state keysets.
- Added strict validators for the four identity sub-objects.
- Enforced mode-specific availability rules:
  - `foundation-readonly` requires `NOT_RUN` for host and paired-device rows.
  - non-foundation modes reject `NOT_RUN` for those rows.
- Validated commitment fields as canonical lowercase hex digests only.
- Bound `running.socket_commitment` to the persisted
  `product_host_socket_identity`.

### `tools/nomad_web/launcher.py`

- Added helpers:
  - `_sha256_json`
  - `_installed_identity`
  - `_running_identity`
  - `_host_public_commitment`
  - `_paired_device_identity`
  - `_compose_identity`
  - `_assert_identity_match`
- `installed` identity reuses `install_lifecycle.status(config)` and the latest
  immutable install `sequence`.
- `running` identity commits only:
  - selected bundle digest
  - persisted run alias
  - process identity projection
  - Product Host socket identity
- host public commitment is fail-closed on authority:
  - `foundation-readonly` => `NOT_RUN`
  - other modes => `UNAVAILABLE`
- paired-device identity is read only from
  `/home/private/host-device-registry.sqlite3` under secure path/artifact
  validation and strict schema validation.
- identity mismatches now fail closed with:
  - `RUNNING_IDENTITY_MISMATCH`
- start paths and status now recompute and compare identity instead of silently
  trusting persisted state.

### `tools/nomad_web/processes.py`

No code change. The existing process commitment primitive was already adequate:

- `process_identity(pid)` returns a SHA-256 commitment over `ps` output.
- P8-A only needed launcher/state wiring on top of that existing primitive.

## Safety Properties Preserved

- No provider credential, bearer, session raw ID, agent raw ID, or socket
  secret is written into the identity contract.
- No host public commitment is fabricated.
- No paired-device commitment is fabricated.
- No silent repair path was added for drift between persisted and recomputed
  identity.
- Stop/start persistence remains scoped to intended run artifacts only.

## Tests Added Or Updated

### Added

- `testkit/nomad-web/test_phase8_identity.py`
  - foundation identity shape and availability rules
  - paired-device authority DB read path
  - paired-device schema mismatch fail-closed
  - explicit confirmation that `processes.py` did not require P8-A edits

### Updated

- `testkit/nomad-web/test_m3e_launcher.py`
  - remote identity assertions for the new state contract
  - mismatch path assertion for `RUNNING_IDENTITY_MISMATCH`
  - fixture updates so installed identity is sourced from `install_status()`
    and existing-run mismatch reaches identity validation instead of real
    bundle verification

- `testkit/nomad-web/test_prebuilt_bundle.py`
  - official-agent-local start/status/restart assertions for the new identity
    payload

## Verification Run

Fresh runs from current disk state:

```text
python3 -m unittest -v testkit.nomad-web.test_phase8_identity
python3 -m unittest -v testkit.nomad-web.test_m3e_launcher
```

Observed result:

- `test_phase8_identity`: PASS
- `test_m3e_launcher`: PASS

Additional targeted official-agent-local prebuilt regressions were started to
validate the end-to-end surface touched by the new identity contract:

```text
python3 -m unittest -v \
  testkit.nomad-web.test_prebuilt_bundle.PrebuiltBundleTests.test_cli_starts_owned_official_agent_with_connected_local_web

python3 -m unittest -v \
  testkit.nomad-web.test_prebuilt_bundle.PrebuiltBundleTests.test_product_host_death_is_degraded_then_owned_crash_recovery_starts_fresh_run
```

At handoff time, those long-running targeted E2E checks were still in progress,
so they are not claimed as PASS evidence here.

## Remaining Blockers

- No code-level blocker remains in the owned P8-A surface.
- The only open verification item is completion of the targeted
  `test_prebuilt_bundle` official-agent-local E2E checks, which are broader and
  slower than the focused launcher/state regressions already passing.

## Files In Scope

- `tools/nomad_web/state.py`
- `tools/nomad_web/launcher.py`
- `testkit/nomad-web/test_phase8_identity.py`
- `testkit/nomad-web/test_m3e_launcher.py`
- `testkit/nomad-web/test_prebuilt_bundle.py`
- `docs/technical/task-reports/PHASE8-INSTALLED-RUNNING-IDENTITY.md`
