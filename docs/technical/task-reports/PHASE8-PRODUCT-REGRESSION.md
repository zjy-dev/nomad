# Phase 8 Final Installed Product Regression (P8-H4)

## Verdict

The final repo-owned installed journey passes from the exact installed bundle.
This is mechanical local evidence, not an external-readiness or production
release verdict. `status` is only a compatibility alias of
`repo_owned_status`; `external_readiness` is fixed to `NOT_RUN`, all six
external gates are `NOT_RUN`, and `production_ready` is false. Internal A
evidence is named `remote_local_evidence_status` and is not promoted into an
external readiness claim.

## Installed journey contract

The source runner verifies and installs an owned copy of the candidate once.
Before deleting that source-bundle copy, it also snapshots the external C3 QA
driver into a private mode-0700 staging directory, rewrites only the driver's
Nomad imports to the exact installed bundle, and pins the resulting mode-0600
bytes by SHA-256. It then removes the source-bundle copy before the lifecycle continues.
From that point, C runs only the canonical installed launcher at
`$NOMAD_WEB_HOME/bin/nomad-web --json` from a mode-0700 working directory
outside the repository and with a clean environment that contains no
`PYTHONPATH`, `PYTHONHOME`, or `NOMAD_WEB_BUNDLE`.

The installed command sequence is:

1. `install-status`
2. `onboarding`
3. `start --provider OPENAI_API_KEY --workspace <outside-repo-cwd>` without
   `--credential-stdin`, which must deterministically return exit 1 and the
   content-free `AGENT_START_INPUTS_INCOMPLETE` error; this is recorded as
   `expected_block=true`, not as a failed stage or Provider E3 evidence
4. `diagnostics --output <mode-0700-parent>/support.json`
5. `reset-remote-access --confirm`
6. `uninstall --confirm`

Every installed CLI result must have the exact expected exit status, empty
stderr, duplicate-key-free canonical JSON, the frozen schema and safe fields.
The diagnostics export must be canonical mode-0600 JSON and is verified through
`diagnostics.verify` loaded from the exact installed content-addressed bundle.
Verification occurs before uninstall; after uninstall the harness does not call
the removed launcher and only asserts that the launcher and owned HOME no
longer exist.

B continues to run the exact installed bundle through C3, covering the
materialized Product Host, Gateway, Web app, browser-visible reply/deny/Stop,
idempotency, and OutcomeUnknown behavior. At action time B verifies and loads
only the staged hash-pinned QA driver, so later mutation or removal of the
repo-local `c3_local_command_smoke.py` cannot change the run. The parent executes
the already-verified bytes with `compile/exec`; its fake child receives those
same bytes through an isolated bootstrap, closing verify-then-reopen races. A
symlink or byte change at the staged pathname fails closed before loading. B
also binds the selected `home/bundles/<digest>` path to the source candidate
digest. B evidence records only the driver SHA-256 and its fixed classification
`external-qa-not-shipped-product-closure`. The QA driver executes its pinned
orchestration bytes and imports Nomad modules only from the exact installed
bundle `lib`; it has no action-time repo QA-helper import. It is deliberately not included in, or
represented as part of, the shipped product bundle closure. A remains internal remote-local
evidence; without operator-owned TLS descriptors it is explicitly
`NOT_RUN/P8G_TLS_CONTROL_INPUT_REQUIRED`. Provider E3 is a separate
`NOT_RUN/PROVIDER_E3_EVIDENCE_NOT_RUN` gate.

No command result, parent evidence, or diagnostic record contains Provider
credentials, raw prompt or response bodies, bearer values, browser storage, or
raw logs. The protected process-loop transcript is not read, diffed, or
modified.

## Executed evidence

- Final product-journey suite: 11/11 PASS. The suite includes a real materialized
  candidate, first install, source-copy removal, exact installed C3, canonical
  launcher lifecycle, installed diagnostics verification, uninstall, and no
  owned HOME residue.
- Focused parser and contract tests cover noncanonical output, exit mismatch,
  fixed external fields, expected missing-credential block, evidence mode,
  non-overwrite behavior, staged-driver hash drift, and independence from later
  repo-driver mutation or removal, symlink rejection, and no-TLS A short-circuit
  before repo-runner import.
- The table-driven C3 parser regression mutates run binding, fake-boundary,
  browser shape and digests, freshness count/type, containment flags and modes,
  exact SQLite file set, journal fields, and elapsed time. Every mutation is
  rejected with `P8G_C3_RESULT_CONTRACT_INVALID`; the evidence projection was
  not weakened.

These results do not satisfy real Provider E3, physical iPhone Safari, a
clean-machine install, Developer ID signing, Apple notarization, or publication
provenance. Those gates remain `NOT_RUN`.
