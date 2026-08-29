# P8-H4 final installed product journey

The source runner is used only to verify and perform the first installation.
After that commit point, the journey removes its owned source-bundle copy and
runs the product lifecycle through the canonical installed launcher at
`$NOMAD_WEB_HOME/bin/nomad-web --json`, from a working directory outside the
repository with no `PYTHONPATH` or `NOMAD_WEB_BUNDLE` dependency.

- Before deleting the owned install-source copy, the runner snapshots
  `c3_local_command_smoke.py` into a private mode-0700 QA directory, rewrites
  its imports to the exact installed bundle's `nomad_web` package, records the
  resulting SHA-256, and later compiles and executes the already-verified bytes
  without reopening the driver pathname. The driver's fake child receives the
  same pinned bytes through an isolated Python bootstrap. B therefore cannot
  read a subsequently changed, removed, or symlink-swapped repo/staged driver
  at action time. It passes the bound content-addressed installed bundle to the
  staged driver and validates the complete mechanical E2 contract.
- A is internal remote-local evidence. Without operator-owned TLS input it is
  `NOT_RUN/P8G_TLS_CONTROL_INPUT_REQUIRED`; it is reported as
  `remote_local_evidence_status`, never as external readiness.
- C runs installed `install-status`, `onboarding`, the expected missing-provider
  credential block, `diagnostics --output`, `reset-remote-access --confirm`,
  and `uninstall --confirm`. The diagnostics file is produced under a mode-0700
  directory, required to be canonical mode-0600 JSON, and verified with the
  exact installed bundle's `diagnostics.verify` before uninstall.

The missing-provider check requires exit 1 and the exact content-free error
`AGENT_START_INPUTS_INCOMPLETE`; it is an expected block inside a passing
repo-owned journey, while Provider E3 remains separately `NOT_RUN`.

Top-level `status` is only a compatibility alias of `repo_owned_status`.
`external_readiness` and all six external gates are always `NOT_RUN`, and
`production_ready` is always false. Evidence is canonical JSON, content-free,
mode 0600, and atomically published without overwriting an existing path.

The pinned C3 driver is explicitly external QA infrastructure and is not
included in, or claimed as part of, the shipped product bundle closure. Its
only Nomad code dependencies are rewritten to the exact installed product
package. Its classification and hash are recorded in B evidence without
exposing its filesystem path or source.
