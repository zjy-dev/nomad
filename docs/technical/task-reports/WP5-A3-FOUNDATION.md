# WP5-A3a Repo-local Launcher Foundation

This package provides `python3 -m tools.nomad_web` with `doctor`, `start`,
`status`, `stop`, and `uninstall`. It builds and launches the existing
loopback-only Relay and Gateway against file-backed SQLite under a dedicated
launcher home.

It deliberately does not launch a Code Agent. The stable state is
`foundation-readonly`, `real_agent_enabled=false`, blocked on a real Provider
credential and a non-fixture production device identity. Relay tokens exist
only in launcher and child environments; status, logs, argv and manifests do
not contain their values.

This is not a Developer ID signed/notarized installer, production authority,
pairing implementation, E2EE system, or Pilot evidence. `allow_once` remains
false. The clean-home test runs real Relay and Gateway processes, proves the
unavailable read-only API before a real Agent exists, then exercises idempotent
stop and scoped uninstall.

Changing `NOMAD_WEB_BUNDLE` while the foundation is running does not hot
upgrade either process. The running pair remains bound to its verified digest
snapshot. A stop followed by start installs and uses the new verified digest;
older snapshots remain until the launcher home is uninstalled.
