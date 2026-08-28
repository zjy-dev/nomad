# Phase 8 CLI and Installed Bundle (P8-H1/H2)

## Verdict

The repo-owned CLI and installed-launcher slice is ready for freeze. This is
not a production release verdict: `production_ready` remains false and real
Provider E3, physical-phone Safari, clean-machine install, Developer ID,
notarization, and publication provenance remain `NOT_RUN`.

## Product surface

The installed CLI now exposes install status, onboarding, diagnostics export,
confirmed remote-access reset, and confirmed uninstall in addition to the
existing install/start/status/stop/doctor lifecycle. Pairing and device revoke
remain on the desktop Web and Product Host authority paths; no parallel CLI
authority was invented. JSON and human output preserve their own stable forms,
and unknown or secret-like exceptions are reduced to a fixed safe code.

The installed launcher is stable at `$NOMAD_WEB_HOME/bin/nomad-web`. It binds
an absolute validated Python interpreter, clears Python/DYLD/Nomad injection
variables, validates the selected bundle into an in-memory snapshot, loads the
Python package from those verified bytes, and holds the lifecycle lock across
the command. `current.json` remains the only install commit point. The strict
release-evidence runner closure remains present but is not advertised as an
ordinary-user command surface.

## Security boundary

This slice protects against hostile invocation environment and races among the
supported install, upgrade, rollback, and launcher paths. It does not claim to
resist another arbitrary process already executing as the same macOS user.
That process can rewrite owner-controlled native, JavaScript, or Web artifacts
and can also attack the launcher itself. Closing that boundary requires the
external release-trust work: signed and notarized artifacts plus a protected
installation/update authority. File modes alone are not represented as such a
security boundary.

## Verification

- Phase 8 and Phase 7 CLI tests: 19/19 PASS.
- Install lifecycle, including hostile environment, in-memory package loading,
  adopted-lock re-entry, selector failure, and upgrade serialization: 19/19
  PASS.
- Prebuilt installed launcher targeted path: PASS.
- Clean-home lifecycle, including confirmed uninstall: 8/8 PASS.
- Bundle closure keeps `diagnostics.py`, `recovery.py`, and the exact internal
  release-evidence runners; extra files remain rejected.

The desktop Web lifecycle coordinator and installed product-journey integration
are separate follow-on packages and are not claimed complete by this record.
