# Iteration 2 Quality and Pilot Security Completion Report

- Status: Implemented locally; external Pilot remains gated by Security DRI signature
- Scope: PRD-216, PRD-217, PRD-225

## Delivered

- Content-free telemetry allowlist and salted HMAC-SHA256 aliases.
- Pilot doctor checks for platform, exact loopback origin and fixed OpenCode
  health/version, with JSON output and actionable error codes.
- Machine-readable acceptance validator for `allow_once=false`, zero duplicate
  Host acceptance, zero unknown gaps, at least one HostAccepted action, and
  allowlisted telemetry.
- Pilot Security Note with deployment, data, retention, cleanup and stop rules.

## Verification

```text
python3 -m unittest discover -s testkit/pilot -t . -p 'test_*.py'
python3 -m testkit.pilot.doctor --help
python3 -m testkit.pilot.acceptance --help
```

## Limits

The doctor does not install dependencies or inspect credentials. The acceptance
runner validates a content-free integration summary; the root integration
harness remains responsible for producing that summary. This work does not
accept D-005, production identity, E2EE, native iOS lifecycle or real repositories.
