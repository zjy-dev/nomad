# Phase 8 Human-Readable Error Recovery (P8-C)

Status: COMPLETE / MODULE API FROZEN / CLI INTEGRATION DEFERRED TO P8-H

## Outcome

P8-C adds a stable, content-safe recovery layer for every non-PASS readiness
gate. The original gate `code` remains available for machines and support, but
users no longer need to interpret it: each blocked or not-run gate now carries
one `recovery_code`, one `category`, one ownership `scope`, and one short
`next_step`.

The module-level API for P8-H and diagnostics is:

```text
recovery_for_code(code) -> recovery action
decorate_gate(gate) -> gate with safe recovery fields
recovery_actions(gates) -> ordered deduplicated actions
recovery_report(gates) -> schema, actions, primary
```

The schema is `nomad.web-companion.recovery.v1`. Scope is exactly one of:

- `REPO_OWNED_RECOVERY`: Nomad can guide or perform the recovery locally.
- `EXTERNAL_GATE`: release evidence or approval must come from outside the
  repository.

## Recovery classes

The fixed categories cover install, app runtime, device security, pairing,
browser storage, network, browser availability, secure connection, real AI
service validation, physical-phone validation, clean install validation, Apple
release checks, distribution checks, and support diagnostics.

Examples of ordinary-user actions include reinstalling Nomad, restarting it,
approving this Mac, pairing or revoking a phone, restoring browser access,
connecting to the intended network, selecting and trusting a certificate, and
completing the external release checks. Each action is one sentence.

Unknown or malformed blocker codes fail closed to:

```json
{
  "recovery_code": "CONTACT_SUPPORT",
  "category": "SUPPORT",
  "scope": "REPO_OWNED_RECOVERY",
  "next_step": "Collect diagnostics and contact support."
}
```

The unknown input is never echoed. Existing gate `next_step` text is replaced
for every non-PASS gate, so a machine path, raw identifier, secret, or internal
error string cannot become user-facing recovery text through that field.

## Doctor integration

`run_doctor` preserves its release and legacy foundation fields and adds:

- `recovery_schema`;
- recovery fields on every non-PASS `release_gates` entry;
- the same recovery fields on each `release_blockers` entry;
- ordered, de-duplicated `recovery_actions`;
- `release_next_step` derived from the primary safe action.

PASS gates are unchanged and do not receive a recovery action. External
`NOT_RUN` gates remain external and never become local PASS.

## Safety and verification

Focused tests cover representative mappings from every recovery family,
repo-owned versus external scope, one-sentence actions, ordered de-duplication,
unknown and malformed code fallback, replacement of unsafe incoming text,
forbidden path/secret/raw-ID/internal-jargon terms, and complete doctor
decoration for every non-PASS gate. A source-contract test also enumerates
static doctor blocker codes and fails if a future known code lacks an explicit
mapping; dynamic unknown codes still use the safe support fallback.

Commands:

```text
python3 -m unittest testkit/nomad-web/test_recovery.py -v
python3 -m unittest testkit/nomad-web/test_release_readiness_doctor.py -v
python3 -m py_compile tools/nomad_web/recovery.py tools/nomad_web/doctor.py testkit/nomad-web/test_recovery.py testkit/nomad-web/test_release_readiness_doctor.py
git diff --check -- tools/nomad_web/recovery.py tools/nomad_web/doctor.py testkit/nomad-web/test_recovery.py testkit/nomad-web/test_release_readiness_doctor.py docs/technical/task-reports/PHASE8-RECOVERY.md
```

## P8-H packaging handoff

P8-C does not modify `cli.py`, `bundle.py`, or `materialize.py`. Before P8-H
imports this API from a packaged CLI, the integration owner must add
`lib/nomad_web/recovery.py` to `REQUIRED_PACKAGE` and ensure materialization does
not exclude it. The current materializer copies Python files by glob, while the
bundle verifier's allowlist does not yet include this new module.

STOP SHA: `2f8d8bb7db1dc045af205b90dc2e6e74725b35af`.
