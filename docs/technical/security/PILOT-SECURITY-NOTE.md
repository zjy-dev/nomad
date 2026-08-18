# Controlled Pilot v0.2 Security Note

| Field | Decision |
| --- | --- |
| Status | Proposed; Security DRI signature required before external use |
| Data | Project-provided disposable repository and temporary Provider account only |
| Capabilities | View, reply, deny, Stop; `allow_once=false` |
| Claim boundary | Does not accept D-005 or Security Envelope v0 |

## Required deployment boundary

- OpenCode and Host bind loopback only. The fixed OpenCode origin is
  `http://127.0.0.1:4096`; version mismatches fail closed.
- The test Relay is not a production identity or E2EE system. External Pilot
  access requires an approved same-origin TLS proxy, unique high-entropy test
  tokens, access logging without message content, and an explicit expiry time.
- No public inbound port is opened on the participant Host. Browser CORS must
  not be widened as a shortcut around the proxy review.
- Pairing codes are short-lived and single-use. Test device bindings and Relay
  channel data are removed at the end of each participant run.

## Data classification and retention

- Relay payloads may contain disposable Session facts, so the Relay remains
  confidential even though the repository is disposable.
- Logs and telemetry must not contain Prompt, source, paths, commands, diff,
  credentials, raw Session/turn IDs, or Provider identifiers. Only allowlisted
  events and salted aliases are permitted. Salt is supplied per Pilot run and
  is never hardcoded in the repository.
- Relay data expires within seven days or is deleted when the run completes,
  whichever happens first. Local temporary Provider credentials are revoked at
  run completion.

## Stop conditions

Immediately stop all invitations and disable the test Relay after any content
field leak, cross-Session operation, duplicate Host acceptance, unexplained
durable-event gap, false Live state, or accepted/exposed mobile `allow_once`.
Preserve content-free evidence, revoke tokens, delete device bindings, and have
the Security DRI approve the root cause and retest before resuming.

## Human approvals still required

- Product, Technical and Security DRI names and contacts.
- TLS proxy configuration, Relay location and access list.
- Temporary Provider account permissions and revocation owner.
- Participant notice, retention statement and incident contact.
- Signed decision that the Pilot remains inside disposable-data scope.
