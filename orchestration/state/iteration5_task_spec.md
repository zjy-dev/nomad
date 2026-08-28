# Iteration 5 Installable Real-Agent Companion

## Objective

Deliver the shortest honest path for a user to install Nomad, run a real
Provider-backed code agent on their Mac, and safely view and perform a bounded
set of actions from Web or Mobile.

## Non-negotiable success criteria

- One supported macOS installation and uninstall path with a stable CLI and
  daemon lifecycle.
- One locked official code-agent adapter completes a real Provider-backed run.
- Host, Relay, Gateway and client use production-intended identities and a
  reviewed security envelope; fixture keys and test routes cannot authorize the
  product path.
- A user can pair a device, view a real session and diff, and safely issue the
  explicitly approved command subset with Host-final authority.
- Revocation, deletion, reconnect, duplicate handling, diagnostics, rollback
  and kill switch have real-process evidence.
- Web may be the first installable client; native Mobile remains a separate
  release gate unless PM evidence makes it launch-critical.

## Claims boundary

Local or synthetic evidence never unlocks Provider, Pilot, production identity,
pairing, E2EE or publication claims. Default production supervisor remains
zero-spawn until all externally rooted gates are independently verified.

## Stop conditions

- Do not fabricate or provision Provider credentials, Developer ID, SSHSIG
  trust/KRL, protected CAS authority, APNs identity or user consent.
- Do not place credentials in argv, repository files, logs, receipts, browser
  bundles or chat.
- Do not enable commands before pairing, revocation, freshness, idempotency and
  Host-final authorization gates pass.
