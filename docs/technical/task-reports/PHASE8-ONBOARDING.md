# Phase 8 P8-B: First Install And Onboarding

## Outcome

P8-B defines one commitment-only onboarding contract for ordinary users and
embeds it in install, upgrade, rollback, and install status results. It does
not change CLI wiring and it never reports production readiness.

The exact states are:

- NOT_INSTALLED
- INSTALLED_NEEDS_START
- INSTALLED_BLOCKED_HOST_IDENTITY
- RUNNING_NEEDS_PAIRING
- RUNNING_PAIRED
- RUNNING_DEGRADED_RECOVERY_REQUIRED

Every result uses schema nomad.web-companion.onboarding.v1, sets
production_ready=false and external_readiness=NOT_RUN, and preserves explicit
NOT_RUN rows for Provider E3, physical iPhone Safari, clean-machine install,
Developer ID signing, notarization, and publication provenance.

## State Derivation

NOT_INSTALLED means there is no verified current selector and no running state.

For an installed and stopped candidate, onboarding runs the installed
bin/nomad-product-host identity-preflight command directly from the
content-addressed bundle:

- READY becomes INSTALLED_NEEDS_START.
- AUTH_REQUIRED, USER_DENIED, KEYCHAIN_LOCKED, CORRUPT, UNAVAILABLE, invalid
  output, timeout, or execution failure becomes
  INSTALLED_BLOCKED_HOST_IDENTITY with a stable blocker code.

For a running candidate, onboarding consumes the P8-A identity substrate. It
requires the selected, installed, and running bundle digests to agree and all
persisted process identities to remain owned. The installed identity comparison
is exact over availability, bundle digest, latest install sequence, and the
P8-A domain-separated install identity digest. A repeated selection of the same
bundle digest at a newer sequence therefore cannot be mistaken for the older
running install:

- paired_device READY becomes RUNNING_PAIRED;
- paired_device UNPAIRED becomes RUNNING_NEEDS_PAIRING;
- source-only foundation mode, identity drift, unavailable paired identity,
  missing processes, or invalid state becomes
  RUNNING_DEGRADED_RECOVERY_REQUIRED.

The response exposes only the installed digest, install sequence, P8-A run
identity commitment, paired-device commitment, pairing epoch, stable blocker
codes, and a stable next-action code. It excludes raw Provider values, raw
Agent/session identifiers, command or prompt content, bearer values, browser
storage, and transcript references.

## Install Lifecycle Integration

install, upgrade, and rollback are stopped-only, so their successful results
classify the newly selected candidate as either INSTALLED_NEEDS_START or
INSTALLED_BLOCKED_HOST_IDENTITY. Public install status also includes the
current onboarding classification. The unlocked classifier is available to a
future caller that already owns lifecycle_lock and therefore does not add a
reentrant lock path.

Rollback remains code-only. It never rolls back pairing, mailbox cursor,
sequence, epoch, revocation, or Host identity state.

## Installed Bundle Closure

The implementation is deliberately in install_lifecycle.py, which is already
part of the strict installed package allowlist. Therefore onboarding works
from the exact installed bundle without a repository checkout.

onboarding.py is a thin source-tree facade. materialize.py explicitly copies
the frozen REQUIRED_PACKAGE set and leaves this facade source-only. The
declarative bundle_manifest.json records the onboarding schema, six states,
installed implementation module, source facade, and honest readiness flags.

P8-H integration requirement: CLI code inside the installed package should
import onboarding_status from install_lifecycle.py. If P8-H instead imports
onboarding.py, it must also update bundle.py REQUIRED_PACKAGE and the
materialized package closure in the same integration change. Directly using
the installed core avoids that redundant package surface.

## Verification

Focused coverage verifies:

- the exact six-state vocabulary;
- NOT_INSTALLED;
- stopped Host identity READY and blocked classifications;
- RUNNING_NEEDS_PAIRING and RUNNING_PAIRED from P8-A commitments;
- identity drift, source-only foundation, and dead/mismatched process recovery;
- fixed external NOT_RUN rows and production_ready=false;
- onboarding embedded in install, upgrade, and rollback results;
- the source-only facade/materialization contract;
- onboarding import and classification from a materialized bundle with a
  working directory outside the repository checkout.

Validated commands:

    python3 -m unittest discover -s testkit/nomad-web -p 'test_phase8_onboarding.py' -v
    python3 -m unittest discover -s testkit/nomad-web -p 'test_install_lifecycle.py' -v
    python3 -m unittest discover -s testkit/nomad-web -p 'test_prebuilt_bundle.py' -v

The prebuilt suite remains the installed-runtime regression. Its successful
official-agent start proves the content-addressed canonical bundle path still
starts Product Host, Agent, and Gateway without relying on checkout files.
