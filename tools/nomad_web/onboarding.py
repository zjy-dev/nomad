"""Ordinary-user onboarding facade for source-tree consumers.

The implementation lives in install_lifecycle so an exact installed bundle is
self-contained under the currently frozen package allowlist.
"""

from .install_lifecycle import (
    ONBOARDING_SCHEMA,
    ONBOARDING_STATES,
    onboarding_status,
    onboarding_status_unlocked,
)

classify = onboarding_status
classify_unlocked = onboarding_status_unlocked

__all__ = [
    "ONBOARDING_SCHEMA", "ONBOARDING_STATES", "classify", "classify_unlocked",
]
