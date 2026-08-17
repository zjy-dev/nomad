"""testkit.e2e: Synthetic fake OpenCode and Nomad E2E harness."""

from .fake_opencode import EventRecord, OpenCodeSession
from .harness import NomadE2EHarness, ProtocolAssertion, main

__all__ = [
    "EventRecord",
    "NomadE2EHarness",
    "OpenCodeSession",
    "ProtocolAssertion",
    "main",
]
