import unittest

from testkit.pilot.telemetry import (
    TelemetryValidationError,
    alias_identifier,
    validate_event,
)


class TelemetryTests(unittest.TestCase):
    def test_allowlisted_event(self):
        validate_event(
            "pilot.command_stage",
            {"action_type": "stop", "request_alias": "alias_123", "stage": "HostAccepted", "error_code": "OK"},
        )

    def test_unknown_and_content_fields_fail_closed(self):
        with self.assertRaises(TelemetryValidationError):
            validate_event("pilot.unknown", {})
        with self.assertRaises(TelemetryValidationError):
            validate_event("pilot.task_result", {"task_id": "T1", "prompt": "private"})

    def test_nested_payload_is_forbidden(self):
        with self.assertRaises(TelemetryValidationError):
            validate_event("pilot.task_result", {"task_id": {"raw": "T1"}})

    def test_alias_requires_external_salt_and_is_stable(self):
        first = alias_identifier("participant@example.test", "pilot-run-salt")
        second = alias_identifier("participant@example.test", "pilot-run-salt")
        self.assertEqual(first, second)
        self.assertNotIn("participant", first)
        with self.assertRaises(TelemetryValidationError):
            alias_identifier("participant@example.test", "")


if __name__ == "__main__":
    unittest.main()
