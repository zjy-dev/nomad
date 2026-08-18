import unittest
from unittest.mock import patch

from testkit.pilot.acceptance import AcceptanceError, validate_result
from testkit.pilot.doctor import check_health, check_loopback


GOOD = {
    "allow_once": False,
    "duplicate_host_acceptance": 0,
    "unknown_gap": 0,
    "command_stages": ["RelayReceived", "HostAccepted"],
    "telemetry": [
        {"name": "pilot.command_stage", "fields": {"action_type": "stop", "request_alias": "alias_1", "stage": "HostAccepted", "error_code": "OK"}}
    ],
}


class AcceptanceTests(unittest.TestCase):
    def test_good_result_passes(self):
        validate_result(GOOD)

    def test_safety_and_reliability_fail_closed(self):
        for key, value in (("allow_once", True), ("duplicate_host_acceptance", 1), ("unknown_gap", 1)):
            candidate = dict(GOOD)
            candidate[key] = value
            with self.assertRaises(AcceptanceError):
                validate_result(candidate)

    def test_telemetry_content_fails(self):
        candidate = dict(GOOD)
        candidate["telemetry"] = [{"name": "pilot.task_result", "fields": {"prompt": "secret"}}]
        with self.assertRaises(AcceptanceError):
            validate_result(candidate)

    def test_doctor_loopback_and_health(self):
        self.assertTrue(check_loopback("http://127.0.0.1:4096").ok)
        self.assertFalse(check_loopback("http://example.com:4096").ok)
        with patch("testkit.pilot.doctor.urllib.request.urlopen", side_effect=OSError()):
            self.assertEqual(check_health("http://127.0.0.1:4096", 0.1).code, "ERR_HOST_OFFLINE")


if __name__ == "__main__":
    unittest.main()
