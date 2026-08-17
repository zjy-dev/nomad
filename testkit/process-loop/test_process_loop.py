import unittest

from testkit.process_loop_import import validate_transcript_module


class TranscriptValidationTest(unittest.TestCase):
    def test_complete_transcript(self):
        module = validate_transcript_module()
        code = "123456"
        steps = [
            {"step": "pair.request", "direction": "mobile→relay", "detail": {"comparison_code": code}},
            {"step": "pair.confirmed", "direction": "relay→mobile", "detail": {"comparison_code": code}},
            {"step": "session.checkpoint", "direction": "relay→mobile", "detail": {"state": "NeedsPermission", "diff_file_count": 3}},
            {"step": "command.deny", "direction": "mobile→relay", "detail": {}},
            {"step": "command.result.deny", "direction": "relay→mobile", "detail": {"status": "HostAccepted", "relay_received_was": "not_host_accepted"}},
            {"step": "command.stop", "direction": "mobile→relay", "detail": {}},
            {"step": "command.result.stop", "direction": "relay→mobile", "detail": {"status": "HostAccepted"}},
            {"step": "command.allow_once", "direction": "mobile→relay", "detail": {}},
            {"step": "command.allow_once", "direction": "relay→mobile", "detail": {"status": "Rejected", "error_code": "ERR_SAFETY_BLOCKED", "allowed": False}},
            {"step": "done", "direction": "mobile→host", "detail": {}},
        ]
        module.validate_transcript({"steps": steps})


if __name__ == "__main__":
    unittest.main()
