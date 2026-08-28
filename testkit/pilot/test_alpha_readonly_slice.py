from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


class AlphaReadonlySliceTests(unittest.TestCase):
    def test_real_local_alpha_readonly_mechanics(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "testkit.pilot.run_alpha_readonly_slice",
                "--repo",
                str(repo),
                "--timeout",
                "180",
            ],
            cwd=repo,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "HOME": os.environ.get("HOME", ""),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=240,
            check=False,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        result = json.loads(completed.stdout)
        self.assertEqual(
            set(result),
            {"marker", "source", "production_ready", "pilot_ready", "evidence"},
        )
        self.assertEqual(result["marker"], "LOCAL_ALPHA_READONLY_MECHANICS_PASS")
        self.assertEqual(result["source"], "SYNTHETIC_SOURCE")
        self.assertIs(result["production_ready"], False)
        self.assertIs(result["pilot_ready"], False)
        self.assertEqual(
            result["evidence"]["relay_routes"],
            {"frame": 1, "frames": 2, "ack": 1, "test_routes": 0},
        )
        self.assertEqual(
            result["evidence"]["gateway_routes"],
            {
                "alpha_session": 2,
                "pilot_commands_blocked": 1,
                "default_pilot_session": 0,
            },
        )
        self.assertEqual(
            result["evidence"]["restart"],
            {"state_continuous": True, "ack_continuous": True},
        )
        self.assertEqual(
            result["evidence"]["secret_hygiene"],
            {"argv_clean": True, "logs_clean": True, "browser_bundle_clean": True},
        )


if __name__ == "__main__":
    unittest.main()
