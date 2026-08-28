from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from testkit.pilot import readiness_doctor as doctor


class ReadinessDoctorTests(unittest.TestCase):
    def test_all_missing_is_content_free_and_blocked(self):
        result = doctor.inspect(environment={})
        self.assertEqual(result["overall"], "BLOCKED_EXTERNAL_OR_LOCAL_GATE")
        self.assertTrue(all(set(g) == {"name", "state", "code"} for g in result["gates"]))
        self.assertTrue(any(g["code"] == "MISSING_ALLOWLISTED_NAME" for g in result["gates"]))

    def test_environment_canary_name_never_leaks_value(self):
        canary = "CREDENTIAL-CANARY-DO-NOT-LOG"
        result = doctor.inspect(environment={"OPENAI_API_KEY": canary})
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(canary, encoded)
        self.assertEqual(next(g for g in result["gates"] if g["name"] == "provider_credential_name")["state"], "AVAILABLE")
        self.assertEqual(doctor._provider_names({"OPENAI_API_KEY": ""}).state, "AVAILABLE")
        self.assertEqual(
            doctor._provider_names({"OPENAI_API_KEY": "a", "ANTHROPIC_API_KEY": "b"}).code,
            "MULTIPLE_ALLOWLISTED_NAMES",
        )

    def test_fake_marker_does_not_make_ready(self):
        result = doctor.inspect(environment={"OPENAI_API_KEY": "marker"})
        self.assertNotEqual(result["overall"], "READY_FOR_PRODUCTION")
        self.assertEqual(next(g for g in result["gates"] if g["name"] == "default_nomad_supervisor")["state"], "EXTERNAL_OWNER_REQUIRED")

    def test_symlink_nonregular_and_writable_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "x"
            path.write_text("x")
            self.assertEqual(doctor._owner_mode(path, directory=False).state, "AVAILABLE")
            path.chmod(0o606)
            self.assertEqual(doctor._owner_mode(path, directory=False).state, "INVALID")
            path.unlink(); path.symlink_to(Path(temp))
            self.assertEqual(doctor._owner_mode(path, directory=False).state, "INVALID")

    def test_no_mutation_and_default_supervisor_is_not_spawned(self):
        before = {p: p.lstat() for p in doctor.FIXED_ARTIFACTS.values() if p.exists()}
        doctor.inspect(environment={})
        after = {p: p.lstat() for p in doctor.FIXED_ARTIFACTS.values() if p.exists()}
        self.assertEqual(set(before), set(after))
        supervisor = next(g for g in doctor.inspect(environment={})["gates"] if g["name"] == "default_nomad_supervisor")
        self.assertEqual(supervisor["state"], "EXTERNAL_OWNER_REQUIRED")
        self.assertEqual(supervisor["code"], "BLOCKED_NATIVE_SUPERVISOR_AUTHORITY_UNAVAILABLE")

    def test_evidence_and_staging_states_are_distinct(self):
        result = doctor.inspect(environment={})
        gates = {g["name"]: g for g in result["gates"]}
        self.assertEqual(gates["lifecycle-evidence-manifest.json"]["code"], "MISSING_REAL_EVIDENCE")
        self.assertEqual(gates["lifecycle-evidence-manifest.json.tmp"]["code"], "AVAILABLE_STAGING_SLOT")

    def test_existing_final_evidence_blocks_operator_preflight(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "lifecycle-certificate.json"
            target.write_text("{}")
            original = doctor.FIXED_ARTIFACTS["lifecycle_certificate"]
            try:
                doctor.FIXED_ARTIFACTS["lifecycle_certificate"] = target
                result = doctor.inspect(environment={"OPENAI_API_KEY": "canary"})
                self.assertEqual(result["overall"], "BLOCKED_EXTERNAL_OR_LOCAL_GATE")
            finally:
                doctor.FIXED_ARTIFACTS["lifecycle_certificate"] = original

    def test_local_directory_gate_blocks_operator_preflight(self):
        original = doctor.FIXED_DIRS["real_task"]
        try:
            doctor.FIXED_DIRS["real_task"] = original / "missing-fixed-directory"
            result = doctor.inspect(environment={"OPENAI_API_KEY": "marker"})
            self.assertEqual(result["overall"], "BLOCKED_EXTERNAL_OR_LOCAL_GATE")
        finally:
            doctor.FIXED_DIRS["real_task"] = original

    def test_external_gates_are_explicit_and_never_production_ready(self):
        result = doctor.inspect(environment={"OPENAI_API_KEY": "marker"})
        gates = {g["name"]: g for g in result["gates"]}
        for name in ("developer_id_host", "sshsig_trust_and_krl", "protected_cas_publication"):
            self.assertEqual(gates[name]["state"], "EXTERNAL_OWNER_REQUIRED")
        self.assertNotEqual(result["overall"], "READY_FOR_PRODUCTION")

    def test_cli_is_canonical_json_and_no_provider_value(self):
        completed = subprocess.run([sys.executable, str(Path(doctor.__file__)) , "--json"], check=False, capture_output=True, text=True)
        self.assertIn('"schema":"nomad.phase4.readiness-doctor.v1"', completed.stdout)
        self.assertNotIn("OPENAI_API_KEY=", completed.stdout)
        self.assertNotIn("CREDENTIAL", completed.stdout)


if __name__ == "__main__":
    unittest.main()
