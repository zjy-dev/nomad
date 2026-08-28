from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).with_name("run_m3e_product_slice.py")
SPEC = importlib.util.spec_from_file_location("run_m3e_product_slice", MODULE)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class ProductSliceTests(unittest.TestCase):
    def test_content_free_non_claims_are_literal(self) -> None:
        source = MODULE.read_text()
        self.assertIn('"provider_e3": "NOT_RUN"', source)
        self.assertIn('"physical_phone": "NOT_RUN"', source)
        self.assertIn('"production_ready": False', source)
        self.assertIn('"network_scope": "lan_direct"', source)
        self.assertIn('"ignore_https_errors": False', source)

    def test_browser_never_enables_https_bypass(self) -> None:
        source = Path(__file__).with_name("run_m3e_desktop_browser.py").read_text()
        self.assertNotIn("ignore_https_errors=True", source)
        self.assertNotIn('"--ignore-certificate-errors"', source)
        self.assertIn('"ignore_https_errors": False', source)
        self.assertIn("--ignore-certificate-errors-spki-list=", source)

    def test_diagnostic_mode_cannot_claim_pass(self) -> None:
        source = MODULE.read_text()
        self.assertIn('"DIAGNOSTIC_COMPLETE" if diagnostic_spki_bypass else "PASS"', source)
        self.assertIn('"tls_verified": not diagnostic_spki_bypass', source)
        self.assertIn('if not diagnostic_spki_bypass:', source)
        self.assertIn('evidence["marker"] = MARKER', source)

    def test_provider_environment_is_removed(self) -> None:
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "secret", "PATH": "/bin"}, clear=True):
            env = harness.sanitized_env({"NOMAD_TEST": "yes"})
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertEqual(env["NOMAD_TEST"], "yes")

    def test_credential_pipe_is_prefilled_and_closed(self) -> None:
        descriptor = harness._credential_pipe()
        self.addCleanup(lambda: os.close(descriptor))
        self.assertEqual(os.read(descriptor, 4096), b"TEST_ONLY_NOMAD_E6D_CANARY_NO_PROVIDER_CALLS")
        self.assertEqual(os.read(descriptor, 1), b"")

    def test_process_topology_requires_exact_seven_roles(self) -> None:
        state = {"processes": [
            {"name": name, "pid": 123, "identity": f"identity-{name}"}
            for name in harness.PROCESS_NAMES
        ]}
        with mock.patch("os.kill"):
            evidence = harness.process_evidence(state)
        self.assertEqual([item["name"] for item in evidence], harness.PROCESS_NAMES)
        state["processes"] = state["processes"][:-1]
        with self.assertRaisesRegex(harness.SliceError, "seven_process_topology_mismatch"):
            harness.process_evidence(state)

    def test_evidence_file_is_private_and_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "evidence.json"
            harness.write_evidence(path, {"z": 1, "a": 2})
            self.assertEqual(path.read_bytes(), b'{"a":2,"z":1}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_default_bundle_and_digest_are_frozen(self) -> None:
        self.assertEqual(harness.DEFAULT_BUNDLE, Path("/tmp/nomad-e6d-final7-bundle"))
        self.assertEqual(len(harness.EXPECTED_BUNDLE_DIGEST), 64)
        self.assertEqual(harness.EXPECTED_BUNDLE_DIGEST, "683382f135833bef10ca8df700d3d06033c0663b3a0a38ff949739400d196423")

    def test_identity_preflight_user_denied_is_zero_process_blocker(self) -> None:
        completed = __import__("types").SimpleNamespace(
            returncode=1, stdout=b'{"status":"USER_DENIED"}\n', stderr=b""
        )
        with mock.patch.object(harness.subprocess, "run", side_effect=[completed, __import__("types").SimpleNamespace(returncode=0, stdout="", stderr="")]):
            result = harness.host_identity_preflight(Path("/tmp/bundle"))
        self.assertEqual(result, {
            "status": "USER_DENIED",
            "business_process_count": 0,
            "ready": False,
            "error_code": "HOST_IDENTITY_USER_DENIED",
            "next_step": "nomad-web authorize-host-identity",
        })

    def test_launcher_error_diagnostics_only_allow_uppercase_codes(self) -> None:
        source = MODULE.read_text()
        self.assertIn('re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", candidate)', source)
        self.assertIn('{"launcher_error_code": code}', source)
        self.assertNotIn('"launcher_stderr"', source)
        self.assertNotIn('"raw_stderr"', source)


if __name__ == "__main__":
    unittest.main()
