from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

from tools.nomad_web import recovery


class RecoveryTests(unittest.TestCase):
    def test_representative_codes_map_to_stable_user_recovery(self) -> None:
        cases = (
            ("RELEASE_BUNDLE_REQUIRED", "INSTALL_NOMAD", "INSTALL", recovery.REPO_OWNED),
            ("RUNTIME_IDENTITY_CHANGED_DURING_LIVE_PROBE", "RESTART_NOMAD", "APP_RUNTIME", recovery.REPO_OWNED),
            ("HOST_IDENTITY_AUTH_REQUIRED", "AUTHORIZE_THIS_MAC", "DEVICE_SECURITY", recovery.EXTERNAL),
            ("PAIRING_NOT_RUN", "PAIR_PHONE", "PAIRING", recovery.REPO_OWNED),
            ("REMOTE_UNINSTALL_REVOKE_REQUIRED", "REVOKE_PHONE", "PAIRING", recovery.REPO_OWNED),
            ("BROWSER_VAULT_LOST", "RESTORE_BROWSER_ACCESS", "BROWSER_STORAGE", recovery.REPO_OWNED),
            ("NON_LOOPBACK_NETWORK_ADDRESS_MISSING", "CONNECT_NETWORK", "NETWORK", recovery.REPO_OWNED),
            ("NORMAL_CHROME_TLS_TRUST_NOT_RUN", "TRUST_CERTIFICATE", "SECURE_CONNECTION", recovery.EXTERNAL),
            ("PROVIDER_E3_NOT_RUN", "RUN_AI_SERVICE_CHECK", "AI_SERVICE", recovery.EXTERNAL),
            ("PHYSICAL_PHONE_SAFARI_NOT_RUN", "RUN_PHONE_CHECK", "PHONE", recovery.EXTERNAL),
        )
        for blocker, code, category, scope in cases:
            with self.subTest(blocker=blocker):
                result = recovery.recovery_for_code(blocker)
                self.assertEqual((result["recovery_code"], result["category"], result["scope"]), (code, category, scope))
                self.assertEqual(result["next_step"].count("."), 1)

    def test_unknown_and_malformed_codes_fail_closed_without_echo(self) -> None:
        canary = "UNKNOWN_/private/user/token-secret-raw-id"
        expected = {
            "recovery_code": "CONTACT_SUPPORT",
            "category": "SUPPORT",
            "scope": recovery.REPO_OWNED,
            "next_step": "Collect diagnostics and contact support.",
        }
        for value in (canary, None, 42, {"code": canary}):
            with self.subTest(value=value):
                result = recovery.recovery_for_code(value)
                self.assertEqual(result, expected)
                self.assertNotIn(canary, json.dumps(result, sort_keys=True))

    def test_decorate_gate_preserves_pass_and_replaces_unsafe_next_step(self) -> None:
        passed = {"name": "bundle", "status": "PASS", "code": "OK", "next_step": None, "observations": {}}
        self.assertEqual(recovery.decorate_gate(passed), passed)
        canary = "/private/user/work?bearer=secret"
        blocked = dict(passed, status="BLOCK", code="UNRECOGNIZED_INTERNAL_CODE", next_step=canary)
        decorated = recovery.decorate_gate(blocked)
        self.assertEqual(decorated["recovery_code"], "CONTACT_SUPPORT")
        self.assertNotIn(canary, json.dumps(decorated, sort_keys=True))

    def test_recovery_report_is_ordered_deduplicated_and_scope_explicit(self) -> None:
        gates = [
            {"status": "PASS", "code": "RELEASE_BUNDLE_VERIFIED"},
            {"status": "BLOCK", "code": "RUNTIME_STATE_INVALID"},
            {"status": "BLOCK", "code": "RUNTIME_PROCESS_IDENTITY_NOT_VERIFIED"},
            {"status": "NOT_RUN", "code": "PROVIDER_E3_NOT_RUN"},
        ]
        report = recovery.recovery_report(gates)
        self.assertEqual(report["schema"], recovery.RECOVERY_SCHEMA)
        self.assertEqual([item["recovery_code"] for item in report["actions"]], ["RESTART_NOMAD", "RUN_AI_SERVICE_CHECK"])
        self.assertEqual(report["primary"], report["actions"][0])
        self.assertEqual({item["scope"] for item in report["actions"]}, {recovery.REPO_OWNED, recovery.EXTERNAL})

    def test_all_known_recovery_fields_are_content_safe(self) -> None:
        forbidden = ("/users/", "/private/", "secret", "token", "bearer", "pid", "uds", "digest", "schema", "relay", "provider", "e3")
        for code in recovery.KNOWN_RECOVERY_BLOCKER_CODES:
            with self.subTest(code=code):
                result = recovery.recovery_for_code(code)
                self.assertEqual(set(result), {"recovery_code", "category", "scope", "next_step"})
                self.assertRegex(result["recovery_code"], r"^[A-Z][A-Z0-9_]*$")
                self.assertIn(result["scope"], {recovery.REPO_OWNED, recovery.EXTERNAL})
                rendered = result["next_step"].lower()
                self.assertFalse(any(item in rendered for item in forbidden), result)

    def test_all_static_doctor_non_pass_codes_have_explicit_mapping(self) -> None:
        source = Path(__file__).resolve().parents[2] / "tools" / "nomad_web" / "doctor.py"
        raw = source.read_text(encoding="utf-8")
        tree = ast.parse(raw)
        codes: set[str] = set(re.findall(r'_LiveProbeError\("([A-Z0-9_]+)"', raw))
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Name) or call.func.id not in {"_gate", "_external_gate"}:
                continue
            code_index = 2 if call.func.id == "_gate" else 1
            if len(call.args) <= code_index or not isinstance(call.args[code_index], ast.Constant):
                continue
            code = call.args[code_index].value
            if not isinstance(code, str):
                continue
            if call.func.id == "_gate" and len(call.args) > 1 and isinstance(call.args[1], ast.Constant) and call.args[1].value == "PASS":
                continue
            codes.add(code)
        missing = codes - recovery.KNOWN_RECOVERY_BLOCKER_CODES
        self.assertEqual(missing, set())


if __name__ == "__main__":
    unittest.main()
