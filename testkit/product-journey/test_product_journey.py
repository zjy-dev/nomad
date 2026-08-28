from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("product_journey", HERE / "run_product_journey.py")
runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runner)


class ProductJourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        if not chrome.is_file():
            raise RuntimeError("P8G_REAL_INTEGRATION_REQUIRES_CHROME")
        from tools.nomad_web.materialize import materialize
        cls._materialize_tmp = tempfile.TemporaryDirectory(prefix="p8g-integration-")
        cls.real_bundle = Path(cls._materialize_tmp.name) / "bundle"
        materialize(ROOT, cls.real_bundle)

    @classmethod
    def tearDownClass(cls):
        cls._materialize_tmp.cleanup()

    def _bundle(self, root: Path) -> Path:
        bundle = root / "source-bundle"
        bundle.mkdir()
        return bundle

    def _c3_result(self) -> dict:
        actions = {
            name: {"browser_path": "visible_control", "browser_requests": 1, "browser_responses": 1, "posts": 1, "replay_side_effects": 0}
            for name in ("reply", "deny", "stop")
        }
        actions["uncertainty"] = {"status": "OutcomeUnknown", "posts": 1, "automatic_retries": 0}
        return {
            "marker": "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS",
            "mechanical_e2": True, "provider_e3": False, "production_ready": False,
            "run_binding": "a" * 64,
            "materialized_product_host": True, "materialized_gateway": True, "materialized_web": True,
            "fake_boundary": "external_loopback_opencode_shape",
            "browser": {"engine": "Google Chrome headless via CDP", "desktop": "1440x900", "mobile": "390x844", "same_projection": True},
            "actions": actions,
            "fresh_five_route_reads": {"minimum_per_route": 5},
            "privacy": {"browser": True, "logs": True, "persistent_sqlite": True, "argv": True},
            "containment": {"fd_10_bootstrap": True, "fd_11_transport_key": True, "independent_keys": True, "browser_has_no_uds": True, "gateway_browser_have_no_upstream_connection": True, "uds_mode": "0600", "uds_parent_mode": "0700", "sqlite_modes": {}},
            "journal": {"mode": "wal", "synchronous": "FULL", "rows": 4},
            "elapsed_seconds": 0.1,
            "cleanup": {"processes": True, "ports": True, "uds": True,
                         "journal": True, "gateway_db": True, "device_registry": True},
        }

    def test_c3_parser_requires_exact_contract(self):
        fake_module = SimpleNamespace(CHROME=Path(__file__), run_smoke=mock.Mock(return_value=self._c3_result()))
        with mock.patch.object(runner, "_load", return_value=fake_module):
            result = runner._run_b(Path("/installed"), "sha256:" + "b" * 64)
        self.assertEqual(result["status"], "PASS")
        invalid = self._c3_result()
        invalid["cleanup"]["ports"] = False
        fake_module.run_smoke.return_value = invalid
        with mock.patch.object(runner, "_load", return_value=fake_module):
            result = runner._run_b(Path("/installed"), "sha256:" + "b" * 64)
        self.assertEqual(result["code"], "P8G_C3_RESULT_CONTRACT_INVALID")

    def test_lifecycle_order_and_installed_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._bundle(root)
            home = root / "home"
            selected = home / "bundles" / ("a" * 64)
            selected.mkdir(parents=True)
            calls = []
            lifecycle = SimpleNamespace(
                install=mock.Mock(side_effect=lambda config, bundle: calls.append(("install", bundle)) or {"current_bundle_digest": "a" * 64}),
                onboarding_status=mock.Mock(side_effect=lambda config: calls.append(("onboarding",)) or {"current_bundle_digest": "a" * 64, "state": "UNONBOARDED"}),
            )
            diagnostics = SimpleNamespace(collect=mock.Mock(side_effect=lambda *args, **kwargs: calls.append(("diagnostics",)) or {"status": "PASS", "production_ready": False}))
            launcher = SimpleNamespace(
                reset_remote_access=mock.Mock(side_effect=lambda *args, **kwargs: calls.append(("reset",)) or {"state": "STOPPED"}),
                uninstall_lifecycle=mock.Mock(side_effect=lambda *args, **kwargs: calls.append(("uninstall",)) or {"state": "UNINSTALLED"}),
            )
            c3 = SimpleNamespace(CHROME=Path(__file__), run_smoke=mock.Mock(side_effect=lambda timeout, chrome, bundle: calls.append(("B", bundle)) or self._c3_result()))
            with mock.patch.object(runner, "_bundle_digest", side_effect=lambda path: calls.append(("digest", path)) or "a" * 64), mock.patch.object(runner, "_load", side_effect=lambda path, name: c3), mock.patch("tools.nomad_web.install_lifecycle.install", lifecycle.install), mock.patch("tools.nomad_web.install_lifecycle.onboarding_status", lifecycle.onboarding_status), mock.patch("tools.nomad_web.diagnostics.collect", diagnostics.collect), mock.patch("tools.nomad_web.launcher.reset_remote_access", launcher.reset_remote_access), mock.patch("tools.nomad_web.launcher.uninstall_lifecycle", launcher.uninstall_lifecycle):
                config_result, selected_result, stages = runner._run_c_prepare(source, home, root)
                calls.append(("B", selected_result))
                calls.append(("A", selected_result))
                runner._run_c_cleanup(config_result, home, stages)
            self.assertEqual(selected_result, selected.resolve())
            self.assertEqual([name for name, *_ in calls if name in {"install", "onboarding", "B", "A", "diagnostics", "reset", "uninstall"}], ["install", "onboarding", "B", "A", "diagnostics", "reset", "uninstall"], stages)
            self.assertEqual(calls[calls.index(("B", selected_result))][1], selected_result)
            self.assertEqual(stages[0]["status"], "PASS")

    def test_parent_status_ignores_external_not_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._bundle(root)
            c = {"name": "C_lifecycle", "status": "PASS", "code": "LIFECYCLE_COMPLETE", "facts": {}}
            b = {"name": "B_c3_local", "status": "PASS", "code": "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS", "facts": {}}
            a = {"name": "A_real_product", "status": "NOT_RUN", "code": "P8G_TLS_CONTROL_INPUT_REQUIRED", "facts": {}}
            with mock.patch.object(runner, "_run_c_prepare", return_value=(SimpleNamespace(), source, [])), mock.patch.object(runner, "_run_b", return_value=b), mock.patch.object(runner, "_run_a", return_value=a), mock.patch.object(runner, "_run_c_cleanup", return_value=c), mock.patch.object(runner, "_bundle_digest", return_value="a" * 64):
                result = runner.run_journey(source, work_root=root / "work")
        self.assertEqual(result["repo_owned_status"], "PASS")
        self.assertEqual(result["external_readiness"], "NOT_RUN")
        self.assertFalse(result["production_ready"])

    def test_real_run_journey_installs_runs_c3_and_removes_home(self):
        with tempfile.TemporaryDirectory(prefix="p8g-real-work-") as temp:
            work = Path(temp) / "work"
            evidence = Path(temp) / "evidence.json"
            result = runner.run_journey(self.real_bundle, work_root=work, evidence=evidence)
            self.assertEqual(result["repo_owned_status"], "PASS", result["stages"])
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["external_readiness"], "NOT_RUN")
            self.assertFalse(result["production_ready"])
            self.assertEqual([stage["name"] for stage in result["stages"]], ["B_c3_local", "A_real_product", "C_lifecycle"])
            self.assertEqual(result["stages"][0]["status"], "PASS")
            self.assertEqual(result["stages"][0]["code"], "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS")
            lifecycle_names = [stage["name"] for stage in result["stages"][2]["facts"]["stages"]]
            self.assertEqual(lifecycle_names, ["install", "onboarding", "diagnostics", "reset", "uninstall", "residue"])
            self.assertTrue(all(stage["status"] == "PASS" for stage in result["stages"][2]["facts"]["stages"]))
            self.assertFalse((work / "home").exists())
            evidence_value = json.loads(evidence.read_text())
            action_evidence = evidence_value["stages"][0]["facts"]["result"]["actions"]
            self.assertEqual(action_evidence["reply"], {"browser_path": "visible_control", "browser_requests": 1, "browser_responses": 1, "posts": 1, "replay_side_effects": 0})
            serialized = json.dumps(evidence_value, sort_keys=True)
            self.assertNotIn("request_body", serialized)
            self.assertNotIn("response_body", serialized)
            self.assertNotIn("csrf", serialized.lower())

    def test_atomic_evidence_is_0600_and_non_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            runner._write_atomic(path, {"value": 1})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, "P8G_EVIDENCE_EXISTS"):
                runner._write_atomic(path, {"value": 2})
            self.assertEqual(json.loads(path.read_text())["value"], 1)

    def test_bundle_verification_errors_are_stable_invalid(self):
        import tools.nomad_web.bundle as bundle_module
        with mock.patch.object(bundle_module, "verify_bundle", side_effect=RuntimeError("invalid")):
            with self.assertRaisesRegex(RuntimeError, "P8G_BUNDLE_VERIFY_FAILED"):
                runner._bundle_digest(Path("/invalid"))
        with tempfile.TemporaryDirectory() as temp:
            invalid = Path(temp) / "invalid"
            invalid.mkdir()
            with self.assertRaisesRegex(RuntimeError, "P8G_BUNDLE_VERIFY_FAILED"):
                runner.run_journey(invalid, work_root=Path(temp) / "work")

    def test_unsafe_work_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            with self.assertRaisesRegex(RuntimeError, "P8G_UNSAFE_WORK_ROOT"):
                runner.run_journey(self._bundle(root), work_root=unsafe)


if __name__ == "__main__":
    unittest.main()
