from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
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
            "browser": {"engine": "Google Chrome headless via CDP", "desktop": "1440x900", "mobile": "390x844", "same_projection": True, "desktop_screenshot_sha256": "b" * 64, "mobile_screenshot_sha256": "c" * 64},
            "actions": actions,
            "fresh_five_route_reads": {"minimum_per_route": 5},
            "privacy": {"browser": True, "logs": True, "persistent_sqlite": True, "argv": True},
            "containment": {"fd_10_bootstrap": True, "fd_11_transport_key": True, "independent_keys": True, "browser_has_no_uds": True, "gateway_browser_have_no_upstream_connection": True, "uds_mode": "0600", "uds_parent_mode": "0700", "sqlite_modes": {"command-1234567890abcdef12345678.sqlite3": "0600", "command-1234567890abcdef12345678.sqlite3-wal": "0600", "command-1234567890abcdef12345678.sqlite3-shm": "0600", "gateway.sqlite3": "0600", "gateway.sqlite3-wal": "0600", "gateway.sqlite3-shm": "0600"}},
            "journal": {"mode": "wal", "synchronous": "FULL", "rows": 4},
            "elapsed_seconds": 0.1,
            "cleanup": {"processes": True, "ports": True, "uds": True,
                         "journal": True, "gateway_db": True, "device_registry": True},
        }

    def _qa_binding(self, bundle_digest: str = "c" * 64) -> dict[str, str]:
        core = {
            "classification": runner.QA_DRIVER_CLASSIFICATION,
            "trusted_source_sha256": runner.QA_DRIVER_SOURCE_SHA256,
            "generated_sha256": "a" * 64,
            "installed_bundle_digest": bundle_digest,
        }
        return {**core, "closure_digest": runner.hashlib.sha256(runner.canonical(core)).hexdigest()}

    def test_c3_parser_requires_exact_contract(self):
        fake_module = SimpleNamespace(CHROME=Path(__file__), run_smoke=mock.Mock(return_value=self._c3_result()))
        with mock.patch.object(runner, "_load_qa_driver", return_value=fake_module):
            result = runner._run_b(Path("/installed"), "c" * 64, Path("/staged-driver"), self._qa_binding(), "sha256:" + "b" * 64)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["facts"]["qa_driver"], self._qa_binding())
        invalid = self._c3_result()
        invalid["cleanup"]["ports"] = False
        fake_module.run_smoke.return_value = invalid
        with mock.patch.object(runner, "_load_qa_driver", return_value=fake_module):
            result = runner._run_b(Path("/installed"), "c" * 64, Path("/staged-driver"), self._qa_binding(), "sha256:" + "b" * 64)
        self.assertEqual(result["code"], "P8G_C3_RESULT_CONTRACT_INVALID")

    def test_c3_parser_table_driven_strict_shape_mutations_block(self):
        def replace(path: tuple[str, ...], value: object):
            def mutate(result: dict) -> None:
                target = result
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return mutate

        def remove(path: tuple[str, ...]):
            def mutate(result: dict) -> None:
                target = result
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]
            return mutate

        cases = {
            "run-binding-short": replace(("run_binding",), "a" * 63),
            "run-binding-uppercase": replace(("run_binding",), "A" * 64),
            "fake-boundary": replace(("fake_boundary",), "other"),
            "browser-extra-key": replace(("browser", "unexpected"), True),
            "browser-engine": replace(("browser", "engine"), "Chrome"),
            "browser-desktop-size": replace(("browser", "desktop"), "1x1"),
            "browser-mobile-size": replace(("browser", "mobile"), "1x1"),
            "browser-same-projection-type": replace(("browser", "same_projection"), 1),
            "browser-screenshot": replace(("browser", "desktop_screenshot_sha256"), "A" * 64),
            "freshness-extra-key": replace(("fresh_five_route_reads", "route"), 5),
            "freshness-below-five": replace(("fresh_five_route_reads", "minimum_per_route"), 4),
            "freshness-bool": replace(("fresh_five_route_reads", "minimum_per_route"), True),
            "containment-missing-key": remove(("containment", "fd_10_bootstrap")),
            "containment-non-bool": replace(("containment", "independent_keys"), 1),
            "containment-uds-mode": replace(("containment", "uds_mode"), "0644"),
            "containment-parent-mode": replace(("containment", "uds_parent_mode"), "0755"),
            "sqlite-file-set": remove(("containment", "sqlite_modes", "gateway.sqlite3-shm")),
            "sqlite-mode": replace(("containment", "sqlite_modes", "gateway.sqlite3"), "0644"),
            "journal-extra-key": replace(("journal", "unexpected"), True),
            "journal-mode": replace(("journal", "mode"), "delete"),
            "journal-synchronous": replace(("journal", "synchronous"), "NORMAL"),
            "journal-rows": replace(("journal", "rows"), 3),
            "journal-rows-bool": replace(("journal", "rows"), True),
            "elapsed-negative": replace(("elapsed_seconds",), -0.1),
            "elapsed-nan": replace(("elapsed_seconds",), float("nan")),
            "elapsed-bool": replace(("elapsed_seconds",), True),
        }
        fake_module = SimpleNamespace(CHROME=Path(__file__), run_smoke=mock.Mock())
        for name, mutate in cases.items():
            invalid = copy.deepcopy(self._c3_result())
            mutate(invalid)
            fake_module.run_smoke.return_value = invalid
            with self.subTest(name=name), mock.patch.object(
                runner, "_load_qa_driver", return_value=fake_module,
            ):
                stage = runner._run_b(
                    Path("/installed"), "c" * 64, Path("/staged-driver"),
                    self._qa_binding(), "sha256:" + "b" * 64,
                )
            self.assertEqual(stage["status"], "BLOCK", name)
            self.assertEqual(stage["code"], "P8G_C3_RESULT_CONTRACT_INVALID", name)

    def test_staged_qa_driver_is_hash_pinned_and_repo_source_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            installed = root / "home" / "bundles" / ("c" * 64)
            package = installed / "lib" / "nomad_web"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "processes.py").write_text("ORIGIN = 'installed'\n", encoding="utf-8")
            (package / "launcher.py").write_text(
                "_bootstrap_host = object()\n"
                "_cleanup_product_host_socket = object()\n"
                "_random_command_key = object()\n"
                "_spawn_product_host = object()\n"
                "_write_fd_secret = object()\n", encoding="utf-8",
            )
            (package / "materialize.py").write_text("materialize = object()\n", encoding="utf-8")
            source = repo / "testkit" / "browser" / "c3_local_command_smoke.py"
            source.parent.mkdir(parents=True)
            source_raw = (
                "from pathlib import Path\n"
                "import sys\n"
                "REPO = Path(__file__).resolve().parents[2]\n"
                "if __package__ in (None, \"\"):\n"
                "    sys.path.insert(0, str(REPO))\n"
                "from tools.nomad_web import processes\n"
                "from tools.nomad_web.launcher import (\n"
                "    _bootstrap_host, _cleanup_product_host_socket,\n"
                "    _random_command_key, _spawn_product_host, _write_fd_secret,\n"
                ")\n"
                "from tools.nomad_web.materialize import materialize\n"
                "IMPORT_ORIGIN = processes.ORIGIN\n"
                f"CHROME = Path({str(runner.CHROME)!r})\n"
                f"def run_smoke(timeout, chrome, bundle): return {self._c3_result()!r}\n"
            )
            source.write_text(source_raw, encoding="utf-8")
            trusted = runner.hashlib.sha256(source_raw.encode()).hexdigest()
            with mock.patch.object(runner, "QA_DRIVER_SOURCE_SHA256", trusted):
                staged, binding = runner._stage_qa_driver(
                    source, root / "owned-stage", installed, installed.name,
                )
            staged_raw = staged.read_bytes()
            self.assertNotIn(str(repo).encode(), staged_raw)
            self.assertNotIn(b"from tools.nomad_web", staged_raw)
            with mock.patch.object(runner, "QA_DRIVER_SOURCE_SHA256", trusted):
                loaded = runner._load_qa_driver(staged, binding, installed, installed.name)
            self.assertEqual(loaded.IMPORT_ORIGIN, "installed")

            source.write_text("raise RuntimeError('MUTATED_REPO_DRIVER_USED')\n", encoding="utf-8")
            with mock.patch.object(runner, "QA_DRIVER_SOURCE_SHA256", trusted):
                mutated = runner._run_b(
                    installed, installed.name, staged, binding,
                    "sha256:" + "b" * 64,
                )
                source.unlink()
                removed = runner._run_b(
                    installed, installed.name, staged, binding,
                    "sha256:" + "b" * 64,
                )

            self.assertEqual(mutated["status"], "PASS")
            self.assertEqual(removed["status"], "PASS")
            self.assertEqual(staged.read_bytes(), staged_raw)
            self.assertEqual(binding["generated_sha256"], runner.hashlib.sha256(staged_raw).hexdigest())
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            self.assertEqual(staged.parent.stat().st_mode & 0o777, 0o700)
            staged.write_text("tampered\n", encoding="utf-8")
            with mock.patch.object(runner, "QA_DRIVER_SOURCE_SHA256", trusted):
                blocked = runner._run_b(
                    installed, installed.name, staged, binding,
                    "sha256:" + "b" * 64,
                )
            self.assertEqual(blocked["code"], "P8H_QA_DRIVER_DIGEST_MISMATCH")
            staged.unlink()
            symlink_target = root / "symlink-target.py"
            symlink_target.write_bytes(staged_raw)
            staged.symlink_to(symlink_target)
            with mock.patch.object(runner, "QA_DRIVER_SOURCE_SHA256", trusted):
                symlinked = runner._run_b(
                    installed, installed.name, staged, binding,
                    "sha256:" + "b" * 64,
                )
            self.assertEqual(symlinked["code"], "P8H_QA_DRIVER_STAGE_INVALID")

    def test_a_without_tls_does_not_import_repo_runner(self):
        with mock.patch.object(runner, "_load", side_effect=AssertionError("repo import")):
            result = runner._run_a(
                Path("/installed"), Path("/evidence"),
                "sha256:" + "b" * 64,
            )
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["code"], "P8G_TLS_CONTROL_INPUT_REQUIRED")

    def test_installed_cli_parser_requires_exit_canonical_json_and_clean_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            launcher = root / "home" / "bin" / "nomad-web"
            cwd = root / "cwd"
            cwd.mkdir()
            value = {"schema": "example.v1", "state": "READY"}
            completed = subprocess.CompletedProcess(
                [str(launcher)], 0, runner.canonical(value), b""
            )
            with mock.patch.object(runner, "_run_process", return_value=completed) as invoked:
                self.assertEqual(runner._installed_json(launcher, cwd, ("install-status",)), value)
            argv, actual_cwd = invoked.call_args.args
            self.assertEqual(argv, [str(launcher), "--json", "install-status"])
            self.assertEqual(actual_cwd, cwd)
            with mock.patch.object(runner, "_run_process", return_value=subprocess.CompletedProcess([], 0, b'{"state": "READY"}\n', b"")):
                with self.assertRaisesRegex(RuntimeError, "P8H_INSTALLED_CLI_NONCANONICAL"):
                    runner._installed_json(launcher, cwd, ("onboarding",))
            with mock.patch.object(runner, "_run_process", return_value=subprocess.CompletedProcess([], 1, runner.canonical(value), b"")):
                with self.assertRaisesRegex(RuntimeError, "P8H_INSTALLED_CLI_EXIT_INVALID"):
                    runner._installed_json(launcher, cwd, ("onboarding",))

    def test_parent_status_ignores_external_not_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._bundle(root)
            c = {"name": "C_lifecycle", "status": "PASS", "code": "LIFECYCLE_COMPLETE", "facts": {}}
            b = {"name": "B_c3_local", "status": "PASS", "code": "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS", "facts": {}}
            a = {"name": "A_real_product", "status": "NOT_RUN", "code": "P8G_TLS_CONTROL_INPUT_REQUIRED", "facts": {}}
            selected = root / ("a" * 64)
            stable = root / "stable"
            with mock.patch.object(runner, "_run_c_install", return_value=(selected, stable, [])), mock.patch.object(runner, "_stage_qa_driver", return_value=(root / "qa", self._qa_binding("a" * 64))), mock.patch.object(runner, "_run_c_installed_prepare"), mock.patch.object(runner, "_run_b", return_value=b), mock.patch.object(runner, "_run_a", return_value=a), mock.patch.object(runner, "_run_c_cleanup", return_value=c), mock.patch.object(runner, "_bundle_digest", return_value="a" * 64):
                result = runner.run_journey(source, work_root=root / "work")
        self.assertEqual(result["repo_owned_status"], "PASS")
        self.assertEqual(result["external_readiness"], "NOT_RUN")
        self.assertEqual(result["remote_local_evidence_status"], "NOT_RUN")
        self.assertEqual(
            result["provider_e3"],
            {"status": "NOT_RUN", "code": "PROVIDER_E3_EVIDENCE_NOT_RUN"},
        )
        self.assertFalse(result["production_ready"])

    def test_real_run_journey_installs_runs_c3_and_removes_home(self):
        with tempfile.TemporaryDirectory(prefix="p8g-real-work-") as temp:
            work = Path(temp) / "work"
            evidence = Path(temp) / "evidence.json"
            result = runner.run_journey(self.real_bundle, work_root=work, evidence=evidence)
            self.assertEqual(result["repo_owned_status"], "PASS", result["stages"])
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["external_readiness"], "NOT_RUN")
            self.assertEqual(result["remote_local_evidence_status"], "NOT_RUN")
            self.assertFalse(result["production_ready"])
            self.assertEqual([stage["name"] for stage in result["stages"]], ["B_c3_local", "A_remote_local_evidence", "C_lifecycle"])
            self.assertEqual(result["stages"][0]["status"], "PASS")
            self.assertEqual(result["stages"][0]["code"], "C3_LOCAL_COMMAND_MECHANICAL_E2_PASS")
            lifecycle_names = [stage["name"] for stage in result["stages"][2]["facts"]["stages"]]
            self.assertEqual(lifecycle_names, ["install", "install-status", "onboarding", "missing-provider-credential", "diagnostics", "reset", "uninstall", "residue"])
            self.assertTrue(all(stage["status"] == "PASS" for stage in result["stages"][2]["facts"]["stages"]))
            missing = result["stages"][2]["facts"]["stages"][3]
            self.assertEqual(missing["code"], "AGENT_START_INPUTS_INCOMPLETE")
            self.assertTrue(missing["facts"]["expected_block"])
            self.assertTrue(result["stages"][2]["facts"]["stages"][1]["facts"]["source_bundle_removed"])
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

    def test_blocked_result_preserves_honest_external_fields(self):
        result = runner._blocked_result("P8G_BUNDLE_VERIFY_FAILED")
        self.assertEqual(result["status"], result["repo_owned_status"])
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(result["remote_local_evidence_status"], "NOT_RUN")
        self.assertEqual(result["external_readiness"], "NOT_RUN")
        self.assertFalse(result["production_ready"])
        self.assertEqual(len(result["external_gates"]), 6)
        self.assertEqual({item["status"] for item in result["external_gates"]}, {"NOT_RUN"})
        self.assertTrue(result["privacy"]["content_free"])

    def test_unsafe_work_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            with self.assertRaisesRegex(RuntimeError, "P8G_UNSAFE_WORK_ROOT"):
                runner.run_journey(self._bundle(root), work_root=unsafe)


if __name__ == "__main__":
    unittest.main()
