from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import install_lifecycle as lifecycle
from tools.nomad_web import onboarding


class Phase8OnboardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nomad-onboarding-")
        self.config = SimpleNamespace(home=Path(self.temporary.name) / "home")
        self.digest = "a" * 64
        self.installed = {
            "schema": lifecycle.STATUS_SCHEMA,
            "state": "INSTALLED",
            "current_bundle_digest": self.digest,
            "bundle_digests": [self.digest],
            "history": [{"sequence": 4}],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_state(self, paired: str, *, digest: str | None = None) -> dict[str, object]:
        selected = digest or self.digest
        install_identity = lifecycle._expected_installed_identity(self.installed)
        if selected != self.digest:
            install_identity = {
                "availability": "READY", "bundle_digest": selected,
                "install_sequence": 4,
                "install_identity": "e" * 64,
            }
        return {
            "bundle_digest": selected,
            "processes": [{"name": "product-host"}],
            "identity": {
                "installed": install_identity,
                "running": {
                    "availability": "READY", "bundle_digest": selected,
                    "run_identity": "b" * 64,
                },
                "host_public_commitment": {"availability": "UNAVAILABLE", "commitment": None},
                "paired_device": {
                    "availability": paired,
                    "device_key_commitment": "d" * 64 if paired == "READY" else None,
                    "pairing_epoch": 7 if paired == "READY" else None,
                },
            },
        }

    def assert_safe(self, value: dict[str, object]) -> None:
        self.assertFalse(value["production_ready"])
        self.assertEqual(value["external_readiness"], "NOT_RUN")
        self.assertEqual({item["status"] for item in value["external_gates"]}, {"NOT_RUN"})
        raw = json.dumps(value, sort_keys=True)
        for secret in ("provider-secret", "raw-agent-id", "raw-command"):
            self.assertNotIn(secret, raw)

    def test_contract_has_exact_six_states_and_source_facade(self) -> None:
        self.assertEqual(len(lifecycle.ONBOARDING_STATES), 6)
        self.assertEqual(lifecycle.ONBOARDING_STATES[0], "NOT_INSTALLED")
        self.assertEqual(lifecycle.ONBOARDING_STATES[-1], "RUNNING_DEGRADED_RECOVERY_REQUIRED")
        self.assertIs(onboarding.classify, lifecycle.onboarding_status)
        self.assertIs(onboarding.classify_unlocked, lifecycle.onboarding_status_unlocked)

    def test_not_installed_is_explicit_and_never_claims_external_pass(self) -> None:
        value = lifecycle.onboarding_status(self.config)
        self.assertEqual(value["state"], "NOT_INSTALLED")
        self.assertEqual(value["next_action"], "INSTALL_VERIFIED_BUNDLE")
        self.assert_safe(value)

    def test_stopped_identity_preflight_classifies_ready_and_blocked(self) -> None:
        ready = subprocess.CompletedProcess([], 0, bytes.fromhex("7b22737461747573223a225245414459227d0a"), b"")
        blocked = subprocess.CompletedProcess([], 1, bytes.fromhex("7b22737461747573223a22415554485f5245515549524544227d0a"), b"")
        with mock.patch.object(lifecycle.subprocess, "run", return_value=ready):
            value = lifecycle._classify_onboarding_unlocked(self.config, self.installed, None)
        self.assertEqual(value["state"], "INSTALLED_NEEDS_START")
        self.assert_safe(value)
        with mock.patch.object(lifecycle.subprocess, "run", return_value=blocked):
            value = lifecycle._classify_onboarding_unlocked(self.config, self.installed, None)
        self.assertEqual(value["state"], "INSTALLED_BLOCKED_HOST_IDENTITY")
        self.assertEqual(value["blockers"], ["HOST_IDENTITY_AUTH_REQUIRED"])

    def test_running_states_consume_p8a_commitments(self) -> None:
        with mock.patch.object(lifecycle.processes, "ownership", return_value="owned"):
            unpaired = lifecycle._classify_onboarding_unlocked(self.config, self.installed, self.run_state("UNPAIRED"))
            paired = lifecycle._classify_onboarding_unlocked(self.config, self.installed, self.run_state("READY"))
            foundation = lifecycle._classify_onboarding_unlocked(self.config, self.installed, self.run_state("NOT_RUN"))
            drift = lifecycle._classify_onboarding_unlocked(self.config, self.installed, self.run_state("UNPAIRED", digest="c" * 64))
        self.assertEqual(unpaired["state"], "RUNNING_NEEDS_PAIRING")
        self.assertEqual(paired["state"], "RUNNING_PAIRED")
        self.assertEqual(paired["run_identity"], "b" * 64)
        self.assertEqual(paired["paired_device_commitment"], "d" * 64)
        self.assertEqual(paired["pairing_epoch"], 7)
        self.assertEqual(foundation["blockers"], ["OFFICIAL_AGENT_RUNTIME_REQUIRED"])
        self.assertEqual(drift["blockers"], ["RUNNING_IDENTITY_MISMATCH"])
        self.assert_safe(paired)

    def test_degraded_process_and_embedded_install_result(self) -> None:
        with mock.patch.object(lifecycle.processes, "ownership", return_value="absent"):
            degraded = lifecycle._classify_onboarding_unlocked(self.config, self.installed, self.run_state("UNPAIRED"))
        self.assertEqual(degraded["state"], "RUNNING_DEGRADED_RECOVERY_REQUIRED")
        self.assertEqual(degraded["blockers"], ["RUNNING_PROCESS_SET_DEGRADED"])
        with mock.patch.object(lifecycle, "_host_identity_blocker", return_value="HOST_IDENTITY_AUTH_REQUIRED"):
            wrapped = lifecycle._with_onboarding(self.config, self.installed, None)
        self.assertEqual(wrapped["onboarding"]["state"], "INSTALLED_BLOCKED_HOST_IDENTITY")

    def test_same_digest_with_stale_install_sequence_requires_recovery(self) -> None:
        running = self.run_state("READY")
        running["identity"]["installed"]["install_sequence"] = 3
        running["identity"]["installed"]["install_identity"] = "e" * 64
        with mock.patch.object(lifecycle.processes, "ownership", return_value="owned"):
            value = lifecycle._classify_onboarding_unlocked(
                self.config, self.installed, running
            )
        self.assertEqual(value["state"], "RUNNING_DEGRADED_RECOVERY_REQUIRED")
        self.assertEqual(value["blockers"], ["RUNNING_IDENTITY_MISMATCH"])

    def test_materialize_explicitly_keeps_facade_source_only(self) -> None:
        from tools.nomad_web import materialize

        self.assertEqual(materialize.SOURCE_ONLY_MODULES, {"onboarding.py"})
        repo = Path(__file__).resolve().parents[2]
        contract = json.loads((repo / "tools" / "nomad_web" / "bundle_manifest.json").read_text())["onboarding"]
        self.assertEqual(contract["states"], list(lifecycle.ONBOARDING_STATES))
        self.assertEqual(contract["installed_runtime_module"], "tools/nomad_web/install_lifecycle.py")
        self.assertFalse(contract["production_ready"])
        self.assertEqual(contract["external_readiness"], "NOT_RUN")

    def test_materialized_bundle_classifies_without_repo_checkout(self) -> None:
        from tools.nomad_web.materialize import materialize

        repo = Path(__file__).resolve().parents[2]
        bundle = Path(self.temporary.name) / "bundle"
        materialize(repo, bundle)
        self.assertFalse((bundle / "lib" / "nomad_web" / "onboarding.py").exists())
        code = (
            "import json,runpy,sys;"
            "sys.path.insert(0,sys.argv[1]);"
            "from pathlib import Path;"
            "from types import SimpleNamespace;"
            "from nomad_web.install_lifecycle import onboarding_status;"
            "print(json.dumps(onboarding_status(SimpleNamespace(home=Path(sys.argv[2]))),sort_keys=True))"
        )
        result = subprocess.run(
            [os.sys.executable, "-I", "-B", "-c", code, str(bundle / "lib"), str(Path(self.temporary.name) / "fresh-home")],
            cwd=self.temporary.name,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["state"], "NOT_INSTALLED")
        self.assertFalse(value["production_ready"])


if __name__ == "__main__":
    unittest.main()
