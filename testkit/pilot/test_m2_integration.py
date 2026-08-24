import io
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from testkit.pilot.m2_integration import IntegrationResult, M2IntegrationHarness, production_harness
from testkit.pilot import m2_integration as integration_mod


class FakeLaunch:
    class Process:
        pid = 24680
        alive = True
        def poll(self): return None if self.alive else 0
    def __init__(self, root):
        self.root = Path(root); self.workspace = self.root / "workspace"; self.install = self.root / "install"; self.workspace.mkdir(parents=True); self.install.mkdir()
        self.process = self.Process()
        self.port = 45678; self.cleaned = False
    def cleanup(self):
        self.cleaned = True; self.process.alive = False; shutil.rmtree(self.root)


class M2IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(); self.calls = []
        self.canary = "CREDENTIAL-CANARY-DO-NOT-LOG"
    def tearDown(self): self.dir.cleanup()
    def _launcher(self, **kwargs):
        self.calls.append((tuple(sorted(kwargs)), kwargs.get("provider_credential_env") is not None, kwargs.get("environment") is not None))
        return FakeLaunch(Path(self.dir.name) / f"launch{len(self.calls)}")
    def _harness(self, present=lambda *_: True, launcher=None):
        return M2IntegrationHarness(credential_present=present, launcher=launcher or self._launcher)

    def test_no_credential_blocks_without_resources(self):
        with self._harness(lambda *_: False) as h:
            self.assertEqual(h.run(provider_credential_env="OPENAI_API_KEY").reason, "BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
            self.assertIsNone(h.temp_root)
        self.assertFalse(self.calls)
    def test_nonallowlisted_blocks(self):
        with self._harness(lambda name, *_: name == "OPENAI_API_KEY") as h: self.assertEqual(h.run(provider_credential_env="OTHER_KEY").status, "BLOCKED")
        self.assertFalse(self.calls)
    def test_wp1_frozen_allowlist_is_the_only_production_allowlist(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1] / "stock-opencode" / "real_task_capture.py"
        spec = importlib.util.spec_from_file_location("wp1_test_capture", path); wp1 = importlib.util.module_from_spec(spec); sys.modules[spec.name] = wp1; spec.loader.exec_module(wp1)
        for name in wp1.TEMPORARY_PROVIDER_ENV_NAMES:
            self.assertTrue(wp1.credential_present(name, {name: "temporary"}))
        self.assertFalse(wp1.credential_present("GOOGLE_API_KEY", {"GOOGLE_API_KEY": "temporary"}))
    def test_production_harness_no_credential_preflights_before_launcher(self):
        with production_harness() as h:
            result = h.run(provider_credential_env="OPENAI_API_KEY", environment={})
            self.assertEqual(result.reason, "BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
            self.assertIsNone(h.temp_root)
    def test_dry_run_blocks_without_launcher(self):
        with self._harness() as h: self.assertEqual(h.run(provider_credential_env="OPENAI_API_KEY", dry_run=True).reason, "BLOCKED_DRY_RUN")
        self.assertFalse(self.calls)
    def test_credential_path_calls_launcher_and_is_blocked(self):
        with self._harness() as h:
            result = h.run(provider_credential_env="OPENAI_API_KEY", environment={"OPENAI_API_KEY": self.canary})
            self.assertEqual(result, IntegrationResult("BLOCKED", "BLOCKED_A0_CERTIFICATE_REQUIRED")); self.assertEqual(len(self.calls), 1)
    def test_normal_production_proxy_v2_is_permanently_blocked(self):
        with self._harness() as h:
            h.run(provider_credential_env="OPENAI_API_KEY")
            self.assertEqual(h._proxy.validate("POST", "/api/session/a/prompt", {}, b"{}").reason, "BLOCKED_A0_CERTIFICATE_REQUIRED")
    def test_fd_probe_receives_exact_secret_and_test_label(self):
        with self._harness() as h:
            h.run(provider_credential_env="OPENAI_API_KEY")
            self.assertEqual(h.run_fd_probe(), {"kind": "TEST_PEER_ONLY_FD_DELIVERY", "secret_bytes": 32, "socket_ok": True})
    def test_parent_fds_noninheritable(self):
        with self._harness() as h:
            h.run(provider_credential_env="OPENAI_API_KEY")
            for fd in (h._parent_socket.fileno(), h._child_socket.fileno(), h._secret_read, h._secret_write): self.assertFalse(os.get_inheritable(fd))
    def test_unrelated_child_does_not_inherit_fd(self):
        with self._harness() as h:
            h.run(provider_credential_env="OPENAI_API_KEY"); fd = h._secret_read
            out = subprocess.check_output([sys.executable, "-c", "import os,sys; print(os.path.exists('/dev/fd/'+sys.argv[1]))", str(fd)], close_fds=True)
            self.assertEqual(out.strip(), b"False")
    def test_cleanup_success_and_idempotence(self):
        h = self._harness(); h.run(provider_credential_env="OPENAI_API_KEY"); launch = h._launch; root = h.temp_root
        self.assertEqual(h.cleanup(),IntegrationResult("CLEANED","CLEANED")); self.assertEqual(h.cleanup(),IntegrationResult("CLEANED","CLEANED")); self.assertTrue(launch.cleaned); self.assertIsNotNone(launch.process.poll()); self.assertFalse(launch.root.exists()); self.assertFalse(root.exists())
    def test_cleanup_on_launcher_error(self):
        def broken(**_): raise RuntimeError("boom")
        h = self._harness(launcher=broken); self.assertEqual(h.run(provider_credential_env="OPENAI_API_KEY").reason, "BLOCKED_A2_SETUP_FAILED"); self.assertIsNone(h.temp_root)
    def test_cleanup_on_proxy_error(self):
        def bad_proxy(*_): raise RuntimeError("boom")
        h = M2IntegrationHarness(credential_present=lambda *_: True, launcher=self._launcher, proxy_factory=bad_proxy)
        self.assertEqual(h.run(provider_credential_env="OPENAI_API_KEY").reason, "BLOCKED_A2_SETUP_FAILED"); self.assertTrue(self.calls[0] and h._launch is None)
    def test_probe_timeout_kills_child_and_cleans_every_resource(self):
        class TimedOutProcess:
            returncode = None
            killed = False
            waited = False
            def communicate(self, timeout): raise subprocess.TimeoutExpired("probe", timeout)
            def kill(self): self.killed = True; self.returncode = -9
            def wait(self, timeout): self.waited = True; return self.returncode
            def poll(self): return self.returncode
        process = TimedOutProcess(); h = self._harness(); h.run(provider_credential_env="OPENAI_API_KEY"); launch=h._launch; root=h.temp_root
        retained_reader=os.dup(h._secret_read)
        try:
            with mock.patch.object(integration_mod.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(RuntimeError, "probe"): h.run_fd_probe()
        finally: os.close(retained_reader)
        self.assertTrue(process.killed and process.waited); self.assertTrue(launch.cleaned); self.assertIsNone(h.temp_root); self.assertFalse(root.exists())
    def test_harness_is_single_use_and_does_not_overwrite_resources(self):
        h=self._harness(); first=h.run(provider_credential_env="OPENAI_API_KEY"); launch=h._launch
        second=h.run(provider_credential_env="OPENAI_API_KEY")
        self.assertEqual(first.reason,"BLOCKED_A0_CERTIFICATE_REQUIRED"); self.assertEqual(second.reason,"BLOCKED_A2_HARNESS_ALREADY_USED"); self.assertIs(h._launch,launch); self.assertEqual(len(self.calls),1); h.cleanup()
    def test_cleanup_incomplete_is_content_free_and_not_hidden(self):
        h=self._harness();h.run(provider_credential_env="OPENAI_API_KEY");launch=h._launch
        launch.cleanup=lambda: None
        result=h.cleanup()
        self.assertEqual(result,IntegrationResult("BLOCKED","BLOCKED_A2_CLEANUP_INCOMPLETE"));self.assertIs(h._launch,launch);self.assertTrue(launch.root.exists())
        launch.process.alive=False;shutil.rmtree(launch.root);h._launch=None;h._launch_binding=None
    def test_credential_canary_absent_from_outputs_and_errors(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), self._harness() as h:
            result = h.run(provider_credential_env="OPENAI_API_KEY", environment={"OPENAI_API_KEY": self.canary})
            self.assertNotIn(self.canary, repr(h)); self.assertNotIn(self.canary, repr(result))
            self.assertNotIn(self.canary, repr(self.calls))
        self.assertNotIn(self.canary, out.getvalue() + err.getvalue())

if __name__ == "__main__": unittest.main()
