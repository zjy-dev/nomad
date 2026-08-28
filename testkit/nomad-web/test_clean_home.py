from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock
from pathlib import Path

from tools.nomad_web import launcher


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class NomadWebCleanHomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[2]
        self.temp = tempfile.TemporaryDirectory(prefix="nomad-web-clean-")
        self.home = Path(self.temp.name) / "web-companion"
        ports: set[int] = set()
        while len(ports) < 3:
            ports.add(free_port())
        self.relay_port, self.gateway_port, self.agent_port = ports
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NOMAD_WEB_HOME": str(self.home),
            "NOMAD_WEB_RELAY_PORT": str(self.relay_port),
            "NOMAD_WEB_GATEWAY_PORT": str(self.gateway_port),
            "NOMAD_WEB_AGENT_PORT": str(self.agent_port),
            "NOMAD_WEB_ALLOW_SOURCE_BUILD": "1",
        }
        self.owned_processes: list[dict] = []

    def tearDown(self) -> None:
        try:
            path = self.home / "run" / "status.json"
            if path.is_file():
                value = json.loads(path.read_text())
                self.owned_processes.extend(value.get("processes", []))
        except Exception:
            pass
        self.run_cli("stop", check=False)
        from tools.nomad_web import processes
        for item in reversed(self.owned_processes):
            if processes.ownership(item) == "owned":
                processes.stop(item)
        self.temp.cleanup()

    def run_cli(self, command: str, check: bool = True) -> tuple[int, dict]:
        result = subprocess.run(
            [sys.executable, "-m", "tools.nomad_web", "--json", command],
            cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")
        lines = [line for line in result.stdout.splitlines() if line]
        return result.returncode, json.loads(lines[-1]) if lines else {}

    def test_clean_home_lifecycle_is_readonly_and_secret_free(self) -> None:
        _, doctor = self.run_cli("doctor")
        self.assertTrue(doctor["foundation_ready"])
        self.assertFalse(doctor["production_ready"])
        _, started = self.run_cli("start")
        self.owned_processes.extend(started["processes"])
        self.assertEqual(started["state"], "RUNNING")
        self.assertFalse(started["real_agent_enabled"])
        self.assertEqual(started["blocked_on"], ["B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY"])
        _, status = self.run_cli("status")
        self.assertEqual(status["state"], "RUNNING")
        self.assertTrue(all(item["alive"] for item in status["processes"]))
        self.assertTrue(Path(status["logs_dir"]).is_dir())
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{self.gateway_port}/api/alpha/session", timeout=5)
            self.fail("foundation without Agent should not have a session")
        except urllib.error.HTTPError as error:
            with error:
                self.assertEqual(error.code, 503)
                body = json.load(error)
                self.assertEqual(body["status"], "unavailable")
        state_bytes = (self.home / "run" / "status.json").read_bytes()
        logs = b"".join(path.read_bytes() for path in (self.home / "logs").glob("*.log"))
        self.assertNotIn(b"NOMAD_ALPHA_RELAY_TOKEN", state_bytes + logs)
        for provider in (b"OPENAI_API_KEY", b"ANTHROPIC_API_KEY"):
            self.assertNotIn(provider, state_bytes + logs)
        _, stopped = self.run_cli("stop")
        self.assertEqual(stopped["state"], "STOPPED")
        _, stopped_again = self.run_cli("stop")
        self.assertEqual(stopped_again["state"], "STOPPED")
        _, removed = self.run_cli("uninstall")
        self.assertEqual(removed["state"], "UNINSTALLED")
        self.assertFalse(self.home.exists())

    def test_uninstall_refuses_unowned_custom_home(self) -> None:
        self.home.mkdir(parents=True)
        sentinel = self.home / "keep.txt"
        sentinel.write_text("user data", encoding="utf-8")
        code, result = self.run_cli("uninstall", check=False)
        self.assertEqual(code, 1)
        self.assertIn(result["error"], {"UNOWNED_NOMAD_WEB_HOME", "UNSAFE_NOMAD_WEB_HOME"})
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "user data")

    def test_uninstall_fail_closed_preserves_untrusted_registry_sidecar(self) -> None:
        from tools.nomad_web.config import Config
        from tools.nomad_web.state import initialize_home

        with mock.patch.dict(os.environ, self.env, clear=True):
            config = Config.load(self.repo)
            initialize_home(config)
            for path in (self.home / "bin", self.home / "run", self.home / "logs"):
                path.mkdir(parents=True, exist_ok=True)
            registry_path = launcher._prepare_device_registry_path(self.home)
            registry_path.write_text("registry")
            os.chmod(registry_path, 0o600)
            wal = Path(str(registry_path) + "-wal")
            wal.write_text("unsafe")
            os.chmod(wal, 0o644)
        code, payload = self.run_cli("uninstall", check=False)
        self.assertEqual(code, 1)
        self.assertEqual(payload["error"], "UNSAFE_DEVICE_REGISTRY")
        self.assertTrue(registry_path.exists())
        self.assertTrue(wal.exists())

    def test_known_canary_token_never_enters_state_logs_or_argv(self) -> None:
        canary = "nomad-secret-canary-never-persist"
        from tools.nomad_web.config import Config
        from tools.nomad_web.launcher import start_foundation, stop_foundation
        with mock.patch.dict(os.environ, self.env, clear=True):
            config = Config.load(self.repo)
            with mock.patch("tools.nomad_web.launcher.secrets.token_urlsafe", return_value=canary):
                started = start_foundation(config)
            self.owned_processes.extend(started["processes"])
            try:
                surface = (self.home / "run" / "status.json").read_bytes()
                surface += b"".join(path.read_bytes() for path in (self.home / "logs").glob("*.log"))
                for item in started["processes"]:
                    command = subprocess.run(
                        ["/bin/ps", "-p", str(item["pid"]), "-o", "command="],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
                    ).stdout
                    surface += command
                self.assertNotIn(canary.encode(), surface)
            finally:
                stop_foundation(config)

    def test_home_symlink_and_runtime_directory_symlink_are_rejected(self) -> None:
        target = Path(self.temp.name) / "target"
        target.mkdir()
        link = Path(self.temp.name) / "home-link"
        link.symlink_to(target, target_is_directory=True)
        symlink_env = dict(self.env, NOMAD_WEB_HOME=str(link))
        result = subprocess.run(
            [sys.executable, "-m", "tools.nomad_web", "--json", "start"],
            cwd=self.repo, env=symlink_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        self.assertTrue(target.is_dir())
        self.home.mkdir(parents=True)
        from tools.nomad_web.config import Config
        from tools.nomad_web.state import initialize_home
        with mock.patch.dict(os.environ, self.env, clear=True):
            config = Config.load(self.repo)
            initialize_home(config)
            external = Path(self.temp.name) / "external"
            external.mkdir()
            (self.home / "logs").symlink_to(external, target_is_directory=True)
            code, payload = self.run_cli("start", check=False)
            self.assertEqual(code, 1)
            self.assertEqual(payload["error"], "UNSAFE_LAUNCHER_DIRECTORY")

    def test_parent_symlink_is_rejected_before_creation(self) -> None:
        target = Path(self.temp.name) / "parent-target"
        target.mkdir()
        link = Path(self.temp.name) / "parent-link"
        link.symlink_to(target, target_is_directory=True)
        candidate = link / "web-companion"
        env = dict(self.env, NOMAD_WEB_HOME=str(candidate))
        result = subprocess.run(
            [sys.executable, "-m", "tools.nomad_web", "--json", "start"],
            cwd=self.repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse((target / "web-companion").exists())

    def test_concurrent_start_converges_on_one_owned_pair(self) -> None:
        barrier = threading.Barrier(3)
        results: list[tuple[int, dict]] = []
        def worker() -> None:
            barrier.wait()
            results.append(self.run_cli("start", check=False))
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=240)
        self.assertEqual([code for code, _ in results], [0, 0])
        _, status = self.run_cli("status")
        state_value = json.loads((self.home / "run" / "status.json").read_text())
        self.owned_processes.extend(state_value["processes"])
        self.assertEqual(status["state"], "RUNNING")
        self.assertEqual([item["name"] for item in status["processes"]], ["relay", "gateway"])

    def test_identity_mismatch_refuses_stop_and_preserves_state(self) -> None:
        self.run_cli("start")
        path = self.home / "run" / "status.json"
        value = json.loads(path.read_text())
        self.owned_processes.extend(value["processes"])
        value["processes"][0]["identity"] = "0" * 64
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(path, 0o600)
        code, payload = self.run_cli("stop", check=False)
        self.assertEqual(code, 1)
        self.assertEqual(payload["error"], "PROCESS_IDENTITY_MISMATCH")
        self.assertTrue(path.exists())
        # Restore the original state so tearDown can safely stop only owned children.
        value["processes"][0]["identity"] = subprocess.run(
            ["/bin/ps", "-p", str(value["processes"][0]["pid"]), "-o", "lstart=", "-o", "command="],
            stdout=subprocess.PIPE, check=True,
        ).stdout.hex()  # replaced below with the exact SHA-256
        import hashlib
        value["processes"][0]["identity"] = hashlib.sha256(bytes.fromhex(value["processes"][0]["identity"])).hexdigest()
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(path, 0o600)


if __name__ == "__main__":
    unittest.main()
