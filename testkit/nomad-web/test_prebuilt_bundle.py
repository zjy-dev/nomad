from __future__ import annotations

import json
import hashlib
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from tools.nomad_web import launcher


def port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class BundleClosureContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[2]

    def test_source_gateway_closure_is_explicit_and_complete(self) -> None:
        from tools.nomad_web.bundle import GATEWAY_MODULES, gateway_module_closure

        source = self.repo / "mobile-reference" / "pilot-gateway"
        self.assertEqual(
            {f"gateway/{name}" for name in gateway_module_closure(source)},
            set(GATEWAY_MODULES),
        )
        self.assertIn("gateway/pairing-session.mjs", GATEWAY_MODULES)

    def test_gateway_closure_rejects_missing_external_and_dynamic_dependencies(self) -> None:
        from tools.nomad_web.bundle import gateway_module_closure

        cases = (
            ("import './missing.mjs';\n", "GATEWAY_MODULE_MISSING"),
            ("import external from 'external-package';\n", "GATEWAY_EXTERNAL_DEPENDENCY"),
            ("import {} from /*gap*/ 'external-package';\n", "GATEWAY_EXTERNAL_DEPENDENCY"),
            ("const x=1; import 'external-package';\n", "GATEWAY_EXTERNAL_DEPENDENCY"),
            ("// comment\rimport 'external-package';\n", "GATEWAY_EXTERNAL_DEPENDENCY"),
            ("export /* gap */ { value } from\n'external-package';\n", "GATEWAY_EXTERNAL_DEPENDENCY"),
            ("import/*gap*/('external-package');\n", "GATEWAY_DYNAMIC_IMPORT_FORBIDDEN"),
            ("await import('./child.mjs');\n", "GATEWAY_DYNAMIC_IMPORT_FORBIDDEN"),
            ("await import(process.env.MODULE);\n", "GATEWAY_DYNAMIC_IMPORT_FORBIDDEN"),
            ("import '../outside.mjs';\n", "INVALID_GATEWAY_MODULE_PATH"),
        )
        for source, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                gateway = Path(temporary)
                (gateway / "server.mjs").write_text(source)
                os.chmod(gateway / "server.mjs", 0o644)
                with self.assertRaisesRegex(RuntimeError, error):
                    gateway_module_closure(gateway)

    def test_gateway_closure_skips_comments_strings_and_template_text(self) -> None:
        from tools.nomad_web.bundle import gateway_module_closure

        with tempfile.TemporaryDirectory() as temporary:
            gateway = Path(temporary)
            (gateway / "server.mjs").write_text(
                "// import 'comment-package';\n"
                "/* export { value } from 'block-comment-package'; */\n"
                "const quoted = \"import('string-package')\";\n"
                "const single = 'export * from \"single-package\"';\n"
                "const template = `import('template-package') ${\"export * from 'expression-string'\"}`;\n"
                "const regex = /import('regex-package')/;\n"
                "import /* before */ {\n child\n} from /* after */ './child.mjs';\n"
                "export /* gap */ { child } from\n './child.mjs';\n"
            )
            (gateway / "child.mjs").write_text("export const child = true;\n")
            for path in gateway.iterdir():
                os.chmod(path, 0o644)
            self.assertEqual(gateway_module_closure(gateway), {"server.mjs", "child.mjs"})

    def test_declarative_manifest_tracks_ingress_and_gateway_closure(self) -> None:
        from tools.nomad_web.bundle import GATEWAY_MODULES

        value = json.loads((self.repo / "tools" / "nomad_web" / "bundle_manifest.json").read_text())
        self.assertEqual(value["schema"], "nomad.web-companion.bundle.v2")
        self.assertEqual(value["ingress_target"], "relay/cmd/nomad-ingress")
        self.assertEqual(
            set(value["gateway_runtime_modules"]),
            {f"mobile-reference/pilot-gateway/{name.removeprefix('gateway/')}" for name in GATEWAY_MODULES},
        )


class PrebuiltBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.temp = tempfile.TemporaryDirectory(prefix="nomad-prebuilt-")
        cls.bundle = Path(cls.temp.name) / "bundle"
        result = subprocess.run(
            [os.sys.executable, "-m", "tools.nomad_web", "--json", "materialize", "--output", str(cls.bundle)],
            cwd=cls.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=240,
        )
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.case = tempfile.TemporaryDirectory(prefix="nomad-prebuilt-run-")
        self.home = Path(self.case.name) / "web-companion"
        shim = Path(self.case.name) / "path"
        shim.mkdir()
        for name, source in (("python3", os.sys.executable), ("node", shutil.which("node"))):
            self.assertIsNotNone(source)
            (shim / name).symlink_to(Path(source).resolve())
        self.env = {
            "PATH": f"{shim}:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "NOMAD_WEB_HOME": str(self.home), "NOMAD_WEB_BUNDLE": str(self.bundle),
            "NOMAD_WEB_RELAY_PORT": str(port()), "NOMAD_WEB_GATEWAY_PORT": str(port()),
            "NOMAD_WEB_AGENT_PORT": str(port()),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        self.call("stop", check=False)
        self.case.cleanup()

    def call(self, command: str, check: bool = True) -> tuple[int, dict]:
        result = subprocess.run(
            [str(self.bundle / "bin" / "nomad-web"), "--json", command],
            cwd=self.case.name, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.splitlines()
        return result.returncode, json.loads(lines[-1]) if lines else {}

    def call_agent_start(self, workspace: Path, secret: str) -> tuple[int, dict]:
        result = subprocess.run(
            [
                str(self.bundle / "bin" / "nomad-web"),
                "--json",
                "start",
                "--provider",
                "OPENAI_API_KEY",
                "--credential-stdin",
                "--workspace",
                str(workspace),
            ],
            cwd=self.case.name,
            env=self.env,
            input=secret,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90,
        )
        lines = result.stdout.splitlines()
        return result.returncode, json.loads(lines[-1]) if lines else {}

    def test_prebuilt_runtime_needs_no_build_toolchain(self) -> None:
        code, doctor = self.call("doctor", check=False)
        self.assertEqual(code, 2)
        self.assertEqual(doctor["runtime_mode"], "prebuilt-bundle")
        self.assertEqual(set(doctor["tools"]), {"python3", "node"})
        _, started = self.call("start")
        self.assertEqual(started["state"], "RUNNING")
        try:
            urllib.request.urlopen(started["web_url"] + "api/alpha/session", timeout=5)
            self.fail("no Agent should produce unavailable")
        except urllib.error.HTTPError as error:
            with error:
                self.assertEqual(error.code, 503)
        self.call("stop")
        self.call("uninstall")

    def test_v2_manifest_has_ingress_and_exact_gateway_module_closure(self) -> None:
        from tools.nomad_web.bundle import (
            GATEWAY_MODULES, REQUIRED, REQUIRED_PACKAGE,
            REQUIRED_RUNNER_CLOSURE, SCHEMA, verify_bundle,
        )

        manifest = verify_bundle(self.bundle)
        entries = {entry["path"]: entry for entry in manifest["files"]}
        self.assertEqual(manifest["schema"], SCHEMA)
        self.assertEqual(entries["bin/nomad-ingress"]["mode"], "0755")
        self.assertGreater(entries["bin/nomad-ingress"]["size_bytes"], 0)
        self.assertEqual(
            {name for name in entries if name.startswith("gateway/") and name.endswith(".mjs")},
            set(GATEWAY_MODULES),
        )
        self.assertEqual(entries["gateway/pairing-session.mjs"]["mode"], "0644")
        self.assertEqual(REQUIRED["bin/nomad-ingress"], 0o755)
        self.assertTrue(REQUIRED_PACKAGE.issubset(entries))
        self.assertTrue(REQUIRED_RUNNER_CLOSURE.issubset(entries))
        self.assertTrue(
            all(entries[name]["mode"] == "0644" for name in REQUIRED_RUNNER_CLOSURE)
        )
        self.assertFalse(any("node_modules" in path.parts for path in self.bundle.rglob("*")))
        loaded = subprocess.run(
            [shutil.which("node"), "--input-type=module", "--eval",
             f"await import({json.dumps((self.bundle / 'gateway' / 'server.mjs').as_uri())})"],
            cwd=self.case.name, env={"PATH": self.env["PATH"], "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        self.assertEqual(loaded.returncode, 0, loaded.stdout + loaded.stderr)

    def test_tampered_and_extra_files_are_rejected(self) -> None:
        from tools.nomad_web.bundle import verify_bundle
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            (clone / "web" / "index.html").write_text("tampered")
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            (clone / "bin" / "nomad-ingress").write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "BUNDLE_FILE_MISMATCH"):
                verify_bundle(clone)
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            os.chmod(clone / "bin" / "nomad-ingress", 0o644)
            with self.assertRaisesRegex(RuntimeError, "UNSAFE_BUNDLE_FILE"):
                verify_bundle(clone)
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            (clone / "empty-dir").mkdir()
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            (clone / "directory-link").symlink_to(clone / "web", target_is_directory=True)
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            manifest = clone / "manifest.json"
            value = json.loads(manifest.read_text())
            manifest.write_text(json.dumps(value, indent=2) + "\n")
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)

    def test_wrapper_isolates_pythonpath_and_materialize_is_exclusive(self) -> None:
        from tools.nomad_web.bundle import verify_bundle
        wrapper = (self.bundle / "bin" / "nomad-web").read_text()
        self.assertIn("unset PYTHONPATH PYTHONHOME", wrapper)
        self.assertIn("python3 -I -B -c", wrapper)
        result = subprocess.run(
            [os.sys.executable, "-m", "tools.nomad_web", "--json", "materialize", "--output", str(self.bundle)],
            cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["error"], "BUNDLE_OUTPUT_EXISTS")
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            (clone / "extra").write_text("x")
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)

    def test_wrapper_rejects_cwd_and_pythonhome_injection(self) -> None:
        hostile = Path(self.case.name) / "hostile"
        package = hostile / "nomad_web"
        package.mkdir(parents=True)
        (package / "__main__.py").write_text("raise SystemExit(77)\n")
        env = dict(self.env, PYTHONPATH=str(hostile), PYTHONHOME=str(hostile / "missing"))
        result = subprocess.run(
            [str(self.bundle / "bin" / "nomad-web"), "--json", "doctor"],
            cwd=hostile, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["runtime_mode"], "prebuilt-bundle")
        self.assertFalse(any(path.name == "__pycache__" for path in self.bundle.rglob("__pycache__")))

    def test_root_mode_and_extra_runtime_module_are_rejected(self) -> None:
        from tools.nomad_web.bundle import verify_bundle
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            os.chmod(clone, 0o777)
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            (clone / "lib" / "nomad_web" / "unexpected.py").write_text("x=1\n")
            with self.assertRaises(RuntimeError):
                verify_bundle(clone)

    def test_v1_manifest_remains_compatible_with_its_exact_legacy_allowlist(self) -> None:
        from tools.nomad_web.bundle import (
            GATEWAY_MODULES_V1, SCHEMA_V1, gateway_module_closure, verify_bundle,
        )

        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / "bundle"
            shutil.copytree(self.bundle, clone)
            self.assertIn("pairing-session.mjs", gateway_module_closure(clone / "gateway"))
            for name in ("bin/nomad-ingress", "gateway/pairing-session.mjs"):
                (clone / name).unlink()
            server_path = clone / "gateway" / "server.mjs"
            legacy_modules = {Path(name).name for name in GATEWAY_MODULES_V1}
            server_path.write_text(
                "".join(
                    f"import './{name}';\n"
                    for name in sorted(legacy_modules - {"server.mjs"})
                ) + "export {};\n"
            )
            self.assertEqual(gateway_module_closure(clone / "gateway"), legacy_modules)
            manifest_path = clone / "manifest.json"
            value = json.loads(manifest_path.read_text())
            value["schema"] = SCHEMA_V1
            value["files"] = [
                entry for entry in value["files"]
                if entry["path"] not in {"bin/nomad-ingress", "gateway/pairing-session.mjs"}
            ]
            server_entry = next(entry for entry in value["files"] if entry["path"] == "gateway/server.mjs")
            server_raw = server_path.read_bytes()
            server_entry["size_bytes"] = len(server_raw)
            server_entry["raw_sha256"] = hashlib.sha256(server_raw).hexdigest()
            core = {key: item for key, item in value.items() if key != "bundle_digest"}
            value["bundle_digest"] = hashlib.sha256(
                json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest()
            manifest_path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            self.assertEqual(verify_bundle(clone)["schema"], SCHEMA_V1)

            (clone / "gateway" / "pairing-session.mjs").write_text("export {};\n")
            with self.assertRaisesRegex(RuntimeError, "BUNDLE_FILE_SET_MISMATCH"):
                verify_bundle(clone)

    def test_verified_official_agent_starts_from_bundle_with_fd_only_secret(self) -> None:
        from tools.nomad_web.agent_runtime import start_agent, stop_agent

        workspace = Path(self.case.name) / "workspace"
        runtime = Path(self.case.name) / "agent-runtime"
        workspace.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe()
        canary = b"nomad-provider-canary-never-persist"
        os.write(write_fd, canary)
        os.close(write_fd)
        record = start_agent(
            self.bundle, workspace, runtime, port(), "OPENAI_API_KEY", read_fd
        )
        try:
            self.assertEqual(record["package"], "opencode-ai")
            self.assertEqual(record["version"], "1.18.16")
            self.assertEqual(
                record["classification"],
                "verified-bundle-runtime-not-provider-evidence",
            )
            self.assertNotIn(canary.decode(), json.dumps(record, sort_keys=True))
            command = subprocess.run(
                ["/bin/ps", "-p", str(record["pid"]), "-o", "command="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout
            self.assertNotIn(canary, command)
            with self.assertRaises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(record["origin"] + "/global/health", timeout=5)
            with denied.exception:
                self.assertEqual(denied.exception.code, 401)
            persisted = b"".join(
                path.read_bytes()
                for path in runtime.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
            self.assertNotIn(canary, persisted)
        finally:
            stop_agent(record)

    def test_cli_starts_owned_official_agent_with_connected_local_web(self) -> None:
        workspace = Path(self.case.name) / "cli-workspace"
        workspace.mkdir(mode=0o700)
        canary = "nomad-cli-provider-canary"
        relay_guard = socket.socket(); relay_guard.bind(("127.0.0.1", int(self.env["NOMAD_WEB_RELAY_PORT"])))
        try: code, started = self.call_agent_start(workspace, canary)
        finally: relay_guard.close()
        self.assertEqual(code, 0, started)
        self.assertEqual(started["mode"], "official-agent-local")
        self.assertTrue(started["real_agent_enabled"])
        self.assertEqual(started["agent_version"], "1.18.16")
        self.assertEqual(
            [item["name"] for item in started["processes"]],
            ["opencode", "product-host", "gateway"],
        )
        self.assertFalse((self.home / "run" / "relay.sqlite3").exists())
        self.assertTrue((self.home / "run" / f"gateway-{started['run_id']}.sqlite3").is_file())
        command_name = hashlib.sha256(f"journal:{started['run_id']}".encode()).hexdigest()[:24]
        command_db = self.home / "run" / f"command-{command_name}.sqlite3"
        registry_path = self.home / launcher.DEVICE_REGISTRY_DIRNAME / launcher.DEVICE_REGISTRY_BASENAME
        self.assertEqual(registry_path.parent.stat().st_mode & 0o777, 0o700)
        self.assertTrue(command_db.is_file())
        self.assertEqual(command_db.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            started["blocked_on"],
            ["PRODUCTION_DEVICE_IDENTITY"],
        )
        surface = (self.home / "run" / "status.json").read_bytes()
        surface += b"".join(path.read_bytes() for path in (self.home / "logs").glob("*.log"))
        for item in started["processes"]:
            surface += subprocess.run(
                ["/bin/ps", "-p", str(item["pid"]), "-o", "command="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            ).stdout
        self.assertNotIn(canary.encode(), surface)
        self.assertNotIn(b"ses_", surface)
        self.assertRegex(started["session_alias"], r"^sess-[0-9a-f]{32}$")
        _, status = self.call("status")
        self.assertEqual(status["state"], "RUNNING")
        self.assertTrue(all(item["alive"] for item in status["processes"]))
        self.call("stop")
        self.assertTrue(registry_path.parent.is_dir())
        self.assertTrue(registry_path.exists())
        self.assertFalse((self.home / "run" / f"gateway-{started['run_id']}.sqlite3").exists())
        self.assertFalse(command_db.exists())
        code, restarted = self.call_agent_start(workspace, "second-start-canary")
        self.assertEqual(code, 0, restarted); self.assertNotEqual(restarted["run_id"], started["run_id"])
        self.assertEqual(registry_path, self.home / launcher.DEVICE_REGISTRY_DIRNAME / launcher.DEVICE_REGISTRY_BASENAME)
        self.call("stop")

    def test_launcher_source_contains_fd11_only_gateway_command_key_contract(self) -> None:
        launcher_source = (self.repo / "tools" / "nomad_web" / "launcher.py").read_text()
        self.assertIn('"command_transport_key":command_transport_key', launcher_source)
        self.assertIn('"command_authority_key":command_authority_key', launcher_source)
        self.assertIn('"command_journal_path":str(command_journal_path)', launcher_source)
        self.assertIn('gateway_args.extend(["--command-key-fd", "11"])', launcher_source)
        self.assertNotIn("--command-transport-key", launcher_source)
        self.assertNotIn("--command-authority-key", launcher_source)

    def test_product_host_death_is_degraded_then_owned_crash_recovery_starts_fresh_run(self) -> None:
        workspace = Path(self.case.name) / "degraded-workspace"
        workspace.mkdir(mode=0o700)
        code, started = self.call_agent_start(workspace, "degraded-provider-canary")
        self.assertEqual(code, 0, started)
        host = next(item for item in started["processes"] if item["name"] == "product-host")
        os.killpg(host["process_group"], 9)
        _, status = self.call("status")
        self.assertEqual(status["state"], "DEGRADED")
        first_alias = started["run_id"]
        code, recovered = self.call_agent_start(workspace, "second-canary")
        self.assertEqual(code, 0, recovered)
        self.assertEqual([item["name"] for item in recovered["processes"]], ["opencode", "product-host", "gateway"])
        self.assertNotEqual(recovered["run_id"], first_alias)
        self.assertTrue((self.home / "run" / f"gateway-{recovered['run_id']}.sqlite3").is_file())
        self.assertFalse((self.home / "run" / f"gateway-{first_alias}.sqlite3").exists())
        self.call("stop")

    def test_missing_or_ambiguous_provider_input_is_zero_spawn(self) -> None:
        from tools.nomad_web.agent_runtime import start_agent

        workspace = Path(self.case.name) / "workspace-zero"
        runtime = Path(self.case.name) / "agent-runtime-zero"
        workspace.mkdir(mode=0o700)
        before = {item.name for item in Path("/proc").iterdir()} if Path("/proc").is_dir() else None
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with mock.patch("tools.nomad_web.agent_runtime.os.posix_spawn") as spawn:
            with self.assertRaisesRegex(RuntimeError, "INVALID_PROVIDER_CREDENTIAL"):
                start_agent(self.bundle, workspace, runtime, port(), "OPENAI_API_KEY", read_fd)
            spawn.assert_not_called()
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"x")
        os.close(write_fd)
        with mock.patch("tools.nomad_web.agent_runtime.os.posix_spawn") as spawn:
            with self.assertRaisesRegex(RuntimeError, "EXACTLY_ONE_PROVIDER_CREDENTIAL_REQUIRED"):
                start_agent(self.bundle, workspace, runtime, port(), "UNSAFE_KEY", read_fd)
            spawn.assert_not_called()
        after = {item.name for item in Path("/proc").iterdir()} if Path("/proc").is_dir() else None
        if before is not None:
            self.assertEqual(before, after)

    def test_agent_identity_failure_kills_and_reaps_child(self) -> None:
        from tools.nomad_web import processes
        from tools.nomad_web.agent_runtime import start_agent

        workspace = Path(self.case.name) / "identity-workspace"
        runtime = Path(self.case.name) / "identity-runtime"
        workspace.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"identity-canary")
        os.close(write_fd)
        original = processes.process_identity
        calls = 0
        observed_pid: int | None = None

        def fail_after_health(pid: int) -> str:
            nonlocal calls, observed_pid
            calls += 1
            observed_pid = pid
            if calls == 1:
                raise RuntimeError("identity failed")
            return original(pid)

        with mock.patch("tools.nomad_web.agent_runtime.processes.process_identity", side_effect=fail_after_health):
            with self.assertRaisesRegex(RuntimeError, "identity failed"):
                start_agent(
                    self.bundle, workspace=workspace,
                    runtime_root=runtime, port=port(), provider_name="OPENAI_API_KEY",
                    credential_fd=read_fd,
                )
        self.assertIsNotNone(observed_pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(observed_pid), 0)

    def test_agent_workspace_symlink_is_rejected_before_spawn(self) -> None:
        from tools.nomad_web.agent_runtime import start_agent

        real_workspace = Path(self.case.name) / "real-workspace"
        real_workspace.mkdir(mode=0o700)
        workspace = Path(self.case.name) / "workspace-link"
        workspace.symlink_to(real_workspace, target_is_directory=True)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"canary")
        os.close(write_fd)
        with self.assertRaisesRegex(RuntimeError, "UNSAFE_AGENT_DIRECTORY"):
            start_agent(
                self.bundle,
                workspace,
                Path(self.case.name) / "agent-runtime-link-case",
                port(),
                "OPENAI_API_KEY",
                read_fd,
            )
        with self.assertRaises(OSError):
            os.fstat(read_fd)

    def test_valid_fd_is_closed_when_log_preparation_fails_without_spawn(self) -> None:
        from tools.nomad_web.agent_runtime import start_agent

        workspace = Path(self.case.name) / "log-failure-workspace"
        runtime = Path(self.case.name) / "log-failure-runtime"
        workspace.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"canary")
        os.close(write_fd)
        original_open = os.open

        def fail_log_only(path, *args, **kwargs):
            flags = int(args[0]) if args else int(kwargs.get("flags", 0))
            if Path(path).name == "agent.log" and flags & os.O_CREAT:
                raise OSError("blocked")
            return original_open(path, *args, **kwargs)

        with mock.patch("tools.nomad_web.agent_runtime.os.open", side_effect=fail_log_only):
            with mock.patch("tools.nomad_web.agent_runtime.os.posix_spawn") as spawn:
                with self.assertRaises(OSError):
                    start_agent(
                        self.bundle, workspace, runtime, port(), "OPENAI_API_KEY", read_fd
                    )
                spawn.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(read_fd)

    def test_partial_launcher_agent_input_closes_supplied_fd(self) -> None:
        from tools.nomad_web.config import Config
        from tools.nomad_web.launcher import start_foundation

        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"canary")
        os.close(write_fd)
        with mock.patch.dict(os.environ, self.env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "AGENT_START_INPUTS_INCOMPLETE"):
                start_foundation(Config.load(self.repo), credential_fd=read_fd)
        with self.assertRaises(OSError):
            os.fstat(read_fd)

    def test_repeated_official_start_closes_unused_supplied_fd(self) -> None:
        from tools.nomad_web.config import Config
        from tools.nomad_web.launcher import start_foundation

        workspace = Path(self.case.name) / "repeat-workspace"
        workspace.mkdir(mode=0o700)
        code, started = self.call_agent_start(workspace, "first-canary")
        self.assertEqual(code, 0, started)
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"unused-second-canary")
        os.close(write_fd)
        with mock.patch.dict(os.environ, self.env, clear=True):
            repeated = start_foundation(
                Config.load(self.repo),
                provider_name="OPENAI_API_KEY",
                credential_fd=read_fd,
                workspace=workspace,
            )
        self.assertEqual(repeated["run_id"], started["run_id"])
        with self.assertRaises(OSError):
            os.fstat(read_fd)


if __name__ == "__main__":
    unittest.main()
