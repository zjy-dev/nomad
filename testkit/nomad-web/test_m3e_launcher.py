from __future__ import annotations

import json
import io
import os
import socket
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import cli, install_lifecycle, launcher, processes, state
from tools.nomad_web.config import Config


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def ports(count: int) -> list[int]:
    result: set[int] = set()
    while len(result) < count:
        result.add(free_port())
    return list(result)


def materialized_bundle(root: Path) -> Path:
    from tools.nomad_web.bundle import verify_bundle
    from tools.nomad_web.materialize import materialize

    bundle = root / "bundle"
    materialize(Path(__file__).resolve().parents[2], bundle)
    verify_bundle(bundle)
    return bundle


class M3ELauncherTests(unittest.TestCase):
    def config(self, root: Path, bundle: Path) -> SimpleNamespace:
        values = ports(8)
        return SimpleNamespace(
            repo_root=root, home=root / "home", bundle_root=bundle,
            relay_port=values[0], gateway_port=values[1], agent_port=values[2],
            join_gateway_port=values[3], relay_host_v2_port=values[4],
            relay_device_v2_port=values[5], relay_admin_port=values[6],
            relay_device_v1_port=values[7],
        )

    def private_fd(self, root: Path, name: str, raw: bytes) -> int:
        path = root / name
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)

    def credential_fd(self, raw: bytes = b"provider-canary") -> int:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, raw)
        os.close(write_fd)
        return read_fd

    def test_start_fails_closed_on_explicit_current_conflict_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            config = self.config(root, bundle)
            with (
                mock.patch.object(
                    launcher, "select_bundle_for_start",
                    side_effect=RuntimeError("EXPLICIT_BUNDLE_CURRENT_CONFLICT"),
                ) as select,
                mock.patch.object(launcher, "_port_free", return_value=True),
                mock.patch.object(processes, "spawn") as spawn,
            ):
                with self.assertRaisesRegex(RuntimeError, "EXPLICIT_BUNDLE_CURRENT_CONFLICT"):
                    launcher.start_foundation(config)
            select.assert_called_once_with(config, bundle)
            spawn.assert_not_called()

    def test_materialized_bundle_exposes_launcher_ingress_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = materialized_bundle(Path(temporary))
            ingress = bundle / "bin" / "nomad-ingress"
            info = ingress.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertFalse(stat.S_ISLNK(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o755)
            self.assertNotEqual(info.st_size, 0)
            launcher_source = Path(launcher.__file__).read_text(encoding="utf-8")
            self.assertIn('bundle / "bin" / "nomad-ingress"', launcher_source)
            self.assertNotIn('bundle / "bin" / "nomad-https-ingress"', launcher_source)

    def test_precreated_relay_v1_database_stays_0600_after_real_relay_init(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); run_dir = root / "run"; run_dir.mkdir(mode=0o700)
            relay_binary = root / "nomad-relay"
            subprocess.run(
                ["go", "build", "-o", str(relay_binary), "./cmd/relay"],
                cwd=repo / "relay", check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            database = launcher._prepare_run_sqlite(run_dir / "relay-host-v1.sqlite3", run_dir)
            listen_port = free_port()
            process = subprocess.Popen(
                [str(relay_binary), "--addr", f"127.0.0.1:{listen_port}", "--db", str(database)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                deadline = launcher.time.monotonic() + 5
                while database.stat().st_size == 0 and launcher.time.monotonic() < deadline:
                    launcher.time.sleep(0.02)
                self.assertGreater(database.stat().st_size, 0)
                launcher._validate_run_sqlite(database, run_dir, require_main=True)
                self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_config_has_eight_unique_loopback_ports_and_legacy_aliases(self) -> None:
        values = ports(8)
        names = (
            "NOMAD_WEB_RELAY_PORT", "NOMAD_WEB_GATEWAY_PORT", "NOMAD_WEB_AGENT_PORT",
            "NOMAD_WEB_JOIN_GATEWAY_PORT", "NOMAD_WEB_RELAY_HOST_V2_PORT",
            "NOMAD_WEB_RELAY_DEVICE_V2_PORT", "NOMAD_WEB_RELAY_ADMIN_PORT",
            "NOMAD_WEB_RELAY_DEVICE_V1_PORT",
        )
        environment = {name: str(value) for name, value in zip(names, values)}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, environment, clear=True):
            os.environ["NOMAD_WEB_HOME"] = str(Path(temporary) / "home")
            config = Config.load(Path(temporary))
        self.assertEqual(config.desktop_gateway_port, config.gateway_port)
        self.assertEqual(config.relay_host_v1_port, config.relay_port)
        self.assertEqual(len({getattr(config, field) for field in (
            "relay_port", "gateway_port", "agent_port", "join_gateway_port",
            "relay_host_v2_port", "relay_device_v2_port", "relay_admin_port",
            "relay_device_v1_port",
        )}), 8)
        environment["NOMAD_WEB_JOIN_GATEWAY_PORT"] = environment["NOMAD_WEB_GATEWAY_PORT"]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, environment, clear=True):
            os.environ["NOMAD_WEB_HOME"] = str(Path(temporary) / "home")
            with self.assertRaisesRegex(RuntimeError, "DUPLICATE_LOOPBACK_PORT"):
                Config.load(Path(temporary))

    def test_remote_partial_inputs_are_zero_spawn_and_close_owned_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; bundle.mkdir()
            config = self.config(root, bundle)
            credential = self.credential_fd()
            with mock.patch.object(processes, "spawn") as spawn:
                with self.assertRaisesRegex(RuntimeError, "REMOTE_START_INPUTS_INCOMPLETE"):
                    launcher.start_foundation(
                        config, provider_name="OPENAI_API_KEY", credential_fd=credential,
                        workspace=root, remote_local_evidence=True,
                    )
                spawn.assert_not_called()
            self.assertFalse(config.home.exists())
            with self.assertRaises(OSError):
                os.fstat(credential)

    def test_ingress_ready_is_byte_exact_eof_and_identity_bound(self) -> None:
        record = {"name": "https-ingress", "pid": 42, "process_group": 42, "identity": "a" * 64, "log": "/tmp/x"}
        expected = b'{"schema":"nomad.https-ingress.ready.v1","ready":true}'
        for raw, accepted in ((expected, True), (b'{"ready":true,"schema":"nomad.https-ingress.ready.v1"}', False), (expected + b"x", False)):
            parent, child = socket.socketpair()
            child.sendall(len(raw).to_bytes(4, "big") + raw); child.shutdown(socket.SHUT_WR)
            with mock.patch.object(processes, "ownership", return_value="owned"):
                if accepted:
                    launcher._wait_ingress_ready(parent, record)
                else:
                    with self.assertRaisesRegex(RuntimeError, "INGRESS_READY_INVALID"):
                        launcher._wait_ingress_ready(parent, record)
            parent.close(); child.close()
        parent, child = socket.socketpair()
        child.sendall(len(expected).to_bytes(4, "big") + expected); child.shutdown(socket.SHUT_WR)
        with mock.patch.object(processes, "ownership", side_effect=["owned", "mismatch"]):
            with self.assertRaisesRegex(RuntimeError, "INGRESS_PROCESS_NOT_OWNED"):
                launcher._wait_ingress_ready(parent, record)
        parent.close(); child.close()

    def test_remote_composition_has_fixed_roles_distinct_fds_and_state_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; bundle.mkdir(); workspace = root / "workspace"; workspace.mkdir(mode=0o700)
            config = self.config(root, bundle)
            state.initialize_home(config)
            credential = self.credential_fd(); cert = self.private_fd(root, "cert.pem", b"cert-canary"); key = self.private_fd(root, "key.pem", b"key-canary")
            calls: list[dict[str, object]] = []; secrets_by_child: dict[str, dict[int, bytes]] = {}; pid = 100
            raw_values = iter((b"c" * 32, b"j" * 32, b"a" * 32, b"t" * 32, b"i" * 32))

            def fake_spawn(name, command, cwd, env, log_path, *, extra_fd_actions=(), close_fds=()):
                nonlocal pid
                pid += 1
                child_secrets = {}
                for source, target in extra_fd_actions:
                    if target in (11, 12) and name != "https-ingress" or target == 12 and name == "https-ingress":
                        child_secrets[target] = os.read(source, 4097)
                    if name == "https-ingress" and target == 13:
                        ready = b'{"schema":"nomad.https-ingress.ready.v1","ready":true}'
                        os.write(source, len(ready).to_bytes(4, "big") + ready)
                        duplicate = socket.socket(fileno=os.dup(source))
                        duplicate.shutdown(socket.SHUT_WR)
                        duplicate.close()
                secrets_by_child[name] = child_secrets
                calls.append({"name": name, "command": list(command), "env": dict(env)})
                return {"name": name, "pid": pid, "process_group": pid, "identity": f"{pid:064x}", "log": str(log_path)}

            host_seen = {}
            def fake_host(binary, cwd, log_path, bootstrap_child, *, admin_bearer_fd=None):
                nonlocal pid
                pid += 1; secrets_by_child["product-host"] = {11: os.read(admin_bearer_fd, 4097)}
                return {"name": "product-host", "pid": pid, "process_group": pid, "identity": f"{pid:064x}", "log": str(log_path)}

            def fake_bootstrap(channel, **kwargs):
                host_seen.update(kwargs)
                return {"parent_dev": 1, "parent_ino": 2, "parent_uid": os.geteuid(), "parent_mode": 0o700, "socket_dev": 3, "socket_ino": 4, "socket_uid": os.geteuid(), "socket_mode": 0o600}

            def fake_agent(_bundle, _workspace, _runtime, port, _provider, fd, log_path):
                nonlocal pid
                os.close(fd); pid += 1
                return {"name": "opencode", "pid": pid, "process_group": pid, "identity": f"{pid:064x}", "log": str(log_path), "origin": f"http://127.0.0.1:{port}", "_server_password": "agent-password-canary", "_workspace_binding_digest": "b" * 64}

            tls_context = object()
            with mock.patch.object(launcher, "select_bundle_for_start", return_value=bundle), mock.patch.object(launcher, "_selected_bundle_digest", return_value="9" * 64), mock.patch.object(launcher, "install_status_unlocked", return_value={"state": "INSTALLED", "current_bundle_digest": "9" * 64, "history": [{"sequence": 1}]}), mock.patch.object(launcher, "_validate_remote_inputs", return_value=("https://pair.example:8443", "192.0.2.10:8443", [])), mock.patch.object(launcher, "_listen_address_free", return_value=True), mock.patch.object(launcher, "_require_host_identity_ready"), mock.patch.object(launcher, "_tls_probe_context", return_value=tls_context), mock.patch.object(launcher, "_spawn_product_host_with_fds", side_effect=fake_host), mock.patch.object(launcher, "start_agent", side_effect=fake_agent), mock.patch.object(launcher, "_create_run_session", return_value="ses_raw"), mock.patch.object(launcher, "_bootstrap_host", side_effect=fake_bootstrap), mock.patch.object(processes, "spawn", side_effect=fake_spawn), mock.patch.object(launcher, "_wait_relay_role"), mock.patch.object(launcher, "_wait_gateway_route"), mock.patch.object(launcher, "_probe_public_negative_routes") as negative, mock.patch.object(processes, "ownership", return_value="owned"), mock.patch.object(launcher.secrets, "token_bytes", side_effect=lambda _size: next(raw_values)), mock.patch.object(launcher.secrets, "token_urlsafe", return_value="relay-admin-canary-value-0123456789"):
                result = launcher._start_remote_unlocked(config, provider_name="OPENAI_API_KEY", credential_fd=credential, workspace=workspace, public_origin="https://pair.example:8443", https_listen="192.0.2.10:8443", tls_cert_fd=cert, tls_key_fd=key)

            names = [item["name"] for item in result["processes"]]
            self.assertEqual(names, ["relay-host", "relay-device", "opencode", "product-host", "desktop-gateway", "join-gateway", "https-ingress"])
            relay_host = next(item for item in calls if item["name"] == "relay-host")["command"]
            relay_device = next(item for item in calls if item["name"] == "relay-device")["command"]
            self.assertEqual(relay_host[relay_host.index("--v2-role") + 1], "host")
            self.assertEqual(relay_device[relay_device.index("--v2-role") + 1], "device")
            self.assertEqual(relay_host[relay_host.index("--v2-db") + 1], relay_device[relay_device.index("--v2-db") + 1])
            self.assertEqual(secrets_by_child["relay-host"][11], secrets_by_child["product-host"][11])
            self.assertNotEqual(secrets_by_child["desktop-gateway"][11], secrets_by_child["join-gateway"][11])
            self.assertEqual(secrets_by_child["join-gateway"][12], secrets_by_child["https-ingress"][12])
            self.assertEqual(host_seen["remote"]["relay_device_public_base_url"], "https://pair.example:8443")
            self.assertEqual(result["schema"], state.REMOTE_STATE_SCHEMA)
            self.assertEqual(result["bundle_digest"], "9" * 64)
            self.assertEqual((result["network_scope"], result["production_external"]), ("lan_direct", False))
            self.assertEqual(result["identity"]["installed"]["availability"], "READY")
            self.assertEqual(result["identity"]["running"]["availability"], "READY")
            self.assertEqual(result["identity"]["host_public_commitment"]["availability"], "UNAVAILABLE")
            self.assertEqual(result["identity"]["host_public_commitment"]["commitment"], None)
            self.assertEqual(result["identity"]["paired_device"]["availability"], "UNPAIRED")
            negative.assert_called_once_with("https://pair.example:8443", "192.0.2.10:8443", tls_context)
            surface = (config.home / "run" / "status.json").read_bytes() + json.dumps(calls).encode()
            for secret in (b"c" * 32, b"j" * 32, b"a" * 32, b"t" * 32, b"relay-admin-canary", b"provider-canary", b"cert-canary", b"key-canary", b"agent-password-canary"):
                self.assertNotIn(secret, surface)

    def test_running_identity_mismatch_blocks_without_silent_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            config = self.config(root, bundle)
            state.initialize_home(config)
            for name in ("bin", "run", "logs"):
                (config.home / name).mkdir(mode=0o700)
            running = {
                "schema": state.STATE_SCHEMA,
                "mode": "official-agent-local",
                "real_agent_enabled": True,
                "bundle_digest": "a" * 64,
                "blocked_on": ["PRODUCTION_DEVICE_IDENTITY"],
                "web_url": f"http://127.0.0.1:{config.gateway_port}/",
                "agent_origin": f"http://127.0.0.1:{config.agent_port}",
                "agent_version": "1.18.16",
                "logs_dir": str(config.home / "logs"),
                "relay_port": config.relay_port,
                "gateway_port": config.gateway_port,
                "agent_port": config.agent_port,
                "run_id": "b" * 64,
                "session_alias": "sess-" + "c" * 32,
                "workspace_binding_digest": "d" * 64,
                "product_host_socket_identity": {
                    "parent_dev": 1,
                    "parent_ino": 2,
                    "parent_uid": os.geteuid(),
                    "parent_mode": 0o700,
                    "socket_dev": 3,
                    "socket_ino": 4,
                    "socket_uid": os.geteuid(),
                    "socket_mode": 0o600,
                },
                "processes": [
                    {"name": "opencode", "pid": 101, "process_group": 101, "identity": "1" * 64, "log": str(config.home / "logs" / "agent.log")},
                    {"name": "product-host", "pid": 102, "process_group": 102, "identity": "2" * 64, "log": str(config.home / "logs" / "host.log")},
                    {"name": "gateway", "pid": 103, "process_group": 103, "identity": "3" * 64, "log": str(config.home / "logs" / "gateway.log")},
                ],
                "identity": {
                    "installed": {
                        "availability": "READY",
                        "bundle_digest": "a" * 64,
                        "install_sequence": 1,
                        "install_identity": "4" * 64,
                    },
                    "running": {
                        "availability": "READY",
                        "bundle_digest": "a" * 64,
                        "run_id": "b" * 64,
                        "process_commitment": "5" * 64,
                        "socket_commitment": "6" * 64,
                        "run_identity": "7" * 64,
                    },
                    "host_public_commitment": {"availability": "UNAVAILABLE", "commitment": None},
                    "paired_device": {"availability": "UNPAIRED", "device_key_commitment": None, "pairing_epoch": None},
                },
            }
            with mock.patch.object(launcher, "select_bundle_for_start", return_value=bundle), mock.patch.object(launcher, "_selected_bundle_digest", return_value="a" * 64), mock.patch.object(launcher, "read_run_state", return_value=running), mock.patch.object(launcher, "install_status_unlocked", return_value={"state": "INSTALLED", "current_bundle_digest": "a" * 64, "history": [{"sequence": 1}]}), mock.patch.object(launcher, "_validate_device_registry_artifacts"), mock.patch.object(processes, "ownership", return_value="owned"):
                with self.assertRaisesRegex(RuntimeError, "RUNNING_IDENTITY_MISMATCH"):
                    launcher._start_unlocked(config, provider_name="OPENAI_API_KEY", credential_fd=9, workspace=root)

    def test_remote_rollback_and_stop_are_reverse_dependency_order(self) -> None:
        process_names = ["relay-host", "relay-device", "opencode", "product-host", "desktop-gateway", "join-gateway", "https-ingress"]
        stopped: list[str] = []
        current = {"mode": "remote-local-evidence", "processes": [{"name": name} for name in process_names]}
        config = SimpleNamespace(home=Path("/private/tmp/nomad-e6-fake-home"))
        with mock.patch.object(launcher, "read_run_state", return_value=current), mock.patch.object(processes, "ownership", return_value="owned"), mock.patch.object(processes, "stop", side_effect=lambda item: stopped.append(item["name"]) or True), mock.patch.object(launcher, "_cleanup_run_artifacts"), mock.patch.object(launcher, "state_path") as path:
            path.return_value.unlink = mock.Mock()
            result = launcher._stop_unlocked(config)
        self.assertEqual(stopped, list(reversed(process_names)))
        self.assertEqual(result["state"], "STOPPED")

    def test_remote_rollback_preserves_primary_error_and_reports_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); run_dir = root / "run"; run_dir.mkdir(mode=0o700)
            unsafe = run_dir / "relay-host-v1.sqlite3"
            unsafe.write_bytes(b"sqlite")
            os.chmod(unsafe, 0o644)
            safe = launcher._prepare_run_sqlite(run_dir / "relay-device-v1.sqlite3", run_dir)
            with self.assertRaisesRegex(RuntimeError, r"^HOST_BOOTSTRAP_INVALID;ROLLBACK_CLEANUP_FAILED$"):
                launcher._rollback_remote_start(
                    RuntimeError("HOST_BOOTSTRAP_INVALID"), [],
                    product_host_socket_path=None, product_host_socket_identity=None,
                    desktop_db_path=None, command_journal_path=None,
                    relay_v1_paths=(unsafe, safe), run_dir=run_dir,
                )
            self.assertTrue(unsafe.exists())
            self.assertFalse(safe.exists())

    def test_restart_stops_before_fresh_remote_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; bundle.mkdir(); workspace = root / "workspace"; workspace.mkdir()
            config = self.config(root, bundle)
            credential = self.credential_fd(); cert = self.private_fd(root, "cert.pem", b"cert"); key = self.private_fd(root, "key.pem", b"key")
            order: list[str] = []
            with mock.patch.object(launcher, "_preflight_remote_agent"), mock.patch.object(launcher, "_validate_remote_inputs", return_value=("https://pair.example:8443", "192.0.2.10:8443", [])), mock.patch.object(launcher, "_stop_unlocked", side_effect=lambda _config: order.append("stop")), mock.patch.object(launcher, "_wait_ports_free"), mock.patch.object(launcher, "_listen_address_free", return_value=True), mock.patch.object(launcher, "_start_remote_unlocked", side_effect=lambda *_args, **_kwargs: order.append("start") or {"state": "RUNNING"}):
                result = launcher.restart_foundation(
                    config, provider_name="OPENAI_API_KEY", credential_fd=credential, workspace=workspace,
                    remote_local_evidence=True, public_origin="https://pair.example:8443",
                    https_listen="192.0.2.10:8443", tls_cert_fd=cert, tls_key_fd=key,
                )
            self.assertEqual(order, ["stop", "start"])
            self.assertEqual(result["state"], "RUNNING")

    def test_stop_then_uninstall_refuses_remote_persistent_state_and_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config = self.config(root, root / "bundle")
            state.initialize_home(config)
            for name in ("bin", "run", "logs"):
                (config.home / name).mkdir(mode=0o700)
            private = config.home / launcher.DEVICE_REGISTRY_DIRNAME
            private.mkdir(mode=0o700)
            artifacts = [private / name for name in (
                launcher.DEVICE_REGISTRY_BASENAME, launcher.PAIRING_STORE_BASENAME,
                launcher.REMOTE_MAILBOX_STATE_BASENAME, launcher.RELAY_V2_BASENAME,
            )]
            for artifact in artifacts:
                artifact.write_bytes(b"persistent")
                os.chmod(artifact, 0o600)
            self.assertIsNone(state.read_run_state(config))
            with self.assertRaisesRegex(RuntimeError, "REMOTE_UNINSTALL_REVOKE_REQUIRED"):
                launcher.uninstall_foundation(config)
            self.assertTrue(config.home.is_dir())
            self.assertTrue(all(artifact.read_bytes() == b"persistent" for artifact in artifacts))

    def test_uninstall_lifecycle_accepts_verified_installed_home_without_runtime_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = materialized_bundle(root)
            config = self.config(root, bundle)

            with mock.patch.object(
                install_lifecycle,
                "_host_identity_blocker",
                return_value="HOST_IDENTITY_AUTH_REQUIRED",
            ):
                install_result = cli.install(config, bundle)
            self.assertEqual(install_result["state"], "INSTALLED")
            self.assertEqual(install_result["onboarding"]["state"], "INSTALLED_BLOCKED_HOST_IDENTITY")
            self.assertFalse((config.home / "bin").exists())
            self.assertFalse((config.home / "run").exists())
            self.assertFalse((config.home / "logs").exists())
            self.assertTrue((config.home / "install").is_dir())
            self.assertTrue((config.home / "bundles").is_dir())

            reset = launcher.reset_remote_access(config)
            self.assertEqual(reset["schema"], "nomad.web-companion.remote-access-reset.v1")
            self.assertEqual(reset["state"], "STOPPED")
            self.assertEqual(reset["remote_access"], "CLEARED")
            self.assertEqual(reset["install_state"], "PRESERVED")
            self.assertEqual(reset["host_identity_disposition"], "retained")
            self.assertTrue(config.home.is_dir())
            self.assertFalse((config.home / "bin").exists())
            self.assertFalse((config.home / "run").exists())
            self.assertFalse((config.home / "logs").exists())

            uninstall = launcher.uninstall_lifecycle(config)
            self.assertEqual(uninstall["schema"], "nomad.web-companion.uninstall-result.v1")
            self.assertEqual(uninstall["state"], "UNINSTALLED")
            self.assertEqual(uninstall["remote_access"], "CLEARED")
            self.assertEqual(uninstall["install_state"], "REMOVED")
            self.assertEqual(uninstall["host_identity_disposition"], "retained")
            self.assertFalse(uninstall["production_ready"])
            self.assertFalse(config.home.exists())

    def test_uninstall_lifecycle_still_rejects_present_runtime_dir_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = materialized_bundle(root)
            config = self.config(root, bundle)
            with mock.patch.object(
                install_lifecycle,
                "_host_identity_blocker",
                return_value="HOST_IDENTITY_AUTH_REQUIRED",
            ):
                cli.install(config, bundle)

            external = root / "external"
            external.mkdir(mode=0o700)
            (config.home / "run").symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "UNSAFE_LAUNCHER_DIRECTORY"):
                launcher.uninstall_lifecycle(config)
            self.assertTrue((config.home / "run").is_symlink())
            self.assertTrue(config.home.exists())

    def test_gateway_route_probe_rejects_wrong_route_table_response(self) -> None:
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            def __init__(self, status, raw): self.status, self.raw, self.headers = status, raw, Headers()
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _limit): return self.raw
        for route_table in ("desktop", "join"):
            wrong = Response(404, b'{"error":"NOT_FOUND"}')
            with mock.patch.object(launcher._NO_PROXY_OPENER, "open", return_value=wrong), mock.patch.object(launcher.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, f"{route_table.upper()}_GATEWAY_NOT_READY"):
                    launcher._wait_gateway_route(14173, route_table, timeout=0.0001)
            exact = Response(405, b'{"error":"METHOD_NOT_ALLOWED"}')
            with mock.patch.object(launcher._NO_PROXY_OPENER, "open", return_value=exact):
                launcher._wait_gateway_route(14173, route_table)

    def test_public_probe_fails_closed_on_certificate_or_san_error(self) -> None:
        context = mock.Mock()
        context.wrap_socket.side_effect = launcher.ssl.SSLCertVerificationError("hostname mismatch")
        raw_socket = mock.Mock()
        with mock.patch.object(launcher.socket, "create_connection", return_value=raw_socket):
            with self.assertRaisesRegex(RuntimeError, "INGRESS_TLS_PROBE_FAILED"):
                launcher._probe_public_negative_routes(
                    "https://pair.example:8443", "192.0.2.10:8443", context
                )
        raw_socket.close.assert_called_once()

    def test_bad_certificate_never_publishes_running_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; bundle.mkdir(); workspace = root / "workspace"; workspace.mkdir()
            config = self.config(root, bundle)
            state.initialize_home(config)
            for name in ("bin", "run", "logs"):
                (config.home / name).mkdir(mode=0o700)
            credential = self.credential_fd(); cert = self.private_fd(root, "bad-cert.pem", b"not a certificate"); key = self.private_fd(root, "key.pem", b"not a key")
            with mock.patch.object(launcher, "select_bundle_for_start", return_value=bundle), mock.patch.object(launcher, "_selected_bundle_digest", return_value="a" * 64), mock.patch.object(launcher, "_listen_address_free", return_value=True), mock.patch.object(launcher, "_require_host_identity_ready"), mock.patch.object(processes, "spawn") as spawn:
                with self.assertRaisesRegex(RuntimeError, "REMOTE_TLS_CERT_INVALID"):
                    launcher._start_remote_unlocked(config, provider_name="OPENAI_API_KEY", credential_fd=credential, workspace=workspace, public_origin="https://pair.example:8443", https_listen="192.0.2.10:8443", tls_cert_fd=cert, tls_key_fd=key)
                spawn.assert_not_called()
            self.assertFalse(state.state_path(config).exists())

    def test_host_identity_preflight_exact_contract_and_zero_business_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; (bundle / "bin").mkdir(parents=True)
            host = bundle / "bin" / "nomad-product-host"; host.write_bytes(b"host"); os.chmod(host, 0o755)
            config = self.config(root, bundle); state.initialize_home(config)
            for name in ("bin", "run", "logs"):
                (config.home / name).mkdir(mode=0o700)
            credential = self.credential_fd(); cert = self.private_fd(root, "cert.pem", b"cert"); key = self.private_fd(root, "key.pem", b"key")
            completed = SimpleNamespace(returncode=1, stdout=b'{"status":"AUTH_REQUIRED"}\n', stderr=b"")
            with mock.patch.object(launcher, "select_bundle_for_start", return_value=bundle), mock.patch.object(launcher, "_selected_bundle_digest", return_value="a" * 64), mock.patch.object(launcher, "_listen_address_free", return_value=True), mock.patch.object(launcher.subprocess, "run", return_value=completed) as command, mock.patch.object(processes, "spawn") as relay_spawn, mock.patch.object(launcher, "start_agent") as agent_spawn:
                with self.assertRaisesRegex(launcher.HostIdentityError, "HOST_IDENTITY_AUTH_REQUIRED") as raised:
                    launcher._start_remote_unlocked(config, provider_name="OPENAI_API_KEY", credential_fd=credential, workspace=root, public_origin="https://pair.example:8443", https_listen="192.0.2.10:8443", tls_cert_fd=cert, tls_key_fd=key)
                self.assertEqual(raised.exception.next_step, "nomad-web authorize-host-identity")
                relay_spawn.assert_not_called(); agent_spawn.assert_not_called()
            self.assertEqual(command.call_args.args[0], [str(host), "identity-preflight", "--non-interactive"])
            self.assertEqual(command.call_args.kwargs["timeout"], launcher.HOST_IDENTITY_PREFLIGHT_TIMEOUT)
            self.assertFalse(state.state_path(config).exists())

    def test_host_identity_parser_rejects_noncanonical_output_and_bad_exit(self) -> None:
        host = Path("/private/tmp/nomad-product-host")
        invalid = (
            SimpleNamespace(returncode=0, stdout=b'{"status": "READY"}\n', stderr=b""),
            SimpleNamespace(returncode=1, stdout=b'{"status":"READY"}\n', stderr=b""),
            SimpleNamespace(returncode=0, stdout=b'{"status":"READY"}\n', stderr=b"unexpected"),
        )
        for result in invalid:
            with self.subTest(result=result), mock.patch.object(launcher.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(launcher.HostIdentityError, "HOST_IDENTITY_PREFLIGHT_INVALID"):
                    launcher._run_host_identity_command(host, ["identity-preflight", "--non-interactive"])

    def test_authorize_cli_runs_host_foreground_and_emits_guidance(self) -> None:
        config = SimpleNamespace(repo_root=Path("/repo"), home=Path("/home"), bundle_root=Path("/bundle"))
        ready = {"schema": "nomad.web-companion.host-identity.v1", "state": "READY", "status": "READY", "production_ready": False}
        output = io.StringIO()
        with mock.patch.object(cli.Config, "load", return_value=config), mock.patch.object(cli, "authorize_host_identity", return_value=ready) as authorize, mock.patch("sys.stdout", output):
            self.assertEqual(cli.run(["--json", "authorize-host-identity"]), 0)
        authorize.assert_called_once_with(config)
        self.assertEqual(json.loads(output.getvalue()), ready)
        output = io.StringIO()
        with mock.patch.object(cli.Config, "load", return_value=config), mock.patch.object(cli, "authorize_host_identity", side_effect=launcher.HostIdentityError("HOST_IDENTITY_AUTH_REQUIRED", next_step="nomad-web authorize-host-identity")), mock.patch("sys.stdout", output):
            self.assertEqual(cli.run(["--json", "authorize-host-identity"]), 1)
        self.assertEqual(json.loads(output.getvalue())["next_step"], "nomad-web authorize-host-identity")

    def test_interactive_authorize_has_separate_timeout_and_error_domain(self) -> None:
        host = Path("/private/tmp/nomad-product-host")
        with mock.patch.object(launcher.subprocess, "run", side_effect=launcher.subprocess.TimeoutExpired([str(host)], launcher.HOST_IDENTITY_AUTHORIZATION_TIMEOUT)) as command:
            with self.assertRaisesRegex(launcher.HostIdentityError, "HOST_IDENTITY_AUTHORIZATION_TIMEOUT"):
                launcher._run_host_identity_command(host, ["authorize-host-identity"], interactive=True)
        self.assertEqual(command.call_args.kwargs["timeout"], launcher.HOST_IDENTITY_AUTHORIZATION_TIMEOUT)
        self.assertIsNone(command.call_args.kwargs["stdin"])
        with mock.patch.object(launcher.subprocess, "run", side_effect=OSError("exec failed")):
            with self.assertRaisesRegex(launcher.HostIdentityError, "HOST_IDENTITY_AUTHORIZATION_FAILED"):
                launcher._run_host_identity_command(host, ["authorize-host-identity"], interactive=True)

    def test_authorize_user_denied_keeps_retry_guidance_and_spawns_no_business_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); bundle = root / "bundle"; (bundle / "bin").mkdir(parents=True)
            host = bundle / "bin" / "nomad-product-host"; host.write_bytes(b"host"); os.chmod(host, 0o755)
            config = self.config(root, bundle)
            denied = SimpleNamespace(returncode=1, stdout=b'{"status":"USER_DENIED"}\n', stderr=b"")
            with mock.patch.object(launcher, "select_bundle_for_start", return_value=bundle), mock.patch.object(launcher, "_selected_bundle_digest", return_value="a" * 64), mock.patch.object(launcher.subprocess, "run", return_value=denied) as command, mock.patch.object(processes, "spawn") as spawn, mock.patch.object(launcher, "start_agent") as agent:
                with self.assertRaisesRegex(launcher.HostIdentityError, "HOST_IDENTITY_USER_DENIED") as raised:
                    launcher.authorize_host_identity(config)
                self.assertEqual(raised.exception.next_step, "nomad-web authorize-host-identity")
                spawn.assert_not_called(); agent.assert_not_called()
            self.assertEqual(command.call_args.args[0], [str(host), "authorize-host-identity"])
            self.assertEqual(command.call_args.kwargs["timeout"], launcher.HOST_IDENTITY_AUTHORIZATION_TIMEOUT)
            self.assertIsNone(command.call_args.kwargs["stdin"])


if __name__ == "__main__":
    unittest.main()
