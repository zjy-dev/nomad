from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import cli, evidence_resume, launcher, state


class P10DiagnosticLauncherTests(unittest.TestCase):
    def config(self, root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            home=root / "home", repo_root=root, bundle_root=root / "bundle",
            relay_port=18089, gateway_port=14173, agent_port=4096,
            join_gateway_port=14174, relay_host_v2_port=18090,
            relay_device_v2_port=18091, relay_admin_port=18092,
            relay_device_v1_port=18093,
        )

    def test_diagnostic_network_is_literal_ipv4_loopback_only(self) -> None:
        policy = launcher._LOOPBACK_DIAGNOSTIC_POLICY
        self.assertEqual(
            launcher._validate_https_listen(
                "127.0.0.1:8443", "https://127.0.0.1:8443",
                loopback_only=True,
            ),
            "127.0.0.1:8443",
        )
        self.assertEqual(
            launcher._validate_diagnostic_public_origin("https://127.0.0.1:8443"),
            "https://127.0.0.1:8443",
        )
        for origin in (
            "https://localhost:8443", "https://[::1]:8443",
            "https://[::ffff:127.0.0.1]:8443",
            "https://0.0.0.0:8443", "https://192.0.2.10:8443",
        ):
            with self.subTest(origin=origin), self.assertRaises(RuntimeError):
                launcher._validate_diagnostic_public_origin(origin)
        for listen in (
            "[::1]:8443", "[::ffff:127.0.0.1]:8443",
            "0.0.0.0:8443", "192.0.2.10:8443",
        ):
            with self.subTest(listen=listen), self.assertRaisesRegex(RuntimeError, "REMOTE_HTTPS_LISTEN_INVALID"):
                launcher._validate_https_listen(
                    listen, "https://127.0.0.1:8443", loopback_only=True,
                )
        with self.assertRaisesRegex(RuntimeError, "REMOTE_HTTPS_LISTEN_INVALID"):
            launcher._validate_https_listen(
                "127.0.0.1:8443", "https://127.0.0.1:8443",
                loopback_only=launcher._ACCEPTED_REMOTE_POLICY.loopback_only,
            )
        for origin in (
            "https://localhost:8443", "https://127.0.0.1:8443",
            "https://[::1]:8443", "https://[::ffff:127.0.0.1]:8443",
            "https://0.0.0.0:8443",
        ):
            with self.subTest(accepted_origin=origin), self.assertRaisesRegex(RuntimeError, "REMOTE_PUBLIC_ORIGIN_INVALID"):
                launcher._reject_loopback_public_origin(launcher._validate_public_origin(origin))
        self.assertFalse(policy.accepted_eligible)
        self.assertEqual(
            launcher._desktop_gateway_policy_argv(policy),
            ["--diagnostic-loopback"],
        )
        self.assertEqual(
            launcher._desktop_gateway_policy_argv(launcher._ACCEPTED_REMOTE_POLICY),
            ["--lifecycle-channel-fd", "12"],
        )

    def test_accepted_network_rejects_loopback_forms_and_keeps_exact_lan(self) -> None:
        for origin in (
            "https://localhost:8443", "https://127.0.0.1:8443",
            "https://[::1]:8443", "https://[::ffff:127.0.0.1]:8443",
        ):
            with self.subTest(origin=origin), self.assertRaisesRegex(RuntimeError, "REMOTE_PUBLIC_ORIGIN_INVALID"):
                launcher._reject_loopback_public_origin(
                    launcher._validate_public_origin(origin),
                )
        for listen in (
            "127.0.0.1:8443", "[::1]:8443",
            "[::ffff:127.0.0.1]:8443", "0.0.0.0:8443",
        ):
            with self.subTest(listen=listen), self.assertRaisesRegex(RuntimeError, "REMOTE_HTTPS_LISTEN_INVALID"):
                launcher._validate_https_listen(
                    listen, "https://192.168.100.3:8443",
                    loopback_only=False,
                )
        origin = launcher._reject_loopback_public_origin(
            launcher._validate_public_origin("https://192.168.100.3:8443"),
        )
        self.assertEqual(origin, "https://192.168.100.3:8443")
        self.assertEqual(
            launcher._validate_https_listen(
                "192.168.100.3:8443", origin, loopback_only=False,
            ),
            "192.168.100.3:8443",
        )

    def test_diagnostic_wrapper_is_explicit_and_cannot_select_accepted_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            bundle = root / "bundle"
            bundle.mkdir()
            workspace = root / "workspace"
            workspace.mkdir()
            descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(3)]
            credential, cert, key = descriptors
            result = {"mode": "remote-loopback-diagnostic"}
            with (
                mock.patch.object(launcher, "_preflight_remote_agent"),
                mock.patch.object(launcher, "_validate_remote_inputs", return_value=("https://127.0.0.1:8443", "127.0.0.1:8443", [])) as validate,
                mock.patch.object(launcher, "initialize_home"),
                mock.patch.object(launcher, "lifecycle_lock") as lock,
                mock.patch.object(launcher, "_start_remote_unlocked", return_value=result) as start,
            ):
                lock.return_value.__enter__.return_value = True
                self.assertIs(launcher.start_remote_loopback_diagnostic(
                    config, bundle, workspace, "OPENAI_API_KEY", credential,
                    "https://127.0.0.1:8443", "127.0.0.1:8443", cert, key,
                ), result)
            self.assertIs(validate.call_args.kwargs["policy"], launcher._LOOPBACK_DIAGNOSTIC_POLICY)
            self.assertIs(start.call_args.kwargs["policy"], launcher._LOOPBACK_DIAGNOSTIC_POLICY)
            self.assertEqual(start.call_args.kwargs["required_bundle"], bundle)
            for descriptor in descriptors:
                os.close(descriptor)

    def test_diagnostic_cli_is_explicit_and_uses_verified_config_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            workspace = root / "workspace"
            workspace.mkdir()
            result = {
                "schema": state.DIAGNOSTIC_STATE_SCHEMA,
                "state": "RUNNING", "mode": "remote-loopback-diagnostic",
                "diagnostic_only": True, "accepted_eligible": False,
            }
            output = __import__("io").StringIO()
            with (
                mock.patch.object(cli.Config, "load", return_value=config),
                mock.patch.object(cli, "start_remote_loopback_diagnostic", return_value=result) as start,
                mock.patch.object(cli.os, "dup", return_value=20),
                mock.patch("sys.stdout", output),
            ):
                code = cli.run([
                    "--json", "start-loopback-diagnostic",
                    "--provider", "OPENAI_API_KEY", "--credential-stdin",
                    "--workspace", str(workspace),
                    "--public-origin", "https://127.0.0.1:8443",
                    "--https-listen", "127.0.0.1:8443",
                    "--tls-cert-fd", "10", "--tls-key-fd", "11",
                ])
            self.assertEqual(code, 0)
            start.assert_called_once_with(
                config, config.bundle_root, workspace, "OPENAI_API_KEY", 20,
                "https://127.0.0.1:8443", "127.0.0.1:8443", 10, 11,
            )
            self.assertEqual(json.loads(output.getvalue()), result)

    def test_diagnostic_cli_rejects_accepted_alias_and_incomplete_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            for arguments in (
                ["--json", "start-loopback-diagnostic"],
                [
                    "--json", "start-loopback-diagnostic", "--remote-local-evidence",
                    "--provider", "OPENAI_API_KEY", "--credential-stdin",
                    "--workspace", str(Path(temporary)),
                    "--public-origin", "https://127.0.0.1:8443",
                    "--https-listen", "127.0.0.1:8443",
                    "--tls-cert-fd", "10", "--tls-key-fd", "11",
                ],
            ):
                with (
                    self.subTest(arguments=arguments),
                    mock.patch.object(cli.Config, "load", return_value=config),
                    mock.patch.object(cli, "start_remote_loopback_diagnostic") as start,
                    mock.patch("sys.stdout", __import__("io").StringIO()),
                ):
                    self.assertEqual(cli.run(arguments), 1)
                    start.assert_not_called()

    def test_bootstrap_v3_fields_are_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            run = home / "run"
            run.mkdir(mode=0o700)
            identity_root = launcher._prepare_diagnostic_identity_root(run, "d" * 64)
            socket_path = launcher._prepare_product_host_socket(home, "e" * 64)
            registry = identity_root / "remote" / launcher.DEVICE_REGISTRY_DIRNAME / launcher.DEVICE_REGISTRY_BASENAME
            registry.parent.mkdir(mode=0o700)
            parent, child = socket.socketpair()
            observed = {}
            listener = []

            def peer() -> None:
                length = int.from_bytes(child.recv(4), "big")
                raw = b""
                while len(raw) < length:
                    raw += child.recv(length - len(raw))
                observed.update(json.loads(raw))
                child.recv(1)
                server = socket.socket(socket.AF_UNIX)
                server.bind(str(socket_path))
                os.chmod(socket_path, 0o600)
                listener.append(server)
                parent_info, socket_info = socket_path.parent.stat(), socket_path.stat()
                ready = {
                    "schema": launcher.REMOTE_HOST_READY_SCHEMA,
                    "parent_dev": parent_info.st_dev, "parent_ino": parent_info.st_ino,
                    "socket_dev": socket_info.st_dev, "socket_ino": socket_info.st_ino,
                    "snapshot_seq": 1, "pairing_ready": True,
                    "remote_mailbox_ready": True,
                }
                encoded = json.dumps(ready, separators=(",", ":")).encode()
                child.sendall(len(encoded).to_bytes(4, "big") + encoded)
                child.shutdown(socket.SHUT_WR)

            worker = threading.Thread(target=peer)
            worker.start()
            launcher._bootstrap_host(
                parent, run_id="a" * 64, origin="http://127.0.0.1:4096",
                session_id="session", password="secret", workspace_digest="b" * 64,
                product_host_socket_path=socket_path, device_registry_path=registry,
                agent_pid=42, agent_process_group=42, agent_process_identity="c" * 64,
                command_transport_key="d" * 44, command_authority_key="e" * 44,
                command_journal_path=run / "journal.sqlite3", join_transport_key="f" * 44,
                remote={"schema": "nomad.product-host.remote-bootstrap.v1"},
                host_identity_scope="diagnostic-ephemeral-local",
                host_identity_root=identity_root,
            )
            worker.join(); parent.close(); child.close(); listener[0].close()
            launcher._cleanup_product_host_socket(socket_path)
            self.assertEqual(observed["schema"], "nomad.product-host.bootstrap.v3")
            self.assertEqual(observed["host_identity_scope"], "diagnostic-ephemeral-local")
            self.assertEqual(observed["host_identity_root"], str(identity_root))
            self.assertNotIn("host_identity_scope", observed["remote"])

    def test_diagnostic_identity_root_is_run_owned_and_cleanup_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary) / "run"
            run.mkdir(mode=0o700)
            root = launcher._prepare_diagnostic_identity_root(run, "a" * 64)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(root.parent.resolve(), run.resolve())
            (root / "private").mkdir(mode=0o700)
            secret = root / "private" / "host-device-identity.json"
            secret.write_bytes(b"diagnostic")
            os.chmod(secret, 0o600)
            launcher._safe_remove_tree(root, root=run.resolve())
            self.assertFalse(root.exists())

    def test_diagnostic_remote_state_uses_exact_remote_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary) / "run"
            run.mkdir(mode=0o700)
            root = launcher._prepare_diagnostic_identity_root(run, "a" * 64)
            remote = root / "remote"
            registry = launcher._prepare_device_registry_path_in_directory(remote)
            persistent = launcher._persistent_remote_paths_in_directory(remote)
            self.assertEqual(registry.parent, remote)
            self.assertTrue(all(path.parent == remote for path in persistent.values()))
            self.assertNotIn("private", registry.relative_to(root).parts)

    def test_stop_cleanup_removes_diagnostic_identity_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            state.initialize_home(config)
            run = config.home / "run"
            run.mkdir(mode=0o700)
            run_id = "a" * 64
            identity_root = launcher._prepare_diagnostic_identity_root(run, run_id)
            current = {
                "mode": "remote-loopback-diagnostic", "run_id": run_id,
                "product_host_socket_identity": {}, "processes": [],
            }
            with (
                mock.patch.object(launcher, "_cleanup_product_host_socket"),
                mock.patch.object(launcher, "_cleanup_command_journal"),
                mock.patch.object(launcher, "_cleanup_gateway_db"),
            ):
                launcher._cleanup_run_artifacts(config, current)
            self.assertFalse(identity_root.exists())

    def test_stop_reaps_diagnostic_run_artifacts_and_waits_all_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            state.initialize_home(config)
            run, logs = config.home / "run", config.home / "logs"
            run.mkdir(mode=0o700); logs.mkdir(mode=0o700)
            run_id = "a" * 64
            identity_root = launcher._prepare_diagnostic_identity_root(run, run_id)
            runtime = run / f"agent-runtime-{run_id}"
            runtime.mkdir(mode=0o700)
            process_records = []
            for index, name in enumerate((
                "relay-host", "relay-device", "opencode", "product-host",
                "desktop-gateway", "join-gateway", "https-ingress",
            )):
                log = logs / f"{name}-{run_id}.log"
                log.write_bytes(b"")
                os.chmod(log, 0o600)
                process_records.append({
                    "name": name, "pid": index + 10,
                    "process_group": index + 10, "identity": f"{index + 1:064x}",
                    "log": str(log),
                })
            current = {
                "mode": "remote-loopback-diagnostic", "run_id": run_id,
                "pairing_public_origin": "https://127.0.0.1:18443",
                "product_host_socket_identity": {}, "processes": process_records,
                **{name: getattr(config, name) for name in (
                    "relay_port", "relay_device_v1_port", "relay_host_v2_port",
                    "relay_device_v2_port", "relay_admin_port", "gateway_port",
                    "join_gateway_port", "agent_port",
                )},
            }
            with (
                mock.patch.object(launcher, "read_run_state", return_value=current),
                mock.patch.object(launcher.processes, "ownership", return_value="gone"),
                mock.patch.object(launcher, "_cleanup_product_host_socket"),
                mock.patch.object(launcher, "_cleanup_command_journal"),
                mock.patch.object(launcher, "_cleanup_gateway_db"),
                mock.patch.object(launcher, "_wait_ports_free") as wait_ports,
            ):
                stopped = launcher._stop_unlocked(config)
            self.assertEqual(stopped["state"], "STOPPED")
            self.assertFalse(identity_root.exists())
            self.assertFalse(runtime.exists())
            self.assertTrue(all(not Path(item["log"]).exists() for item in process_records))
            self.assertEqual(
                set(wait_ports.call_args.args[0]),
                {
                    config.relay_port, config.relay_device_v1_port,
                    config.relay_host_v2_port, config.relay_device_v2_port,
                    config.relay_admin_port, config.gateway_port,
                    config.join_gateway_port, config.agent_port, 18443,
                },
            )

    def test_diagnostic_never_touches_lifecycle_coordinator_or_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = root / "lifecycle-journal"
            journal.write_bytes(b"accepted-journal-sentinel")
            before = (journal.stat().st_ino, journal.read_bytes())
            source = Path(launcher.__file__).read_text(encoding="utf-8")
            self.assertIn("if not policy.diagnostic_only:", source)
            self.assertIn("lifecycle_coordinator.spawn_worker", source)
            state_value = {"mode": "remote-loopback-diagnostic", "lifecycle_coordinator": None}
            self.assertIsNone(state_value["lifecycle_coordinator"])
            self.assertEqual((journal.stat().st_ino, journal.read_bytes()), before)

    def test_desktop_gateway_policy_argv_is_exactly_separated(self) -> None:
        diagnostic = launcher._desktop_gateway_policy_argv(
            launcher._LOOPBACK_DIAGNOSTIC_POLICY,
        )
        self.assertEqual(diagnostic, ["--diagnostic-loopback"])
        self.assertEqual(diagnostic.count("--diagnostic-loopback"), 1)
        self.assertNotIn("--lifecycle-channel-fd", diagnostic)

        accepted = launcher._desktop_gateway_policy_argv(
            launcher._ACCEPTED_REMOTE_POLICY,
        )
        self.assertEqual(accepted, ["--lifecycle-channel-fd", "12"])
        self.assertNotIn("--diagnostic-loopback", accepted)

        self.assertEqual(
            launcher._ingress_policy_argv(launcher._LOOPBACK_DIAGNOSTIC_POLICY),
            ["--diagnostic-loopback"],
        )
        self.assertEqual(
            launcher._ingress_policy_argv(launcher._ACCEPTED_REMOTE_POLICY),
            [],
        )

    def test_diagnostic_wrapper_closes_owned_fds_on_base_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            workspace = root / "workspace"; workspace.mkdir()
            descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(3)]
            with (
                mock.patch.object(launcher, "_preflight_remote_agent"),
                mock.patch.object(launcher, "_validate_remote_inputs", return_value=("https://127.0.0.1:8443", "127.0.0.1:8443", [])),
                mock.patch.object(launcher, "initialize_home"),
                mock.patch.object(launcher, "lifecycle_lock") as lock,
                mock.patch.object(launcher, "_start_remote_unlocked", side_effect=KeyboardInterrupt),
            ):
                lock.return_value.__enter__.return_value = True
                with self.assertRaises(KeyboardInterrupt):
                    launcher.start_remote_loopback_diagnostic(
                        config, config.bundle_root, workspace, "OPENAI_API_KEY",
                        descriptors[0], "https://127.0.0.1:8443",
                        "127.0.0.1:8443", descriptors[1], descriptors[2],
                    )
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_remote_rollback_handles_base_exception_and_reaps_reverse_order(self) -> None:
        children = [
            {"name": name, "pid": index + 10}
            for index, name in enumerate(("relay-host", "opencode", "https-ingress"))
        ]
        stopped = []
        with (
            mock.patch.object(launcher.processes, "stop", side_effect=lambda child: stopped.append(child["name"]) or True),
            mock.patch.object(launcher, "_cleanup_product_host_socket"),
            mock.patch.object(launcher, "_cleanup_gateway_db"),
            mock.patch.object(launcher, "_cleanup_command_journal"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                launcher._rollback_remote_start(
                    KeyboardInterrupt(), children, product_host_socket_path=None,
                    product_host_socket_identity=None, desktop_db_path=None,
                    command_journal_path=None, relay_v1_paths=(Path("/missing-a"), Path("/missing-b")),
                    run_dir=Path("/tmp"), diagnostic_identity_root=None,
                )
        self.assertEqual(stopped, ["https-ingress", "opencode", "relay-host"])

    def test_remote_rollback_accepts_child_that_already_exited(self) -> None:
        children = [{"name": "https-ingress", "pid": 42}]
        with (
            mock.patch.object(launcher.processes, "stop", return_value=False),
            mock.patch.object(launcher.processes, "ownership", return_value="absent"),
            mock.patch.object(launcher, "_cleanup_product_host_socket"),
            mock.patch.object(launcher, "_cleanup_gateway_db"),
            mock.patch.object(launcher, "_cleanup_command_journal"),
        ):
            with self.assertRaisesRegex(RuntimeError, "INGRESS_READY_INVALID"):
                launcher._rollback_remote_start(
                    RuntimeError("INGRESS_READY_INVALID"), children,
                    product_host_socket_path=None,
                    product_host_socket_identity=None, desktop_db_path=None,
                    command_journal_path=None,
                    relay_v1_paths=(Path("/missing-a"), Path("/missing-b")),
                    run_dir=Path("/tmp"), diagnostic_identity_root=None,
                )

    def test_diagnostic_rollback_removes_pre_ready_host_socket_after_reap(self) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            home = Path(temporary) / "home"
            run = home / "run"
            run.mkdir(parents=True, mode=0o700)
            run_id = "a" * 64
            diagnostic_root = launcher._prepare_diagnostic_identity_root(
                run, run_id,
            )
            socket_path = launcher._prepare_product_host_socket(home, run_id)
            expected_parent = launcher._socket_parent_identity(socket_path)
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o600)
            listener.close()
            with (
                mock.patch.object(launcher.processes, "stop", return_value=False),
                mock.patch.object(launcher.processes, "ownership", return_value="absent"),
                mock.patch.object(launcher, "_cleanup_gateway_db"),
                mock.patch.object(launcher, "_cleanup_command_journal"),
            ):
                with self.assertRaisesRegex(RuntimeError, "HOST_READY_INVALID"):
                    launcher._rollback_remote_start(
                        RuntimeError("HOST_READY_INVALID"),
                        [{"name": "product-host", "pid": 42}],
                        product_host_socket_path=socket_path,
                        product_host_socket_identity=expected_parent,
                        desktop_db_path=None, command_journal_path=None,
                        relay_v1_paths=(run / "missing-a", run / "missing-b"),
                        run_dir=run, diagnostic_identity_root=diagnostic_root,
                    )
            self.assertFalse(socket_path.parent.exists())
            self.assertFalse(diagnostic_root.exists())

    def test_injected_desktop_failure_removes_all_run_scoped_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            run, logs = home / "run", home / "logs"
            run.mkdir(parents=True, mode=0o700); logs.mkdir(mode=0o700)
            run_id = "f" * 64
            identity_root = launcher._prepare_diagnostic_identity_root(run, run_id)
            runtime = run / f"agent-runtime-{run_id}"
            runtime.mkdir(mode=0o700)
            log_paths = tuple(
                logs / f"{name}-{run_id}.log"
                for name in (
                    "relay-host", "relay-device", "agent", "product-host",
                    "desktop-gateway", "join-gateway", "https-ingress",
                )
            )
            for path in log_paths:
                path.write_bytes(b"")
                os.chmod(path, 0o600)
            children = [
                {"name": name, "pid": index + 20}
                for index, name in enumerate(("relay-host", "relay-device", "opencode", "product-host"))
            ]
            with (
                mock.patch.object(launcher.processes, "stop", return_value=True),
                mock.patch.object(launcher, "_cleanup_product_host_socket"),
                mock.patch.object(launcher, "_cleanup_gateway_db"),
                mock.patch.object(launcher, "_cleanup_command_journal"),
            ):
                with self.assertRaisesRegex(RuntimeError, "DESKTOP_GATEWAY_NOT_READY"):
                    launcher._rollback_remote_start(
                        RuntimeError("DESKTOP_GATEWAY_NOT_READY"), children,
                        product_host_socket_path=None, product_host_socket_identity=None,
                        desktop_db_path=None, command_journal_path=None,
                        relay_v1_paths=(run / "relay-host-v1.sqlite3", run / "relay-device-v1.sqlite3"),
                        run_dir=run, diagnostic_identity_root=identity_root,
                        diagnostic_agent_runtime=runtime, diagnostic_logs=log_paths,
                        logs_dir=logs,
                    )
            self.assertFalse(identity_root.exists())
            self.assertFalse(runtime.exists())
            self.assertFalse(any(path.exists() for path in log_paths))
            self.assertFalse(any(run_id in path.name for path in (*run.iterdir(), *logs.iterdir())))

    def test_diagnostic_state_schema_cannot_be_upgraded_to_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            state.initialize_home(config)
            for name in ("run", "logs"):
                (config.home / name).mkdir(mode=0o700, exist_ok=True)
            processes = [
                {
                    "name": name, "pid": index + 10,
                    "process_group": index + 10, "identity": f"{index + 1:064x}",
                    "log": str(config.home / "logs" / f"{name}.log"),
                }
                for index, name in enumerate((
                    "relay-host", "relay-device", "opencode", "product-host",
                    "desktop-gateway", "join-gateway", "https-ingress",
                ))
            ]
            socket_identity = {
                "parent_dev": 1, "parent_ino": 2, "parent_uid": os.geteuid(),
                "parent_mode": 0o700, "socket_dev": 3, "socket_ino": 4,
                "socket_uid": os.geteuid(), "socket_mode": 0o600,
            }
            value = {
                "schema": state.DIAGNOSTIC_STATE_SCHEMA,
                "mode": "remote-loopback-diagnostic",
                "real_agent_enabled": True, "remote_enabled": True,
                "diagnostic_only": True, "accepted_eligible": False,
                "identity_scope": "diagnostic-ephemeral-local",
                "tls_scope": "self-signed-spki-diagnostic",
                "external_gates": [{"gate": gate, "status": "NOT_RUN"} for gate in launcher.DIAGNOSTIC_EXTERNAL_GATES],
                "bundle_digest": "a" * 64,
                "blocked_on": ["PRODUCTION_EXTERNAL_TOPOLOGY", "PHYSICAL_PHONE_EVIDENCE", "PROVIDER_E3_EVIDENCE"],
                "desktop_url": f"http://127.0.0.1:{config.gateway_port}/",
                "pairing_public_origin": "https://127.0.0.1:8443",
                "pairing_ready": True, "remote_mailbox_ready": True,
                "network_scope": "loopback_diagnostic", "production_external": False,
                "agent_origin": f"http://127.0.0.1:{config.agent_port}",
                "agent_version": "1.18.16", "logs_dir": str(config.home / "logs"),
                "relay_port": config.relay_port, "gateway_port": config.gateway_port,
                "agent_port": config.agent_port, "join_gateway_port": config.join_gateway_port,
                "relay_host_v2_port": config.relay_host_v2_port,
                "relay_device_v2_port": config.relay_device_v2_port,
                "relay_admin_port": config.relay_admin_port,
                "relay_device_v1_port": config.relay_device_v1_port,
                "processes": processes, "run_id": "b" * 64,
                "lifecycle_coordinator": None,
                "session_alias": "sess-" + "d" * 32,
                "workspace_binding_digest": "e" * 64,
                "product_host_socket_identity": socket_identity,
                "identity": {
                    "installed": {"availability": "NOT_RUN", "bundle_digest": None, "install_sequence": None, "install_identity": None},
                    "running": {"availability": "NOT_RUN", "bundle_digest": None, "run_id": None, "process_commitment": None, "socket_commitment": None, "run_identity": None},
                    "host_public_commitment": {"availability": "NOT_RUN", "commitment": None},
                    "paired_device": {"availability": "NOT_RUN", "device_key_commitment": None, "pairing_epoch": None},
                },
            }
            state.validate_run_state(config, value)
            serialized = json.dumps(value, sort_keys=True)
            self.assertNotIn('"status": "PASS"', serialized)
            self.assertNotIn('"status": "READY"', serialized)
            self.assertNotIn('"status": "ACCEPTED"', serialized)
            self.assertNotIn('"tls_verified": true', serialized)
            for mutation in (
                {"mode": "remote-local-evidence"},
                {"accepted_eligible": True},
                {"diagnostic_only": False},
                {"network_scope": "lan_direct"},
                {"production_external": True},
            ):
                candidate = {**value, **mutation}
                with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, "INVALID_STATE"):
                    state.validate_run_state(config, candidate)
            accepted = dict(value)
            accepted["schema"] = state.REMOTE_STATE_SCHEMA
            with self.assertRaisesRegex(RuntimeError, "INVALID_STATE"):
                state.validate_run_state(config, accepted)

    def test_accepted_state_contract_has_no_diagnostic_keys(self) -> None:
        self.assertTrue(state.REMOTE_RUN_KEYS.isdisjoint({
            "diagnostic_only", "accepted_eligible", "identity_scope",
            "tls_scope", "external_gates",
        }))
        self.assertNotEqual(state.REMOTE_STATE_SCHEMA, state.DIAGNOSTIC_STATE_SCHEMA)
        forged = launcher._RemoteLaunchPolicy(
            mode="remote-local-evidence", loopback_only=True,
            identity_scope=launcher.HOST_IDENTITY_SCOPE_LOCAL_INSTALLED,
            diagnostic_only=True, accepted_eligible=True, network_scope="lan_direct",
        )
        with self.assertRaisesRegex(RuntimeError, "REMOTE_POLICY_INVALID"):
            launcher._validate_remote_inputs(
                self.config(Path("/tmp")), public_origin=None, https_listen=None,
                tls_cert_fd=None, tls_key_fd=None, policy=forged,
            )

    def test_resume_aggregator_rejects_diagnostic_classification_first(self) -> None:
        for evidence in (
            {"mode": "remote-loopback-diagnostic"},
            {"diagnostic_only": True},
            {"accepted_eligible": False},
        ):
            with self.subTest(evidence=evidence), self.assertRaisesRegex(
                evidence_resume.EvidenceResumeError, "DIAGNOSTIC_EVIDENCE_FORBIDDEN",
            ):
                evidence_resume._validate_common_evidence(evidence, {}, {})


if __name__ == "__main__":
    unittest.main()
