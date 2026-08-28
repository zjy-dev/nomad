from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import importlib.util

_SPEC = importlib.util.spec_from_file_location("provider_e3_runner", Path(__file__).with_name("run_provider_e3.py"))
e3 = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(e3)


def manifest() -> dict[str, str | bool]:
    return {
        "bundle_digest": "sha256:" + "a" * 64,
        "source_commit_oid": "b" * 40,
        "launcher_version": "1.0.0",
        "classification": "release",
    }


def running_state() -> dict[str, object]:
    return {
        "schema": "nomad.web-companion.state.v2",
        "mode": "remote-local-evidence",
        "real_agent_enabled": True,
        "remote_enabled": True,
        "blocked_on": ["PRODUCTION_DEVICE_IDENTITY"],
        "desktop_url": "http://127.0.0.1:14173/",
        "pairing_public_origin": "https://192.168.100.3:18443",
        "pairing_ready": True,
        "remote_mailbox_ready": True,
        "network_scope": "lan_direct",
        "production_external": False,
        "agent_origin": "http://127.0.0.1:4096",
        "agent_version": "1.18.16",
        "logs_dir": "/tmp/provider-e3/logs",
        "relay_port": 18089,
        "gateway_port": 14173,
        "agent_port": 4096,
        "join_gateway_port": 14174,
        "relay_host_v2_port": 18090,
        "relay_device_v2_port": 18091,
        "relay_admin_port": 18092,
        "relay_device_v1_port": 18093,
        "processes": [
            {"name": "relay-host", "pid": 101, "process_group": 101, "identity": "1" * 64, "log": "/tmp/provider-e3/logs/relay-host.log"},
            {"name": "relay-device", "pid": 102, "process_group": 102, "identity": "2" * 64, "log": "/tmp/provider-e3/logs/relay-device.log"},
            {"name": "opencode", "pid": 103, "process_group": 103, "identity": "3" * 64, "log": "/tmp/provider-e3/logs/opencode.log"},
            {"name": "product-host", "pid": 104, "process_group": 104, "identity": "4" * 64, "log": "/tmp/provider-e3/logs/product-host.log"},
            {"name": "desktop-gateway", "pid": 105, "process_group": 105, "identity": "5" * 64, "log": "/tmp/provider-e3/logs/desktop-gateway.log"},
            {"name": "join-gateway", "pid": 106, "process_group": 106, "identity": "6" * 64, "log": "/tmp/provider-e3/logs/join-gateway.log"},
            {"name": "https-ingress", "pid": 107, "process_group": 107, "identity": "7" * 64, "log": "/tmp/provider-e3/logs/https-ingress.log"},
        ],
        "run_id": "8" * 64,
        "session_alias": "sess-" + "9" * 32,
        "workspace_binding_digest": "a" * 64,
        "product_host_socket_identity": {
            "parent_dev": 1, "parent_ino": 2, "parent_uid": 501, "parent_mode": 0o700,
            "socket_dev": 3, "socket_ino": 4, "socket_uid": 501, "socket_mode": 0o600,
        },
    }


class ProviderE3HarnessTests(unittest.TestCase):
    def test_credential_reader_rejects_newline_and_overflow(self):
        self.assertEqual(e3._read_credential(io.BytesIO(b"secret\n")), bytearray())
        self.assertEqual(e3._read_credential(io.BytesIO(b"x" * 16385)), bytearray())
        self.assertEqual(e3._read_credential(io.BytesIO(b"secret")), bytearray(b"secret"))

    def test_secret_scan_is_content_free(self):
        findings = e3.scan_text("OPENAI_API_KEY=super-secret", ("super-secret",))
        self.assertEqual(findings, ["SECRET_SHAPED_TEXT_PRESENT", "SECRET_VALUE_PRESENT"])
        self.assertNotIn("super-secret", json.dumps(findings))
        self.assertEqual(e3.scan_argv(["nomad-web", "--json", "start"], ("super-secret",)), [])
        self.assertTrue(e3.scan_json({"argv": ["OPENAI_API_KEY=secret"]})[0].startswith("SECRET_"))
        self.assertEqual(e3.scan_artifacts(["nomad-web"], {"state": "RUNNING"}, {"status": "NOT_RUN"}, ("super-secret",)), [])

    def test_allowlist_and_missing_credential_short_circuit(self):
        with mock.patch.object(e3, "verify_bundle", side_effect=AssertionError("must not inspect")):
            blocked = e3.run_provider_e3(
                Path("bundle"), "BAD_PROVIDER", bytearray(b"x"), Path("workspace"),
                public_origin=None, https_listen=None, tls_cert_fd=None, tls_key_fd=None,
            )
            missing = e3.run_provider_e3(
                Path("bundle"), "OPENAI_API_KEY", bytearray(), Path("workspace"),
                public_origin=None, https_listen=None, tls_cert_fd=None, tls_key_fd=None,
            )
        self.assertEqual(blocked["status"], "BLOCK")
        self.assertEqual(blocked["reason"], "PROVIDER_NOT_ALLOWLISTED")
        self.assertEqual(missing["status"], "NOT_RUN")
        self.assertEqual(missing["reason"], "CREDENTIAL_MISSING_OR_INVALID")

    def test_identity_preflight_block_prevents_runtime_start(self):
        with mock.patch.object(e3, "verify_bundle", return_value=manifest()), mock.patch.object(
            e3, "host_identity_preflight", return_value={"ready": False, "error_code": "HOST_IDENTITY_AUTH_REQUIRED", "next_step": "nomad-web authorize-host-identity"}
        ), mock.patch.object(e3, "_start_command") as start:
            result = e3.run_provider_e3(
                Path("bundle"), "OPENAI_API_KEY", bytearray(b"secret"), Path("workspace"),
                public_origin=None, https_listen=None, tls_cert_fd=None, tls_key_fd=None,
            )
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(result["reason"], "HOST_IDENTITY_AUTH_REQUIRED")
        self.assertEqual(result["next_step"], "nomad-web authorize-host-identity")
        start.assert_not_called()

    def test_missing_operator_tls_inputs_block_before_runtime_start(self):
        with mock.patch.object(e3, "verify_bundle", return_value=manifest()), mock.patch.object(
            e3, "host_identity_preflight", return_value={"ready": True, "status": "READY"}
        ), mock.patch.object(e3, "_start_command") as start:
            with self.assertRaisesRegex(e3.ProviderE3Error, "REMOTE_TLS_OPERATOR_INPUTS_REQUIRED"):
                e3.run_provider_e3(
                    Path("bundle"), "OPENAI_API_KEY", bytearray(b"secret"), Path("workspace"),
                    public_origin=None, https_listen=None, tls_cert_fd=None, tls_key_fd=None,
                )
        start.assert_not_called()

    def test_execute_scenarios_marks_all_not_run_without_capability(self):
        client = mock.Mock()
        client.capability.return_value = (503, {"error": "COMMAND_CAPABILITY_UNAVAILABLE"})
        scenarios, summary = e3.execute_scenarios(client)
        self.assertFalse(summary["available"])
        self.assertEqual([item["status"] for item in scenarios], ["NOT_RUN"] * 6)
        self.assertEqual(scenarios[0]["reason_code"], "COMMAND_CAPABILITY_UNAVAILABLE")
        self.assertEqual(scenarios[4]["reason_code"], "NO_SAFE_RECONNECT_TRIGGER")
        self.assertEqual(scenarios[5]["reason_code"], "NO_SAFE_OUTCOME_UNKNOWN_TRIGGER")

    def test_overall_status_requires_exact_six_passes(self):
        self.assertEqual(
            e3._overall_status([{"name": name, "status": "PASS"} for name in e3.SCENARIO_NAMES]),
            "PASS",
        )
        mixed = [{"name": e3.SCENARIO_NAMES[0], "status": "PASS"}] + [
            {"name": name, "status": "NOT_RUN"} for name in e3.SCENARIO_NAMES[1:]
        ]
        self.assertEqual(e3._overall_status(mixed), "NOT_RUN")
        with_fail = [{"name": name, "status": "PASS"} for name in e3.SCENARIO_NAMES]
        with_fail[2]["status"] = "FAIL"
        self.assertEqual(e3._overall_status(with_fail), "FAIL")
        with_block = [{"name": name, "status": "PASS"} for name in e3.SCENARIO_NAMES]
        with_block[3]["status"] = "BLOCK"
        self.assertEqual(e3._overall_status(with_block), "BLOCK")

    def test_execute_scenarios_reply_not_run_when_question_missing(self):
        client = mock.Mock()
        client.capability.return_value = (200, {
            "schema": "nomad.gateway.command-capability.v1",
            "csrf_token": "csrf_token_00000001",
            "capability": {
                "schema": "nomad.product-host.command-capability.v1",
                "capability_id": "capability_00000001",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "next_command_seq": 1,
                "issued_at": "2026-08-29T00:00:00Z",
                "expires_at": "2026-08-29T00:00:30Z",
                "view": True,
                "reply": None,
                "deny": None,
                "stop": None,
                "allow_once": False,
            },
        })
        scenarios, _ = e3.execute_scenarios(client)
        self.assertEqual(scenarios[0]["status"], "NOT_RUN")
        self.assertEqual(scenarios[0]["reason_code"], "REAL_QUESTION_NOT_OBSERVED")
        client.command.assert_not_called()

    def test_execute_scenarios_deny_not_run_when_permission_missing(self):
        client = mock.Mock()
        client.capability.return_value = (200, {
            "schema": "nomad.gateway.command-capability.v1",
            "csrf_token": "csrf_token_00000001",
            "capability": {
                "schema": "nomad.product-host.command-capability.v1",
                "capability_id": "capability_00000001",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "next_command_seq": 1,
                "issued_at": "2026-08-29T00:00:00Z",
                "expires_at": "2026-08-29T00:00:30Z",
                "view": True,
                "reply": None,
                "deny": None,
                "stop": {"turn_alias": "turn-" + "1" * 32},
                "allow_once": False,
            },
        })
        client.command.side_effect = [
            (200, {
                "schema": "nomad.gateway.command-receipt.v1",
                "receipt_id": "receipt_00000001",
                "request_id": "provider_e3_stop_0000000000000001",
                "action": "stop",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "accepted_at": "2026-08-29T00:00:00Z",
                "status": "HostAccepted",
                "error_code": "OK",
                "idempotent_replay": False,
            }),
            (200, {
                "schema": "nomad.gateway.command-receipt.v1",
                "receipt_id": "receipt_00000001",
                "request_id": "provider_e3_stop_0000000000000001",
                "action": "stop",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "accepted_at": "2026-08-29T00:00:00Z",
                "status": "HostAccepted",
                "error_code": "OK",
                "idempotent_replay": True,
            }),
        ]
        scenarios, _ = e3.execute_scenarios(client)
        self.assertEqual(scenarios[1]["status"], "NOT_RUN")
        self.assertEqual(scenarios[1]["reason_code"], "REAL_PERMISSION_NOT_OBSERVED")

    def test_execute_scenarios_stop_not_run_when_capability_missing(self):
        client = mock.Mock()
        client.capability.return_value = (200, {
            "schema": "nomad.gateway.command-capability.v1",
            "csrf_token": "csrf_token_00000001",
            "capability": {
                "schema": "nomad.product-host.command-capability.v1",
                "capability_id": "capability_00000001",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "next_command_seq": 1,
                "issued_at": "2026-08-29T00:00:00Z",
                "expires_at": "2026-08-29T00:00:30Z",
                "view": True,
                "reply": None,
                "deny": None,
                "stop": None,
                "allow_once": False,
            },
        })
        scenarios, _ = e3.execute_scenarios(client)
        self.assertEqual(scenarios[2]["status"], "NOT_RUN")
        self.assertEqual(scenarios[2]["reason_code"], "LIVE_STOP_CAPABILITY_NOT_OBSERVED")

    def test_execute_scenarios_duplicate_requires_idempotent_replay(self):
        client = mock.Mock()
        client.capability.return_value = (200, {
            "schema": "nomad.gateway.command-capability.v1",
            "csrf_token": "csrf_token_00000001",
            "capability": {
                "schema": "nomad.product-host.command-capability.v1",
                "capability_id": "capability_00000001",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "next_command_seq": 1,
                "issued_at": "2026-08-29T00:00:00Z",
                "expires_at": "2026-08-29T00:00:30Z",
                "view": True,
                "reply": None,
                "deny": None,
                "stop": {"turn_alias": "turn-" + "1" * 32},
                "allow_once": False,
            },
        })
        client.command.side_effect = [
            (200, {
                "schema": "nomad.gateway.command-receipt.v1",
                "receipt_id": "receipt_00000001",
                "request_id": "provider_e3_stop_0000000000000001",
                "action": "stop",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "accepted_at": "2026-08-29T00:00:00Z",
                "status": "HostAccepted",
                "error_code": "OK",
                "idempotent_replay": False,
            }),
            (200, {
                "schema": "nomad.gateway.command-receipt.v1",
                "receipt_id": "receipt_00000001",
                "request_id": "provider_e3_stop_0000000000000001",
                "action": "stop",
                "snapshot_seq": 1,
                "snapshot_digest": "sha256:" + "a" * 64,
                "accepted_at": "2026-08-29T00:00:00Z",
                "status": "HostAccepted",
                "error_code": "OK",
                "idempotent_replay": True,
            }),
        ]
        scenarios, _ = e3.execute_scenarios(client)
        self.assertEqual(scenarios[3]["status"], "PASS")
        self.assertEqual(scenarios[3]["reason_code"], "REPLAY_IDEMPOTENT")

    def test_execute_scenarios_reconnect_and_outcome_unknown_default_not_run(self):
        client = mock.Mock()
        client.capability.return_value = (503, {"error": "COMMAND_CAPABILITY_UNAVAILABLE"})
        scenarios, _ = e3.execute_scenarios(client)
        self.assertEqual(scenarios[4]["status"], "NOT_RUN")
        self.assertEqual(scenarios[4]["reason_code"], "NO_SAFE_RECONNECT_TRIGGER")
        self.assertEqual(scenarios[5]["status"], "NOT_RUN")
        self.assertEqual(scenarios[5]["reason_code"], "NO_SAFE_OUTCOME_UNKNOWN_TRIGGER")

    def test_direct_agent_writable_shortcut_is_rejected(self):
        with self.assertRaisesRegex(e3.ProviderE3Error, "DIRECT_AGENT_WRITABLE_SHORTCUT_FORBIDDEN"):
            e3.reject_direct_agent_write("http://127.0.0.1:4096/api/session/current", "http://127.0.0.1:4096")

    def test_validate_runtime_state_rejects_invalid_schema(self):
        state = running_state()
        state["schema"] = "nomad.web-companion.state.v1"
        with self.assertRaisesRegex(e3.ProviderE3Error, "LAUNCHER_STATE_INVALID"):
            e3._validate_runtime_state(state)

    def test_validate_runtime_state_rejects_invalid_process_contract(self):
        state = running_state()
        state["processes"] = list(state["processes"])
        state["processes"][3] = dict(state["processes"][3], name="wrong-name")
        with self.assertRaisesRegex(e3.ProviderE3Error, "LAUNCHER_STATE_INVALID"):
            e3._validate_runtime_state(state)

    def test_validate_runtime_state_rejects_duplicate_identity_and_non_loopback_desktop(self):
        state = running_state()
        state["desktop_url"] = "http://192.0.2.10:14173/"
        with self.assertRaisesRegex(e3.ProviderE3Error, "LAUNCHER_STATE_INVALID"):
            e3._validate_runtime_state(state)
        state = running_state()
        state["processes"] = list(state["processes"])
        state["processes"][1] = dict(state["processes"][1], identity=state["processes"][0]["identity"])
        with self.assertRaisesRegex(e3.ProviderE3Error, "LAUNCHER_STATE_INVALID"):
            e3._validate_runtime_state(state)

    def test_write_evidence_is_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "evidence.json"
            e3.write_evidence(target, {"schema": e3.SCHEMA, "status": "NOT_RUN", "reason": "TEST"})
            mode = target.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            with self.assertRaises(FileExistsError):
                e3.write_evidence(target, {"schema": e3.SCHEMA, "status": "NOT_RUN", "reason": "TEST"})

    def test_main_reaches_real_remote_local_evidence_launch_path(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            state = running_state()
            fake_cleanup = {"stop_invoked": True, "state_cleared": True, "owned_processes_stopped": True}
            start_calls: list[list[str]] = []

            def fake_start(bundle: Path, provider: str, workspace: Path, credential: bytearray, env: dict[str, str], public_origin: str, https_listen: str, tls_cert_fd: int, tls_key_fd: int):
                start_calls.append([
                    str(bundle / "bin" / "nomad-web"), "--json", "start",
                    "--provider", provider, "--credential-stdin",
                    "--workspace", str(workspace), "--remote-local-evidence",
                    "--public-origin", public_origin, "--https-listen", https_listen,
                    "--tls-cert-fd", str(tls_cert_fd), "--tls-key-fd", str(tls_key_fd),
                ])
                return start_calls[-1], {"state": "RUNNING"}

            stream = io.StringIO("opaque-provider-secret")
            with mock.patch.object(e3.sys, "stdin", stream), mock.patch.object(
                e3, "verify_bundle", return_value=manifest()
            ), mock.patch.object(
                e3, "host_identity_preflight", return_value={"ready": True, "status": "READY"}
            ), mock.patch.object(
                e3, "_private_root", return_value=Path(directory) / "runtime"
            ), mock.patch.object(
                e3, "_reserved_ports", return_value=(18089, 14173, 4096, 14174, 18090, 18091, 18092, 18093)
            ), mock.patch.object(
                e3, "_start_command", side_effect=fake_start
            ), mock.patch.object(
                e3, "read_run_state", return_value=state
            ), mock.patch.object(
                e3, "execute_scenarios", return_value=(e3._not_run_matrix(), {"http_status": 503, "available": False, "reply": False, "deny": False, "stop": False})
            ), mock.patch.object(
                e3, "_stop_runtime", return_value=fake_cleanup
            ):
                rc = e3.main([
                    "--bundle", str(Path(directory) / "bundle"),
                    "--provider", "OPENAI_API_KEY",
                    "--credential-stdin",
                    "--workspace", directory,
                    "--public-origin", "https://pair.example:18443",
                    "--https-listen", "192.0.2.10:18443",
                    "--tls-cert-fd", "11",
                    "--tls-key-fd", "12",
                    "--evidence", str(evidence),
                ])

            self.assertEqual(rc, 0)
            self.assertTrue(start_calls)
            self.assertIn("--remote-local-evidence", start_calls[0])
            self.assertIn("--tls-cert-fd", start_calls[0])
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(payload["topology"]["process_names"], e3.PROCESS_NAMES)
            self.assertEqual(payload["cleanup"], fake_cleanup)
            self.assertEqual(payload["status"], "NOT_RUN")

    def test_main_invalid_runtime_state_blocks_and_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            invalid = running_state()
            invalid["schema"] = "nomad.web-companion.state.v1"
            fake_cleanup = {"stop_invoked": True, "state_cleared": True, "owned_processes_stopped": True}
            stream = io.StringIO("opaque-provider-secret")

            def fake_start(bundle: Path, provider: str, workspace: Path, credential: bytearray, env: dict[str, str], public_origin: str, https_listen: str, tls_cert_fd: int, tls_key_fd: int):
                return ["start"], {"state": "RUNNING"}

            with mock.patch.object(e3.sys, "stdin", stream), mock.patch.object(
                e3, "verify_bundle", return_value=manifest()
            ), mock.patch.object(
                e3, "host_identity_preflight", return_value={"ready": True, "status": "READY"}
            ), mock.patch.object(
                e3, "_private_root", return_value=Path(directory) / "runtime"
            ), mock.patch.object(
                e3, "_reserved_ports", return_value=(18089, 14173, 4096, 14174, 18090, 18091, 18092, 18093)
            ), mock.patch.object(
                e3, "_start_command", side_effect=fake_start
            ), mock.patch.object(
                e3, "read_run_state", return_value=invalid
            ), mock.patch.object(
                e3, "_stop_runtime", return_value=fake_cleanup
            ):
                rc = e3.main([
                    "--bundle", str(Path(directory) / "bundle"),
                    "--provider", "OPENAI_API_KEY",
                    "--credential-stdin",
                    "--workspace", directory,
                    "--public-origin", "https://pair.example:18443",
                    "--https-listen", "192.0.2.10:18443",
                    "--tls-cert-fd", "11",
                    "--tls-key-fd", "12",
                    "--evidence", str(evidence),
                ])

            self.assertEqual(rc, 2)
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "BLOCK")
            self.assertEqual(payload["reason"], "LAUNCHER_STATE_INVALID")

    def test_main_keeps_credential_out_of_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            stream = io.StringIO("opaque-provider-secret")
            with mock.patch.object(e3.sys, "stdin", stream), mock.patch.object(
                e3, "run_provider_e3", return_value={"schema": e3.SCHEMA, "status": "NOT_RUN", "reason": "TEST", "source_binding": e3.source_binding(), "scenarios": e3._not_run_matrix()}
            ):
                rc = e3.main([
                    "--bundle", str(Path(directory) / "bundle"),
                    "--provider", "OPENAI_API_KEY",
                    "--credential-stdin",
                    "--workspace", directory,
                    "--public-origin", "https://pair.example:18443",
                    "--https-listen", "192.0.2.10:18443",
                    "--tls-cert-fd", "11",
                    "--tls-key-fd", "12",
                    "--evidence", str(evidence),
                ])
            self.assertEqual(rc, 0)
            self.assertNotIn("opaque-provider-secret", evidence.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
