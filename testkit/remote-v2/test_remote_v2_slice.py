from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("run_remote_v2_slice.py")
SPEC = importlib.util.spec_from_file_location("run_remote_v2_slice", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class RemoteV2HarnessTests(unittest.TestCase):
    def test_canonical_json_is_single_stable_line(self) -> None:
        self.assertEqual(harness.canonical_json({"z": 1, "a": 2}), b'{"a":2,"z":1}')

    def test_private_root_and_provision_modes_and_shape(self) -> None:
        root = harness._private_root()
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        provision_path, secrets = harness.make_provision(root)
        self.assertEqual(stat.S_IMODE(provision_path.stat().st_mode), 0o600)
        value = json.loads(provision_path.read_bytes())
        self.assertEqual(
            set(value),
            {
                "device_key_commitment", "device_token_digest", "epoch",
                "host_identity_commitment", "host_token_digest", "mailbox_id",
            },
        )
        self.assertNotIn(secrets["host_bearer"], provision_path.read_text())
        self.assertNotIn(secrets["device_bearer"], provision_path.read_text())
        self.assertEqual(value["mailbox_id"], secrets["mailbox_id"])
        vector = json.loads(harness.VECTOR_PATH.read_bytes())
        self.assertEqual(value["epoch"], vector["frame"]["epoch"])
        self.assertEqual(value["host_identity_commitment"], vector["host_signing_commitment"])
        self.assertEqual(value["device_key_commitment"], vector["device_signing_commitment"])

    def test_private_file_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "value.json"
            harness._exclusive_private_json(path, {"one": 1})
            with self.assertRaises(FileExistsError):
                harness._exclusive_private_json(path, {"two": 2})
            self.assertEqual(path.read_bytes(), b'{"one":1}')

    def test_private_copy_is_exclusive_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.write_bytes(b"state")
            destination = root / "destination"
            harness._exclusive_private_copy(source, destination)
            self.assertEqual(destination.read_bytes(), b"state")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                harness._exclusive_private_copy(source, destination)

    def test_child_env_drops_provider_names_without_reading_values(self) -> None:
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "secret-canary", "PATH": "/bin"}, clear=True):
            env = harness.sanitized_child_env({"NOMAD_TEST": "ok"})
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["NOMAD_TEST"], "ok")

    def test_preflight_blocks_until_both_real_helpers_exist(self) -> None:
        with mock.patch.object(harness, "RUST_SOURCE", Path("/definitely/missing/rust")), mock.patch.object(
            harness, "NODE_HELPER", Path("/definitely/missing/node")
        ):
            result = harness.helper_preflight()
        self.assertEqual(result["status"], "BLOCKED_HELPERS_REQUIRED")
        self.assertEqual(result["provider"], "NOT_RUN")
        self.assertEqual(result["physical_phone"], "NOT_RUN")

    def test_run_has_no_synthetic_fallback(self) -> None:
        with mock.patch.object(
            harness, "helper_preflight", return_value={"status": "BLOCKED_HELPERS_REQUIRED"}
        ):
            with self.assertRaisesRegex(harness.HarnessError, "required_real_process_helpers_missing"):
                harness.run_slice()

    def test_success_evidence_never_claims_provider_phone_or_production(self) -> None:
        source = MODULE_PATH.read_text()
        self.assertIn('"provider": "NOT_RUN"', source)
        self.assertIn('"physical_phone": "NOT_RUN"', source)
        self.assertIn('"production_ready": False', source)
        self.assertIn('"relay_processes": 2', source)
        self.assertIn('"restart_cursor": "VERIFIED"', source)
        self.assertIn('"pending_restart": "VERIFIED"', source)
        self.assertIn('"wrong_role": "VERIFIED"', source)

    def test_relay_commands_fix_roles_and_only_host_provisions(self) -> None:
        base = dict(
            binary=Path("/private/relay"), legacy_port=1001, v2_port=1002,
            legacy_db=Path("/private/v1.db"), v2_db=Path("/private/shared.db"),
        )
        host = harness.relay_command(
            **base, role="host", provision_file=Path("/private/provision.json")
        )
        device = harness.relay_command(**base, role="device", provision_file=None)
        self.assertEqual(host[host.index("--v2-role") + 1], "host")
        self.assertEqual(device[device.index("--v2-role") + 1], "device")
        self.assertIn("--v2-provision-file", host)
        self.assertNotIn("--v2-provision-file", device)
        self.assertIn("--v2-loopback-test-http", host)

    def test_invalid_relay_role_is_rejected(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "invalid_relay_role"):
            harness.relay_command(
                Path("/relay"), role="both", legacy_port=1, v2_port=2,
                legacy_db=Path("/v1"), v2_db=Path("/v2"), provision_file=None,
            )

    def test_helper_commands_keep_bearers_out_of_argv(self) -> None:
        seen: list[tuple[list[str], dict[str, str]]] = []

        def fake(command, *, env, cwd, expect_success=True):
            seen.append((command, dict(env)))
            return {"status": "OK"}

        with mock.patch.object(harness, "_run_json_child", side_effect=fake):
            harness.run_host_phase(
                Path("/host"), "revoke", "http://127.0.0.1:1", Path("/state"), "host-secret"
            )
            harness.run_device_phase(
                "consume-receipt", "http://127.0.0.1:2", Path("/state2"), "device-secret"
            )
        flat_argv = " ".join(word for command, _ in seen for word in command)
        self.assertNotIn("host-secret", flat_argv)
        self.assertNotIn("device-secret", flat_argv)
        self.assertEqual(seen[0][1]["NOMAD_REMOTE_V2_HOST_TOKEN"], "host-secret")
        self.assertEqual(seen[1][1]["NOMAD_REMOTE_V2_DEVICE_TOKEN"], "device-secret")
        self.assertEqual(
            seen[1][0][:3],
            ["node", "--no-warnings", "--experimental-transform-types"],
        )

    def test_temp_root_is_resolved_and_private(self) -> None:
        root = harness._private_root()
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        self.assertEqual(root, root.resolve(strict=True))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
