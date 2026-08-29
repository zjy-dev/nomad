from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import launcher, state


def config(root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        home=root / "home",
        repo_root=root,
        relay_port=18081,
        gateway_port=14173,
        agent_port=4096,
        join_gateway_port=14174,
        relay_host_v2_port=18082,
        relay_device_v2_port=18083,
        relay_admin_port=18084,
        relay_device_v1_port=18085,
    )


class Phase8IdentityTests(unittest.TestCase):
    def test_foundation_state_identity_is_not_run_or_unavailable_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = config(root)
            state.initialize_home(cfg)
            for name in ("bin", "run", "logs"):
                (cfg.home / name).mkdir(mode=0o700)
            value = {
                "schema": state.STATE_SCHEMA,
                "mode": "foundation-readonly",
                "real_agent_enabled": False,
                "blocked_on": ["B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY"],
                "bundle_digest": None,
                "web_url": f"http://127.0.0.1:{cfg.gateway_port}/",
                "agent_origin": None,
                "agent_version": None,
                "logs_dir": str(cfg.home / "logs"),
                "relay_port": cfg.relay_port,
                "gateway_port": cfg.gateway_port,
                "agent_port": cfg.agent_port,
                "processes": [
                    {"name": "relay", "pid": 101, "process_group": 101, "identity": "1" * 64, "log": str(cfg.home / "logs" / "relay.log")},
                    {"name": "gateway", "pid": 102, "process_group": 102, "identity": "2" * 64, "log": str(cfg.home / "logs" / "gateway.log")},
                ],
                "run_id": None,
                "session_alias": None,
                "workspace_binding_digest": None,
                "product_host_socket_identity": None,
                "identity": {
                    "installed": {
                        "availability": "NOT_RUN",
                        "bundle_digest": None,
                        "install_sequence": None,
                        "install_identity": None,
                    },
                    "running": {
                        "availability": "NOT_RUN",
                        "bundle_digest": None,
                        "run_id": None,
                        "process_commitment": None,
                        "socket_commitment": None,
                        "run_identity": None,
                    },
                    "host_public_commitment": {"availability": "NOT_RUN", "commitment": None},
                    "paired_device": {"availability": "NOT_RUN", "device_key_commitment": None, "pairing_epoch": None},
                },
            }
            state.write_run_state(cfg, value)
            observed = state.read_run_state(cfg)
            assert observed is not None
            self.assertEqual(observed["identity"]["host_public_commitment"]["availability"], "NOT_RUN")
            self.assertEqual(observed["identity"]["paired_device"]["availability"], "NOT_RUN")

    def test_paired_device_identity_reads_authority_db_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = config(root)
            state.initialize_home(cfg)
            private = cfg.home / launcher.DEVICE_REGISTRY_DIRNAME
            private.mkdir(mode=0o700)
            os.chmod(private, 0o700)
            database = private / launcher.DEVICE_REGISTRY_BASENAME
            connection = sqlite3.connect(database)
            try:
                connection.executescript(
                    """
                    CREATE TABLE device_registry (
                        row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_alias TEXT NOT NULL,
                        principal_alias TEXT NOT NULL,
                        signing_key_digest BLOB NOT NULL,
                        agreement_key_digest BLOB NOT NULL,
                        state TEXT NOT NULL,
                        activated_epoch INTEGER NOT NULL,
                        revoked_epoch INTEGER,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                connection.execute(
                    """
                    INSERT INTO device_registry (
                        device_alias, principal_alias, signing_key_digest,
                        agreement_key_digest, state, activated_epoch, revoked_epoch,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', ?, NULL, ?, ?)
                    """,
                    (
                        "device-1",
                        "principal-1",
                        bytes.fromhex("11" * 32),
                        bytes.fromhex("22" * 32),
                        7,
                        "2026-08-29T00:00:00Z",
                        "2026-08-29T00:00:00Z",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            os.chmod(database, 0o600)
            paired = launcher._paired_device_identity(cfg.home, "official-agent-local")
            self.assertEqual(paired["availability"], "READY")
            self.assertEqual(paired["pairing_epoch"], 7)
            self.assertRegex(paired["device_key_commitment"], r"^[0-9a-f]{64}$")

    def test_paired_device_schema_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = config(root)
            state.initialize_home(cfg)
            private = cfg.home / launcher.DEVICE_REGISTRY_DIRNAME
            private.mkdir(mode=0o700)
            os.chmod(private, 0o700)
            database = private / launcher.DEVICE_REGISTRY_BASENAME
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE device_registry (unexpected INTEGER)")
                connection.commit()
            finally:
                connection.close()
            os.chmod(database, 0o600)
            with self.assertRaisesRegex(RuntimeError, "PAIRED_DEVICE_IDENTITY_SCHEMA_MISMATCH"):
                launcher._paired_device_identity(cfg.home, "official-agent-local")

    def test_paired_device_identity_not_run_when_private_registry_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = config(root)
            state.initialize_home(cfg)
            paired = launcher._paired_device_identity(cfg.home, "official-agent-local")
            self.assertEqual(
                paired,
                {
                    "availability": "NOT_RUN",
                    "device_key_commitment": None,
                    "pairing_epoch": None,
                },
            )

    def test_processes_module_does_not_need_phase8_changes(self) -> None:
        source = Path(launcher.processes.__file__).read_text(encoding="utf-8")
        self.assertIn("def process_identity(pid: int) -> str:", source)
        self.assertIn("return hashlib.sha256(result.stdout).hexdigest()", source)
        self.assertNotIn("host_public_commitment", source)


if __name__ == "__main__":
    unittest.main()
