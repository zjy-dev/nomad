from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import diagnostics
from tools.nomad_web import install_lifecycle
from tools.nomad_web import state


class DiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nomad-diagnostics-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        (self.home / "logs").mkdir(parents=True, mode=0o700)
        self.config = SimpleNamespace(home=self.home)
        self.digest = "a" * 64
        self.log = self.home / "logs" / "product-host.log"
        self.log.write_bytes(b"PROVIDER-CREDENTIAL-CANARY\nHOST_IDENTITY_AUTH_REQUIRED\n")
        os.chmod(self.log, 0o600)
        self.installed = {
            "schema": install_lifecycle.STATUS_SCHEMA,
            "state": "INSTALLED",
            "current_bundle_digest": self.digest,
            "bundle_digests": [self.digest],
            "history": [{
                "sequence": 1, "operation": "install",
                "from_bundle_digest": None, "to_bundle_digest": self.digest,
                "state_snapshot_digest": None, "rollback_of_sequence": None,
            }],
        }
        self.onboarding = {
            "schema": install_lifecycle.ONBOARDING_SCHEMA,
            "state": "RUNNING_NEEDS_PAIRING", "production_ready": False,
            "external_readiness": "NOT_RUN",
            "external_gates": [
                {"code": code, "status": "NOT_RUN"}
                for code in install_lifecycle.EXTERNAL_GATES
            ],
            "installed_bundle_digest": self.digest, "install_sequence": 1,
            "run_identity": "1" * 64, "paired_device_commitment": None,
            "pairing_epoch": None, "blockers": ["PAIRED_DEVICE_REQUIRED"],
            "next_action": "PAIR_PHONE",
        }
        self.runtime = {
            "schema": state.REMOTE_STATE_SCHEMA, "mode": "remote-local-evidence",
            "real_agent_enabled": True, "remote_enabled": True,
            "bundle_digest": self.digest, "blocked_on": ["PRODUCTION_DEVICE_IDENTITY"],
            "pairing_ready": True, "remote_mailbox_ready": True,
            "network_scope": "lan_direct",
            "processes": [
                {
                    "name": name, "pid": 123 + index, "process_group": 123 + index,
                    "identity": f"{3 + index:064x}", "log": str(self.log),
                }
                for index, name in enumerate((
                    "relay-host", "relay-device", "opencode", "product-host",
                    "desktop-gateway", "join-gateway", "https-ingress",
                ))
            ],
            "identity": {
                "installed": {
                    "availability": "READY", "bundle_digest": self.digest,
                    "install_sequence": 1, "install_identity": "d" * 64,
                },
                "running": {
                    "availability": "READY", "bundle_digest": self.digest,
                    "process_commitment": "e" * 64,
                    "socket_commitment": "f" * 64, "run_identity": "1" * 64,
                },
                "host_public_commitment": {"availability": "UNAVAILABLE", "commitment": None},
                "paired_device": {"availability": "UNPAIRED", "device_key_commitment": None, "pairing_epoch": None},
            },
        }

    @contextmanager
    def owned_lock(self, *_: object, **__: object):
        yield True

    def collect(self) -> dict[str, object]:
        with mock.patch.object(diagnostics.state, "lifecycle_lock", self.owned_lock), mock.patch.object(
            diagnostics.install_lifecycle, "status_unlocked", return_value=self.installed
        ), mock.patch.object(
            diagnostics.state, "read_run_state", return_value=self.runtime
        ), mock.patch.object(
            diagnostics.install_lifecycle, "onboarding_status_unlocked", return_value=self.onboarding
        ), mock.patch.object(diagnostics.processes, "ownership", return_value="owned"):
            return diagnostics.collect(self.config)

    def test_deterministic_canonical_support_manifest(self) -> None:
        first = self.collect()
        second = self.collect()
        self.assertEqual(first, second)
        diagnostics.verify(first)
        self.assertEqual(first["classification"], diagnostics.CLASSIFICATION)
        self.assertFalse(first["production_ready"])
        self.assertFalse(first["readiness_evidence"])
        self.assertEqual(first["manifest_digest"], hashlib.sha256(
            diagnostics._canonical({key: value for key, value in first.items() if key != "manifest_digest"})
        ).hexdigest())
        rendered = diagnostics._canonical(first)
        self.assertNotIn(b"PROVIDER-CREDENTIAL-CANARY", rendered)
        self.assertEqual(first["logs"][0]["raw_sha256"], hashlib.sha256(self.log.read_bytes()).hexdigest())
        self.assertEqual(len(first["logs"]), 7)

    def test_tampered_manifest_is_rejected(self) -> None:
        value = self.collect()
        value["runtime"]["process_count"] = 99
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_RUNTIME_STATE_INVALID"):
            diagnostics.verify(value)

    def test_incomplete_allowed_key_manifest_is_rejected_even_with_new_digest(self) -> None:
        value = self.collect()
        value["runtime"].pop("network_scope")
        core = {key: item for key, item in value.items() if key != "manifest_digest"}
        value["manifest_digest"] = hashlib.sha256(diagnostics._canonical(core)).hexdigest()
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_RUNTIME_STATE_INVALID"):
            diagnostics.verify(value)

    def test_mutated_recovery_next_step_with_recomputed_digest_is_rejected(self) -> None:
        value = self.collect()
        value["recovery"]["actions"][0]["next_step"] = "raw prompt and agent id"
        value["recovery"]["primary"] = dict(value["recovery"]["actions"][0])
        core = {key: item for key, item in value.items() if key != "manifest_digest"}
        value["manifest_digest"] = hashlib.sha256(diagnostics._canonical(core)).hexdigest()
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_RECOVERY_INVALID"):
            diagnostics.verify(value)

    def test_symlink_log_is_rejected(self) -> None:
        target = self.root / "target.log"
        target.write_text("safe")
        self.log.unlink()
        self.log.symlink_to(target)
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_LOG_FILE_POLICY_INVALID"):
            self.collect()

    def test_unowned_log_path_and_process_are_rejected_or_redacted(self) -> None:
        outside = self.root / "outside.log"
        outside.write_text("secret")
        os.chmod(outside, 0o600)
        self.runtime["processes"][0]["log"] = str(outside)
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_LOG_NOT_OWNED"):
            self.collect()
        self.runtime["processes"][0]["log"] = str(self.log)
        with mock.patch.object(diagnostics.state, "lifecycle_lock", self.owned_lock), mock.patch.object(
            diagnostics.install_lifecycle, "status_unlocked", return_value=self.installed
        ), mock.patch.object(diagnostics.state, "read_run_state", return_value=self.runtime), mock.patch.object(
            diagnostics.install_lifecycle, "onboarding_status_unlocked", return_value=self.onboarding
        ), mock.patch.object(diagnostics.processes, "ownership", return_value="mismatch"):
            value = diagnostics.collect(self.config)
        self.assertEqual(value["owned_processes"][0]["identity"], None)
        self.assertEqual(value["logs"], [])

    def test_secret_canaries_and_unknown_codes_never_enter_output(self) -> None:
        canaries = ("sk-provider-secret", "bearer-secret", "raw-agent-id", "raw prompt", "raw command")
        self.onboarding["blockers"] = [canaries[0]]
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_ONBOARDING_INVALID") as raised:
            self.collect()
        for canary in canaries:
            self.assertNotIn(canary, str(raised.exception).lower())

    def test_protected_transcript_is_never_opened_or_named(self) -> None:
        protected = self.root / "testkit" / "process-loop" / "last-transcript.json"
        protected.parent.mkdir(parents=True)
        protected.write_text("PROTECTED-TRANSCRIPT-CANARY")
        original_open = diagnostics.os.open

        def guarded_open(path: object, *args: object, **kwargs: object) -> int:
            self.assertNotEqual(Path(path), protected)
            return original_open(path, *args, **kwargs)

        with mock.patch.object(diagnostics.os, "open", side_effect=guarded_open):
            value = self.collect()
        rendered = diagnostics._canonical(value)
        self.assertNotIn(b"PROTECTED-TRANSCRIPT-CANARY", rendered)
        self.assertNotIn(b"last-transcript", rendered)
        self.assertFalse(value["privacy_scan"]["protected_transcript_accessed"])
        with mock.patch.object(diagnostics, "collect", return_value=value):
            with self.assertRaisesRegex(
                diagnostics.DiagnosticsError, "DIAGNOSTICS_PROTECTED_TRANSCRIPT_FORBIDDEN"
            ):
                diagnostics.export(self.config, protected)

    def test_unowned_extra_log_is_not_read_or_exported(self) -> None:
        unowned = self.home / "logs" / "unowned.log"
        unowned.write_text("UNOWNED-SECRET-CANARY")
        os.chmod(unowned, 0o600)
        original_open = diagnostics.os.open

        def guarded_open(path: object, *args: object, **kwargs: object) -> int:
            self.assertNotEqual(Path(path), unowned)
            return original_open(path, *args, **kwargs)

        with mock.patch.object(diagnostics.os, "open", side_effect=guarded_open):
            value = self.collect()
        self.assertNotIn(b"UNOWNED-SECRET-CANARY", diagnostics._canonical(value))
        self.assertEqual(len(value["logs"]), 7)

    def test_unknown_input_field_is_allowlist_violation(self) -> None:
        self.runtime["provider_credential"] = "secret"
        with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_RUNTIME_STATE_INVALID"):
            self.collect()

    def test_missing_home_collection_is_read_only(self) -> None:
        missing = self.root / "missing-home"
        value = diagnostics.collect(SimpleNamespace(home=missing))
        self.assertFalse(missing.exists())
        self.assertEqual(value["installed"]["state"], "NOT_INSTALLED")
        self.assertEqual(value["runtime"]["status"], "NOT_RUNNING")

    def test_export_is_private_canonical_exclusive_and_non_overwriting(self) -> None:
        output_dir = self.root / "export"
        output_dir.mkdir(mode=0o700)
        output = output_dir / "diagnostics.json"
        expected = self.collect()
        with mock.patch.object(diagnostics, "collect", return_value=expected):
            result = diagnostics.export(self.config, output)
            self.assertEqual(result, expected)
            self.assertEqual(output.read_bytes(), diagnostics._canonical(expected) + b"\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_OUTPUT_EXISTS"):
                diagnostics.export(self.config, output)
        self.assertEqual(output.read_bytes(), diagnostics._canonical(expected) + b"\n")

    def test_output_symlink_and_unsafe_directory_fail_closed(self) -> None:
        target = self.root / "target"
        target.write_text("preserve")
        safe_dir = self.root / "safe"
        safe_dir.mkdir(mode=0o700)
        link = safe_dir / "diagnostics.json"
        link.symlink_to(target)
        with mock.patch.object(diagnostics, "collect", return_value=self.collect()):
            with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_OUTPUT_EXISTS"):
                diagnostics.export(self.config, link)
            output_dir = self.root / "unsafe"
            output_dir.mkdir(mode=0o777)
            os.chmod(output_dir, 0o777)
            with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_OUTPUT_DIRECTORY_INVALID"):
                diagnostics.export(self.config, output_dir / "diagnostics.json")
        self.assertEqual(target.read_text(), "preserve")

    def test_parent_directory_swap_publishes_only_through_opened_fd(self) -> None:
        output_dir = self.root / "published"
        output_dir.mkdir(mode=0o700)
        output = output_dir / "diagnostics.json"
        moved = self.root / "original-opened-directory"
        expected = self.collect()
        original_write = diagnostics._write_all

        def swap_after_write(descriptor: int, raw: bytes) -> None:
            original_write(descriptor, raw)
            output_dir.rename(moved)
            output_dir.mkdir(mode=0o700)

        with mock.patch.object(diagnostics, "collect", return_value=expected), mock.patch.object(
            diagnostics, "_write_all", side_effect=swap_after_write
        ):
            diagnostics.export(self.config, output)
        self.assertFalse(output.exists())
        published = moved / "diagnostics.json"
        self.assertEqual(published.read_bytes(), diagnostics._canonical(expected) + b"\n")
        self.assertEqual(list(output_dir.iterdir()), [])

    def test_opened_parent_identity_change_rolls_back_published_file(self) -> None:
        output_dir = self.root / "changed"
        output_dir.mkdir(mode=0o700)
        output = output_dir / "diagnostics.json"
        expected = self.collect()
        original_fstat = diagnostics.os.fstat
        calls = 0

        def changed(descriptor: int) -> object:
            nonlocal calls
            info = original_fstat(descriptor)
            calls += 1
            if calls >= 3:
                return SimpleNamespace(
                    st_dev=info.st_dev, st_ino=info.st_ino, st_uid=info.st_uid,
                    st_mode=(info.st_mode & ~0o777) | 0o755,
                )
            return info

        with mock.patch.object(diagnostics, "collect", return_value=expected), mock.patch.object(
            diagnostics.os, "fstat", side_effect=changed
        ):
            with self.assertRaisesRegex(diagnostics.DiagnosticsError, "DIAGNOSTICS_OUTPUT_DIRECTORY_CHANGED"):
                diagnostics.export(self.config, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
