from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import install_lifecycle as lifecycle
from tools.nomad_web import state


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class InstallLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nomad-install-lifecycle-")
        self.root = Path(self.temporary.name)
        self.config = SimpleNamespace(
            home=self.root / "home",
            _test_host_identity_root=self.root / "host-identity-root",
        )
        self.bundles = self.root / "sources"
        self.bundles.mkdir(mode=0o700)
        self.v1 = self.make_bundle("v1", b"#!/bin/sh\nprintf 'v1:%s\n' \"$*\"\n")
        self.v2 = self.make_bundle("v2", b"#!/bin/sh\nprintf 'v2:%s\n' \"$*\"\n")
        self.verifier = mock.patch.object(lifecycle, "verify_bundle", side_effect=self.verify_bundle)
        self.verifier.start()

    def tearDown(self) -> None:
        self.verifier.stop()
        self.temporary.cleanup()

    def make_bundle(self, name: str, payload: bytes) -> Path:
        root = self.bundles / name
        (root / "bin").mkdir(parents=True, mode=0o755)
        package = root / "lib" / "nomad_web"
        package.mkdir(parents=True, mode=0o755)
        executable = root / "bin" / "nomad-web"
        executable.write_bytes(payload)
        os.chmod(executable, 0o755)
        readme = root / "README.txt"
        readme.write_bytes(name.encode())
        os.chmod(readme, 0o644)
        (package / "__init__.py").write_text("# test package\n")
        (package / "bundle.py").write_text(
            "import json,sys\n"
            "def verify_bundle(root):\n"
            " raise AssertionError('installed launcher reread bundle path')\n"
            "def verify_bundle_snapshot(files,modes,directories):\n"
            " if 'bootstrap-failure' in sys.argv: raise ValueError('/secret/bootstrap/path')\n"
            " assert set(files)==set(modes)\n"
            " assert modes['manifest.json']==0o644\n"
            " return json.loads(files['manifest.json'])\n"
        )
        (package / "install_lifecycle.py").write_text(
            "def _validate_current(value):\n"
            " assert value['history'][-1]['to_bundle_digest'] == value['bundle_digest']\n"
        )
        (package / "state.py").write_text(
            "from contextlib import contextmanager\n"
            "@contextmanager\n"
            "def adopt_lifecycle_lock(home, descriptor):\n"
            " yield\n"
        )
        (package / "cli.py").write_text(
            "from pathlib import Path\n"
            "import time\n"
            "def run(args):\n"
            " version=(Path(__file__).parents[2]/'README.txt').read_text()\n"
            " if args and args[0]=='hold':\n"
            "  Path(args[1]).write_text('ready')\n"
            "  while not Path(args[2]).exists(): time.sleep(0.01)\n"
            " print(f\"{version}:{' '.join(args)}\")\n"
            " return 0\n"
        )
        os.chmod(package / "__init__.py", 0o644)
        os.chmod(package / "bundle.py", 0o644)
        os.chmod(package / "cli.py", 0o644)
        os.chmod(package / "install_lifecycle.py", 0o644)
        os.chmod(package / "state.py", 0o644)
        entries = []
        for relative, mode in (
            ("README.txt", 0o644), ("bin/nomad-web", 0o755),
            ("lib/nomad_web/__init__.py", 0o644),
            ("lib/nomad_web/bundle.py", 0o644),
            ("lib/nomad_web/cli.py", 0o644),
            ("lib/nomad_web/install_lifecycle.py", 0o644),
            ("lib/nomad_web/state.py", 0o644),
        ):
            raw = (root / relative).read_bytes()
            entries.append({
                "path": relative, "size_bytes": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(), "mode": f"{mode:04o}",
            })
        core = {"schema": "nomad.web-companion.prebuilt.v2", "files": entries}
        digest = hashlib.sha256(canonical(core)).hexdigest()
        manifest = {"bundle_digest": digest, **core}
        (root / lifecycle.MANIFEST).write_bytes(canonical(manifest) + b"\n")
        os.chmod(root / lifecycle.MANIFEST, 0o644)
        os.chmod(root / "bin", 0o755)
        os.chmod(root / "lib" / "nomad_web", 0o755)
        os.chmod(root / "lib", 0o755)
        os.chmod(root, 0o755)
        return root

    def verify_bundle(self, root: Path) -> dict[str, object]:
        root = Path(root)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
            raise RuntimeError("UNSAFE_BUNDLE_ROOT")
        manifest_path = root / lifecycle.MANIFEST
        manifest_info = manifest_path.lstat()
        if (
            not stat.S_ISREG(manifest_info.st_mode) or stat.S_ISLNK(manifest_info.st_mode)
            or manifest_info.st_nlink != 1 or stat.S_IMODE(manifest_info.st_mode) != 0o644
        ):
            raise RuntimeError("UNSAFE_BUNDLE_FILE")
        manifest = json.loads(manifest_path.read_bytes())
        if manifest_path.read_bytes() != canonical(manifest) + b"\n":
            raise RuntimeError("INVALID_BUNDLE_MANIFEST")
        expected = {lifecycle.MANIFEST}
        for entry in manifest["files"]:
            expected.add(entry["path"])
            path = root / entry["path"]
            file_info = path.lstat()
            if (
                not stat.S_ISREG(file_info.st_mode) or stat.S_ISLNK(file_info.st_mode)
                or file_info.st_nlink != 1
                or stat.S_IMODE(file_info.st_mode) != int(entry["mode"], 8)
            ):
                raise RuntimeError("UNSAFE_BUNDLE_FILE")
            raw = path.read_bytes()
            if len(raw) != entry["size_bytes"] or hashlib.sha256(raw).hexdigest() != entry["raw_sha256"]:
                raise RuntimeError("BUNDLE_FILE_MISMATCH")
        actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() or path.is_symlink()}
        if actual != expected:
            raise RuntimeError("BUNDLE_FILE_SET_MISMATCH")
        return manifest

    def install(self, source: Path | None = None) -> dict[str, object]:
        return lifecycle.install(self.config, source or self.v1)

    def private_file(self, name: str, raw: bytes) -> Path:
        private = self.config.home / "private"
        private.mkdir(mode=0o700, exist_ok=True)
        os.chmod(private, 0o700)
        path = private / name
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return path

    def digest(self, source: Path) -> str:
        return json.loads((source / lifecycle.MANIFEST).read_bytes())["bundle_digest"]

    def assert_v1_current_and_state(self, expected_state: bytes) -> None:
        observed = lifecycle.status(self.config)
        self.assertEqual(observed["current_bundle_digest"], self.digest(self.v1))
        self.assertEqual(
            (self.config.home / "private" / "relay-v2.sqlite3").read_bytes(),
            expected_state,
        )

    def test_install_copies_exact_allowlist_and_is_idempotent(self) -> None:
        first = self.install()
        second = self.install()
        self.assertEqual(first, second)
        self.assertEqual(first["state"], "INSTALLED")
        self.assertEqual(
            first["onboarding"]["state"], "INSTALLED_BLOCKED_HOST_IDENTITY"
        )
        self.assertFalse(first["onboarding"]["production_ready"])
        self.assertEqual(len(first["history"]), 1)
        target = self.config.home / "bundles" / self.digest(self.v1)
        self.assertEqual((target / "bin" / "nomad-web").read_bytes(), self.v1.joinpath("bin/nomad-web").read_bytes())
        self.assertEqual(
            {str(path.relative_to(target)) for path in target.rglob("*") if path.is_file()},
            {
                "README.txt", "bin/nomad-web", "manifest.json",
                "lib/nomad_web/__init__.py", "lib/nomad_web/bundle.py",
                "lib/nomad_web/cli.py",
                "lib/nomad_web/install_lifecycle.py",
                "lib/nomad_web/state.py",
            },
        )
        self.assertFalse((self.config.home / "install" / "current.json").is_symlink())
        stable = self.config.home / "bin" / "nomad-web"
        self.assertTrue(stable.is_file())
        self.assertFalse(stable.is_symlink())
        self.assertEqual(stat.S_IMODE(stable.stat().st_mode), 0o755)
        self.assertEqual(stable.read_bytes(), lifecycle._stable_launcher_bytes())

    def test_stable_launcher_uses_current_without_sources_and_ignores_python_injection(self) -> None:
        self.install()
        stable = self.config.home / "bin" / "nomad-web"
        hostile = self.root / "hostile"
        (hostile / "nomad_web").mkdir(parents=True)
        (hostile / "nomad_web" / "__main__.py").write_text("raise SystemExit(77)\n")
        removed_v1 = self.root / "removed-v1-source"
        self.v1.rename(removed_v1)
        environment = {
            "PATH": str(hostile),
            "LANG": "C", "LC_ALL": "C",
            "NOMAD_WEB_HOME": str(self.root / "wrong-home"),
            "NOMAD_WEB_BUNDLE": str(removed_v1),
            "PYTHONPATH": str(hostile),
            "PYTHONHOME": str(hostile / "missing"),
        }
        python_canary = hostile / "python3"
        python_canary.write_text(
            "#!/bin/sh\nprintf 'hostile-python-executed\\n' >&2\nexit 91\n"
        )
        os.chmod(python_canary, 0o755)

        first = subprocess.run(
            [str(stable), "alpha", "beta"], cwd=hostile, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(first.stdout, "v1:alpha beta\n")
        self.assertNotIn("hostile-python-executed", first.stderr)

        lifecycle.upgrade(self.config, self.v2)
        removed_v2 = self.root / "removed-v2-source"
        self.v2.rename(removed_v2)
        second = subprocess.run(
            [str(stable), "gamma"], cwd=hostile, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "v2:gamma\n")

        lifecycle.rollback(self.config)
        rolled_back = subprocess.run(
            [str(stable), "delta"], cwd=hostile, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(rolled_back.returncode, 0, rolled_back.stdout + rolled_back.stderr)
        self.assertEqual(rolled_back.stdout, "v1:delta\n")

    def test_stable_launcher_fails_closed_on_installed_bundle_tamper(self) -> None:
        self.install()
        stable = self.config.home / "bin" / "nomad-web"
        target = self.config.home / "bundles" / self.digest(self.v1) / "README.txt"
        target.write_bytes(b"tampered")
        result = subprocess.run(
            [str(stable), "--json", "status"],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {
            "schema": "nomad.web-companion.error.v1",
            "state": "BLOCKED",
            "error": "INSTALLED_BUNDLE_FILE_MISMATCH",
            "production_ready": False,
        })
        self.assertNotIn(str(self.config.home), result.stdout)

    def test_stable_launcher_redacts_unexpected_bootstrap_failure(self) -> None:
        self.install()
        stable = self.config.home / "bin" / "nomad-web"
        environment = {
            "PATH": "/hostile", "LANG": "C", "LC_ALL": "C",
        }
        json_result = subprocess.run(
            [str(stable), "--json", "bootstrap-failure"], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(json_result.returncode, 1)
        self.assertEqual(json_result.stderr, "")
        self.assertEqual(json.loads(json_result.stdout), {
            "schema": "nomad.web-companion.error.v1",
            "state": "BLOCKED",
            "error": "INSTALLED_LAUNCHER_FAILURE",
            "production_ready": False,
        })
        self.assertNotIn("/secret/bootstrap/path", json_result.stdout)
        self.assertNotIn(str(self.config.home), json_result.stdout)

        human = subprocess.run(
            [str(stable), "bootstrap-failure"], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(human.returncode, 1)
        self.assertEqual(human.stdout, "")
        self.assertEqual(human.stderr, "nomad-web: installed launcher failed\n")
        self.assertNotIn("/secret/bootstrap/path", human.stderr)

    def test_stable_launcher_holds_lifecycle_lock_through_snapshot_cli_run(self) -> None:
        self.install()
        stable = self.config.home / "bin" / "nomad-web"
        ready = self.root / "launcher-ready"
        release = self.root / "launcher-release"
        child = subprocess.Popen(
            [str(stable), "hold", str(ready), str(release)],
            env={"PATH": "/hostile", "LANG": "C", "LC_ALL": "C"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 10
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not ready.exists():
            child.terminate()
            stdout, stderr = child.communicate(timeout=5)
            self.fail(stdout + stderr)

        completed = threading.Event()
        failures: list[BaseException] = []

        def upgrade() -> None:
            try:
                lifecycle.upgrade(self.config, self.v2)
            except BaseException as error:
                failures.append(error)
            finally:
                completed.set()

        worker = threading.Thread(target=upgrade, daemon=True)
        worker.start()
        self.assertFalse(completed.wait(0.2))
        self.assertEqual(
            json.loads((self.config.home / "install" / "current.json").read_bytes())["bundle_digest"],
            self.digest(self.v1),
        )
        release.write_text("release")
        stdout, stderr = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 0, stdout + stderr)
        worker.join(timeout=10)
        self.assertTrue(completed.is_set())
        self.assertEqual(failures, [])
        self.assertTrue(stdout.startswith("v1:hold "))
        self.assertEqual(lifecycle.status(self.config)["current_bundle_digest"], self.digest(self.v2))

    def test_stable_launcher_publish_failure_does_not_commit_selector(self) -> None:
        real_replace = lifecycle.os.replace

        def fail_launcher_once(source: Path, target: Path) -> None:
            if Path(target) == self.config.home / "bin" / "nomad-web":
                raise OSError(5, "injected stable launcher failure")
            real_replace(source, target)

        with mock.patch.object(lifecycle.os, "replace", side_effect=fail_launcher_once):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(lifecycle.status(self.config)["state"], "NOT_INSTALLED")
        self.assertFalse((self.config.home / "bin" / "nomad-web").exists())
        repaired = self.install()
        self.assertEqual(repaired["current_bundle_digest"], self.digest(self.v1))
        self.assertEqual(
            (self.config.home / "bin" / "nomad-web").read_bytes(),
            lifecycle._stable_launcher_bytes(),
        )

    def test_first_selector_failure_leaves_only_inert_launcher(self) -> None:
        real_replace = lifecycle.os.replace

        def fail_current(source: Path, target: Path) -> None:
            if Path(target) == self.config.home / "install" / "current.json":
                raise OSError(5, "injected selector failure")
            real_replace(source, target)

        with mock.patch.object(lifecycle.os, "replace", side_effect=fail_current):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(lifecycle.status(self.config)["state"], "NOT_INSTALLED")
        stable = self.config.home / "bin" / "nomad-web"
        self.assertTrue(stable.is_file())
        result = subprocess.run(
            [str(stable), "--json", "status"],
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {
            "schema": "nomad.web-companion.error.v1",
            "state": "BLOCKED",
            "error": "INSTALLED_LAUNCHER_FAILURE",
            "production_ready": False,
        })
        self.assertNotIn(str(self.config.home), result.stdout)
        self.assertNotIn("install/current.json", result.stdout)

    def test_install_rejects_tamper_symlink_hardlink_and_extra_file(self) -> None:
        cases: list[tuple[str, Callable[[Path], object]]] = []
        cases.append(("tamper", lambda root: (root / "README.txt").write_bytes(b"tamper")))
        cases.append(("extra", lambda root: (root / "extra").write_bytes(b"x")))

        def symlink(root: Path) -> None:
            (root / "README.txt").unlink()
            (root / "README.txt").symlink_to(root / "bin" / "nomad-web")

        def hardlink(root: Path) -> None:
            os.link(root / "README.txt", root / "linked")

        cases.extend((("symlink", symlink), ("hardlink", hardlink)))
        for index, (name, mutate) in enumerate(cases):
            with self.subTest(name=name):
                source = self.make_bundle(f"bad-{index}", f"bad-{index}".encode())
                mutate(source)
                with self.assertRaises(RuntimeError):
                    lifecycle.install(self.config, source)
                self.assertEqual(lifecycle.status(self.config)["state"], "NOT_INSTALLED")

    def test_install_and_start_selector_reject_legacy_bundle_runtime(self) -> None:
        legacy = self.make_bundle("legacy", b"legacy")
        manifest_path = legacy / lifecycle.MANIFEST
        manifest = json.loads(manifest_path.read_bytes())
        manifest["schema"] = "nomad.web-companion.prebuilt.v1"
        core = {key: value for key, value in manifest.items() if key != "bundle_digest"}
        manifest["bundle_digest"] = hashlib.sha256(canonical(core)).hexdigest()
        manifest_path.write_bytes(canonical(manifest) + b"\n")
        with self.assertRaisesRegex(RuntimeError, "LEGACY_BUNDLE_RUNTIME_UNSUPPORTED"):
            lifecycle.install(self.config, legacy)
        with lifecycle.lifecycle_lock(self.config, create=True):
            with self.assertRaisesRegex(RuntimeError, "LEGACY_BUNDLE_RUNTIME_UNSUPPORTED"):
                lifecycle.select_bundle_for_start(self.config, legacy)

    def test_status_rejects_tampered_installed_bundle_and_unsafe_current(self) -> None:
        self.install()
        target = self.config.home / "bundles" / self.digest(self.v1) / "README.txt"
        target.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "BUNDLE_FILE_MISMATCH"):
            lifecycle.status(self.config)

        target.write_bytes(b"v1")
        current = self.config.home / "install" / "current.json"
        raw = current.read_bytes()
        current.unlink()
        elsewhere = self.root / "elsewhere"
        elsewhere.write_bytes(raw)
        os.chmod(elsewhere, 0o600)
        current.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            lifecycle.status(self.config)

    def test_requires_authoritative_stopped_state_without_public_bypass(self) -> None:
        running = {"schema": "authoritative-running"}
        with mock.patch.object(lifecycle, "read_run_state", return_value=running):
            with self.assertRaisesRegex(RuntimeError, "INSTALL_LIFECYCLE_REQUIRES_STOP"):
                lifecycle.install(self.config, self.v1)
        self.install()
        with mock.patch.object(lifecycle, "read_run_state", return_value=running):
            with self.assertRaisesRegex(RuntimeError, "INSTALL_LIFECYCLE_REQUIRES_STOP"):
                lifecycle.upgrade(self.config, self.v2)
            with self.assertRaisesRegex(RuntimeError, "INSTALL_LIFECYCLE_REQUIRES_STOP"):
                lifecycle.rollback(self.config)
        with self.assertRaises(TypeError):
            lifecycle.rollback(self.config, run_state=None)

    def test_upgrade_is_idempotent_and_history_has_digests_but_no_secret(self) -> None:
        self.install()
        self.private_file("relay-v2.sqlite3", b"secret-database-bytes")
        first = lifecycle.upgrade(self.config, self.v2)
        second = lifecycle.upgrade(self.config, self.v2)
        self.assertEqual(first, second)
        self.assertEqual(first["current_bundle_digest"], self.digest(self.v2))
        self.assertIn(first["onboarding"]["state"], lifecycle.ONBOARDING_STATES)
        self.assertEqual([entry["operation"] for entry in first["history"]], ["install", "upgrade"])
        current_raw = (self.config.home / "install" / "current.json").read_bytes()
        self.assertNotIn(b"secret-database-bytes", current_raw)
        snapshot_digest = first["history"][-1]["state_snapshot_digest"]
        self.assertRegex(snapshot_digest, r"^[0-9a-f]{64}$")

    def test_rollback_changes_only_code_and_keeps_nonce_revoke_state_forward(self) -> None:
        self.install()
        database = self.private_file("relay-v2.sqlite3", b"v1 database")
        cursor = self.private_file("remote-mailbox.sqlite3", b"v1 cursor")
        identity = self.private_file("host-device-registry.sqlite3", b"identity-v1")
        unowned = self.private_file("operator-note", b"leave me alone")
        lifecycle.upgrade(self.config, self.v2)
        database.write_bytes(b"v2 database")
        cursor.write_bytes(b"v2 cursor")
        sidecar = self.private_file("relay-v2.sqlite3-wal", b"v2 only")
        identity.write_bytes(b"identity-v2")

        rolled_back = lifecycle.rollback(self.config)
        self.assertEqual(rolled_back["current_bundle_digest"], self.digest(self.v1))
        self.assertIn(rolled_back["onboarding"]["state"], lifecycle.ONBOARDING_STATES)
        self.assertEqual(database.read_bytes(), b"v2 database")
        self.assertEqual(cursor.read_bytes(), b"v2 cursor")
        self.assertEqual(sidecar.read_bytes(), b"v2 only")
        self.assertEqual(identity.read_bytes(), b"identity-v2")
        self.assertEqual(unowned.read_bytes(), b"leave me alone")
        repeated = lifecycle.rollback(self.config)
        self.assertEqual(repeated, rolled_back)

    def test_upgrade_crash_boundaries_are_one_complete_old_or_new_selector(self) -> None:
        stages = (
            "source_verified", "state_snapshotted", "bundle_copied",
            "bundle_verified", "bundle_published", "before_current_switch",
            "after_current_switch",
        )
        for index, failure_stage in enumerate(stages):
            with self.subTest(stage=failure_stage):
                case_home = self.root / f"failure-home-{index}"
                config = SimpleNamespace(
                    home=case_home,
                    _test_host_identity_root=(
                        self.root / f"failure-host-identity-{index}"
                    ),
                )
                lifecycle.install(config, self.v1)
                private = case_home / "private"
                private.mkdir(mode=0o700)
                database = private / "relay-v2.sqlite3"
                database.write_bytes(b"old-state")
                os.chmod(database, 0o600)

                def inject(stage: str) -> None:
                    if stage == failure_stage:
                        database.write_bytes(b"mutated-state")
                        os.chmod(database, 0o600)
                        raise RuntimeError(f"FAIL_{stage}")

                with mock.patch.object(lifecycle, "_checkpoint", side_effect=inject):
                    with self.assertRaisesRegex(RuntimeError, f"FAIL_{failure_stage}"):
                        lifecycle.upgrade(config, self.v2)
                observed = lifecycle.status(config)
                expected = self.digest(self.v2) if failure_stage == "after_current_switch" else self.digest(self.v1)
                self.assertEqual(observed["current_bundle_digest"], expected)
                self.assertEqual(len(observed["history"]), 2 if failure_stage == "after_current_switch" else 1)
                self.assertEqual(database.read_bytes(), b"mutated-state")

    def test_fsync_failure_leaves_complete_old_selector_and_forward_state(self) -> None:
        self.install()
        database = self.private_file("relay-v2.sqlite3", b"old-state")
        real_fsync = lifecycle.os.fsync
        armed = False
        failed = False

        def checkpoint(stage: str) -> None:
            nonlocal armed
            if stage == "before_current_switch":
                database.write_bytes(b"new-state")
                os.chmod(database, 0o600)
                armed = True

        def fsync_once(descriptor: int) -> None:
            nonlocal failed
            if armed and not failed:
                failed = True
                raise OSError(5, "injected fsync failure")
            real_fsync(descriptor)

        with (
            mock.patch.object(lifecycle, "_checkpoint", side_effect=checkpoint),
            mock.patch.object(lifecycle.os, "fsync", side_effect=fsync_once),
        ):
            with self.assertRaises(OSError):
                lifecycle.upgrade(self.config, self.v2)
        self.assertTrue(failed)
        self.assert_v1_current_and_state(b"new-state")

    def test_bundle_rename_failure_keeps_old_selector_and_forward_state(self) -> None:
        self.install()
        database = self.private_file("relay-v2.sqlite3", b"old-state")
        real_rename = lifecycle._rename_exclusive

        def fail_bundle(source: Path, target: Path) -> None:
            if target.parent == self.config.home / "bundles" and target.name == self.digest(self.v2):
                database.write_bytes(b"new-state")
                os.chmod(database, 0o600)
                raise OSError(5, "injected rename failure")
            real_rename(source, target)

        with mock.patch.object(lifecycle, "_rename_exclusive", side_effect=fail_bundle):
            with self.assertRaises(OSError):
                lifecycle.upgrade(self.config, self.v2)
        self.assert_v1_current_and_state(b"new-state")
        self.assertEqual(list((self.config.home / "install" / "staging").iterdir()), [])

    def test_current_switch_failure_keeps_old_selector_and_forward_state(self) -> None:
        self.install()
        database = self.private_file("relay-v2.sqlite3", b"old-state")
        real_replace = lifecycle.os.replace
        failed = False

        def replace(source: Path, target: Path) -> None:
            nonlocal failed
            if Path(target) == self.config.home / "install" / "current.json" and not failed:
                failed = True
                database.write_bytes(b"new-state")
                os.chmod(database, 0o600)
                raise OSError(5, "injected current switch failure")
            real_replace(source, target)

        with mock.patch.object(lifecycle.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                lifecycle.upgrade(self.config, self.v2)
        self.assertTrue(failed)
        self.assert_v1_current_and_state(b"new-state")

    def test_rollback_switch_failure_leaves_complete_new_selector_and_forward_state(self) -> None:
        self.install()
        database = self.private_file("relay-v2.sqlite3", b"old-state")
        lifecycle.upgrade(self.config, self.v2)
        database.write_bytes(b"new-state")
        os.chmod(database, 0o600)
        real_replace = lifecycle.os.replace
        failed = False

        def replace(source: Path, target: Path) -> None:
            nonlocal failed
            if Path(target) == self.config.home / "install" / "current.json" and not failed:
                failed = True
                raise OSError(5, "injected rollback switch failure")
            real_replace(source, target)

        with mock.patch.object(lifecycle.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                lifecycle.rollback(self.config)
        self.assertEqual(lifecycle.status(self.config)["current_bundle_digest"], self.digest(self.v2))
        self.assertEqual(database.read_bytes(), b"new-state")

    def test_start_selector_rejects_explicit_conflict_and_uses_current(self) -> None:
        self.install()
        with lifecycle.lifecycle_lock(self.config, create=True):
            selected = lifecycle.select_bundle_for_start(self.config, self.v1)
            self.assertEqual(
                selected,
                (self.config.home / "bundles" / self.digest(self.v1)).resolve(strict=True),
            )
            self.assertEqual(selected, selected.resolve(strict=True))
            self.assertEqual(lifecycle.select_bundle_for_start(self.config, None), selected)
            with self.assertRaisesRegex(RuntimeError, "EXPLICIT_BUNDLE_CURRENT_CONFLICT"):
                lifecycle.select_bundle_for_start(self.config, self.v2)

    def test_status_unlocked_reads_current_without_relocking_marker(self) -> None:
        self.install()
        with lifecycle.lifecycle_lock(self.config, create=True):
            with mock.patch.object(lifecycle, "lifecycle_lock", side_effect=AssertionError("unexpected re-lock")):
                observed = lifecycle.status_unlocked(self.config)
        self.assertEqual(observed["state"], "INSTALLED")
        self.assertEqual(observed["current_bundle_digest"], self.digest(self.v1))

    def test_adopted_lifecycle_lock_reenters_and_rejects_marker_replacement(self) -> None:
        self.install()
        marker = self.config.home / state.HOME_MARKER
        descriptor = os.open(
            marker, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            with state.adopt_lifecycle_lock(self.config.home, descriptor):
                with lifecycle.lifecycle_lock(self.config, create=False) as owned:
                    self.assertTrue(owned)
                raw = marker.read_bytes()
                marker.unlink()
                marker.write_bytes(raw)
                os.chmod(marker, 0o600)
                with self.assertRaisesRegex(
                    RuntimeError, "LIFECYCLE_LOCK_MARKER_CHANGED",
                ):
                    with lifecycle.lifecycle_lock(self.config, create=False):
                        pass
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
