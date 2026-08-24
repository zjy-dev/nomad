"""WP1 content-free unit tests."""
from __future__ import annotations

import copy
import importlib.util
import json
import pickle
import sys
import tempfile
import threading
import unittest
import weakref
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SPEC = importlib.util.spec_from_file_location("real_task_capture", Path(__file__).with_name("real_task_capture.py"))
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

RUN = "run-" + "a" * 20


class _FakeLiveProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode = None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class RealTaskCaptureTest(unittest.TestCase):
    def _test_facts(self, marker: str = "a") -> dict[str, object]:
        digest = marker * 64
        return {
            "package_name": "opencode-ai",
            "package_version": "1.18.16",
            "package_lock_raw_digest": digest,
            "full_locked_dependency_count": 3,
            "full_locked_dependency_digest": digest,
            "installed_platform_dependency_count": 2,
            "installed_platform_dependency_digest": digest,
            "entrypoint_realpath": "/private/test/opencode",
            "entrypoint_raw_digest": digest,
            "npm_executable_realpath": "/private/test/npm",
            "npm_version": "11.12.1",
            "task_spec_digest": digest,
            "fixture_manifest_digest": digest,
            "adapter_id": "opencode",
            "adapter_version": "1.18.16",
        }

    def _test_issuance(
        self, root: Path, *, pid: int = 41001, marker: str = "a"
    ) -> tuple[object, _FakeLiveProcess]:
        paths = {name: root / name for name in (
            "workspace", "home", "xdg", "install"
        )}
        for path in paths.values():
            path.mkdir()
        process = _FakeLiveProcess(pid)
        launch = mod._issue_test_only_locked_launch(
            root=root, workspace=paths["workspace"], home=paths["home"],
            xdg=paths["xdg"], install=paths["install"], port=32123,
            process=process, facts=self._test_facts(marker),
        )
        return launch, process

    def _artifact_record(
        self, root: Path, *, task_digest: str | None = None,
        live_digest: str | None = None,
    ) -> tuple[object, object, object]:
        paths = {name: root / name for name in (
            "workspace", "home", "xdg", "install"
        )}
        for path in paths.values():
            path.mkdir()
        package_dir = paths["install"] / "node_modules" / "opencode-ai"
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": "opencode-ai", "version": "1.18.16"}),
            encoding="utf-8",
        )
        lock = paths["install"] / "package-lock.json"
        lock.write_bytes(b"lock")
        entrypoint = package_dir / "opencode"
        entrypoint.write_bytes(b"native image")
        entrypoint.chmod(0o755)
        npm = root / "npm"
        npm.write_bytes(b"npm")
        npm.chmod(0o755)
        manifest = mod.fixture_manifest()
        mod.materialize_fixture(paths["workspace"], manifest)
        _payload, current_task_digest = mod.load_task_spec()
        facts = self._test_facts()
        facts.update({
            "package_lock_raw_digest": mod._sha256_bytes(b"lock"),
            "entrypoint_realpath": str(entrypoint),
            "entrypoint_raw_digest": mod._sha256_bytes(b"native image"),
            "npm_executable_realpath": str(npm),
            "task_spec_digest": task_digest or current_task_digest,
            "fixture_manifest_digest": manifest["digest"],
        })
        process = _FakeLiveProcess(42001)
        measurement = object.__new__(mod._LockedOpenCodeLaunchMeasurement)
        record = mod._LockedLaunchRegistryRecord(
            issuer=object(), measurement=measurement, facts=tuple(facts.items()),
            process=process, process_pid=process.pid, root=root,
            workspace=paths["workspace"], home=paths["home"],
            xdg=paths["xdg"], install=paths["install"], port=32123,
            provenance_digest=mod._shape_digest(facts), verify_artifacts=True,
        )

        class _Capture:
            sha256 = staticmethod(mod._sha256_bytes)

            @staticmethod
            def full_locked_closure(_path: Path) -> dict[str, object]:
                return {
                    "full_locked_dependency_count": facts["full_locked_dependency_count"],
                    "full_locked_dependency_digest": facts["full_locked_dependency_digest"],
                }

            @staticmethod
            def installed_platform_closure(
                _path: Path, _install: Path
            ) -> dict[str, object]:
                return {
                    "installed_platform_dependency_count": facts["installed_platform_dependency_count"],
                    "installed_platform_dependency_digest": facts["installed_platform_dependency_digest"],
                }

            @staticmethod
            def run(*_args: object, **_kwargs: object) -> object:
                return SimpleNamespace(stdout="11.12.1\n")

        class _Darwin:
            _SINK_TOKEN = object()
            calls = 0

            @classmethod
            def verify_live_executable(cls, *_args: object) -> object:
                cls.calls += 1
                return object()

            @classmethod
            def _new_locked_launch_measurement_sink(
                cls, token: object, target: object
            ) -> object:
                if token is not cls._SINK_TOKEN:
                    raise AssertionError("token")
                return target

            @staticmethod
            def _bridge_verified_live_executable(
                _live: object, target: object
            ) -> object:
                object.__setattr__(target, "_process_pid", process.pid)
                object.__setattr__(target, "_entrypoint_realpath", str(entrypoint))
                object.__setattr__(
                    target, "_entrypoint_raw_digest",
                    live_digest or facts["entrypoint_raw_digest"],
                )
                object.__setattr__(target, "_sealed", True)
                return target

        return record, _Capture, _Darwin

    def test_preflight_requires_allowlisted_nonempty_explicit_credential(self) -> None:
        spec = mod.load_task_spec()
        self.assertEqual(mod.preflight("PATH", {"PATH": "x"})["reason_codes"][0], "BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
        self.assertEqual(mod.preflight("OTHER_TOKEN", {"OTHER_TOKEN": "x"})["reason_codes"][0], "BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
        self.assertEqual(mod.preflight("OPENAI_API_KEY", {"OPENAI_API_KEY": "  "})["reason_codes"][0], "BLOCKED_TEMPORARY_PROVIDER_CREDENTIAL_REQUIRED")
        self.assertEqual(mod.preflight("OPENAI_API_KEY", {"OPENAI_API_KEY": "temporary"}, task_spec=spec)["status"], "READY")

    def test_task_spec_and_generated_fixture_match_project_manifest(self) -> None:
        spec, spec_digest = mod.load_task_spec()
        self.assertEqual(len(spec_digest), 64)
        manifest = mod.verify_fixture_manifest()
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            self.assertEqual(mod.materialize_fixture(workspace, manifest), manifest["digest"])
            for entry in manifest["files"]:
                content = (workspace / entry["relative_name"]).read_bytes()
                self.assertEqual(mod._sha256_bytes(content), entry["sha256"])

    def test_task_spec_rejects_nested_action_extra_field_and_minimum_tampering(self) -> None:
        original = json.loads(mod.DEFAULT_TASK_SPEC.read_text(encoding="utf-8"))
        for mutate in (
            lambda value: value["task_flow"][0].update(operator_action="wrong"),
            lambda value: value["task_flow"][1].update(extra="forbidden"),
            lambda value: value["task_flow"][1].update(expected_file_count_min=2),
        ):
            with tempfile.TemporaryDirectory() as temp:
                candidate = json.loads(json.dumps(original))
                mutate(candidate)
                path = mod.REAL_TASK_DIR / "task-spec-test-tampered.json"
                path.write_text(json.dumps(candidate), encoding="utf-8")
                try:
                    with self.assertRaisesRegex(mod.RealTaskError, "BLOCKED_REAL_TASK_SPEC_INVALID"):
                        mod.load_task_spec(path)
                finally:
                    path.unlink(missing_ok=True)

    def test_command_shape_fixture_is_tamper_evident(self) -> None:
        fixture = mod.verify_command_shape_fixture()
        self.assertEqual(set(fixture["actions"]), set(mod.V2_ACTIONS))
        with tempfile.TemporaryDirectory() as temp:
            tampered = Path(temp) / "command-shapes.json"
            payload = json.loads(mod.COMMAND_SHAPES.read_text(encoding="utf-8"))
            payload["actions"]["stop"]["operation_id"] = "v2.session.wrong"
            tampered.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(mod.RealTaskError, "BLOCKED_COMMAND_SHAPE_MISSING"):
                mod.verify_command_shape_fixture(tampered)

    def test_command_shape_fixture_binds_current_m1_provenance(self) -> None:
        self.assertEqual(
            mod.verify_command_shape_fixture()["runtime_provenance_digest"],
            mod.current_m1_runtime_provenance_digest(),
        )

    def test_base_environment_has_isolated_auth_roots_and_no_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = mod.isolated_base_env(home=root / "home", xdg=root / "xdg")
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertFalse(any(name.endswith("_TOKEN") for name in env))
        self.assertEqual(env["HOME"], str(root / "home"))
        self.assertEqual(env["XDG_DATA_HOME"], str(root / "xdg" / "data"))

    def test_wp1_receipt_uses_shared_contract_and_rejects_proxy_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = Path(temp) / "receipts.ndjson"
            first = mod.append_wp1_receipt(store, run_id=RUN, stage="runtime_provenance_verified", sequence=1, predecessor_digest=None, reason_code="verified")
            second = mod.append_wp1_receipt(store, run_id=RUN, stage="credential_scope_configured", sequence=2, predecessor_digest=first, reason_code="configured")
            self.assertEqual(len(store.read_text().splitlines()), 2)
            with self.assertRaisesRegex(mod.RealTaskError, "STAGE_OWNERSHIP"):
                mod.append_wp1_receipt(store, run_id=RUN, stage="stop_upstream_executed", sequence=3, predecessor_digest=second, reason_code="forbidden")
            with self.assertRaisesRegex(Exception, "STAGE_ORDER"):
                mod.read_receipt_store(store, expected_run_id=RUN)

    def test_exact_v2_shape_extractor_is_content_free_and_requires_all_actions(self) -> None:
        paths = {}
        for action, (operation_id, route) in mod.V2_ACTIONS.items():
            paths[route] = {"post": {"operationId": operation_id, "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["mode"], "properties": {"mode": {"type": "string", "enum": ["reject"], "example": "secret", "description": "no"}}}}}}, "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {}}}}}}}}
        shapes = mod.extract_command_shapes({"paths": paths, "components": {"schemas": {}}})
        rendered = json.dumps(shapes)
        self.assertEqual(set(shapes), set(mod.V2_ACTIONS))
        self.assertEqual(
            shapes["question_reply"]["operation_id"],
            "v2.session.question.reply",
        )
        self.assertNotIn("secret", rendered)
        self.assertNotIn("description", rendered)
        self.assertIn("reject", rendered)
        del paths[mod.V2_ACTIONS["stop"][1]]
        with self.assertRaisesRegex(mod.RealTaskError, "BLOCKED_COMMAND_SHAPE_MISSING"):
            mod.extract_command_shapes({"paths": paths, "components": {"schemas": {}}})

    def test_cleanup_removes_disposable_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            launch = mod.LockedOpenCodeLaunch(root, root, root, root, root, 1, None, "a" * 64)
            launch.cleanup()
            self.assertFalse(root.exists())

    def test_measurement_is_complete_frozen_nonserializable_and_legacy_is_untrusted(self) -> None:
        with self.assertRaises(TypeError):
            mod._LockedOpenCodeLaunchMeasurement()
        self.assertTrue({
            "_package_name", "_package_version", "_package_lock_raw_digest",
            "_full_locked_dependency_count", "_full_locked_dependency_digest",
            "_installed_platform_dependency_count",
            "_installed_platform_dependency_digest", "_entrypoint_realpath",
            "_entrypoint_raw_digest", "_npm_executable_realpath", "_npm_version",
            "_task_spec_digest", "_fixture_manifest_digest", "_adapter_id",
            "_adapter_version", "_process_pid", "_root", "_install",
            "_workspace", "_port",
        }.issubset(set(mod._LockedOpenCodeLaunchMeasurement.__slots__)))
        self.assertFalse(hasattr(mod, "_construct_locked_measurement"))

        legacy = mod.LockedOpenCodeLaunch(
            Path("/root"), Path("/root"), Path("/root"), Path("/root"),
            Path("/root"), 1, None, "a" * 64,
        )
        self.assertEqual(legacy.provenance_digest, "a" * 64)
        with self.assertRaisesRegex(mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"):
            mod._measurement_facts(legacy)

    def test_registered_types_are_weak_identity_keys_and_reject_copy_pickle_subclass(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            launch, _process = self._test_issuance(Path(temp).resolve())
            measurement = object.__getattribute__(
                launch, "_LockedOpenCodeLaunch__measurement"
            )
            self.assertIs(weakref.ref(launch)(), launch)
            self.assertIs(weakref.ref(measurement)(), measurement)
            for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaises(TypeError):
                        operation(launch)
                    with self.assertRaises(TypeError):
                        operation(measurement)
        with self.assertRaises(TypeError):
            class _LaunchSubclass(mod.LockedOpenCodeLaunch):
                pass
        with self.assertRaises(TypeError):
            class _MeasurementSubclass(mod._LockedOpenCodeLaunchMeasurement):
                pass

    def test_fake_launch_with_fake_or_registered_measurement_never_enters_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            issued, _process = self._test_issuance(root)
            registered_measurement = object.__getattribute__(
                issued, "_LockedOpenCodeLaunch__measurement"
            )
            fake_measurement = object.__new__(mod._LockedOpenCodeLaunchMeasurement)
            for measurement in (fake_measurement, registered_measurement, object()):
                fake = object.__new__(mod.LockedOpenCodeLaunch)
                object.__setattr__(
                    fake, "_LockedOpenCodeLaunch__measurement", measurement
                )
                with self.subTest(measurement=type(measurement).__name__):
                    with self.assertRaisesRegex(
                        mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                    ):
                        mod._measurement_facts(fake)
                    with self.assertRaisesRegex(
                        mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                    ):
                        mod._consume_test_only_locked_launch(fake)

    def test_registered_launch_rejects_replaced_or_mutated_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            first_root, second_root = root / "first", root / "second"
            first_root.mkdir()
            second_root.mkdir()
            first, _first_process = self._test_issuance(first_root, pid=41001)
            second, _second_process = self._test_issuance(
                second_root, pid=41002, marker="b"
            )
            original = object.__getattribute__(
                first, "_LockedOpenCodeLaunch__measurement"
            )
            other = object.__getattribute__(
                second, "_LockedOpenCodeLaunch__measurement"
            )
            for replacement in (other, object.__new__(mod._LockedOpenCodeLaunchMeasurement), object()):
                object.__setattr__(
                    first, "_LockedOpenCodeLaunch__measurement", replacement
                )
                with self.subTest(replacement=type(replacement).__name__):
                    with self.assertRaisesRegex(
                        mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                    ):
                        mod._consume_test_only_locked_launch(first)
            object.__setattr__(first, "_LockedOpenCodeLaunch__measurement", original)
            object.__setattr__(original, "_adapter_version", "forged")
            with self.assertRaisesRegex(
                mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
            ):
                mod._consume_test_only_locked_launch(first)

    def test_registry_snapshot_rejects_launch_process_path_port_and_seal_mutation(self) -> None:
        mutations = (
            lambda launch, _measurement: object.__setattr__(launch, "process", _FakeLiveProcess(41001)),
            lambda launch, _measurement: object.__setattr__(launch, "port", 32124),
            lambda launch, _measurement: object.__setattr__(launch, "root", launch.workspace),
            lambda _launch, measurement: object.__setattr__(measurement, "_sealed", False),
            lambda _launch, measurement: object.__setattr__(measurement, "_process_pid", 99999),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                launch, _process = self._test_issuance(
                    Path(temp).resolve(), pid=41001 + index
                )
                measurement = object.__getattribute__(
                    launch, "_LockedOpenCodeLaunch__measurement"
                )
                mutate(launch, measurement)
                with self.assertRaisesRegex(
                    mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                ):
                    mod._consume_test_only_locked_launch(launch)

    def test_test_issuance_cannot_cross_production_boundary_and_consumes_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            launch, process = self._test_issuance(root)
            with self.assertRaisesRegex(
                mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
            ):
                mod._measurement_facts(launch)
            with self.assertRaisesRegex(
                mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
            ):
                mod._consume_verified_locked_launch(launch)
            consumed = mod._consume_test_only_locked_launch(launch)
            self.assertEqual(consumed.facts, self._test_facts())
            self.assertIs(consumed.process, process)
            self.assertEqual(consumed.process_pid, process.pid)
            self.assertEqual(consumed.root, root)
            self.assertEqual(consumed.workspace, root / "workspace")
            self.assertEqual(consumed.port, 32123)
            with self.assertRaisesRegex(
                mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
            ):
                mod._consume_test_only_locked_launch(launch)

    def test_test_registry_consume_is_atomic_across_threads(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            launch, _process = self._test_issuance(Path(temp).resolve())
            gate = threading.Barrier(8)
            successes: list[object] = []
            failures: list[str] = []
            result_lock = threading.Lock()

            def consume() -> None:
                gate.wait()
                try:
                    value = mod._consume_test_only_locked_launch(launch)
                    with result_lock:
                        successes.append(value)
                except mod.RealTaskError as error:
                    with result_lock:
                        failures.append(error.code)

            threads = [threading.Thread(target=consume) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(len(successes), 1)
            self.assertEqual(
                failures, ["BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"] * 7
            )

    def test_dependency_counts_must_fit_rust_u16_nonzero_contract(self) -> None:
        for field in (
            "full_locked_dependency_count",
            "installed_platform_dependency_count",
        ):
            for value in (0, 65536, -1, True):
                with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp).resolve()
                    paths = {name: root / name for name in (
                        "workspace", "home", "xdg", "install"
                    )}
                    for path in paths.values():
                        path.mkdir()
                    facts = self._test_facts()
                    facts[field] = value
                    with self.assertRaisesRegex(
                        mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                    ):
                        mod._issue_test_only_locked_launch(
                            root=root, workspace=paths["workspace"],
                            home=paths["home"], xdg=paths["xdg"],
                            install=paths["install"], port=32123,
                            process=_FakeLiveProcess(41001), facts=facts,
                        )

    def test_production_recheck_requires_current_default_task_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            record, capture, darwin = self._artifact_record(
                Path(temp).resolve(), task_digest="b" * 64
            )
            with (mock.patch.object(mod, "_capture_contract", return_value=capture),
                  mock.patch.object(mod, "_darwin_live_executable", return_value=darwin),
                  mock.patch.object(mod, "isolated_base_env", return_value={})):
                with self.assertRaisesRegex(
                    mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                ):
                    mod._verify_registry_artifacts(record)
            self.assertEqual(darwin.calls, 0)

    def test_production_recheck_remeasures_live_native_image(self) -> None:
        for live_digest, succeeds in ((None, True), ("c" * 64, False)):
            with self.subTest(live_digest=live_digest), tempfile.TemporaryDirectory() as temp:
                record, capture, darwin = self._artifact_record(
                    Path(temp).resolve(), live_digest=live_digest
                )
                with (mock.patch.object(mod, "_capture_contract", return_value=capture),
                      mock.patch.object(mod, "_darwin_live_executable", return_value=darwin),
                      mock.patch.object(mod, "isolated_base_env", return_value={})):
                    if succeeds:
                        mod._verify_registry_artifacts(record)
                    else:
                        with self.assertRaisesRegex(
                            mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                        ):
                            mod._verify_registry_artifacts(record)
                self.assertEqual(darwin.calls, 1)

    def test_shape_probe_and_public_constructor_are_not_production_issuance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for name in ("workspace", "home", "xdg", "install"):
                (root / name).mkdir()
            shape_probe = mod.LockedOpenCodeLaunch(
                root, root / "workspace", root / "home", root / "xdg",
                root / "install", 32123, _FakeLiveProcess(41001), "a" * 64,
            )
            for operation in (
                mod._measurement_facts, mod._consume_verified_locked_launch
            ):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaisesRegex(
                        mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                    ):
                        operation(shape_probe)

    def test_legacy_and_object_new_launches_cannot_consume(self) -> None:
        root = Path("/private/legacy")
        legacy = mod.LockedOpenCodeLaunch(
            root, root, root, root, root, 32123, None, "a" * 64
        )
        blank = object.__new__(mod.LockedOpenCodeLaunch)
        for launch in (legacy, blank):
            with self.subTest(launch=launch):
                with self.assertRaisesRegex(
                    mod.RealTaskError, "BLOCKED_LOCKED_RUNTIME_UNAVAILABLE"
                ):
                    mod._consume_verified_locked_launch(launch)

    def test_npm_is_resolved_once_to_canonical_regular_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            executable = root / "npm-real"
            executable.write_text("#!/bin/sh\n")
            executable.chmod(0o755)
            alias = root / "npm"
            alias.symlink_to(executable)
            with mock.patch.object(mod.shutil, "which", return_value=str(alias)):
                self.assertEqual(mod._canonical_npm_executable(), executable.resolve())

    def test_fixture_recheck_detects_materialized_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            manifest = mod.fixture_manifest()
            mod.materialize_fixture(workspace, manifest)
            self.assertTrue(mod._fixture_matches_workspace(workspace, manifest))
            (workspace / "README.md").write_text("changed")
            self.assertFalse(mod._fixture_matches_workspace(workspace, manifest))


if __name__ == "__main__":
    unittest.main()
