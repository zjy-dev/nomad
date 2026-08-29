from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import lifecycle_coordinator as coordinator
from tools.nomad_web import processes
from tools.nomad_web.state import initialize_home


class LifecycleCoordinatorTests(unittest.TestCase):
    @staticmethod
    def reset_result() -> dict:
        return {
            "schema": "nomad.web-companion.remote-access-reset.v1",
            "state": "STOPPED", "mode": "foundation-readonly",
            "remote_access": "CLEARED", "install_state": "PRESERVED",
            "host_identity_disposition": "retained", "production_ready": False,
        }

    def request(self, request_id: str = "request_0123456789abcdef", operation: str = "reset_remote_access") -> dict:
        return {
            "schema": coordinator.REQUEST_SCHEMA,
            "operation": operation,
            "confirm": True,
            "request_id": request_id,
            "run_id": "1" * 64,
            "bundle_digest": "2" * 64,
            "install_sequence": 7,
            "gateway_identity": "3" * 64,
            "coordinator_identity": "4" * 64,
        }

    def test_protocol_is_canonical_exact_bounded_and_rejects_duplicates(self) -> None:
        request = self.request()
        raw = coordinator.canonical_json(request)
        self.assertEqual(coordinator.decode_message(raw, schema=coordinator.REQUEST_SCHEMA), request)
        invalid = (
            json.dumps(request).encode(),
            raw[:-1] + b',"extra":true}',
            raw.replace(b'"confirm":true', b'"confirm":false'),
            b'{"schema":"nomad.web-companion.lifecycle-request.v1","schema":"nomad.web-companion.lifecycle-request.v1"}',
            b"x" * (coordinator.MAX_FRAME_BYTES + 1),
        )
        for value in invalid:
            with self.subTest(value=value[:80]), self.assertRaises(RuntimeError):
                coordinator.decode_message(value, schema=coordinator.REQUEST_SCHEMA)

    def test_journal_is_private_durable_idempotent_single_flight_and_conflict_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "journal"
            journal = coordinator.OperationJournal(root, home_commitment="a" * 64)
            request = self.request()
            accepted = journal.accept(request)
            self.assertEqual(accepted["state"], "ACCEPTED")
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            files = list(root.glob("operation-*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
            self.assertEqual(journal.accept(request), accepted)
            conflict = self.request(operation="uninstall")
            with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_REQUEST_ID_CONFLICT"):
                journal.accept(conflict)
            with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_OPERATION_IN_PROGRESS"):
                journal.accept(self.request("another_request_abcdef"))
            self.assertEqual(journal.commit(request, accepted["commit_challenge"])["state"], "COMMITTED")
            result = self.reset_result()
            self.assertEqual(journal.complete(request, result=result)["state"], "COMPLETED")
            self.assertEqual(journal.accept(request)["result"], result)
            self.assertEqual(
                files[0].read_bytes(),
                coordinator.canonical_json(journal.records()[0]) + b"\n",
            )

    def test_operation_status_queries_explicit_and_latest_without_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(home=Path(temporary) / "home")
            journal = coordinator.OperationJournal(
                coordinator.journal_root(config.home, "uninstall"),
                home_commitment=coordinator.home_commitment(config.home),
            )
            request = self.request("operation_status_012345", "uninstall")
            accepted = journal.accept(request)
            journal.commit(request, accepted["commit_challenge"])
            journal.complete(request, result={
                "schema": "nomad.web-companion.uninstall-result.v1",
                "state": "UNINSTALLED", "mode": "foundation-readonly",
                "remote_access": "CLEARED", "install_state": "REMOVED",
                "host_identity_disposition": "retained", "production_ready": False,
            })
            journal.close()
            explicit = coordinator.operation_status(config, request["request_id"])
            latest = coordinator.operation_status(config, latest=True)
            self.assertEqual(
                {key: value for key, value in explicit.items() if key != "latest_known"},
                {key: value for key, value in latest.items() if key != "latest_known"},
            )
            self.assertEqual(explicit["state"], "completed")
            self.assertNotIn("request", explicit)
            self.assertNotIn("commit_challenge", explicit)
            self.assertFalse(explicit["latest_known"])
            self.assertTrue(latest["latest_known"])

    def test_operation_status_keeps_live_committed_worker_in_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(home=Path(temporary) / "home")
            journal = coordinator.OperationJournal(
                coordinator.journal_root(config.home, "uninstall"),
                home_commitment=coordinator.home_commitment(config.home),
            )
            for operation in ("reset_remote_access", "uninstall"):
                request = self.request(f"live_{operation}_012345", operation)
                worker = {"pid": 42, "process_group": 42, "identity": "d" * 64}
                accepted = journal.accept(request, worker)
                journal.commit(request, accepted["commit_challenge"])
                with mock.patch.object(processes, "ownership", return_value="owned"), mock.patch.object(journal, "reconcile") as reconcile:
                    status = coordinator.operation_status(config, request["request_id"])
                self.assertEqual(status["state"], "committed")
                self.assertFalse(status["terminal"]); reconcile.assert_not_called()
                journal.complete(request, result=(self.reset_result() if operation == "reset_remote_access" else {
                    "schema": "nomad.web-companion.uninstall-result.v1", "state": "UNINSTALLED", "mode": "foundation-readonly", "remote_access": "CLEARED", "install_state": "REMOVED", "host_identity_disposition": "retained", "production_ready": False,
                }))
            journal.close()

    def test_legacy_v1_journal_terminal_survives_and_inflight_becomes_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "journal"
            journal = coordinator.OperationJournal(root, home_commitment="a" * 64)
            cases = (("legacy_completed_012345", "COMPLETED"), ("legacy_committed_012345", "COMMITTED"))
            for request_id, state in cases:
                request = self.request(request_id, "reset_remote_access")
                legacy = {
                    "schema": coordinator.LEGACY_JOURNAL_SCHEMA, "request": request,
                    "state": state, "commit_challenge": "e" * 64,
                    "result": self.reset_result() if state == "COMPLETED" else None,
                    "error": None,
                }
                journal._create(journal._name(request_id), coordinator.canonical_json(legacy) + b"\n")
            records = journal.records()
            self.assertEqual(records[0]["state"], "OUTCOME_UNKNOWN")
            self.assertEqual(records[1]["state"], "COMPLETED")
            self.assertTrue(all(record["schema"] == coordinator.JOURNAL_SCHEMA for record in records))
            self.assertTrue(all("worker_binding" in record for record in records))

    def test_worker_sends_accepted_only_after_intent_exists_then_waits_for_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = coordinator.OperationJournal(Path(temporary) / "journal", home_commitment="a" * 64)
            server, client = socket.socketpair()
            request = self.request()
            executed: list[str] = []
            outcome: list[dict] = []

            def worker() -> None:
                outcome.append(coordinator.serve_once(
                    SimpleNamespace(home=Path(temporary) / "home"), server,
                    gateway={}, coordinator={"pid": 99, "process_group": 99, "identity": request["coordinator_identity"]}, journal=journal,
                    verifier=lambda *_args, **_kwargs: None,
                    executor=lambda _config, operation: executed.append(operation) or self.reset_result(),
                ))

            thread = threading.Thread(target=worker)
            thread.start()
            try:
                coordinator.send_message(client, request)
                accepted = self.receive_response(client)
                self.assertEqual(accepted["state"], "ACCEPTED")
                self.assertEqual(journal.records()[0]["state"], "ACCEPTED")
                self.assertEqual(executed, [])
                self.assertRegex(accepted["commit_challenge"], r"^[0-9a-f]{64}$")
                commit = dict(
                    request, schema=coordinator.COMMIT_SCHEMA,
                    commit_challenge=accepted["commit_challenge"],
                )
                coordinator.send_message(client, commit)
                completed = self.receive_response(client)
                self.assertEqual(completed["state"], "COMPLETED")
                self.assertEqual(executed, ["reset_remote_access"])
            finally:
                client.close(); server.close(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(outcome[0]["state"], "COMPLETED")

    def test_destructive_executor_requires_committed_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(
                home=Path(temporary) / "home", relay_port=18089,
                gateway_port=14173, agent_port=4096, join_gateway_port=14174,
                relay_host_v2_port=18090, relay_device_v2_port=18091,
                relay_admin_port=18092, relay_device_v1_port=18093,
            )
            journal = coordinator.OperationJournal(Path(temporary) / "journal", home_commitment="a" * 64)
            request = self.request()
            journal.accept(request)
            gateway = {"pid": 12345, "process_group": 12345, "identity": request["gateway_identity"]}
            with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_OPERATION_NOT_COMMITTED"):
                coordinator.execute_operation(
                    config, request["operation"], request=request,
                    gateway=gateway, coordinator={
                        "pid": os.getpid(), "process_group": os.getpid(),
                        "identity": request["coordinator_identity"],
                    }, journal=journal,
                )

    def test_wrong_commit_challenge_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = coordinator.OperationJournal(Path(temporary) / "journal", home_commitment="a" * 64)
            request = self.request()
            accepted = journal.accept(request)
            self.assertNotEqual(accepted["commit_challenge"], "0" * 64)
            with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_COMMIT_MISMATCH"):
                journal.commit(request, "0" * 64)
            self.assertEqual(journal.records()[0]["state"], "ACCEPTED")

    def test_reconcile_resolves_every_crash_window_without_replay(self) -> None:
        from tools.nomad_web import launcher

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = SimpleNamespace(home=root / "home")
            journal = coordinator.OperationJournal(root / "journal", home_commitment="a" * 64)
            accepted_request = self.request("accepted_crash_window")
            journal.accept(accepted_request)
            resolved = journal.reconcile(config)
            self.assertEqual(resolved[0]["state"], "FAILED")
            self.assertEqual(resolved[0]["error"], "LIFECYCLE_COMMIT_NOT_OBSERVED")

            uninstall_request = self.request("uninstall_crash_done", "uninstall")
            accepted = journal.accept(uninstall_request)
            journal.commit(uninstall_request, accepted["commit_challenge"])
            resolved = journal.reconcile(config)
            self.assertEqual(resolved[0]["state"], "COMPLETED")

            config.home.mkdir()
            unknown_request = self.request("uninstall_crash_unknown", "uninstall")
            accepted = journal.accept(unknown_request)
            journal.commit(unknown_request, accepted["commit_challenge"])
            with mock.patch.object(launcher, "_reset_remote_access_unlocked") as replay:
                resolved = journal.reconcile(config)
            replay.assert_not_called()
            self.assertEqual(resolved[0]["state"], "OUTCOME_UNKNOWN")
            self.assertEqual(resolved[0]["error"], "LIFECYCLE_OUTCOME_UNKNOWN")
            self.assertEqual(journal.accept(self.request("flight_released_after_unknown"))["state"], "ACCEPTED")

    def test_crash_injection_after_commit_is_reconciled_without_executor_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = SimpleNamespace(home=root / "home")
            journal = coordinator.OperationJournal(root / "journal", home_commitment="a" * 64)
            server, client = socket.socketpair()
            request = self.request("crash_after_commit", "uninstall")
            observed: list[str] = []

            def crash(stage: str) -> None:
                if stage == "after_commit":
                    raise RuntimeError("INJECTED_PROCESS_CRASH")

            def worker() -> None:
                try:
                    coordinator.serve_once(
                        config, server, gateway={}, coordinator={"pid": 99, "process_group": 99, "identity": request["coordinator_identity"]}, journal=journal,
                        verifier=lambda *_args, **_kwargs: None,
                        executor=lambda *_args, **_kwargs: observed.append("executed") or {},
                    )
                except RuntimeError as error:
                    observed.append(str(error))

            with mock.patch.object(coordinator, "_checkpoint", side_effect=crash):
                thread = threading.Thread(target=worker)
                thread.start()
                coordinator.send_message(client, request)
                accepted = self.receive_response(client)
                coordinator.send_message(client, dict(
                    request, schema=coordinator.COMMIT_SCHEMA,
                    commit_challenge=accepted["commit_challenge"],
                ))
                thread.join(timeout=2)
            server.close(); client.close()
            self.assertEqual(observed, ["INJECTED_PROCESS_CRASH"])
            self.assertEqual(journal.records()[0]["state"], "COMMITTED")
            self.assertEqual(journal.reconcile(config)[0]["state"], "COMPLETED")
            self.assertNotIn("executed", observed)

    def test_journal_rejects_root_rename_swap_after_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "journal"
            journal = coordinator.OperationJournal(root, home_commitment="a" * 64)
            moved = base / "journal-old"
            root.rename(moved)
            root.mkdir(mode=0o700)
            (root / "marker.json").write_bytes((moved / "marker.json").read_bytes())
            os.chmod(root / "marker.json", 0o600)
            with self.assertRaisesRegex(RuntimeError, "UNSAFE_LIFECYCLE_JOURNAL_ROOT"):
                journal.records()

    def test_directory_inode_lock_survives_marker_replacement_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "journal"
            first = coordinator.OperationJournal(root, home_commitment="a" * 64)
            second = coordinator.OperationJournal(root, home_commitment="a" * 64)
            first_entered = threading.Event()
            release_first = threading.Event()
            second_entered = threading.Event()

            def hold_first() -> None:
                with first._locked():
                    first_entered.set()
                    release_first.wait(timeout=2)

            def enter_second() -> None:
                with second._locked():
                    second_entered.set()

            thread_a = threading.Thread(target=hold_first)
            thread_b = threading.Thread(target=enter_second)
            thread_a.start()
            self.assertTrue(first_entered.wait(timeout=1))
            marker = root / "marker.json"
            raw = marker.read_bytes()
            marker.unlink()
            marker.write_bytes(raw)
            os.chmod(marker, 0o600)
            thread_b.start()
            self.assertFalse(second_entered.wait(timeout=0.1))
            release_first.set()
            thread_a.join(timeout=2)
            thread_b.join(timeout=2)
            self.assertTrue(second_entered.is_set())

    def test_journal_concurrent_accept_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = coordinator.OperationJournal(Path(temporary) / "journal", home_commitment="a" * 64)
            barrier = threading.Barrier(3)
            outcomes: list[str] = []

            def accept(request: dict) -> None:
                barrier.wait()
                try:
                    outcomes.append(journal.accept(request)["request"]["request_id"])
                except RuntimeError as error:
                    outcomes.append(str(error))

            threads = [
                threading.Thread(target=accept, args=(self.request("concurrent_request_one"),)),
                threading.Thread(target=accept, args=(self.request("concurrent_request_two"),)),
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=2)
            self.assertEqual(len(journal.records()), 1)
            self.assertEqual(outcomes.count("LIFECYCLE_OPERATION_IN_PROGRESS"), 1)

    def test_locked_primitives_perform_real_reset_and_uninstall_without_relocking(self) -> None:
        from tools.nomad_web import launcher

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host_identity = root / "host-identity"
            host_identity.write_text("preserve", encoding="utf-8")
            for operation in ("reset_remote_access", "uninstall"):
                home = root / operation
                config = SimpleNamespace(home=home)
                initialize_home(config)
                for name in ("bin", "run", "logs"):
                    (home / name).mkdir(mode=0o700)
                private = home / "private"
                private.mkdir(mode=0o700)
                remote = private / "remote-mailbox.sqlite3"
                remote.write_bytes(b"owned")
                os.chmod(remote, 0o600)
                with coordinator.lifecycle_lock(config, create=False) as owned:
                    self.assertTrue(owned)
                    if operation == "reset_remote_access":
                        result = launcher._reset_remote_access_unlocked(config)
                    else:
                        launcher._reset_remote_access_unlocked(config)
                        result = launcher._uninstall_lifecycle_unlocked(config)
                self.assertEqual(result["host_identity_disposition"], "retained")
                if operation == "reset_remote_access":
                    self.assertTrue(home.is_dir())
                    self.assertFalse(private.exists())
                else:
                    self.assertFalse(home.exists())
                self.assertEqual(host_identity.read_text(encoding="utf-8"), "preserve")

    def test_direct_uninstall_still_blocks_until_remote_state_is_reset(self) -> None:
        from tools.nomad_web import launcher

        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(home=Path(temporary) / "home")
            initialize_home(config)
            for name in ("bin", "run", "logs"):
                (config.home / name).mkdir(mode=0o700)
            private = config.home / "private"
            private.mkdir(mode=0o700)
            remote = private / "remote-mailbox.sqlite3"
            remote.write_bytes(b"owned")
            os.chmod(remote, 0o600)
            with self.assertRaisesRegex(RuntimeError, "REMOTE_UNINSTALL_REVOKE_REQUIRED"):
                launcher.uninstall_lifecycle(config)
            self.assertTrue(remote.is_file())

    def test_worker_action_stops_real_workload_before_reset_cleanup(self) -> None:
        from tools.nomad_web import launcher

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = SimpleNamespace(home=root / "home")
            initialize_home(config)
            for name in ("bin", "run", "logs"):
                (config.home / name).mkdir(mode=0o700)
            child = processes.spawn(
                "workload", ["/bin/sleep", "30"], root,
                processes.minimal_env(), config.home / "logs" / "workload.log",
            )
            run_state = {"mode": "foundation-readonly", "processes": [child]}
            fake_path = mock.Mock()
            fake_path.unlink = mock.Mock()
            try:
                with mock.patch("tools.nomad_web.launcher.read_run_state", return_value=run_state), mock.patch("tools.nomad_web.launcher._cleanup_run_artifacts"), mock.patch("tools.nomad_web.launcher.state_path", return_value=fake_path):
                    with coordinator.lifecycle_lock(config, create=False) as owned:
                        self.assertTrue(owned)
                        result = launcher._reset_remote_access_unlocked(config)
                self.assertEqual(result["state"], "STOPPED")
                self.assertEqual(processes.ownership(child), "absent")
                fake_path.unlink.assert_called_once_with(missing_ok=True)
            finally:
                if processes.ownership(child) == "owned":
                    processes.stop(child)

    def test_stop_preserves_only_exact_coordinator_self_binding(self) -> None:
        from tools.nomad_web import launcher

        workload = {"name": "desktop-gateway", "pid": 101, "process_group": 101, "identity": "a" * 64, "log": "/tmp/gateway.log"}
        sidecar = {"name": "lifecycle-coordinator", "pid": 202, "process_group": 202, "identity": "b" * 64}
        current = {"mode": "remote-local-evidence", "processes": [workload], "lifecycle_coordinator": sidecar}
        stopped = []
        with mock.patch.object(launcher, "read_run_state", return_value=current), mock.patch.object(processes, "ownership", side_effect=lambda record: "owned" if record in (workload, sidecar) else "mismatch"), mock.patch.object(processes, "stop", side_effect=lambda record: stopped.append(record["name"]) or True), mock.patch.object(launcher, "_cleanup_run_artifacts"), mock.patch.object(launcher, "state_path") as path:
            path.return_value.unlink = mock.Mock()
            launcher._stop_unlocked(SimpleNamespace())
            self.assertEqual(stopped, ["desktop-gateway", "lifecycle-coordinator"])
            stopped.clear()
            launcher._stop_unlocked(
                SimpleNamespace(), preserve_lifecycle_coordinator={
                    name: sidecar[name] for name in ("pid", "process_group", "identity")
                },
            )
            self.assertEqual(stopped, ["desktop-gateway"])

    def test_spawn_worker_is_separate_session_and_not_a_workload_record(self) -> None:
        gateway = {"pid": 12345, "process_group": 12345, "identity": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(
                home=Path(temporary) / "home", relay_port=18089,
                gateway_port=14173, agent_port=4096, join_gateway_port=14174,
                relay_host_v2_port=18090, relay_device_v2_port=18091,
                relay_admin_port=18092, relay_device_v1_port=18093,
            )
            record, channel, release_fd, operational_fd = coordinator.spawn_worker(config, gateway=gateway)
            try:
                self.assertEqual(record["name"], "lifecycle-coordinator")
                self.assertEqual(record["pid"], record["process_group"])
                self.assertNotEqual(record["process_group"], os.getpgrp())
                self.assertEqual(os.getsid(record["pid"]), record["pid"])
            finally:
                coordinator.release_worker(release_fd)
                coordinator.confirm_worker_operational(operational_fd, record)
                channel.close()
                try:
                    os.waitpid(record["pid"], 0)
                except ChildProcessError:
                    pass

    def test_missing_worker_ready_ack_kills_and_reaps_without_returning_record(self) -> None:
        gateway = {"pid": 12345, "process_group": 12345, "identity": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            coordinator.os, "posix_spawn", return_value=4242,
        ), mock.patch.object(
            coordinator.processes, "process_identity", return_value="b" * 64,
        ), mock.patch.object(
            coordinator.processes, "ownership", return_value="owned",
        ), mock.patch.object(
            coordinator, "_receive_worker_signal",
            side_effect=RuntimeError("LIFECYCLE_COORDINATOR_START_FAILED"),
        ), mock.patch.object(coordinator.os, "killpg") as kill, mock.patch.object(
            coordinator.os, "waitpid",
        ) as wait:
            config = SimpleNamespace(
                home=Path(temporary) / "home", relay_port=18089,
                gateway_port=14173, agent_port=4096, join_gateway_port=14174,
                relay_host_v2_port=18090, relay_device_v2_port=18091,
                relay_admin_port=18092, relay_device_v1_port=18093,
            )
            with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_COORDINATOR_START_FAILED"):
                coordinator.spawn_worker(config, gateway=gateway)
            kill.assert_called_once_with(4242, 9)
            wait.assert_called_once_with(4242, 0)

    def test_malformed_journal_blocks_operational_ack(self) -> None:
        gateway = {"pid": 12345, "process_group": 12345, "identity": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(
                home=Path(temporary) / "home", relay_port=18089,
                gateway_port=14173, agent_port=4096, join_gateway_port=14174,
                relay_host_v2_port=18090, relay_device_v2_port=18091,
                relay_admin_port=18092, relay_device_v1_port=18093,
            )
            root = coordinator.journal_root(config.home, "uninstall")
            journal = coordinator.OperationJournal(
                root, home_commitment=coordinator.home_commitment(config.home),
            )
            journal._create("operation-malformed_record_01.json", b"{}\n")
            journal.close()
            record, channel, release_fd, operational_fd = coordinator.spawn_worker(
                config, gateway=gateway, run_id="b" * 64,
                bundle_digest="c" * 64, install_sequence=1,
            )
            try:
                coordinator.release_worker(release_fd)
                with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_COORDINATOR_START_FAILED"):
                    coordinator.confirm_worker_operational(operational_fd, record)
            finally:
                channel.close()
                try: os.waitpid(record["pid"], 0)
                except ChildProcessError: pass

    def test_spawn_worker_early_failure_closes_created_descriptors(self) -> None:
        gateway = {"pid": 12345, "process_group": 12345, "identity": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(home=Path(temporary) / "relative")
            before = len(list(Path("/dev/fd").iterdir()))
            with self.assertRaisesRegex(RuntimeError, "LIFECYCLE_WORKER_BOOTSTRAP_INVALID"):
                coordinator.spawn_worker(config, gateway=gateway)
            self.assertEqual(len(list(Path("/dev/fd").iterdir())), before)

    def test_existing_gateway_channel_receives_content_free_worker_bootstrap(self) -> None:
        gateway = {"pid": 12345, "process_group": 12345, "identity": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            config = SimpleNamespace(
                home=Path(temporary) / "home", relay_port=18089,
                gateway_port=14173, agent_port=4096, join_gateway_port=14174,
                relay_host_v2_port=18090, relay_device_v2_port=18091,
                relay_admin_port=18092, relay_device_v1_port=18093,
            )
            gateway_channel, worker_channel = socket.socketpair()
            record = None
            try:
                record, returned, release_fd, operational_fd = coordinator.spawn_worker(
                    config, gateway=gateway, run_id="b" * 64,
                    bundle_digest="c" * 64, install_sequence=9,
                    channel=worker_channel,
                )
                self.assertIsNone(returned)
                coordinator.release_worker(release_fd)
                size = int.from_bytes(coordinator._recv_exact(gateway_channel, 4), "big")
                ready = json.loads(coordinator._recv_exact(gateway_channel, size))
                self.assertEqual(ready, {
                    "schema": coordinator.GATEWAY_BOOTSTRAP_SCHEMA,
                    "run_id": "b" * 64, "bundle_digest": "c" * 64,
                    "install_sequence": 9, "gateway_identity": "a" * 64,
                    "coordinator_identity": record["identity"],
                })
                self.assertEqual(os.getsid(record["pid"]), record["pid"])
                coordinator.confirm_worker_operational(operational_fd, record)
            finally:
                gateway_channel.close()
                if record is not None:
                    try:
                        os.waitpid(record["pid"], 0)
                    except ChildProcessError:
                        pass

    def test_process_stop_fails_closed_for_self_group(self) -> None:
        self_record = {"pid": os.getpid(), "process_group": os.getpgrp(), "identity": "a" * 64}
        with mock.patch.object(processes, "ownership", return_value="owned"), mock.patch.object(processes.os, "killpg") as kill:
            self.assertFalse(processes.stop(self_record))
            kill.assert_not_called()

    def test_real_gateway_process_group_initiates_reset_and_uninstall(self) -> None:
        gateway_module = Path(__file__).resolve().parents[2] / "mobile-reference" / "pilot-gateway" / "server.mjs"
        node_program = (
            "import {createLifecycleBridge} from " + json.dumps(gateway_module.as_uri()) + ";"
            "const bridge=createLifecycleBridge({channelFd:12});"
            "const accepted=await bridge.begin(process.argv[1],'operation_0123456789');"
            "process.stdout.write(JSON.stringify(accepted)+'\\n');"
            "await bridge.commit();"
        )
        for operation in ("reset_remote_access", "uninstall"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); home = root / "home"; home.mkdir(mode=0o700)
                install = home / "install"; install.mkdir(mode=0o700)
                retained = install / "retained"; retained.write_text("installed", encoding="utf-8")
                host_identity = root / "host-identity"; host_identity.write_text("retained", encoding="utf-8")
                gateway_end, worker_end = socket.socketpair()
                gateway = processes.spawn(
                    "desktop-gateway",
                    ["node", "--input-type=module", "-e", node_program, operation],
                    root, processes.minimal_env(), root / "gateway.log",
                    extra_fd_actions=((gateway_end.fileno(), 12),),
                    close_fds=(gateway_end.fileno(),),
                )
                gateway_end.close()
                pid = os.fork()
                if pid == 0:
                    try:
                        os.setsid(); parent_end = worker_end
                        binding = {
                            "pid": os.getpid(), "process_group": os.getpgrp(),
                            "identity": processes.process_identity(os.getpid()),
                        }
                        ready = coordinator.gateway_bootstrap(
                            run_id="b" * 64, bundle_digest="c" * 64,
                            install_sequence=1, gateway=gateway, coordinator=binding,
                        )
                        parent_end.sendall(len(ready).to_bytes(4, "big") + ready)
                        def verify(_config, request, **_bindings):
                            assert request["gateway_identity"] == gateway["identity"]
                            assert request["coordinator_identity"] == binding["identity"]
                            assert processes.ownership(gateway) == "owned"
                        def execute(_config, selected):
                            os.killpg(gateway["process_group"], 15)
                            if selected == "uninstall": shutil.rmtree(home)
                            return (
                                {"schema": "nomad.web-companion.remote-access-reset.v1", "state": "STOPPED", "mode": "foundation-readonly", "remote_access": "CLEARED", "install_state": "PRESERVED", "host_identity_disposition": "retained", "production_ready": False}
                                if selected == "reset_remote_access" else
                                {"schema": "nomad.web-companion.uninstall-result.v1", "state": "UNINSTALLED", "mode": "foundation-readonly", "remote_access": "CLEARED", "install_state": "REMOVED", "host_identity_disposition": "retained", "production_ready": False}
                            )
                        coordinator.serve_once(
                            SimpleNamespace(home=home), parent_end, gateway=gateway,
                            coordinator=binding, journal=coordinator.OperationJournal(
                                root / "journal",
                                home_commitment=coordinator.home_commitment(home),
                            ), verifier=verify, executor=execute,
                        )
                        os._exit(0)
                    except BaseException as error:
                        (root / "coordinator-error.txt").write_text(
                            repr(error), encoding="utf-8",
                        )
                        os._exit(1)
                worker_end.close()
                reaper = threading.Thread(target=os.waitpid, args=(gateway["pid"], 0))
                reaper.start()
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and processes.ownership(gateway) != "absent":
                    time.sleep(0.02)
                self.assertEqual(processes.ownership(gateway), "absent")
                waited, status = os.waitpid(pid, 0)
                self.assertEqual(waited, pid)
                self.assertEqual(
                    os.waitstatus_to_exitcode(status), 0,
                    "; ".join(
                        path.read_text(encoding="utf-8")
                        for path in (root / "coordinator-error.txt", root / "gateway.log")
                        if path.exists()
                    ) or "no child error",
                )
                reaper.join(timeout=2)
                record = coordinator.OperationJournal(
                    root / "journal", home_commitment=coordinator.home_commitment(home),
                ).records()[0]
                self.assertEqual(record["state"], "COMPLETED")
                self.assertEqual(host_identity.read_text(encoding="utf-8"), "retained")
                self.assertEqual(home.exists(), operation == "reset_remote_access")
                if operation == "reset_remote_access": self.assertTrue(retained.is_file())

    @staticmethod
    def receive_response(channel: socket.socket) -> dict:
        size = int.from_bytes(coordinator._recv_exact(channel, 4), "big")
        return json.loads(coordinator._recv_exact(channel, size))


if __name__ == "__main__":
    unittest.main()
