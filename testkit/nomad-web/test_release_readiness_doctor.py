from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import doctor


def config(root: Path, *, bundle: Path | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        repo_root=root, home=root / "home", bundle_root=bundle,
        relay_port=18089, gateway_port=14173, agent_port=4096,
        join_gateway_port=14174, relay_host_v2_port=18090,
        relay_device_v2_port=18091, relay_admin_port=18092,
        relay_device_v1_port=18093,
    )


def gates(result: Mapping[str, object]) -> dict[str, dict[str, object]]:
    return {item["name"]: item for item in result["release_gates"]}  # type: ignore[index, misc]


def canonical_response(
    status: int, reason: str, value: Mapping[str, object], *,
    cache_control: bool = False, extra_headers: Mapping[str, str] | None = None,
) -> bytes:
    body = json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode() + b"\n"
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if cache_control:
        headers["Cache-Control"] = "no-store"
    headers.update(extra_headers or {})
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{name}: {item}\r\n" for name, item in headers.items())
    return head.encode("ascii") + b"\r\n" + body


class NameOnlyEnvironment(Mapping[str, object]):
    """A mapping that fails the test if any Provider value is fetched."""

    def __init__(self, names: set[str]):
        self.names = names

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self.names

    def __getitem__(self, name: str) -> object:
        raise AssertionError(f"environment value read: {name}")

    def __iter__(self) -> Iterator[str]:
        return iter(self.names)

    def __len__(self) -> int:
        return len(self.names)


class ReleaseReadinessDoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nomad-release-doctor-")
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "bin").mkdir()
        (self.bundle / "bin" / "nomad-product-host").write_bytes(b"binary")
        self.manifest = {"bundle_digest": "a" * 64}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def completed(status: str, returncode: int | None = None, *, stderr: bytes = b"") -> subprocess.CompletedProcess[bytes]:
        if returncode is None:
            returncode = 0 if status == "READY" else 1
        return subprocess.CompletedProcess(
            args=[], returncode=returncode,
            stdout=f'{{"status":"{status}"}}\n'.encode("ascii"), stderr=stderr,
        )

    def common_patches(self):
        return (
            mock.patch.object(doctor, "verify_bundle", return_value=self.manifest),
            mock.patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(doctor, "_free", return_value=True),
            mock.patch.object(doctor, "_read_runtime_state", return_value=(None, False)),
            mock.patch.object(doctor, "_network_address_presence", return_value={"lan_ip_present": True, "global_ip_present": False}),
            mock.patch.object(doctor, "_chrome_gate", return_value=doctor._gate(
                "google_chrome", "PASS", "GOOGLE_CHROME_AVAILABLE", None, {"present": True},
            )),
        )

    def run_with_common_patches(
        self, *, environment: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        patches = self.common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], mock.patch.object(
            doctor.subprocess, "run", return_value=self.completed("READY"),
        ):
            return doctor.run_doctor(config(self.root, bundle=self.bundle), environment=environment or {})

    def test_host_identity_status_table_and_exact_noninteractive_command(self) -> None:
        cases = (
            ("READY", "PASS", "HOST_IDENTITY_READY", None),
            ("AUTH_REQUIRED", "BLOCK", "HOST_IDENTITY_AUTH_REQUIRED", "nomad-web authorize-host-identity"),
            ("USER_DENIED", "BLOCK", "HOST_IDENTITY_USER_DENIED", "nomad-web authorize-host-identity"),
            ("KEYCHAIN_LOCKED", "BLOCK", "HOST_IDENTITY_KEYCHAIN_LOCKED", "unlock the login Keychain and rerun doctor"),
            ("CORRUPT", "BLOCK", "HOST_IDENTITY_CORRUPT", "repair the Host identity and rerun doctor"),
            ("UNAVAILABLE", "BLOCK", "HOST_IDENTITY_UNAVAILABLE", "verify macOS Keychain availability and rerun doctor"),
        )
        for identity_status, gate_status, code, next_step in cases:
            with self.subTest(identity_status=identity_status), mock.patch.object(
                doctor.subprocess, "run", return_value=self.completed(identity_status),
            ) as run:
                result = doctor._host_identity_gate(self.bundle)
                self.assertEqual((result["status"], result["code"], result["next_step"]), (gate_status, code, next_step))
                run.assert_called_once_with(
                    [str(self.bundle / "bin" / "nomad-product-host"), "identity-preflight", "--non-interactive"],
                    cwd=self.bundle,
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=doctor.HOST_IDENTITY_TIMEOUT_SECONDS, check=False,
                )

    def test_host_identity_invalid_output_table_fails_closed(self) -> None:
        cases = (
            subprocess.CompletedProcess([], 0, b'{"status":"READY"}', b""),
            subprocess.CompletedProcess([], 1, b'{"status":"READY"}\n', b""),
            subprocess.CompletedProcess([], 0, b'{"status":"UNKNOWN"}\n', b""),
            subprocess.CompletedProcess([], 0, b'{"status":"READY"}\n', b"diagnostic"),
            subprocess.CompletedProcess([], 0, b'{"status": "READY"}\n', b""),
        )
        for result in cases:
            with self.subTest(result=result), mock.patch.object(doctor.subprocess, "run", return_value=result):
                gate = doctor._host_identity_gate(self.bundle)
                self.assertEqual((gate["status"], gate["code"]), ("BLOCK", "HOST_IDENTITY_PREFLIGHT_INVALID"))
        with mock.patch.object(doctor.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 5)):
            gate = doctor._host_identity_gate(self.bundle)
            self.assertEqual((gate["status"], gate["code"]), ("BLOCK", "HOST_IDENTITY_PREFLIGHT_TIMEOUT"))

    def test_all_runtime_ports_are_checked_and_one_collision_blocks(self) -> None:
        expected_ports = [getattr(config(self.root), name) for name in doctor.RUNTIME_PORT_FIELDS]
        for occupied in (None, "relay_port", "join_gateway_port", "relay_device_v1_port"):
            checked: list[int] = []

            def available(port: int) -> bool:
                checked.append(port)
                return occupied is None or port != getattr(config(self.root), occupied)

            patches = self.common_patches()
            with self.subTest(occupied=occupied), patches[0], patches[1], mock.patch.object(doctor, "_free", side_effect=available), patches[3], patches[4], patches[5], mock.patch.object(doctor.subprocess, "run", return_value=self.completed("READY")):
                result = doctor.run_doctor(config(self.root, bundle=self.bundle), environment={})
            port_gate = gates(result)["runtime_ports"]
            self.assertEqual(checked, expected_ports)
            self.assertEqual(port_gate["observations"]["checked_port_count"], 8)  # type: ignore[index]
            self.assertEqual(port_gate["status"], "PASS" if occupied is None else "BLOCK")
            self.assertEqual(port_gate["code"], "ALL_RUNTIME_PORTS_AVAILABLE" if occupied is None else "RUNTIME_PORT_IN_USE")

    def test_provider_name_presence_table_never_reads_values_or_passes(self) -> None:
        cases = (
            (set(), 0, False, "PROVIDER_CREDENTIAL_SOURCE_NAME_NOT_PRESENT"),
            ({"OPENAI_API_KEY"}, 1, True, "PROVIDER_E3_NOT_RUN"),
            ({"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}, 2, True, "PROVIDER_E3_NOT_RUN"),
        )
        for names, count, present, code in cases:
            with self.subTest(names=names):
                result = self.run_with_common_patches(environment=NameOnlyEnvironment(names))
                gate = gates(result)["provider_e3"]
                self.assertEqual(gate["status"], "NOT_RUN")
                self.assertEqual(gate["code"], code)
                self.assertEqual(gate["observations"], {
                    "credential_source_name_present": present,
                    "credential_source_name_count": count,
                    "credential_value_inspected": False,
                })
                self.assertFalse(result["production_ready"])

    def test_no_bundle_blocks_release_and_skips_identity_command(self) -> None:
        cfg = config(self.root)
        (self.root / "relay" / "cmd" / "relay").mkdir(parents=True)
        (self.root / "mobile-reference" / "pilot-gateway").mkdir(parents=True)
        (self.root / "mobile-reference" / "pilot-gateway" / "server.mjs").touch()
        (self.root / "mobile-reference" / "package.json").touch()
        with mock.patch.object(doctor.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(doctor, "_free", return_value=True), mock.patch.object(doctor, "_read_runtime_state", return_value=(None, False)), mock.patch.object(doctor, "_network_address_presence", return_value={"lan_ip_present": True, "global_ip_present": False}), mock.patch.object(doctor, "_chrome_gate", return_value=doctor._gate("google_chrome", "PASS", "GOOGLE_CHROME_AVAILABLE", None, {"present": True})), mock.patch.object(doctor.subprocess, "run") as run:
            result = doctor.run_doctor(cfg, environment={})
        release = gates(result)
        self.assertTrue(result["foundation_ready"])
        self.assertEqual((release["bundle_verify"]["status"], release["bundle_verify"]["code"]), ("BLOCK", "RELEASE_BUNDLE_REQUIRED"))
        self.assertEqual(release["bundle_digest"]["status"], "NOT_RUN")
        self.assertEqual(release["host_identity"]["status"], "NOT_RUN")
        self.assertEqual(result["release_readiness"], "BLOCK")
        self.assertFalse(result["production_ready"])
        run.assert_not_called()

    def test_running_state_is_required_for_process_pairing_and_relay_pass(self) -> None:
        stopped_process, stopped_pairing, stopped_relay = doctor._runtime_live_gates(
            config(self.root), None, False,
        )
        self.assertEqual(stopped_process["status"], "NOT_RUN")
        self.assertEqual(stopped_pairing["status"], "NOT_RUN")
        self.assertEqual(stopped_relay["status"], "NOT_RUN")

        records = [
            {"name": name, "pid": index + 10, "process_group": index + 10, "identity": "a" * 64}
            for index, name in enumerate(sorted(doctor.REMOTE_PROCESS_NAMES))
        ]
        running = {
            "mode": "remote-local-evidence", "processes": records, "run_id": "f" * 64,
        }
        identity = (1, 2, 3, 0o700, 4, 5, 6, 0o600)
        listeners = (("relay_port", 18089, 10),)
        with mock.patch.object(doctor, "_measure_process_ownership", side_effect=[("owned",) * len(records)] * 2), mock.patch.object(doctor, "_measure_product_host_socket", side_effect=[identity, identity]), mock.patch.object(doctor, "_probe_product_host_pairing") as pairing_probe, mock.patch.object(doctor, "_probe_relay_roles") as relay_probe, mock.patch.object(doctor, "_measure_listener_process_bindings", side_effect=[listeners, listeners]):
            process_gate, pairing_gate, relay_gate = doctor._runtime_live_gates(config(self.root), running, False)
        self.assertEqual(process_gate["status"], "PASS")
        self.assertEqual(pairing_gate["status"], "PASS")
        self.assertEqual(relay_gate["status"], "PASS")
        pairing_probe.assert_called_once_with(config(self.root), running)
        relay_probe.assert_called_once_with(config(self.root), running)

    def test_live_probe_failure_and_identity_drift_block(self) -> None:
        records = [{"name": name} for name in sorted(doctor.REMOTE_PROCESS_NAMES)]
        running = {"mode": "remote-local-evidence", "processes": records, "run_id": "f" * 64}
        identity = (1, 2, 3, 0o700, 4, 5, 6, 0o600)
        cases = (
            (None, doctor._LiveProbeError("RELAY_ROLE_LIVE_PROBE_FAILED"), ("owned",) * 7, identity, "RUNTIME_ROLE_LIVE_PROBE_FAILED"),
            (None, None, ("owned",) * 6 + ("mismatch",), identity, "RUNTIME_IDENTITY_CHANGED_DURING_LIVE_PROBE"),
            (None, None, ("owned",) * 7, identity[:-1] + (0o644,), "RUNTIME_IDENTITY_CHANGED_DURING_LIVE_PROBE"),
        )
        for pairing_error, relay_error, after, after_socket, expected in cases:
            listeners = (("relay_port", 18089, 10),)
            with self.subTest(expected=expected), mock.patch.object(doctor, "_measure_process_ownership", side_effect=[("owned",) * 7, after]), mock.patch.object(doctor, "_measure_product_host_socket", side_effect=[identity, after_socket]), mock.patch.object(doctor, "_probe_product_host_pairing", side_effect=pairing_error), mock.patch.object(doctor, "_probe_relay_roles", side_effect=relay_error), mock.patch.object(doctor, "_measure_listener_process_bindings", side_effect=[listeners, listeners]):
                process_gate, pairing_gate, relay_gate = doctor._runtime_live_gates(config(self.root), running, False)
            self.assertEqual(process_gate["status"], "BLOCK")
            self.assertEqual(process_gate["code"], expected)
            if expected == "RUNTIME_IDENTITY_CHANGED_DURING_LIVE_PROBE":
                self.assertEqual((pairing_gate["status"], relay_gate["status"]), ("BLOCK", "BLOCK"))
            else:
                self.assertEqual(relay_gate["status"], "BLOCK")

    def test_runtime_port_gate_cannot_pass_when_live_probe_fails(self) -> None:
        running = {"mode": "remote-local-evidence"}
        availability = {name: False for name in doctor.RUNTIME_PORT_FIELDS}
        process_gate = doctor._gate(
            "runtime_processes", "BLOCK", "RUNTIME_ROLE_LIVE_PROBE_FAILED", "repair runtime",
        )
        gate = doctor._runtime_ports_gate(availability, running, process_gate, False)
        self.assertEqual((gate["status"], gate["code"]), ("BLOCK", "RUNTIME_PORT_LIVE_STATE_NOT_VERIFIED"))

    def test_product_host_pairing_probe_is_exact_content_free_and_strict(self) -> None:
        cfg = config(self.root)
        running = {"run_id": "f" * 64}
        response = canonical_response(
            401, "Unauthorized", {"schema": "nomad.product-host.error.v1", "code": "UNAUTHORIZED"},
            cache_control=True,
        )
        with mock.patch.object(doctor, "_product_host_socket_path", return_value=Path("/private/tmp/product-host.sock")), mock.patch.object(doctor, "_unix_exchange", return_value=response) as exchange:
            doctor._probe_product_host_pairing(cfg, running)
        request = exchange.call_args.args[1]
        self.assertIn(b"POST /internal/pairing/joins HTTP/1.1\r\n", request)
        self.assertTrue(request.endswith(doctor.PRODUCT_HOST_PAIRING_PROBE_BODY))
        self.assertNotIn(b"Authorization", request)
        self.assertNotIn(b"X-Nomad-Transport", request)

        invalid = (
            response.replace(b"401 Unauthorized", b"200 OK"),
            response.replace(b"UNAUTHORIZED", b"COMMAND_UNAVAILABLE"),
            response.replace(b"Cache-Control: no-store\r\n", b""),
        )
        for raw in invalid:
            with self.subTest(raw=raw), mock.patch.object(doctor, "_product_host_socket_path", return_value=Path("/private/tmp/product-host.sock")), mock.patch.object(doctor, "_unix_exchange", return_value=raw):
                with self.assertRaisesRegex(doctor._LiveProbeError, "PRODUCT_HOST_PAIRING_LIVE_PROBE_FAILED"):
                    doctor._probe_product_host_pairing(cfg, running)
        with mock.patch.object(doctor, "_product_host_socket_path", return_value=Path("/private/tmp/product-host.sock")), mock.patch.object(doctor, "_unix_exchange", side_effect=TimeoutError):
            with self.assertRaisesRegex(doctor._LiveProbeError, "PRODUCT_HOST_PAIRING_LIVE_PROBE_FAILED"):
                doctor._probe_product_host_pairing(cfg, running)

    def test_relay_live_probes_are_role_specific_and_strict(self) -> None:
        cfg = config(self.root)
        running = {name: getattr(cfg, name) for name in doctor.RUNTIME_PORT_FIELDS}
        observed: list[tuple[int, str, str, bytes | None, Mapping[str, str] | None]] = []

        def exchange(port: int, method: str, path: str, body: bytes | None = None, headers: Mapping[str, str] | None = None) -> bytes:
            observed.append((port, method, path, body, headers))
            if path == "/health":
                return canonical_response(200, "OK", {"status": "ok", "protocol": "TEST-ONLY/1", "timestamp": 1})
            if path == doctor.RELAY_ADMIN_PATH:
                return canonical_response(405, "Method Not Allowed", {"error": "method not allowed"}, cache_control=True, extra_headers={"Allow": "POST"})
            if method == "POST":
                direction = json.loads(body)["direction"]
                expected = "host_to_device" if port == cfg.relay_host_v2_port else "device_to_host"
                return canonical_response(410 if direction == expected else 403, "Gone" if direction == expected else "Forbidden", {"error": "Gone" if direction == expected else "Forbidden"}, cache_control=True)
            direction = path.split("direction=", 1)[1].split("&", 1)[0]
            expected = "device_to_host" if port == cfg.relay_host_v2_port else "host_to_device"
            self.assertEqual(direction, expected)
            return canonical_response(404, "Not Found", {"error": "Not Found"}, cache_control=True)

        with mock.patch.object(doctor, "_tcp_exchange", side_effect=exchange):
            doctor._probe_relay_roles(cfg, running)
        self.assertEqual(len(observed), 9)
        self.assertEqual({item[0] for item in observed}, {cfg.relay_port, cfg.relay_device_v1_port, cfg.relay_host_v2_port, cfg.relay_device_v2_port, cfg.relay_admin_port})
        for _, _, _, body, headers in observed:
            self.assertNotIn(b"secret", body or b"")
            self.assertNotIn("secret", json.dumps(dict(headers or {})))

        bad = canonical_response(200, "OK", {"status": "ok", "protocol": "wrong", "timestamp": 1})
        with mock.patch.object(doctor, "_tcp_exchange", return_value=bad):
            with self.assertRaisesRegex(doctor._LiveProbeError, "RELAY_ROLE_LIVE_PROBE_FAILED"):
                doctor._probe_relay_roles(cfg, running)
        with mock.patch.object(doctor, "_tcp_exchange", side_effect=TimeoutError):
            with self.assertRaisesRegex(doctor._LiveProbeError, "RELAY_ROLE_LIVE_PROBE_FAILED"):
                doctor._probe_relay_roles(cfg, running)
        running["relay_host_v2_port"] += 1
        with mock.patch.object(doctor, "_probe_v1_health"):
            with self.assertRaisesRegex(doctor._LiveProbeError, "RELAY_ROLE_LIVE_PROBE_FAILED"):
                doctor._probe_relay_roles(cfg, running)

    def test_product_host_socket_identity_is_state_bound(self) -> None:
        cfg = config(self.root)
        cfg.home.mkdir()
        running = {"run_id": "f" * 64}
        path = doctor._product_host_socket_path(cfg, running)
        path.parent.mkdir(mode=0o700)
        listener = doctor.socket.socket(doctor.socket.AF_UNIX, doctor.socket.SOCK_STREAM)
        try:
            listener.bind(str(path))
            path.chmod(0o600)
            parent, leaf = path.parent.lstat(), path.lstat()
            running["product_host_socket_identity"] = {
                "parent_dev": parent.st_dev, "parent_ino": parent.st_ino,
                "parent_uid": parent.st_uid, "parent_mode": 0o700,
                "socket_dev": leaf.st_dev, "socket_ino": leaf.st_ino,
                "socket_uid": leaf.st_uid, "socket_mode": 0o600,
            }
            self.assertEqual(len(doctor._measure_product_host_socket(cfg, running)), 8)
            running["product_host_socket_identity"]["socket_ino"] += 1
            with self.assertRaisesRegex(doctor._LiveProbeError, "PRODUCT_HOST_SOCKET_IDENTITY_NOT_VERIFIED"):
                doctor._measure_product_host_socket(cfg, running)
        finally:
            listener.close()
            path.unlink(missing_ok=True)
            path.parent.rmdir()

    def test_tls_and_external_gates_never_pass_and_output_is_content_free(self) -> None:
        canary = "PROVIDER-CREDENTIAL-CANARY-DO-NOT-READ"
        result = self.run_with_common_patches(environment={"OPENAI_API_KEY": canary})
        release = gates(result)
        self.assertIn(release["tls_inputs"]["status"], {"BLOCK", "NOT_RUN"})
        self.assertIn(release["normal_chrome_tls_trust"]["status"], {"BLOCK", "NOT_RUN"})
        for name in ("provider_e3", "physical_phone_safari", "clean_machine_install", "developer_id_signing", "notarization", "publication_provenance"):
            self.assertEqual(release[name]["status"], "NOT_RUN")
        self.assertNotIn(canary, json.dumps(result, sort_keys=True))
        self.assertFalse(result["production_ready"])

    def test_bundle_and_digest_pass_only_after_strict_verification(self) -> None:
        result = self.run_with_common_patches(environment={})
        release = gates(result)
        self.assertEqual(release["bundle_verify"]["status"], "PASS")
        self.assertEqual(release["bundle_digest"]["status"], "PASS")
        self.assertEqual(release["bundle_digest"]["observations"]["bundle_digest"], "a" * 64)  # type: ignore[index]
        self.assertFalse(result["production_ready"])

    def test_runtime_bundle_binding_requires_current_configured_and_state_digest(self) -> None:
        cfg = config(self.root, bundle=self.bundle)
        cfg.home.mkdir()
        installed = cfg.home / "bundles" / ("a" * 64)
        installed.mkdir(parents=True)
        running = {"mode": "remote-local-evidence", "bundle_digest": "a" * 64}
        current = {"state": "INSTALLED", "current_bundle_digest": "a" * 64}
        with mock.patch.object(doctor, "install_status", return_value=current), mock.patch.object(doctor, "verify_bundle", return_value=self.manifest):
            gate, selected = doctor._runtime_bundle_binding_gate(cfg, running, False, self.manifest, True)
        self.assertEqual(gate["status"], "PASS")
        self.assertEqual(selected, installed.resolve())

        for configured, selected_digest, state_digest in (("b" * 64, "a" * 64, "a" * 64), ("a" * 64, "b" * 64, "a" * 64), ("a" * 64, "a" * 64, "b" * 64)):
            with self.subTest(configured=configured, selected=selected_digest, state=state_digest):
                (cfg.home / "bundles" / state_digest).mkdir(parents=True, exist_ok=True)
                candidate = dict(running, bundle_digest=state_digest)
                configured_manifest = {"bundle_digest": configured}
                current = {"state": "INSTALLED", "current_bundle_digest": selected_digest}
                with mock.patch.object(doctor, "install_status", return_value=current), mock.patch.object(doctor, "verify_bundle", return_value={"bundle_digest": state_digest}):
                    gate, selected = doctor._runtime_bundle_binding_gate(cfg, candidate, False, configured_manifest, True)
                self.assertEqual((gate["status"], gate["code"], selected), ("BLOCK", "CURRENT_BUNDLE_DIGEST_MISMATCH", None))

    def test_process_paths_and_listener_pids_are_exactly_bound(self) -> None:
        bundle = self.bundle.resolve()
        for relative in doctor.REMOTE_ARTIFACT_PATHS.values():
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
        records = [{"name": name, "pid": index + 101} for index, name in enumerate(doctor.REMOTE_ARTIFACT_PATHS)]
        expected_by_pid = {item["pid"]: (bundle / doctor.REMOTE_ARTIFACT_PATHS[item["name"]]).resolve() for item in records}
        with mock.patch.object(doctor, "_command_has_exact_path", side_effect=lambda pid, expected: expected_by_pid[pid] == expected), mock.patch.object(doctor, "_process_text_paths", side_effect=lambda pid: (expected_by_pid[pid],)):
            doctor._verify_process_executables(records, bundle)
        with mock.patch.object(doctor, "_command_has_exact_path", return_value=False):
            with self.assertRaisesRegex(doctor._LiveProbeError, "RUNTIME_EXECUTABLE_BINDING_NOT_VERIFIED"):
                doctor._verify_process_executables(records, bundle)

        cfg = config(self.root)
        running = {name: getattr(cfg, name) for name in doctor.RUNTIME_PORT_FIELDS}
        running["processes"] = [{"name": role, "pid": index + 201} for index, role in enumerate(doctor.REMOTE_PROCESS_NAMES)]
        pid_by_role = {item["name"]: item["pid"] for item in running["processes"]}
        with mock.patch.object(doctor, "_listener_pids", side_effect=lambda port: {pid_by_role[next(role for field, role in doctor.LISTENER_ROLE_FIELDS.items() if getattr(cfg, field) == port)]}):
            doctor._measure_listener_process_bindings(cfg, running)
        with mock.patch.object(doctor, "_listener_pids", return_value={99999}):
            with self.assertRaisesRegex(doctor._LiveProbeError, "LISTENER_PROCESS_BINDING_NOT_VERIFIED"):
                doctor._measure_listener_process_bindings(cfg, running)


if __name__ == "__main__":
    unittest.main()
