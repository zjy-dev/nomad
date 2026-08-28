from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


MODULE = Path(__file__).with_name("run_m3e_product_slice.py")
SPEC = importlib.util.spec_from_file_location("run_m3e_product_slice", MODULE)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)

REPO_ROOT = MODULE.parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from tools.nomad_web import evidence_resume as resume


class ProductSliceTests(unittest.TestCase):
    def test_content_free_non_claims_are_literal(self) -> None:
        source = MODULE.read_text()
        self.assertIn('"provider_e3": "NOT_RUN"', source)
        self.assertIn('"physical_phone": "NOT_RUN"', source)
        self.assertIn('"production_ready": False', source)
        self.assertIn('"network_scope": "lan_direct"', source)
        self.assertIn('"ignore_https_errors": False', source)

    def test_browser_never_enables_https_bypass(self) -> None:
        source = Path(__file__).with_name("run_m3e_desktop_browser.py").read_text()
        self.assertNotIn("ignore_https_errors=True", source)
        self.assertNotIn('"--ignore-certificate-errors"', source)
        self.assertIn('"ignore_https_errors": False', source)
        self.assertIn("--ignore-certificate-errors-spki-list=", source)

    def test_tls_material_is_not_accepted_by_path_argv_or_environment(self) -> None:
        source = MODULE.read_text()
        self.assertNotIn('parser.add_argument("--tls-', source)
        self.assertNotIn('os.environ["NOMAD_TLS', source)
        self.assertNotIn("create_certificates", source)
        self.assertNotIn("certutil", source)
        self.assertIn("NOMAD_TLS_FDS_V1", source)

    def test_diagnostic_mode_cannot_claim_pass(self) -> None:
        source = MODULE.read_text()
        self.assertIn('"DIAGNOSTIC_COMPLETE" if diagnostic_spki_bypass else "PASS"', source)
        self.assertIn('"tls_verified": not diagnostic_spki_bypass', source)
        self.assertIn('if not diagnostic_spki_bypass:', source)
        self.assertIn('evidence["marker"] = MARKER', source)

    def test_provider_environment_is_removed(self) -> None:
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "secret", "PATH": "/bin"}, clear=True):
            env = harness.sanitized_env({"NOMAD_TEST": "yes"})
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertEqual(env["NOMAD_TEST"], "yes")

    def test_credential_pipe_is_prefilled_and_closed(self) -> None:
        descriptor = harness._credential_pipe()
        self.addCleanup(lambda: os.close(descriptor))
        self.assertEqual(os.read(descriptor, 4096), b"TEST_ONLY_NOMAD_E6D_CANARY_NO_PROVIDER_CALLS")
        self.assertEqual(os.read(descriptor, 1), b"")

    def test_process_topology_requires_exact_seven_roles(self) -> None:
        state = {"processes": [
            {"name": name, "pid": 123, "identity": f"identity-{name}"}
            for name in harness.PROCESS_NAMES
        ]}
        with mock.patch("os.kill"):
            evidence = harness.process_evidence(state)
        self.assertEqual([item["name"] for item in evidence], harness.PROCESS_NAMES)
        state["processes"] = state["processes"][:-1]
        with self.assertRaisesRegex(harness.SliceError, "seven_process_topology_mismatch"):
            harness.process_evidence(state)

    def test_evidence_file_is_private_and_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "evidence.json"
            harness.write_evidence(path, {"z": 1, "a": 2})
            self.assertEqual(path.read_bytes(), b'{"a":2,"z":1}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_bundle_is_explicit_and_digest_comes_from_verified_manifest(self) -> None:
        source = MODULE.read_text()
        self.assertIn('parser.add_argument("--bundle", type=Path, required=True)', source)
        self.assertNotIn("nomad-e6d-final7-bundle", source)
        self.assertNotIn("EXPECTED_BUNDLE_DIGEST", source)
        manifest = {
            "bundle_digest": "a" * 64,
            "source_commit_oid": "b" * 40,
            "launcher_version": "0.1.0",
            "classification": "repo-local-prebuilt-not-production-authority",
            "agent_runtime": {"provider_backed": False},
        }
        package_root = str(REPO_ROOT / "tools")
        if package_root not in sys.path:
            sys.path.insert(0, package_root)
        with mock.patch("nomad_web.bundle.verify_bundle", return_value=manifest):
            self.assertEqual(harness.load_manifest(Path("/not/final7")), manifest)

    def test_identity_preflight_user_denied_is_zero_process_blocker(self) -> None:
        completed = __import__("types").SimpleNamespace(
            returncode=1, stdout=b'{"status":"USER_DENIED"}\n', stderr=b""
        )
        with mock.patch.object(harness.subprocess, "run", side_effect=[completed, __import__("types").SimpleNamespace(returncode=0, stdout="", stderr="")]):
            result = harness.host_identity_preflight(Path("/tmp/bundle"))
        self.assertEqual(result, {
            "status": "USER_DENIED",
            "business_process_count": 0,
            "ready": False,
            "error_code": "HOST_IDENTITY_USER_DENIED",
            "next_step": "nomad-web authorize-host-identity",
        })

    def test_launcher_error_diagnostics_only_allow_uppercase_codes(self) -> None:
        source = MODULE.read_text()
        self.assertIn('re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", candidate)', source)
        self.assertIn('{"launcher_error_code": code}', source)
        self.assertNotIn('"launcher_stderr"', source)
        self.assertNotIn('"raw_stderr"', source)


class EvidenceResumeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.output = self.root / "resumed.json"
        self.manifest = {
            "bundle_digest": "a" * 64,
            "source_commit_oid": "b" * 40,
            "launcher_version": "0.1.0",
            "classification": "repo-local-prebuilt-not-production-authority",
            "files": [
                {"path": resume.PRODUCT_RUNNER_ENTRY, "size_bytes": 7, "raw_sha256": "1" * 64, "mode": "0644"},
                {"path": resume.BROWSER_RUNNER_ENTRY, "size_bytes": 7, "raw_sha256": "2" * 64, "mode": "0644"},
                {"path": resume.PACKAGE_INIT_ENTRY, "size_bytes": 7, "raw_sha256": "3" * 64, "mode": "0644"},
                {"path": resume.BUNDLE_VERIFIER_ENTRY, "size_bytes": 7, "raw_sha256": "4" * 64, "mode": "0644"},
            ],
        }

    def evidence(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": resume.EVIDENCE_SCHEMA,
            "status": "BLOCK",
            "code": "HOST_IDENTITY_USER_DENIED",
            "bundle": {
                "digest": self.manifest["bundle_digest"],
                "source_commit_oid": self.manifest["source_commit_oid"],
                "launcher_version": self.manifest["launcher_version"],
                "classification": self.manifest["classification"],
            },
            "source_binding": resume._manifest_source_binding(self.manifest),
            "parent_evidence_digest": None,
            "network_scope": "lan_direct",
            "provider_e3": "NOT_RUN",
            "physical_phone": "NOT_RUN",
            "production_ready": False,
            "content_free": True,
            "diagnostic_tls_bypass": False,
        }
        value.update(changes)
        return value

    def write_parent(self, value: dict[str, object] | None = None, *, canonical: bool = True) -> Path:
        path = self.root / "parent.json"
        raw = resume._canonical(value or self.evidence())
        path.write_bytes(raw + (b"\n" if canonical else b" \n"))
        os.chmod(path, 0o600)
        return path

    def verify(self, path: Path) -> str:
        with mock.patch.object(resume, "verify_bundle", return_value=self.manifest):
            return resume.verify_resume_parent(path, self.bundle)

    def test_parent_tamper_noncanonical_is_rejected(self) -> None:
        with self.assertRaisesRegex(resume.EvidenceResumeError, "EVIDENCE_NOT_CANONICAL"):
            self.verify(self.write_parent(canonical=False))

    def test_wrong_bundle_is_rejected(self) -> None:
        evidence = self.evidence()
        evidence["bundle"] = {**evidence["bundle"], "digest": "c" * 64}  # type: ignore[arg-type]
        with self.assertRaisesRegex(resume.EvidenceResumeError, "PARENT_BUNDLE_MISMATCH"):
            self.verify(self.write_parent(evidence))

    def test_old_runner_source_is_rejected(self) -> None:
        evidence = self.evidence(source_binding={
            "product_runner_raw_sha256": "d" * 64,
            "browser_runner_raw_sha256": "e" * 64,
        })
        with self.assertRaisesRegex(resume.EvidenceResumeError, "RUNNER_SOURCE_MISMATCH"):
            self.verify(self.write_parent(evidence))

    def test_diagnostic_evidence_is_rejected(self) -> None:
        evidence = self.evidence(diagnostic_tls_bypass=True)
        with self.assertRaisesRegex(resume.EvidenceResumeError, "DIAGNOSTIC_EVIDENCE_FORBIDDEN"):
            self.verify(self.write_parent(evidence))

    def test_nonallowlisted_blocker_is_rejected(self) -> None:
        evidence = self.evidence(code="browser_remote_projection_timeout")
        with self.assertRaisesRegex(resume.EvidenceResumeError, "PARENT_BLOCKER_NOT_RESUMABLE"):
            self.verify(self.write_parent(evidence))

    def test_output_exists_is_rejected_without_running(self) -> None:
        parent = self.write_parent()
        self.output.write_text("preserve")
        with mock.patch.object(resume.subprocess, "run") as run:
            with self.assertRaisesRegex(resume.EvidenceResumeError, "EVIDENCE_OUTPUT_EXISTS"):
                resume.resume_blocked_evidence(
                    parent, self.bundle, self.output,
                    tls_ca_fd=0, tls_cert_fd=1, tls_key_fd=2,
                )
        run.assert_not_called()
        self.assertEqual(self.output.read_text(), "preserve")

    def test_private_file_policy_and_block_status_are_required(self) -> None:
        parent = self.write_parent(self.evidence(status="PASS"))
        with self.assertRaisesRegex(resume.EvidenceResumeError, "PARENT_STATUS_NOT_BLOCK"):
            self.verify(parent)
        parent.unlink()
        parent = self.write_parent()
        os.chmod(parent, 0o644)
        with self.assertRaisesRegex(resume.EvidenceResumeError, "EVIDENCE_FILE_POLICY_INVALID"):
            self.verify(parent)

    def test_resume_runs_complete_runner_and_binds_parent_digest(self) -> None:
        parent = self.write_parent()
        expected_parent = hashlib.sha256(parent.read_bytes()).hexdigest()
        tls_fds = tuple(self._tls_fd(b"material") for _ in range(3))
        self.addCleanup(lambda: [os.close(item) for item in tls_fds])

        def completed(command: list[str], **kwargs: object) -> object:
            self.assertIn("--bundle", command)
            self.assertIn("--evidence", command)
            self.assertNotIn("--preflight", command)
            self.assertNotIn("--diagnostic-spki-bypass", command)
            self.assertEqual(command[1:4], ["-I", "-B", "-c"])
            self.assertEqual(command[command.index("--parent-evidence-digest") + 1], expected_parent)
            control = kwargs["input"]
            self.assertRegex(control, r"^NOMAD_TLS_FDS_V1 [0-9]+ [0-9]+ [0-9]+\n$")
            self.assertEqual(len(kwargs["pass_fds"]), 4)
            result = self.evidence(
                parent_evidence_digest=expected_parent,
                source_binding=resume._manifest_source_binding(manifest),
            )
            resume._canonical(result)
            descriptor = os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, resume._canonical(result) + b"\n")
            finally:
                os.close(descriptor)
            return SimpleNamespace(returncode=2)

        staged_root = self.root / "staged"
        staged_root.mkdir(mode=0o700)
        staged = staged_root / "staged-product.py"
        staged.write_text("# staged")
        os.chmod(staged, 0o644)
        manifest = dict(self.manifest)
        manifest["files"] = [
            ({**item, "size_bytes": staged.stat().st_size, "raw_sha256": hashlib.sha256(staged.read_bytes()).hexdigest()})
            if item["path"] == resume.PRODUCT_RUNNER_ENTRY else item
            for item in self.manifest["files"]
        ]
        parent.unlink()
        parent = self.write_parent(self.evidence(
            source_binding=resume._manifest_source_binding(manifest)
        ))
        expected_parent = hashlib.sha256(parent.read_bytes()).hexdigest()
        temporary = mock.Mock()
        snapshot_owner = mock.Mock()
        with mock.patch.object(resume, "verify_bundle", return_value=manifest), mock.patch.object(
            resume, "_snapshot_verified_bundle", return_value=(snapshot_owner, self.bundle, manifest)
        ), mock.patch.object(
            resume, "_stage_runner_closure", return_value=(None, staged, self.root / "staged-browser.py")
        ), mock.patch.object(resume.subprocess, "run", side_effect=completed) as run:
            result = resume.resume_blocked_evidence(
                parent, self.bundle, self.output, runner_args=("--keep-runtime",),
                tls_ca_fd=tls_fds[0], tls_cert_fd=tls_fds[1], tls_key_fd=tls_fds[2],
            )
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result["parent_evidence_digest"], expected_parent)
        self.assertEqual(result["provider_e3"], "NOT_RUN")
        self.assertEqual(result["physical_phone"], "NOT_RUN")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        snapshot_owner.cleanup.assert_called_once_with()

    def test_resume_forbids_partial_or_diagnostic_runner_arguments(self) -> None:
        parent = self.write_parent()
        for argument in ("--preflight", "--diagnostic-spki-bypass", "--bundle"):
            with self.subTest(argument=argument), self.assertRaisesRegex(
                resume.EvidenceResumeError, "RUNNER_ARGUMENT_FORBIDDEN"
            ):
                resume.resume_blocked_evidence(
                    parent, self.bundle, self.output, (argument,),
                    tls_ca_fd=0, tls_cert_fd=1, tls_key_fd=2,
                )

    def _tls_fd(self, raw: bytes) -> int:
        path = self.root / f"tls-{len(list(self.root.glob('tls-*')))}"
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return os.open(path, os.O_RDONLY)

    def test_source_bundle_swap_after_snapshot_does_not_change_runner_bundle(self) -> None:
        parent = self.write_parent()
        tls_fds = tuple(self._tls_fd(b"material") for _ in range(3))
        self.addCleanup(lambda: [os.close(item) for item in tls_fds])
        snapshot = self.root / "immutable-snapshot"
        snapshot.mkdir()
        product = snapshot / "product.py"
        product.write_text("# product")
        os.chmod(product, 0o644)
        manifest = dict(self.manifest)
        manifest["files"] = [
            ({**item, "size_bytes": product.stat().st_size, "raw_sha256": hashlib.sha256(product.read_bytes()).hexdigest()})
            if item["path"] == resume.PRODUCT_RUNNER_ENTRY else item
            for item in self.manifest["files"]
        ]
        parent.unlink()
        parent = self.write_parent(self.evidence(source_binding=resume._manifest_source_binding(manifest)))
        parent_digest = hashlib.sha256(parent.read_bytes()).hexdigest()
        owner = mock.Mock()
        swapped = self.root / "swapped-source"

        def snapshot_once(_: Path, __: object) -> tuple[object, Path, object]:
            return owner, snapshot, manifest

        def completed(command: list[str], **_: object) -> object:
            # This callback occurs only after snapshot construction and parent
            # validation. Replacing the caller's source path here must not
            # affect either execution or child-result validation.
            self.bundle.rename(swapped)
            self.bundle.mkdir()
            (self.bundle / "attacker").write_text("B")
            selected = Path(command[command.index("--bundle") + 1])
            self.assertEqual(selected, snapshot)
            self.assertNotEqual(selected, self.bundle)
            result = self.evidence(
                parent_evidence_digest=parent_digest,
                source_binding=resume._manifest_source_binding(manifest),
            )
            descriptor = os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, resume._canonical(result) + b"\n")
            finally:
                os.close(descriptor)
            return SimpleNamespace(returncode=2)

        with mock.patch.object(resume, "verify_bundle", return_value=manifest) as verify, mock.patch.object(
            resume, "_snapshot_verified_bundle", side_effect=snapshot_once
        ), mock.patch.object(
            resume, "_stage_runner_closure", return_value=(None, product, snapshot / "browser.py")
        ), mock.patch.object(resume.subprocess, "run", side_effect=completed):
            result = resume.resume_blocked_evidence(
                parent, self.bundle, self.output,
                tls_ca_fd=tls_fds[0], tls_cert_fd=tls_fds[1], tls_key_fd=tls_fds[2],
            )
        self.assertEqual(result["parent_evidence_digest"], parent_digest)
        self.assertEqual(verify.call_count, 1)
        owner.cleanup.assert_called_once_with()

    def test_mid_snapshot_source_swap_is_zero_spawn_block(self) -> None:
        manifest = {
            "files": [
                {"path": "a", "size_bytes": 1, "raw_sha256": hashlib.sha256(b"a").hexdigest(), "mode": "0644"},
                {"path": "b", "size_bytes": 1, "raw_sha256": hashlib.sha256(b"b").hexdigest(), "mode": "0644"},
            ]
        }
        (self.bundle / "a").write_bytes(b"a")
        (self.bundle / "b").write_bytes(b"b")
        for path in self.bundle.iterdir():
            os.chmod(path, 0o644)
        original = resume._read_manifest_file
        reads = 0

        def swapping(root_fd: int, name: str, expected: object) -> bytes:
            nonlocal reads
            raw = original(root_fd, name, expected)
            reads += 1
            if reads == 1:
                moved = self.root / "source-a"
                self.bundle.rename(moved)
                self.bundle.mkdir()
            return raw

        with mock.patch.object(resume, "_read_manifest_file", side_effect=swapping), mock.patch.object(
            resume.subprocess, "run"
        ) as run:
            with self.assertRaisesRegex(resume.EvidenceResumeError, "BUNDLE_SNAPSHOT_SOURCE_CHANGED"):
                resume._snapshot_verified_bundle(self.bundle, manifest)
        run.assert_not_called()

    def test_runner_closure_is_read_from_manifest_bound_fds_and_staged(self) -> None:
        product_raw = b"product"
        browser_raw = b"browser"
        manifest = dict(self.manifest)
        manifest["files"] = [
            {"path": resume.PRODUCT_RUNNER_ENTRY, "size_bytes": len(product_raw), "raw_sha256": hashlib.sha256(product_raw).hexdigest(), "mode": "0644"},
            {"path": resume.BROWSER_RUNNER_ENTRY, "size_bytes": len(browser_raw), "raw_sha256": hashlib.sha256(browser_raw).hexdigest(), "mode": "0644"},
            {"path": resume.PACKAGE_INIT_ENTRY, "size_bytes": len(browser_raw), "raw_sha256": hashlib.sha256(browser_raw).hexdigest(), "mode": "0644"},
            {"path": resume.BUNDLE_VERIFIER_ENTRY, "size_bytes": len(browser_raw), "raw_sha256": hashlib.sha256(browser_raw).hexdigest(), "mode": "0644"},
        ]
        for name, raw in ((resume.PRODUCT_RUNNER_ENTRY, product_raw), (resume.BROWSER_RUNNER_ENTRY, browser_raw), (resume.PACKAGE_INIT_ENTRY, browser_raw), (resume.BUNDLE_VERIFIER_ENTRY, browser_raw)):
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            os.chmod(path, 0o644)
        owner, product, browser = resume._stage_runner_closure(self.bundle, manifest)
        self.assertIsNone(owner)
        self.assertEqual(product.read_bytes(), product_raw)
        self.assertEqual(browser.read_bytes(), browser_raw)
        self.assertEqual(stat.S_IMODE(product.stat().st_mode), 0o644)

    def test_browser_runner_executes_the_same_snapshotted_bytes(self) -> None:
        raw = b"# exact browser runner bytes"
        expected_digest = hashlib.sha256(raw).hexdigest()
        completed = SimpleNamespace(
            returncode=0,
            stdout=resume._canonical({
                "schema": "nomad.m3e.desktop-browser-evidence.v1",
                "runner_raw_sha256": expected_digest,
                "status": "PASS",
            }) + b"\n",
            stderr=b"",
        )
        with mock.patch.object(harness, "browser_runner_snapshot", return_value=(raw, expected_digest)), mock.patch.object(
            harness.subprocess, "run", return_value=completed
        ) as invoked:
            result = harness.run_browser(
                "http://127.0.0.1:1", "https://192.168.100.3:2",
                self.root, {}, None,
            )
        self.assertEqual(result["runner_raw_sha256"], expected_digest)
        self.assertEqual(invoked.call_args.kwargs["input"], raw)
        command = invoked.call_args.args[0]
        self.assertNotIn(str(harness.BROWSER_RUNNER), command)
        self.assertEqual(command[5:8], ["-I", "-B", "-c"])


class TlsFdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_tls_control_is_stdin_only_and_exact(self) -> None:
        with mock.patch.object(sys, "stdin", SimpleNamespace(buffer=__import__("io").BytesIO(b"NOMAD_TLS_FDS_V1 3 4 5\n"))):
            self.assertEqual(harness.read_tls_fd_control(), (3, 4, 5))
        with mock.patch.object(sys, "stdin", SimpleNamespace(buffer=__import__("io").BytesIO(b"NOMAD_TLS_FDS_V1 3 3 5\n"))):
            with self.assertRaisesRegex(harness.SliceError, "TLS_FD_CONTROL_INVALID"):
                harness.read_tls_fd_control()

    def test_tls_snapshot_validates_chain_san_and_key_before_launch(self) -> None:
        snapshot_root = self.root / "snapshots"
        snapshot_root.mkdir(mode=0o700)
        descriptors = []
        for index in range(3):
            path = self.root / str(index)
            path.write_bytes(b"pem")
            os.chmod(path, 0o600)
            descriptors.append(os.open(path, os.O_RDONLY))
        self.addCleanup(lambda: [os.close(item) for item in descriptors])
        run_results = [
            SimpleNamespace(stdout="operator-cert.pem: OK\n"),
            SimpleNamespace(stdout="Certificate will not expire\n"),
            SimpleNamespace(stdout="IP Address 192.168.100.3 does match certificate\n"),
            SimpleNamespace(stdout="PUBLIC\n"),
            SimpleNamespace(stdout="PUBLIC\n"),
        ]
        with mock.patch.object(harness, "run_checked", side_effect=run_results) as checked:
            paths = harness.snapshot_and_validate_tls(snapshot_root, tuple(descriptors))
        self.assertEqual(checked.call_count, 5)
        self.assertTrue(all(path.read_bytes() == b"pem" for path in paths.values()))
        commands = [call.args[0] for call in checked.call_args_list]
        self.assertIn("-checkip", commands[2])
        self.assertIn(harness.LAN_ADDRESS, commands[2])

    def test_key_mismatch_fails_before_product_start(self) -> None:
        snapshot_root = self.root / "snapshots"
        snapshot_root.mkdir(mode=0o700)
        descriptors = []
        for index in range(3):
            path = self.root / str(index)
            path.write_bytes(b"pem")
            os.chmod(path, 0o600)
            descriptors.append(os.open(path, os.O_RDONLY))
        self.addCleanup(lambda: [os.close(item) for item in descriptors])
        run_results = [SimpleNamespace(stdout="OK"), SimpleNamespace(stdout="OK"), SimpleNamespace(stdout="OK"), SimpleNamespace(stdout="A"), SimpleNamespace(stdout="B")]
        with mock.patch.object(harness, "run_checked", side_effect=run_results), mock.patch.object(harness, "start_product") as start:
            with self.assertRaisesRegex(harness.SliceError, "operator_tls_key_mismatch"):
                harness.snapshot_and_validate_tls(snapshot_root, tuple(descriptors))
        start.assert_not_called()

    def test_runner_digest_mismatch_fails_before_tls_or_product_start(self) -> None:
        manifest = {
            "files": [
                {"path": harness.PRODUCT_RUNNER_ENTRY, "raw_sha256": "a" * 64},
                {"path": harness.BROWSER_RUNNER_ENTRY, "raw_sha256": "b" * 64},
            ]
        }
        with mock.patch.object(harness, "load_manifest", return_value=manifest), mock.patch.object(
            harness, "source_binding", return_value={
                "product_runner_raw_sha256": "c" * 64,
                "browser_runner_raw_sha256": "d" * 64,
            },
        ), mock.patch.object(harness, "snapshot_and_validate_tls") as tls, mock.patch.object(
            harness, "start_product"
        ) as start:
            with self.assertRaisesRegex(harness.SliceError, "runner_source_binding_mismatch"):
                harness.run_slice(self.root, None, False, tls_descriptors=(3, 4, 5))
        tls.assert_not_called()
        start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
