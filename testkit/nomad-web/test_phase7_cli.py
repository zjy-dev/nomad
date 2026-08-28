from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import cli


class Phase7CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nomad-phase7-cli-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.config = SimpleNamespace(
            repo_root=root, home=root / "home", bundle_root=None
        )

    def invoke(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output = StringIO()
        with mock.patch.object(cli.Config, "load", return_value=self.config), redirect_stdout(output):
            code = cli.run(["--json", *arguments])
        return code, json.loads(output.getvalue())

    def invoke_text(self, *arguments: str) -> tuple[int, str]:
        output = StringIO()
        with mock.patch.object(cli.Config, "load", return_value=self.config), redirect_stdout(output):
            code = cli.run(list(arguments))
        return code, output.getvalue()

    def tls_arguments(self) -> tuple[str, ...]:
        root = Path(self.temporary.name)
        files = ((root / "ca.pem", 0o644), (root / "cert.pem", 0o644),
                 (root / "key.pem", 0o600))
        for path, mode in files:
            path.write_text(path.name, encoding="ascii")
            path.chmod(mode)
        return (
            "--tls-ca", str(files[0][0]), "--tls-cert", str(files[1][0]),
            "--tls-key", str(files[2][0]),
        )

    def test_doctor_text_reports_release_contract_and_primary_next_step(self) -> None:
        result = {
            "state": "READY",
            "classification": "repo-local-foundation-not-production-authority",
            "next_step": "nomad-web start",
            "release_readiness": "BLOCK",
            "release_blockers": [
                {
                    "gate": "bundle_verify",
                    "code": "RELEASE_BUNDLE_REQUIRED",
                    "next_step": "set the exact release candidate",
                },
                {
                    "gate": "provider_e3",
                    "code": "PROVIDER_E3_NOT_RUN",
                    "next_step": "run Provider E3",
                },
            ],
            "release_next_step": "set the exact release candidate",
        }
        output = StringIO()
        with redirect_stdout(output):
            cli._emit(result, False)
        rendered = output.getvalue()
        self.assertIn("Release readiness: BLOCK\n", rendered)
        self.assertIn("Release blockers:\n", rendered)
        self.assertIn("- bundle_verify: RELEASE_BUNDLE_REQUIRED\n", rendered)
        self.assertIn("- provider_e3: PROVIDER_E3_NOT_RUN\n", rendered)
        self.assertIn("Release next step: set the exact release candidate\n", rendered)
        self.assertNotIn("Next: nomad-web start", rendered)
        self.assertEqual(
            result["release_next_step"],
            result["release_blockers"][0]["next_step"],
        )

    def test_doctor_exit_is_bound_to_release_readiness(self) -> None:
        for status, expected in (("PASS", 0), ("BLOCK", 2), ("NOT_RUN", 2)):
            with self.subTest(status=status), mock.patch.object(
                cli, "run_doctor", return_value={"release_readiness": status}
            ):
                code, result = self.invoke("doctor")
            self.assertEqual(code, expected)
            self.assertEqual(result["release_readiness"], status)

    def test_install_upgrade_and_rollback_dispatch(self) -> None:
        bundle = Path(self.temporary.name) / "candidate"
        for command, handler_name in (("install", "install"), ("upgrade", "upgrade")):
            result = {"state": "INSTALLED"}
            with self.subTest(command=command), mock.patch.object(
                cli, handler_name, return_value=result
            ) as handler:
                code, emitted = self.invoke(command, "--bundle", str(bundle))
            self.assertEqual((code, emitted), (0, result))
            handler.assert_called_once_with(self.config, bundle)

        result = {"state": "INSTALLED"}
        with mock.patch.object(cli, "rollback", return_value=result) as handler:
            code, emitted = self.invoke("rollback")
        self.assertEqual((code, emitted), (0, result))
        handler.assert_called_once_with(self.config)

    def test_install_and_resume_require_explicit_paths(self) -> None:
        for arguments, error in (
            (("install",), "INSTALL_BUNDLE_REQUIRED"),
            (("upgrade",), "INSTALL_BUNDLE_REQUIRED"),
            (("resume-evidence",), "RESUME_EVIDENCE_INPUTS_REQUIRED"),
            (("resume-evidence", "--from", "parent", "--bundle", "bundle",
              "--output", "child"), "RESUME_TLS_INPUTS_REQUIRED"),
        ):
            with self.subTest(arguments=arguments):
                code, result = self.invoke(*arguments)
            self.assertEqual(code, 1)
            self.assertEqual(result["error"], error)

    def test_resume_maps_pass_and_block_and_forwards_keep_runtime(self) -> None:
        parent = Path(self.temporary.name) / "parent.json"
        bundle = Path(self.temporary.name) / "bundle"
        output = Path(self.temporary.name) / "child.json"
        ca = Path(self.temporary.name) / "ca.pem"
        cert = Path(self.temporary.name) / "cert.pem"
        key = Path(self.temporary.name) / "key.pem"
        for path, mode in ((ca, 0o644), (cert, 0o644), (key, 0o600)):
            path.write_text(path.name, encoding="ascii")
            path.chmod(mode)
        arguments = (
            "resume-evidence", "--from", str(parent), "--bundle",
            str(bundle), "--output", str(output), "--keep-runtime",
            "--tls-ca", str(ca), "--tls-cert", str(cert),
            "--tls-key", str(key),
        )
        for status, expected in (("PASS", 0), ("BLOCK", 2)):
            result = {"status": status, "production_ready": False}
            with self.subTest(status=status), mock.patch.object(
                cli, "resume_blocked_evidence", return_value=result
            ) as resume:
                code, emitted = self.invoke(*arguments)
            self.assertEqual((code, emitted), (expected, result))
            call = resume.call_args
            self.assertEqual(call.args, (parent, bundle, output, ("--keep-runtime",)))
            self.assertEqual(set(call.kwargs), {"tls_ca_fd", "tls_cert_fd", "tls_key_fd"})
            self.assertTrue(all(isinstance(value, int) for value in call.kwargs.values()))
            for descriptor in call.kwargs.values():
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertNotIn(str(ca), repr(call))
            self.assertNotIn(str(cert), repr(call))
            self.assertNotIn(str(key), repr(call))

    def test_human_resume_pass_and_block_show_status_with_matching_exit(self) -> None:
        root = Path(self.temporary.name)
        arguments = (
            "resume-evidence", "--from", str(root / "parent.json"),
            "--bundle", str(root / "bundle"), "--output",
            str(root / "child.json"), *self.tls_arguments(),
        )
        for status, expected in (("PASS", 0), ("BLOCK", 2)):
            result = {"status": status, "production_ready": False}
            with self.subTest(status=status), mock.patch.object(
                cli, "resume_blocked_evidence", return_value=result
            ):
                code, rendered = self.invoke_text(*arguments)
            self.assertEqual(code, expected)
            self.assertIn(f"State: {status}\n", rendered)
            self.assertIn("Production ready: false\n", rendered)
            self.assertNotIn("State: READY", rendered)

    def test_resume_rejects_unsafe_tls_file_and_closes_partial_opens(self) -> None:
        root = Path(self.temporary.name)
        parent, bundle, output = root / "parent", root / "bundle", root / "output"
        ca, cert, key = root / "ca", root / "cert", root / "key"
        for path, mode in ((ca, 0o644), (cert, 0o644), (key, 0o644)):
            path.write_text("tls", encoding="ascii")
            path.chmod(mode)
        with mock.patch.object(cli, "resume_blocked_evidence") as resume:
            code, result = self.invoke(
                "resume-evidence", "--from", str(parent), "--bundle", str(bundle),
                "--output", str(output), "--tls-ca", str(ca),
                "--tls-cert", str(cert), "--tls-key", str(key),
            )
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "TLS_INPUT_FILE_POLICY_INVALID")
        resume.assert_not_called()

    def test_resume_tls_open_failure_is_stable_and_closes_prior_fds(self) -> None:
        root = Path(self.temporary.name)
        ca = root / "ca"
        ca.write_text("tls", encoding="ascii")
        ca.chmod(0o644)
        missing = root / "missing"
        opened: list[int] = []
        real_open = os.open

        def observed_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            descriptor = real_open(path, flags, *args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with mock.patch.object(cli, "resume_blocked_evidence") as resume, mock.patch.object(
            cli.os, "open", side_effect=observed_open
        ):
            code, result = self.invoke(
                "resume-evidence", "--from", str(root / "parent"),
                "--bundle", str(root / "bundle"), "--output", str(root / "output"),
                "--tls-ca", str(ca), "--tls-cert", str(missing),
                "--tls-key", str(missing),
            )
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "TLS_INPUT_OPEN_FAILED")
        resume.assert_not_called()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_verify_release_uses_source_facts_and_never_upgrades_not_run(self) -> None:
        record = Path(self.temporary.name) / "record.json"
        record.write_text("{}", encoding="utf-8")
        verdict = SimpleNamespace(
            status="NOT_RUN", code="PRODUCTION_RELEASE_TRUST_NOT_RUN",
            mechanical_checks_passed=True, production_ready=False,
        )
        facts = {"source_commit": "a" * 40, "dirty": False}
        with mock.patch.object(cli, "collect_git_facts", return_value=facts), mock.patch.object(
            cli, "verify_record", return_value=verdict
        ) as verify:
            code, result = self.invoke("verify-release", "--record", str(record))
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertFalse(result["production_ready"])
        verify.assert_called_once_with(
            {}, actual_source_commit=facts["source_commit"], dirty=False
        )

    def test_human_verify_not_run_and_blocked_show_verdict_with_matching_exit(self) -> None:
        record = Path(self.temporary.name) / "record.json"
        record.write_text("{}", encoding="utf-8")
        facts = {"source_commit": "a" * 40, "dirty": False}
        cases = (
            ("NOT_RUN", "PRODUCTION_RELEASE_TRUST_NOT_RUN", True),
            ("BLOCKED", "BLOCKED_RECORD_SHAPE", False),
        )
        for status, verdict_code, mechanical in cases:
            verdict = SimpleNamespace(
                status=status, code=verdict_code,
                mechanical_checks_passed=mechanical, production_ready=False,
            )
            with self.subTest(status=status), mock.patch.object(
                cli, "collect_git_facts", return_value=facts
            ), mock.patch.object(cli, "verify_record", return_value=verdict):
                code, rendered = self.invoke_text(
                    "verify-release", "--record", str(record)
                )
            self.assertEqual(code, 2)
            self.assertIn(f"State: {status}\n", rendered)
            self.assertIn(f"Code: {verdict_code}\n", rendered)
            self.assertIn(
                f"Mechanical checks passed: {str(mechanical).lower()}\n", rendered
            )
            self.assertIn("Production ready: false\n", rendered)
            self.assertNotIn("State: READY", rendered)

    def test_command_exception_is_exit_one_with_stable_error(self) -> None:
        with mock.patch.object(cli, "rollback", side_effect=RuntimeError("INSTALL_NOT_PRESENT")):
            code, result = self.invoke("rollback")
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "INSTALL_NOT_PRESENT")


if __name__ == "__main__":
    unittest.main()
