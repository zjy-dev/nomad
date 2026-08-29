from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.nomad_web import cli


class Phase8CliTests(unittest.TestCase):
    ERROR_MODULES = (
        "agent_runtime.py",
        "bundle.py",
        "config.py",
        "diagnostics.py",
        "doctor.py",
        "evidence_resume.py",
        "install_lifecycle.py",
        "launcher.py",
        "lifecycle_coordinator.py",
        "materialize.py",
        "processes.py",
        "release_verify.py",
        "state.py",
    )
    ERROR_TYPES = frozenset({
        "RuntimeError", "HostIdentityError", "DiagnosticsError",
        "EvidenceResumeError", "ProcessError",
    })

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="nomad-phase8-cli-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.config = SimpleNamespace(
            repo_root=root, home=root / "home", bundle_root=None
        )

    def invoke_json(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output = StringIO()
        with mock.patch.object(
            cli.Config, "load", return_value=self.config
        ), redirect_stdout(output):
            code = cli.run(["--json", *arguments])
        return code, json.loads(output.getvalue())

    def invoke_text(self, *arguments: str) -> tuple[int, str]:
        output = StringIO()
        with mock.patch.object(
            cli.Config, "load", return_value=self.config
        ), redirect_stdout(output):
            code = cli.run(list(arguments))
        return code, output.getvalue()

    @staticmethod
    def onboarding(state: str) -> dict[str, object]:
        actions = {
            "NOT_INSTALLED": "INSTALL_VERIFIED_BUNDLE",
            "INSTALLED_NEEDS_START": "START_INSTALLED_BUNDLE",
            "INSTALLED_BLOCKED_HOST_IDENTITY": "AUTHORIZE_HOST_IDENTITY",
            "RUNNING_NEEDS_PAIRING": "PAIR_PHONE",
            "RUNNING_PAIRED": "USE_INSTALLED_CANDIDATE",
            "RUNNING_DEGRADED_RECOVERY_REQUIRED": "RECOVER_RUNNING_IDENTITY",
        }
        blockers = (
            ["HOST_IDENTITY_AUTH_REQUIRED"]
            if state == "INSTALLED_BLOCKED_HOST_IDENTITY"
            else ["RUNTIME_STATE_INVALID"]
            if state == "RUNNING_DEGRADED_RECOVERY_REQUIRED"
            else []
        )
        return {
            "schema": "nomad.web-companion.onboarding.v1",
            "state": state,
            "production_ready": False,
            "external_readiness": "NOT_RUN",
            "external_gates": [
                {"code": "PROVIDER_E3_NOT_RUN", "status": "NOT_RUN"}
            ],
            "installed_bundle_digest": None,
            "install_sequence": None,
            "run_identity": None,
            "paired_device_commitment": None,
            "pairing_epoch": None,
            "blockers": blockers,
            "next_action": actions[state],
        }

    def test_install_status_routes_to_lifecycle_and_not_installed_is_success(self) -> None:
        onboarding = self.onboarding("NOT_INSTALLED")
        result = {
            "schema": "nomad.web-companion.install-status.v1",
            "state": "NOT_INSTALLED",
            "current_bundle_digest": None,
            "bundle_digests": [],
            "history": [],
            "onboarding": onboarding,
        }
        with mock.patch.object(
            cli, "install_status", return_value=result
        ) as status:
            code, emitted = self.invoke_json("install-status")
        self.assertEqual((code, emitted), (0, result))
        status.assert_called_once_with(self.config)

        with mock.patch.object(cli, "install_status", return_value=result):
            code, rendered = self.invoke_text("install-status")
        self.assertEqual(code, 0)
        self.assertEqual(
            rendered,
            "State: NOT_INSTALLED\n"
            "Mode: nomad-web\n"
            "Onboarding: NOT_INSTALLED\n"
            "Production ready: false\n"
            "External readiness: NOT_RUN\n"
            "Next: Install Nomad from the release download.\n",
        )

    def test_onboarding_six_states_freeze_json_and_exit_semantics(self) -> None:
        states = (
            "NOT_INSTALLED",
            "INSTALLED_NEEDS_START",
            "INSTALLED_BLOCKED_HOST_IDENTITY",
            "RUNNING_NEEDS_PAIRING",
            "RUNNING_PAIRED",
            "RUNNING_DEGRADED_RECOVERY_REQUIRED",
        )
        for state in states:
            result = self.onboarding(state)
            expected = 2 if state == "RUNNING_DEGRADED_RECOVERY_REQUIRED" else 0
            with self.subTest(state=state), mock.patch.object(
                cli, "onboarding_status", return_value=result
            ) as status:
                code, emitted = self.invoke_json("onboarding")
            self.assertEqual((code, emitted), (expected, result))
            status.assert_called_once_with(self.config)

    def test_blocked_onboarding_is_human_recoverable_and_not_failure(self) -> None:
        result = self.onboarding("INSTALLED_BLOCKED_HOST_IDENTITY")
        with mock.patch.object(cli, "onboarding_status", return_value=result):
            code, rendered = self.invoke_text("onboarding")
        self.assertEqual(code, 0)
        self.assertEqual(
            rendered,
            "State: INSTALLED_BLOCKED_HOST_IDENTITY\n"
            "Mode: nomad-web\n"
            "Production ready: false\n"
            "External readiness: NOT_RUN\n"
            "Blockers: HOST_IDENTITY_AUTH_REQUIRED\n"
            "Next: Approve Nomad for this Mac when prompted.\n",
        )
        self.assertNotIn("{", rendered)

    def test_diagnostics_requires_one_output_and_routes_to_export(self) -> None:
        code, result = self.invoke_json("diagnostics")
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "DIAGNOSTICS_OUTPUT_REQUIRED")

        output = Path(self.temporary.name) / "support.json"
        diagnostics = {
            "schema": "nomad.web-companion.support-diagnostics.v1",
            "classification": "support-only-not-readiness-evidence",
            "production_ready": False,
            "readiness_evidence": False,
            "manifest_digest": "a" * 64,
        }
        with mock.patch.object(
            cli, "export_diagnostics", return_value=diagnostics
        ) as export:
            code, emitted = self.invoke_json(
                "diagnostics", "--output", str(output)
            )
        self.assertEqual((code, emitted), (0, diagnostics))
        export.assert_called_once_with(self.config, output)

        with mock.patch.object(cli, "export_diagnostics", return_value=diagnostics):
            code, rendered = self.invoke_text(
                "diagnostics", "--output", str(output)
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            rendered,
            "State: EXPORTED\n"
            "Mode: support-only-not-readiness-evidence\n"
            "Production ready: false\n"
            "Readiness evidence: false\n",
        )

    def test_reset_and_uninstall_use_lifecycle_handlers(self) -> None:
        reset = {
            "schema": "nomad.web-companion.remote-access-reset.v1",
            "state": "STOPPED",
            "mode": "foundation-readonly",
            "remote_access": "CLEARED",
            "install_state": "PRESERVED",
            "host_identity_disposition": "retained",
            "production_ready": False,
        }
        uninstall = {
            "schema": "nomad.web-companion.uninstall-result.v1",
            "state": "UNINSTALLED",
            "mode": "foundation-readonly",
            "remote_access": "CLEARED",
            "install_state": "REMOVED",
            "host_identity_disposition": "retained",
            "production_ready": False,
        }
        for command, handler_name, result in (
            ("reset-remote-access", "reset_remote_access", reset),
            ("uninstall", "uninstall_lifecycle", uninstall),
        ):
            with self.subTest(command=command), mock.patch.object(
                cli, handler_name, return_value=result
            ) as handler:
                code, emitted = self.invoke_json(command, "--confirm")
            self.assertEqual((code, emitted), (0, result))
            handler.assert_called_once_with(self.config)

        with mock.patch.object(cli, "reset_remote_access", return_value=reset):
            code, rendered = self.invoke_text("reset-remote-access", "--confirm")
        self.assertEqual(code, 0)
        self.assertEqual(
            rendered,
            "State: STOPPED\n"
            "Mode: foundation-readonly\n"
            "Production ready: false\n"
            "Remote access: CLEARED\n"
            "Install state: PRESERVED\n"
            "Host identity: retained\n",
        )
        with mock.patch.object(cli, "uninstall_lifecycle", return_value=uninstall):
            code, rendered = self.invoke_text("uninstall", "--confirm")
        self.assertEqual(code, 0)
        self.assertEqual(
            rendered,
            "State: UNINSTALLED\n"
            "Mode: foundation-readonly\n"
            "Production ready: false\n"
            "Remote access: CLEARED\n"
            "Install state: REMOVED\n"
            "Host identity: retained\n",
        )

    def test_operation_status_routes_and_exit_semantics(self) -> None:
        base = {
            "schema": "nomad.web-companion.lifecycle-operation-status.v1",
            "operation_id": "operation_0123456789",
            "operation": "uninstall", "terminal": True,
            "error": None, "recovery": None,
            "latest_known": False,
        }
        for arguments, state, expected in (
            (("--operation-id", "operation_0123456789"), "completed", 0),
            (("--latest",), "outcome_unknown", 2),
            (("--latest",), "failed", 1),
        ):
            result = {**base, "state": state, "latest_known": "--latest" in arguments}
            with self.subTest(state=state), mock.patch.object(cli, "operation_status", return_value=result) as status:
                code, emitted = self.invoke_json("operation-status", *arguments)
            self.assertEqual((code, emitted), (expected, result))
            status.assert_called_once_with(
                self.config,
                "operation_0123456789" if "--operation-id" in arguments else None,
                latest="--latest" in arguments,
            )
        with mock.patch.object(cli, "operation_status", return_value=base):
            _, rendered = self.invoke_text("operation-status", "--latest")
        self.assertNotIn("Error: None", rendered)

    def test_destructive_lifecycle_commands_require_confirmation(self) -> None:
        for command, handler_name, expected in (
            (
                "reset-remote-access",
                "reset_remote_access",
                "RESET_CONFIRMATION_REQUIRED",
            ),
            ("uninstall", "uninstall_lifecycle", "UNINSTALL_CONFIRMATION_REQUIRED"),
        ):
            with self.subTest(command=command), mock.patch.object(
                cli, handler_name
            ) as handler:
                code, result = self.invoke_json(command)
            self.assertEqual(code, 1)
            self.assertEqual(result["error"], expected)
            handler.assert_not_called()
            with mock.patch.object(cli, handler_name) as human_handler:
                human_code, rendered = self.invoke_text(command)
            self.assertEqual(human_code, 1)
            self.assertEqual(
                rendered,
                "State: BLOCKED\n"
                "Mode: nomad-web\n"
                f"Error: {expected}\n"
                "Production ready: false\n",
            )
            human_handler.assert_not_called()

    def test_errors_preserve_output_mode_and_never_echo_arbitrary_text(self) -> None:
        cases = (
            (RuntimeError("INSTALL_NOT_PRESENT"), "INSTALL_NOT_PRESENT"),
            (RuntimeError("SECRET_TOKEN_CANARY"), "LAUNCHER_FAILURE"),
            (RuntimeError("SK_LIVE_ABC123"), "LAUNCHER_FAILURE"),
            (RuntimeError("A" * 10_000), "LAUNCHER_FAILURE"),
            (RuntimeError("Secret /tmp/private token"), "LAUNCHER_FAILURE"),
            (RuntimeError("UPPER CASE"), "LAUNCHER_FAILURE"),
            (RuntimeError("ÉCHEC"), "LAUNCHER_FAILURE"),
        )
        for error, expected in cases:
            with self.subTest(error=repr(error)), mock.patch.object(
                cli, "rollback", side_effect=error
            ):
                code, result = self.invoke_json("rollback")
            self.assertEqual(code, 1)
            self.assertEqual(result["error"], expected)
            if expected == "LAUNCHER_FAILURE":
                self.assertNotIn(str(error), json.dumps(result))

        with mock.patch.object(
            cli, "rollback", side_effect=RuntimeError("Secret /tmp/private token")
        ):
            code, rendered = self.invoke_text("rollback")
        self.assertEqual(code, 1)
        self.assertEqual(
            rendered,
            "State: BLOCKED\n"
            "Mode: nomad-web\n"
            "Error: LAUNCHER_FAILURE\n"
            "Production ready: false\n",
        )
        self.assertNotIn("Secret", rendered)
        self.assertNotIn("{", rendered)

        unsafe = cli.HostIdentityError(
            "HOST_IDENTITY_AUTH_REQUIRED", next_step="open /tmp/private-token"
        )
        with mock.patch.object(cli, "authorize_host_identity", side_effect=unsafe):
            code, result = self.invoke_json("authorize-host-identity")
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "HOST_IDENTITY_AUTH_REQUIRED")
        self.assertNotIn("next_step", result)

    def test_reachable_literal_error_codes_are_explicitly_allowlisted(self) -> None:
        module_root = Path(cli.__file__).resolve().parent
        literal_codes: set[str] = set()
        for module_name in self.ERROR_MODULES:
            source = (module_root / module_name).read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(source)):
                if (
                    not isinstance(node, ast.Raise)
                    or not isinstance(node.exc, ast.Call)
                    or not node.exc.args
                ):
                    continue
                function = node.exc.func
                error_type = (
                    function.id
                    if isinstance(function, ast.Name)
                    else function.attr
                    if isinstance(function, ast.Attribute)
                    else None
                )
                value = node.exc.args[0]
                if (
                    error_type in self.ERROR_TYPES
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    literal_codes.add(value.value)
        self.assertTrue(literal_codes)
        self.assertEqual(literal_codes - cli.KNOWN_ERROR_CODES, set())
        self.assertTrue(all(code.isascii() for code in cli.KNOWN_ERROR_CODES))
        self.assertTrue(all(
            0 < len(code) <= cli.MAX_ERROR_CODE_LENGTH
            for code in cli.KNOWN_ERROR_CODES
        ))

    def test_json_parse_errors_are_canonical_content_free_and_stderr_empty(self) -> None:
        canaries = (
            ("SECRET_TOKEN_CANARY",),
            ("--tls-cert-fd", "SK_LIVE_ABC123", "start"),
            tuple(),
        )
        root = Path(__file__).resolve().parents[2]
        for arguments in canaries:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [
                        sys.executable, "-c",
                        "from tools.nomad_web.cli import run; raise SystemExit(run())",
                        "--json", *arguments,
                    ],
                    cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, timeout=30,
                )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            self.assertEqual(
                result.stdout,
                '{"error":"CLI_ARGUMENT_INVALID","production_ready":false,'
                '"schema":"nomad.web-companion.error.v1","state":"BLOCKED"}\n',
            )
            for canary in arguments:
                self.assertNotIn(canary, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
