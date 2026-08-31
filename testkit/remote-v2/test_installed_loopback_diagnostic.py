from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import sqlite3
import unittest
from unittest import mock


ROOT = Path(__file__).parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("installed_loopback_diagnostic", "installed_loopback_diagnostic.py")
browser = load("run_m3e_desktop_browser_p10_contract", "run_m3e_desktop_browser.py")


class AcceptedBrowserIsolationTests(unittest.TestCase):
    def test_phone_emulation_is_not_a_cli_option(self) -> None:
        argv = [
            "browser", "--desktop-url", "http://127.0.0.1:1",
            "--public-origin", "https://127.0.0.1:2", "--profile", "/tmp/profile",
            "--phone-emulation",
        ]
        with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
            browser.parse_args()

    def test_default_path_retains_accepted_schema_and_desktop_pages(self) -> None:
        self.assertEqual(browser._result_schema(False), browser.SCHEMA)
        self.assertEqual(browser._page_modes(False), ["desktop", "desktop"])
        self.assertEqual(browser._browser_mode_evidence(False), {})
        self.assertEqual(browser._diagnostic_write_command_evidence(False, 1), {})

    def test_private_phone_emulation_has_diagnostic_schema(self) -> None:
        self.assertEqual(browser._result_schema(True), browser.LOOPBACK_DIAGNOSTIC_SCHEMA)
        self.assertEqual(browser._page_modes(True), ["desktop", "phone-emulation"])

    def test_private_diagnostic_zero_write_count_is_content_free_evidence(self) -> None:
        self.assertEqual(
            browser._diagnostic_write_command_evidence(True, 0),
            {"write_command_post_count": 0},
        )

    def test_private_diagnostic_rejects_one_write_command(self) -> None:
        with self.assertRaisesRegex(
            browser.BrowserEvidenceError, "diagnostic_write_command_observed",
        ) as raised:
            browser._diagnostic_write_command_evidence(True, 1)
        self.assertEqual(raised.exception.diagnostics, {"write_command_post_count": 1})

    def test_only_exact_command_post_is_counted(self) -> None:
        self.assertTrue(browser._is_write_command_post(
            "https://127.0.0.1:4443/api/commands", "POST",
        ))
        self.assertTrue(browser._is_write_command_post(
            "https://127.0.0.1:4443/api/commands?request=opaque", "POST",
        ))
        for url, method in (
            ("https://127.0.0.1:4443/api/commands", "GET"),
            ("https://127.0.0.1:4443/api/commands/", "POST"),
            ("https://127.0.0.1:4443/api/desktop/pairing/create", "POST"),
            ("https://127.0.0.1:4443/api/desktop/devices/revoke", "POST"),
        ):
            self.assertFalse(browser._is_write_command_post(url, method))

    def test_private_phone_emulation_requires_spki_before_playwright(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            chrome = Path(raw) / "chrome"; chrome.write_bytes(b"chrome")
            args = argparse.Namespace(
                chrome=chrome, desktop_url="http://127.0.0.1:1",
                public_origin="https://127.0.0.1:2", diagnostic_spki_sha256=None,
                profile=Path(raw) / "profile", timeout_ms=1,
            )
            with self.assertRaisesRegex(
                browser.BrowserEvidenceError,
                "installed_loopback_phone_emulation_requires_spki",
            ):
                browser.run(args, _installed_loopback_phone_emulation=True)


class CliAndLoopbackContractTests(unittest.TestCase):
    def test_cli_requires_explicit_exact_mode_bundle_chrome_and_artifact_dir(self) -> None:
        parsed = runner.parse_args([
            "--mode", runner.MODE, "--installed-bundle", "/x/bundles/" + "a" * 64,
            "--chrome", "/Applications/Google Chrome", "--artifact-dir", "/tmp/a",
        ])
        self.assertEqual(parsed.mode, runner.MODE)
        with self.assertRaises(SystemExit):
            runner.parse_args([
                "--mode", "remote-loopback-diagnostic",
                "--installed-bundle", "/bundle", "--chrome", "/chrome",
                "--artifact-dir", "/artifacts",
            ])

    def test_cli_has_one_bundle_argument_and_no_accepted_mode(self) -> None:
        source = (ROOT / "installed_loopback_diagnostic.py").read_text()
        self.assertEqual(source.count('parser.add_argument("--installed-bundle"'), 1)
        self.assertNotIn("--verified-bundle", source)
        self.assertNotIn("remote-local-evidence", source)

    def test_only_literal_ipv4_loopback_urls_are_valid(self) -> None:
        self.assertTrue(runner._literal_loopback_url("https://127.0.0.1:443", https=True))
        self.assertTrue(runner._literal_loopback_url("http://127.0.0.1:1/", https=False))
        for value in (
            "https://localhost:443", "https://[::1]:443",
            "https://[::ffff:127.0.0.1]:443", "https://0.0.0.0:443",
            "https://192.168.1.2:443", "https://127.0.0.1.evil:443",
            "https://user@127.0.0.1:443",
        ):
            self.assertFalse(runner._literal_loopback_url(value, https=True), value)

    def test_launcher_state_rejects_nonloopback_and_non_diagnostic(self) -> None:
        state = launcher_state()
        runner.validate_launcher_state(state, "a" * 64, 19000)
        for change in (
            {"mode": "remote-local-evidence"},
            {"accepted_eligible": True},
            {"pairing_ready": False},
            {"remote_mailbox_ready": False},
            {"pairing_public_origin": "https://localhost:4443"},
            {"agent_origin": "http://0.0.0.0:4096"},
        ):
            with self.assertRaisesRegex(runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_STATE_INVALID"):
                runner.validate_launcher_state({**state, **change}, "a" * 64, 19000)

    def test_launcher_state_requires_exact_nonclaim_gates_and_no_dispatch(self) -> None:
        state = launcher_state()
        for gates in ([], state["external_gates"][:-1], [
            *state["external_gates"][:-1], {"gate": "writes", "status": "COMPLETE"},
        ]):
            with self.assertRaisesRegex(runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_GATES_INVALID"):
                runner.validate_launcher_state({**state, "external_gates": gates}, "a" * 64, 19000)
        with self.assertRaisesRegex(runner.DiagnosticError, "PROVIDER_DISPATCH_INVALID"):
            runner.validate_launcher_state({**state, "_initial_prompt_dispatch": {}}, "a" * 64, 19000)

    def test_running_status_requires_running_live_unique_roles_without_sidecar(self) -> None:
        status = running_status()
        runner.validate_running_status(status, "a" * 64, 19000)
        for change in (
            {"state": "DEGRADED"},
            {"lifecycle_coordinator": {"name": "coordinator", "pid": 999, "alive": True}},
            {"processes": status["processes"][:-1]},
            {"processes": [{**status["processes"][0], "pid": status["processes"][1]["pid"]}, *status["processes"][1:]]},
            {"processes": [{**status["processes"][0], "alive": False}, *status["processes"][1:]]},
            {"processes": [{**status["processes"][0], "ownership": "owned"}, *status["processes"][1:]]},
        ):
            with self.subTest(change=change):
                with self.assertRaisesRegex(
                    runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_RUNNING_STATUS_INVALID",
                ):
                    runner.validate_running_status({**status, **change}, "a" * 64, 19000)

    def test_google_chrome_requires_exact_canonical_regular_executable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "Applications" / "Google Chrome.app" / "Contents" / "MacOS"
            root.mkdir(parents=True)
            chrome = root / "Google Chrome"
            chrome.write_bytes(b"chrome")
            os.chmod(chrome, 0o500)
            canonical_chrome = chrome.resolve()
            with mock.patch.object(
                runner, "EXPECTED_GOOGLE_CHROME_EXECUTABLE", canonical_chrome,
            ):
                self.assertEqual(
                    runner.verify_google_chrome_executable(canonical_chrome),
                    canonical_chrome,
                )
                symlink = Path(raw) / "chrome-link"
                symlink.symlink_to(chrome)
                with self.assertRaisesRegex(runner.DiagnosticError, "GOOGLE_CHROME_UNSAFE"):
                    runner.verify_google_chrome_executable(symlink)
                os.chmod(chrome, 0o522)
                with self.assertRaisesRegex(runner.DiagnosticError, "GOOGLE_CHROME_UNSAFE"):
                    runner.verify_google_chrome_executable(chrome)

    def test_runner_never_imports_or_adds_installed_bundle_to_sys_path(self) -> None:
        source = (ROOT / "installed_loopback_diagnostic.py").read_text()
        for forbidden in (
            "_dynamic_bundle_modules", "importlib", "sys.path",
            "runpy", 'import nomad_web', 'from nomad_web',
        ):
            self.assertNotIn(forbidden, source)

    def test_clean_launcher_environment_has_no_code_or_provider_injection(self) -> None:
        with mock.patch.dict(os.environ, {
            "PYTHONPATH": "/poison", "NOMAD_WEB_BUNDLE": "/poison",
            "OPENAI_API_KEY": "secret", "PATH": "/usr/bin:/bin",
            "UV_INDEX_URL": "https://poison", "PIP_INDEX_URL": "https://poison",
            "PYTHONHOME": "/poison", "VIRTUAL_ENV": "/poison",
            "PIP_KEYRING_PROVIDER": "subprocess",
        }):
            env = runner.clean_launcher_env()
        self.assertEqual(set(env), {"HOME", "PATH", "NO_PROXY", "no_proxy"})
        self.assertFalse(set(env) & runner.PROVIDER_NAMES)

    def test_allowed_tools_resolve_to_safe_absolute_regular_files(self) -> None:
        path = runner.resolve_allowed_tool("openssl")
        self.assertTrue(path.is_absolute())
        self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
        self.assertFalse(path.is_symlink())
        with mock.patch.object(runner, "ALLOWED_TOOL_CANDIDATES", {
            "uv": (Path("/definitely/missing/uv"),),
        }):
            with self.assertRaisesRegex(runner.DiagnosticError, "UV_TOOL_UNSAFE_OR_MISSING"):
                runner.resolve_allowed_tool("uv")

    def test_uv_group_writable_source_is_safe_only_via_pinned_private_snapshot(self) -> None:
        raw_uv = b"pinned uv executable bytes"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_parent = root / "Cellar"; source_parent.mkdir(mode=0o775)
            os.chmod(source_parent, 0o775)
            source = source_parent / "uv"; source.write_bytes(raw_uv); os.chmod(source, 0o500)
            locator = root / "uv-link"; locator.symlink_to(source)
            private = root / "run"; private.mkdir(mode=0o700)
            version = mock.Mock(
                returncode=0, stderr=b"",
                stdout=runner.PINNED_UV_VERSION.encode("ascii") + b"\n",
            )
            with (
                mock.patch.object(runner, "PINNED_UV_CANDIDATE", locator),
                mock.patch.object(runner, "PINNED_UV_RESOLVED", source.resolve()),
                mock.patch.object(
                    runner, "PINNED_UV_SHA256", hashlib.sha256(raw_uv).hexdigest(),
                ),
                mock.patch.object(runner.subprocess, "run", return_value=version) as execute,
            ):
                snapshot = runner.snapshot_pinned_uv(private, runner.clean_launcher_env())
            self.assertEqual(snapshot, private / "uv-pinned")
            self.assertEqual(snapshot.read_bytes(), raw_uv)
            self.assertEqual(stat.S_IMODE(snapshot.lstat().st_mode), 0o500)
            self.assertEqual(snapshot.lstat().st_nlink, 1)
            self.assertEqual(execute.call_args.args[0], [
                str(snapshot), "--no-config", "--no-python-downloads", "--version",
            ])

    def test_uv_snapshot_rejects_wrong_hash_and_source_replacement(self) -> None:
        raw_uv = b"pinned uv executable bytes"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); source = root / "uv"
            source.write_bytes(raw_uv); os.chmod(source, 0o500)
            private = root / "run"; private.mkdir(mode=0o700)
            common = (
                mock.patch.object(runner, "PINNED_UV_CANDIDATE", source),
                mock.patch.object(runner, "PINNED_UV_RESOLVED", source.resolve()),
            )
            with common[0], common[1], mock.patch.object(runner, "PINNED_UV_SHA256", "0" * 64):
                with self.assertRaisesRegex(runner.DiagnosticError, "UV_TOOL_IDENTITY_MISMATCH"):
                    runner.snapshot_pinned_uv(private, runner.clean_launcher_env())
            self.assertFalse((private / "uv-pinned").exists())

            original_fstat = os.fstat
            calls = 0

            def replaced(descriptor):
                nonlocal calls
                calls += 1
                info = original_fstat(descriptor)
                if calls == 2:
                    changed = mock.Mock()
                    for field in (
                        "st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                        "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
                    ):
                        setattr(changed, field, getattr(info, field))
                    changed.st_ctime_ns += 1
                    return changed
                return info

            with (
                mock.patch.object(runner, "PINNED_UV_CANDIDATE", source),
                mock.patch.object(runner, "PINNED_UV_RESOLVED", source.resolve()),
                mock.patch.object(
                    runner, "PINNED_UV_SHA256", hashlib.sha256(raw_uv).hexdigest(),
                ),
                mock.patch.object(runner.os, "fstat", side_effect=replaced),
            ):
                with self.assertRaisesRegex(runner.DiagnosticError, "UV_TOOL_IDENTITY_MISMATCH"):
                    runner.snapshot_pinned_uv(private, runner.clean_launcher_env())
            self.assertFalse((private / "uv-pinned").exists())

    def test_standalone_has_only_exact_spki_certificate_bypass(self) -> None:
        source = (ROOT / "installed_loopback_diagnostic.py").read_text()
        self.assertNotIn("ignore_https_errors=True", source)
        self.assertNotIn('"--ignore-certificate-errors"', source)
        browser_source = (ROOT / "run_m3e_desktop_browser.py").read_text()
        self.assertIn("--ignore-certificate-errors-spki-list=", browser_source)


class TlsAndEvidenceTests(unittest.TestCase):
    def _bundle_with_runner(self, root: Path, raw: bytes = b"print('browser')\n") -> Path:
        bundle = root / ("0" * 64)
        target = bundle / "testkit" / "remote-v2" / "run_m3e_desktop_browser.py"
        target.parent.mkdir(parents=True); target.write_bytes(raw); os.chmod(target, 0o644)
        core = {
            "schema": "nomad.web-companion.prebuilt.v2",
            "files": [{
                "path": "testkit/remote-v2/run_m3e_desktop_browser.py",
                "size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "mode": "0644",
            }],
        }
        digest = hashlib.sha256(runner.canonical_manifest_json(core)).hexdigest()
        renamed = root / digest; bundle.rename(renamed)
        manifest = {**core, "bundle_digest": digest}
        (renamed / "manifest.json").write_bytes(runner.canonical_manifest_json(manifest) + b"\n")
        os.chmod(renamed / "manifest.json", 0o644); os.chmod(renamed, 0o755)
        return renamed

    def test_browser_runner_bytes_are_bound_to_manifest_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle = self._bundle_with_runner(Path(raw))
            content, digest = runner._read_browser_runner(bundle)
            self.assertEqual(digest, hashlib.sha256(content).hexdigest())
            path = bundle / "testkit/remote-v2/run_m3e_desktop_browser.py"
            path.write_bytes(content + b"# tamper\n")
            with self.assertRaisesRegex(runner.DiagnosticError, "MANIFEST_MISMATCH"):
                runner._read_browser_runner(bundle)

    def test_browser_runner_rejects_manifest_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle = self._bundle_with_runner(Path(raw))
            manifest_path = bundle / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["files"][0]["raw_sha256"] = "f" * 64
            manifest_path.write_bytes(runner.canonical_manifest_json(manifest) + b"\n")
            with self.assertRaisesRegex(runner.DiagnosticError, "MANIFEST_DIGEST_INVALID"):
                runner._read_browser_runner(bundle)

    def test_browser_runner_rejects_bundle_replaced_after_install_status(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle = self._bundle_with_runner(Path(raw))
            identity = runner._file_identity(bundle.lstat())
            original = Path(raw) / "old"; bundle.rename(original); bundle.mkdir(mode=0o755)
            with self.assertRaisesRegex(runner.DiagnosticError, "INSTALLED_BUNDLE_REPLACED"):
                runner._read_browser_runner(bundle, identity)

    def test_browser_executes_only_hardened_uv_snapshot_argv_and_clean_env(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); bundle = self._bundle_with_runner(root)
            snapshot = root / "uv-pinned"; snapshot.write_bytes(b"uv"); os.chmod(snapshot, 0o500)
            chrome = root / "chrome"; chrome.write_bytes(b"chrome")
            profile = root / "profile"; profile.mkdir()
            runner_raw = (bundle / "testkit/remote-v2/run_m3e_desktop_browser.py").read_bytes()
            value = {
                "schema": runner.BROWSER_SCHEMA, "status": "DIAGNOSTIC_COMPLETE",
                "runner_raw_sha256": hashlib.sha256(runner_raw).hexdigest(),
                "content_free": True, "write_command_post_count": 0,
                "https": {"ignore_https_errors": False, "spki_allowlist_count": 1},
                "browser": {"page_modes": ["desktop", "phone-emulation"]},
                "journey": {"actions": {
                    "reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN",
                }},
            }
            completed = mock.Mock(
                returncode=0, stderr=b"",
                stdout=json.dumps(value, sort_keys=True).encode("utf-8") + b"\n",
            )
            clean = runner.clean_launcher_env()
            process = mock.Mock(
                pid=4321, returncode=0,
                communicate=mock.Mock(return_value=(completed.stdout, completed.stderr)),
            )
            with (
                mock.patch.object(runner.subprocess, "Popen", return_value=process) as execute,
                mock.patch.object(runner, "cleanup_browser_process"),
            ):
                runner.run_browser(
                    bundle, chrome, "http://127.0.0.1:1", "https://127.0.0.1:2",
                    profile, "A" * 44, clean, snapshot,
                )
            command = execute.call_args.args[0]
            self.assertEqual(command[:10], [
                str(snapshot), "--no-config", "--no-python-downloads", "run",
                "--isolated", "--no-project", "--no-env-file",
                "--with", "playwright==1.62.0", "python",
            ])
            self.assertEqual(execute.call_args.kwargs["env"], clean)
            self.assertTrue(execute.call_args.kwargs["start_new_session"])
            self.assertEqual(set(clean), {"HOME", "PATH", "NO_PROXY", "no_proxy"})

    def test_browser_cleanup_terminates_group_then_kills_on_timeout(self) -> None:
        process = mock.Mock(pid=4321)
        process.wait = mock.Mock(side_effect=[
            runner.subprocess.TimeoutExpired(["uv"], 5),
            0,
        ])
        with (
            mock.patch.object(runner.os, "killpg") as killpg,
            mock.patch.object(runner, "_profile_process_lines", return_value=[]),
        ):
            runner.cleanup_browser_process(process, Path("/tmp/profile"))
        self.assertEqual(
            [call.args for call in killpg.call_args_list],
            [(4321, runner.signal.SIGTERM), (4321, runner.signal.SIGKILL)],
        )

    def test_browser_cleanup_rejects_profile_process_residue(self) -> None:
        process = mock.Mock(pid=4321)
        process.wait = mock.Mock(return_value=0)
        with (
            mock.patch.object(runner.os, "killpg"),
            mock.patch.object(runner.time, "sleep"),
            mock.patch.object(
                runner, "_profile_process_lines",
                side_effect=[[b"4321 4321 chrome /tmp/profile"]] * 21,
            ),
        ):
            with self.assertRaisesRegex(runner.DiagnosticError, "BROWSER_DIAGNOSTIC_PROCESS_LEAK"):
                runner.cleanup_browser_process(process, Path("/tmp/profile"))

    def test_run_browser_surfaces_cleanup_failure_after_successful_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); bundle = self._bundle_with_runner(root)
            snapshot = root / "uv-pinned"; snapshot.write_bytes(b"uv"); os.chmod(snapshot, 0o500)
            chrome = root / "chrome"; chrome.write_bytes(b"chrome")
            profile = root / "profile"; profile.mkdir()
            runner_raw = (bundle / "testkit/remote-v2/run_m3e_desktop_browser.py").read_bytes()
            value = {
                "schema": runner.BROWSER_SCHEMA, "status": "DIAGNOSTIC_COMPLETE",
                "runner_raw_sha256": hashlib.sha256(runner_raw).hexdigest(),
                "content_free": True, "write_command_post_count": 0,
                "https": {"ignore_https_errors": False, "spki_allowlist_count": 1},
                "browser": {"page_modes": ["desktop", "phone-emulation"]},
                "journey": {"actions": {
                    "reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN",
                }},
            }
            process = mock.Mock(
                pid=4321, returncode=0,
                communicate=mock.Mock(return_value=(
                    json.dumps(value, sort_keys=True).encode("utf-8") + b"\n", b"",
                )),
            )
            with (
                mock.patch.object(runner.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    runner, "cleanup_browser_process",
                    side_effect=runner.DiagnosticError("BROWSER_DIAGNOSTIC_PROCESS_LEAK"),
                ),
            ):
                with self.assertRaisesRegex(runner.DiagnosticError, "BROWSER_DIAGNOSTIC_PROCESS_LEAK"):
                    runner.run_browser(
                        bundle, chrome, "http://127.0.0.1:1", "https://127.0.0.1:2",
                        profile, "A" * 44, runner.clean_launcher_env(), snapshot,
                    )

    def test_zero_command_journal_required(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw); (home / "run").mkdir()
            state = {"run_id": "c" * 64}
            path = runner.command_journal_path(home, state["run_id"])
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE commands (request_id TEXT)")
            connection.commit(); connection.close(); os.chmod(path, 0o600)
            runner.assert_command_journal_empty(home, state)
            connection = sqlite3.connect(path)
            connection.execute("INSERT INTO commands VALUES ('opaque')")
            connection.commit(); connection.close()
            with self.assertRaisesRegex(runner.DiagnosticError, "HOST_WRITE_COMMAND_DETECTED"):
                runner.assert_command_journal_empty(home, state)

    def test_existing_wrong_mode_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "artifacts"; path.mkdir(mode=0o755)
            os.chmod(path, 0o755)
            with self.assertRaisesRegex(runner.DiagnosticError, "ARTIFACT_DIRECTORY_UNSAFE"):
                runner.ensure_artifact_dir(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_symlink_artifact_is_rejected_without_mutating_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); target = root / "target"; target.mkdir(mode=0o755)
            os.chmod(target, 0o755)
            link = root / "artifacts"; link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(runner.DiagnosticError, "ARTIFACT_DIRECTORY_UNSAFE"):
                runner.ensure_artifact_dir(link)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertTrue(link.is_symlink())

    def test_artifact_path_must_be_absolute_and_parent_must_exist(self) -> None:
        with self.assertRaisesRegex(runner.DiagnosticError, "MUST_BE_ABSOLUTE"):
            runner.ensure_artifact_dir(Path("relative"))
        with tempfile.TemporaryDirectory() as raw:
            missing = Path(raw) / "missing" / "artifacts"
            with self.assertRaises(runner.DiagnosticError) as raised:
                runner.ensure_artifact_dir(missing)
            self.assertEqual(str(raised.exception), "ARTIFACT_DIRECTORY_PARENT_MISSING")

        sticky_target = Path("/tmp") / next(tempfile._get_candidate_names())
        try:
            self.assertEqual(runner.ensure_artifact_dir(sticky_target), sticky_target.resolve())
        finally:
            if sticky_target.is_dir():
                sticky_target.rmdir()

        with tempfile.TemporaryDirectory() as raw:
            writable_parent = Path(raw)
            os.chmod(writable_parent, 0o1777)
            try:
                with self.assertRaisesRegex(
                    runner.DiagnosticError, "ARTIFACT_DIRECTORY_ANCESTOR_UNSAFE",
                ):
                    runner.ensure_artifact_dir(writable_parent / "artifacts")
                self.assertFalse((writable_parent / "artifacts").exists())
            finally:
                os.chmod(writable_parent, 0o700)

    def test_generated_tls_has_only_literal_loopback_san_and_single_spki(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            openssl = runner.resolve_allowed_tool("openssl")
            cert, key, pin = runner.generate_loopback_tls(root, openssl)
            self.assertEqual(stat.S_IMODE(cert.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(len(__import__("base64").b64decode(pin, validate=True)), 32)
            text = __import__("subprocess").check_output([
                "openssl", "x509", "-in", str(cert), "-noout", "-text",
            ], text=True)
            san = text.split("X509v3 Subject Alternative Name:", 1)[1].splitlines()[1]
            self.assertEqual(san.strip(), "IP Address:127.0.0.1")
            self.assertNotIn("DNS:", text)

    def test_success_contract_has_no_acceptance_claims(self) -> None:
        value = success_evidence()
        runner.validate_success_evidence(value)
        serialized = runner.canonical_json(value).decode()
        self.assertNotRegex(serialized, r"(?i)PASS|READY|ACCEPTED")
        for key in ("remote_local_evidence", "external", "physical", "provider"):
            self.assertEqual(value[key], "NOT_RUN")
        self.assertFalse(value["tls_verified"])

    def test_success_contract_rejects_forbidden_claim_at_any_depth(self) -> None:
        for word in ("PASS", "READY", "ACCEPTED"):
            value = success_evidence(); value["nested"] = {"claim": word}
            with self.assertRaisesRegex(runner.DiagnosticError, "SUCCESS_EVIDENCE_FORBIDDEN_CLAIM"):
                runner.validate_success_evidence(value)

    def test_atomic_private_nonoverwrite_and_secret_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw); os.chmod(directory, 0o700)
            path = directory / runner.EVIDENCE_NAME
            runner.write_atomic_nonoverwrite(path, success_evidence())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(json.loads(path.read_text()), success_evidence())
            with self.assertRaisesRegex(runner.DiagnosticError, "EVIDENCE_ALREADY_EXISTS"):
                runner.write_atomic_nonoverwrite(path, success_evidence())
        with self.assertRaisesRegex(runner.DiagnosticError, "ARTIFACT_SECRET_SCAN_FAILED"):
            runner.scan_content_free(b"-----BEGIN PRIVATE KEY-----")


class MockLauncherIntegrationTests(unittest.TestCase):
    def test_nonzero_canonical_stable_error_extracts_only_allowlisted_code(self) -> None:
        safe = {
            "schema": "nomad.web-companion.error.v1", "state": "BLOCKED",
            "error": "DIAGNOSTIC_BUNDLE_BINDING_MISMATCH",
            "production_ready": False,
        }
        cases = (
            (runner.canonical_json(safe) + b"\n", "DIAGNOSTIC_BUNDLE_BINDING_MISMATCH"),
            (runner.canonical_json({**safe, "error": "SECRET=/tmp/leak"}) + b"\n", "UNKNOWN"),
            (b'{"state":"BLOCKED","schema":"nomad.web-companion.error.v1"}\n', "UNKNOWN"),
            (b"not-json SECRET\n", "UNKNOWN"),
        )
        for stdout, expected in cases:
            result = runner.subprocess.CompletedProcess(["launcher"], 1, stdout, b"sensitive stderr")
            with self.subTest(expected=expected), mock.patch.object(runner.subprocess, "run", return_value=result):
                with self.assertRaises(runner.StableCliError) as raised:
                    runner._run_stable_json(
                        ["/safe/launcher", "--json", "start-loopback-diagnostic"],
                        "LAUNCHER_DIAGNOSTIC_START_BLOCKED", env={},
                    )
                self.assertEqual(raised.exception.safe_code, expected)
                self.assertNotIn("sensitive", str(raised.exception))
                self.assertNotIn("SECRET", str(raised.exception))

    def test_desktop_gateway_not_ready_is_preserved_as_safe_start_code(self) -> None:
        value = {
            "schema": "nomad.web-companion.error.v1", "state": "BLOCKED",
            "error": "DESKTOP_GATEWAY_NOT_READY", "production_ready": False,
        }
        result = runner.subprocess.CompletedProcess(
            ["launcher"], 1, runner.canonical_json(value) + b"\n", b"hidden",
        )
        with mock.patch.object(runner.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(
                runner.StableCliError,
                "LAUNCHER_DIAGNOSTIC_START_BLOCKED_DESKTOP_GATEWAY_NOT_READY",
            ) as raised:
                runner._run_stable_json(
                    ["/safe/launcher", "--json", "start-loopback-diagnostic"],
                    "LAUNCHER_DIAGNOSTIC_START_BLOCKED", env={},
                )
        self.assertEqual(raised.exception.safe_code, "DESKTOP_GATEWAY_NOT_READY")
        self.assertNotIn("hidden", str(raised.exception))

    def test_stable_cli_exact_argv_fds_env_and_post_context_cleanup(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); chrome = root / "chrome"; chrome.write_bytes(b"chrome")
            bundle = root / "bundles" / ("a" * 64); bundle.mkdir(parents=True)
            launcher = root / "bin" / "nomad-web"; launcher.parent.mkdir()
            launcher.write_bytes(b"#!/bin/sh\n"); os.chmod(launcher, 0o755)
            artifacts = root / "artifacts"
            state = launcher_state(root)

            def fake_tls(temp, _openssl):
                cert = temp / "cert"; key = temp / "key"
                cert.write_bytes(b"cert"); key.write_bytes(b"key")
                os.chmod(cert, 0o600); os.chmod(key, 0o600)
                return cert, key, "A" * 44

            def stable(command, code, **kwargs):
                calls.append((command, kwargs))
                if command[-1] == "install-status":
                    return {
                        "schema": runner.INSTALL_STATUS_SCHEMA, "state": "INSTALLED",
                        "current_bundle_digest": "a" * 64,
                    }
                if command[2] == "start-loopback-diagnostic":
                    cert_fd = int(command[-3]); key_fd = int(command[-1])
                    self.assertEqual(kwargs["pass_fds"], (cert_fd, key_fd))
                    self.assertEqual(kwargs["input_bytes"], runner.CANARY)
                    self.assertTrue(stat.S_ISREG(os.fstat(cert_fd).st_mode))
                    self.assertTrue(stat.S_ISREG(os.fstat(key_fd).st_mode))
                    return state
                if command[2] == "status" and not any(
                    prior[0][2] == "stop" for prior in calls[:-1]
                ):
                    return running_status(root)
                return {"state": "STOPPED"}

            def cleanup(home, _state, ports, temporary_root, artifact_dir):
                self.assertEqual(home, root)
                self.assertEqual(len(ports), 9)
                self.assertFalse(os.path.lexists(temporary_root))
                self.assertEqual(list(artifact_dir.iterdir()), [])

            with (
                mock.patch.object(runner, "verify_google_chrome_executable", return_value=chrome),
                mock.patch.object(runner, "verify_installed_bundle", return_value=(bundle, launcher)),
                mock.patch.object(
                    runner, "resolve_allowed_tool",
                    side_effect=lambda name: Path("/usr/bin/openssl") if name == "openssl" else Path("/safe/uv"),
                ),
                mock.patch.object(
                    runner, "snapshot_pinned_uv",
                    side_effect=lambda root, _env: root / "uv-pinned",
                ),
                mock.patch.object(runner, "reserve_loopback_ports", return_value=[19000]),
                mock.patch.object(runner, "snapshot_runtime_entries", return_value={"run": None, "logs": None}),
                mock.patch.object(runner, "generate_loopback_tls", side_effect=fake_tls),
                mock.patch.object(runner, "run_browser", return_value=browser_evidence()) as run_browser,
                mock.patch.object(runner, "_run_stable_json", side_effect=stable),
                mock.patch.object(runner, "assert_command_journal_empty"),
                mock.patch.object(runner, "assert_cleanup_verified", side_effect=cleanup),
            ):
                result = runner.run_diagnostic(argparse.Namespace(
                    mode=runner.MODE, installed_bundle=bundle, chrome=chrome, artifact_dir=artifacts,
                ))
            self.assertEqual([call[0][2] for call in calls], [
                "install-status", "start-loopback-diagnostic", "status", "status", "stop", "status",
            ])
            start, options = calls[1]
            self.assertEqual(start[:13], [
                str(launcher), "--json", "start-loopback-diagnostic",
                "--provider", "OPENAI_API_KEY", "--credential-stdin",
                "--workspace", str(Path.cwd().resolve()),
                "--public-origin", "https://127.0.0.1:19000",
                "--https-listen", "127.0.0.1:19000", "--tls-cert-fd",
            ])
            self.assertEqual(start[-2], "--tls-key-fd")
            self.assertEqual(options["timeout_seconds"], 120)
            self.assertEqual(calls[2][0], [str(launcher), "--json", "status"])
            self.assertEqual(calls[3][0], [str(launcher), "--json", "status"])
            self.assertEqual(calls[4][0], [str(launcher), "--json", "stop"])
            self.assertEqual(calls[4][1]["timeout_seconds"], 30)
            self.assertEqual(calls[5][0], [str(launcher), "--json", "status"])
            self.assertFalse(set(options["env"]) & (runner.PROVIDER_NAMES | {"PYTHONPATH", "NOMAD_WEB_BUNDLE"}))
            uv_snapshot = run_browser.call_args.args[-2]
            self.assertEqual(uv_snapshot.name, "uv-pinned")
            self.assertFalse(os.path.lexists(uv_snapshot.parent))
            self.assertEqual(
                run_browser.call_args.args[-1], runner._file_identity(bundle.lstat()),
            )
            self.assertEqual(result["status"], "DIAGNOSTIC_COMPLETE")
            self.assertTrue((artifacts / runner.EVIDENCE_NAME).is_file())

    def test_start_timeout_always_stops_checks_status_and_residue_then_fails(self) -> None:
        calls: list[tuple[str, int]] = []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); chrome = root / "chrome"; chrome.write_bytes(b"chrome")
            bundle = root / "bundles" / ("a" * 64); bundle.mkdir(parents=True)
            launcher = root / "bin" / "nomad-web"; launcher.parent.mkdir()
            launcher.write_bytes(b"#!/bin/sh\n"); os.chmod(launcher, 0o755)
            artifacts = root / "artifacts"

            def fake_tls(temp, _openssl):
                cert = temp / "cert"; key = temp / "key"
                cert.write_bytes(b"cert"); key.write_bytes(b"key")
                return cert, key, "A" * 44

            def stable(command, code, **kwargs):
                calls.append((command[2], kwargs.get("timeout_seconds", 60)))
                if command[2] == "install-status":
                    return {"schema": runner.INSTALL_STATUS_SCHEMA, "state": "INSTALLED", "current_bundle_digest": "a" * 64}
                if command[2] == "start-loopback-diagnostic":
                    raise runner.subprocess.TimeoutExpired(command, 120)
                return {"state": "STOPPED"}

            def failed_cleanup(_home, _bundle, ports, temporary_root, artifact_dir, before):
                self.assertEqual(len(ports), 9)
                self.assertFalse(os.path.lexists(temporary_root))
                self.assertEqual(list(artifact_dir.iterdir()), [])
                self.assertEqual(before, {"run": None, "logs": None})

            with (
                mock.patch.object(runner, "verify_google_chrome_executable", return_value=chrome),
                mock.patch.object(runner, "verify_installed_bundle", return_value=(bundle, launcher)),
                mock.patch.object(runner, "resolve_allowed_tool", return_value=Path("/safe/tool")),
                mock.patch.object(
                    runner, "snapshot_pinned_uv",
                    side_effect=lambda root, _env: root / "uv-pinned",
                ),
                mock.patch.object(runner, "reserve_loopback_ports", return_value=[19000]),
                mock.patch.object(runner, "snapshot_runtime_entries", return_value={"run": None, "logs": None}),
                mock.patch.object(runner, "generate_loopback_tls", side_effect=fake_tls),
                mock.patch.object(runner, "_run_stable_json", side_effect=stable),
                mock.patch.object(runner, "assert_failed_start_cleanup", side_effect=failed_cleanup) as cleanup,
            ):
                with self.assertRaisesRegex(runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_START_BLOCKED_UNKNOWN"):
                    runner.run_diagnostic(argparse.Namespace(
                        mode=runner.MODE, installed_bundle=bundle, chrome=chrome, artifact_dir=artifacts,
                    ))
            self.assertEqual(calls, [
                ("install-status", 60), ("start-loopback-diagnostic", 120),
                ("stop", 30), ("status", 60),
            ])
            cleanup.assert_called_once()
            self.assertFalse((artifacts / runner.EVIDENCE_NAME).exists())

    def test_failed_start_owned_run_or_log_residue_is_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw); (home / "run").mkdir(); (home / "logs").mkdir()
            before = runner.snapshot_runtime_entries(home)
            for residue in (home / "run" / "agent-runtime-new", home / "logs" / "host-new.log"):
                with self.subTest(residue=residue):
                    if residue.suffix:
                        residue.write_bytes(b"log")
                    else:
                        residue.mkdir()
                    with self.assertRaisesRegex(
                        runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED",
                    ):
                        runner.assert_no_new_owned_runtime_entries(home, before)
                    if residue.is_dir():
                        residue.rmdir()
                    else:
                        residue.unlink()

    def test_runtime_snapshot_accepts_fresh_absent_roots_without_creating(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"; home.mkdir()
            self.assertEqual(
                runner.snapshot_runtime_entries(home),
                {"run": None, "logs": None},
            )
            self.assertFalse((home / "run").exists())
            self.assertFalse((home / "logs").exists())

    def test_runtime_snapshot_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"; home.mkdir()
            target = Path(raw) / "target"; target.mkdir()
            (home / "run").symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(
                runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_RUNTIME_ROOT_UNSAFE",
            ):
                runner.snapshot_runtime_entries(home)

    def test_failed_start_cleanup_accepts_launcher_created_empty_roots(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"; home.mkdir()
            before = runner.snapshot_runtime_entries(home)
            for name in ("run", "logs"):
                path = home / name; path.mkdir(mode=0o700); os.chmod(path, 0o700)
            runner.assert_no_new_owned_runtime_entries(home, before)

    def test_failed_start_cleanup_rejects_bad_created_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"; home.mkdir()
            before = runner.snapshot_runtime_entries(home)
            (home / "run").mkdir(mode=0o755); os.chmod(home / "run", 0o755)
            with self.assertRaisesRegex(
                runner.DiagnosticError, "LAUNCHER_DIAGNOSTIC_START_CLEANUP_FAILED",
            ):
                runner.assert_no_new_owned_runtime_entries(home, before)

    def test_start_safe_cli_error_survives_cleanup_without_raw_output(self) -> None:
        error = runner.StableCliError(
            "LAUNCHER_DIAGNOSTIC_START_BLOCKED",
            "DIAGNOSTIC_BUNDLE_BINDING_MISMATCH",
        )
        self.assertEqual(
            str(error),
            "LAUNCHER_DIAGNOSTIC_START_BLOCKED_DIAGNOSTIC_BUNDLE_BINDING_MISMATCH",
        )

    def test_cleanup_rejects_any_live_process(self) -> None:
        state = launcher_state()
        with mock.patch.object(runner.os, "kill"):
            with self.assertRaisesRegex(runner.DiagnosticError, "PROCESS_LEAK"):
                runner.assert_processes_stopped(state)

    def test_cleanup_rejects_state_runtime_log_tls_artifact_and_port_residue(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "home"; (home / "run").mkdir(parents=True)
            (home / "logs").mkdir(); artifacts = Path(raw) / "artifacts"; artifacts.mkdir()
            temporary = Path(raw) / "gone"
            state = launcher_state(home)
            ports = runner.launcher_ports(state, 19000)
            with mock.patch.object(runner, "assert_processes_stopped"), mock.patch.object(runner, "assert_ports_released"):
                residues = [
                    home / "run" / "status.json",
                    home / "run" / f"agent-runtime-{state['run_id']}",
                    Path(state["processes"][0]["log"]),
                    temporary, artifacts / "unexpected",
                ]
                for residue in residues:
                    with self.subTest(residue=residue):
                        if residue.name.startswith("agent-runtime-") or residue == temporary:
                            residue.mkdir()
                        else:
                            residue.write_bytes(b"x")
                        with self.assertRaises(runner.DiagnosticError):
                            runner.assert_cleanup_verified(home, state, ports, temporary, artifacts)
                        if residue.is_dir():
                            residue.rmdir()
                        else:
                            residue.unlink()
            with mock.patch.object(runner, "assert_processes_stopped"), mock.patch.object(
                runner, "assert_ports_released", side_effect=runner.DiagnosticError("LAUNCHER_DIAGNOSTIC_PORT_LEAK"),
            ):
                with self.assertRaisesRegex(runner.DiagnosticError, "PORT_LEAK"):
                    runner.assert_cleanup_verified(home, state, ports, temporary, artifacts)


def launcher_state(home: Path = Path("/tmp/nomad-home")) -> dict[str, object]:
    run_id = "c" * 64
    return {
        "schema": runner.DIAGNOSTIC_STATE_SCHEMA,
        "mode": runner.LAUNCHER_MODE, "diagnostic_only": True,
        "accepted_eligible": False, "network_scope": "loopback_diagnostic",
        "identity_scope": "diagnostic-ephemeral-local",
        "tls_scope": "self-signed-spki-diagnostic",
        "production_external": False, "bundle_digest": "a" * 64,
        "pairing_ready": True, "remote_mailbox_ready": True,
        "desktop_url": "http://127.0.0.1:14173/",
        "pairing_public_origin": "https://127.0.0.1:19000",
        "agent_origin": "http://127.0.0.1:4096",
        "relay_port": 18089, "gateway_port": 14173, "agent_port": 4096,
        "join_gateway_port": 14174, "relay_host_v2_port": 18090,
        "relay_device_v2_port": 18091, "relay_admin_port": 18092,
        "relay_device_v1_port": 18093, "run_id": run_id,
        "logs_dir": str(home / "logs"),
        "external_gates": [{"gate": name, "status": "NOT_RUN"} for name in ("external_topology", "provider_e3", "physical_phone", "writes")],
        "processes": [
            {
                "name": name, "pid": index + 10, "identity": f"identity-{index}",
                "log": str(home / "logs" / f"{name}-{run_id}.log"),
            }
            for index, name in enumerate(runner.EXPECTED_ROLES)
        ],
    }


def running_status(home: Path = Path("/tmp/nomad-home")) -> dict[str, object]:
    state = launcher_state(home)
    return {
        **state,
        "state": "RUNNING",
        "processes": [
            {"name": item["name"], "pid": item["pid"], "alive": True}
            for item in state["processes"]
        ],
        "lifecycle_coordinator": None,
    }


def browser_evidence() -> dict[str, object]:
    return {
        "write_command_post_count": 0,
        "browser": {"executable_sha256": "b" * 64},
        "journey": {
            "pairing": "VERIFIED", "refresh_recovery": "VERIFIED",
            "revoke": "VERIFIED", "revoked_browser_blocked": "VERIFIED",
            "actions": {"view": "VERIFIED", "reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN"},
        },
    }


def success_evidence() -> dict[str, object]:
    return {
        "schema": runner.SCHEMA, "status": "DIAGNOSTIC_COMPLETE",
        "repo_owned": "mechanical", "tls_verified": False,
        "remote_local_evidence": "NOT_RUN", "external": "NOT_RUN",
        "physical": "NOT_RUN", "provider": "NOT_RUN",
        "writes": {"reply": "NOT_RUN", "deny": "NOT_RUN", "stop": "NOT_RUN"},
        "content_free": True, "cleanup": "VERIFIED",
    }


if __name__ == "__main__":
    unittest.main()
