#!/usr/bin/env python3
"""Offline tests for registry-bound stock capture."""
from __future__ import annotations
import contextlib, importlib.util, io, json, subprocess, sys, unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("capture_contract", Path(__file__).with_name("capture_contract.py")); capture = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader; sys.modules[SPEC.name] = capture; SPEC.loader.exec_module(capture)

class Tests(unittest.TestCase):
    def test_sse_unknown_names_and_values_never_persist(self):
        old = capture.urllib.request.urlopen
        class R:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def __iter__(self): return iter([b'data: {"id":"SECRET","type":"safe","properties":{"prompt":"SECRET"},"privateField":"SECRET"}\n'])
        try: capture.urllib.request.urlopen = lambda *_a, **_k: R(); shape = capture.event_shape("http://fake")
        finally: capture.urllib.request.urlopen = old
        text = json.dumps(shape); self.assertEqual(shape["unexpected_field_count"], 1); self.assertNotIn("SECRET", text); self.assertNotIn("privateField", text)

    def test_schema_names_not_values_and_sensitive_names_redacted(self):
        shape = capture.schema_shape({"type":"object", "properties":{"id":{}, "metadata":{}, "title":{}, "path":{}}}, {})
        self.assertEqual(shape["safe_property_names"], ["id"]); self.assertEqual(shape["redacted_property_count"], 3)

    def test_pack_rejects_integrity_mismatch(self):
        old = capture.run
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); (root / "opencode-ai-1.18.16.tgz").write_bytes(b"bad")
            try:
                capture.run = lambda *_a, **_k: subprocess.CompletedProcess([], 0, '[{"filename":"opencode-ai-1.18.16.tgz"}]')
                with self.assertRaisesRegex(capture.CaptureError, "PACK_INTEGRITY_MISMATCH"): capture.pack_exact(root, capture.RegistryArtifact("sha512-bad", "bad", "https://x"), {})
            finally: capture.run = old

    def test_pack_rejects_name_version_and_filename_mismatch(self):
        old = capture.run
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp)
            try:
                capture.run = lambda *_a, **_k: subprocess.CompletedProcess([], 0, '[{"name":"other","version":"9","filename":"other.tgz"}]')
                with self.assertRaisesRegex(capture.CaptureError, "PACK_INTEGRITY_MISMATCH"):
                    capture.pack_exact(root, capture.RegistryArtifact("sha512-x", "x", "https://x"), {})
            finally: capture.run = old

    def test_lockfile_rejects_missing_integrity_and_non_registry(self):
        with __import__("tempfile").TemporaryDirectory() as temp:
            path = Path(temp) / "package-lock.json"
            path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1", "resolved": "https://registry.npmjs.org/a/-/a.tgz"}}}))
            with self.assertRaisesRegex(capture.CaptureError, "LOCKFILE_INTEGRITY_INVALID"):
                capture.locked_dependencies(path)
            path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1", "integrity": "sha512-x", "resolved": "git+https://x"}}}))
            with self.assertRaisesRegex(capture.CaptureError, "NON_REGISTRY_DEPENDENCY"):
                capture.locked_dependencies(path)

    def test_locked_root_and_exact_package_are_required(self):
        old_package, old_lock = capture.LOCKED_PACKAGE, capture.LOCKED_LOCK
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); capture.LOCKED_PACKAGE, capture.LOCKED_LOCK = root / "package.json", root / "package-lock.json"
            capture.LOCKED_PACKAGE.write_text('{"name":"nomad-stock-opencode-locked-runtime","version":"1.0.0","private":true,"dependencies":{"opencode-ai":"1.18.15"}}')
            capture.LOCKED_LOCK.write_text(json.dumps({"lockfileVersion":3,"packages":{"":{"dependencies":{"opencode-ai":"1.18.16"}},"node_modules/opencode-ai":{"version":"1.18.16","integrity":"good","resolved":"https://registry.npmjs.org/opencode-ai/-/opencode-ai-1.18.16.tgz"}}}))
            try:
                with self.assertRaisesRegex(capture.CaptureError, "LOCKED_PACKAGE_INVALID"):
                    capture.validate_locked_runtime(capture.RegistryArtifact("good", "x", "https://registry.npmjs.org/opencode-ai/-/opencode-ai-1.18.16.tgz"))
            finally: capture.LOCKED_PACKAGE, capture.LOCKED_LOCK = old_package, old_lock

    def test_locked_root_registry_mismatch_is_rejected(self):
        old_package, old_lock = capture.LOCKED_PACKAGE, capture.LOCKED_LOCK
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); capture.LOCKED_PACKAGE, capture.LOCKED_LOCK = root / "package.json", root / "package-lock.json"
            capture.LOCKED_PACKAGE.write_text('{"name":"nomad-stock-opencode-locked-runtime","version":"1.0.0","private":true,"packageManager":"npm@11.12.1","dependencies":{"opencode-ai":"1.18.16"}}')
            capture.LOCKED_LOCK.write_text(json.dumps({"lockfileVersion":3,"packages":{"":{"name":"nomad-stock-opencode-locked-runtime","version":"1.0.0","dependencies":{"opencode-ai":"1.18.16"}},"node_modules/opencode-ai":{"version":"1.18.16","integrity":"wrong","resolved":"https://registry.npmjs.org/opencode-ai/-/opencode-ai-1.18.16.tgz"}}}))
            try:
                with self.assertRaisesRegex(capture.CaptureError, "LOCK_ROOT_REGISTRY_MISMATCH"):
                    capture.validate_locked_runtime(capture.RegistryArtifact("good", "x", "https://registry.npmjs.org/opencode-ai/-/opencode-ai-1.18.16.tgz"))
            finally: capture.LOCKED_PACKAGE, capture.LOCKED_LOCK = old_package, old_lock

    def test_required_route_missing_rejected(self):
        old_json = capture.get_json
        try:
            capture.wait_health = lambda _b: {"healthy":True, "version":"1.18.16"}
            capture.get_json = lambda _b, _r: {"paths": {"/event": {}}, "components": {"schemas": {}}}
            with self.assertRaisesRegex(capture.CaptureError, "REQUIRED_ROUTE_MISSING"): capture.capture_from_server("http://fake", {})
        finally: capture.get_json = old_json

    def test_official_path_spawns_and_cleans_same_binary(self):
        old = {name:getattr(capture,name) for name in ("registry_artifact","pack_exact","run","free_port","capture_from_server","full_locked_closure", "installed_platform_closure", "validate_locked_runtime", "validate_registry_closure")}
        calls = []; spawned = []
        class P:
            def terminate(self): calls.append("terminate")
            def wait(self, timeout): calls.append("wait")
        try:
            capture.registry_artifact = lambda: capture.RegistryArtifact("sha512-x", "x", "https://x")
            def fake_pack(root, _a, _e):
                tarball = root / "pkg.tgz"; tarball.write_bytes(b"package"); return tarball
            capture.pack_exact = fake_pack
            def fake_run(args, **kw):
                if args[:2] == ["npm", "ci"]:
                    binary = kw["cwd"] / "node_modules/.bin/opencode"
                    binary.parent.mkdir(parents=True); binary.write_bytes(b"binary")
                return subprocess.CompletedProcess(args, 0, "1.18.16\n")
            capture.run = fake_run
            package_hash = capture.sha256(capture.LOCKED_PACKAGE.read_bytes()); lock_hash = capture.sha256(capture.LOCKED_LOCK.read_bytes())
            full = {"full_locked_dependency_count": 13, "full_locked_dependency_digest": "b", "all_locked_dependencies_registry_integrity_bound": True}
            capture.full_locked_closure = lambda _path: full
            capture.installed_platform_closure = lambda *_a: {"installed_platform_dependency_count": 2, "installed_platform_dependency_digest": "i"}
            capture.validate_locked_runtime = lambda _artifact: {**full, "package_json_sha256": package_hash, "package_lock_sha256": lock_hash, "lock_artifact": "locked-runtime/package-lock.json"}
            capture.validate_registry_closure = lambda _path: None
            capture.free_port = lambda: 45678
            capture.capture_from_server = lambda base, prov: {"base":base, "provenance":prov}
            old_popen = capture.subprocess.Popen
            capture.subprocess.Popen = lambda args, **_kw: (spawned.append(args) or P())
            result = capture.official_capture()
        finally:
            capture.subprocess.Popen = old_popen
            for name, value in old.items(): setattr(capture, name, value)
        self.assertEqual(result["base"], "http://127.0.0.1:45678"); self.assertIn("terminate", calls); self.assertIn("wait", calls); self.assertIn("serve", spawned[0]); self.assertEqual(result["provenance"]["server_binding_method"], "same_observed_validated_npm_ci_entrypoint_spawned_loopback")

    def test_cli_error_does_not_leak_command_output_or_credentials(self):
        old = capture.official_capture
        old_argv = sys.argv
        try:
            capture.official_capture = lambda: (_ for _ in ()).throw(capture.CaptureError("BLOCKED_NPM_REGISTRY"))
            sys.argv = ["capture_contract.py"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output): status = capture.main()
        finally:
            capture.official_capture = old; sys.argv = old_argv
        self.assertEqual(status, 2); self.assertIn("BLOCKED_NPM_REGISTRY", output.getvalue()); self.assertNotIn("credential", output.getvalue())

    def test_manifest_tamper_is_rejected_before_live_capture(self):
        old = capture.official_capture
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); fixture = {"provenance": {"registry_integrity": "x", "tarball_sha256": "y", "lockfile_sha256": "z", "dependency_integrity_digest": "d", "classification": "c"}}
            fixture_path, manifest_path = root / "f.json", root / "m.json"
            fixture_path.write_text(json.dumps(fixture)); manifest_path.write_text(json.dumps({"tampered": True}))
            try:
                capture.official_capture = lambda: self.fail("must not recapture after manifest mismatch")
                self.assertEqual(capture.verify_fixture(fixture_path, manifest_path), 2)
            finally: capture.official_capture = old

    def test_official_runtime_uses_npm_ci_not_dynamic_install(self):
        source = Path(__file__).with_name("capture_contract.py").read_text()
        self.assertIn('["npm", "ci"', source)
        self.assertNotIn('npm", "install", "--prefix"', source)

    def test_npm_ci_has_exact_required_invocation(self):
        source = Path(__file__).with_name("capture_contract.py").read_text()
        self.assertIn('["npm", "ci", f"--registry={REGISTRY_ORIGIN}", "--ignore-scripts=false", "--no-audit", "--no-fund"]', source)

    def test_manifest_recalculates_committed_asset_hashes(self):
        old_package, old_lock = capture.LOCKED_PACKAGE, capture.LOCKED_LOCK
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); capture.LOCKED_PACKAGE, capture.LOCKED_LOCK = root / "package.json", root / "package-lock.json"
            capture.LOCKED_PACKAGE.write_bytes(b"package"); capture.LOCKED_LOCK.write_bytes(b"lock")
            fixture = {"schema":"fixture", "provenance": {"package_json_sha256":capture.sha256(b"package"), "package_lock_sha256":capture.sha256(b"lock"), "registry_integrity":"sri", "registry_shasum":"sha1", "tarball_sha256":"tar", "full_locked_dependency_count":1, "full_locked_dependency_digest":"full", "installed_platform_dependency_count":1, "installed_platform_dependency_digest":"installed", "classification":"class", "execution_provenance_scope":capture.EXECUTION_PROVENANCE_SCOPE, "postinstall_final_code_attested":False, "observed_installed_entrypoint_wrapper_sha256":"wrapper", "observed_installed_entrypoint_target_sha256":"target", "os":"os", "arch":"arch", "npm_version":"1.2.3", "npm_compatibility_rule":"exact"}}
            try:
                old_full = capture.full_locked_closure; capture.full_locked_closure = lambda _p: {"full_locked_dependency_count":1, "full_locked_dependency_digest":"full"}
                manifest = capture.manifest_for(fixture, Path(__file__).with_name("capture_contract.py"))
                self.assertEqual(manifest["package_json_sha256"], capture.sha256(b"package"))
                self.assertEqual(manifest["package_lock_sha256"], capture.sha256(b"lock"))
                fixture["provenance"]["package_json_sha256"] = "tampered"
                with self.assertRaisesRegex(capture.CaptureError, "FIXTURE_LOCAL_ASSET_MISMATCH"):
                    capture.manifest_for(fixture, Path(__file__).with_name("capture_contract.py"))
            finally: capture.full_locked_closure = old_full; capture.LOCKED_PACKAGE, capture.LOCKED_LOCK = old_package, old_lock

    def test_any_closure_field_mismatch_is_detected(self):
        base = {"full_locked_dependency_count":13, "full_locked_dependency_digest":"f", "installed_platform_dependency_count":2, "installed_platform_dependency_digest":"i"}
        for key in tuple(base):
            changed = dict(base); changed[key] = "different"
            self.assertIn(key, capture.closure_diagnostic(base, changed)["different_fields"])

    def test_full_capture_compare_does_not_exclude_provenance_fields(self):
        source = Path(__file__).with_name("capture_contract.py").read_text()
        self.assertIn("canonical_bytes(live) != canonical_bytes(fixture)", source)
        self.assertNotIn(".pop(", source)

    def test_wrong_platform_or_npm_blocks_before_live_capture(self):
        old_capture, old_manifest = capture.official_capture, capture.manifest_for
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); fixture_path, manifest_path = root / "fixture.json", root / "manifest.json"
            fixture = {"provenance": {"os": "wrong-os", "arch": "wrong-arch", "npm_version": "0.0.0"}}
            fixture_path.write_text(json.dumps(fixture)); manifest_path.write_text("{}")
            try:
                capture.manifest_for = lambda *_a: {}
                capture.official_capture = lambda: self.fail("environment gate must run before live capture")
                output = io.StringIO()
                with contextlib.redirect_stdout(output): status = capture.verify_fixture(fixture_path, manifest_path)
                self.assertEqual(status, 2)
                self.assertEqual(json.loads(output.getvalue())["error_code"], "BLOCKED_ENVIRONMENT_COMPATIBILITY_MISMATCH")
            finally: capture.official_capture, capture.manifest_for = old_capture, old_manifest

    def test_entrypoint_realpath_escape_is_rejected(self):
        with __import__("tempfile").TemporaryDirectory() as temp:
            root = Path(temp); install = root / "runtime"; bindir = install / "node_modules/.bin"
            bindir.mkdir(parents=True); outside = root / "outside"; outside.write_bytes(b"code")
            (bindir / "opencode").symlink_to(outside)
            with self.assertRaisesRegex(capture.CaptureError, "BLOCKED_ENTRYPOINT_OUTSIDE_LOCKED_RUNTIME"):
                capture.observed_installed_entrypoint(bindir / "opencode", install)

    def test_execution_claim_is_fixed_and_postinstall_is_not_attested(self):
        self.assertEqual(capture.EXECUTION_PROVENANCE_SCOPE, "registry_archives_exact_lock_fresh_npm_ci_selected_packages_and_spawned_entrypoint")
        source = Path(__file__).with_name("capture_contract.py").read_text()
        self.assertIn('"postinstall_final_code_attested": False', source)

    def test_readme_does_not_overclaim_postinstall_execution_closure(self):
        readme = Path(__file__).with_name("README.md").read_text().lower()
        self.assertIn("does not attest", readme)
        self.assertIn("postinstall", readme)
        self.assertNotIn("executed dependency closure", readme)
        self.assertNotIn("complete execution closure", readme)

if __name__ == "__main__": unittest.main()
