from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = Path(__file__).with_name("verify_host_artifact.py")
spec = importlib.util.spec_from_file_location("nomad_verify_host_artifact", VERIFIER)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


@unittest.skipUnless(sys.platform == "darwin", "initial host artifact policy is Darwin")
class HostArtifactVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            ["cargo", "build", "--manifest-path", "connector/Cargo.toml",
             "--release", "--bin", "nomad-host"],
            cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.source_binary = ROOT / "connector/target/release/nomad-host"
        cls.head = subprocess.check_output(
            ["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        cls.lock_digest = hashlib.sha256(
            (ROOT / "connector/Cargo.lock").read_bytes()
        ).hexdigest()
        version = subprocess.check_output(["rustc", "-Vv"], text=True)
        cls.rust = dict(line.split(": ", 1) for line in version.splitlines() if ": " in line)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nomad-host-artifact-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "nomad-host"
        shutil.copyfile(self.source_binary, self.binary)
        self.binary.chmod(0o755)
        raw = self.binary.read_bytes()
        container = module._extract_container(raw)
        self.expected = {
            "schema_version": module.EXPECTED_SCHEMA,
            "source_commit_oid": self.head,
            "cargo_lock_raw_sha256": self.lock_digest,
            "build_profile": "release",
            "target_triple": "aarch64-apple-darwin",
            "rustc_release": self.rust["release"],
            "rustc_commit_hash": self.rust["commit-hash"],
            "rustc_host": self.rust["host"],
            "llvm_version": self.rust["LLVM version"],
            "actual_launch_protocol_version": 1,
        }
        core = {
            "schema_version": module.MANIFEST_SCHEMA,
            "artifact_class": "candidate-adhoc",
            "artifact_basename": "nomad-host",
            "artifact_size_bytes": len(raw),
            "artifact_raw_sha256": hashlib.sha256(raw).hexdigest(),
            "platform": "darwin-arm64",
            "target_triple": self.expected["target_triple"],
            "source_commit_oid": self.head,
            "cargo_lock_raw_sha256": self.lock_digest,
            "build_profile": "release",
            "rustc_release": self.expected["rustc_release"],
            "rustc_commit_hash": self.expected["rustc_commit_hash"],
            "rustc_host": self.expected["rustc_host"],
            "llvm_version": self.expected["llvm_version"],
            "actual_launch_protocol_version": 1,
            "embedded_release": {
                "availability": "unavailable",
                "container_raw_sha256": hashlib.sha256(container.raw).hexdigest(),
            },
            "macos_codesign": module._codesign(self.binary),
            "host_artifact_sequence": 1,
            "previous_host_manifest_digest": "0" * 64,
        }
        self.manifest = {
            **core,
            "host_manifest_digest": hashlib.sha256(module._canonical(core)).hexdigest(),
        }
        self.baseline_manifest = copy.deepcopy(self.manifest)
        self.baseline_expected = copy.deepcopy(self.expected)
        self.manifest_path = self.root / "manifest.json"
        self.expected_path = self.root / "expected.json"
        self.write()

    def write(self):
        self.manifest_path.write_bytes(module._canonical(self.manifest))
        self.expected_path.write_bytes(module._canonical(self.expected))

    def reseal(self):
        core = {key: value for key, value in self.manifest.items() if key != "host_manifest_digest"}
        self.manifest["host_manifest_digest"] = hashlib.sha256(
            module._canonical(core)
        ).hexdigest()
        self.write()

    def blocked(self):
        with self.assertRaises(module.VerifyError):
            module.verify_host_artifact(self.binary, self.manifest_path, self.expected_path)

    def test_real_release_nomad_host_candidate_verifies(self):
        module.verify_host_artifact(self.binary, self.manifest_path, self.expected_path)

    def test_manifest_and_expected_mutations_block(self):
        for target, key, value in [
            ("manifest", "artifact_basename", "actual-launch-adopter"),
            ("manifest", "artifact_class", "production-developer-id"),
            ("manifest", "artifact_raw_sha256", "0" * 64),
            ("manifest", "host_artifact_sequence", 2),
            ("expected", "source_commit_oid", "f" * 40),
            ("expected", "build_profile", "debug"),
        ]:
            saved_manifest, saved_expected = copy.deepcopy(self.manifest), copy.deepcopy(self.expected)
            if target == "manifest":
                self.manifest[key] = value; self.reseal()
            else:
                self.expected[key] = value; self.write()
            self.blocked()
            self.manifest, self.expected = saved_manifest, saved_expected; self.write()

    def test_noncanonical_duplicate_extra_and_missing_json_block(self):
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2))
        self.blocked(); self.write()
        raw = self.manifest_path.read_text(); self.manifest_path.write_text(
            raw[:-1] + ',"schema_version":"nomad.nomad-host-artifact.v1"}'
        )
        self.blocked(); self.write()
        self.manifest["extra"] = True; self.reseal(); self.blocked()

    def test_binary_mutation_symlink_hardlink_and_multiple_container_block(self):
        raw = bytearray(self.binary.read_bytes()); raw[64] ^= 1; self.binary.write_bytes(raw)
        self.blocked()
        shutil.copyfile(self.source_binary, self.binary); self.binary.chmod(0o755)
        link = self.root / "linked"; os.link(self.binary, link); self.blocked(); link.unlink()
        target = self.binary; alias = self.root / "alias"; target.rename(alias); target.symlink_to(alias)
        self.blocked(); target.unlink(); alias.rename(target)
        with target.open("ab") as handle:
            handle.write(b"NOMADREL" + (1).to_bytes(2, "big") + b"\0" + (0).to_bytes(4, "big"))
        self.blocked()

    def test_codesign_and_embedded_release_claim_mutation_block(self):
        self.manifest["macos_codesign"]["cdhash"] = "0" * 40
        self.reseal(); self.blocked()
        self.manifest = copy.deepcopy(self.baseline_manifest); self.write()
        self.manifest["embedded_release"]["container_raw_sha256"] = "0" * 64
        self.reseal(); self.blocked()

    def test_cli_tuple_is_exact_and_content_free(self):
        command = [sys.executable, str(VERIFIER), str(self.binary),
                   str(self.manifest_path), str(self.expected_path)]
        ok = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual((ok.returncode, ok.stdout, ok.stderr), (0, module.SUCCESS + "\n", ""))
        self.manifest["artifact_size_bytes"] = 1; self.reseal()
        bad = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual((bad.returncode, bad.stdout, bad.stderr), (1, "", module.BLOCKED + "\n"))

    def test_verifier_has_no_write_sign_git_provider_or_runtime_surface(self):
        source = VERIFIER.read_text(); tree = ast.parse(source)
        forbidden = {"write","write_text","write_bytes","replace","rename",
                     "unlink","mkdir","makedirs","system","getenv"}
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                function = node.func
                calls.add(function.attr if isinstance(function, ast.Attribute) else
                          function.id if isinstance(function, ast.Name) else "")
        self.assertTrue(forbidden.isdisjoint(calls), forbidden & calls)
        self.assertNotIn("--sign", source)
        self.assertNotIn("git", source.lower())
        for name in ("OPENAI_API_KEY","ANTHROPIC_API_KEY","GEMINI_API_KEY",
                     "OPENROUTER_API_KEY","DEEPSEEK_API_KEY"):
            self.assertNotIn(name, source)


if __name__ == "__main__":
    unittest.main()
