from __future__ import annotations

import ast
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


module = load("nomad_b0c4_tests", HERE / "verify_host_post_cas_checkout.py")
publication = module.publication


@unittest.skipUnless(Path("/usr/bin/git").is_file(), "fixed Git unavailable")
class PostCasCheckoutTests(unittest.TestCase):
    object_format = "sha1"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nomad-b0c4-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.snapshots = self.base / "snapshots"
        self.snapshots.mkdir()
        self.git("init", "-q", f"--object-format={self.object_format}")
        self.git("config", "user.name", "Nomad Test")
        self.git("config", "user.email", "nomad@example.invalid")
        (self.repo / "README").write_text("source\n")
        self.git("add", "README")
        self.git("commit", "-q", "-m", "source")
        self.source = self.output("rev-parse", "HEAD")
        self.values, self.paths = self.build_publication()

    def git(self, *args: str) -> None:
        subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), *args], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def output(self, *args: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), *args], check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    @staticmethod
    def seal(value: dict, field: str) -> dict:
        return {**value, field: publication.digest(value)}

    def build_publication(self):
        binary = b"nomad production host\n"
        embedded = {
            "availability": "verified", "container_raw_sha256": "0" * 64,
            "source_commit_oid": self.source, "release_index_digest": "1" * 64,
            "bundle_manifest_digest": "2" * 64, "evidence_manifest_digest": "3" * 64,
            "approval_record_digest": "4" * 64,
            "approval_signature_raw_digest": "5" * 64, "trust_root_id": "test-root",
            "adapter_id": "opencode", "adapter_version": "1.18.16",
            "reviewed_version": "1.18.16",
        }
        host_core = {
            "schema_version": module.HOST_SCHEMA,
            "artifact_class": "production-developer-id", "artifact_basename": "nomad-host",
            "artifact_size_bytes": len(binary),
            "artifact_raw_sha256": hashlib.sha256(binary).hexdigest(),
            "platform": "darwin-arm64", "target_triple": "aarch64-apple-darwin",
            "source_commit_oid": self.source, "cargo_lock_raw_sha256": "6" * 64,
            "build_profile": "release", "rustc_release": "1.90.0",
            "rustc_commit_hash": "7" * 40, "rustc_host": "aarch64-apple-darwin",
            "llvm_version": "20.1", "actual_launch_protocol_version": 1,
            "embedded_release": embedded, "macos_codesign": {"mode": "developer-id"},
            "host_artifact_sequence": 1, "previous_host_manifest_digest": "0" * 64,
        }
        host = self.seal(host_core, "host_manifest_digest")
        candidate_id = "sha256-" + host["host_manifest_digest"]
        candidate_root = f"evidence/host-artifacts/candidates/{candidate_id}"
        active_core = {
            "schema_version": module.lineage_contract.ACTIVE_SCHEMA, "operation": "forward",
            "active_candidate_id": candidate_id,
            "host_manifest_digest": host["host_manifest_digest"],
            "artifact_raw_sha256": host["artifact_raw_sha256"],
            "embedded_release_index_digest": embedded["release_index_digest"],
            "bundle_manifest_digest": embedded["bundle_manifest_digest"],
            "evidence_manifest_digest": embedded["evidence_manifest_digest"],
            "host_approval_digest": "8" * 64, "host_artifact_sequence": 1,
            "previous_host_active_index_digest": "0" * 64,
            "source_commit_oid": self.source, "expected_parent_oid": self.source,
            "rollback_from_active_index_digest": None,
            "rollback_target_candidate_id": None,
        }
        active = self.seal(active_core, "active_index_digest")
        files = {
            "evidence/host-artifacts/current.json": publication.canonical(active),
            f"{candidate_root}/nomad-host": binary,
            f"{candidate_root}/host-manifest.json": publication.canonical(host),
            f"{candidate_root}/expected-build.json": publication.canonical({"fixture": "expected"}),
            f"{candidate_root}/evidence-release-reference.json": publication.canonical({"fixture": "reference"}),
        }
        for relative, raw in files.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            if relative.endswith("/nomad-host"):
                path.chmod(0o755)
        self.git("add", "evidence/host-artifacts")
        self.git("commit", "-q", "-m", "proposed host publication")
        proposed = self.output("rev-parse", "HEAD")
        self.git("update-ref", module.REF, proposed)
        entries = []
        for path, raw in files.items():
            entries.append({
                "path": path, "kind": "regular",
                "mode": "100755" if path.endswith("/nomad-host") else "100644",
                "size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            })
        entries.sort(key=lambda item: item["path"])
        tree_core = [{key: entry[key] for key in sorted(publication.ENTRY_FIELDS)} for entry in entries]
        tree_digest = publication.digest(tree_core)
        path_digest = publication.digest([entry["path"] for entry in entries])
        candidate_tree = publication.digest([
            entry for entry in tree_core if entry["path"].startswith(candidate_root + "/")
        ])
        by_path = {entry["path"]: entry for entry in entries}
        raw_paths = {
            "active_index": "evidence/host-artifacts/current.json",
            "candidate_manifest": f"{candidate_root}/host-manifest.json",
            "expected_build": f"{candidate_root}/expected-build.json",
            "binary": f"{candidate_root}/nomad-host",
            "reference": f"{candidate_root}/evidence-release-reference.json",
        }
        raw_facts = {}
        for prefix, path in raw_paths.items():
            raw_facts[f"{prefix}_raw_sha256"] = by_path[path]["raw_sha256"]
            size_name = "active_index_raw_size_bytes" if prefix == "active_index" else f"{prefix}_size_bytes"
            raw_facts[size_name] = by_path[path]["size_bytes"]
        source_core = {
            "schema_version": publication.SOURCE_SCHEMA,
            "repository_object_format": self.object_format,
            "source_commit_oid": self.source, "head_oid": self.source,
            "index_tree_digest": "9" * 64, "worktree_tree_digest": "a" * 64,
            "untracked_paths_digest": publication.digest([]), "worktree_clean": True,
            "index_clean": True, "untracked_clean": True,
            "cargo_lock_raw_sha256": "b" * 64,
        }
        source_snapshot = self.seal(source_core, "snapshot_digest")
        lineage_core = {
            "schema_version": publication.LINEAGE_SCHEMA, "operation": "forward",
            "parent_snapshot_digest": "c" * 64,
            "active_index_digest": active["active_index_digest"],
            "host_manifest_digest": host["host_manifest_digest"], "candidate_id": candidate_id,
            "candidate_tree_digest": candidate_tree, "b0c2_request_digest": "d" * 64,
            "host_artifact_sequence": 1, **raw_facts,
        }
        lineage = self.seal(lineage_core, "lineage_snapshot_digest")
        tree = self.seal({
            "schema_version": publication.TREE_SCHEMA,
            "repository_object_format": self.object_format,
            "proposed_commit_oid": proposed, "expected_parent_oid": self.source,
            "source_commit_oid": self.source, "unique_first_parent_oid": self.source,
            "proposed_tree_digest": tree_digest, "tree_paths_digest": path_digest,
            "tree_entries": entries,
        }, "snapshot_digest")
        request = self.seal({
            "schema_version": publication.REQUEST_SCHEMA, "operation": "forward",
            "protected_ref": module.REF,
            "repository_object_format": self.object_format,
            "expected_parent_oid": self.source, "proposed_commit_oid": proposed,
            "source_commit_oid": self.source,
            "active_index_digest": active["active_index_digest"],
            "host_manifest_digest": host["host_manifest_digest"], "candidate_id": candidate_id,
            "proposed_tree_digest": tree_digest, "proposed_tree_paths_digest": path_digest,
            "b0c2_request_digest": "d" * 64, "parent_snapshot_digest": "c" * 64,
            "source_snapshot_digest": source_snapshot["snapshot_digest"],
        }, "publication_request_digest")
        values = {"request": request, "tree": tree, "source": source_snapshot, "lineage": lineage}
        paths = []
        for name in ("request", "tree", "source", "lineage"):
            path = self.snapshots / f"{name}.json"
            path.write_bytes(publication.canonical(values[name]))
            paths.append(path)
        return values, paths

    def verify(self, runner=module._bounded):
        module._verify_with_environment(self.paths, self.repo, Path("/usr/bin/git"), runner)

    def rewrite_snapshots(self):
        for name, path in zip(("request", "tree", "source", "lineage"), self.paths):
            path.write_bytes(publication.canonical(self.values[name]))

    def convert_to_rollback(self):
        current_path = self.repo / "evidence/host-artifacts/current.json"
        target_active = publication.json.loads(current_path.read_bytes())
        current_path.write_bytes(publication.canonical({"different_active_candidate": True}))
        self.git("add", "evidence/host-artifacts/current.json")
        self.git("commit", "-q", "-m", "later active candidate")
        parent = self.output("rev-parse", "HEAD")
        previous_active_digest = "e" * 64
        target_active.update({
            "operation": "rollback", "host_artifact_sequence": 3,
            "previous_host_active_index_digest": previous_active_digest,
            "expected_parent_oid": parent,
            "rollback_from_active_index_digest": previous_active_digest,
            "rollback_target_candidate_id": target_active["active_candidate_id"],
        })
        target_active["active_index_digest"] = module.lineage_contract._digest({
            key: value for key, value in target_active.items() if key != "active_index_digest"
        })
        raw = publication.canonical(target_active)
        current_path.write_bytes(raw)
        self.git("add", "evidence/host-artifacts/current.json")
        self.git("commit", "-q", "-m", "rollback host publication")
        proposed = self.output("rev-parse", "HEAD")
        self.git("update-ref", module.REF, proposed)

        entry = next(item for item in self.values["tree"]["tree_entries"]
                     if item["path"] == "evidence/host-artifacts/current.json")
        entry.update(size_bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest())
        tree_core = [{key: item[key] for key in sorted(publication.ENTRY_FIELDS)}
                     for item in self.values["tree"]["tree_entries"]]
        tree_digest = publication.digest(tree_core)
        self.values["tree"].update(
            proposed_commit_oid=proposed, expected_parent_oid=parent,
            unique_first_parent_oid=parent, proposed_tree_digest=tree_digest,
        )
        self.values["lineage"].update(
            operation="rollback", active_index_digest=target_active["active_index_digest"],
            host_artifact_sequence=3,
            active_index_raw_sha256=hashlib.sha256(raw).hexdigest(),
            active_index_raw_size_bytes=len(raw),
        )
        self.values["request"].update(
            operation="rollback", expected_parent_oid=parent,
            proposed_commit_oid=proposed,
            active_index_digest=target_active["active_index_digest"],
            proposed_tree_digest=tree_digest,
        )
        for name, field in (("tree", "snapshot_digest"),
                            ("lineage", "lineage_snapshot_digest"),
                            ("request", "publication_request_digest")):
            self.values[name][field] = publication.digest({
                key: value for key, value in self.values[name].items() if key != field
            })
        self.rewrite_snapshots()

    def test_real_git_positive_reads_immutable_objects(self):
        result = module._verify_with_environment(self.paths, self.repo, Path("/usr/bin/git"))
        self.assertIs(type(result), module._TestPostCasCheckout)
        self.assertTrue(module._is_verified_test(result))
        self.assertEqual(result.candidate_id, self.values["request"]["candidate_id"])
        self.assertEqual(result.operation, "forward")
        self.assertEqual(result.publication_sequence, result.host_artifact_sequence)
        self.assertEqual(result.binary_path.name, "nomad-host")
        with self.assertRaises(TypeError):
            module._TestPostCasCheckout()

    def test_real_git_rollback_changes_only_current_and_reuses_candidate(self):
        self.convert_to_rollback()
        result = module._verify_with_environment(self.paths, self.repo, Path("/usr/bin/git"))
        self.assertEqual(result.operation, "rollback")
        self.assertGreater(result.publication_sequence, result.host_artifact_sequence)

    def test_wrong_ref_and_dirty_checkout_block(self):
        self.git("update-ref", module.REF, self.source)
        with self.assertRaises(module.Error):
            self.verify()
        self.git("update-ref", module.REF, self.values["request"]["proposed_commit_oid"])
        (self.repo / "dirty").write_text("x")
        with self.assertRaises(module.Error):
            self.verify()

    def test_caller_consistent_raw_substitution_cannot_replace_git_blob(self):
        entry = next(item for item in self.values["tree"]["tree_entries"] if item["path"].endswith("/nomad-host"))
        entry["raw_sha256"] = "f" * 64
        self.values["lineage"]["binary_raw_sha256"] = "f" * 64
        tree_core = [{key: item[key] for key in sorted(publication.ENTRY_FIELDS)} for item in self.values["tree"]["tree_entries"]]
        candidate_root = f"evidence/host-artifacts/candidates/{self.values['request']['candidate_id']}/"
        self.values["tree"]["proposed_tree_digest"] = publication.digest(tree_core)
        self.values["request"]["proposed_tree_digest"] = self.values["tree"]["proposed_tree_digest"]
        self.values["lineage"]["candidate_tree_digest"] = publication.digest([
            item for item in tree_core if item["path"].startswith(candidate_root)
        ])
        for name, field in (("tree", "snapshot_digest"), ("lineage", "lineage_snapshot_digest"), ("request", "publication_request_digest")):
            self.values[name][field] = publication.digest({key: value for key, value in self.values[name].items() if key != field})
        self.rewrite_snapshots()
        publication.verify(*self.paths)
        with self.assertRaises(module.Error):
            self.verify()

    def test_after_observation_ref_change_blocks(self):
        calls = 0

        def runner(argv, cwd, limit):
            nonlocal calls
            result = module._bounded(argv, cwd, limit)
            if tuple(argv[3:]) == ("show-ref", "--verify", "--hash", module.REF):
                calls += 1
                if calls == 2:
                    return 0, (self.source + "\n").encode()
            return result

        with self.assertRaises(module.Error):
            self.verify(runner)

    def test_each_immutable_blob_substitution_blocks(self):
        candidate_root = f"evidence/host-artifacts/candidates/{self.values['request']['candidate_id']}"
        paths = (
            "evidence/host-artifacts/current.json",
            f"{candidate_root}/nomad-host",
            f"{candidate_root}/host-manifest.json",
            f"{candidate_root}/expected-build.json",
            f"{candidate_root}/evidence-release-reference.json",
        )
        for target in paths:
            with self.subTest(target=target):
                def runner(argv, cwd, limit, target=target):
                    result = module._bounded(argv, cwd, limit)
                    if tuple(argv[3:]) == (
                        "cat-file", "blob",
                        f"{self.values['request']['proposed_commit_oid']}:{target}",
                    ):
                        return 0, result[1] + b"x"
                    return result
                with self.assertRaises(module.Error):
                    self.verify(runner)

    def test_wrong_parent_and_object_type_block(self):
        proposed = self.values["request"]["proposed_commit_oid"]
        parent = self.values["request"]["expected_parent_oid"]
        for target, replacement in (
            (("rev-list", "--parents", "-n", "1", proposed), f"{proposed}\n".encode()),
            (("cat-file", "-t", parent), b"blob\n"),
        ):
            with self.subTest(target=target):
                def runner(argv, cwd, limit, target=target, replacement=replacement):
                    result = module._bounded(argv, cwd, limit)
                    return (0, replacement) if tuple(argv[3:]) == target else result
                with self.assertRaises(module.Error):
                    self.verify(runner)

    def test_tree_parser_extra_and_malformed_records_block(self):
        path = b"evidence/host-artifacts/current.json"
        oid = b"a" * 40
        expected = {path.decode(): "100644"}
        valid = b"100644 blob " + oid + b"\t" + path + b"\0"
        self.assertEqual(module._tree_records(valid, "sha1", expected), {path.decode(): oid.decode()})
        for raw in (b"100644 blob " + oid + b" " + path + b"\0", b"", b"100644 tree " + oid + b"\t" + path + b"\0"):
            with self.assertRaises(module.Error):
                module._tree_records(raw, "sha1", expected)

    def test_tree_parser_wrong_mode_oid_duplicate_and_extra_block(self):
        path = b"evidence/host-artifacts/current.json"
        oid = b"a" * 40
        expected = {path.decode(): "100644"}
        records = (
            b"100755 blob " + oid + b"\t" + path + b"\0",
            b"100644 blob short\t" + path + b"\0",
            (b"100644 blob " + oid + b"\t" + path + b"\0") * 2,
            b"100644 blob " + oid + b"\textra\0",
        )
        for raw in records:
            with self.subTest(raw=raw):
                with self.assertRaises(module.Error):
                    module._tree_records(raw, "sha1", expected)

    def test_changed_paths_exact_and_unrelated_commit_change_blocks(self):
        expected = {entry["path"] for entry in self.values["tree"]["tree_entries"]}
        module._changed_paths(b"\0".join(path.encode() for path in sorted(expected)) + b"\0", expected)
        for raw in (
            b"",
            b"\0".join(path.encode() for path in sorted(expected | {"README"})) + b"\0",
        ):
            with self.assertRaises(module.Error):
                module._changed_paths(raw, expected)
        module._changed_paths(
            b"\0".join(path.encode() for path in reversed(sorted(expected))) + b"\0",
            expected,
        )

        original = module._bounded
        diff_suffix = (
            "diff-tree", "--no-commit-id", "--name-only", "-r", "-z",
            self.values["request"]["expected_parent_oid"],
            self.values["request"]["proposed_commit_oid"],
        )

        def runner(argv, cwd, limit):
            result = original(argv, cwd, limit)
            if tuple(argv[3:]) == diff_suffix:
                return 0, result[1] + b"README\0"
            return result

        with self.assertRaises(module.Error):
            self.verify(runner)

    def test_snapshot_substitution_after_same_read_does_not_change_frozen_values(self):
        original = publication._read_and_verify

        def swap_after_read(*paths):
            result = original(*paths)
            self.values["request"]["protected_ref"] = "refs/heads/other"
            self.values["request"]["publication_request_digest"] = publication.digest({
                key: value for key, value in self.values["request"].items()
                if key != "publication_request_digest"
            })
            self.rewrite_snapshots()
            return result

        with mock.patch.object(publication, "_read_and_verify", side_effect=swap_after_read):
            self.verify()

    def test_bounded_overflow_and_cleanup_uncertain_block(self):
        command = ("/usr/bin/git", "-C", str(self.repo), "rev-parse", "HEAD")
        code, output = module._bounded(command, self.repo, 0)
        self.assertEqual(code, 125)
        self.assertEqual(len(output), 1)

        class Stdout:
            def fileno(self):
                return 9

            def close(self):
                return None

        class Process:
            pid = 123
            stdout = Stdout()

            def poll(self):
                return None

            def kill(self):
                raise OSError

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("git", timeout)

        class Selector:
            def register(self, *_):
                return None

            def select(self, *_):
                raise OSError

            def close(self):
                return None

        with mock.patch.object(module.subprocess, "Popen", return_value=Process()), \
                mock.patch.object(module.selectors, "DefaultSelector", return_value=Selector()), \
                mock.patch.object(module.os, "kill", side_effect=OSError):
            with self.assertRaises(module.CleanupUnconfirmed):
                module._bounded(command, self.repo, 1)

    def test_exact_command_allowlist_and_cli_surface(self):
        request = self.values["request"]
        self.assertFalse(module._allowed(("update-ref", module.REF, request["proposed_commit_oid"]), request))
        self.assertFalse(module._allowed(("cat-file", "blob", request["proposed_commit_oid"] + ":other"), request))
        source = (HERE / "verify_host_post_cas_checkout.py").read_text()
        tree = ast.parse(source)
        arguments = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"]
        self.assertEqual(len(arguments), 1)
        cli_loop = next(node for node in ast.walk(tree) if isinstance(node, ast.For)
                        and isinstance(node.target, ast.Name) and node.target.id == "name")
        self.assertEqual(tuple(item.value for item in cli_loop.iter.elts),
                         ("request", "tree", "source", "lineage"))
        self.assertNotIn("getenv", source)

@unittest.skipUnless(Path("/usr/bin/git").is_file(), "fixed Git unavailable")
class PostCasCheckoutSha256Tests(PostCasCheckoutTests):
    object_format = "sha256"


if __name__ == "__main__":
    unittest.main()
