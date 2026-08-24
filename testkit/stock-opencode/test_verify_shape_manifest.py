import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "verify_shape_manifest.py"
spec = importlib.util.spec_from_file_location("shape_manifest_verifier", VERIFIER)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def certificate():
    core = {
        "schema_version": "nomad.stock-opencode.lifecycle-certificate.v1",
        "expected_event_sequence": ["session.created", "question.asked", "session.diff", "permission.asked"],
        "diff_file_count": 1,
        "v1_routes_verified": ["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"],
        "v2_routes_verified": ["/api/session/{sessionID}/prompt", "/api/session/{sessionID}/question/{requestID}/reply", "/api/session/{sessionID}/permission/{requestID}/reply", "/api/session/{sessionID}/interrupt"],
    }
    return {**core, "structural_digest": module.digest(core)}


def event(marker, event_type, properties):
    return {
        "marker": marker,
        "observed_event_type": event_type,
        "property_field_count": len(properties),
        "property_field_names": sorted(properties),
        "property_field_types": properties,
    }


def shape_manifest(cert):
    task, fixture, shapes, rules = module.current_sources()
    source = {
        "certificate_structural_digest": cert["structural_digest"],
        "launch_provenance_digest": "a" * 64,
        "task_spec_digest": task,
        "fixture_manifest_digest": fixture,
        "command_shapes_canonical_digest": shapes,
        "rule_config_digest": rules,
    }
    events = [
        event("created", "session.created", {"info": {"type": "dict", "properties": {}}, "sessionID": {"type": "str"}}),
        event("question", "question.asked", {"id": {"type": "str"}, "questions": {"type": "list", "items": {"type": "null"}, "count": 0}, "sessionID": {"type": "str"}, "tool": {"type": "dict", "properties": {}}}),
        event("diff", "session.diff", {"diff": {"type": "list", "items": {"type": "null"}, "count": 0}, "sessionID": {"type": "str"}}),
        event("permission", "permission.asked", {"always": {"type": "bool"}, "id": {"type": "str"}, "metadata": {"type": "dict", "dynamic_keys": True, "field_count": 0}, "patterns": {"type": "list", "items": {"type": "null"}, "count": 0}, "permission": {"type": "str"}, "sessionID": {"type": "str"}, "tool": {"type": "dict", "properties": {}}}),
    ]
    core = {
        "schema_version": "nomad.stock-opencode.lifecycle-shape-manifest.v1",
        **source,
        "source_binding_digest": module.digest(source),
        "events": events,
        "snapshot_cardinalities": dict(module.CARDINALITIES),
        "session_id_equality": True,
        "question_snapshot_id_used_in_reply_route": True,
        "permission_snapshot_id_used_in_reply_route": True,
        "question_permission_ids_distinct": True,
        "diff_count_relation": "files_ge_1",
        "permission_name_is_bash": True,
        "patterns_is_single_string_list": True,
        "pattern_matches_fixed_test_command": True,
    }
    return {**core, "manifest_digest": module.digest(core)}


def reseal(value):
    source = {name: value[name] for name in module.SOURCE_BINDING_FIELDS}
    value["source_binding_digest"] = module.digest(source)
    value["manifest_digest"] = module.digest({name: item for name, item in value.items() if name != "manifest_digest"})


class VerifyShapeManifestTest(unittest.TestCase):
    def files(self, manifest=None, cert=None, manifest_bytes=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        manifest_path, certificate_path = Path(directory.name) / "manifest.json", Path(directory.name) / "certificate.json"
        cert = certificate() if cert is None else cert
        if manifest_bytes is None:
            manifest = shape_manifest(cert) if manifest is None else manifest
            manifest_bytes = json.dumps(manifest).encode("utf-8")
        manifest_path.write_bytes(manifest_bytes)
        certificate_path.write_text(json.dumps(cert), encoding="utf-8")
        return manifest_path, certificate_path

    def assert_code(self, mutate, expected):
        value = shape_manifest(certificate())
        mutate(value)
        manifest_path, certificate_path = self.files(value)
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, expected)

    def run_cli(self, manifest_path, certificate_path):
        return subprocess.run(
            [sys.executable, str(VERIFIER), str(manifest_path), str(certificate_path)],
            capture_output=True, text=True, check=False,
        )

    def test_valid_manifest(self):
        manifest_path, certificate_path = self.files()
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path), module.Verdict("VERIFIED", "VERIFIED"))

    def test_certificate_missing_is_forwarded_before_manifest(self):
        self.assertEqual(module.verify_shape_manifest(Path("/missing-manifest"), Path("/missing-certificate")).code, "BLOCKED_CERTIFICATE_MISSING")

    def test_manifest_missing_after_valid_certificate(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        certificate_path = Path(directory.name) / "certificate.json"
        certificate_path.write_text(json.dumps(certificate()), encoding="utf-8")
        self.assertEqual(module.verify_shape_manifest(Path(directory.name) / "none.json", certificate_path).code, "BLOCKED_MANIFEST_MISSING")

    def test_certificate_invalid_json_is_not_a_manifest_error(self):
        manifest_path, certificate_path = self.files()
        certificate_path.write_text("{", encoding="utf-8")
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_CERTIFICATE_JSON")

    def test_certificate_duplicate_key_is_not_a_manifest_error(self):
        manifest_path, certificate_path = self.files()
        certificate_path.write_text('{"x": 1, "x": 2}', encoding="utf-8")
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_CERTIFICATE_DUPLICATE")

    def test_certificate_schema_is_forwarded_before_manifest(self):
        cert = certificate()
        cert["schema_version"] = "wrong"
        manifest_path, certificate_path = self.files(cert=cert)
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_CERTIFICATE_SCHEMA")

    def test_manifest_symlink_is_blocked(self):
        manifest_path, certificate_path = self.files()
        target = manifest_path.with_name("target.json")
        os.replace(manifest_path, target)
        manifest_path.symlink_to(target)
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "BLOCKED_MANIFEST_MISSING")

    def test_manifest_directory_is_blocked(self):
        manifest_path, certificate_path = self.files()
        manifest_path.unlink()
        manifest_path.mkdir()
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "BLOCKED_MANIFEST_MISSING")

    def test_manifest_too_large(self):
        manifest_path, certificate_path = self.files(manifest_bytes=b" " * (module.MAX_MANIFEST_BYTES + 1))
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_MANIFEST_SIZE")

    def test_manifest_invalid_utf8(self):
        manifest_path, certificate_path = self.files(manifest_bytes=b"\xff")
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_MANIFEST_UTF8")

    def test_manifest_duplicate_json_key(self):
        manifest_path, certificate_path = self.files(manifest_bytes=b'{"x":1,"x":2}')
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_MANIFEST_DUPLICATE")

    def test_manifest_invalid_json(self):
        manifest_path, certificate_path = self.files(manifest_bytes=b"{")
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_MANIFEST_JSON")

    def test_exact_field_set_required(self):
        self.assert_code(lambda value: value.update({"extra": True}), "FAIL_MANIFEST_FIELDS")

    def test_schema_required(self):
        self.assert_code(lambda value: value.update({"schema_version": "wrong"}), "FAIL_MANIFEST_SCHEMA")

    def test_digest_format_required(self):
        self.assert_code(lambda value: value.update({"launch_provenance_digest": "ABC"}), "FAIL_MANIFEST_DIGEST_FORMAT")

    def test_certificate_binding_required(self):
        def mutate(value):
            value["certificate_structural_digest"] = "0" * 64
            reseal(value)
        self.assert_code(mutate, "FAIL_MANIFEST_CERT_BINDING")

    def test_source_binding_required(self):
        self.assert_code(lambda value: value.update({"source_binding_digest": "0" * 64}), "FAIL_MANIFEST_SOURCE_BINDING")

    def test_current_source_digest_required(self):
        def mutate(value):
            value["task_spec_digest"] = "0" * 64
            reseal(value)
        self.assert_code(mutate, "FAIL_MANIFEST_SOURCE_ARTIFACT")

    def test_malformed_current_source_is_rejected(self):
        manifest_path, certificate_path = self.files()
        with mock.patch.object(module, "current_sources", side_effect=module.DuplicateKey("x")):
            self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path).code, "FAIL_MANIFEST_SOURCE_ARTIFACT")

    def test_event_order_required(self):
        def mutate(value):
            value["events"][0]["marker"] = "diff"
            reseal(value)
        self.assert_code(mutate, "FAIL_MANIFEST_EVENTS")

    def test_event_field_names_must_be_sorted_and_unique(self):
        def mutate(value):
            value["events"][0]["property_field_names"] = ["sessionID", "info"]
            reseal(value)
        self.assert_code(mutate, "FAIL_MANIFEST_EVENTS")

    def test_event_type_policy_required(self):
        def mutate(value):
            value["events"][0]["property_field_types"]["secret"] = {"type": "str"}
            value["events"][0]["property_field_names"].append("secret")
            value["events"][0]["property_field_names"].sort()
            value["events"][0]["property_field_count"] += 1
            reseal(value)
        self.assert_code(mutate, "FAIL_MANIFEST_EVENTS")

    def test_dynamic_metadata_only_allowed_at_metadata(self):
        def mutate(value):
            value["events"][0]["property_field_types"]["info"] = {"type": "dict", "dynamic_keys": True, "field_count": 0}
            reseal(value)
        self.assert_code(mutate, "FAIL_MANIFEST_EVENTS")

    def test_cardinality_required(self):
        self.assert_code(lambda value: value.update({"snapshot_cardinalities": {}}), "FAIL_MANIFEST_CARDINALITY")

    def test_each_relation_boolean_is_required(self):
        for field in module.RELATION_FIELDS:
            with self.subTest(field=field):
                def mutate(value, field=field):
                    value[field] = False
                    reseal(value)
                self.assert_code(mutate, "FAIL_MANIFEST_RELATIONS")

    def test_diff_relation_required(self):
        self.assert_code(lambda value: value.update({"diff_count_relation": "none"}), "FAIL_MANIFEST_RELATIONS")

    def test_manifest_digest_required(self):
        self.assert_code(lambda value: value.update({"manifest_digest": "0" * 64}), "FAIL_MANIFEST_DIGEST")

    def test_cli_valid_output_is_exact(self):
        manifest_path, certificate_path = self.files()
        result = self.run_cli(manifest_path, certificate_path)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "VERIFIED\n", ""))

    def test_cli_missing_manifest_output_is_exact(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        certificate_path = Path(directory.name) / "certificate.json"
        certificate_path.write_text(json.dumps(certificate()), encoding="utf-8")
        result = self.run_cli(Path(directory.name) / "missing.json", certificate_path)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", "BLOCKED_MANIFEST_MISSING\n"))

    def test_cli_tampered_manifest_output_is_exact(self):
        value = shape_manifest(certificate())
        value["manifest_digest"] = "0" * 64
        manifest_path, certificate_path = self.files(value)
        result = self.run_cli(manifest_path, certificate_path)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", "FAIL_MANIFEST_DIGEST\n"))

    def test_cli_tampered_certificate_output_is_exact(self):
        cert = certificate()
        cert["structural_digest"] = "0" * 64
        manifest_path, certificate_path = self.files(cert=cert)
        result = self.run_cli(manifest_path, certificate_path)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", "FAIL_CERTIFICATE_DIGEST\n"))

    def test_verifier_isolated_import_has_no_side_effects(self):
        production = [
            HERE / "real-task/lifecycle-certificate.json",
            HERE / "real-task/lifecycle-shape-manifest.json",
        ]
        self.assertTrue(all(not path.exists() for path in production))
        code = (
            "import importlib.util,json,sys;before=list(sys.path);before_modules=set(sys.modules);"
            "s=importlib.util.spec_from_file_location('isolated_shape_verifier',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);"
            "blocked={'discover_lifecycle','verify_certificate','real_task_capture'};"
            "print(json.dumps({'path_unchanged':before==sys.path,"
            "'forbidden_modules':sorted(name for name in sys.modules if name.split('.')[-1] in blocked),"
            "'verifier_loaded':'isolated_shape_verifier' in sys.modules}))"
        )
        result = subprocess.run([sys.executable, "-c", code, str(VERIFIER)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertTrue(report["path_unchanged"])
        self.assertEqual(report["forbidden_modules"], [])
        self.assertTrue(report["verifier_loaded"])
        self.assertTrue(all(not path.exists() for path in production))

    def test_a41_builder_manifest_verifies(self):
        generator_path = HERE / "discover_lifecycle.py"
        generator_spec = importlib.util.spec_from_file_location("test_only_discover_lifecycle", generator_path)
        self.assertIsNotNone(generator_spec)
        self.assertIsNotNone(generator_spec.loader)
        generator = importlib.util.module_from_spec(generator_spec)
        old_module = sys.modules.get(generator_spec.name)
        sys.modules[generator_spec.name] = generator
        try:
            generator_spec.loader.exec_module(generator)
            cert = certificate()
            completed = generator.CompletedRealDiscovery(cert, generator._COMPLETION_TOKEN)
            candidate = generator.StructuralCandidate(cert)
            task_digest, fixture_digest, shape_digest, _ = module.current_sources()
            session_id, question_id, permission_id = "session-a4", "question-a4", "permission-a4"
            routes = {
                "question_reply": {"route": "/api/session/{sessionID}/question/{requestID}/reply"},
                "permission_reply": {"route": "/api/session/{sessionID}/permission/{requestID}/reply"},
            }
            event_shapes = [
                generator._event_shape("created", "session.created", {"sessionID": session_id, "info": {}}),
                generator._event_shape("question", "question.asked", {"id": question_id, "sessionID": session_id, "questions": [], "tool": {}}),
                generator._event_shape("diff", "session.diff", {"sessionID": session_id, "diff": []}),
                generator._event_shape("permission", "permission.asked", {"id": permission_id, "sessionID": session_id, "permission": "bash", "patterns": ["node test/arithmetic.test.js"], "metadata": {}, "always": False, "tool": {}}),
            ]
            value = generator._build_shape_manifest(
                candidate, completed, launch_provenance_digest="a" * 64,
                task_spec_digest=task_digest, fixture_manifest_digest=fixture_digest,
                command_shapes_canonical_digest=shape_digest, event_shapes=event_shapes,
                snapshot_cardinalities=dict(module.CARDINALITIES), session_id=session_id,
                session_snapshot={"id": session_id}, question_id=question_id, permission_id=permission_id,
                question_reply_route=f"/api/session/{session_id}/question/{question_id}/reply",
                permission_reply_route=f"/api/session/{session_id}/permission/{permission_id}/reply",
                routes=routes, permission_snapshot={"permission": "bash", "patterns": ["node test/arithmetic.test.js"]},
            )
        finally:
            if old_module is None:
                sys.modules.pop(generator_spec.name, None)
            else:
                sys.modules[generator_spec.name] = old_module
        manifest_path, certificate_path = self.files(value, cert)
        self.assertEqual(module.verify_shape_manifest(manifest_path, certificate_path), module.Verdict("VERIFIED", "VERIFIED"))

    def test_frozen_policy_and_rules_match_generator_ast(self):
        tree = ast.parse((HERE / "discover_lifecycle.py").read_text(encoding="utf-8"))
        assignments = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
        generator_policy = ast.literal_eval(assignments["_POLICY"])
        test_command = ast.literal_eval(assignments["TEST_COMMAND"])

        class ReplaceCommand(ast.NodeTransformer):
            def visit_Name(self, node):
                if node.id == "TEST_COMMAND":
                    return ast.copy_location(ast.Constant(test_command), node)
                return node

        generator_rules = ast.literal_eval(ast.fix_missing_locations(ReplaceCommand().visit(assignments["SESSION_PERMISSION_RULES"])))
        self.assertEqual(module.POLICY, generator_policy)
        self.assertEqual(module.RULES, generator_rules)

    def test_frozen_certificate_contract_matches_a3_ast(self):
        tree = ast.parse((HERE / "verify_certificate.py").read_text(encoding="utf-8"))
        assignments = {node.targets[0].id: node.value for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
        fields_node = assignments["FIELDS"]
        self.assertIsInstance(fields_node, ast.Call)
        self.assertEqual(module.CERTIFICATE_FIELDS, frozenset(ast.literal_eval(fields_node.args[0])))
        self.assertEqual(module.CERTIFICATE_V1_ROUTES, ast.literal_eval(assignments["V1"]))
        self.assertEqual(module.CERTIFICATE_V2_ROUTES, ast.literal_eval(assignments["V2"]))
        self.assertEqual(module.ASCII_EVENT.pattern, ast.literal_eval(assignments["ASCII_EVENT"].args[0]))


if __name__ == "__main__":
    unittest.main()
