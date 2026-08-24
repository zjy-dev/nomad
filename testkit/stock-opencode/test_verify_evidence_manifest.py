import ast
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "verify_evidence_manifest.py"
spec = importlib.util.spec_from_file_location("evidence_manifest_verifier", VERIFIER)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def certificate():
    core = {
        "schema_version": "nomad.stock-opencode.lifecycle-certificate.v1",
        "expected_event_sequence": ["session.created", "question.asked", "session.diff", "permission.asked"],
        "diff_file_count": 1, "v1_routes_verified": module.CERTIFICATE_V1_ROUTES, "v2_routes_verified": module.CERTIFICATE_V2_ROUTES,
    }
    return {**core, "structural_digest": module.canonical_digest(core)}


class EvidenceManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "real-task").mkdir(); (self.root / "locked-runtime").mkdir()
        for relative in ("official-stock-contract.json", "capture-manifest.json", "capture_contract.py", "real-task/task-spec.json", "real-task/fixture-manifest.json", "real-task/command-shapes.json", "locked-runtime/package.json", "locked-runtime/package-lock.json"):
            source, target = HERE / relative, self.root / relative
            shutil.copyfile(source, target)
        self.old_root = module.ROOT; module.ROOT = self.root
        self.addCleanup(setattr, module, "ROOT", self.old_root)

    def pair(self):
        cert = certificate(); task, fixture, shapes, rules = module._current_sources()
        source = {
            "certificate_structural_digest": cert["structural_digest"], "launch_provenance_digest": "a" * 64,
            "task_spec_digest": task, "fixture_manifest_digest": fixture,
            "command_shapes_canonical_digest": shapes, "rule_config_digest": rules,
        }
        spec = importlib.util.spec_from_file_location("b01_test_discovery", HERE / "discover_lifecycle.py"); generator = importlib.util.module_from_spec(spec); sys.modules[spec.name] = generator; spec.loader.exec_module(generator)
        try:
            session, question, permission = "s1", "q1", "p1"
            events = [
                generator._event_shape("created", "session.created", {"sessionID": session, "info": {}}),
                generator._event_shape("question", "question.asked", {"id": question, "sessionID": session, "questions": [], "tool": {}}),
                generator._event_shape("diff", "session.diff", {"sessionID": session, "diff": []}),
                generator._event_shape("permission", "permission.asked", {"id": permission, "sessionID": session, "permission": "bash", "patterns": [generator.TEST_COMMAND], "metadata": {}, "always": False, "tool": {}}),
            ]
            completed = generator.CompletedRealDiscovery(cert, generator._COMPLETION_TOKEN)
            candidate = generator.StructuralCandidate(cert)
            routes = generator.verified_routes()
            shape = generator._build_shape_manifest(candidate, completed, launch_provenance_digest="a" * 64, task_spec_digest=task, fixture_manifest_digest=fixture, command_shapes_canonical_digest=shapes, event_shapes=events, snapshot_cardinalities=module.CARDINALITIES, session_id=session, session_snapshot={"id": session}, question_id=question, permission_id=permission, question_reply_route=routes["question_reply"]["route"].replace("{sessionID}", session).replace("{requestID}", question), permission_reply_route=routes["permission_reply"]["route"].replace("{sessionID}", session).replace("{requestID}", permission), routes=routes, permission_snapshot={"permission": "bash", "patterns": [generator.TEST_COMMAND]})
        finally:
            sys.modules.pop("b01_test_discovery", None)
        core = {
            "schema_version": "nomad.stock-opencode.evidence-manifest.v1",
            "certificate_digest": module.canonical_digest(cert), "shape_manifest_digest": module.canonical_digest(shape),
            "certificate_structural_digest": cert["structural_digest"],
            "source_binding_digest": shape["source_binding_digest"],
            "historical_certified_launch_provenance_digest": shape["launch_provenance_digest"],
            "task_spec_digest": task, "fixture_manifest_digest": fixture,
            "command_shapes_canonical_digest": shapes, "rule_config_digest": rules,
            "current_committed_evidence_provenance_digest": module._committed_provenance(),
            "reviewed_version": "v0.1.0",
        }
        return cert, shape, {**core, "evidence_manifest_digest": module.canonical_digest(core)}

    def paths(self, evidence=None, cert=None, shape=None, evidence_bytes=None):
        default_cert, default_shape, default_evidence = self.pair()
        cert, shape, evidence = cert or default_cert, shape or default_shape, evidence or default_evidence
        paths = self.root / "evidence.json", self.root / "certificate.json", self.root / "shape.json"
        paths[1].write_text(json.dumps(cert), encoding="utf-8"); paths[2].write_text(json.dumps(shape), encoding="utf-8")
        paths[0].write_bytes(json.dumps(evidence).encode() if evidence_bytes is None else evidence_bytes)
        return paths

    def verify(self, *paths):
        return module.verify_evidence_manifest(*paths)

    def reseal(self, evidence):
        evidence["evidence_manifest_digest"] = module.canonical_digest({key: value for key, value in evidence.items() if key != "evidence_manifest_digest"})

    def test_valid_pair(self):
        self.assertEqual(self.verify(*self.paths()), module.Verdict("VERIFIED", "VERIFIED"))

    def test_public_derivation_is_fresh_pure_and_verifier_equivalent(self):
        cert, shape, expected = self.pair(); before = {path: path.stat().st_mtime_ns for path in self.root.rglob("*") if path.is_file()}
        cert_before, shape_before = copy.deepcopy(cert), copy.deepcopy(shape)
        first = module.derive_evidence_manifest(cert, shape, "v0.1.0")
        second = module.derive_evidence_manifest(cert, shape, "v0.1.0")
        self.assertEqual(first, expected); self.assertEqual(second, expected); self.assertIsNot(first, second)
        self.assertEqual(before, {path: path.stat().st_mtime_ns for path in self.root.rglob("*") if path.is_file()})
        self.assertEqual(cert, cert_before); self.assertEqual(shape, shape_before)
        for field in first:
            with self.subTest(field=field):
                tampered = dict(first); tampered[field] = "x" if field == "reviewed_version" else "0" * 64
                self.assertNotEqual(self.verify(*self.paths(tampered, cert, shape)).status, "VERIFIED")

    def test_public_derivation_controlled_errors_are_content_free(self):
        cert, shape, _ = self.pair()
        for mutate, code in ((lambda c, s: c.update(v1_routes_verified=[]), "FAIL_EVIDENCE_MANIFEST_PAIR_INTEGRITY"), (lambda c, s: s.update(events=[]), "FAIL_EVIDENCE_MANIFEST_PAIR_INTEGRITY"), (lambda c, s: None, "FAIL_EVIDENCE_MANIFEST_REVIEWED_VERSION")):
            with self.subTest(code=code):
                changed_cert, changed_shape = dict(cert), dict(shape); mutate(changed_cert, changed_shape)
                with self.assertRaises(module.EvidenceDerivationError) as error:
                    module.derive_evidence_manifest(changed_cert, changed_shape, "" if code.endswith("REVIEWED_VERSION") else "v0.1.0")
                self.assertEqual((error.exception.code, str(error.exception)), (code, code))
        old = module.ROOT; module.ROOT = self.root / "absent"
        try:
            with self.assertRaises(module.EvidenceDerivationError) as error:
                module.derive_evidence_manifest(cert, shape, "v0.1.0")
            self.assertEqual((error.exception.code, str(error.exception)), ("FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT", "FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT"))
        finally:
            module.ROOT = old

    def test_real_source_and_provenance_failures_have_helper_verifier_cli_parity(self):
        cert, shape, evidence = self.pair()
        cases = (("real-task/task-spec.json", b"{}", "FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT"), ("real-task/fixture-manifest.json", b"{}", "FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT"), ("real-task/command-shapes.json", b"{}", "FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT"), ("locked-runtime/package-lock.json", b"{", "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE"), ("capture-manifest.json", b"{}", "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE"))
        for relative, malformed, code in cases:
            with self.subTest(relative=relative):
                target = self.root / relative; original = target.read_bytes(); target.write_bytes(malformed)
                try:
                    with self.assertRaises(module.EvidenceDerivationError) as error:
                        module.derive_evidence_manifest(cert, shape, "v0.1.0")
                    self.assertEqual(error.exception.code, code)
                    paths = self.root / "evidence.json", self.root / "certificate.json", self.root / "shape.json"
                    paths[0].write_text(json.dumps(evidence)); paths[1].write_text(json.dumps(cert)); paths[2].write_text(json.dumps(shape))
                    self.assertEqual(self.verify(*paths).code, code)
                    harness = ("import importlib.util,sys; s=importlib.util.spec_from_file_location('b01c_cli',sys.argv[1]); "
                               "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);m.ROOT=m.Path(sys.argv[2]); "
                               "sys.argv=[sys.argv[1],*sys.argv[3:]];raise SystemExit(m.main())")
                    result = subprocess.run([sys.executable, "-c", harness, str(VERIFIER), str(self.root), *(str(path) for path in paths)], capture_output=True, text=True, check=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", code + "\n"))
                finally:
                    target.write_bytes(original)

    def test_missing_pair_components(self):
        paths = self.paths()
        for index, code in ((0, "MANIFEST"), (1, "CERTIFICATE"), (2, "SHAPE")):
            with self.subTest(code=code):
                paths[index].unlink()
                self.assertEqual(self.verify(*paths).code, f"BLOCKED_EVIDENCE_MANIFEST_{code}_MISSING")
                if index == 0: paths = self.paths()
                else: paths[index].write_text("{}")

    def test_evidence_file_safety_classes(self):
        paths = self.paths()
        paths[0].unlink(); paths[0].mkdir()
        self.assertEqual(self.verify(*paths).code, "BLOCKED_EVIDENCE_MANIFEST_MANIFEST_MISSING")
        paths[0].rmdir(); target = self.root / "target"; target.write_text("{}"); paths[0].symlink_to(target)
        self.assertEqual(self.verify(*paths).code, "BLOCKED_EVIDENCE_MANIFEST_MANIFEST_MISSING")
        paths[0].unlink(); paths[0].write_bytes(b"x" * (module.MAX_BYTES + 1))
        self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_MANIFEST_SIZE")
        paths[0].write_bytes(b"\xff"); self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_MANIFEST_UTF8")
        paths[0].write_bytes(b"{"); self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_MANIFEST_JSON")
        paths[0].write_bytes(b'{"x":1,"x":2}'); self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_MANIFEST_DUPLICATE")

    def test_pair_file_safety_classes(self):
        paths = self.paths()
        paths[1].write_bytes(b"\xff"); self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_CERTIFICATE_UTF8")
        paths = self.paths(); paths[2].write_bytes(b'{"x":1,"x":2}')
        self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_SHAPE_DUPLICATE")

    def test_fields_schema_digest_and_version(self):
        for mutate, code in (
            (lambda e: e.update(extra=True), "FIELDS"),
            (lambda e: e.update(schema_version="bad"), "SCHEMA"),
            (lambda e: e.update(evidence_manifest_digest="0" * 64), "DIGEST"),
            (lambda e: e.update(reviewed_version=""), "REVIEWED_VERSION"),
            (lambda e: e.update(reviewed_version="x key"), "REVIEWED_VERSION"),
            (lambda e: e.update(prompt="no"), "FIELDS"),
        ):
            with self.subTest(code=code):
                _, _, evidence = self.pair(); mutate(evidence); self.assertIn(code, self.verify(*self.paths(evidence)).code)

    def test_pair_and_binding_mismatches(self):
        for field, code in (("certificate_digest", "PAIR_BINDING"), ("shape_manifest_digest", "PAIR_BINDING"), ("certificate_structural_digest", "STRUCTURAL_BINDING"), ("source_binding_digest", "HISTORICAL_BINDING"), ("historical_certified_launch_provenance_digest", "HISTORICAL_BINDING")):
            with self.subTest(field=field):
                _, _, evidence = self.pair(); evidence[field] = "0" * 64; self.reseal(evidence)
                self.assertEqual(self.verify(*self.paths(evidence)).code, f"FAIL_EVIDENCE_MANIFEST_{code}")

    def test_self_consistent_certificate_contract_failures(self):
        for field, value in (("v1_routes_verified", []), ("expected_event_sequence", ["session.created"] * 4), ("diff_file_count", 0)):
            with self.subTest(field=field):
                cert, shape, evidence = self.pair(); cert[field] = value; cert["structural_digest"] = module.canonical_digest({k: v for k, v in cert.items() if k != "structural_digest"})
                shape["certificate_structural_digest"] = cert["structural_digest"]; source = {k: shape[k] for k in module.SOURCE_BINDING_FIELDS}; shape["source_binding_digest"] = module.canonical_digest(source); shape["manifest_digest"] = module.canonical_digest({k:v for k,v in shape.items() if k != "manifest_digest"})
                evidence["certificate_digest"] = module.canonical_digest(cert); evidence["shape_manifest_digest"] = module.canonical_digest(shape); evidence["certificate_structural_digest"] = cert["structural_digest"]; evidence["source_binding_digest"] = shape["source_binding_digest"]; self.reseal(evidence)
                self.assertEqual(self.verify(*self.paths(evidence, cert, shape)).code, "FAIL_EVIDENCE_MANIFEST_PAIR_INTEGRITY")

    def test_self_consistent_shape_contract_failures(self):
        mutations = {
            "missing_event": lambda s: s["events"].pop(), "extra_event": lambda s: s["events"].append(s["events"][-1]),
            "policy": lambda s: s["events"][0]["property_field_types"].update(secret={"type": "str"}),
            "depth": lambda s: s["events"][0]["property_field_types"].update(info={"type": "dict", "properties": {"time": {"type": "dict", "properties": {"created": {"type": "dict", "properties": {"x": {"type": "str"}}}}}}}),
            "count": lambda s: s["events"][1].update(property_field_count=99),
            "cardinality": lambda s: s.update(snapshot_cardinalities={}),
            "diff_relation": lambda s: s.update(diff_count_relation="bad"),
        }
        mutations.update({field: (lambda s, field=field: s.update({field: False})) for field in module.RELATION_FIELDS})
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                cert, shape, evidence = self.pair(); mutate(shape); shape["manifest_digest"] = module.canonical_digest({k:v for k,v in shape.items() if k != "manifest_digest"}); evidence["shape_manifest_digest"] = module.canonical_digest(shape); self.reseal(evidence)
                self.assertEqual(self.verify(*self.paths(evidence, cert, shape)).code, "FAIL_EVIDENCE_MANIFEST_PAIR_INTEGRITY")

    def test_source_digest_and_source_bytes_tamper(self):
        _, _, evidence = self.pair(); evidence["task_spec_digest"] = "0" * 64; self.reseal(evidence)
        self.assertEqual(self.verify(*self.paths(evidence)).code, "FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT")
        for relative in ("official-stock-contract.json", "capture_contract.py", "locked-runtime/package.json", "locked-runtime/package-lock.json"):
            with self.subTest(relative=relative):
                paths=self.paths()
                target=self.root/relative; original=target.read_bytes(); target.write_bytes(original+b" ")
                if relative == "official-stock-contract.json":
                    payload=json.loads(original); payload["schema"]="tampered"; target.write_text(json.dumps(payload))
                self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE")
                target.write_bytes(original)

    def test_stale_and_cross_file_claims_fail_closed(self):
        paths=self.paths()
        capture=self.root/"capture-manifest.json"; data=json.loads(capture.read_text()); old=data["full_locked_dependency_count"]; data["full_locked_dependency_count"]=old+1; capture.write_text(json.dumps(data))
        self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE")

    def test_entrypoint_provenance_is_committed_and_cross_checked(self):
        paths = self.paths()  # Freeze valid evidence before changing both source files.
        capture_path, official_path = self.root / "capture-manifest.json", self.root / "official-stock-contract.json"
        capture, official = json.loads(capture_path.read_text()), json.loads(official_path.read_text())
        for field in ("observed_installed_entrypoint_wrapper_sha256", "observed_installed_entrypoint_target_sha256"):
            with self.subTest(field=field, mode="both"):
                changed_capture, changed_official = json.loads(json.dumps(capture)), json.loads(json.dumps(official))
                changed_capture[field] = "f" * 64; changed_official["provenance"][field] = "f" * 64
                capture_path.write_text(json.dumps(changed_capture)); official_path.write_text(json.dumps(changed_official))
                self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE")
            with self.subTest(field=field, mode="single"):
                capture_path.write_text(json.dumps(capture)); official_path.write_text(json.dumps(official))
                changed_capture = json.loads(json.dumps(capture)); changed_capture[field] = "e" * 64
                capture_path.write_text(json.dumps(changed_capture))
                self.assertEqual(self.verify(*paths).code, "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE")
        capture_path.write_text(json.dumps(capture)); official_path.write_text(json.dumps(official))

    def test_locked_location_contract(self):
        self.assertEqual(module._package_name_from_location("node_modules/pkg"), "pkg")
        self.assertEqual(module._package_name_from_location("node_modules/a/node_modules/@scope/pkg"), "@scope/pkg")
        for location in ("evil/node_modules/pkg", "pkg", "node_modules/@scope", "node_modules/@/pkg", "node_modules/a/extra"):
            with self.subTest(location=location):
                with self.assertRaises(ValueError): module._package_name_from_location(location)
        for entry in ({"version": "1", "integrity": "x", "resolved": "file:x"}, {"version": "1", "integrity": "x", "resolved": "https://registry.npmjs.org/x", "link": True}):
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError): module._locked_closure({"lockfileVersion": 3, "packages": {"": {}, "node_modules/pkg": entry}})

    def test_source_files_are_regular_bounded_and_json_safe(self):
        paths = self.paths()
        json_sources = ("real-task/task-spec.json", "real-task/fixture-manifest.json", "real-task/command-shapes.json", "official-stock-contract.json", "capture-manifest.json", "locked-runtime/package.json", "locked-runtime/package-lock.json")
        for relative in json_sources + ("capture_contract.py",):
            target = self.root / relative; original = target.read_bytes()
            for mode in ("symlink", "dir", "oversize"):
                with self.subTest(relative=relative, mode=mode):
                    target.unlink();
                    if mode == "symlink": target.symlink_to(self.root / "evidence.json")
                    elif mode == "dir": target.mkdir()
                    else: target.write_bytes(b"x" * (module.SOURCE_MAX_BYTES + 1))
                    self.assertIn(self.verify(*paths).code, {"FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT", "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE"})
                    if target.is_dir(): target.rmdir()
                    else: target.unlink()
                    target.write_bytes(original)
            if relative in json_sources:
                with self.subTest(relative=relative, mode="duplicate"):
                    target.write_bytes(b'{"x":1,"x":2}')
                    self.assertIn(self.verify(*paths).code, {"FAIL_EVIDENCE_MANIFEST_SOURCE_ARTIFACT", "FAIL_EVIDENCE_MANIFEST_COMMITTED_PROVENANCE"})
                    target.write_bytes(original)

    def test_cli_and_isolated_import(self):
        paths = self.paths(); result=subprocess.run([sys.executable,str(VERIFIER),*(str(path) for path in paths)],capture_output=True,text=True,check=False)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,"VERIFIED\n",""))
        paths[0].unlink(); result=subprocess.run([sys.executable,str(VERIFIER),*(str(path) for path in paths)],capture_output=True,text=True,check=False)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(1,"","BLOCKED_EVIDENCE_MANIFEST_MANIFEST_MISSING\n"))
        paths = self.paths(); evidence = json.loads(paths[0].read_text()); evidence["evidence_manifest_digest"] = "0" * 64; paths[0].write_text(json.dumps(evidence)); result = subprocess.run([sys.executable, str(VERIFIER), *(str(path) for path in paths)], capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", "FAIL_EVIDENCE_MANIFEST_DIGEST\n"))
        paths = self.paths(); cert = json.loads(paths[1].read_text()); cert["v1_routes_verified"] = []; cert["structural_digest"] = module.canonical_digest({k:v for k,v in cert.items() if k != "structural_digest"}); paths[1].write_text(json.dumps(cert)); result = subprocess.run([sys.executable, str(VERIFIER), *(str(path) for path in paths)], capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", "FAIL_EVIDENCE_MANIFEST_PAIR_BINDING\n"))
        paths = self.paths(); shape = json.loads(paths[2].read_text()); shape["events"].pop(); shape["manifest_digest"] = module.canonical_digest({k:v for k,v in shape.items() if k != "manifest_digest"}); paths[2].write_text(json.dumps(shape)); result = subprocess.run([sys.executable, str(VERIFIER), *(str(path) for path in paths)], capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, "", "FAIL_EVIDENCE_MANIFEST_PAIR_BINDING\n"))
        code=("import importlib.util,json,sys;before=list(sys.path);s=importlib.util.spec_from_file_location('isolated_b01',sys.argv[1]);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);blocked={'discover_lifecycle','real_task_capture','capture_contract'};print(json.dumps([before==sys.path,sorted(n for n in sys.modules if n.split('.')[-1] in blocked)]))")
        result=subprocess.run([sys.executable,"-c",code,str(VERIFIER)],capture_output=True,text=True,check=False)
        self.assertEqual((result.returncode,result.stderr,json.loads(result.stdout)),(0,"",[True,[]]))
        before = {path.relative_to(self.root): path.stat().st_mtime_ns for path in self.root.rglob("*") if path.is_file()}
        isolated = ("import importlib.util,sys; s=importlib.util.spec_from_file_location('b01c',sys.argv[1]); "
                    "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)")
        result = subprocess.run([sys.executable, "-c", isolated, str(VERIFIER)], cwd=self.root, env={"PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True, check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        self.assertEqual(before, {path.relative_to(self.root): path.stat().st_mtime_ns for path in self.root.rglob("*") if path.is_file()})

    def test_static_parity_with_a4_rules_and_capture_closure(self):
        a4=ast.parse((HERE/"verify_shape_manifest.py").read_text()); assignments={node.targets[0].id:node.value for node in a4.body if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
        self.assertEqual(module.RULES, ast.literal_eval(assignments["RULES"]))
        self.assertEqual(module.SOURCE_BINDING_FIELDS, ast.literal_eval(assignments["SOURCE_BINDING_FIELDS"]))
        for name in ("FIELDS", "CERTIFICATE_FIELDS", "CERTIFICATE_V1_ROUTES", "CERTIFICATE_V2_ROUTES", "MARKER_ORDER", "MARKER_CANDIDATES", "RELATION_FIELDS", "CARDINALITIES", "POLICY"):
            node = assignments[name]
            expected = eval(compile(ast.Expression(node), "<a4-constants>", "eval"), {"__builtins__": {}, "frozenset": frozenset})
            self.assertEqual(getattr(module, "SHAPE_FIELDS" if name == "FIELDS" else name), expected)
        contract=(HERE/"capture_contract.py").read_text(encoding="utf-8")
        self.assertIn('sorted((entry.name, entry.version, entry.integrity)', contract)
        self.assertIn('lockfileVersion', contract)
        a3 = ast.parse((HERE / "verify_certificate.py").read_text(encoding="utf-8"))
        a3_assignments = {node.targets[0].id: node.value for node in a3.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
        for name, local_name in (("FIELDS", "CERTIFICATE_FIELDS"), ("V1", "CERTIFICATE_V1_ROUTES"), ("V2", "CERTIFICATE_V2_ROUTES"), ("MARKER_ORDER", "MARKER_ORDER"), ("MARKER_CANDIDATES", "MARKER_CANDIDATES")):
            node = a3_assignments[name]
            expected = eval(compile(ast.Expression(node), "<a3-constants>", "eval"), {"__builtins__": {}, "frozenset": frozenset})
            self.assertEqual(getattr(module, local_name), expected)
        ascii_assignment = a3_assignments["ASCII_EVENT"]
        self.assertIsInstance(ascii_assignment, ast.Call)
        self.assertEqual(ast.literal_eval(ascii_assignment.args[0]), module.ASCII_EVENT.pattern)

    def test_derivation_api_has_no_authority_or_side_effect_surfaces(self):
        tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        derive = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "derive_evidence_manifest")
        self.assertEqual([argument.arg for argument in derive.args.args], ["certificate", "shape_manifest", "reviewed_version"])
        def callable_name(node):
            if isinstance(node, ast.Name): return node.id
            if isinstance(node, ast.Attribute):
                parent = callable_name(node.value)
                return (parent + "." if parent else "") + node.attr
            return ""
        reachable, pending = set(), {"derive_evidence_manifest"}
        while pending:
            name = pending.pop()
            if name in reachable: continue
            reachable.add(name)
            for call in ast.walk(functions[name]):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in functions:
                    pending.add(call.func.id)
        calls = {callable_name(call.func) for name in reachable for call in ast.walk(functions[name]) if isinstance(call, ast.Call)}
        forbidden = {"open", "os.write", "os.mkdir", "os.rename", "os.unlink", "subprocess.Popen", "subprocess.run", "os.system", "socket.socket"}
        self.assertFalse(calls & forbidden)
        self.assertFalse(any(any(word in call.lower() for word in ("approval", "authority", "credential", "sign", "network")) for call in calls))
        self.assertNotIn("discover_lifecycle", VERIFIER.read_text(encoding="utf-8"))

    def test_derivation_does_not_call_unrelated_authority_surface(self):
        cert, shape, expected = self.pair(); original = module._content_free
        def sentinel(*_args): raise AssertionError("unrelated authority surface")
        module._content_free = sentinel
        try:
            self.assertEqual(module.derive_evidence_manifest(cert, shape, "v0.1.0"), expected)
        finally:
            module._content_free = original


if __name__ == "__main__":
    unittest.main()
