from __future__ import annotations

import ast
import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import types
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
TARGET = HERE / "verify_release_bundle.py"
SPEC = importlib.util.spec_from_file_location("release_bundle_verifier", TARGET)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def write_json(path: Path, value: object) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    path.write_bytes(raw)
    return raw


class BundleFixture:
    def __init__(self, root: Path, parent: dict | None = None, reviewed: str = "v0.1.0", evidence_digest: str = "a" * 64):
        self.root = root
        (root / module.BUNDLES_NAME).mkdir(parents=True)
        evidence = {
            "schema_version": module.OPENCODE_POLICY["evidence_schema"],
            "reviewed_version": reviewed,
            "evidence_manifest_digest": evidence_digest,
        }
        certificate = {"schema_version": "test-certificate"}
        shape = {"schema_version": "test-shape"}
        approval = {
            "schema_version": module.OPENCODE_POLICY["approval_schema"],
            "evidence_manifest_digest": evidence["evidence_manifest_digest"],
            "reviewed_version": reviewed,
            "scope": module.OPENCODE_POLICY["approval_scope"],
            "principal": "security@example",
            "issued_at": "2026-08-20T00:00:00Z",
            "expires_at": "2026-08-21T00:00:00Z",
            "trust_root_id": "ssh-ed25519:TEST",
            "signing_namespace": "nomad-m2-release-authorization-v1",
            "signature_file": module.SIGNATURE_NAME,
        }
        signature = b"SSHSIG-TEST"
        raws = {
            "lifecycle-certificate.json": module._canonical(certificate),
            "lifecycle-shape-manifest.json": module._canonical(shape),
            "lifecycle-evidence-manifest.json": module._canonical(evidence),
        }
        descriptors = {name: {"raw_sha256": module._raw_digest(raw), "size_bytes": len(raw)} for name, raw in raws.items()}
        manifest_core = {
            "schema_version": "nomad.agent-evidence.bundle-manifest.v1",
            "adapter_id": "opencode",
            "adapter_version": "1.18.16",
            "adapter_contract_digest": module.OPENCODE_CONTRACT_DIGEST,
            "approval_scope": module.OPENCODE_POLICY["approval_scope"],
            "reviewed_version": reviewed,
            "evidence_manifest_digest": evidence["evidence_manifest_digest"],
            "approval_record_digest": module._digest(approval),
            "approval_signature_raw_digest": module._raw_digest(signature),
            "trust_root_id": approval["trust_root_id"],
            "adapter_artifacts": descriptors,
        }
        self.manifest = {**manifest_core, "bundle_manifest_digest": module._digest(manifest_core)}
        self.bundle_id = "sha256-" + self.manifest["bundle_manifest_digest"]
        self.bundle = root / module.BUNDLES_NAME / self.bundle_id
        self.adapter = self.bundle / "adapter"
        self.adapter.mkdir(parents=True)
        write_json(self.bundle / module.MANIFEST_NAME, self.manifest)
        for name, raw in raws.items():
            (self.adapter / name).write_bytes(raw)
        write_json(self.bundle / module.APPROVAL_NAME, approval)
        (self.bundle / module.SIGNATURE_NAME).write_bytes(signature)
        previous = "0" * 64 if parent is None else parent["release_index_digest"]
        sequence = 1 if parent is None else parent["release_sequence"] + 1
        index_core = {
            "schema_version": "nomad.agent-evidence.release-index.v1",
            "active_bundle_id": self.bundle_id,
            "bundle_manifest_digest": self.manifest["bundle_manifest_digest"],
            "adapter_id": self.manifest["adapter_id"],
            "adapter_version": self.manifest["adapter_version"],
            "reviewed_version": reviewed,
            "evidence_manifest_digest": self.manifest["evidence_manifest_digest"],
            "approval_record_digest": self.manifest["approval_record_digest"],
            "previous_release_index_digest": previous,
            "release_sequence": sequence,
        }
        self.index = {**index_core, "release_index_digest": module._digest(index_core)}
        write_json(root / module.INDEX_NAME, self.index)

    def reseal_manifest(self):
        core = {key: value for key, value in self.manifest.items() if key != "bundle_manifest_digest"}
        self.manifest["bundle_manifest_digest"] = module._digest(core)

    def relocate_resealed_bundle(self):
        old = self.bundle
        new_id = "sha256-" + self.manifest["bundle_manifest_digest"]
        new = self.root / module.BUNDLES_NAME / new_id
        old.rename(new); self.bundle = new; self.adapter = new / "adapter"; self.bundle_id = new_id
        write_json(new / module.MANIFEST_NAME, self.manifest)
        self.index.update(active_bundle_id=new_id, bundle_manifest_digest=self.manifest["bundle_manifest_digest"], adapter_id=self.manifest["adapter_id"], adapter_version=self.manifest["adapter_version"], reviewed_version=self.manifest["reviewed_version"], evidence_manifest_digest=self.manifest["evidence_manifest_digest"], approval_record_digest=self.manifest["approval_record_digest"])
        self.reseal_index()

    def reseal_index(self):
        core = {key: value for key, value in self.index.items() if key != "release_index_digest"}
        self.index["release_index_digest"] = module._digest(core)
        write_json(self.root / module.INDEX_NAME, self.index)


class ReleaseBundleVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "releases"
        self.fixture = BundleFixture(self.root)
        self.adapter_calls = []
        self.approval_calls = []

    def adapter_ok(self, path, manifest):
        self.adapter_calls.append((path, manifest)); return True

    def approval_ok(self, path, manifest):
        self.approval_calls.append((path, manifest)); return True

    def verify(self, parent=None, adapter=None, approval=None):
        return module._verify_release_tree(self.root, parent, adapter or self.adapter_ok, approval or self.approval_ok)

    def test_valid_first_release_mechanics_only(self):
        self.assertEqual(self.verify(), module.Verdict("VERIFIED", "VERIFIED_RELEASE_BUNDLE"))
        self.assertEqual(len(self.adapter_calls), 1); self.assertEqual(len(self.approval_calls), 1)

    def test_compare_immutable_bundle_identical_and_different(self):
        with tempfile.TemporaryDirectory() as temp:
            other=BundleFixture(Path(temp)/"releases"); self.assertEqual(module.compare_immutable_bundle(self.fixture.bundle,other.bundle),module.Verdict("IDENTICAL","IDENTICAL"))
            (other.adapter/"lifecycle-certificate.json").write_bytes(b"different")
            self.assertEqual(module.compare_immutable_bundle(self.fixture.bundle,other.bundle).status,"DIFFERENT")

    def test_compare_immutable_bundle_rejects_extra_symlink_hardlink_and_bad_basename(self):
        with tempfile.TemporaryDirectory() as temp:
            other=BundleFixture(Path(temp)/"releases"); extra=other.bundle/"extra"; extra.write_text("x")
            self.assertEqual(module.compare_immutable_bundle(self.fixture.bundle,other.bundle).status,"DIFFERENT"); extra.unlink()
            target=other.adapter/"lifecycle-certificate.json"; hard=Path(temp)/"hard"; os.link(target,hard)
            self.assertEqual(module.compare_immutable_bundle(self.fixture.bundle,other.bundle).status,"DIFFERENT"); hard.unlink()
            renamed=other.bundle.parent/("sha256-"+("0"*64)); other.bundle.rename(renamed)
            self.assertEqual(module.compare_immutable_bundle(self.fixture.bundle,renamed).status,"DIFFERENT")

    def test_compare_immutable_bundle_detects_directory_identity_change(self):
        original=module._directory_identity; counts={}
        def changing(path):
            counts[path]=counts.get(path,0)+1
            if path==self.fixture.bundle and counts[path]>=2:return (999,999)
            return original(path)
        with mock.patch.object(module,"_directory_identity",side_effect=changing):
            self.assertEqual(module._immutable_bundle_snapshot(self.fixture.bundle),None)

    def test_relative_reader_detects_file_entry_replacement(self):
        directory_fd=module._open_directory(self.fixture.bundle)
        original=module.os.stat
        def replaced(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==module.MANIFEST_NAME and kwargs.get("dir_fd")==directory_fd:
                fields={name:getattr(value,name) for name in ("st_mode","st_ino","st_dev","st_nlink")}; fields["st_ino"]+=1
                return types.SimpleNamespace(**fields)
            return value
        try:
            with mock.patch.object(module.os,"stat",side_effect=replaced):
                with self.assertRaises(module.UnsafeFile): module._read_relative(directory_fd,module.MANIFEST_NAME,module.MAX_JSON)
        finally: os.close(directory_fd)

    def test_compare_helper_has_no_write_subprocess_or_authority_surface(self):
        source=TARGET.read_text(); tree=ast.parse(source); function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="compare_immutable_bundle")
        self.assertEqual([arg.arg for arg in function.args.args],["expected_bundle","existing_bundle"])
        segment=ast.get_source_segment(source,function)
        for forbidden in ("subprocess","write","unlink","rename","replace","approval_verifier","adapter_verifier","git"):
            self.assertNotIn(forbidden,segment)

    def test_index_schema_digest_and_binding(self):
        for mutation, code in (
            (lambda x: x.update(extra=1), "FAIL_RELEASE_INDEX_SCHEMA"),
            (lambda x: x.update(release_sequence=True), "FAIL_RELEASE_INDEX_SCHEMA"),
            (lambda x: x.update(release_index_digest="0" * 64), "FAIL_RELEASE_INDEX_SCHEMA"),
            (lambda x: x.update(adapter_version="other"), "FAIL_RELEASE_INDEX_SCHEMA"),
        ):
            with self.subTest(code=code):
                original = dict(self.fixture.index); mutation(self.fixture.index); write_json(self.root/module.INDEX_NAME, self.fixture.index)
                self.assertEqual(self.verify().code, code)
                self.fixture.index = original; write_json(self.root/module.INDEX_NAME, original)

    def test_manifest_schema_policy_digest_and_directory_identity(self):
        cases = (
            (lambda x: x.update(extra=1), "FAIL_RELEASE_BUNDLE_SCHEMA"),
            (lambda x: x.update(adapter_id="unknown"), "FAIL_RELEASE_ADAPTER_POLICY"),
            (lambda x: x.update(adapter_contract_digest="0" * 64), "FAIL_RELEASE_ADAPTER_POLICY"),
        )
        for mutation, code in cases:
            with self.subTest(code=code),tempfile.TemporaryDirectory() as temp:
                fixture=BundleFixture(Path(temp)/"releases"); mutation(fixture.manifest); fixture.reseal_manifest(); fixture.relocate_resealed_bundle()
                verdict=module._verify_release_tree(fixture.root,None,lambda *_:True,lambda *_:True)
                self.assertEqual(verdict.code, code)
        with tempfile.TemporaryDirectory() as temp:
            fixture=BundleFixture(Path(temp)/"releases"); fixture.manifest["bundle_manifest_digest"]="0"*64; write_json(fixture.bundle/module.MANIFEST_NAME,fixture.manifest)
            self.assertEqual(module._verify_release_tree(fixture.root,None,lambda *_:True,lambda *_:True).code,"FAIL_RELEASE_BUNDLE_DIGEST")

    def test_self_consistent_index_manifest_mismatch(self):
        self.fixture.index["reviewed_version"]="other"; self.fixture.reseal_index()
        self.assertEqual(self.verify().code,"FAIL_RELEASE_INDEX_BINDING")

    def test_exact_layout_rejects_extra_nested_and_symlink(self):
        extra = self.fixture.bundle / "extra"; extra.write_text("x")
        self.assertEqual(self.verify().code, "FAIL_RELEASE_BUNDLE_LAYOUT"); extra.unlink()
        nested = self.fixture.adapter / "nested"; nested.mkdir()
        self.assertEqual(self.verify().code, "FAIL_RELEASE_ADAPTER_LAYOUT"); nested.rmdir()
        target = self.fixture.adapter / "lifecycle-certificate.json"; raw = target.read_bytes(); target.unlink(); actual = self.root / "actual"; actual.write_bytes(raw); target.symlink_to(actual)
        self.assertEqual(self.verify().code, "FAIL_RELEASE_BUNDLE_FILE_POLICY")

    def test_hardlink_size_and_raw_digest_fail_closed(self):
        target = self.fixture.adapter / "lifecycle-certificate.json"; other = self.root / "hard"; os.link(target, other)
        self.assertEqual(self.verify().code, "FAIL_RELEASE_BUNDLE_FILE_POLICY"); other.unlink()
        target.write_bytes(b"tampered")
        self.assertEqual(self.verify().code, "FAIL_RELEASE_ARTIFACT_BINDING")

    def test_evidence_and_approval_cross_binding(self):
        evidence = self.fixture.adapter / "lifecycle-evidence-manifest.json"; value=json.loads(evidence.read_text())
        value["reviewed_version"]="other"; evidence.write_bytes(module._canonical(value)); descriptor=self.fixture.manifest["adapter_artifacts"][evidence.name]; descriptor.update(raw_sha256=module._raw_digest(evidence.read_bytes()),size_bytes=evidence.stat().st_size)
        self.fixture.reseal_manifest(); self.fixture.relocate_resealed_bundle()
        self.assertEqual(self.verify().code,"FAIL_RELEASE_EVIDENCE_BINDING")

    def test_approval_digest_signature_scope_and_trust_binding(self):
        approval_path=self.fixture.bundle/module.APPROVAL_NAME; approval=json.loads(approval_path.read_text()); approval["scope"]="wrong"; write_json(approval_path,approval)
        self.fixture.manifest["approval_record_digest"]=module._digest(approval); self.fixture.reseal_manifest(); self.fixture.relocate_resealed_bundle()
        self.assertEqual(self.verify().code,"FAIL_RELEASE_APPROVAL_BINDING")

    def test_approval_filename_signature_and_verifier_failure(self):
        approval_path = self.fixture.bundle / module.APPROVAL_NAME; approval=json.loads(approval_path.read_text()); approval["signature_file"]="other.sig"; write_json(approval_path,approval)
        self.assertEqual(self.verify().code, "FAIL_RELEASE_APPROVAL_BINDING")
        self.setUp()
        self.assertEqual(self.verify(approval=lambda *_:False).code, "BLOCKED_EXTERNAL_APPROVAL_VERIFICATION")
        self.assertEqual(self.verify(adapter=lambda *_:False).code, "FAIL_RELEASE_ADAPTER_VERIFICATION")

    def test_outer_approval_hardlink_duplicate_and_signature_digest(self):
        approval=self.fixture.bundle/module.APPROVAL_NAME; other=self.root/"hard-approval"; os.link(approval,other)
        self.assertEqual(self.verify().code,"FAIL_RELEASE_BUNDLE_FILE_POLICY"); other.unlink()
        approval.write_bytes(b'{"x":1,"x":2}')
        self.assertEqual(self.verify().code,"FAIL_RELEASE_BUNDLE_FILE_POLICY")

    def test_signature_raw_digest_tamper(self):
        (self.fixture.bundle/module.SIGNATURE_NAME).write_bytes(b"tampered")
        self.assertEqual(self.verify().code,"FAIL_RELEASE_APPROVAL_BINDING")

    def test_parent_lineage_sequence_and_no_reactivation(self):
        parent = dict(self.fixture.index)
        with tempfile.TemporaryDirectory() as temp:
            later_root=Path(temp)/"later"; later=BundleFixture(later_root,parent,"v0.2.0","b"*64)
            verdict=module._verify_release_tree(later_root,parent,lambda *_:True,lambda *_:True)
            self.assertEqual(verdict.status,"VERIFIED")
            later.index["release_sequence"] += 1; later.reseal_index()
            self.assertEqual(module._verify_release_tree(later_root,parent,lambda *_:True,lambda *_:True).code,"BLOCKED_EXPECTED_PARENT_INDEX")
            later.index["release_sequence"] = parent["release_sequence"]+1; later.index["active_bundle_id"] = parent["active_bundle_id"]; later.reseal_index()
            self.assertEqual(module._verify_release_tree(later_root,parent,lambda *_:True,lambda *_:True).code,"FAIL_RELEASE_BUNDLE_FILE_POLICY")

    def test_duplicate_json_oversize_and_missing(self):
        (self.root/module.INDEX_NAME).write_bytes(b'{"x":1,"x":2}')
        self.assertEqual(self.verify().code,"FAIL_RELEASE_BUNDLE_FILE_POLICY")
        (self.root/module.INDEX_NAME).write_bytes(b"x"*(module.MAX_JSON+1))
        self.assertEqual(self.verify().code,"FAIL_RELEASE_BUNDLE_FILE_POLICY")
        (self.root/module.INDEX_NAME).unlink()
        self.assertEqual(self.verify().code,"FAIL_RELEASE_BUNDLE_FILE_POLICY")

    def test_production_cli_has_only_two_governance_inputs_and_no_mutation(self):
        source=TARGET.read_text(); tree=ast.parse(source)
        self.assertNotIn("commit", {node.attr for node in ast.walk(tree) if isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id=="subprocess"})
        self.assertNotIn("--root",source); self.assertNotIn("--trust",source); self.assertNotIn("--verifier",source)
        self.assertIn('parser.add_argument("--expected-parent-oid", required=True)',source)
        self.assertIn('parser.add_argument("--source-commit-oid", required=True)',source)
        for forbidden in ("git commit","git push","update-ref","private_key","-Y sign"):
            self.assertNotIn(forbidden,source)

    def test_cli_exact_stream_contract(self):
        old=sys.argv
        try:
            sys.argv=["verify_release_bundle.py","--expected-parent-oid","a"*40,"--source-commit-oid","b"*40]
            with mock.patch.object(module,"verify_production",return_value=module.Verdict("VERIFIED","VERIFIED_RELEASE_BUNDLE")),mock.patch("sys.stdout",new_callable=__import__('io').StringIO) as stdout:
                self.assertEqual(module.main(),0); self.assertEqual(stdout.getvalue(),"VERIFIED_RELEASE_BUNDLE\n")
            with mock.patch.object(module,"verify_production",return_value=module.Verdict("BLOCKED","BLOCKED_SOURCE_COMMIT_OID")),mock.patch("sys.stderr",new_callable=__import__('io').StringIO) as stderr:
                self.assertEqual(module.main(),1); self.assertEqual(stderr.getvalue(),"BLOCKED_SOURCE_COMMIT_OID\n")
        finally: sys.argv=old

    def test_bounded_process_rejects_overflow(self):
        code,output=module._bounded_process([sys.executable,"-c","print('x'*5000)"],HERE,64,{"LC_ALL":"C","LANG":"C"})
        self.assertNotEqual(code,0); self.assertLessEqual(len(output),65)

    def test_bounded_process_timeout_reaps_child_without_reader_thread(self):
        before={thread.ident for thread in __import__('threading').enumerate()}
        code,output=module._bounded_process([sys.executable,"-c","import time;time.sleep(5)"],HERE,64,{"LC_ALL":"C","LANG":"C"},timeout_seconds=0.02)
        after={thread.ident for thread in __import__('threading').enumerate()}
        self.assertEqual(code,125); self.assertEqual(output,b""); self.assertEqual(before,after)

    def test_bounded_process_mock_kill_wait_close_contract(self):
        class Pipe:
            def fileno(self): return 7
            def close(self): calls.append("close")
        class Process:
            stdout=Pipe(); returncode=None
            def poll(self): return self.returncode
            def kill(self): calls.append("kill")
            def wait(self,timeout=None): calls.append(("wait",timeout)); self.returncode=-9; return -9
        class Selector:
            def register(self,*args): pass
            def select(self,_): return []
            def close(self): calls.append("selector-close")
        calls=[]
        with mock.patch.object(module.subprocess,"Popen",return_value=Process()),mock.patch.object(module.selectors,"DefaultSelector",return_value=Selector()),mock.patch.object(module.time,"monotonic",side_effect=[0,1]):
            code,_=module._bounded_process(["x"],HERE,timeout_seconds=0.1)
        self.assertEqual(code,125); self.assertIn("kill",calls); self.assertTrue(any(item[0]=="wait" and item[1] is not None for item in calls if isinstance(item,tuple))); self.assertIn("selector-close",calls); self.assertIn("close",calls)

    def test_terminate_kill_oserror_uses_pid_fallback_and_finite_wait(self):
        class Process:
            pid=43210; returncode=None
            def poll(self): return self.returncode
            def kill(self): raise OSError("redacted")
            def wait(self,timeout=None): calls.append(("wait",timeout)); self.returncode=-9; return -9
        calls=[]
        with mock.patch.object(module.os,"kill",side_effect=lambda pid,sig:calls.append(("os.kill",pid,sig))):
            self.assertTrue(module._terminate_and_reap(Process(),0.01))
        self.assertIn(("os.kill",43210,module.signal.SIGKILL),calls); self.assertIn(("wait",0.01),calls)

    def test_double_kill_failure_is_cleanup_unconfirmed_not_success(self):
        class Pipe:
            def fileno(self): return 7
            def close(self): calls.append("close")
        class Process:
            pid=43210; stdout=Pipe(); returncode=None
            def poll(self): return None
            def kill(self): raise OSError("redacted")
            def wait(self,timeout=None): calls.append(("wait",timeout)); raise subprocess.TimeoutExpired("x",timeout)
        class Selector:
            def register(self,*args): pass
            def select(self,_): return []
            def close(self): calls.append("selector-close")
        calls=[]
        with mock.patch.object(module.subprocess,"Popen",return_value=Process()),mock.patch.object(module.selectors,"DefaultSelector",return_value=Selector()),mock.patch.object(module.os,"kill",side_effect=OSError("redacted")),mock.patch.object(module.time,"monotonic",side_effect=[0,1]):
            code,_=module._bounded_process(["x"],HERE,timeout_seconds=0.1)
        self.assertEqual(code,126); self.assertIn("selector-close",calls); self.assertIn("close",calls); self.assertTrue(all(item[1] is not None for item in calls if isinstance(item,tuple) and item[0]=="wait"))
        with mock.patch.object(module,"_bounded_process",return_value=(126,b"")):
            self.assertEqual(module.verify_production("a"*40,"b"*40).code,"BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED")

    def test_internal_verifier_cleanup_unconfirmed_maps_stable_code(self):
        def unconfirmed(*_): raise module.CleanupUnconfirmed
        self.assertEqual(self.verify(adapter=unconfirmed).code,"BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED")

    def test_cleanup_failure_is_controlled_and_does_not_mask_as_success(self):
        class Pipe:
            def fileno(self): return 7
            def close(self): raise OSError("redacted")
        class Process:
            stdout=Pipe(); returncode=0
            def poll(self): return 0
            def wait(self,timeout=None): return 0
        class Selector:
            def register(self,*args): pass
            def select(self,_): return [(object(),object())]
            def close(self): raise OSError("redacted")
        with mock.patch.object(module.subprocess,"Popen",return_value=Process()),mock.patch.object(module.selectors,"DefaultSelector",return_value=Selector()),mock.patch.object(module.os,"read",side_effect=[b"VERIFIED\n",b""]):
            code,output=module._bounded_process(["x"],HERE)
        self.assertEqual(code,126); self.assertEqual(output,b"VERIFIED\n")

    def test_real_temporary_b03_approval_seam(self):
        approval_spec=importlib.util.spec_from_file_location("c1_approval",Path(__file__).resolve().parents[1]/"stock-opencode"/"verify_approval_record.py"); approval_module=importlib.util.module_from_spec(approval_spec); sys.modules[approval_spec.name]=approval_module; approval_spec.loader.exec_module(approval_module)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); trust=root/"trust"; trust.mkdir(); key=root/"key"
            subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(key)],check=True)
            public=key.with_suffix(".pub").read_text().split(); principal="release-dri"
            (trust/"allowed_signers").write_text(f'{principal} namespaces="{approval_module.NAMESPACE}" {public[0]} {public[1]}\n')
            subprocess.run(["ssh-keygen","-q","-k","-f",str(trust/"revoked.krl")],check=True)
            fingerprint=subprocess.run(["ssh-keygen","-lf",str(key.with_suffix(".pub"))],capture_output=True,text=True,check=True).stdout.split()[1]; executable=str(Path("/usr/bin/ssh-keygen").resolve())
            policy={"schema_version":"nomad.stock-opencode.trust-root-policy.v1","trust_root_id":"ssh-ed25519:"+fingerprint,"fingerprint":fingerprint,"principal":principal,"namespace":approval_module.NAMESPACE,"key_type":"ssh-ed25519","max_validity_seconds":2592000,"clock_skew_seconds":0,"ssh_keygen":{"platform_paths":{"darwin-arm64":[executable],"linux-x86_64":[executable]}},"revocation_policy":{"require_krl":True}}
            write_json(trust/"trust-root-policy.json",policy)
            approval_path=self.fixture.bundle/module.APPROVAL_NAME; approval=json.loads(approval_path.read_text()); now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0); approval.update(principal=principal,issued_at=now.isoformat().replace("+00:00","Z"),expires_at=(now+dt.timedelta(days=1)).isoformat().replace("+00:00","Z"),trust_root_id=policy["trust_root_id"],signing_namespace=approval_module.NAMESPACE)
            write_json(approval_path,approval); payload=root/"payload"; payload.write_bytes(approval_module.domain(approval)); subprocess.run(["ssh-keygen","-Y","sign","-f",str(key),"-n",approval_module.NAMESPACE,str(payload)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True); payload.with_suffix(".sig").replace(self.fixture.bundle/module.SIGNATURE_NAME)
            self.fixture.manifest.update(approval_record_digest=module._digest(approval),approval_signature_raw_digest=module._raw_digest((self.fixture.bundle/module.SIGNATURE_NAME).read_bytes()),trust_root_id=policy["trust_root_id"]); self.fixture.reseal_manifest(); self.fixture.relocate_resealed_bundle()
            def approval_verify(bundle,manifest):
                verdict=approval_module.verify_approval_record(bundle/module.APPROVAL_NAME,expected_evidence_manifest_digest=manifest["evidence_manifest_digest"],expected_reviewed_version=manifest["reviewed_version"],trust_dir=trust,platform_id="darwin-arm64",tool_resolver=lambda _:executable)
                return verdict.status=="VERIFIED"
            self.assertEqual(module._verify_release_tree(self.root,None,lambda *_:True,approval_verify).status,"VERIFIED")
        sys.modules.pop(approval_spec.name,None)

    def test_production_git_oid_and_parent_matrix(self):
        parent="a"*40; source="b"*40
        responses={
            ("rev-parse","--show-object-format"):(0,b"sha1\n"),
            ("cat-file","-t",parent):(0,b"commit\n"),
            ("cat-file","-t",source):(0,b"commit\n"),
            ("rev-parse","HEAD"):(0,(source+"\n").encode()),
            ("rev-list","--parents","-n","1",source):(0,(source+" "+parent+"\n").encode()),
            ("status","--porcelain=v1","--untracked-files=all"):(0,b""),
            ("ls-tree","--name-only",parent,"--","evidence/agent-releases/current.json"):(0,b""),
            ("log","--first-parent","--format=%H",parent,"--","evidence/agent-releases/current.json"):(0,b""),
        }
        with mock.patch.object(module,"RELEASE_ROOT",self.root),mock.patch.object(module,"_git_executable",return_value=Path("/usr/bin/git")),mock.patch.object(module,"_git",side_effect=lambda _git,*args:responses[args]),mock.patch.object(module,"_verify_release_tree",return_value=module.Verdict("VERIFIED","VERIFIED_RELEASE_BUNDLE")) as verify:
            self.assertEqual(module.verify_production(parent,source).status,"VERIFIED")
            self.assertIsNone(verify.call_args.args[1])
        self.assertEqual(module.verify_production("bad",source).code,"BLOCKED_SOURCE_COMMIT_OID")

    def test_production_dirty_wrong_type_and_external_trust_block(self):
        parent="a"*40; source="b"*40
        base={
            ("rev-parse","--show-object-format"):(0,b"sha1\n"),
            ("cat-file","-t",parent):(0,b"commit\n"),
            ("cat-file","-t",source):(0,b"commit\n"),
            ("rev-parse","HEAD"):(0,(source+"\n").encode()),
            ("rev-list","--parents","-n","1",source):(0,(source+" "+parent+"\n").encode()),
            ("status","--porcelain=v1","--untracked-files=all"):(0,b"?? x\n"),
        }
        with mock.patch.object(module,"_git_executable",return_value=Path("/usr/bin/git")),mock.patch.object(module,"_git",side_effect=lambda _git,*args:base[args]):
            self.assertEqual(module.verify_production(parent,source).code,"BLOCKED_SOURCE_COMMIT_OID")

    def test_parent_exists_but_show_failure_is_blocked(self):
        with mock.patch.object(module,"_git",side_effect=[(0,b"evidence/agent-releases/current.json\n"),(1,b"")]):
            error,parent=module._load_parent_index(Path("/usr/bin/git"),"a"*40)
        self.assertEqual(error.code,"BLOCKED_EXPECTED_PARENT_INDEX"); self.assertIsNone(parent)


if __name__ == "__main__":
    unittest.main()
