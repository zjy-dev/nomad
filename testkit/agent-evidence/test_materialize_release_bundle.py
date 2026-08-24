from __future__ import annotations

import ast
import ctypes
import errno
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("release_materializer",HERE/"materialize_release_bundle.py")
assert SPEC and SPEC.loader
module=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=module;SPEC.loader.exec_module(module)
c1=module.c1


def write_json(path,value): path.write_bytes(c1._canonical(value))


class MaterializerTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.release=self.base/"release";self.bundles=self.release/c1.BUNDLES_NAME;self.bundles.mkdir(parents=True);self.release.chmod(0o755);self.bundles.chmod(0o755);self.inputs={name:self.base/name for name in c1.OPENCODE_POLICY["artifacts"]}
  evidence={"schema_version":c1.OPENCODE_POLICY["evidence_schema"],"reviewed_version":"v0.1.0","evidence_manifest_digest":"a"*64};write_json(self.inputs["lifecycle-certificate.json"],{"schema":"cert"});write_json(self.inputs["lifecycle-shape-manifest.json"],{"schema":"shape"});write_json(self.inputs["lifecycle-evidence-manifest.json"],evidence)
  self.approval=self.base/"approval.json";self.signature=self.base/"signature";approval={"schema_version":c1.OPENCODE_POLICY["approval_schema"],"evidence_manifest_digest":"a"*64,"reviewed_version":"v0.1.0","scope":c1.OPENCODE_POLICY["approval_scope"],"principal":"dri","issued_at":"2026-08-20T00:00:00Z","expires_at":"2026-08-21T00:00:00Z","trust_root_id":"root","signing_namespace":"ns","signature_file":c1.SIGNATURE_NAME};write_json(self.approval,approval);self.signature.write_bytes(b"sig")
 def publish_move(self,source,bundles,name): os.rename(source,bundles/name);return module.Verdict("PUBLISHED_INACTIVE","PUBLISHED_INACTIVE")
 def call(self,publisher=None,adapter=lambda *_:True,approval=lambda *_:True):return module._materialize(self.release,self.inputs,self.approval,self.signature,adapter,approval,publisher or self.publish_move)
 def test_first_release_candidate_tree(self):
  result=self.call();self.assertEqual(result.code,"CANDIDATE_RELEASE_TREE");index=json.loads((self.release/module.PROPOSED_NAME).read_text());self.assertEqual((index["previous_release_index_digest"],index["release_sequence"]),(module.ZERO,1));self.assertFalse((self.release/c1.INDEX_NAME).exists());self.assertTrue((self.bundles/index["active_bundle_id"]).is_dir())
 def test_later_lineage_and_same_bundle_rejected(self):
  parent_core={"schema_version":"nomad.agent-evidence.release-index.v1","active_bundle_id":"sha256-"+"b"*64,"bundle_manifest_digest":"b"*64,"adapter_id":"opencode","adapter_version":"1.18.16","reviewed_version":"old","evidence_manifest_digest":"b"*64,"approval_record_digest":"b"*64,"previous_release_index_digest":module.ZERO,"release_sequence":1};parent={**parent_core,"release_index_digest":c1._digest(parent_core)};write_json(self.release/c1.INDEX_NAME,parent);result=self.call();index=json.loads((self.release/module.PROPOSED_NAME).read_text());self.assertEqual(result.code,"CANDIDATE_RELEASE_TREE");self.assertEqual((index["previous_release_index_digest"],index["release_sequence"]),(parent["release_index_digest"],2))
 def test_malformed_active_index_is_lineage_blocker(self):
  (self.release/c1.INDEX_NAME).write_text("{}")
  self.assertEqual(self.call().code,"BLOCKED_EXPECTED_PARENT_INDEX")
 def test_missing_symlink_and_oversize_inputs_block(self):
  for name in tuple(self.inputs):
   with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
    original=self.inputs[name];self.inputs[name]=Path(temp)/"missing";self.assertEqual(self.call().code,"BLOCKED_INPUT_STAGED_MISSING");self.inputs[name]=original
  target=self.inputs["lifecycle-certificate.json"];raw=target.read_bytes();target.unlink();actual=self.base/"actual";actual.write_bytes(raw);target.symlink_to(actual);self.assertEqual(self.call().code,"BLOCKED_INPUT_STAGED_MISSING")
 def test_verifier_failures_and_cleanup_unconfirmed(self):
  self.assertEqual(self.call(adapter=lambda *_:False).code,"FAIL_C1_INTERNAL_VERIFICATION")
  def fail(*_):raise c1.CleanupUnconfirmed
  self.assertEqual(self.call(adapter=fail).code,"BLOCKED_SUBPROCESS_CLEANUP_UNCONFIRMED")
 def test_proposed_collision_and_active_lineage_change(self):
  (self.release/module.PROPOSED_NAME).write_text("existing");self.assertEqual(self.call().code,"BLOCKED_PROPOSED_INDEX_EXISTS")
  (self.release/module.PROPOSED_NAME).unlink()
  def publish(source,bundles,name):write_json(self.release/c1.INDEX_NAME,{"changed":True});return module.Verdict("ALREADY_IDENTICAL","ALREADY_IDENTICAL")
  self.assertEqual(self.call(publish).code,"BLOCKED_EXPECTED_PARENT_INDEX");self.assertFalse((self.release/module.PROPOSED_NAME).exists())
 def test_publisher_collision_and_already_identical_paths(self):
  self.assertEqual(self.call(lambda *_:module.Verdict("BLOCKED","BLOCKED_BUNDLE_COLLISION")).code,"BLOCKED_BUNDLE_COLLISION")
  with tempfile.TemporaryDirectory() as temp:
   test=MaterializerTest("test_first_release_candidate_tree");test.setUp()
   try:self.assertEqual(test.call(lambda *_:module.Verdict("ALREADY_IDENTICAL","ALREADY_IDENTICAL")).code,"CANDIDATE_RELEASE_TREE")
   finally:test.doCleanups()
 def test_darwin_and_linux_exclusive_abi(self):
  candidate=self.release/".candidate-test";candidate_bundles=candidate/c1.BUNDLES_NAME;candidate_bundles.mkdir(parents=True);source=candidate_bundles/("sha256-"+"a"*64);source.mkdir();seen=[]
  class Fn:
   def __call__(self,*args):seen.append(args);return 0
  class Lib:renamex_np=Fn();syscall=Fn()
  def move_source(*_):os.rename(source,self.bundles/source.name);seen.append(_);return 0
  Lib.renamex_np=mock.Mock(side_effect=move_source)
  with mock.patch.object(module,"_fsync_dir"),mock.patch.object(c1,"compare_immutable_bundle",return_value=c1.Verdict("IDENTICAL","IDENTICAL")):
   self.assertEqual(module.exclusive_dir_publish(source,self.bundles,"sha256-"+"a"*64,system="Darwin",machine="arm64",library_factory=lambda *_a,**_k:Lib()).status,"PUBLISHED_INACTIVE")
  self.assertEqual(len(Lib.renamex_np.call_args.args),3);source=candidate_bundles/("sha256-"+"b"*64);source.mkdir()
  def move_linux(*_):os.rename(source,self.bundles/source.name);seen.append(_);return 0
  Lib.syscall=mock.Mock(side_effect=move_linux)
  with mock.patch.object(module,"_fsync_dir"),mock.patch.object(c1,"compare_immutable_bundle",return_value=c1.Verdict("IDENTICAL","IDENTICAL")):
   self.assertEqual(module.exclusive_dir_publish(source,self.bundles,"sha256-"+"b"*64,system="Linux",machine="x86_64",library_factory=lambda *_a,**_k:Lib()).status,"PUBLISHED_INACTIVE")
  self.assertEqual(len(Lib.syscall.call_args.args),6);self.assertEqual(Lib.syscall.call_args.args[0].value,316)
 def test_errno_matrix_and_no_fallback(self):
  candidate=self.release/".candidate-test";candidate_bundles=candidate/c1.BUNDLES_NAME;candidate_bundles.mkdir(parents=True);source=candidate_bundles/("sha256-"+"c"*64);source.mkdir()
  class Fn:
   argtypes=None;restype=None
   def __init__(self,value):self.value=value
   def __call__(self,*_):ctypes.set_errno(self.value);return -1
  class Lib:
   def __init__(self,value):self.renamex_np=Fn(value);self.syscall=Fn(value)
  for value,code in ((errno.ENOSYS,"BLOCKED_UNSUPPORTED_NO_REPLACE"),(errno.EXDEV,"BLOCKED_CROSS_DEVICE"),(errno.EPERM,"BLOCKED_OUTPUT_DIR_POLICY"),(errno.EIO,"BLOCKED_ATOMIC_PUBLISH")):
   with self.subTest(value=value):self.assertEqual(module.exclusive_dir_publish(source,self.bundles,"sha256-"+"c"*64,system="Darwin",machine="arm64",library_factory=lambda *_a,v=value,**_k:Lib(v)).code,code)
  self.assertEqual(module.exclusive_dir_publish(source,self.bundles,"sha256-"+"c"*64,system="Other",machine="x").code,"BLOCKED_UNSUPPORTED_NO_REPLACE")
 def test_eexist_uses_c1b_compare(self):
  candidate=self.release/".candidate-test";candidate_bundles=candidate/c1.BUNDLES_NAME;candidate_bundles.mkdir(parents=True);source=candidate_bundles/("sha256-"+"d"*64);source.mkdir()
  class Fn:
   def __call__(self,*_):ctypes.set_errno(errno.EEXIST);return -1
  class Lib:renamex_np=Fn()
  with mock.patch.object(c1,"compare_immutable_bundle",return_value=c1.Verdict("IDENTICAL","IDENTICAL")) as compare:self.assertEqual(module.exclusive_dir_publish(source,self.bundles,"sha256-"+"d"*64,system="Darwin",machine="arm64",library_factory=lambda *_a,**_k:Lib()).status,"ALREADY_IDENTICAL");compare.assert_called_once()
 def test_symlink_source_rejected_before_syscall(self):
  candidate=self.release/".candidate-test";candidate_bundles=candidate/c1.BUNDLES_NAME;candidate_bundles.mkdir(parents=True);actual=candidate_bundles/"actual";actual.mkdir();source=candidate_bundles/("sha256-"+"e"*64);source.symlink_to(actual,target_is_directory=True)
  called=[]
  self.assertEqual(module.exclusive_dir_publish(source,self.bundles,source.name,system="Darwin",machine="arm64",library_factory=lambda *_a,**_k:called.append(1)).code,"BLOCKED_OUTPUT_DIR_POLICY");self.assertFalse(called);self.assertTrue(source.is_symlink())
 @unittest.skipUnless(sys.platform=="darwin" and __import__('platform').machine()=="arm64","Darwin arm64 smoke")
 def test_real_darwin_renamex_np_smoke(self):
  candidate=self.release/".candidate-smoke";candidate_bundles=candidate/c1.BUNDLES_NAME;candidate_bundles.mkdir(parents=True);source=candidate_bundles/("sha256-"+"f"*64);source.mkdir();
  with mock.patch.object(c1,"compare_immutable_bundle",return_value=c1.Verdict("IDENTICAL","IDENTICAL")):
   result=module.exclusive_dir_publish(source,self.bundles,source.name,system="Darwin",machine="arm64")
  self.assertEqual(result.status,"PUBLISHED_INACTIVE");self.assertTrue((self.bundles/source.name).is_dir());self.assertFalse(source.exists())
 def test_write_fsync_failures_preserve_candidate(self):
  with mock.patch.object(module.os,"fsync",side_effect=OSError("redacted")):self.assertEqual(self.call().code,"BLOCKED_DIRECTORY_FSYNC")
  self.assertTrue(any(path.name.startswith(".candidate-") for path in self.release.iterdir()))
 def test_production_missing_approval_is_precise_blocker(self):
  missing=self.base/"missing"
  result=module._materialize(self.release,self.inputs,missing,missing,lambda *_:True,lambda *_:True,self.publish_move)
  self.assertEqual(result.code,"BLOCKED_EXTERNAL_APPROVAL_VERIFICATION")
 def test_cli_no_args_and_no_mutation_authority(self):
  source=(HERE/"materialize_release_bundle.py").read_text();tree=ast.parse(source);self.assertNotIn("argparse",source)
  for forbidden in ("git commit","git push","update-ref","private_key","-Y sign","rmtree","unlink(","os.replace","os.rename") :self.assertNotIn(forbidden,source)
  old=sys.argv
  try:
   sys.argv=["materialize_release_bundle.py","extra"]
   with mock.patch("sys.stderr",new_callable=__import__('io').StringIO) as stderr:self.assertEqual(module.main(),1);self.assertEqual(stderr.getvalue(),"BLOCKED_OUTPUT_DIR_POLICY\n")
  finally:sys.argv=old

if __name__=="__main__":unittest.main()
