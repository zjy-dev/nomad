from __future__ import annotations
import copy,hashlib,importlib.util,pickle,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("nomad_host_publication_authorization_tests",HERE/"host_publication_authorization.py")
assert SPEC and SPEC.loader
module=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=module;SPEC.loader.exec_module(module)

class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);root=Path(self.temp.name);self.binary=(root/"nomad-host").resolve();self.raw=b"exact published host\n";self.binary.write_bytes(self.raw);self.binary.chmod(0o755);self.digest=hashlib.sha256(self.raw).hexdigest();self.record=root/"host-approval.json";self.record.write_bytes(b"approval")
 def values(self,operation="forward"):
  artifact_sequence=7;publication_sequence=7 if operation=="forward" else 9
  common={"host_manifest_digest":"1"*64,"artifact_raw_sha256":self.digest,"release_index_digest":"2"*64,"bundle_manifest_digest":"3"*64,"evidence_manifest_digest":"4"*64,"source_commit_oid":"5"*40,"host_artifact_sequence":artifact_sequence,"binary_path":self.binary}
  rv={**common,"approval_record_digest":"6"*64,"approval_signature_raw_digest":"7"*64,"executable_vnode_digest":"8"*64}
  cv={**common,"host_approval_digest":hashlib.sha256(b"approval").hexdigest(),"candidate_id":"sha256-"+common["host_manifest_digest"],"publication_sequence":publication_sequence,"operation":operation,"proposed_commit_oid":"a"*40,"protected_ref":module.post_cas.REF,"active_index_digest":"b"*64}
  return rv,cv
 def chain(self,operation="forward"):
  rv,cv=self.values(operation);relation=module.relation._issue_test_relation(rv);approval=module.approval._issue_test_approval(self.record,relation);checkout=module.post_cas._issue_test_checkout(cv);return relation,approval,checkout
 def join(self,operation="forward"):
  return module._combine(module._TEST_AUTHORIZATION_TOKEN,*self.chain(operation))
 def test_registered_forward_and_rollback_join_to_test_authority(self):
  for operation in ("forward","rollback"):
   result=self.join(operation);self.assertTrue(module._is_verified_test_authorization(result));self.assertFalse(module._is_verified_production_authorization(result));self.assertEqual(result.operation,operation)
   with self.assertRaises(TypeError):pickle.dumps(result)
   with self.assertRaises(TypeError):copy.copy(result)
 def test_equal_but_different_relation_forged_exact_and_duck_block(self):
  relation,approval,checkout=self.chain();equal_relation=module.relation._issue_test_relation({name:getattr(relation,name) for name in module.relation._OpaqueRelation.__slots__ if name!="__weakref__"})
  with self.assertRaises(module.AuthorizationError):module._combine(module._TEST_AUTHORIZATION_TOKEN,equal_relation,approval,checkout)
  forged=object.__new__(module.relation._TestProductionHostRelation)
  for name in module.relation._OpaqueRelation.__slots__:
   if name!="__weakref__":object.__setattr__(forged,name,getattr(relation,name))
  self.assertFalse(module.relation._is_verified_test(forged))
  with self.assertRaises(module.AuthorizationError):module._combine(module._TEST_AUTHORIZATION_TOKEN,forged,approval,checkout)
  with self.assertRaises(module.AuthorizationError):module._combine(module._TEST_AUTHORIZATION_TOKEN,object(),approval,checkout)
 def test_final_authority_forge_subclass_and_production_cross_block(self):
  result=self.join();forged=object.__new__(module._TestPublishedHostAuthorization);self.assertFalse(module._is_verified_test_authorization(forged))
  class Child(module._TestPublishedHostAuthorization):pass
  child=object.__new__(Child);self.assertFalse(module._is_verified_test_authorization(child))
  self.assertTrue(module._is_verified_test_authorization(result))
  object.__setattr__(result,"artifact_raw_sha256","f"*64);self.assertFalse(module._is_verified_test_authorization(result))
  with self.assertRaises(module.AuthorizationError):module._combine(object(),*self.chain())
 def test_sequence_hash_hardlink_and_public_production_block(self):
  relation,approval,checkout=self.chain("rollback");object.__setattr__(checkout,"publication_sequence",checkout.host_artifact_sequence)
  with self.assertRaises(module.AuthorizationError):module._combine(module._TEST_AUTHORIZATION_TOKEN,relation,approval,checkout)
  self.binary.write_bytes(b"mutated")
  with self.assertRaises(module.AuthorizationError):self.join()
  self.binary.write_bytes(self.raw);self.binary.with_name("other").hardlink_to(self.binary)
  with self.assertRaises(module.AuthorizationError):self.join()
  missing=Path("/definitely/missing")
  with self.assertRaises(module.AuthorizationError):module.authorize(*(missing for _ in range(10)))

if __name__=="__main__":unittest.main()
