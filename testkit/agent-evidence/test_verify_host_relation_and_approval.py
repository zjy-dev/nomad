import importlib.util,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
module=load("nomad_combiner_tests",HERE/"verify_host_relation_and_approval.py")
class Tests(unittest.TestCase):
 def facts(self):return module.relation.RelationFacts(*(str(i)*64 for i in range(1,8)))
 def test_both_required(self):
  values={name:None for name in module.relation._OpaqueRelation.__slots__ if name!="__weakref__"}
  facts=module.relation._issue_test_relation(values)
  record=Path(__file__);approved=module.approval._issue_test_approval(record,facts)
  self.assertIs(module._combine(lambda:facts,lambda _:approved),approved)
  forged=object.__new__(module.relation._TestProductionHostRelation)
  for name in values:object.__setattr__(forged,name,None)
  for relation_call,approval_call in ((lambda:(_ for _ in ()).throw(Exception()),lambda _:approved),(lambda:facts,lambda _:module.approval.HostApprovalVerdict("BLOCKED",module.approval.BLOCKED)),(lambda:True,lambda _:approved),(lambda:forged,lambda _:approved),(lambda:module.relation.RelationFacts(*(str(i)*64 for i in range(1,8))),lambda _:approved)):
   self.assertEqual(module._combine(relation_call,approval_call).code,module.BLOCKED)
 def test_public_production_inputs_block(self):
  missing=Path("/definitely/missing");self.assertEqual(module.verify(missing,missing,missing,missing,missing,missing).code,module.BLOCKED)
 def test_source_has_no_bypass_publish_or_authority(self):
  source=(HERE/"verify_host_relation_and_approval.py").read_text();self.assertNotIn("approved=True",source);self.assertNotIn("PUBLISHED",source);self.assertNotIn("AUTHORIZED",source);self.assertNotIn("git",source.lower());self.assertNotIn("API_KEY",source)
if __name__=="__main__":unittest.main()
