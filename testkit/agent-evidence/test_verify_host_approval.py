from __future__ import annotations
import datetime as dt,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
module=load("nomad_host_approval_tests",HERE/"verify_host_approval.py");relation=load("nomad_relation_facts_for_approval",HERE/"verify_host_production_relation.py")
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.trust=self.root/"trust";self.trust.mkdir();self.key=self.root/"key";self.record=self.root/"host-approval.json"
  subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(self.key)],check=True);public=self.key.with_suffix(".pub").read_text().split();self.principal="host-release-dri";exe=str(Path("/usr/bin/ssh-keygen").resolve())
  (self.trust/"allowed_signers").write_text(f'{self.principal} namespaces="{module.HOST_SPEC.namespace}" {public[0]} {public[1]}\n');subprocess.run(["ssh-keygen","-q","-k","-f",str(self.trust/"revoked.krl")],check=True);fp=subprocess.check_output(["ssh-keygen","-lf",str(self.key.with_suffix(".pub"))],text=True).split()[1]
  policy={"schema_version":module.HOST_SPEC.trust_policy_schema,"trust_root_id":"ssh-ed25519:"+fp,"fingerprint":fp,"principal":self.principal,"namespace":module.HOST_SPEC.namespace,"key_type":"ssh-ed25519","max_validity_seconds":2592000,"clock_skew_seconds":0,"ssh_keygen":{"platform_paths":{"darwin-arm64":[exe],"linux-x86_64":[exe]}},"revocation_policy":{"require_krl":True}};(self.trust/"trust-root-policy.json").write_text(json.dumps(policy));self.facts=relation.RelationFacts("1"*64,"2"*64,"3"*64,"4"*64,"5"*64,"6"*64,"7"*64);now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0);self.value={"schema_version":module.HOST_SPEC.schema_version,"host_manifest_digest":self.facts.host_manifest_digest,"artifact_raw_sha256":self.facts.artifact_raw_sha256,"embedded_release_index_digest":self.facts.release_index_digest,"bundle_manifest_digest":self.facts.bundle_manifest_digest,"evidence_manifest_digest":self.facts.evidence_manifest_digest,"approval_scope":module.HOST_SPEC.scope,"principal":self.principal,"issued_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+dt.timedelta(days=1)).isoformat().replace("+00:00","Z"),"trust_root_id":policy["trust_root_id"],"signing_namespace":module.HOST_SPEC.namespace,"signature_file":module.HOST_SPEC.signature_file};self.sign()
 def sign(self):
  self.record.write_text(json.dumps(self.value));payload=self.root/"payload";payload.write_bytes(module.host_domain(self.value));subprocess.run(["ssh-keygen","-Y","sign","-f",str(self.key),"-n",module.HOST_SPEC.namespace,str(payload)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);payload.with_suffix(".sig").replace(self.root/module.HOST_SPEC.signature_file)
 def verify(self,**kwargs):return module._verify(self.record,self.facts,trust_dir=self.trust,platform_id="darwin-arm64",tool_resolver=lambda _:"/usr/bin/ssh-keygen",**kwargs)
 def test_valid_mechanics(self):
  result=self.verify();self.assertIs(type(result),module._TestProductionHostApproval);self.assertIs(result.relation,self.facts);self.assertEqual(len(result.host_approval_digest),64);self.assertFalse(hasattr(result,"binary_path"))
  with self.assertRaises(TypeError):module._TestProductionHostApproval()
 def test_binding_scope_namespace_time_signature_and_krl_block(self):
  for field,value in (("host_manifest_digest","0"*64),("approval_scope","bad"),("signing_namespace","bad"),("expires_at",self.value["issued_at"])):
   old=self.value[field];self.value[field]=value;self.sign();self.assertEqual(self.verify().code,module.BLOCKED);self.value[field]=old
  self.sign();(self.root/module.HOST_SPEC.signature_file).write_bytes(b"bad");self.assertEqual(self.verify().code,module.BLOCKED)
  self.sign();subprocess.run(["ssh-keygen","-q","-k","-u","-f",str(self.trust/"revoked.krl"),str(self.key.with_suffix(".pub"))],check=True);self.assertEqual(self.verify().code,module.BLOCKED)
 def test_production_trust_absent_blocks(self):self.assertEqual(module.verify_host_approval(self.record,self.facts).code,module.BLOCKED)
 def test_core_is_single_and_adapter_has_no_sign_git_provider(self):
  source=(HERE/"verify_host_approval.py").read_text();self.assertIn("core._verify_signed_record",source);self.assertNotIn("-Y\",\"verify",source);self.assertNotIn("API_KEY",source);self.assertNotIn("git",source.lower())
if __name__=="__main__":unittest.main()
