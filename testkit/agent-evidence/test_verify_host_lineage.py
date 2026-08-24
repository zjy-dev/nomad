from __future__ import annotations
import ast,copy,hashlib,importlib.util,os,sys,tempfile,unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent;VERIFIER=HERE/"verify_host_lineage.py"
spec=importlib.util.spec_from_file_location("nomad_host_lineage_test_module",VERIFIER);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)

class LineageTests(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def seal(self,value,field):value={**value,field:module._digest(value)};return value
 def values(self,operation="forward",sequence=1,parent_digest=module.ZERO,parent_candidate=None,history=(),target=None):
  target=target or "sha256-"+"1"*64;manifest=target[7:];oid="a"*40
  candidate={"schema_version":module.CANDIDATE_SCHEMA,"candidate_id":target,"host_manifest_digest":manifest,"artifact_raw_sha256":"2"*64,"embedded_release_index_digest":"3"*64,"bundle_manifest_digest":"4"*64,"evidence_manifest_digest":"5"*64,"host_approval_digest":"6"*64,"source_commit_oid":oid,"candidate_tree_digest":"7"*64}
  parent={"schema_version":module.PARENT_SCHEMA,"expected_parent_oid":"b"*40,"protected_ref":module.PROTECTED_REF,"repository_object_format":"sha1","parent_active_index_digest":parent_digest,"parent_active_candidate_id":parent_candidate,"parent_host_artifact_sequence":sequence-1,"parent_tree_digest":"8"*64}
  history_core={"schema_version":module.HISTORY_SCHEMA,"protected_ref":module.PROTECTED_REF,"through_active_index_digest":parent_digest,"active_candidate_ids":sorted(history)};history_value=self.seal(history_core,"history_digest")
  allow_core={"schema_version":module.ALLOWLIST_SCHEMA,"protected_ref":module.PROTECTED_REF,"allowed_candidate_ids":sorted(history if operation=="rollback" else ()),"rollback_policy_digest":"9"*64};allow=self.seal(allow_core,"allowlist_digest")
  active_core={"schema_version":module.ACTIVE_SCHEMA,"operation":operation,"active_candidate_id":target,**{k:candidate[k] for k in ("host_manifest_digest","artifact_raw_sha256","embedded_release_index_digest","bundle_manifest_digest","evidence_manifest_digest","host_approval_digest")},"host_artifact_sequence":sequence,"previous_host_active_index_digest":parent_digest,"source_commit_oid":oid,"expected_parent_oid":parent["expected_parent_oid"],"rollback_from_active_index_digest":parent_digest if operation=="rollback" else None,"rollback_target_candidate_id":target if operation=="rollback" else None};active=self.seal(active_core,"active_index_digest")
  request_core={"schema_version":module.REQUEST_SCHEMA,"operation":operation,"expected_parent_oid":parent["expected_parent_oid"],"parent_active_index_digest":parent_digest,"target_candidate_id":target,"rollback_policy_digest":allow["rollback_policy_digest"] if operation=="rollback" else None,"rollback_reason_digest":"c"*64 if operation=="rollback" else None,"external_rollback_allowlist_digest":allow["allowlist_digest"] if operation=="rollback" else None};request=self.seal(request_core,"request_digest")
  return {"active":active,"parent":parent,"history":history_value,"candidate":candidate,"request":request,"allowlist":allow}
 def write(self,values):
  paths=[]
  for name in ("active","parent","history","candidate","request","allowlist"):
   path=self.root/(name+".json");path.write_bytes(module._canonical(values[name]));paths.append(path)
  return paths
 def verify(self,values):module.verify_lineage(*self.write(values))
 def blocked(self,values):
  with self.assertRaises(module.LineageError):self.verify(values)
 def test_first_and_second_forward(self):
  self.verify(self.values())
  first="sha256-"+"a"*64;self.verify(self.values(sequence=2,parent_digest="d"*64,parent_candidate=first,history=(first,),target="sha256-"+"b"*64))
 def test_valid_rollback(self):
  old="sha256-"+"1"*64;current="sha256-"+"2"*64;self.verify(self.values("rollback",3,"d"*64,current,(old,current),old))
 def test_sequence_parent_replay_and_forward_old_candidate_block(self):
  base=self.values(sequence=2,parent_digest="d"*64,parent_candidate="sha256-"+"a"*64,history=("sha256-"+"a"*64,),target="sha256-"+"b"*64)
  for field,value in (("host_artifact_sequence",1),("previous_host_active_index_digest","e"*64),("active_candidate_id","sha256-"+"a"*64)):
   x=copy.deepcopy(base);x["active"][field]=value;x["active"]["active_index_digest"]=module._digest({k:v for k,v in x["active"].items() if k!="active_index_digest"});self.blocked(x)
 def test_rollback_without_allowlist_parent_or_reason_blocks(self):
  old="sha256-"+"1"*64;current="sha256-"+"2"*64;base=self.values("rollback",3,"d"*64,current,(old,current),old)
  for target,field,value in (("allowlist","allowed_candidate_ids",[]),("active","rollback_from_active_index_digest","e"*64),("request","rollback_reason_digest",None)):
   x=copy.deepcopy(base);x[target][field]=value;digest={"allowlist":"allowlist_digest","active":"active_index_digest","request":"request_digest"}[target];x[target][digest]=module._digest({k:v for k,v in x[target].items() if k!=digest});self.blocked(x)
 def test_candidate_digest_canonical_duplicate_and_cli(self):
  values=self.values();values["candidate"]["artifact_raw_sha256"]="f"*64;self.blocked(values)
  values=self.values();paths=self.write(values);paths[0].write_text(paths[0].read_text()+" ")
  with self.assertRaises(module.LineageError):module.verify_lineage(*paths)
  paths=self.write(values);raw=paths[0].read_text();paths[0].write_text(raw[:-1]+',"operation":"forward"}')
  with self.assertRaises(module.LineageError):module.verify_lineage(*paths)
  paths=self.write(self.values());result=__import__("subprocess").run([sys.executable,str(VERIFIER),*(str(x) for x in paths)],capture_output=True,text=True);self.assertEqual((result.returncode,result.stdout,result.stderr),(0,module.SUCCESS+"\n",""))
 def test_symlink_hardlink_history_tamper_and_sha256_oid(self):
  values=self.values();paths=self.write(values);original=paths[0];alias=self.root/"alias";original.rename(alias);original.symlink_to(alias)
  with self.assertRaises(module.LineageError):module.verify_lineage(*paths)
  original.unlink();alias.rename(original);hard=self.root/"hard";os.link(original,hard)
  with self.assertRaises(module.LineageError):module.verify_lineage(*paths)
  hard.unlink();values=self.values();values["history"]["active_candidate_ids"]=["sha256-"+"f"*64];values["history"]["history_digest"]=module._digest({k:v for k,v in values["history"].items() if k!="history_digest"});self.blocked(values)
  values=self.values();values["parent"]["repository_object_format"]="sha256";values["parent"]["expected_parent_oid"]="b"*64;values["active"]["expected_parent_oid"]="b"*64;values["request"]["expected_parent_oid"]="b"*64;values["candidate"]["source_commit_oid"]="a"*64;values["active"]["source_commit_oid"]="a"*64
  values["active"]["active_index_digest"]=module._digest({k:v for k,v in values["active"].items() if k!="active_index_digest"});values["request"]["request_digest"]=module._digest({k:v for k,v in values["request"].items() if k!="request_digest"});self.verify(values)
 def test_no_git_sign_provider_or_write_surface(self):
  source=VERIFIER.read_text();tree=ast.parse(source);forbidden={"Popen","run","system","write","write_text","write_bytes","unlink","rename","replace","getenv"};calls=set()
  for node in ast.walk(tree):
   if isinstance(node,ast.Call):calls.add(node.func.attr if isinstance(node.func,ast.Attribute) else node.func.id if isinstance(node.func,ast.Name) else "")
  self.assertTrue(calls.isdisjoint(forbidden),calls&forbidden);self.assertNotIn("git",source.lower());self.assertNotIn("API_KEY",source)
if __name__=="__main__":unittest.main()
