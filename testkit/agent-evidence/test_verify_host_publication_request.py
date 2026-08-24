import ast,copy,importlib.util,sys,tempfile,unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
HERE=Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location("nomad_publication_request_tests",HERE/"verify_host_publication_request.py");m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def seal(self,v,f):return {**v,f:m.digest(v)}
 def values(self,operation="forward"):
  candidate="sha256-"+"a"*64;parent="b"*40;proposed="c"*40;source="d"*40;root=f"evidence/host-artifacts/candidates/{candidate}"
  entries=[]
  for path,mode,size,digest in (("evidence/host-artifacts/current.json","100644",100,"1"*64),(root+"/nomad-host","100755",1000,"2"*64),(root+"/host-manifest.json","100644",200,"3"*64),(root+"/expected-build.json","100644",100,"4"*64),(root+"/evidence-release-reference.json","100644",80,"5"*64)):entries.append({"path":path,"kind":"regular","mode":mode,"size_bytes":size,"raw_sha256":digest})
  entries.sort(key=lambda x:x["path"]);entry_by_path={e["path"]:e for e in entries};tree_core=[{k:e[k] for k in sorted(m.ENTRY_FIELDS)} for e in entries];tree_digest=m.digest(tree_core);path_digest=m.digest([e["path"] for e in entries]);candidate_tree=m.digest([e for e in tree_core if e["path"].startswith(root+"/")]);parent_snapshot="6"*64;b0c2="7"*64;source_core={"schema_version":m.SOURCE_SCHEMA,"repository_object_format":"sha1","source_commit_oid":source,"head_oid":source,"index_tree_digest":"8"*64,"worktree_tree_digest":"9"*64,"untracked_paths_digest":m.digest([]),"worktree_clean":True,"index_clean":True,"untracked_clean":True,"cargo_lock_raw_sha256":"a"*64};source_value=self.seal(source_core,"snapshot_digest");lineage_paths={"active_index":"evidence/host-artifacts/current.json","candidate_manifest":root+"/host-manifest.json","expected_build":root+"/expected-build.json","binary":root+"/nomad-host","reference":root+"/evidence-release-reference.json"};lineage_raw_facts={key:value for prefix,path in lineage_paths.items() for key,value in ((prefix+"_raw_sha256",entry_by_path[path]["raw_sha256"]),(("active_index_raw_size_bytes" if prefix=="active_index" else prefix+"_size_bytes"),entry_by_path[path]["size_bytes"]))};lineage_core={"schema_version":m.LINEAGE_SCHEMA,"operation":operation,"parent_snapshot_digest":parent_snapshot,"active_index_digest":"1"*64,"host_manifest_digest":candidate[7:],"candidate_id":candidate,"candidate_tree_digest":candidate_tree,"b0c2_request_digest":b0c2,"host_artifact_sequence":2,**lineage_raw_facts};lineage=self.seal(lineage_core,"lineage_snapshot_digest");tree_value=self.seal({"schema_version":m.TREE_SCHEMA,"repository_object_format":"sha1","proposed_commit_oid":proposed,"expected_parent_oid":parent,"source_commit_oid":source,"unique_first_parent_oid":parent,"proposed_tree_digest":tree_digest,"tree_paths_digest":path_digest,"tree_entries":entries},"snapshot_digest");request_core={"schema_version":m.REQUEST_SCHEMA,"operation":operation,"protected_ref":m.REF,"repository_object_format":"sha1","expected_parent_oid":parent,"proposed_commit_oid":proposed,"source_commit_oid":source,"active_index_digest":lineage["active_index_digest"],"host_manifest_digest":candidate[7:],"candidate_id":candidate,"proposed_tree_digest":tree_digest,"proposed_tree_paths_digest":path_digest,"b0c2_request_digest":b0c2,"parent_snapshot_digest":parent_snapshot,"source_snapshot_digest":source_value["snapshot_digest"]};request=self.seal(request_core,"publication_request_digest");return {"request":request,"tree":tree_value,"source":source_value,"lineage":lineage}
 def write(self,v):
  paths=[]
  for n in ("request","tree","source","lineage"):
   p=self.root/(n+".json");p.write_bytes(m.canonical(v[n]));paths.append(p)
  return paths
 def verify(self,v):m.verify(*self.write(v))
 def blocked(self,v):
  with self.assertRaises(m.Error):self.verify(v)
 def reseal(self,v,n,f):v[n][f]=m.digest({k:x for k,x in v[n].items() if k!=f})
 def tree_entry(self,v,suffix):return next(e for e in v["tree"]["tree_entries"] if e["path"].endswith(suffix))
 def reseal_tree_mechanics(self,v):
  entries=v["tree"]["tree_entries"];tree_core=[{k:e[k] for k in sorted(m.ENTRY_FIELDS)} for e in entries];candidate_root=f"evidence/host-artifacts/candidates/{v['request']['candidate_id']}/";v["tree"]["proposed_tree_digest"]=m.digest(tree_core);v["tree"]["tree_paths_digest"]=m.digest([e["path"] for e in entries]);v["request"]["proposed_tree_digest"]=v["tree"]["proposed_tree_digest"];v["request"]["proposed_tree_paths_digest"]=v["tree"]["tree_paths_digest"];v["lineage"]["candidate_tree_digest"]=m.digest([e for e in tree_core if e["path"].startswith(candidate_root)]);self.reseal(v,"tree","snapshot_digest");self.reseal(v,"request","publication_request_digest");self.reseal(v,"lineage","lineage_snapshot_digest")
 def test_valid_forward_and_rollback(self):self.verify(self.values());self.verify(self.values("rollback"))
 def test_same_read_result_is_recursively_immutable(self):
  snapshots=m._read_and_verify(*self.write(self.values()))
  with self.assertRaises(TypeError):snapshots.request["operation"]="rollback"
  with self.assertRaises(TypeError):snapshots.tree["tree_entries"][0]["mode"]="100600"
  with self.assertRaises(FrozenInstanceError):snapshots.request={}
 def test_parent_source_lineage_and_dirty_mutations_block(self):
  base=self.values()
  for target,field,value,digest_field in (("tree","unique_first_parent_oid","e"*40,"snapshot_digest"),("source","worktree_clean",False,"snapshot_digest"),("lineage","operation","rollback","lineage_snapshot_digest"),("request","protected_ref","refs/heads/other","publication_request_digest")):
   v=copy.deepcopy(base);v[target][field]=value;self.reseal(v,target,digest_field);self.blocked(v)
 def test_tree_path_mode_digest_and_extra_mutations_block(self):
  base=self.values()
  for mutate in (lambda v:v["tree"]["tree_entries"][0].__setitem__("mode","100600"),lambda v:v["tree"]["tree_entries"].append({"path":"extra","kind":"regular","mode":"100644","size_bytes":1,"raw_sha256":"f"*64}),lambda v:v["request"].__setitem__("proposed_tree_digest","0"*64)):
   v=copy.deepcopy(base);mutate(v);self.reseal(v,"tree","snapshot_digest");self.reseal(v,"request","publication_request_digest");self.blocked(v)
 def test_current_raw_digest_mismatch_with_semantic_digest_unchanged_blocks(self):
  v=self.values();semantic_digest=v["lineage"]["active_index_digest"];self.tree_entry(v,"/current.json")["raw_sha256"]="f"*64;self.reseal_tree_mechanics(v);self.assertEqual(v["lineage"]["active_index_digest"],semantic_digest);self.blocked(v)
 def test_current_size_mismatch_blocks_after_reseal(self):
  v=self.values();self.tree_entry(v,"/current.json")["size_bytes"]+=1;self.reseal_tree_mechanics(v);self.blocked(v)
 def test_each_candidate_raw_digest_mismatch_blocks_after_reseal(self):
  for suffix in ("/nomad-host","/host-manifest.json","/expected-build.json","/evidence-release-reference.json"):
   with self.subTest(suffix=suffix):
    v=self.values();self.tree_entry(v,suffix)["raw_sha256"]="f"*64;self.reseal_tree_mechanics(v);self.blocked(v)
 def test_each_candidate_size_mismatch_blocks_after_reseal(self):
  for suffix in ("/nomad-host","/host-manifest.json","/expected-build.json","/evidence-release-reference.json"):
   with self.subTest(suffix=suffix):
    v=self.values();self.tree_entry(v,suffix)["size_bytes"]+=1;self.reseal_tree_mechanics(v);self.blocked(v)
 def test_lineage_raw_field_contract_and_values_block_after_reseal(self):
  digest_fields=("active_index_raw_sha256","candidate_manifest_raw_sha256","expected_build_raw_sha256","binary_raw_sha256","reference_raw_sha256");size_fields=("active_index_raw_size_bytes","candidate_manifest_size_bytes","expected_build_size_bytes","binary_size_bytes","reference_size_bytes")
  for field in digest_fields+size_fields:
   with self.subTest(case="missing",field=field):
    v=self.values();del v["lineage"][field];self.reseal(v,"lineage","lineage_snapshot_digest");self.blocked(v)
  v=self.values();v["lineage"]["unexpected_raw_fact"]="f"*64;self.reseal(v,"lineage","lineage_snapshot_digest");self.blocked(v)
  for field in digest_fields:
   with self.subTest(case="invalid_digest",field=field):
    v=self.values();v["lineage"][field]="A"*64;self.reseal(v,"lineage","lineage_snapshot_digest");self.blocked(v)
  for field in size_fields:
   for invalid in (True,0,-1,"100"):
    with self.subTest(case="invalid_size",field=field,value=invalid):
     v=self.values();v["lineage"][field]=invalid;self.reseal(v,"lineage","lineage_snapshot_digest");self.blocked(v)
 def test_noncanonical_duplicate_cli_and_no_git_surface(self):
  paths=self.write(self.values());paths[0].write_text(paths[0].read_text()+" ")
  with self.assertRaises(m.Error):m.verify(*paths)
  paths=self.write(self.values());result=__import__("subprocess").run([sys.executable,str(HERE/"verify_host_publication_request.py"),*(str(x) for x in paths)],capture_output=True,text=True);self.assertEqual((result.returncode,result.stdout,result.stderr),(0,m.SUCCESS+"\n",""));source=(HERE/"verify_host_publication_request.py").read_text();tree=ast.parse(source);calls={n.func.attr if isinstance(n.func,ast.Attribute) else n.func.id if isinstance(n.func,ast.Name) else "" for n in ast.walk(tree) if isinstance(n,ast.Call)};self.assertTrue(calls.isdisjoint({"Popen","run","system","write","write_text","write_bytes","unlink","rename","replace","getenv"}));self.assertNotIn("git",source.lower())
if __name__=="__main__":unittest.main()
