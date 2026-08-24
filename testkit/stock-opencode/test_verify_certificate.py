import ast,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
P=Path(__file__).with_name("verify_certificate.py");s=importlib.util.spec_from_file_location("verify",P);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
def valid():
 core={"schema_version":"nomad.stock-opencode.lifecycle-certificate.v1","expected_event_sequence":["session.created","question.asked","session.diff","permission.asked"],"diff_file_count":1,"v1_routes_verified":m.V1,"v2_routes_verified":m.V2};return {**core,"structural_digest":m._digest(core)}
class TestVerifier(unittest.TestCase):
 def write(self,value):
  t=tempfile.NamedTemporaryFile(mode="w",delete=False);json.dump(value,t);t.close();self.addCleanup(lambda:Path(t.name).unlink(missing_ok=True));return Path(t.name)
 def test_valid(self):self.assertEqual(m.verify_certificate(self.write(valid())).status,"VERIFIED")
 def test_frozen_contract_matches_discovery_source(self):
  tree=ast.parse(Path(__file__).with_name("discover_lifecycle.py").read_text(encoding="utf-8"));values={}
  def static_value(node):
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="frozenset" and len(node.args)==1 and not node.keywords:return frozenset(ast.literal_eval(node.args[0]))
   if isinstance(node,ast.Dict):return {ast.literal_eval(key):static_value(value) for key,value in zip(node.keys,node.values)}
   return ast.literal_eval(node)
  for node in tree.body:
   if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in {"CERTIFICATE_V1_ROUTES","MARKER_ORDER","MARKER_CANDIDATES"}:
    values[node.targets[0].id]=static_value(node.value)
  self.assertEqual(values["CERTIFICATE_V1_ROUTES"],m.V1);self.assertEqual(tuple(values["MARKER_ORDER"]),m.MARKER_ORDER)
  self.assertEqual({key:frozenset(value) for key,value in values["MARKER_CANDIDATES"].items()},m.MARKER_CANDIDATES)
  shapes=json.loads((Path(__file__).with_name("real-task")/"command-shapes.json").read_text(encoding="utf-8"))
  self.assertEqual([shapes["actions"][name]["route"] for name in ("session_prompt","question_reply","permission_reply","stop")],m.V2)
 def test_verifier_import_has_no_discovery_or_sys_path_side_effect(self):
  code=("import importlib.util,json,sys;before=list(sys.path);"
        "s=importlib.util.spec_from_file_location('isolated_verify',sys.argv[1]);"
        "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);"
        "print(json.dumps({'same':before==sys.path,'discover':any(k.startswith('a3_discover') for k in sys.modules)}))")
  result=subprocess.run([sys.executable,"-c",code,str(P)],capture_output=True,text=True,check=True)
  self.assertEqual(json.loads(result.stdout),{"same":True,"discover":False})
 def test_missing(self):self.assertEqual(m.verify_certificate(Path("/no/such")).code,"BLOCKED_CERTIFICATE_MISSING")
 def test_empty(self):self.assertEqual(m.verify_certificate(self.write({})).status,"FAIL")
 def test_schema(self):x=valid();x["schema_version"]="x";self.assertIn("SCHEMA",m.verify_certificate(self.write(x)).code)
 def test_missing_field(self):x=valid();del x["diff_file_count"];self.assertIn("FIELDS",m.verify_certificate(self.write(x)).code)
 def test_extra_field(self):x=valid();x["extra"]=1;self.assertIn("FIELDS",m.verify_certificate(self.write(x)).code)
 def test_events(self):x=valid();x["expected_event_sequence"]=["session.created"]*4;self.assertIn("EVENTS",m.verify_certificate(self.write(x)).code)
 def test_order(self):x=valid();x["expected_event_sequence"][1],x["expected_event_sequence"][2]=x["expected_event_sequence"][2],x["expected_event_sequence"][1];self.assertIn("EVENTS",m.verify_certificate(self.write(x)).code)
 def test_non_ascii(self):x=valid();x["expected_event_sequence"][1]="问";self.assertIn("EVENTS",m.verify_certificate(self.write(x)).code)
 def test_diff_bool(self):x=valid();x["diff_file_count"]=True;self.assertIn("DIFF",m.verify_certificate(self.write(x)).code)
 def test_v1(self):x=valid();x["v1_routes_verified"]=[];self.assertIn("V1",m.verify_certificate(self.write(x)).code)
 def test_v2(self):x=valid();x["v2_routes_verified"]=[];self.assertIn("V2",m.verify_certificate(self.write(x)).code)
 def test_digest(self):x=valid();x["structural_digest"]="0"*64;self.assertIn("DIGEST",m.verify_certificate(self.write(x)).code)
 def test_duplicate(self):
  p=self.write({});p.write_text('{"schema_version":"x","schema_version":"y"}');self.assertIn("DUPLICATE",m.verify_certificate(p).code)
 def test_dir(self):
  with tempfile.TemporaryDirectory()as d:self.assertEqual(m.verify_certificate(Path(d)).status,"BLOCKED")
 def test_symlink_is_blocked_without_following(self):
  target=self.write(valid());link=target.with_name(target.name+"-link");os.symlink(target,link);self.addCleanup(lambda:link.unlink(missing_ok=True));self.assertEqual(m.verify_certificate(link).code,"BLOCKED_CERTIFICATE_MISSING")
 def test_oversize(self):
  p=self.write({});p.write_bytes(b" "+b"x"*(m.MAX_BYTES+1));self.assertIn("SIZE",m.verify_certificate(p).code)
 def test_utf8(self):
  p=self.write({});p.write_bytes(b'\xff');self.assertIn("UTF8",m.verify_certificate(p).code)
 def test_json(self):
  p=self.write({});p.write_text('{');self.assertIn("JSON",m.verify_certificate(p).code)
 def test_cli(self):
  p=self.write(valid());ok=subprocess.run([sys.executable,str(P),str(p)],capture_output=True,text=True);bad=subprocess.run([sys.executable,str(P),"/nope"],capture_output=True,text=True);self.assertEqual((ok.returncode,ok.stdout.strip()),(0,"VERIFIED"));self.assertEqual((bad.returncode,bad.stderr.strip()),(1,"BLOCKED_CERTIFICATE_MISSING"))
if __name__=="__main__":unittest.main()
