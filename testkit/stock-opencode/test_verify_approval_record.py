import datetime as dt
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import shutil
from pathlib import Path

HERE=Path(__file__).resolve().parent; P=HERE/"verify_approval_record.py"
s=importlib.util.spec_from_file_location("approval",P); m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
DIGEST="a"*64; VERSION="v0.1.0"

class ApprovalTest(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name);self.trust=self.root/"trust";self.trust.mkdir();self.record=self.root/"approval.json";self.key=self.root/"key"
  subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(self.key)],check=True)
  public=self.key.with_suffix(".pub").read_text().split(); self.principal="release-dri";self.allowed=self.trust/"allowed_signers"
  self.allowed.write_text(f'{self.principal} namespaces="{m.NAMESPACE}" {public[0]} {public[1]}\n')
  self.krl=self.trust/"revoked.krl";subprocess.run(["ssh-keygen","-q","-k","-f",str(self.krl)],check=True)
  fp=subprocess.run(["ssh-keygen","-lf",str(self.key.with_suffix(".pub"))],capture_output=True,text=True,check=True).stdout.split()[1]
  exe=str(Path("/usr/bin/ssh-keygen").resolve());self.policy={"schema_version":"nomad.stock-opencode.trust-root-policy.v1","trust_root_id":"ssh-ed25519:"+fp,"fingerprint":fp,"principal":self.principal,"namespace":m.NAMESPACE,"key_type":"ssh-ed25519","max_validity_seconds":2592000,"clock_skew_seconds":0,"ssh_keygen":{"platform_paths":{"darwin-arm64":[exe],"linux-x86_64":[exe]}},"revocation_policy":{"require_krl":True}}
  (self.trust/"trust-root-policy.json").write_text(json.dumps(self.policy));self.value=self.record_value();self.write_and_sign()
 def record_value(self):
  now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0);return {"schema_version":"nomad.stock-opencode.approval-record.v1","evidence_manifest_digest":DIGEST,"reviewed_version":VERSION,"scope":m.SCOPE,"principal":self.principal,"issued_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+dt.timedelta(days=1)).isoformat().replace("+00:00","Z"),"trust_root_id":self.policy["trust_root_id"],"signing_namespace":m.NAMESPACE,"signature_file":"approval.sig"}
 def write_and_sign(self):
  self.record.write_text(json.dumps(self.value)); data=m.domain(self.value); source=self.root/"payload";source.write_bytes(data)
  subprocess.run(["ssh-keygen","-Y","sign","-f",str(self.key),"-n",m.NAMESPACE,str(source)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
  source.with_suffix(source.suffix+".sig").replace(self.root/self.value["signature_file"])
 def verify(self,**kwargs):
  options={"expected_evidence_manifest_digest":DIGEST,"expected_reviewed_version":VERSION,"trust_dir":self.trust,"platform_id":"darwin-arm64","tool_resolver":lambda _: "/usr/bin/ssh-keygen"};options.update(kwargs)
  return m.verify_approval_record(self.record,**options)
 def test_valid(self): self.assertEqual(self.verify(),m.Verdict("VERIFIED","VERIFIED"))
 def test_bundle_scope_time_and_schema(self):
  for field,value,code in (("evidence_manifest_digest","b"*64,"BUNDLE_BINDING"),("scope","bad","SCOPE"),("expires_at",self.value["issued_at"],"TIME_WINDOW"),("signature_file","../x","FILE_POLICY")):
   with self.subTest(field=field):
    old=self.value[field];self.value[field]=value;self.record.write_text(json.dumps(self.value));self.assertIn(code,self.verify().code);self.value[field]=old;self.write_and_sign()
 def test_bad_signature_and_revocation(self):
  other=self.root/"other";subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(other)],check=True);source=self.root/"other-payload";source.write_bytes(m.domain(self.value));subprocess.run(["ssh-keygen","-Y","sign","-f",str(other),"-n",m.NAMESPACE,str(source)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);source.with_suffix(source.suffix+".sig").replace(self.root/"approval.sig");self.assertEqual(self.verify().code,"FAIL_APPROVAL_SIGNATURE")
  self.write_and_sign();subprocess.run(["ssh-keygen","-q","-k","-u","-f",str(self.krl),str(self.key.with_suffix(".pub"))],check=True);self.assertEqual(self.verify().code,"FAIL_APPROVAL_SIGNATURE")
 def test_allowed_policy_and_tool_fail_closed(self):
  self.allowed.write_text("bad principal ssh-ed25519 xxx\n");self.assertEqual(self.verify().code,"FAIL_APPROVAL_ALLOWED_SIGNERS")
  parts=self.key.with_suffix(".pub").read_text().split();self.allowed.write_text(f'{self.principal} namespaces="{m.NAMESPACE}" {parts[0]} {parts[1]}\n');self.policy["fingerprint"]="SHA256:bad";(self.trust/"trust-root-policy.json").write_text(json.dumps(self.policy));self.assertEqual(self.verify().code,"FAIL_APPROVAL_FINGERPRINT")
  self.assertEqual(self.verify(tool_resolver=lambda _:None).code,"BLOCKED_SSH_KEYGEN_UNAVAILABLE")
 def test_file_safety_and_cli(self):
  self.record.write_bytes(b'{"x":1,"x":2}');self.assertEqual(self.verify().code,"FAIL_APPROVAL_DUPLICATE_KEY");self.write_and_sign()
  result=subprocess.run([sys.executable,str(P),str(self.record),DIGEST,VERSION],capture_output=True,text=True);self.assertEqual(result.returncode,1)
 def test_source_has_no_signing_operation(self):
  text=P.read_text();self.assertNotIn("-Y\",\"sign",text);self.assertNotIn("-t\",\"ed25519",text)
 def test_version_binding(self):
  self.assertEqual(self.verify(expected_reviewed_version='wrong').code,'FAIL_APPROVAL_BUNDLE_BINDING')
 def test_policy_extra_field(self):
  self.policy['extra']=1;(self.trust/'trust-root-policy.json').write_text(json.dumps(self.policy));self.assertEqual(self.verify().code,'FAIL_APPROVAL_TRUST_POLICY')
 def test_policy_platform_rejection(self):
  self.assertEqual(self.verify(platform_id='unsupported').code,'FAIL_APPROVAL_TRUST_POLICY')
 def test_signature_basename_variants(self):
  for name in ('.','..','x/y','x\\y','../approval.sig',''):
   self.value['signature_file']=name;self.record.write_text(json.dumps(self.value));self.assertEqual(self.verify().code,'FAIL_APPROVAL_FILE_POLICY')
  self.value['signature_file']='approval.sig';self.write_and_sign()
 def test_signature_symlink_rejected(self):
  self.record.parent.joinpath('approval.sig').unlink();self.record.parent.joinpath('approval.sig').symlink_to(self.key);self.assertEqual(self.verify().code,'FAIL_APPROVAL_FILE_POLICY')
 def test_allowed_signer_grammar(self):
  parts=self.key.with_suffix('.pub').read_text().split()
  for line in ('', 'a\nb\n', '* namespaces="'+m.NAMESPACE+'" '+parts[0]+' '+parts[1]+'\n', self.principal+' cert-authority '+parts[0]+' '+parts[1]+'\n', self.principal+' namespaces="'+m.NAMESPACE+'" ssh-rsa '+parts[1]+'\n'):
   self.allowed.write_text(line);self.assertEqual(self.verify().code,'FAIL_APPROVAL_ALLOWED_SIGNERS')
  self.write_and_sign()
 def test_record_duplicate_and_extra(self):
  self.record.write_bytes(b'{"schema_version":"x","schema_version":"y"}');self.assertEqual(self.verify().code,'FAIL_APPROVAL_DUPLICATE_KEY');self.record.write_text(json.dumps({**self.value,'extra':1}));self.assertEqual(self.verify().code,'FAIL_APPROVAL_SCHEMA');self.write_and_sign()
 def test_missing_inputs_are_blocked(self):
  self.record.unlink();self.assertEqual(self.verify().code,'BLOCKED_APPROVAL_RECORD_MISSING');self.record_value=self.record_value
 def test_lf_nonzero_is_tool(self):
  class R:
   returncode=255;stdout=b''
  def run(argv,**kwargs): return R()
  self.assertEqual(self.verify(runner=run).code,'FAIL_APPROVAL_TOOL')
 def test_formal_nonzero_is_signature(self):
  calls=[]
  class R:
   returncode=0;stdout=(b'256 '+self.policy['fingerprint'].encode()+b' root (ED25519)')
  class S:
   returncode=255;stdout=b''
  def run(argv,**kwargs): calls.append(argv);return R() if '-lf' in argv else S()
  self.assertEqual(self.verify(runner=run).code,'FAIL_APPROVAL_SIGNATURE')
 def test_formal_oserror_is_tool(self):
  def run(argv,**kwargs):
   if '-lf' in argv:
    class R:returncode=0;stdout=(b'256 '+self.policy['fingerprint'].encode()+b' root (ED25519)')
    return R()
   raise OSError('x')
  self.assertEqual(self.verify(runner=run).code,'FAIL_APPROVAL_TOOL')
 def test_formal_timeout_is_tool(self):
  def run(argv,**kwargs):
   if '-lf' in argv:
    class R:returncode=0;stdout=(b'256 '+self.policy['fingerprint'].encode()+b' root (ED25519)')
    return R()
   raise subprocess.TimeoutExpired(argv,1)
  self.assertEqual(self.verify(runner=run).code,'FAIL_APPROVAL_TOOL')
 def test_formal_signal_is_tool(self):
  def run(argv,**kwargs):
   class R:returncode=(-1 if '-Y' in argv else 0);stdout=(b'' if '-Y' in argv else b'256 '+self.policy['fingerprint'].encode()+b' root (ED25519)')
   return R()
  self.assertEqual(self.verify(runner=run).code,'FAIL_APPROVAL_TOOL')
 def test_snapshots_are_private_and_originals_absent_from_argv(self):
  seen=[];modes=[]
  def audit(paths):
   seen.extend(paths);modes.extend([Path(x).stat().st_mode & 0o777 for x in paths]);self.record.unlink();self.allowed.unlink();self.krl.unlink()
  self.assertEqual(self.verify(audit_hook=lambda paths:audit(paths)).status,'VERIFIED')
  self.assertTrue(seen and modes==[0o600]*len(seen))
 def test_snapshot_argv_and_cleanup(self):
  seen=[];live=[]
  def audit(paths):live.extend(paths)
  class R:returncode=0;stdout=(b'256 '+self.policy['fingerprint'].encode()+b' root (ED25519)')
  def run(argv,**kwargs):seen.append(argv);return R()
  self.verify(runner=run,audit_hook=audit);self.assertTrue(all(not str(self.root) in ' '.join(x) for x in seen if '-Y' in x));self.assertTrue(all(not Path(x).exists() for x in live))
 def test_expected_digest_type_rejected(self): self.assertEqual(self.verify(expected_evidence_manifest_digest='bad').code,'FAIL_APPROVAL_SCHEMA')
 def test_expected_version_bound(self): self.assertEqual(self.verify(expected_reviewed_version='x\n').code,'FAIL_APPROVAL_SCHEMA')
 def test_missing_policy_exact_code(self): (self.trust/'trust-root-policy.json').unlink();self.assertEqual(self.verify().code,'BLOCKED_TRUST_POLICY_MISSING')
 def test_missing_allowed_exact_code(self): self.allowed.unlink();self.assertEqual(self.verify().code,'BLOCKED_ALLOWED_SIGNERS_MISSING')
 def test_missing_krl_exact_code(self): self.krl.unlink();self.assertEqual(self.verify().code,'BLOCKED_REVOCATION_KRL_MISSING')
 def test_formal_stdout_is_devnull(self):
  seen=[]
  class R:returncode=255;stdout=b''
  def run(argv,**kw):seen.append(kw);return R()
  self.verify(runner=run);self.assertTrue(seen)
 def test_cli_wrong_args_stderr(self):
  x=subprocess.run([sys.executable,str(P)],capture_output=True,text=True);self.assertEqual(x.returncode,1);self.assertEqual(x.stdout,'');self.assertIn('BLOCKED_APPROVAL_RECORD_MISSING',x.stderr)
 def test_tampered_api_exact_scope(self):
  self.record.write_text(json.dumps({**self.value,'scope':'bad'}));self.assertEqual(self.verify().code,'FAIL_APPROVAL_SCOPE')
 def test_cleanup_failure_is_controlled(self):
  class C:
   def __enter__(self):self.path=tempfile.mkdtemp();self.test.addCleanup(shutil.rmtree,self.path,True);return self.path
   def __exit__(self,*args):raise OSError('cleanup')
   def __init__(self,test):self.test=test
  self.assertEqual(self.verify(temp_factory=lambda:C(self)).code,'FAIL_APPROVAL_FILE_POLICY')
 def test_cleanup_silent_nonremoval_is_controlled(self):
  class C:
   def __init__(self,test):self.test=test
   def __enter__(self):self.path=tempfile.mkdtemp();self.test.addCleanup(shutil.rmtree,self.path,True);return self.path
   def __exit__(self,*args):return False
  self.assertEqual(self.verify(temp_factory=lambda:C(self)).code,'FAIL_APPROVAL_FILE_POLICY')
 def test_clock_skew_is_hard_bounded(self):
  self.policy['clock_skew_seconds']=301;(self.trust/'trust-root-policy.json').write_text(json.dumps(self.policy));self.assertEqual(self.verify().code,'FAIL_APPROVAL_TRUST_POLICY')
  self.policy['clock_skew_seconds']=300;(self.trust/'trust-root-policy.json').write_text(json.dumps(self.policy));self.write_and_sign();self.assertEqual(self.verify().status,'VERIFIED')
 def test_timestamp_grammar_is_strict_utc_seconds(self):
  for value in ('2026-08-20','2026-08-20T00:00:00+00:00','2026-08-20T00:00:00.123Z'):
   with self.subTest(value=value):
    self.value['issued_at']=value;self.record.write_text(json.dumps(self.value));self.assertEqual(self.verify().code,'FAIL_APPROVAL_TIME_WINDOW')
if __name__=="__main__":unittest.main()
