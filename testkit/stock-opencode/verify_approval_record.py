#!/usr/bin/env python3
from __future__ import annotations
import base64, datetime as dt, json, os, platform, re, stat, subprocess, sys, tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
ROOT=Path(__file__).resolve().parent; RECORD_PATH=ROOT/'real-task/lifecycle-approval-record.json'; TRUST_DIR=ROOT/'security/trust/b0.3'
MAX_BYTES=128*1024; MAX_OUTPUT=4096; TIMEOUT=5; MAX_VALIDITY=2592000; MAX_CLOCK_SKEW=300
FIELDS=frozenset('schema_version evidence_manifest_digest reviewed_version scope principal issued_at expires_at trust_root_id signing_namespace signature_file'.split())
POLICY_FIELDS=frozenset('schema_version trust_root_id fingerprint principal namespace key_type max_validity_seconds clock_skew_seconds ssh_keygen revocation_policy'.split()); SSH_FIELDS=frozenset('platform_paths'.split())
HEX=re.compile(r'^[0-9a-f]{64}$'); BASENAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'); PRINCIPAL=re.compile(r'^[A-Za-z0-9._@-]{1,128}$'); FP=re.compile(r'^SHA256:[A-Za-z0-9+/]+={0,2}$')
UTC_TIME=re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
NAMESPACE='nomad-m2-release-authorization-v1'; SCOPE='nomad.m2.complete-evidence-bundle'
@dataclass(frozen=True)
class Verdict: status:str; code:str
@dataclass(frozen=True)
class RecordSpec:
 schema_version:str; fields:frozenset[str]; scope_field:str; scope:str; namespace:str; trust_policy_schema:str; signature_file:str|None
class DuplicateKey(ValueError): pass
class NotRegular(OSError): pass
def _pairs(items):
 d={}
 for k,v in items:
  if k in d: raise DuplicateKey(k)
  d[k]=v
 return d
def _read(path,limit=MAX_BYTES):
 fd=os.open(str(path),os.O_RDONLY|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_NOFOLLOW',0)); st=os.fstat(fd)
 try:
  if not stat.S_ISREG(st.st_mode): raise NotRegular(str(path))
  out=b''
  while len(out)<=limit:
   x=os.read(fd,min(65536,limit+1-len(out)))
   if not x:return out
   out+=x
  raise OverflowError
 finally:os.close(fd)
def _json(path):return json.loads(_read(path).decode('utf-8'),object_pairs_hook=_pairs)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def domain(r):return b'nomad-release-authorization\napproval-record-v1\n'+canonical({k:v for k,v in r.items() if k!='signature_file'})+b'\n'
def _missing(k):return Verdict('BLOCKED','BLOCKED_'+k+'_MISSING')
def _time(v):
 if not isinstance(v,str) or not UTC_TIME.fullmatch(v):raise ValueError
 return dt.datetime.fromisoformat(v[:-1]+'+00:00')
def _allowed(s,namespace=NAMESPACE):
 if not isinstance(s,str) or len(s)>MAX_BYTES or len([x for x in s.splitlines() if x.strip() and not x.lstrip().startswith('#')])!=1:raise ValueError
 p=s.splitlines();line=next(x for x in p if x.strip() and not x.lstrip().startswith('#')); parts=line.split(' ')
 if len(parts)!=4 or any(not x for x in parts):raise ValueError
 principal,opt,typ,key=parts
 if not PRINCIPAL.fullmatch(principal) or any(x in principal for x in ',*?[]') or opt!=f'namespaces="{namespace}"' or typ!='ssh-ed25519':raise ValueError
 try:raw=base64.b64decode(key,validate=True)
 except Exception:raise ValueError from None
 if len(raw)!=51 or raw[:4]!=b'\0\0\0\x0b' or raw[4:15]!=b'ssh-ed25519' or raw[15:19]!=b'\0\0\0\x20':raise ValueError
 return principal,f'{typ} {key}\n'
def _run(argv,*,input=b'',runner=subprocess.run,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL):
 try:
  if runner is subprocess.run and stdout is subprocess.PIPE:
   with tempfile.TemporaryFile() as f:
    result=runner(argv,input=input,stdout=f,stderr=stderr,timeout=TIMEOUT,check=False);f.seek(0);result.stdout=f.read(MAX_OUTPUT+1)
    if len(result.stdout)>MAX_OUTPUT: return result
    return result
  return runner(argv,input=input,stdout=stdout,stderr=stderr,timeout=TIMEOUT,check=False)
 except (OSError,subprocess.TimeoutExpired):return None
def _fp(exe,pub_path,runner):
 r=_run([exe,'-lf',str(pub_path)],runner=runner)
 if r is None or r.returncode!=0 or not isinstance(r.stdout,bytes) or len(r.stdout)>MAX_OUTPUT:raise RuntimeError
 w=r.stdout.decode('ascii').strip().split()
 if len(w)<2 or not FP.fullmatch(w[1]):raise RuntimeError
 return w[1]
def _platform():
 return 'darwin-arm64' if platform.system()=='Darwin' and platform.machine()=='arm64' else 'linux-x86_64' if platform.system()=='Linux' and platform.machine()=='x86_64' else None
def _fd_bytes(fd,limit=MAX_BYTES):
 out=b''
 while len(out)<=limit:
  x=os.read(fd,min(65536,limit+1-len(out)))
  if not x:return out
  out+=x
 raise OverflowError
def _snapshot(root,name,data):
 fd=os.open(str(root/name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_CLOEXEC',0),0o600)
 try:
  pos=0
  while pos<len(data):pos+=os.write(fd,data[pos:])
  os.fsync(fd)
 finally:os.close(fd)
 return root/name
def _verify_signed_record(record_path,*,spec,binding_cb,domain_cb,argument_cb=lambda:True,trust_dir=TRUST_DIR,now=None,platform_id=None,tool_resolver=lambda _: '/usr/bin/ssh-keygen',runner=subprocess.run,temp_factory=tempfile.TemporaryDirectory,audit_hook=None):
 record_path=Path(record_path);trust_dir=Path(trust_dir)
 try:
  r=_json(record_path)
 except FileNotFoundError:return _missing('APPROVAL_RECORD')
 except DuplicateKey:return Verdict('FAIL','FAIL_APPROVAL_DUPLICATE_KEY')
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 if not isinstance(spec,RecordSpec) or not isinstance(r,dict) or set(r)!=spec.fields or r.get('schema_version')!=spec.schema_version:return Verdict('FAIL','FAIL_APPROVAL_SCHEMA')
 try:arguments_ok=argument_cb()
 except Exception:arguments_ok=False
 if any(not isinstance(r.get(k),str) for k in spec.fields) or arguments_ok is not True:return Verdict('FAIL','FAIL_APPROVAL_SCHEMA')
 sig=r.get('signature_file')
 if not isinstance(sig,str) or not BASENAME.fullmatch(sig) or sig in ('.','..') or '/' in sig or '\\' in sig:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 if spec.signature_file is not None and sig!=spec.signature_file:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 parent=Path(record_path).parent; sigpath=parent/sig
 try:sb=_read(sigpath)
 except FileNotFoundError:return _missing('APPROVAL_SIGNATURE')
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 if not sb:return Verdict('FAIL','FAIL_APPROVAL_SIGNATURE')
 try:policy=_json(Path(trust_dir)/'trust-root-policy.json')
 except FileNotFoundError:return _missing('TRUST_POLICY')
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 try:allowed=_read(Path(trust_dir)/'allowed_signers').decode('utf-8')
 except FileNotFoundError:return _missing('ALLOWED_SIGNERS')
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 try:krl=_read(Path(trust_dir)/'revoked.krl')
 except FileNotFoundError:return _missing('REVOCATION_KRL')
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 try:principal,pub=_allowed(allowed,spec.namespace)
 except ValueError:return Verdict('FAIL','FAIL_APPROVAL_ALLOWED_SIGNERS')
 if not isinstance(policy,dict) or set(policy)!=POLICY_FIELDS or policy.get('schema_version')!=spec.trust_policy_schema:return Verdict('FAIL','FAIL_APPROVAL_TRUST_POLICY')
 try:binding_ok=binding_cb(r)
 except Exception:binding_ok=False
 if binding_ok is not True:return Verdict('FAIL','FAIL_APPROVAL_BUNDLE_BINDING')
 if r.get(spec.scope_field)!=spec.scope:return Verdict('FAIL','FAIL_APPROVAL_SCOPE')
 pid=platform_id or _platform(); ssh=policy.get('ssh_keygen')
 if pid is None or r.get('principal')!=principal or r.get('signing_namespace')!=spec.namespace or policy.get('principal')!=principal or policy.get('namespace')!=spec.namespace or policy.get('key_type')!='ssh-ed25519' or policy.get('max_validity_seconds')!=MAX_VALIDITY or type(policy.get('clock_skew_seconds')) is not int or not 0<=policy['clock_skew_seconds']<=MAX_CLOCK_SKEW or policy.get('revocation_policy')!={'require_krl':True}:return Verdict('FAIL','FAIL_APPROVAL_TRUST_POLICY')
 if not isinstance(ssh,dict) or set(ssh)!=SSH_FIELDS or set(ssh.get('platform_paths',{}))!={'darwin-arm64','linux-x86_64'} or not all(isinstance(x,list) and x and all(isinstance(y,str) and os.path.isabs(y) for y in x) for x in ssh.get('platform_paths',{}).values()) or pid not in ssh['platform_paths']:return Verdict('FAIL','FAIL_APPROVAL_TRUST_POLICY')
 exe=tool_resolver(pid)
 if not exe:return Verdict('BLOCKED','BLOCKED_SSH_KEYGEN_UNAVAILABLE')
 try:
  real=os.path.realpath(exe);st=os.stat(real)
  if not stat.S_ISREG(st.st_mode) or not os.access(real,os.X_OK) or real not in ssh['platform_paths'][pid]:raise ValueError
  fp=None
 except RuntimeError:return Verdict('FAIL','FAIL_APPROVAL_TOOL')
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_TRUST_POLICY')
 try:
  issued,expires=_time(r['issued_at']),_time(r['expires_at']);cur=now or dt.datetime.now(dt.timezone.utc);skew=policy['clock_skew_seconds']
  if issued>=expires or (expires-issued).total_seconds()>MAX_VALIDITY or issued>cur+dt.timedelta(seconds=skew) or expires<=cur-dt.timedelta(seconds=skew):raise ValueError
 except Exception:return Verdict('FAIL','FAIL_APPROVAL_TIME_WINDOW')
 context=temp_factory(); td=None; root=None; snapshots=[]; verdict=None; cleanup_error=None
 try:
  td=context.__enter__();root=Path(td);os.chmod(root,0o700)
  if (root.stat().st_mode & 0o777)!=0o700: verdict=Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
  else:
   snap_allowed=_snapshot(root,'allowed_signers',allowed.encode());snap_krl=_snapshot(root,'revoked.krl',krl);snap_sig=_snapshot(root,'approval.sig',sb);snap_pub=_snapshot(root,'expected.pub',pub.encode());snapshots=[snap_allowed,snap_krl,snap_sig,snap_pub]
   if audit_hook:audit_hook([str(snap_allowed),str(snap_krl),str(snap_sig),str(snap_pub)])
   try:fp=_fp(real,snap_pub,runner)
   except RuntimeError:verdict=Verdict('FAIL','FAIL_APPROVAL_TOOL')
   if verdict is None and (policy.get('fingerprint')!=fp or policy.get('trust_root_id')!='ssh-ed25519:'+fp or r.get('trust_root_id')!=policy.get('trust_root_id')):verdict=Verdict('FAIL','FAIL_APPROVAL_FINGERPRINT')
   if verdict is None:
    try:payload=domain_cb(r)
    except Exception:payload=None
    out=None if payload is None else _run([real,'-Y','verify','-f',str(snap_allowed),'-I',principal,'-n',spec.namespace,'-r',str(snap_krl),'-s',str(snap_sig)],input=payload,runner=runner,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    verdict=Verdict('FAIL','FAIL_APPROVAL_TOOL') if out is None or out.returncode<0 else Verdict('VERIFIED','VERIFIED') if out.returncode==0 else Verdict('FAIL','FAIL_APPROVAL_SIGNATURE')
 except Exception:
  verdict=Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 finally:
  try:context.__exit__(None,None,None)
  except Exception:cleanup_error=True
 if root is not None and (root.exists() or any(path.exists() for path in snapshots)):cleanup_error=True
 if cleanup_error:return Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
 return verdict or Verdict('FAIL','FAIL_APPROVAL_FILE_POLICY')
EVIDENCE_SPEC=RecordSpec('nomad.stock-opencode.approval-record.v1',FIELDS,'scope',SCOPE,NAMESPACE,'nomad.stock-opencode.trust-root-policy.v1',None)
def verify_approval_record(record_path=RECORD_PATH,*,expected_evidence_manifest_digest,expected_reviewed_version,trust_dir=TRUST_DIR,now=None,platform_id=None,tool_resolver=lambda _: '/usr/bin/ssh-keygen',runner=subprocess.run,temp_factory=tempfile.TemporaryDirectory,audit_hook=None):
 return _verify_signed_record(record_path,spec=EVIDENCE_SPEC,binding_cb=lambda r:r.get('evidence_manifest_digest')==expected_evidence_manifest_digest and r.get('reviewed_version')==expected_reviewed_version,domain_cb=domain,argument_cb=lambda:isinstance(expected_evidence_manifest_digest,str) and HEX.fullmatch(expected_evidence_manifest_digest) is not None and isinstance(expected_reviewed_version,str) and expected_reviewed_version.isprintable() and 1<=len(expected_reviewed_version)<=256,trust_dir=trust_dir,now=now,platform_id=platform_id,tool_resolver=tool_resolver,runner=runner,temp_factory=temp_factory,audit_hook=audit_hook)
def main():
 if len(sys.argv)!=4:print('BLOCKED_APPROVAL_RECORD_MISSING',file=sys.stderr);return 1
 v=verify_approval_record(Path(sys.argv[1]),expected_evidence_manifest_digest=sys.argv[2],expected_reviewed_version=sys.argv[3]);print(v.code,file=sys.stdout if v.status=='VERIFIED' else sys.stderr);return 0 if v.status=='VERIFIED' else 1
if __name__=='__main__':raise SystemExit(main())
