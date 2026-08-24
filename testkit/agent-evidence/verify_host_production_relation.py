#!/usr/bin/env python3
"""Read-only B0c-1a production Host/release relation verifier mechanics."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,stat,sys,weakref
from dataclasses import dataclass
from pathlib import Path
HERE=Path(__file__).resolve().parent
SUCCESS="VERIFIED_HOST_PRODUCTION_RELATION";BLOCKED="BLOCKED_HOST_PRODUCTION_RELATION";MAX=64*1024*1024
EXPECTED_SCHEMA="nomad.nomad-host-expected-build.v1"
EXPECTED_FIELDS={"schema_version","source_commit_oid","cargo_lock_raw_sha256","build_profile","target_triple","rustc_release","rustc_commit_hash","rustc_host","llvm_version","actual_launch_protocol_version"}
# Provisioned only by reviewed production release policy. Caller input can never
# select or replace it. Synthetic tests use the private _verify_with_policy seam.
PRODUCTION_DEVELOPER_ID_POLICY=None
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
nomadrel=load("nomadrel_for_production_relation",HERE/"nomadrel.py");release=load("release_tree_for_production_relation",HERE/"verify_release_bundle.py");host_candidate=load("host_candidate_policy_for_production_relation",HERE/"verify_host_artifact.py")
HOST_FIELDS={"schema_version","artifact_class","artifact_basename","artifact_size_bytes","artifact_raw_sha256","platform","target_triple","source_commit_oid","cargo_lock_raw_sha256","build_profile","rustc_release","rustc_commit_hash","rustc_host","llvm_version","actual_launch_protocol_version","embedded_release","macos_codesign","host_artifact_sequence","previous_host_manifest_digest","host_manifest_digest"}
EMBEDDED_FIELDS={"availability","container_raw_sha256","source_commit_oid","release_index_digest","bundle_manifest_digest","evidence_manifest_digest","approval_record_digest","approval_signature_raw_digest","trust_root_id","adapter_id","adapter_version","reviewed_version"}
SIGN_FIELDS={"mode","format","identifier","team_id","signing_identity","cdhash","full_cdhash","designated_requirement_digest","executable_vnode_digest"}
class Error(Exception):pass
class Duplicate(ValueError):pass
def pairs(items):
 r={}
 for k,v in items:
  if k in r:raise Duplicate
  r[k]=v
 return r
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def hex64(v):return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v)
def read(path,limit=256*1024):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
  with os.fdopen(fd,"rb",closefd=True) as f:
   before=os.fstat(f.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=limit:raise Error
   raw=f.read(limit+1);after=os.fstat(f.fileno())
  current=os.stat(path,follow_symlinks=False);identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
  if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(current):raise Error
  return raw
 except Error:raise
 except Exception:raise Error from None
def read_json(path):
 raw=read(path);
 try:v=json.loads(raw,object_pairs_hook=pairs)
 except Exception:raise Error from None
 if not isinstance(v,dict) or raw!=canonical(v):raise Error
 return v
@dataclass(frozen=True)
class RelationFacts:
 host_manifest_digest:str;artifact_raw_sha256:str;release_index_digest:str;bundle_manifest_digest:str;evidence_manifest_digest:str;approval_record_digest:str;approval_signature_raw_digest:str
class _OpaqueRelation:
 __slots__=("host_manifest_digest","artifact_raw_sha256","release_index_digest","bundle_manifest_digest","evidence_manifest_digest","approval_record_digest","approval_signature_raw_digest","source_commit_oid","host_artifact_sequence","executable_vnode_digest","binary_path","__weakref__")
 def __init__(self,*_):raise TypeError("private verified relation")
 def __setattr__(self,_n,_v):raise TypeError("frozen verified relation")
 def __reduce__(self):raise TypeError("private verified relation")
 def __repr__(self):return f"{type(self).__name__}(<redacted>)"
class _VerifiedProductionHostRelation(_OpaqueRelation):__slots__=()
class _TestProductionHostRelation(_OpaqueRelation):__slots__=()
_PRODUCTION_RESULTS=weakref.WeakKeyDictionary();_TEST_RESULTS=weakref.WeakKeyDictionary()
def _snapshot(value):return tuple(getattr(value,name) for name in _OpaqueRelation.__slots__ if name!="__weakref__")
def _test_result(values):
 value=object.__new__(_TestProductionHostRelation)
 for name,item in values.items():object.__setattr__(value,name,item)
 _TEST_RESULTS[value]=_snapshot(value)
 return value
def _is_verified_production(value):return type(value) is _VerifiedProductionHostRelation and _PRODUCTION_RESULTS.get(value)!=None and _PRODUCTION_RESULTS.get(value)==_snapshot(value)
def _is_verified_test(value):return type(value) is _TestProductionHostRelation and _TEST_RESULTS.get(value)!=None and _TEST_RESULTS.get(value)==_snapshot(value)
def _issue_test_relation(values):return _test_result(values)
def _verify_relation_values(binary_path,host_manifest_path,expected_path,release_root,sign_result_path,policy):
 host=read_json(host_manifest_path);expected=read_json(expected_path);result=read_json(sign_result_path)
 if set(expected)!=EXPECTED_FIELDS or expected.get("schema_version")!=EXPECTED_SCHEMA:raise Error
 try:host_candidate._validate_expected(expected)
 except Exception:raise Error from None
 if set(host)!=HOST_FIELDS or host.get("schema_version")!="nomad.nomad-host-artifact.v1" or host.get("artifact_class")!="production-developer-id" or host.get("artifact_basename")!="nomad-host" or binary_path.name!="nomad-host":raise Error
 core=dict(host);observed=core.pop("host_manifest_digest",None)
 if not hex64(observed) or observed!=hashlib.sha256(canonical(core)).hexdigest():raise Error
 binary=read(binary_path,MAX);facts=nomadrel.extract(binary)
 if facts.availability!="verified" or host.get("artifact_size_bytes")!=len(binary) or host.get("artifact_raw_sha256")!=hashlib.sha256(binary).hexdigest():raise Error
 embedded=host.get("embedded_release")
 if not isinstance(embedded,dict) or set(embedded)!=EMBEDDED_FIELDS or embedded.get("availability")!="verified":raise Error
 mapping={"container_raw_sha256":hashlib.sha256(facts.raw).hexdigest(),"source_commit_oid":facts.source_commit_oid,"release_index_digest":facts.release_index_digest,"bundle_manifest_digest":facts.bundle_manifest_digest,"evidence_manifest_digest":facts.evidence_manifest_digest,"approval_record_digest":facts.approval_record_digest,"approval_signature_raw_digest":facts.approval_signature_raw_digest,"trust_root_id":facts.trust_root_id,"adapter_id":facts.adapter_id,"adapter_version":facts.adapter_version,"reviewed_version":facts.reviewed_version}
 if any(embedded.get(k)!=v for k,v in mapping.items()) or host.get("source_commit_oid")!=facts.source_commit_oid:raise Error
 for field in ("source_commit_oid","cargo_lock_raw_sha256","build_profile","target_triple","rustc_release","rustc_commit_hash","rustc_host","llvm_version","actual_launch_protocol_version"):
  if host.get(field)!=expected.get(field):raise Error
 cdhash=result.get("cdhash")
 if set(result)!=SIGN_FIELDS or set(policy)!=SIGN_FIELDS or result!=policy or host.get("macos_codesign")!=result or result.get("mode")!="developer-id" or result.get("format")!="Mach-O thin (arm64)" or not isinstance(cdhash,str) or len(cdhash)!=40 or any(c not in "0123456789abcdef" for c in cdhash) or not all(hex64(result.get(k)) for k in ("full_cdhash","designated_requirement_digest","executable_vnode_digest")):raise Error
 root_before=release._directory_identity(release_root);index,index_raw=release._read_json(release_root/release.INDEX_NAME)
 if root_before is None or not release._valid_index(index):raise Error
 bundle=release_root/release.BUNDLES_NAME/index["active_bundle_id"];snapshot=release._immutable_bundle_snapshot(bundle)
 if snapshot is None:raise Error
 index_after,index_after_raw=release._read_json(release_root/release.INDEX_NAME)
 if index_after!=index or index_after_raw!=index_raw or release._directory_identity(release_root)!=root_before:raise Error
 pairs_to_compare={"outer/current.json":index_raw,"outer/bundle-manifest.json":snapshot[release.MANIFEST_NAME],"outer/release-approval-record.json":snapshot[release.APPROVAL_NAME],"outer/release-approval-record.sshsig":snapshot[release.SIGNATURE_NAME]}
 for name,raw in pairs_to_compare.items():
  if facts.entries.get(name)!=raw:raise Error
 for name in release.OPENCODE_POLICY["artifacts"]:
  if facts.entries.get("adapter/"+name)!=snapshot.get("adapter/"+name):raise Error
 if index["release_index_digest"]!=facts.release_index_digest or index["bundle_manifest_digest"]!=facts.bundle_manifest_digest or index["evidence_manifest_digest"]!=facts.evidence_manifest_digest or index["approval_record_digest"]!=facts.approval_record_digest:raise Error
 return {"host_manifest_digest":observed,"artifact_raw_sha256":host["artifact_raw_sha256"],"release_index_digest":facts.release_index_digest,"bundle_manifest_digest":facts.bundle_manifest_digest,"evidence_manifest_digest":facts.evidence_manifest_digest,"approval_record_digest":facts.approval_record_digest,"approval_signature_raw_digest":facts.approval_signature_raw_digest,"source_commit_oid":host["source_commit_oid"],"host_artifact_sequence":host["host_artifact_sequence"],"executable_vnode_digest":result["executable_vnode_digest"],"binary_path":binary_path.resolve(strict=True)}
def _verify_with_policy(binary_path,host_manifest_path,expected_path,release_root,sign_result_path,policy):
 return _test_result(_verify_relation_values(binary_path,host_manifest_path,expected_path,release_root,sign_result_path,policy))
def verify(binary_path,host_manifest_path,expected_path,release_root,sign_result_path):
 if PRODUCTION_DEVELOPER_ID_POLICY is None:raise Error
 values=_verify_relation_values(binary_path,host_manifest_path,expected_path,release_root,sign_result_path,PRODUCTION_DEVELOPER_ID_POLICY);value=object.__new__(_VerifiedProductionHostRelation)
 for name,item in values.items():object.__setattr__(value,name,item)
 _PRODUCTION_RESULTS[value]=_snapshot(value);return value
def main():
 p=argparse.ArgumentParser(add_help=False)
 for n in ("binary","host_manifest","expected","release_root","sign_result"):p.add_argument(n,type=Path)
 try:
  a=p.parse_args();paths=[(x if x.is_absolute() else Path.cwd()/x).absolute() for x in (a.binary,a.host_manifest,a.expected,a.release_root,a.sign_result)];verify(*paths);print(SUCCESS);return 0
 except (Error,SystemExit):print(BLOCKED,file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
