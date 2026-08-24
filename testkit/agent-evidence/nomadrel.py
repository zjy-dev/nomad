"""Shared read-only NOMADREL framing and relation parser."""
from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
from typing import Mapping
MAGIC=b"NOMADREL";MAX_ENTRY=512*1024;MAX_ENTRIES=64
OUTER={"outer/bundle-manifest.json","outer/current.json","outer/embedded-meta.json","outer/release-approval-record.json","outer/release-approval-record.sshsig"}
MANIFEST_FIELDS={"schema_version","adapter_id","adapter_version","adapter_contract_digest","approval_scope","reviewed_version","evidence_manifest_digest","approval_record_digest","approval_signature_raw_digest","trust_root_id","adapter_artifacts","bundle_manifest_digest"}
INDEX_FIELDS={"schema_version","active_bundle_id","bundle_manifest_digest","adapter_id","adapter_version","reviewed_version","evidence_manifest_digest","approval_record_digest","previous_release_index_digest","release_sequence","release_index_digest"}
META_FIELDS={"schema_version","source_commit_oid","expected_parent_oid","release_index_digest","bundle_manifest_digest","adapter_id","adapter_version","adapter_contract_digest","reviewed_version","evidence_manifest_digest","approval_record_digest","approval_signature_raw_digest","trust_root_id","metadata_digest"}
APPROVAL_FIELDS={"schema_version","evidence_manifest_digest","reviewed_version","scope","principal","issued_at","expires_at","trust_root_id","signing_namespace","signature_file"}
EVIDENCE_FIELDS={"schema_version","certificate_digest","shape_manifest_digest","certificate_structural_digest","source_binding_digest","historical_certified_launch_provenance_digest","task_spec_digest","fixture_manifest_digest","command_shapes_canonical_digest","rule_config_digest","current_committed_evidence_provenance_digest","reviewed_version","evidence_manifest_digest"}
ARTIFACTS={"lifecycle-certificate.json","lifecycle-shape-manifest.json","lifecycle-evidence-manifest.json"}
OPENCODE_CONTRACT_DIGEST="1461500ae84735435bf448e1f74c8f4e3b5d73ba173c1895b4de46377409fa68"
class ParseError(ValueError):pass
class DuplicateKey(ValueError):pass
def _pairs(items):
 r={}
 for k,v in items:
  if k in r:raise DuplicateKey
  r[k]=v
 return r
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()
def raw_digest(v):return hashlib.sha256(v).hexdigest()
def json_value(raw):
 try:v=json.loads(raw.decode("utf-8"),object_pairs_hook=_pairs)
 except Exception:raise ParseError from None
 if not isinstance(v,dict):raise ParseError
 return v
def hex64(v):return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v)
@dataclass(frozen=True)
class Facts:
 raw:bytes;availability:str;entries:Mapping[str,bytes];source_commit_oid:str|None=None;release_index_digest:str|None=None;bundle_manifest_digest:str|None=None;evidence_manifest_digest:str|None=None;approval_record_digest:str|None=None;approval_signature_raw_digest:str|None=None;trust_root_id:str|None=None;adapter_id:str|None=None;adapter_version:str|None=None;reviewed_version:str|None=None
def parse_at(binary:bytes,start:int)->Facts:
 try:
  if binary[start:start+8]!=MAGIC or start+15>len(binary) or int.from_bytes(binary[start+8:start+10],"big")!=1:raise ParseError
  availability=binary[start+10];count=int.from_bytes(binary[start+11:start+15],"big");cursor=start+15
  if availability==0:
   if count!=0:raise ParseError
   return Facts(binary[start:cursor],"unavailable",{})
  if availability!=1 or not 1<=count<=MAX_ENTRIES:raise ParseError
  entries={};previous=None
  for _ in range(count):
   if cursor+2>len(binary):raise ParseError
   nl=int.from_bytes(binary[cursor:cursor+2],"big");cursor+=2
   if not 1<=nl<=256 or cursor+nl+36>len(binary):raise ParseError
   name=binary[cursor:cursor+nl].decode("ascii");cursor+=nl
   if previous is not None and previous>=name or name in entries or name.count("/")!=1:raise ParseError
   prefix,base=name.split("/");
   if prefix not in ("outer","adapter") or not base or base in (".","..") or any(not(c.isalnum() or c in "._-") for c in base):raise ParseError
   length=int.from_bytes(binary[cursor:cursor+4],"big");cursor+=4
   if not 1<=length<=MAX_ENTRY or cursor+32+length>len(binary):raise ParseError
   wanted=binary[cursor:cursor+32];cursor+=32;data=binary[cursor:cursor+length];cursor+=length
   if hashlib.sha256(data).digest()!=wanted:raise ParseError
   entries[name]=data;previous=name
  if set(entries)!=OUTER|{"adapter/"+x for x in ARTIFACTS}:raise ParseError
  manifest=json_value(entries["outer/bundle-manifest.json"]);index=json_value(entries["outer/current.json"]);meta=json_value(entries["outer/embedded-meta.json"]);approval=json_value(entries["outer/release-approval-record.json"]);evidence=json_value(entries["adapter/lifecycle-evidence-manifest.json"])
  if set(manifest)!=MANIFEST_FIELDS or set(index)!=INDEX_FIELDS or set(meta)!=META_FIELDS or set(approval)!=APPROVAL_FIELDS or set(evidence)!=EVIDENCE_FIELDS:raise ParseError
  if manifest["schema_version"]!="nomad.agent-evidence.bundle-manifest.v1" or index["schema_version"]!="nomad.agent-evidence.release-index.v1" or meta["schema_version"]!="nomad.agent-evidence.embedded-release.v1" or approval["schema_version"]!="nomad.stock-opencode.approval-record.v1" or evidence["schema_version"]!="nomad.stock-opencode.evidence-manifest.v1":raise ParseError
  if manifest["adapter_id"]!="opencode" or manifest["adapter_version"]!="1.18.16" or manifest["adapter_contract_digest"]!=OPENCODE_CONTRACT_DIGEST or manifest["approval_scope"]!="nomad.m2.complete-evidence-bundle" or approval["signing_namespace"]!="nomad-m2-release-authorization-v1" or approval["signature_file"]!="release-approval-record.sshsig":raise ParseError
  def sealed(v,field):
   core=dict(v);observed=core.pop(field,None)
   if not hex64(observed) or observed!=digest(core):raise ParseError
   return observed
  bd=sealed(manifest,"bundle_manifest_digest");rid=sealed(index,"release_index_digest");sealed(meta,"metadata_digest")
  if index["active_bundle_id"]!="sha256-"+bd or index["bundle_manifest_digest"]!=bd or meta["bundle_manifest_digest"]!=bd or meta["release_index_digest"]!=rid:raise ParseError
  descriptors=manifest.get("adapter_artifacts")
  if not isinstance(descriptors,dict) or set(descriptors)!=ARTIFACTS:raise ParseError
  for name in ARTIFACTS:
   desc=descriptors[name];raw=entries["adapter/"+name]
   if not isinstance(desc,dict) or set(desc)!={"size_bytes","raw_sha256"} or type(desc["size_bytes"]) is not int or desc["size_bytes"]!=len(raw) or desc["raw_sha256"]!=raw_digest(raw):raise ParseError
  ard=raw_digest(entries["outer/release-approval-record.json"]);asd=raw_digest(entries["outer/release-approval-record.sshsig"]);emd=manifest["evidence_manifest_digest"]
  repeated=("adapter_id","adapter_version","reviewed_version","evidence_manifest_digest","approval_record_digest")
  if any(index[k]!=manifest[k] for k in repeated) or any(meta[k]!=manifest[k] for k in ("adapter_id","adapter_version","adapter_contract_digest","reviewed_version","evidence_manifest_digest","approval_record_digest","approval_signature_raw_digest","trust_root_id")):raise ParseError
  if manifest["approval_record_digest"]!=ard or manifest["approval_signature_raw_digest"]!=asd or approval["evidence_manifest_digest"]!=emd or approval["reviewed_version"]!=manifest["reviewed_version"] or approval["scope"]!=manifest["approval_scope"] or approval["trust_root_id"]!=manifest["trust_root_id"] or approval["signature_file"]!="release-approval-record.sshsig" or evidence["evidence_manifest_digest"]!=emd or evidence["reviewed_version"]!=manifest["reviewed_version"]:raise ParseError
  source_oid=meta["source_commit_oid"]
  if not all(hex64(x) for x in (rid,bd,emd,ard,asd)) or not isinstance(source_oid,str) or len(source_oid) not in (40,64) or any(c not in "0123456789abcdef" for c in source_oid):raise ParseError
  return Facts(binary[start:cursor],"verified",entries,meta["source_commit_oid"],rid,bd,emd,ard,asd,manifest["trust_root_id"],manifest["adapter_id"],manifest["adapter_version"],manifest["reviewed_version"])
 except ParseError:raise
 except Exception:raise ParseError from None
def extract(binary:bytes)->Facts:
 candidates=[];offset=0
 while True:
  offset=binary.find(MAGIC,offset)
  if offset<0:break
  try:candidates.append(parse_at(binary,offset))
  except ParseError:pass
  offset+=1
 if len(candidates)!=1:raise ParseError
 return candidates[0]
