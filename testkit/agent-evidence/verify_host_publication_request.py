#!/usr/bin/env python3
"""Read-only B0c-3 protected publication request mechanics verifier."""
from __future__ import annotations
import argparse,hashlib,json,os,stat,sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
SUCCESS="VERIFIED_HOST_PROTECTED_PUBLICATION_MECHANICS";BLOCKED="BLOCKED_HOST_PROTECTED_PUBLICATION_MECHANICS";MAX=512*1024;REF="refs/heads/production/nomad-host"
REQUEST_SCHEMA="nomad.host-artifact-publication-request.v1";TREE_SCHEMA="nomad.host-proposed-tree-snapshot.v1";SOURCE_SCHEMA="nomad.host-source-clean-snapshot.v1";LINEAGE_SCHEMA="nomad.host-lineage-verification-snapshot.v1"
REQUEST_FIELDS={"schema_version","operation","protected_ref","repository_object_format","expected_parent_oid","proposed_commit_oid","source_commit_oid","active_index_digest","host_manifest_digest","candidate_id","proposed_tree_digest","proposed_tree_paths_digest","b0c2_request_digest","parent_snapshot_digest","source_snapshot_digest","publication_request_digest"}
TREE_FIELDS={"schema_version","repository_object_format","proposed_commit_oid","expected_parent_oid","source_commit_oid","unique_first_parent_oid","proposed_tree_digest","tree_paths_digest","tree_entries","snapshot_digest"};ENTRY_FIELDS={"path","kind","mode","size_bytes","raw_sha256"}
SOURCE_FIELDS={"schema_version","repository_object_format","source_commit_oid","head_oid","index_tree_digest","worktree_tree_digest","untracked_paths_digest","worktree_clean","index_clean","untracked_clean","cargo_lock_raw_sha256","snapshot_digest"}
LINEAGE_FIELDS={"schema_version","operation","parent_snapshot_digest","active_index_digest","host_manifest_digest","candidate_id","candidate_tree_digest","b0c2_request_digest","host_artifact_sequence","active_index_raw_sha256","active_index_raw_size_bytes","candidate_manifest_raw_sha256","candidate_manifest_size_bytes","expected_build_raw_sha256","expected_build_size_bytes","binary_raw_sha256","binary_size_bytes","reference_raw_sha256","reference_size_bytes","lineage_snapshot_digest"}
class Error(Exception):pass
class Duplicate(ValueError):pass
@dataclass(frozen=True)
class _VerifiedPublicationSnapshots:
 request:object
 tree:object
 source:object
 lineage:object
def pairs(items):
 r={}
 for k,v in items:
  if k in r:raise Duplicate
  r[k]=v
 return r
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()
def hex64(v):return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v)
def candidate(v):return isinstance(v,str) and v.startswith("sha256-") and hex64(v[7:])
def oid(v,fmt):return isinstance(v,str) and len(v)==(40 if fmt=="sha1" else 64 if fmt=="sha256" else 0) and all(c in "0123456789abcdef" for c in v)
def read(path):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
  with os.fdopen(fd,"rb",closefd=True) as f:
   before=os.fstat(f.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=MAX:raise Error
   raw=f.read(MAX+1);after=os.fstat(f.fileno())
  current=os.stat(path,follow_symlinks=False);identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
  if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(current):raise Error
  value=json.loads(raw,object_pairs_hook=pairs)
  if not isinstance(value,dict) or raw!=canonical(value):raise Error
  return value
 except Error:raise
 except Exception:raise Error from None
def sealed(value,fields,schema,name):
 if set(value)!=fields or value.get("schema_version")!=schema:raise Error
 core=dict(value);observed=core.pop(name,None)
 if not hex64(observed) or observed!=digest(core):raise Error
def _freeze(value):
 if isinstance(value,dict):return MappingProxyType({key:_freeze(item) for key,item in value.items()})
 if isinstance(value,list):return tuple(_freeze(item) for item in value)
 return value
def _verify_values(request,tree,source,lineage):
 sealed(request,REQUEST_FIELDS,REQUEST_SCHEMA,"publication_request_digest");sealed(tree,TREE_FIELDS,TREE_SCHEMA,"snapshot_digest");sealed(source,SOURCE_FIELDS,SOURCE_SCHEMA,"snapshot_digest");sealed(lineage,LINEAGE_FIELDS,LINEAGE_SCHEMA,"lineage_snapshot_digest")
 fmt=request.get("repository_object_format");operation=request.get("operation")
 if fmt not in ("sha1","sha256") or operation not in ("forward","rollback") or request.get("protected_ref")!=REF:raise Error
 for value in (request.get("expected_parent_oid"),request.get("proposed_commit_oid"),request.get("source_commit_oid")):
  if not oid(value,fmt):raise Error
 if request["proposed_commit_oid"]==request["expected_parent_oid"]:raise Error
 if any(value.get("repository_object_format")!=fmt for value in (tree,source)):raise Error
 if tree.get("proposed_commit_oid")!=request["proposed_commit_oid"] or tree.get("expected_parent_oid")!=request["expected_parent_oid"] or tree.get("unique_first_parent_oid")!=request["expected_parent_oid"] or tree.get("source_commit_oid")!=request["source_commit_oid"]:raise Error
 if source.get("source_commit_oid")!=request["source_commit_oid"] or source.get("head_oid")!=request["source_commit_oid"] or not all(source.get(k) is True for k in ("worktree_clean","index_clean","untracked_clean")):raise Error
 empty_digest=digest([])
 if source.get("untracked_paths_digest")!=empty_digest or not all(hex64(source.get(k)) for k in ("index_tree_digest","worktree_tree_digest","cargo_lock_raw_sha256")):raise Error
 if request.get("source_snapshot_digest")!=source.get("snapshot_digest"):raise Error
 if request.get("operation")!=lineage.get("operation") or request.get("active_index_digest")!=lineage.get("active_index_digest") or request.get("host_manifest_digest")!=lineage.get("host_manifest_digest") or request.get("candidate_id")!=lineage.get("candidate_id") or request.get("b0c2_request_digest")!=lineage.get("b0c2_request_digest") or request.get("parent_snapshot_digest")!=lineage.get("parent_snapshot_digest"):raise Error
 if not candidate(request.get("candidate_id")) or request["candidate_id"]!="sha256-"+request.get("host_manifest_digest",""):raise Error
 for field in ("active_index_digest","host_manifest_digest","proposed_tree_digest","proposed_tree_paths_digest","b0c2_request_digest","parent_snapshot_digest","source_snapshot_digest"):
  if not hex64(request.get(field)):raise Error
 entries=tree.get("tree_entries")
 if not isinstance(entries,list) or not entries:raise Error
 paths=[]
 candidate_root=f"evidence/host-artifacts/candidates/{request['candidate_id']}"
 expected_modes={"evidence/host-artifacts/current.json":"100644",f"{candidate_root}/nomad-host":"100755",f"{candidate_root}/host-manifest.json":"100644",f"{candidate_root}/expected-build.json":"100644",f"{candidate_root}/evidence-release-reference.json":"100644"}
 observed={}
 for entry in entries:
  if not isinstance(entry,dict) or set(entry)!=ENTRY_FIELDS or entry.get("kind")!="regular" or entry.get("path") in observed or type(entry.get("size_bytes")) is not int or entry["size_bytes"]<=0 or not hex64(entry.get("raw_sha256")):raise Error
  observed[entry["path"]]=entry;paths.append(entry["path"])
 if set(observed)!=set(expected_modes) or any(observed[p]["mode"]!=mode for p,mode in expected_modes.items()) or paths!=sorted(paths):raise Error
 lineage_paths={"active_index":"evidence/host-artifacts/current.json","candidate_manifest":f"{candidate_root}/host-manifest.json","expected_build":f"{candidate_root}/expected-build.json","binary":f"{candidate_root}/nomad-host","reference":f"{candidate_root}/evidence-release-reference.json"}
 for prefix,path in lineage_paths.items():
  raw_sha256=lineage.get(f"{prefix}_raw_sha256");size_bytes=lineage.get("active_index_raw_size_bytes" if prefix=="active_index" else f"{prefix}_size_bytes")
  if not hex64(raw_sha256) or type(size_bytes) is not int or size_bytes<=0 or raw_sha256!=observed[path]["raw_sha256"] or size_bytes!=observed[path]["size_bytes"]:raise Error
 tree_core=[{k:entry[k] for k in sorted(ENTRY_FIELDS)} for entry in entries]
 if tree.get("proposed_tree_digest")!=digest(tree_core) or tree.get("tree_paths_digest")!=digest(paths) or request.get("proposed_tree_digest")!=tree["proposed_tree_digest"] or request.get("proposed_tree_paths_digest")!=tree["tree_paths_digest"]:raise Error
 if lineage.get("candidate_tree_digest")!=digest([entry for entry in tree_core if entry["path"].startswith(candidate_root+"/")]) or not isinstance(lineage.get("host_artifact_sequence"),int) or isinstance(lineage.get("host_artifact_sequence"),bool) or lineage["host_artifact_sequence"]<=0:raise Error
def _read_and_verify(request_path,tree_path,source_path,lineage_path):
 request,tree,source,lineage=map(read,(request_path,tree_path,source_path,lineage_path))
 _verify_values(request,tree,source,lineage)
 return _VerifiedPublicationSnapshots(*map(_freeze,(request,tree,source,lineage)))
def verify(request_path,tree_path,source_path,lineage_path):
 _read_and_verify(request_path,tree_path,source_path,lineage_path)
def main():
 p=argparse.ArgumentParser(add_help=False)
 for n in ("request","tree","source","lineage"):p.add_argument(n,type=Path)
 try:a=p.parse_args();verify(*[(x if x.is_absolute() else Path.cwd()/x).absolute() for x in (a.request,a.tree,a.source,a.lineage)]);print(SUCCESS);return 0
 except (Error,SystemExit):print(BLOCKED,file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
