#!/usr/bin/env python3
"""Read-only B0c-2 host active-index and rollback lineage verifier."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, sys
from pathlib import Path

SUCCESS="VERIFIED_HOST_ACTIVE_LINEAGE"
BLOCKED="BLOCKED_HOST_ACTIVE_LINEAGE"
MAX=256*1024
ZERO="0"*64
ACTIVE_SCHEMA="nomad.host-artifact-active-index.v1"
PARENT_SCHEMA="nomad.host-artifact-parent-snapshot.v1"
HISTORY_SCHEMA="nomad.host-artifact-history-snapshot.v1"
CANDIDATE_SCHEMA="nomad.host-artifact-candidate-binding.v1"
REQUEST_SCHEMA="nomad.host-artifact-publication-request.v1"
ALLOWLIST_SCHEMA="nomad.host-artifact-rollback-allowlist.v1"
PROTECTED_REF="refs/heads/production/nomad-host"
ACTIVE_FIELDS={"schema_version","operation","active_candidate_id","host_manifest_digest","artifact_raw_sha256","embedded_release_index_digest","bundle_manifest_digest","evidence_manifest_digest","host_approval_digest","host_artifact_sequence","previous_host_active_index_digest","source_commit_oid","expected_parent_oid","rollback_from_active_index_digest","rollback_target_candidate_id","active_index_digest"}
PARENT_FIELDS={"schema_version","expected_parent_oid","protected_ref","repository_object_format","parent_active_index_digest","parent_active_candidate_id","parent_host_artifact_sequence","parent_tree_digest"}
HISTORY_FIELDS={"schema_version","protected_ref","through_active_index_digest","active_candidate_ids","history_digest"}
CANDIDATE_FIELDS={"schema_version","candidate_id","host_manifest_digest","artifact_raw_sha256","embedded_release_index_digest","bundle_manifest_digest","evidence_manifest_digest","host_approval_digest","source_commit_oid","candidate_tree_digest"}
REQUEST_FIELDS={"schema_version","operation","expected_parent_oid","parent_active_index_digest","target_candidate_id","rollback_policy_digest","rollback_reason_digest","external_rollback_allowlist_digest","request_digest"}
ALLOWLIST_FIELDS={"schema_version","protected_ref","allowed_candidate_ids","rollback_policy_digest","allowlist_digest"}

class LineageError(Exception): pass
class DuplicateKey(ValueError): pass
def _pairs(items):
    result={}
    for key,value in items:
        if key in result: raise DuplicateKey
        result[key]=value
    return result
def _canonical(value):
    try:return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    except Exception:raise LineageError from None
def _digest(value):return hashlib.sha256(_canonical(value)).hexdigest()
def _hex(value):return isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def _candidate(value):return isinstance(value,str) and value.startswith("sha256-") and _hex(value[7:])
def _oid(value,object_format):
    length=40 if object_format=="sha1" else 64 if object_format=="sha256" else 0
    return isinstance(value,str) and len(value)==length and all(c in "0123456789abcdef" for c in value)
def _read(path):
    try:
        if not path.is_absolute():raise LineageError
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        with os.fdopen(fd,"rb",closefd=True) as file:
            before=os.fstat(file.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size<=0 or before.st_size>MAX:raise LineageError
            raw=file.read(MAX+1);after=os.fstat(file.fileno())
        current=os.stat(path,follow_symlinks=False)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
        if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(current):raise LineageError
        value=json.loads(raw,object_pairs_hook=_pairs)
        if not isinstance(value,dict) or raw!=_canonical(value):raise LineageError
        return value
    except LineageError:raise
    except Exception:raise LineageError from None
def _sealed(value,fields,schema,digest_field):
    if set(value)!=fields or value.get("schema_version")!=schema:raise LineageError
    core=dict(value);observed=core.pop(digest_field,None)
    if not _hex(observed) or observed!=_digest(core):raise LineageError
def _positive_int(value):return isinstance(value,int) and not isinstance(value,bool) and value>0

def verify_lineage(active_path:Path,parent_path:Path,history_path:Path,candidate_path:Path,request_path:Path,allowlist_path:Path)->None:
    active,parent,history,candidate,request,allowlist=map(_read,(active_path,parent_path,history_path,candidate_path,request_path,allowlist_path))
    _sealed(active,ACTIVE_FIELDS,ACTIVE_SCHEMA,"active_index_digest");_sealed(history,HISTORY_FIELDS,HISTORY_SCHEMA,"history_digest");_sealed(request,REQUEST_FIELDS,REQUEST_SCHEMA,"request_digest");_sealed(allowlist,ALLOWLIST_FIELDS,ALLOWLIST_SCHEMA,"allowlist_digest")
    if set(parent)!=PARENT_FIELDS or parent.get("schema_version")!=PARENT_SCHEMA or set(candidate)!=CANDIDATE_FIELDS or candidate.get("schema_version")!=CANDIDATE_SCHEMA:raise LineageError
    object_format=parent.get("repository_object_format")
    if (parent.get("protected_ref")!=PROTECTED_REF or history.get("protected_ref")!=PROTECTED_REF or allowlist.get("protected_ref")!=PROTECTED_REF or not _oid(parent.get("expected_parent_oid"),object_format) or active.get("expected_parent_oid")!=parent.get("expected_parent_oid") or request.get("expected_parent_oid")!=parent.get("expected_parent_oid")) :raise LineageError
    for value in (parent.get("parent_active_index_digest"),parent.get("parent_tree_digest"),history.get("through_active_index_digest"),candidate.get("candidate_tree_digest"),allowlist.get("rollback_policy_digest")):
        if not _hex(value):raise LineageError
    history_ids=history.get("active_candidate_ids");allowed=allowlist.get("allowed_candidate_ids")
    if not isinstance(history_ids,list) or history_ids!=sorted(set(history_ids)) or not all(_candidate(x) for x in history_ids) or not isinstance(allowed,list) or allowed!=sorted(set(allowed)) or not all(_candidate(x) for x in allowed):raise LineageError
    if history.get("through_active_index_digest")!=parent.get("parent_active_index_digest"):raise LineageError
    candidate_id=candidate.get("candidate_id")
    if not _candidate(candidate_id) or candidate_id!="sha256-"+str(candidate.get("host_manifest_digest")):raise LineageError
    if active.get("active_candidate_id")!=candidate_id or request.get("target_candidate_id")!=candidate_id:raise LineageError
    for field in ("host_manifest_digest","artifact_raw_sha256","embedded_release_index_digest","bundle_manifest_digest","evidence_manifest_digest","host_approval_digest"):
        if not _hex(candidate.get(field)) or active.get(field)!=candidate.get(field):raise LineageError
    if not _oid(candidate.get("source_commit_oid"),object_format) or active.get("source_commit_oid")!=candidate.get("source_commit_oid"):raise LineageError
    parent_sequence=parent.get("parent_host_artifact_sequence");sequence=active.get("host_artifact_sequence")
    if not isinstance(parent_sequence,int) or isinstance(parent_sequence,bool) or parent_sequence<0 or not _positive_int(sequence) or sequence!=parent_sequence+1:raise LineageError
    parent_digest=parent.get("parent_active_index_digest");parent_candidate=parent.get("parent_active_candidate_id")
    first=parent_sequence==0
    if first:
        if parent_digest!=ZERO or parent_candidate is not None or history_ids:raise LineageError
    else:
        if not _hex(parent_digest) or not _candidate(parent_candidate) or parent_candidate not in history_ids:raise LineageError
    if active.get("previous_host_active_index_digest")!=parent_digest or request.get("parent_active_index_digest")!=parent_digest:raise LineageError
    operation=active.get("operation")
    if operation not in ("forward","rollback") or request.get("operation")!=operation:raise LineageError
    if operation=="forward":
        if active.get("rollback_from_active_index_digest") is not None or active.get("rollback_target_candidate_id") is not None or candidate_id in history_ids or candidate_id==parent_candidate:raise LineageError
        if any(request.get(field) is not None for field in ("rollback_policy_digest","rollback_reason_digest","external_rollback_allowlist_digest")):raise LineageError
    else:
        if first or active.get("rollback_from_active_index_digest")!=parent_digest or active.get("rollback_target_candidate_id")!=candidate_id or candidate_id not in history_ids or candidate_id==parent_candidate or candidate_id not in allowed:raise LineageError
        if request.get("rollback_policy_digest")!=allowlist.get("rollback_policy_digest") or request.get("external_rollback_allowlist_digest")!=allowlist.get("allowlist_digest") or not _hex(request.get("rollback_reason_digest")):raise LineageError

def main():
    parser=argparse.ArgumentParser(add_help=False)
    for name in ("active","parent","history","candidate","request","allowlist"):parser.add_argument(name,type=Path)
    try:
        values=parser.parse_args();paths=[(p if p.is_absolute() else Path.cwd()/p).absolute() for p in (values.active,values.parent,values.history,values.candidate,values.request,values.allowlist)];verify_lineage(*paths);print(SUCCESS);return 0
    except (LineageError,SystemExit):print(BLOCKED,file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
