#!/usr/bin/env python3
"""B0c-1b host approval adapter over the shared SSHSIG verifier core."""
from __future__ import annotations
import hashlib,importlib.util,sys,weakref
from dataclasses import dataclass
from pathlib import Path
HERE=Path(__file__).resolve().parent;STOCK=HERE.parent/"stock-opencode"
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
core=load("nomad_shared_signed_record_core",STOCK/"verify_approval_record.py")
HOST_FIELDS=frozenset("schema_version host_manifest_digest artifact_raw_sha256 embedded_release_index_digest bundle_manifest_digest evidence_manifest_digest approval_scope principal issued_at expires_at trust_root_id signing_namespace signature_file".split())
HOST_SPEC=core.RecordSpec("nomad.host-artifact-approval.v1",HOST_FIELDS,"approval_scope","nomad.host-artifact-publication","nomad-host-artifact-publication-v1","nomad.host-artifact-trust-root-policy.v1","host-approval.sshsig")
PRODUCTION_TRUST=HERE/"security/trust/host-artifact"
SUCCESS="VERIFIED_HOST_APPROVAL";BLOCKED="BLOCKED_EXTERNAL_HOST_APPROVAL"
@dataclass(frozen=True)
class HostApprovalVerdict:status:str;code:str
class _OpaqueApproval:
 __slots__=("host_approval_digest","relation","__weakref__")
 def __init__(self,*_):raise TypeError("private verified approval")
 def __setattr__(self,_n,_v):raise TypeError("frozen verified approval")
 def __reduce__(self):raise TypeError("private verified approval")
 def __repr__(self):return f"{type(self).__name__}(<redacted>)"
class _VerifiedProductionHostApproval(_OpaqueApproval):__slots__=()
class _TestProductionHostApproval(_OpaqueApproval):__slots__=()
_PRODUCTION_RESULTS=weakref.WeakKeyDictionary();_TEST_RESULTS=weakref.WeakKeyDictionary()
def _snapshot(value):return (value.host_approval_digest,id(value.relation))
def host_domain(record):return b"nomad-host-artifact-publication\nhost-approval-v1\n"+core.canonical({k:v for k,v in record.items() if k!="signature_file"})+b"\n"
def _binding(record,facts):
 return all(isinstance(getattr(facts,name,None),str) and record.get(field)==getattr(facts,name) for field,name in (("host_manifest_digest","host_manifest_digest"),("artifact_raw_sha256","artifact_raw_sha256"),("embedded_release_index_digest","release_index_digest"),("bundle_manifest_digest","bundle_manifest_digest"),("evidence_manifest_digest","evidence_manifest_digest")))
def _test_approval(record_path,facts):
 value=object.__new__(_TestProductionHostApproval)
 object.__setattr__(value,"relation",facts)
 object.__setattr__(value,"host_approval_digest",hashlib.sha256(core._read(record_path)).hexdigest())
 _TEST_RESULTS[value]=_snapshot(value)
 return value
def _is_verified_production(value):return type(value) is _VerifiedProductionHostApproval and _PRODUCTION_RESULTS.get(value)!=None and _PRODUCTION_RESULTS.get(value)==_snapshot(value)
def _is_verified_test(value):return type(value) is _TestProductionHostApproval and _TEST_RESULTS.get(value)!=None and _TEST_RESULTS.get(value)==_snapshot(value)
def _issue_test_approval(record_path,facts):return _test_approval(record_path,facts)
def _verify(record_path,facts,*,trust_dir,**kwargs):
 verdict=core._verify_signed_record(record_path,spec=HOST_SPEC,binding_cb=lambda record:_binding(record,facts),domain_cb=host_domain,trust_dir=trust_dir,**kwargs)
 return _test_approval(record_path,facts) if verdict.status=="VERIFIED" else HostApprovalVerdict("BLOCKED",BLOCKED)
def verify_host_approval(record_path,facts):
 relation_module=sys.modules.get(type(facts).__module__)
 expected=getattr(relation_module,"_VerifiedProductionHostRelation",None);checker=getattr(relation_module,"_is_verified_production",None)
 if expected is None or type(facts) is not expected or checker is None or not checker(facts):return HostApprovalVerdict("BLOCKED",BLOCKED)
 verdict=core._verify_signed_record(record_path,spec=HOST_SPEC,binding_cb=lambda record:_binding(record,facts),domain_cb=host_domain,trust_dir=PRODUCTION_TRUST)
 if verdict.status!="VERIFIED":return HostApprovalVerdict("BLOCKED",BLOCKED)
 value=object.__new__(_VerifiedProductionHostApproval);object.__setattr__(value,"relation",facts);object.__setattr__(value,"host_approval_digest",hashlib.sha256(core._read(record_path)).hexdigest());_PRODUCTION_RESULTS[value]=_snapshot(value);return value
