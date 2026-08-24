"""Read-only composition of B0c-1a relation and B0c-1b host approval."""
from __future__ import annotations
import importlib.util,sys
from dataclasses import dataclass
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
relation=load("nomad_relation_for_combiner",HERE/"verify_host_production_relation.py");approval=load("nomad_host_approval_for_combiner",HERE/"verify_host_approval.py")
SUCCESS="VERIFIED_HOST_RELATION_AND_APPROVAL_MECHANICS";BLOCKED="BLOCKED_HOST_RELATION_AND_APPROVAL"
@dataclass(frozen=True)
class Verdict:status:str;code:str
def _combine(relation_call,approval_call):
 try:facts=relation_call()
 except Exception:return Verdict("BLOCKED",BLOCKED)
 if not relation._is_verified_test(facts):return Verdict("BLOCKED",BLOCKED)
 try:result=approval_call(facts)
 except Exception:return Verdict("BLOCKED",BLOCKED)
 return result if approval._is_verified_test(result) else Verdict("BLOCKED",BLOCKED)
def verify(binary,manifest,expected,release_root,sign_result,host_approval):
 try:
  facts=relation.verify(binary,manifest,expected,release_root,sign_result)
  if not relation._is_verified_production(facts):raise ValueError
  result=approval.verify_host_approval(host_approval,facts)
  return result if approval._is_verified_production(result) else Verdict("BLOCKED",BLOCKED)
 except Exception:return Verdict("BLOCKED",BLOCKED)
