import hashlib,importlib.util,json,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location("nomadrel_tests",HERE/"nomadrel.py");m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
def seal(value,field):value={**value,field:m.digest(value)};return value
def frame(entries):
 out=bytearray(b"NOMADREL"+(1).to_bytes(2,"big")+b"\1"+len(entries).to_bytes(4,"big"))
 for name,data in sorted(entries.items()):out+=len(name).to_bytes(2,"big")+name.encode()+len(data).to_bytes(4,"big")+hashlib.sha256(data).digest()+data
 return bytes(out)
def vector():
 evidence={"schema_version":"nomad.stock-opencode.evidence-manifest.v1","certificate_digest":"1"*64,"shape_manifest_digest":"2"*64,"certificate_structural_digest":"3"*64,"source_binding_digest":"4"*64,"historical_certified_launch_provenance_digest":"5"*64,"task_spec_digest":"6"*64,"fixture_manifest_digest":"7"*64,"command_shapes_canonical_digest":"8"*64,"rule_config_digest":"9"*64,"current_committed_evidence_provenance_digest":"a"*64,"reviewed_version":"v1","evidence_manifest_digest":"b"*64};er=m.canonical(evidence);approval={"schema_version":"nomad.stock-opencode.approval-record.v1","evidence_manifest_digest":evidence["evidence_manifest_digest"],"reviewed_version":"v1","scope":"nomad.m2.complete-evidence-bundle","principal":"dri","issued_at":"2026-08-21T00:00:00Z","expires_at":"2026-08-22T00:00:00Z","trust_root_id":"root","signing_namespace":"nomad-m2-release-authorization-v1","signature_file":"release-approval-record.sshsig"};ar=m.canonical(approval);sig=b"sig";cert=b"{}";shape=b"{}";desc=lambda raw:{"raw_sha256":m.raw_digest(raw),"size_bytes":len(raw)}
 manifest=seal({"schema_version":"nomad.agent-evidence.bundle-manifest.v1","adapter_id":"opencode","adapter_version":"1.18.16","adapter_contract_digest":m.OPENCODE_CONTRACT_DIGEST,"approval_scope":approval["scope"],"reviewed_version":"v1","evidence_manifest_digest":evidence["evidence_manifest_digest"],"approval_record_digest":m.raw_digest(ar),"approval_signature_raw_digest":m.raw_digest(sig),"trust_root_id":"root","adapter_artifacts":{"lifecycle-certificate.json":desc(cert),"lifecycle-shape-manifest.json":desc(shape),"lifecycle-evidence-manifest.json":desc(er)}},"bundle_manifest_digest")
 index=seal({"schema_version":"nomad.agent-evidence.release-index.v1","active_bundle_id":"sha256-"+manifest["bundle_manifest_digest"],"bundle_manifest_digest":manifest["bundle_manifest_digest"],"adapter_id":"opencode","adapter_version":"1.18.16","reviewed_version":"v1","evidence_manifest_digest":evidence["evidence_manifest_digest"],"approval_record_digest":m.raw_digest(ar),"previous_release_index_digest":"0"*64,"release_sequence":1},"release_index_digest")
 meta=seal({"schema_version":"nomad.agent-evidence.embedded-release.v1","source_commit_oid":"d"*40,"expected_parent_oid":"e"*40,"release_index_digest":index["release_index_digest"],"bundle_manifest_digest":manifest["bundle_manifest_digest"],"adapter_id":"opencode","adapter_version":"1.18.16","adapter_contract_digest":manifest["adapter_contract_digest"],"reviewed_version":"v1","evidence_manifest_digest":evidence["evidence_manifest_digest"],"approval_record_digest":m.raw_digest(ar),"approval_signature_raw_digest":m.raw_digest(sig),"trust_root_id":"root"},"metadata_digest")
 entries={"adapter/lifecycle-certificate.json":cert,"adapter/lifecycle-evidence-manifest.json":er,"adapter/lifecycle-shape-manifest.json":shape,"outer/bundle-manifest.json":m.canonical(manifest),"outer/current.json":m.canonical(index),"outer/embedded-meta.json":m.canonical(meta),"outer/release-approval-record.json":ar,"outer/release-approval-record.sshsig":sig};return frame(entries),entries
class Tests(unittest.TestCase):
 def test_verified_facts(self):
  raw,_=vector();f=m.extract(b"prefix"+raw+b"suffix");self.assertEqual((f.availability,f.source_commit_oid,f.adapter_id,f.adapter_version),("verified","d"*40,"opencode","1.18.16"))
 def test_relation_mutations_reject(self):
  raw,entries=vector()
  for name in ("outer/current.json","outer/embedded-meta.json","outer/release-approval-record.json","adapter/lifecycle-evidence-manifest.json","outer/release-approval-record.sshsig"):
   changed=dict(entries)
   if name=="outer/current.json":v=m.json_value(changed[name]);v["adapter_version"]="bad";core={k:x for k,x in v.items() if k!="release_index_digest"};v["release_index_digest"]=m.digest(core);changed[name]=m.canonical(v)
   elif name=="outer/embedded-meta.json":v=m.json_value(changed[name]);v["adapter_version"]="bad";core={k:x for k,x in v.items() if k!="metadata_digest"};v["metadata_digest"]=m.digest(core);changed[name]=m.canonical(v)
   else:changed[name]=changed[name]+b" "
   with self.subTest(name=name),self.assertRaises(m.ParseError):m.extract(frame(changed))
 def test_unavailable_and_multiple_candidates(self):
  unavailable=b"NOMADREL\x00\x01\x00\x00\x00\x00\x00";self.assertEqual(m.extract(unavailable).availability,"unavailable")
  with self.assertRaises(m.ParseError):m.extract(unavailable+unavailable)
if __name__=="__main__":unittest.main()
