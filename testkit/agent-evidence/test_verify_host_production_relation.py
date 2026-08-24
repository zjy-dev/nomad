from __future__ import annotations
import ast, copy, hashlib, importlib.util, json, sys, tempfile, unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
module=load("nomad_host_production_relation_tests",HERE/"verify_host_production_relation.py")
vectors=load("nomadrel_vectors_for_host_relation",HERE/"test_nomadrel.py")

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        container,entries=vectors.vector();facts=module.nomadrel.extract(container)
        self.release_root=self.root/"releases";(self.release_root/"bundles").mkdir(parents=True)
        index=json.loads(entries["outer/current.json"]);bundle=self.release_root/"bundles"/index["active_bundle_id"];adapter=bundle/"adapter";adapter.mkdir(parents=True)
        (self.release_root/"current.json").write_bytes(entries["outer/current.json"]);(bundle/"bundle-manifest.json").write_bytes(entries["outer/bundle-manifest.json"]);(bundle/"release-approval-record.json").write_bytes(entries["outer/release-approval-record.json"]);(bundle/"release-approval-record.sshsig").write_bytes(entries["outer/release-approval-record.sshsig"])
        for name in module.release.OPENCODE_POLICY["artifacts"]:(adapter/name).write_bytes(entries["adapter/"+name])
        self.binary=self.root/"nomad-host";self.binary.write_bytes(b"MACHO"+container+b"TAIL")
        self.policy={"mode":"developer-id","format":"Mach-O thin (arm64)","identifier":"com.example.nomad.host","team_id":"TEAM123456","signing_identity":"Developer ID Application: Example","cdhash":"c"*40,"full_cdhash":"d"*64,"designated_requirement_digest":"e"*64,"executable_vnode_digest":"f"*64}
        self.expected={"schema_version":module.EXPECTED_SCHEMA,"source_commit_oid":facts.source_commit_oid,"cargo_lock_raw_sha256":"1"*64,"build_profile":"release","target_triple":"aarch64-apple-darwin","rustc_release":"1.95.0","rustc_commit_hash":"2"*40,"rustc_host":"aarch64-apple-darwin","llvm_version":"22.1.2","actual_launch_protocol_version":1}
        embedded={"availability":"verified","container_raw_sha256":hashlib.sha256(facts.raw).hexdigest(),"source_commit_oid":facts.source_commit_oid,"release_index_digest":facts.release_index_digest,"bundle_manifest_digest":facts.bundle_manifest_digest,"evidence_manifest_digest":facts.evidence_manifest_digest,"approval_record_digest":facts.approval_record_digest,"approval_signature_raw_digest":facts.approval_signature_raw_digest,"trust_root_id":facts.trust_root_id,"adapter_id":facts.adapter_id,"adapter_version":facts.adapter_version,"reviewed_version":facts.reviewed_version}
        raw=self.binary.read_bytes();core={"schema_version":"nomad.nomad-host-artifact.v1","artifact_class":"production-developer-id","artifact_basename":"nomad-host","artifact_size_bytes":len(raw),"artifact_raw_sha256":hashlib.sha256(raw).hexdigest(),"platform":"darwin-arm64","target_triple":self.expected["target_triple"],"source_commit_oid":self.expected["source_commit_oid"],"cargo_lock_raw_sha256":self.expected["cargo_lock_raw_sha256"],"build_profile":"release","rustc_release":self.expected["rustc_release"],"rustc_commit_hash":self.expected["rustc_commit_hash"],"rustc_host":self.expected["rustc_host"],"llvm_version":self.expected["llvm_version"],"actual_launch_protocol_version":1,"embedded_release":embedded,"macos_codesign":self.policy,"host_artifact_sequence":1,"previous_host_manifest_digest":"0"*64}
        self.host={**core,"host_manifest_digest":hashlib.sha256(module.canonical(core)).hexdigest()};self.paths={k:self.root/(k+".json") for k in ("host","expected","sign")};self.write();self.adapter=adapter
    def write(self):
        self.paths["host"].write_bytes(module.canonical(self.host));self.paths["expected"].write_bytes(module.canonical(self.expected));self.paths["sign"].write_bytes(module.canonical(self.policy))
    def reseal(self):
        core={k:v for k,v in self.host.items() if k!="host_manifest_digest"};self.host["host_manifest_digest"]=hashlib.sha256(module.canonical(core)).hexdigest();self.write()
    def verify(self):return module._verify_with_policy(self.binary,self.paths["host"],self.paths["expected"],self.release_root,self.paths["sign"],self.policy)
    def blocked(self):
        with self.assertRaises(module.Error):self.verify()
    def test_valid_relation(self):
        result=self.verify();self.assertIs(type(result),module._TestProductionHostRelation);self.assertTrue(module._is_verified_test(result));self.assertEqual(result.release_index_digest,self.host["embedded_release"]["release_index_digest"]);self.assertEqual(result.source_commit_oid,self.expected["source_commit_oid"]);self.assertEqual(result.binary_path,self.binary.resolve())
        with self.assertRaises(TypeError):module._TestProductionHostRelation()
        forged=object.__new__(module._TestProductionHostRelation);self.assertFalse(module._is_verified_test(forged))
    def test_binary_manifest_expected_sign_and_release_mutation_block(self):
        base=(copy.deepcopy(self.host),copy.deepcopy(self.expected),copy.deepcopy(self.policy),self.binary.read_bytes(),(self.adapter/"lifecycle-certificate.json").read_bytes())
        for case in range(5):
            self.host,self.expected,self.policy,raw,cert=copy.deepcopy(base[0]),copy.deepcopy(base[1]),copy.deepcopy(base[2]),base[3],base[4];self.binary.write_bytes(raw);(self.adapter/"lifecycle-certificate.json").write_bytes(cert)
            if case==0:self.binary.write_bytes(raw+b"x")
            elif case==1:self.host["embedded_release"]["release_index_digest"]="0"*64;self.reseal()
            elif case==2:self.expected["build_profile"]="debug";self.write()
            elif case==3:self.policy["team_id"]="OTHER";self.write()
            else:(self.adapter/"lifecycle-certificate.json").write_bytes(b"bad")
            self.blocked()
    def test_public_production_policy_absent_blocks(self):
        with self.assertRaises(module.Error):module.verify(self.binary,self.paths["host"],self.paths["expected"],self.release_root,self.paths["sign"])
    def test_release_current_replacement_between_snapshot_reads_blocks(self):
        original=module.release._immutable_bundle_snapshot
        def changing(path):
            result=original(path);current=json.loads((self.release_root/"current.json").read_text());current["reviewed_version"]="changed";(self.release_root/"current.json").write_bytes(module.canonical(current));return result
        with mock.patch.object(module.release,"_immutable_bundle_snapshot",side_effect=changing):
            self.blocked()
    def test_no_git_sign_write_provider_surface(self):
        source=(HERE/"verify_host_production_relation.py").read_text();tree=ast.parse(source);calls={n.func.attr if isinstance(n.func,ast.Attribute) else n.func.id if isinstance(n.func,ast.Name) else "" for n in ast.walk(tree) if isinstance(n,ast.Call)};self.assertTrue(calls.isdisjoint({"Popen","run","system","write","write_text","write_bytes","unlink","rename","replace","getenv"}));self.assertNotIn("API_KEY",source)
if __name__=="__main__":unittest.main()
