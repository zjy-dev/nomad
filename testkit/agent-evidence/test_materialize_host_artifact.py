from __future__ import annotations

import copy
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module

host_fixture = load("nomad_host_fixture_materializer_tests", HERE / "test_verify_host_artifact.py")
module = load("nomad_host_materializer_tests", HERE / "materialize_host_artifact.py")


@unittest.skipUnless(sys.platform == "darwin", "initial materializer policy is Darwin")
class HostCandidateMaterializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        host_fixture.HostArtifactVerifierTests.setUpClass()

    def setUp(self):
        self.fixture = host_fixture.HostArtifactVerifierTests(
            "test_real_release_nomad_host_candidate_verifies"
        )
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.temp = tempfile.TemporaryDirectory(prefix="nomad-host-candidate-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name); os.chmod(self.root, 0o700)
        self.candidates = self.root / "candidates"; self.candidates.mkdir(mode=0o700)
        self.reference = self.fixture.root / "reference.json"
        self.reference.write_bytes(module._canonical({
            "schema_version": module.REFERENCE_SCHEMA, "availability": "unavailable"
        }))

    def call(self, **kwargs):
        return module.materialize_host_candidate(
            self.fixture.binary, self.fixture.manifest_path, self.fixture.expected_path,
            self.reference, self.root, **kwargs
        )

    def candidate(self):
        return next(self.candidates.iterdir())

    def test_real_candidate_tree_and_identical_repeat(self):
        self.assertEqual(self.call().code, module.SUCCESS)
        candidate = self.candidate()
        self.assertEqual(set(path.name for path in candidate.iterdir()), {
            "nomad-host", "host-manifest.json", "expected-build.json",
            "evidence-release-reference.json"
        })
        self.assertEqual(oct((candidate / "nomad-host").stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct((candidate / "host-manifest.json").stat().st_mode & 0o777), "0o600")
        proposal = module.verifier._read_json(self.root / "current.json.proposed")[0]
        self.assertEqual(proposal["candidate_id"], candidate.name)
        self.assertEqual(self.call().code, module.SUCCESS)
        self.assertTrue(list(self.root.glob(".candidate-*")))

    def test_existing_tree_bytes_mode_extra_symlink_and_hardlink_collide(self):
        mutators = [
            lambda c: (c / "host-manifest.json").write_bytes(b"{}"),
            lambda c: (c / "nomad-host").chmod(0o600),
            lambda c: (c / "extra").write_bytes(b"x"),
        ]
        for mutate in mutators:
            with self.subTest(mutate=mutate):
                self.tearDownCandidate(); self.assertEqual(self.call().code, module.SUCCESS)
                mutate(self.candidate()); self.assertEqual(self.call().code, module.BLOCKED)

        self.tearDownCandidate(); self.assertEqual(self.call().code, module.SUCCESS)
        target = self.candidate() / "expected-build.json"; raw = target.read_bytes(); target.unlink()
        elsewhere = self.root / "elsewhere"; elsewhere.write_bytes(raw); target.symlink_to(elsewhere)
        self.assertEqual(self.call().code, module.BLOCKED)

        self.tearDownCandidate(); self.assertEqual(self.call().code, module.SUCCESS)
        target = self.candidate() / "expected-build.json"; link = self.root / "hard"; os.link(target, link)
        self.assertEqual(self.call().code, module.BLOCKED)

    def test_existing_candidate_directory_mode_is_exact(self):
        for mode in (0o755,0o710):
            with self.subTest(mode=oct(mode)):
                self.tearDownCandidate();self.assertEqual(self.call().code,module.SUCCESS)
                self.candidate().chmod(mode)
                self.assertEqual(self.call().code,module.BLOCKED)

    def tearDownCandidate(self):
        for path in sorted(self.root.glob(".candidate-*")):
            import shutil; shutil.rmtree(path)
        import shutil
        for path in self.candidates.iterdir(): shutil.rmtree(path)
        proposed = self.root / "current.json.proposed"
        if proposed.exists(): proposed.unlink()

    def test_proposed_index_existing_mismatch_blocks_identical_passes(self):
        self.assertEqual(self.call().code, module.SUCCESS)
        self.assertEqual(self.call().code, module.SUCCESS)
        (self.root / "current.json.proposed").write_bytes(b"{}")
        self.assertEqual(self.call().code, module.PROPOSAL_INCOMPLETE)

    def test_proposed_index_modes_are_exact(self):
        for mode in (0o644, 0o660, 0o700):
            with self.subTest(mode=oct(mode)):
                self.tearDownCandidate(); self.assertEqual(self.call().code, module.SUCCESS)
                proposed=self.root/"current.json.proposed";proposed.chmod(mode)
                self.assertEqual(self.call().code,module.PROPOSAL_INCOMPLETE)

    def test_input_symlink_hardlink_and_verified_reference_block(self):
        original = self.fixture.binary
        alias = self.fixture.root / "binary-alias"; original.rename(alias); original.symlink_to(alias)
        self.assertEqual(self.call().code, module.BLOCKED)
        original.unlink(); alias.rename(original)
        hard = self.fixture.root / "hard"; os.link(original, hard)
        self.assertEqual(self.call().code, module.BLOCKED); hard.unlink()
        self.reference.write_bytes(module._canonical({
            "schema_version":module.REFERENCE_SCHEMA, "availability":"verified",
            "release_index_digest":"1"*64, "bundle_manifest_digest":"2"*64,
            "evidence_manifest_digest":"3"*64, "approval_record_digest":"4"*64,
            "approval_signature_raw_digest":"5"*64
        }))
        self.assertEqual(self.call().code, module.BLOCKED)

    def test_write_fsync_and_publish_faults_block_and_preserve_staging(self):
        with mock.patch.object(module.artifact_fs, "write_exclusive", side_effect=OSError()):
            self.assertEqual(self.call().code, module.BLOCKED)
        with mock.patch.object(module.artifact_fs, "fsync_dir", side_effect=OSError()):
            self.assertEqual(self.call().code, module.BLOCKED)
        self.assertEqual(self.call(publisher=lambda *_: (_ for _ in ()).throw(OSError())).code, module.BLOCKED)
        self.assertTrue(list(self.root.glob(".candidate-*")))

    def test_candidate_published_proposal_failure_is_orphan_and_retry_recovers(self):
        original=module._write_or_compare
        with mock.patch.object(module,"_write_or_compare",side_effect=OSError()):
            self.assertEqual(self.call().code,module.PROPOSAL_INCOMPLETE)
        candidate=self.candidate();self.assertTrue(candidate.is_dir())
        self.assertFalse((self.root/"current.json.proposed").exists())
        with mock.patch.object(module,"_write_or_compare",side_effect=original):
            self.assertEqual(self.call().code,module.SUCCESS)
        self.assertTrue((self.root/"current.json.proposed").is_file())

    def test_darwin_no_replace_error_and_unsupported_platform_block(self):
        source = self.root / ".candidate-test"; source.mkdir(mode=0o700)
        target = self.candidates / ("sha256-" + "a" * 64)
        class Function:
            def __call__(self, *_): return -1
        class Library:
            renamex_np = Function()
        with mock.patch.object(module.ctypes, "get_errno", return_value=5):
            with self.assertRaises(module.MaterializeError):
                module._publish_no_replace(source, target, system="Darwin", machine="arm64", library_factory=lambda *_a, **_k: Library())
        with self.assertRaises(module.MaterializeError):
            module._publish_no_replace(source, target, system="Other", machine="x")

    def test_linux_renameat2_success_eexist_and_errno_matrix(self):
        import shutil,errno
        def make_tree(name):
            path=self.root/name;path.mkdir(mode=0o700)
            for filename,mode in (("nomad-host",0o700),("host-manifest.json",0o600),("expected-build.json",0o600),("evidence-release-reference.json",0o600)):
                item=path/filename;item.write_bytes(filename.encode());item.chmod(mode)
            return path
        calls=[]
        class Function:
            restype=None
            def __init__(self,result,move=False):self.result=result;self.move=move
            def __call__(self,*args):
                calls.append(args)
                if self.move:
                    old=pathlib.Path(bytes(args[2]).decode());new=pathlib.Path(bytes(args[4]).decode());os.rename(old,new)
                return self.result
        class Library:
            def __init__(self,function):self.syscall=function
        source=make_tree(".candidate-linux-success");target=self.candidates/("sha256-"+"b"*64)
        self.assertEqual(module._publish_no_replace(source,target,system="Linux",machine="x86_64",library_factory=lambda *_a,**_k:Library(Function(0,True))),"PUBLISHED_INACTIVE")
        args=calls[-1];self.assertEqual((args[0],args[1],args[3],args[5]),(316,-100,-100,1));self.assertEqual(bytes(args[2]).decode(),str(source.absolute()));self.assertEqual(bytes(args[4]).decode(),str(target.absolute()))
        source=make_tree(".candidate-linux-identical")
        for item in target.iterdir(): (source/item.name).write_bytes(item.read_bytes());(source/item.name).chmod(item.stat().st_mode&0o777)
        with mock.patch.object(module.ctypes,"get_errno",return_value=errno.EEXIST):self.assertEqual(module._publish_no_replace(source,target,system="Linux",machine="x86_64",library_factory=lambda *_a,**_k:Library(Function(-1))),"ALREADY_IDENTICAL")
        (source/"host-manifest.json").write_bytes(b"different")
        with mock.patch.object(module.ctypes,"get_errno",return_value=errno.EEXIST):
            with self.assertRaises(module.MaterializeError):module._publish_no_replace(source,target,system="Linux",machine="x86_64",library_factory=lambda *_a,**_k:Library(Function(-1)))
        shutil.rmtree(source)
        for value in (errno.ENOSYS,getattr(errno,"EOPNOTSUPP",errno.ENOSYS),errno.EXDEV,errno.EACCES,errno.EPERM,errno.EIO):
            source=make_tree(".candidate-linux-error")
            with self.subTest(errno=value),mock.patch.object(module.ctypes,"get_errno",return_value=value):
                with self.assertRaises(module.MaterializeError):module._publish_no_replace(source,self.candidates/("sha256-"+"c"*64),system="Linux",machine="x86_64",library_factory=lambda *_a,**_k:Library(Function(-1)))
            shutil.rmtree(source)

    def test_fresh_import_is_side_effect_free_and_creates_no_cache(self):
        import subprocess
        script=HERE/"materialize_host_artifact.py"
        before={p.relative_to(self.root) for p in self.root.rglob("*")}
        code=("import importlib.util,sys; p=sys.argv[1]; s=importlib.util.spec_from_file_location('isolated_host_materializer',p); "
              "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)")
        result=subprocess.run([sys.executable,"-c",code,str(script)],cwd=self.root,env={"PYTHONDONTWRITEBYTECODE":"1","LC_ALL":"C","LANG":"C"},capture_output=True,text=True)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,"",""))
        self.assertEqual(before,{p.relative_to(self.root) for p in self.root.rglob("*")})
        self.assertFalse(any(p.name=="__pycache__" for p in self.root.rglob("*")))

    def test_cli_tuple_exact(self):
        command = [sys.executable, str(HERE / "materialize_host_artifact.py"),
                   str(self.fixture.binary), str(self.fixture.manifest_path),
                   str(self.fixture.expected_path), str(self.reference), str(self.root)]
        ok = __import__("subprocess").run(command, capture_output=True, text=True)
        self.assertEqual((ok.returncode,ok.stdout,ok.stderr),(0,module.SUCCESS+"\n",""))
        (self.root / "current.json.proposed").write_bytes(b"{}")
        bad = __import__("subprocess").run(command, capture_output=True, text=True)
        self.assertEqual((bad.returncode,bad.stdout,bad.stderr),(1,"",module.PROPOSAL_INCOMPLETE+"\n"))


if __name__ == "__main__": unittest.main()
