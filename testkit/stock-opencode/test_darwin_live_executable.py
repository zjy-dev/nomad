from __future__ import annotations

import ast
import ctypes
import errno
import importlib.util
import json
import os
import pickle
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "darwin_live_executable.py"
PROBE = ROOT / "darwin_libproc_abi_probe.c"
ABI = ROOT / "darwin-libproc-abi.json"

spec = importlib.util.spec_from_file_location("nomad_darwin_live_executable", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


@unittest.skipUnless(sys.platform == "darwin", "Darwin-only kernel verifier")
class DarwinLiveExecutableTests(unittest.TestCase):
    def open_executable(self, path: Path):
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        return os.fdopen(descriptor, "rb", closefd=True)

    def launch_sleep(self, path: Path = Path("/bin/sleep")):
        process = subprocess.Popen(
            [str(path), "20"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "LANG": "C"},
        )
        # The production caller invokes the verifier only after OpenCode health.
        # This generic sleep harness has no health route, so bounded-poll the
        # kernel image proof outside the verifier; the verifier remains fail-closed.
        deadline = time.monotonic() + 2
        measurement = None
        while time.monotonic() < deadline:
            probe = self.open_executable(path)
            try:
                measurement = module.verify_live_executable(
                    process, probe, path.parent, os.getpid()
                )
                break
            except module.VerificationError:
                if not probe.closed:
                    probe.close()
                time.sleep(0.01)
        else:
            self.fail("controlled sleep image did not stabilize")
        self.addCleanup(self.stop, process)
        return process, measurement

    @staticmethod
    def stop(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            try:
                os.kill(process.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def assert_blocked(self, function) -> None:
        with self.assertRaises(module.VerificationError) as captured:
            function()
        self.assertEqual(str(captured.exception), module.BLOCKED)
        self.assertNotIn("/bin", repr(captured.exception))

    def test_live_mapped_vnode_matches_owned_executable_fd(self):
        process, measurement = self.launch_sleep()
        self.assertEqual(repr(measurement), "VerifiedLiveExecutable(<redacted>)")
        with self.assertRaises(TypeError):
            pickle.dumps(measurement)
        with self.assertRaises(TypeError):
            type(measurement)(None, None, None)
        with self.assertRaises(module.VerificationError):
            module._bridge_verified_live_executable(
                measurement, lambda **facts: facts, marker="forbidden-export"
            )
        with self.assertRaises(module.VerificationError):
            module._new_locked_launch_measurement_sink(
                module._SINK_TOKEN, lambda **facts: facts
            )
        class DuckSink:
            pass
        with self.assertRaises(module.VerificationError):
            module._bridge_verified_live_executable(measurement, DuckSink())

    def test_wrong_fd_wrong_root_and_exited_process_block(self):
        process, _ = self.launch_sleep()
        self.assert_blocked(lambda: module.verify_live_executable(
            process, self.open_executable(Path("/bin/cat")), Path("/bin"), os.getpid()))
        self.assert_blocked(lambda: module.verify_live_executable(
            process, self.open_executable(Path("/bin/sleep")), Path("/tmp"), os.getpid()))
        process.terminate(); process.wait(timeout=3)
        self.assert_blocked(lambda: module.verify_live_executable(
            process, self.open_executable(Path("/bin/sleep")), Path("/bin"), os.getpid()))

    def test_stopped_process_and_wrong_supervisor_block(self):
        process, _ = self.launch_sleep()
        os.kill(process.pid, signal.SIGSTOP)
        time.sleep(0.05)
        self.assert_blocked(lambda: module.verify_live_executable(
            process, self.open_executable(Path("/bin/sleep")), Path("/bin"), os.getpid()))
        os.kill(process.pid, signal.SIGCONT)
        self.assert_blocked(lambda: module.verify_live_executable(
            process, self.open_executable(Path("/bin/sleep")), Path("/bin"), os.getpid() + 1))

    def test_path_replacement_after_spawn_blocks(self):
        with tempfile.TemporaryDirectory(prefix="nomad-darwin-live-") as directory:
            root = Path(directory)
            target = root / "sleep"
            shutil.copyfile("/bin/sleep", target)
            target.chmod(0o755)
            opened = self.open_executable(target)
            process, _ = self.launch_sleep(Path("/bin/sleep"))
            before = os.fstat(opened.fileno())

            class StableApi:
                def pidinfo(self, pid, flavor, address, output, size):
                    ctypes.set_errno(0)
                    if flavor == 3:
                        value = ctypes.cast(output, ctypes.POINTER(module._ProcBsdInfo)).contents
                        value.pid, value.ppid, value.status = pid, os.getpid(), 3
                        value.start_sec, value.start_usec = 1, 1
                        return ctypes.sizeof(value)
                    if address:
                        ctypes.set_errno(errno.EINVAL)
                        return 0
                    value = ctypes.cast(output, ctypes.POINTER(module._RegionWithPath)).contents
                    value.region.address, value.region.size = 0x1000, 0x1000
                    value.region.protection = 4
                    stat_value = value.vnode_path.vnode.stat
                    stat_value.device, stat_value.inode = before.st_dev, before.st_ino
                    stat_value.size, stat_value.mode = before.st_size, before.st_mode
                    stat_value.mtime = before.st_mtime_ns // 1_000_000_000
                    stat_value.mtime_nsec = before.st_mtime_ns % 1_000_000_000
                    stat_value.ctime = before.st_ctime_ns // 1_000_000_000
                    stat_value.ctime_nsec = before.st_ctime_ns % 1_000_000_000
                    stat_value.generation = getattr(before, "st_gen", 0)
                    return ctypes.sizeof(value)

            replacement = root / "replacement"
            shutil.copyfile("/bin/echo", replacement)
            replacement.chmod(replacement.stat().st_mode | stat.S_IXUSR)
            os.replace(replacement, target)
            self.assert_blocked(lambda: module._verify_live_executable(
                process, opened, root, os.getpid(), ABI, StableApi()))

    def test_abi_artifact_tamper_and_unknown_fields_block(self):
        process, _ = self.launch_sleep()
        for mutate in (
            lambda value: value["structs"]["proc_bsdinfo"].__setitem__("size", 999),
            lambda value: value.__setitem__("unexpected", True),
        ):
            value = json.loads(ABI.read_text())
            mutate(value)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "abi.json"
                path.write_text(json.dumps(value))
                self.assert_blocked(lambda path=path: module._verify_live_executable(
                    process, self.open_executable(Path("/bin/sleep")), Path("/bin"),
                    os.getpid(), path, module._LibProc()))

    def test_region_termination_errno_and_short_return_are_exact(self):
        class Proc:
            pid = 42
        target = module._VnodeIdentity(1, 2, 3, 4, 5, 6, 7, 8, 0o100755)

        class Api:
            def __init__(self, result, error):
                self.result, self.error = result, error
            def pidinfo(self, *_):
                ctypes.set_errno(self.error)
                return self.result

        self.assertEqual(module._regions(Proc(), target, Api(0, errno.EINVAL)), ())
        self.assertEqual(module._regions(Proc(), target, Api(0, 0)), ())
        for api in (Api(0, errno.EIO), Api(1, 0), Api(ctypes.sizeof(module._RegionWithPath) - 1, 0)):
            with self.assertRaises(module.VerificationError):
                module._regions(Proc(), target, api)

    def test_sdk_generator_matches_committed_abi(self):
        clang = shutil.which("clang")
        self.assertIsNotNone(clang)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "probe"
            subprocess.run([clang, "-Wall", "-Wextra", "-Werror", str(PROBE), "-o", str(binary)], check=True)
            lines = subprocess.check_output([str(binary)], text=True).splitlines()
        self.assertEqual(lines, [
            "proc_bsdinfo 136 0 4 12 16 120 128",
            "proc_regioninfo 96 0 16 80 88",
            "vinfo_stat 136 0 4 8 40 48 56 64 88 112",
            "proc_regionwithpathinfo 1272 0 96 96 248",
            "constants 3 8 1 2 3 4 5 4 1024 4",
        ])
        artifact = json.loads(ABI.read_text())
        constants = [int(part) for part in lines[-1].split()[1:]]
        self.assertEqual(constants, [
            artifact["constants"][key] for key in (
                "proc_pid_tbsd_info", "proc_pid_region_path_info", "sidl",
                "srun", "sleep", "sstop", "szomb", "proc_flag_inexit",
                "max_path_len", "vm_prot_execute"
            )
        ])
        self.assertEqual(
            __import__("hashlib").sha256(ABI.read_bytes()).hexdigest(),
            module.ABI_RAW_SHA256,
        )

    def test_production_verifier_has_no_process_creation_or_credentials(self):
        tree = ast.parse(MODULE_PATH.read_text())
        forbidden = {"Popen", "run", "call", "check_output", "check_call",
                     "posix_spawn", "fork", "execve", "system", "getenv"}
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                function = node.func
                calls.add(function.attr if isinstance(function, ast.Attribute) else
                          function.id if isinstance(function, ast.Name) else "")
        self.assertTrue(forbidden.isdisjoint(calls), forbidden & calls)
        source = MODULE_PATH.read_text()
        for sensitive in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                          "GOOGLE_GENERATIVE_AI_API_KEY", "OPENROUTER_API_KEY",
                          "DEEPSEEK_API_KEY"):
            self.assertNotIn(sensitive, source)


if __name__ == "__main__":
    unittest.main()
