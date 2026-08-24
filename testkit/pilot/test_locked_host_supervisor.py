from __future__ import annotations

import hashlib
import os
import pickle
import select
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from testkit.pilot import locked_host_supervisor as module
from testkit.pilot.observing_proxy import ObservingProxy


ROOT = Path(__file__).resolve().parents[2]
ADOPTER = ROOT / "connector" / "target" / "debug" / "actual-launch-adopter"
HOST = ROOT / "connector" / "target" / "debug" / "nomad-host"


def facts() -> dict[str, object]:
    return {
        "package_name": "opencode-ai",
        "package_version": "1.18.16",
        "package_lock_raw_digest": "1" * 64,
        "full_locked_dependency_count": 12,
        "full_locked_dependency_digest": "2" * 64,
        "installed_platform_dependency_count": 3,
        "installed_platform_dependency_digest": "3" * 64,
        "entrypoint_realpath": "/locked/node_modules/opencode/bin/opencode",
        "entrypoint_raw_digest": "4" * 64,
        "npm_executable_realpath": "/usr/local/bin/npm",
        "npm_version": "11.12.1",
        "task_spec_digest": "5" * 64,
        "fixture_manifest_digest": "6" * 64,
        "adapter_id": "opencode",
        "adapter_version": "1.18.16",
    }


def launch():
    return module._issue_test_locked_launch(facts())


class StartedProxy:
    def __init__(self) -> None:
        self.root = tempfile.TemporaryDirectory()
        self.proxy = ObservingProxy("http://127.0.0.1:43123", Path(self.root.name), "a" * 64)
        self.proxy.start()

    def close(self) -> None:
        self.proxy.shutdown()
        self.root.cleanup()


@unittest.skipUnless(ADOPTER.is_file(), "build actual-launch-adopter with actual_launch_test_helper")
class RealAdopterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.started = StartedProxy()
        self.addCleanup(self.started.close)

    def test_python_to_rust_three_fd_e2e(self) -> None:
        authorization = module._issue_test_host_authorization(ADOPTER)
        result = module._supervise_test_host(authorization, launch(), self.started.proxy)
        self.assertEqual(result, module.SupervisorResult("VERIFIED", "ADOPTED_ACTUAL_LAUNCH_PROVENANCE"))
        self.assertFalse(any(thread.name.startswith("host-") for thread in threading.enumerate()))

    def test_wrong_payload_is_content_free_blocked_and_reaped(self) -> None:
        value = launch()
        value._measurement._facts["npm_version"] = "wrong"
        result = module._supervise_test_host(
            module._issue_test_host_authorization(ADOPTER),
            value,
            self.started.proxy,
        )
        self.assertEqual(result, module.SupervisorResult("BLOCKED", module.BLOCKED))
        self.assertFalse(any(thread.name.startswith("host-") for thread in threading.enumerate()))

    def test_credential_canary_is_absent_from_host_spawn_surface(self) -> None:
        seen: dict[str, object] = {}
        original = subprocess.Popen

        def capture(*args, **kwargs):
            seen["argv"] = args[0]
            seen["env"] = kwargs.get("env")
            return original(*args, **kwargs)

        canary = "NOMAD_PROVIDER_CREDENTIAL_CANARY_77f8"
        with mock.patch.dict(os.environ, {"PROVIDER_TOKEN": canary}), mock.patch.object(module.subprocess, "Popen", side_effect=capture):
            result = module._supervise_test_host(
                module._issue_test_host_authorization(ADOPTER),
                launch(),
                self.started.proxy,
            )
        self.assertEqual(result.status, "VERIFIED")
        self.assertNotIn(canary, repr(seen))
        self.assertEqual(seen["env"], {"LC_ALL": "C", "LANG": "C", "RUST_BACKTRACE": "0"})
        self.assertEqual(len(seen["argv"]), 5)

    def test_explicitly_inheritable_unrelated_fd_is_not_inherited(self) -> None:
        sentinel_read, sentinel_write = os.pipe()
        os.set_inheritable(sentinel_write, True)
        observed = []
        original = subprocess.Popen

        def inspect(*args, **kwargs):
            process = original(*args, **kwargs)
            os.close(sentinel_write)
            ready, _, _ = select.select([sentinel_read], [], [], 1)
            observed.append(bool(ready) and os.read(sentinel_read, 1) == b"")
            return process

        try:
            with mock.patch.object(module.subprocess, "Popen", side_effect=inspect):
                result = module._supervise_test_host(
                    module._issue_test_host_authorization(ADOPTER), launch(),
                    self.started.proxy,
                )
        finally:
            os.close(sentinel_read)
            try:
                os.close(sentinel_write)
            except OSError:
                pass
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(observed, [True])


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.started = StartedProxy()
        self.addCleanup(self.started.close)

    def test_envelope_exact_shape_claim_and_canonical_payload(self) -> None:
        secret = bytearray(range(32)); run_id = "a" * 64
        envelope, claim = module._test_payload_and_envelope(launch(), run_id, secret)
        self.assertEqual(envelope[:8], b"NOMADALP")
        self.assertEqual(envelope[8:10], b"\0\1")
        size = int.from_bytes(envelope[10:14], "big")
        payload = envelope[78:]
        self.assertEqual(size, len(payload))
        self.assertEqual(envelope[14:46], hashlib.sha256(payload).digest())
        self.assertEqual(payload, module.json.dumps(module.json.loads(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii"))
        expected_claim = hashlib.sha256(module._canonical([b"nomad-c1a-transport-claim-v1", b"\0\1", run_id.encode(), hashlib.sha256(payload).digest()])).hexdigest()
        self.assertEqual(claim, expected_claim)

    def test_private_test_types_are_exact_and_nonserializable(self) -> None:
        with self.assertRaises(TypeError):
            module._TestPublishedHostAuthorization()
        authorization = module._issue_test_host_authorization(ADOPTER) if ADOPTER.is_file() else None
        if authorization is not None:
            with self.assertRaises(TypeError):
                pickle.dumps(authorization)
        value = launch()._measurement
        with self.assertRaises(TypeError):
            pickle.dumps(value)
        self.assertEqual(module.supervise_locked_host(object(), object(), object()), module.SupervisorResult("BLOCKED", module.BLOCKED))

    @unittest.skipUnless(HOST.is_file(), "build default nomad-host")
    def test_normal_unavailable_nomad_host_blocks_exactly(self) -> None:
        result = module._supervise_test_host(
            module._issue_test_host_authorization(HOST, adopter=False),
            launch(),
            self.started.proxy,
        )
        self.assertEqual(result, module.SupervisorResult("BLOCKED", module.BLOCKED))

    def test_output_overflow_and_timeout_are_bounded_and_joined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / "host-helper"
            helper.write_text("#!/bin/sh\nhead -c 8192 /dev/zero\nsleep 30\n")
            helper.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            result = module._supervise_test_host(
                module._issue_test_host_authorization(helper),
                launch(),
                self.started.proxy,
                timeout=6.2,
            )
        self.assertEqual(result, module.SupervisorResult("BLOCKED", module.BLOCKED))
        self.assertFalse(any(thread.name.startswith("host-") for thread in threading.enumerate()))


if __name__ == "__main__":
    unittest.main()
