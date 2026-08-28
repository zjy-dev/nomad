import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_verify", ROOT / "tools/nomad_web/release_verify.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = module; SPEC.loader.exec_module(module)


def record():
    bundle = "a" * 64
    provenance = {"source_commit": "b" * 40, "dirty": False, "bundle_digest": bundle}
    provenance["provenance_digest"] = module.canonical_digest(provenance)
    facts = {
        "codesign": {"status": "verified", "tool": "codesign", "identity_type": "Developer ID Application", "team_id": "TEAM123456", "certificate_team_id": "TEAM123456", "certificate_sha256": "c" * 64},
        "notary": {"status": "verified", "tool": "xcrun", "status_text": "Accepted"},
        "ticket": {"status": "verified", "tool": "xcrun", "status_text": "Accepted"},
        "staple": {"status": "verified", "tool": "xcrun", "status_text": "Stapled"},
        "spctl": {"status": "verified", "tool": "spctl", "status_text": "Accepted"},
    }
    return {"schema": module.SCHEMA, "policy": {"adapter": "nomad-web", "signing": "developer-id", "distribution": "notarized-stapled"}, "provenance": provenance, "artifacts": {"bundle": {"raw_digest": bundle, "size_bytes": 1}, "mach_o": [{"path_alias": "app", "digest": {"pre": "d" * 64, "post": "e" * 64}, "signed": True}]}, "distribution": {"digest": bundle}, "publication": {"published_digest": bundle, "download_digest": bundle}, "tool_facts": facts}


class ReleaseTrustTests(unittest.TestCase):
    def test_fixture_is_mechanical_only(self):
        verdict = module.verify_record(record())
        self.assertEqual(
            (verdict.status, verdict.code),
            ("NOT_RUN", "PRODUCTION_RELEASE_TRUST_NOT_RUN"),
        )
        self.assertTrue(verdict.mechanical_checks_passed)
        self.assertFalse(verdict.production_ready)

    def test_mechanical_fixture_has_no_success_exit_semantics(self):
        fixture = record()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "release-record.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            output = StringIO()
            with mock.patch.object(
                module,
                "collect_git_facts",
                return_value={
                    "source_commit": fixture["provenance"]["source_commit"],
                    "dirty": False,
                },
            ), redirect_stdout(output):
                exit_code = module.main([str(path)])
        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["code"], "PRODUCTION_RELEASE_TRUST_NOT_RUN")
        self.assertTrue(result["mechanical_checks_passed"])
        self.assertFalse(result["production_ready"])

    def test_tamper_team_notary_staple_download_mismatch(self):
        cases = [("team", "BLOCKED_SIGNING_IDENTITY"), ("certificate", "BLOCKED_SIGNING_IDENTITY"), ("notary", "NOT_RUN_NOTARY"), ("staple", "NOT_RUN_STAPLE"), ("download", "BLOCKED_PUBLICATION_DIGEST")]
        for case, expected in cases:
            item = record()
            with self.subTest(case=case):
                if case == "team": item["tool_facts"]["codesign"]["team_id"] = "BAD"
                elif case == "certificate": item["tool_facts"]["codesign"]["certificate_team_id"] = "DIFFTEAM99"
                elif case == "download": item["publication"]["download_digest"] = "f" * 64
                else: item["tool_facts"][case]["status_text"] = "Rejected" if case == "notary" else "Missing"
                self.assertEqual(module.verify_record(item).code, expected)


if __name__ == "__main__": unittest.main()
