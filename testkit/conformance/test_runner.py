import json
import tempfile
import unittest
from pathlib import Path

from run import (
    canonical_snapshot_digest,
    semantic_diff,
    validate_adapter_support_matrix,
    validate_contracts,
)


class ConformanceRunnerTest(unittest.TestCase):
    def test_repository_corpus_passes(self):
        root = Path(__file__).resolve().parents[2] / "contracts"
        report = validate_contracts(root)
        self.assertEqual([], report["findings"], report)
        self.assertGreaterEqual(report["trace_count"], 7)

    def test_missing_contracts_has_precise_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            report = validate_contracts(Path(directory))
        self.assertEqual("FAIL", report["status"])
        missing = [finding for finding in report["findings"] if finding["code"] == "E_MISSING"]
        self.assertEqual(6, len(missing))

    def test_semantic_diff_is_deterministic(self):
        expected = {"b": 2, "a": {"x": [1, 2]}}
        actual = {"c": 3, "a": {"x": [1, 4]}}
        self.assertEqual(
            [
                "$.b: missing",
                "$.c: unexpected",
                "$.a.x[1]: expected 2, got 4",
            ],
            semantic_diff(expected, actual),
        )

    def test_duplicate_seq_fails(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "contracts"
            (root / "schemas").mkdir(parents=True)
            (root / "traces").mkdir()
            for source in (repo / "contracts" / "schemas").glob("*.json"):
                (root / "schemas" / source.name).write_bytes(source.read_bytes())
            trace = json.loads((repo / "contracts" / "traces" / "trace-001-normal-completion.json").read_text())
            trace["events"][1]["seq"] = 1
            snapshot_name = "snapshot.json"
            (root / "traces" / "trace.json").write_text(json.dumps(trace))
            (root / "traces" / snapshot_name).write_bytes(
                (repo / "contracts" / "traces" / "snapshot-001-normal-completion.json").read_bytes()
            )
            manifest = {
                "corpus_version": "1.0.0",
                "contract_version": "1.0.0",
                "traces": [{"id": "bad", "file": "trace.json", "expected_snapshot": snapshot_name}],
            }
            (root / "traces" / "manifest.json").write_text(json.dumps(manifest))
            report = validate_contracts(root)
        self.assertTrue(any(item["code"] == "E_EVENT_SEQ" for item in report["findings"]))

    def test_snapshot_digest_is_canonical_and_tamper_evident(self):
        snapshot = {"session_id": "s1", "snapshot_seq": 1, "state_summary": {"a": "值"}}
        digest = canonical_snapshot_digest(snapshot)
        reordered = {"state_summary": {"a": "值"}, "snapshot_seq": 1, "session_id": "s1", "digest": digest}
        self.assertEqual(digest, canonical_snapshot_digest(reordered))
        reordered["state_summary"]["a"] = "changed"
        self.assertNotEqual(digest, canonical_snapshot_digest(reordered))

    def test_repository_support_matrix_passes(self):
        root = Path(__file__).resolve().parents[2] / "contracts"
        findings = []
        validate_adapter_support_matrix(root, findings)
        self.assertEqual([], [finding.__dict__ for finding in findings])

    def test_support_matrix_rejects_false_broad_support_claims(self):
        repo = Path(__file__).resolve().parents[2] / "contracts"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            matrix = json.loads((repo / "adapter_support_matrix.json").read_text())
            matrix["supported_versions"] = ["1.18.16", "2.0.0"]
            matrix["supported_actions"] = ["view", "reply", "deny", "Stop", "allow_once"]
            matrix["no_capability"]["semantics"] = "unavailable"
            matrix["fail_closed"]["unsupported_action_surface"] = "ERR_INTERNAL"
            (root / "adapter_support_matrix.json").write_text(
                json.dumps(matrix, ensure_ascii=False, indent=2)
            )
            findings = []
            validate_adapter_support_matrix(root, findings)
        codes = {finding.code for finding in findings}
        self.assertIn("E_MATRIX_SUPPORTED_VERSIONS", codes)
        self.assertIn("E_MATRIX_ACTIONS", codes)
        self.assertIn("E_MATRIX_NO_CAPABILITY_MODE", codes)
        self.assertIn("E_MATRIX_FAIL_ACTION", codes)


if __name__ == "__main__":
    unittest.main()
