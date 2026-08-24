import os
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from testkit.iteration3_receipts import REQUIRED_STAGES, STAGE_BINDINGS

from testkit.pilot.iteration3_real_slice import (
    PINNED_OPENCODE_PACKAGE,
    Outcome,
    REQUIRED_CHECKPOINTS,
    CandidateAttestation,
    assess_real_slice,
    build_opencode_command,
    provider_credential_available,
    redact,
    receipt_digest,
    verify_receipt_store,
    ReceiptVerificationError,
    verify_official_binary,
)


class Iteration3RealSliceTests(unittest.TestCase):
    def _receipt_store(self, directory, *, mutate=None):
        records = []
        aliases = {
            "question_reply": "req-" + "1" * 64,
            "permission_deny": "req-" + "2" * 64,
            "stop": "req-" + "3" * 64,
        }
        for sequence, stage in enumerate(REQUIRED_STAGES, 1):
            role, source = STAGE_BINDINGS[stage]
            subject_alias = next((alias for prefix, alias in aliases.items() if stage.startswith(prefix)), "none")
            record = {
                "schema_version": 1, "run_id": "run_0123456789abcdef", "process_role": role,
                "stage": stage, "sequence": sequence, "timestamp": f"2026-08-19T12:00:{sequence:02d}Z",
                "predecessor_digest": records[-1]["digest"] if records else None, "source": source,
                "status": "completed", "reason_code": "ok",
                "subject_alias": subject_alias,
                "counts": {"upstream_executions": 1 if stage.endswith("_upstream_executed") else 0},
            }
            if stage == "workspace_cleaned":
                record["counts"]["workspace_entries_remaining"] = 0
            if stage == "credential_scope_audit_completed":
                record["counts"]["credential_scope_violations"] = 0
            record["digest"] = receipt_digest(record)
            records.append(record)
        if mutate:
            mutate(records)
        path = Path(directory) / "receipts.ndjson"
        path.write_text("\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")
        return path

    def test_valid_synthetic_receipts_only_produce_internal_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self._receipt_store(directory)
            verified = verify_receipt_store(store, expected_run_id="run_0123456789abcdef")
            self.assertEqual(verified.receipt_count, len(REQUIRED_STAGES))
            result = assess_real_slice(credential_available=True, provenance=self._provenance(), candidate=None, expected_run_id=verified.run_id, receipt_store=store)
        self.assertEqual(result.outcome, Outcome.BLOCKED)
        self.assertIn("BLOCKED_REAL_RECEIPT_INTEGRATION_UNAVAILABLE", result.reason_codes)

    def test_receipt_tamper_reorder_missing_duplicate_and_payload_are_rejected(self):
        cases = {
            "tamper": lambda records: records[0].update(reason_code="changed"),
            "reorder": lambda records: records.__setitem__(slice(0, 2), [records[1], records[0]]),
            "missing": lambda records: records.pop(),
            "duplicate": lambda records: records.append(records[-1].copy()),
            "payload": lambda records: records[0].update(raw_session_id="secret"),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, mutate in cases.items():
                with self.subTest(name=name):
                    with self.assertRaises(ReceiptVerificationError):
                        verify_receipt_store(self._receipt_store(directory, mutate=mutate), expected_run_id="run_0123456789abcdef")

    def test_receipt_process_scope_cleanup_and_execution_invariants_are_rejected(self):
        mutations = {
            "wrong_process": lambda records: records[0].update(process_role="mobile"),
            "duplicate_execution": lambda records: records[9]["counts"].update(upstream_executions=2),
            "unclean_workspace": lambda records: records[-1]["counts"].update(workspace_entries_remaining=1),
            "credential_leak": lambda records: records[-1]["counts"].update(credential_scope_violations=1),
            "secret_key": lambda records: records[0].update(api_key="never"),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    with self.assertRaises(ReceiptVerificationError):
                        verify_receipt_store(self._receipt_store(directory, mutate=mutate), expected_run_id="run_0123456789abcdef")

    def test_receipt_action_pairs_must_match_and_be_distinct(self):
        mutations = {
            "reply_pair_mismatch": lambda records: records[9].update(subject_alias="req-" + "4" * 64),
            "permission_pair_mismatch": lambda records: records[13].update(subject_alias="req-" + "4" * 64),
            "stop_pair_mismatch": lambda records: records[15].update(subject_alias="req-" + "4" * 64),
            "aliases_not_distinct": lambda records: records[12].update(subject_alias=records[8]["subject_alias"]),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    with self.assertRaises(ReceiptVerificationError):
                        verify_receipt_store(self._receipt_store(directory, mutate=mutate), expected_run_id="run_0123456789abcdef")

    def test_missing_credential_is_blocked_not_pass(self):
        result = assess_real_slice(credential_available=False, provenance=None, candidate=None, expected_run_id="nonce")
        self.assertEqual(result.outcome, Outcome.BLOCKED)
        self.assertIn("BLOCKED_PROVIDER_CREDENTIAL_ABSENT", result.reason_codes)

    def test_dry_run_is_skip_even_with_synthetic_claims(self):
        synthetic = self._candidate(source_kind="synthetic")
        result = assess_real_slice(credential_available=True, provenance=None, candidate=synthetic, expected_run_id="nonce", dry_run=True)
        self.assertEqual(result.outcome, Outcome.SKIP)

    def test_synthetic_source_cannot_pass(self):
        result = assess_real_slice(
            credential_available=True,
            provenance=self._provenance(),
            candidate=self._candidate(source_kind="synthetic"), expected_run_id="nonce",
        )
        self.assertEqual(result.outcome, Outcome.FAIL)
        self.assertIn("FAIL_NON_OFFICIAL_SOURCE", result.reason_codes)

    def test_all_true_candidate_is_blocked_without_real_verifier(self):
        result = assess_real_slice(
            credential_available=True,
            provenance=self._provenance(),
            candidate=self._candidate(), expected_run_id="nonce",
        )
        self.assertEqual(result.outcome, Outcome.BLOCKED)
        self.assertIn("BLOCKED_VERIFIER_UNAVAILABLE", result.reason_codes)
        self.assertNotIn("credential", str(result.evidence).lower())

    def test_required_checkpoint_failure_is_fail(self):
        claims = self._claims()
        claims["stop_host_accepted"] = False
        result = assess_real_slice(credential_available=True, provenance=self._provenance(), candidate=self._candidate(claims=claims), expected_run_id="nonce")
        self.assertEqual(result.outcome, Outcome.FAIL)
        self.assertIn("FAIL_CHECKPOINT_STOP_HOST_ACCEPTED", result.reason_codes)

    def test_credential_presence_and_redaction(self):
        self.assertTrue(provider_credential_available("OPENAI_API_KEY", {"OPENAI_API_KEY": " not-logged "}))
        self.assertFalse(provider_credential_available("OPENAI_API_KEY", {}))
        self.assertFalse(provider_credential_available("PROVIDER", {"PROVIDER": "value"}))
        self.assertEqual(redact({"OPENAI_API_KEY": "secret", "detail": "prompt"}), {"OPENAI_API_KEY": "[REDACTED]", "detail": "[REDACTED]"})

    def test_run_id_mismatch_and_missing_claim_fail(self):
        mismatch = assess_real_slice(credential_available=True, provenance=self._provenance(), candidate=self._candidate(run_id="other"), expected_run_id="nonce")
        self.assertIn("FAIL_RUN_ID_MISMATCH", mismatch.reason_codes)
        missing = assess_real_slice(credential_available=True, provenance=self._provenance(), candidate=self._candidate(claims={}), expected_run_id="nonce")
        self.assertEqual(missing.outcome, Outcome.FAIL)

    def test_pinned_command_and_executed_provenance(self):
        self.assertEqual(build_opencode_command()[:3], ["npx", "--yes", PINNED_OPENCODE_PACKAGE])
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "opencode"
            binary.write_text("#!/bin/sh\nprintf 'OpenCode 1.18.16\\n'\n", encoding="utf-8")
            binary.chmod(0o700)
            provenance = verify_official_binary(binary)
            self.assertEqual(provenance.verification_method, "executed_binary")
            with self.assertRaisesRegex(ValueError, "VERSION_MISMATCH"):
                binary.write_text("#!/bin/sh\nprintf 'OpenCode 1.18.15\\n'\n", encoding="utf-8")
                verify_official_binary(binary)

    def test_forged_provenance_fields_never_pass(self):
        good = self._provenance()
        for provenance in (
            type(good)("other@1.18.16", good.version_output, good.sha256, good.verification_method),
            type(good)(good.package, "9.9.9", good.sha256, good.verification_method),
            type(good)(good.package, good.version_output, "not-a-hash", good.verification_method),
        ):
            result = assess_real_slice(credential_available=True, provenance=provenance, candidate=self._candidate(), expected_run_id="nonce")
            self.assertNotEqual(result.outcome, Outcome.PASS)
            self.assertEqual(result.outcome, Outcome.FAIL)

    def test_forged_provenance_is_not_masked_by_absent_driver(self):
        good = self._provenance()
        forged = type(good)(good.package, good.version_output, "not-a-hash", good.verification_method)
        result = assess_real_slice(credential_available=True, provenance=forged, candidate=None, expected_run_id="nonce")
        self.assertEqual(result.outcome, Outcome.FAIL)
        self.assertIn("FAIL_BINARY_PROVENANCE_HASH", result.reason_codes)

    def test_version_command_receives_no_provider_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "opencode"
            binary.write_text(
                "#!/bin/sh\n[ -z \"${OPENAI_API_KEY+x}\" ] || exit 37\nprintf 'OpenCode 1.18.16\\n'\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "do-not-leak"}):
                self.assertEqual(verify_official_binary(binary).verification_method, "executed_binary")

    def test_malicious_version_output_does_not_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "opencode"
            binary.write_text("#!/bin/sh\nprintf 'PRIVATE-PROMPT 1.18.15\\n'\n", encoding="utf-8")
            binary.chmod(0o700)
            with self.assertRaisesRegex(ValueError, "^ERR_OPENCODE_VERSION_MISMATCH$") as error:
                verify_official_binary(binary)
            self.assertNotIn("PRIVATE-PROMPT", str(error.exception))

    def test_cli_blocked_is_nonzero_and_never_echoes_credential(self):
        command = [sys.executable, "testkit/pilot/iteration3_real_slice.py", "--provider-credential-env", "OPENAI_API_KEY"]
        env = dict(os.environ, OPENAI_API_KEY="do-not-leak")
        blocked = subprocess.run(command, cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(blocked.returncode, 1)
        self.assertNotIn("do-not-leak", blocked.stdout + blocked.stderr)
        skipped = subprocess.run(command + ["--dry-run"], cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, env=env, check=False)
        self.assertEqual(skipped.returncode, 0)

    @staticmethod
    def _provenance():
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "opencode"
            binary.write_text("#!/bin/sh\nprintf 'OpenCode 1.18.16\\n'\n", encoding="utf-8")
            binary.chmod(0o700)
            return verify_official_binary(binary)

    @staticmethod
    def _claims():
        return {name: True for name in REQUIRED_CHECKPOINTS}

    @classmethod
    def _candidate(cls, *, run_id="nonce", source_kind="official_stock_runtime", claims=None):
        return CandidateAttestation(run_id, source_kind, True, True, cls._claims() if claims is None else claims)


if __name__ == "__main__":
    unittest.main()
