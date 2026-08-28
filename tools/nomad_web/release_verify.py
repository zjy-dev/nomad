#!/usr/bin/env python3
"""Fail-closed, read-only release trust verifier scaffold.

This module consumes a canonical, content-free fact record.  It never signs,
notarizes, staples, publishes, downloads, or treats a claimed tool result as
proof.  Missing credentials and ad-hoc/unsigned facts remain NOT_RUN/BLOCK.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HEX64 = re.compile(r"^[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}|[0-9a-f]{64}$")
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
SCHEMA = "nomad.release-trust.v1"


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_digest(value: object) -> str:
    return digest_bytes(canonical_json(value))


@dataclass(frozen=True)
class Verdict:
    status: str
    code: str
    mechanical_checks_passed: bool = False
    production_ready: bool = False


def _hex(value: object) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _oid(value: object) -> bool:
    return isinstance(value, str) and (len(value) in (40, 64)) and bool(re.fullmatch(r"[0-9a-f]+", value))


def _digest_match(value: object, expected: object) -> bool:
    return _hex(value) and value == expected


def _tool_fact(facts: dict[str, Any], name: str) -> bool:
    value = facts.get(name)
    return isinstance(value, dict) and value.get("status") == "verified" and value.get("tool") in {"codesign", "xcrun", "spctl"}


def _required_digest_pair(value: object) -> bool:
    return isinstance(value, dict) and set(value) == {"pre", "post"} and _hex(value["pre"]) and _hex(value["post"]) and value["pre"] != value["post"]


def verify_record(record: object, *, actual_source_commit: str | None = None, dirty: bool | None = None) -> Verdict:
    if not isinstance(record, dict) or set(record) != {"schema", "policy", "provenance", "artifacts", "distribution", "publication", "tool_facts"}:
        return Verdict("BLOCKED", "BLOCKED_RECORD_SHAPE")
    if record.get("schema") != SCHEMA or record.get("policy") != {"adapter": "nomad-web", "signing": "developer-id", "distribution": "notarized-stapled"}:
        return Verdict("BLOCKED", "BLOCKED_TRUST_POLICY")
    provenance = record["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {"source_commit", "dirty", "bundle_digest", "provenance_digest"}:
        return Verdict("BLOCKED", "BLOCKED_PROVENANCE_SHAPE")
    if not _oid(provenance["source_commit"]) or provenance["dirty"] is not False or not _hex(provenance["bundle_digest"]):
        return Verdict("BLOCKED", "BLOCKED_SOURCE_PROVENANCE")
    if actual_source_commit is not None and provenance["source_commit"] != actual_source_commit:
        return Verdict("BLOCKED", "BLOCKED_SOURCE_COMMIT_MISMATCH")
    if dirty is True:
        return Verdict("BLOCKED", "BLOCKED_DIRTY_WORKTREE")
    core = {k: v for k, v in provenance.items() if k != "provenance_digest"}
    if provenance["provenance_digest"] != canonical_digest(core):
        return Verdict("BLOCKED", "BLOCKED_PROVENANCE_DIGEST")
    artifacts = record["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {"bundle", "mach_o"}:
        return Verdict("BLOCKED", "BLOCKED_ARTIFACT_SHAPE")
    bundle = artifacts["bundle"]
    if not isinstance(bundle, dict) or set(bundle) != {"raw_digest", "size_bytes"} or not _hex(bundle["raw_digest"]):
        return Verdict("BLOCKED", "BLOCKED_BUNDLE_DIGEST")
    if bundle["raw_digest"] != provenance["bundle_digest"] or type(bundle["size_bytes"]) is not int or bundle["size_bytes"] <= 0:
        return Verdict("BLOCKED", "BLOCKED_BUNDLE_DIGEST")
    mach_o = artifacts["mach_o"]
    if not isinstance(mach_o, list) or not mach_o or any(not isinstance(x, dict) or set(x) != {"path_alias", "digest", "signed"} or not isinstance(x["path_alias"], str) or not _required_digest_pair(x["digest"]) or x["signed"] is not True for x in mach_o):
        return Verdict("BLOCKED", "BLOCKED_MACH_O_FACTS")
    facts = record["tool_facts"]
    if not isinstance(facts, dict) or not _tool_fact(facts, "codesign"):
        return Verdict("NOT_RUN", "NOT_RUN_CODESIGN")
    signing = facts["codesign"]
    if (
        signing.get("identity_type") != "Developer ID Application"
        or not isinstance(signing.get("team_id"), str)
        or TEAM_ID.fullmatch(signing["team_id"]) is None
        or signing.get("certificate_team_id") != signing.get("team_id")
        or not isinstance(signing.get("certificate_sha256"), str)
        or not _hex(signing["certificate_sha256"])
    ):
        return Verdict("BLOCKED", "BLOCKED_SIGNING_IDENTITY")
    if not _tool_fact(facts, "notary") or facts["notary"].get("status_text") != "Accepted":
        return Verdict("NOT_RUN", "NOT_RUN_NOTARY")
    if not _tool_fact(facts, "ticket") or facts["ticket"].get("status_text") != "Accepted":
        return Verdict("NOT_RUN", "NOT_RUN_TICKET")
    if not _tool_fact(facts, "staple") or facts["staple"].get("status_text") != "Stapled":
        return Verdict("NOT_RUN", "NOT_RUN_STAPLE")
    if not _tool_fact(facts, "spctl") or facts["spctl"].get("status_text") != "Accepted":
        return Verdict("NOT_RUN", "NOT_RUN_SPCTL")
    distribution = record["distribution"]
    publication = record["publication"]
    if not isinstance(distribution, dict) or set(distribution) != {"digest"} or not _digest_match(distribution["digest"], provenance["bundle_digest"]):
        return Verdict("BLOCKED", "BLOCKED_DISTRIBUTION_DIGEST")
    if not isinstance(publication, dict) or set(publication) != {"published_digest", "download_digest"} or not _digest_match(publication["published_digest"], provenance["bundle_digest"]) or not _digest_match(publication["download_digest"], provenance["bundle_digest"]):
        return Verdict("BLOCKED", "BLOCKED_PUBLICATION_DIGEST")
    # This verifier checks only the internal consistency of a supplied record.
    # It does not independently perform the protected production release chain,
    # so mechanically complete input is not release evidence or a success.
    return Verdict(
        "NOT_RUN",
        "PRODUCTION_RELEASE_TRUST_NOT_RUN",
        mechanical_checks_passed=True,
        production_ready=False,
    )


def collect_git_facts(repo: Path) -> dict[str, object]:
    def run(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=repo, text=True, stderr=subprocess.DEVNULL).strip()
    return {"source_commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain", "--untracked-files=all"))}


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    args = parser.parse_args(argv)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    facts = collect_git_facts(Path.cwd())
    verdict = verify_record(record, actual_source_commit=facts["source_commit"], dirty=bool(facts["dirty"]))
    print(json.dumps({"status": verdict.status, "code": verdict.code, "mechanical_checks_passed": verdict.mechanical_checks_passed, "production_ready": verdict.production_ready}, sort_keys=True))
    return 0 if verdict.status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
