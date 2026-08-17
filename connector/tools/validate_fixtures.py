#!/usr/bin/env python3
"""
validate_fixtures.py — HC-001 fixture validator for the Nomad OpenCode connector.

Checks:
  1. All fixture files are valid JSON.
  2. Every fixture carries `"label": "synthetic"` (no captured fixtures allowed).
  3. Every fixture carries a `source` block with the required fields.
  4. Every fixture carries a `"fixture": "synthetic"` top-level marker.
  5. The `captured/` directory does not exist (explicit HC-001 constraint).
  6. The provenance.json exists and is internally consistent.
  7. At least 7 fixture targets are covered (session, message, tool, permission, diff, abort, snapshot).
  8. Provenance upstream commit matches fixture source commit.
  9. Fixture `generatedAt` dates exist and are valid ISO dates.
  10. Fixture `label` matches the directory name (`synthetic`).
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

CONNECTOR_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = CONNECTOR_DIR / "fixtures"
SYNTHETIC_DIR = FIXTURES_DIR / "synthetic"
CAPTURED_DIR = FIXTURES_DIR / "captured"
PROVENANCE_FILE = FIXTURES_DIR / "provenance.json"
SCHEMA_DIR = FIXTURES_DIR / "schema"

REQUIRED_TARGETS = {"session", "message", "tool", "permission", "diff", "abort", "snapshot"}
REQUIRED_SOURCE_FIELDS = {"type", "upstream", "commit", "reason", "captureCommand"}


def check_json_file(path):
    """Check that a file exists and contains valid JSON. Returns (data, error_msg)."""
    try:
        with open(path) as f:
            return json.load(f), None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    except FileNotFoundError:
        return None, "File not found"


def validate_provenance(provenance):
    """Validate provenance.json internal consistency."""
    errors = []
    if provenance.get("schema") != "nomad.connector.provenance.v1":
        errors.append("provenance.schema must be 'nomad.connector.provenance.v1'")

    upstream = provenance.get("upstream", {})
    version = upstream.get("version")
    commit = upstream.get("commit")
    tag = upstream.get("tag")

    if not version or not commit:
        errors.append("provenance.upstream.version and .commit are required")
    if tag and tag != f"v{version}":
        errors.append(f"provenance.upstream.tag '{tag}' does not match version 'v{version}'")

    checksums = provenance.get("checksums", {})
    for key in ("sourceTarball", "sourceZipball"):
        entry = checksums.get(key, {})
        if not entry.get("url"):
            errors.append(f"provenance.checksums.{key}.url is required")

    return errors, version, commit


def validate_fixture(filepath, provenance_commit):
    """Validate a single fixture file. Returns list of error strings."""
    errors = []
    data, err = check_json_file(filepath)
    if err:
        return [f"{filepath.relative_to(CONNECTOR_DIR)}: {err}"]

    # Check 1: top-level fixture marker
    if data.get("fixture") != "synthetic":
        errors.append(f"fixture.fixture must be 'synthetic', got '{data.get('fixture')}'")

    # Check 2: label
    label = data.get("label")
    if label != "synthetic":
        errors.append(f"fixture.label must be 'synthetic', got '{label}'")

    # Check 3: target
    target = data.get("target")
    if not target or not isinstance(target, str):
        errors.append("fixture.target is required and must be a string")

    # Check 4: generatedAt
    generated_at = data.get("generatedAt")
    if not generated_at:
        errors.append("fixture.generatedAt is required")
    else:
        try:
            datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"fixture.generatedAt '{generated_at}' is not a valid ISO date")

    # Check 5: source block
    source = data.get("source")
    if not source:
        errors.append("fixture.source block is required")
    else:
        missing = REQUIRED_SOURCE_FIELDS - set(source.keys())
        if missing:
            errors.append(f"fixture.source missing required fields: {sorted(missing)}")
        if source.get("type") != "schema-derived":
            errors.append(f"fixture.source.type must be 'schema-derived', got '{source.get('type')}'")
        if source.get("captureCommand") is not None:
            errors.append("fixture.source.captureCommand must be null for synthetic fixtures")

        # Cross-check commit with provenance
        src_commit = source.get("commit")
        if src_commit and provenance_commit and src_commit != provenance_commit:
            errors.append(
                f"fixture.source.commit '{src_commit}' does not match provenance commit '{provenance_commit}'"
            )

    # Check 6: cases or events
    if "cases" not in data and "events" not in data:
        errors.append("fixture must contain 'cases' or 'events' array")

    rel = str(filepath.relative_to(CONNECTOR_DIR))
    return [f"{rel}: {e}" for e in errors]


def validate_label_matches_directory(fixtures_dir):
    """All fixtures must live under synthetic/ and have label 'synthetic'."""
    errors = []
    for sub in FIXTURES_DIR.iterdir():
        if sub.is_dir() and sub.name != "synthetic" and sub.name != "schema":
            # We allow schema/ directory for schema snapshots
            if sub.name == "captured":
                errors.append("captured/ directory must NOT exist (HC-001 constraint)")
    return errors


def main():
    all_errors = []

    # --- Check captured/ does not exist ---
    if CAPTURED_DIR.exists():
        all_errors.append(
            "FAIL: captured/ directory exists — HC-001 requires NO captured directory. "
            "All fixtures must be synthetic."
        )

    # --- Check provenance.json exists and is valid ---
    provenance, err = check_json_file(PROVENANCE_FILE)
    if err:
        all_errors.append(f"provenance.json: {err}")
        provenance_commit = None
        provenance_version = None
    else:
        prov_errors, provenance_version, provenance_commit = validate_provenance(provenance)
        for e in prov_errors:
            all_errors.append(f"provenance.json: {e}")

    # --- Check schema files exist ---
    for schema_file in ("openapi-endpoints.json", "openapi-types.json"):
        spath = SCHEMA_DIR / schema_file
        if not spath.exists():
            all_errors.append(f"Schema snapshot missing: {schema_file}")

    # --- Check all fixture files ---
    fixture_files = sorted(SYNTHETIC_DIR.glob("*.json"))
    if not fixture_files:
        all_errors.append("No fixture files found under fixtures/synthetic/")

    covered_targets = set()
    for fpath in fixture_files:
        data, _ = check_json_file(fpath)
        target = data.get("target", "unknown") if data else "unknown"
        covered_targets.add(target)
        file_errors = validate_fixture(fpath, provenance_commit)
        all_errors.extend(file_errors)

    # --- Check target coverage ---
    missing_targets = REQUIRED_TARGETS - covered_targets
    if missing_targets:
        all_errors.append(
            f"Missing fixture targets: {sorted(missing_targets)}. "
            f"HC-001 requires at least these 7: {sorted(REQUIRED_TARGETS)}"
        )

    # --- Check label matches directory ---
    label_errors = validate_label_matches_directory(SYNTHETIC_DIR)
    all_errors.extend(label_errors)

    # --- Report ---
    fixture_count = len(fixture_files)
    print(f"Validator: Nomad OpenCode connector fixtures (HC-001)")
    print(f"  Provenance : v{provenance_version or '?'}")
    print(f"  Commit     : {provenance_commit or '?'}")
    print(f"  Fixtures   : {fixture_count}")
    print(f"  Targets    : {sorted(covered_targets)}")
    print()

    if all_errors:
        print(f"FAIL — {len(all_errors)} error(s):")
        for e in all_errors:
            print(f"  ✗ {e}")
        sys.exit(1)
    else:
        print("PASS — All fixture checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
