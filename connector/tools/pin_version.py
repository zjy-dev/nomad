#!/usr/bin/env python3
"""
pin_version.py — Pin the upstream OpenCode version for the Nomad connector.

Usage:
  python pin_version.py --version 1.18.16 [--tag v1.18.16] [--commit <sha>] [--license MIT]

Updates connector/fixtures/provenance.json with the given version metadata.
Does NOT fetch from the network — takes user-supplied values for reproducibility.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROVENANCE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "provenance.json"


def main():
    parser = argparse.ArgumentParser(description="Pin the upstream OpenCode version")
    parser.add_argument("--version", required=True, help="OpenCode version (e.g. 1.18.16)")
    parser.add_argument("--tag", default=None, help="Git tag (e.g. v1.18.16). Defaults to 'v' + version")
    parser.add_argument("--commit", required=True, help="Git commit SHA")
    parser.add_argument("--license", default="MIT", help="License identifier")
    parser.add_argument("--repo", default="https://github.com/anomalyco/opencode", help="Repository URL")
    parser.add_argument("--published-at", default=None, help="ISO date of release")
    parser.add_argument("--note", default="Pinned via pin_version.py", help="Notes for this pin")

    args = parser.parse_args()

    tag = args.tag or f"v{args.version}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    provenance = {
        "schema": "nomad.connector.provenance.v1",
        "upstream": {
            "name": "OpenCode",
            "version": args.version,
            "tag": tag,
            "commit": args.commit,
            "repository": args.repo,
            "license": args.license,
            "publishedAt": args.published_at or now,
            "fetchedAt": now,
            "fetchedBy": args.note
        },
        "checksums": {
            "sourceTarball": {
                "url": f"https://github.com/anomalyco/opencode/archive/refs/tags/{tag}.tar.gz",
                "sha256": None,
                "note": "Run with --fetch-checksums (requires authenticated GitHub access) to populate."
            },
            "sourceZipball": {
                "url": f"https://github.com/anomalyco/opencode/archive/refs/tags/{tag}.zip",
                "sha256": None,
                "note": "Same as sourceTarball."
            },
            "binary": {
                "url": None,
                "sha256": None,
                "note": "OpenCode does not publish signed binary artifacts for this version."
            }
        },
        "upstreamAPISummary": {
            "baseURL": "http://127.0.0.1:4096",
            "defaultHostname": "127.0.0.1",
            "defaultPort": 4096,
            "docsPath": "/doc",
            "discovery": "Loopback only. Connector MUST reject any non-loopback address."
        },
        "changePolicy": {
            "onVersionChange": "Update this manifest, regenerate fixtures, and re-run validator before merging.",
            "onSchemaChange": "Regenerate schema/ snapshots and verify all fixtures still validate."
        }
    }

    PROVENANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PROVENANCE_PATH, "w") as f:
        json.dump(provenance, f, indent=2)
        f.write("\n")

    print(f"Pinned OpenCode {args.version} ({tag}) at commit {args.commit}")
    print(f"Written: {PROVENANCE_PATH}")
    print("Next step: run gen_fixtures.py and then validate_fixtures.py")


if __name__ == "__main__":
    main()
