#!/usr/bin/env python3
"""
gen_fixtures.py — Generate synthetic fixture stubs for Nomad OpenCode connector.

Reads provenance.json and schema/ snapshots to produce fixture skeletons with the
correct synthetic labeling. Does NOT populate payload content — that is the task
of the fixture author.

Usage:
  python gen_fixtures.py          # generate all targets
  python gen_fixtures.py --target session  # generate one target
"""

import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

CONNECTOR_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = CONNECTOR_DIR / "fixtures"
SYNTHETIC_DIR = FIXTURES_DIR / "synthetic"
PROVENANCE_PATH = FIXTURES_DIR / "provenance.json"

TARGETS = [
    "session", "message", "tool", "permission", "diff", "abort", "snapshot", "sse-trace"
]


def get_source_block(provenance):
    """Build the standard source block from provenance."""
    upstream = provenance.get("upstream", {})
    return {
        "type": "schema-derived",
        "upstream": f"OpenCode v{upstream.get('version', '?')}",
        "commit": upstream.get("commit", "?"),
        "reason": (
            "Payloads constructed from the published OpenCode TypeScript type definitions "
            "and endpoint table. No live server was available at fixture time. "
            "These payloads must pass schema conformance checks but are NOT live-captured."
        ),
        "captureCommand": None
    }


def generate_stub(provenance, target):
    """Generate a minimal synthetic fixture stub for the given target."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    source = get_source_block(provenance)

    if target == "sse-trace":
        return {
            "fixture": "synthetic",
            "target": target,
            "label": "synthetic",
            "generatedAt": now,
            "source": source,
            "cases": [
                {
                    "id": f"{target}.stub",
                    "description": f"Stub — replace with real {target} cases",
                    "events": []
                }
            ]
        }
    else:
        return {
            "fixture": "synthetic",
            "target": target,
            "label": "synthetic",
            "generatedAt": now,
            "source": source,
            "cases": [
                {
                    "id": f"{target}.stub",
                    "description": f"Stub — replace with real {target} cases",
                    "request": {
                        "method": "GET",
                        "path": "/placeholder"
                    },
                    "response": {
                        "status": 200,
                        "body": {}
                    }
                }
            ]
        }


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic fixture stubs")
    parser.add_argument("--target", choices=TARGETS, help="Generate only one target")
    parser.add_argument("--force", action="store_true", help="Overwrite existing fixture files")
    args = parser.parse_args()

    provenance, err = None, None
    try:
        with open(PROVENANCE_PATH) as f:
            provenance = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading provenance.json: {e}")
        print("Run pin_version.py first.")
        sys.exit(1)

    SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)
    targets = [args.target] if args.target else TARGETS

    for target in targets:
        outfile = SYNTHETIC_DIR / f"{target}.json"
        if outfile.exists() and not args.force:
            print(f"SKIP {target}.json (exists; use --force to overwrite)")
            continue
        data = generate_stub(provenance, target)
        with open(outfile, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        print(f"OK   {target}.json")

    print(f"\nGenerated stubs in {SYNTHETIC_DIR}")
    print("Next step: populate cases with real payloads, then run validate_fixtures.py")


if __name__ == "__main__":
    main()
