#!/usr/bin/env python3
"""Generate synthetic fixtures for RT-001 and update the manifest.

This module is intentionally pure Python with no external dependencies
so it can run on any CI machine. Fixtures are small JSON files that
capture the *structure* of a workload (event counts, sizes, and
relationships) rather than the actual payloads — the runtime is
responsible for reading them and exercising the right paths.

Usage:
    python3 gen_fixtures.py [--output-dir runtime-spike/fixtures]
    python3 gen_fixtures.py --manifest-only
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gen_cold_start(output_dir: Path) -> tuple[str, dict]:
    """Minimal startup fixture: 1 init event, small session metadata."""
    fixture = {
        "kind": "cold-start",
        "workload_id": "ws-cold-start",
        "description": "Spawn-to-first-commit measurement fixture",
        "session": {
            "session_id": "sess-cold-start-001",
            "seq_start": 0,
            "events": [
                {
                    "seq": 1,
                    "type": "session.init",
                    "turn_id": None,
                    "ts_offset_ms": 0,
                    "payload_size_bytes": 256,
                },
            ],
        },
        "read_ops": [],
    }
    path = output_dir / "cold-start.json"
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    return "cold-start.json", fixture


def gen_recovery_100k(output_dir: Path) -> tuple[str, dict]:
    """100k durable events across 500 turns, 20 snapshots, query probes."""
    events = []
    seq = 0
    for turn_idx in range(500):
        turn_id = f"turn-{turn_idx:05d}"
        # ~199 events per turn to reach 100k total
        for i in range(199):
            seq += 1
            events.append({
                "seq": seq,
                "type": _pick_event_type(turn_idx, i),
                "turn_id": turn_id,
                "ts_offset_ms": seq * 10,
                "payload_size_bytes": random.randint(64, 4096),
            })
        seq += 1
        events.append({
            "seq": seq,
            "type": "turn.completed",
            "turn_id": turn_id,
            "ts_offset_ms": seq * 10,
            "payload_size_bytes": 128,
        })

    snapshots = []
    for snap_idx in range(20):
        snap_seq = (snap_idx + 1) * 5000
        snapshots.append({
            "snapshot_id": f"snap-{snap_idx:03d}",
            "seq": snap_seq,
            "turn_id": f"turn-{snap_idx * 250:05d}",
            "ts_offset_ms": snap_seq * 10,
        })

    query_probes = [
        {"kind": "last-1k", "from_seq": seq - 1000, "to_seq": seq},
        {"kind": "last-1k", "from_seq": 50000 - 1000, "to_seq": 50000},
        {"kind": "cursor-resume", "from_seq": 0, "to_seq": seq},
        {"kind": "cursor-resume", "from_seq": 50000, "to_seq": seq},
    ]

    fixture = {
        "kind": "recovery-100k",
        "workload_id": "ws-recovery-100k",
        "description": "100k durable events, 20 snapshots, query probes",
        "session": {
            "session_id": "sess-recovery-100k",
            "seq_start": 1,
            "events": events,
        },
        "snapshots": snapshots,
        "read_ops": query_probes,
    }
    path = output_dir / "recovery-100k.json"
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    return "recovery-100k.json", fixture


def gen_append_burst(output_dir: Path) -> tuple[str, dict]:
    """50k sustained append with concurrent reader simulation."""
    events = []
    for i in range(50000):
        events.append({
            "seq": i + 1,
            "type": _pick_event_type(i // 200, i % 200),
            "turn_id": f"turn-{i // 200:05d}",
            "ts_offset_ms": i * 5,
            "payload_size_bytes": random.randint(64, 2048),
        })

    fixture = {
        "kind": "append-burst",
        "workload_id": "ws-append-durable",
        "description": "50k sustained append with concurrent readers",
        "session": {
            "session_id": "sess-append-burst",
            "seq_start": 1,
            "events": events,
        },
        "concurrent_readers": 10,
        "reader_pattern": "last-1k-every-1000-events",
    }
    path = output_dir / "append-burst.json"
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    return "append-burst.json", fixture


def gen_long_session(output_dir: Path) -> tuple[str, dict]:
    """8-hour session: 500 turns, 5000 tool events, periodic snapshots."""
    events = []
    seq = 0
    for turn_idx in range(500):
        turn_id = f"turn-{turn_idx:05d}"
        for i in range(10):
            seq += 1
            events.append({
                "seq": seq,
                "type": _pick_event_type(turn_idx, i),
                "turn_id": turn_id,
                "ts_offset_ms": seq * 100,
                "payload_size_bytes": random.randint(64, 4096),
            })
        seq += 1
        events.append({
            "seq": seq,
            "type": "turn.completed",
            "turn_id": turn_id,
            "ts_offset_ms": seq * 100,
            "payload_size_bytes": 128,
        })

    # 8 snapshots over the 8-hour session
    snapshots = []
    for snap_idx in range(8):
        snap_seq = (snap_idx + 1) * (seq // 8)
        snapshots.append({
            "snapshot_id": f"snap-{snap_idx:03d}",
            "seq": snap_seq,
            "turn_id": f"turn-{(snap_idx * 500 // 8):05d}",
            "ts_offset_ms": snap_seq * 100,
        })

    # RSS measurement checkpoints (hours 0, 1, 2, 4, 8)
    rss_checkpoints = []
    for h in [0, 1, 2, 4, 8]:
        rss_checkpoints.append({
            "hour": h,
            "expected_min_events": (h * len(events)) // 8,
        })

    fixture = {
        "kind": "long-session",
        "workload_id": "ws-long-session-rss",
        "description": "8-hour session for RSS drift measurement",
        "session": {
            "session_id": "sess-long-session",
            "seq_start": 1,
            "events": events,
        },
        "snapshots": snapshots,
        "rss_checkpoints": rss_checkpoints,
    }
    path = output_dir / "long-session-8h.json"
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    return "long-session-8h.json", fixture


def gen_ipc_roundtrip(output_dir: Path) -> tuple[str, dict]:
    """Command/reply ACK frames for IPC round-trip measurement."""
    frames = []
    for i in range(1000):
        frames.append({
            "frame_id": f"frame-{i:04d}",
            "type": "command.request" if i % 3 == 0 else ("command.reply" if i % 3 == 1 else "command.ack"),
            "payload_size_bytes": random.randint(32, 512),
            "seq": i + 1,
        })

    fixture = {
        "kind": "ipc-roundtrip",
        "workload_id": "ws-sidecar-ipc",
        "description": "Command/reply ACK frames for IPC measurement",
        "frames": frames,
        "roundtrips": 1000,
        "expected_min_frames_per_roundtrip": 3,
    }
    path = output_dir / "ipc-roundtrip.json"
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    return "ipc-roundtrip.json", fixture


def gen_query_resume(output_dir: Path) -> tuple[str, dict]:
    """Query and cursor-resume payloads for read-path p95 measurement."""
    queries = []
    for q_type in ["last-1k", "last-1k", "cursor-resume", "cursor-resume", "last-100"]:
        queries.append({
            "query_type": q_type,
            "params": {
                "from_seq": 0,
                "to_seq": 100000,
                "limit": 1000 if q_type == "last-1k" else 100,
            },
        })

    fixture = {
        "kind": "query-resume",
        "workload_id": "ws-recovery-100k",
        "description": "Read-path query and cursor-resume payloads",
        "queries": queries,
        "repeats_per_query": 100,
    }
    path = output_dir / "query-resume.json"
    path.write_text(json.dumps(fixture, indent=2) + "\n")
    return "query-resume.json", fixture


def _pick_event_type(turn_idx: int, event_idx: int) -> str:
    """Deterministic event type assignment."""
    r = random.Random(f"{turn_idx}-{event_idx}")
    n = r.random()
    if n < 0.40:
        return "message.content"
    elif n < 0.55:
        return "tool.started"
    elif n < 0.70:
        return "tool.completed"
    elif n < 0.80:
        return "message.reasoning"
    elif n < 0.85:
        return "permission.requested"
    elif n < 0.90:
        return "permission.denied"
    elif n < 0.95:
        return "permission.allowed"
    else:
        return "message.edit"


GENERATORS = [
    gen_cold_start,
    gen_recovery_100k,
    gen_append_burst,
    gen_long_session,
    gen_ipc_roundtrip,
    gen_query_resume,
]


def generate_all(output_dir: Path) -> list[dict]:
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for gen_fn in GENERATORS:
        filename, _ = gen_fn(output_dir)
        sha = sha256_file(output_dir / filename)
        entries.append({
            "file": filename,
            "sha256": sha,
        })
        print(f"  generated {filename}  sha256={sha}")
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate RT-001 synthetic fixtures")
    parser.add_argument("--output-dir", "-o", type=str,
                        default=str(Path(__file__).resolve().parent.parent / "fixtures"),
                        help="Output directory (default: runtime-spike/fixtures)")
    parser.add_argument("--manifest-only", action="store_true",
                        help="Only regenerate manifest with current hashes")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)

    if not args.manifest_only:
        print("RT-001 fixture generation")
        print(f"  output dir: {output_dir}")
        entries = generate_all(output_dir)

        # Update manifest
        manifest_path = output_dir / "manifest.json"
        manifest = {
            "_comment": "RT-001 synthetic fixture manifest. Hashes are sha256 of file contents at generation time.",
            "version": 1,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "fixtures": [
                {
                    "file": e["file"],
                    "sha256": e["sha256"],
                    "source": f"scripts/gen_fixtures.py (function: {_guess_source(e['file'])})",
                    "used_by": _guess_workload(e["file"]),
                    "note": _guess_note(e["file"]),
                }
                for e in entries
            ],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"  wrote {manifest_path}")
    else:
        # Recompute hashes for existing fixture files
        manifest_path = output_dir / "manifest.json"
        existing = json.loads(manifest_path.read_text())
        for entry in existing["fixtures"]:
            fpath = output_dir / entry["file"]
            if fpath.exists():
                entry["sha256"] = sha256_file(fpath)
                print(f"  updated hash for {entry['file']}")
        manifest_path.write_text(json.dumps(existing, indent=2) + "\n")

    return 0


def _guess_source(filename: str) -> str:
    mapping = {
        "cold-start.json": "scripts/gen_fixtures.py (gen_cold_start)",
        "recovery-100k.json": "scripts/gen_fixtures.py (gen_recovery_100k)",
        "append-burst.json": "scripts/gen_fixtures.py (gen_append_burst)",
        "long-session-8h.json": "scripts/gen_fixtures.py (gen_long_session)",
        "ipc-roundtrip.json": "scripts/gen_fixtures.py (gen_ipc_roundtrip)",
        "query-resume.json": "scripts/gen_fixtures.py (gen_query_resume)",
    }
    return mapping.get(filename, "unknown")


def _guess_workload(filename: str) -> list[str]:
    mapping = {
        "cold-start.json": ["ws-cold-start"],
        "recovery-100k.json": ["ws-recovery-100k"],
        "append-burst.json": ["ws-append-durable"],
        "long-session-8h.json": ["ws-long-session-rss"],
        "ipc-roundtrip.json": ["ws-sidecar-ipc"],
        "query-resume.json": ["ws-recovery-100k"],
    }
    return mapping.get(filename, [])


def _guess_note(filename: str) -> str:
    mapping = {
        "cold-start.json": "Minimal startup fixture: 1 init event, used for spawn-to-first-commit measurement.",
        "recovery-100k.json": "100k durable events, 500 turns, 20 snapshots. Covers replay, gap detection, snapshot seek.",
        "append-burst.json": "50k sustained append batch with 10 concurrent readers. Measures insert throughput.",
        "long-session-8h.json": "8-hour workload: 500 turns, 5000 tool events. Used for RSS drift measurement.",
        "ipc-roundtrip.json": "Command/reply ACK frames for IPC round-trip measurement.",
        "query-resume.json": "Query and cursor-resume payloads for read-path p95 measurement.",
    }
    return mapping.get(filename, "")


if __name__ == "__main__":
    sys.exit(main())