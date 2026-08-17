#!/usr/bin/env python3
"""HC-002 driver: measure cold start, idle RSS, SQLite WAL, SSE parsing,
and binary metadata for both Rust and Go spike binaries.

Usage: python3 run_benchmarks.py
Outputs:
  spikes/connector-stack/data/results.json (raw tables)
  stdout: formatted report
"""

import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPIKE_ROOT = ROOT
DATA_DIR = SPIKE_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

RUST_BIN = ROOT / "rust" / "target" / "release" / "spike"
GO_BIN = ROOT / "go" / "bin" / "spike"

N_COLD_START = 20
N_IDLE_SAMPLES = 5
N_SQLITE_TX = 5000
N_SSE_EVENTS = 5000
IDLE_SLEEP_S = 30


def percentile(values, pct):
    """Nearest-rank percentile, 0-indexed, ceil-based.
    Same formula across cold_start, idle_rss, sse.
    Example: p95 of 20 elements -> ceil(20*0.95)=19 -> index 18.
    """
    vs = sorted(values)
    idx = max(0, int(__import__('math').ceil(len(vs) * pct)) - 1)
    return vs[idx]


def p95(values):
    """Shorthand for percentile(values, 0.95)."""
    return percentile(values, 0.95)


def run(cmd, check=True, capture=True, env=None, timeout=None):
    """Thin wrapper around subprocess.run so the script is self-contained."""
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        p = subprocess.run(
            cmd,
            env=merged,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None
    if check and p.returncode != 0:
        print(f"  [warn] non-zero exit ({p.returncode}) for {cmd[:120] if isinstance(cmd, list) else cmd[:120]}", file=sys.stderr)
    return p


def read_rss_kb(pid):
    """Read RSS via `ps -o rss= -p <pid>` (macOS: KB)."""
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
        return int(out.strip())
    except Exception:
        return None


def measure_cold_start(label, bin_path, mode_args, n=N_COLD_START):
    """Time from process launch to the first 'READY' line on stdout."""
    times_ms = []
    for _ in range(n):
        t0 = time.perf_counter()
        p = subprocess.Popen(
            [str(bin_path)] + mode_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env={**os.environ, "SPIKE_ROOT": str(ROOT)},
        )
        try:
            line = p.stdout.readline()
        except Exception:
            line = ""
        t1 = time.perf_counter()
        # Kill the child if it's still running (idle/server modes).
        if p.poll() is None:
            p.kill()
            p.wait(timeout=5)
        if line.strip() == "READY":
            times_ms.append((t1 - t0) * 1000.0)
    if not times_ms:
        return None
    times_ms.sort()
    return {
        "label": label,
        "n": len(times_ms),
        "min_ms": times_ms[0],
        "p50_ms": times_ms[len(times_ms) // 2],
        "p95_ms": p95(times_ms),
        "max_ms": times_ms[-1],
        "mean_ms": statistics.mean(times_ms),
    }


def measure_idle_rss(label, bin_path, sleep_s=IDLE_SLEEP_S, samples=N_IDLE_SAMPLES):
    """Launch the idle mode, sample RSS after a settle period, then kill."""
    rss_kb = []
    for _ in range(samples):
        p = subprocess.Popen(
            [str(bin_path), "idle"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "SPIKE_ROOT": str(ROOT)},
        )
        # Drain the READY line.
        try:
            raw = p.stdout.readline()
            line = raw.decode().strip() if isinstance(raw, bytes) else raw.strip()
        except Exception:
            line = ""
        if line.strip() != "READY":
            p.kill(); p.wait(timeout=5)
            continue
        # Let the process settle.
        time.sleep(2.0)
        start = time.time()
        local_samples = []
        while time.time() - start < sleep_s:
            rss = read_rss_kb(p.pid)
            if rss is not None:
                local_samples.append(rss)
            time.sleep(0.5)
        if p.poll() is None:
            p.kill()
            p.wait(timeout=5)
        if local_samples:
            avg_kb = sum(local_samples) / len(local_samples)
            rss_kb.append(avg_kb)
    if not rss_kb:
        return None
    return {
        "label": label,
        "samples": len(rss_kb),
        "mean_kb": statistics.mean(rss_kb),
        "p95_kb": p95(rss_kb),
        "min_kb": min(rss_kb),
        "max_kb": max(rss_kb),
    }


def parse_sqlite_output(line):
    """SQLITE_WAL result={...} -> dict of floats."""
    m = re.search(r"SQLITE_WAL result=(\{.*\})", line)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def run_sqlite_bench(label, bin_path, n=N_SQLITE_TX):
    db_file = DATA_DIR / f"test-{label}.db"
    # Clean up prior run.
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_file) + suffix)
        if p.exists():
            p.unlink()
    env = {**os.environ, "SPIKE_ROOT": str(ROOT)}
    p = run([str(bin_path), "sqlite", str(db_file), str(n)], timeout=120, env=env)
    if p is None:
        return None
    out = p.stdout or ""
    for line in out.splitlines():
        parsed = parse_sqlite_output(line)
        if parsed:
            parsed["label"] = label
            return parsed
    return None


def wait_http(url, timeout_s=10):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def run_sse_bench(label, bin_path, n=N_SSE_EVENTS):
    """Launch the SSE server, POST N events, record per-event RTT."""
    server = subprocess.Popen(
        [str(bin_path), "sse"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "SPIKE_ROOT": str(ROOT)},
    )
    try:
        if not wait_http("http://127.0.0.1:4097/health", timeout_s=10):
            return {"label": label, "error": "server did not come up"}

        # Measure RSS during load.
        rss_start = read_rss_kb(server.pid)

        times_ms = []
        for i in range(n):
            payload = json.dumps({
                "seq": i,
                "label": "bench",
                "payload": f"payload-{i}",
                "ts": int(time.time() * 1000),
            }).encode("utf-8")
            t0 = time.perf_counter()
            req = urllib.request.Request(
                "http://127.0.0.1:4097/sse",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    _ = resp.read()
            except Exception as e:
                return {"label": label, "error": f"request failed at i={i}: {e}"}
            times_ms.append((time.perf_counter() - t0) * 1000.0)

        rss_end = read_rss_kb(server.pid)
        times_ms.sort()
        return {
            "label": label,
            "n": n,
            "p50_ms": times_ms[len(times_ms) // 2],
            "p95_ms": p95(times_ms),
            "max_ms": times_ms[-1],
            "min_ms": times_ms[0],
            "server_rss_kb_start": rss_start,
            "server_rss_kb_end": rss_end,
        }
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=5)


def binary_metadata(label, bin_path):
    """Collect size, link mode, and code-sign notes for a built binary."""
    size = bin_path.stat().st_size
    # Use `file` to capture static vs dynamic linkage.
    p = run(["file", str(bin_path)], check=False)
    file_out = p.stdout.strip() if p else ""
    # otool for Mach-O details.
    p2 = run(["otool", "-L", str(bin_path)], check=False)
    deps = p2.stdout.strip().splitlines() if p2 else []
    # codesign --verify (may fail if not signed, that's OK for a spike).
    p3 = run(["codesign", "--verify", "--deep", "--strict", str(bin_path)], check=False)
    signed = (p3 is not None and p3.returncode == 0)
    return {
        "label": label,
        "size_bytes": size,
        "size_mb": round(size / (1024 * 1024), 2),
        "file_output": file_out,
        "dynamic_lib_deps": len([d for d in deps if d.strip()]),
        "signed": signed,
    }


def main():
    results = {
        "meta": {
            "date": time.strftime("%Y-%m-%d"),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "n_cold_start": N_COLD_START,
            "n_idle_samples": N_IDLE_SAMPLES,
            "n_sqlite_tx": N_SQLITE_TX,
            "n_sse_events": N_SSE_EVENTS,
        },
        "cold_start": {},
        "idle_rss": {},
        "sqlite_wal": {},
        "sse": {},
        "binary_meta": {},
    }

    print("=" * 60)
    print("HC-002 Connector Stack Spike — Benchmark Run")
    print("=" * 60)

    if not RUST_BIN.exists():
        print(f"[error] Rust binary not found at {RUST_BIN}", file=sys.stderr)
        sys.exit(1)
    if not GO_BIN.exists():
        print(f"[error] Go binary not found at {GO_BIN}", file=sys.stderr)
        sys.exit(1)

    for label, bin_path in [("rust", RUST_BIN), ("go", GO_BIN)]:
        print(f"\n--- cold start ({label}) ---")
        r = measure_cold_start(label, bin_path, ["idle"])
        results["cold_start"][label] = r
        print(f"  min={r['min_ms']:.2f}  p50={r['p50_ms']:.2f}  p95={r['p95_ms']:.2f}  max={r['max_ms']:.2f} ms")

        print(f"--- idle RSS ({label}) ---")
        r = measure_idle_rss(label, bin_path)
        results["idle_rss"][label] = r
        print(f"  mean={r['mean_kb']:.0f} KB  p95={r['p95_kb']:.0f} KB  max={r['max_kb']:.0f} KB")

        print(f"--- SQLite WAL ({label}) ---")
        r = run_sqlite_bench(label, bin_path)
        results["sqlite_wal"][label] = r
        print(f"  total={r['total_ms']:.3f} ms  p50={r['p50_ms']:.6f}  p95={r['p95_ms']:.6f}  max={r['max_ms']:.6f} ms")

        print(f"--- SSE ({label}) ---")
        r = run_sse_bench(label, bin_path)
        results["sse"][label] = r
        print(f"  p50={r['p50_ms']:.3f}  p95={r['p95_ms']:.3f}  max={r['max_ms']:.3f} ms  rss_start={r['server_rss_kb_start']}KB end={r['server_rss_kb_end']}KB")

        print(f"--- binary meta ({label}) ---")
        r = binary_metadata(label, bin_path)
        results["binary_meta"][label] = r
        print(f"  size={r['size_mb']} MB  dynamic_lib_deps={r['dynamic_lib_deps']}  signed={r['signed']}")

    # Write raw results.
    out_path = DATA_DIR / "results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nRaw results written to {out_path}")

    # Print a compact comparison table for the report.
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    cs = results["cold_start"]
    print(f"{'cold_start p50 (ms)':<30} rust={cs['rust']['p50_ms']:.2f}  go={cs['go']['p50_ms']:.2f}")
    print(f"{'cold_start p95 (ms)':<30} rust={cs['rust']['p95_ms']:.2f}  go={cs['go']['p95_ms']:.2f}")

    idle = results["idle_rss"]
    print(f"{'idle RSS mean (KB)':<30} rust={idle['rust']['mean_kb']:.0f}  go={idle['go']['mean_kb']:.0f}")

    sql = results["sqlite_wal"]
    print(f"{'sqlite p50 (ms)':<30} rust={sql['rust']['p50_ms']:.6f}  go={sql['go']['p50_ms']:.6f}")
    print(f"{'sqlite p95 (ms)':<30} rust={sql['rust']['p95_ms']:.6f}  go={sql['go']['p95_ms']:.6f}")
    print(f"{'sqlite total (ms)':<30} rust={sql['rust']['total_ms']:.3f}  go={sql['go']['total_ms']:.3f}")

    sse = results["sse"]
    print(f"{'sse p50 (ms)':<30} rust={sse['rust']['p50_ms']:.3f}  go={sse['go']['p50_ms']:.3f}")
    print(f"{'sse p95 (ms)':<30} rust={sse['rust']['p95_ms']:.3f}  go={sse['go']['p95_ms']:.3f}")

    meta = results["binary_meta"]
    print(f"{'binary size (MB)':<30} rust={meta['rust']['size_mb']}  go={meta['go']['size_mb']}")


if __name__ == "__main__":
    main()
