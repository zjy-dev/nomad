# HC-002 Environment Manifest

- Date: 2026-08-17
- Host: Apple Silicon Mac (arm64), macOS 26.5.2 (25F84)
- CPU: 18 cores (hw.ncpu)
- RAM: 48 GB (hw.memsize = 51539607552)
- Rust: rustc 1.95.0 (59807616e 2026-04-14), cargo 1.95.0
- Go: go1.26.3 darwin/arm64
- macOS SDK: Apple clang 21.0.0 (clang-2100.1.1.101)
- SQLite (client): 3.51.0 2025-06-12
- Python: 3.9.6

## Benchmark workloads (identical across languages)

1. **Cold start** — time-to-first-log line after a clean process launch (no warm cache). Run 20 times per language, report min/p50/p95.
2. **Idle RSS** — process resident memory after startup, idle 30 s, sampled via `ps`. Run 5 times, report mean and p95.
3. **SQLite WAL transaction** — N=5000 transactions inserting one row each (id, payload, ts, seq) into a WAL-mode SQLite DB. Single writer thread. Report: p50, p95, max ms/op; total wall time; fsync strategy.
4. **SSE parsing stub** — a single-threaded HTTP server that accepts `POST /sse` and echoes a fixed-size event payload as a server-sent event. Client posts 5000 events. Report: per-event round-trip p50/p95, server RSS under load.
5. **Keychain feasibility boundary** — code-level adapter boundary only. Both prototypes expose a `KeychainStore` trait/interface with no-op implementation; the ADR discusses the production adapter (Security.framework / keyring vs homebrew). No real keychain I/O performed in the spike.
6. **Signed single-binary distribution** — build both binaries (release mode), capture binary size, link mode (static vs dynamic), and codesign/ditto feasibility notes. No real notarization run.
7. **Team / on-call risk** — qualitative analysis based on the authors' assessment of Rust vs Go ramp-up, panic/segfault triage, dependency audit surface, and long-term maintenance for a 4-person team. Not a benchmark; recorded in the ADR.

## Shared fixtures

Both prototypes share the same schema-free JSON payload shape (`events.jsonl` used only as a synthetic stream, never a contract fixture). The spike does NOT touch `contracts/`; it is a standalone implementation comparison.

## Run notes

- No product connector code is implemented.
- No contract is modified.
- No commits are expected or performed.
- ADR status remains `Proposed` until cross-check confirms reproducibility.
