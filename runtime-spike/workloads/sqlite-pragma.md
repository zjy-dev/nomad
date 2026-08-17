# RT-001: equal SQLite PRAGMA specification

These PRAGMA settings are frozen and must be applied identically to
both the OpenCode baseline and the Rust runtime. Any divergence in
durability, caching, or WAL behavior between the two invalidates the
comparison.

## 1. PRAGMA block

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA cache_size = -2000;
PRAGMA mmap_size = 268435456;
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = INCREMENTAL;
PRAGMA temp_store = MEMORY;
PRAGMA busy_timeout = 5000;
```

### Rationale

| PRAGMA | Value | Rationale |
| --- | --- | --- |
| `journal_mode` | `WAL` | Concurrent readers + one writer without locking. Required for the append-only runtime design. |
| `synchronous` | `NORMAL` | Same durability level used by most embedded SQLite production systems. Full `FULL` is a separate test condition. |
| `wal_autocheckpoint` | `1000` | Checkpoint every 1000 frames — matches typical high-throughput workloads. |
| `cache_size` | `-2000` | 2000 pages (~2 MiB). Smaller caches force the runtime to show whether it uses memory efficiently. |
| `mmap_size` | `268435456` | 256 MiB mapped. Gives the runtime a fair chance without handing it the entire file. |
| `foreign_keys` | `ON` | Enforces referential integrity consistently across both implementations. |
| `auto_vacuum` | `INCREMENTAL` | Prevents fragmentation without the full-VACUUM stop-the-world. |
| `temp_store` | `MEMORY` | Temp tables and indices in RAM — not on the critical path but keeps comparison fair. |
| `busy_timeout` | `5000` | 5 seconds before returning SQLITE_BUSY. Prevents indefinite blocking. |

## 2. Verifying equality

A Python helper (`validators/check_pragma.py`) reads the runtime's
active PRAGMA values and compares them against this block. The check
passes only if every value matches exactly.

The helper also verifies that the baseline run and the runtime run both
use the same version of SQLite (`sqlite3 --version` or `SELECT
sqlite_version()`). SQLite version mismatches can produce different
query plans and are therefore flagged even if PRAGMA values match.

## 3. What is NOT equalized

- `page_size` — kept at the SQLite default (4096). Changing page size
  has architectural implications for the runtime and is not a PRAGMA
  toggle.
- `journal_size_limit` — kept at SQLite default. A custom limit would
  advantage the side that set it.
- `mmap_size` for the temp file — not set, keeping SQLite defaults.

## 4. How to use

Both baseline and runtime must run the following setup before each
measurement:

```python
import sqlite3

conn = sqlite3.connect(":memory:")
conn.execute("PRAGMA journal_mode = WAL")
conn.execute("PRAGMA synchronous = NORMAL")
conn.execute("PRAGMA wal_autocheckpoint = 1000")
conn.execute("PRAGMA cache_size = -2000")
conn.execute("PRAGMA mmap_size = 268435456")
conn.execute("PRAGMA foreign_keys = ON")
conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
conn.execute("PRAGMA temp_store = MEMORY")
conn.execute("PRAGMA busy_timeout = 5000")

# Verify: dump all PRAGMA values
cursor = conn.execute("PRAGMA journal_mode")
assert cursor.fetchone()[0] == "wal"
cursor = conn.execute("PRAGMA synchronous")
assert cursor.fetchone()[0] == "normal"
# ...
```

The runtime's Rust equivalent:

```rust
use rusqlite::Connection;

let conn = Connection::open_in_memory().unwrap();
conn.pragma_update(None, "journal_mode", "WAL").unwrap();
conn.pragma_update(None, "synchronous", "NORMAL").unwrap();
// ...
```

## 5. Explicit out-of-scope

- Tuning PRAGMA to get a favorable number and then calling it "the
  baseline setting."
- Measuring with one set and reporting with another.
- Omitting `foreign_keys` or `auto_vacuum` from either side.