# Nomad contract conformance runner

This standard-library Python runner validates the language-neutral schemas,
manifest, golden traces, expected snapshots, and the authoritative adapter
support matrix under `contracts/`. It does not import Host, Mobile, Relay or
Runtime implementation types.

Run from the repository root:

```bash
python3 testkit/conformance/run.py
python3 -m unittest discover -s testkit/conformance -p 'test_*.py'
```

To compare an implementation's projected snapshots with the golden corpus:

```bash
python3 testkit/conformance/run.py --actual-snapshots path/to/snapshots
```

Output and findings are deterministically sorted. `--json` emits a machine-readable
report including contract versions and supported checks. Missing or incomplete
contracts produce stable non-zero diagnostics.

The support-matrix validation is intentionally narrow and honest. It currently
accepts only the exact OpenCode adapter contract:

- adapter id `opencode`
- exact supported version `1.18.16`
- supported actions `view`, `reply`, `deny`, and `Stop`
- `allow_once=false`
- `NoCapability => snapshot + capability=null`
- unsupported version, shape, and action-surface cases fail closed

Snapshot digests use SHA-256 over UTF-8 canonical JSON of the complete snapshot
object excluding `digest`, with sorted keys, compact separators, and Unicode
encoded directly (`ensure_ascii=false`). The runner rejects placeholder, stale,
or tampered digests.
