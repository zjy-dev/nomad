# Nomad contract conformance runner

This standard-library Python runner validates the language-neutral schemas,
manifest, golden traces and expected snapshots under `contracts/`. It does not
import Host, Mobile, Relay or Runtime implementation types.

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

Snapshot digests use SHA-256 over UTF-8 canonical JSON of the complete snapshot
object excluding `digest`, with sorted keys, compact separators, and Unicode
encoded directly (`ensure_ascii=false`). The runner rejects placeholder, stale,
or tampered digests.
