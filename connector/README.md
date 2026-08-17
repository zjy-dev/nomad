# Nomad Connector — OpenCode

Connector adapter that bridges Nomad to the OpenCode runtime.

## Layout

```
connector/
  fixtures/
    provenance.json          # Pinned OpenCode version metadata
    schema/                  # Upstream API snapshots (types + endpoints)
    synthetic/               # Synthetic fixtures (schema-derived, labeled "synthetic")
  tools/
    validate_fixtures.py     # Validator — run before merging
    pin_version.py           # Pin a new upstream version
    gen_fixtures.py          # Generate fixture stubs
  README.md                  # This file
```

## Version pinning

All fixtures are pinned to a specific OpenCode release. See `fixtures/provenance.json` for the current version, commit, and upstream metadata.

To pin a new version:

```bash
python connector/tools/pin_version.py \
  --version 1.18.16 \
  --commit a3647eb025c7615159d417dcc49fc39fdaeba65b \
  --license MIT
```

## Fixtures

All fixtures under `fixtures/synthetic/` are **schema-derived synthetic payloads**. They were constructed from the OpenCode TypeScript type definitions and endpoint table at the pinned commit. No live OpenCode server was available at fixture time.

Each fixture file carries:

- `"fixture": "synthetic"` — top-level marker
- `"label": "synthetic"` — no captured fixtures exist
- `"source"` block — upstream version, commit, and derivation note
- `"captureCommand": null` — explicitly not live-captured

### Target coverage (HC-001)

| Target | Fixture file |
|--------|-------------|
| session | `synthetic/session.json` |
| message | `synthetic/message.json` |
| tool | `synthetic/tool.json` |
| permission | `synthetic/permission.json` |
| diff | `synthetic/diff.json` |
| abort | `synthetic/abort.json` |
| snapshot | `synthetic/snapshot.json` |
| sse-trace | `synthetic/sse-trace.json` |

## Validation

Run the validator before committing changes to fixtures or provenance:

```bash
python connector/tools/validate_fixtures.py
```

The validator checks:

1. All fixture files are valid JSON
2. Every fixture has `"label": "synthetic"`
3. Every fixture has a `source` block with required fields
4. Every fixture has `"fixture": "synthetic"` top-level marker
5. No `captured/` directory exists
6. Provenance.json is internally consistent
7. All 7 required targets are covered
8. Provenance commit matches fixture source commits
9. Fixture `generatedAt` dates are valid ISO dates

## Schema snapshots

`fixtures/schema/` contains two files extracted from the pinned OpenCode source:

- `openapi-endpoints.json` — all HTTP paths and methods
- `openapi-types.json` — TypeScript type definitions consumed by the adapter

These are informational snapshots. If the upstream schema changes, regenerate them and re-run the validator.

## Constraints

- No `captured/` directory. All fixtures are synthetic.
- No secrets or credentials in fixture data.
- Connector communicates over loopback only (`127.0.0.1:4096`). Non-loopback addresses must be rejected.
