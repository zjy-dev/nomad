# Iteration 3 M2 A4: Same-Run Lifecycle Shape Evidence Dispatch

**Sole Authority Dispatch** — *A4: Same-run structural shape capture, independent verifier, runbook corrections. No B/C implementation.*

## Goal

The real A0 run must produce enough reviewed structural evidence for B2 (stock event semantic mapper) without raw values or content. The current certificate (event types, routes, diff count) is insufficient to prove raw property mapping. A lifecycle shape manifest from the same run carries structural property shapes, ID relationships, and source artifact bindings — all content-free.

## Certificate Schema Decision

**Certificate schema remains unchanged** (`nomad.stock-opencode.lifecycle-certificate.v1`, 6 fields). The certificate is a compact commit marker. A new `lifecycle-shape-manifest.json` carries the structural evidence. The manifest binds the certificate via the certificate's inner `structural_digest` (computed from the in-memory frozen certificate evidence before either file is written). No read of an absent certificate file occurs.

## Lifecycle Shape Manifest Schema

**File**: `real-task/lifecycle-shape-manifest.json`
**Schema**: `nomad.stock-opencode.lifecycle-shape-manifest.v1`

### Digest ordering (acyclic)

`manifest_digest` is the SHA256 of the canonical JSON of the manifest core (all fields except `manifest_digest` itself). The manifest core includes `source_binding_digest`, which is a separate composite:

```
source_binding_digest = SHA256(canonical {
  certificate_structural_digest,
  launch_provenance_digest,
  task_spec_digest,
  fixture_manifest_digest,
  command_shapes_canonical_digest,
  rule_config_digest
})
```

No `evidence_bundle_digest` or other composite digest separate from `source_binding_digest`. The manifest core contains `source_binding_digest` as a field; `manifest_digest` covers the entire core including it. No circular dependency.

### Top-level fields (manifest core)

| Field | Type | Content | Source |
|-------|------|---------|--------|
| `schema_version` | str | `"nomad.stock-opencode.lifecycle-shape-manifest.v1"` | Constant |
| `certificate_structural_digest` | str | SHA256 hex of the certificate's canonical core (same as `structural_digest` inside the certificate) | Frozen in-memory `CompletedRealDiscovery.evidence` before any write |
| `launch_provenance_digest` | str | `launch.provenance_digest` | `RealRunAuthority.provenance_digest` |
| `task_spec_digest` | str | Already-canonical digest from `load_task_spec()` return value (second element, `_shape_digest(payload)`) | `load_task_spec()[1]` — no re-hash |
| `fixture_manifest_digest` | str | `manifest["digest"]` | `verify_fixture_manifest()` result |
| `command_shapes_canonical_digest` | str | `canonical_digest(verify_command_shape_fixture())` | `_wp1().verify_command_shape_fixture()` canonical |
| `rule_config_digest` | str | SHA256 of canonical `SESSION_PERMISSION_RULES` JSON | `canonical_digest(SESSION_PERMISSION_RULES)` |
| `source_binding_digest` | str | SHA256 of canonical `{certificate_structural_digest, launch_provenance_digest, task_spec_digest, fixture_manifest_digest, command_shapes_canonical_digest, rule_config_digest}` | Computed from the six digests above |
| `events` | list | 4 entries, one per `MARKER_ORDER` | `_run_protocol` in-memory capture |
| `snapshot_cardinalities` | dict | `{"/session/{id}": 1, "/question": 1, "/permission": 1, "/session/{id}/diff": 1}` | `_run_protocol` request count |
| `session_id_equality` | bool | Whether POST /session response `id` == GET /session/{id} snapshot `id` | Cross-check in memory |
| `question_snapshot_id_used_in_reply_route` | bool | Whether the question `id` from GET /question was used in the reply route path | Cross-check in memory |
| `permission_snapshot_id_used_in_reply_route` | bool | Whether the permission `id` from GET /permission was used in the reply route path | Cross-check in memory |
| `question_permission_ids_distinct` | bool | Whether question_id != permission_id | Cross-check in memory |
| `diff_count_relation` | str | `"files_ge_1"` (content-free: files count >= 1) | `_diff_count` |
| `permission_name_is_bash` | bool | Whether the observed permission snapshot has `permission == "bash"` | `_snapshot_id` snapshot |
| `patterns_is_single_string_list` | bool | Whether `patterns` is a list containing exactly one string | `_snapshot_id` snapshot |
| `pattern_matches_fixed_test_command` | bool | Whether the single pattern string equals `TEST_COMMAND` | `_snapshot_id` snapshot |
| `manifest_digest` | str | SHA256 of canonical JSON of all other fields in the manifest core (excluding `manifest_digest` itself) | Computed last |

### Event entry schema (4 entries, one per `MARKER_ORDER`)

Each event entry records the structural shape of the SSE event's `properties` field at the time the marker was observed. The shape is extracted from the live event properties using a schema-only extractor that discards all raw values.

| Sub-field | Type | Content |
|-----------|------|---------|
| `marker` | str | `"created"`, `"question"`, `"diff"`, `"permission"` |
| `observed_event_type` | str | Exact event type string (e.g. `"session.created"`) |
| `property_field_count` | int | Number of top-level property fields, must equal `len(property_field_names)` |
| `property_field_names` | list[str] | Sorted names matching the safe identifier regex and the reviewed structural-name policy below |
| `property_field_types` | dict | `{name: shape}` — see property shape definition below |

**Key set consistency**: Each event entry must have exactly `property_field_count` entries in `property_field_names`, and exactly those names as keys in `property_field_types`. Every name in `property_field_names` must have a corresponding entry in `property_field_types`, and there must be no extra keys in `property_field_types`.

### Property shape definition

The property shape extractor recursively inspects event properties and returns a schema-only struct. Raw values are never recorded.

**Shape struct**:
```json
{
  "type": "null" | "bool" | "int" | "float" | "str" | "list" | "dict",
  "properties": { "<name>": <shape> },   // only for type "dict"
  "items": { "type": "..." },            // only for type "list"
  "count": <int>                         // only for type "list": number of items
}
```

**Rules**:
- Allowed types: `null`, `bool`, `int`, `float`, `str`, `list`, `dict`. `bool` is distinct from `int` — Python `bool` is mapped to `"bool"`, not `"int"`. Any unsupported type → `DiscoveryError("BLOCKED_CONTENT_POLICY")`.
- Depth: max 3 levels. At depth 3, `dict` properties are truncated (only `type: "dict"`, no `properties`).
- Field count: max 16 per level. Fields beyond 16 are silently omitted.
- Array items: inspect one representative item (first non-null item). If the array is empty, record `items: {"type": "null"}`. If the array has heterogeneous types, record `items: {"type": "mixed"}` or raise `DiscoveryError`. Never assume the first item type is representative without checking all items.
- Field names: each must match `^[a-zA-Z_][a-zA-Z0-9_]{0,63}$` (safe ASCII identifier, max 64 chars). Reviewed structural identifiers needed for mapping, including `id`, `sessionID`, `info`, `permission`, `patterns`, `tool`, `status`, `files`, `additions`, `deletions`, and `type`, are allowed as **names only**; their values are never persisted. Reject any name containing secret-like tokens `api_key`, `secret`, `credential`, `token`, `password`, `authorization`, or `auth` (case-insensitive), and reject unknown names not present in a versioned per-event reviewed allowlist. Encountering an unknown name blocks certification rather than silently dropping it.
- `list` items: record only the type of the representative item, never the value. `count` is the number of items (not the values).

### Content-free constraint

No raw IDs, prompt, answer, path, command, diff, tool output, provider name/key. The schema-only property shape extractor discards all raw values. Booleans like `session_id_equality`, `question_snapshot_id_used_in_reply_route`, `permission_snapshot_id_used_in_reply_route`, `question_permission_ids_distinct` prove relationships without revealing values.

## Atomic Ordering

1. `_run_protocol` already collects raw transient values in memory only
2. A4.1 extends `_run_protocol` to build a shape manifest struct from the same in-memory values
3. `_evidence()` (certificate) is built from in-memory observed events, diff count, and routes — still frozen in memory at this point
4. `_certify()` is called first, consuming the `RealRunAuthority` (single consume). The returned `CompletedRealDiscovery` carries the private `_COMPLETION_TOKEN`.
5. Manifest is written first: `atomic_shape_write(MANIFEST_PATH, manifest, completed)` — requires `CompletedRealDiscovery` with `_COMPLETION_TOKEN`, validates via `_validate_completed`, writes `.tmp` then `os.replace`
6. Certificate is written last: the existing `atomic_certificate_write(CERTIFICATE_PATH, completed)` — the commit marker
7. Both writes are authorized by the same `CompletedRealDiscovery` (the single `_certify` result). No second `RealRunAuthority.consume()` call — the authority is consumed exactly once in `_certify()`.
8. The manifest's `certificate_structural_digest` is computed from the in-memory frozen certificate evidence before either write; no read of an absent certificate file occurs
9. Existing files never overwritten: `if MANIFEST_PATH.exists(): raise DiscoveryError("BLOCKED_ORPHAN_SHAPE_MANIFEST")`

## Orphan Policy

**Track shape_written_by_this_run**: A boolean flag `_shape_written` is set to `True` immediately after `atomic_shape_write` succeeds. Only manifests created by the current invocation may be cleaned up automatically.

**Cleanup within exception**: Within the `discover()` `try/finally`, if `atomic_shape_write` succeeded (`_shape_written is True`) and `atomic_certificate_write` fails (exception), remove the manifest file within the same exception handler before re-raising. Never delete a pre-existing orphan manifest automatically.

**Crash orphan**: If the process crashes after the manifest write but before the certificate write, the manifest file is left on disk. The next run checks `if MANIFEST_PATH.exists()` and raises `BLOCKED_ORPHAN_SHAPE_MANIFEST`. The operator runbook specifies exact removal: `rm real-task/lifecycle-shape-manifest.json`, then re-run.

**Both exist**: If both manifest and certificate exist on disk (e.g., after a successful run), the next run's `if CERTIFICATE_PATH.exists()` check blocks with `BLOCKED_CERTIFICATE_ALREADY_EXISTS`. The runbook requires explicit operator action to remove old evidence before re-running.

**Run never overwrites**: Both `atomic_shape_write` and `atomic_certificate_write` check existence before writing. No silent overwrite.

## A4.1: Generator Changes + Tests

**Files**: `discover_lifecycle.py` (extend `_run_protocol`, `discover()`), `test_discover_lifecycle.py` (new tests)

**Changes**:
- `_run_protocol` returns a `StructuralCandidate` that now includes both the certificate evidence and the shape manifest struct
- New `_build_shape_manifest()` function that takes the same in-memory values (session_id, question_id, permission_id, observed events, event properties snapshots, snapshot responses, diff response, routes, permission snapshot raw values, `CompletedRealDiscovery` frozen evidence, launch provenance, `load_task_spec()[1]`, `verify_fixture_manifest()` digest, `verify_command_shape_fixture()` canonical, `SESSION_PERMISSION_RULES` canonical) and produces the content-free manifest dict
- New `_extract_property_shape(properties: Mapping) -> dict` — schema-only extractor as defined above
- `_certify()` unchanged — single consume
- `discover()` calls `_certify()`, builds manifest, calls `atomic_shape_write()`, then `atomic_certificate_write()`
- `atomic_shape_write(path, manifest, completed)` — requires `CompletedRealDiscovery` with `_COMPLETION_TOKEN`, validates via `_validate_completed`, writes `.tmp` then `os.replace`
- `MANIFEST_PATH = ROOT / "real-task" / "lifecycle-shape-manifest.json"`
- `discover()` block check: checks `CERTIFICATE_PATH.exists()` first (existing gate), then `MANIFEST_PATH.exists()` → `BLOCKED_ORPHAN_SHAPE_MANIFEST`
- `_shape_written = False` before manifest write, set to `True` after `atomic_shape_write` succeeds
- If `atomic_shape_write` succeeds and `atomic_certificate_write` fails within the same `try`/`except`, check `_shape_written` and remove manifest file before re-raising

**Tests** (22 new):

| # | Test | Detail |
|---|------|--------|
| 1-4 | 4 markers each produce correct event entry | Observe session.created / question.v2.asked / session.diff / permission.v2.asked → event entry with exact key set, self-consistent field_count/names/types |
| 5 | Property field names/types | `session.created` properties has `sessionID: str` at top level, name matches safe regex |
| 6 | Property shape bounded depth | Nested dict properties truncated at 3 levels |
| 7 | Property shape bounded count | >16 fields at one level: extra fields omitted |
| 8 | Property shape field policy | Reviewed structural names such as `sessionID`/`id` are retained as names; secret-like and unknown names are rejected |
| 9 | Property shape bool distinct from int | Python `True` → `"bool"`, not `"int"` |
| 10 | Property shape heterogeneous array | Mixed types → `mixed` or rejected |
| 11 | Property shape empty array | `items: {"type": "null"}` |
| 12 | Session id equality | POST /session id == GET /session/{id} id → `True` |
| 13 | Question snapshot id used in reply route | question_id matches reply route path component → `True` |
| 14 | Permission snapshot id used in reply route | permission_id matches reply route path component → `True` |
| 15 | Question and permission ids distinct | Different IDs → `True` |
| 16 | Diff count relation | `_diff_count` returns 1 → `"files_ge_1"` |
| 17 | Permission shape booleans | `permission_name_is_bash=True`, `patterns_is_single_string_list=True`, `pattern_matches_fixed_test_command=True` |
| 18 | Rule config digest binds permission rules | `canonical_digest(SESSION_PERMISSION_RULES)` matches |
| 19 | Snapshot cardinalities | 1 GET per endpoint |
| 20 | Manifest digest matches computed | `_digest(manifest_core_without_manifest_digest)` |
| 21 | Source binding digest matches composite | `source_binding_digest == _digest({six component digests})` |
| 22 | Certificate structural digest binds in-memory certificate | `manifest.certificate_structural_digest == evidence["structural_digest"]` |
| 23 | Existing manifest file blocks → `BLOCKED_ORPHAN_SHAPE_MANIFEST` | `MANIFEST_PATH.exists()` before any write |
| 24 | Orphan cleanup: manifest write succeeds, cert write fails → manifest removed | `_shape_written` guards cleanup; pre-existing orphan not deleted |
| 25 | Crash orphan requires runbook removal | Both exist → `BLOCKED_CERTIFICATE_ALREADY_EXISTS` |
| 26 | Event entry key set consistency | Each event entry has matching `property_field_count` == `len(property_field_names)` == `len(property_field_types)` |
| 27 | task_spec_digest is not re-hashed | Digest matches `load_task_spec()[1]` directly |

**No production files generated in tests** — tests use `ScriptedTransport` with `TemporaryDirectory` fixtures.

## A4.2: Independent Read-Only Bundle Verifier + Tests

**New file**: `testkit/stock-opencode/verify_shape_manifest.py`
**New test**: `testkit/stock-opencode/test_verify_shape_manifest.py`

**Design**: `verify_shape_manifest(manifest_path: Path, certificate_path: Path) -> Verdict` — stdlib-only, read-only, no ability to write/sign/unlock.

**Validation rules**:
1. Manifest file exists, bounded, valid JSON, no duplicate keys
2. `schema_version == "nomad.stock-opencode.lifecycle-shape-manifest.v1"`
3. All required core fields present, no extra: `schema_version`, `certificate_structural_digest`, `launch_provenance_digest`, `task_spec_digest`, `fixture_manifest_digest`, `command_shapes_canonical_digest`, `rule_config_digest`, `source_binding_digest`, `events`, `snapshot_cardinalities`, `session_id_equality`, `question_snapshot_id_used_in_reply_route`, `permission_snapshot_id_used_in_reply_route`, `question_permission_ids_distinct`, `diff_count_relation`, `permission_name_is_bash`, `patterns_is_single_string_list`, `pattern_matches_fixed_test_command`, `manifest_digest`
4. `certificate_structural_digest` matches the `structural_digest` field inside the certificate at `certificate_path` (which must also pass `verify_certificate()` first)
5. `source_binding_digest` matches computed SHA256 of canonical `{certificate_structural_digest, launch_provenance_digest, task_spec_digest, fixture_manifest_digest, command_shapes_canonical_digest, rule_config_digest}`
6. Source artifact digests: `launch_provenance_digest`, `task_spec_digest`, `fixture_manifest_digest`, `command_shapes_canonical_digest`, `rule_config_digest`, `source_binding_digest` are all valid 64-hex strings
7. Events have exactly 4 entries matching `MARKER_ORDER`, each with valid marker/observed_event_type/property_field_count/property_field_names/property_field_types
8. Each event entry has consistent key set: `property_field_count == len(property_field_names)`, and `property_field_names` matches `property_field_types` keys exactly
9. Property field names match the safe identifier regex and per-event reviewed allowlist; `sessionID`/`id` are allowed as schema names, secret-like or unknown names are rejected
10. Property field types bounded to 3 levels, max 16 fields per level, array items record type only (`mixed` or single type), no raw values, `bool` distinct from `int`
11. `snapshot_cardinalities` has exactly 4 expected keys with positive ints
12. `session_id_equality`, `question_snapshot_id_used_in_reply_route`, `permission_snapshot_id_used_in_reply_route`, `question_permission_ids_distinct` are bools
13. `diff_count_relation == "files_ge_1"`
14. `permission_name_is_bash`, `patterns_is_single_string_list`, `pattern_matches_fixed_test_command` are bools
15. `rule_config_digest` matches `canonical_digest(SESSION_PERMISSION_RULES)`
16. `manifest_digest` matches computed SHA256 of canonical manifest core (all other fields)
17. Content-free: no forbidden content patterns

**Tests** (17): missing file, wrong schema, extra field, missing field, certificate structural digest mismatch, source binding digest mismatch, event count wrong, event entry key set inconsistency, property field name forbidden, property field type depth violation, cardinality wrong, permission shape bools wrong, rule config digest mismatch, source artifact digest format wrong, manifest digest mismatch, content violation, valid pair.

**CLI**:
```bash
python3 testkit/stock-opencode/verify_shape_manifest.py <manifest_path> <certificate_path>
```
- Missing/bad → exit 1, stderr: `FAIL_MANIFEST_*` or `BLOCKED_MANIFEST_MISSING`
- Valid pair → exit 0, stdout: `VERIFIED`

## A4.3: Runbook/Governance Corrections

**Files**: `iteration3_m2_operator_runbook.md`, `iteration3_m2_post_certificate_dispatch.md`

**Runbook changes**:
- Add manifest generation step: `_certify()` called first, then manifest written with `atomic_shape_write`, then certificate
- Add `verify_shape_manifest.py` to the verification sequence
- If orphan manifest is detected (`BLOCKED_ORPHAN_SHAPE_MANIFEST`), operator removes `lifecycle-shape-manifest.json` manually: `rm real-task/lifecycle-shape-manifest.json`
- The operator produces both files locally; neither is auto-committed
- Independent evidence audit now verifies both files, cross-checks the structural digest binding, and validates the source binding digest

**Post-certificate dispatch changes** (no edit needed — already references lifecycle shape manifest as required for B2):
- Confirm B2 remains blocked until both `lifecycle-shape-manifest.json` and `lifecycle-certificate.json` exist with verified cross-binding and source artifact digest consistency

## Inputs/Outputs/Files/Acceptance

| Item | Path | Action |
|------|------|--------|
| Manifest generator | `discover_lifecycle.py` | Extend (A4.1) |
| Manifest tests | `test_discover_lifecycle.py` | 27 new tests (A4.1) |
| Manifest verifier | `verify_shape_manifest.py` | New (A4.2) |
| Manifest verifier tests | `test_verify_shape_manifest.py` | New, 17 tests (A4.2) |
| Shape manifest | `real-task/lifecycle-shape-manifest.json` | Output (operator run) |
| Certificate | `real-task/lifecycle-certificate.json` | Output (operator run, unchanged) |

**Acceptance**:
```bash
python3 -m unittest discover -s testkit/stock-opencode -p 'test_*.py' -v
```
All tests PASS.

**No-go**: Manifest digest mismatch → `FAIL_MANIFEST_DIGEST`. Certificate structural digest mismatch → `FAIL_MANIFEST_CERTIFICATE_BINDING`. Source binding digest mismatch → `FAIL_MANIFEST_SOURCE_BINDING`. All block B2.

## Key Constraint

**Real certificate alone still cannot unblock B2.** The certificate proves a real OpenCode session completed with question→diff→permission→stop, but it does not prove the structural property shapes of the live events, the ID relationship booleans, or the source artifact digest binding. The shape manifest is required for B2 to map real event types to `StockObservationOutcome` variants and verify the entire evidence bundle. Without both files verified and cross-bound, the mapper remains blocked.
