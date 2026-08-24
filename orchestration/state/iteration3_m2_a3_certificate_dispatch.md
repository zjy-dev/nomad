# Iteration 3 M2 A3: Lifecycle Certificate Verification Dispatch

**Sole Authority Dispatch** — *A3: Read-only certificate verifier, runbook/audit correction, governance. No implementation of B/C.*

## Scope

One new file `testkit/stock-opencode/verify_certificate.py`, one new test file `testkit/stock-opencode/test_verify_certificate.py`. Corrections to `iteration3_completion_audit.md` and `iteration3_m2_operator_runbook.md`. No changes to `discover_lifecycle.py`, `observing_proxy.py`, `m2_integration.py`, any Rust, any Relay, receipts.

## A3: Certificate Verifier (`verify_certificate.py`)

### Design

`verify_certificate(path: Path) -> Verdict` is a **read-only, stdlib-only** function that validates a `lifecycle-certificate.json` against the exact schema and content-free contract. It has **no private authority token, no ability to write, sign, or unlock**. The only tokens it uses are the public constants exported from `discover_lifecycle.py` (route lists, marker candidates, ASCII event patterns).

**Validation rules** (exact match to `_validate_completed` logic, but without the `_COMPLETION_TOKEN` gate):

1. **Schema version**: `"nomad.stock-opencode.lifecycle-certificate.v1"`
2. **Required fields**: `schema_version`, `expected_event_sequence`, `diff_file_count`, `v1_routes_verified`, `v2_routes_verified`, `structural_digest`. No extra, no missing.
3. **Event sequence**: exactly 4 events, each matching `_ASCII_EVENT` regex and belonging to `MARKER_CANDIDATES` in `MARKER_ORDER`.
4. **Diff file count**: int, 1 ≤ count ≤ 10000.
5. **V1 routes**: exactly `["/session(POST)", "/event", "/session/{id}", "/session/{id}/diff", "/question", "/permission"]`.
6. **V2 routes**: exactly the routes from `verified_routes()` for session_prompt, question_reply, permission_reply, stop.
7. **Structural digest**: SHA256 of sorted canonical JSON of the other 5 fields, matches the claimed `structural_digest`.
8. **Content-free**: no field contains credential, prompt, source, path, command, diff_content, personal_identifier, or raw_session_content.

**CLI interface**:
```bash
python3 testkit/stock-opencode/verify_certificate.py <path>
```
- Missing file → exit 1, stderr: `BLOCKED_CERTIFICATE_MISSING`
- Valid fixture → exit 0, stdout: `VERIFIED`
- Tampered file → exit 1, stderr: `FAIL_CERTIFICATE_<REASON>`

### Test file (`test_verify_certificate.py`)

| # | Test | Expected |
|---|------|----------|
| 1 | Missing file path | `BLOCKED_CERTIFICATE_MISSING`, exit 1 |
| 2 | Empty JSON object | `FAIL`, exit 1 |
| 3 | Wrong schema version | `FAIL`, exit 1 |
| 4 | Missing field | `FAIL`, exit 1 |
| 5 | Extra field | `FAIL`, exit 1 |
| 6 | Wrong event count | `FAIL`, exit 1 |
| 7 | Wrong event order | `FAIL`, exit 1 |
| 8 | Non-ASCII event name | `FAIL`, exit 1 |
| 9 | Wrong diff_file_count type | `FAIL`, exit 1 |
| 10 | Wrong V1 routes | `FAIL`, exit 1 |
| 11 | Wrong V2 routes | `FAIL`, exit 1 |
| 12 | Digest mismatch | `FAIL`, exit 1 |
| 13 | Content field contains forbidden pattern | `FAIL`, exit 1 |
| 14 | Valid fixture from `_evidence()` | `VERIFIED`, exit 0 |

### Corrections to `iteration3_completion_audit.md`

1. **Product phase plan**: `PASS` → `PARTIAL` — no formal M2 entrance gate record exists.
2. **Credential isolation**: `PASS` → `PARTIAL` — the PASS is for code/test boundary only, not a real-scope audit with real credential exposure scanning.
3. **At-most-once**: `PASS` → `PARTIAL` — the PASS is for the synthetic scaffold, not real upstream behavior with real OpenCode session dedup.
4. **Multi-Agent decoupling**: `PASS` → `PARTIAL` — only the OpenCode adapter anti-corruption layer is implemented; Host/Relay/Mobile portability is not yet proven.

### Corrections to `iteration3_m2_operator_runbook.md`

1. **Command**: `python3 testkit/stock-opencode/discover_lifecycle.py` (not `python3 -m testkit.stock-opencode...` — hyphen in directory name breaks module import).
2. **Provider model counts**: Actual isolated 1.18.16 probes show OpenAI 48, Anthropic 15, Google 37 (both `GEMINI_API_KEY` and `GOOGLE_GENERATIVE_AI_API_KEY`), OpenRouter 339, DeepSeek 4. Remove the "1 model each" column.
3. **Model request**: A0 DOES send a disposable prompt + model request via OpenCode. Replace "no actual model request" with "disposable project-owned prompt, zero operator content".
4. **Validation section**: Replace private `_validate_completed` + fake `_COMPLETION_TOKEN` + `jsonschema` import with a call to the new `verify_certificate.py` CLI tool. No private APIs, no third-party libraries.
5. **Error explanations**: `BLOCKED_UPSTREAM_HTTP_REJECTED` means OpenCode returned 4xx/5xx, not "OpenCode not running". Add `BLOCKED_SSE_TIMEOUT` (OpenCode running but no events within timeout).
6. **Certificate path**: The output shows `certificate_path` as basename (`lifecycle-certificate.json`), not absolute path. Document this.
7. **Governance**: Replace "never commit" with the governance model below.

### A3 Governance

1. **Generated certificate is a local candidate**, not auto-committed. It is produced by the operator runbook, verified by `verify_certificate.py`, and then subject to independent evidence audit.
2. **Independent evidence audit**: Before any versioning, a second party (or automated CI step) runs `verify_certificate.py` on the certificate and confirms `VERIFIED` exit 0. The audit confirms content-free compliance (no forbidden fields).
3. **Explicit user approval**: Only after the audit passes does the user explicitly approve versioning. The versioned artifact is the content-free certificate JSON + the manifest digest that binds it to the known locked runtime.
4. **B/C remains blocked**: Until a reviewed certificate exists in the working tree, B/C packages remain blocked. `RealLifecycleEvidence::Unavailable` is the only variant.
5. **Release blocked**: Until versioned evidence exists in the repository (committed content-free certificate + manifest digest), the release gate remains closed. The `lifecycle-certificate.json` itself is committed only after audit; the `capture-manifest.json` and `official-stock-contract.json` are already committed.

### Files Owned

| File | Action | Owner |
|------|--------|-------|
| `testkit/stock-opencode/verify_certificate.py` | Create | A3 |
| `testkit/stock-opencode/test_verify_certificate.py` | Create | A3 |
| `orchestration/state/iteration3_completion_audit.md` | Edit (4 dimension corrections) | A3 |
| `orchestration/state/iteration3_m2_operator_runbook.md` | Edit (7 corrections) | A3 |

### Acceptance

```bash
# Verifier tests
python3 -m unittest testkit.stock-opencode.test_verify_certificate -v
# 14 tests PASS, no regressions

# CLI smoke
python3 testkit/stock-opencode/verify_certificate.py nonexistent.json
# Exit 1, stderr: BLOCKED_CERTIFICATE_MISSING
```

## B/C Blocked

B1 (capability verification), B2 (receipt emission), C (end-to-end) remain blocked until a reviewed `lifecycle-certificate.json` exists in the working tree and the user has approved versioning. A3's verifier is the read-only gate — it proves the certificate is valid without enabling any production path.