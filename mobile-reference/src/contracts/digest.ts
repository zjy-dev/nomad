/**
 * Canonical JSON + SHA-256 digest (snapshot.schema.json digest_spec).
 *
 * Format: sha256:<hex>
 * Encoding: JSON with sort_keys + separators=(',', ':') + ensure_ascii=false, UTF-8.
 *
 * Produces the same output as the Python spec for the same object. Verified
 * against golden snapshots in tests.
 */

// SHA-256 uses Web Crypto, available in supported browsers and Node 24 tests.

export interface SnapshotLike {
  session_id?: unknown;
  snapshot_seq?: unknown;
  last_applied_seq?: unknown;
  turn_state?: unknown;
  turn_id?: unknown;
  host_connectivity?: unknown;
  client_freshness?: unknown;
  state_summary?: unknown;
  created_at?: unknown;
  version?: unknown;
  [key: string]: unknown;
}

export function canonicalJson(value: unknown): string {
  return canon(value);
}

function canon(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    // Match JSON number formatting used by Python's json.dumps default
    if (!Number.isFinite(value)) throw new Error('non-finite number not allowed in canonical JSON');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canon).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value as object).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = (value as Record<string, unknown>)[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canon(v));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error('unsupported value for canonical JSON: ' + typeof value);
}

/** Returns the snapshot object stripped of its `digest` field. */
export function stripDigest(snapshot: SnapshotLike): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(snapshot)) {
    if (k === 'digest') continue;
    out[k] = snapshot[k];
  }
  return out;
}

/**
 * Compute the expected sha256:<hex> digest for a snapshot object (with or
 * without a `digest` field). The digest field is excluded from hashing.
 */
export async function computeSnapshotDigest(snapshot: SnapshotLike): Promise<string> {
  const stripped = stripDigest(snapshot);
  const canonical = canon(stripped);
  const bytes = new TextEncoder().encode(canonical);
  const hashBytes = await sha256(bytes);
  return 'sha256:' + toHex(hashBytes);
}

function sha256(data: Uint8Array): Promise<Uint8Array> {
  if (globalThis.crypto?.subtle?.digest) {
    const buffer = data.slice().buffer as ArrayBuffer;
    return globalThis.crypto.subtle
      .digest('SHA-256', buffer)
      .then((buf: ArrayBuffer) => new Uint8Array(buf));
  }
  return Promise.reject(new Error('Web Crypto SHA-256 is unavailable in this environment'));
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Verify that `snapshot.digest` matches the canonical hash of the rest of
 * the snapshot. Returns { ok: true } or { ok: false, expected, actual }.
 */
export async function verifySnapshotDigest(
  snapshot: SnapshotLike & { digest?: string }
): Promise<{ ok: true } | { ok: false; expected: string; actual: string }> {
  const expected = await computeSnapshotDigest(snapshot);
  if (expected === snapshot.digest) return { ok: true };
  return { ok: false, expected, actual: snapshot.digest ?? '<missing>' };
}
