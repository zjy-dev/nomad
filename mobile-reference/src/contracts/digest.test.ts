/**
 * Tests for canonical JSON + SHA-256 digest.
 *
 * These tests verify that the TypeScript implementation matches the Python
 * spec exactly by checking the golden snapshots in contracts/traces/*.
 */

import { describe, it, expect } from 'vitest';
import { canonicalJson, computeSnapshotDigest, stripDigest, verifySnapshotDigest } from './digest';
import { loadAllGoldenSnapshots } from './_test-helpers';

describe('canonicalJson', () => {
  it('sorts object keys alphabetically', () => {
    const obj = { z: 1, a: 2, m: 3 };
    expect(canonicalJson(obj)).toBe('{"a":2,"m":3,"z":1}');
  });

  it('preserves array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles nested objects with key sorting', () => {
    const obj = { outer: { b: 1, a: 2 } };
    expect(canonicalJson(obj)).toBe('{"outer":{"a":2,"b":1}}');
  });

  it('uses null/true/false literals', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(false)).toBe('false');
  });

  it('strips undefined values from objects', () => {
    expect(canonicalJson({ a: 1, b: undefined, c: 2 })).toBe('{"a":1,"c":2}');
  });

  it('throws on non-finite numbers', () => {
    expect(() => canonicalJson(Infinity)).toThrow();
    expect(() => canonicalJson(NaN)).toThrow();
  });

  it('round-trips Unicode strings via ensure_ascii=false equivalent', () => {
    // Python's json.dumps(ensure_ascii=False) keeps UTF-8 codepoints literal.
    expect(canonicalJson({ msg: 'hello' })).toBe('{"msg":"hello"}');
    expect(canonicalJson({ msg: '你好' })).toBe('{"msg":"你好"}');
  });

  it('canonicalizes the exact Python output for a known complex object', () => {
    // This matches: json.dumps(obj, sort_keys=True, separators=(',', ':'),
    // ensure_ascii=False)
    const obj = {
      session_id: 'abc',
      snapshot_seq: 5,
      nested: { a: 1, b: [1, 2, 3] },
    };
    expect(canonicalJson(obj)).toBe(
      '{"nested":{"a":1,"b":[1,2,3]},"session_id":"abc","snapshot_seq":5}'
    );
  });
});

describe('stripDigest', () => {
  it('removes the digest field while preserving others', () => {
    const snap = { session_id: 's1', digest: 'sha256:abc', last_applied_seq: 3 };
    const out = stripDigest(snap);
    expect(out).toEqual({ session_id: 's1', last_applied_seq: 3 });
    expect(out.digest).toBeUndefined();
  });

  it('does not mutate the input', () => {
    const snap = { session_id: 's1', digest: 'sha256:abc' };
    stripDigest(snap);
    expect('digest' in snap).toBe(true);
  });
});

describe('computeSnapshotDigest — golden snapshots', () => {
  const golden = loadAllGoldenSnapshots();

  for (const { file, snapshot } of golden) {
    it(`matches ${file}`, async () => {
      const digest = await computeSnapshotDigest(snapshot);
      expect(digest).toBe(snapshot.digest);
    });
  }
});

describe('verifySnapshotDigest', () => {
  it('returns ok=true when digest matches', async () => {
    const snap = loadAllGoldenSnapshots()[0].snapshot;
    const result = await verifySnapshotDigest(snap);
    expect(result).toEqual({ ok: true });
  });

  it('returns ok=false with expected/actual when digest is tampered', async () => {
    const snap = { ...loadAllGoldenSnapshots()[0].snapshot, digest: 'sha256:bad' };
    const result = await verifySnapshotDigest(snap);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.expected).toBeTruthy();
      expect(result.actual).toBe('sha256:bad');
    }
  });

  it('returns ok=false when digest is missing', async () => {
    const snap = { ...loadAllGoldenSnapshots()[0].snapshot };
    delete snap.digest;
    const result = await verifySnapshotDigest(snap);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.actual).toBe('<missing>');
    }
  });
});
