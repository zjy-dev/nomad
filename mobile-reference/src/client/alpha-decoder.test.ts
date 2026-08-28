import { describe, expect, it } from 'vitest';
import { AlphaAvailabilityError, AlphaResponseError, decodeAlphaSession } from './alpha-decoder';
import { computeSnapshotDigest } from '../contracts/digest';

async function response() {
  const value = {
    schema: 'nomad.alpha.readonly.v1',
    status: 'available',
    session: {
      session_id: `sess-${'1'.repeat(32)}`,
      semantics_version: '1.0.0',
      turn_id: `turn-${'2'.repeat(32)}`,
      turn_state: 'Running',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      updated_at: '2026-08-24T10:00:00Z',
    },
    last_applied_seq: 8,
    digest: 'sha256:placeholder',
    events: [
      { event_type: 'turn.started', session_id: `sess-${'1'.repeat(32)}`, event_id: `evt-${'3'.repeat(32)}`, turn_id: `turn-${'2'.repeat(32)}`, seq: 2, timestamp: '2026-08-24T09:59:00Z', durable: true },
      { event_type: 'session.updated', session_id: `sess-${'1'.repeat(32)}`, event_id: `evt-${'4'.repeat(32)}`, turn_id: null, seq: 8, timestamp: '2026-08-24T10:00:00Z', durable: true },
    ],
    changes: { status: 'unavailable', files: [] },
    provenance: { source: 'local-alpha-projector', relay_ingress_verified: true, gateway_schema_verified: true },
  };
  value.digest = await computeSnapshotDigest(value);
  return value;
}

function failure(status: 'unavailable' | 'unknown') {
  return {
    schema: 'nomad.alpha.readonly.v1',
    status,
    session: null,
    last_applied_seq: null,
    digest: null,
    events: [],
    changes: { status: 'unavailable', files: [] },
    provenance: { source: 'local-alpha-gateway', relay_ingress_verified: false, gateway_schema_verified: false },
  };
}

describe('decodeAlphaSession', () => {
  it('maps an available response with a verified canonical digest to a read-only SessionView', async () => {
    const view = await decodeAlphaSession(await response());
    expect(view.mode).toBe('readonly-alpha');
    expect(view.writable).toBe(false);
    expect(view.approval).toBeNull();
    expect(view.state.lastAppliedSeq).toBe(8);
    expect(view.state.events.map((event) => event.seq)).toEqual([2, 8]);
    expect(view.state.events.every((event) => Object.keys(event.payload).length === 0)).toBe(true);
    expect(view.changes).toEqual(expect.objectContaining({ status: 'unavailable', files: [] }));
  });

  it.each([
    ['schema', (value: Awaited<ReturnType<typeof response>>) => { value.schema = 'nomad.alpha.other.v1'; }],
    ['digest shape', (value: Awaited<ReturnType<typeof response>>) => { value.digest = 'sha256:bad'; }],
    ['provenance', (value: Awaited<ReturnType<typeof response>>) => { value.provenance.gateway_schema_verified = false; }],
    ['event order', (value: Awaited<ReturnType<typeof response>>) => { value.events[1].seq = 1; }],
  ])('rejects invalid %s instead of trusting a cast', async (_name, mutate) => {
    const value = await response();
    mutate(value);
    await expect(decodeAlphaSession(value)).rejects.toThrow(AlphaResponseError);
  });

  it('rejects a well-formed but incorrect digest', async () => {
    const value = await response();
    value.digest = `sha256:${'0'.repeat(64)}`;
    const error = await decodeAlphaSession(value).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AlphaResponseError);
    expect((error as AlphaResponseError).status).toBe('unknown');
  });

  it.each(['unavailable', 'unknown'] as const)('recognizes a valid 200 %s envelope without fabricating SessionView', async (status) => {
    const error = await decodeAlphaSession(failure(status)).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AlphaAvailabilityError);
    expect((error as AlphaAvailabilityError).status).toBe(status);
    expect(error).not.toBeInstanceOf(AlphaResponseError);
  });

  it('treats malformed failure envelopes as incompatible unknown errors', async () => {
    const malformed = failure('unavailable');
    malformed.provenance.gateway_schema_verified = true;
    await expect(decodeAlphaSession(malformed)).rejects.toThrow(AlphaResponseError);
  });
});
