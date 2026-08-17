/**
 * Tests for the deterministic session reducer.
 *
 * Covers: seq monotonicity, gap detection, duplicate idempotency,
 * version mismatch → Stale, OutcomeUnknown handling, safe-operation gate,
 * and snapshot digest verification (pass + tamper).
 */

import { describe, it, expect } from 'vitest';
import {
  reduceEvents,
  initEmptyState,
  recoverFromSnapshot,
  canSubmitSafeOperations,
  applyResumeResult,
  parseDiffCount,
} from './reducer';
import type { ContractEvent } from './types';
import { loadAllGoldenSnapshots, loadGoldenSnapshot } from './_test-helpers';

function makeEvent(
  seq: number,
  type: ContractEvent['event_type'],
  sessionId = 'sess-1',
  turnId: string | null = 'turn-1',
  payload: Record<string, unknown> = {}
): ContractEvent {
  return {
    event_type: type,
    session_id: sessionId,
    turn_id: turnId,
    event_id: `${sessionId}:${seq}`,
    seq,
    timestamp: new Date(Date.now() + seq).toISOString(),
    durable: true,
    payload,
  };
}

describe('reduceEvents — seq monotonicity', () => {
  it('applies events in seq order', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'session.created', 's1', null);
    const ev2 = makeEvent(2, 'turn.started', 's1', 't1');
    const out = reduceEvents(base, [ev1, ev2]);
    expect(out.lastAppliedSeq).toBe(2);
    expect(out.session.turn_state).toBe('Running');
    expect(out.events.length).toBe(2);
  });

  it('applies events with non-contiguous seq (no gap because lastAppliedSeq=0 before)', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev = makeEvent(5, 'turn.started', 's1', 't1');
    const out = reduceEvents(base, [ev]);
    expect(out.lastAppliedSeq).toBe(5);
    // Gap 1..4 should be detected (lastAppliedSeq was 0, so 5 > 1).
    expect(out.gapToSeq).toBe(4);
  });
});

describe('reduceEvents — gap detection', () => {
  it('marks gap when seq > lastAppliedSeq + 1', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'turn.started', 's1', 't1');
    const ev3 = makeEvent(3, 'tool.started', 's1', 't1', { tool_name: 'grep' });
    const out = reduceEvents(base, [ev1, ev3]);
    expect(out.lastAppliedSeq).toBe(3);
    expect(out.gapToSeq).toBe(2);
    const gapNode = out.timeline.find((n) => n.kind === 'gap');
    expect(gapNode).toBeDefined();
    if (gapNode && gapNode.kind === 'gap') {
      expect(gapNode.fromSeq).toBe(2);
      expect(gapNode.toSeq).toBe(2);
    }
  });

  it('clears gap when events fill the hole', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'turn.started', 's1', 't1');
    const ev2 = makeEvent(2, 'tool.started', 's1', 't1', { tool_name: 'grep' });
    const out = reduceEvents(base, [ev1, ev2]);
    expect(out.gapToSeq).toBeNull();
    expect(out.lastAppliedSeq).toBe(2);
  });
});

describe('reduceEvents — duplicate idempotency', () => {
  it('drops duplicate event_id without side effect', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev = makeEvent(1, 'turn.started', 's1', 't1');
    const dup: ContractEvent = { ...ev, event_id: ev.event_id };
    const out = reduceEvents(base, [ev, dup]);
    expect(out.events.length).toBe(1);
    expect(out.duplicatesDropped).toBe(1);
  });

  it('deduplicates across separate reductions', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev = makeEvent(1, 'turn.started', 's1', 't1');
    const once = reduceEvents(base, [ev]);
    const twiec = reduceEvents(once, [ev]);
    expect(twiec.events.length).toBe(1);
    expect(twiec.duplicatesDropped).toBe(1);
  });
});

describe('reduceEvents — OutcomeUnknown handling', () => {
  it('records outcome-unknown tool names', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev = makeEvent(
      1,
      'turn.outcome_unknown',
      's1',
      't1',
      { tool_name: 'shell', reason: 'blocked by safety policy' }
    );
    const out = reduceEvents(base, [ev]);
    expect(out.session.turn_state).toBe('OutcomeUnknown');
    expect(out.outcomeUnknownTools).toEqual(['shell']);
  });

  it('does not duplicate same tool in outcomeUnknownTools', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'turn.outcome_unknown', 's1', 't1', { tool_name: 'shell' });
    const ev2 = makeEvent(2, 'turn.outcome_unknown', 's1', 't1', { tool_name: 'shell' });
    const out = reduceEvents(base, [ev1, ev2]);
    expect(out.outcomeUnknownTools.length).toBe(1);
  });

  it('tracks multiple distinct tools in outcomeUnknownTools', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'turn.outcome_unknown', 's1', 't1', { tool_name: 'shell' });
    const ev2 = makeEvent(2, 'turn.outcome_unknown', 's1', 't1', { tool_name: 'grep' });
    const out = reduceEvents(base, [ev1, ev2]);
    expect(out.outcomeUnknownTools).toEqual(['shell', 'grep']);
  });
});

describe('reduceEvents — tool state transitions', () => {
  it('upserts tool status: started → completed', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'tool.started', 's1', 't1', { tool_name: 'grep' });
    const ev2 = makeEvent(2, 'tool.completed', 's1', 't1', { tool_name: 'grep' });
    const out = reduceEvents(base, [ev1, ev2]);
    expect(out.tools).toEqual([{ tool_name: 'grep', status: 'Completed' }]);
  });

  it('tracks separate tools independently', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'tool.started', 's1', 't1', { tool_name: 'grep' });
    const ev2 = makeEvent(2, 'tool.started', 's1', 't1', { tool_name: 'edit' });
    const ev3 = makeEvent(3, 'tool.failed', 's1', 't1', { tool_name: 'grep' });
    const out = reduceEvents(base, [ev1, ev2, ev3]);
    expect(out.tools).toEqual([
      { tool_name: 'grep', status: 'Failed' },
      { tool_name: 'edit', status: 'Running' },
    ]);
  });
});

describe('reduceEvents — permission state', () => {
  it('sets NeedsPermission and active permission id', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev = makeEvent(1, 'permission.requested', 's1', 't1', {
      permission_id: 'perm_file_edit',
    });
    const out = reduceEvents(base, [ev]);
    expect(out.session.turn_state).toBe('NeedsPermission');
    expect(out.activePermissionId).toBe('perm_file_edit');
  });

  it('resets after permission.resolved', () => {
    const base = initEmptyState({ sessionId: 's1' });
    const ev1 = makeEvent(1, 'permission.requested', 's1', 't1', { permission_id: 'p1' });
    const ev2 = makeEvent(2, 'permission.resolved', 's1', 't1', { permission_id: 'p1' });
    const out = reduceEvents(base, [ev1, ev2]);
    expect(out.session.turn_state).toBe('Running');
    expect(out.activePermissionId).toBeNull();
  });
});

describe('reduceEvents — unknown event types trigger version mismatch', () => {
  it('sets client_freshness=Stale and versionStatus=incompatible', () => {
    const base = initEmptyState({ sessionId: 's1' });
    // Create a synthetic contract event with an unsupported type.
    const bad: ContractEvent = {
      event_type: 'future.protocol.event' as ContractEvent['event_type'],
      session_id: 's1',
      turn_id: 't1',
      event_id: 's1:1',
      seq: 1,
      timestamp: new Date().toISOString(),
      durable: true,
      payload: {},
    };
    const out = reduceEvents(base, [bad]);
    expect(out.versionStatus).toBe('incompatible');
    expect(out.session.client_freshness).toBe('Stale');
  });
});

describe('recoverFromSnapshot — digest verification', () => {
  it('verifies all 9 golden snapshots', async () => {
    const golden = loadAllGoldenSnapshots();
    for (const { snapshot } of golden) {
      const snap = snapshot as any;
      const state = await recoverFromSnapshot(snap, []);
      expect(state.digestStatus).toBe('verified');
      // After verification with no events and no gaps, client should be Live.
      // (version-mismatch snapshot is tested separately)
      if (snap.version !== '0.9.0') {
        expect(state.session.client_freshness).toBe('Live');
      }
    }
  });

  it('sets client_freshness=Stale on digest mismatch', async () => {
    const { snapshot } = loadGoldenSnapshot('snapshot-001-normal-completion.json');
    const tampered = { ...snapshot, digest: 'sha256:deadbeef' } as any;
    const state = await recoverFromSnapshot(tampered, []);
    expect(state.digestStatus).toBe('mismatch');
    expect(state.session.client_freshness).toBe('Stale');
  });

  it('keeps client_freshness=Reconnecting before digest is verified', async () => {
    const base = initEmptyState({ sessionId: 's1' });
    // No snapshot = Reconnecting.
    expect(base.session.client_freshness).toBe('Reconnecting');
  });

  it('marks versionStatus=incompatible for unknown version', async () => {
    const { snapshot } = loadGoldenSnapshot('snapshot-007-version-mismatch.json');
    const mismatched = { ...snapshot, version: '0.9.0' };
    const state = await recoverFromSnapshot(mismatched as any, []);
    expect(state.versionStatus).toBe('incompatible');
    // Because of version incompatibility, client should not be Live.
    expect(state.session.client_freshness).not.toBe('Live');
  });

  it('detects gaps after snapshot recovery', async () => {
    const { snapshot } = loadGoldenSnapshot('snapshot-001-normal-completion.json');
    const state = await recoverFromSnapshot(snapshot as any, [
      makeEvent(10, 'turn.started', 'sess_normal_001', 'turn_001'), // gap: 9..9
    ]);
    expect(state.gapToSeq).toBe(9);
    // With gap still open, client stays Reconnecting, not Live.
    expect(state.session.client_freshness).not.toBe('Live');
  });
});

describe('canSubmitSafeOperations — INV-001-4 gate', () => {
  it('blocks when host is offline', () => {
    const state = initEmptyState({ sessionId: 's1' });
    const offline = { ...state, session: { ...state.session, host_connectivity: 'Offline' as const } };
    const r = canSubmitSafeOperations(offline);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/offline/i);
  });

  it('blocks when client is Reconnecting', () => {
    const state = initEmptyState({ sessionId: 's1' });
    const r = canSubmitSafeOperations(state);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/not live/i);
  });

  it('blocks when client is Stale', () => {
    const state = initEmptyState({ sessionId: 's1' });
    const stale = { ...state, session: { ...state.session, client_freshness: 'Stale' as const } };
    const r = canSubmitSafeOperations(stale);
    expect(r.ok).toBe(false);
  });

  it('blocks when digest status is mismatch', () => {
    const state = initEmptyState({ sessionId: 's1' });
    const bad = {
      ...state,
      session: { ...state.session, host_connectivity: 'Online' as const, client_freshness: 'Live' as const },
      digestStatus: 'mismatch' as const,
    };
    const r = canSubmitSafeOperations(bad);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/mismatch/i);
  });

  it('blocks when version is incompatible', () => {
    const state = initEmptyState({ sessionId: 's1' });
    const bad = {
      ...state,
      session: { ...state.session, host_connectivity: 'Online' as const, client_freshness: 'Live' as const },
      versionStatus: 'incompatible' as const,
    };
    const r = canSubmitSafeOperations(bad);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/version/i);
  });

  it('passes with Online + Live + verified + ok version', () => {
    const state = initEmptyState({ sessionId: 's1' });
    const good = {
      ...state,
      session: { ...state.session, host_connectivity: 'Online' as const, client_freshness: 'Live' as const },
      digestStatus: 'verified' as const,
    };
    const r = canSubmitSafeOperations(good);
    expect(r).toEqual({ ok: true });
  });
});

describe('applyResumeResult', () => {
  it('handles ERR_GAP_DETECTED → stale + gap + note', async () => {
    const state = initEmptyState({ sessionId: 's1' });
    const out = await applyResumeResult(state, {
      result_code: 'ERR_GAP_DETECTED',
      session_id: 's1',
      gap_from_seq: 3,
      gap_to_seq: 7,
    });
    expect(out.session.client_freshness).toBe('Stale');
    expect(out.gapToSeq).toBe(7);
    const note = out.timeline.find((n) => n.kind === 'note');
    expect(note).toBeDefined();
  });

  it('handles ERR_SNAPSHOT_MISMATCH → digest mismatch + stale', async () => {
    const state = initEmptyState({ sessionId: 's1' });
    const out = await applyResumeResult(state, {
      result_code: 'ERR_SNAPSHOT_MISMATCH',
      session_id: 's1',
    });
    expect(out.digestStatus).toBe('mismatch');
    expect(out.session.client_freshness).toBe('Stale');
  });

  it('handles ERR_VERSION_INCOMPATIBLE', async () => {
    const state = initEmptyState({ sessionId: 's1' });
    const out = await applyResumeResult(state, {
      result_code: 'ERR_VERSION_INCOMPATIBLE',
      session_id: 's1',
    });
    expect(out.versionStatus).toBe('incompatible');
    expect(out.session.client_freshness).toBe('Stale');
  });

  it('handles ERR_RETENTION_EXCEEDED', async () => {
    const state = initEmptyState({ sessionId: 's1' });
    const out = await applyResumeResult(state, {
      result_code: 'ERR_RETENTION_EXCEEDED',
      session_id: 's1',
    });
    expect(out.session.client_freshness).toBe('Stale');
  });

  it('handles ERR_NO_SESSION', async () => {
    const state = initEmptyState({ sessionId: 's1' });
    const out = await applyResumeResult(state, {
      result_code: 'ERR_NO_SESSION',
      session_id: 's1',
    });
    expect(out.session.client_freshness).toBe('Stale');
  });
});

describe('parseDiffCount', () => {
  it('extracts number from "3 files changed"', () => {
    expect(parseDiffCount('3 files changed')).toBe(3);
    expect(parseDiffCount('1 file changed')).toBe(1);
    expect(parseDiffCount('100 files changed')).toBe(100);
  });

  it('returns null for unparseable summary', () => {
    expect(parseDiffCount(null)).toBeNull();
    expect(parseDiffCount(undefined)).toBeNull();
    expect(parseDiffCount('')).toBeNull();
    expect(parseDiffCount('something else')).toBeNull();
  });
});
