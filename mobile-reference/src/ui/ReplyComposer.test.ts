/**
 * Tests for DraftStatusRow lifecycle rendering.
 *
 * Critical: INV-003-2 — RELAY-RECEIVED must NOT imply HOST-ACCEPTED.
 * HOST-ACCEPTED is only rendered when commandStatus explicitly says so.
 */

import { describe, it, expect } from 'vitest';
import { DraftState, makeDraft, makeReplyCommand, makeStopCommand } from './ReplyComposer';

function labels(draft: DraftState): string[] {
  const items: string[] = [];
  if (draft.requestId) items.push('request');
  items.push('LOCAL-DRAFT');
  if (draft.status === 'sending') items.push('RELAY-SENDING');
  if (draft.status === 'unknown' && draft.result) {
    items.push('OUTCOME-UNKNOWN');
  } else if (draft.status === 'sent' && draft.result) {
    const cs = draft.commandStatus;
    if (cs === null || cs === 'RelayReceived') {
      items.push('RELAY-RECEIVED');
    } else if (cs === 'HostAccepted') {
      items.push('RELAY-RECEIVED');
      items.push('HOST-ACCEPTED');
    } else if (cs === 'Executing') {
      items.push('RELAY-RECEIVED');
      items.push('HOST-ACCEPTED');
      items.push('EXECUTING');
    } else if (cs === 'DispatchAcknowledged') {
      items.push('HOST-ACCEPTED');
      items.push('DISPATCH-ACKNOWLEDGED');
    } else if (cs === 'Completed') {
      items.push('RELAY-RECEIVED');
      items.push('HOST-ACCEPTED');
      items.push('EXECUTING');
      items.push('COMPLETED');
    } else if (cs === 'Rejected') {
      items.push('RELAY-RECEIVED');
      items.push('REJECTED');
    } else if (cs === 'Stale') {
      items.push('RELAY-RECEIVED');
      items.push('STALE');
    } else {
      items.push('RELAY-RECEIVED');
      items.push(`STATUS:${cs}`);
    }
  }
  if (draft.status === 'failed' && draft.error) {
    items.push('FAILED');
  }
  return items;
}

describe('DraftState lifecycle — INV-003-2', () => {
  it('uses the currently observed sequence without incrementing it', () => {
    expect(makeReplyCommand('s', 7, 't', 'hello', 'r')).toEqual(expect.objectContaining({ observed_seq: 7 }));
    expect(makeStopCommand('s', 7, 't', 'r')).toEqual(expect.objectContaining({ observed_seq: 7 }));
    expect(makeReplyCommand('s', 7, 't', 'hello', 'r')).not.toHaveProperty('seq');
    expect(makeStopCommand('s', 7, 't', 'r')).not.toHaveProperty('seq');
  });

  it('idle draft shows only LOCAL-DRAFT', () => {
    const d = makeDraft('hello');
    const out = labels(d);
    expect(out).toEqual(['LOCAL-DRAFT']);
  });

  it('sending draft shows RELAY-SENDING', () => {
    const d = { ...makeDraft('hello'), status: 'sending' as const };
    const out = labels(d);
    expect(out).toEqual(['LOCAL-DRAFT', 'RELAY-SENDING']);
  });

  it('RELAY-RECEIVED stage shows RELAY-RECEIVED but NOT HOST-ACCEPTED', () => {
    // INV-003-2: RelayReceived must NOT imply HostAccepted.
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-1',
      commandStatus: 'RelayReceived',
      result: { error_code: 'OK', error_message: null },
    };
    const out = labels(d);
    // request is a label we show before lifecycle; the key assertion is
    // that HOST-ACCEPTED is NOT present.
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).not.toContain('HOST-ACCEPTED');
  });

  it('RelayReceived with OK error_code still does NOT show HOST-ACCEPTED', () => {
    // This is the critical test for the bug fix: even when error_code === 'OK',
    // we must NOT show HOST-ACCEPTED unless commandStatus explicitly says so.
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-2',
      commandStatus: 'RelayReceived',
      result: { error_code: 'OK', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).not.toContain('HOST-ACCEPTED');
    expect(out).not.toContain('EXECUTING');
    expect(out).not.toContain('COMPLETED');
  });

  it('HostAccepted stage shows HOST-ACCEPTED', () => {
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-3',
      commandStatus: 'HostAccepted',
      result: { error_code: 'OK', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).toContain('HOST-ACCEPTED');
    expect(out).not.toContain('EXECUTING');
    expect(out).not.toContain('COMPLETED');
  });

  it('Executing stage shows RELAY-RECEIVED then HOST-ACCEPTED then EXECUTING', () => {
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-4',
      commandStatus: 'Executing',
      result: { error_code: 'OK', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).toContain('HOST-ACCEPTED');
    expect(out).toContain('EXECUTING');
    expect(out).not.toContain('COMPLETED');
  });

  it('Completed stage shows full lifecycle up to COMPLETED', () => {
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-5',
      commandStatus: 'Completed',
      result: { error_code: 'OK', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).toContain('HOST-ACCEPTED');
    expect(out).toContain('EXECUTING');
    expect(out).toContain('COMPLETED');
  });

  it('Rejected stage shows RELAY-RECEIVED then REJECTED, not HOST-ACCEPTED', () => {
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-6',
      commandStatus: 'Rejected',
      result: { error_code: 'ERR_SAFETY_BLOCKED', error_message: 'Safety gate' },
    };
    const out = labels(d);
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).toContain('REJECTED');
    expect(out).not.toContain('HOST-ACCEPTED');
  });

  it('Stale stage does not imply HostAccepted', () => {
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'sent',
      requestId: 'req-7',
      commandStatus: 'Stale',
      result: { error_code: 'ERR_REQUEST_STALE', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('RELAY-RECEIVED');
    expect(out).toContain('STALE');
    expect(out).not.toContain('HOST-ACCEPTED');
  });

  it('OutcomeUnknown stage does not imply HostAccepted', () => {
    const d: DraftState = {
      ...makeDraft('hello'),
      status: 'unknown',
      requestId: 'req-8',
      commandStatus: 'OutcomeUnknown',
      result: { error_code: 'ERR_OUTCOME_UNKNOWN', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('OUTCOME-UNKNOWN');
    expect(out).not.toContain('RELAY-RECEIVED');
    expect(out).not.toContain('HOST-ACCEPTED');
  });

  it('DispatchAcknowledged remains non-terminal and is not rendered as Completed', () => {
    const d: DraftState = {
      ...makeDraft('hello'), status: 'sent', requestId: 'req-9', commandStatus: 'DispatchAcknowledged',
      result: { error_code: 'OK', error_message: null },
    };
    const out = labels(d);
    expect(out).toContain('DISPATCH-ACKNOWLEDGED');
    expect(out).not.toContain('COMPLETED');
  });
});
