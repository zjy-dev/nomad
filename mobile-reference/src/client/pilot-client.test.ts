import { describe, expect, it } from 'vitest';
import { PilotSessionClient } from './pilot-client';

describe('PilotSessionClient', () => {
  it('loads a deterministic product session without UI-specific state', async () => {
    const view = await new PilotSessionClient().loadCurrentSession();
    expect(view.provenance).toBe('pilot');
    expect(view.state.session.turn_state).toBe('NeedsPermission');
    expect(view.state.session.host_connectivity).toBe('Online');
    expect(view.state.session.client_freshness).toBe('Live');
    expect(view.approval?.tool).toBeTruthy();
  });

  it('never manufactures diff files from diffFileCount', async () => {
    const view = await new PilotSessionClient().loadCurrentSession();
    view.state.diffFileCount = 3;
    expect(view.changes).toEqual(expect.objectContaining({ status: 'empty', source: null, baseline: null, files: [] }));
  });

  it('keeps golden traces behind the explicit lab API', async () => {
    const client = new PilotSessionClient();
    await expect(client.listTraceSessions()).resolves.toHaveLength(9);
    await expect(client.loadTraceSession('trace-001-normal-completion')).resolves.toEqual(expect.objectContaining({ provenance: 'trace-lab' }));
  });

  it('keeps version-incompatible trace stale after digest verification', async () => {
    const view = await new PilotSessionClient().loadTraceSession('trace-007-version-mismatch');
    expect(view.state.versionStatus).toBe('incompatible');
    expect(view.state.session.client_freshness).toBe('Stale');
  });

  it('adapts explicit public deny to the historical internal decision without exposing allow_once', async () => {
    const client = new PilotSessionClient();
    const result = await client.submitCommand({
      command_type: 'deny',
      request_id: 'public-deny-1',
      session_id: 'pilot-session',
      observed_seq: 3,
      permission_id: 'perm-1',
      action_hash: 'sha256:deny-only',
      expires_at: '2026-08-25T12:00:00Z',
    });
    expect(result.result.error_code).toBe('OK');
  });

  it.each([
    { command_type: 'interrupt_and_send', request_id: 'legacy-1', session_id: 'pilot-session', observed_seq: 3, interrupt_turn_id: 'turn-1', new_content: 'next' },
    { command_type: 'permission_decision', request_id: 'legacy-2', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', decision: 'allow_once', action_hash: 'hash', expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'deny', request_id: 'missing-permission', session_id: 'pilot-session', observed_seq: 3, action_hash: 'hash', expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'deny', request_id: 'missing-action', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'deny', request_id: 'missing-expiry', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: 'hash' },
    { command_type: 'reply', request_id: 'polluted-status', session_id: 'pilot-session', observed_seq: 3, content: 'hello', status: 'Completed' },
    { command_type: 'stop', request_id: 'polluted-result', session_id: 'pilot-session', observed_seq: 3, target_turn_id: 'turn-1', result: { error_code: 'OK' } },
    { command_type: 'deny', request_id: 'polluted-decision', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: 'hash', expires_at: '2026-08-25T12:00:00Z', decision: 'deny' },
    { command_type: 'reply', request_id: 'legacy-seq', session_id: 'pilot-session', seq: 3, content: 'hello' },
    { command_type: 'reply', request_id: 'r'.repeat(129), session_id: 'pilot-session', observed_seq: 3, content: 'hello' },
    { command_type: 'reply', request_id: 'long-session', session_id: 's'.repeat(65), observed_seq: 3, content: 'hello' },
    { command_type: 'reply', request_id: 'long-content', session_id: 'pilot-session', observed_seq: 3, content: 'x'.repeat(65537) },
    { command_type: 'reply', request_id: 'long-turn', session_id: 'pilot-session', observed_seq: 3, turn_id: 't'.repeat(65), content: 'hello' },
    { command_type: 'deny', request_id: 'long-permission', session_id: 'pilot-session', observed_seq: 3, permission_id: 'p'.repeat(129), action_hash: 'hash', expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'deny', request_id: 'long-action', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: 'h'.repeat(129), expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'stop', request_id: 'long-target', session_id: 'pilot-session', observed_seq: 3, target_turn_id: 't'.repeat(65) },
    { command_type: 'reply', request_id: 'unsafe-seq', session_id: 'pilot-session', observed_seq: Number.MAX_SAFE_INTEGER + 1, content: 'hello' },
    { command_type: 'deny', request_id: 'offset-time', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: 'hash', expires_at: '2026-08-25T12:00:00+00:00' },
    { command_type: 'deny', request_id: 'fraction-time', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: 'hash', expires_at: '2026-08-25T12:00:00.000Z' },
    { command_type: 'deny', request_id: 'invalid-date', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: 'hash', expires_at: '2026-02-30T12:00:00Z' },
    { command_type: 'reply', request_id: '', session_id: 'pilot-session', observed_seq: 3, content: 'hello' },
    { command_type: 'reply', request_id: 'empty-session', session_id: '', observed_seq: 3, content: 'hello' },
    { command_type: 'reply', request_id: 'empty-content', session_id: 'pilot-session', observed_seq: 3, content: '' },
    { command_type: 'reply', request_id: 'empty-turn', session_id: 'pilot-session', observed_seq: 3, turn_id: '', content: 'hello' },
    { command_type: 'deny', request_id: 'empty-permission', session_id: 'pilot-session', observed_seq: 3, permission_id: '', action_hash: 'hash', expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'deny', request_id: 'empty-action', session_id: 'pilot-session', observed_seq: 3, permission_id: 'perm-1', action_hash: '', expires_at: '2026-08-25T12:00:00Z' },
    { command_type: 'stop', request_id: 'empty-target', session_id: 'pilot-session', observed_seq: 3, target_turn_id: '' },
  ])('runtime-rejects non-public or incomplete command $command_type', async (legacy) => {
    const result = await new PilotSessionClient().submitCommand(legacy as never);
    expect(result).toEqual({ status: 'Rejected', result: { error_code: 'ERR_SAFETY_BLOCKED', error_message: 'Unsupported public command.' } });
  });

  it('rejects inherited required fields and custom prototypes', async () => {
    const inherited = Object.assign(Object.create({ request_id: 'inherited' }), {
      command_type: 'reply', session_id: 'pilot-session', observed_seq: 3, content: 'hello',
    });
    const result = await new PilotSessionClient().submitCommand(inherited as never);
    expect(result.result.error_code).toBe('ERR_SAFETY_BLOCKED');
  });

  it('accepts an exact null-prototype public request', async () => {
    const request = Object.assign(Object.create(null), {
      command_type: 'reply', request_id: 'null-prototype', session_id: 'pilot-session', observed_seq: 3, content: 'hello',
    });
    const result = await new PilotSessionClient().submitCommand(request);
    expect(result.result.error_code).toBe('OK');
  });
});
