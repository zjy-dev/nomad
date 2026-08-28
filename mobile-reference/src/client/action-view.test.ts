import { describe, expect, it } from 'vitest';
import { PilotSessionClient } from './pilot-client';
import type { BrowserCommandCapability, SessionView } from './types';
import { composeActionView } from './action-view';

const NOW = Date.parse('2026-08-26T05:00:00Z');

describe('composeActionView', () => {
  it('composes a generic deny card without approval facts or capability secrets', async () => {
    const view = await officialView('NeedsPermission');
    view.approval = null;
    const binding = capability(view);

    const action = composeActionView(view, binding, NOW);

    expect(action.deny).toEqual({
      visible: true, enabled: true, disabledReason: null,
      summary: 'Host reports one protected action pending',
      expiresAt: '2026-08-26T05:00:20.000Z',
    });
    expect(JSON.stringify(action)).not.toContain('permission_alias');
    expect(JSON.stringify(action)).not.toContain('sha256:');
    expect(JSON.stringify(action)).not.toContain('turn_alias');
  });

  it('keeps Stop available for an active projection even when projection turn_id is null', async () => {
    const view = await officialView('Running');
    view.state.session.turn_id = null;

    expect(composeActionView(view, capability(view), NOW).stop).toEqual({
      visible: true, enabled: true, disabledReason: null,
      scope: 'Stop the current Agent turn on this Mac',
    });
  });

  it('does not turn generic NeedsInput or a reply capability into a writable reply', async () => {
    const view = await officialView('NeedsInput');
    const reply = composeActionView(view, capability(view), NOW).reply;

    expect(reply.visible).toBe(true);
    expect(reply.enabled).toBe(false);
    expect(reply.explanation).toBe('Reviewable question context is not yet available.');
    expect(reply.disabledReason).toMatch(/safe question summary/i);
  });

  it('enables reply only when the capability contains the safe pending-question summary', async () => {
    const view = await officialView('NeedsInput');
    const binding = capability(view);
    if (!binding.capability.reply) throw new Error('expected reply capability');
    binding.capability.reply.summary = {
      schema: 'nomad.product-host.pending-question-summary.v1',
      question_count: 1, answer_mode: 'free_text', response_hint: 'single_short_reply',
      prompt: 'Provide a short reply for: deployment region.',
    };

    expect(composeActionView(view, binding, NOW).reply).toEqual({
      visible: true, enabled: true, disabledReason: null,
      explanation: 'Your reply goes to this pending request',
      prompt: 'Provide a short reply for: deployment region.',
    });
  });

  it('fails closed when an injected summary bypasses the strict HTTP decoder', async () => {
    const view = await officialView('NeedsInput');
    const binding = capability(view);
    if (!binding.capability.reply) throw new Error('expected reply capability');
    (binding.capability.reply as unknown as { summary: Record<string, unknown> }).summary = {
      schema: 'nomad.product-host.pending-question-summary.v1', question_count: 1,
      answer_mode: 'free_text', response_hint: 'single_short_reply', prompt: 'unsafe\ntext',
    };

    expect(composeActionView(view, binding, NOW).reply.enabled).toBe(false);
  });

  it.each([
    ['missing', null],
    ['stale sequence', (view: SessionView) => capability(view, { snapshotSeq: view.state.lastAppliedSeq + 1 })],
    ['stale digest', (view: SessionView) => capability(view, { digest: `sha256:${'9'.repeat(64)}` })],
    ['expired capability', (view: SessionView) => capability(view, { expiresAt: '2026-08-26T04:59:59.000Z' })],
  ])('renders action context but disables commands for a %s capability', async (_name, makeBinding) => {
    const view = await officialView('NeedsPermission');
    const binding = typeof makeBinding === 'function' ? makeBinding(view) : makeBinding;
    const action = composeActionView(view, binding, NOW);

    expect(action.deny.visible).toBe(true);
    expect(action.deny.enabled).toBe(false);
    expect(action.stop.visible).toBe(true);
    expect(action.stop.enabled).toBe(false);
    expect(action.deny.disabledReason).toBeTruthy();
  });
});

async function officialView(turnState: SessionView['state']['session']['turn_state']): Promise<SessionView> {
  const view = await new PilotSessionClient().loadCurrentSession();
  view.mode = 'official-local';
  view.writable = true;
  view.state.session.turn_state = turnState;
  view.state.session.host_connectivity = 'Online';
  view.state.session.client_freshness = 'Live';
  view.state.digestStatus = 'verified';
  view.state.expectedDigest = `sha256:${'a'.repeat(64)}`;
  return view;
}

function capability(view: SessionView, overrides: { snapshotSeq?: number; digest?: string; expiresAt?: string } = {}): BrowserCommandCapability {
  return {
    csrfToken: 'csrf_token_00000001',
    displaySnapshotSeq: overrides.snapshotSeq ?? view.state.lastAppliedSeq,
    displaySnapshotDigest: overrides.digest ?? view.state.expectedDigest!,
    capability: {
      schema: 'nomad.product-host.command-capability.v1', capability_id: 'capability_00000001',
      snapshot_seq: 701, snapshot_digest: `sha256:${'7'.repeat(64)}`,
      next_command_seq: 1, issued_at: '2026-08-26T04:59:59.000Z', expires_at: overrides.expiresAt ?? '2026-08-26T05:00:30.000Z',
      view: true, reply: { turn_alias: 'turn_alias_000001', input_alias: 'input_alias_00001' },
      deny: { permission_alias: 'permission_alias_1', action_hash: `sha256:${'b'.repeat(64)}`, expires_at: '2026-08-26T05:00:20.000Z' },
      stop: { turn_alias: 'turn_alias_000001' }, allow_once: false,
    },
  };
}
