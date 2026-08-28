import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { PilotSessionClient } from '../client/pilot-client';
import { AlphaAvailabilityError, AlphaResponseError } from '../client/alpha-decoder';
import type { BrowserCommandCapability, GatewayCommandReceipt, SessionClient, SessionMode, SessionView, TraceLabClient, TraceSummary } from '../client/types';
import { isTraceLabClient } from '../client/types';
import { RemoteSessionError } from '../remote/paired-session';
import { App } from './App';

let root: Root | null = null;
let container: HTMLDivElement | null = null;

beforeAll(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});

afterEach(() => {
  if (root) act(() => root?.unmount());
  root = null;
  container?.remove();
  container = null;
});

async function renderApp(client: SessionClient, labMode: boolean, mode?: SessionMode) {
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  const sessionDeferred = deferred<SessionView>();
  const tracesDeferred = deferred<TraceSummary[]>();
  const commandMethod = client.submitCommand ? { submitCommand: (command: Parameters<NonNullable<SessionClient['submitCommand']>>[0]) => client.submitCommand!(command) } : {};
  const capabilityMethods = {
    ...(client.loadCommandCapability ? { loadCommandCapability: () => client.loadCommandCapability!() } : {}),
    ...(client.submitCapabilityCommand ? { submitCapabilityCommand: (...args: Parameters<NonNullable<SessionClient['submitCapabilityCommand']>>) => client.submitCapabilityCommand!(...args) } : {}),
  };
  const controlledClient: SessionClient | TraceLabClient = isTraceLabClient(client)
    ? {
        ...client,
        mode: client.mode,
        writable: client.writable,
        loadCurrentSession: () => sessionDeferred.promise,
        listTraceSessions: () => tracesDeferred.promise,
        loadTraceSession: (traceId) => client.loadTraceSession(traceId),
        refreshSession: (sessionId) => client.refreshSession(sessionId),
        ...commandMethod,
        ...capabilityMethods,
      }
    : {
        ...client,
        mode: client.mode,
        writable: client.writable,
        loadCurrentSession: () => sessionDeferred.promise,
        refreshSession: (sessionId) => client.refreshSession(sessionId),
        ...commandMethod,
        ...capabilityMethods,
      };
  await act(async () => {
    root?.render(<App client={controlledClient} labMode={labMode} mode={mode} />);
  });
  await act(async () => {
    if (labMode && isTraceLabClient(client)) {
      try { tracesDeferred.resolve(await client.listTraceSessions()); } catch (error) { tracesDeferred.reject(error); }
    } else {
      try { sessionDeferred.resolve(await client.loadCurrentSession()); } catch (error) { sessionDeferred.reject(error); }
    }
    await Promise.resolve();
  });
  return container;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function button(name: string): HTMLButtonElement {
  const match = [...(container?.querySelectorAll('button') ?? [])].find((item) => item.textContent?.trim().includes(name));
  if (!(match instanceof HTMLButtonElement)) throw new Error(`Button not found: ${name}`);
  return match;
}

describe('Read-only Alpha and explicit fixture modes', () => {
  it('opens directly into the task console and does not expose the trace loader', async () => {
    const output = await renderApp(new PilotSessionClient(), false);
    expect(output.textContent).toContain('DEMO DATA');
    expect(output.textContent).toContain('The agent is waiting before a change');
    expect(output.textContent).toContain('Last activity');
    expect(output.textContent).not.toContain('Golden traces');
    expect(output.querySelector('[data-testid="trace-lab"]')).toBeNull();
  });

  it('renders the trace lab only when explicitly selected', async () => {
    const output = await renderApp(new PilotSessionClient(), true);
    expect(output.querySelector('[data-testid="trace-lab"]')).not.toBeNull();
    expect(output.textContent).toContain('TRACE LAB');
    expect(output.textContent).toContain('Golden traces');
    expect(output.querySelectorAll('[aria-label^="Load trace"]')).toHaveLength(9);
  });

  it('renders Read-only Alpha with Activity, Refresh, and Changes but no command UI', async () => {
    const view = await new PilotSessionClient().loadCurrentSession();
    view.mode = 'readonly-alpha';
    view.writable = false;
    view.provenance = 'alpha-readonly';
    view.changes = { status: 'unavailable', source: null, baseline: null, files: [], reason: 'Read-only Alpha does not expose a verified workspace diff.' };
    const readonlyClient: SessionClient = {
      mode: 'readonly-alpha',
      writable: false,
      loadCurrentSession: async () => view,
      refreshSession: async () => view,
    };

    const output = await renderApp(readonlyClient, false, 'readonly-alpha');
    const labels = [...output.querySelectorAll('button')].map((item) => item.textContent?.trim());
    expect(output.textContent).toContain('READ-ONLY ALPHA');
    expect(output.textContent).toContain('Read-only Alpha');
    expect(labels).toEqual(expect.arrayContaining(['ActivitySee what happened', 'RefreshVerify the latest state', 'ChangesSee availability status']));
    expect(output.querySelector('button[aria-label="Action"]')).toBeNull();
    expect(labels.some((label) => /Stop task|Deny request|Review request/.test(label ?? ''))).toBe(false);
    expect(output.querySelector('textarea')).toBeNull();
    expect(output.querySelector('.modal')).toBeNull();
  });

  it('shows an unavailable state after a default client failure without demo fallback', async () => {
    const readonlyClient: SessionClient = {
      mode: 'readonly-alpha',
      writable: false,
      loadCurrentSession: async () => { throw new AlphaAvailabilityError('unavailable'); },
      refreshSession: async () => { throw new AlphaAvailabilityError('unavailable'); },
    };
    const output = await renderApp(readonlyClient, false, 'readonly-alpha');
    expect(output.textContent).toContain('Session unavailable');
    expect(output.textContent).toContain('READ-ONLY ALPHA');
    expect(output.textContent).not.toContain('DEMO DATA');
    expect(output.textContent).not.toContain('Golden traces');
    expect(output.textContent).not.toContain('Controlled refactor');
  });

  it('shows unknown for a rejected Gateway schema without demo fallback', async () => {
    const readonlyClient: SessionClient = {
      mode: 'readonly-alpha',
      writable: false,
      loadCurrentSession: async () => { throw new AlphaResponseError(); },
      refreshSession: async () => { throw new AlphaResponseError(); },
    };
    const output = await renderApp(readonlyClient, false, 'readonly-alpha');
    expect(output.textContent).toContain('Session state unknown');
    expect(output.textContent).not.toContain('DEMO DATA');
    expect(output.textContent).not.toContain('Controlled refactor');
  });

  it('preserves the last known session and marks it reconnecting when refresh becomes unavailable', async () => {
    const view = await new PilotSessionClient().loadCurrentSession();
    view.mode = 'readonly-alpha';
    view.writable = false;
    view.provenance = 'alpha-readonly';
    const readonlyClient: SessionClient = {
      mode: 'readonly-alpha',
      writable: false,
      loadCurrentSession: async () => view,
      refreshSession: async () => { throw new AlphaAvailabilityError('unavailable'); },
    };
    const output = await renderApp(readonlyClient, false, 'readonly-alpha');
    expect(output.textContent).toContain(view.state.session.session_id);

    await act(async () => button('Refresh').click());

    expect(output.textContent).toContain('Session unavailable');
    expect(output.textContent).toContain(view.state.session.session_id);
    expect(output.textContent).toContain('Offline');
    expect(output.textContent).toContain('Reconnecting');
    expect(output.textContent).not.toContain('OutcomeUnknown');
    expect(output.querySelector('.control-grid')).not.toBeNull();
    expect(output.querySelector('.app-bottombar')).not.toBeNull();
  });

  it('shows an authoritative empty Changes state with no sample filenames', async () => {
    const output = await renderApp(new PilotSessionClient(), false);
    await act(async () => button('Changes').click());
    expect(output.querySelector('[data-testid="changes-empty"]')).not.toBeNull();
    expect(output.textContent).toContain('No verified changes yet');
    expect(output.textContent).not.toContain('src/app.tsx');
  });

  it('removes approval entirely and only offers deny or Stop', async () => {
    const output = await renderApp(new PilotSessionClient(), false);
    await act(async () => button('Action').click());
    expect(output.textContent).toContain('Review request');
    expect(output.textContent).toContain('Deny request');
    expect(output.textContent).toContain('Stop task instead');
    expect([...output.querySelectorAll('button')].some((item) => /allow/i.test(item.textContent ?? ''))).toBe(false);
  });

  it('submits deny with current observed_seq and no response fields', async () => {
    const pilot = new PilotSessionClient();
    const view = await pilot.loadCurrentSession();
    const submitCommand = vi.fn<NonNullable<SessionClient['submitCommand']>>(async () => ({ status: 'Completed' as const, result: { error_code: 'OK' as const, error_message: null } }));
    const client: SessionClient = { loadCurrentSession: async () => view, refreshSession: async () => view, submitCommand };
    const output = await renderApp(client, false);
    await act(async () => button('Action').click());
    await act(async () => button('Deny request').click());
    expect(submitCommand).toHaveBeenCalledTimes(1);
    const request = submitCommand.mock.calls[0][0];
    expect(request).toEqual(expect.objectContaining({ command_type: 'deny', observed_seq: view.state.lastAppliedSeq, expires_at: view.approval?.expiresAt }));
    expect(request).not.toHaveProperty('seq');
    expect(request).not.toHaveProperty('status');
    expect(request).not.toHaveProperty('result');
    expect(output.textContent).toContain('The denial was completed.');
  });

  it('does not submit deny when expiry is missing', async () => {
    const pilot = new PilotSessionClient();
    const view = await pilot.loadCurrentSession();
    if (!view.approval) throw new Error('expected approval fixture');
    view.approval.expiresAt = '';
    const submitCommand = vi.fn<NonNullable<SessionClient['submitCommand']>>(async () => ({ status: 'Completed' as const, result: { error_code: 'OK' as const, error_message: null } }));
    const client: SessionClient = { loadCurrentSession: async () => view, refreshSession: async () => view, submitCommand };
    await renderApp(client, false);
    await act(async () => button('Action').click());
    await act(async () => button('Deny request').click());
    expect(submitCommand).not.toHaveBeenCalled();
  });

  it.each(['Offline', 'Stale'] as const)('disables commands while %s', async (condition) => {
    const pilot = new PilotSessionClient();
    const view = await pilot.loadCurrentSession();
    if (condition === 'Offline') view.state.session.host_connectivity = 'Offline';
    else view.state.session.client_freshness = 'Stale';
    const client: SessionClient = {
      loadCurrentSession: async () => view,
      refreshSession: async () => view,
      submitCommand: async () => ({ status: 'Completed', result: { error_code: 'OK', error_message: null } }),
    };
    const output = await renderApp(client, false);
    await act(async () => button('Action').click());
    expect(output.textContent).toContain('Actions are paused');
    expect(button('Deny request').disabled).toBe(true);
    expect(button('Stop task instead').disabled).toBe(true);
  });

  it('does not describe a Running turn as safe when the state is Stale', async () => {
    const pilot = new PilotSessionClient();
    const view = await pilot.loadTraceSession('trace-007-version-mismatch');
    const client: SessionClient = {
      loadCurrentSession: async () => view,
      refreshSession: async () => view,
      submitCommand: async () => ({ status: 'Rejected', result: { error_code: 'ERR_SAFETY_BLOCKED', error_message: 'State is stale.' } }),
    };
    const output = await renderApp(client, false);
    expect(output.textContent).toContain('Check this task');
    expect(output.textContent).not.toContain('No action needed');
  });

  it('does not turn RelayReceived Stop into a false Cancelled state', async () => {
    const pilot = new PilotSessionClient();
    const view = await pilot.loadCurrentSession();
    const client: SessionClient = {
      loadCurrentSession: async () => view,
      refreshSession: async () => view,
      submitCommand: async () => ({ status: 'RelayReceived', result: { error_code: 'OK', error_message: null } }),
    };
    const output = await renderApp(client, false);
    await act(async () => button('Stop task').click());
    const confirm = [...output.querySelectorAll('.modal button')].find((item) => item.textContent?.trim() === 'Stop task');
    expect(confirm).toBeInstanceOf(HTMLButtonElement);
    await act(async () => (confirm as HTMLButtonElement).click());
    expect(output.textContent).toContain('Relay received Stop. Waiting for the Host.');
    expect(output.textContent).not.toContain('Task stopped');
  });
});

describe('official local capability gating', () => {
  it('renders a safe pending-question prompt directly above an enabled reply composer', async () => {
    const view = await officialPermissionView();
    view.state.session.turn_state = 'NeedsInput';
    view.state.activePermissionId = null;
    view.approval = null;
    const binding = capability(view);
    if (!binding.capability.reply) throw new Error('expected reply capability');
    binding.capability.reply.summary = {
      schema: 'nomad.product-host.pending-question-summary.v1', question_count: 1,
      answer_mode: 'free_text', response_hint: 'single_short_reply',
      prompt: 'Provide a short reply for: deployment region.',
    };
    const client = officialClient(view, async () => binding, vi.fn());

    const output = await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });

    const composer = output.querySelector('textarea');
    expect(output.textContent).toContain('Provide a short reply for: deployment region.');
    expect(output.textContent).toContain('Your reply goes to this pending request');
    expect(composer).toBeInstanceOf(HTMLTextAreaElement);
    expect((composer as HTMLTextAreaElement).disabled).toBe(false);
    expect(JSON.stringify(view)).not.toContain('deployment region');
  });

  it('keeps generic NeedsInput disabled when the reply capability has no safe summary', async () => {
    const view = await officialPermissionView();
    view.state.session.turn_state = 'NeedsInput';
    view.state.activePermissionId = null;
    view.approval = null;
    const client = officialClient(view, async () => capability(view), vi.fn());

    const output = await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });

    expect(output.textContent).toContain('Reviewable question context is not yet available.');
    expect(output.querySelector('textarea')).toBeNull();
  });

  it.each([
    ['absent', () => null],
    ['stale sequence', (view: SessionView) => capability(view, { snapshotSeq: view.state.lastAppliedSeq + 1 })],
    ['stale digest', (view: SessionView) => capability(view, { digest: `sha256:${'9'.repeat(64)}` })],
    ['expired', (view: SessionView) => capability(view, { expiresAt: new Date(Date.now() - 1).toISOString() })],
  ])('keeps actions disabled when capability is %s', async (_name, makeCapability) => {
    const view = await officialPermissionView();
    const submitCapabilityCommand = vi.fn<NonNullable<SessionClient['submitCapabilityCommand']>>();
    const client = officialClient(view, async () => makeCapability(view), submitCapabilityCommand);
    const output = await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });
    await act(async () => button('Action').click());
    expect(button('Deny request').disabled).toBe(true);
    expect(button('Stop task instead').disabled).toBe(true);
    expect(submitCapabilityCommand).not.toHaveBeenCalled();
    expect(output.textContent).toMatch(/read-only|changed|expired/i);
  });

  it.each(['Offline', 'Stale'] as const)('does not fetch or enable capability while projection is %s', async (condition) => {
    const view = await officialPermissionView();
    if (condition === 'Offline') view.state.session.host_connectivity = 'Offline';
    else view.state.session.client_freshness = 'Stale';
    const loadCommandCapability = vi.fn(async () => capability(view));
    const client = officialClient(view, loadCommandCapability, vi.fn());
    await renderApp(client, false, 'official-local');
    await act(async () => button('Action').click());
    expect(button('Deny request').disabled).toBe(true);
    expect(loadCommandCapability).not.toHaveBeenCalled();
  });

  it('sends one deny for a rapid double click and keeps the scope locked in flight', async () => {
    const view = await officialPermissionView();
    const pending = deferred<GatewayCommandReceipt>();
    const submitCapabilityCommand = vi.fn<NonNullable<SessionClient['submitCapabilityCommand']>>(() => pending.promise);
    const client = officialClient(view, async () => capability(view), submitCapabilityCommand);
    await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });
    await act(async () => button('Action').click());
    const deny = button('Deny request');
    await act(async () => { deny.click(); deny.click(); await Promise.resolve(); });
    expect(submitCapabilityCommand).toHaveBeenCalledTimes(1);
    expect(deny.disabled).toBe(true);
    await act(async () => pending.resolve(receipt(view, 'DispatchAcknowledged', 'deny')));
    expect(container?.textContent).toContain('acknowledged the denial');
    expect(container?.textContent).not.toContain('The denial was completed.');
  });

  it('treats an already-pending same request as waiting, not OutcomeUnknown', async () => {
    const view = await officialPermissionView();
    const submitCapabilityCommand = vi.fn<NonNullable<SessionClient['submitCapabilityCommand']>>(async () => {
      throw new RemoteSessionError('COMMAND_ALREADY_PENDING', 'same request still pending');
    });
    const client = officialClient(view, async () => capability(view), submitCapabilityCommand);
    await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });
    await act(async () => button('Action').click());
    await act(async () => button('Deny request').click());
    expect(container?.textContent).toContain('Relay received your denial. Waiting for the Host.');
    expect(container?.textContent).not.toContain('Result unknown; the denial was not retried.');
  });

  it('shows OutcomeUnknown prominently, never retries, and remains locked after ordinary refresh', async () => {
    const view = await officialPermissionView();
    const submitCapabilityCommand = vi.fn<NonNullable<SessionClient['submitCapabilityCommand']>>(async () => receipt(view, 'OutcomeUnknown', 'deny', 'ERR_OUTCOME_UNKNOWN'));
    const client = officialClient(view, async () => capability(view), submitCapabilityCommand);
    await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });
    await act(async () => button('Action').click());
    await act(async () => button('Deny request').click());
    expect(container?.textContent).toContain('Result unknown; the denial was not retried.');
    await act(async () => button('Home').click());
    await act(async () => button('Refresh').click());
    await act(async () => button('Action').click());
    expect(submitCapabilityCommand).toHaveBeenCalledTimes(1);
    expect(button('Deny request').disabled).toBe(true);
  });

  it('does not render DispatchAcknowledged Stop as cancelled or completed', async () => {
    const view = await officialPermissionView();
    const submitCapabilityCommand = vi.fn<NonNullable<SessionClient['submitCapabilityCommand']>>(async () => receipt(view, 'DispatchAcknowledged', 'stop'));
    const client = officialClient(view, async () => capability(view), submitCapabilityCommand);
    const output = await renderApp(client, false, 'official-local');
    await act(async () => { await Promise.resolve(); });
    await act(async () => button('Stop task').click());
    const confirm = [...output.querySelectorAll('.modal button')].find((item) => item.textContent?.trim() === 'Stop task') as HTMLButtonElement;
    await act(async () => confirm.click());
    expect(output.textContent).toContain('Waiting for authoritative cancellation.');
    expect(output.textContent).not.toContain('Task stopped');
    expect(view.state.session.turn_state).toBe('NeedsPermission');
  });
});

async function officialPermissionView(): Promise<SessionView> {
  const view = await new PilotSessionClient().loadCurrentSession();
  view.mode = 'official-local';
  view.writable = true;
  view.state.session.host_connectivity = 'Online';
  view.state.session.client_freshness = 'Live';
  view.state.digestStatus = 'verified';
  view.state.expectedDigest = `sha256:${'a'.repeat(64)}`;
  return view;
}

function capability(view: SessionView, overrides: { snapshotSeq?: number; digest?: string; expiresAt?: string } = {}): BrowserCommandCapability {
  const now = Date.now();
  return {
    csrfToken: 'csrf_token_00000001',
    displaySnapshotSeq: overrides.snapshotSeq ?? view.state.lastAppliedSeq,
    displaySnapshotDigest: overrides.digest ?? view.state.expectedDigest!,
    capability: {
      schema: 'nomad.product-host.command-capability.v1', capability_id: 'capability_00000001',
      snapshot_seq: 701, snapshot_digest: `sha256:${'7'.repeat(64)}`,
      next_command_seq: 1, issued_at: new Date(now - 1_000).toISOString(), expires_at: overrides.expiresAt ?? new Date(now + 20_000).toISOString(),
      view: true, reply: { turn_alias: 'turn_alias_000001', input_alias: 'input_alias_00001' },
      deny: { permission_alias: 'permission_alias_1', action_hash: `sha256:${'b'.repeat(64)}`, expires_at: new Date(now + 15_000).toISOString() },
      stop: { turn_alias: 'turn_alias_000001' }, allow_once: false,
    },
  };
}

function officialClient(view: SessionView, loadCommandCapability: NonNullable<SessionClient['loadCommandCapability']>, submitCapabilityCommand: NonNullable<SessionClient['submitCapabilityCommand']>): SessionClient {
  return { mode: 'official-local', writable: true, loadCurrentSession: async () => view, refreshSession: async () => view, loadCommandCapability, submitCapabilityCommand };
}

function receipt(view: SessionView, status: GatewayCommandReceipt['status'], action: GatewayCommandReceipt['action'], errorCode: GatewayCommandReceipt['error_code'] = null): GatewayCommandReceipt {
  return {
    schema: 'nomad.gateway.command-receipt.v1', receipt_id: 'receipt_00000001', request_id: 'request_00000001', action,
    snapshot_seq: view.state.lastAppliedSeq, snapshot_digest: view.state.expectedDigest!, accepted_at: new Date().toISOString(),
    status, error_code: errorCode, idempotent_replay: false,
  };
}
