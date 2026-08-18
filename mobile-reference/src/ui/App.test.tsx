import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { PilotSessionClient } from '../client/pilot-client';
import type { SessionClient, SessionView, TraceLabClient, TraceSummary } from '../client/types';
import { isTraceLabClient } from '../client/types';
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

async function renderApp(client: SessionClient, labMode: boolean) {
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  const sessionDeferred = deferred<SessionView>();
  const tracesDeferred = deferred<TraceSummary[]>();
  const controlledClient: SessionClient | TraceLabClient = isTraceLabClient(client)
    ? {
        ...client,
        loadCurrentSession: () => sessionDeferred.promise,
        listTraceSessions: () => tracesDeferred.promise,
        loadTraceSession: (traceId) => client.loadTraceSession(traceId),
        refreshSession: (sessionId) => client.refreshSession(sessionId),
        submitCommand: (command) => client.submitCommand(command),
      }
    : {
        ...client,
        loadCurrentSession: () => sessionDeferred.promise,
        refreshSession: (sessionId) => client.refreshSession(sessionId),
        submitCommand: (command) => client.submitCommand(command),
      };
  await act(async () => {
    root?.render(<App client={controlledClient} labMode={labMode} />);
  });
  await act(async () => {
    if (labMode && isTraceLabClient(client)) {
      tracesDeferred.resolve(await client.listTraceSessions());
    } else {
      sessionDeferred.resolve(await client.loadCurrentSession());
    }
  });
  return container;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function button(name: string): HTMLButtonElement {
  const match = [...(container?.querySelectorAll('button') ?? [])].find((item) => item.textContent?.trim().includes(name));
  if (!(match instanceof HTMLButtonElement)) throw new Error(`Button not found: ${name}`);
  return match;
}

describe('Controlled Pilot product route', () => {
  it('opens directly into the task console and does not expose the trace loader', async () => {
    const output = await renderApp(new PilotSessionClient(), false);
    expect(output.textContent).toContain('The agent is waiting before a change');
    expect(output.textContent).toContain('Last activity');
    expect(output.textContent).not.toContain('Golden traces');
    expect(output.querySelector('[data-testid="trace-lab"]')).toBeNull();
  });

  it('renders the trace lab only when explicitly selected', async () => {
    const output = await renderApp(new PilotSessionClient(), true);
    expect(output.querySelector('[data-testid="trace-lab"]')).not.toBeNull();
    expect(output.textContent).toContain('Golden traces');
    expect(output.querySelectorAll('[aria-label^="Load trace"]')).toHaveLength(9);
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
