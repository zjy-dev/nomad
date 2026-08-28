import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { SessionClient, SessionView } from '../client/types';
import { useReadonlyLiveRefresh } from './useReadonlyLiveRefresh';

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
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function view(seq: number): SessionView {
  return {
    state: {
      session: {
        session_id: 'sess-' + '1'.repeat(32), semantics_version: '1.0.0', turn_id: null,
        turn_state: 'Running', host_connectivity: 'Online', client_freshness: 'Live',
        updated_at: '2026-08-25T12:00:00.000Z',
      },
      events: [], timeline: [], tools: [], activePermissionId: null, diffFileCount: 0,
      lastAppliedSeq: seq, gapToSeq: null, digestStatus: 'verified', expectedDigest: null,
      actualDigest: null, versionStatus: 'ok', duplicatesDropped: 0, outcomeUnknownTools: [],
    },
    display: { title: 'Owned session', hostLabel: 'Local Host', workspaceLabel: 'Private workspace' },
    approval: null,
    changes: { status: 'unavailable', source: null, baseline: null, files: [] },
    provenance: 'alpha-readonly', mode: 'readonly-alpha', writable: false,
  };
}

function Harness({ client, onSuccess, onFailure, sessionId = 'sess-' + '1'.repeat(32) }: {
  client: SessionClient;
  onSuccess: (value: SessionView) => void;
  onFailure: (error: unknown, freshness: 'Reconnecting' | 'Stale') => void;
  sessionId?: string | null;
}) {
  useReadonlyLiveRefresh({
    enabled: true, client, sessionId, onSuccess, onFailure,
  });
  return null;
}

async function renderHarness(client: SessionClient, onSuccess = vi.fn(), onFailure = vi.fn(), sessionId: string | null = 'sess-' + '1'.repeat(32)) {
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  await act(async () => { root?.render(<Harness client={client} onSuccess={onSuccess} onFailure={onFailure} sessionId={sessionId} />); });
  return { onSuccess, onFailure };
}

describe('useReadonlyLiveRefresh', () => {
  it('collects three sequential snapshots without overlapping requests', async () => {
    vi.useFakeTimers();
    let active = 0;
    let maximumActive = 0;
    let seq = 0;
    const client: SessionClient = {
      loadCurrentSession: async () => view(0),
      refreshSession: vi.fn(async () => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await Promise.resolve();
        active -= 1;
        return view(++seq);
      }),
    };
    const { onSuccess } = await renderHarness(client);

    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });

    expect(client.refreshSession).toHaveBeenCalledTimes(3);
    expect(maximumActive).toBe(1);
    expect(onSuccess).toHaveBeenCalledTimes(3);
    expect(onSuccess.mock.calls.map(([item]) => item.state.lastAppliedSeq)).toEqual([1, 2, 3]);
  });

  it('backs off after failure and then recovers without discarding the caller last-good', async () => {
    vi.useFakeTimers();
    const client: SessionClient = {
      loadCurrentSession: async () => view(0),
      refreshSession: vi.fn()
        .mockRejectedValueOnce(new Error('private detail'))
        .mockResolvedValueOnce(view(2)),
    };
    const { onSuccess, onFailure } = await renderHarness(client);

    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(onFailure).toHaveBeenCalledWith(expect.any(Error), 'Reconnecting');
    expect(onSuccess).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });
    expect(onSuccess).toHaveBeenCalledWith(view(2));
  });

  it('retries initial load until the Host has its first snapshot', async () => {
    vi.useFakeTimers();
    const client: SessionClient = {
      loadCurrentSession: vi.fn()
        .mockRejectedValueOnce(new Error('not ready'))
        .mockResolvedValueOnce(view(1)),
      refreshSession: vi.fn(async () => view(2)),
    };
    const { onSuccess, onFailure } = await renderHarness(client, vi.fn(), vi.fn(), null);
    expect(onFailure).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(250); });
    expect(client.loadCurrentSession).toHaveBeenCalledTimes(2);
    expect(client.refreshSession).not.toHaveBeenCalled();
    expect(onSuccess).toHaveBeenCalledWith(view(1));
  });

  it('pauses while hidden, resumes immediately, and ignores an in-flight result after unmount', async () => {
    vi.useFakeTimers();
    let visibility: DocumentVisibilityState = 'hidden';
    vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility);
    let resolveRefresh!: (value: SessionView) => void;
    const pending = new Promise<SessionView>((resolve) => { resolveRefresh = resolve; });
    const client: SessionClient = {
      loadCurrentSession: async () => view(0),
      refreshSession: vi.fn(() => pending),
    };
    const { onSuccess } = await renderHarness(client);
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(client.refreshSession).not.toHaveBeenCalled();

    visibility = 'visible';
    document.dispatchEvent(new Event('visibilitychange'));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(client.refreshSession).toHaveBeenCalledTimes(1);

    act(() => root?.unmount());
    root = null;
    resolveRefresh(view(9));
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(onSuccess).not.toHaveBeenCalled();
    expect(client.refreshSession).toHaveBeenCalledTimes(1);
  });
});
