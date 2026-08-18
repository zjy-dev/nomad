import { describe, expect, it, vi } from 'vitest';
import { HttpSessionClient } from './http-client';
import type { SessionView } from './types';

const fakeView = { provenance: 'captured' } as SessionView;

describe('HttpSessionClient', () => {
  it('uses injected routes and codecs without assuming an API envelope', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ payload: 'host-view' }), { status: 200 }));
    const client = new HttpSessionClient({
      baseUrl: 'https://pilot.example/',
      routes: { currentSession: '/mobile/current', refreshSession: (id) => `/mobile/${id}`, commands: '/mobile/commands' },
      fetchImpl,
      decodeSession: (payload) => {
        expect(payload).toEqual({ payload: 'host-view' });
        return fakeView;
      },
      decodeCommand: () => ({ status: 'RelayReceived', result: { error_code: 'OK', error_message: null } }),
    });

    await expect(client.loadCurrentSession()).resolves.toBe(fakeView);
    expect(fetchImpl).toHaveBeenCalledWith('https://pilot.example/mobile/current', expect.objectContaining({ headers: expect.objectContaining({ accept: 'application/json' }) }));
  });

  it('keeps Relay receipt distinct from Host acceptance', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ stage: 'relay' }), { status: 200 }));
    const client = new HttpSessionClient({
      baseUrl: 'https://pilot.example',
      routes: { currentSession: '/session', refreshSession: (id) => `/session/${id}`, commands: '/commands' },
      fetchImpl,
      decodeSession: () => fakeView,
      decodeCommand: () => ({ status: 'RelayReceived', result: { error_code: 'OK', error_message: null } }),
    });
    const result = await client.submitCommand({ command_type: 'reply', request_id: 'req-1', session_id: 's1', seq: 2, content: 'Continue' });
    expect(result.status).toBe('RelayReceived');
    expect(result.status).not.toBe('HostAccepted');
  });
});
