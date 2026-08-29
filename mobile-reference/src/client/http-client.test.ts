import { afterEach, describe, expect, it, vi } from 'vitest';
import { CommandResponseError, HttpSessionClient } from './http-client';
import { AlphaAvailabilityError, AlphaResponseError } from './alpha-decoder';
import { sessionModeFromSearch, type BrowserCommandCapability, type CapabilityCommandIntent, type SessionView } from './types';

const fakeView = { provenance: 'alpha-readonly', mode: 'readonly-alpha', writable: false } as SessionView;

afterEach(() => vi.useRealTimers());

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

describe('HttpSessionClient', () => {
  it('uses Read-only Alpha by default and enables fixture modes only through explicit flags', () => {
    expect(sessionModeFromSearch('')).toBe('official-local');
    expect(sessionModeFromSearch('?demo=0&lab=0')).toBe('official-local');
    expect(sessionModeFromSearch('?readonly=1')).toBe('readonly-alpha');
    expect(sessionModeFromSearch('?demo=1')).toBe('demo');
    expect(sessionModeFromSearch('?lab=1')).toBe('trace-lab');
  });

  it('uses only GET /api/alpha/session for initial load and refresh', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => new Response(JSON.stringify({ schema: 'alpha' }), { status: 200 }));
    const decodeSession = vi.fn(() => fakeView);
    const client = new HttpSessionClient({ baseUrl: 'https://mobile.example/', fetchImpl, decodeSession });

    await expect(client.loadCurrentSession()).resolves.toBe(fakeView);
    await expect(client.refreshSession('caller-cannot-select-session')).resolves.toBe(fakeView);

    expect(client.mode).toBe('official-local');
    expect(client.writable).toBe(true);
    expect(typeof client.submitCapabilityCommand).toBe('function');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    for (const [url, init] of fetchImpl.mock.calls) {
      expect(url).toBe('https://mobile.example/api/alpha/session');
      expect(init).toEqual(expect.objectContaining({ method: 'GET' }));
      expect(String(url)).not.toContain('/api/pilot/');
    }
  });

  it('binds the native fetch receiver to globalThis', async () => {
    const originalFetch = globalThis.fetch;
    const calls: Array<{ receiver: unknown; url: unknown; init: unknown }> = [];
    globalThis.fetch = function receiverSensitiveFetch(this: unknown, url: unknown, init: unknown) {
      calls.push({ receiver: this, url, init });
      if (this !== globalThis) return Promise.reject(new TypeError('Illegal invocation'));
      return Promise.resolve(new Response(JSON.stringify({ schema: 'alpha' }), { status: 200 }));
    } as typeof fetch;
    try {
      const client = new HttpSessionClient({
        baseUrl: 'https://mobile.example',
        decodeSession: () => fakeView,
      });
      await expect(client.loadCurrentSession()).resolves.toBe(fakeView);
      expect(calls).toHaveLength(1);
      expect(calls[0].receiver).toBe(globalThis);
      expect(calls[0].url).toBe('https://mobile.example/api/alpha/session');
      expect(calls[0].init).toEqual(expect.objectContaining({ method: 'GET' }));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it.each([
    [503, 'unavailable'],
    [503, 'unknown'],
  ] as const)('surfaces Gateway %s %s as typed availability without decoding or fallback', async (statusCode, status) => {
    const decodeSession = vi.fn(() => fakeView);
    const client = new HttpSessionClient({
      baseUrl: 'https://mobile.example',
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(failure(status)), { status: statusCode })),
      decodeSession,
    });

    const error = await client.loadCurrentSession().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AlphaAvailabilityError);
    expect((error as AlphaAvailabilityError).status).toBe(status);
    expect(decodeSession).not.toHaveBeenCalled();
  });

  it('surfaces network failure without returning demo data', async () => {
    const decodeSession = vi.fn(() => fakeView);
    const client = new HttpSessionClient({
      baseUrl: 'https://mobile.example',
      fetchImpl: vi.fn<typeof fetch>().mockRejectedValue(new Error('offline')),
      decodeSession,
    });

    const error = await client.loadCurrentSession().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AlphaAvailabilityError);
    expect((error as AlphaAvailabilityError).status).toBe('unavailable');
    expect(decodeSession).not.toHaveBeenCalled();
  });

  it('classifies a malformed 503 envelope as typed incompatible unknown', async () => {
    const client = new HttpSessionClient({
      baseUrl: 'https://mobile.example',
      fetchImpl: vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ status: 'unavailable' }), { status: 503 })),
      decodeSession: () => fakeView,
    });
    const error = await client.loadCurrentSession().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AlphaResponseError);
    expect((error as AlphaResponseError).status).toBe('unknown');
  });

  it('loads an exact same-origin capability with allow_once exactly false', async () => {
    const payload = capabilityEnvelope();
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(json(payload));
    const client = makeClient(fetchImpl);

    await expect(client.loadCommandCapability()).resolves.toEqual({
      capability: payload.capability,
      csrfToken: payload.csrf_token,
      displaySnapshotSeq: payload.display_snapshot_seq,
      displaySnapshotDigest: payload.display_snapshot_digest,
    });
    expect(fetchImpl).toHaveBeenCalledWith('https://mobile.example/api/commands/capability', { method: 'GET', credentials: 'same-origin', headers: { accept: 'application/json' } });
  });

  it.each(['absent', 'null'] as const)('accepts an optional reply summary when it is %s', async (kind) => {
    const payload = capabilityEnvelope();
    if (!payload.capability.reply) throw new Error('expected reply capability');
    if (kind === 'absent') delete (payload.capability.reply as Partial<typeof payload.capability.reply>).summary;
    else (payload.capability.reply as Record<string, unknown>).summary = null;

    const binding = await makeClient(vi.fn<typeof fetch>().mockResolvedValue(json(payload))).loadCommandCapability();

    expect(binding?.capability.reply?.summary).toBe(kind === 'absent' ? undefined : null);
  });

  it('treats unavailable capability as absent and rejects malformed, polluted, and allow_once=true documents', async () => {
    await expect(makeClient(vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 503 }))).loadCommandCapability()).resolves.toBeNull();
    for (const mutate of [
      (value: ReturnType<typeof capabilityEnvelope>) => { (value.capability as Record<string, unknown>).allow_once = true; },
      (value: ReturnType<typeof capabilityEnvelope>) => { (value.capability as Record<string, unknown>).raw_session_id = 'raw-secret-id'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { value.capability.snapshot_digest = 'bad'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { value.display_snapshot_digest = 'bad'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { value.display_snapshot_seq = 0; },
      (value: ReturnType<typeof capabilityEnvelope>) => { (value as Record<string, unknown>).unknown = true; },
      (value: ReturnType<typeof capabilityEnvelope>) => { delete (value as Partial<typeof value>).display_snapshot_digest; },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) (value.capability.reply.summary as Record<string, unknown>).schema = 'wrong'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) value.capability.reply.summary.question_count = 2 as 1; },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) value.capability.reply.summary.answer_mode = 'choices' as 'free_text'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) value.capability.reply.summary.response_hint = 'long' as 'single_short_reply'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) value.capability.reply.summary.prompt = 'x'.repeat(161); },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) value.capability.reply.summary.prompt = 'unsafe\ntext'; },
      (value: ReturnType<typeof capabilityEnvelope>) => { if (value.capability.reply?.summary) (value.capability.reply.summary as Record<string, unknown>).unknown = true; },
      (value: ReturnType<typeof capabilityEnvelope>) => { value.capability.expires_at = new Date(Date.parse(value.capability.issued_at) + 31_000).toISOString(); },
      (value: ReturnType<typeof capabilityEnvelope>) => { value.capability.expires_at = new Date(Date.now() - 1).toISOString(); },
    ]) {
      const payload = capabilityEnvelope();
      mutate(payload);
      await expect(makeClient(vi.fn<typeof fetch>().mockResolvedValue(json(payload))).loadCommandCapability()).rejects.toBeInstanceOf(CommandResponseError);
    }
  });

  it.each([
    ['reply', { turn_alias: 'turn_alias_000001', input_alias: 'input_alias_00001', content: 'Continue safely' }],
    ['deny', { permission_alias: 'permission_alias_1', action_hash: `sha256:${'b'.repeat(64)}`, permission_expires_at: 'CAPABILITY_EXPIRY' }],
    ['stop', { turn_alias: 'turn_alias_000001' }],
  ] as const)('posts exact %s command using the capability issued_at when local time is two seconds later', async (action, fields) => {
    const capabilityPayload = capabilityEnvelope();
    vi.useFakeTimers();
    vi.setSystemTime(Date.parse(capabilityPayload.capability.issued_at) + 2_000);
    const calls: GatewayCall[] = [];
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith('/capability')) return json(capabilityPayload);
      const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return json(receiptFor(request, action === 'stop' ? 'DispatchAcknowledged' : 'HostAccepted'));
    });
    const client = makeClient(fetchImpl);
    const binding = await client.loadCommandCapability();
    if (!binding) throw new Error('expected capability');
    const normalizedFields = action === 'deny' ? { ...fields, permission_expires_at: capabilityPayload.capability.deny.expires_at } : fields;
    const intent = { action, ...normalizedFields } as CapabilityCommandIntent;
    const result = await client.submitCapabilityCommand(binding, intent);

    expect(result.status).toBe(action === 'stop' ? 'DispatchAcknowledged' : 'HostAccepted');
    expect(calls).toHaveLength(2);
    const post = calls[1];
    expect(post.url).toBe('https://mobile.example/api/commands');
    expect(post.init?.method).toBe('POST');
    expect(post.init?.credentials).toBe('same-origin');
    expect(post.init?.headers).toEqual({ accept: 'application/json', 'content-type': 'application/json', 'X-Nomad-CSRF': 'csrf_token_00000001' });
    const body = JSON.parse(String(post.init?.body));
    expect(body).toEqual({
      schema: 'nomad.gateway.command.v1', capability_id: 'capability_00000001',
      request_id: expect.stringMatching(/^req_[0-9a-f]{32}$/), nonce: expect.stringMatching(/^nonce_[0-9a-f]{32}$/),
      command_seq: 19, expected_snapshot_seq: 17, expected_snapshot_digest: DIGEST_A,
      issued_at: capabilityPayload.capability.issued_at, expires_at: capabilityPayload.capability.expires_at, action, ...normalizedFields,
    });
    expect(JSON.stringify(body)).not.toMatch(/session_id|turn_id|permission_id|credential|provider|allow/i);
    expect(JSON.stringify(body)).not.toContain('pending-question-summary');
    expect(JSON.stringify(body)).not.toContain('deployment region');
  });

  it('rejects a mismatched target or expired capability before POST', async () => {
    const live = capabilityEnvelope();
    const fetchImpl = vi.fn<typeof fetch>();
    const client = makeClient(fetchImpl);
    const binding = browserBinding(live);
    await expect(client.submitCapabilityCommand(binding, { action: 'stop', turn_alias: 'wrong_alias_0001' })).rejects.toBeInstanceOf(CommandResponseError);
    binding.capability.expires_at = new Date(Date.now() - 1).toISOString();
    await expect(client.submitCapabilityCommand(binding, { action: 'stop', turn_alias: 'turn_alias_000001' })).rejects.toBeInstanceOf(CommandResponseError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('returns OutcomeUnknown honestly and performs exactly one POST with no automatic retry', async () => {
    const payload = capabilityEnvelope();
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
      const request = JSON.parse(String(init?.body));
      return json(receiptFor(request, 'OutcomeUnknown', 'ERR_OUTCOME_UNKNOWN'));
    });
    const client = makeClient(fetchImpl);
    const binding = browserBinding(payload);
    await expect(client.submitCapabilityCommand(binding, { action: 'stop', turn_alias: 'turn_alias_000001' })).resolves.toMatchObject({ status: 'OutcomeUnknown', error_code: 'ERR_OUTCOME_UNKNOWN' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('does not retry a transport failure and rejects polluted or cross-bound receipts', async () => {
    const payload = capabilityEnvelope();
    const binding = browserBinding(payload);
    const failedFetch = vi.fn<typeof fetch>().mockRejectedValue(new Error('connection lost'));
    await expect(makeClient(failedFetch).submitCapabilityCommand(binding, { action: 'stop', turn_alias: 'turn_alias_000001' })).rejects.toThrow('connection lost');
    expect(failedFetch).toHaveBeenCalledTimes(1);

    for (const mutate of [
      (receipt: Record<string, unknown>) => { receipt.raw_permission_id = 'private-id'; },
      (receipt: Record<string, unknown>) => { receipt.snapshot_seq = 999; },
      (receipt: Record<string, unknown>) => { receipt.action = 'deny'; },
    ]) {
      const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
        const request = JSON.parse(String(init?.body));
        const receipt = receiptFor(request, 'HostAccepted') as Record<string, unknown>;
        mutate(receipt);
        return json(receipt);
      });
      await expect(makeClient(fetchImpl).submitCapabilityCommand(binding, { action: 'stop', turn_alias: 'turn_alias_000001' })).rejects.toBeInstanceOf(CommandResponseError);
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    }
  });
});

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
type GatewayCall = { url: string; init?: RequestInit };

function makeClient(fetchImpl: typeof fetch) {
  return new HttpSessionClient({ baseUrl: 'https://mobile.example', fetchImpl, decodeSession: () => fakeView });
}

function capabilityEnvelope() {
  const issued = new Date(Date.now() - 1_000);
  return {
    schema: 'nomad.gateway.command-capability.v1' as const, csrf_token: 'csrf_token_00000001',
    display_snapshot_seq: 17, display_snapshot_digest: `sha256:${'c'.repeat(64)}`,
    capability: {
      schema: 'nomad.product-host.command-capability.v1' as const, capability_id: 'capability_00000001',
      snapshot_seq: 17, snapshot_digest: DIGEST_A, next_command_seq: 19, issued_at: issued.toISOString(),
      expires_at: new Date(issued.getTime() + 30_000).toISOString(), view: true as const,
      reply: {
        turn_alias: 'turn_alias_000001', input_alias: 'input_alias_00001',
        summary: {
          schema: 'nomad.product-host.pending-question-summary.v1' as const, question_count: 1 as const,
          answer_mode: 'free_text' as const, response_hint: 'single_short_reply' as const,
          prompt: 'Provide a short reply for: deployment region.',
        },
      },
      deny: { permission_alias: 'permission_alias_1', action_hash: `sha256:${'b'.repeat(64)}`, expires_at: new Date(issued.getTime() + 20_000).toISOString() },
      stop: { turn_alias: 'turn_alias_000001' }, allow_once: false as const,
    },
  };
}

function browserBinding(payload: ReturnType<typeof capabilityEnvelope>): BrowserCommandCapability {
  return {
    capability: payload.capability, csrfToken: payload.csrf_token,
    displaySnapshotSeq: payload.display_snapshot_seq, displaySnapshotDigest: payload.display_snapshot_digest,
  };
}

function receiptFor(request: Record<string, unknown>, status: string, errorCode: string | null = null) {
  return {
    schema: 'nomad.gateway.command-receipt.v1', receipt_id: 'receipt_00000001', request_id: request.request_id,
    action: request.action, snapshot_seq: request.expected_snapshot_seq, snapshot_digest: request.expected_snapshot_digest,
    accepted_at: new Date().toISOString(), status, error_code: errorCode, idempotent_replay: false,
  };
}

function json(value: unknown): Response { return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } }); }
