import { describe, expect, it, vi } from 'vitest';

import type { RemoteOpaqueFrame } from './crypto';
import { DeviceRelayClient, DeviceRelayClientError } from './relay-client';

describe('DeviceRelayClient', () => {
  it('publishes device_to_host with exact path, bearer header, and canonical body', async () => {
    const frame = makeFrame({ direction: 'device_to_host', sequence: 7 });
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe('https://relay.example.test/v2/mailboxes/mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/frames');
      expect(init?.method).toBe('POST');
      expect(normalizeHeaders(init?.headers)).toEqual({
        accept: 'application/json',
        authorization: 'Bearer device-secret-token',
        'content-type': 'application/json',
      });
      expect(String(init?.body)).toBe(JSON.stringify(frame));
      return jsonResponse(201, { stored: true, idempotent: false });
    });

    const client = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test/',
      bearerToken: 'device-secret-token',
      fetchImpl,
    });

    await expect(client.publishDeviceFrame(frame)).resolves.toEqual({
      stored: true,
      idempotent: false,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reads host_to_device with exact query and decodes strict frame arrays', async () => {
    const first = makeFrame({ direction: 'host_to_device', sequence: 3 });
    const second = makeFrame({ direction: 'host_to_device', sequence: 4, message_id: 'msg-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' });
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe('https://relay.example.test/v2/mailboxes/mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/frames?direction=host_to_device&after_sequence=2');
      expect(init?.method).toBe('GET');
      expect(normalizeHeaders(init?.headers)).toEqual({
        accept: 'application/json',
        authorization: 'Bearer device-secret-token',
      });
      expect(init?.body).toBeUndefined();
      return jsonResponse(200, [first, second]);
    });

    const client = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl,
    });

    await expect(client.readHostFrames(first.mailbox_id, 2)).resolves.toEqual([first, second]);
  });

  it('decodes frames in a real browser runtime without Node Buffer', async () => {
    const first = makeFrame({ direction: 'host_to_device', sequence: 1 });
    const response = {
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      text: async () => JSON.stringify([first]),
    } as Response;
    const saved = globalThis.Buffer;
    Reflect.deleteProperty(globalThis, 'Buffer');
    try {
      const client = new DeviceRelayClient({
        baseUrl: 'https://relay.example.test',
        bearerToken: 'device-secret-token',
        fetchImpl: vi.fn<typeof fetch>(async () => response),
      });
      await expect(client.readHostFrames(first.mailbox_id, 0)).resolves.toEqual([first]);
    } finally {
      globalThis.Buffer = saved;
    }
  });

  it('acks host_to_device with exact body and no extra fields', async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe('https://relay.example.test/v2/mailboxes/mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/acks');
      expect(init?.method).toBe('POST');
      expect(String(init?.body)).toBe(JSON.stringify({
        schema: 'nomad.relay.opaque-ack.v2',
        mailbox_id: 'mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        direction: 'host_to_device',
        epoch: 3,
        acked_through_sequence: 9,
      }));
      return jsonResponse(200, { acked: true });
    });

    const client = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl,
    });

    await expect(client.ackHostFrames('mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 3, 9)).resolves.toBeUndefined();
  });

  it('allows explicit test-only loopback http and rejects non-loopback cleartext', async () => {
    const loopback = new DeviceRelayClient({
      baseUrl: 'http://127.0.0.1:9999',
      bearerToken: 'device-secret-token',
      allowLoopbackHttp: true,
      fetchImpl: vi.fn<typeof fetch>(async () => jsonResponse(200, [])),
    });
    await expect(loopback.readHostFrames('mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0)).resolves.toEqual([]);

    expect(() => new DeviceRelayClient({
      baseUrl: 'http://example.test',
      bearerToken: 'device-secret-token',
    })).toThrowError(expect.objectContaining({ code: 'INSECURE_BASE_URL' } satisfies Partial<DeviceRelayClientError>));
  });

  it('fails closed on wrong direction publish and incompatible responses', async () => {
    const client = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl: vi.fn<typeof fetch>(async () => jsonResponse(201, { stored: true, idempotent: false })),
    });

    await expect(client.publishDeviceFrame(makeFrame({ direction: 'host_to_device' }))).rejects.toMatchObject({
      code: 'INVALID_DIRECTION',
    } satisfies Partial<DeviceRelayClientError>);

    const badStatus = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl: vi.fn<typeof fetch>(async () => jsonResponse(200, { stored: true, idempotent: false })),
    });
    await expect(badStatus.publishDeviceFrame(makeFrame({ direction: 'device_to_host' }))).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
    } satisfies Partial<DeviceRelayClientError>);

    const badFrameList = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl: vi.fn<typeof fetch>(async () => jsonResponse(200, [{ ...makeFrame({ direction: 'device_to_host' }) }])),
    });
    await expect(badFrameList.readHostFrames('mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0)).rejects.toMatchObject({
      code: 'INVALID_FRAME',
    } satisfies Partial<DeviceRelayClientError>);

    const nonIncreasing = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl: vi.fn<typeof fetch>(async () => jsonResponse(200, [
        makeFrame({ direction: 'host_to_device', sequence: 3 }),
        makeFrame({ direction: 'host_to_device', sequence: 3, message_id: 'msg-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }),
      ])),
    });
    await expect(nonIncreasing.readHostFrames('mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 2)).rejects.toMatchObject({
      code: 'INVALID_FRAME',
    } satisfies Partial<DeviceRelayClientError>);
  });

  it('rejects duplicate-key JSON responses fail closed', async () => {
    const client = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl: vi.fn<typeof fetch>(async () => new Response(
        '{"stored":true,"stored":false,"idempotent":false}',
        { status: 201, headers: { 'content-type': 'application/json' } },
      )),
    });

    await expect(client.publishDeviceFrame(makeFrame({ direction: 'device_to_host' }))).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
    } satisfies Partial<DeviceRelayClientError>);
  });

  it('redacts token details from thrown errors', async () => {
    const client = new DeviceRelayClient({
      baseUrl: 'https://relay.example.test',
      bearerToken: 'device-secret-token',
      fetchImpl: vi.fn<typeof fetch>(async () => {
        throw new Error('socket failed with device-secret-token');
      }),
    });

    await expect(client.readHostFrames('mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0)).rejects.toMatchObject({
      code: 'NETWORK_ERROR',
      message: 'Relay request failed before an authoritative response was received.',
    } satisfies Partial<DeviceRelayClientError>);
  });
});

function makeFrame(overrides: Partial<RemoteOpaqueFrame>): RemoteOpaqueFrame {
  return {
    schema: 'nomad.relay.opaque-frame.v2',
    crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1',
    mailbox_id: 'mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    direction: 'device_to_host',
    epoch: 3,
    sequence: 1,
    message_id: 'msg-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    issued_at: 1_700_000_000,
    expires_at: 1_700_000_600,
    nonce: 'AQIDBAUGBwgJCgsM',
    ciphertext: 'AQIDBAUGBwgJCgsMDQ4PEA',
    ...overrides,
  };
}

function jsonResponse(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function normalizeHeaders(value: HeadersInit | undefined): Record<string, string> {
  const headers = new Headers(value);
  return Array.from(headers.entries()).reduce<Record<string, string>>((acc, [key, item]) => {
    acc[key] = item;
    return acc;
  }, {});
}
