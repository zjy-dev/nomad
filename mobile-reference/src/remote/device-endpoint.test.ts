import { describe, expect, it, vi } from 'vitest';

import type { RemoteOpaqueFrame } from './crypto';
import { DeviceEndpoint, DeviceEndpointError, type DeviceEnvelopeCodec, type DurableDeviceState } from './device-endpoint';

describe('DeviceEndpoint', () => {
  it('reserves device_to_host next_sequence before encrypt and publish', async () => {
    const steps: string[] = [];
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => null),
      persistPendingOutboundFrame: vi.fn(async (_mailboxId, _direction, _epoch, pending) => {
        steps.push(`persist-pending:${pending.sequence}`);
      }),
      clearPendingOutboundFrame: vi.fn(async (_mailboxId, _direction, _epoch, sequence) => {
        steps.push(`clear-pending:${sequence}`);
      }),
      reserveNextSequence: vi.fn(async () => {
        steps.push('reserve');
        return 8;
      }),
      loadAppliedThroughSequence: vi.fn(async () => 0),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async (_mailboxId, _direction, _epoch, batch) => {
        steps.push(`persist-applied:${batch.appliedThroughSequence}`);
      }),
      clearPendingAppliedBatch: vi.fn(async (_mailboxId, _direction, _epoch, sequence) => {
        steps.push(`clear-applied:${sequence}`);
      }),
    });
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async ({ mailboxId, epoch, sequence }) => {
        steps.push('encrypt');
        expect(sequence).toBe(8);
        return makeFrame({
          mailbox_id: mailboxId,
          direction: 'device_to_host',
          epoch,
          sequence,
        });
      }),
      decryptHostEnvelope: vi.fn(async () => ({ type: 'unknown-envelope' })),
    };
    const relay = {
      publishDeviceFrame: vi.fn(async (frame: RemoteOpaqueFrame) => {
        steps.push('publish');
        expect(frame.sequence).toBe(8);
        return { stored: true, idempotent: false };
      }),
      readHostFrames: vi.fn(async () => []),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const endpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay,
    });

    await expect(endpoint.publishDeviceEnvelope({ any: 'payload' })).resolves.toMatchObject({
      frame: expect.objectContaining({ direction: 'device_to_host', sequence: 8 }),
      relay: { stored: true, idempotent: false },
    });
    expect(steps).toEqual(['reserve', 'encrypt', 'persist-pending:8', 'publish', 'clear-pending:8']);
  });

  it('fails OUTBOUND_RECOVERY_REQUIRED when a new publish arrives while pending outbound exists', async () => {
    const pendingFrame = makeFrame({
      direction: 'device_to_host',
      sequence: 11,
      message_id: 'msg-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    });
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => ({ sequence: 11, frame: pendingFrame })),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 12),
      loadAppliedThroughSequence: vi.fn(async () => 0),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async () => undefined),
      clearPendingAppliedBatch: vi.fn(async () => undefined),
    });
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async () => {
        throw new Error('must not re-encrypt');
      }),
      decryptHostEnvelope: vi.fn(async () => ({ boundary: 'unknown' })),
    };
    const relay = {
      publishDeviceFrame: vi.fn(async (frame: RemoteOpaqueFrame) => {
        expect(frame).toBe(pendingFrame);
        return { stored: false, idempotent: true };
      }),
      readHostFrames: vi.fn(async () => []),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const endpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay,
    });

    await expect(endpoint.publishDeviceEnvelope({ ignored: true })).rejects.toMatchObject({
      code: 'OUTBOUND_RECOVERY_REQUIRED',
      message: 'Device publish is blocked until the exact pending outbound frame is retried.',
    } satisfies Partial<DeviceEndpointError>);
    expect(state.reserveNextSequence).not.toHaveBeenCalled();
    expect(codec.encryptDeviceEnvelope).not.toHaveBeenCalled();
    expect(relay.publishDeviceFrame).not.toHaveBeenCalled();
    expect(state.persistPendingOutboundFrame).not.toHaveBeenCalled();
  });

  it('retries persisted pending outbound frame without reserving a new sequence or re-encrypting', async () => {
    const pendingFrame = makeFrame({
      direction: 'device_to_host',
      sequence: 11,
      message_id: 'msg-efefefefefefefefefefefefefefefef',
    });
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => ({ sequence: 11, frame: pendingFrame })),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 12),
      loadAppliedThroughSequence: vi.fn(async () => 0),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async () => undefined),
      clearPendingAppliedBatch: vi.fn(async () => undefined),
    });
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async () => {
        throw new Error('must not re-encrypt');
      }),
      decryptHostEnvelope: vi.fn(async () => ({ boundary: 'unknown' })),
    };
    const relay = {
      publishDeviceFrame: vi.fn(async (frame: RemoteOpaqueFrame) => {
        expect(frame).toBe(pendingFrame);
        return { stored: false, idempotent: true };
      }),
      readHostFrames: vi.fn(async () => []),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const endpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay,
    });

    await expect(endpoint.retryPendingOutbound()).resolves.toEqual({
      frame: pendingFrame,
      relay: { stored: false, idempotent: true },
    });
    expect(state.reserveNextSequence).not.toHaveBeenCalled();
    expect(codec.encryptDeviceEnvelope).not.toHaveBeenCalled();
    expect(state.persistPendingOutboundFrame).not.toHaveBeenCalled();
  });

  it('persists host_to_device applied_through before ack', async () => {
    const steps: string[] = [];
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => null),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 1),
      loadAppliedThroughSequence: vi.fn(async () => {
        steps.push('load');
        return 4;
      }),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async (_mailboxId, _direction, _epoch, batch) => {
        steps.push(`persist:${batch.appliedThroughSequence}`);
        expect(batch.envelopes).toHaveLength(2);
      }),
      clearPendingAppliedBatch: vi.fn(async (_mailboxId, _direction, _epoch, sequence) => {
        steps.push(`clear:${sequence}`);
      }),
    });
    const first = makeFrame({
      direction: 'host_to_device',
      sequence: 5,
      message_id: 'msg-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    });
    const second = makeFrame({
      direction: 'host_to_device',
      sequence: 9,
      message_id: 'msg-cccccccccccccccccccccccccccccccc',
    });
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async () => makeFrame({ direction: 'device_to_host' })),
      decryptHostEnvelope: vi.fn(async (frame) => {
        steps.push(`decrypt:${frame.sequence}`);
        return { boundary: 'unknown', sequence: frame.sequence };
      }),
    };
    const relay = {
      publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
      readHostFrames: vi.fn(async () => {
        steps.push('read');
        return [first, second];
      }),
      ackHostFrames: vi.fn(async (_mailboxId: string, _epoch: number, sequence: number) => {
        steps.push(`ack:${sequence}`);
      }),
    };
    const endpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay,
    });

    await expect(endpoint.receiveHostEnvelopes()).resolves.toEqual([
      { frame: first, envelope: { boundary: 'unknown', sequence: 5 } },
      { frame: second, envelope: { boundary: 'unknown', sequence: 9 } },
    ]);
    expect(steps).toEqual(['load', 'read', 'decrypt:5', 'decrypt:9', 'persist:9', 'ack:9', 'clear:9']);
  });

  it('reloads previously applied envelopes and retries only ACK after reconnect', async () => {
    const first = makeFrame({
      direction: 'host_to_device',
      sequence: 5,
      message_id: 'msg-ffffffffffffffffffffffffffffffff',
    });
    const persisted = {
      appliedThroughSequence: 5,
      envelopes: [{ frame: first, envelope: { boundary: 'unknown', sequence: 5 } }],
    };
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => null),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 1),
      loadAppliedThroughSequence: vi.fn(async () => 4),
      loadPendingAppliedBatch: vi.fn(async () => persisted),
      persistAppliedHostBatch: vi.fn(async () => undefined),
      clearPendingAppliedBatch: vi.fn(async () => undefined),
    });
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async () => makeFrame({ direction: 'device_to_host' })),
      decryptHostEnvelope: vi.fn(async () => {
        throw new Error('must not decrypt persisted batch again');
      }),
    };
    const relay = {
      publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
      readHostFrames: vi.fn(async () => {
        throw new Error('must not re-read before ack retry');
      }),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const endpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay,
    });

    await expect(endpoint.receiveHostEnvelopes()).resolves.toEqual(persisted.envelopes);
    expect(relay.readHostFrames).not.toHaveBeenCalled();
    expect(codec.decryptHostEnvelope).not.toHaveBeenCalled();
    expect(relay.ackHostFrames).toHaveBeenCalledWith(MAILBOX_ID, 4, 5);
  });

  it('uses persisted applied_through cursor as the exact read boundary', async () => {
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => null),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 1),
      loadAppliedThroughSequence: vi.fn(async () => 12),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async () => undefined),
      clearPendingAppliedBatch: vi.fn(async () => undefined),
    });
    const relay = {
      publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
      readHostFrames: vi.fn(async (_mailboxId: string, afterSequence: number) => {
        expect(afterSequence).toBe(12);
        return [];
      }),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async () => makeFrame({ direction: 'device_to_host' })),
      decryptHostEnvelope: vi.fn(async () => ({ boundary: 'unknown' })),
    };
    const endpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay,
    });

    await expect(endpoint.receiveHostEnvelopes()).resolves.toEqual([]);
    expect(relay.ackHostFrames).not.toHaveBeenCalled();
    expect(state.persistAppliedHostBatch).not.toHaveBeenCalled();
  });

  it('fails closed on duplicate or wrong-tuple frames, but allows gaps', async () => {
    const state = makeState({
      loadPendingOutboundFrame: vi.fn(async () => null),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 1),
      loadAppliedThroughSequence: vi.fn(async () => 4),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async () => undefined),
      clearPendingAppliedBatch: vi.fn(async () => undefined),
    });
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async () => makeFrame({ direction: 'device_to_host' })),
      decryptHostEnvelope: vi.fn(async () => ({ boundary: 'unknown' })),
    };
    const duplicateRelay = {
      publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
      readHostFrames: vi.fn(async () => [
        makeFrame({ direction: 'host_to_device', sequence: 6 }),
        makeFrame({ direction: 'host_to_device', sequence: 6, message_id: 'msg-dddddddddddddddddddddddddddddddd' }),
      ]),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const duplicate = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state,
      codec,
      relay: duplicateRelay,
    });
    await expect(duplicate.receiveHostEnvelopes()).rejects.toMatchObject({
      code: 'INVALID_FRAME_ORDER',
    } satisfies Partial<DeviceEndpointError>);
    expect(state.persistAppliedHostBatch).not.toHaveBeenCalled();
    expect(duplicateRelay.ackHostFrames).not.toHaveBeenCalled();

    const gapRelay = {
      publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
      readHostFrames: vi.fn(async () => [
        makeFrame({ direction: 'host_to_device', sequence: 6 }),
        makeFrame({ direction: 'host_to_device', sequence: 10, message_id: 'msg-10101010101010101010101010101010' }),
      ]),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const gapState = makeState({
      loadPendingOutboundFrame: vi.fn(async () => null),
      persistPendingOutboundFrame: vi.fn(async () => undefined),
      clearPendingOutboundFrame: vi.fn(async () => undefined),
      reserveNextSequence: vi.fn(async () => 1),
      loadAppliedThroughSequence: vi.fn(async () => 4),
      loadPendingAppliedBatch: vi.fn(async () => null),
      persistAppliedHostBatch: vi.fn(async () => undefined),
      clearPendingAppliedBatch: vi.fn(async () => undefined),
    });
    const gapEndpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state: gapState,
      codec,
      relay: gapRelay,
    });
    await expect(gapEndpoint.receiveHostEnvelopes()).resolves.toEqual([
      { frame: makeFrame({ direction: 'host_to_device', sequence: 6 }), envelope: { boundary: 'unknown' } },
      { frame: makeFrame({ direction: 'host_to_device', sequence: 10, message_id: 'msg-10101010101010101010101010101010' }), envelope: { boundary: 'unknown' } },
    ]);

    const wrongTupleRelay = {
      publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
      readHostFrames: vi.fn(async () => [
        makeFrame({ mailbox_id: OTHER_MAILBOX_ID, direction: 'host_to_device', sequence: 5 }),
      ]),
      ackHostFrames: vi.fn(async () => undefined),
    };
    const wrongTuple = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state: makeState({
        loadPendingOutboundFrame: vi.fn(async () => null),
        persistPendingOutboundFrame: vi.fn(async () => undefined),
        clearPendingOutboundFrame: vi.fn(async () => undefined),
        reserveNextSequence: vi.fn(async () => 1),
        loadAppliedThroughSequence: vi.fn(async () => 4),
        loadPendingAppliedBatch: vi.fn(async () => null),
        persistAppliedHostBatch: vi.fn(async () => undefined),
        clearPendingAppliedBatch: vi.fn(async () => undefined),
      }),
      codec,
      relay: wrongTupleRelay,
    });
    await expect(wrongTuple.receiveHostEnvelopes()).rejects.toMatchObject({
      code: 'INVALID_FRAME',
    } satisfies Partial<DeviceEndpointError>);
  });

  it('surfaces publish/read/ack failures without leaking payload details', async () => {
    const codec: DeviceEnvelopeCodec = {
      encryptDeviceEnvelope: vi.fn(async ({ mailboxId, epoch, sequence }) =>
        makeFrame({ mailbox_id: mailboxId, direction: 'device_to_host', epoch, sequence, ciphertext: SECRET_CANARY })),
      decryptHostEnvelope: vi.fn(async () => ({ boundary: 'unknown' })),
    };
    const publishEndpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state: makeState({
        loadPendingOutboundFrame: vi.fn(async () => null),
        persistPendingOutboundFrame: vi.fn(async () => undefined),
        clearPendingOutboundFrame: vi.fn(async () => undefined),
        reserveNextSequence: vi.fn(async () => 2),
        loadAppliedThroughSequence: vi.fn(async () => 0),
        loadPendingAppliedBatch: vi.fn(async () => null),
        persistAppliedHostBatch: vi.fn(async () => undefined),
        clearPendingAppliedBatch: vi.fn(async () => undefined),
      }),
      codec,
      relay: {
        publishDeviceFrame: vi.fn(async () => {
          throw new Error(`transport failed ${SECRET_CANARY}`);
        }),
        readHostFrames: vi.fn(async () => []),
        ackHostFrames: vi.fn(async () => undefined),
      },
    });
    await expect(publishEndpoint.publishDeviceEnvelope({ hidden: SECRET_CANARY })).rejects.toMatchObject({
      code: 'PUBLISH_FAILED',
      message: 'Device publish did not complete with an authoritative Relay response.',
    } satisfies Partial<DeviceEndpointError>);

    const ackEndpoint = new DeviceEndpoint({
      mailboxId: MAILBOX_ID,
      epoch: 4,
      state: makeState({
        loadPendingOutboundFrame: vi.fn(async () => null),
        persistPendingOutboundFrame: vi.fn(async () => undefined),
        clearPendingOutboundFrame: vi.fn(async () => undefined),
        reserveNextSequence: vi.fn(async () => 1),
        loadAppliedThroughSequence: vi.fn(async () => 0),
        loadPendingAppliedBatch: vi.fn(async () => null),
        persistAppliedHostBatch: vi.fn(async () => undefined),
        clearPendingAppliedBatch: vi.fn(async () => undefined),
      }),
      codec,
      relay: {
        publishDeviceFrame: vi.fn(async () => ({ stored: true, idempotent: false })),
        readHostFrames: vi.fn(async () => [makeFrame({ direction: 'host_to_device', sequence: 1 })]),
        ackHostFrames: vi.fn(async () => {
          throw new Error(`ack failed ${SECRET_CANARY}`);
        }),
      },
    });
    await expect(ackEndpoint.receiveHostEnvelopes()).rejects.toMatchObject({
      code: 'ACK_FAILED',
      message: 'Device ACK did not complete with an authoritative Relay response.',
    } satisfies Partial<DeviceEndpointError>);
  });
});

function makeState(overrides: DurableDeviceState): DurableDeviceState {
  return overrides;
}

function makeFrame(overrides: Partial<RemoteOpaqueFrame>): RemoteOpaqueFrame {
  return {
    schema: 'nomad.relay.opaque-frame.v2',
    crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1',
    mailbox_id: MAILBOX_ID,
    direction: 'host_to_device',
    epoch: 4,
    sequence: 1,
    message_id: 'msg-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    issued_at: 1_700_000_000,
    expires_at: 1_700_000_600,
    nonce: 'AQIDBAUGBwgJCgsM',
    ciphertext: 'AQIDBAUGBwgJCgsMDQ4PEA',
    ...overrides,
  };
}

const MAILBOX_ID = 'mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const OTHER_MAILBOX_ID = 'mbx-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const SECRET_CANARY = 'device-secret-canary';
