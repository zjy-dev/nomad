import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { computeSnapshotDigest } from '../contracts/digest';
import {
  type RemoteApplicationFrameBinding,
  parseRemoteApplicationEnvelope,
} from './application-envelope';

const TEST_DIGEST = `sha256:${'a'.repeat(64)}`;
const RECEIPT_STATUSES = [
  'HostAccepted',
  'Dispatching',
  'DispatchAcknowledged',
  'Rejected',
  'Stale',
  'Expired',
  'OutcomeUnknown',
] as const;
const RECEIPT_ERROR_CODES = [
  'OK',
  'ERR_DUPLICATE_REQUEST',
  'ERR_REQUEST_STALE',
  'ERR_REQUEST_EXPIRED',
  'ERR_INCOMPATIBLE_VERSION',
  'ERR_REQUEST_REVOKED',
  'ERR_OUTCOME_UNKNOWN',
  'ERR_COMMAND_REJECTED',
  'ERR_PERMISSION_DENIED',
  'ERR_SAFETY_BLOCKED',
  'ERR_HOST_OFFLINE',
] as const;

describe('remote application envelope', () => {
  it('parses a strict projection envelope with content-safe snapshot and capability', async () => {
    const frame = binding('host_to_device', 7);
    const snapshotEnvelope = await productSnapshotEnvelope();
    const envelope = {
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: snapshotEnvelope,
        capability: commandCapability(snapshotEnvelope),
      },
    };

    const parsed = await parseRemoteApplicationEnvelope(canonicalJson(envelope), frame);
    if (parsed.kind !== 'projection') {
      throw new Error(`expected projection envelope, got ${parsed.kind}`);
    }
    expect(parsed.kind).toBe('projection');
    expect(parsed.payload.snapshot.snapshot.turn_state).toBe('NeedsInput');
    expect(parsed.payload.capability?.allow_once).toBe(false);
    expect(parsed.payload.capability?.snapshot_seq).toBe(parsed.payload.snapshot.snapshot_seq);
    expect(parsed.payload.capability?.snapshot_digest).toBe(parsed.payload.snapshot.digest);
    expect(parsed.payload.capability?.reply?.summary).toBeDefined();
    expect(JSON.stringify(parsed)).not.toContain('session_id');
    expect(JSON.stringify(parsed)).not.toContain('permission_id');
  });

  it('parses a strict device_to_host command envelope for reply deny and stop actions', async () => {
    const replyFrame = binding('device_to_host', 8);
    const replyEnvelope = {
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      mailbox_id: replyFrame.mailbox_id,
      direction: replyFrame.direction,
      epoch: replyFrame.epoch,
      sequence: replyFrame.sequence,
      message_id: replyFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: gatewayCommand('reply'),
      },
    };
    await expect(parseRemoteApplicationEnvelope(canonicalJson(replyEnvelope), replyFrame)).resolves.toMatchObject({
      kind: 'command',
      payload: { command: { action: 'reply' } },
    });

    const denyFrame = binding('device_to_host', 9);
    const denyEnvelope = {
      ...replyEnvelope,
      mailbox_id: denyFrame.mailbox_id,
      direction: denyFrame.direction,
      epoch: denyFrame.epoch,
      sequence: denyFrame.sequence,
      message_id: denyFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: gatewayCommand('deny'),
      },
    };
    await expect(parseRemoteApplicationEnvelope(canonicalJson(denyEnvelope), denyFrame)).resolves.toMatchObject({
      kind: 'command',
      payload: { command: { action: 'deny' } },
    });

    const stopFrame = binding('device_to_host', 10);
    const stopEnvelope = {
      ...replyEnvelope,
      mailbox_id: stopFrame.mailbox_id,
      direction: stopFrame.direction,
      epoch: stopFrame.epoch,
      sequence: stopFrame.sequence,
      message_id: stopFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: gatewayCommand('stop'),
      },
    };
    await expect(parseRemoteApplicationEnvelope(canonicalJson(stopEnvelope), stopFrame)).resolves.toMatchObject({
      kind: 'command',
      payload: { command: { action: 'stop' } },
    });
  });

  it('parses a strict host_to_device receipt envelope using current C3 receipt statuses only', async () => {
    for (const [index, status] of RECEIPT_STATUSES.entries()) {
      const receiptFrame = binding('host_to_device', 11 + index);
      const envelope = {
        schema: 'nomad.remote.application-envelope.v1',
        kind: 'receipt',
        mailbox_id: receiptFrame.mailbox_id,
        direction: receiptFrame.direction,
        epoch: receiptFrame.epoch,
        sequence: receiptFrame.sequence,
        message_id: receiptFrame.message_id,
        payload: {
          schema: 'nomad.remote.receipt.v1',
          receipt: gatewayReceipt(status),
        },
      };

      const parsed = await parseRemoteApplicationEnvelope(canonicalJson(envelope), receiptFrame);
      if (parsed.kind !== 'receipt') {
        throw new Error(`expected receipt envelope, got ${parsed.kind}`);
      }
      expect(parsed.payload.receipt.status).toBe(status);
    }
  });

  it('fails closed on exact outer binding mismatch before payload application', async () => {
    const frame = binding('host_to_device', 12);
    const snapshotEnvelope = await productSnapshotEnvelope();
    const envelope = {
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: snapshotEnvelope,
        capability: null,
      },
    };

    await expect(
      parseRemoteApplicationEnvelope(
        canonicalJson({ ...envelope, sequence: frame.sequence + 1 }),
        frame,
      ),
    ).rejects.toThrowError(expect.objectContaining({ code: 'APPLICATION_ENVELOPE_BINDING_MISMATCH' }));
  });

  it('fails closed on kind direction mismatch and unknown kind', async () => {
    const hostFrame = binding('host_to_device', 13);
    const commandEnvelope = {
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      mailbox_id: hostFrame.mailbox_id,
      direction: hostFrame.direction,
      epoch: hostFrame.epoch,
      sequence: hostFrame.sequence,
      message_id: hostFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: gatewayCommand('reply'),
      },
    };
    await expect(parseRemoteApplicationEnvelope(canonicalJson(commandEnvelope), hostFrame)).rejects.toThrowError(
      expect.objectContaining({ code: 'INVALID_APPLICATION_ENVELOPE' }),
    );

    const deviceFrame = binding('device_to_host', 14);
    const unknownKind = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'mystery',
      mailbox_id: deviceFrame.mailbox_id,
      direction: deviceFrame.direction,
      epoch: deviceFrame.epoch,
      sequence: deviceFrame.sequence,
      message_id: deviceFrame.message_id,
      payload: {},
    });
    await expect(parseRemoteApplicationEnvelope(unknownKind, deviceFrame)).rejects.toThrowError(
      expect.objectContaining({ code: 'INVALID_APPLICATION_ENVELOPE' }),
    );
  });

  it('fails closed on duplicate unknown trailing non-canonical and oversize plaintext', async () => {
    const frame = binding('host_to_device', 15);
    const snapshotEnvelope = await productSnapshotEnvelope();
    const duplicate = `{"schema":"nomad.remote.application-envelope.v1","kind":"projection","mailbox_id":"${frame.mailbox_id}","direction":"host_to_device","epoch":1,"sequence":15,"message_id":"${frame.message_id}","payload":{},"payload":{}}`;
    await expect(parseRemoteApplicationEnvelope(duplicate, frame)).rejects.toMatchObject({
      code: 'INVALID_APPLICATION_ENVELOPE',
    });

    const unknown = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: snapshotEnvelope,
        capability: null,
        extra: true,
      },
    });
    await expect(parseRemoteApplicationEnvelope(unknown, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    await expect(parseRemoteApplicationEnvelope(`${await canonicalProjection(frame)}\n`, frame)).rejects.toMatchObject({
      code: 'NON_CANONICAL_APPLICATION_ENVELOPE',
    });

    const nonCanonical = JSON.stringify({
      kind: 'projection',
      schema: 'nomad.remote.application-envelope.v1',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        capability: null,
        snapshot: snapshotEnvelope,
        schema: 'nomad.remote.projection.v1',
      },
    });
    await expect(parseRemoteApplicationEnvelope(nonCanonical, frame)).rejects.toMatchObject({
      code: 'NON_CANONICAL_APPLICATION_ENVELOPE',
    });

    const oversize = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      mailbox_id: frame.mailbox_id,
      direction: 'device_to_host',
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: {
          ...gatewayCommand('reply'),
          content: 'x'.repeat(16 * 1024),
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(oversize, binding('device_to_host', 15))).rejects.toMatchObject({
      code: 'INVALID_COMMAND_PAYLOAD',
    });
  });

  it('rejects allow_once unknown action raw Agent identifier fields and invalid cross-language values', async () => {
    const frame = binding('host_to_device', 16);
    const snapshotEnvelope = await productSnapshotEnvelope();
    const pollutedProjection = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: {
          ...snapshotEnvelope,
          snapshot: {
            ...snapshotEnvelope.snapshot,
            session_id: 'ses_raw_private',
          },
        },
        capability: null,
      },
    });
    await expect(parseRemoteApplicationEnvelope(pollutedProjection, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    const allowOnceProjection = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: snapshotEnvelope,
        capability: {
          ...commandCapability(snapshotEnvelope),
          allow_once: true,
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(allowOnceProjection, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    const commandFrame = binding('device_to_host', 17);
    const unknownAction = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      mailbox_id: commandFrame.mailbox_id,
      direction: commandFrame.direction,
      epoch: commandFrame.epoch,
      sequence: commandFrame.sequence,
      message_id: commandFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: {
          ...gatewayCommand('reply'),
          action: 'allow_once',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(unknownAction, commandFrame)).rejects.toMatchObject({
      code: 'INVALID_COMMAND_PAYLOAD',
    });

    const rawIdReceipt = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'receipt',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.receipt.v1',
        receipt: {
          ...gatewayReceipt('DispatchAcknowledged'),
          raw_permission_id: 'per_raw_private',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(rawIdReceipt, frame)).rejects.toMatchObject({
      code: 'INVALID_RECEIPT_PAYLOAD',
    });

    const invalidReceiptStatus = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'receipt',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.receipt.v1',
        receipt: {
          ...gatewayReceipt('HostAccepted'),
          status: 'ERR_COMMAND_REJECTED',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidReceiptStatus, frame)).rejects.toMatchObject({
      code: 'INVALID_RECEIPT_PAYLOAD',
    });

    const invalidReceiptError = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'receipt',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.receipt.v1',
        receipt: {
          ...gatewayReceipt('Rejected'),
          error_code: 'ERR_NOT_REAL',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidReceiptError, frame)).rejects.toMatchObject({
      code: 'INVALID_RECEIPT_PAYLOAD',
    });

    const removedReceiptError = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'receipt',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.receipt.v1',
        receipt: {
          ...gatewayReceipt('Rejected'),
          error_code: 'COMMAND_UNAVAILABLE',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(removedReceiptError, frame)).rejects.toMatchObject({
      code: 'INVALID_RECEIPT_PAYLOAD',
    });

    const invalidSummaryProjection = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: snapshotEnvelope,
        capability: {
          ...commandCapability(snapshotEnvelope),
          reply: {
            turn_alias: 'turn-11111111111111111111111111111111',
            input_alias: 'input-22222222222222222222222222222222',
          },
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidSummaryProjection, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    const invalidCapabilityBinding = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: snapshotEnvelope,
        capability: {
          ...commandCapability(snapshotEnvelope),
          snapshot_digest: TEST_DIGEST,
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidCapabilityBinding, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });
  });

  it('accepts current gateway receipt error codes and rejects receipt payloads above 4 KiB', async () => {
    for (const [index, errorCode] of RECEIPT_ERROR_CODES.entries()) {
      const frame = binding('host_to_device', 30 + index);
      const envelope = {
        schema: 'nomad.remote.application-envelope.v1',
        kind: 'receipt',
        mailbox_id: frame.mailbox_id,
        direction: frame.direction,
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id,
        payload: {
          schema: 'nomad.remote.receipt.v1',
          receipt: {
            ...gatewayReceipt('Rejected'),
            error_code: errorCode,
          },
        },
      };
      const parsed = await parseRemoteApplicationEnvelope(canonicalJson(envelope), frame);
      if (parsed.kind !== 'receipt') {
        throw new Error(`expected receipt envelope, got ${parsed.kind}`);
      }
      expect(parsed.payload.receipt.error_code).toBe(errorCode);
      expect(parsed.payload.receipt.accepted_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    }

    const frame = binding('host_to_device', 60);
    const oversizeReceipt = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'receipt',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.receipt.v1',
        receipt: {
          ...gatewayReceipt('Rejected'),
          receipt_id: 'receipt_' + 'a'.repeat(5000),
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(oversizeReceipt, frame)).rejects.toMatchObject({
      code: 'INVALID_RECEIPT_PAYLOAD',
    });
  });

  it('rejects reply content above 8 KiB and envelopes exceeding depth or node budgets', async () => {
    const commandFrame = binding('device_to_host', 70);
    const oversizeReply = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      mailbox_id: commandFrame.mailbox_id,
      direction: commandFrame.direction,
      epoch: commandFrame.epoch,
      sequence: commandFrame.sequence,
      message_id: commandFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: {
          ...gatewayCommand('reply'),
          content: 'x'.repeat(8 * 1024 + 1),
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(oversizeReply, commandFrame)).rejects.toMatchObject({
      code: 'INVALID_COMMAND_PAYLOAD',
    });

    const deepJson = buildDeepEnvelope(commandFrame, 17);
    await expect(parseRemoteApplicationEnvelope(deepJson, commandFrame)).rejects.toMatchObject({
      code: 'INVALID_APPLICATION_ENVELOPE',
    });

    const wideFrame = binding('host_to_device', 71);
    const wideJson = buildWideProjectionEnvelope(wideFrame, 4097);
    await expect(parseRemoteApplicationEnvelope(wideJson, wideFrame)).rejects.toMatchObject({
      code: 'INVALID_APPLICATION_ENVELOPE',
    });
  });

  it('rejects non producer-aligned timestamps aliases and turn states', async () => {
    const frame = binding('host_to_device', 72);
    const snapshotEnvelope = await productSnapshotEnvelope();

    const invalidUpdatedAt = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: {
          ...snapshotEnvelope,
          snapshot: {
            ...snapshotEnvelope.snapshot,
            updated_at: '2026-08-27T00:00:00Z',
          },
        },
        capability: null,
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidUpdatedAt, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    const invalidTurnState = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: {
          ...snapshotEnvelope,
          snapshot: {
            ...snapshotEnvelope.snapshot,
            turn_state: 'Failed',
          },
        },
        capability: null,
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidTurnState, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    const invalidAlias = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'projection',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.projection.v1',
        snapshot: {
          ...snapshotEnvelope,
          snapshot: {
            ...snapshotEnvelope.snapshot,
            session_alias: 'sess-ABCDEF0123456789abcdef0123456789',
          },
        },
        capability: null,
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidAlias, frame)).rejects.toMatchObject({
      code: 'INVALID_PROJECTION_PAYLOAD',
    });

    const commandFrame = binding('device_to_host', 73);
    const invalidCommandTimestamp = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      mailbox_id: commandFrame.mailbox_id,
      direction: commandFrame.direction,
      epoch: commandFrame.epoch,
      sequence: commandFrame.sequence,
      message_id: commandFrame.message_id,
      payload: {
        schema: 'nomad.remote.command.v1',
        command: {
          ...gatewayCommand('reply'),
          issued_at: '2026-08-27T00:00:00.000Z',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(invalidCommandTimestamp, commandFrame)).rejects.toMatchObject({
      code: 'INVALID_COMMAND_PAYLOAD',
    });

    const receiptEnvelope = canonicalJson({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'receipt',
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload: {
        schema: 'nomad.remote.receipt.v1',
        receipt: {
          ...gatewayReceipt('Rejected'),
          accepted_at: '2026-08-27T00:00:01.000Z',
        },
      },
    });
    await expect(parseRemoteApplicationEnvelope(receiptEnvelope, frame)).rejects.toMatchObject({
      code: 'INVALID_RECEIPT_PAYLOAD',
    });
  });

  it('parses and round-trips the shared application vectors byte-for-byte', async () => {
    const vectors = sharedVector();
    expect(vectors.marker).toBe('TEST_ONLY_VECTOR');

    for (const entry of [vectors.projection, vectors.command, vectors.receipt]) {
      const parsed = await parseRemoteApplicationEnvelope(entry.canonical_json, entry.frame_binding);
      expect(canonicalJson(parsed)).toBe(entry.canonical_json);
    }
  });
});

interface SharedVectorEntry {
  canonical_json: string;
  frame_binding: RemoteApplicationFrameBinding;
}
interface SharedVectorFile {
  marker: string;
  projection: SharedVectorEntry;
  command: SharedVectorEntry;
  receipt: SharedVectorEntry;
}

function sharedVector(): SharedVectorFile {
  return JSON.parse(
    readFileSync(
      resolve(process.cwd(), '../contracts/vectors/remote-application-v1.json'),
      'utf8',
    ),
  ) as SharedVectorFile;
}

async function canonicalProjection(frame: RemoteApplicationFrameBinding): Promise<string> {
  return canonicalJson({
    schema: 'nomad.remote.application-envelope.v1',
    kind: 'projection',
    mailbox_id: frame.mailbox_id,
    direction: frame.direction,
    epoch: frame.epoch,
    sequence: frame.sequence,
    message_id: frame.message_id,
    payload: {
      schema: 'nomad.remote.projection.v1',
      snapshot: await productSnapshotEnvelope(),
      capability: null,
    },
  });
}

function binding(direction: 'host_to_device' | 'device_to_host', sequence: number): RemoteApplicationFrameBinding {
  return {
    mailbox_id: 'mbx-' + 'ab'.repeat(32),
    direction,
    epoch: 1,
    sequence,
    message_id: 'msg-' + sequence.toString(16).padStart(2, '0').repeat(16).slice(0, 32),
  };
}

async function productSnapshotEnvelope() {
  const snapshot = {
    session_alias: 'sess-0123456789abcdef0123456789abcdef',
    updated_at: '2026-08-27T00:00:00.000Z',
    turn_state: 'NeedsInput',
    pending_input_alias: 'input-11111111111111111111111111111111',
    pending_permission_alias: null,
    diff_file_count: 0,
    writable: false as const,
    evidence_class: 'official_registry_shape_only_not_provider_lifecycle' as const,
  };
  const withoutDigest = {
    schema: 'nomad.product-host.snapshot.v1' as const,
    host_instance_id: 'host-0123456789abcdef0123456789abcdef',
    snapshot_seq: 7,
    snapshot,
  };
  return {
    ...withoutDigest,
    digest: await computeSnapshotDigest(withoutDigest),
  };
}

function commandCapability(snapshotEnvelope: Awaited<ReturnType<typeof productSnapshotEnvelope>>) {
  return {
    schema: 'nomad.product-host.command-capability.v1' as const,
    capability_id: 'capability_00000001',
    snapshot_seq: snapshotEnvelope.snapshot_seq,
    snapshot_digest: snapshotEnvelope.digest,
    next_command_seq: 19,
    issued_at: '2026-08-27T00:00:00Z',
    expires_at: '2026-08-27T00:00:30Z',
    view: true as const,
    reply: {
      turn_alias: 'turn-11111111111111111111111111111111',
      input_alias: 'input-22222222222222222222222222222222',
      summary: {
        schema: 'nomad.product-host.pending-question-summary.v1' as const,
        question_count: 1 as const,
        answer_mode: 'free_text' as const,
        response_hint: 'single_short_reply' as const,
        prompt: 'Provide a short reply for: deployment region.',
      },
    },
    deny: {
      permission_alias: 'permission-33333333333333333333333333333333',
      action_hash: TEST_DIGEST,
      expires_at: '2026-08-27T00:00:30Z',
    },
    stop: {
      turn_alias: 'turn-11111111111111111111111111111111',
    },
    allow_once: false as const,
  };
}

function gatewayCommand(action: 'reply' | 'deny' | 'stop') {
  const common = {
    schema: 'nomad.gateway.command.v1' as const,
    capability_id: 'capability_00000001',
    request_id: 'request_00000001',
    nonce: 'nonce_0000000001',
    command_seq: 19,
    expected_snapshot_seq: 7,
    expected_snapshot_digest: TEST_DIGEST,
    issued_at: '2026-08-27T00:00:00Z',
    expires_at: '2026-08-27T00:00:30Z',
    action,
  };
  if (action === 'reply') {
    return {
      ...common,
      action: 'reply' as const,
      turn_alias: 'turn-11111111111111111111111111111111',
      input_alias: 'input-22222222222222222222222222222222',
      content: 'hello from device',
    };
  }
  if (action === 'deny') {
    return {
      ...common,
      action: 'deny' as const,
      permission_alias: 'permission-33333333333333333333333333333333',
      action_hash: TEST_DIGEST,
      permission_expires_at: '2026-08-27T00:00:30Z',
    };
  }
  return {
    ...common,
    action: 'stop' as const,
    turn_alias: 'turn-11111111111111111111111111111111',
  };
}

function gatewayReceipt(status: 'HostAccepted' | 'Dispatching' | 'DispatchAcknowledged' | 'Rejected' | 'Stale' | 'Expired' | 'OutcomeUnknown') {
  return {
    schema: 'nomad.gateway.command-receipt.v1' as const,
    receipt_id: 'receipt_00000001',
    request_id: 'request_00000001',
    action: 'reply' as const,
    snapshot_seq: 7,
    snapshot_digest: TEST_DIGEST,
    accepted_at: '2026-08-27T00:00:01Z',
    status,
    error_code: status === 'OutcomeUnknown' ? 'ERR_OUTCOME_UNKNOWN' : 'OK',
    idempotent_replay: false,
  };
}

function buildDeepEnvelope(frame: RemoteApplicationFrameBinding, depth: number): string {
  let value: unknown = 'leaf';
  for (let index = 0; index < depth; index += 1) {
    value = [value];
  }
  return canonicalJson({
    schema: 'nomad.remote.application-envelope.v1',
    kind: 'command',
    mailbox_id: frame.mailbox_id,
    direction: frame.direction,
    epoch: frame.epoch,
    sequence: frame.sequence,
    message_id: frame.message_id,
    payload: {
      schema: 'nomad.remote.command.v1',
      command: {
        ...gatewayCommand('reply'),
        content: value,
      },
    },
  });
}

function buildWideProjectionEnvelope(frame: RemoteApplicationFrameBinding, nodeCount: number): string {
  const extras: unknown[] = [];
  for (let index = 0; index < nodeCount; index += 1) {
    extras.push(index);
  }
  return canonicalJson({
    schema: 'nomad.remote.application-envelope.v1',
    kind: 'projection',
    mailbox_id: frame.mailbox_id,
    direction: frame.direction,
    epoch: frame.epoch,
    sequence: frame.sequence,
    message_id: frame.message_id,
    payload: {
      schema: 'nomad.remote.projection.v1',
      snapshot: {
        schema: 'nomad.product-host.snapshot.v1',
        host_instance_id: 'host-0123456789abcdef0123456789abcdef',
        snapshot_seq: 7,
        digest: TEST_DIGEST,
        snapshot: {
          ...baseProductSnapshot().snapshot,
          extras,
        },
      },
      capability: null,
    },
  });
}

function baseProductSnapshot() {
  return {
    schema: 'nomad.product-host.snapshot.v1' as const,
    host_instance_id: 'host-0123456789abcdef0123456789abcdef',
    snapshot_seq: 7,
    snapshot: {
      session_alias: 'sess-0123456789abcdef0123456789abcdef',
      updated_at: '2026-08-27T00:00:00.000Z',
      turn_state: 'NeedsInput',
      pending_input_alias: 'input-11111111111111111111111111111111',
      pending_permission_alias: null,
      diff_file_count: 0,
      writable: false as const,
      evidence_class: 'official_registry_shape_only_not_provider_lifecycle' as const,
    },
  };
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
      .join(',')}}`;
  }
  throw new Error('unsupported test value');
}
