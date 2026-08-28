import type { RemoteOpaqueFrame } from './crypto';
import type {
  DeviceRelayTransport,
  PublishFrameResponse,
} from './relay-client';

const DIRECTION_HOST_TO_DEVICE = 'host_to_device' as const;
const DIRECTION_DEVICE_TO_HOST = 'device_to_host' as const;

export interface DurableDeviceState {
  loadPendingOutboundFrame(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
  ): Promise<PendingOutboundFrame | null>;
  persistPendingOutboundFrame(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
    pending: PendingOutboundFrame,
  ): Promise<void>;
  clearPendingOutboundFrame(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
    sequence: number,
  ): Promise<void>;
  reserveNextSequence(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
  ): Promise<number>;
  loadAppliedThroughSequence(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
  ): Promise<number>;
  loadPendingAppliedBatch(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
  ): Promise<PersistedAppliedBatch | null>;
  persistAppliedHostBatch(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
    batch: PersistedAppliedBatch,
  ): Promise<void>;
  clearPendingAppliedBatch(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
    appliedThroughSequence: number,
  ): Promise<void>;
}

export interface DeviceEnvelopeCodec {
  encryptDeviceEnvelope(input: {
    mailboxId: string;
    epoch: number;
    sequence: number;
    envelope: unknown;
  }): Promise<RemoteOpaqueFrame>;
  decryptHostEnvelope(frame: RemoteOpaqueFrame): Promise<unknown>;
}

export interface DeviceEndpointOptions {
  mailboxId: string;
  epoch: number;
  relay: DeviceRelayTransport;
  state: DurableDeviceState;
  codec: DeviceEnvelopeCodec;
}

export interface PublishedDeviceEnvelope {
  frame: RemoteOpaqueFrame;
  relay: PublishFrameResponse;
}

export interface PendingOutboundFrame {
  sequence: number;
  frame: RemoteOpaqueFrame;
}

export interface ReceivedHostEnvelope {
  frame: RemoteOpaqueFrame;
  envelope: unknown;
}

export interface PersistedAppliedBatch {
  appliedThroughSequence: number;
  envelopes: ReadonlyArray<ReceivedHostEnvelope>;
}

export class DeviceEndpointError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class DeviceEndpoint {
  constructor(private readonly options: DeviceEndpointOptions) {
    validateMailboxId(options.mailboxId);
    validateEpoch(options.epoch);
  }

  async publishDeviceEnvelope(envelope: unknown): Promise<PublishedDeviceEnvelope> {
    const { mailboxId, epoch } = this.options;
    const pending = await this.options.state.loadPendingOutboundFrame(
      mailboxId,
      DIRECTION_DEVICE_TO_HOST,
      epoch,
    );
    if (pending !== null) {
      validatePendingOutboundFrame(pending, mailboxId, epoch);
      throw new DeviceEndpointError(
        'OUTBOUND_RECOVERY_REQUIRED',
        'Device publish is blocked until the exact pending outbound frame is retried.',
      );
    }
    try {
      const sequence = await this.options.state.reserveNextSequence(
        mailboxId,
        DIRECTION_DEVICE_TO_HOST,
        epoch,
      );
      validatePositiveSequence(sequence, 'sequence');
      const frame = await this.options.codec.encryptDeviceEnvelope({
        mailboxId,
        epoch,
        sequence,
        envelope,
      });
      validateOutboundFrame(frame, mailboxId, epoch, sequence);
      const outbound: PendingOutboundFrame = { sequence, frame };
      await this.options.state.persistPendingOutboundFrame(
        mailboxId,
        DIRECTION_DEVICE_TO_HOST,
        epoch,
        outbound,
      );
      const relay = await this.options.relay.publishDeviceFrame(outbound.frame);
      await this.options.state.clearPendingOutboundFrame(
        mailboxId,
        DIRECTION_DEVICE_TO_HOST,
        epoch,
        outbound.sequence,
      );
      return { frame: outbound.frame, relay };
    } catch {
      throw new DeviceEndpointError(
        'PUBLISH_FAILED',
        'Device publish did not complete with an authoritative Relay response.',
      );
    }
  }

  async retryPendingOutbound(): Promise<PublishedDeviceEnvelope> {
    const { mailboxId, epoch } = this.options;
    const pending = await this.options.state.loadPendingOutboundFrame(
      mailboxId,
      DIRECTION_DEVICE_TO_HOST,
      epoch,
    );
    if (pending === null) {
      throw new DeviceEndpointError(
        'OUTBOUND_RECOVERY_REQUIRED',
        'Device publish retry requires an exact pending outbound frame.',
      );
    }
    validatePendingOutboundFrame(pending, mailboxId, epoch);
    try {
      const relay = await this.options.relay.publishDeviceFrame(pending.frame);
      await this.options.state.clearPendingOutboundFrame(
        mailboxId,
        DIRECTION_DEVICE_TO_HOST,
        epoch,
        pending.sequence,
      );
      return { frame: pending.frame, relay };
    } catch {
      throw new DeviceEndpointError(
        'PUBLISH_FAILED',
        'Device publish did not complete with an authoritative Relay response.',
      );
    }
  }

  async receiveHostEnvelopes(): Promise<ReceivedHostEnvelope[]> {
    const { mailboxId, epoch } = this.options;
    const pending = await this.options.state.loadPendingAppliedBatch(
      mailboxId,
      DIRECTION_HOST_TO_DEVICE,
      epoch,
    );
    if (pending !== null) {
      validatePersistedAppliedBatch(pending, mailboxId, epoch);
      try {
        await this.options.relay.ackHostFrames(
          mailboxId,
          epoch,
          pending.appliedThroughSequence,
        );
        await this.options.state.clearPendingAppliedBatch(
          mailboxId,
          DIRECTION_HOST_TO_DEVICE,
          epoch,
          pending.appliedThroughSequence,
        );
        return [...pending.envelopes];
      } catch {
        throw new DeviceEndpointError(
          'ACK_FAILED',
          'Device ACK did not complete with an authoritative Relay response.',
        );
      }
    }

    const appliedThrough = await this.options.state.loadAppliedThroughSequence(
      mailboxId,
      DIRECTION_HOST_TO_DEVICE,
      epoch,
    );
    validateNonNegativeSequence(appliedThrough, 'applied_through_sequence');

    let frames: RemoteOpaqueFrame[];
    try {
      frames = await this.options.relay.readHostFrames(mailboxId, appliedThrough);
    } catch {
      throw new DeviceEndpointError(
        'READ_FAILED',
        'Device read did not complete with an authoritative Relay response.',
      );
    }
    validateInboundFrames(frames, mailboxId, epoch, appliedThrough);

    const decoded: ReceivedHostEnvelope[] = [];
    for (const frame of frames) {
      try {
        const envelope = await this.options.codec.decryptHostEnvelope(frame);
        decoded.push({ frame, envelope });
      } catch {
        throw new DeviceEndpointError(
          'DECRYPT_FAILED',
          'Device could not validate a Relay frame at the application-envelope boundary.',
        );
      }
    }
    if (frames.length === 0) {
      return decoded;
    }

    const lastSequence = frames[frames.length - 1]?.sequence;
    if (lastSequence === undefined) {
      throw new DeviceEndpointError(
        'INVALID_STATE',
        'Device receive cursor is invalid.',
      );
    }
    const batch: PersistedAppliedBatch = {
      appliedThroughSequence: lastSequence,
      envelopes: decoded,
    };
    validatePersistedAppliedBatch(batch, mailboxId, epoch);
    await this.options.state.persistAppliedHostBatch(
      mailboxId,
      DIRECTION_HOST_TO_DEVICE,
      epoch,
      batch,
    );
    try {
      await this.options.relay.ackHostFrames(mailboxId, epoch, lastSequence);
      await this.options.state.clearPendingAppliedBatch(
        mailboxId,
        DIRECTION_HOST_TO_DEVICE,
        epoch,
        lastSequence,
      );
    } catch {
      throw new DeviceEndpointError(
        'ACK_FAILED',
        'Device ACK did not complete with an authoritative Relay response.',
      );
    }
    return decoded;
  }
}

function validatePendingOutboundFrame(
  pending: PendingOutboundFrame,
  mailboxId: string,
  epoch: number,
): void {
  validatePositiveSequence(pending.sequence, 'sequence');
  validateOutboundFrame(pending.frame, mailboxId, epoch, pending.sequence);
}

function validateOutboundFrame(
  frame: RemoteOpaqueFrame,
  mailboxId: string,
  epoch: number,
  sequence: number,
): void {
  validateFrameShape(frame);
  if (
    frame.mailbox_id !== mailboxId
    || frame.direction !== DIRECTION_DEVICE_TO_HOST
    || frame.epoch !== epoch
    || frame.sequence !== sequence
  ) {
    throw new DeviceEndpointError(
      'INVALID_FRAME',
      'Device codec returned a frame outside the reserved transport tuple.',
    );
  }
}

function validatePersistedAppliedBatch(
  batch: PersistedAppliedBatch,
  mailboxId: string,
  epoch: number,
): void {
  validatePositiveSequence(batch.appliedThroughSequence, 'applied_through_sequence');
  if (!Array.isArray(batch.envelopes) || batch.envelopes.length === 0) {
    throw new DeviceEndpointError(
      'INVALID_STATE',
      'Device applied batch is invalid.',
    );
  }
  let previous = 0;
  for (const entry of batch.envelopes) {
    validateFrameShape(entry.frame);
    if (
      entry.frame.mailbox_id !== mailboxId
      || entry.frame.direction !== DIRECTION_HOST_TO_DEVICE
      || entry.frame.epoch !== epoch
      || entry.frame.sequence > batch.appliedThroughSequence
      || entry.frame.sequence <= previous
    ) {
      throw new DeviceEndpointError(
        'INVALID_STATE',
        'Device applied batch is invalid.',
      );
    }
    previous = entry.frame.sequence;
  }
}

function validateInboundFrames(
  frames: RemoteOpaqueFrame[],
  mailboxId: string,
  epoch: number,
  appliedThrough: number,
): void {
  let previous = appliedThrough;
  for (const frame of frames) {
    validateFrameShape(frame);
    if (
      frame.mailbox_id !== mailboxId
      || frame.direction !== DIRECTION_HOST_TO_DEVICE
      || frame.epoch !== epoch
    ) {
      throw new DeviceEndpointError(
        'INVALID_FRAME',
        'Relay returned a frame outside the active mailbox tuple.',
      );
    }
    if (frame.sequence <= previous) {
      throw new DeviceEndpointError(
        'INVALID_FRAME_ORDER',
        'Relay returned non-monotonic host_to_device frames.',
      );
    }
    previous = frame.sequence;
  }
}

function validateFrameShape(frame: RemoteOpaqueFrame): void {
  if (
    !frame
    || typeof frame !== 'object'
    || typeof frame.mailbox_id !== 'string'
    || typeof frame.direction !== 'string'
    || typeof frame.epoch !== 'number'
    || typeof frame.sequence !== 'number'
    || typeof frame.nonce !== 'string'
    || typeof frame.ciphertext !== 'string'
    || typeof frame.message_id !== 'string'
    || typeof frame.issued_at !== 'number'
    || typeof frame.expires_at !== 'number'
  ) {
    throw new DeviceEndpointError('INVALID_FRAME', 'Relay frame is incompatible.');
  }
  validateMailboxId(frame.mailbox_id);
  validateEpoch(frame.epoch);
  validatePositiveSequence(frame.sequence, 'sequence');
}

function validateMailboxId(mailboxId: string): void {
  if (!/^mbx-[0-9a-f]{64}$/.test(mailboxId)) {
    throw new DeviceEndpointError(
      'INVALID_MAILBOX_ID',
      'Device mailbox_id is invalid.',
    );
  }
}

function validateEpoch(epoch: number): void {
  validatePositiveSequence(epoch, 'epoch');
}

function validatePositiveSequence(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new DeviceEndpointError(
      'INVALID_SEQUENCE',
      `Device ${field} is invalid.`,
    );
  }
}

function validateNonNegativeSequence(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new DeviceEndpointError(
      'INVALID_SEQUENCE',
      `Device ${field} is invalid.`,
    );
  }
}
