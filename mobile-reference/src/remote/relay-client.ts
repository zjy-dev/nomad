import {
  parseCanonicalJson,
  type RemoteOpaqueFrame,
} from './crypto';

const FRAME_SCHEMA = 'nomad.relay.opaque-frame.v2';
const ACK_SCHEMA = 'nomad.relay.opaque-ack.v2';
const FRAME_SUITE = 'p256-hkdf-sha256-aes256gcm-v1';
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const MAX_WIRE_FRAME_BYTES = 96 * 1024;
const MAX_TTL_SECONDS = 10 * 60;
const MAX_FRAME_BATCH = 100;
const SMALL_RESPONSE_LIMIT = 4 * 1024;
const FRAME_LIST_RESPONSE_LIMIT = MAX_FRAME_BATCH * MAX_WIRE_FRAME_BYTES + 64 * 1024;
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/;
const MAILBOX_ID = /^mbx-[0-9a-f]{64}$/;
const MESSAGE_ID = /^msg-[0-9a-f]{32}$/;
const DIRECTION = /^(host_to_device|device_to_host)$/;

export type RelayDirection = 'host_to_device' | 'device_to_host';

export interface OpaqueAckV2 {
  schema: typeof ACK_SCHEMA;
  mailbox_id: string;
  direction: RelayDirection;
  epoch: number;
  acked_through_sequence: number;
}

export interface PublishFrameResponse {
  stored: boolean;
  idempotent: boolean;
}

export interface DeviceRelayClientOptions {
  baseUrl: string;
  bearerToken: string;
  allowLoopbackHttp?: boolean;
  fetchImpl?: typeof fetch;
}

export interface DeviceRelayTransport {
  publishDeviceFrame(frame: RemoteOpaqueFrame): Promise<PublishFrameResponse>;
  readHostFrames(mailboxId: string, afterSequence: number): Promise<RemoteOpaqueFrame[]>;
  ackHostFrames(mailboxId: string, epoch: number, ackedThroughSequence: number): Promise<void>;
}

export class DeviceRelayClientError extends Error {
  readonly code: string;
  readonly status: number | null;

  constructor(code: string, message: string, status: number | null = null) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class DeviceRelayClient implements DeviceRelayTransport {
  private readonly fetchImpl: typeof fetch;
  private readonly baseUrl: string;

  constructor(private readonly options: DeviceRelayClientOptions) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.baseUrl = normalizeBaseUrl(options.baseUrl, options.allowLoopbackHttp === true);
    if (!validBearerToken(options.bearerToken)) {
      throw new DeviceRelayClientError(
        'INVALID_BEARER',
        'Relay bearer configuration is invalid.',
      );
    }
  }

  async publishDeviceFrame(frame: RemoteOpaqueFrame): Promise<PublishFrameResponse> {
    validateFrame(frame);
    if (frame.direction !== 'device_to_host') {
      throw new DeviceRelayClientError(
        'INVALID_DIRECTION',
        'Device relay client only publishes device_to_host frames.',
      );
    }
    const response = await this.fetchJson(
      `/v2/mailboxes/${frame.mailbox_id}/frames`,
      {
        method: 'POST',
        headers: this.requestHeaders(true),
        body: serializeFrame(frame),
      },
      SMALL_RESPONSE_LIMIT,
    );
    if (response.status !== 200 && response.status !== 201) {
      throw new DeviceRelayClientError(
        'INVALID_HTTP_STATUS',
        `Relay returned an unexpected publish status (${response.status}).`,
        response.status,
      );
    }
    const decoded = decodePublishResponse(response.payload);
    if (
      (response.status === 201 && (!decoded.stored || decoded.idempotent))
      || (response.status === 200 && (decoded.stored || !decoded.idempotent))
    ) {
      throw new DeviceRelayClientError(
        'INVALID_RESPONSE',
        'Relay publish response is incompatible.',
        response.status,
      );
    }
    return decoded;
  }

  async readHostFrames(mailboxId: string, afterSequence: number): Promise<RemoteOpaqueFrame[]> {
    validateMailboxId(mailboxId);
    validateSequence(afterSequence, true, 'after_sequence');
    const response = await this.fetchJson(
      `/v2/mailboxes/${mailboxId}/frames?direction=host_to_device&after_sequence=${afterSequence}`,
      {
        method: 'GET',
        headers: this.requestHeaders(false),
      },
      FRAME_LIST_RESPONSE_LIMIT,
    );
    if (response.status !== 200) {
      throw new DeviceRelayClientError(
        'INVALID_HTTP_STATUS',
        `Relay returned an unexpected read status (${response.status}).`,
        response.status,
      );
    }
    return decodeReadFrames(response.payload, mailboxId, afterSequence);
  }

  async ackHostFrames(
    mailboxId: string,
    epoch: number,
    ackedThroughSequence: number,
  ): Promise<void> {
    const ack: OpaqueAckV2 = {
      schema: ACK_SCHEMA,
      mailbox_id: mailboxId,
      direction: 'host_to_device',
      epoch,
      acked_through_sequence: ackedThroughSequence,
    };
    validateAck(ack);
    const response = await this.fetchJson(
      `/v2/mailboxes/${mailboxId}/acks`,
      {
        method: 'POST',
        headers: this.requestHeaders(true),
        body: serializeAck(ack),
      },
      SMALL_RESPONSE_LIMIT,
    );
    if (response.status !== 200) {
      throw new DeviceRelayClientError(
        'INVALID_HTTP_STATUS',
        `Relay returned an unexpected ack status (${response.status}).`,
        response.status,
      );
    }
    const raw = exactObject(response.payload, ['acked']);
    if (raw.acked !== true) {
      throw new DeviceRelayClientError(
        'INVALID_RESPONSE',
        'Relay ack response is incompatible.',
        response.status,
      );
    }
  }

  private requestHeaders(withBody: boolean): HeadersInit {
    return withBody
      ? {
          authorization: `Bearer ${this.options.bearerToken}`,
          accept: 'application/json',
          'content-type': 'application/json',
        }
      : {
          authorization: `Bearer ${this.options.bearerToken}`,
          accept: 'application/json',
        };
  }

  private async fetchJson(
    path: string,
    init: RequestInit,
    maxBytes: number,
  ): Promise<{ status: number; payload: unknown }> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    } catch {
      throw new DeviceRelayClientError(
        'NETWORK_ERROR',
        'Relay request failed before an authoritative response was received.',
      );
    }
    const contentType = response.headers.get('content-type');
    if (contentType === null || contentType.split(';', 1)[0].trim() !== 'application/json') {
      throw new DeviceRelayClientError(
        'INVALID_RESPONSE',
        'Relay response content type is incompatible.',
        response.status,
      );
    }
    const raw = await response.text();
    if (byteLength(raw) > maxBytes) {
      throw new DeviceRelayClientError(
        'RESPONSE_TOO_LARGE',
        'Relay response exceeded the bounded transport contract.',
        response.status,
      );
    }
    let payload: unknown;
    try {
      payload = parseCanonicalJson(raw);
    } catch {
      throw new DeviceRelayClientError(
        'INVALID_RESPONSE',
        'Relay response body is not valid JSON.',
        response.status,
      );
    }
    return { status: response.status, payload };
  }
}

function normalizeBaseUrl(input: string, allowLoopbackHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new DeviceRelayClientError(
      'INVALID_BASE_URL',
      'Relay base URL is invalid.',
    );
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new DeviceRelayClientError(
      'INVALID_BASE_URL',
      'Relay base URL must not include credentials, query, or fragment.',
    );
  }
  if (url.protocol === 'https:') {
    return url.href.replace(/\/$/, '');
  }
  if (url.protocol === 'http:' && allowLoopbackHttp && isLoopbackHost(url.hostname)) {
    return url.href.replace(/\/$/, '');
  }
  throw new DeviceRelayClientError(
    'INSECURE_BASE_URL',
    'Relay base URL must be HTTPS unless explicit test-only loopback HTTP is enabled.',
  );
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

function validBearerToken(value: string): boolean {
  return value.length > 0 && value.length <= 4096 && !/[\u0000-\u0020\u007f]/.test(value);
}

function decodePublishResponse(value: unknown): PublishFrameResponse {
  const raw = exactObject(value, ['stored', 'idempotent']);
  if (typeof raw.stored !== 'boolean' || typeof raw.idempotent !== 'boolean') {
    throw new DeviceRelayClientError(
      'INVALID_RESPONSE',
      'Relay publish response is incompatible.',
    );
  }
  return {
    stored: raw.stored,
    idempotent: raw.idempotent,
  };
}

function decodeReadFrames(
  value: unknown,
  mailboxId: string,
  afterSequence: number,
): RemoteOpaqueFrame[] {
  if (!Array.isArray(value) || value.length > MAX_FRAME_BATCH) {
    throw new DeviceRelayClientError(
      'INVALID_RESPONSE',
      'Relay frame list response is incompatible.',
    );
  }
  const frames = value.map((entry) => decodeFrame(entry));
  let previous = afterSequence;
  for (const frame of frames) {
    if (frame.mailbox_id !== mailboxId || frame.direction !== 'host_to_device') {
      throw new DeviceRelayClientError(
        'INVALID_FRAME',
        'Relay frame list response is incompatible.',
      );
    }
    if (frame.sequence <= afterSequence || frame.sequence <= previous) {
      throw new DeviceRelayClientError(
        'INVALID_FRAME',
        'Relay frame list response is incompatible.',
      );
    }
    previous = frame.sequence;
  }
  return frames;
}

function decodeFrame(value: unknown): RemoteOpaqueFrame {
  const raw = exactObject(value, [
    'schema',
    'crypto_suite',
    'mailbox_id',
    'direction',
    'epoch',
    'sequence',
    'message_id',
    'issued_at',
    'expires_at',
    'nonce',
    'ciphertext',
  ]);
  const frame: RemoteOpaqueFrame = {
    schema: raw.schema as RemoteOpaqueFrame['schema'],
    crypto_suite: raw.crypto_suite as RemoteOpaqueFrame['crypto_suite'],
    mailbox_id: raw.mailbox_id as string,
    direction: raw.direction as RemoteOpaqueFrame['direction'],
    epoch: raw.epoch as number,
    sequence: raw.sequence as number,
    message_id: raw.message_id as string,
    issued_at: raw.issued_at as number,
    expires_at: raw.expires_at as number,
    nonce: raw.nonce as string,
    ciphertext: raw.ciphertext as string,
  };
  validateFrame(frame);
  return frame;
}

function validateFrame(frame: RemoteOpaqueFrame): void {
  if (frame.schema !== FRAME_SCHEMA || frame.crypto_suite !== FRAME_SUITE) {
    throw new DeviceRelayClientError('INVALID_FRAME', 'Relay frame is incompatible.');
  }
  validateMailboxId(frame.mailbox_id);
  validateDirection(frame.direction);
  validateSequence(frame.epoch, false, 'epoch');
  validateSequence(frame.sequence, false, 'sequence');
  if (!MESSAGE_ID.test(frame.message_id)) {
    throw new DeviceRelayClientError('INVALID_FRAME', 'Relay frame message_id is invalid.');
  }
  if (!Number.isSafeInteger(frame.issued_at) || frame.issued_at <= 0
      || !Number.isSafeInteger(frame.expires_at) || frame.expires_at <= frame.issued_at
      || frame.expires_at - frame.issued_at > MAX_TTL_SECONDS
      || frame.issued_at > MAX_SAFE_INTEGER || frame.expires_at > MAX_SAFE_INTEGER) {
    throw new DeviceRelayClientError('INVALID_FRAME', 'Relay frame expiry window is invalid.');
  }
  const nonce = decodeBase64Url(frame.nonce, 'nonce');
  if (nonce.byteLength !== 12) {
    throw new DeviceRelayClientError('INVALID_FRAME', 'Relay frame nonce is invalid.');
  }
  const ciphertext = decodeBase64Url(frame.ciphertext, 'ciphertext');
  if (ciphertext.byteLength < 16 || ciphertext.byteLength > MAX_WIRE_FRAME_BYTES) {
    throw new DeviceRelayClientError('INVALID_FRAME', 'Relay frame ciphertext is invalid.');
  }
}

function validateAck(ack: OpaqueAckV2): void {
  if (ack.schema !== ACK_SCHEMA) {
    throw new DeviceRelayClientError('INVALID_ACK', 'Relay ack schema is invalid.');
  }
  validateMailboxId(ack.mailbox_id);
  validateDirection(ack.direction);
  validateSequence(ack.epoch, false, 'epoch');
  validateSequence(ack.acked_through_sequence, false, 'acked_through_sequence');
}

function validateMailboxId(mailboxId: string): void {
  if (!MAILBOX_ID.test(mailboxId)) {
    throw new DeviceRelayClientError('INVALID_MAILBOX_ID', 'Relay mailbox_id is invalid.');
  }
}

function validateDirection(direction: string): asserts direction is RelayDirection {
  if (!DIRECTION.test(direction)) {
    throw new DeviceRelayClientError('INVALID_DIRECTION', 'Relay direction is invalid.');
  }
}

function validateSequence(value: number, zeroAllowed: boolean, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SAFE_INTEGER || (!zeroAllowed && value === 0)) {
    throw new DeviceRelayClientError('INVALID_SEQUENCE', `Relay ${field} is invalid.`);
  }
}

function serializeFrame(frame: RemoteOpaqueFrame): string {
  validateFrame(frame);
  return JSON.stringify({
    schema: frame.schema,
    crypto_suite: frame.crypto_suite,
    mailbox_id: frame.mailbox_id,
    direction: frame.direction,
    epoch: frame.epoch,
    sequence: frame.sequence,
    message_id: frame.message_id,
    issued_at: frame.issued_at,
    expires_at: frame.expires_at,
    nonce: frame.nonce,
    ciphertext: frame.ciphertext,
  });
}

function serializeAck(ack: OpaqueAckV2): string {
  validateAck(ack);
  return JSON.stringify({
    schema: ack.schema,
    mailbox_id: ack.mailbox_id,
    direction: ack.direction,
    epoch: ack.epoch,
    acked_through_sequence: ack.acked_through_sequence,
  });
}

function exactObject(value: unknown, keys: string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeviceRelayClientError('INVALID_RESPONSE', 'Relay response is incompatible.');
  }
  const raw = value as Record<string, unknown>;
  const actual = Object.keys(raw).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new DeviceRelayClientError('INVALID_RESPONSE', 'Relay response is incompatible.');
  }
  return raw;
}

function decodeBase64Url(value: unknown, field: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !BASE64URL_NOPAD.test(value)) {
    throw new DeviceRelayClientError('INVALID_FRAME', `Relay ${field} encoding is invalid.`);
  }
  const padded = value + '==='.slice((value.length + 3) % 4);
  try {
    const decoded = Uint8Array.from(
      Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
    );
    if (Buffer.from(decoded).toString('base64url') !== value) {
      throw new Error('non-canonical');
    }
    return decoded;
  } catch {
    throw new DeviceRelayClientError('INVALID_FRAME', `Relay ${field} encoding is invalid.`);
  }
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
