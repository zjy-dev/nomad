import type { CommandCapability, GatewayCommandRequest } from '../client/types';
import { computeSnapshotDigest } from '../contracts/digest';

const encoder = new TextEncoder();

const MAX_CANONICAL_PLAINTEXT_BYTES = 32 * 1024;
const MAX_COMMAND_PAYLOAD_BYTES = 16 * 1024;
const MAX_RECEIPT_PAYLOAD_BYTES = 4 * 1024;
const MAX_REPLY_CONTENT_BYTES = 8 * 1024;
const MAX_JSON_DEPTH = 16;
const MAX_JSON_NODES = 4096;
const ENVELOPE_SCHEMA = 'nomad.remote.application-envelope.v1';
const PROJECTION_SCHEMA = 'nomad.remote.projection.v1';
const COMMAND_SCHEMA = 'nomad.remote.command.v1';
const RECEIPT_SCHEMA = 'nomad.remote.receipt.v1';
const PRODUCT_SNAPSHOT_SCHEMA = 'nomad.product-host.snapshot.v1';
const PRODUCT_COMMAND_CAPABILITY_SCHEMA = 'nomad.product-host.command-capability.v1';
const PRODUCT_PENDING_QUESTION_SUMMARY_SCHEMA = 'nomad.product-host.pending-question-summary.v1';
const GATEWAY_COMMAND_SCHEMA = 'nomad.gateway.command.v1';
const GATEWAY_COMMAND_RECEIPT_SCHEMA = 'nomad.gateway.command-receipt.v1';

const MAILBOX_ID = /^mbx-[0-9a-f]{64}$/;
const MESSAGE_ID = /^msg-[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HOST_INSTANCE_ID = /^host-[0-9a-f]{32}$/;
const OPAQUE = /^[A-Za-z0-9_-]{8,160}$/;
const SESSION_ALIAS = /^sess-[0-9a-f]{32}$/;
const TURN_ALIAS = /^turn-[0-9a-f]{32}$/;
const INPUT_ALIAS = /^input-[0-9a-f]{32}$/;
const PERMISSION_ALIAS = /^permission-[0-9a-f]{32}$/;
const DIRECTION = /^(host_to_device|device_to_host)$/;

const TURN_STATES = new Set([
  'Running',
  'NeedsInput',
  'NeedsPermission',
  'Completed',
  'OutcomeUnknown',
]);
export type RemoteDirection = 'host_to_device' | 'device_to_host';
export type RemoteApplicationEnvelopeKind = 'projection' | 'command' | 'receipt';
export type RemoteReceiptStatus =
  | 'HostAccepted'
  | 'Dispatching'
  | 'DispatchAcknowledged'
  | 'Rejected'
  | 'Stale'
  | 'Expired'
  | 'OutcomeUnknown';
export type RemoteReceiptErrorCode =
  | 'OK'
  | 'ERR_DUPLICATE_REQUEST'
  | 'ERR_REQUEST_STALE'
  | 'ERR_REQUEST_EXPIRED'
  | 'ERR_INCOMPATIBLE_VERSION'
  | 'ERR_REQUEST_REVOKED'
  | 'ERR_OUTCOME_UNKNOWN'
  | 'ERR_COMMAND_REJECTED'
  | 'ERR_PERMISSION_DENIED'
  | 'ERR_SAFETY_BLOCKED'
  | 'ERR_HOST_OFFLINE';

export interface RemoteApplicationFrameBinding {
  mailbox_id: string;
  direction: RemoteDirection;
  epoch: number;
  sequence: number;
  message_id: string;
}

export interface ProductSnapshotEnvelope {
  schema: typeof PRODUCT_SNAPSHOT_SCHEMA;
  host_instance_id: string;
  snapshot_seq: number;
  digest: string;
  snapshot: ProductReadonlySnapshot;
}

export interface ProductReadonlySnapshot {
  session_alias: string;
  updated_at: string;
  turn_state: string;
  pending_input_alias: string | null;
  pending_permission_alias: string | null;
  diff_file_count: number;
  writable: false;
  evidence_class: 'official_registry_shape_only_not_provider_lifecycle';
}

export interface RemoteProjectionPayload {
  schema: typeof PROJECTION_SCHEMA;
  snapshot: ProductSnapshotEnvelope;
  capability: CommandCapability | null;
}

export interface RemoteCommandPayload {
  schema: typeof COMMAND_SCHEMA;
  command: GatewayCommandRequest;
}

export interface RemoteReceiptPayload {
  schema: typeof RECEIPT_SCHEMA;
  receipt: RemoteGatewayCommandReceipt;
}

export interface RemoteGatewayCommandReceipt {
  schema: typeof GATEWAY_COMMAND_RECEIPT_SCHEMA;
  receipt_id: string;
  request_id: string;
  action: GatewayCommandRequest['action'];
  snapshot_seq: number;
  snapshot_digest: string;
  accepted_at: string;
  status: RemoteReceiptStatus;
  error_code: RemoteReceiptErrorCode;
  idempotent_replay: boolean;
}

interface DecodedEnvelopeBase {
  schema: typeof ENVELOPE_SCHEMA;
  kind: RemoteApplicationEnvelopeKind;
  mailbox_id: string;
  direction: RemoteDirection;
  epoch: number;
  sequence: number;
  message_id: string;
  payload: unknown;
}

interface RemoteApplicationEnvelopeBase<K extends RemoteApplicationEnvelopeKind, P> {
  schema: typeof ENVELOPE_SCHEMA;
  kind: K;
  mailbox_id: string;
  direction: RemoteDirection;
  epoch: number;
  sequence: number;
  message_id: string;
  payload: P;
}

export type RemoteProjectionEnvelope = RemoteApplicationEnvelopeBase<'projection', RemoteProjectionPayload>;
export type RemoteCommandEnvelope = RemoteApplicationEnvelopeBase<'command', RemoteCommandPayload>;
export type RemoteReceiptEnvelope = RemoteApplicationEnvelopeBase<'receipt', RemoteReceiptPayload>;
export type RemoteApplicationEnvelope =
  | RemoteProjectionEnvelope
  | RemoteCommandEnvelope
  | RemoteReceiptEnvelope;

export class RemoteApplicationEnvelopeError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export async function parseRemoteApplicationEnvelope(
  canonicalPlaintextJson: string,
  authenticatedFrame: RemoteApplicationFrameBinding,
): Promise<RemoteApplicationEnvelope> {
  validateFrameBinding(authenticatedFrame);
  if (typeof canonicalPlaintextJson !== 'string') {
    throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
  }
  if (encoder.encode(canonicalPlaintextJson).byteLength > MAX_CANONICAL_PLAINTEXT_BYTES) {
    throw new RemoteApplicationEnvelopeError('APPLICATION_ENVELOPE_TOO_LARGE');
  }
  const parsed = parseStrictCanonicalJson(canonicalPlaintextJson);
  if (!isObject(parsed)) {
    throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
  }
  if (canonicalize(parsed) !== canonicalPlaintextJson) {
    throw new RemoteApplicationEnvelopeError('NON_CANONICAL_APPLICATION_ENVELOPE');
  }

  const raw = decodeEnvelopeBase(parsed, authenticatedFrame);

  if (raw.kind === 'projection') {
    if (raw.direction !== 'host_to_device') {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    return {
      schema: ENVELOPE_SCHEMA,
      kind: 'projection',
      mailbox_id: raw.mailbox_id,
      direction: raw.direction,
      epoch: raw.epoch,
      sequence: raw.sequence,
      message_id: raw.message_id,
      payload: await decodeProjectionPayload(raw.payload),
    };
  }
  if (raw.kind === 'command') {
    if (raw.direction !== 'device_to_host') {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    return {
      schema: ENVELOPE_SCHEMA,
      kind: 'command',
      mailbox_id: raw.mailbox_id,
      direction: raw.direction,
      epoch: raw.epoch,
      sequence: raw.sequence,
      message_id: raw.message_id,
      payload: decodeCommandPayload(raw.payload),
    };
  }
  if (raw.kind === 'receipt') {
    if (raw.direction !== 'host_to_device') {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    return {
      schema: ENVELOPE_SCHEMA,
      kind: 'receipt',
      mailbox_id: raw.mailbox_id,
      direction: raw.direction,
      epoch: raw.epoch,
      sequence: raw.sequence,
      message_id: raw.message_id,
      payload: decodeReceiptPayload(raw.payload),
    };
  }
  throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
}

function decodeEnvelopeBase(
  value: unknown,
  authenticatedFrame: RemoteApplicationFrameBinding,
): DecodedEnvelopeBase {
  const raw = exactObject(
    value,
    ['schema', 'kind', 'mailbox_id', 'direction', 'epoch', 'sequence', 'message_id', 'payload'],
    'INVALID_APPLICATION_ENVELOPE',
  );
  const schema = decodeExactSchema(raw.schema, ENVELOPE_SCHEMA, 'INVALID_APPLICATION_ENVELOPE');
  const kind = decodeEnvelopeKind(raw.kind);
  const mailboxId = decodeMailboxId(raw.mailbox_id, 'INVALID_APPLICATION_ENVELOPE');
  const direction = decodeDirection(raw.direction, 'INVALID_APPLICATION_ENVELOPE');
  const epoch = decodePositiveInteger(raw.epoch, 'INVALID_APPLICATION_ENVELOPE');
  const sequence = decodePositiveInteger(raw.sequence, 'INVALID_APPLICATION_ENVELOPE');
  const messageId = decodeMessageId(raw.message_id, 'INVALID_APPLICATION_ENVELOPE');
  validateOuterBinding(
    {
      mailbox_id: mailboxId,
      direction,
      epoch,
      sequence,
      message_id: messageId,
    },
    authenticatedFrame,
  );
  return {
    schema,
    kind,
    mailbox_id: mailboxId,
    direction,
    epoch,
    sequence,
    message_id: messageId,
    payload: raw.payload,
  };
}

function validateFrameBinding(binding: RemoteApplicationFrameBinding): void {
  if (!MAILBOX_ID.test(binding.mailbox_id)) {
    throw new RemoteApplicationEnvelopeError('INVALID_FRAME_BINDING');
  }
  if (!DIRECTION.test(binding.direction)) {
    throw new RemoteApplicationEnvelopeError('INVALID_FRAME_BINDING');
  }
  if (!safePositiveInteger(binding.epoch) || !safePositiveInteger(binding.sequence)) {
    throw new RemoteApplicationEnvelopeError('INVALID_FRAME_BINDING');
  }
  if (!MESSAGE_ID.test(binding.message_id)) {
    throw new RemoteApplicationEnvelopeError('INVALID_FRAME_BINDING');
  }
}

function validateOuterBinding(
  value: {
    mailbox_id: string;
    direction: RemoteDirection;
    epoch: number;
    sequence: number;
    message_id: string;
  },
  authenticatedFrame: RemoteApplicationFrameBinding,
): void {
  if (
    value.mailbox_id !== authenticatedFrame.mailbox_id ||
    value.direction !== authenticatedFrame.direction ||
    value.epoch !== authenticatedFrame.epoch ||
    value.sequence !== authenticatedFrame.sequence ||
    value.message_id !== authenticatedFrame.message_id
  ) {
    throw new RemoteApplicationEnvelopeError('APPLICATION_ENVELOPE_BINDING_MISMATCH');
  }
}

async function decodeProjectionPayload(value: unknown): Promise<RemoteProjectionPayload> {
  const raw = exactObject(value, ['schema', 'snapshot', 'capability'], 'INVALID_PROJECTION_PAYLOAD');
  const snapshot = await decodeProductSnapshotEnvelope(raw.snapshot);
  const capability = raw.capability === null ? null : decodeCommandCapability(raw.capability, snapshot);
  return {
    schema: decodeExactSchema(raw.schema, PROJECTION_SCHEMA, 'INVALID_PROJECTION_PAYLOAD'),
    snapshot,
    capability,
  };
}

async function decodeProductSnapshotEnvelope(value: unknown): Promise<ProductSnapshotEnvelope> {
  const raw = exactObject(
    value,
    ['schema', 'host_instance_id', 'snapshot_seq', 'digest', 'snapshot'],
    'INVALID_PROJECTION_PAYLOAD',
  );
  const schema = decodeExactSchema(raw.schema, PRODUCT_SNAPSHOT_SCHEMA, 'INVALID_PROJECTION_PAYLOAD');
  const hostInstanceId = decodeHostInstanceId(raw.host_instance_id, 'INVALID_PROJECTION_PAYLOAD');
  const snapshotSeq = decodePositiveInteger(raw.snapshot_seq, 'INVALID_PROJECTION_PAYLOAD');
  const digest = decodeDigest(raw.digest, 'INVALID_PROJECTION_PAYLOAD');
  const snapshot = decodeProductReadonlySnapshot(raw.snapshot);
  const expectedDigest = await computeSnapshotDigest({
    schema,
    host_instance_id: hostInstanceId,
    snapshot_seq: snapshotSeq,
    snapshot,
  });
  if (digest !== expectedDigest) {
    throw new RemoteApplicationEnvelopeError('INVALID_PROJECTION_PAYLOAD');
  }
  return {
    schema,
    host_instance_id: hostInstanceId,
    snapshot_seq: snapshotSeq,
    digest,
    snapshot,
  };
}

function decodeProductReadonlySnapshot(value: unknown): ProductReadonlySnapshot {
  const raw = exactObject(
    value,
    [
      'session_alias',
      'updated_at',
      'turn_state',
      'pending_input_alias',
      'pending_permission_alias',
      'diff_file_count',
      'writable',
      'evidence_class',
    ],
    'INVALID_PROJECTION_PAYLOAD',
  );
  const sessionAlias = decodePrefixedOpaque(raw.session_alias, SESSION_ALIAS, 'INVALID_PROJECTION_PAYLOAD');
  const updatedAt = decodeMillisecondUtcTimestamp(raw.updated_at, 'INVALID_PROJECTION_PAYLOAD');
  const turnState = decodeTurnState(raw.turn_state, 'INVALID_PROJECTION_PAYLOAD');
  const pendingInputAlias = decodeOptionalPrefixedOpaque(
    raw.pending_input_alias,
    INPUT_ALIAS,
    'INVALID_PROJECTION_PAYLOAD',
  );
  const pendingPermissionAlias = decodeOptionalPrefixedOpaque(
    raw.pending_permission_alias,
    PERMISSION_ALIAS,
    'INVALID_PROJECTION_PAYLOAD',
  );
  const diffFileCount = decodeBoundedInteger(raw.diff_file_count, 0, 256, 'INVALID_PROJECTION_PAYLOAD');
  if (raw.writable !== false || raw.evidence_class !== 'official_registry_shape_only_not_provider_lifecycle') {
    throw new RemoteApplicationEnvelopeError('INVALID_PROJECTION_PAYLOAD');
  }
  return {
    session_alias: sessionAlias,
    updated_at: updatedAt,
    turn_state: turnState,
    pending_input_alias: pendingInputAlias,
    pending_permission_alias: pendingPermissionAlias,
    diff_file_count: diffFileCount,
    writable: false,
    evidence_class: 'official_registry_shape_only_not_provider_lifecycle',
  };
}

function decodeCommandCapability(value: unknown, snapshot: ProductSnapshotEnvelope): CommandCapability {
  const raw = exactObject(
    value,
    [
      'schema',
      'capability_id',
      'snapshot_seq',
      'snapshot_digest',
      'next_command_seq',
      'issued_at',
      'expires_at',
      'view',
      'reply',
      'deny',
      'stop',
      'allow_once',
    ],
    'INVALID_PROJECTION_PAYLOAD',
  );
  const schema = decodeExactSchema(
    raw.schema,
    PRODUCT_COMMAND_CAPABILITY_SCHEMA,
    'INVALID_PROJECTION_PAYLOAD',
  );
  const capabilityId = decodeOpaque(raw.capability_id, 'INVALID_PROJECTION_PAYLOAD');
  const snapshotSeq = decodePositiveInteger(raw.snapshot_seq, 'INVALID_PROJECTION_PAYLOAD');
  const nextCommandSeq = decodePositiveInteger(raw.next_command_seq, 'INVALID_PROJECTION_PAYLOAD');
  const snapshotDigest = decodeDigest(raw.snapshot_digest, 'INVALID_PROJECTION_PAYLOAD');
  const issuedAt = decodeWholeSecondUtcTimestamp(raw.issued_at, 'INVALID_PROJECTION_PAYLOAD');
  const expiresAt = decodeWholeSecondUtcTimestamp(raw.expires_at, 'INVALID_PROJECTION_PAYLOAD');
  if (raw.view !== true || raw.allow_once !== false) {
    throw new RemoteApplicationEnvelopeError('INVALID_PROJECTION_PAYLOAD');
  }
  const ttl = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (ttl <= 0 || ttl > 30_000) {
    throw new RemoteApplicationEnvelopeError('INVALID_PROJECTION_PAYLOAD');
  }
  if (snapshotSeq !== snapshot.snapshot_seq || snapshotDigest !== snapshot.digest || nextCommandSeq <= 0) {
    throw new RemoteApplicationEnvelopeError('INVALID_PROJECTION_PAYLOAD');
  }
  return {
    schema,
    capability_id: capabilityId,
    snapshot_seq: snapshotSeq,
    snapshot_digest: snapshotDigest,
    next_command_seq: nextCommandSeq,
    issued_at: issuedAt,
    expires_at: expiresAt,
    view: true,
    reply: decodeReplyAction(raw.reply),
    deny: decodeDenyAction(raw.deny),
    stop: decodeStopAction(raw.stop),
    allow_once: false,
  };
}

function decodeReplyAction(value: unknown): CommandCapability['reply'] {
  if (value === null) {
    return null;
  }
  const raw = exactObject(value, ['turn_alias', 'input_alias', 'summary'], 'INVALID_PROJECTION_PAYLOAD');
  const turnAlias = decodePrefixedOpaque(raw.turn_alias, TURN_ALIAS, 'INVALID_PROJECTION_PAYLOAD');
  const inputAlias = decodePrefixedOpaque(raw.input_alias, INPUT_ALIAS, 'INVALID_PROJECTION_PAYLOAD');
  return {
    turn_alias: turnAlias,
    input_alias: inputAlias,
    summary: raw.summary === null ? null : decodePendingQuestionSummary(raw.summary),
  };
}

function decodePendingQuestionSummary(value: unknown): NonNullable<NonNullable<CommandCapability['reply']>['summary']> {
  const raw = exactObject(
    value,
    ['schema', 'question_count', 'answer_mode', 'response_hint', 'prompt'],
    'INVALID_PROJECTION_PAYLOAD',
  );
  const schema = decodeExactSchema(
    raw.schema,
    PRODUCT_PENDING_QUESTION_SUMMARY_SCHEMA,
    'INVALID_PROJECTION_PAYLOAD',
  );
  if (raw.question_count !== 1 || raw.answer_mode !== 'free_text' || raw.response_hint !== 'single_short_reply') {
    throw new RemoteApplicationEnvelopeError('INVALID_PROJECTION_PAYLOAD');
  }
  const prompt = decodeSafePrompt(raw.prompt, 'INVALID_PROJECTION_PAYLOAD');
  return {
    schema,
    question_count: 1,
    answer_mode: 'free_text',
    response_hint: 'single_short_reply',
    prompt,
  };
}

function decodeDenyAction(value: unknown): CommandCapability['deny'] {
  if (value === null) {
    return null;
  }
  const raw = exactObject(value, ['permission_alias', 'action_hash', 'expires_at'], 'INVALID_PROJECTION_PAYLOAD');
  const permissionAlias = decodePrefixedOpaque(raw.permission_alias, PERMISSION_ALIAS, 'INVALID_PROJECTION_PAYLOAD');
  const actionHash = decodeDigest(raw.action_hash, 'INVALID_PROJECTION_PAYLOAD');
  const expiresAt = decodeWholeSecondUtcTimestamp(raw.expires_at, 'INVALID_PROJECTION_PAYLOAD');
  return {
    permission_alias: permissionAlias,
    action_hash: actionHash,
    expires_at: expiresAt,
  };
}

function decodeStopAction(value: unknown): CommandCapability['stop'] {
  if (value === null) {
    return null;
  }
  const raw = exactObject(value, ['turn_alias'], 'INVALID_PROJECTION_PAYLOAD');
  return {
    turn_alias: decodePrefixedOpaque(raw.turn_alias, TURN_ALIAS, 'INVALID_PROJECTION_PAYLOAD'),
  };
}

function decodeCommandPayload(value: unknown): RemoteCommandPayload {
  enforceCanonicalObjectSize(value, MAX_COMMAND_PAYLOAD_BYTES, 'INVALID_COMMAND_PAYLOAD');
  const raw = exactObject(value, ['schema', 'command'], 'INVALID_COMMAND_PAYLOAD');
  return {
    schema: decodeExactSchema(raw.schema, COMMAND_SCHEMA, 'INVALID_COMMAND_PAYLOAD'),
    command: decodeGatewayCommandRequest(raw.command),
  };
}

function decodeGatewayCommandRequest(value: unknown): GatewayCommandRequest {
  if (!isObject(value)) {
    throw new RemoteApplicationEnvelopeError('INVALID_COMMAND_PAYLOAD');
  }
  enforceCanonicalObjectSize(value, MAX_COMMAND_PAYLOAD_BYTES, 'INVALID_COMMAND_PAYLOAD');
  const action = decodeCommandAction(value.action, 'INVALID_COMMAND_PAYLOAD');
  const raw =
    action === 'reply'
      ? exactObject(
          value,
          [
            'schema',
            'capability_id',
            'request_id',
            'nonce',
            'command_seq',
            'expected_snapshot_seq',
            'expected_snapshot_digest',
            'issued_at',
            'expires_at',
            'action',
            'turn_alias',
            'input_alias',
            'content',
          ],
          'INVALID_COMMAND_PAYLOAD',
        )
      : action === 'deny'
        ? exactObject(
            value,
            [
              'schema',
              'capability_id',
              'request_id',
              'nonce',
              'command_seq',
              'expected_snapshot_seq',
              'expected_snapshot_digest',
              'issued_at',
              'expires_at',
              'action',
              'permission_alias',
              'action_hash',
              'permission_expires_at',
            ],
            'INVALID_COMMAND_PAYLOAD',
          )
        : exactObject(
            value,
            [
              'schema',
              'capability_id',
              'request_id',
              'nonce',
              'command_seq',
              'expected_snapshot_seq',
              'expected_snapshot_digest',
              'issued_at',
              'expires_at',
              'action',
              'turn_alias',
            ],
            'INVALID_COMMAND_PAYLOAD',
          );
  const schema = decodeExactSchema(raw.schema, GATEWAY_COMMAND_SCHEMA, 'INVALID_COMMAND_PAYLOAD');
  const capabilityId = decodeOpaque(raw.capability_id, 'INVALID_COMMAND_PAYLOAD');
  const requestId = decodeOpaque(raw.request_id, 'INVALID_COMMAND_PAYLOAD');
  const nonce = decodeOpaque(raw.nonce, 'INVALID_COMMAND_PAYLOAD');
  const commandSeq = decodePositiveInteger(raw.command_seq, 'INVALID_COMMAND_PAYLOAD');
  const expectedSnapshotSeq = decodePositiveInteger(raw.expected_snapshot_seq, 'INVALID_COMMAND_PAYLOAD');
  const expectedSnapshotDigest = decodeDigest(raw.expected_snapshot_digest, 'INVALID_COMMAND_PAYLOAD');
  const issuedAt = decodeWholeSecondUtcTimestamp(raw.issued_at, 'INVALID_COMMAND_PAYLOAD');
  const expiresAt = decodeWholeSecondUtcTimestamp(raw.expires_at, 'INVALID_COMMAND_PAYLOAD');
  const ttl = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (ttl <= 0 || ttl > 30_000) {
    throw new RemoteApplicationEnvelopeError('INVALID_COMMAND_PAYLOAD');
  }
  if (action === 'reply') {
    const turnAlias = decodePrefixedOpaque(raw.turn_alias, TURN_ALIAS, 'INVALID_COMMAND_PAYLOAD');
    const inputAlias = decodePrefixedOpaque(raw.input_alias, INPUT_ALIAS, 'INVALID_COMMAND_PAYLOAD');
    const content = decodeReplyContent(raw.content, 'INVALID_COMMAND_PAYLOAD');
    return {
      schema,
      capability_id: capabilityId,
      request_id: requestId,
      nonce,
      command_seq: commandSeq,
      expected_snapshot_seq: expectedSnapshotSeq,
      expected_snapshot_digest: expectedSnapshotDigest,
      issued_at: issuedAt,
      expires_at: expiresAt,
      action: 'reply',
      turn_alias: turnAlias,
      input_alias: inputAlias,
      content,
    };
  }
  if (action === 'deny') {
    const permissionAlias = decodePrefixedOpaque(raw.permission_alias, PERMISSION_ALIAS, 'INVALID_COMMAND_PAYLOAD');
    const actionHash = decodeDigest(raw.action_hash, 'INVALID_COMMAND_PAYLOAD');
    const permissionExpiresAt = decodeWholeSecondUtcTimestamp(raw.permission_expires_at, 'INVALID_COMMAND_PAYLOAD');
    return {
      schema,
      capability_id: capabilityId,
      request_id: requestId,
      nonce,
      command_seq: commandSeq,
      expected_snapshot_seq: expectedSnapshotSeq,
      expected_snapshot_digest: expectedSnapshotDigest,
      issued_at: issuedAt,
      expires_at: expiresAt,
      action: 'deny',
      permission_alias: permissionAlias,
      action_hash: actionHash,
      permission_expires_at: permissionExpiresAt,
    };
  }
  const turnAlias = decodePrefixedOpaque(raw.turn_alias, TURN_ALIAS, 'INVALID_COMMAND_PAYLOAD');
  return {
    schema,
    capability_id: capabilityId,
    request_id: requestId,
    nonce,
    command_seq: commandSeq,
    expected_snapshot_seq: expectedSnapshotSeq,
    expected_snapshot_digest: expectedSnapshotDigest,
    issued_at: issuedAt,
    expires_at: expiresAt,
    action: 'stop',
    turn_alias: turnAlias,
  };
}

function decodeReceiptPayload(value: unknown): RemoteReceiptPayload {
  enforceCanonicalObjectSize(value, MAX_RECEIPT_PAYLOAD_BYTES, 'INVALID_RECEIPT_PAYLOAD');
  const raw = exactObject(value, ['schema', 'receipt'], 'INVALID_RECEIPT_PAYLOAD');
  return {
    schema: decodeExactSchema(raw.schema, RECEIPT_SCHEMA, 'INVALID_RECEIPT_PAYLOAD'),
    receipt: decodeGatewayCommandReceipt(raw.receipt),
  };
}

function decodeGatewayCommandReceipt(value: unknown): RemoteGatewayCommandReceipt {
  const raw = exactObject(
    value,
    [
      'schema',
      'receipt_id',
      'request_id',
      'action',
      'snapshot_seq',
      'snapshot_digest',
      'accepted_at',
      'status',
      'error_code',
      'idempotent_replay',
    ],
    'INVALID_RECEIPT_PAYLOAD',
  );
  const schema = decodeExactSchema(raw.schema, GATEWAY_COMMAND_RECEIPT_SCHEMA, 'INVALID_RECEIPT_PAYLOAD');
  const receiptId = decodeOpaque(raw.receipt_id, 'INVALID_RECEIPT_PAYLOAD');
  const requestId = decodeOpaque(raw.request_id, 'INVALID_RECEIPT_PAYLOAD');
  const action = decodeCommandAction(raw.action, 'INVALID_RECEIPT_PAYLOAD');
  const snapshotSeq = decodePositiveInteger(raw.snapshot_seq, 'INVALID_RECEIPT_PAYLOAD');
  const snapshotDigest = decodeDigest(raw.snapshot_digest, 'INVALID_RECEIPT_PAYLOAD');
  const acceptedAt = decodeWholeSecondUtcTimestamp(raw.accepted_at, 'INVALID_RECEIPT_PAYLOAD');
  const status = decodeReceiptStatus(raw.status, 'INVALID_RECEIPT_PAYLOAD');
  const errorCode = decodeReceiptError(raw.error_code, 'INVALID_RECEIPT_PAYLOAD');
  if (typeof raw.idempotent_replay !== 'boolean') {
    throw new RemoteApplicationEnvelopeError('INVALID_RECEIPT_PAYLOAD');
  }
  return {
    schema,
    receipt_id: receiptId,
    request_id: requestId,
    action,
    snapshot_seq: snapshotSeq,
    snapshot_digest: snapshotDigest,
    accepted_at: acceptedAt,
    status,
    error_code: errorCode,
    idempotent_replay: raw.idempotent_replay,
  };
}

function decodeExactSchema<T extends string>(value: unknown, expected: T, code: string): T {
  if (value !== expected) {
    throw new RemoteApplicationEnvelopeError(code);
  }
  return expected;
}

function decodeEnvelopeKind(value: unknown): RemoteApplicationEnvelopeKind {
  if (value === 'projection' || value === 'command' || value === 'receipt') {
    return value;
  }
  throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
}

function decodeDirection(value: unknown, code: string): RemoteDirection {
  if (value === 'host_to_device' || value === 'device_to_host') {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeMailboxId(value: unknown, code: string): string {
  if (typeof value === 'string' && MAILBOX_ID.test(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeMessageId(value: unknown, code: string): string {
  if (typeof value === 'string' && MESSAGE_ID.test(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeHostInstanceId(value: unknown, code: string): string {
  if (typeof value === 'string' && HOST_INSTANCE_ID.test(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodePositiveInteger(value: unknown, code: string): number {
  if (safePositiveInteger(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeBoundedInteger(value: unknown, min: number, max: number, code: string): number {
  if (safeInteger(value) && value >= min && value <= max) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeDigest(value: unknown, code: string): string {
  if (digest(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeOpaque(value: unknown, code: string): string {
  if (opaque(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodePrefixedOpaque(value: unknown, pattern: RegExp, code: string): string {
  if (prefixedOpaque(value, pattern)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeOptionalPrefixedOpaque(value: unknown, pattern: RegExp, code: string): string | null {
  if (value === null || prefixedOpaque(value, pattern)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeTimestamp(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value === 'string' && pattern.test(value) && Number.isFinite(Date.parse(value))) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeWholeSecondUtcTimestamp(value: unknown, code: string): string {
  return decodeTimestamp(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, code);
}

function decodeMillisecondUtcTimestamp(value: unknown, code: string): string {
  return decodeTimestamp(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, code);
}

function decodeSafePrompt(value: unknown, code: string): string {
  if (safePrompt(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeTurnState(value: unknown, code: string): string {
  if (typeof value === 'string' && TURN_STATES.has(value)) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeCommandAction(
  value: unknown,
  code: string,
): GatewayCommandRequest['action'] {
  if (value === 'reply' || value === 'deny' || value === 'stop') {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeReplyContent(value: unknown, code: string): string {
  if (
    typeof value === 'string' &&
    value.trim().length > 0 &&
    encoder.encode(value).byteLength <= MAX_REPLY_CONTENT_BYTES
  ) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeReceiptStatus(value: unknown, code: string): RemoteReceiptStatus {
  if (
    value === 'HostAccepted' ||
    value === 'Dispatching' ||
    value === 'DispatchAcknowledged' ||
    value === 'Rejected' ||
    value === 'Stale' ||
    value === 'Expired' ||
    value === 'OutcomeUnknown'
  ) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function decodeReceiptError(value: unknown, code: string): RemoteReceiptErrorCode {
  if (
    value === 'OK' ||
    value === 'ERR_DUPLICATE_REQUEST' ||
    value === 'ERR_REQUEST_STALE' ||
    value === 'ERR_REQUEST_EXPIRED' ||
    value === 'ERR_INCOMPATIBLE_VERSION' ||
    value === 'ERR_REQUEST_REVOKED' ||
    value === 'ERR_OUTCOME_UNKNOWN' ||
    value === 'ERR_COMMAND_REJECTED' ||
    value === 'ERR_PERMISSION_DENIED' ||
    value === 'ERR_SAFETY_BLOCKED' ||
    value === 'ERR_HOST_OFFLINE'
  ) {
    return value;
  }
  throw new RemoteApplicationEnvelopeError(code);
}

function exactObject(
  value: unknown,
  keys: string[],
  code: string,
): Record<string, unknown> {
  if (!isObject(value)) {
    throw new RemoteApplicationEnvelopeError(code);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new RemoteApplicationEnvelopeError(code);
  }
  return value;
}

function enforceCanonicalObjectSize(value: unknown, maxBytes: number, code: string): void {
  if (!isObject(value)) {
    throw new RemoteApplicationEnvelopeError(code);
  }
  if (encoder.encode(canonicalize(value)).byteLength > maxBytes) {
    throw new RemoteApplicationEnvelopeError(code);
  }
}

function parseStrictCanonicalJson(json: string): unknown {
  const parser = new StrictJsonParser(json);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.isAtEnd()) {
    throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
  }
  return value;
}

function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(',')}}`;
  }
  throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
}

function isObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value);
}

function safePositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function digest(value: unknown): value is string {
  return typeof value === 'string' && DIGEST.test(value);
}

function opaque(value: unknown): value is string {
  return typeof value === 'string' && OPAQUE.test(value);
}

function prefixedOpaque(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && pattern.test(value);
}

function safePrompt(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 160 &&
    /^Provide a short reply for: [a-z0-9]+(?:[ -][a-z0-9]+){0,5}\.$/.test(value)
  );
}

class StrictJsonParser {
  private readonly source: string;
  private index = 0;
  private nodeCount = 0;
  private depth = 0;

  constructor(source: string) {
    this.source = source;
  }

  parseValue(): unknown {
    this.skipWhitespace();
    const current = this.peek();
    if (current === undefined) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    if (current === '"') return this.parseString();
    if (current === '{') return this.parseObject();
    if (current === '[') return this.parseArray();
    if (current === 't') return this.parseLiteral('true', true);
    if (current === 'f') return this.parseLiteral('false', false);
    if (current === 'n') return this.parseLiteral('null', null);
    if (current === '-' || isDigit(current)) return this.parseNumber();
    throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
  }

  skipWhitespace(): void {
    while (this.index < this.source.length) {
      const current = this.source.charCodeAt(this.index);
      if (current !== 0x20 && current !== 0x0a && current !== 0x0d && current !== 0x09) {
        break;
      }
      this.index += 1;
    }
  }

  isAtEnd(): boolean {
    return this.index === this.source.length;
  }

  private parseObject(): Record<string, unknown> {
    this.enterContainer();
    this.expect('{');
    this.skipWhitespace();
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    if (this.peek() === '}') {
      this.index += 1;
      this.leaveContainer();
      return out;
    }
    while (true) {
      this.skipWhitespace();
      if (this.peek() !== '"') {
        throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
      }
      const key = this.parseString();
      if (seen.has(key)) {
        throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
      }
      seen.add(key);
      this.skipWhitespace();
      this.expect(':');
      out[key] = this.parseValue();
      this.skipWhitespace();
      const current = this.peek();
      if (current === '}') {
        this.index += 1;
        this.leaveContainer();
        return out;
      }
      if (current !== ',') {
        throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
      }
      this.index += 1;
    }
  }

  private parseArray(): unknown[] {
    this.enterContainer();
    this.expect('[');
    this.skipWhitespace();
    const out: unknown[] = [];
    if (this.peek() === ']') {
      this.index += 1;
      this.leaveContainer();
      return out;
    }
    while (true) {
      out.push(this.parseValue());
      this.skipWhitespace();
      const current = this.peek();
      if (current === ']') {
        this.index += 1;
        this.leaveContainer();
        return out;
      }
      if (current !== ',') {
        throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
      }
      this.index += 1;
    }
  }

  private parseString(): string {
    this.countNode();
    const start = this.index;
    this.expect('"');
    while (this.index < this.source.length) {
      const current = this.source.charCodeAt(this.index);
      if (current === 0x22) {
        this.index += 1;
        try {
          return JSON.parse(this.source.slice(start, this.index)) as string;
        } catch {
          throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
        }
      }
      if (current === 0x5c) {
        this.index += 1;
        if (this.index >= this.source.length) {
          throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
        }
        const escaped = this.source.charCodeAt(this.index);
        if (escaped === 0x75) {
          for (let offset = 1; offset <= 4; offset += 1) {
            const code = this.source.charCodeAt(this.index + offset);
            if (!isHexCodeUnit(code)) {
              throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
            }
          }
          this.index += 5;
          continue;
        }
        if (!isJsonEscapeCodeUnit(escaped)) {
          throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
        }
        this.index += 1;
        continue;
      }
      if (current <= 0x1f) {
        throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
      }
      this.index += 1;
    }
    throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
  }

  private parseNumber(): number {
    this.countNode();
    const remainder = this.source.slice(this.index);
    const match = remainder.match(/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/);
    if (!match) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    const token = match[0];
    this.index += token.length;
    const value = Number(token);
    if (!Number.isFinite(value)) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    return value;
  }

  private parseLiteral(token: string, value: boolean | null): boolean | null {
    this.countNode();
    if (this.source.slice(this.index, this.index + token.length) !== token) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    this.index += token.length;
    return value;
  }

  private expect(expected: string): void {
    if (this.peek() !== expected) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
    this.index += 1;
  }

  private peek(): string | undefined {
    return this.source[this.index];
  }

  private countNode(): void {
    this.nodeCount += 1;
    if (this.nodeCount > MAX_JSON_NODES) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
  }

  private enterContainer(): void {
    this.countNode();
    this.depth += 1;
    if (this.depth > MAX_JSON_DEPTH) {
      throw new RemoteApplicationEnvelopeError('INVALID_APPLICATION_ENVELOPE');
    }
  }

  private leaveContainer(): void {
    this.depth -= 1;
  }
}

function isDigit(value: string): boolean {
  return value >= '0' && value <= '9';
}

function isHexCodeUnit(value: number): boolean {
  return (
    (value >= 0x30 && value <= 0x39) ||
    (value >= 0x41 && value <= 0x46) ||
    (value >= 0x61 && value <= 0x66)
  );
}

function isJsonEscapeCodeUnit(value: number): boolean {
  return (
    value === 0x22 ||
    value === 0x5c ||
    value === 0x2f ||
    value === 0x62 ||
    value === 0x66 ||
    value === 0x6e ||
    value === 0x72 ||
    value === 0x74
  );
}
