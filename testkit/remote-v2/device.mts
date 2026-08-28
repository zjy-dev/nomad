import { tmpdir } from 'node:os';
import { constants as FS_CONSTANTS } from 'node:fs';
import { mkdtemp, open, lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const RESULT_SCHEMA = 'nomad.remote-v2.device-phase.v1';
const STATE_SCHEMA = 'nomad.remote-v2.device-state.v1';
const VECTOR_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../contracts/vectors/remote-envelope-v2.json',
);
const MAX_STATE_BYTES = 512 * 1024;
const STATE_DIR_MODE = 0o700;
const STATE_FILE_MODE = 0o600;
const FRAME_TTL_SECONDS = 30;
const COMMAND_TTL_SECONDS = 20;
const OPAQUE_ID_BYTES = 16;
const MESSAGE_ID_BYTES = 16;
const PHASES = new Set(['consume-projection', 'publish-command', 'consume-receipt'] as const);
const DIRECTION_HOST_TO_DEVICE = 'host_to_device' as const;
const DIRECTION_DEVICE_TO_HOST = 'device_to_host' as const;

type Phase = 'consume-projection' | 'publish-command' | 'consume-receipt';

interface CliOptions {
  phase: Phase;
  relayUrl: string;
  statePath: string;
}

interface StoredDirectionDeviceToHost {
  direction: typeof DIRECTION_DEVICE_TO_HOST;
  next_sequence: number;
  pending_outbound_frame: PendingOutboundFrame | null;
}

interface StoredDirectionHostToDevice {
  direction: typeof DIRECTION_HOST_TO_DEVICE;
  applied_through_sequence: number;
  pending_applied_batch: PersistedAppliedBatch | null;
  applied_batch: PersistedAppliedBatch | null;
}

interface StoredState {
  schema: typeof STATE_SCHEMA;
  mailbox_id: string;
  epoch: number;
  device_to_host: StoredDirectionDeviceToHost;
  host_to_device: StoredDirectionHostToDevice;
}

interface DeviceSecrets {
  mailboxId: string;
  epoch: number;
  context: {
    mailboxId: string;
    epoch: number;
    hostSigningCommitment: string;
    hostAgreementCommitment: string;
    deviceSigningCommitment: string;
    deviceAgreementCommitment: string;
  };
  hostAgreementPublicKey: CryptoKey;
  deviceSigningPrivateKey: CryptoKey;
  deviceAgreementPrivateKey: CryptoKey;
  deviceSigningPublicKeySec1: Uint8Array;
  deviceAgreementPublicKeySec1: Uint8Array;
}

interface RemoteOpaqueFrame {
  schema: 'nomad.relay.opaque-frame.v2';
  crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1';
  mailbox_id: string;
  direction: 'host_to_device' | 'device_to_host';
  epoch: number;
  sequence: number;
  message_id: string;
  issued_at: number;
  expires_at: number;
  nonce: string;
  ciphertext: string;
}

interface PendingOutboundFrame {
  sequence: number;
  frame: RemoteOpaqueFrame;
}

interface ReceivedHostEnvelope {
  frame: RemoteOpaqueFrame;
  envelope: unknown;
}

interface PersistedAppliedBatch {
  appliedThroughSequence: number;
  envelopes: ReadonlyArray<ReceivedHostEnvelope>;
}

interface DurableDeviceState {
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

interface DeviceEnvelopeCodec {
  encryptDeviceEnvelope(input: {
    mailboxId: string;
    epoch: number;
    sequence: number;
    envelope: unknown;
  }): Promise<RemoteOpaqueFrame>;
  decryptHostEnvelope(frame: RemoteOpaqueFrame): Promise<unknown>;
}

interface RemoteApplicationEnvelope {
  kind: 'projection' | 'command' | 'receipt';
  mailbox_id: string;
  direction: 'host_to_device' | 'device_to_host';
  epoch: number;
  sequence: number;
  message_id: string;
  payload: unknown;
}

interface RemoteProjectionEnvelope extends RemoteApplicationEnvelope {
  kind: 'projection';
  payload: {
    schema: 'nomad.remote.projection.v1';
    snapshot: unknown;
    capability: CommandCapability | null;
  };
}

interface RemoteReceiptEnvelope extends RemoteApplicationEnvelope {
  kind: 'receipt';
  payload: unknown;
}

interface CommandCapability {
  schema: 'nomad.product-host.command-capability.v1';
  capability_id: string;
  snapshot_seq: number;
  snapshot_digest: string;
  next_command_seq: number;
  issued_at: string;
  expires_at: string;
  view: true;
  stop: { turn_alias: string } | null;
  allow_once: false;
}

type GatewayCommandRequest = {
  schema: 'nomad.gateway.command.v1';
  capability_id: string;
  request_id: string;
  nonce: string;
  command_seq: number;
  expected_snapshot_seq: number;
  expected_snapshot_digest: string;
  issued_at: string;
  expires_at: string;
  action: 'stop';
  turn_alias: string;
};

interface StopCommandIntent {
  kind: 'stop_command_intent';
  capability: CommandCapability;
}

interface RemoteModules {
  DeviceEndpoint: new (options: {
    mailboxId: string;
    epoch: number;
    relay: unknown;
    state: DurableDeviceState;
    codec: DeviceEnvelopeCodec;
  }) => {
    retryPendingOutbound(): Promise<unknown>;
    publishDeviceEnvelope(envelope: unknown): Promise<{ frame: RemoteOpaqueFrame }>;
    receiveHostEnvelopes(): Promise<ReceivedHostEnvelope[]>;
  };
  DeviceRelayClient: new (options: {
    baseUrl: string;
    bearerToken: string;
    allowLoopbackHttp?: boolean;
  }) => unknown;
  canonicalJson(value: unknown): string;
  decryptRemoteFrame(input: Record<string, unknown>): Promise<{
    canonicalPlaintextJson: string;
  }>;
  encryptRemoteFrame(input: Record<string, unknown>): Promise<{
    frame: RemoteOpaqueFrame;
  }>;
  importAgreementPrivateKeyPkcs8(pkcs8: Uint8Array, extractable?: boolean): Promise<CryptoKey>;
  importAgreementPublicKeySec1(raw: Uint8Array): Promise<CryptoKey>;
  importSigningPrivateKeyPkcs8(pkcs8: Uint8Array, extractable?: boolean): Promise<CryptoKey>;
  parseAndValidateRemoteVector(value: unknown): Record<string, string> & {
    frame: RemoteOpaqueFrame;
  };
  parseCanonicalJson(json: string): unknown;
  parseRemoteApplicationEnvelope(
    canonicalPlaintextJson: string,
    authenticatedFrame: {
      mailbox_id: string;
      direction: 'host_to_device' | 'device_to_host';
      epoch: number;
      sequence: number;
      message_id: string;
    },
  ): Promise<RemoteApplicationEnvelope>;
  validateFrame(frame: RemoteOpaqueFrame): void;
}

let remoteModulesPromise: Promise<RemoteModules> | null = null;
let remoteRuntime: RemoteModules | null = null;

class DeviceCliError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

async function getRemoteModules(): Promise<RemoteModules> {
  if (remoteModulesPromise !== null) {
    return remoteModulesPromise;
  }
  remoteModulesPromise = (async () => {
    const sourceRoot = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../mobile-reference/src',
    );
    const tempRoot = await mkdtemp(path.join(tmpdir(), 'nomad-remote-v2-ts-'));
    const files = [
      'remote/crypto.ts',
      'remote/relay-client.ts',
      'remote/device-endpoint.ts',
      'remote/application-envelope.ts',
      'client/types.ts',
      'contracts/digest.ts',
      'contracts/types.ts',
      'contracts/reducer.ts',
    ];
    for (const relative of files) {
      const from = path.join(sourceRoot, relative);
      const to = path.join(tempRoot, relative);
      await mkdir(path.dirname(to), { recursive: true, mode: STATE_DIR_MODE });
      const content = await readFile(from, 'utf8');
      const rewritten = content.replace(
        /(from\s+['"])(\.[^'"]+)(['"])/g,
        (_full, prefix, specifier, suffix) => {
          if (specifier.endsWith('.ts') || specifier.endsWith('.js') || specifier.endsWith('.mjs')) {
            return `${prefix}${specifier}${suffix}`;
          }
          return `${prefix}${specifier}.ts${suffix}`;
        },
      );
      await writeFile(to, rewritten, { mode: STATE_FILE_MODE });
    }
    const [crypto, relay, endpoint, envelope] = await Promise.all([
      import(pathToFileURL(path.join(tempRoot, 'remote/crypto.ts')).href),
      import(pathToFileURL(path.join(tempRoot, 'remote/relay-client.ts')).href),
      import(pathToFileURL(path.join(tempRoot, 'remote/device-endpoint.ts')).href),
      import(pathToFileURL(path.join(tempRoot, 'remote/application-envelope.ts')).href),
    ]);
    return {
      DeviceEndpoint: endpoint.DeviceEndpoint,
      DeviceRelayClient: relay.DeviceRelayClient,
      canonicalJson: crypto.canonicalJson,
      decryptRemoteFrame: crypto.decryptRemoteFrame,
      encryptRemoteFrame: crypto.encryptRemoteFrame,
      importAgreementPrivateKeyPkcs8: crypto.importAgreementPrivateKeyPkcs8,
      importAgreementPublicKeySec1: crypto.importAgreementPublicKeySec1,
      importSigningPrivateKeyPkcs8: crypto.importSigningPrivateKeyPkcs8,
      parseAndValidateRemoteVector: crypto.parseAndValidateRemoteVector,
      parseCanonicalJson: crypto.parseCanonicalJson,
      parseRemoteApplicationEnvelope: envelope.parseRemoteApplicationEnvelope,
      validateFrame: crypto.validateFrame,
    };
  })();
  return remoteModulesPromise;
}

async function ensureRemoteRuntime(): Promise<RemoteModules> {
  if (remoteRuntime !== null) {
    return remoteRuntime;
  }
  remoteRuntime = await getRemoteModules();
  return remoteRuntime;
}

function requireRemoteRuntime(): RemoteModules {
  if (remoteRuntime === null) {
    throw new DeviceCliError('REMOTE_RUNTIME_UNINITIALIZED');
  }
  return remoteRuntime;
}

class JsonDurableDeviceState implements DurableDeviceState {
  private readonly statePath: string;
  private readonly mailboxId: string;
  private readonly epoch: number;

  constructor(statePath: string, mailboxId: string, epoch: number) {
    this.statePath = path.resolve(statePath);
    this.mailboxId = mailboxId;
    this.epoch = epoch;
  }

  async loadPendingOutboundFrame(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
  ): Promise<PendingOutboundFrame | null> {
    const state = await this.readState(mailboxId, epoch);
    this.assertDeviceTuple(mailboxId, direction, epoch);
    return state.device_to_host.pending_outbound_frame;
  }

  async persistPendingOutboundFrame(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
    pending: PendingOutboundFrame,
  ): Promise<void> {
    this.assertDeviceTuple(mailboxId, direction, epoch);
    validatePendingOutboundFrame(pending, mailboxId, epoch);
    await this.writeUpdatedState(mailboxId, epoch, (state) => {
      state.device_to_host.pending_outbound_frame = pending;
      return state;
    });
  }

  async clearPendingOutboundFrame(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
    sequence: number,
  ): Promise<void> {
    this.assertDeviceTuple(mailboxId, direction, epoch);
    ensurePositiveInteger(sequence, 'INVALID_SEQUENCE');
    await this.writeUpdatedState(mailboxId, epoch, (state) => {
      const pending = state.device_to_host.pending_outbound_frame;
      if (pending !== null && pending.sequence === sequence) {
        state.device_to_host.pending_outbound_frame = null;
      }
      return state;
    });
  }

  async reserveNextSequence(
    mailboxId: string,
    direction: typeof DIRECTION_DEVICE_TO_HOST,
    epoch: number,
  ): Promise<number> {
    this.assertDeviceTuple(mailboxId, direction, epoch);
    let reserved = 0;
    await this.writeUpdatedState(mailboxId, epoch, (state) => {
      reserved = state.device_to_host.next_sequence;
      ensurePositiveInteger(reserved, 'INVALID_STATE');
      state.device_to_host.next_sequence = reserved + 1;
      return state;
    });
    return reserved;
  }

  async loadAppliedThroughSequence(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
  ): Promise<number> {
    const state = await this.readState(mailboxId, epoch);
    this.assertHostTuple(mailboxId, direction, epoch);
    return state.host_to_device.applied_through_sequence;
  }

  async loadPendingAppliedBatch(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
  ): Promise<PersistedAppliedBatch | null> {
    const state = await this.readState(mailboxId, epoch);
    this.assertHostTuple(mailboxId, direction, epoch);
    return state.host_to_device.pending_applied_batch;
  }

  async persistAppliedHostBatch(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
    batch: PersistedAppliedBatch,
  ): Promise<void> {
    this.assertHostTuple(mailboxId, direction, epoch);
    validatePersistedAppliedBatch(batch, mailboxId, epoch);
    await this.writeUpdatedState(mailboxId, epoch, (state) => {
      state.host_to_device.pending_applied_batch = batch;
      return state;
    });
  }

  async clearPendingAppliedBatch(
    mailboxId: string,
    direction: typeof DIRECTION_HOST_TO_DEVICE,
    epoch: number,
    appliedThroughSequence: number,
  ): Promise<void> {
    this.assertHostTuple(mailboxId, direction, epoch);
    ensurePositiveInteger(appliedThroughSequence, 'INVALID_SEQUENCE');
    await this.writeUpdatedState(mailboxId, epoch, (state) => {
      const pending = state.host_to_device.pending_applied_batch;
      if (pending !== null && pending.appliedThroughSequence === appliedThroughSequence) {
        state.host_to_device.pending_applied_batch = null;
        state.host_to_device.applied_batch = pending;
        state.host_to_device.applied_through_sequence = appliedThroughSequence;
      }
      return state;
    });
  }

  async loadLatestAppliedBatch(): Promise<PersistedAppliedBatch | null> {
    const state = await this.readState(this.mailboxId, this.epoch);
    return state.host_to_device.applied_batch;
  }

  private assertDeviceTuple(mailboxId: string, direction: string, epoch: number): void {
    if (
      mailboxId !== this.mailboxId
      || direction !== DIRECTION_DEVICE_TO_HOST
      || epoch !== this.epoch
    ) {
      throw new DeviceCliError('STATE_TUPLE_MISMATCH');
    }
  }

  private assertHostTuple(mailboxId: string, direction: string, epoch: number): void {
    if (
      mailboxId !== this.mailboxId
      || direction !== DIRECTION_HOST_TO_DEVICE
      || epoch !== this.epoch
    ) {
      throw new DeviceCliError('STATE_TUPLE_MISMATCH');
    }
  }

  private async readState(mailboxId: string, epoch: number): Promise<StoredState> {
    const file = await this.readStateFileOrDefault();
    validateStoredState(file, mailboxId, epoch);
    return file;
  }

  private async writeUpdatedState(
    mailboxId: string,
    epoch: number,
    update: (current: StoredState) => StoredState,
  ): Promise<void> {
    const current = await this.readState(mailboxId, epoch);
    const next = update(structuredClone(current));
    validateStoredState(next, mailboxId, epoch);
    await this.writeStateFile(next);
  }

  private async readStateFileOrDefault(): Promise<StoredState> {
    const parent = await ensureSafeStateParent(this.statePath);
    try {
      const handle = await open(this.statePath, FS_CONSTANTS.O_RDONLY | noFollowFlag());
      try {
        const stat = await handle.stat();
        ensureSafeStateFileStat(stat.mode, stat.uid, stat.nlink);
        if (stat.size > MAX_STATE_BYTES) {
          throw new DeviceCliError('STATE_TOO_LARGE');
        }
        const raw = await handle.readFile({ encoding: 'utf8' });
        if (Buffer.byteLength(raw, 'utf8') > MAX_STATE_BYTES) {
          throw new DeviceCliError('STATE_TOO_LARGE');
        }
        const runtime = requireRemoteRuntime();
        const parsed = runtime.parseCanonicalJson(raw);
        if (runtime.canonicalJson(parsed) !== raw) {
          throw new DeviceCliError('NON_CANONICAL_STATE');
        }
        return parsed as StoredState;
      } finally {
        await handle.close();
      }
    } catch (error) {
      if (isMissingFile(error)) {
        const initial = defaultState(this.mailboxId, this.epoch);
        await this.writeStateFile(initial, parent);
        return initial;
      }
      throw error;
    }
  }

  private async writeStateFile(value: StoredState, parent?: string): Promise<void> {
    const directory = parent ?? await ensureSafeStateParent(this.statePath);
    const tempPath = path.join(
      directory,
      `.device-state-${randomHex(16)}.tmp`,
    );
    const handle = await open(
      tempPath,
      FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | noFollowFlag(),
      STATE_FILE_MODE,
    );
    try {
      const runtime = requireRemoteRuntime();
      const raw = runtime.canonicalJson(value);
      if (Buffer.byteLength(raw, 'utf8') > MAX_STATE_BYTES) {
        throw new DeviceCliError('STATE_TOO_LARGE');
      }
      await handle.writeFile(raw);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tempPath, this.statePath);
    const stat = await lstat(this.statePath);
    ensureSafeStateFileStat(stat.mode, stat.uid, stat.nlink);
  }
}

function defaultState(mailboxId: string, epoch: number): StoredState {
  return {
    schema: STATE_SCHEMA,
    mailbox_id: mailboxId,
    epoch,
    device_to_host: {
      direction: DIRECTION_DEVICE_TO_HOST,
      next_sequence: 1,
      pending_outbound_frame: null,
    },
    host_to_device: {
      direction: DIRECTION_HOST_TO_DEVICE,
      applied_through_sequence: 0,
      pending_applied_batch: null,
      applied_batch: null,
    },
  };
}

function validateStoredState(value: unknown, mailboxId: string, epoch: number): asserts value is StoredState {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_STATE');
  }
  const top = exactKeys(value as Record<string, unknown>, [
    'schema',
    'mailbox_id',
    'epoch',
    'device_to_host',
    'host_to_device',
  ]);
  if (
    top.schema !== STATE_SCHEMA
    || top.mailbox_id !== mailboxId
    || top.epoch !== epoch
  ) {
    throw new DeviceCliError('INVALID_STATE');
  }
  validateDeviceToHostState(top.device_to_host, mailboxId, epoch);
  validateHostToDeviceState(top.host_to_device, mailboxId, epoch);
}

function validateDeviceToHostState(value: unknown, mailboxId: string, epoch: number): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_STATE');
  }
  const raw = exactKeys(value as Record<string, unknown>, [
    'direction',
    'next_sequence',
    'pending_outbound_frame',
  ]);
  if (raw.direction !== DIRECTION_DEVICE_TO_HOST) {
    throw new DeviceCliError('INVALID_STATE');
  }
  ensurePositiveInteger(raw.next_sequence, 'INVALID_STATE');
  if (raw.pending_outbound_frame !== null) {
    validatePendingOutboundFrame(raw.pending_outbound_frame, mailboxId, epoch);
  }
}

function validateHostToDeviceState(value: unknown, mailboxId: string, epoch: number): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_STATE');
  }
  const raw = exactKeys(value as Record<string, unknown>, [
    'direction',
    'applied_through_sequence',
    'pending_applied_batch',
    'applied_batch',
  ]);
  if (raw.direction !== DIRECTION_HOST_TO_DEVICE) {
    throw new DeviceCliError('INVALID_STATE');
  }
  ensureNonNegativeInteger(raw.applied_through_sequence, 'INVALID_STATE');
  if (raw.pending_applied_batch !== null) {
    validatePersistedAppliedBatch(raw.pending_applied_batch, mailboxId, epoch);
  }
  if (raw.applied_batch !== null) {
    validatePersistedAppliedBatch(raw.applied_batch, mailboxId, epoch);
  }
}

function validatePendingOutboundFrame(value: unknown, mailboxId: string, epoch: number): asserts value is PendingOutboundFrame {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_STATE');
  }
  const raw = exactKeys(value as Record<string, unknown>, ['sequence', 'frame']);
  ensurePositiveInteger(raw.sequence, 'INVALID_STATE');
  requireRemoteRuntime().validateFrame(raw.frame as RemoteOpaqueFrame);
  if (
    (raw.frame as RemoteOpaqueFrame).mailbox_id !== mailboxId
    || (raw.frame as RemoteOpaqueFrame).direction !== DIRECTION_DEVICE_TO_HOST
    || (raw.frame as RemoteOpaqueFrame).epoch !== epoch
    || (raw.frame as RemoteOpaqueFrame).sequence !== raw.sequence
  ) {
    throw new DeviceCliError('INVALID_STATE');
  }
}

function validatePersistedAppliedBatch(value: unknown, mailboxId: string, epoch: number): asserts value is PersistedAppliedBatch {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_STATE');
  }
  const raw = exactKeys(value as Record<string, unknown>, ['appliedThroughSequence', 'envelopes']);
  ensurePositiveInteger(raw.appliedThroughSequence, 'INVALID_STATE');
  if (!Array.isArray(raw.envelopes) || raw.envelopes.length === 0) {
    throw new DeviceCliError('INVALID_STATE');
  }
  let previous = 0;
  for (const item of raw.envelopes) {
    validateReceivedHostEnvelope(item, mailboxId, epoch);
    if (
      item.frame.sequence <= previous
      || item.frame.sequence > raw.appliedThroughSequence
    ) {
      throw new DeviceCliError('INVALID_STATE');
    }
    previous = item.frame.sequence;
  }
}

function validateReceivedHostEnvelope(value: unknown, mailboxId: string, epoch: number): asserts value is ReceivedHostEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_STATE');
  }
  const raw = exactKeys(value as Record<string, unknown>, ['frame', 'envelope']);
  requireRemoteRuntime().validateFrame(raw.frame as RemoteOpaqueFrame);
  const frame = raw.frame as RemoteOpaqueFrame;
  if (
    frame.mailbox_id !== mailboxId
    || frame.direction !== DIRECTION_HOST_TO_DEVICE
    || frame.epoch !== epoch
  ) {
    throw new DeviceCliError('INVALID_STATE');
  }
  parseEnvelopeObject(raw.envelope, frame);
}

function parseEnvelopeObject(value: unknown, frame: RemoteOpaqueFrame): RemoteApplicationEnvelope {
  const runtime = requireRemoteRuntime();
  const canonical = runtime.canonicalJson(value);
  return runtime.parseRemoteApplicationEnvelope(
    canonical,
    {
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
    },
  );
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): Record<string, unknown> {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new DeviceCliError('INVALID_STATE');
  }
  return value;
}

async function ensureSafeStateParent(statePath: string): Promise<string> {
  const parent = path.dirname(statePath);
  if (parent === '.' || parent === '') {
    throw new DeviceCliError('UNSAFE_STATE_PARENT');
  }
  await mkdir(parent, { mode: STATE_DIR_MODE, recursive: true });
  const info = await lstat(parent);
  if (
    !info.isDirectory()
    || info.isSymbolicLink()
    || (typeof process.geteuid === 'function' && info.uid !== process.geteuid())
    || (info.mode & 0o077) !== 0
  ) {
    throw new DeviceCliError('UNSAFE_STATE_PARENT');
  }
  const canonical = path.resolve(await readRealPath(parent));
  if (canonical !== path.resolve(parent)) {
    throw new DeviceCliError('UNSAFE_STATE_PARENT');
  }
  return parent;
}

async function readRealPath(target: string): Promise<string> {
  const fs = await import('node:fs/promises');
  return fs.realpath(target);
}

function ensureSafeStateFileStat(mode: number, uid: number, nlink: number): void {
  if (
    (mode & 0o170000) !== 0o100000
    || (typeof process.geteuid === 'function' && uid !== process.geteuid())
    || (mode & 0o777) !== STATE_FILE_MODE
    || nlink !== 1
  ) {
    throw new DeviceCliError('UNSAFE_STATE_FILE');
  }
}

function noFollowFlag(): number {
  return typeof FS_CONSTANTS.O_NOFOLLOW === 'number' ? FS_CONSTANTS.O_NOFOLLOW : 0;
}

function isMissingFile(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'code' in error && (error as { code?: string }).code === 'ENOENT';
}

function ensurePositiveInteger(value: unknown, code: string): asserts value is number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new DeviceCliError(code);
  }
}

function ensureNonNegativeInteger(value: unknown, code: string): asserts value is number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new DeviceCliError(code);
  }
}

async function loadDeviceSecrets(): Promise<DeviceSecrets> {
  const runtime = await ensureRemoteRuntime();
  const raw = await readFile(VECTOR_PATH, 'utf8');
  const vector = runtime.parseAndValidateRemoteVector(runtime.parseCanonicalJson(raw));
  const context = {
    mailboxId: vector.frame.mailbox_id,
    epoch: vector.frame.epoch,
    hostSigningCommitment: vector.host_signing_commitment,
    hostAgreementCommitment: vector.host_agreement_commitment,
    deviceSigningCommitment: vector.device_signing_commitment,
    deviceAgreementCommitment: vector.device_agreement_commitment,
  };
  return {
    mailboxId: context.mailboxId,
    epoch: context.epoch,
    context,
    hostAgreementPublicKey: await runtime.importAgreementPublicKeySec1(fromBase64Url(vector.host_agreement_public_key_sec1)),
    deviceSigningPrivateKey: await runtime.importSigningPrivateKeyPkcs8(fromBase64Url(vector.device_signing_private_key_pkcs8)),
    deviceAgreementPrivateKey: await runtime.importAgreementPrivateKeyPkcs8(fromBase64Url(vector.device_agreement_private_key_pkcs8)),
    deviceSigningPublicKeySec1: fromBase64Url(vector.device_signing_public_key_sec1),
    deviceAgreementPublicKeySec1: fromBase64Url(vector.device_agreement_public_key_sec1),
  };
}

function buildCodec(secrets: DeviceSecrets): DeviceEnvelopeCodec {
  return {
    encryptDeviceEnvelope: async ({ mailboxId, epoch, sequence, envelope }) => {
      const runtime = await ensureRemoteRuntime();
      const issuedAtSeconds = Math.floor(Date.now() / 1000);
      const messageId = `msg-${randomHex(MESSAGE_ID_BYTES)}`;
      const frameTemplate = {
        schema: 'nomad.relay.opaque-frame.v2' as const,
        crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1' as const,
        mailbox_id: mailboxId,
        direction: DIRECTION_DEVICE_TO_HOST,
        epoch,
        sequence,
        message_id: messageId,
        issued_at: issuedAtSeconds,
        expires_at: issuedAtSeconds + FRAME_TTL_SECONDS,
        nonce: 'AAAAAAAAAAAAAAAA',
      };
      const commandEnvelope = buildStopCommandEnvelope(
        decodeStopCommandIntent(envelope),
        mailboxId,
        epoch,
        sequence,
        messageId,
      );
      const validated = await runtime.parseRemoteApplicationEnvelope(
        runtime.canonicalJson(commandEnvelope),
        {
          mailbox_id: mailboxId,
          direction: DIRECTION_DEVICE_TO_HOST,
          epoch,
          sequence,
          message_id: frameTemplate.message_id,
        },
      );
      if (validated.kind !== 'command') {
        throw new DeviceCliError('INVALID_COMMAND_ENVELOPE');
      }
      return (
        await runtime.encryptRemoteFrame({
          frame: frameTemplate,
          plaintext: validated,
          senderSigningPrivateKey: secrets.deviceSigningPrivateKey,
          senderSigningPublicKeySec1: secrets.deviceSigningPublicKeySec1,
          senderAgreementPrivateKey: secrets.deviceAgreementPrivateKey,
          senderAgreementPublicKeySec1: secrets.deviceAgreementPublicKeySec1,
          recipientAgreementPublicKey: secrets.hostAgreementPublicKey,
          context: secrets.context,
        })
      ).frame;
    },
    decryptHostEnvelope: async (frame) => {
      const runtime = await ensureRemoteRuntime();
      const decrypted = await runtime.decryptRemoteFrame({
        frame,
        recipientAgreementPrivateKey: secrets.deviceAgreementPrivateKey,
        context: secrets.context,
        expectedSenderSigningCommitment: secrets.context.hostSigningCommitment,
        expectedSenderAgreementCommitment: secrets.context.hostAgreementCommitment,
      });
      return runtime.parseRemoteApplicationEnvelope(
        decrypted.canonicalPlaintextJson,
        {
          mailbox_id: frame.mailbox_id,
          direction: frame.direction,
          epoch: frame.epoch,
          sequence: frame.sequence,
          message_id: frame.message_id,
        },
      );
    },
  };
}

function takeRelayBearer(): string {
  const value = process.env.NOMAD_REMOTE_V2_DEVICE_TOKEN;
  delete process.env.NOMAD_REMOTE_V2_DEVICE_TOKEN;
  if (typeof value !== 'string' || value.length === 0) {
    throw new DeviceCliError('MISSING_DEVICE_BEARER');
  }
  return value;
}

async function exactNodeFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const requestUrl = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  const sourceInit = typeof input === 'string' || input instanceof URL ? init : {
    method: input.method,
    headers: input.headers,
    body: input.body,
    signal: input.signal,
    redirect: input.redirect,
    ...(init ?? {}),
  };
  if (sourceInit.redirect !== undefined && sourceInit.redirect !== 'manual') {
    throw new DeviceCliError('UNSUPPORTED_FETCH_REDIRECT');
  }

  const method = (sourceInit.method ?? 'GET').toUpperCase();
  const body = await encodeRequestBody(sourceInit.body);
  const headers = filterRelayRequestHeaders(sourceInit.headers, body);
  // Node suppresses all implicit headers when `setDefaultHeaders` is false.
  // Supply only the mandatory HTTP Host header in addition to the explicit
  // Relay allowlist assembled above.
  headers.host = requestUrl.host;
  const transport = requestUrl.protocol === 'https:' ? https : requestUrl.protocol === 'http:' ? http : null;
  if (transport === null) {
    throw new DeviceCliError('INVALID_BASE_URL');
  }

  return await new Promise<Response>((resolve, reject) => {
    const request = transport.request(
      {
        protocol: requestUrl.protocol,
        hostname: requestUrl.hostname,
        port: requestUrl.port === '' ? undefined : Number(requestUrl.port),
        path: `${requestUrl.pathname}${requestUrl.search}`,
        method,
        headers,
        setDefaultHeaders: false,
        agent: false,
        servername: requestUrl.hostname,
      },
      async (response) => {
        try {
          const chunks: Buffer[] = [];
          for await (const chunk of response) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          }
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(response.headers)) {
            if (value === undefined) {
              continue;
            }
            if (Array.isArray(value)) {
              for (const item of value) {
                responseHeaders.append(key, item);
              }
            } else {
              responseHeaders.set(key, value);
            }
          }
          resolve(new Response(Buffer.concat(chunks), {
            status: response.statusCode ?? 0,
            statusText: response.statusMessage ?? '',
            headers: responseHeaders,
          }));
        } catch (error) {
          reject(error);
        }
      },
    );

    const abortSignal = sourceInit.signal;
    const abortListener = () => {
      request.destroy(new Error('ABORT_ERR'));
    };
    if (abortSignal !== undefined) {
      if (abortSignal.aborted) {
        abortListener();
        return;
      }
      abortSignal.addEventListener('abort', abortListener, { once: true });
    }
    request.once('error', (error) => {
      if (abortSignal !== undefined) {
        abortSignal.removeEventListener('abort', abortListener);
      }
      reject(error);
    });
    request.once('response', () => {
      if (abortSignal !== undefined) {
        abortSignal.removeEventListener('abort', abortListener);
      }
    });
    if (body !== null) {
      request.end(body);
      return;
    }
    request.end();
  });
}

async function encodeRequestBody(body: BodyInit | null | undefined): Promise<Buffer | null> {
  if (body === null || body === undefined) {
    return null;
  }
  if (typeof body === 'string') {
    return Buffer.from(body, 'utf8');
  }
  if (body instanceof Uint8Array) {
    return Buffer.from(body);
  }
  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }
  if (ArrayBuffer.isView(body)) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }
  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString(), 'utf8');
  }
  if (typeof Blob !== 'undefined' && body instanceof Blob) {
    return Buffer.from(await body.arrayBuffer());
  }
  throw new DeviceCliError('UNSUPPORTED_FETCH_BODY');
}

function filterRelayRequestHeaders(
  input: HeadersInit | undefined,
  body: Buffer | null,
): Record<string, string> {
  const output: Record<string, string> = {};
  const headers = new Headers(input ?? {});
  for (const [key, value] of headers.entries()) {
    const normalized = key.toLowerCase();
    if (
      normalized === 'authorization'
      || normalized === 'accept'
      || normalized === 'content-type'
    ) {
      output[normalized] = value;
    }
  }
  if (body !== null) {
    output['content-length'] = String(body.byteLength);
  }
  return output;
}

async function buildEndpoint(options: CliOptions): Promise<{
  endpoint: DeviceEndpoint;
  state: JsonDurableDeviceState;
}> {
  const runtime = await ensureRemoteRuntime();
  const secrets = await loadDeviceSecrets();
  const state = new JsonDurableDeviceState(options.statePath, secrets.mailboxId, secrets.epoch);
  const relay = new runtime.DeviceRelayClient({
    baseUrl: options.relayUrl,
    bearerToken: takeRelayBearer(),
    allowLoopbackHttp: true,
    fetchImpl: exactNodeFetch,
  });
  const endpoint = new runtime.DeviceEndpoint({
    mailboxId: secrets.mailboxId,
    epoch: secrets.epoch,
    relay,
    state,
    codec: buildCodec(secrets),
  });
  return { endpoint, state };
}

function projectionFromEnvelopes(envelopes: readonly ReceivedHostEnvelope[]): RemoteProjectionEnvelope | null {
  for (let index = envelopes.length - 1; index >= 0; index -= 1) {
    const envelope = envelopes[index]?.envelope;
    if (envelope && typeof envelope === 'object' && (envelope as RemoteApplicationEnvelope).kind === 'projection') {
      return envelope as RemoteProjectionEnvelope;
    }
  }
  return null;
}

function receiptFromEnvelopes(envelopes: readonly ReceivedHostEnvelope[]): RemoteReceiptEnvelope | null {
  for (let index = envelopes.length - 1; index >= 0; index -= 1) {
    const envelope = envelopes[index]?.envelope;
    if (envelope && typeof envelope === 'object' && (envelope as RemoteApplicationEnvelope).kind === 'receipt') {
      return envelope as RemoteReceiptEnvelope;
    }
  }
  return null;
}

function buildStopCommandEnvelope(
  intent: StopCommandIntent,
  mailboxId: string,
  epoch: number,
  sequence: number,
  messageId: string,
): RemoteApplicationEnvelope {
  const capability = intent.capability;
  validateStopCapability(capability);
  const issuedAtDate = new Date(Math.floor(Date.now() / 1000) * 1000);
  const capabilityExpiry = Date.parse(capability.expires_at);
  if (!Number.isFinite(capabilityExpiry) || capabilityExpiry <= issuedAtDate.getTime()) {
    throw new DeviceCliError('STOP_CAPABILITY_EXPIRED');
  }
  const expiresAtDate = new Date(
    Math.min(capabilityExpiry, issuedAtDate.getTime() + COMMAND_TTL_SECONDS * 1000),
  );
  if (expiresAtDate.getTime() <= issuedAtDate.getTime()) {
    throw new DeviceCliError('STOP_CAPABILITY_EXPIRED');
  }
  const command: GatewayCommandRequest = {
    schema: 'nomad.gateway.command.v1',
    capability_id: capability.capability_id,
    request_id: `req-${randomBase64UrlOpaque()}`,
    nonce: `nonce-${randomBase64UrlOpaque()}`,
    command_seq: capability.next_command_seq,
    expected_snapshot_seq: capability.snapshot_seq,
    expected_snapshot_digest: capability.snapshot_digest,
    issued_at: toWholeSecondUtc(issuedAtDate),
    expires_at: toWholeSecondUtc(expiresAtDate),
    action: 'stop',
    turn_alias: capability.stop.turn_alias,
  };
  const envelope = {
    schema: 'nomad.remote.application-envelope.v1' as const,
    kind: 'command' as const,
    mailbox_id: mailboxId,
    direction: DIRECTION_DEVICE_TO_HOST,
    epoch,
    sequence,
    message_id: messageId,
    payload: {
      schema: 'nomad.remote.command.v1' as const,
      command,
    },
  };
  return envelope;
}

function decodeStopCommandIntent(value: unknown): StopCommandIntent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DeviceCliError('INVALID_COMMAND_INTENT');
  }
  const raw = exactKeys(value as Record<string, unknown>, ['kind', 'capability']);
  if (raw.kind !== 'stop_command_intent') {
    throw new DeviceCliError('INVALID_COMMAND_INTENT');
  }
  validateStopCapability(raw.capability as CommandCapability);
  return {
    kind: 'stop_command_intent',
    capability: raw.capability as CommandCapability,
  };
}

function validateStopCapability(capability: CommandCapability): void {
  if (
    capability.schema !== 'nomad.product-host.command-capability.v1'
    || capability.view !== true
    || capability.allow_once !== false
    || capability.stop === null
  ) {
    throw new DeviceCliError('STOP_CAPABILITY_UNAVAILABLE');
  }
}

function toWholeSecondUtc(value: Date): string {
  return new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

async function runPhase(options: CliOptions): Promise<void> {
  const runtime = await ensureRemoteRuntime();
  const { endpoint, state } = await buildEndpoint(options);
  if (options.phase === 'consume-projection') {
    const received = await endpoint.receiveHostEnvelopes();
    const latest = projectionFromEnvelopes(received)
      ?? projectionFromEnvelopes((await state.loadLatestAppliedBatch())?.envelopes ?? []);
    if (latest === null) {
      throw new DeviceCliError('PROJECTION_REQUIRED');
    }
    return;
  }
  if (options.phase === 'publish-command') {
    try {
      await endpoint.retryPendingOutbound();
      return;
    } catch (error) {
      if (!isErrorCode(error, 'OUTBOUND_RECOVERY_REQUIRED')) {
        throw error;
      }
    }
    const latestProjection = projectionFromEnvelopes((await state.loadLatestAppliedBatch())?.envelopes ?? []);
    if (latestProjection === null) {
      throw new DeviceCliError('PROJECTION_REQUIRED');
    }
    const capability = latestProjection.payload.capability;
    if (capability === null || capability.stop === null) {
      throw new DeviceCliError('STOP_CAPABILITY_UNAVAILABLE');
    }
    await endpoint.publishDeviceEnvelope({
      kind: 'stop_command_intent',
      capability,
    } satisfies StopCommandIntent);
    return;
  }
  const received = await endpoint.receiveHostEnvelopes();
  const latest = receiptFromEnvelopes(received)
    ?? receiptFromEnvelopes((await state.loadLatestAppliedBatch())?.envelopes ?? []);
  if (latest === null) {
    throw new DeviceCliError('RECEIPT_REQUIRED');
  }
}

function isErrorCode(error: unknown, code: string): boolean {
  return !!error && typeof error === 'object' && 'code' in error && (error as { code?: string }).code === code;
}

function parseArgs(argv: readonly string[]): CliOptions {
  let phase: string | undefined;
  let relayUrl: string | undefined;
  let statePath: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item === '--phase') {
      phase = argv[++index];
    } else if (item === '--relay-url') {
      relayUrl = argv[++index];
    } else if (item === '--state' || item === '--state-path') {
      statePath = argv[++index];
    } else if (!item.startsWith('-') && phase === undefined) {
      phase = item;
    } else {
      throw new DeviceCliError('INVALID_ARGUMENTS');
    }
  }
  if (!phase || !PHASES.has(phase as Phase) || !relayUrl || !statePath) {
    throw new DeviceCliError('INVALID_ARGUMENTS');
  }
  return {
    phase: phase as Phase,
    relayUrl,
    statePath,
  };
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new DeviceCliError('INVALID_VECTOR_ENCODING');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function randomHex(bytes: number): string {
  const raw = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(raw);
  return Buffer.from(raw).toString('hex');
}

function randomBase64UrlOpaque(): string {
  const raw = new Uint8Array(OPAQUE_ID_BYTES);
  globalThis.crypto.getRandomValues(raw);
  return Buffer.from(raw).toString('base64url');
}

function result(value: { phase: Phase | null; status: 'OK' | 'ERROR'; error?: string }): string {
  return JSON.stringify(
    {
      schema: RESULT_SCHEMA,
      phase: value.phase,
      status: value.status,
      ...(value.error ? { error: value.error } : {}),
    },
  );
}

async function main(): Promise<number> {
  let phase: Phase | null = null;
  try {
    const options = parseArgs(process.argv.slice(2));
    phase = options.phase;
    await runPhase(options);
    process.stdout.write(result({ phase, status: 'OK' }) + '\n');
    return 0;
  } catch (error) {
    const code = isErrorCode(error, (error as { code?: string }).code ?? '')
      ? (error as { code: string }).code
      : 'DEVICE_PHASE_FAILED';
    process.stdout.write(result({ phase, status: 'ERROR', error: code }) + '\n');
    return 1;
  }
}

void main().then((code) => {
  process.exitCode = code;
});
