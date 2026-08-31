import type { GatewayCommandRequest } from '../client/types';
import {
  parseRemoteApplicationEnvelope,
  type RemoteApplicationEnvelope,
  type RemoteGatewayCommandReceipt,
  type RemoteProjectionEnvelope,
} from './application-envelope';
import {
  BrowserVault,
  BrowserVaultError,
  type BrowserVaultSession,
} from './browser-vault';
import {
  canonicalJson,
  computeKeyCommitment,
  decryptRemoteFrame,
  deriveDeterministicNonceAsync,
  encryptRemoteFrame,
  exportPublicKeySec1,
  importAgreementPublicKeySec1,
  type RemoteFrameMetadata,
  type RemoteOpaqueFrame,
  type RemoteSharedContext,
} from './crypto';
import {
  DeviceEndpoint,
  DeviceEndpointError,
  type DeviceEnvelopeCodec,
  type DurableDeviceState,
  type PendingOutboundFrame,
  type PersistedAppliedBatch,
} from './device-endpoint';
import {
  DeviceRelayClient,
  DeviceRelayClientError,
  type DeviceRelayTransport,
} from './relay-client';

const DURABLE_STATE_SCHEMA = 'nomad.m3e.paired-session-state.v1';
const APPLICATION_ENVELOPE_SCHEMA = 'nomad.remote.application-envelope.v1';
const COMMAND_PAYLOAD_SCHEMA = 'nomad.remote.command.v1';
const GATEWAY_COMMAND_SCHEMA = 'nomad.gateway.command.v1';
const FRAME_SCHEMA = 'nomad.relay.opaque-frame.v2';
const FRAME_SUITE = 'p256-hkdf-sha256-aes256gcm-v1';
const FRAME_TTL_SECONDS = 60;
const MAX_CAS_ATTEMPTS = 16;
const MAX_REPLY_BYTES = 8 * 1024;
const PAIRED_SESSION_NAMESPACE = 'paired-session';
const encoder = new TextEncoder();

export type RemoteSessionConnection =
  | 'reconnecting'
  | 'live'
  | 'revoked'
  | 'key_lost'
  | 'unavailable';

export type RemoteSessionIntent =
  | { action: 'view' }
  | { action: 'reply'; content: string }
  | { action: 'deny' }
  | { action: 'stop' };

export type RemotePendingCommandStatus =
  | 'prepared'
  | 'published'
  | 'HostAccepted'
  | 'Dispatching'
  | 'DispatchAcknowledged'
  | 'Rejected'
  | 'Stale'
  | 'Expired'
  | 'OutcomeUnknown';

export interface RemotePendingCommand {
  request_id: string;
  action: 'reply' | 'deny' | 'stop';
  command_seq: number;
  snapshot_seq: number;
  snapshot_digest: string;
  status: RemotePendingCommandStatus;
}

export interface RemoteSessionSnapshot {
  connection: RemoteSessionConnection;
  last_good_projection: RemoteProjectionEnvelope['payload'] | null;
  last_receipt: RemoteGatewayCommandReceipt | null;
  pending_command: RemotePendingCommand | null;
  available_actions: ReadonlyArray<'view' | 'reply' | 'deny' | 'stop'>;
  error_code: string | null;
}

/** UI-facing boundary. This module deliberately has no React dependency. */
export interface RemoteSessionPort {
  getSnapshot(): RemoteSessionSnapshot;
  subscribe(listener: (snapshot: RemoteSessionSnapshot) => void): () => void;
  poll(): Promise<RemoteSessionSnapshot>;
  dispatch(intent: RemoteSessionIntent | unknown): Promise<RemoteSessionSnapshot>;
  retryPending(): Promise<RemoteSessionSnapshot>;
}

export interface PairedSessionStateKey {
  mailboxId: string;
  epoch: number;
}

export interface PairedSessionDurableState {
  schema: typeof DURABLE_STATE_SCHEMA;
  revision: number;
  hostToDeviceAppliedThroughSequence: number;
  deviceToHostNextSequence: number;
  pendingOutbound: PendingOutboundFrame | null;
  pendingAppliedBatch: PersistedAppliedBatch | null;
  lastGoodProjection: RemoteProjectionEnvelope | null;
  lastReceipt: RemoteGatewayCommandReceipt | null;
  pendingCommand: RemotePendingCommand | null;
  revoked: boolean;
}

/** Atomic state boundary. Production factories adapt BrowserVault's generic
 * namespace CAS; explicit implementations are reserved for tests or another
 * durable backend and are never silently replaced with memory storage. */
export interface PairedSessionStateStore {
  load(key: PairedSessionStateKey): Promise<PairedSessionDurableState | null>;
  compareAndSwap(
    key: PairedSessionStateKey,
    expectedRevision: number | null,
    next: PairedSessionDurableState,
  ): Promise<boolean>;
}

export interface CreateRemoteSessionPortOptions {
  session: BrowserVaultSession;
  /** Required in production unless an explicit durable stateStore is supplied. */
  vault?: BrowserVault;
  /** Explicit durable backend override, primarily for tests. */
  stateStore?: PairedSessionStateStore;
  fetchImpl?: typeof fetch;
  allowLoopbackHttp?: boolean;
  now?: () => Date;
  randomBytes?: (length: number) => Uint8Array;
}

export interface RestoreRemoteSessionPortOptions
  extends Omit<CreateRemoteSessionPortOptions, 'session'> {
  vault: BrowserVault;
}

export class RemoteSessionError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class MemoryPairedSessionStateStore implements PairedSessionStateStore {
  private readonly records = new Map<string, PairedSessionDurableState>();

  async load(key: PairedSessionStateKey): Promise<PairedSessionDurableState | null> {
    const value = this.records.get(stateKey(key));
    return value === undefined ? null : cloneState(value);
  }

  async compareAndSwap(
    key: PairedSessionStateKey,
    expectedRevision: number | null,
    next: PairedSessionDurableState,
  ): Promise<boolean> {
    const storageKey = stateKey(key);
    const current = this.records.get(storageKey);
    if (expectedRevision === null ? current !== undefined : current?.revision !== expectedRevision) {
      return false;
    }
    this.records.set(storageKey, cloneState(next));
    return true;
  }
}

/**
 * Production adapter backed by BrowserVault's generic IndexedDB namespace.
 * BrowserVault owns the atomic transaction and has no dependency on this
 * module, avoiding a BrowserVault <-> paired-session import cycle.
 */
export function createBrowserVaultPairedSessionStateStore(
  vault: BrowserVault,
): PairedSessionStateStore {
  return {
    load: async (key) => {
      const record = await vault.loadNamespaceRecord<PairedSessionDurableState>(
        PAIRED_SESSION_NAMESPACE,
        browserVaultStateKey(key),
      );
      if (record === null) return null;
      validateDurableState(record.value);
      if (record.revision !== record.value.revision) {
        throw new RemoteSessionError(
          'INVALID_DURABLE_STATE',
          'Browser vault namespace revision does not match paired session state.',
        );
      }
      return cloneState(record.value);
    },
    compareAndSwap: async (key, expectedRevision, next) => {
      validateDurableState(next);
      const expectedNextRevision = expectedRevision === null ? 0 : expectedRevision + 1;
      if (next.revision !== expectedNextRevision) {
        throw new RemoteSessionError(
          'INVALID_DURABLE_STATE',
          'Paired session revision does not match the compare-and-swap transition.',
        );
      }
      return vault.compareAndSwapNamespaceRecord(
        PAIRED_SESSION_NAMESPACE,
        browserVaultStateKey(key),
        expectedRevision,
        cloneState(next),
      );
    },
  };
}

export class PairedSessionDurableAdapter implements DurableDeviceState {
  private cached: PairedSessionDurableState | null = null;

  constructor(
    private readonly store: PairedSessionStateStore,
    private readonly key: PairedSessionStateKey,
    private readonly seed: { appliedThrough: number; nextSequence: number },
  ) {}

  async initialize(): Promise<PairedSessionDurableState> {
    return this.update((state) => {
      // DeviceEndpoint always persists the exact encrypted frame before the
      // first Relay call. Therefore a prepared command without that frame is
      // provably pre-publish and can be discarded after a crash.
      const recovered = state.pendingCommand?.status === 'prepared' && state.pendingOutbound === null
        ? { ...state, pendingCommand: null }
        : state;
      return { state: recovered, result: recovered };
    });
  }

  snapshot(): PairedSessionDurableState {
    if (this.cached === null) {
      throw new RemoteSessionError('PAIRED_SESSION_NOT_INITIALIZED', 'Paired session state is not initialized.');
    }
    return cloneState(this.cached);
  }

  async loadPendingOutboundFrame(
    mailboxId: string, direction: 'device_to_host', epoch: number,
  ): Promise<PendingOutboundFrame | null> {
    this.assertTuple(mailboxId, direction, epoch, 'device_to_host');
    return cloneValue((await this.read()).pendingOutbound);
  }

  async persistPendingOutboundFrame(
    mailboxId: string,
    direction: 'device_to_host',
    epoch: number,
    pending: PendingOutboundFrame,
  ): Promise<void> {
    this.assertTuple(mailboxId, direction, epoch, 'device_to_host');
    await this.update((state) => {
      if (state.pendingOutbound !== null && canonicalJson(state.pendingOutbound) !== canonicalJson(pending)) {
        throw new RemoteSessionError('PENDING_OUTBOUND_CONFLICT', 'A different outbound frame is already pending.');
      }
      return { state: { ...state, pendingOutbound: cloneValue(pending) }, result: undefined };
    });
  }

  async clearPendingOutboundFrame(
    mailboxId: string,
    direction: 'device_to_host',
    epoch: number,
    sequence: number,
  ): Promise<void> {
    this.assertTuple(mailboxId, direction, epoch, 'device_to_host');
    await this.update((state) => {
      if (state.pendingOutbound?.sequence !== sequence) {
        throw new RemoteSessionError('PENDING_OUTBOUND_CONFLICT', 'Pending outbound sequence changed unexpectedly.');
      }
      const pendingCommand = state.pendingCommand?.status === 'prepared'
        ? { ...state.pendingCommand, status: 'published' as const }
        : state.pendingCommand;
      return { state: { ...state, pendingOutbound: null, pendingCommand }, result: undefined };
    });
  }

  async reserveNextSequence(
    mailboxId: string, direction: 'device_to_host', epoch: number,
  ): Promise<number> {
    this.assertTuple(mailboxId, direction, epoch, 'device_to_host');
    return this.update((state) => {
      const sequence = state.deviceToHostNextSequence;
      if (!safePositive(sequence) || sequence === Number.MAX_SAFE_INTEGER) {
        throw new RemoteSessionError('INVALID_DURABLE_STATE', 'Device sequence state is invalid.');
      }
      return {
        state: { ...state, deviceToHostNextSequence: sequence + 1 },
        result: sequence,
      };
    });
  }

  async loadAppliedThroughSequence(
    mailboxId: string, direction: 'host_to_device', epoch: number,
  ): Promise<number> {
    this.assertTuple(mailboxId, direction, epoch, 'host_to_device');
    return (await this.read()).hostToDeviceAppliedThroughSequence;
  }

  async loadPendingAppliedBatch(
    mailboxId: string, direction: 'host_to_device', epoch: number,
  ): Promise<PersistedAppliedBatch | null> {
    this.assertTuple(mailboxId, direction, epoch, 'host_to_device');
    return cloneValue((await this.read()).pendingAppliedBatch);
  }

  async persistAppliedHostBatch(
    mailboxId: string,
    direction: 'host_to_device',
    epoch: number,
    batch: PersistedAppliedBatch,
  ): Promise<void> {
    this.assertTuple(mailboxId, direction, epoch, 'host_to_device');
    await this.update((state) => {
      if (batch.appliedThroughSequence < state.hostToDeviceAppliedThroughSequence) {
        throw new RemoteSessionError('INVALID_DURABLE_STATE', 'Host cursor cannot move backwards.');
      }
      let accepted = state;
      for (const entry of batch.envelopes) {
        if (!isRemoteApplicationEnvelope(entry.envelope)) {
          throw new RemoteSessionError('INVALID_HOST_ENVELOPE', 'Decoded Host envelope is incompatible.');
        }
        accepted = applyHostEnvelopeToState(accepted, entry.envelope);
      }
      if (accepted.revoked) {
        accepted = { ...accepted, pendingOutbound: null };
      }
      return {
        state: {
          ...accepted,
          hostToDeviceAppliedThroughSequence: batch.appliedThroughSequence,
          pendingAppliedBatch: cloneValue(batch),
        },
        result: undefined,
      };
    });
  }

  async clearPendingAppliedBatch(
    mailboxId: string,
    direction: 'host_to_device',
    epoch: number,
    appliedThroughSequence: number,
  ): Promise<void> {
    this.assertTuple(mailboxId, direction, epoch, 'host_to_device');
    await this.update((state) => {
      if (state.pendingAppliedBatch?.appliedThroughSequence !== appliedThroughSequence) {
        throw new RemoteSessionError('INVALID_DURABLE_STATE', 'Pending applied cursor changed unexpectedly.');
      }
      return { state: { ...state, pendingAppliedBatch: null }, result: undefined };
    });
  }

  async setPendingCommand(pending: RemotePendingCommand): Promise<void> {
    await this.update((state) => {
      if (state.pendingCommand !== null) {
        throw new RemoteSessionError('COMMAND_ALREADY_PENDING', 'A remote command is already pending.');
      }
      return { state: { ...state, pendingCommand: { ...pending } }, result: undefined };
    });
  }

  async setPendingCommandStatus(status: RemotePendingCommandStatus): Promise<void> {
    await this.update((state) => {
      if (state.pendingCommand === null) {
        throw new RemoteSessionError('PENDING_COMMAND_MISSING', 'No remote command is pending.');
      }
      return {
        state: { ...state, pendingCommand: { ...state.pendingCommand, status } },
        result: undefined,
      };
    });
  }

  async applyHostEnvelope(envelope: RemoteApplicationEnvelope): Promise<void> {
    await this.update((state) => ({
      state: applyHostEnvelopeToState(state, envelope),
      result: undefined,
    }));
  }

  async markRevoked(): Promise<void> {
    await this.update((state) => ({ state: { ...state, revoked: true }, result: undefined }));
  }

  private async read(): Promise<PairedSessionDurableState> {
    const loaded = await this.store.load(this.key);
    if (loaded === null) {
      return this.initialize();
    }
    validateDurableState(loaded);
    this.cached = cloneState(loaded);
    return loaded;
  }

  private assertTuple(
    mailboxId: string,
    direction: 'host_to_device' | 'device_to_host',
    epoch: number,
    expectedDirection: 'host_to_device' | 'device_to_host',
  ): void {
    if (mailboxId !== this.key.mailboxId || epoch !== this.key.epoch || direction !== expectedDirection) {
      throw new RemoteSessionError('STATE_TUPLE_MISMATCH', 'Durable state access is outside the paired mailbox tuple.');
    }
  }

  private async update<T>(
    mutator: (state: PairedSessionDurableState) => { state: PairedSessionDurableState; result: T },
  ): Promise<T> {
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
      const loaded = await this.store.load(this.key);
      const current = loaded ?? initialState(this.seed);
      validateDurableState(current);
      const { state, result } = mutator(cloneState(current));
      const next = { ...state, revision: loaded === null ? 0 : loaded.revision + 1 };
      validateDurableState(next);
      if (await this.store.compareAndSwap(this.key, loaded?.revision ?? null, next)) {
        this.cached = cloneState(next);
        return result;
      }
    }
    throw new RemoteSessionError('STATE_CONTENTION', 'Paired session state could not be updated atomically.');
  }
}

export async function restoreRemoteSessionPort(
  options: RestoreRemoteSessionPortOptions,
): Promise<RemoteSessionPort> {
  let session: BrowserVaultSession;
  try {
    session = await options.vault.restorePairedDevice();
  } catch (error) {
    if (error instanceof BrowserVaultError
        && (error.code === 'BROWSER_VAULT_KEY_LOST' || error.code === 'WRAPPED_BEARER_INVALID')) {
      throw new RemoteSessionError('KEY_LOST', 'Secure browser device keys were lost; re-pairing is required.');
    }
    throw new RemoteSessionError('VAULT_RESTORE_FAILED', 'Paired browser state could not be restored.');
  }
  return createRemoteSessionPort({
    ...options,
    session,
    stateStore: options.stateStore ?? createBrowserVaultPairedSessionStateStore(options.vault),
  });
}

export async function createRemoteSessionPort(
  options: CreateRemoteSessionPortOptions,
): Promise<RemoteSessionPort> {
  const stateStore = options.stateStore
    ?? (options.vault === undefined ? undefined : createBrowserVaultPairedSessionStateStore(options.vault));
  if (stateStore === undefined) {
    throw new RemoteSessionError(
      'PAIRED_SESSION_STORE_REQUIRED',
      'Paired sessions require an atomic durable state store.',
    );
  }
  validateVaultSessionKeys(options.session);
  const adapter = new PairedSessionDurableAdapter(
    stateStore,
    { mailboxId: options.session.bundle.mailbox_id, epoch: options.session.bundle.pairing_epoch },
    {
      appliedThrough: options.session.transport.host_to_device_applied_through_sequence,
      nextSequence: options.session.transport.device_to_host_next_sequence,
    },
  );
  await adapter.initialize();
  const runtime = await PairedRemoteSession.create(options, adapter);
  return runtime;
}

class PairedRemoteSession implements RemoteSessionPort {
  private readonly listeners = new Set<(snapshot: RemoteSessionSnapshot) => void>();
  private connection: RemoteSessionConnection;
  private errorCode: string | null = null;
  private operation: Promise<void> = Promise.resolve();

  private constructor(
    private readonly options: CreateRemoteSessionPortOptions,
    private readonly state: PairedSessionDurableAdapter,
    private readonly endpoint: DeviceEndpoint,
    private readonly relayGuard: RevocationAwareRelay,
    private readonly keyGuard: KeyLossAwareCodec,
  ) {
    this.connection = state.snapshot().revoked ? 'revoked' : 'reconnecting';
  }

  static async create(
    options: CreateRemoteSessionPortOptions,
    state: PairedSessionDurableAdapter,
  ): Promise<PairedRemoteSession> {
    const relay = new DeviceRelayClient({
      baseUrl: options.session.bundle.relay_base_url,
      bearerToken: options.session.deviceBearer,
      allowLoopbackHttp: options.allowLoopbackHttp,
      fetchImpl: options.fetchImpl,
    });
    const relayGuard = new RevocationAwareRelay(relay);
    const keyGuard = await buildCodec(options);
    const endpoint = new DeviceEndpoint({
      mailboxId: options.session.bundle.mailbox_id,
      epoch: options.session.bundle.pairing_epoch,
      relay: relayGuard,
      state,
      codec: keyGuard,
    });
    return new PairedRemoteSession(options, state, endpoint, relayGuard, keyGuard);
  }

  getSnapshot(): RemoteSessionSnapshot {
    const durable = this.state.snapshot();
    const projection = durable.lastGoodProjection?.payload ?? null;
    const actions: Array<'view' | 'reply' | 'deny' | 'stop'> =
      durable.revoked || this.connection === 'key_lost' ? [] : ['view'];
    if (this.connection === 'live' && durable.pendingCommand === null && projection !== null
        && projection.capability !== null) {
      if (projection.capability.reply !== null) actions.push('reply');
      if (projection.capability.deny !== null) actions.push('deny');
      if (projection.capability.stop !== null) actions.push('stop');
    }
    return {
      connection: durable.revoked ? 'revoked' : this.connection,
      last_good_projection: cloneValue(projection),
      last_receipt: cloneValue(durable.lastReceipt),
      pending_command: cloneValue(durable.pendingCommand),
      available_actions: actions,
      error_code: this.errorCode,
    };
  }

  subscribe(listener: (snapshot: RemoteSessionSnapshot) => void): () => void {
    this.listeners.add(listener);
    listener(this.getSnapshot());
    return () => this.listeners.delete(listener);
  }

  async poll(): Promise<RemoteSessionSnapshot> {
    return this.serial(async () => {
      this.requireActive();
      try {
        await this.endpoint.receiveHostEnvelopes();
        if (this.state.snapshot().revoked) {
          this.connection = 'revoked';
          this.errorCode = 'DEVICE_REVOKED';
        } else {
          this.connection = 'live';
          this.errorCode = null;
        }
      } catch (error) {
        await this.handleRuntimeFailure(error);
        throw this.publicError(error);
      } finally {
        this.notify();
      }
      return this.getSnapshot();
    });
  }

  async dispatch(intent: RemoteSessionIntent | unknown): Promise<RemoteSessionSnapshot> {
    const decoded = decodeIntent(intent);
    if (decoded.action === 'view') {
      return this.poll();
    }
    return this.serial(async () => {
      this.requireActive();
      const durable = this.state.snapshot();
      if (durable.pendingCommand !== null) {
        const code = durable.pendingCommand.status === 'OutcomeUnknown'
          ? 'OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION'
          : 'COMMAND_ALREADY_PENDING';
        throw new RemoteSessionError(code, 'A new request cannot replace the existing remote request.');
      }
      const projection = durable.lastGoodProjection?.payload ?? null;
      const command = buildGatewayCommand(
        projection,
        decoded,
        this.options.now ?? (() => new Date()),
        this.options.randomBytes ?? secureRandomBytes,
      );
      await this.state.setPendingCommand({
        request_id: command.request_id,
        action: command.action,
        command_seq: command.command_seq,
        snapshot_seq: command.expected_snapshot_seq,
        snapshot_digest: command.expected_snapshot_digest,
        status: 'prepared',
      });
      try {
        await this.endpoint.publishDeviceEnvelope({ command });
        this.connection = 'live';
        this.errorCode = null;
      } catch (error) {
        await this.handleRuntimeFailure(error);
        throw this.publicError(error);
      } finally {
        this.notify();
      }
      return this.getSnapshot();
    });
  }

  async retryPending(): Promise<RemoteSessionSnapshot> {
    return this.serial(async () => {
      this.requireActive();
      const durable = this.state.snapshot();
      if (durable.pendingCommand === null || durable.pendingOutbound === null) {
        throw new RemoteSessionError('EXACT_RETRY_UNAVAILABLE', 'No exact encrypted outbound frame is pending.');
      }
      if (durable.pendingCommand.status === 'OutcomeUnknown') {
        throw new RemoteSessionError(
          'OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION',
          'OutcomeUnknown is never retried automatically or with a replacement request.',
        );
      }
      try {
        await this.endpoint.retryPendingOutbound();
        this.connection = 'live';
        this.errorCode = null;
      } catch (error) {
        await this.handleRuntimeFailure(error);
        throw this.publicError(error);
      } finally {
        this.notify();
      }
      return this.getSnapshot();
    });
  }

  private requireActive(): void {
    if (this.state.snapshot().revoked || this.connection === 'revoked') {
      throw new RemoteSessionError('DEVICE_REVOKED', 'This paired browser has been revoked.');
    }
    if (this.connection === 'key_lost') {
      throw new RemoteSessionError('KEY_LOST', 'Secure browser device keys were lost; re-pairing is required.');
    }
  }

  private async handleRuntimeFailure(error: unknown): Promise<void> {
    if (this.relayGuard.revoked) {
      await this.state.markRevoked();
      this.connection = 'revoked';
      this.errorCode = 'DEVICE_REVOKED';
      return;
    }
    if (this.keyGuard.keyLost || isKeyOperationFailure(error)) {
      this.connection = 'key_lost';
      this.errorCode = 'KEY_LOST';
      return;
    }
    this.connection = 'reconnecting';
    this.errorCode = errorCode(error);
  }

  private publicError(error: unknown): RemoteSessionError {
    if (this.connection === 'revoked') {
      return new RemoteSessionError('DEVICE_REVOKED', 'This paired browser has been revoked.');
    }
    if (this.connection === 'key_lost') {
      return new RemoteSessionError('KEY_LOST', 'Secure browser device keys were lost; re-pairing is required.');
    }
    return error instanceof RemoteSessionError
      ? error
      : new RemoteSessionError(errorCode(error), 'Remote session operation failed closed.');
  }

  private notify(): void {
    const snapshot = this.getSnapshot();
    for (const listener of this.listeners) listener(snapshot);
  }

  private async serial<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operation;
    let release: () => void = () => {};
    this.operation = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

class RevocationAwareRelay implements DeviceRelayTransport {
  revoked = false;

  constructor(private readonly relay: DeviceRelayTransport) {}

  publishDeviceFrame(frame: RemoteOpaqueFrame) {
    return this.guard(() => this.relay.publishDeviceFrame(frame));
  }

  readHostFrames(mailboxId: string, afterSequence: number) {
    return this.guard(() => this.relay.readHostFrames(mailboxId, afterSequence));
  }

  ackHostFrames(mailboxId: string, epoch: number, ackedThroughSequence: number) {
    return this.guard(() => this.relay.ackHostFrames(mailboxId, epoch, ackedThroughSequence));
  }

  private async guard<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof DeviceRelayClientError && (error.status === 401 || error.status === 410)) {
        this.revoked = true;
      }
      throw error;
    }
  }
}

async function buildCodec(
  options: CreateRemoteSessionPortOptions,
): Promise<KeyLossAwareCodec> {
  const session = options.session;
  const deviceSigningSec1 = await exportPublicKeySec1(session.deviceSigningKeyPair.publicKey);
  const deviceAgreementSec1 = await exportPublicKeySec1(session.deviceAgreementKeyPair.publicKey);
  const hostSigningSec1 = decodeBase64Url(session.bundle.host_signing_public_key_sec1);
  const hostAgreementSec1 = decodeBase64Url(session.bundle.host_agreement_public_key_sec1);
  const hostAgreementPublicKey = await importAgreementPublicKeySec1(hostAgreementSec1);
  const context: RemoteSharedContext = {
    mailboxId: session.bundle.mailbox_id,
    epoch: session.bundle.pairing_epoch,
    hostSigningCommitment: await computeKeyCommitment(hostSigningSec1),
    hostAgreementCommitment: await computeKeyCommitment(hostAgreementSec1),
    deviceSigningCommitment: await computeKeyCommitment(deviceSigningSec1),
    deviceAgreementCommitment: await computeKeyCommitment(deviceAgreementSec1),
  };
  const now = options.now ?? (() => new Date());
  const randomBytes = options.randomBytes ?? secureRandomBytes;

  const codec: KeyLossAwareCodec = {
    keyLost: false,
    encryptDeviceEnvelope: async ({ mailboxId, epoch, sequence, envelope }) => {
      try {
        const command = decodeOutboundCommand(envelope);
        const issuedAt = epochSeconds(now());
        const frame: RemoteFrameMetadata = {
          schema: FRAME_SCHEMA,
          crypto_suite: FRAME_SUITE,
          mailbox_id: mailboxId,
          direction: 'device_to_host',
          epoch,
          sequence,
          message_id: `msg-${hex(randomBytes(16), 16)}`,
          issued_at: issuedAt,
          expires_at: issuedAt + FRAME_TTL_SECONDS,
          nonce: toBase64Url(await deriveDeterministicNonceAsync('device_to_host', sequence)),
        };
        const applicationEnvelope = {
          schema: APPLICATION_ENVELOPE_SCHEMA,
          kind: 'command',
          mailbox_id: mailboxId,
          direction: 'device_to_host',
          epoch,
          sequence,
          message_id: frame.message_id,
          payload: { schema: COMMAND_PAYLOAD_SCHEMA, command },
        };
        const encrypted = await encryptRemoteFrame({
          frame,
          plaintext: applicationEnvelope,
          senderSigningPrivateKey: session.deviceSigningKeyPair.privateKey,
          senderSigningPublicKeySec1: deviceSigningSec1,
          senderAgreementPrivateKey: session.deviceAgreementKeyPair.privateKey,
          senderAgreementPublicKeySec1: deviceAgreementSec1,
          recipientAgreementPublicKey: hostAgreementPublicKey,
          context,
        });
        await parseRemoteApplicationEnvelope(encrypted.canonicalPlaintextJson, frame);
        return encrypted.frame;
      } catch (error) {
        if (isKeyOperationFailure(error)) codec.keyLost = true;
        throw error;
      }
    },
    decryptHostEnvelope: async (frame) => {
      try {
        const decrypted = await decryptRemoteFrame({
          frame,
          recipientAgreementPrivateKey: session.deviceAgreementKeyPair.privateKey,
          context,
          expectedSenderSigningCommitment: context.hostSigningCommitment,
          expectedSenderAgreementCommitment: context.hostAgreementCommitment,
        });
        return await parseRemoteApplicationEnvelope(
          decrypted.canonicalPlaintextJson,
          frame,
        );
      } catch (error) {
        if (isKeyOperationFailure(error)) codec.keyLost = true;
        throw error;
      }
    },
  };
  return codec;
}

interface KeyLossAwareCodec extends DeviceEnvelopeCodec {
  keyLost: boolean;
}

function buildGatewayCommand(
  projection: RemoteProjectionEnvelope['payload'] | null,
  intent: Exclude<RemoteSessionIntent, { action: 'view' }>,
  now: () => Date,
  randomBytes: (length: number) => Uint8Array,
): GatewayCommandRequest {
  const capability = projection?.capability;
  if (projection === null || capability === null || capability === undefined || capability.allow_once !== false) {
    throw new RemoteSessionError('COMMAND_UNAVAILABLE', 'No current safe command capability is available.');
  }
  const current = now();
  const currentMs = current.getTime();
  if (!Number.isFinite(currentMs)
      || currentMs < Date.parse(capability.issued_at)
      || currentMs >= Date.parse(capability.expires_at)) {
    throw new RemoteSessionError('CAPABILITY_EXPIRED', 'The remote command capability is expired or not yet valid.');
  }
  const issuedAt = wholeSecondUtc(current);
  const common = {
    schema: GATEWAY_COMMAND_SCHEMA as typeof GATEWAY_COMMAND_SCHEMA,
    capability_id: capability.capability_id,
    request_id: `req-${hex(randomBytes(16), 16)}`,
    nonce: `nonce-${hex(randomBytes(16), 16)}`,
    command_seq: capability.next_command_seq,
    expected_snapshot_seq: capability.snapshot_seq,
    expected_snapshot_digest: capability.snapshot_digest,
    issued_at: issuedAt,
    expires_at: capability.expires_at,
  };
  if (intent.action === 'reply') {
    if (capability.reply === null || intent.content.trim().length === 0
        || encoder.encode(intent.content).byteLength > MAX_REPLY_BYTES) {
      throw new RemoteSessionError('COMMAND_UNAVAILABLE', 'Reply is not available for the last good projection.');
    }
    return {
      ...common,
      action: 'reply',
      turn_alias: capability.reply.turn_alias,
      input_alias: capability.reply.input_alias,
      content: intent.content,
    };
  }
  if (intent.action === 'deny') {
    if (capability.deny === null) {
      throw new RemoteSessionError('COMMAND_UNAVAILABLE', 'Deny is not available for the last good projection.');
    }
    return {
      ...common,
      action: 'deny',
      permission_alias: capability.deny.permission_alias,
      action_hash: capability.deny.action_hash,
      permission_expires_at: capability.deny.expires_at,
    };
  }
  if (capability.stop === null) {
    throw new RemoteSessionError('COMMAND_UNAVAILABLE', 'Stop is not available for the last good projection.');
  }
  return { ...common, action: 'stop', turn_alias: capability.stop.turn_alias };
}

function decodeIntent(value: unknown): RemoteSessionIntent {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RemoteSessionError('UNSUPPORTED_ACTION', 'Only view, reply, deny, and Stop are supported.');
  }
  const raw = value as Record<string, unknown>;
  if (raw.action === 'view' && exactKeys(raw, ['action'])) return { action: 'view' };
  if (raw.action === 'reply' && exactKeys(raw, ['action', 'content']) && typeof raw.content === 'string') {
    return { action: 'reply', content: raw.content };
  }
  if (raw.action === 'deny' && exactKeys(raw, ['action'])) return { action: 'deny' };
  if (raw.action === 'stop' && exactKeys(raw, ['action'])) return { action: 'stop' };
  throw new RemoteSessionError('UNSUPPORTED_ACTION', 'Only view, reply, deny, and Stop are supported.');
}

function decodeOutboundCommand(value: unknown): GatewayCommandRequest {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || !exactKeys(value as Record<string, unknown>, ['command'])) {
    throw new RemoteSessionError('INVALID_OUTBOUND_COMMAND', 'Outbound command wrapper is invalid.');
  }
  const command = (value as { command: GatewayCommandRequest }).command;
  if (command?.schema !== GATEWAY_COMMAND_SCHEMA
      || (command.action !== 'reply' && command.action !== 'deny' && command.action !== 'stop')) {
    throw new RemoteSessionError('INVALID_OUTBOUND_COMMAND', 'Outbound action is invalid.');
  }
  return command;
}

function initialState(seed: { appliedThrough: number; nextSequence: number }): PairedSessionDurableState {
  return {
    schema: DURABLE_STATE_SCHEMA,
    revision: 0,
    hostToDeviceAppliedThroughSequence: seed.appliedThrough,
    deviceToHostNextSequence: seed.nextSequence,
    pendingOutbound: null,
    pendingAppliedBatch: null,
    lastGoodProjection: null,
    lastReceipt: null,
    pendingCommand: null,
    revoked: false,
  };
}

function validateDurableState(state: PairedSessionDurableState): void {
  if (state.schema !== DURABLE_STATE_SCHEMA
      || !Number.isSafeInteger(state.revision) || state.revision < 0
      || !Number.isSafeInteger(state.hostToDeviceAppliedThroughSequence)
      || state.hostToDeviceAppliedThroughSequence < 0
      || !safePositive(state.deviceToHostNextSequence)
      || typeof state.revoked !== 'boolean') {
    throw new RemoteSessionError('INVALID_DURABLE_STATE', 'Paired session durable state is invalid.');
  }
  if (state.pendingCommand !== null) {
    const pending = state.pendingCommand;
    const statuses: ReadonlyArray<RemotePendingCommandStatus> = [
      'prepared', 'published', 'HostAccepted', 'Dispatching', 'DispatchAcknowledged',
      'Rejected', 'Stale', 'Expired', 'OutcomeUnknown',
    ];
    if (!/^req-[0-9a-f]{32}$/.test(pending.request_id)
        || !['reply', 'deny', 'stop'].includes(pending.action)
        || !safePositive(pending.command_seq)
        || !safePositive(pending.snapshot_seq)
        || !/^sha256:[0-9a-f]{64}$/.test(pending.snapshot_digest)
        || !statuses.includes(pending.status)) {
      throw new RemoteSessionError('INVALID_DURABLE_STATE', 'Pending command state is invalid.');
    }
  }
}

function isRemoteApplicationEnvelope(value: unknown): value is RemoteApplicationEnvelope {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const envelope = value as Partial<RemoteApplicationEnvelope>;
  return envelope.schema === APPLICATION_ENVELOPE_SCHEMA
    && (envelope.kind === 'projection' || envelope.kind === 'receipt');
}

function applyHostEnvelopeToState(
  state: PairedSessionDurableState,
  envelope: RemoteApplicationEnvelope,
): PairedSessionDurableState {
  if (envelope.kind === 'command') {
    throw new RemoteSessionError('INVALID_HOST_ENVELOPE', 'Host cannot publish a device command envelope.');
  }
  if (envelope.kind === 'projection') {
    const current = state.lastGoodProjection;
    const incoming = envelope.payload.snapshot;
    if (current !== null) {
      const previous = current.payload.snapshot;
      if (previous.host_instance_id !== incoming.host_instance_id) {
        throw new RemoteSessionError('HOST_INSTANCE_CHANGED', 'Host identity changed inside the paired epoch.');
      }
      if (incoming.snapshot_seq < previous.snapshot_seq) return state;
      if (incoming.snapshot_seq === previous.snapshot_seq) {
        if (incoming.digest !== previous.digest) {
          throw new RemoteSessionError('PROJECTION_CONFLICT', 'Same-sequence projection digest changed.');
        }
        return state;
      }
    }
    return { ...state, lastGoodProjection: cloneValue(envelope) };
  }

  const receipt = envelope.payload.receipt;
  const pending = state.pendingCommand;
  if (pending === null) {
    if (state.lastReceipt?.request_id === receipt.request_id
        && canonicalJson(state.lastReceipt) === canonicalJson(receipt)) {
      return state;
    }
    throw new RemoteSessionError('UNBOUND_RECEIPT', 'Host receipt is not bound to the pending request.');
  }
  if (receipt.request_id !== pending.request_id
      || receipt.action !== pending.action
      || receipt.snapshot_seq !== pending.snapshot_seq
      || receipt.snapshot_digest !== pending.snapshot_digest) {
    throw new RemoteSessionError('UNBOUND_RECEIPT', 'Host receipt binding does not match the pending request.');
  }
  if (pending.status === 'OutcomeUnknown' && receipt.status !== 'OutcomeUnknown') {
    throw new RemoteSessionError('OUTCOME_UNKNOWN_FINAL', 'OutcomeUnknown cannot be replaced automatically.');
  }
  const revoked = receipt.status === 'Rejected' && String(receipt.error_code) === 'ERR_REQUEST_REVOKED';
  const terminal = receipt.status === 'DispatchAcknowledged'
    || receipt.status === 'Rejected'
    || receipt.status === 'Stale'
    || receipt.status === 'Expired';
  return {
    ...state,
    lastReceipt: { ...receipt },
    pendingCommand: terminal ? null : { ...pending, status: receipt.status },
    pendingOutbound: terminal ? null : state.pendingOutbound,
    revoked: state.revoked || revoked,
  };
}

function validateVaultSessionKeys(session: BrowserVaultSession): void {
  try {
    validateKey(session.deviceSigningKeyPair.publicKey, 'public', 'ECDSA', 'verify');
    validateKey(session.deviceSigningKeyPair.privateKey, 'private', 'ECDSA', 'sign');
    validateKey(session.deviceAgreementKeyPair.publicKey, 'public', 'ECDH', '');
    validateKey(session.deviceAgreementKeyPair.privateKey, 'private', 'ECDH', 'deriveBits');
    if (session.deviceSigningKeyPair.privateKey.extractable
        || session.deviceAgreementKeyPair.privateKey.extractable) {
      throw new Error('extractable_private_key');
    }
  } catch {
    throw new RemoteSessionError('KEY_LOST', 'Secure browser device keys were lost; re-pairing is required.');
  }
}

function validateKey(
  key: CryptoKey,
  type: KeyType,
  algorithm: string,
  usage: KeyUsage | '',
): void {
  if (!(key instanceof CryptoKey) || key.type !== type || key.algorithm.name !== algorithm
      || (usage !== '' && !key.usages.includes(usage))) {
    throw new Error('invalid_key');
  }
}

function isKeyOperationFailure(error: unknown): boolean {
  if (error instanceof RemoteSessionError && error.code === 'KEY_LOST') return true;
  if (error instanceof DOMException) {
    return error.name === 'InvalidAccessError' || error.name === 'DataError';
  }
  return false;
}

function errorCode(error: unknown): string {
  if (error instanceof RemoteSessionError
      || error instanceof DeviceEndpointError
      || error instanceof DeviceRelayClientError) {
    return error.code;
  }
  return 'REMOTE_SESSION_FAILED';
}

function wholeSecondUtc(value: Date): string {
  return new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString().replace('.000Z', 'Z');
}

function epochSeconds(value: Date): number {
  const result = Math.floor(value.getTime() / 1000);
  if (!safePositive(result)) {
    throw new RemoteSessionError('INVALID_CLOCK', 'Remote session clock is invalid.');
  }
  return result;
}

function secureRandomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function hex(value: Uint8Array, expectedLength: number): string {
  if (!(value instanceof Uint8Array) || value.byteLength !== expectedLength) {
    throw new RemoteSessionError('INVALID_RANDOM_SOURCE', 'Remote session random source is invalid.');
  }
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new RemoteSessionError('KEY_LOST', 'Paired public-key material is invalid.');
  }
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
    const decoded = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    if (toBase64Url(decoded) !== value) throw new Error('noncanonical');
    return decoded;
  } catch {
    throw new RemoteSessionError('KEY_LOST', 'Paired public-key material is invalid.');
  }
}

function toBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function safePositive(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function stateKey(key: PairedSessionStateKey): string {
  return `${key.mailboxId}:device_to_host:${String(key.epoch)}`;
}

function browserVaultStateKey(key: PairedSessionStateKey): string {
  return `${key.mailboxId}:${String(key.epoch)}`;
}

function cloneState(value: PairedSessionDurableState): PairedSessionDurableState {
  return cloneValue(value);
}

function cloneValue<T>(value: T): T {
  return value === null || value === undefined
    ? value
    : JSON.parse(JSON.stringify(value)) as T;
}
