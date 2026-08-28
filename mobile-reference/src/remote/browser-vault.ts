import {
  canonicalJson,
  computeKeyCommitment,
  deriveSharedSecret,
  exportPublicKeySec1,
  importAgreementPublicKeySec1,
  importSigningPublicKeySec1,
} from './crypto';
import type {
  DurableDeviceState,
  PendingOutboundFrame,
  PersistedAppliedBatch,
} from './device-endpoint';

const subtle = globalThis.crypto?.subtle;

if (!subtle) {
  throw new Error('WebCrypto is unavailable in this environment');
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const VAULT_SCHEMA = 'nomad.m3e.browser-vault.v1';
const SIGNED_BUNDLE_SCHEMA = 'nomad.m3e.signed-provisioning-bundle.v1';
const PROVISIONING_BUNDLE_SCHEMA = 'nomad.m3e.provisioning-bundle.v1';
const DEFAULT_DB_NAME = 'nomad-m3e-browser-vault';
const RECORD_STORE = 'records';
const MAILBOX_ID = /^mbx-[0-9a-f]{64}$/;
const OPAQUE = /^[A-Za-z0-9_-]{1,160}$/;
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/;

const STATE_RECORD = 'vault-state';
const SIGNING_PUBLIC_RECORD = 'device-signing-public';
const SIGNING_PRIVATE_RECORD = 'device-signing-private';
const AGREEMENT_PUBLIC_RECORD = 'device-agreement-public';
const AGREEMENT_PRIVATE_RECORD = 'device-agreement-private';
const SIGNING_KEY_BINDING_DOMAIN = 'nomad.m3e.browser-vault.signing-key-binding.v1\n';

export interface BrowserVaultTransportState {
  host_to_device_applied_through_sequence: number;
  device_to_host_next_sequence: number;
}

export interface BrowserVaultNamespaceRecord<T> {
  revision: number;
  value: T;
}

export interface ProvisioningBundle {
  schema: typeof PROVISIONING_BUNDLE_SCHEMA;
  device_alias: string;
  pairing_epoch: number;
  mailbox_id: string;
  relay_base_url: string;
  host_signing_public_key_sec1: string;
  host_agreement_public_key_sec1: string;
  wrapped_device_bearer: string;
  wrap_nonce: string;
  issued_at: string;
}

export interface SignedProvisioningBundle {
  schema: typeof SIGNED_BUNDLE_SCHEMA;
  bundle: ProvisioningBundle;
  provisioning_signature_p1363: string;
}

export interface BrowserVaultComparisonContext {
  comparison_code: string;
  host_signing_commitment: string;
  host_agreement_commitment: string;
  device_signing_commitment: string;
  device_agreement_commitment: string;
}

export interface BrowserVaultPersistInput {
  deviceSigningKeyPair: CryptoKeyPair;
  deviceAgreementKeyPair: CryptoKeyPair;
  signedProvisioningBundle: SignedProvisioningBundle;
  comparisonContext: BrowserVaultComparisonContext;
  transport?: BrowserVaultTransportState;
}

export interface BrowserVaultSession {
  comparisonCode: string;
  bundle: ProvisioningBundle;
  signedProvisioningBundle: SignedProvisioningBundle;
  deviceBearer: string;
  deviceSigningKeyPair: CryptoKeyPair;
  deviceAgreementKeyPair: CryptoKeyPair;
  transport: BrowserVaultTransportState;
}

interface BrowserVaultStateRecord extends BrowserVaultComparisonContext {
  schema: typeof VAULT_SCHEMA;
  signed_provisioning_bundle: SignedProvisioningBundle;
  transport: BrowserVaultTransportState;
}

export interface BrowserVaultDatabase {
  clear(): Promise<void>;
  close(): void;
  delete(key: string): Promise<void>;
  deleteIfSequence(key: string, expectedSequence: number): Promise<void>;
  get<T>(key: string): Promise<T | undefined>;
  loadNamespaceRecord<T>(key: string): Promise<BrowserVaultNamespaceRecord<T> | undefined>;
  reserveSequence(key: string, stateKey: string): Promise<number>;
  put(key: string, value: unknown): Promise<void>;
  putAppliedBatch(
    appliedThroughKey: string,
    pendingBatchKey: string,
    stateKey: string,
    batch: PersistedAppliedBatch,
  ): Promise<void>;
  compareAndSwapNamespaceRecord<T>(
    key: string,
    expectedRevision: number | null,
    nextValue: T,
  ): Promise<boolean>;
}

export interface BrowserVaultOptions {
  databaseFactory?: () => Promise<BrowserVaultDatabase>;
}

export class BrowserVaultError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class BrowserVault implements DurableDeviceState {
  private databasePromise: Promise<BrowserVaultDatabase> | null = null;

  constructor(private readonly options: BrowserVaultOptions = {}) {}

  async persistProvisionedDevice(input: BrowserVaultPersistInput): Promise<BrowserVaultSession> {
    const database = await this.getDatabase();
    const signing = validateKeyPair(input.deviceSigningKeyPair, 'ECDSA', 'sign');
    const agreement = validateKeyPair(input.deviceAgreementKeyPair, 'ECDH', 'deriveBits');
    const signedBundle = decodeSignedProvisioningBundle(input.signedProvisioningBundle);
    const signingPublicKeySec1 = await exportPublicKeySec1(signing.publicKey);
    const agreementPublicKeySec1 = await exportPublicKeySec1(agreement.publicKey);
    const signingCommitment = await computeKeyCommitment(signingPublicKeySec1);
    const agreementCommitment = await computeKeyCommitment(agreementPublicKeySec1);
    const comparisonContext = decodeComparisonContext(input.comparisonContext);

    if (
      comparisonContext.device_signing_commitment !== signingCommitment
      || comparisonContext.device_agreement_commitment !== agreementCommitment
    ) {
      throw new BrowserVaultError(
        'DEVICE_KEY_COMMITMENT_MISMATCH',
        'Browser device keys do not match the confirmed pairing transcript.',
      );
    }

    await verifySignedProvisioningBundle(signedBundle, comparisonContext);

    const state: BrowserVaultStateRecord = {
      schema: VAULT_SCHEMA,
      comparison_code: comparisonContext.comparison_code,
      host_signing_commitment: comparisonContext.host_signing_commitment,
      host_agreement_commitment: comparisonContext.host_agreement_commitment,
      device_signing_commitment: comparisonContext.device_signing_commitment,
      device_agreement_commitment: comparisonContext.device_agreement_commitment,
      signed_provisioning_bundle: signedBundle,
      transport: decodeTransportState(input.transport ?? defaultTransportState()),
    };

    try {
      await database.put(STATE_RECORD, state);
      await database.put(SIGNING_PUBLIC_RECORD, signing.publicKey);
      await database.put(SIGNING_PRIVATE_RECORD, signing.privateKey);
      await database.put(AGREEMENT_PUBLIC_RECORD, agreement.publicKey);
      await database.put(AGREEMENT_PRIVATE_RECORD, agreement.privateKey);
      return await this.restorePairedDevice();
    } catch (error) {
      await this.clear().catch(() => {});
      if (error instanceof BrowserVaultError) {
        throw error;
      }
      throw new BrowserVaultError(
        'BROWSER_VAULT_PERSIST_FAILED',
        'Browser vault persistence failed before restore could be verified.',
      );
    }
  }

  async restorePairedDevice(): Promise<BrowserVaultSession> {
    const database = await this.getDatabase();
    try {
      const state = decodeStateRecord(await database.get<unknown>(STATE_RECORD));
      const signingPublicKey = validateStoredPublicKey(
        await database.get<unknown>(SIGNING_PUBLIC_RECORD),
        'ECDSA',
        'verify',
        'BROWSER_VAULT_KEY_LOST',
      );
      const signingPrivateKey = validateStoredPrivateKey(
        await database.get<unknown>(SIGNING_PRIVATE_RECORD),
        'ECDSA',
        'sign',
        'BROWSER_VAULT_KEY_LOST',
      );
      const agreementPublicKey = validateStoredPublicKey(
        await database.get<unknown>(AGREEMENT_PUBLIC_RECORD),
        'ECDH',
        '',
        'BROWSER_VAULT_KEY_LOST',
      );
      const agreementPrivateKey = validateStoredPrivateKey(
        await database.get<unknown>(AGREEMENT_PRIVATE_RECORD),
        'ECDH',
        'deriveBits',
        'BROWSER_VAULT_KEY_LOST',
      );

      const signingPublicKeySec1 = await exportPublicKeySec1(signingPublicKey);
      const agreementPublicKeySec1 = await exportPublicKeySec1(agreementPublicKey);
      const signingCommitment = await computeKeyCommitment(signingPublicKeySec1);
      const agreementCommitment = await computeKeyCommitment(agreementPublicKeySec1);
      if (
        signingCommitment !== state.device_signing_commitment
        || agreementCommitment !== state.device_agreement_commitment
      ) {
        throw new BrowserVaultError(
          'BROWSER_VAULT_KEY_LOST',
          'Browser vault keys no longer match the paired device identity.',
        );
      }

      await verifyStoredKeyBindings(
        signingPublicKey,
        signingPrivateKey,
        agreementPublicKey,
        agreementPrivateKey,
      );
      await verifySignedProvisioningBundle(state.signed_provisioning_bundle, state);
      const deviceBearer = await unwrapDeviceBearer(
        state.signed_provisioning_bundle.bundle,
        agreementPrivateKey,
      );

      return {
        comparisonCode: state.comparison_code,
        bundle: state.signed_provisioning_bundle.bundle,
        signedProvisioningBundle: state.signed_provisioning_bundle,
        deviceBearer,
        deviceSigningKeyPair: {
          publicKey: signingPublicKey,
          privateKey: signingPrivateKey,
        },
        deviceAgreementKeyPair: {
          publicKey: agreementPublicKey,
          privateKey: agreementPrivateKey,
        },
        transport: state.transport,
      };
    } catch (error) {
      // A partial/corrupt vault must never be treated as a recoverable browser
      // identity. Clear it and require a fresh pairing ceremony.
      await database.clear().catch(() => {});
      if (error instanceof BrowserVaultError) {
        throw error;
      }
      throw new BrowserVaultError(
        'BROWSER_VAULT_RESTORE_FAILED',
        'Browser vault restore failed and requires re-pairing.',
      );
    }
  }

  async updateTransportState(transport: BrowserVaultTransportState): Promise<void> {
    const database = await this.getDatabase();
    const current = decodeStateRecord(await database.get<unknown>(STATE_RECORD));
    const updated: BrowserVaultStateRecord = {
      ...current,
      transport: decodeTransportState(transport),
    };
    await database.put(STATE_RECORD, updated);
  }

  async loadNamespaceRecord<T>(
    namespace: string,
    key: string,
  ): Promise<BrowserVaultNamespaceRecord<T> | null> {
    const database = await this.getDatabase();
    const record = await database.loadNamespaceRecord<T>(namespaceRecordKey(namespace, key));
    if (record === undefined) {
      return null;
    }
    return decodeNamespaceRecord<T>(record);
  }

  async compareAndSwapNamespaceRecord<T>(
    namespace: string,
    key: string,
    expectedRevision: number | null,
    nextValue: T,
  ): Promise<boolean> {
    if (expectedRevision !== null && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)) {
      throw new BrowserVaultError('INVALID_NAMESPACE_RECORD', 'Namespace record revision is invalid.');
    }
    assertStructuredCloneValue(nextValue);
    return (await this.getDatabase()).compareAndSwapNamespaceRecord(
      namespaceRecordKey(namespace, key),
      expectedRevision,
      nextValue,
    );
  }

  async loadPendingOutboundFrame(
    mailboxId: string,
    direction: 'device_to_host',
    epoch: number,
  ): Promise<PendingOutboundFrame | null> {
    return (await this.getDatabase()).get<PendingOutboundFrame>(transportKey(mailboxId, direction, epoch, 'pending-outbound'))
      .then((value) => value ?? null);
  }

  async persistPendingOutboundFrame(
    mailboxId: string,
    direction: 'device_to_host',
    epoch: number,
    pending: PendingOutboundFrame,
  ): Promise<void> {
    await (await this.getDatabase()).put(transportKey(mailboxId, direction, epoch, 'pending-outbound'), pending);
  }

  async clearPendingOutboundFrame(
    mailboxId: string,
    direction: 'device_to_host',
    epoch: number,
    sequence: number,
  ): Promise<void> {
    await (await this.getDatabase()).deleteIfSequence(
      transportKey(mailboxId, direction, epoch, 'pending-outbound'),
      sequence,
    );
  }

  async reserveNextSequence(
    mailboxId: string,
    direction: 'device_to_host',
    epoch: number,
  ): Promise<number> {
    return (await this.getDatabase()).reserveSequence(
      transportKey(mailboxId, direction, epoch, 'next-sequence'),
      STATE_RECORD,
    );
  }

  async loadAppliedThroughSequence(
    mailboxId: string,
    direction: 'host_to_device',
    epoch: number,
  ): Promise<number> {
    const database = await this.getDatabase();
    const tupleValue = await database.get<number>(
      transportKey(mailboxId, direction, epoch, 'applied-through'),
    );
    if (tupleValue !== undefined) {
      return tupleValue;
    }
    const state = decodeStateRecord(await database.get<unknown>(STATE_RECORD));
    return state.transport.host_to_device_applied_through_sequence;
  }

  async loadPendingAppliedBatch(
    mailboxId: string,
    direction: 'host_to_device',
    epoch: number,
  ): Promise<PersistedAppliedBatch | null> {
    return (await this.getDatabase()).get<PersistedAppliedBatch>(
      transportKey(mailboxId, direction, epoch, 'pending-applied'),
    ).then((value) => value ?? null);
  }

  async persistAppliedHostBatch(
    mailboxId: string,
    direction: 'host_to_device',
    epoch: number,
    batch: PersistedAppliedBatch,
  ): Promise<void> {
    await (await this.getDatabase()).putAppliedBatch(
      transportKey(mailboxId, direction, epoch, 'applied-through'),
      transportKey(mailboxId, direction, epoch, 'pending-applied'),
      STATE_RECORD,
      batch,
    );
  }

  async clearPendingAppliedBatch(
    mailboxId: string,
    direction: 'host_to_device',
    epoch: number,
    appliedThroughSequence: number,
  ): Promise<void> {
    await (await this.getDatabase()).deleteIfSequence(
      transportKey(mailboxId, direction, epoch, 'pending-applied'),
      appliedThroughSequence,
    );
  }

  async clear(): Promise<void> {
    const database = await this.getDatabase();
    await database.clear();
  }

  async close(): Promise<void> {
    if (this.databasePromise === null) {
      return;
    }
    const database = await this.databasePromise;
    database.close();
    this.databasePromise = null;
  }

  private async getDatabase(): Promise<BrowserVaultDatabase> {
    if (this.databasePromise === null) {
      const factory = this.options.databaseFactory ?? (() => openBrowserVaultDatabase());
      this.databasePromise = factory().catch(() => {
        throw new BrowserVaultError(
          'BROWSER_VAULT_UNAVAILABLE',
          'Browser vault storage is unavailable in this environment.',
        );
      });
    }
    return this.databasePromise;
  }
}

export async function openBrowserVaultDatabase(
  dbName = DEFAULT_DB_NAME,
  indexedDbFactory: IDBFactory | undefined = globalThis.indexedDB,
): Promise<BrowserVaultDatabase> {
  if (indexedDbFactory === undefined) {
    throw new BrowserVaultError(
      'BROWSER_VAULT_UNAVAILABLE',
      'IndexedDB is unavailable in this browser.',
    );
  }
  const database = await openIndexedDb(dbName, indexedDbFactory);
  return {
    clear: () => runTransaction(database, 'readwrite', (store) => promisifyRequest(store.clear())),
    close: () => database.close(),
    delete: (key) => runTransaction(database, 'readwrite', (store) => promisifyRequest(store.delete(key))),
    deleteIfSequence: (key, expectedSequence) => runTransaction(database, 'readwrite', async (store) => {
      const current = await promisifyRequest(store.get(key)) as { sequence?: unknown; appliedThroughSequence?: unknown } | undefined;
      const currentSequence = current?.sequence ?? current?.appliedThroughSequence;
      if (currentSequence === expectedSequence) {
        await promisifyRequest(store.delete(key));
      }
    }),
    get: <T>(key: string) => runTransaction(database, 'readonly', async (store) => {
      const result = await promisifyRequest(store.get(key));
      return result as T | undefined;
    }),
    loadNamespaceRecord: <T>(key: string) => runTransaction(database, 'readonly', async (store) => {
      const result = await promisifyRequest(store.get(key));
      return result as BrowserVaultNamespaceRecord<T> | undefined;
    }),
    put: (key, value) => runTransaction(database, 'readwrite', async (store) => {
      await promisifyRequest(store.put(value, key));
    }),
    reserveSequence: (key, stateKey) => runTransaction(database, 'readwrite', async (store) => {
      const current = await promisifyRequest(store.get(key));
      const state = decodeStateRecord(await promisifyRequest(store.get(stateKey)));
      const reserved = current === undefined
        ? state.transport.device_to_host_next_sequence
        : decodePositiveSequence(current);
      await promisifyRequest(store.put(reserved + 1, key));
      await promisifyRequest(store.put({
        ...state,
        transport: {
          ...state.transport,
          device_to_host_next_sequence: reserved + 1,
        },
      }, stateKey));
      return reserved;
    }),
    putAppliedBatch: (appliedThroughKey, pendingBatchKey, stateKey, batch) => runTransaction(
      database,
      'readwrite',
      async (store) => {
        const state = decodeStateRecord(await promisifyRequest(store.get(stateKey)));
        await promisifyRequest(store.put(batch.appliedThroughSequence, appliedThroughKey));
        await promisifyRequest(store.put(batch, pendingBatchKey));
        await promisifyRequest(store.put({
          ...state,
          transport: {
            ...state.transport,
            host_to_device_applied_through_sequence: batch.appliedThroughSequence,
          },
        }, stateKey));
      },
    ),
    compareAndSwapNamespaceRecord: <T>(key: string, expectedRevision: number | null, nextValue: T) => runTransaction(
      database,
      'readwrite',
      async (store) => {
        const currentValue = await promisifyRequest(store.get(key));
        const current = currentValue === undefined
          ? null
          : decodeNamespaceRecord<unknown>(currentValue);
        if (expectedRevision === null ? current !== null : current?.revision !== expectedRevision) {
          return false;
        }
        const next: BrowserVaultNamespaceRecord<T> = {
          revision: current === null ? 0 : current.revision + 1,
          value: nextValue,
        };
        await promisifyRequest(store.put(next, key));
        return true;
      },
    ),
  };
}

function defaultTransportState(): BrowserVaultTransportState {
  return {
    host_to_device_applied_through_sequence: 0,
    device_to_host_next_sequence: 1,
  };
}

function transportKey(
  mailboxId: string,
  direction: 'host_to_device' | 'device_to_host',
  epoch: number,
  kind: string,
): string {
  if (!MAILBOX_ID.test(mailboxId) || !Number.isSafeInteger(epoch) || epoch < 1) {
    throw new BrowserVaultError('INVALID_TRANSPORT_STATE', 'Transport tuple is invalid.');
  }
  return `transport:${mailboxId}:${direction}:${String(epoch)}:${kind}`;
}

function decodePositiveSequence(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new BrowserVaultError('INVALID_TRANSPORT_STATE', 'Transport sequence is invalid.');
  }
  return value;
}

function namespaceRecordKey(namespace: string, key: string): string {
  if (!/^[a-z][a-z0-9.-]{0,63}$/.test(namespace) || !/^[A-Za-z0-9:_-]{1,384}$/.test(key)) {
    throw new BrowserVaultError('INVALID_NAMESPACE_RECORD', 'Namespace record key is invalid.');
  }
  return `namespace:${namespace}:${key}`;
}

function decodeNamespaceRecord<T>(value: unknown): BrowserVaultNamespaceRecord<T> {
  const raw = exactObject(value, ['revision', 'value'], 'INVALID_NAMESPACE_RECORD');
  if (typeof raw.revision !== 'number' || !Number.isSafeInteger(raw.revision) || raw.revision < 0) {
    throw new BrowserVaultError('INVALID_NAMESPACE_RECORD', 'Namespace record revision is invalid.');
  }
  assertStructuredCloneValue(raw.value);
  return { revision: raw.revision, value: raw.value as T };
}

function assertStructuredCloneValue(value: unknown): void {
  if (value === undefined) {
    throw new BrowserVaultError('INVALID_NAMESPACE_RECORD', 'Namespace record value is invalid.');
  }
  try {
    structuredClone(value);
  } catch {
    throw new BrowserVaultError('INVALID_NAMESPACE_RECORD', 'Namespace record value is not cloneable.');
  }
}

export function decodeSignedProvisioningBundle(value: unknown): SignedProvisioningBundle {
  const raw = exactObject(value, ['schema', 'bundle', 'provisioning_signature_p1363'], 'INVALID_PROVISIONING_BUNDLE');
  if (raw.schema !== SIGNED_BUNDLE_SCHEMA) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning bundle schema is incompatible.');
  }
  if (!isBase64Url(raw.provisioning_signature_p1363)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning signature encoding is invalid.');
  }
  const signatureBytes = fromBase64Url(raw.provisioning_signature_p1363, 'INVALID_PROVISIONING_BUNDLE');
  if (signatureBytes.byteLength !== 64) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning signature length is invalid.');
  }
  return {
    schema: SIGNED_BUNDLE_SCHEMA,
    bundle: decodeProvisioningBundle(raw.bundle),
    provisioning_signature_p1363: raw.provisioning_signature_p1363,
  };
}

function decodeProvisioningBundle(value: unknown): ProvisioningBundle {
  const raw = exactObject(
    value,
    [
      'schema',
      'device_alias',
      'pairing_epoch',
      'mailbox_id',
      'relay_base_url',
      'host_signing_public_key_sec1',
      'host_agreement_public_key_sec1',
      'wrapped_device_bearer',
      'wrap_nonce',
      'issued_at',
    ],
    'INVALID_PROVISIONING_BUNDLE',
  );
  if (raw.schema !== PROVISIONING_BUNDLE_SCHEMA) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning bundle schema is incompatible.');
  }
  if (typeof raw.device_alias !== 'string' || !OPAQUE.test(raw.device_alias)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Device alias is invalid.');
  }
  if (typeof raw.mailbox_id !== 'string' || !MAILBOX_ID.test(raw.mailbox_id)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning mailbox is invalid.');
  }
  if (typeof raw.pairing_epoch !== 'number' || !Number.isSafeInteger(raw.pairing_epoch) || raw.pairing_epoch < 1) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning epoch is invalid.');
  }
  validateRelayBaseUrl(raw.relay_base_url);
  ensureExactSec1Base64Url(raw.host_signing_public_key_sec1, 'INVALID_PROVISIONING_BUNDLE');
  ensureExactSec1Base64Url(raw.host_agreement_public_key_sec1, 'INVALID_PROVISIONING_BUNDLE');
  if (!isBase64Url(raw.wrapped_device_bearer)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Wrapped bearer encoding is invalid.');
  }
  const wrappedDeviceBearer = fromBase64Url(raw.wrapped_device_bearer, 'INVALID_PROVISIONING_BUNDLE');
  if (wrappedDeviceBearer.byteLength < 17 || wrappedDeviceBearer.byteLength > 8192) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Wrapped bearer length is invalid.');
  }
  if (!isBase64Url(raw.wrap_nonce)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Wrap nonce encoding is invalid.');
  }
  const wrapNonce = fromBase64Url(raw.wrap_nonce, 'INVALID_PROVISIONING_BUNDLE');
  if (wrapNonce.byteLength !== 12) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Wrap nonce length is invalid.');
  }
  if (!isCanonicalUtcTimestamp(raw.issued_at)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Provisioning timestamp is invalid.');
  }
  return {
    schema: PROVISIONING_BUNDLE_SCHEMA,
    device_alias: raw.device_alias as string,
    pairing_epoch: raw.pairing_epoch as number,
    mailbox_id: raw.mailbox_id as string,
    relay_base_url: raw.relay_base_url as string,
    host_signing_public_key_sec1: raw.host_signing_public_key_sec1 as string,
    host_agreement_public_key_sec1: raw.host_agreement_public_key_sec1 as string,
    wrapped_device_bearer: raw.wrapped_device_bearer as string,
    wrap_nonce: raw.wrap_nonce as string,
    issued_at: raw.issued_at as string,
  };
}

function decodeComparisonContext(value: unknown): BrowserVaultComparisonContext {
  const raw = exactObject(
    value,
    [
      'comparison_code',
      'host_signing_commitment',
      'host_agreement_commitment',
      'device_signing_commitment',
      'device_agreement_commitment',
    ],
    'INVALID_PROVISIONING_BUNDLE',
  );
  if (typeof raw.comparison_code !== 'string' || !/^[0-9]{6}$/.test(raw.comparison_code)) {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Comparison code is invalid.');
  }
  for (const field of [
    raw.host_signing_commitment,
    raw.host_agreement_commitment,
    raw.device_signing_commitment,
    raw.device_agreement_commitment,
  ]) {
    if (typeof field !== 'string' || !/^[0-9a-f]{64}$/.test(field)) {
      throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Pairing commitments are invalid.');
    }
  }
  return {
    comparison_code: raw.comparison_code as string,
    host_signing_commitment: raw.host_signing_commitment as string,
    host_agreement_commitment: raw.host_agreement_commitment as string,
    device_signing_commitment: raw.device_signing_commitment as string,
    device_agreement_commitment: raw.device_agreement_commitment as string,
  };
}

function decodeStateRecord(value: unknown): BrowserVaultStateRecord {
  const raw = exactObject(
    value,
    [
      'schema',
      'comparison_code',
      'host_signing_commitment',
      'host_agreement_commitment',
      'device_signing_commitment',
      'device_agreement_commitment',
      'signed_provisioning_bundle',
      'transport',
    ],
    'BROWSER_VAULT_EMPTY',
  );
  if (raw.schema !== VAULT_SCHEMA) {
    throw new BrowserVaultError('BROWSER_VAULT_EMPTY', 'Browser vault state is missing or incompatible.');
  }
  const comparisonContext = decodeComparisonContext({
    comparison_code: raw.comparison_code,
    host_signing_commitment: raw.host_signing_commitment,
    host_agreement_commitment: raw.host_agreement_commitment,
    device_signing_commitment: raw.device_signing_commitment,
    device_agreement_commitment: raw.device_agreement_commitment,
  });
  return {
    schema: VAULT_SCHEMA,
    ...comparisonContext,
    signed_provisioning_bundle: decodeSignedProvisioningBundle(raw.signed_provisioning_bundle),
    transport: decodeTransportState(raw.transport),
  };
}

function decodeTransportState(value: unknown): BrowserVaultTransportState {
  const raw = exactObject(
    value,
    ['host_to_device_applied_through_sequence', 'device_to_host_next_sequence'],
    'INVALID_TRANSPORT_STATE',
  );
  if (
    typeof raw.host_to_device_applied_through_sequence !== 'number'
    || !Number.isSafeInteger(raw.host_to_device_applied_through_sequence)
    || raw.host_to_device_applied_through_sequence < 0
  ) {
    throw new BrowserVaultError('INVALID_TRANSPORT_STATE', 'Host-to-device cursor is invalid.');
  }
  if (
    typeof raw.device_to_host_next_sequence !== 'number'
    || !Number.isSafeInteger(raw.device_to_host_next_sequence)
    || raw.device_to_host_next_sequence < 1
  ) {
    throw new BrowserVaultError('INVALID_TRANSPORT_STATE', 'Device-to-host cursor is invalid.');
  }
  return {
    host_to_device_applied_through_sequence: raw.host_to_device_applied_through_sequence as number,
    device_to_host_next_sequence: raw.device_to_host_next_sequence as number,
  };
}

async function verifySignedProvisioningBundle(
  signedBundle: SignedProvisioningBundle,
  comparisonContext: BrowserVaultComparisonContext,
): Promise<void> {
  const hostSigningSec1 = fromBase64Url(
    signedBundle.bundle.host_signing_public_key_sec1,
    'INVALID_PROVISIONING_BUNDLE',
  );
  const hostAgreementSec1 = fromBase64Url(
    signedBundle.bundle.host_agreement_public_key_sec1,
    'INVALID_PROVISIONING_BUNDLE',
  );
  const hostSigningCommitment = await computeKeyCommitment(hostSigningSec1);
  const hostAgreementCommitment = await computeKeyCommitment(hostAgreementSec1);
  if (
    hostSigningCommitment !== comparisonContext.host_signing_commitment
    || hostAgreementCommitment !== comparisonContext.host_agreement_commitment
  ) {
    throw new BrowserVaultError(
      'HOST_KEY_COMMITMENT_MISMATCH',
      'Provisioning bundle host keys do not match the pairing comparison transcript.',
    );
  }
  const hostSigningPublicKey = await importSigningPublicKeySec1(hostSigningSec1);
  const signature = fromBase64Url(
    signedBundle.provisioning_signature_p1363,
    'INVALID_PROVISIONING_BUNDLE',
  );
  const verified = await subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    hostSigningPublicKey,
    ownBytes(signature),
    ownBytes(encoder.encode(canonicalJson(signedBundle.bundle))),
  );
  if (!verified) {
    throw new BrowserVaultError('PROVISIONING_SIGNATURE_INVALID', 'Provisioning bundle signature is invalid.');
  }
}

async function verifyStoredKeyBindings(
  signingPublicKey: CryptoKey,
  signingPrivateKey: CryptoKey,
  agreementPublicKey: CryptoKey,
  agreementPrivateKey: CryptoKey,
): Promise<void> {
  try {
    const randomChallenge = crypto.getRandomValues(new Uint8Array(32));
    const signingChallenge = concatBytes(
      encoder.encode(SIGNING_KEY_BINDING_DOMAIN),
      randomChallenge,
    );
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingPrivateKey,
      ownBytes(signingChallenge),
    );
    const signingMatches = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      signingPublicKey,
      signature,
      ownBytes(signingChallenge),
    );
    if (!signingMatches) {
      throw new Error('signing_key_mismatch');
    }

    const ephemeralAgreement = await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    );
    const storedSideSecret = await deriveSharedSecret(
      agreementPrivateKey,
      ephemeralAgreement.publicKey,
    );
    const ephemeralSideSecret = await deriveSharedSecret(
      ephemeralAgreement.privateKey,
      agreementPublicKey,
    );
    if (!bytesEqual(storedSideSecret, ephemeralSideSecret)) {
      throw new Error('agreement_key_mismatch');
    }
  } catch {
    throw new BrowserVaultError(
      'BROWSER_VAULT_KEY_LOST',
      'Browser vault private keys no longer match the committed device public keys.',
    );
  }
}

async function unwrapDeviceBearer(
  bundle: ProvisioningBundle,
  deviceAgreementPrivateKey: CryptoKey,
): Promise<string> {
  const hostAgreementPublicKey = await importAgreementPublicKeySec1(
    fromBase64Url(bundle.host_agreement_public_key_sec1, 'INVALID_PROVISIONING_BUNDLE'),
  );
  const sharedSecret = await deriveSharedSecret(deviceAgreementPrivateKey, hostAgreementPublicKey);
  const vaultKey = await deriveVaultKey(sharedSecret, bundle.mailbox_id, bundle.pairing_epoch);
  const aesKey = await subtle.importKey('raw', ownBytes(vaultKey), { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ownBytes(fromBase64Url(bundle.wrap_nonce, 'INVALID_PROVISIONING_BUNDLE')),
        tagLength: 128,
      },
      aesKey,
      ownBytes(fromBase64Url(bundle.wrapped_device_bearer, 'INVALID_PROVISIONING_BUNDLE')),
    );
  } catch {
    throw new BrowserVaultError('WRAPPED_BEARER_INVALID', 'Wrapped device bearer could not be restored.');
  }
  const bearer = decoder.decode(new Uint8Array(plaintext));
  if (bearer.length === 0 || bearer.length > 4096 || /[\u0000-\u0020\u007f]/.test(bearer)) {
    throw new BrowserVaultError('WRAPPED_BEARER_INVALID', 'Wrapped device bearer is invalid.');
  }
  return bearer;
}

async function deriveVaultKey(
  sharedSecret: Uint8Array,
  mailboxId: string,
  pairingEpoch: number,
): Promise<Uint8Array> {
  const hkdfKey = await subtle.importKey('raw', ownBytes(sharedSecret), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: ownBytes(new Uint8Array([])),
      info: ownBytes(encoder.encode(`nomad.m3e.browser-vault.v1\n${mailboxId}\n${String(pairingEpoch)}`)),
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(bits);
}

function validateKeyPair(pair: CryptoKeyPair, algorithmName: string, privateUsage: KeyUsage): CryptoKeyPair {
  validateStoredPublicKey(pair.publicKey, algorithmName, algorithmName === 'ECDH' ? '' : 'verify', 'INVALID_DEVICE_KEY');
  validateStoredPrivateKey(pair.privateKey, algorithmName, privateUsage, 'INVALID_DEVICE_KEY');
  return pair;
}

function validateStoredPublicKey(
  value: unknown,
  algorithmName: string,
  requiredUsage: KeyUsage | '',
  missingCode: string,
): CryptoKey {
  if (!(value instanceof CryptoKey)) {
    throw new BrowserVaultError(missingCode, 'Browser vault keys are unavailable.');
  }
  if (value.type !== 'public' || value.algorithm.name !== algorithmName) {
    throw new BrowserVaultError(missingCode, 'Browser vault keys are incompatible.');
  }
  if (requiredUsage !== '' && !value.usages.includes(requiredUsage)) {
    throw new BrowserVaultError(missingCode, 'Browser vault keys are incompatible.');
  }
  return value;
}

function validateStoredPrivateKey(
  value: unknown,
  algorithmName: string,
  requiredUsage: KeyUsage,
  missingCode: string,
): CryptoKey {
  if (!(value instanceof CryptoKey)) {
    throw new BrowserVaultError(missingCode, 'Browser vault keys are unavailable.');
  }
  if (value.type !== 'private' || value.algorithm.name !== algorithmName || value.extractable) {
    throw new BrowserVaultError(missingCode, 'Browser vault keys are incompatible.');
  }
  if (!value.usages.includes(requiredUsage)) {
    throw new BrowserVaultError(missingCode, 'Browser vault keys are incompatible.');
  }
  return value;
}

function exactObject(value: unknown, keys: readonly string[], code: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new BrowserVaultError(code, 'Browser vault state is incompatible.');
  }
  const raw = value as Record<string, unknown>;
  const actual = Object.keys(raw).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new BrowserVaultError(code, 'Browser vault state is incompatible.');
  }
  return raw;
}

function isCanonicalUtcTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    return false;
  }
  const milliseconds = Date.parse(value);
  return (
    Number.isFinite(milliseconds)
    && new Date(milliseconds).toISOString().replace('.000Z', 'Z') === value
  );
}

function isBase64Url(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && BASE64URL_NOPAD.test(value);
}

function ensureExactSec1Base64Url(value: unknown, code: string): void {
  if (!isBase64Url(value)) {
    throw new BrowserVaultError(code, 'Public key encoding is invalid.');
  }
  const decoded = fromBase64Url(value, code);
  if (decoded.byteLength !== 65) {
    throw new BrowserVaultError(code, 'Public key length is invalid.');
  }
}

function fromBase64Url(value: string, code: string): Uint8Array {
  if (!BASE64URL_NOPAD.test(value) || value.length % 4 === 1) {
    throw new BrowserVaultError(code, 'Base64url value is invalid.');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new BrowserVaultError(code, 'Base64url value is invalid.');
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (toBase64Url(decoded) !== value) {
    throw new BrowserVaultError(code, 'Base64url value is invalid.');
  }
  return decoded;
}

function toBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function ownBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value);
}

function validateRelayBaseUrl(value: unknown): asserts value is string {
  if (typeof value !== 'string') {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Relay base URL is invalid.');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Relay base URL is invalid.');
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Relay base URL is invalid.');
  }
  if (url.protocol === 'https:') {
    return;
  }
  if (url.protocol === 'http:' && isLoopbackHost(url.hostname)) {
    return;
  }
  throw new BrowserVaultError('INVALID_PROVISIONING_BUNDLE', 'Relay base URL is invalid.');
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';
}

async function openIndexedDb(dbName: string, indexedDbFactory: IDBFactory): Promise<IDBDatabase> {
  const request = indexedDbFactory.open(dbName, 1);
  request.onupgradeneeded = () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(RECORD_STORE)) {
      database.createObjectStore(RECORD_STORE);
    }
  };
  const database = await promisifyOpenRequest(request);
  database.onclose = null;
  return database;
}

async function runTransaction<T>(
  database: IDBDatabase,
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => Promise<T>,
): Promise<T> {
  const transaction = database.transaction(RECORD_STORE, mode);
  const store = transaction.objectStore(RECORD_STORE);
  try {
    const result = await operation(store);
    await promisifyTransaction(transaction);
    return result;
  } catch (error) {
    transaction.abort();
    throw error;
  }
}

function promisifyOpenRequest(request: IDBOpenDBRequest): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexeddb_open_failed'));
    request.onblocked = () => reject(new Error('indexeddb_open_blocked'));
  });
}

function promisifyRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexeddb_request_failed'));
  });
}

function promisifyTransaction(transaction: IDBTransaction): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error('indexeddb_transaction_failed'));
    transaction.onabort = () => reject(transaction.error ?? new Error('indexeddb_transaction_aborted'));
  });
}
