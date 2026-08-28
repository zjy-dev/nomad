import { describe, expect, it, vi } from 'vitest';

import { computeSnapshotDigest } from '../contracts/digest';
import type { GatewayCommandRequest } from '../client/types';
import type { BrowserVault, BrowserVaultNamespaceRecord, BrowserVaultSession } from './browser-vault';
import {
  canonicalJson,
  computeKeyCommitment,
  decryptRemoteFrame,
  encryptRemoteFrame,
  exportPublicKeySec1,
  generateRuntimeP256AgreementKeyPair,
  generateRuntimeP256SigningKeyPair,
  importAgreementPublicKeySec1,
  type RemoteFrameMetadata,
  type RemoteOpaqueFrame,
  type RemoteRuntimeKeyPair,
  type RemoteSharedContext,
} from './crypto';
import {
  createRemoteSessionPort,
  createBrowserVaultPairedSessionStateStore,
  MemoryPairedSessionStateStore,
  PairedSessionDurableAdapter,
  RemoteSessionError,
  restoreRemoteSessionPort,
  type PairedSessionDurableState,
  type PairedSessionStateStore,
} from './paired-session';

const MAILBOX_ID = `mbx-${'a'.repeat(64)}`;
const HOST_INSTANCE_ID = `host-${'b'.repeat(32)}`;
const SESSION_ALIAS = `sess-${'c'.repeat(32)}`;
const TURN_ALIAS = `turn-${'d'.repeat(32)}`;
const INPUT_ALIAS = `input-${'e'.repeat(32)}`;
const PERMISSION_ALIAS = `permission-${'f'.repeat(32)}`;
const SNAPSHOT_TIME = '2026-08-28T01:00:00.000Z';
const CAPABILITY_ISSUED = '2026-08-28T01:00:00Z';
const CAPABILITY_EXPIRES = '2026-08-28T01:00:30Z';
const NOW = new Date('2026-08-28T01:00:01.500Z');

describe('paired remote session runtime', () => {
  it('polls, decrypts, strictly applies a view projection, and exposes no raw Agent IDs', async () => {
    const harness = await createHarness();
    const projection = await projectionPayload(7);
    harness.hostFrames.push(await harness.encryptHostEnvelope(1, 'projection', projection));

    const snapshot = await harness.port.poll();

    expect(snapshot.connection).toBe('live');
    expect(snapshot.last_good_projection).toEqual(projection);
    expect(snapshot.available_actions).toEqual(['view', 'reply', 'deny', 'stop']);
    expect(harness.acked).toEqual([1]);
    expect(JSON.stringify(snapshot)).not.toMatch(/session_id|turn_id|permission_id|question_id|tool_call_id/);
    expect(JSON.stringify(snapshot)).not.toContain('raw-agent-session');
  });

  it.each([
    ['reply', { action: 'reply', content: 'ship it' }],
    ['deny', { action: 'deny' }],
    ['stop', { action: 'stop' }],
  ] as const)('publishes canonical %s with one stable request ID', async (action, intent) => {
    const harness = await createHarness();
    harness.hostFrames.push(await harness.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await harness.port.poll();

    const snapshot = await harness.port.dispatch(intent);

    expect(snapshot.pending_command).toMatchObject({
      action,
      request_id: 'req-01010101010101010101010101010101',
      command_seq: 19,
      status: 'published',
    });
    expect(harness.published).toHaveLength(1);
    const decoded = await harness.decryptDeviceFrame(harness.published[0]);
    expect(decoded).toMatchObject({
      schema: 'nomad.remote.application-envelope.v1',
      kind: 'command',
      payload: {
        schema: 'nomad.remote.command.v1',
        command: {
          schema: 'nomad.gateway.command.v1',
          action,
          request_id: 'req-01010101010101010101010101010101',
        },
      },
    });
    expect(canonicalJson(decoded)).not.toContain('allow_once');
    expect(JSON.stringify(decoded)).not.toMatch(/session_id|turn_id|permission_id/);
  });

  it('rejects allow_once and unknown actions before any publish', async () => {
    const harness = await createHarness();
    harness.hostFrames.push(await harness.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await harness.port.poll();

    await expect(harness.port.dispatch({ action: 'allow_once' })).rejects.toMatchObject({
      code: 'UNSUPPORTED_ACTION',
    } satisfies Partial<RemoteSessionError>);
    await expect(harness.port.dispatch({ action: 'approve' })).rejects.toMatchObject({
      code: 'UNSUPPORTED_ACTION',
    } satisfies Partial<RemoteSessionError>);
    expect(harness.published).toHaveLength(0);
  });

  it('keeps last-good projection on duplicate and reconnect, without creating another command', async () => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture });
    const projection = await projectionPayload(7);
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', projection));
    await first.port.poll();
    await first.port.dispatch({ action: 'reply', content: 'once' });
    expect(first.published).toHaveLength(1);

    const second = await createHarness({ store, fixture });
    second.hostFrames.push(await second.encryptHostEnvelope(2, 'projection', projection));
    const reconnected = await second.port.poll();

    expect(reconnected.connection).toBe('live');
    expect(reconnected.last_good_projection?.snapshot.snapshot_seq).toBe(7);
    expect(reconnected.pending_command?.request_id).toBe('req-01010101010101010101010101010101');
    expect(second.published).toHaveLength(0);
    await expect(second.port.dispatch({ action: 'reply', content: 'duplicate' })).rejects.toMatchObject({
      code: 'COMMAND_ALREADY_PENDING',
    });
  });

  it('retries only the exact pending encrypted frame after an ambiguous publish', async () => {
    const harness = await createHarness({ publishFailureOnce: new TypeError('connection reset') });
    harness.hostFrames.push(await harness.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await harness.port.poll();

    await expect(harness.port.dispatch({ action: 'stop' })).rejects.toMatchObject({ code: 'PUBLISH_FAILED' });
    const firstBody = harness.publishAttempts[0];
    expect(firstBody).toBeDefined();

    const retry = await harness.port.retryPending();
    expect(retry.pending_command).toMatchObject({
      request_id: 'req-01010101010101010101010101010101',
      status: 'published',
    });
    expect(harness.publishAttempts).toHaveLength(2);
    expect(harness.publishAttempts[1]).toBe(firstBody);
  });

  it('keeps exact retry reachable after reload when pending command and frame both survive an ambiguous publish', async () => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture, publishFailureOnce: new TypeError('connection reset') });
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await first.port.poll();

    await expect(first.port.dispatch({ action: 'stop' })).rejects.toMatchObject({ code: 'PUBLISH_FAILED' });
    const originalFrame = first.publishAttempts[0];
    expect(first.port.getSnapshot().pending_command).toMatchObject({
      request_id: 'req-01010101010101010101010101010101',
      status: 'prepared',
    });

    const second = await createHarness({ store, fixture });
    expect(second.port.getSnapshot().pending_command).toMatchObject({
      request_id: 'req-01010101010101010101010101010101',
      status: 'prepared',
    });

    const retried = await second.port.retryPending();
    expect(retried.pending_command).toMatchObject({
      request_id: 'req-01010101010101010101010101010101',
      status: 'published',
    });
    expect(second.publishAttempts).toHaveLength(1);
    expect(second.publishAttempts[0]).toBe(originalFrame);
  });

  it('clears exact pending outbound atomically when a terminal Host receipt resolves the matching request', async () => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture, publishFailureOnce: new TypeError('connection reset') });
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await first.port.poll();

    await expect(first.port.dispatch({ action: 'stop' })).rejects.toMatchObject({ code: 'PUBLISH_FAILED' });
    const pending = first.port.getSnapshot().pending_command;
    if (pending === null) throw new Error('expected pending stop');

    first.hostFrames.push(await first.encryptHostEnvelope(2, 'receipt', receiptPayload({
      action: 'stop',
      requestId: pending.request_id,
      snapshotDigest: pending.snapshot_digest,
      status: 'DispatchAcknowledged',
      errorCode: 'OK',
    })));
    const resolved = await first.port.poll();
    expect(resolved.pending_command).toBeNull();

    const second = await createHarness({ store, fixture });
    expect(second.port.getSnapshot().pending_command).toBeNull();
    await expect(second.port.retryPending()).rejects.toMatchObject({ code: 'EXACT_RETRY_UNAVAILABLE' });
  });

  it('rejects a next-command receipt mismatch and preserves the original exact retry state', async () => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture, publishFailureOnce: new TypeError('connection reset') });
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await first.port.poll();

    await expect(first.port.dispatch({ action: 'reply', content: 'still pending' })).rejects.toMatchObject({ code: 'PUBLISH_FAILED' });
    const pending = first.port.getSnapshot().pending_command;
    if (pending === null) throw new Error('expected pending reply');

    first.hostFrames.push(await first.encryptHostEnvelope(2, 'receipt', receiptPayload({
      action: 'reply',
      requestId: 'req-ffffffffffffffffffffffffffffffff',
      snapshotDigest: pending.snapshot_digest,
      status: 'DispatchAcknowledged',
      errorCode: 'OK',
    })));
    await expect(first.port.poll()).rejects.toMatchObject({ code: 'UNBOUND_RECEIPT' });

    const second = await createHarness({ store, fixture });
    expect(second.port.getSnapshot().pending_command?.request_id).toBe(pending.request_id);
    const retried = await second.port.retryPending();
    expect(retried.pending_command?.request_id).toBe(pending.request_id);
  });

  it('persists OutcomeUnknown and never creates or retries a replacement request', async () => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture });
    const projection = await projectionPayload(7);
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', projection));
    await first.port.poll();
    await first.port.dispatch({ action: 'deny' });
    const pending = first.port.getSnapshot().pending_command;
    if (pending === null) throw new Error('expected pending deny');
    first.hostFrames.push(await first.encryptHostEnvelope(2, 'receipt', receiptPayload({
      action: 'deny',
      requestId: 'req-01010101010101010101010101010101',
      snapshotDigest: pending.snapshot_digest,
      status: 'OutcomeUnknown',
      errorCode: 'ERR_OUTCOME_UNKNOWN',
    })));
    const unknown = await first.port.poll();
    expect(unknown.pending_command?.status).toBe('OutcomeUnknown');

    const second = await createHarness({ store, fixture });
    expect(second.port.getSnapshot().pending_command?.request_id).toBe('req-01010101010101010101010101010101');
    await expect(second.port.retryPending()).rejects.toMatchObject({ code: 'EXACT_RETRY_UNAVAILABLE' });
    await expect(second.port.dispatch({ action: 'deny' })).rejects.toMatchObject({
      code: 'OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION',
    });
    expect(second.published).toHaveLength(0);
  });

  it.each([401, 410])('enters durable revoked state on Relay %s', async (status) => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture, readStatus: status });

    await expect(first.port.poll()).rejects.toMatchObject({ code: 'DEVICE_REVOKED' });
    expect(first.port.getSnapshot().connection).toBe('revoked');

    const second = await createHarness({ store, fixture });
    expect(second.port.getSnapshot().connection).toBe('revoked');
    await expect(second.port.dispatch({ action: 'view' })).rejects.toMatchObject({ code: 'DEVICE_REVOKED' });
  });

  it('enters durable revoked state on an authoritative Host revoked receipt', async () => {
    const store = new MemoryPairedSessionStateStore();
    const fixture = await createCryptoFixture();
    const first = await createHarness({ store, fixture });
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await first.port.poll();
    await first.port.dispatch({ action: 'stop' });
    const pending = first.port.getSnapshot().pending_command;
    if (pending === null) throw new Error('expected pending Stop');
    first.hostFrames.push(await first.encryptHostEnvelope(2, 'receipt', receiptPayload({
      action: 'stop',
      requestId: pending.request_id,
      snapshotDigest: pending.snapshot_digest,
      status: 'Rejected',
      errorCode: 'ERR_REQUEST_REVOKED',
    })));

    const revoked = await first.port.poll();
    expect(revoked.connection).toBe('revoked');
    expect(revoked.available_actions).toEqual([]);

    const second = await createHarness({ store, fixture });
    expect(second.port.getSnapshot().connection).toBe('revoked');
    await expect(second.port.dispatch({ action: 'stop' })).rejects.toMatchObject({ code: 'DEVICE_REVOKED' });
    expect(second.published).toHaveLength(0);
  });

  it('fails closed when production construction omits its durable store', async () => {
    const fixture = await createCryptoFixture();
    await expect(createRemoteSessionPort({ session: fixture.session })).rejects.toMatchObject({
      code: 'PAIRED_SESSION_STORE_REQUIRED',
    });
  });

  it('fails closed before Relay access when a paired private key is lost', async () => {
    const fixture = await createCryptoFixture();
    fixture.session.deviceSigningKeyPair = {
      publicKey: fixture.session.deviceSigningKeyPair.publicKey,
      privateKey: fixture.session.deviceSigningKeyPair.publicKey,
    };
    await expect(createRemoteSessionPort({
      session: fixture.session,
      stateStore: new MemoryPairedSessionStateStore(),
    })).rejects.toMatchObject({ code: 'KEY_LOST' });
  });

  it('uses BrowserVault namespace CAS by default and restores last-good state after reopen', async () => {
    const fixture = await createCryptoFixture();
    const namespace = new NamespaceVaultRecords();
    const firstVault = namespace.vault(fixture.session);
    const first = await createHarness({ fixture, vault: firstVault });
    first.hostFrames.push(await first.encryptHostEnvelope(1, 'projection', await projectionPayload(7)));
    await first.port.poll();

    const reopenedVault = namespace.vault(fixture.session);
    const reopened = await restoreRemoteSessionPort({
      vault: reopenedVault,
      fetchImpl: unreachableFetch(),
      allowLoopbackHttp: true,
      now: () => new Date(NOW),
    });

    expect(reopened.getSnapshot().last_good_projection?.snapshot.snapshot_seq).toBe(7);
    expect(reopened.getSnapshot().connection).toBe('reconnecting');
    expect(namespace.recordCount).toBe(1);
    expect(namespace.keys()).toEqual([`paired-session:${MAILBOX_ID}:4`]);
  });

  it('rejects a stale BrowserVault namespace CAS without overwriting the winner', async () => {
    const namespace = new NamespaceVaultRecords();
    const vault = namespace.vault();
    const store = createBrowserVaultPairedSessionStateStore(vault);
    const key = { mailboxId: MAILBOX_ID, epoch: 4 };
    const adapter = new PairedSessionDurableAdapter(store, key, { appliedThrough: 0, nextSequence: 1 });
    await adapter.initialize();
    const stale = await store.load(key);
    if (stale === null) throw new Error('expected initialized state');
    const winner: PairedSessionDurableState = { ...stale, revision: stale.revision + 1, revoked: true };
    const loser: PairedSessionDurableState = { ...stale, revision: stale.revision + 1, deviceToHostNextSequence: 9 };

    await expect(store.compareAndSwap(key, stale.revision, winner)).resolves.toBe(true);
    await expect(store.compareAndSwap(key, stale.revision, loser)).resolves.toBe(false);
    await expect(store.load(key)).resolves.toMatchObject({ revoked: true, deviceToHostNextSequence: 1 });
  });
});

interface CryptoFixture {
  session: BrowserVaultSession;
  hostSigning: RemoteRuntimeKeyPair;
  hostAgreement: RemoteRuntimeKeyPair;
  deviceSigningSec1: Uint8Array;
  deviceAgreementSec1: Uint8Array;
  hostSigningSec1: Uint8Array;
  hostAgreementSec1: Uint8Array;
  context: RemoteSharedContext;
}

interface HarnessOptions {
  store?: PairedSessionStateStore;
  vault?: BrowserVault;
  fixture?: CryptoFixture;
  publishFailureOnce?: Error;
  readStatus?: number;
}

async function createHarness(options: HarnessOptions = {}) {
  const fixture = options.fixture ?? await createCryptoFixture();
  const store = options.store ?? (options.vault === undefined ? new MemoryPairedSessionStateStore() : undefined);
  const hostFrames: RemoteOpaqueFrame[] = [];
  const published: RemoteOpaqueFrame[] = [];
  const publishAttempts: string[] = [];
  const acked: number[] = [];
  let publishFailure = options.publishFailureOnce;
  let randomCall = 0;
  const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (init?.method === 'POST' && url.pathname.endsWith('/frames')) {
      const body = String(init.body);
      publishAttempts.push(body);
      if (publishFailure !== undefined) {
        const failure = publishFailure;
        publishFailure = undefined;
        throw failure;
      }
      published.push(JSON.parse(body) as RemoteOpaqueFrame);
      return jsonResponse({ idempotent: false, stored: true }, 201);
    }
    if (init?.method === 'POST' && url.pathname.endsWith('/acks')) {
      const ack = JSON.parse(String(init.body)) as { acked_through_sequence: number };
      acked.push(ack.acked_through_sequence);
      return jsonResponse({ acked: true });
    }
    if (init?.method === 'GET' && url.pathname.endsWith('/frames')) {
      if (options.readStatus !== undefined) {
        return jsonResponse({ error: 'revoked' }, options.readStatus);
      }
      const after = Number(url.searchParams.get('after_sequence'));
      return jsonResponse(hostFrames.filter((frame) => frame.sequence > after));
    }
    throw new Error(`unexpected request ${String(input)}`);
  }) as unknown as typeof fetch;

  const port = await createRemoteSessionPort({
    session: fixture.session,
    stateStore: store,
    vault: options.vault,
    fetchImpl,
    allowLoopbackHttp: true,
    now: () => new Date(NOW),
    randomBytes: (length) => {
      randomCall += 1;
      return new Uint8Array(length).fill(randomCall);
    },
  });

  return {
    port,
    store,
    hostFrames,
    published,
    publishAttempts,
    acked,
    encryptHostEnvelope: (sequence: number, kind: 'projection' | 'receipt', payload: unknown) =>
      encryptHostEnvelope(fixture, sequence, kind, payload),
    decryptDeviceFrame: (frame: RemoteOpaqueFrame) => decryptDeviceFrame(fixture, frame),
    fixture,
  };
}

class NamespaceVaultRecords {
  private readonly records = new Map<string, BrowserVaultNamespaceRecord<unknown>>();

  get recordCount(): number {
    return this.records.size;
  }

  keys(): string[] {
    return [...this.records.keys()];
  }

  vault(session?: BrowserVaultSession): BrowserVault {
    return {
      restorePairedDevice: vi.fn(async () => {
        if (session === undefined) throw new Error('session unavailable');
        return session;
      }),
      loadNamespaceRecord: vi.fn(async <T>(namespace: string, key: string) => {
        const record = this.records.get(`${namespace}:${key}`);
        return record === undefined ? null : structuredClone(record) as BrowserVaultNamespaceRecord<T>;
      }),
      compareAndSwapNamespaceRecord: vi.fn(async <T>(
        namespace: string,
        key: string,
        expectedRevision: number | null,
        value: T,
      ) => {
        const storageKey = `${namespace}:${key}`;
        const current = this.records.get(storageKey);
        if (expectedRevision === null ? current !== undefined : current?.revision !== expectedRevision) {
          return false;
        }
        this.records.set(storageKey, {
          revision: current === undefined ? 0 : current.revision + 1,
          value: structuredClone(value),
        });
        return true;
      }),
    } as unknown as BrowserVault;
  }
}

function unreachableFetch(): typeof fetch {
  return vi.fn(async () => {
    throw new Error('network must not be used during restore');
  }) as unknown as typeof fetch;
}

async function createCryptoFixture(): Promise<CryptoFixture> {
  const hostSigning = await generateRuntimeP256SigningKeyPair();
  const hostAgreement = await generateRuntimeP256AgreementKeyPair();
  const deviceSigning = await generateRuntimeP256SigningKeyPair();
  const deviceAgreement = await generateRuntimeP256AgreementKeyPair();
  const hostSigningSec1 = await exportPublicKeySec1(hostSigning.publicKey);
  const hostAgreementSec1 = await exportPublicKeySec1(hostAgreement.publicKey);
  const deviceSigningSec1 = await exportPublicKeySec1(deviceSigning.publicKey);
  const deviceAgreementSec1 = await exportPublicKeySec1(deviceAgreement.publicKey);
  const context: RemoteSharedContext = {
    mailboxId: MAILBOX_ID,
    epoch: 4,
    hostSigningCommitment: await computeKeyCommitment(hostSigningSec1),
    hostAgreementCommitment: await computeKeyCommitment(hostAgreementSec1),
    deviceSigningCommitment: await computeKeyCommitment(deviceSigningSec1),
    deviceAgreementCommitment: await computeKeyCommitment(deviceAgreementSec1),
  };
  const session: BrowserVaultSession = {
    comparisonCode: '123456',
    bundle: {
      schema: 'nomad.m3e.provisioning-bundle.v1',
      device_alias: 'device_browser_001',
      pairing_epoch: 4,
      mailbox_id: MAILBOX_ID,
      relay_base_url: 'http://127.0.0.1:8787',
      host_signing_public_key_sec1: toBase64Url(hostSigningSec1),
      host_agreement_public_key_sec1: toBase64Url(hostAgreementSec1),
      wrapped_device_bearer: 'opaque',
      wrap_nonce: 'opaque',
      issued_at: CAPABILITY_ISSUED,
    },
    signedProvisioningBundle: {} as BrowserVaultSession['signedProvisioningBundle'],
    deviceBearer: 'device-bearer',
    deviceSigningKeyPair: deviceSigning,
    deviceAgreementKeyPair: deviceAgreement,
    transport: {
      host_to_device_applied_through_sequence: 0,
      device_to_host_next_sequence: 1,
    },
  };
  return {
    session, hostSigning, hostAgreement, deviceSigningSec1, deviceAgreementSec1,
    hostSigningSec1, hostAgreementSec1, context,
  };
}

async function encryptHostEnvelope(
  fixture: CryptoFixture,
  sequence: number,
  kind: 'projection' | 'receipt',
  payload: unknown,
): Promise<RemoteOpaqueFrame> {
  const frame = frameMetadata('host_to_device', sequence);
  const encrypted = await encryptRemoteFrame({
    frame,
    plaintext: {
      schema: 'nomad.remote.application-envelope.v1',
      kind,
      mailbox_id: frame.mailbox_id,
      direction: frame.direction,
      epoch: frame.epoch,
      sequence: frame.sequence,
      message_id: frame.message_id,
      payload,
    },
    senderSigningPrivateKey: fixture.hostSigning.privateKey,
    senderSigningPublicKeySec1: fixture.hostSigningSec1,
    senderAgreementPrivateKey: fixture.hostAgreement.privateKey,
    senderAgreementPublicKeySec1: fixture.hostAgreementSec1,
    recipientAgreementPublicKey: fixture.session.deviceAgreementKeyPair.publicKey,
    context: fixture.context,
  });
  return encrypted.frame;
}

async function decryptDeviceFrame(fixture: CryptoFixture, frame: RemoteOpaqueFrame): Promise<unknown> {
  const deviceAgreementPublic = await importAgreementPublicKeySec1(fixture.deviceAgreementSec1);
  expect(deviceAgreementPublic).toBeDefined();
  const decrypted = await decryptRemoteFrame({
    frame,
    recipientAgreementPrivateKey: fixture.hostAgreement.privateKey,
    context: fixture.context,
    expectedSenderSigningCommitment: fixture.context.deviceSigningCommitment,
    expectedSenderAgreementCommitment: fixture.context.deviceAgreementCommitment,
  });
  return decrypted.plaintext;
}

function frameMetadata(direction: 'host_to_device' | 'device_to_host', sequence: number): RemoteFrameMetadata {
  return {
    schema: 'nomad.relay.opaque-frame.v2',
    crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1',
    mailbox_id: MAILBOX_ID,
    direction,
    epoch: 4,
    sequence,
    message_id: `msg-${sequence.toString(16).padStart(32, '0')}`,
    issued_at: Math.floor(NOW.getTime() / 1000),
    expires_at: Math.floor(NOW.getTime() / 1000) + 60,
    nonce: toBase64Url(deriveNonce(direction, sequence)),
  };
}

function deriveNonce(direction: 'host_to_device' | 'device_to_host', sequence: number): Uint8Array {
  const nonce = new Uint8Array(12);
  nonce.set(direction === 'host_to_device' ? [1, 2, 3, 4] : [5, 6, 7, 8]);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(sequence), false);
  return nonce;
}

async function projectionPayload(snapshotSeq: number) {
  const snapshot = {
    schema: 'nomad.product-host.snapshot.v1' as const,
    host_instance_id: HOST_INSTANCE_ID,
    snapshot_seq: snapshotSeq,
    snapshot: {
      session_alias: SESSION_ALIAS,
      updated_at: SNAPSHOT_TIME,
      turn_state: 'NeedsInput',
      pending_input_alias: INPUT_ALIAS,
      pending_permission_alias: PERMISSION_ALIAS,
      diff_file_count: 1,
      writable: false as const,
      evidence_class: 'official_registry_shape_only_not_provider_lifecycle' as const,
    },
  };
  const digest = await computeSnapshotDigest(snapshot);
  return {
    schema: 'nomad.remote.projection.v1' as const,
    snapshot: { ...snapshot, digest },
    capability: {
      schema: 'nomad.product-host.command-capability.v1' as const,
      capability_id: 'capability_00000001',
      snapshot_seq: snapshotSeq,
      snapshot_digest: digest,
      next_command_seq: 19,
      issued_at: CAPABILITY_ISSUED,
      expires_at: CAPABILITY_EXPIRES,
      view: true as const,
      reply: {
        turn_alias: TURN_ALIAS,
        input_alias: INPUT_ALIAS,
        summary: {
          schema: 'nomad.product-host.pending-question-summary.v1' as const,
          question_count: 1 as const,
          answer_mode: 'free_text' as const,
          response_hint: 'single_short_reply' as const,
          prompt: 'Provide a short reply for: deployment region.',
        },
      },
      deny: {
        permission_alias: PERMISSION_ALIAS,
        action_hash: digest,
        expires_at: CAPABILITY_EXPIRES,
      },
      stop: { turn_alias: TURN_ALIAS },
      allow_once: false as const,
    },
  };
}

function receiptPayload(options: {
  action: GatewayCommandRequest['action'];
  requestId: string;
  snapshotDigest: string;
  status: 'OutcomeUnknown' | 'Rejected' | 'DispatchAcknowledged';
  errorCode: 'ERR_OUTCOME_UNKNOWN' | 'ERR_REQUEST_REVOKED' | 'OK';
}) {
  return {
    schema: 'nomad.remote.receipt.v1',
    receipt: {
      schema: 'nomad.gateway.command-receipt.v1',
      receipt_id: 'receipt_00000001',
      request_id: options.requestId,
      action: options.action,
      snapshot_seq: 7,
      snapshot_digest: options.snapshotDigest,
      accepted_at: '2026-08-28T01:00:02Z',
      status: options.status,
      error_code: options.errorCode,
      idempotent_replay: false,
    },
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(canonicalJson(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function toBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}
