import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  BrowserVault,
  type BrowserVaultComparisonContext,
  type BrowserVaultDatabase,
  type ProvisioningBundle,
  type SignedProvisioningBundle,
} from './browser-vault';
import {
  canonicalJson,
  computeKeyCommitment,
  deriveSharedSecret,
  exportPublicKeySec1,
  generateRuntimeP256AgreementKeyPair,
  generateRuntimeP256SigningKeyPair,
} from './crypto';
import type { PendingOutboundFrame, PersistedAppliedBatch } from './device-endpoint';

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

describe('M3-E browser vault', () => {
  it('persists and restores both non-extractable P-256 keypairs through structured clone', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();
    const firstVault = vaultFor(database);

    const persisted = await firstVault.persistProvisionedDevice(fixture.persistInput);

    expect(persisted.deviceBearer).toBe(fixture.deviceBearer);
    expect(persisted.deviceSigningKeyPair.privateKey.extractable).toBe(false);
    expect(persisted.deviceAgreementKeyPair.privateKey.extractable).toBe(false);
    expect(database.cloneCount).toBeGreaterThanOrEqual(10);

    const restored = await vaultFor(database).restorePairedDevice();
    expect(restored.deviceBearer).toBe(fixture.deviceBearer);
    expect(restored.comparisonCode).toBe(fixture.comparisonContext.comparison_code);
    expect(restored.deviceSigningKeyPair.privateKey).toBeInstanceOf(CryptoKey);
    expect(restored.deviceAgreementKeyPair.privateKey).toBeInstanceOf(CryptoKey);
    expect(restored.deviceSigningKeyPair.privateKey.extractable).toBe(false);
    expect(restored.deviceAgreementKeyPair.privateKey.extractable).toBe(false);
    await expect(subtle.exportKey('pkcs8', restored.deviceSigningKeyPair.privateKey)).rejects.toThrow();
    await expect(subtle.exportKey('pkcs8', restored.deviceAgreementKeyPair.privateKey)).rejects.toThrow();

    const signingProbe = encoder.encode('structured-clone signing probe');
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      restored.deviceSigningKeyPair.privateKey,
      ownBytes(signingProbe),
    );
    await expect(subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      restored.deviceSigningKeyPair.publicKey,
      signature,
      ownBytes(signingProbe),
    )).resolves.toBe(true);

    const restoredSecret = await deriveSharedSecret(
      restored.deviceAgreementKeyPair.privateKey,
      fixture.hostAgreementKeyPair.publicKey,
    );
    const hostSecret = await deriveSharedSecret(
      fixture.hostAgreementKeyPair.privateKey,
      restored.deviceAgreementKeyPair.publicKey,
    );
    expect(toHex(restoredSecret)).toBe(toHex(hostSecret));
  });

  it('stores only the wrapped bearer and never persists bearer plaintext', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();

    await vaultFor(database).persistProvisionedDevice(fixture.persistInput);

    expect(database.serializedRecords()).toContain(fixture.signedBundle.bundle.wrapped_device_bearer);
    expect(database.serializedRecords()).not.toContain(fixture.deviceBearer);
  });

  it('accepts only whole-second UTC provisioning timestamps', async () => {
    for (const issuedAt of [
      '2026-08-27T08:00:00.000Z',
      '2026-08-27T10:00:00+02:00',
    ]) {
      const fixture = await createProvisioningFixture();
      fixture.signedBundle.bundle.issued_at = issuedAt;
      await expect(vaultFor(new StructuredCloneDatabase()).persistProvisionedDevice(
        fixture.persistInput,
      )).rejects.toMatchObject({ code: 'INVALID_PROVISIONING_BUNDLE' });
    }
  });

  it('fails closed and clears the vault when a persisted private key is lost', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();
    await vaultFor(database).persistProvisionedDevice(fixture.persistInput);
    await database.delete('device-signing-private');

    await expect(vaultFor(database).restorePairedDevice()).rejects.toMatchObject({
      code: 'BROWSER_VAULT_KEY_LOST',
    });
    expect(database.size).toBe(0);
  });

  it('proves the restored signing private key matches the committed public key', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();
    await vaultFor(database).persistProvisionedDevice(fixture.persistInput);
    const mismatchedSigning = await generateRuntimeP256SigningKeyPair();
    await database.put('device-signing-private', mismatchedSigning.privateKey);

    await expect(vaultFor(database).restorePairedDevice()).rejects.toMatchObject({
      code: 'BROWSER_VAULT_KEY_LOST',
    });
    expect(database.size).toBe(0);
  });

  it('proves the restored agreement private key matches by ECDH before bearer unwrap', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();
    await vaultFor(database).persistProvisionedDevice(fixture.persistInput);
    const mismatchedAgreement = await generateRuntimeP256AgreementKeyPair();
    await database.put('device-agreement-private', mismatchedAgreement.privateKey);

    await expect(vaultFor(database).restorePairedDevice()).rejects.toMatchObject({
      code: 'BROWSER_VAULT_KEY_LOST',
    });
    expect(database.size).toBe(0);
  });

  it('fails closed when IndexedDB is unavailable instead of falling back to browser storage', async () => {
    const vault = new BrowserVault({
      databaseFactory: async () => {
        throw new Error('private_mode_indexeddb_denied');
      },
    });

    await expect(vault.restorePairedDevice()).rejects.toMatchObject({
      code: 'BROWSER_VAULT_UNAVAILABLE',
    });
  });

  it('fails pairing completion when the IndexedDB key persistence self-check loses a CryptoKey', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();
    database.dropAfterPut = 'device-agreement-private';

    await expect(vaultFor(database).persistProvisionedDevice(fixture.persistInput)).rejects.toMatchObject({
      code: 'BROWSER_VAULT_KEY_LOST',
    });
    expect(database.size).toBe(0);
  });

  it('contains no localStorage or sessionStorage credential path', () => {
    for (const file of ['browser-vault.ts', 'pairing-client.ts']) {
      const source = readFileSync(resolve(process.cwd(), 'src/remote', file), 'utf8');
      expect(source).not.toMatch(/\b(?:localStorage|sessionStorage)\b/);
    }
  });

  it('atomically persists durable endpoint state across vault reopen', async () => {
    const database = new StructuredCloneDatabase();
    const fixture = await createProvisioningFixture();
    const mailboxId = fixture.signedBundle.bundle.mailbox_id;
    const epoch = fixture.signedBundle.bundle.pairing_epoch;
    const firstVault = vaultFor(database);
    await firstVault.persistProvisionedDevice(fixture.persistInput);
    expect(await firstVault.reserveNextSequence(mailboxId, 'device_to_host', epoch)).toBe(1);
    expect(await firstVault.reserveNextSequence(mailboxId, 'device_to_host', epoch)).toBe(2);
    const outbound: PendingOutboundFrame = {
      sequence: 2,
      frame: opaqueFrame(mailboxId, 'device_to_host', epoch, 2),
    };
    await firstVault.persistPendingOutboundFrame(mailboxId, 'device_to_host', epoch, outbound);
    const applied: PersistedAppliedBatch = {
      appliedThroughSequence: 4,
      envelopes: [{
        frame: opaqueFrame(mailboxId, 'host_to_device', epoch, 4),
        envelope: { schema: 'opaque-test-envelope.v1' },
      }],
    };
    await firstVault.persistAppliedHostBatch(mailboxId, 'host_to_device', epoch, applied);
    await firstVault.close();

    const reopened = vaultFor(database);
    expect(await reopened.loadPendingOutboundFrame(mailboxId, 'device_to_host', epoch)).toEqual(outbound);
    expect(await reopened.loadAppliedThroughSequence(mailboxId, 'host_to_device', epoch)).toBe(4);
    expect(await reopened.loadPendingAppliedBatch(mailboxId, 'host_to_device', epoch)).toEqual(applied);
    await reopened.clearPendingOutboundFrame(mailboxId, 'device_to_host', epoch, 1);
    expect(await reopened.loadPendingOutboundFrame(mailboxId, 'device_to_host', epoch)).toEqual(outbound);
    await reopened.clearPendingOutboundFrame(mailboxId, 'device_to_host', epoch, 2);
    await reopened.clearPendingAppliedBatch(mailboxId, 'host_to_device', epoch, 3);
    expect(await reopened.loadPendingAppliedBatch(mailboxId, 'host_to_device', epoch)).toEqual(applied);
    await reopened.clearPendingAppliedBatch(mailboxId, 'host_to_device', epoch, 4);
    expect(await reopened.loadPendingOutboundFrame(mailboxId, 'device_to_host', epoch)).toBeNull();
    expect(await reopened.loadPendingAppliedBatch(mailboxId, 'host_to_device', epoch)).toBeNull();
  });

  it('provides monotonic namespace CAS across reopen, conflict, and concurrent writers', async () => {
    const database = new StructuredCloneDatabase();
    const firstVault = vaultFor(database);
    const namespace = 'paired-session';
    const key = `mbx-${'8e'.repeat(32)}:7`;
    expect(await firstVault.loadNamespaceRecord(namespace, key)).toBeNull();
    expect(await firstVault.compareAndSwapNamespaceRecord(namespace, key, null, { state: 'initial' })).toBe(true);
    expect(await firstVault.compareAndSwapNamespaceRecord(namespace, key, null, { state: 'stale-create' })).toBe(false);
    await firstVault.close();

    const reopened = vaultFor(database);
    expect(await reopened.loadNamespaceRecord(namespace, key)).toEqual({
      revision: 0,
      value: { state: 'initial' },
    });
    const concurrent = await Promise.all([
      reopened.compareAndSwapNamespaceRecord(namespace, key, 0, { writer: 'alpha' }),
      reopened.compareAndSwapNamespaceRecord(namespace, key, 0, { writer: 'beta' }),
    ]);
    expect(concurrent.filter(Boolean)).toHaveLength(1);
    const after = await reopened.loadNamespaceRecord<{ writer: string }>(namespace, key);
    expect(after?.revision).toBe(1);
    expect(['alpha', 'beta']).toContain(after?.value.writer);
  });

  it('rejects invalid namespace records and never falls back in private mode', async () => {
    const vault = vaultFor(new StructuredCloneDatabase());
    await expect(vault.loadNamespaceRecord('../paired-session', 'key')).rejects.toMatchObject({
      code: 'INVALID_NAMESPACE_RECORD',
    });
    await expect(vault.compareAndSwapNamespaceRecord('paired-session', 'bad/key', null, {})).rejects.toMatchObject({
      code: 'INVALID_NAMESPACE_RECORD',
    });
    await expect(vault.compareAndSwapNamespaceRecord('paired-session', 'valid:key', -1, {})).rejects.toMatchObject({
      code: 'INVALID_NAMESPACE_RECORD',
    });

    const unavailable = new BrowserVault({
      databaseFactory: async () => {
        throw new Error('private_mode_indexeddb_denied');
      },
    });
    await expect(unavailable.loadNamespaceRecord('paired-session', 'valid:key')).rejects.toMatchObject({
      code: 'BROWSER_VAULT_UNAVAILABLE',
    });
  });
});

class StructuredCloneDatabase implements BrowserVaultDatabase {
  private readonly records = new Map<string, unknown>();
  cloneCount = 0;
  dropAfterPut: string | null = null;

  get size(): number {
    return this.records.size;
  }

  async clear(): Promise<void> {
    this.records.clear();
  }

  close(): void {}

  async delete(key: string): Promise<void> {
    this.records.delete(key);
  }

  async deleteIfSequence(key: string, expectedSequence: number): Promise<void> {
    const value = this.records.get(key) as { sequence?: number; appliedThroughSequence?: number } | undefined;
    if ((value?.sequence ?? value?.appliedThroughSequence) === expectedSequence) {
      this.records.delete(key);
    }
  }

  async get<T>(key: string): Promise<T | undefined> {
    const value = this.records.get(key);
    if (value === undefined) {
      return undefined;
    }
    this.cloneCount += 1;
    return structuredClone(value) as T;
  }

  async loadNamespaceRecord<T>(key: string) {
    return this.get<{ revision: number; value: T }>(key);
  }

  async put(key: string, value: unknown): Promise<void> {
    this.cloneCount += 1;
    this.records.set(key, structuredClone(value));
    if (key === this.dropAfterPut) {
      this.records.delete(key);
    }
  }

  async reserveSequence(key: string, stateKey: string): Promise<number> {
    const state = this.records.get(stateKey) as {
      transport: { device_to_host_next_sequence: number };
    };
    const reserved = (this.records.get(key) as number | undefined)
      ?? state.transport.device_to_host_next_sequence;
    this.records.set(key, reserved + 1);
    state.transport.device_to_host_next_sequence = reserved + 1;
    this.records.set(stateKey, state);
    return reserved;
  }

  async putAppliedBatch(
    appliedThroughKey: string,
    pendingBatchKey: string,
    stateKey: string,
    batch: PersistedAppliedBatch,
  ): Promise<void> {
    const state = this.records.get(stateKey) as {
      transport: { host_to_device_applied_through_sequence: number };
    };
    this.records.set(appliedThroughKey, batch.appliedThroughSequence);
    this.records.set(pendingBatchKey, structuredClone(batch));
    state.transport.host_to_device_applied_through_sequence = batch.appliedThroughSequence;
    this.records.set(stateKey, state);
  }

  async compareAndSwapNamespaceRecord<T>(
    key: string,
    expectedRevision: number | null,
    nextValue: T,
  ): Promise<boolean> {
    const current = this.records.get(key) as { revision: number; value: unknown } | undefined;
    if (expectedRevision === null ? current !== undefined : current?.revision !== expectedRevision) {
      return false;
    }
    await Promise.resolve();
    const latest = this.records.get(key) as { revision: number; value: unknown } | undefined;
    if (expectedRevision === null ? latest !== undefined : latest?.revision !== expectedRevision) {
      return false;
    }
    this.records.set(key, structuredClone({
      revision: current === undefined ? 0 : current.revision + 1,
      value: nextValue,
    }));
    return true;
  }

  serializedRecords(): string {
    return JSON.stringify([...this.records.entries()]);
  }
}

function vaultFor(database: BrowserVaultDatabase): BrowserVault {
  return new BrowserVault({ databaseFactory: async () => database });
}

async function createProvisioningFixture() {
  const hostSigningKeyPair = await generateRuntimeP256SigningKeyPair();
  const hostAgreementKeyPair = await generateRuntimeP256AgreementKeyPair();
  const deviceSigningKeyPair = await generateRuntimeP256SigningKeyPair();
  const deviceAgreementKeyPair = await generateRuntimeP256AgreementKeyPair();
  const hostSigningPublicKeySec1 = await exportPublicKeySec1(hostSigningKeyPair.publicKey);
  const hostAgreementPublicKeySec1 = await exportPublicKeySec1(hostAgreementKeyPair.publicKey);
  const deviceSigningPublicKeySec1 = await exportPublicKeySec1(deviceSigningKeyPair.publicKey);
  const deviceAgreementPublicKeySec1 = await exportPublicKeySec1(deviceAgreementKeyPair.publicKey);
  const mailboxId = `mbx-${'1a'.repeat(32)}`;
  const pairingEpoch = 7;
  const deviceBearer = 'nomad-device-bearer-7-opaque-secret';
  const nonce = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  const sharedSecret = await deriveSharedSecret(
    hostAgreementKeyPair.privateKey,
    deviceAgreementKeyPair.publicKey,
  );
  const vaultKey = await deriveVaultKey(sharedSecret, mailboxId, pairingEpoch);
  const aesKey = await subtle.importKey(
    'raw',
    ownBytes(vaultKey),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const wrappedBearer = await subtle.encrypt(
    { name: 'AES-GCM', iv: ownBytes(nonce), tagLength: 128 },
    aesKey,
    ownBytes(encoder.encode(deviceBearer)),
  );
  const bundle: ProvisioningBundle = {
    schema: 'nomad.m3e.provisioning-bundle.v1',
    device_alias: 'phone_alpha',
    pairing_epoch: pairingEpoch,
    mailbox_id: mailboxId,
    relay_base_url: 'https://relay.nomad.example',
    host_signing_public_key_sec1: toBase64Url(hostSigningPublicKeySec1),
    host_agreement_public_key_sec1: toBase64Url(hostAgreementPublicKeySec1),
    wrapped_device_bearer: toBase64Url(new Uint8Array(wrappedBearer)),
    wrap_nonce: toBase64Url(nonce),
    issued_at: '2026-08-27T08:00:00Z',
  };
  const provisioningSignature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    hostSigningKeyPair.privateKey,
    ownBytes(encoder.encode(canonicalJson(bundle))),
  );
  const signedBundle: SignedProvisioningBundle = {
    schema: 'nomad.m3e.signed-provisioning-bundle.v1',
    bundle,
    provisioning_signature_p1363: toBase64Url(new Uint8Array(provisioningSignature)),
  };
  const comparisonContext: BrowserVaultComparisonContext = {
    comparison_code: '482913',
    host_signing_commitment: await computeKeyCommitment(hostSigningPublicKeySec1),
    host_agreement_commitment: await computeKeyCommitment(hostAgreementPublicKeySec1),
    device_signing_commitment: await computeKeyCommitment(deviceSigningPublicKeySec1),
    device_agreement_commitment: await computeKeyCommitment(deviceAgreementPublicKeySec1),
  };

  return {
    comparisonContext,
    deviceBearer,
    hostAgreementKeyPair,
    signedBundle,
    persistInput: {
      deviceSigningKeyPair,
      deviceAgreementKeyPair,
      signedProvisioningBundle: signedBundle,
      comparisonContext,
    },
  };
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

function ownBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value);
}

function toBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString('hex');
}

function opaqueFrame(
  mailboxId: string,
  direction: 'host_to_device' | 'device_to_host',
  epoch: number,
  sequence: number,
) {
  return {
    schema: 'nomad.relay.opaque-frame.v2' as const,
    crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1' as const,
    mailbox_id: mailboxId,
    direction,
    epoch,
    sequence,
    message_id: `msg-${String(sequence).padStart(32, '0')}`,
    issued_at: 1_700_000_000,
    expires_at: 1_700_000_600,
    nonce: 'AAAAAAAAAAAAAAAA',
    ciphertext: 'ciphertext',
  };
}
