import { describe, expect, it, vi } from 'vitest';

import type {
  BrowserVault,
  BrowserVaultPersistInput,
  BrowserVaultSession,
  SignedProvisioningBundle,
} from './browser-vault';
import {
  canonicalJson,
  computeKeyCommitment,
  deriveSharedSecret,
  exportPublicKeySec1,
  generateRuntimeP256AgreementKeyPair,
  generateRuntimeP256SigningKeyPair,
  importAgreementPublicKeySec1,
  importSigningPublicKeySec1,
} from './crypto';
import { PairingClient } from './pairing-client';

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

describe('M3-E pairing client', () => {
  it('clears the join fragment immediately and produces the dual-proof comparison transcript', async () => {
    const joinId = 'join_12345678';
    const joinSecret = toBase64Url(Uint8Array.from({ length: 32 }, (_, index) => index + 1));
    const challengeId = 'challenge_123456';
    const challengeBytes = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
    const prospectiveEpoch = 9;
    const hostSigningKeyPair = await generateRuntimeP256SigningKeyPair();
    const hostAgreementKeyPair = await generateRuntimeP256AgreementKeyPair();
    const hostSigningPublicKeySec1 = await exportPublicKeySec1(hostSigningKeyPair.publicKey);
    const hostAgreementPublicKeySec1 = await exportPublicKeySec1(hostAgreementKeyPair.publicKey);
    const signedBundle = placeholderSignedBundle(
      hostSigningPublicKeySec1,
      hostAgreementPublicKeySec1,
      prospectiveEpoch,
    );
    let storedSession: BrowserVaultSession | null = null;
    const persistProvisionedDevice = vi.fn(async (input: BrowserVaultPersistInput) => {
      storedSession = {
      comparisonCode: input.comparisonContext.comparison_code,
      bundle: input.signedProvisioningBundle.bundle,
      signedProvisioningBundle: input.signedProvisioningBundle,
      deviceBearer: 'restored-only-in-memory',
      deviceSigningKeyPair: input.deviceSigningKeyPair,
      deviceAgreementKeyPair: input.deviceAgreementKeyPair,
      transport: {
        host_to_device_applied_through_sequence: 0,
        device_to_host_next_sequence: 1,
      },
      } satisfies BrowserVaultSession;
      return storedSession;
    });
    const restorePairedDevice = vi.fn(async () => {
      if (storedSession === null) throw new Error('not_persisted');
      return storedSession;
    });
    const close = vi.fn(async () => {});
    const clear = vi.fn(async () => {});
    const vault = { persistProvisionedDevice, restorePairedDevice, close, clear } as unknown as BrowserVault;
    const requests: Array<{ url: string; init: RequestInit; body: Record<string, unknown> }> = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const requestInit = init ?? {};
      const body = JSON.parse(String(requestInit.body)) as Record<string, unknown>;
      requests.push({ url, init: requestInit, body });
      if (url.endsWith('/api/pairing/join/start')) {
        return jsonResponse({
          schema: 'nomad.m3e.pairing.start-response.v1',
          challenge_id: challengeId,
          challenge_bytes_b64: toBase64Url(challengeBytes),
          prospective_epoch: prospectiveEpoch,
          host_signing_public_key_sec1: toBase64Url(hostSigningPublicKeySec1),
          host_agreement_public_key_sec1: toBase64Url(hostAgreementPublicKeySec1),
          issued_at: '2026-08-27T08:00:00Z',
          expires_at: '2026-08-27T08:02:00Z',
        });
      }
      if (url.endsWith('/api/pairing/join/confirm')) {
        return jsonResponse({
          schema: 'nomad.m3e.pairing.confirm-response.v1',
          signed_provisioning_bundle: signedBundle,
        });
      }
      return jsonResponse({
        schema: 'nomad.m3e.pairing.complete-response.v1',
        device_alias: signedBundle.bundle.device_alias,
        pairing_epoch: prospectiveEpoch,
      });
    }) as unknown as typeof fetch;
    const replaceState = vi.fn();
    const client = new PairingClient({
      baseUrl: 'https://pair.nomad.example',
      fetchImpl,
      historyImpl: { replaceState },
      locationImpl: {
        href: `https://pair.nomad.example/j/${joinId}?source=qr#${joinSecret}`,
        origin: 'https://pair.nomad.example',
        pathname: `/j/${joinId}`,
        search: '?source=qr',
        hash: `#${joinSecret}`,
      },
      nowImpl: () => Date.parse('2026-08-27T08:00:30Z'),
      vault,
    });

    const startPromise = client.startFromCurrentLocation();
    expect(replaceState).toHaveBeenCalledOnce();
    expect(replaceState).toHaveBeenCalledWith(
      null,
      '',
      `https://pair.nomad.example/j/${joinId}?source=qr`,
    );

    const started = await startPromise;
    expect(requests).toHaveLength(1);
    expect(requests[0].body.join_secret).toBe(joinSecret);
    expect(requests[0].body).not.toHaveProperty('join_secert');
    expect(requests[0].init.credentials).toBe('include');

    const deviceSigningPublicKeySec1 = fromBase64Url(
      expectString(requests[0].body.device_signing_public_key_sec1),
    );
    const deviceAgreementPublicKeySec1 = fromBase64Url(
      expectString(requests[0].body.device_agreement_public_key_sec1),
    );
    const transcriptHash = await independentTranscriptHash({
      joinId,
      challengeId,
      challengeBytes,
      prospectiveEpoch,
      hostSigningPublicKeySec1,
      hostAgreementPublicKeySec1,
      deviceSigningPublicKeySec1,
      deviceAgreementPublicKeySec1,
    });
    const comparisonDigest = await sha256(concatBytes(
      encoder.encode('nomad.m3e.compare.v1\n'),
      transcriptHash,
    ));
    const expectedComparisonCode = (
      ((comparisonDigest[0] << 16) | (comparisonDigest[1] << 8) | comparisonDigest[2])
      % 1_000_000
    ).toString().padStart(6, '0');
    expect(started.comparisonCode).toBe(expectedComparisonCode);

    const confirmed = await client.confirm();
    expect(confirmed.comparisonCode).toBe(expectedComparisonCode);
    expect(requests).toHaveLength(3);
    const confirmBody = requests[1].body;
    expect(confirmBody).toEqual(expect.objectContaining({
      challenge_id: challengeId,
      expected_epoch: prospectiveEpoch,
    }));
    expect(confirmBody).not.toHaveProperty('device_bearer');
    const completeBody = requests[2].body;
    expect(requests[2].url).toMatch(/\/api\/pairing\/join\/complete$/);
    expect(completeBody).toEqual({
      schema: 'nomad.m3e.pairing.vault-commit.v1',
      challenge_id: challengeId,
      expected_epoch: prospectiveEpoch,
      device_vault_signature_p1363: expect.any(String),
    });

    const signingProofDigest = await sha256(concatBytes(
      encoder.encode('nomad.m3e.signing-proof.v1\n'),
      transcriptHash,
    ));
    const deviceSigningPublicKey = await importSigningPublicKeySec1(deviceSigningPublicKeySec1);
    await expect(subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      deviceSigningPublicKey,
      ownBytes(fromBase64Url(expectString(confirmBody.device_signing_signature_p1363))),
      ownBytes(signingProofDigest),
    )).resolves.toBe(true);

    const deviceAgreementPublicKey = await importAgreementPublicKeySec1(deviceAgreementPublicKeySec1);
    const sharedSecret = await deriveSharedSecret(
      hostAgreementKeyPair.privateKey,
      deviceAgreementPublicKey,
    );
    const agreementProofKeyBytes = await derivePairingProofKey(sharedSecret);
    const agreementProofKey = await subtle.importKey(
      'raw',
      ownBytes(agreementProofKeyBytes),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    await expect(subtle.verify(
      'HMAC',
      agreementProofKey,
      ownBytes(fromBase64Url(expectString(confirmBody.device_agreement_mac))),
      ownBytes(transcriptHash),
    )).resolves.toBe(true);

    expect(persistProvisionedDevice).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
    expect(restorePairedDevice).toHaveBeenCalledOnce();
    const persistInput = persistProvisionedDevice.mock.calls[0][0];
    expect(persistInput.deviceSigningKeyPair.privateKey.extractable).toBe(false);
    expect(persistInput.deviceAgreementKeyPair.privateKey.extractable).toBe(false);
    expect(persistInput.comparisonContext).toEqual({
      comparison_code: expectedComparisonCode,
      host_signing_commitment: await computeKeyCommitment(hostSigningPublicKeySec1),
      host_agreement_commitment: await computeKeyCommitment(hostAgreementPublicKeySec1),
      device_signing_commitment: await computeKeyCommitment(deviceSigningPublicKeySec1),
      device_agreement_commitment: await computeKeyCommitment(deviceAgreementPublicKeySec1),
    });

    const signedBundleDigest = await sha256(encoder.encode(canonicalJson(signedBundle)));
    const vaultCommitDigest = await sha256(concatBytes(
      encoder.encode('nomad.m3e.vault-commit.v1\n'),
      signedBundleDigest,
    ));
    await expect(subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      deviceSigningPublicKey,
      ownBytes(fromBase64Url(expectString(completeBody.device_vault_signature_p1363))),
      ownBytes(vaultCommitDigest),
    )).resolves.toBe(true);
  });

  it('keeps the fragment cleared when join start fails', async () => {
    const replaceState = vi.fn();
    const joinSecret = toBase64Url(Uint8Array.from({ length: 32 }, (_, index) => index));
    const client = new PairingClient({
      baseUrl: 'https://pair.nomad.example',
      fetchImpl: vi.fn(async () => {
        throw new Error('offline');
      }) as unknown as typeof fetch,
      historyImpl: { replaceState },
      locationImpl: {
        href: `https://pair.nomad.example/j/join_12345678#${joinSecret}`,
        origin: 'https://pair.nomad.example',
        pathname: '/j/join_12345678',
        search: '',
        hash: `#${joinSecret}`,
      },
      vault: {} as BrowserVault,
    });

    const startPromise = client.startFromCurrentLocation();
    expect(replaceState).toHaveBeenCalledWith(
      null,
      '',
      'https://pair.nomad.example/j/join_12345678',
    );
    await expect(startPromise).rejects.toMatchObject({ code: 'PAIRING_NETWORK_ERROR' });
    expect(replaceState).toHaveBeenCalledOnce();
  });

  it('clears a malformed secret fragment before rejecting the join URL', async () => {
    const replaceState = vi.fn();
    const client = new PairingClient({
      baseUrl: 'https://pair.nomad.example',
      fetchImpl: vi.fn() as unknown as typeof fetch,
      historyImpl: { replaceState },
      locationImpl: {
        href: 'https://pair.nomad.example/j/join_12345678#secret+not-base64url',
        origin: 'https://pair.nomad.example',
        pathname: '/j/join_12345678',
        search: '',
        hash: '#secret+not-base64url',
      },
      vault: {} as BrowserVault,
    });

    await expect(client.startFromCurrentLocation()).rejects.toMatchObject({
      code: 'JOIN_SECRET_REQUIRED',
    });
    expect(replaceState).toHaveBeenCalledWith(
      null,
      '',
      'https://pair.nomad.example/j/join_12345678',
    );
  });

  it('requires canonical 32-byte join secrets before making a request', async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const client = directClient(fetchImpl);

    for (const secret of [
      toBase64Url(new Uint8Array(31)),
      toBase64Url(new Uint8Array(33)),
      toBase64Url(new Uint8Array(32)) + '=',
    ]) {
      await expect(client.start('join_12345678', secret)).rejects.toMatchObject({
        code: 'INVALID_JOIN_SECRET',
      });
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('rejects duplicate keys at start, confirm, and nested bundle levels', async () => {
    const startDuplicate = '{"schema":"nomad.m3e.pairing.start-response.v1","schema":"nomad.m3e.pairing.start-response.v1"}';
    await expect(startWithRawResponse(startDuplicate)).rejects.toMatchObject({
      code: 'PAIRING_INVALID_RESPONSE',
    });

    const fixture = await startForConfirm();
    const confirmDuplicate = '{"schema":"nomad.m3e.pairing.confirm-response.v1","schema":"nomad.m3e.pairing.confirm-response.v1","signed_provisioning_bundle":{}}';
    fixture.setConfirmBody(confirmDuplicate);
    await expect(fixture.client.confirm()).rejects.toMatchObject({ code: 'PAIRING_INVALID_RESPONSE' });

    const nestedFixture = await startForConfirm();
    const validBundle = placeholderSignedBundle(
      nestedFixture.hostSigningPublicKeySec1,
      nestedFixture.hostAgreementPublicKeySec1,
      9,
    );
    const bundleText = JSON.stringify(validBundle);
    const duplicateNestedBundle = bundleText.replace(
      '"device_alias":"device-phone_alpha"',
      '"device_alias":"device-phone_alpha","device_alias":"device-phone_beta"',
    );
    nestedFixture.setConfirmBody(
      '{"schema":"nomad.m3e.pairing.confirm-response.v1","signed_provisioning_bundle":' + duplicateNestedBundle + '}',
    );
    await expect(nestedFixture.client.confirm()).rejects.toMatchObject({ code: 'PAIRING_INVALID_RESPONSE' });
  });

  it('rejects oversized pairing responses before JSON decoding', async () => {
    await expect(startWithRawResponse('{"padding":"' + 'x'.repeat(65 * 1024) + '"}')).rejects.toMatchObject({
      code: 'PAIRING_INVALID_RESPONSE',
    });
  });

  it('requires a canonical 32-byte challenge and live canonical UTC lifetime at most 120 seconds', async () => {
    const validChallenge = toBase64Url(new Uint8Array(32));
    const invalidPayloads = [
      { challenge_bytes_b64: toBase64Url(new Uint8Array(31)) },
      { challenge_bytes_b64: validChallenge + '=' },
      { issued_at: '2026-08-27T08:00:00.000Z' },
      { expires_at: '2026-08-27T08:02:00.001Z' },
      { expires_at: '2026-08-27T10:02:00+02:00' },
      { issued_at: '2026-08-27T08:02:00Z', expires_at: '2026-08-27T08:01:59Z' },
      { expires_at: '2026-08-27T08:00:30Z' },
    ];

    for (const override of invalidPayloads) {
      await expect(startWithPayload(override)).rejects.toMatchObject({
        code: 'INVALID_PAIRING_RESPONSE',
      });
    }
  });

  it('aborts and clears the vault when persistence or Host completion fails', async () => {
    for (const failureStage of ['persist', 'complete'] as const) {
      const lifecycle = await lifecycleFixture(failureStage);
      await expect(lifecycle.client.confirm()).rejects.toThrow();

      expect(lifecycle.paths()).toEqual([
        '/api/pairing/join/start',
        '/api/pairing/join/confirm',
        ...(failureStage === 'complete' ? ['/api/pairing/join/complete'] : []),
        '/api/pairing/join/abort',
      ]);
      expect(lifecycle.abortBodies()).toEqual([{
        schema: 'nomad.m3e.pairing.abort.v1',
        challenge_id: 'challenge_123456',
        expected_epoch: 9,
      }]);
      expect(lifecycle.clear).toHaveBeenCalled();
      await expect(lifecycle.client.confirm()).rejects.toMatchObject({ code: 'PAIRING_NOT_STARTED' });
    }
  });

  it('rejects an expired pending challenge before confirm and aborts fail closed', async () => {
    let nowMs = Date.parse('2026-08-27T08:00:30Z');
    const lifecycle = await lifecycleFixture('none', () => nowMs);
    nowMs = Date.parse('2026-08-27T08:02:00Z');

    await expect(lifecycle.client.confirm()).rejects.toMatchObject({ code: 'PAIRING_EXPIRED' });
    expect(lifecycle.paths()).toEqual([
      '/api/pairing/join/start',
      '/api/pairing/join/abort',
    ]);
    expect(lifecycle.clear).toHaveBeenCalledOnce();
  });

  it('provides async best-effort abort for a started pairing', async () => {
    const lifecycle = await lifecycleFixture('none');

    await lifecycle.client.abortPending();

    expect(lifecycle.paths()).toEqual([
      '/api/pairing/join/start',
      '/api/pairing/join/abort',
    ]);
    expect(lifecycle.clear).toHaveBeenCalledOnce();
    await expect(lifecycle.client.confirm()).rejects.toMatchObject({ code: 'PAIRING_NOT_STARTED' });
  });
});

function placeholderSignedBundle(
  hostSigningPublicKeySec1: Uint8Array,
  hostAgreementPublicKeySec1: Uint8Array,
  pairingEpoch: number,
): SignedProvisioningBundle {
  return {
    schema: 'nomad.m3e.signed-provisioning-bundle.v1',
    bundle: {
      schema: 'nomad.m3e.provisioning-bundle.v1',
      device_alias: 'device-phone_alpha',
      pairing_epoch: pairingEpoch,
      mailbox_id: `mbx-${'2b'.repeat(32)}`,
      relay_base_url: 'https://relay.nomad.example',
      host_signing_public_key_sec1: toBase64Url(hostSigningPublicKeySec1),
      host_agreement_public_key_sec1: toBase64Url(hostAgreementPublicKeySec1),
      wrapped_device_bearer: toBase64Url(new Uint8Array(17)),
      wrap_nonce: 'AAAAAAAAAAAAAAAA',
      issued_at: '2026-08-27T08:01:00Z',
    },
    provisioning_signature_p1363: toBase64Url(new Uint8Array(64)),
  };
}

async function independentTranscriptHash(input: {
  joinId: string;
  challengeId: string;
  challengeBytes: Uint8Array;
  prospectiveEpoch: number;
  hostSigningPublicKeySec1: Uint8Array;
  hostAgreementPublicKeySec1: Uint8Array;
  deviceSigningPublicKeySec1: Uint8Array;
  deviceAgreementPublicKeySec1: Uint8Array;
}): Promise<Uint8Array> {
  const fields = [
    'nomad.m3e.pairing.v1\n',
    input.joinId,
    '\n',
    input.challengeId,
    '\n',
    toHex(await sha256(input.challengeBytes)),
    '\n',
    String(input.prospectiveEpoch),
    '\n',
    await computeKeyCommitment(input.hostSigningPublicKeySec1),
    '\n',
    await computeKeyCommitment(input.hostAgreementPublicKeySec1),
    '\n',
    await computeKeyCommitment(input.deviceSigningPublicKeySec1),
    '\n',
    await computeKeyCommitment(input.deviceAgreementPublicKeySec1),
  ];
  return sha256(encoder.encode(fields.join('')));
}

async function derivePairingProofKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
  const hkdfKey = await subtle.importKey('raw', ownBytes(sharedSecret), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: ownBytes(new Uint8Array([])),
      info: ownBytes(encoder.encode('nomad.m3e.agreement-proof.v1')),
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(bits);
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function directClient(fetchImpl: typeof fetch): PairingClient {
  return new PairingClient({
    baseUrl: 'https://pair.nomad.example',
    fetchImpl,
    historyImpl: { replaceState: vi.fn() },
    locationImpl: {
      href: 'https://pair.nomad.example/',
      origin: 'https://pair.nomad.example',
      pathname: '/',
      search: '',
      hash: '',
    },
    nowImpl: () => Date.parse('2026-08-27T08:00:30Z'),
    vault: {} as BrowserVault,
  });
}

async function startWithRawResponse(raw: string): Promise<unknown> {
  const fetchImpl = vi.fn(async () => new Response(raw, {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })) as unknown as typeof fetch;
  return directClient(fetchImpl).start('join_12345678', toBase64Url(new Uint8Array(32)));
}

async function startWithPayload(overrides: Record<string, unknown>): Promise<unknown> {
  const hostSigning = await generateRuntimeP256SigningKeyPair();
  const hostAgreement = await generateRuntimeP256AgreementKeyPair();
  const payload = {
    schema: 'nomad.m3e.pairing.start-response.v1',
    challenge_id: 'challenge_123456',
    challenge_bytes_b64: toBase64Url(new Uint8Array(32)),
    prospective_epoch: 9,
    host_signing_public_key_sec1: toBase64Url(await exportPublicKeySec1(hostSigning.publicKey)),
    host_agreement_public_key_sec1: toBase64Url(await exportPublicKeySec1(hostAgreement.publicKey)),
    issued_at: '2026-08-27T08:00:00Z',
    expires_at: '2026-08-27T08:02:00Z',
    ...overrides,
  };
  const fetchImpl = vi.fn(async () => jsonResponse(payload)) as unknown as typeof fetch;
  return directClient(fetchImpl).start('join_12345678', toBase64Url(new Uint8Array(32)));
}

async function startForConfirm() {
  const hostSigning = await generateRuntimeP256SigningKeyPair();
  const hostAgreement = await generateRuntimeP256AgreementKeyPair();
  const hostSigningPublicKeySec1 = await exportPublicKeySec1(hostSigning.publicKey);
  const hostAgreementPublicKeySec1 = await exportPublicKeySec1(hostAgreement.publicKey);
  let confirmBody = '{}';
  const fetchImpl = vi.fn(async (input: string | URL | Request) => {
    if (String(input).endsWith('/start')) {
      return jsonResponse({
        schema: 'nomad.m3e.pairing.start-response.v1',
        challenge_id: 'challenge_123456',
        challenge_bytes_b64: toBase64Url(new Uint8Array(32)),
        prospective_epoch: 9,
        host_signing_public_key_sec1: toBase64Url(hostSigningPublicKeySec1),
        host_agreement_public_key_sec1: toBase64Url(hostAgreementPublicKeySec1),
        issued_at: '2026-08-27T08:00:00Z',
        expires_at: '2026-08-27T08:02:00Z',
      });
    }
    return new Response(confirmBody, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;
  const client = directClient(fetchImpl);
  await client.start('join_12345678', toBase64Url(new Uint8Array(32)));
  return {
    client,
    hostSigningPublicKeySec1,
    hostAgreementPublicKeySec1,
    setConfirmBody(value: string) {
      confirmBody = value;
    },
  };
}

async function lifecycleFixture(
  failureStage: 'none' | 'persist' | 'complete',
  nowImpl: () => number = () => Date.parse('2026-08-27T08:00:30Z'),
) {
  const hostSigning = await generateRuntimeP256SigningKeyPair();
  const hostAgreement = await generateRuntimeP256AgreementKeyPair();
  const hostSigningPublicKeySec1 = await exportPublicKeySec1(hostSigning.publicKey);
  const hostAgreementPublicKeySec1 = await exportPublicKeySec1(hostAgreement.publicKey);
  const signedBundle = placeholderSignedBundle(hostSigningPublicKeySec1, hostAgreementPublicKeySec1, 9);
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  const clear = vi.fn(async () => {});
  const close = vi.fn(async () => {});
  let persisted: BrowserVaultSession | null = null;
  const vault = {
    clear,
    close,
    async persistProvisionedDevice(input: BrowserVaultPersistInput) {
      if (failureStage === 'persist') throw new Error('persist_failed');
      persisted = {
        comparisonCode: input.comparisonContext.comparison_code,
        bundle: input.signedProvisioningBundle.bundle,
        signedProvisioningBundle: input.signedProvisioningBundle,
        deviceBearer: 'memory-only',
        deviceSigningKeyPair: input.deviceSigningKeyPair,
        deviceAgreementKeyPair: input.deviceAgreementKeyPair,
        transport: {
          host_to_device_applied_through_sequence: 0,
          device_to_host_next_sequence: 1,
        },
      };
      return persisted;
    },
    async restorePairedDevice() {
      if (persisted === null) throw new Error('restore_failed');
      return persisted;
    },
  } as unknown as BrowserVault;
  const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push({ path, body });
    if (path.endsWith('/start')) {
      return jsonResponse({
        schema: 'nomad.m3e.pairing.start-response.v1',
        challenge_id: 'challenge_123456',
        challenge_bytes_b64: toBase64Url(new Uint8Array(32)),
        prospective_epoch: 9,
        host_signing_public_key_sec1: toBase64Url(hostSigningPublicKeySec1),
        host_agreement_public_key_sec1: toBase64Url(hostAgreementPublicKeySec1),
        issued_at: '2026-08-27T08:00:00Z',
        expires_at: '2026-08-27T08:02:00Z',
      });
    }
    if (path.endsWith('/confirm')) {
      return jsonResponse({
        schema: 'nomad.m3e.pairing.confirm-response.v1',
        signed_provisioning_bundle: signedBundle,
      });
    }
    if (path.endsWith('/complete')) {
      if (failureStage === 'complete') return jsonResponse({ error: 'complete_failed' }, 503);
      return jsonResponse({
        schema: 'nomad.m3e.pairing.complete-response.v1',
        device_alias: signedBundle.bundle.device_alias,
        pairing_epoch: 9,
      });
    }
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  const client = new PairingClient({
    baseUrl: 'https://pair.nomad.example',
    fetchImpl,
    historyImpl: { replaceState: vi.fn() },
    locationImpl: {
      href: 'https://pair.nomad.example/',
      origin: 'https://pair.nomad.example',
      pathname: '/',
      search: '',
      hash: '',
    },
    nowImpl,
    vault,
  });
  await client.start('join_12345678', toBase64Url(new Uint8Array(32)));
  return {
    client,
    clear,
    paths: () => calls.map((call) => call.path),
    abortBodies: () => calls.filter((call) => call.path.endsWith('/abort')).map((call) => call.body),
  };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', ownBytes(value)));
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

function expectString(value: unknown): string {
  expect(typeof value).toBe('string');
  return value as string;
}

function ownBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value);
}

function toBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString('hex');
}
