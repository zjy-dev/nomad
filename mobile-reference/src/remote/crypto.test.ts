import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  RemoteCryptoError,
  canonicalJson,
  computeKeyCommitment,
  decodePaddedPlaintext,
  deriveDeterministicNonce,
  deriveDeterministicNonceAsync,
  deriveDirectionKeyBytes,
  deriveSalt,
  deriveSharedSecret,
  encryptRemoteFrame,
  exportPublicKeySec1,
  generateRuntimeP256AgreementKeyPair,
  generateRuntimeP256SigningKeyPair,
  decryptRemoteFrame,
  importAgreementPrivateKeyPkcs8,
  parseAndValidateRemoteVector,
} from './crypto';

describe('remote crypto codec', () => {
  it('generates non-extractable runtime key pairs', async () => {
    const signing = await generateRuntimeP256SigningKeyPair();
    const agreement = await generateRuntimeP256AgreementKeyPair();

    expect(signing.privateKey.extractable).toBe(false);
    expect(agreement.privateKey.extractable).toBe(false);
    expect(signing.publicKey.type).toBe('public');
    expect(agreement.publicKey.type).toBe('public');
  });

  it('derives deterministic nonce bytes for both sync and async paths', async () => {
    const host = deriveDeterministicNonce('host_to_device', 7);
    const hostAsync = await deriveDeterministicNonceAsync('host_to_device', 7);
    const device = deriveDeterministicNonce('device_to_host', 9);
    const deviceAsync = await deriveDeterministicNonceAsync('device_to_host', 9);

    expect(Array.from(host)).toEqual(Array.from(hostAsync));
    expect(Array.from(device)).toEqual(Array.from(deviceAsync));
    expect(toHex(host.slice(0, 4))).toBe('35dcaba9');
    expect(toHex(device.slice(0, 4))).toBe('2ead7703');
    expect(toHex(host.slice(4))).toBe('0000000000000007');
    expect(toHex(device.slice(4))).toBe('0000000000000009');
  });

  it('derives the same shared secret and salt-bound direction keys on both sides', async () => {
    const hostSigning = await generateRuntimeP256SigningKeyPair();
    const hostAgreement = await generateRuntimeP256AgreementKeyPair();
    const deviceSigning = await generateRuntimeP256SigningKeyPair();
    const deviceAgreement = await generateRuntimeP256AgreementKeyPair();

    const hostSigningSec1 = await exportPublicKeySec1(hostSigning.publicKey);
    const hostAgreementSec1 = await exportPublicKeySec1(hostAgreement.publicKey);
    const deviceSigningSec1 = await exportPublicKeySec1(deviceSigning.publicKey);
    const deviceAgreementSec1 = await exportPublicKeySec1(deviceAgreement.publicKey);

    const context = {
      mailboxId: mailboxId(),
      epoch: 3,
      hostSigningCommitment: await computeKeyCommitment(hostSigningSec1),
      hostAgreementCommitment: await computeKeyCommitment(hostAgreementSec1),
      deviceSigningCommitment: await computeKeyCommitment(deviceSigningSec1),
      deviceAgreementCommitment: await computeKeyCommitment(deviceAgreementSec1),
    };

    const hostSecret = await deriveSharedSecret(hostAgreement.privateKey, deviceAgreement.publicKey);
    const deviceSecret = await deriveSharedSecret(deviceAgreement.privateKey, hostAgreement.publicKey);
    expect(toHex(hostSecret)).toBe(toHex(deviceSecret));

    const salt = await deriveSalt(context);
    const hostToDeviceA = await deriveDirectionKeyBytes(hostSecret, salt, 'host_to_device');
    const hostToDeviceB = await deriveDirectionKeyBytes(deviceSecret, salt, 'host_to_device');
    const deviceToHostA = await deriveDirectionKeyBytes(hostSecret, salt, 'device_to_host');
    const deviceToHostB = await deriveDirectionKeyBytes(deviceSecret, salt, 'device_to_host');

    expect(toHex(hostToDeviceA)).toBe(toHex(hostToDeviceB));
    expect(toHex(deviceToHostA)).toBe(toHex(deviceToHostB));
    expect(toHex(hostToDeviceA)).not.toBe(toHex(deviceToHostA));
  });

  it('round-trips host_to_device and device_to_host frames with generated keys', async () => {
    const fixture = await createFixture();

    const hostPlaintext = { zebra: 1, alpha: ['x', true], nested: { b: 2, a: 1 } };
    const hostFrame = frame({
      mailbox_id: fixture.context.mailboxId,
      direction: 'host_to_device',
      epoch: fixture.context.epoch,
      sequence: 11,
      message_id: messageId('11'),
      issued_at: 1700000000,
      expires_at: 1700000600,
      nonce: 'placeholder',
    });
    const hostEncrypted = await encryptRemoteFrame({
      frame: hostFrame,
      plaintext: hostPlaintext,
      senderSigningPrivateKey: fixture.host.signing.privateKey,
      senderSigningPublicKeySec1: fixture.host.signingSec1,
      senderAgreementPrivateKey: fixture.host.agreement.privateKey,
      senderAgreementPublicKeySec1: fixture.host.agreementSec1,
      recipientAgreementPublicKey: fixture.device.agreement.publicKey,
      context: fixture.context,
      paddingBytes: new Uint8Array(512 - 4 - new TextEncoder().encode(canonicalJson(hostPlaintext)).length),
    });
    const hostDecrypted = await decryptRemoteFrame({
      frame: hostEncrypted.frame,
      recipientAgreementPrivateKey: fixture.device.agreement.privateKey,
      context: fixture.context,
      expectedSenderSigningCommitment: fixture.context.hostSigningCommitment,
      expectedSenderAgreementCommitment: fixture.context.hostAgreementCommitment,
    });

    expect(hostDecrypted.plaintext).toEqual(hostPlaintext);
    expect(hostDecrypted.canonicalPlaintextJson).toBe(canonicalJson(hostPlaintext));
    expect(toHex(hostDecrypted.senderSigningPublicKeySec1)).toBe(toHex(fixture.host.signingSec1));
    expect(toHex(hostDecrypted.senderAgreementPublicKeySec1)).toBe(toHex(fixture.host.agreementSec1));
    expect(toHex(hostDecrypted.nonceBytes)).toBe(toHex(await deriveDeterministicNonceAsync('host_to_device', 11)));
    expect(toHex(hostEncrypted.symmetricKeyBytes)).toBe(toHex(hostDecrypted.symmetricKeyBytes));
    expect(toHex(hostEncrypted.aad)).toBe(toHex(hostDecrypted.aad));

    const devicePlaintext = { ack: true, seq: 11, notes: ['ok'] };
    const deviceFrame = frame({
      mailbox_id: fixture.context.mailboxId,
      direction: 'device_to_host',
      epoch: fixture.context.epoch,
      sequence: 12,
      message_id: messageId('12'),
      issued_at: 1700000001,
      expires_at: 1700000601,
      nonce: 'placeholder',
    });
    const deviceEncrypted = await encryptRemoteFrame({
      frame: deviceFrame,
      plaintext: devicePlaintext,
      senderSigningPrivateKey: fixture.device.signing.privateKey,
      senderSigningPublicKeySec1: fixture.device.signingSec1,
      senderAgreementPrivateKey: fixture.device.agreement.privateKey,
      senderAgreementPublicKeySec1: fixture.device.agreementSec1,
      recipientAgreementPublicKey: fixture.host.agreement.publicKey,
      context: fixture.context,
      paddingBytes: new Uint8Array(512 - 4 - new TextEncoder().encode(canonicalJson(devicePlaintext)).length),
    });
    const deviceDecrypted = await decryptRemoteFrame({
      frame: deviceEncrypted.frame,
      recipientAgreementPrivateKey: fixture.host.agreement.privateKey,
      context: fixture.context,
      expectedSenderSigningCommitment: fixture.context.deviceSigningCommitment,
      expectedSenderAgreementCommitment: fixture.context.deviceAgreementCommitment,
    });

    expect(deviceDecrypted.plaintext).toEqual(devicePlaintext);
    expect(deviceDecrypted.canonicalPlaintextJson).toBe(canonicalJson(devicePlaintext));
    expect(toHex(deviceEncrypted.symmetricKeyBytes)).toBe(toHex(deviceDecrypted.symmetricKeyBytes));
  });

  it('fails closed on nonce, commitment, and ciphertext mutations', async () => {
    const fixture = await createFixture();
    const plaintext = { msg: 'hello', step: 1 };
    const original = await encryptRemoteFrame({
      frame: frame({
        mailbox_id: fixture.context.mailboxId,
        direction: 'host_to_device',
        epoch: fixture.context.epoch,
        sequence: 21,
        message_id: messageId('21'),
        issued_at: 1700000010,
        expires_at: 1700000610,
        nonce: 'placeholder',
      }),
      plaintext,
      senderSigningPrivateKey: fixture.host.signing.privateKey,
      senderSigningPublicKeySec1: fixture.host.signingSec1,
      senderAgreementPrivateKey: fixture.host.agreement.privateKey,
      senderAgreementPublicKeySec1: fixture.host.agreementSec1,
      recipientAgreementPublicKey: fixture.device.agreement.publicKey,
      context: fixture.context,
      paddingBytes: new Uint8Array(512 - 4 - new TextEncoder().encode(canonicalJson(plaintext)).length),
    });

    await expect(
      decryptRemoteFrame({
        frame: { ...original.frame, nonce: original.frame.nonce.slice(0, -1) + flipBase64Tail(original.frame.nonce) },
        recipientAgreementPrivateKey: fixture.device.agreement.privateKey,
        context: fixture.context,
        expectedSenderSigningCommitment: fixture.context.hostSigningCommitment,
        expectedSenderAgreementCommitment: fixture.context.hostAgreementCommitment,
      }),
    ).rejects.toMatchObject({ code: 'NONCE_MISMATCH' } satisfies Partial<RemoteCryptoError>);

    await expect(
      decryptRemoteFrame({
        frame: original.frame,
        recipientAgreementPrivateKey: fixture.device.agreement.privateKey,
        context: fixture.context,
        expectedSenderSigningCommitment: fixture.context.deviceSigningCommitment,
        expectedSenderAgreementCommitment: fixture.context.hostAgreementCommitment,
      }),
    ).rejects.toMatchObject({
      code: 'SENDER_SIGNING_COMMITMENT_MISMATCH',
    } satisfies Partial<RemoteCryptoError>);

    await expect(
      decryptRemoteFrame({
        frame: { ...original.frame, ciphertext: mutateCiphertext(original.frame.ciphertext) },
        recipientAgreementPrivateKey: fixture.device.agreement.privateKey,
        context: fixture.context,
        expectedSenderSigningCommitment: fixture.context.hostSigningCommitment,
        expectedSenderAgreementCommitment: fixture.context.hostAgreementCommitment,
      }),
    ).rejects.toMatchObject({ code: 'SIGNATURE_INVALID' } satisfies Partial<RemoteCryptoError>);
  });

  it('rejects non-canonical padded plaintext payloads', () => {
    const encoded = encodeManualPaddedPlaintext('{"b":1,"a":2}', 512);
    expect(() => decodePaddedPlaintext(encoded)).toThrowError(
      expect.objectContaining({ code: 'NON_CANONICAL_JSON' }),
    );
  });

  it('rejects duplicate JSON keys in padded plaintext before canonicalization', () => {
    const encoded = encodeManualPaddedPlaintext('{"alpha":1,"alpha":2}', 512);
    expect(() => decodePaddedPlaintext(encoded)).toThrowError(
      expect.objectContaining({ code: 'PLAINTEXT_JSON_INVALID' }),
    );
  });

  it('fails closed when encrypt input frame mailbox or epoch does not match context', async () => {
    const fixture = await createFixture();
    const plaintext = { msg: 'hello' };

    await expect(
      encryptRemoteFrame({
        frame: frame({
          mailbox_id: otherMailboxId(),
          direction: 'host_to_device',
          epoch: fixture.context.epoch,
          sequence: 31,
          message_id: messageId('31'),
          issued_at: 1700000020,
          expires_at: 1700000620,
          nonce: 'placeholder',
        }),
        plaintext,
        senderSigningPrivateKey: fixture.host.signing.privateKey,
        senderSigningPublicKeySec1: fixture.host.signingSec1,
        senderAgreementPrivateKey: fixture.host.agreement.privateKey,
        senderAgreementPublicKeySec1: fixture.host.agreementSec1,
        recipientAgreementPublicKey: fixture.device.agreement.publicKey,
        context: fixture.context,
        paddingBytes: new Uint8Array(512 - 4 - new TextEncoder().encode(canonicalJson(plaintext)).length),
      }),
    ).rejects.toMatchObject({ code: 'FRAME_CONTEXT_MISMATCH' } satisfies Partial<RemoteCryptoError>);

    await expect(
      encryptRemoteFrame({
        frame: frame({
          mailbox_id: fixture.context.mailboxId,
          direction: 'host_to_device',
          epoch: fixture.context.epoch + 1,
          sequence: 32,
          message_id: messageId('32'),
          issued_at: 1700000021,
          expires_at: 1700000621,
          nonce: 'placeholder',
        }),
        plaintext,
        senderSigningPrivateKey: fixture.host.signing.privateKey,
        senderSigningPublicKeySec1: fixture.host.signingSec1,
        senderAgreementPrivateKey: fixture.host.agreement.privateKey,
        senderAgreementPublicKeySec1: fixture.host.agreementSec1,
        recipientAgreementPublicKey: fixture.device.agreement.publicKey,
        context: fixture.context,
        paddingBytes: new Uint8Array(512 - 4 - new TextEncoder().encode(canonicalJson(plaintext)).length),
      }),
    ).rejects.toMatchObject({ code: 'FRAME_CONTEXT_MISMATCH' } satisfies Partial<RemoteCryptoError>);
  });

  it('fails closed when decrypt input frame mailbox or epoch does not match context', async () => {
    const fixture = await createFixture();
    const plaintext = { msg: 'hello', step: 2 };
    const encrypted = await encryptRemoteFrame({
      frame: frame({
        mailbox_id: fixture.context.mailboxId,
        direction: 'host_to_device',
        epoch: fixture.context.epoch,
        sequence: 41,
        message_id: messageId('41'),
        issued_at: 1700000030,
        expires_at: 1700000630,
        nonce: 'placeholder',
      }),
      plaintext,
      senderSigningPrivateKey: fixture.host.signing.privateKey,
      senderSigningPublicKeySec1: fixture.host.signingSec1,
      senderAgreementPrivateKey: fixture.host.agreement.privateKey,
      senderAgreementPublicKeySec1: fixture.host.agreementSec1,
      recipientAgreementPublicKey: fixture.device.agreement.publicKey,
      context: fixture.context,
      paddingBytes: new Uint8Array(512 - 4 - new TextEncoder().encode(canonicalJson(plaintext)).length),
    });

    await expect(
      decryptRemoteFrame({
        frame: encrypted.frame,
        recipientAgreementPrivateKey: fixture.device.agreement.privateKey,
        context: {
          ...fixture.context,
          mailboxId: otherMailboxId(),
        },
        expectedSenderSigningCommitment: fixture.context.hostSigningCommitment,
        expectedSenderAgreementCommitment: fixture.context.hostAgreementCommitment,
      }),
    ).rejects.toMatchObject({ code: 'FRAME_CONTEXT_MISMATCH' } satisfies Partial<RemoteCryptoError>);

    await expect(
      decryptRemoteFrame({
        frame: encrypted.frame,
        recipientAgreementPrivateKey: fixture.device.agreement.privateKey,
        context: {
          ...fixture.context,
          epoch: fixture.context.epoch + 1,
        },
        expectedSenderSigningCommitment: fixture.context.hostSigningCommitment,
        expectedSenderAgreementCommitment: fixture.context.hostAgreementCommitment,
      }),
    ).rejects.toMatchObject({ code: 'FRAME_CONTEXT_MISMATCH' } satisfies Partial<RemoteCryptoError>);
  });

  it('decrypts the checked-in WebCrypto vector used by the Rust verifier', async () => {
    const raw = readFileSync(
      resolve(process.cwd(), '../contracts/vectors/remote-envelope-v2.json'),
      'utf8',
    );
    const vector = parseAndValidateRemoteVector(JSON.parse(raw));
    const deviceAgreement = await importAgreementPrivateKeyPkcs8(
      fromBase64UrlNoPad(vector.device_agreement_private_key_pkcs8),
    );
    const decrypted = await decryptRemoteFrame({
      frame: vector.frame,
      recipientAgreementPrivateKey: deviceAgreement,
      context: {
        mailboxId: vector.frame.mailbox_id,
        epoch: vector.frame.epoch,
        hostSigningCommitment: vector.host_signing_commitment,
        hostAgreementCommitment: vector.host_agreement_commitment,
        deviceSigningCommitment: vector.device_signing_commitment,
        deviceAgreementCommitment: vector.device_agreement_commitment,
      },
      expectedSenderSigningCommitment: vector.host_signing_commitment,
      expectedSenderAgreementCommitment: vector.host_agreement_commitment,
    });

    expect(decrypted.canonicalPlaintextJson).toBe(vector.canonical_plaintext_json);
    expect(toHex(decrypted.salt)).toBe(vector.salt);
    expect(toHex(decrypted.symmetricKeyBytes)).toBe(vector.host_to_device_key);
    expect(toHex(decrypted.nonceBytes)).toBe(vector.nonce);
    expect(toBase64UrlNoPad(decrypted.aad)).toBe(vector.aad);

    const rustDecrypted = await decryptRemoteFrame({
      frame: vector.rust_frame,
      recipientAgreementPrivateKey: deviceAgreement,
      context: {
        mailboxId: vector.rust_frame.mailbox_id,
        epoch: vector.rust_frame.epoch,
        hostSigningCommitment: vector.host_signing_commitment,
        hostAgreementCommitment: vector.host_agreement_commitment,
        deviceSigningCommitment: vector.device_signing_commitment,
        deviceAgreementCommitment: vector.device_agreement_commitment,
      },
      expectedSenderSigningCommitment: vector.host_signing_commitment,
      expectedSenderAgreementCommitment: vector.host_agreement_commitment,
    });
    expect(rustDecrypted.canonicalPlaintextJson).toBe(vector.canonical_plaintext_json);
  });

  it('decrypts the Rust vector without the Node Buffer global', async () => {
    const raw = readFileSync(
      resolve(process.cwd(), '../contracts/vectors/remote-envelope-v2.json'),
      'utf8',
    );
    const vector = parseAndValidateRemoteVector(JSON.parse(raw));
    const deviceAgreementPkcs8 = fromBase64UrlNoPad(
      vector.device_agreement_private_key_pkcs8,
    );
    const saved = globalThis.Buffer;
    Reflect.deleteProperty(globalThis, 'Buffer');
    try {
      const deviceAgreement = await importAgreementPrivateKeyPkcs8(
        deviceAgreementPkcs8,
      );
      await expect(decryptRemoteFrame({
        frame: vector.rust_frame,
        recipientAgreementPrivateKey: deviceAgreement,
        context: {
          mailboxId: vector.rust_frame.mailbox_id,
          epoch: vector.rust_frame.epoch,
          hostSigningCommitment: vector.host_signing_commitment,
          hostAgreementCommitment: vector.host_agreement_commitment,
          deviceSigningCommitment: vector.device_signing_commitment,
          deviceAgreementCommitment: vector.device_agreement_commitment,
        },
        expectedSenderSigningCommitment: vector.host_signing_commitment,
        expectedSenderAgreementCommitment: vector.host_agreement_commitment,
      })).resolves.toMatchObject({
        canonicalPlaintextJson: vector.canonical_plaintext_json,
      });
    } finally {
      globalThis.Buffer = saved;
    }
  });
});

async function createFixture() {
  const hostSigning = await generateRuntimeP256SigningKeyPair();
  const hostAgreement = await generateRuntimeP256AgreementKeyPair();
  const deviceSigning = await generateRuntimeP256SigningKeyPair();
  const deviceAgreement = await generateRuntimeP256AgreementKeyPair();

  const hostSigningSec1 = await exportPublicKeySec1(hostSigning.publicKey);
  const hostAgreementSec1 = await exportPublicKeySec1(hostAgreement.publicKey);
  const deviceSigningSec1 = await exportPublicKeySec1(deviceSigning.publicKey);
  const deviceAgreementSec1 = await exportPublicKeySec1(deviceAgreement.publicKey);

  return {
    host: {
      signing: hostSigning,
      agreement: hostAgreement,
      signingSec1: hostSigningSec1,
      agreementSec1: hostAgreementSec1,
    },
    device: {
      signing: deviceSigning,
      agreement: deviceAgreement,
      signingSec1: deviceSigningSec1,
      agreementSec1: deviceAgreementSec1,
    },
    context: {
      mailboxId: mailboxId(),
      epoch: 1,
      hostSigningCommitment: await computeKeyCommitment(hostSigningSec1),
      hostAgreementCommitment: await computeKeyCommitment(hostAgreementSec1),
      deviceSigningCommitment: await computeKeyCommitment(deviceSigningSec1),
      deviceAgreementCommitment: await computeKeyCommitment(deviceAgreementSec1),
    },
  };
}

function frame(overrides: {
  mailbox_id: string;
  direction: 'host_to_device' | 'device_to_host';
  epoch: number;
  sequence: number;
  message_id: string;
  issued_at: number;
  expires_at: number;
  nonce: string;
}) {
  return {
    schema: 'nomad.relay.opaque-frame.v2' as const,
    crypto_suite: 'p256-hkdf-sha256-aes256gcm-v1' as const,
    ...overrides,
  };
}

function mailboxId(): string {
  return 'mbx-' + 'ab'.repeat(32);
}

function otherMailboxId(): string {
  return 'mbx-' + 'cd'.repeat(32);
}

function messageId(byteHex: string): string {
  return 'msg-' + byteHex.padStart(2, '0').repeat(16);
}

function mutateCiphertext(ciphertext: string): string {
  const packet = fromBase64UrlNoPad(ciphertext);
  packet[131] ^= 0x01;
  return toBase64UrlNoPad(packet);
}

function flipBase64Tail(value: string): string {
  return value.endsWith('A') ? 'B' : 'A';
}

function encodeManualPaddedPlaintext(json: string, bucketSize: number): Uint8Array {
  const jsonBytes = new TextEncoder().encode(json);
  const output = new Uint8Array(bucketSize);
  const view = new DataView(output.buffer);
  view.setUint32(0, jsonBytes.length, false);
  output.set(jsonBytes, 4);
  return output;
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function toBase64UrlNoPad(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64UrlNoPad(value: string): Uint8Array {
  const padded = value + '==='.slice((value.length + 3) % 4);
  return new Uint8Array(Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}
