const cryptoApi = globalThis.crypto;

if (!cryptoApi?.subtle) {
  throw new Error('WebCrypto is unavailable in this environment');
}

const subtle = cryptoApi.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const FRAME_SCHEMA = 'nomad.relay.opaque-frame.v2';
const FRAME_SUITE = 'p256-hkdf-sha256-aes256gcm-v1';
const SALT_PREFIX = 'nomad.remote-envelope.salt.v2\n';
const INFO_PREFIX = 'nomad.remote-envelope.key.v2\n';
const NONCE_PREFIX = 'nomad.remote-envelope.nonce.v2\n';
const AAD_PREFIX = 'nomad.remote-envelope.v2\n';
const TEST_VECTOR_MARKER = 'TEST_ONLY_VECTOR';
const MAX_JSON_BYTES = 32 * 1024;
const MAX_WIRE_BYTES = 96 * 1024;
const MAX_TTL_SECONDS = 10 * 60;
const SEALED_PREFIX_VERSION = 0x01;
const GCM_TAG_BYTES = 16;
const P256_PUBLIC_KEY_BYTES = 65;
const P1363_SIGNATURE_BYTES = 64;
const NONCE_BYTES = 12;
const LENGTH_PREFIX_BYTES = 4;
const PLAINTEXT_BUCKETS = [512, 2048, 8192, 32768, 65536] as const;
const FRAME_KEYS = [
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
] as const;

const MAILBOX_ID = /^mbx-[0-9a-f]{64}$/;
const MESSAGE_ID = /^msg-[0-9a-f]{32}$/;
const DIRECTION = /^(host_to_device|device_to_host)$/;
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/;
const NONCE_DIRECTION_PREFIX: Record<RemoteDirection, [number, number, number, number]> = {
  host_to_device: [0x35, 0xdc, 0xab, 0xa9],
  device_to_host: [0x2e, 0xad, 0x77, 0x03],
};
const VECTOR_REQUIRED_KEYS = new Set([
  'marker',
  'frame',
  'rust_frame',
  'host_signing_public_key_sec1',
  'host_agreement_public_key_sec1',
  'device_signing_public_key_sec1',
  'device_agreement_public_key_sec1',
  'host_signing_commitment',
  'host_agreement_commitment',
  'device_signing_commitment',
  'device_agreement_commitment',
  'shared_secret',
  'salt',
  'host_to_device_key',
  'device_to_host_key',
  'nonce',
  'aad',
  'ciphertext_and_tag',
  'sealed_packet',
  'canonical_plaintext_json',
  'host_signing_private_key_pkcs8',
  'host_agreement_private_key_pkcs8',
  'device_signing_private_key_pkcs8',
  'device_agreement_private_key_pkcs8',
]);

export type RemoteDirection = 'host_to_device' | 'device_to_host';

export interface RemoteFrameMetadata {
  schema: typeof FRAME_SCHEMA;
  crypto_suite: typeof FRAME_SUITE;
  mailbox_id: string;
  direction: RemoteDirection;
  epoch: number;
  sequence: number;
  message_id: string;
  issued_at: number;
  expires_at: number;
  nonce: string;
}

export interface RemoteOpaqueFrame extends RemoteFrameMetadata {
  ciphertext: string;
}

export interface RemoteSharedContext {
  mailboxId: string;
  epoch: number;
  hostSigningCommitment: string;
  hostAgreementCommitment: string;
  deviceSigningCommitment: string;
  deviceAgreementCommitment: string;
}

export interface RemoteRuntimeKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface RemoteVector {
  marker: typeof TEST_VECTOR_MARKER;
  frame: RemoteOpaqueFrame;
  rust_frame: RemoteOpaqueFrame;
  host_signing_public_key_sec1: string;
  host_agreement_public_key_sec1: string;
  device_signing_public_key_sec1: string;
  device_agreement_public_key_sec1: string;
  host_signing_commitment: string;
  host_agreement_commitment: string;
  device_signing_commitment: string;
  device_agreement_commitment: string;
  shared_secret: string;
  salt: string;
  host_to_device_key: string;
  device_to_host_key: string;
  nonce: string;
  aad: string;
  ciphertext_and_tag: string;
  sealed_packet: string;
  canonical_plaintext_json: string;
  host_signing_private_key_pkcs8: string;
  host_agreement_private_key_pkcs8: string;
  device_signing_private_key_pkcs8: string;
  device_agreement_private_key_pkcs8: string;
}

export interface RemoteEncryptInput {
  frame: RemoteFrameMetadata;
  plaintext: unknown;
  senderSigningPrivateKey: CryptoKey;
  senderSigningPublicKeySec1: Uint8Array;
  senderAgreementPrivateKey: CryptoKey;
  senderAgreementPublicKeySec1: Uint8Array;
  recipientAgreementPublicKey: CryptoKey;
  context: RemoteSharedContext;
  paddingBytes?: Uint8Array;
}

export interface RemoteEncryptOutput {
  frame: RemoteOpaqueFrame;
  canonicalPlaintextJson: string;
  aad: Uint8Array;
  salt: Uint8Array;
  symmetricKeyBytes: Uint8Array;
  nonceBytes: Uint8Array;
  ciphertextAndTag: Uint8Array;
  sealedPacket: Uint8Array;
}

export interface RemoteDecryptInput {
  frame: RemoteOpaqueFrame;
  recipientAgreementPrivateKey: CryptoKey;
  context: RemoteSharedContext;
  expectedSenderSigningCommitment: string;
  expectedSenderAgreementCommitment: string;
}

export interface RemoteDecryptOutput {
  plaintext: unknown;
  canonicalPlaintextJson: string;
  senderSigningPublicKeySec1: Uint8Array;
  senderAgreementPublicKeySec1: Uint8Array;
  nonceBytes: Uint8Array;
  aad: Uint8Array;
  symmetricKeyBytes: Uint8Array;
  salt: Uint8Array;
}

export class RemoteCryptoError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export function canonicalJson(value: unknown): string {
  return canon(value);
}

export async function generateRuntimeP256SigningKeyPair(): Promise<RemoteRuntimeKeyPair> {
  const pair = await subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false,
    ['sign', 'verify'],
  );
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
  };
}

export async function generateRuntimeP256AgreementKeyPair(): Promise<RemoteRuntimeKeyPair> {
  const pair = await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    false,
    ['deriveBits'],
  );
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
  };
}

export async function exportPublicKeySec1(publicKey: CryptoKey): Promise<Uint8Array> {
  const raw = new Uint8Array(await subtle.exportKey('raw', publicKey));
  ensureSec1Point(raw);
  return raw;
}

export async function importSigningPublicKeySec1(raw: Uint8Array): Promise<CryptoKey> {
  ensureSec1Point(raw);
  return subtle.importKey(
    'raw',
    ownedBytes(raw),
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false,
    ['verify'],
  );
}

export async function importAgreementPublicKeySec1(raw: Uint8Array): Promise<CryptoKey> {
  ensureSec1Point(raw);
  return subtle.importKey(
    'raw',
    ownedBytes(raw),
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    false,
    [],
  );
}

export async function importSigningPrivateKeyPkcs8(
  pkcs8: Uint8Array,
  extractable = false,
): Promise<CryptoKey> {
  return subtle.importKey(
    'pkcs8',
    ownedBytes(pkcs8),
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    extractable,
    ['sign'],
  );
}

export async function importAgreementPrivateKeyPkcs8(
  pkcs8: Uint8Array,
  extractable = false,
): Promise<CryptoKey> {
  return subtle.importKey(
    'pkcs8',
    ownedBytes(pkcs8),
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    extractable,
    ['deriveBits'],
  );
}

export async function computeKeyCommitment(publicKeySec1: Uint8Array): Promise<string> {
  ensureSec1Point(publicKeySec1);
  return bytesToHex(await sha256(publicKeySec1));
}

export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<Uint8Array> {
  const bits = await subtle.deriveBits(
    {
      name: 'ECDH',
      public: publicKey,
    },
    privateKey,
    256,
  );
  return new Uint8Array(bits);
}

export async function deriveSalt(context: RemoteSharedContext): Promise<Uint8Array> {
  validateSharedContext(context);
  const parts = [
    SALT_PREFIX,
    context.mailboxId,
    '\n',
    context.hostSigningCommitment,
    '\n',
    context.hostAgreementCommitment,
    '\n',
    context.deviceSigningCommitment,
    '\n',
    context.deviceAgreementCommitment,
    '\n',
    String(context.epoch),
  ];
  return sha256(encoder.encode(parts.join('')));
}

export async function deriveDirectionKeyBytes(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  direction: RemoteDirection,
): Promise<Uint8Array> {
  ensureBytes(sharedSecret, 32, 'INVALID_SHARED_SECRET');
  ensureBytes(salt, 32, 'INVALID_SALT');
  const hkdfKey = await subtle.importKey('raw', ownedBytes(sharedSecret), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: ownedBytes(salt),
      info: ownedBytes(encoder.encode(`${INFO_PREFIX}${direction}`)),
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(bits);
}

export function deriveDeterministicNonce(direction: RemoteDirection, sequence: number): Uint8Array {
  validateDirection(direction);
  validateSequence(sequence);
  const nonce = new Uint8Array(NONCE_BYTES);
  nonce.set(NONCE_DIRECTION_PREFIX[direction], 0);
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  view.setBigUint64(4, BigInt(sequence), false);
  return nonce;
}

export async function deriveDeterministicNonceAsync(
  direction: RemoteDirection,
  sequence: number,
): Promise<Uint8Array> {
  validateDirection(direction);
  validateSequence(sequence);
  const prefix = await sha256(encoder.encode(`${NONCE_PREFIX}${direction}`));
  const nonce = new Uint8Array(NONCE_BYTES);
  nonce.set(prefix.slice(0, 4), 0);
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  view.setBigUint64(4, BigInt(sequence), false);
  return nonce;
}

export function canonicalFrameMetadata(frame: RemoteFrameMetadata): RemoteFrameMetadata {
  validateFrameMetadata(frame);
  return {
    schema: FRAME_SCHEMA,
    crypto_suite: FRAME_SUITE,
    mailbox_id: frame.mailbox_id,
    direction: frame.direction,
    epoch: frame.epoch,
    sequence: frame.sequence,
    message_id: frame.message_id,
    issued_at: frame.issued_at,
    expires_at: frame.expires_at,
    nonce: frame.nonce,
  };
}

export function frameAadBytes(frame: RemoteFrameMetadata): Uint8Array {
  return encoder.encode(`${AAD_PREFIX}${canonicalJson(canonicalFrameMetadata(frame))}`);
}

export function paddedPlaintextBucketLength(jsonByteLength: number): number {
  if (!Number.isSafeInteger(jsonByteLength) || jsonByteLength < 0) {
    throw new RemoteCryptoError('INVALID_PLAINTEXT_LENGTH');
  }
  const needed = LENGTH_PREFIX_BYTES + jsonByteLength;
  const bucket = PLAINTEXT_BUCKETS.find((value) => value >= needed);
  if (bucket === undefined) {
    throw new RemoteCryptoError('PLAINTEXT_TOO_LARGE');
  }
  return bucket;
}

export function encodePaddedPlaintext(
  canonicalPlaintextJson: string,
  paddingBytes?: Uint8Array,
): Uint8Array {
  const jsonBytes = encoder.encode(canonicalPlaintextJson);
  if (jsonBytes.byteLength > MAX_JSON_BYTES) {
    throw new RemoteCryptoError('PLAINTEXT_TOO_LARGE');
  }
  const bucket = paddedPlaintextBucketLength(jsonBytes.byteLength);
  const output = new Uint8Array(bucket);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  view.setUint32(0, jsonBytes.byteLength, false);
  output.set(jsonBytes, LENGTH_PREFIX_BYTES);
  const paddingLength = bucket - LENGTH_PREFIX_BYTES - jsonBytes.byteLength;
  if (paddingBytes !== undefined) {
    if (!(paddingBytes instanceof Uint8Array) || paddingBytes.byteLength !== paddingLength) {
      throw new RemoteCryptoError('INVALID_PADDING_BYTES');
    }
    output.set(paddingBytes, LENGTH_PREFIX_BYTES + jsonBytes.byteLength);
  } else if (paddingLength > 0) {
    cryptoApi.getRandomValues(output.subarray(LENGTH_PREFIX_BYTES + jsonBytes.byteLength));
  }
  return output;
}

export function decodePaddedPlaintext(encoded: Uint8Array): { canonicalPlaintextJson: string; plaintext: unknown } {
  if (!(encoded instanceof Uint8Array)) {
    throw new RemoteCryptoError('INVALID_PADDED_PLAINTEXT');
  }
  if (!PLAINTEXT_BUCKETS.includes(encoded.byteLength as (typeof PLAINTEXT_BUCKETS)[number])) {
    throw new RemoteCryptoError('INVALID_PADDING_BUCKET');
  }
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const jsonLength = view.getUint32(0, false);
  if (jsonLength > MAX_JSON_BYTES || jsonLength + LENGTH_PREFIX_BYTES > encoded.byteLength) {
    throw new RemoteCryptoError('INVALID_LENGTH_PREFIX');
  }
  const jsonBytes = encoded.slice(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + jsonLength);
  const canonicalPlaintextJson = decoder.decode(jsonBytes);
  const parsed = parseCanonicalJson(canonicalPlaintextJson);
  if (canonicalJson(parsed) !== canonicalPlaintextJson) {
    throw new RemoteCryptoError('NON_CANONICAL_JSON');
  }
  return {
    canonicalPlaintextJson,
    plaintext: parsed,
  };
}

export async function encryptRemoteFrame(input: RemoteEncryptInput): Promise<RemoteEncryptOutput> {
  validateFrameContextBinding(input.frame, input.context);
  const sharedSecret = await deriveSharedSecret(
    input.senderAgreementPrivateKey,
    input.recipientAgreementPublicKey,
  );
  const salt = await deriveSalt(input.context);
  const symmetricKeyBytes = await deriveDirectionKeyBytes(sharedSecret, salt, input.frame.direction);
  const nonceBytes = await deriveDeterministicNonceAsync(input.frame.direction, input.frame.sequence);
  const frame = canonicalFrameMetadata({
    ...input.frame,
    nonce: toBase64UrlNoPad(nonceBytes),
  });
  const aad = frameAadBytes(frame);
  const canonicalPlaintextJson = canonicalJson(input.plaintext);
  const encodedPlaintext = encodePaddedPlaintext(canonicalPlaintextJson, input.paddingBytes);
  const aesKey = await importAesKey(symmetricKeyBytes);
  const encrypted = new Uint8Array(
    await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ownedBytes(nonceBytes),
        additionalData: ownedBytes(aad),
        tagLength: 128,
      },
      aesKey,
      ownedBytes(encodedPlaintext),
    ),
  );
  const digest = await sha256(concatBytes(aad, encrypted));
  const signature = new Uint8Array(
    await subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      input.senderSigningPrivateKey,
      ownedBytes(digest),
    ),
  );
  if (signature.byteLength !== P1363_SIGNATURE_BYTES) {
    throw new RemoteCryptoError('INVALID_SIGNATURE_LENGTH');
  }
  ensureSec1Point(input.senderSigningPublicKeySec1);
  ensureSec1Point(input.senderAgreementPublicKeySec1);
  const sealedPacket = concatBytes(
    new Uint8Array([SEALED_PREFIX_VERSION]),
    input.senderSigningPublicKeySec1,
    input.senderAgreementPublicKeySec1,
    signature,
    encrypted,
  );
  if (sealedPacket.byteLength > MAX_WIRE_BYTES) {
    throw new RemoteCryptoError('SEALED_PACKET_TOO_LARGE');
  }
  return {
    frame: {
      ...frame,
      ciphertext: toBase64UrlNoPad(sealedPacket),
    },
    canonicalPlaintextJson,
    aad,
    salt,
    symmetricKeyBytes,
    nonceBytes,
    ciphertextAndTag: encrypted,
    sealedPacket,
  };
}

export async function decryptRemoteFrame(input: RemoteDecryptInput): Promise<RemoteDecryptOutput> {
  validateFrame(input.frame);
  validateSharedContext(input.context);
  validateFrameContextBinding(input.frame, input.context);
  const expectedNonce = await deriveDeterministicNonceAsync(input.frame.direction, input.frame.sequence);
  if (input.frame.nonce !== toBase64UrlNoPad(expectedNonce)) {
    throw new RemoteCryptoError('NONCE_MISMATCH');
  }
  const sealedPacket = fromBase64UrlNoPad(input.frame.ciphertext, 'INVALID_CIPHERTEXT_ENCODING');
  if (
    sealedPacket.byteLength <
    1 + P256_PUBLIC_KEY_BYTES + P256_PUBLIC_KEY_BYTES + P1363_SIGNATURE_BYTES + GCM_TAG_BYTES
  ) {
    throw new RemoteCryptoError('INVALID_SEALED_PACKET');
  }
  if (sealedPacket[0] !== SEALED_PREFIX_VERSION) {
    throw new RemoteCryptoError('INVALID_SEALED_PACKET_VERSION');
  }
  const senderSigningPublicKeySec1 = sealedPacket.slice(1, 1 + P256_PUBLIC_KEY_BYTES);
  const senderAgreementPublicKeySec1 = sealedPacket.slice(
    1 + P256_PUBLIC_KEY_BYTES,
    1 + P256_PUBLIC_KEY_BYTES * 2,
  );
  const signature = sealedPacket.slice(
    1 + P256_PUBLIC_KEY_BYTES * 2,
    1 + P256_PUBLIC_KEY_BYTES * 2 + P1363_SIGNATURE_BYTES,
  );
  const ciphertextAndTag = sealedPacket.slice(1 + P256_PUBLIC_KEY_BYTES * 2 + P1363_SIGNATURE_BYTES);
  ensureSec1Point(senderSigningPublicKeySec1);
  ensureSec1Point(senderAgreementPublicKeySec1);
  const signingCommitment = await computeKeyCommitment(senderSigningPublicKeySec1);
  const agreementCommitment = await computeKeyCommitment(senderAgreementPublicKeySec1);
  if (signingCommitment !== input.expectedSenderSigningCommitment) {
    throw new RemoteCryptoError('SENDER_SIGNING_COMMITMENT_MISMATCH');
  }
  if (agreementCommitment !== input.expectedSenderAgreementCommitment) {
    throw new RemoteCryptoError('SENDER_AGREEMENT_COMMITMENT_MISMATCH');
  }
  const aad = frameAadBytes({
    schema: input.frame.schema,
    crypto_suite: input.frame.crypto_suite,
    mailbox_id: input.frame.mailbox_id,
    direction: input.frame.direction,
    epoch: input.frame.epoch,
    sequence: input.frame.sequence,
    message_id: input.frame.message_id,
    issued_at: input.frame.issued_at,
    expires_at: input.frame.expires_at,
    nonce: input.frame.nonce,
  });
  const digest = await sha256(concatBytes(aad, ciphertextAndTag));
  const signingPublicKey = await importSigningPublicKeySec1(senderSigningPublicKeySec1);
  const verified = await subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    signingPublicKey,
    ownedBytes(signature),
    ownedBytes(digest),
  );
  if (!verified) {
    throw new RemoteCryptoError('SIGNATURE_INVALID');
  }
  const senderAgreementPublicKey = await importAgreementPublicKeySec1(senderAgreementPublicKeySec1);
  const sharedSecret = await deriveSharedSecret(input.recipientAgreementPrivateKey, senderAgreementPublicKey);
  const salt = await deriveSalt(input.context);
  const symmetricKeyBytes = await deriveDirectionKeyBytes(sharedSecret, salt, input.frame.direction);
  const aesKey = await importAesKey(symmetricKeyBytes);
  let decrypted: Uint8Array;
  try {
    decrypted = new Uint8Array(
      await subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ownedBytes(expectedNonce),
          additionalData: ownedBytes(aad),
          tagLength: 128,
        },
        aesKey,
        ownedBytes(ciphertextAndTag),
      ),
    );
  } catch {
    throw new RemoteCryptoError('AES_GCM_INVALID');
  }
  const { canonicalPlaintextJson, plaintext } = decodePaddedPlaintext(decrypted);
  return {
    plaintext,
    canonicalPlaintextJson,
    senderSigningPublicKeySec1,
    senderAgreementPublicKeySec1,
    nonceBytes: expectedNonce,
    aad,
    symmetricKeyBytes,
    salt,
  };
}

export function parseAndValidateRemoteVector(value: unknown): RemoteVector {
  if (!isObject(value) || Object.keys(value).some((key) => !VECTOR_REQUIRED_KEYS.has(key))) {
    throw new RemoteCryptoError('INVALID_VECTOR');
  }
  const vector = value as Record<string, unknown>;
  if (vector.marker !== TEST_VECTOR_MARKER) {
    throw new RemoteCryptoError('INVALID_VECTOR_MARKER');
  }
  validateFrame(vector.frame as RemoteOpaqueFrame);
  validateFrame(vector.rust_frame as RemoteOpaqueFrame);
  for (const field of [
    'host_signing_public_key_sec1',
    'host_agreement_public_key_sec1',
    'device_signing_public_key_sec1',
    'device_agreement_public_key_sec1',
    'host_signing_commitment',
    'host_agreement_commitment',
    'device_signing_commitment',
    'device_agreement_commitment',
    'shared_secret',
    'salt',
    'host_to_device_key',
    'device_to_host_key',
    'nonce',
    'aad',
    'ciphertext_and_tag',
    'sealed_packet',
    'canonical_plaintext_json',
    'host_signing_private_key_pkcs8',
    'host_agreement_private_key_pkcs8',
    'device_signing_private_key_pkcs8',
    'device_agreement_private_key_pkcs8',
  ]) {
    if (typeof vector[field] !== 'string' || vector[field].length === 0) {
      throw new RemoteCryptoError('INVALID_VECTOR');
    }
  }
  return vector as unknown as RemoteVector;
}

export function validateFrameMetadata(frame: RemoteFrameMetadata): void {
  if (!isObject(frame)) {
    throw new RemoteCryptoError('INVALID_FRAME');
  }
  const keys = Object.keys(frame).sort();
  const expected = [...FRAME_KEYS].filter((key) => key !== 'ciphertext').sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new RemoteCryptoError('UNKNOWN_FRAME_FIELD');
  }
  if (frame.schema !== FRAME_SCHEMA || frame.crypto_suite !== FRAME_SUITE) {
    throw new RemoteCryptoError('UNSUPPORTED_FRAME');
  }
  if (!MAILBOX_ID.test(frame.mailbox_id)) {
    throw new RemoteCryptoError('INVALID_MAILBOX_ID');
  }
  validateDirection(frame.direction);
  validateSequence(frame.sequence);
  if (!Number.isSafeInteger(frame.epoch) || frame.epoch < 1) {
    throw new RemoteCryptoError('INVALID_EPOCH');
  }
  if (!MESSAGE_ID.test(frame.message_id)) {
    throw new RemoteCryptoError('INVALID_MESSAGE_ID');
  }
  if (!Number.isSafeInteger(frame.issued_at) || !Number.isSafeInteger(frame.expires_at)) {
    throw new RemoteCryptoError('INVALID_ISSUE_WINDOW');
  }
  if (
    frame.expires_at <= frame.issued_at ||
    frame.expires_at - frame.issued_at > MAX_TTL_SECONDS
  ) {
    throw new RemoteCryptoError('INVALID_ISSUE_WINDOW');
  }
  const nonceBytes = fromBase64UrlNoPad(frame.nonce, 'INVALID_NONCE_ENCODING');
  ensureBytes(nonceBytes, NONCE_BYTES, 'INVALID_NONCE_LENGTH');
}

export function validateFrame(frame: RemoteOpaqueFrame): void {
  if (!isObject(frame)) {
    throw new RemoteCryptoError('INVALID_FRAME');
  }
  const keys = Object.keys(frame).sort();
  const expected = [...FRAME_KEYS].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new RemoteCryptoError('UNKNOWN_FRAME_FIELD');
  }
  validateFrameMetadata({
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
  });
  if (typeof frame.ciphertext !== 'string' || frame.ciphertext.length === 0) {
    throw new RemoteCryptoError('INVALID_CIPHERTEXT');
  }
  if (!BASE64URL_NOPAD.test(frame.ciphertext)) {
    throw new RemoteCryptoError('INVALID_CIPHERTEXT_ENCODING');
  }
  const packet = fromBase64UrlNoPad(frame.ciphertext, 'INVALID_CIPHERTEXT_ENCODING');
  if (packet.byteLength > MAX_WIRE_BYTES) {
    throw new RemoteCryptoError('SEALED_PACKET_TOO_LARGE');
  }
}

function validateSharedContext(context: RemoteSharedContext): void {
  if (!isObject(context)) {
    throw new RemoteCryptoError('INVALID_CONTEXT');
  }
  if (!MAILBOX_ID.test(context.mailboxId)) {
    throw new RemoteCryptoError('INVALID_MAILBOX_ID');
  }
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    throw new RemoteCryptoError('INVALID_EPOCH');
  }
  for (const value of [
    context.hostSigningCommitment,
    context.hostAgreementCommitment,
    context.deviceSigningCommitment,
    context.deviceAgreementCommitment,
  ]) {
    if (!/^[0-9a-f]{64}$/.test(value)) {
      throw new RemoteCryptoError('INVALID_COMMITMENT');
    }
  }
}

function validateFrameContextBinding(frame: RemoteFrameMetadata | RemoteOpaqueFrame, context: RemoteSharedContext): void {
  if (frame.mailbox_id !== context.mailboxId || frame.epoch !== context.epoch) {
    throw new RemoteCryptoError('FRAME_CONTEXT_MISMATCH');
  }
}

function validateDirection(direction: RemoteDirection): void {
  if (!DIRECTION.test(direction)) {
    throw new RemoteCryptoError('INVALID_DIRECTION');
  }
}

function validateSequence(sequence: number): void {
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new RemoteCryptoError('INVALID_SEQUENCE');
  }
}

function ensureSec1Point(raw: Uint8Array): void {
  ensureBytes(raw, P256_PUBLIC_KEY_BYTES, 'INVALID_PUBLIC_KEY');
  if (raw[0] !== 0x04) {
    throw new RemoteCryptoError('INVALID_PUBLIC_KEY');
  }
}

function ensureBytes(value: Uint8Array, expectedLength: number, code: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== expectedLength) {
    throw new RemoteCryptoError(code);
  }
}

async function importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  ensureBytes(keyBytes, 32, 'INVALID_AES_KEY');
  return subtle.importKey('raw', ownedBytes(keyBytes), { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export function parseCanonicalJson(json: string): unknown {
  const parser = new StrictJsonParser(json);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.isAtEnd()) {
    throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
  }
  return value;
}

function canon(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new RemoteCryptoError('INVALID_JSON_NUMBER');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canon).join(',')}]`;
  if (isObject(value)) {
    const entries = Object.keys(value)
      .sort()
      .map((key) => {
        const entry = (value as Record<string, unknown>)[key];
        if (entry === undefined) {
          throw new RemoteCryptoError('INVALID_CANONICAL_JSON');
        }
        return `${JSON.stringify(key)}:${canon(entry)}`;
      });
    return `{${entries.join(',')}}`;
  }
  throw new RemoteCryptoError('INVALID_CANONICAL_JSON');
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', ownedBytes(data)));
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function toBase64UrlNoPad(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64UrlNoPad(value: string, code: string): Uint8Array {
  if (!BASE64URL_NOPAD.test(value) || value.length % 4 === 1) {
    throw new RemoteCryptoError(code);
  }
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  try {
    const binary = atob(padded);
    const decoded = Uint8Array.from(
      binary, (character) => character.charCodeAt(0),
    );
    if (toBase64UrlNoPad(decoded) !== value) throw new Error('non-canonical');
    return decoded;
  } catch {
    throw new RemoteCryptoError(code);
  }
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

class StrictJsonParser {
  private readonly source: string;
  private index = 0;

  constructor(source: string) {
    this.source = source;
  }

  parseValue(): unknown {
    this.skipWhitespace();
    const current = this.peek();
    if (current === undefined) {
      throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
    }
    if (current === '"') return this.parseString();
    if (current === '{') return this.parseObject();
    if (current === '[') return this.parseArray();
    if (current === 't') return this.parseLiteral('true', true);
    if (current === 'f') return this.parseLiteral('false', false);
    if (current === 'n') return this.parseLiteral('null', null);
    if (current === '-' || isDigit(current)) return this.parseNumber();
    throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
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
    this.expect('{');
    this.skipWhitespace();
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    if (this.peek() === '}') {
      this.index += 1;
      return out;
    }
    while (true) {
      this.skipWhitespace();
      if (this.peek() !== '"') {
        throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
      }
      const key = this.parseString();
      if (seen.has(key)) {
        throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
      }
      seen.add(key);
      this.skipWhitespace();
      this.expect(':');
      const value = this.parseValue();
      out[key] = value;
      this.skipWhitespace();
      const current = this.peek();
      if (current === '}') {
        this.index += 1;
        return out;
      }
      if (current !== ',') {
        throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
      }
      this.index += 1;
    }
  }

  private parseArray(): unknown[] {
    this.expect('[');
    this.skipWhitespace();
    const out: unknown[] = [];
    if (this.peek() === ']') {
      this.index += 1;
      return out;
    }
    while (true) {
      out.push(this.parseValue());
      this.skipWhitespace();
      const current = this.peek();
      if (current === ']') {
        this.index += 1;
        return out;
      }
      if (current !== ',') {
        throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
      }
      this.index += 1;
    }
  }

  private parseString(): string {
    const start = this.index;
    this.expect('"');
    while (this.index < this.source.length) {
      const current = this.source.charCodeAt(this.index);
      if (current === 0x22) {
        this.index += 1;
        try {
          return JSON.parse(this.source.slice(start, this.index)) as string;
        } catch {
          throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
        }
      }
      if (current === 0x5c) {
        this.index += 1;
        if (this.index >= this.source.length) {
          throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
        }
        const escaped = this.source.charCodeAt(this.index);
        if (escaped === 0x75) {
          for (let offset = 1; offset <= 4; offset += 1) {
            const code = this.source.charCodeAt(this.index + offset);
            if (!isHexCodeUnit(code)) {
              throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
            }
          }
          this.index += 5;
          continue;
        }
        if (!isJsonEscapeCodeUnit(escaped)) {
          throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
        }
        this.index += 1;
        continue;
      }
      if (current <= 0x1f) {
        throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
      }
      this.index += 1;
    }
    throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
  }

  private parseNumber(): number {
    const remainder = this.source.slice(this.index);
    const match = remainder.match(/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/);
    if (!match) {
      throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
    }
    const token = match[0];
    this.index += token.length;
    const value = Number(token);
    if (!Number.isFinite(value)) {
      throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
    }
    return value;
  }

  private parseLiteral(token: string, value: boolean | null): boolean | null {
    if (this.source.slice(this.index, this.index + token.length) !== token) {
      throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
    }
    this.index += token.length;
    return value;
  }

  private expect(expected: string): void {
    if (this.peek() !== expected) {
      throw new RemoteCryptoError('PLAINTEXT_JSON_INVALID');
    }
    this.index += 1;
  }

  private peek(): string | undefined {
    return this.source[this.index];
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
  return value === 0x22 || value === 0x5c || value === 0x2f || value === 0x62 || value === 0x66 || value === 0x6e || value === 0x72 || value === 0x74;
}
