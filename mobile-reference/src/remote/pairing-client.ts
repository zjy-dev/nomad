import {
  computeKeyCommitment,
  deriveSharedSecret,
  exportPublicKeySec1,
  generateRuntimeP256AgreementKeyPair,
  generateRuntimeP256SigningKeyPair,
  importAgreementPublicKeySec1,
} from './crypto';
import {
  BrowserVault,
  decodeSignedProvisioningBundle,
  type BrowserVaultComparisonContext,
  type BrowserVaultSession,
  type SignedProvisioningBundle,
} from './browser-vault';

const subtle = globalThis.crypto?.subtle;

if (!subtle) {
  throw new Error('WebCrypto is unavailable in this environment');
}

const encoder = new TextEncoder();
const JOIN_ID = /^[A-Za-z0-9_-]{8,160}$/;
const CHALLENGE_ID = /^[A-Za-z0-9_-]{8,160}$/;
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/;
const TRANSCRIPT_SCHEMA = 'nomad.m3e.pairing.start-response.v1';
const CONFIRM_RESPONSE_SCHEMA = 'nomad.m3e.pairing.confirm-response.v1';
const COMPLETE_RESPONSE_SCHEMA = 'nomad.m3e.pairing.complete-response.v1';
const VAULT_COMMIT_SCHEMA = 'nomad.m3e.pairing.vault-commit.v1';
const ABORT_SCHEMA = 'nomad.m3e.pairing.abort.v1';
const VAULT_COMMIT_DOMAIN = 'nomad.m3e.vault-commit.v1\n';
const DEVICE_ALIAS = /^device-[A-Za-z0-9_-]{8,128}$/;
const PAIRING_SECRET_BYTES = 32;
const MAX_PAIRING_RESPONSE_BYTES = 64 * 1024;
const MAX_JSON_DEPTH = 16;
const MAX_JSON_NODES = 4096;
const MAX_PAIRING_TTL_MS = 120_000;

export interface PairingClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  historyImpl?: Pick<History, 'replaceState'>;
  locationImpl?: Pick<Location, 'href' | 'origin' | 'pathname' | 'search' | 'hash'>;
  nowImpl?: () => number;
  vault: BrowserVault;
}

export interface PairingJoinStartResult {
  joinId: string;
  challengeId: string;
  comparisonCode: string;
  prospectiveEpoch: number;
  expiresAt: string;
}

export interface PairingConfirmResult {
  session: BrowserVaultSession;
  comparisonCode: string;
}

interface PairingStartPayload {
  schema: typeof TRANSCRIPT_SCHEMA;
  challenge_id: string;
  challenge_bytes_b64: string;
  prospective_epoch: number;
  host_signing_public_key_sec1: string;
  host_agreement_public_key_sec1: string;
  issued_at: string;
  expires_at: string;
}

interface PairingConfirmPayload {
  schema: typeof CONFIRM_RESPONSE_SCHEMA;
  signed_provisioning_bundle: SignedProvisioningBundle;
}

interface PendingPairingState {
  joinId: string;
  comparisonContext: BrowserVaultComparisonContext;
  challengeId: string;
  challengeBytes: Uint8Array;
  prospectiveEpoch: number;
  hostSigningPublicKeySec1: Uint8Array;
  hostAgreementPublicKeySec1: Uint8Array;
  expiresAtMs: number;
  deviceSigningKeyPair: CryptoKeyPair;
  deviceAgreementKeyPair: CryptoKeyPair;
  deviceSigningPublicKeySec1: Uint8Array;
  deviceAgreementPublicKeySec1: Uint8Array;
}

export class PairingClientError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class PairingClient {
  private readonly fetchImpl: typeof fetch;
  private readonly baseUrl: string;
  private readonly historyImpl: Pick<History, 'replaceState'>;
  private readonly locationImpl: Pick<Location, 'href' | 'origin' | 'pathname' | 'search' | 'hash'>;
  private readonly nowImpl: () => number;
  private pending: PendingPairingState | null = null;

  constructor(private readonly options: PairingClientOptions) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.historyImpl = options.historyImpl ?? globalThis.history;
    this.locationImpl = options.locationImpl ?? globalThis.location;
    this.nowImpl = options.nowImpl ?? Date.now;
  }

  async startFromCurrentLocation(): Promise<PairingJoinStartResult> {
    const locationHref = this.locationImpl.href;
    const url = new URL(locationHref);
    const joinSecret = url.hash.startsWith('#') ? url.hash.slice(1) : '';
    if (url.hash !== '') {
      // Clear even malformed fragments: an unparseable secret is still secret
      // material and must not remain in browser history or the address bar.
      this.clearJoinFragment();
    }
    const joinId = decodeJoinId(url.pathname);
    if (!isExactBase64UrlBytes(joinSecret, PAIRING_SECRET_BYTES)) {
      throw new PairingClientError('JOIN_SECRET_REQUIRED', 'Pairing join secret is missing from the URL fragment.');
    }
    return this.start(joinId, joinSecret);
  }

  async start(joinId: string, joinSecret: string): Promise<PairingJoinStartResult> {
    this.pending = null;
    validateJoinId(joinId);
    if (!isExactBase64UrlBytes(joinSecret, PAIRING_SECRET_BYTES)) {
      throw new PairingClientError('INVALID_JOIN_SECRET', 'Pairing join secret is invalid.');
    }
    const deviceSigningKeyPair = await generateRuntimeP256SigningKeyPair();
    const deviceAgreementKeyPair = await generateRuntimeP256AgreementKeyPair();
    const deviceSigningPublicKeySec1 = await exportPublicKeySec1(deviceSigningKeyPair.publicKey);
    const deviceAgreementPublicKeySec1 = await exportPublicKeySec1(deviceAgreementKeyPair.publicKey);

    const response = await this.fetchJson('/api/pairing/join/start', {
      method: 'POST',
      credentials: 'include',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: canonicalJson({
        join_id: joinId,
        join_secret: joinSecret,
        device_signing_public_key_sec1: toBase64Url(deviceSigningPublicKeySec1),
        device_agreement_public_key_sec1: toBase64Url(deviceAgreementPublicKeySec1),
      }),
    });
    const payload = decodeStartPayload(response, this.nowImpl());

    const hostSigningPublicKeySec1 = fromBase64Url(payload.host_signing_public_key_sec1, 'INVALID_PAIRING_RESPONSE');
    const hostAgreementPublicKeySec1 = fromBase64Url(payload.host_agreement_public_key_sec1, 'INVALID_PAIRING_RESPONSE');
    const challengeBytes = fromBase64Url(payload.challenge_bytes_b64, 'INVALID_PAIRING_RESPONSE');
    const comparisonContext = await buildComparisonContext({
      joinId,
      challengeId: payload.challenge_id,
      challengeBytes,
      prospectiveEpoch: payload.prospective_epoch,
      hostSigningPublicKeySec1,
      hostAgreementPublicKeySec1,
      deviceSigningPublicKeySec1,
      deviceAgreementPublicKeySec1,
    });

    this.pending = {
      joinId,
      comparisonContext,
      challengeId: payload.challenge_id,
      challengeBytes,
      prospectiveEpoch: payload.prospective_epoch,
      expiresAtMs: Date.parse(payload.expires_at),
      hostSigningPublicKeySec1,
      hostAgreementPublicKeySec1,
      deviceSigningKeyPair,
      deviceAgreementKeyPair,
      deviceSigningPublicKeySec1,
      deviceAgreementPublicKeySec1,
    };

    return {
      joinId,
      challengeId: payload.challenge_id,
      comparisonCode: comparisonContext.comparison_code,
      prospectiveEpoch: payload.prospective_epoch,
      expiresAt: payload.expires_at,
    };
  }

  async confirm(): Promise<PairingConfirmResult> {
    const pending = this.pending;
    if (pending === null) {
      throw new PairingClientError('PAIRING_NOT_STARTED', 'Pairing confirmation requires a current start challenge.');
    }
    if (this.nowImpl() >= pending.expiresAtMs) {
      await this.failClosed(pending);
      throw new PairingClientError('PAIRING_EXPIRED', 'Pairing challenge expired before confirmation.');
    }

    try {
    const transcriptHash = await computeTranscriptHash({
      joinId: pending.joinId,
      challengeId: pending.challengeId,
      challengeBytes: pending.challengeBytes,
      prospectiveEpoch: pending.prospectiveEpoch,
      hostSigningPublicKeySec1: pending.hostSigningPublicKeySec1,
      hostAgreementPublicKeySec1: pending.hostAgreementPublicKeySec1,
      deviceSigningPublicKeySec1: pending.deviceSigningPublicKeySec1,
      deviceAgreementPublicKeySec1: pending.deviceAgreementPublicKeySec1,
    });
    const deviceSigningProof = await signTranscriptProof(
      pending.deviceSigningKeyPair.privateKey,
      transcriptHash,
    );
    const deviceAgreementMac = await computeAgreementProof(
      pending.deviceAgreementKeyPair.privateKey,
      pending.hostAgreementPublicKeySec1,
      transcriptHash,
    );

    const response = await this.fetchJson('/api/pairing/join/confirm', {
      method: 'POST',
      credentials: 'include',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: canonicalJson({
        challenge_id: pending.challengeId,
        expected_epoch: pending.prospectiveEpoch,
        device_signing_signature_p1363: toBase64Url(deviceSigningProof),
        device_agreement_mac: toBase64Url(deviceAgreementMac),
      }),
    });
      const payload = decodeConfirmPayload(response);
      await this.options.vault.persistProvisionedDevice({
      deviceSigningKeyPair: pending.deviceSigningKeyPair,
      deviceAgreementKeyPair: pending.deviceAgreementKeyPair,
      signedProvisioningBundle: payload.signed_provisioning_bundle,
      comparisonContext: pending.comparisonContext,
      });
      await this.options.vault.close();
      const session = await this.options.vault.restorePairedDevice();
      const vaultCommitSignature = await signVaultCommit(
        session.signedProvisioningBundle,
        session.deviceSigningKeyPair.privateKey,
      );
      const completeResponse = await this.fetchJson('/api/pairing/join/complete', {
        method: 'POST',
        credentials: 'include',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
        },
        body: canonicalJson({
          schema: VAULT_COMMIT_SCHEMA,
          challenge_id: pending.challengeId,
          expected_epoch: pending.prospectiveEpoch,
          device_vault_signature_p1363: toBase64Url(vaultCommitSignature),
        }),
      });
      decodeCompletePayload(completeResponse, session.bundle.device_alias, pending.prospectiveEpoch);
      this.pending = null;
      return {
        session,
        comparisonCode: session.comparisonCode,
      };
    } catch (error) {
      await this.failClosed(pending);
      throw error;
    }
  }

  cancelPending(): void {
    this.pending = null;
  }

  async abortPending(): Promise<void> {
    const pending = this.pending;
    if (pending === null) {
      return;
    }
    await this.failClosed(pending);
  }

  private async failClosed(pending: PendingPairingState): Promise<void> {
    this.pending = null;
    await Promise.allSettled([
      this.abortPairing(pending),
      Promise.resolve().then(() => this.options.vault.clear()),
      Promise.resolve().then(() => this.options.vault.close()),
    ]);
  }

  private async abortPairing(pending: PendingPairingState): Promise<void> {
    await this.fetchJson('/api/pairing/join/abort', {
      method: 'POST',
      credentials: 'include',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: canonicalJson({
        schema: ABORT_SCHEMA,
        challenge_id: pending.challengeId,
        expected_epoch: pending.prospectiveEpoch,
      }),
    }, true);
  }

  private clearJoinFragment(): void {
    const replacement = `${this.locationImpl.origin}${this.locationImpl.pathname}${this.locationImpl.search}`;
    this.historyImpl.replaceState(null, '', replacement);
  }

  private async fetchJson(path: string, init: RequestInit, allowEmpty = false): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    } catch {
      throw new PairingClientError('PAIRING_NETWORK_ERROR', 'Pairing request failed before an authoritative response was received.');
    }
    if (allowEmpty && response.status === 204) {
      return null;
    }
    const contentType = response.headers.get('content-type');
    if (contentType === null || contentType.split(';', 1)[0].trim() !== 'application/json') {
      throw new PairingClientError('PAIRING_INVALID_RESPONSE', 'Pairing response content type is incompatible.');
    }
    if (!response.ok) {
      throw new PairingClientError('PAIRING_HTTP_ERROR', 'Pairing request was not accepted.');
    }
    let payloadText: string;
    try {
      payloadText = await readBoundedResponseText(response, MAX_PAIRING_RESPONSE_BYTES);
    } catch {
      throw new PairingClientError('PAIRING_INVALID_RESPONSE', 'Pairing response JSON is invalid.');
    }
    return parseStrictJson(payloadText);
  }
}

function decodeStartPayload(value: unknown, nowMs: number): PairingStartPayload {
  const raw = exactObject(
    value,
    [
      'schema',
      'challenge_id',
      'challenge_bytes_b64',
      'prospective_epoch',
      'host_signing_public_key_sec1',
      'host_agreement_public_key_sec1',
      'issued_at',
      'expires_at',
    ],
    'INVALID_PAIRING_RESPONSE',
  );
  if (raw.schema !== TRANSCRIPT_SCHEMA) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing start schema is incompatible.');
  }
  if (
    typeof raw.challenge_id !== 'string'
    || !CHALLENGE_ID.test(raw.challenge_id)
    || !isExactBase64UrlBytes(raw.challenge_bytes_b64, PAIRING_SECRET_BYTES)
  ) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing challenge fields are invalid.');
  }
  if (
    typeof raw.prospective_epoch !== 'number'
    || !Number.isSafeInteger(raw.prospective_epoch)
    || raw.prospective_epoch < 1
  ) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing epoch is invalid.');
  }
  ensureSec1(raw.host_signing_public_key_sec1, 'INVALID_PAIRING_RESPONSE');
  ensureSec1(raw.host_agreement_public_key_sec1, 'INVALID_PAIRING_RESPONSE');
  if (!isCanonicalUtcTimestamp(raw.issued_at) || !isCanonicalUtcTimestamp(raw.expires_at)) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing timestamps are invalid.');
  }
  const issuedAtMs = Date.parse(raw.issued_at);
  const expiresAtMs = Date.parse(raw.expires_at);
  if (
    expiresAtMs <= issuedAtMs
    || expiresAtMs - issuedAtMs > MAX_PAIRING_TTL_MS
    || expiresAtMs <= nowMs
  ) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing challenge lifetime is invalid.');
  }
  return {
    schema: TRANSCRIPT_SCHEMA,
    challenge_id: raw.challenge_id as string,
    challenge_bytes_b64: raw.challenge_bytes_b64 as string,
    prospective_epoch: raw.prospective_epoch as number,
    host_signing_public_key_sec1: raw.host_signing_public_key_sec1 as string,
    host_agreement_public_key_sec1: raw.host_agreement_public_key_sec1 as string,
    issued_at: raw.issued_at as string,
    expires_at: raw.expires_at as string,
  };
}

function decodeConfirmPayload(value: unknown): PairingConfirmPayload {
  const raw = exactObject(
    value,
    ['schema', 'signed_provisioning_bundle'],
    'INVALID_PAIRING_RESPONSE',
  );
  if (raw.schema !== CONFIRM_RESPONSE_SCHEMA) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing confirm schema is incompatible.');
  }
  let signedProvisioningBundle: SignedProvisioningBundle;
  try {
    signedProvisioningBundle = decodeSignedProvisioningBundle(raw.signed_provisioning_bundle);
  } catch {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing provisioning bundle is invalid.');
  }
  return {
    schema: CONFIRM_RESPONSE_SCHEMA,
    signed_provisioning_bundle: signedProvisioningBundle,
  };
}

function decodeCompletePayload(value: unknown, expectedAlias: string, expectedEpoch: number): void {
  const raw = exactObject(
    value,
    ['schema', 'device_alias', 'pairing_epoch'],
    'INVALID_PAIRING_RESPONSE',
  );
  if (
    raw.schema !== COMPLETE_RESPONSE_SCHEMA
    || typeof raw.device_alias !== 'string'
    || !DEVICE_ALIAS.test(raw.device_alias)
    || raw.device_alias !== expectedAlias
    || typeof raw.pairing_epoch !== 'number'
    || !Number.isSafeInteger(raw.pairing_epoch)
    || raw.pairing_epoch !== expectedEpoch
  ) {
    throw new PairingClientError('INVALID_PAIRING_RESPONSE', 'Pairing completion response is invalid.');
  }
}

async function buildComparisonContext(input: {
  joinId: string;
  challengeId: string;
  challengeBytes: Uint8Array;
  prospectiveEpoch: number;
  hostSigningPublicKeySec1: Uint8Array;
  hostAgreementPublicKeySec1: Uint8Array;
  deviceSigningPublicKeySec1: Uint8Array;
  deviceAgreementPublicKeySec1: Uint8Array;
}): Promise<BrowserVaultComparisonContext> {
  const hostSigningCommitment = await computeKeyCommitment(input.hostSigningPublicKeySec1);
  const hostAgreementCommitment = await computeKeyCommitment(input.hostAgreementPublicKeySec1);
  const deviceSigningCommitment = await computeKeyCommitment(input.deviceSigningPublicKeySec1);
  const deviceAgreementCommitment = await computeKeyCommitment(input.deviceAgreementPublicKeySec1);
  const transcriptHash = await computeTranscriptHash({
    ...input,
  });
  const comparisonCode = await computeComparisonCode(transcriptHash);
  return {
    comparison_code: comparisonCode,
    host_signing_commitment: hostSigningCommitment,
    host_agreement_commitment: hostAgreementCommitment,
    device_signing_commitment: deviceSigningCommitment,
    device_agreement_commitment: deviceAgreementCommitment,
  };
}

async function computeTranscriptHash(input: {
  joinId: string;
  challengeId: string;
  challengeBytes: Uint8Array;
  prospectiveEpoch: number;
  hostSigningPublicKeySec1: Uint8Array;
  hostAgreementPublicKeySec1: Uint8Array;
  deviceSigningPublicKeySec1: Uint8Array;
  deviceAgreementPublicKeySec1: Uint8Array;
}): Promise<Uint8Array> {
  const parts = [
    'nomad.m3e.pairing.v1\n',
    input.joinId,
    '\n',
    input.challengeId,
    '\n',
    toLowerHex(await sha256(input.challengeBytes)),
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
  return sha256(encoder.encode(parts.join('')));
}

async function signTranscriptProof(privateKey: CryptoKey, transcriptHash: Uint8Array): Promise<Uint8Array> {
  const digest = await sha256(concatBytes(
    encoder.encode('nomad.m3e.signing-proof.v1\n'),
    transcriptHash,
  ));
  return new Uint8Array(await subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    privateKey,
    ownBytes(digest),
  ));
}

async function signVaultCommit(
  signedProvisioningBundle: SignedProvisioningBundle,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const signedBundleDigest = await sha256(
    encoder.encode(canonicalJson(signedProvisioningBundle)),
  );
  const vaultCommitDigest = await sha256(concatBytes(
    encoder.encode(VAULT_COMMIT_DOMAIN),
    signedBundleDigest,
  ));
  return new Uint8Array(await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    ownBytes(vaultCommitDigest),
  ));
}

async function computeAgreementProof(
  privateKey: CryptoKey,
  hostAgreementPublicKeySec1: Uint8Array,
  transcriptHash: Uint8Array,
): Promise<Uint8Array> {
  const hostAgreementPublicKey = await importAgreementPublicKeySec1(hostAgreementPublicKeySec1);
  const sharedSecret = await deriveSharedSecret(privateKey, hostAgreementPublicKey);
  const agreementSecret = await derivePairingProofKey(sharedSecret);
  const hmacKey = await subtle.importKey(
    'raw',
    ownBytes(agreementSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await subtle.sign('HMAC', hmacKey, ownBytes(transcriptHash)));
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

async function computeComparisonCode(transcriptHash: Uint8Array): Promise<string> {
  const digest = await sha256(concatBytes(
    encoder.encode('nomad.m3e.compare.v1\n'),
    transcriptHash,
  ));
  const value = (
    (digest[0] << 16)
    | (digest[1] << 8)
    | digest[2]
  ) % 1_000_000;
  return value.toString().padStart(6, '0');
}

function decodeJoinId(pathname: string): string {
  const match = pathname.match(/\/j\/([A-Za-z0-9_-]{8,160})$/);
  if (!match) {
    throw new PairingClientError('INVALID_JOIN_ID', 'Pairing join URL path is invalid.');
  }
  return match[1];
}

function validateJoinId(joinId: string): void {
  if (!JOIN_ID.test(joinId)) {
    throw new PairingClientError('INVALID_JOIN_ID', 'Pairing join identifier is invalid.');
  }
}

function normalizeBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new PairingClientError('INVALID_PAIRING_BASE_URL', 'Pairing base URL is invalid.');
  }
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new PairingClientError('INVALID_PAIRING_BASE_URL', 'Pairing base URL is invalid.');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopbackHost(url.hostname))) {
    throw new PairingClientError('INVALID_PAIRING_BASE_URL', 'Pairing base URL is invalid.');
  }
  return url.href.replace(/\/$/, '');
}

function exactObject(value: unknown, keys: readonly string[], code: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PairingClientError(code, 'Pairing payload is incompatible.');
  }
  const raw = value as Record<string, unknown>;
  const actual = Object.keys(raw).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new PairingClientError(code, 'Pairing payload is incompatible.');
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

function isExactBase64UrlBytes(value: unknown, byteLength: number): value is string {
  if (!isBase64Url(value)) {
    return false;
  }
  try {
    return fromBase64Url(value, 'INVALID_BASE64URL').byteLength === byteLength;
  } catch {
    return false;
  }
}

function ensureSec1(value: unknown, code: string): void {
  if (!isBase64Url(value) || fromBase64Url(value, code).byteLength !== 65) {
    throw new PairingClientError(code, 'Pairing public key is invalid.');
  }
}

function fromBase64Url(value: string, code: string): Uint8Array {
  if (!BASE64URL_NOPAD.test(value) || value.length % 4 === 1) {
    throw new PairingClientError(code, 'Base64url data is invalid.');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new PairingClientError(code, 'Base64url data is invalid.');
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (toBase64Url(decoded) !== value) {
    throw new PairingClientError(code, 'Base64url data is invalid.');
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

function toLowerHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', ownBytes(value)));
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => sortJson(entry));
  }
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      output[key] = sortJson((value as Record<string, unknown>)[key]);
    }
    return output;
  }
  return value;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';
}

function ownBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value);
}

async function readBoundedResponseText(response: Response, maximumBytes: number): Promise<string> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes) {
      throw new PairingClientError('PAIRING_INVALID_RESPONSE', 'Pairing response is too large.');
    }
  }
  if (response.body === null) {
    return '';
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > maximumBytes) {
        await reader.cancel();
        throw new PairingClientError('PAIRING_INVALID_RESPONSE', 'Pairing response is too large.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function parseStrictJson(source: string): unknown {
  const parser = new StrictJsonParser(source);
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.isAtEnd()) {
    throw new PairingClientError('PAIRING_INVALID_RESPONSE', 'Pairing response JSON is invalid.');
  }
  return value;
}

class StrictJsonParser {
  private index = 0;
  private nodeCount = 0;
  private depth = 0;

  constructor(private readonly source: string) {}

  parseValue(): unknown {
    this.skipWhitespace();
    const current = this.peek();
    if (current === undefined) this.fail();
    if (current === '"') return this.parseString();
    if (current === '{') return this.parseObject();
    if (current === '[') return this.parseArray();
    if (current === 't') return this.parseLiteral('true', true);
    if (current === 'f') return this.parseLiteral('false', false);
    if (current === 'n') return this.parseLiteral('null', null);
    if (current === '-' || isDigit(current)) return this.parseNumber();
    return this.fail();
  }

  skipWhitespace(): void {
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      if (code !== 0x20 && code !== 0x0a && code !== 0x0d && code !== 0x09) break;
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
    const output: Record<string, unknown> = {};
    const seen = new Set<string>();
    if (this.peek() === '}') {
      this.index += 1;
      this.leaveContainer();
      return output;
    }
    while (true) {
      this.skipWhitespace();
      if (this.peek() !== '"') this.fail();
      const key = this.parseString();
      if (seen.has(key)) this.fail();
      seen.add(key);
      this.skipWhitespace();
      this.expect(':');
      output[key] = this.parseValue();
      this.skipWhitespace();
      if (this.peek() === '}') {
        this.index += 1;
        this.leaveContainer();
        return output;
      }
      this.expect(',');
    }
  }

  private parseArray(): unknown[] {
    this.enterContainer();
    this.expect('[');
    this.skipWhitespace();
    const output: unknown[] = [];
    if (this.peek() === ']') {
      this.index += 1;
      this.leaveContainer();
      return output;
    }
    while (true) {
      output.push(this.parseValue());
      this.skipWhitespace();
      if (this.peek() === ']') {
        this.index += 1;
        this.leaveContainer();
        return output;
      }
      this.expect(',');
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
          return this.fail();
        }
      }
      if (current === 0x5c) {
        this.index += 1;
        const escaped = this.source.charCodeAt(this.index);
        if (escaped === 0x75) {
          for (let offset = 1; offset <= 4; offset += 1) {
            if (!isHexCodeUnit(this.source.charCodeAt(this.index + offset))) this.fail();
          }
          this.index += 5;
          continue;
        }
        if (!isJsonEscapeCodeUnit(escaped)) this.fail();
        this.index += 1;
        continue;
      }
      if (current <= 0x1f) this.fail();
      this.index += 1;
    }
    return this.fail();
  }

  private parseNumber(): number {
    this.countNode();
    const match = this.source.slice(this.index).match(/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/);
    if (!match) return this.fail();
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) return this.fail();
    return value;
  }

  private parseLiteral(token: string, value: boolean | null): boolean | null {
    this.countNode();
    if (this.source.slice(this.index, this.index + token.length) !== token) return this.fail();
    this.index += token.length;
    return value;
  }

  private expect(expected: string): void {
    if (this.peek() !== expected) this.fail();
    this.index += 1;
  }

  private peek(): string | undefined {
    return this.source[this.index];
  }

  private countNode(): void {
    this.nodeCount += 1;
    if (this.nodeCount > MAX_JSON_NODES) this.fail();
  }

  private enterContainer(): void {
    this.countNode();
    this.depth += 1;
    if (this.depth > MAX_JSON_DEPTH) this.fail();
  }

  private leaveContainer(): void {
    this.depth -= 1;
  }

  private fail(): never {
    throw new PairingClientError('PAIRING_INVALID_RESPONSE', 'Pairing response JSON is invalid.');
  }
}

function isDigit(value: string): boolean {
  return value >= '0' && value <= '9';
}

function isHexCodeUnit(value: number): boolean {
  return (
    (value >= 0x30 && value <= 0x39)
    || (value >= 0x41 && value <= 0x46)
    || (value >= 0x61 && value <= 0x66)
  );
}

function isJsonEscapeCodeUnit(value: number): boolean {
  return (
    value === 0x22 || value === 0x5c || value === 0x2f || value === 0x62
    || value === 0x66 || value === 0x6e || value === 0x72 || value === 0x74
  );
}
