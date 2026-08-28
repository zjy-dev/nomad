import { createHash, createHmac, createSecretKey, randomBytes } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, readSync, realpathSync } from 'node:fs';
import { request as nodeRequest } from 'node:http';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { TextDecoder } from 'node:util';

export const PRODUCT_HOST_SCHEMA = 'nomad.product-host.snapshot.v1';
export const PRODUCT_HOST_CURRENT_PATH = '/internal/session/current';
export const PRODUCT_HOST_STREAM_PATH = '/internal/session/stream';
export const PRODUCT_HOST_CAPABILITY_PATH = '/internal/commands/capability';
export const PRODUCT_HOST_COMMAND_PATH = '/internal/commands';
export const PRODUCT_HOST_PAIRING_CREATE_PATH = '/internal/pairing/joins';
export const PRODUCT_HOST_PAIRING_APPROVE_PATH = '/internal/pairing/joins/approve';
export const PRODUCT_HOST_PAIRING_CANCEL_PATH = '/internal/pairing/joins/cancel';
export const PRODUCT_HOST_PAIRING_STATUS_PATH = '/internal/pairing/joins/status';
export const PRODUCT_HOST_JOIN_START_PATH = '/internal/pairing/join/start';
export const PRODUCT_HOST_JOIN_CONFIRM_PATH = '/internal/pairing/join/confirm';
export const PRODUCT_HOST_JOIN_COMPLETE_PATH = '/internal/pairing/join/complete';
export const PRODUCT_HOST_JOIN_ABORT_PATH = '/internal/pairing/join/abort';
export const PRODUCT_HOST_DEVICE_CURRENT_PATH = '/internal/devices/current';
export const PRODUCT_HOST_DEVICE_REVOKE_PATH = '/internal/devices/revoke';
export const MAX_PRODUCT_HOST_BYTES = 64 * 1024;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HOST_INSTANCE = /^host-[0-9a-f]{32}$/;
const SESSION_ALIAS = /^sess-[0-9a-f]{32}$/;
const PENDING_ALIAS = /^(?:input|permission)-[0-9a-f]{32}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const PAIRING_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const TURN_STATES = new Set(['Running', 'NeedsInput', 'NeedsPermission', 'Completed', 'OutcomeUnknown']);
const EVIDENCE_CLASS = 'official_registry_shape_only_not_provider_lifecycle';
const OPAQUE_ID = /^[A-Za-z0-9_-]{8,160}$/;
const COMMAND_STATUSES = new Set(['HostAccepted', 'Dispatching', 'DispatchAcknowledged', 'Rejected', 'Stale', 'Expired', 'OutcomeUnknown']);
const ERROR_CODES = new Set(['OK', 'ERR_REQUEST_EXPIRED', 'ERR_REQUEST_STALE', 'ERR_INCOMPATIBLE_VERSION', 'ERR_REQUEST_REVOKED', 'ERR_DUPLICATE_REQUEST', 'ERR_HOST_OFFLINE', 'ERR_SAFETY_BLOCKED', 'ERR_PERMISSION_DENIED', 'ERR_OUTCOME_UNKNOWN']);
const PAIRING_ERROR_CODES = new Set(['INVALID_REQUEST', 'UNAUTHORIZED', 'PAIRING_INVALID', 'PAIRING_EXPIRED', 'PAIRING_REPLAY', 'PAIRING_DESKTOP_APPROVAL_REQUIRED', 'PAIRING_PROOF_INVALID', 'PAIRING_CONFLICT', 'PAIRING_RELAY_UNAVAILABLE', 'PAIRING_STORAGE', 'PAIRING_CRYPTO', 'PAIRING_NOT_FOUND', 'COMMAND_UNAVAILABLE']);
const JOIN_ID = /^join-[0-9a-f]{32}$/;
const CHALLENGE_ID = /^challenge-[A-Za-z0-9_-]{8,128}$/;
const DEVICE_ALIAS = /^device-[A-Za-z0-9_-]{8,128}$/;
const MAILBOX_ID = /^mbx-[0-9a-f]{64}$/;
const COMPARISON_CODE = /^[0-9]{6}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const PAIRING_STATES = new Set(['created', 'started_awaiting_desktop_approval', 'desktop_approved', 'provisioned_pending_vault', 'active', 'cancelled', 'expired', 'compensated', 'revoked']);
const utf8 = new TextDecoder('utf-8', { fatal: true });
const EMPTY_SHA256 = createHash('sha256').update(Buffer.alloc(0)).digest('hex');

export class ProductHostClientError extends Error {
  constructor(code, statusCode) { super(code); this.name = 'ProductHostClientError'; this.code = code; this.statusCode = statusCode; }
}

export class ProductHostClient {
  constructor(socketPath, options = {}) {
    this.socketPath = validateSocketPath(socketPath);
    this.request = options.request ?? nodeRequest;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.expectedIdentity = options.expectedIdentity ?? null;
    this.commandKey = options.commandKey ?? null;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.randomBytes = options.randomBytes ?? randomBytes;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 25_000 || this.timeoutMs > 60_000) fail('INVALID_TIMEOUT');
  }

  async getCurrent() {
    const result = await this.#request(PRODUCT_HOST_CURRENT_PATH);
    return validateProductHostSnapshot(result.body);
  }

  async getStream(afterSnapshotSeq) {
    if (!Number.isSafeInteger(afterSnapshotSeq) || afterSnapshotSeq < 0) fail('INVALID_AFTER_SEQ');
    const result = await this.#request(PRODUCT_HOST_STREAM_PATH + '?after_snapshot_seq=' + afterSnapshotSeq, { allowNoContent: true });
    if (result.statusCode === 204) return null;
    const envelope = validateProductHostSnapshot(result.body);
    if (envelope.snapshot_seq !== afterSnapshotSeq + 1) fail('PRODUCT_HOST_STREAM_INVALID');
    return envelope;
  }


  async getCommandCapability() {
    const result = await this.#request(PRODUCT_HOST_CAPABILITY_PATH, { authenticate: true });
    return validateCommandCapability(result.body);
  }

  async postCommand(command) {
    validateCommandRequest(command);
    const body = Buffer.from(JSON.stringify(command), 'utf8');
    if (body.length === 0 || body.length > 16 * 1024) fail('PRODUCT_HOST_COMMAND_TOO_LARGE');
    const result = await this.#request(PRODUCT_HOST_COMMAND_PATH, { method: 'POST', body, authenticate: true });
    const receipt = validateCommandReceipt(result.body);
    if (receipt.request_id !== command.request_id || receipt.action !== command.action || receipt.snapshot_seq !== command.expected_snapshot_seq || receipt.snapshot_digest !== command.expected_snapshot_digest) fail('PRODUCT_HOST_RECEIPT_MISMATCH');
    return receipt;
  }

  createPairing(request) { return this.#postPairing(PRODUCT_HOST_PAIRING_CREATE_PATH, validateCreateRequest(request), validatePairingCreated); }
  approvePairing(request) { return this.#postPairing(PRODUCT_HOST_PAIRING_APPROVE_PATH, validateApproveRequest(request), null); }
  cancelPairing(request) { return this.#postPairing(PRODUCT_HOST_PAIRING_CANCEL_PATH, validateCancelRequest(request), null); }
  getPairingStatus(request) { return this.#postPairing(PRODUCT_HOST_PAIRING_STATUS_PATH, validateStatusRequest(request), validatePairingStatus); }

  async startPairing(request) {
    validateStartRequest(request);
    const internal = { schema: 'nomad.m3e.internal.pairing-start.v1', ...request };
    return this.#postPairing(PRODUCT_HOST_JOIN_START_PATH, internal, validatePairingHostStart);
  }

  async confirmPairing(capability, request) {
    validateConfirmRequest(request);
    const internal = { schema: 'nomad.m3e.internal.pairing-confirm.v1', join_cookie_capability: validateJoinCapability(capability), ...request };
    return this.#postPairing(PRODUCT_HOST_JOIN_CONFIRM_PATH, internal, validatePairingConfirm);
  }

  async completePairing(capability, request) {
    validateCompleteRequest(request);
    const { schema: _browserSchema, ...fields } = request;
    const internal = { schema: 'nomad.m3e.internal.pairing-complete.v1', join_cookie_capability: validateJoinCapability(capability), ...fields };
    return this.#postPairing(PRODUCT_HOST_JOIN_COMPLETE_PATH, internal, validatePairingComplete);
  }

  async abortPairing(capability, request) {
    validateAbortRequest(request);
    const { schema: _browserSchema, ...fields } = request;
    const internal = { schema: 'nomad.m3e.internal.pairing-abort.v1', join_cookie_capability: validateJoinCapability(capability), ...fields };
    return this.#postPairing(PRODUCT_HOST_JOIN_ABORT_PATH, internal, null);
  }

  async getCurrentDevice() {
    const result = await this.#request(PRODUCT_HOST_DEVICE_CURRENT_PATH, { authenticate: true, parseErrorResponse: true });
    return validateDeviceCurrent(result.body);
  }

  revokeDevice(request) { return this.#postPairing(PRODUCT_HOST_DEVICE_REVOKE_PATH, validateRevokeRequest(request), validateDeviceRevoke); }

  async #postPairing(path, value, validator) {
    const body = Buffer.from(canonicalJson(value), 'utf8');
    if (body.length === 0 || body.length > 16 * 1024) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID');
    try {
      const result = await this.#request(path, { method: 'POST', body, authenticate: true, allowNoContent: validator === null, parseErrorResponse: true });
      if (validator === null) {
        if (result.statusCode !== 204) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
        return undefined;
      }
      return validator(result.body);
    } finally {
      // Pairing bodies may contain the join secret or short-lived cookie
      // capability. They are never retained after the authenticated UDS call.
      body.fill(0);
    }
  }

  async #request(path, options = {}) {
    const before = socketIdentity(this.socketPath);
    if (this.expectedIdentity && !matchesExpectedIdentity(before, this.expectedIdentity)) fail('PRODUCT_HOST_SOCKET_CHANGED');
    let result; let requestError; let identityChanged = false;
    try {
      result = await requestBounded(this.request, this.socketPath, path, this.timeoutMs, options, this.commandKey, this.now, this.randomBytes);
    }
    catch (error) {
      requestError = error instanceof ProductHostClientError ? error : new ProductHostClientError('PRODUCT_HOST_UNAVAILABLE');
    } finally {
      try { identityChanged = !sameSocketIdentity(before, socketIdentity(this.socketPath)); }
      catch { identityChanged = true; }
    }
    if (identityChanged) fail('PRODUCT_HOST_SOCKET_CHANGED');
    if (requestError) throw requestError;
    return result;
  }
}

export function readCommandKeyFromFd(fd) {
  if (!Number.isInteger(fd) || fd < 3) fail('INVALID_COMMAND_KEY_FD');
  const source = Buffer.alloc(33); let offset = 0;
  try {
    const info = fstatSync(fd);
    if (!info.isFIFO() && !info.isSocket()) fail('INVALID_COMMAND_KEY_FD');
    while (offset < source.length) {
      const count = readSync(fd, source, offset, source.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== 32) fail('INVALID_COMMAND_KEY');
    return createSecretKey(source.subarray(0, 32));
  } catch (error) {
    if (error instanceof ProductHostClientError) throw error;
    fail('INVALID_COMMAND_KEY_FD');
  } finally {
    source.fill(0);
    try { closeSync(fd); } catch {}
  }
}

export function transportAuthHeaders(key, method, path, body = Buffer.alloc(0), timestamp = Math.floor(Date.now() / 1000), nonceBytes = randomBytes(16)) {
  if (!key || !Number.isSafeInteger(timestamp) || timestamp < 0 || !Buffer.isBuffer(nonceBytes) || nonceBytes.length !== 16) fail('COMMAND_TRANSPORT_AUTH_INVALID');
  const nonce = nonceBytes.toString('hex');
  const bodyDigest = body.length === 0 ? EMPTY_SHA256 : createHash('sha256').update(body).digest('hex');
  const material = 'nomad.product-host.transport.v1\n' + method + '\n' + path + '\n' + timestamp + '\n' + nonce + '\n' + bodyDigest;
  const mac = createHmac('sha256', key).update(material, 'utf8').digest('hex');
  return { 'X-Nomad-Transport-Time': String(timestamp), 'X-Nomad-Transport-Nonce': nonce, 'X-Nomad-Transport-Mac': mac };
}

export function validateCommandCapability(value) {
  object(value); exact(value, ['schema', 'capability_id', 'snapshot_seq', 'snapshot_digest', 'next_command_seq', 'issued_at', 'expires_at', 'view', 'reply', 'deny', 'stop', 'allow_once']);
  if (value.schema !== 'nomad.product-host.command-capability.v1' || !OPAQUE_ID.test(value.capability_id ?? '') || !positive(value.snapshot_seq) || !DIGEST.test(value.snapshot_digest ?? '') || !positive(value.next_command_seq)) fail('PRODUCT_HOST_CAPABILITY_INVALID');
  if (!validTimestamp(value.issued_at) || !validTimestamp(value.expires_at) || Date.parse(value.expires_at) <= Date.parse(value.issued_at) || Date.parse(value.expires_at) - Date.parse(value.issued_at) > 30_000 || value.view !== true || value.allow_once !== false) fail('PRODUCT_HOST_CAPABILITY_INVALID');
  validateReplyCapability(value.reply);
  validateNullableAction(value.stop, ['turn_alias'], ['turn-']);
  if (value.deny !== null) {
    object(value.deny); exact(value.deny, ['permission_alias', 'action_hash', 'expires_at']);
    if (!alias(value.deny.permission_alias, 'permission-') || !DIGEST.test(value.deny.action_hash ?? '') || !validTimestamp(value.deny.expires_at)) fail('PRODUCT_HOST_CAPABILITY_INVALID');
  }
  return value;
}

export function validateCommandRequest(value) {
  object(value);
  const common = ['schema', 'capability_id', 'request_id', 'nonce', 'command_seq', 'expected_snapshot_seq', 'expected_snapshot_digest', 'issued_at', 'expires_at', 'action'];
  const additions = value.action === 'reply' ? ['turn_alias', 'input_alias', 'content'] : value.action === 'deny' ? ['permission_alias', 'action_hash', 'permission_expires_at'] : value.action === 'stop' ? ['turn_alias'] : [];
  exact(value, [...common, ...additions]);
  if (value.schema !== 'nomad.gateway.command.v1' || !OPAQUE_ID.test(value.capability_id ?? '') || !OPAQUE_ID.test(value.request_id ?? '') || !OPAQUE_ID.test(value.nonce ?? '') || !positive(value.command_seq) || !positive(value.expected_snapshot_seq) || !DIGEST.test(value.expected_snapshot_digest ?? '') || !validTimestamp(value.issued_at) || !validTimestamp(value.expires_at)) fail('PRODUCT_HOST_COMMAND_INVALID');
  if (value.action === 'reply' && (!alias(value.turn_alias, 'turn-') || !alias(value.input_alias, 'input-') || typeof value.content !== 'string' || value.content.trim().length === 0 || Buffer.byteLength(value.content) > 8 * 1024)) fail('PRODUCT_HOST_COMMAND_INVALID');
  if (value.action === 'deny' && (!alias(value.permission_alias, 'permission-') || !DIGEST.test(value.action_hash ?? '') || !validTimestamp(value.permission_expires_at))) fail('PRODUCT_HOST_COMMAND_INVALID');
  if (value.action === 'stop' && !alias(value.turn_alias, 'turn-')) fail('PRODUCT_HOST_COMMAND_INVALID');
  return value;
}

export function validateCommandReceipt(value) {
  object(value); exact(value, ['schema', 'receipt_id', 'request_id', 'action', 'snapshot_seq', 'snapshot_digest', 'accepted_at', 'status', 'error_code', 'idempotent_replay']);
  if (value.schema !== 'nomad.product-host.command-receipt.v1' || !OPAQUE_ID.test(value.receipt_id ?? '') || !OPAQUE_ID.test(value.request_id ?? '') || !['reply', 'deny', 'stop'].includes(value.action) || !positive(value.snapshot_seq) || !DIGEST.test(value.snapshot_digest ?? '')) fail('PRODUCT_HOST_RECEIPT_INVALID');
  if (value.accepted_at !== null && !validTimestamp(value.accepted_at)) fail('PRODUCT_HOST_RECEIPT_INVALID');
  if (!COMMAND_STATUSES.has(value.status) || value.error_code !== null && !ERROR_CODES.has(value.error_code) || typeof value.idempotent_replay !== 'boolean') fail('PRODUCT_HOST_RECEIPT_INVALID');
  return value;
}

export function validatePairingCreated(value) {
  pairingObject(value); pairingExact(value, ['schema', 'join_id', 'join_secret', 'expires_at']);
  if (value.schema !== 'nomad.m3e.pairing.created.v1' || !JOIN_ID.test(value.join_id ?? '') || !base64urlBytes(value.join_secret, 32) || !validPairingTimestamp(value.expires_at)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  return value;
}

function validateCreateRequest(value) { object(value); exact(value, ['schema']); if (value.schema !== 'nomad.m3e.pairing.create.v1') fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateApproveRequest(value) { object(value); exact(value, ['schema', 'join_id', 'challenge_id', 'expected_epoch', 'comparison_code']); if (value.schema !== 'nomad.m3e.pairing.desktop-approve.v1' || !JOIN_ID.test(value.join_id ?? '') || !CHALLENGE_ID.test(value.challenge_id ?? '') || !positive(value.expected_epoch) || !COMPARISON_CODE.test(value.comparison_code ?? '')) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateCancelRequest(value) { object(value); exact(value, ['schema', 'join_id']); if (value.schema !== 'nomad.m3e.pairing.cancel.v1' || !JOIN_ID.test(value.join_id ?? '')) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateStatusRequest(value) { object(value); exact(value, ['schema', 'join_id']); if (value.schema !== 'nomad.m3e.pairing.status.v1' || !JOIN_ID.test(value.join_id ?? '')) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateStartRequest(value) { object(value); exact(value, ['join_id', 'join_secret', 'device_signing_public_key_sec1', 'device_agreement_public_key_sec1']); if (!JOIN_ID.test(value.join_id ?? '') || !base64urlBytes(value.join_secret, 32) || !sec1PublicKey(value.device_signing_public_key_sec1) || !sec1PublicKey(value.device_agreement_public_key_sec1) || value.device_signing_public_key_sec1 === value.device_agreement_public_key_sec1) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateConfirmRequest(value) { object(value); exact(value, ['challenge_id', 'expected_epoch', 'device_signing_signature_p1363', 'device_agreement_mac']); if (!CHALLENGE_ID.test(value.challenge_id ?? '') || !positive(value.expected_epoch) || !base64urlBytes(value.device_signing_signature_p1363, 64) || !base64urlBytes(value.device_agreement_mac, 32)) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateCompleteRequest(value) { object(value); exact(value, ['schema', 'challenge_id', 'expected_epoch', 'device_vault_signature_p1363']); if (value.schema !== 'nomad.m3e.pairing.vault-commit.v1' || !CHALLENGE_ID.test(value.challenge_id ?? '') || !positive(value.expected_epoch) || !base64urlBytes(value.device_vault_signature_p1363, 64)) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateAbortRequest(value) { object(value); exact(value, ['schema', 'challenge_id', 'expected_epoch']); if (value.schema !== 'nomad.m3e.pairing.abort.v1' || !CHALLENGE_ID.test(value.challenge_id ?? '') || !positive(value.expected_epoch)) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function validateRevokeRequest(value) { object(value); exact(value, ['device_alias', 'expected_epoch']); if (!DEVICE_ALIAS.test(value.device_alias ?? '') || !positive(value.expected_epoch)) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }

export function validatePairingStatus(value) {
  pairingObject(value); pairingExact(value, ['schema', 'join_id', 'state', 'challenge_id', 'expected_epoch', 'comparison_code', 'expires_at']);
  if (value.schema !== 'nomad.m3e.pairing.status-response.v1' || !JOIN_ID.test(value.join_id ?? '') || !PAIRING_STATES.has(value.state) || !validPairingTimestamp(value.expires_at)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  const pendingFieldsNull = value.challenge_id === null && value.expected_epoch === null && value.comparison_code === null;
  const pendingFieldsSet = CHALLENGE_ID.test(value.challenge_id ?? '') && positive(value.expected_epoch) && COMPARISON_CODE.test(value.comparison_code ?? '');
  if (!pendingFieldsNull && !pendingFieldsSet) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  return value;
}

export function validatePairingHostStart(value) {
  pairingObject(value); pairingExact(value, ['schema', 'join_cookie_capability', 'join_cookie_max_age_seconds', 'browser_start']);
  if (value.schema !== 'nomad.m3e.pairing.host-start.v1' || !base64urlBytes(value.join_cookie_capability, 32) || !Number.isSafeInteger(value.join_cookie_max_age_seconds) || value.join_cookie_max_age_seconds < 1 || value.join_cookie_max_age_seconds > 120) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  validatePairingStart(value.browser_start);
  const remaining = Math.floor((Date.parse(value.browser_start.expires_at) - Date.parse(value.browser_start.issued_at)) / 1000);
  if (value.join_cookie_max_age_seconds > remaining) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  return value;
}

export function validatePairingStart(value) {
  pairingObject(value); pairingExact(value, ['schema', 'challenge_id', 'challenge_bytes_b64', 'prospective_epoch', 'host_signing_public_key_sec1', 'host_agreement_public_key_sec1', 'issued_at', 'expires_at']);
  if (value.schema !== 'nomad.m3e.pairing.start-response.v1' || !CHALLENGE_ID.test(value.challenge_id ?? '') || !base64urlBytes(value.challenge_bytes_b64, 32) || !positive(value.prospective_epoch) || !sec1PublicKey(value.host_signing_public_key_sec1) || !sec1PublicKey(value.host_agreement_public_key_sec1) || value.host_signing_public_key_sec1 === value.host_agreement_public_key_sec1 || !validPairingTimestamp(value.issued_at) || !validPairingTimestamp(value.expires_at) || Date.parse(value.expires_at) <= Date.parse(value.issued_at) || Date.parse(value.expires_at) - Date.parse(value.issued_at) > 120_000) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  return value;
}

export function validatePairingConfirm(value) {
  pairingObject(value); pairingExact(value, ['schema', 'signed_provisioning_bundle']);
  if (value.schema !== 'nomad.m3e.pairing.confirm-response.v1') fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  validateSignedBundle(value.signed_provisioning_bundle);
  return value;
}

export function validatePairingComplete(value) {
  pairingObject(value); pairingExact(value, ['schema', 'device_alias', 'pairing_epoch']);
  if (value.schema !== 'nomad.m3e.pairing.complete-response.v1' || !DEVICE_ALIAS.test(value.device_alias ?? '') || !positive(value.pairing_epoch)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  return value;
}

export function validateDeviceCurrent(value) {
  pairingObject(value); pairingExact(value, ['schema', 'principal_alias', 'paired', 'device']);
  if (value.schema !== 'nomad.product-host.device-current.v1' || typeof value.principal_alias !== 'string' || !OPAQUE_ID.test(value.principal_alias) || typeof value.paired !== 'boolean') fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  if (value.paired === false && value.device !== null) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  if (value.paired === true) {
    pairingObject(value.device); pairingExact(value.device, ['device_alias', 'pairing_epoch']);
    if (!DEVICE_ALIAS.test(value.device.device_alias ?? '') || !positive(value.device.pairing_epoch)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  }
  return value;
}

export function validateDeviceRevoke(value) {
  pairingObject(value); pairingExact(value, ['schema', 'principal_alias', 'device_alias', 'status', 'prior_epoch', 'revoked_epoch']);
  if (value.schema !== 'nomad.product-host.device-revoke.v1' || !OPAQUE_ID.test(value.principal_alias ?? '') || !DEVICE_ALIAS.test(value.device_alias ?? '') || !['revoked', 'already_revoked'].includes(value.status) || !positive(value.revoked_epoch)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  if (value.status === 'revoked' && (!positive(value.prior_epoch) || value.revoked_epoch !== value.prior_epoch + 1) || value.status === 'already_revoked' && value.prior_epoch !== null) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  return value;
}

function validateSignedBundle(value) {
  pairingObject(value); pairingExact(value, ['schema', 'bundle', 'provisioning_signature_p1363']);
  if (value.schema !== 'nomad.m3e.signed-provisioning-bundle.v1' || !base64urlBytes(value.provisioning_signature_p1363, 64)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
  pairingObject(value.bundle); pairingExact(value.bundle, ['schema', 'device_alias', 'pairing_epoch', 'mailbox_id', 'relay_base_url', 'host_signing_public_key_sec1', 'host_agreement_public_key_sec1', 'wrapped_device_bearer', 'wrap_nonce', 'issued_at']);
  let relay; try { relay = new URL(value.bundle.relay_base_url); } catch { fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID'); }
  if (value.bundle.schema !== 'nomad.m3e.provisioning-bundle.v1' || !DEVICE_ALIAS.test(value.bundle.device_alias ?? '') || !positive(value.bundle.pairing_epoch) || !MAILBOX_ID.test(value.bundle.mailbox_id ?? '') || relay.protocol !== 'https:' || relay.username || relay.password || relay.search || relay.hash || !sec1PublicKey(value.bundle.host_signing_public_key_sec1) || !sec1PublicKey(value.bundle.host_agreement_public_key_sec1) || value.bundle.host_signing_public_key_sec1 === value.bundle.host_agreement_public_key_sec1 || !base64urlAtLeast(value.bundle.wrapped_device_bearer, 17, 256) || !base64urlBytes(value.bundle.wrap_nonce, 12) || !validPairingTimestamp(value.bundle.issued_at)) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID');
}

export function validateProductHostSnapshot(value) {
  object(value); exact(value, ['schema', 'host_instance_id', 'snapshot_seq', 'digest', 'snapshot']);
  if (value.schema !== PRODUCT_HOST_SCHEMA || !HOST_INSTANCE.test(value.host_instance_id ?? '')) fail('PRODUCT_HOST_SCHEMA_INVALID');
  if (!Number.isSafeInteger(value.snapshot_seq) || value.snapshot_seq < 1 || !DIGEST.test(value.digest ?? '')) fail('PRODUCT_HOST_SCHEMA_INVALID');
  const snapshot = value.snapshot;
  object(snapshot); exact(snapshot, ['session_alias', 'updated_at', 'turn_state', 'pending_input_alias', 'pending_permission_alias', 'diff_file_count', 'writable', 'evidence_class']);
  if (!SESSION_ALIAS.test(snapshot.session_alias ?? '') || !RFC3339.test(snapshot.updated_at ?? '') || new Date(snapshot.updated_at).toISOString() !== snapshot.updated_at) fail('PRODUCT_HOST_SCHEMA_INVALID');
  if (!TURN_STATES.has(snapshot.turn_state) || !nullableAlias(snapshot.pending_input_alias, 'input-') || !nullableAlias(snapshot.pending_permission_alias, 'permission-')) fail('PRODUCT_HOST_SCHEMA_INVALID');
  if (!Number.isSafeInteger(snapshot.diff_file_count) || snapshot.diff_file_count < 0 || snapshot.diff_file_count > 256 || snapshot.writable !== false) fail('PRODUCT_HOST_SCHEMA_INVALID');
  if (snapshot.evidence_class !== EVIDENCE_CLASS) fail('PRODUCT_HOST_SCHEMA_INVALID');
  const withoutDigest = { schema: value.schema, host_instance_id: value.host_instance_id, snapshot_seq: value.snapshot_seq, snapshot: value.snapshot };
  const digest = 'sha256:' + createHash('sha256').update(canonicalJson(withoutDigest), 'utf8').digest('hex');
  if (digest !== value.digest) fail('PRODUCT_HOST_DIGEST_MISMATCH');
  return value;
}

export function browserProjectionFromProductHost(envelope, connectivity = {}) {
  validateProductHostSnapshot(envelope);
  const hostConnectivity = connectivity.hostConnectivity ?? 'Online';
  const clientFreshness = connectivity.clientFreshness ?? 'Live';
  if (!['Online', 'Offline'].includes(hostConnectivity) || !['Live', 'Reconnecting', 'Stale'].includes(clientFreshness)) fail('PRODUCT_HOST_SCHEMA_INVALID');
  const response = {
    schema: 'nomad.alpha.readonly.v1', status: 'available',
    session: {
      session_id: envelope.snapshot.session_alias, semantics_version: '1.0.0', turn_id: null,
      turn_state: envelope.snapshot.turn_state, host_connectivity: hostConnectivity,
      client_freshness: clientFreshness, updated_at: envelope.snapshot.updated_at,
    },
    last_applied_seq: envelope.snapshot_seq, digest: 'sha256:placeholder', events: [],
    changes: { status: 'unavailable', files: [], aggregate_file_count: envelope.snapshot.diff_file_count },
    provenance: { source: 'local-host-direct', relay_ingress_verified: false, gateway_schema_verified: true },
  };
  const withoutDigest = { ...response }; delete withoutDigest.digest;
  response.digest = 'sha256:' + createHash('sha256').update(canonicalJson(withoutDigest), 'utf8').digest('hex');
  return response;
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('PRODUCT_HOST_SCHEMA_INVALID'); return JSON.stringify(value); }
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  object(value);
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}

function validateSocketPath(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || basename(value) !== 'product-host.sock' || value.includes('\0') || Buffer.byteLength(value) > 100) fail('INVALID_PRODUCT_HOST_SOCKET');
  return value;
}

function socketIdentity(path) {
  try {
    const parent = dirname(path); const directory = lstatSync(parent, { bigint: true }); const socket = lstatSync(path, { bigint: true }); const uid = BigInt(process.getuid());
    if (directory.isSymbolicLink() || !directory.isDirectory() || realpathSync(parent) !== parent || directory.uid !== uid || (directory.mode & 0o777n) !== 0o700n) fail('UNSAFE_PRODUCT_HOST_DIRECTORY');
    if (socket.isSymbolicLink() || !socket.isSocket() || socket.uid !== uid || (socket.mode & 0o777n) !== 0o600n) fail('UNSAFE_PRODUCT_HOST_SOCKET');
    return {
      parentDev: directory.dev, parentIno: directory.ino, parentUid: directory.uid, parentMode: directory.mode & 0o777n,
      socketDev: socket.dev, socketIno: socket.ino, socketUid: socket.uid, socketMode: socket.mode & 0o777n,
    };
  } catch (error) { if (error instanceof ProductHostClientError) throw error; fail('PRODUCT_HOST_UNAVAILABLE'); }
}

function sameSocketIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function matchesExpectedIdentity(actual, expected) {
  return actual.parentDev === BigInt(expected.parentDev)
    && actual.parentIno === BigInt(expected.parentIno)
    && actual.socketDev === BigInt(expected.socketDev)
    && actual.socketIno === BigInt(expected.socketIno);
}

function requestBounded(request, socketPath, path, timeoutMs, options, commandKey, now, random) {
  return new Promise((resolvePromise, reject) => {
    let settled = false; const finish = (callback, value) => { if (!settled) { settled = true; callback(value); } };
    const method = options.method ?? 'GET'; const body = options.body;
    const headers = { Host: 'localhost', Accept: 'application/json', Connection: 'close' };
    if (body) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = String(body.length); }
    if (options.authenticate) {
      if (!commandKey) fail('COMMAND_TRANSPORT_KEY_MISSING');
      Object.assign(headers, transportAuthHeaders(commandKey, method, path, body ?? Buffer.alloc(0), now(), random(16)));
    }
    const outgoing = request({ socketPath, path, method, headers, setHost: false }, (response) => {
      const accepted = response.statusCode === 200 || options.allowNoContent && response.statusCode === 204;
      if (!accepted && !options.parseErrorResponse) {
        response.destroy();
        const code = response.statusCode === 503 ? 'PRODUCT_HOST_NOT_READY' : response.statusCode === 409 ? 'PRODUCT_HOST_RESTARTED' : 'PRODUCT_HOST_HTTP_REJECTED';
        return finish(reject, new ProductHostClientError(code, response.statusCode));
      }
      const lengthHeaders = response.rawHeaders.filter((_value, index) => index % 2 === 0 && response.rawHeaders[index].toLowerCase() === 'content-length');
      const declared = response.headers['content-length'];
      if (lengthHeaders.length !== 1 || typeof declared !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > MAX_PRODUCT_HOST_BYTES || response.headers['transfer-encoding'] !== undefined) {
        response.destroy();
        return finish(reject, new ProductHostClientError('PRODUCT_HOST_FRAMING_INVALID'));
      }
      if (response.statusCode === 204 && declared !== '0') {
        response.destroy();
        return finish(reject, new ProductHostClientError('PRODUCT_HOST_FRAMING_INVALID'));
      }
      if (response.statusCode !== 204 && (response.headers['content-type'] !== 'application/json' || response.headers['content-encoding'] !== undefined)) {
        response.destroy();
        return finish(reject, new ProductHostClientError('PRODUCT_HOST_CONTENT_TYPE_INVALID'));
      }
      const chunks = []; let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_PRODUCT_HOST_BYTES || response.statusCode === 204) response.destroy(new ProductHostClientError(response.statusCode === 204 ? 'PRODUCT_HOST_FRAMING_INVALID' : 'PRODUCT_HOST_RESPONSE_TOO_LARGE'));
        else chunks.push(chunk);
      });
      response.on('error', (error) => finish(reject, error));
      response.on('end', () => {
        if (size !== Number(declared)) return finish(reject, new ProductHostClientError('PRODUCT_HOST_FRAMING_INVALID'));
        if (response.statusCode === 204) return finish(resolvePromise, { statusCode: 204, body: '' });
        if (size === 0) return finish(reject, new ProductHostClientError('PRODUCT_HOST_RESPONSE_INVALID'));
        try {
          const joined = Buffer.concat(chunks); let raw;
          try { raw = utf8.decode(joined); }
          finally { joined.fill(0); for (const chunk of chunks) chunk.fill(0); }
          const parsed = strictJson(raw);
          if (!accepted) {
            object(parsed); exact(parsed, ['schema', 'code']);
            if (parsed.schema !== 'nomad.product-host.error.v1' || !PAIRING_ERROR_CODES.has(parsed.code)) throw new Error('error');
            return finish(reject, new ProductHostClientError(parsed.code, response.statusCode));
          }
          finish(resolvePromise, { statusCode: response.statusCode, body: parsed });
        } catch { finish(reject, new ProductHostClientError('PRODUCT_HOST_RESPONSE_INVALID')); }
      });
    });
    outgoing.setTimeout(timeoutMs, () => outgoing.destroy(new ProductHostClientError('PRODUCT_HOST_TIMEOUT')));
    outgoing.on('error', (error) => finish(reject, error)); outgoing.end(body);
  });
}

function strictJson(raw) {
  let index = 0; let nodes = 0;
  const ws = () => { while (' \t\r\n'.includes(raw[index] ?? '!')) index += 1; };
  const value = (depth) => {
    ws(); if (++nodes > 8192 || depth > 16) throw new Error('budget'); const char = raw[index];
    if (char === '{') return objectValue(depth + 1); if (char === '[') return arrayValue(depth + 1); if (char === '"') return stringValue();
    for (const pair of [['true', true], ['false', false], ['null', null]]) if (raw.startsWith(pair[0], index)) { index += pair[0].length; return pair[1]; }
    const match = raw.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/); if (!match) throw new Error('value'); index += match[0].length; const number = Number(match[0]); if (!Number.isFinite(number)) throw new Error('number'); return number;
  };
  const stringValue = () => { const start = index++; while (index < raw.length) { const code = raw.charCodeAt(index++); if (code === 34) return JSON.parse(raw.slice(start, index)); if (code < 32) throw new Error('string'); if (code === 92) { const escaped = raw[index++]; if (escaped === 'u') { if (!/^[0-9a-fA-F]{4}$/.test(raw.slice(index, index + 4))) throw new Error('escape'); index += 4; } else if (!'"\\/bfnrt'.includes(escaped ?? '')) throw new Error('escape'); } } throw new Error('string'); };
  const objectValue = (depth) => { index += 1; ws(); const result = {}; const keys = new Set(); if (raw[index] === '}') { index += 1; return result; } while (true) { ws(); if (raw[index] !== '"') throw new Error('key'); const key = stringValue(); if (keys.has(key)) throw new Error('duplicate'); keys.add(key); ws(); if (raw[index++] !== ':') throw new Error('colon'); result[key] = value(depth); ws(); const delimiter = raw[index++]; if (delimiter === '}') return result; if (delimiter !== ',') throw new Error('delimiter'); } };
  const arrayValue = (depth) => { index += 1; ws(); const result = []; if (raw[index] === ']') { index += 1; return result; } while (true) { result.push(value(depth)); ws(); const delimiter = raw[index++]; if (delimiter === ']') return result; if (delimiter !== ',') throw new Error('delimiter'); } };
  const parsed = value(0); ws(); if (index !== raw.length) throw new Error('trailing'); return parsed;
}

function nullableAlias(value, prefix) { return value === null || (PENDING_ALIAS.test(value ?? '') && value.startsWith(prefix)); }
function alias(value, prefix) { return typeof value === 'string' && value.startsWith(prefix) && /^[a-z]+-[0-9a-f]{32}$/.test(value); }
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function validTimestamp(value) { return typeof value === 'string' && RFC3339.test(value) && Number.isFinite(Date.parse(value)); }
function validPairingTimestamp(value) { return typeof value === 'string' && PAIRING_TIMESTAMP.test(value) && new Date(value).toISOString() === value.replace(/Z$/, '.000Z'); }
function validateJoinCapability(value) { if (!base64urlBytes(value, 32)) fail('PRODUCT_HOST_PAIRING_REQUEST_INVALID'); return value; }
function base64urlBytes(value, bytes) { if (typeof value !== 'string' || !BASE64URL.test(value)) return false; const decoded = Buffer.from(value, 'base64url'); return decoded.length === bytes && decoded.toString('base64url') === value; }
function base64urlAtLeast(value, minimum, maximum) { if (typeof value !== 'string' || !BASE64URL.test(value)) return false; const decoded = Buffer.from(value, 'base64url'); return decoded.length >= minimum && decoded.length <= maximum && decoded.toString('base64url') === value; }
function sec1PublicKey(value) { return base64urlBytes(value, 65) && Buffer.from(value, 'base64url')[0] === 4; }
function validateReplyCapability(value) {
  if (value === null) return;
  object(value);
  exact(value, Object.prototype.hasOwnProperty.call(value, 'summary') ? ['turn_alias', 'input_alias', 'summary'] : ['turn_alias', 'input_alias']);
  if (!alias(value.turn_alias, 'turn-') || !alias(value.input_alias, 'input-')) fail('PRODUCT_HOST_CAPABILITY_INVALID');
  if (value.summary !== undefined && value.summary !== null) {
    object(value.summary);
    exact(value.summary, ['schema', 'question_count', 'answer_mode', 'response_hint', 'prompt']);
    if (value.summary.schema !== 'nomad.product-host.pending-question-summary.v1'
        || value.summary.question_count !== 1 || value.summary.answer_mode !== 'free_text'
        || value.summary.response_hint !== 'single_short_reply' || !safePrompt(value.summary.prompt)) {
      fail('PRODUCT_HOST_CAPABILITY_INVALID');
    }
  }
}
function safePrompt(value) { return typeof value === 'string' && value.length <= 160 && /^Provide a short reply for: [a-z0-9]+(?:[ -][a-z0-9]+){0,5}\.$/.test(value); }
function validateNullableAction(value, keys, prefixes) { if (value === null) return; object(value); exact(value, keys); keys.forEach((key, index) => { if (!alias(value[key], prefixes[index])) fail('PRODUCT_HOST_CAPABILITY_INVALID'); }); }
function object(value) { if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail('PRODUCT_HOST_SCHEMA_INVALID'); }
function exact(value, keys) { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail('PRODUCT_HOST_SCHEMA_INVALID'); }
function pairingObject(value) { if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID'); }
function pairingExact(value, keys) { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail('PRODUCT_HOST_PAIRING_RESPONSE_INVALID'); }
function fail(code) { throw new ProductHostClientError(code); }
