import { createHash } from 'node:crypto';

export const ALPHA_HOST_SCHEMA = 'nomad.alpha.readonly.host.v1';
export const ALPHA_SCHEMA = 'nomad.alpha.readonly.v1';
export const MAX_PROJECTION_BYTES = 64 * 1024;
export const MAX_EVENTS = 32;

const SESSION_ALIAS = /^sess-[0-9a-f]{32}$/;
const EVENT_ALIAS = /^evt-[0-9a-f]{32}$/;
const TURN_ALIAS = /^turn-[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const TURN_STATES = new Set(['None', 'Running', 'NeedsInput', 'NeedsPermission', 'Stopping', 'Completed', 'Cancelled', 'Failed', 'OutcomeUnknown']);
const EVENT_TYPES = new Set([
  'session.created', 'session.updated', 'turn.started', 'message.accepted',
  'message.completed', 'tool.started', 'tool.completed', 'tool.failed',
  'permission.requested', 'permission.resolved', 'diff.updated',
  'turn.stopping', 'turn.completed', 'turn.cancelled', 'turn.failed',
  'turn.outcome_unknown', 'session.compacted',
]);

export class ProjectionValidationError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('INVALID_NUMBER');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  fail('INVALID_JSON_VALUE');
}

export function projectionDigest(projection) {
  assertObject(projection, 'INVALID_PROJECTION');
  const withoutDigest = {};
  for (const key of Object.keys(projection)) {
    if (key !== 'digest') withoutDigest[key] = projection[key];
  }
  return `sha256:${createHash('sha256').update(canonicalJson(withoutDigest), 'utf8').digest('hex')}`;
}

export function validateHostProjection(projection) {
  validateCommonProjection(projection, ALPHA_HOST_SCHEMA, 'seq');
  if (
    projection.provenance.source !== 'local-alpha-projector'
    ||
    projection.provenance.relay_ingress_verified !== false
    || projection.provenance.gateway_schema_verified !== false
  ) fail('UNVERIFIED_HOST_PROVENANCE_REQUIRED');
  if (projectionDigest(projection) !== projection.digest) fail('DIGEST_MISMATCH');
  return projection;
}

export function browserProjectionFromHost(host) {
  validateHostProjection(host);
  const response = {
    schema: ALPHA_SCHEMA,
    status: host.status,
    session: structuredClone(host.session),
    last_applied_seq: host.seq,
    digest: 'sha256:placeholder',
    events: structuredClone(host.events),
    changes: structuredClone(host.changes),
    provenance: {
      source: 'local-alpha-projector',
      relay_ingress_verified: true,
      gateway_schema_verified: true,
    },
  };
  response.digest = projectionDigest(response);
  return validateBrowserProjection(response);
}

export function validateBrowserProjection(projection) {
  validateCommonProjection(projection, ALPHA_SCHEMA, 'last_applied_seq');
  const relaySource = projection.provenance.source === 'local-alpha-projector'
    && projection.provenance.relay_ingress_verified === true;
  const directSource = projection.provenance.source === 'local-host-direct'
    && projection.provenance.relay_ingress_verified === false;
  if ((!relaySource && !directSource) || projection.provenance.gateway_schema_verified !== true) fail('VERIFIED_GATEWAY_PROVENANCE_REQUIRED');
  validateBrowserChanges(projection.changes, directSource);
  if (projectionDigest(projection) !== projection.digest) fail('DIGEST_MISMATCH');
  return projection;
}

function validateCommonProjection(projection, schema, seqKey) {
  assertObject(projection, 'INVALID_PROJECTION');
  assertExactKeys(projection, ['schema', 'status', 'session', seqKey, 'digest', 'events', 'changes', 'provenance']);
  assertBoundedJson(projection);
  if (Buffer.byteLength(JSON.stringify(projection), 'utf8') > MAX_PROJECTION_BYTES) fail('PROJECTION_TOO_LARGE');
  if (projection.schema !== schema) fail('UNSUPPORTED_SCHEMA');
  if (projection.status !== 'available') fail('INVALID_STATUS');
  if (!Number.isSafeInteger(projection[seqKey]) || projection[seqKey] < 0) fail('INVALID_SEQ');
  if (typeof projection.digest !== 'string' || !DIGEST.test(projection.digest)) fail('INVALID_DIGEST');
  validateSession(projection.session);
  validateEvents(projection.events, projection.session.session_id, projection[seqKey]);
  if (schema === ALPHA_HOST_SCHEMA) validateChanges(projection.changes);
  validateProvenanceShape(projection.provenance);
}

function validateBrowserChanges(changes, directSource) {
  if (!directSource) return validateChanges(changes);
  assertObject(changes, 'INVALID_CHANGES');
  assertExactKeys(changes, ['status', 'files', 'aggregate_file_count']);
  if (changes.status !== 'unavailable' || !Array.isArray(changes.files) || changes.files.length !== 0) fail('INVALID_CHANGES');
  if (!Number.isSafeInteger(changes.aggregate_file_count) || changes.aggregate_file_count < 0 || changes.aggregate_file_count > 256) fail('INVALID_CHANGES');
}

function validateSession(session) {
  assertObject(session, 'INVALID_SESSION');
  assertExactKeys(session, ['session_id', 'semantics_version', 'turn_id', 'turn_state', 'host_connectivity', 'client_freshness', 'updated_at']);
  if (!SESSION_ALIAS.test(session.session_id ?? '')) fail('INVALID_SESSION_ID');
  if (session.turn_id !== null && !TURN_ALIAS.test(session.turn_id ?? '')) fail('INVALID_TURN_ID');
  if (session.semantics_version !== '1.0.0') fail('UNSUPPORTED_SEMANTICS');
  if (!TURN_STATES.has(session.turn_state)) fail('INVALID_TURN_STATE');
  if (!['Online', 'Offline'].includes(session.host_connectivity)) fail('INVALID_HOST_CONNECTIVITY');
  if (!['Live', 'Reconnecting', 'Stale'].includes(session.client_freshness)) fail('INVALID_CLIENT_FRESHNESS');
  if (!validTimestamp(session.updated_at)) fail('INVALID_UPDATED_AT');
}

function validateEvents(events, sessionId, topSeq) {
  if (!Array.isArray(events) || events.length > MAX_EVENTS) fail('INVALID_EVENTS');
  let previousSeq = null;
  const eventIds = new Set();
  for (const event of events) {
    assertObject(event, 'INVALID_EVENT');
    assertAllowedKeys(event, ['event_type', 'session_id', 'event_id', 'seq', 'timestamp', 'durable', 'turn_id']);
    for (const key of ['event_type', 'session_id', 'event_id', 'seq', 'timestamp', 'durable']) {
      if (!(key in event)) fail('INVALID_EVENT');
    }
    if (!EVENT_TYPES.has(event.event_type) || event.session_id !== sessionId) fail('INVALID_EVENT');
    if (!EVENT_ALIAS.test(event.event_id ?? '') || eventIds.has(event.event_id)) fail('INVALID_EVENT');
    if (!Number.isSafeInteger(event.seq) || event.seq < 1 || event.seq > topSeq) fail('INVALID_EVENT_SEQ');
    if (previousSeq !== null && event.seq <= previousSeq) fail('INVALID_EVENT_SEQ');
    if (!validTimestamp(event.timestamp) || event.durable !== true) fail('INVALID_EVENT');
    if ('turn_id' in event && event.turn_id !== null && !TURN_ALIAS.test(event.turn_id ?? '')) fail('INVALID_EVENT');
    previousSeq = event.seq;
    eventIds.add(event.event_id);
  }
}

function validateChanges(changes) {
  assertObject(changes, 'INVALID_CHANGES');
  assertExactKeys(changes, ['status', 'files']);
  if (changes.status !== 'unavailable' || !Array.isArray(changes.files) || changes.files.length !== 0) fail('INVALID_CHANGES');
}

function validateProvenanceShape(provenance) {
  assertObject(provenance, 'INVALID_PROVENANCE');
  assertExactKeys(provenance, ['source', 'relay_ingress_verified', 'gateway_schema_verified']);
  if (
    !['local-alpha-projector', 'local-host-direct'].includes(provenance.source)
    || typeof provenance.relay_ingress_verified !== 'boolean'
    || typeof provenance.gateway_schema_verified !== 'boolean'
  ) fail('INVALID_PROVENANCE');
}

function assertBoundedJson(value, depth = 0, budget = { nodes: 0 }) {
  if (depth > 16 || ++budget.nodes > 8192) fail('PROJECTION_TOO_COMPLEX');
  if (typeof value === 'string' && Buffer.byteLength(value, 'utf8') > 32 * 1024) fail('STRING_TOO_LARGE');
  if (typeof value === 'number' && !Number.isFinite(value)) fail('INVALID_NUMBER');
  if (Array.isArray(value)) {
    for (const item of value) assertBoundedJson(item, depth + 1, budget);
  } else if (isObject(value)) {
    for (const item of Object.values(value)) assertBoundedJson(item, depth + 1, budget);
  }
}

function assertObject(value, code) {
  if (!isObject(value)) fail(code);
}

function assertExactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_FIELD');
}

function assertAllowedKeys(value, allowed) {
  const keys = new Set(allowed);
  if (Object.keys(value).some((key) => !keys.has(key))) fail('UNKNOWN_FIELD');
}

function validTimestamp(value) {
  return typeof value === 'string' && RFC3339.test(value) && Number.isFinite(Date.parse(value));
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function fail(code) {
  throw new ProjectionValidationError(code);
}
