import type { ViewState } from '../contracts/reducer';
import type { ContractEvent, EventType, Session } from '../contracts/types';
import { verifySnapshotDigest } from '../contracts/digest';
import type { SessionView } from './types';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SESSION_ALIAS = /^sess-[0-9a-f]{32}$/;
const EVENT_ALIAS = /^evt-[0-9a-f]{32}$/;
const TURN_ALIAS = /^turn-[0-9a-f]{32}$/;
const EVENT_TYPES = new Set<EventType>([
  'session.created', 'session.updated', 'turn.started', 'message.accepted',
  'message.completed', 'tool.started', 'tool.completed', 'tool.failed',
  'permission.requested', 'permission.resolved', 'diff.updated',
  'turn.stopping', 'turn.completed', 'turn.cancelled', 'turn.failed',
  'turn.outcome_unknown', 'session.compacted',
]);
const TURN_STATES = new Set<Session['turn_state']>(['None', 'Running', 'NeedsInput', 'NeedsPermission', 'Stopping', 'Completed', 'Cancelled', 'Failed', 'OutcomeUnknown']);
export type AlphaAvailability = 'unavailable' | 'unknown';

export class AlphaAvailabilityError extends Error {
  constructor(readonly status: AlphaAvailability) {
    super(status === 'unknown'
      ? 'The local Alpha session state is unknown.'
      : 'The local Alpha session is unavailable.');
    this.name = 'AlphaAvailabilityError';
  }
}

export class AlphaResponseError extends Error {
  readonly status = 'unknown' as const;

  constructor() {
    super('The local Alpha response is incompatible.');
    this.name = 'AlphaResponseError';
  }
}

export async function decodeAlphaSession(payload: unknown): Promise<SessionView> {
  const response = decodeEnvelope(payload);
  if (response.status === 'unavailable' || response.status === 'unknown') throwAvailability(response);
  if (response.status !== 'available') incompatible();
  if (!safeSeq(response.last_applied_seq) || typeof response.digest !== 'string' || !DIGEST.test(response.digest)) unknown();

  const session = decodeSession(response.session);
  const events = decodeEvents(response.events, session.session_id, response.last_applied_seq);
  const provenance = object(response.provenance);
  exactKeys(provenance, ['source', 'relay_ingress_verified', 'gateway_schema_verified']);
  if (
    !['local-alpha-projector', 'local-host-direct'].includes(String(provenance.source))
    || provenance.relay_ingress_verified !== (provenance.source === 'local-alpha-projector')
    || provenance.gateway_schema_verified !== true
  ) unknown();
  const aggregateFileCount = decodeUnavailableChanges(response.changes, provenance.source === 'local-host-direct');
  try {
    const verification = await verifySnapshotDigest(response as Record<string, unknown> & { digest: string });
    if (!verification.ok) unknown();
  } catch (error) {
    if (error instanceof AlphaResponseError) throw error;
    incompatible();
  }

  const state: ViewState = {
    session,
    events,
    timeline: events.map((event) => ({ kind: 'event' as const, seq: event.seq, event })),
    tools: [],
    activePermissionId: null,
    diffFileCount: aggregateFileCount,
    lastAppliedSeq: response.last_applied_seq,
    gapToSeq: null,
    digestStatus: 'verified',
    expectedDigest: response.digest,
    actualDigest: response.digest,
    versionStatus: 'ok',
    duplicatesDropped: 0,
    outcomeUnknownTools: [],
  };

  return {
    state,
    display: {
      title: 'Read-only Alpha session',
      hostLabel: 'Local Alpha Host',
      workspaceLabel: 'Workspace details unavailable',
      lastActivityLabel: events.length === 0 ? 'Waiting for Host activity' : `Host state verified at sequence ${response.last_applied_seq}`,
    },
    approval: null,
    changes: {
      status: 'unavailable',
      source: null,
      baseline: null,
      files: [],
      reason: 'Read-only Alpha does not expose a verified workspace diff.',
    },
    provenance: 'alpha-readonly',
    mode: 'readonly-alpha',
    writable: false,
  };
}

export function decodeAlphaFailure(payload: unknown): never {
  const response = decodeEnvelope(payload);
  if (response.status !== 'unavailable' && response.status !== 'unknown') incompatible();
  return throwAvailability(response);
}

function decodeEnvelope(payload: unknown): Record<string, unknown> {
  const response = object(payload);
  exactKeys(response, ['schema', 'status', 'session', 'last_applied_seq', 'digest', 'events', 'changes', 'provenance']);
  if (response.schema !== 'nomad.alpha.readonly.v1') incompatible();
  return response;
}

function throwAvailability(response: Record<string, unknown>): never {
  if (response.status !== 'unavailable' && response.status !== 'unknown') incompatible();
  if (response.session !== null || response.last_applied_seq !== null || response.digest !== null) incompatible();
  if (!Array.isArray(response.events) || response.events.length !== 0) incompatible();
  decodeUnavailableChanges(response.changes);
  const provenance = object(response.provenance);
  exactKeys(provenance, ['source', 'relay_ingress_verified', 'gateway_schema_verified']);
  if (
    !['local-alpha-gateway', 'local-host-direct'].includes(String(provenance.source))
    || provenance.relay_ingress_verified !== false
    || provenance.gateway_schema_verified !== false
  ) incompatible();
  throw new AlphaAvailabilityError(response.status);
}

function decodeSession(value: unknown): Session {
  const session = object(value);
  exactKeys(session, ['session_id', 'semantics_version', 'turn_id', 'turn_state', 'host_connectivity', 'client_freshness', 'updated_at']);
  if (typeof session.session_id !== 'string' || !SESSION_ALIAS.test(session.session_id)) unknown();
  if (session.turn_id !== null && (typeof session.turn_id !== 'string' || !TURN_ALIAS.test(session.turn_id))) unknown();
  if (session.semantics_version !== '1.0.0' || typeof session.turn_state !== 'string' || !TURN_STATES.has(session.turn_state as Session['turn_state'])) unknown();
  if (session.host_connectivity !== 'Online' && session.host_connectivity !== 'Offline') unknown();
  if (!['Live', 'Reconnecting', 'Stale'].includes(String(session.client_freshness)) || !timestamp(session.updated_at)) unknown();
  return {
    session_id: session.session_id,
    semantics_version: '1.0.0',
    turn_id: session.turn_id as string | null,
    turn_state: session.turn_state as Session['turn_state'],
    host_connectivity: session.host_connectivity,
    client_freshness: session.client_freshness as Session['client_freshness'],
    updated_at: session.updated_at as string,
  };
}

function decodeEvents(value: unknown, sessionId: string, topSeq: number): ContractEvent[] {
  if (!Array.isArray(value) || value.length > 32) unknown();
  let previous = 0;
  const ids = new Set<string>();
  return value.map((item) => {
    const event = object(item);
    allowedKeys(event, ['event_type', 'session_id', 'event_id', 'turn_id', 'seq', 'timestamp', 'durable']);
    for (const required of ['event_type', 'session_id', 'event_id', 'seq', 'timestamp', 'durable']) {
      if (!(required in event)) unknown();
    }
    if (typeof event.event_type !== 'string' || !EVENT_TYPES.has(event.event_type as EventType)) unknown();
    if (event.session_id !== sessionId || typeof event.event_id !== 'string' || !EVENT_ALIAS.test(event.event_id) || ids.has(event.event_id)) unknown();
    if (!safeSeq(event.seq) || event.seq === 0 || event.seq <= previous || event.seq > topSeq) unknown();
    if (event.turn_id !== undefined && event.turn_id !== null && (typeof event.turn_id !== 'string' || !TURN_ALIAS.test(event.turn_id))) unknown();
    if (!timestamp(event.timestamp) || event.durable !== true) unknown();
    previous = event.seq;
    ids.add(event.event_id);
    return {
      event_type: event.event_type as EventType,
      session_id: sessionId,
      turn_id: (event.turn_id ?? null) as string | null,
      event_id: event.event_id,
      seq: event.seq,
      timestamp: event.timestamp as string,
      durable: true,
      payload: {},
    };
  });
}

function decodeUnavailableChanges(value: unknown, directSource = false): number {
  const changes = object(value);
  exactKeys(changes, directSource ? ['status', 'files', 'aggregate_file_count'] : ['status', 'files']);
  if (changes.status !== 'unavailable' || !Array.isArray(changes.files) || changes.files.length !== 0) unknown();
  if (directSource && (!safeSeq(changes.aggregate_file_count) || Number(changes.aggregate_file_count) > 256)) unknown();
  return directSource ? Number(changes.aggregate_file_count) : 0;
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) incompatible();
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) unknown();
}

function allowedKeys(value: Record<string, unknown>, allowed: string[]): void {
  const keys = new Set(allowed);
  if (Object.keys(value).some((key) => !keys.has(key))) unknown();
}

function safeSeq(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function unknown(): never {
  throw new AlphaResponseError();
}

function incompatible(): never {
  throw new AlphaResponseError();
}
