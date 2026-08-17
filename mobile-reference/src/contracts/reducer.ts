/**
 * Deterministic Session reducer.
 *
 * Input: snapshot (optional recovery base) + ordered durable events.
 * Output: the full view model used by the Mobile client.
 *
 * The reducer is a pure function of (snapshot + events) => state. Given
 * the same inputs, it must produce the same digest as the Host's snapshot
 * for that seq. Gap / duplicate / version handling is implemented here
 * rather than in the UI, so that the contract conformance test can assert
 * on the reducer directly.
 */

import {
  ContractEvent,
  Snapshot,
  StateSummary,
  ToolState,
  Session,
  ResumeResultCode,
} from './types';
import { computeSnapshotDigest } from './digest';

export interface ViewState {
  session: Session;
  events: ContractEvent[];
  timeline: TimelineNode[];
  tools: ToolState[];
  activePermissionId: string | null;
  diffFileCount: number;
  lastAppliedSeq: number;
  /** Gap detection: when non-null, seq range [lastAppliedSeq+1, gapToSeq] is missing. */
  gapToSeq: number | null;
  /** Digest verification result at last snapshot point. */
  digestStatus: 'verified' | 'pending' | 'mismatch' | 'none';
  expectedDigest: string | null;
  actualDigest: string | null;
  versionStatus: 'ok' | 'incompatible';
  /** Number of duplicate events observed (idempotent, no side effect). */
  duplicatesDropped: number;
  /** Outcome-unknown tool invocations still waiting on user action. */
  outcomeUnknownTools: string[];
}

export type TimelineNode =
  | { kind: 'event'; seq: number; event: ContractEvent }
  | { kind: 'gap'; fromSeq: number; toSeq: number }
  | { kind: 'note'; text: string };

const SUPPORTED_VERSION = '1.0.0';

const EVENT_TYPES = new Set<string>([
  'session.created',
  'session.updated',
  'turn.started',
  'message.accepted',
  'message.completed',
  'tool.started',
  'tool.completed',
  'tool.failed',
  'permission.requested',
  'permission.resolved',
  'diff.updated',
  'turn.stopping',
  'turn.completed',
  'turn.cancelled',
  'turn.failed',
  'turn.outcome_unknown',
  'session.compacted',
]);

/**
 * Apply events to an existing state. Duplicates (same event_id) are dropped
 * idempotently. Gaps are marked but NOT auto-filled (INV-004-3).
 */
export function reduceEvents(
  base: ViewState,
  events: ContractEvent[]
): ViewState {
  const byId = new Set<string>([...base.events.map((e) => e.event_id)]);
  const out: ViewState = {
    ...base,
    events: [...base.events],
    timeline: [...base.timeline],
    duplicatesDropped: base.duplicatesDropped,
    tools: [...base.tools.map((t) => ({ ...t }))],
  };

  for (const ev of events) {
    // Unknown event type -> treat as protocol mismatch; fail closed.
    if (!EVENT_TYPES.has(ev.event_type)) {
      return {
        ...out,
        versionStatus: 'incompatible',
        session: { ...out.session, client_freshness: 'Stale' },
      };
    }
    if (byId.has(ev.event_id)) {
      out.duplicatesDropped += 1;
      continue;
    }
    byId.add(ev.event_id);

    // Gap detection before applying: the "last seq seen" is lastAppliedSeq,
    // which reflects the highest seq already incorporated into the state
    // (either from the snapshot recovery base or from previously applied
    // events).
    const last = out.lastAppliedSeq;
    if (ev.seq > last + 1) {
      const from = last + 1;
      out.timeline.push({ kind: 'gap', fromSeq: from, toSeq: ev.seq - 1 });
      out.gapToSeq = ev.seq - 1;
    }

    out.events.push(ev);
    out.lastAppliedSeq = ev.seq;
    out.timeline.push({ kind: 'event', seq: ev.seq, event: ev });

    applyEventMutations(out, ev);
  }

  return out;
}

function applyEventMutations(out: ViewState, ev: ContractEvent): void {
  const payload = ev.payload ?? {};
  switch (ev.event_type) {
    case 'session.created':
      out.session = {
        session_id: ev.session_id,
        semantics_version: out.session.semantics_version,
        turn_id: null,
        turn_state: 'None',
        host_connectivity: out.session.host_connectivity,
        client_freshness: out.session.client_freshness,
        updated_at: ev.timestamp,
      };
      break;
    case 'session.updated':
      out.session = { ...out.session, updated_at: ev.timestamp };
      break;
    case 'turn.started':
      out.session = {
        ...out.session,
        turn_id: ev.turn_id,
        turn_state: 'Running',
        updated_at: ev.timestamp,
      };
      break;
    case 'message.accepted':
      // Mobile reply/reply-ack; keep state but mark updated.
      out.session = { ...out.session, updated_at: ev.timestamp };
      break;
    case 'message.completed':
      out.session = { ...out.session, updated_at: ev.timestamp };
      break;
    case 'tool.started':
      upsertTool(out, payload.tool_name ?? 'unknown', 'Running');
      break;
    case 'tool.completed':
      upsertTool(out, payload.tool_name ?? 'unknown', 'Completed');
      break;
    case 'tool.failed':
      upsertTool(out, payload.tool_name ?? 'unknown', 'Failed');
      break;
    case 'turn.stopping':
      out.session = { ...out.session, turn_state: 'Stopping', updated_at: ev.timestamp };
      break;
    case 'turn.completed':
      out.session = {
        ...out.session,
        turn_state: 'Completed',
        turn_id: null,
        updated_at: ev.timestamp,
      };
      break;
    case 'turn.cancelled':
      out.session = {
        ...out.session,
        turn_state: 'Cancelled',
        turn_id: null,
        updated_at: ev.timestamp,
      };
      break;
    case 'turn.failed':
      out.session = {
        ...out.session,
        turn_state: 'Failed',
        turn_id: null,
        updated_at: ev.timestamp,
      };
      break;
    case 'turn.outcome_unknown':
      out.session = {
        ...out.session,
        turn_state: 'OutcomeUnknown',
        updated_at: ev.timestamp,
      };
      if (payload.tool_name) {
        if (!out.outcomeUnknownTools.includes(payload.tool_name)) {
          out.outcomeUnknownTools.push(payload.tool_name);
        }
      }
      break;
    case 'permission.requested':
      out.session = { ...out.session, turn_state: 'NeedsPermission', updated_at: ev.timestamp };
      out.activePermissionId = payload.permission_id ?? ev.event_id;
      break;
    case 'permission.resolved':
      out.session = {
        ...out.session,
        turn_state: 'Running',
        updated_at: ev.timestamp,
      };
      out.activePermissionId = null;
      break;
    case 'diff.updated': {
      const count = parseDiffCount(payload.summary);
      out.diffFileCount = count ?? out.diffFileCount;
      break;
    }
    case 'session.compacted':
      out.timeline.push({
        kind: 'note',
        text: `Events older than seq ${ev.seq} were compacted; recovered via snapshot.`,
      });
      break;
  }
}

function upsertTool(out: ViewState, name: string, status: ToolState['status']): void {
  const existing = out.tools.find((t) => t.tool_name === name);
  if (existing) {
    existing.status = status;
  } else {
    out.tools.push({ tool_name: name, status });
  }
}

function parseDiffCount(summary: string | null | undefined): number | null {
  if (!summary) return null;
  const m = summary.match(/(\d+)\s+files?\s+changed/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

// ---------- Initial construction ----------

export interface InitOptions {
  sessionId: string;
  contractVersion?: string;
}

export function initEmptyState(opts: InitOptions): ViewState {
  return {
    session: {
      session_id: opts.sessionId,
      semantics_version: opts.contractVersion ?? SUPPORTED_VERSION,
      turn_id: null,
      turn_state: 'None',
      host_connectivity: 'Online',
      client_freshness: 'Reconnecting',
      updated_at: new Date().toISOString(),
    },
    events: [],
    timeline: [],
    tools: [],
    activePermissionId: null,
    diffFileCount: 0,
    lastAppliedSeq: 0,
    gapToSeq: null,
    digestStatus: 'none',
    expectedDigest: null,
    actualDigest: null,
    versionStatus: 'ok',
    duplicatesDropped: 0,
    outcomeUnknownTools: [],
  };
}

// ---------- Snapshot recovery ----------

/**
 * Recover from a snapshot. The snapshot is trusted as a recovery base but
 * its digest is verified before the client is allowed to transition to
 * `client_freshness=Live`. INV-004-1.
 *
 * If the digest mismatches, `client_freshness` stays Stale and safe
 * operations (Approval, Stop) are blocked at the UI layer.
 */
export async function recoverFromSnapshot(
  snapshot: Snapshot,
  eventsAfter: ContractEvent[] = []
): Promise<ViewState> {
  const base: ViewState = {
    session: {
      session_id: snapshot.session_id,
      semantics_version: snapshot.version,
      turn_id: snapshot.turn_id,
      turn_state: snapshot.turn_state,
      host_connectivity: snapshot.host_connectivity,
      client_freshness: 'Reconnecting',
      updated_at: snapshot.created_at,
    },
    events: [],
    timeline: [],
    tools: snapshot.state_summary.tool_states.map((t) => ({ ...t })),
    activePermissionId: snapshot.state_summary.active_permission,
    diffFileCount: snapshot.state_summary.diff_file_count,
    lastAppliedSeq: snapshot.last_applied_seq,
    gapToSeq: null,
    digestStatus: 'pending',
    expectedDigest: snapshot.digest,
    actualDigest: null,
    versionStatus: snapshot.version === SUPPORTED_VERSION ? 'ok' : 'incompatible',
    duplicatesDropped: 0,
    outcomeUnknownTools: [],
  };

  // Compute expected digest from the full received snapshot (excluding
  // digest field) and compare against the declared digest. The digest
  // verification must operate on the raw snapshot object, not a lossy
  // projection. Reducer projection consistency is a separate concern.
  const actual = await computeSnapshotDigest(snapshot as unknown as import('./digest').SnapshotLike);
  base.actualDigest = actual;
  if (actual === snapshot.digest) {
    base.digestStatus = 'verified';
    // Only after verification + applied events do we transition to Live.
    const applied = reduceEvents(base, eventsAfter);
    if (applied.gapToSeq === null && applied.versionStatus === 'ok') {
      applied.session = { ...applied.session, client_freshness: 'Live' };
    }
    return applied;
  } else {
    base.digestStatus = 'mismatch';
    base.session = { ...base.session, client_freshness: 'Stale' };
    return base;
  }
}

/** Reduce current state into a snapshot-shaped object for digest computation. */
function reduceToSnapshot(state: ViewState, _ref: Snapshot): Snapshot {
  const summary: StateSummary = {
    session_status: state.session.turn_state === 'None' ? 'idle' : 'active',
    active_turn: state.session.turn_id,
    active_permission: state.activePermissionId,
    diff_file_count: state.diffFileCount,
    test_status: null,
    tool_states: state.tools.map((t) => ({ ...t })),
  };
  return {
    session_id: state.session.session_id,
    snapshot_seq: state.lastAppliedSeq,
    digest: '',
    last_applied_seq: state.lastAppliedSeq,
    turn_state: state.session.turn_state,
    turn_id: state.session.turn_id,
    host_connectivity: state.session.host_connectivity,
    client_freshness: state.session.client_freshness,
    state_summary: summary,
    created_at: state.session.updated_at,
    version: state.session.semantics_version,
  };
}

// ---------- Safe-operation gate ----------

/**
 * INV-001-4: Approval and Stop submissions MUST be rejected unless
 * host_connectivity=Online AND client_freshness=Live.
 */
export function canSubmitSafeOperations(state: ViewState): { ok: true } | { ok: false; reason: string } {
  if (state.session.host_connectivity !== 'Online') {
    return { ok: false, reason: 'Host is offline.' };
  }
  if (state.session.client_freshness !== 'Live') {
    return { ok: false, reason: 'Client is not live (reconnecting or stale).' };
  }
  if (state.versionStatus !== 'ok') {
    return { ok: false, reason: 'Protocol version is incompatible. Safe operations are blocked.' };
  }
  if (state.digestStatus !== 'verified') {
    return { ok: false, reason: `Snapshot digest is ${state.digestStatus}. Safe operations require a verified snapshot.` };
  }
  return { ok: true };
}

// ---------- Resume result application ----------

/**
 * Apply a ResumeResult to current state. Handles gap, compaction, version,
 * retention, no-session and mismatch paths.
 */
export async function applyResumeResult(
  current: ViewState,
  result: {
    result_code: ResumeResultCode;
    session_id: string;
    snapshot?: Snapshot;
    events?: ContractEvent[];
    gap_from_seq?: number | null;
    gap_to_seq?: number | null;
    compaction_boundary_seq?: number | null;
    error_message?: string | null;
  }
): Promise<ViewState> {
  switch (result.result_code) {
    case 'OK':
      if (result.snapshot && result.snapshot.last_applied_seq > current.lastAppliedSeq) {
        return recoverFromSnapshot(result.snapshot, result.events ?? []);
      }
      return reduceEvents(current, result.events ?? []);
    case 'ERR_GAP_DETECTED':
      return {
        ...current,
        session: { ...current.session, client_freshness: 'Stale' },
        gapToSeq: result.gap_to_seq ?? current.gapToSeq,
        timeline: [
          ...current.timeline,
          {
            kind: 'note',
            text: `Gap detected between seq ${result.gap_from_seq} and ${result.gap_to_seq}. Manual recovery required (auto-fill forbidden).`,
          },
        ],
      };
    case 'ERR_SNAPSHOT_MISMATCH':
      return {
        ...current,
        session: { ...current.session, client_freshness: 'Stale' },
        digestStatus: 'mismatch',
      };
    case 'ERR_VERSION_INCOMPATIBLE':
      return {
        ...current,
        versionStatus: 'incompatible',
        session: { ...current.session, client_freshness: 'Stale' },
      };
    case 'ERR_RETENTION_EXCEEDED':
      return {
        ...current,
        session: { ...current.session, client_freshness: 'Stale' },
        timeline: [
          ...current.timeline,
          {
            kind: 'note',
            text: 'Retention window exceeded. Recovery not possible; start a new session.',
          },
        ],
      };
    case 'ERR_NO_SESSION':
      return {
        ...current,
        session: { ...current.session, client_freshness: 'Stale' },
        timeline: [
          ...current.timeline,
          { kind: 'note', text: 'Session not found on Host.' },
        ],
      };
  }
}

// Re-export some helpers
export { parseDiffCount };
export const _testing = { reduceToSnapshot };
