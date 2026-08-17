/**
 * Mock Host / Relay API backed by inlined golden traces
 * (see src/mock/generated-traces.ts).
 *
 * When swapping in a real E2E Host/Relay, keep the same function
 * signatures (`loadTrace`, `resume`, `submitCommand`, etc.) and replace
 * the body. See README.md#e2e-swap.
 */

import { getTrace, listTraceIds, MANIFEST } from './generated-traces';
import type {
  ContractEvent,
  Snapshot,
  TraceMeta,
  ResumeRequest,
  ResumeResult,
  Command,
  CommandResult,
  CommandStatus,
} from '../contracts/types';

export interface TraceEntry {
  trace: TraceMeta;
  snapshot: Snapshot;
}

// ---------- In-memory mock session ----------

class MockSession {
  readonly sessionId: string;
  private events: ContractEvent[] = [];
  private snapshot: Snapshot | null = null;
  private lastSeq = 0;
  private commandResults = new Map<string, { status: CommandStatus; result: CommandResult }>();

  constructor(sessionId: string) {
    this.sessionId = sessionId;
  }

  push(event: ContractEvent): void {
    if (event.seq <= this.lastSeq) return; // idempotent duplicate
    this.events.push(event);
    this.lastSeq = event.seq;
  }

  setSnapshot(s: Snapshot): void {
    this.snapshot = s;
    this.lastSeq = s.snapshot_seq;
  }

  snapshotAt(seq: number): Snapshot | null {
    if (!this.snapshot) return null;
    if (seq <= this.snapshot.snapshot_seq) return this.snapshot;
    return null;
  }

  eventsAfter(seq: number): ContractEvent[] {
    return this.events.filter((e) => e.seq > seq);
  }

  submit(cmd: Command): { status: CommandStatus; result: CommandResult } {
    const existing = this.commandResults.get(cmd.request_id);
    if (existing) return existing; // INV-003-1 idempotency

    // Phase 1: RelayReceived — the relay has accepted the command
    const result: CommandResult = { error_code: 'OK', error_message: null };
    const relayReceived: { status: CommandStatus; result: CommandResult } = {
      status: 'RelayReceived',
      result,
    };
    this.commandResults.set(cmd.request_id, relayReceived);

    // Phase 2: HostAccepted — host acknowledges the command
    // (In real life this would be an RPC; here we advance synchronously.)
    const hostAccepted: { status: CommandStatus; result: CommandResult } = {
      status: 'HostAccepted',
      result,
    };
    this.commandResults.set(cmd.request_id, hostAccepted);

    // Phase 3: Executing → Completed
    switch (cmd.command_type) {
      case 'reply':
      case 'stop': {
        const seq = this.lastSeq + 1;
        result.accepted_at_seq = seq;
        result.event_id = `${cmd.session_id}:${seq}`;
        break;
      }
      case 'interrupt_and_send': {
        const seq = this.lastSeq + 1;
        result.stopped_at_seq = seq;
        result.new_event_id = `${cmd.session_id}:${seq + 1}`;
        break;
      }
      case 'permission_decision': {
        const seq = this.lastSeq + 1;
        result.resolved_at_seq = seq;
        result.event_id = `${cmd.session_id}:${seq}`;
        break;
      }
    }
    const completed: { status: CommandStatus; result: CommandResult } = {
      status: 'Completed',
      result,
    };
    this.commandResults.set(cmd.request_id, completed);
    return completed;
  }

  getCommand(requestId: string): { status: CommandStatus; result: CommandResult } {
    const entry = this.commandResults.get(requestId);
    if (!entry) return { status: 'RelayReceived', result: { error_code: 'OK', error_message: null } };
    return entry;
  }
}

class MockHost {
  private sessions = new Map<string, MockSession>();

  listTraces(): { id: string; scenario: string; session_id: string; description: string }[] {
    return MANIFEST.traces.map((t) => ({
      id: t.id,
      scenario: t.scenario,
      session_id: t.file.replace(/^trace-/, '').replace(/\.json$/, ''),
      description: t.description,
    }));
  }

  getTraceMeta(traceId: string): { trace: TraceMeta; snapshot: Snapshot } | null {
    const entry = getTrace(traceId);
    if (!entry) return null;
    return entry;
  }

  loadTrace(traceId: string): { sessionId: string; events: ContractEvent[]; snapshot: Snapshot } | null {
    const entry = getTrace(traceId);
    if (!entry) return null;
    const { trace } = entry as TraceEntry;
    let { snapshot } = entry as TraceEntry;
    // Synthetic/disposable product checkpoint: expose the real pending state
    // at seq 3 for the permission scenario. The snapshot is canonical and
    // derived from the same golden events; it is not a live OpenCode capture.
    if (traceId === 'trace-004-permission-competition') {
      snapshot = {
        session_id: 'sess_perm_004',
        snapshot_seq: 3,
        digest: 'sha256:a85ee2dbce17caf1ab9909727170487d6cd7ea0119e5af7a18a1e564010dc532',
        last_applied_seq: 3,
        turn_state: 'NeedsPermission',
        turn_id: 'turn_001',
        host_connectivity: 'Online',
        client_freshness: 'Live',
        state_summary: {
          session_status: 'active',
          active_turn: 'turn_001',
          active_permission: 'perm_001',
          diff_file_count: 0,
          test_status: null,
          tool_states: [],
        },
        created_at: '2026-08-17T13:00:03Z',
        version: '1.0.0',
      };
    }
    const m = new MockSession(trace.session_id);
    for (const ev of trace.events.filter((event) => event.seq <= snapshot.snapshot_seq)) m.push(ev);
    m.setSnapshot(snapshot);
    this.sessions.set(trace.session_id, m);
    return {
      sessionId: trace.session_id,
      events: trace.events.filter((event) => event.seq <= snapshot.snapshot_seq),
      snapshot,
    };
  }

  async resume(req: ResumeRequest): Promise<ResumeResult> {
    const m = this.sessions.get(req.session_id);
    if (!m) {
      return { result_code: 'ERR_NO_SESSION', session_id: req.session_id, error_message: 'Session not found' };
    }
    const snap = m.snapshotAt(req.last_applied_seq);
    if (!snap) {
      return {
        result_code: 'ERR_SNAPSHOT_MISMATCH',
        session_id: req.session_id,
        error_message: 'Snapshot for this seq is not available',
      };
    }
    const eventsAfter = m.eventsAfter(req.last_applied_seq);
    return {
      result_code: 'OK',
      session_id: req.session_id,
      snapshot: snap,
      events: eventsAfter,
    };
  }

  submitCommand(cmd: Command): { status: CommandStatus; result: CommandResult } {
    let m = this.sessions.get(cmd.session_id);
    if (!m) {
      m = new MockSession(cmd.session_id);
      this.sessions.set(cmd.session_id, m);
    }
    return m.submit(cmd);
  }

  getCommandStatus(sessionId: string, requestId: string): { status: CommandStatus; result: CommandResult } {
    const m = this.sessions.get(sessionId);
    if (!m) return { status: 'RelayReceived', result: { error_code: 'OK', error_message: null } };
    return m.getCommand(requestId);
  }
}

let _host: MockHost | null = null;

export function createMockHost(): MockHost {
  if (_host) return _host;
  _host = new MockHost();
  return _host;
}

export function _resetMockHost(): void {
  _host = null;
}

export function getMockHost(): MockHost {
  return createMockHost();
}

export { listTraceIds };
