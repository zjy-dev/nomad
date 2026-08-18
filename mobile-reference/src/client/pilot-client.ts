import { recoverFromSnapshot } from '../contracts/reducer';
import type { Command } from '../contracts/types';
import { createMockHost } from '../mock/api';
import type { SessionClient, SessionView, TraceLabClient, TraceSummary } from './types';

const PILOT_TRACE = 'trace-004-permission-competition';

/**
 * Deterministic Pilot adapter used by the local product and browser tests.
 * UI components only see SessionClient; replacing this adapter requires no UI edits.
 */
export class PilotSessionClient implements SessionClient, TraceLabClient {
  private readonly host = createMockHost();
  private currentTraceId = PILOT_TRACE;

  async loadCurrentSession(): Promise<SessionView> {
    this.currentTraceId = PILOT_TRACE;
    return this.loadTrace(PILOT_TRACE, 'pilot');
  }

  async refreshSession(_sessionId: string): Promise<SessionView> {
    return this.loadTrace(this.currentTraceId, this.currentTraceId === PILOT_TRACE ? 'pilot' : 'trace-lab');
  }

  async submitCommand(command: Command) {
    return this.host.submitCommand(command);
  }

  async getCommandStatus(sessionId: string, requestId: string) {
    return this.host.getCommandStatus(sessionId, requestId);
  }

  async listTraceSessions(): Promise<TraceSummary[]> {
    return this.host.listTraces().map(({ id, scenario, description }) => ({ id, scenario, description }));
  }

  async loadTraceSession(traceId: string): Promise<SessionView> {
    this.currentTraceId = traceId;
    return this.loadTrace(traceId, 'trace-lab');
  }

  private async loadTrace(traceId: string, provenance: SessionView['provenance']): Promise<SessionView> {
    const loaded = this.host.loadTrace(traceId);
    if (!loaded) throw new Error(`Trace ${traceId} is unavailable.`);
    const state = await recoverFromSnapshot(loaded.snapshot, []);
    state.events = [...loaded.events];
    state.timeline = loaded.events.map((event) => ({ kind: 'event' as const, seq: event.seq, event }));
    // The version-mismatch golden trace carries negotiation failure outside
    // the snapshot schema. Reflect that contract fact in the trace-lab view
    // instead of letting successful digest verification imply Live/safe.
    if (traceId === 'trace-007-version-mismatch') {
      state.versionStatus = 'incompatible';
      state.session = { ...state.session, client_freshness: 'Stale' };
    }

    return {
      state,
      display: {
        title: provenance === 'pilot' ? 'Controlled refactor' : humanizeScenario(traceId),
        hostLabel: 'MacBook Pilot Host',
        workspaceLabel: provenance === 'pilot' ? 'Disposable workspace' : 'Trace lab fixture',
        lastActivityLabel: lastActivity(state),
      },
      approval: state.activePermissionId
        ? {
            tool: 'Workspace editor',
            operation: 'Modify an existing source file',
            arguments: [
              { label: 'Scope', value: 'One tracked source file' },
              { label: 'Intent', value: 'Apply the refactor prepared by the agent' },
            ],
            workingDirectory: 'Disposable Pilot workspace',
            resources: ['Tracked source file', 'Current working tree'],
            expiresAt: '2026-08-18T18:30:00+08:00',
            source: provenance === 'pilot' ? 'Deterministic Pilot Host adapter' : 'Golden trace adapter',
            actionHash: 'sha256:pilot-deny-only',
          }
        : null,
      changes: {
        status: 'empty',
        source: null,
        baseline: null,
        files: [],
        reason: 'The Host has not supplied a verified workspace diff for this session.',
      },
      provenance,
    };
  }
}

function humanizeScenario(traceId: string): string {
  return traceId.replace(/^trace-\d+-/, '').replaceAll('-', ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function lastActivity(state: SessionView['state']): string {
  const last = state.events[state.events.length - 1];
  if (!last) return 'Waiting for the first Host update';
  switch (last.event_type) {
    case 'permission.requested': return 'Paused before changing the workspace';
    case 'tool.started': return `Started ${last.payload.tool_name ?? 'a tool'}`;
    case 'tool.completed': return `Finished ${last.payload.tool_name ?? 'a tool'}`;
    case 'turn.completed': return 'Finished the task';
    case 'turn.failed': return 'Task ended with an error';
    default: return 'Session state updated';
  }
}
