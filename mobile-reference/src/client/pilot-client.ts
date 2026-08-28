import { recoverFromSnapshot } from '../contracts/reducer';
import { createMockHost } from '../mock/api';
import type { PublicCommandRequest, SessionClient, SessionView, TraceLabClient, TraceSummary } from './types';

type InternalCommand = Parameters<ReturnType<typeof createMockHost>['submitCommand']>[0];

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

  async submitCommand(command: PublicCommandRequest) {
    if (!isExactPublicCommand(command)) {
      return { status: 'Rejected' as const, result: { error_code: 'ERR_SAFETY_BLOCKED' as const, error_message: 'Unsupported public command.' } };
    }
    return this.host.submitCommand(toInternalCommand(command));
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

function toInternalCommand(command: PublicCommandRequest): InternalCommand {
  switch (command.command_type) {
    case 'reply':
      return {
        command_type: 'reply', request_id: command.request_id, session_id: command.session_id,
        seq: command.observed_seq, turn_id: command.turn_id, content: command.content,
      };
    case 'deny':
      return {
        command_type: 'permission_decision', request_id: command.request_id, session_id: command.session_id,
        seq: command.observed_seq, permission_id: command.permission_id, decision: 'deny',
        action_hash: command.action_hash, expires_at: command.expires_at,
      };
    case 'stop':
      return {
        command_type: 'stop', request_id: command.request_id, session_id: command.session_id,
        seq: command.observed_seq, target_turn_id: command.target_turn_id,
      };
  }
}

function isExactPublicCommand(command: unknown): command is PublicCommandRequest {
  if (!isPlainDataObject(command)) return false;
  const value = command as Record<string, unknown>;
  if (!boundedString(value.request_id, 128) || !boundedString(value.session_id, 64) || !Number.isSafeInteger(value.observed_seq) || Number(value.observed_seq) < 0) return false;
  switch (value.command_type) {
    case 'reply':
      return exactFields(value, ['command_type', 'request_id', 'session_id', 'observed_seq', 'content'], ['turn_id'])
        && boundedString(value.content, 65536)
        && (!Object.hasOwn(value, 'turn_id') || value.turn_id === null || boundedString(value.turn_id, 64));
    case 'deny':
      return exactFields(value, ['command_type', 'request_id', 'session_id', 'observed_seq', 'permission_id', 'action_hash', 'expires_at'])
        && boundedString(value.permission_id, 128) && boundedString(value.action_hash, 128)
        && strictUtcSecond(value.expires_at);
    case 'stop':
      return exactFields(value, ['command_type', 'request_id', 'session_id', 'observed_seq', 'target_turn_id'])
        && boundedString(value.target_turn_id, 64);
    default:
      return false;
  }
}

function exactFields(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((field) => Object.hasOwn(value, field)) && Object.keys(value).every((field) => allowed.has(field));
}

function isPlainDataObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && [...value].length >= 1 && [...value].length <= maximum;
}

function strictUtcSecond(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value.replace('Z', '.000Z');
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
