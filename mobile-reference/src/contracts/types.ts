/**
 * Contract types derived from contracts/schemas/*.schema.json (v1).
 * This file is the single source of truth for the Mobile Reference client.
 * Keep field names and enums in sync with the schemas — the reducer and
 * mock API consume the raw contract JSON unchanged.
 */

// ---------- Session (session.schema.json) ----------

export type TurnState =
  | 'None'
  | 'Running'
  | 'NeedsInput'
  | 'NeedsPermission'
  | 'Stopping'
  | 'Completed'
  | 'Cancelled'
  | 'Failed'
  | 'OutcomeUnknown';

export type HostConnectivity = 'Online' | 'Offline';
export type ClientFreshness = 'Live' | 'Reconnecting' | 'Stale';

export interface Session {
  session_id: string;
  semantics_version: string;
  turn_id: string | null;
  turn_state: TurnState;
  host_connectivity: HostConnectivity;
  client_freshness: ClientFreshness;
  updated_at: string;
}

// ---------- Events (events.schema.json) ----------

export type EventType =
  | 'session.created'
  | 'session.updated'
  | 'turn.started'
  | 'message.accepted'
  | 'message.completed'
  | 'tool.started'
  | 'tool.completed'
  | 'tool.failed'
  | 'permission.requested'
  | 'permission.resolved'
  | 'diff.updated'
  | 'turn.stopping'
  | 'turn.completed'
  | 'turn.cancelled'
  | 'turn.failed'
  | 'turn.outcome_unknown'
  | 'session.compacted';

export interface EventPayload {
  summary?: string | null;
  state_change?: string | null;
  tool_name?: string | null;
  permission_id?: string | null;
  action?: string | null;
  reason?: string | null;
  [key: string]: unknown;
}

export interface ChunkRef {
  ref_id: string;
  size_bytes: number;
  encoding: string;
}

export interface ContractEvent {
  event_type: EventType;
  session_id: string;
  turn_id: string | null;
  event_id: string;
  seq: number;
  timestamp: string;
  durable: true;
  payload: EventPayload;
  chunk_ref?: ChunkRef | null;
}

// ---------- Snapshot (snapshot.schema.json) ----------

export interface ToolState {
  tool_name: string;
  status: 'NotStarted' | 'Running' | 'Completed' | 'Failed';
}

export interface StateSummary {
  session_status: string;
  active_turn: string | null;
  active_permission: string | null;
  diff_file_count: number;
  test_status: string | null;
  tool_states: ToolState[];
}

export interface Snapshot {
  session_id: string;
  snapshot_seq: number;
  digest: string;
  last_applied_seq: number;
  turn_state: TurnState;
  turn_id: string | null;
  host_connectivity: HostConnectivity;
  client_freshness: ClientFreshness;
  state_summary: StateSummary;
  created_at: string;
  version: string;
}

export interface ResumeRequest {
  session_id: string;
  last_applied_seq: number;
  client_version: string;
  known_snapshot_seq?: number | null;
  known_snapshot_digest?: string | null;
}

export type ResumeResultCode =
  | 'OK'
  | 'ERR_GAP_DETECTED'
  | 'ERR_SNAPSHOT_MISMATCH'
  | 'ERR_RETENTION_EXCEEDED'
  | 'ERR_VERSION_INCOMPATIBLE'
  | 'ERR_NO_SESSION';

export interface ResumeResult {
  result_code: ResumeResultCode;
  session_id: string;
  snapshot?: Snapshot;
  events?: ContractEvent[];
  gap_from_seq?: number | null;
  gap_to_seq?: number | null;
  compaction_boundary_seq?: number | null;
  error_message?: string | null;
}

// ---------- Shared public response enums ----------
// CommandStatus and ErrorCode are shared by the public response-only
// CommandSubmission model and legacy internal command results.

export type CommandStatus =
  | 'RelayReceived'
  | 'HostAccepted'
  | 'Executing'
  | 'Completed'
  | 'Rejected'
  | 'Expired'
  | 'Stale'
  | 'Incompatible'
  | 'Revoked'
  | 'OutcomeUnknown';

export type ErrorCode =
  | 'OK'
  | 'ERR_REQUEST_EXPIRED'
  | 'ERR_REQUEST_STALE'
  | 'ERR_INCOMPATIBLE_VERSION'
  | 'ERR_REQUEST_REVOKED'
  | 'ERR_DUPLICATE_REQUEST'
  | 'ERR_HOST_OFFLINE'
  | 'ERR_SAFETY_BLOCKED'
  | 'ERR_PERMISSION_DENIED'
  | 'ERR_OUTCOME_UNKNOWN';

// ---------- Legacy internal command models ----------
// CommandResult, BaseCommand and the Command union below are retained only for
// historical trace/mock/Host compatibility. They are not public First Real
// User Web/Gateway request DTOs; those live in client/types.ts.

export interface CommandResult {
  error_code: ErrorCode;
  error_message: string | null;
  // reply
  accepted_at_seq?: number | null;
  event_id?: string | null;
  // stop
  // (same fields, used as accepted_at_seq / event_id)
  // interrupt_and_send
  stopped_at_seq?: number | null;
  new_event_id?: string | null;
  // permission_decision
  resolved_at_seq?: number | null;
}

export interface BaseCommand {
  command_type: 'reply' | 'stop' | 'interrupt_and_send' | 'permission_decision';
  request_id: string;
  session_id: string;
  seq: number;
  status?: CommandStatus;
  result?: CommandResult;
}

export interface ReplyCommand extends BaseCommand {
  command_type: 'reply';
  turn_id?: string | null;
  content: string;
}

export interface StopCommand extends BaseCommand {
  command_type: 'stop';
  target_turn_id: string;
}

export interface InterruptAndSendCommand extends BaseCommand {
  command_type: 'interrupt_and_send';
  interrupt_turn_id: string;
  new_content: string;
}

export type PermissionDecision = 'allow_once' | 'deny';

export interface PermissionDecisionCommand extends BaseCommand {
  command_type: 'permission_decision';
  permission_id: string;
  decision: PermissionDecision;
  action_hash: string;
  expires_at: string;
}

export type Command =
  | ReplyCommand
  | StopCommand
  | InterruptAndSendCommand
  | PermissionDecisionCommand;

// ---------- Trace fixture wrappers ----------

export interface TraceMeta {
  trace_id: string;
  scenario: string;
  description: string;
  contract_version: string;
  session_id: string;
  events: ContractEvent[];
  expected_snapshot_ref: string;
  notes?: string;
}
