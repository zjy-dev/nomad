import type { CommandStatus, ErrorCode } from '../contracts/types';
import type { ViewState } from '../contracts/reducer';

/** Client-only product projection. This is not part of Session Semantics v0. */
export interface SessionView {
  state: ViewState;
  display: SessionDisplay;
  approval: ApprovalFacts | null;
  changes: ChangesView;
  provenance: 'alpha-readonly' | 'pilot' | 'captured' | 'trace-lab';
  mode?: SessionMode;
  writable?: boolean;
}

export type SessionMode = 'official-local' | 'readonly-alpha' | 'demo' | 'trace-lab';

export function sessionModeFromSearch(search: string): SessionMode {
  const params = new URLSearchParams(search);
  if (params.get('lab') === '1') return 'trace-lab';
  if (params.get('demo') === '1') return 'demo';
  if (params.get('readonly') === '1') return 'readonly-alpha';
  return 'official-local';
}

export interface SessionDisplay {
  title: string;
  hostLabel: string;
  workspaceLabel: string;
  lastActivityLabel?: string;
}

/** Facts supplied by the Host adapter. Explanations must never replace these facts. */
export interface ApprovalFacts {
  tool: string;
  operation: string;
  arguments: Array<{ label: string; value: string }>;
  workingDirectory: string | null;
  resources: string[];
  expiresAt: string;
  source: string;
  /** Required for deny submission, but intentionally not rendered in the product UI. */
  actionHash: string;
}

export type DiffLine = { type: 'add' | 'del' | 'ctx'; text: string };
export interface DiffHunk { header: string; lines: DiffLine[] }
export interface DiffFile {
  path: string;
  added: number;
  removed: number;
  hunks: DiffHunk[];
  external?: boolean;
  binary?: boolean;
  truncated?: boolean;
}

/** Authoritative diff view model. `files` is never synthesized from an event count. */
export interface ChangesView {
  status: 'available' | 'empty' | 'invalid' | 'unavailable';
  source: string | null;
  baseline: string | null;
  files: DiffFile[];
  reason?: string;
}

export interface CommandSubmission {
  status: CommandLifecycleStatus;
  result: PublicCommandResult;
}

export type CommandLifecycleStatus = CommandStatus | 'Dispatching' | 'DispatchAcknowledged';

export interface PublicCommandResult {
  error_code: ErrorCode;
  error_message: string | null;
  accepted_at_seq?: number | null;
  resolved_at_seq?: number | null;
  event_id?: string | null;
}

export const PUBLIC_COMMAND_TYPES = ['reply', 'deny', 'stop'] as const;
export type PublicCommandType = typeof PUBLIC_COMMAND_TYPES[number];

export interface PublicBaseCommandRequest {
  command_type: PublicCommandType;
  request_id: string;
  session_id: string;
  /** Freshness/CAS input only; never a Host or durable-sequence allocation. */
  observed_seq: number;
}

export interface PublicReplyCommandRequest extends PublicBaseCommandRequest {
  command_type: 'reply';
  turn_id?: string | null;
  content: string;
}

export interface PublicDenyCommandRequest extends PublicBaseCommandRequest {
  command_type: 'deny';
  permission_id: string;
  action_hash: string;
  expires_at: string;
}

export interface PublicStopCommandRequest extends PublicBaseCommandRequest {
  command_type: 'stop';
  target_turn_id: string;
}

export type PublicCommandRequest = PublicReplyCommandRequest | PublicDenyCommandRequest | PublicStopCommandRequest;

export function isPublicCommandType(value: unknown): value is PublicCommandType {
  return typeof value === 'string' && (PUBLIC_COMMAND_TYPES as readonly string[]).includes(value);
}

/** Exact, content-safe capability exposed by the same-origin local Gateway. */
export interface CommandCapability {
  schema: 'nomad.product-host.command-capability.v1';
  capability_id: string;
  snapshot_seq: number;
  snapshot_digest: string;
  next_command_seq: number;
  issued_at: string;
  expires_at: string;
  view: true;
  reply: ReplyActionCapability | null;
  deny: DenyActionCapability | null;
  stop: StopActionCapability | null;
  allow_once: false;
}

export interface ReplyActionCapability {
  turn_alias: string;
  input_alias: string;
  summary?: PendingQuestionSummary | null;
}

export interface PendingQuestionSummary {
  schema: 'nomad.product-host.pending-question-summary.v1';
  question_count: 1;
  answer_mode: 'free_text';
  response_hint: 'single_short_reply';
  prompt: string;
}

export interface DenyActionCapability {
  permission_alias: string;
  action_hash: string;
  expires_at: string;
}

export interface StopActionCapability {
  turn_alias: string;
}

/** CSRF is a Gateway/browser binding and is deliberately outside the Host capability. */
export interface BrowserCommandCapability {
  capability: CommandCapability;
  csrfToken: string;
  /** Gateway binding to the exact browser projection rendered to the user. */
  displaySnapshotSeq: number;
  displaySnapshotDigest: string;
}

/**
 * Content-safe controls composed for rendering. Capability data scopes an
 * action; it never supplies Agent-authored content or establishes task truth.
 */
export interface ActionControlView {
  visible: boolean;
  enabled: boolean;
  disabledReason: string | null;
}

export interface ActionView {
  deny: ActionControlView & {
    summary: 'Host reports one protected action pending';
    expiresAt: string | null;
  };
  stop: ActionControlView & {
    scope: 'Stop the current Agent turn on this Mac';
  };
  reply: ActionControlView & {
    explanation: 'Reviewable question context is not yet available.' | 'Your reply goes to this pending request';
    prompt: string | null;
  };
}

export type CapabilityCommandIntent =
  | { action: 'reply'; turn_alias: string; input_alias: string; content: string }
  | { action: 'deny'; permission_alias: string; action_hash: string; permission_expires_at: string }
  | { action: 'stop'; turn_alias: string };

interface GatewayBaseCommandRequest {
  schema: 'nomad.gateway.command.v1';
  capability_id: string;
  request_id: string;
  nonce: string;
  command_seq: number;
  expected_snapshot_seq: number;
  expected_snapshot_digest: string;
  issued_at: string;
  expires_at: string;
  action: PublicCommandType;
}

export type GatewayCommandRequest = GatewayBaseCommandRequest & (
  | { action: 'reply'; turn_alias: string; input_alias: string; content: string }
  | { action: 'deny'; permission_alias: string; action_hash: string; permission_expires_at: string }
  | { action: 'stop'; turn_alias: string }
);

export interface GatewayCommandReceipt {
  schema: 'nomad.gateway.command-receipt.v1';
  receipt_id: string;
  request_id: string;
  action: PublicCommandType;
  snapshot_seq: number;
  snapshot_digest: string;
  accepted_at: string | null;
  status: 'HostAccepted' | 'Dispatching' | 'DispatchAcknowledged' | 'Rejected' | 'Stale' | 'Expired' | 'OutcomeUnknown';
  error_code: ErrorCode | null;
  idempotent_replay: boolean;
}

export interface TraceSummary {
  id: string;
  scenario: string;
  description: string;
}

/** UI boundary for Pilot, HTTP, and trace-lab implementations. */
export interface SessionClient {
  readonly mode?: SessionMode;
  readonly writable?: boolean;
  loadCurrentSession(): Promise<SessionView>;
  refreshSession(sessionId: string): Promise<SessionView>;
  submitCommand?(command: PublicCommandRequest): Promise<CommandSubmission>;
  getCommandStatus?(sessionId: string, requestId: string): Promise<CommandSubmission>;
  loadCommandCapability?(): Promise<BrowserCommandCapability | null>;
  submitCapabilityCommand?(capability: BrowserCommandCapability, intent: CapabilityCommandIntent): Promise<GatewayCommandReceipt>;
}

export interface TraceLabClient extends SessionClient {
  listTraceSessions(): Promise<TraceSummary[]>;
  loadTraceSession(traceId: string): Promise<SessionView>;
}

export function isTraceLabClient(client: SessionClient): client is TraceLabClient {
  const candidate = client as Partial<TraceLabClient>;
  return typeof candidate.listTraceSessions === 'function' && typeof candidate.loadTraceSession === 'function';
}
