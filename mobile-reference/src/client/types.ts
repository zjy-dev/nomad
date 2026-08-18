import type { Command, CommandResult, CommandStatus } from '../contracts/types';
import type { ViewState } from '../contracts/reducer';

/** Client-only product projection. This is not part of Session Semantics v0. */
export interface SessionView {
  state: ViewState;
  display: SessionDisplay;
  approval: ApprovalFacts | null;
  changes: ChangesView;
  provenance: 'pilot' | 'captured' | 'trace-lab';
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
  expiresAt: string | null;
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
  status: 'available' | 'empty' | 'invalid';
  source: string | null;
  baseline: string | null;
  files: DiffFile[];
  reason?: string;
}

export interface CommandSubmission {
  status: CommandStatus;
  result: CommandResult;
}

export interface TraceSummary {
  id: string;
  scenario: string;
  description: string;
}

/** UI boundary for Pilot, HTTP, and trace-lab implementations. */
export interface SessionClient {
  loadCurrentSession(): Promise<SessionView>;
  refreshSession(sessionId: string): Promise<SessionView>;
  submitCommand(command: Command): Promise<CommandSubmission>;
  getCommandStatus?(sessionId: string, requestId: string): Promise<CommandSubmission>;
}

export interface TraceLabClient extends SessionClient {
  listTraceSessions(): Promise<TraceSummary[]>;
  loadTraceSession(traceId: string): Promise<SessionView>;
}

export function isTraceLabClient(client: SessionClient): client is TraceLabClient {
  const candidate = client as Partial<TraceLabClient>;
  return typeof candidate.listTraceSessions === 'function' && typeof candidate.loadTraceSession === 'function';
}
