import { useState } from 'react';
import type { Command, CommandResult, CommandStatus } from '../contracts/types';

export interface DraftState {
  text: string;
  status: 'idle' | 'drafting' | 'sending' | 'sent' | 'failed';
  requestId: string | null;
  commandStatus: CommandStatus | null;
  result: CommandResult | null;
  error: string | null;
  createdAt: string;
  sentAt: string | null;
}

export function makeDraft(initialText = ''): DraftState {
  return {
    text: initialText,
    status: 'idle',
    requestId: null,
    commandStatus: null,
    result: null,
    error: null,
    createdAt: new Date().toISOString(),
    sentAt: null,
  };
}

interface ReplyComposerProps {
  draft: DraftState;
  onChange: (text: string) => void;
  onSubmit: (content: string, requestId: string) => Promise<CommandResult>;
  onClear: () => void;
  disabled?: boolean;
}

export function ReplyComposer({ draft, onChange, onSubmit, onClear, disabled }: ReplyComposerProps) {
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit() {
    if (!draft.text.trim() || submitting) return;
    const requestId = `cli_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    setSubmitting(true);
    try {
      await onSubmit(draft.text, requestId);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="draft">
      <div className="draft-meta">
        <span>Draft · {draft.text.length} chars</span>
        <span className="muted" style={{ fontFamily: 'var(--mono)' }}>
          created {formatTime(draft.createdAt)}
        </span>
      </div>
      <textarea
        value={draft.text}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Type your reply to the agent…"
        aria-label="Reply to agent"
        disabled={disabled}
      />
      <div className="btn-row" style={{ marginTop: 10 }}>
        <button
          className="btn btn--primary"
          onClick={handleSubmit}
          disabled={disabled || submitting || !draft.text.trim()}
          aria-label="Send reply"
        >
          {submitting ? 'Sending…' : 'Send reply'}
        </button>
        <button className="btn btn--ghost" onClick={onClear} disabled={draft.status === 'idle' || submitting}>
          Discard
        </button>
      </div>
      <DraftStatusRow draft={draft} />
    </div>
  );
}

function DraftStatusRow({ draft }: { draft: DraftState }) {
  const items: Array<{ label: string; cls: string; highlight?: boolean }> = [];
  if (draft.requestId) items.push({ label: `request_id: ${draft.requestId}`, cls: 'muted', highlight: true });

  items.push({ label: 'LOCAL-DRAFT', cls: 'muted' });
  if (draft.status === 'sending') items.push({ label: 'RELAY-SENDING', cls: 'muted' });
  if (draft.status === 'sent' && draft.result) {
    // INV-003-2: RELAY-RECEIVED is always shown when the relay has acknowledged.
    // HOST-ACCEPTED is ONLY shown when the explicit commandStatus says so —
    // never inferred from error_code === 'OK'.
    const cs = draft.commandStatus;
    if (cs === null || cs === 'RelayReceived') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
    } else if (cs === 'HostAccepted') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: 'HOST-ACCEPTED', cls: 'muted' });
    } else if (cs === 'Executing') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: 'HOST-ACCEPTED', cls: 'muted' });
      items.push({ label: 'EXECUTING', cls: 'muted' });
    } else if (cs === 'Completed') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: 'HOST-ACCEPTED', cls: 'muted' });
      items.push({ label: 'EXECUTING', cls: 'muted' });
      items.push({ label: 'COMPLETED', cls: 'muted' });
    } else if (cs === 'Rejected') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: `REJECTED:${draft.result.error_code}`, cls: 'muted' });
    } else if (cs === 'Stale') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: 'STALE', cls: 'muted' });
    } else if (cs === 'OutcomeUnknown') {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: 'OUTCOME-UNKNOWN', cls: 'muted' });
    } else {
      items.push({ label: 'RELAY-RECEIVED', cls: 'muted' });
      items.push({ label: `STATUS:${cs}`, cls: 'muted' });
    }
  }
  if (draft.status === 'failed' && draft.error) {
    items.push({ label: `FAILED:${draft.error}`, cls: 'muted' });
  }
  return (
    <div className="draft-status" aria-live="polite">
      {items.map((it, i) => (
        <span key={i} className={it.cls} style={it.highlight ? { color: 'var(--text)' } : undefined}>
          {it.label}
        </span>
      ))}
    </div>
  );
}

export function makeReplyCommand(
  sessionId: string,
  seq: number,
  turnId: string | null,
  content: string,
  requestId: string
): Command {
  return {
    command_type: 'reply',
    request_id: requestId,
    session_id: sessionId,
    seq,
    turn_id: turnId,
    content,
  };
}

export function makeStopCommand(sessionId: string, seq: number, targetTurnId: string, requestId: string): Command {
  return {
    command_type: 'stop',
    request_id: requestId,
    session_id: sessionId,
    seq,
    target_turn_id: targetTurnId,
  };
}

export function makeInterruptAndSendCommand(
  sessionId: string,
  seq: number,
  interruptTurnId: string,
  newContent: string,
  requestId: string
): Command {
  return {
    command_type: 'interrupt_and_send',
    request_id: requestId,
    session_id: sessionId,
    seq,
    interrupt_turn_id: interruptTurnId,
    new_content: newContent,
  };
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}
