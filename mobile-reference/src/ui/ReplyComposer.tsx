import { useRef, useState } from 'react';
import type { CommandLifecycleStatus, PublicCommandResult, PublicReplyCommandRequest, PublicStopCommandRequest } from '../client/types';

export interface DraftState {
  text: string;
  status: 'idle' | 'drafting' | 'sending' | 'sent' | 'unknown' | 'failed';
  requestId: string | null;
  commandStatus: CommandLifecycleStatus | null;
  result: PublicCommandResult | null;
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
  onSubmit: (content: string, requestId: string) => Promise<PublicCommandResult>;
  onClear: () => void;
  disabled?: boolean;
  capabilityDisabled?: boolean;
  disabledReason?: string;
}

export function ReplyComposer({ draft, onChange, onSubmit, onClear, disabled, capabilityDisabled = false, disabledReason }: ReplyComposerProps) {
  const [submitting, setSubmitting] = useState(false);
  const submittingRef = useRef(false);

  async function handleSubmit() {
    if (!draft.text.trim() || submittingRef.current || disabled || capabilityDisabled) return;
    const requestId = `cli_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    submittingRef.current = true;
    setSubmitting(true);
    try {
      await onSubmit(draft.text, requestId);
    } finally {
      submittingRef.current = false;
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
        disabled={disabled || capabilityDisabled}
      />
      <div className="btn-row" style={{ marginTop: 10 }}>
        <button
          className="btn btn--primary"
          onClick={handleSubmit}
          disabled={disabled || capabilityDisabled || submitting || !draft.text.trim()}
          aria-label="Send reply"
        >
          {submitting ? 'Sending…' : 'Send reply'}
        </button>
        <button className="btn btn--ghost" onClick={onClear} disabled={draft.status === 'idle' || submitting}>
          Discard
        </button>
      </div>
      {capabilityDisabled && disabledReason && <div className="command-status" role="status">{disabledReason}</div>}
      <DraftStatusRow draft={draft} />
    </div>
  );
}

function DraftStatusRow({ draft }: { draft: DraftState }) {
  const items: Array<{ label: string; cls: string; highlight?: boolean }> = [];
  items.push({ label: 'Saved on this phone', cls: 'draft-stage' });
  if (draft.status === 'sending') items.push({ label: 'Sending to local Gateway', cls: 'draft-stage draft-stage--current' });
  if (draft.status === 'unknown' && draft.result) {
    items.push({ label: 'Result unknown; not retried', cls: 'draft-stage draft-stage--current' });
  } else if (draft.status === 'sent' && draft.result) {
    // INV-003-2: RELAY-RECEIVED is always shown when the relay has acknowledged.
    // HOST-ACCEPTED is ONLY shown when the explicit commandStatus says so —
    // never inferred from error_code === 'OK'.
    const cs = draft.commandStatus;
    if (cs === null || cs === 'RelayReceived') {
      items.push({ label: 'Relay received', cls: 'draft-stage draft-stage--current' });
    } else if (cs === 'HostAccepted') {
      items.push({ label: 'Sent to local Gateway', cls: 'draft-stage' });
      items.push({ label: 'Host accepted', cls: 'draft-stage draft-stage--current' });
    } else if (cs === 'Dispatching' || cs === 'Executing') {
      items.push({ label: 'Sent to local Gateway', cls: 'draft-stage' });
      items.push({ label: 'Host accepted', cls: 'draft-stage' });
      items.push({ label: 'Host is dispatching; outcome not final', cls: 'draft-stage draft-stage--current' });
    } else if (cs === 'DispatchAcknowledged') {
      items.push({ label: 'Sent to local Gateway', cls: 'draft-stage' });
      items.push({ label: 'Host accepted', cls: 'draft-stage' });
      items.push({ label: 'Agent endpoint acknowledged; waiting for authoritative state', cls: 'draft-stage draft-stage--current' });
    } else if (cs === 'Completed') {
      items.push({ label: 'Relay received', cls: 'draft-stage' });
      items.push({ label: 'Host accepted', cls: 'draft-stage' });
      items.push({ label: 'Agent continued', cls: 'draft-stage' });
      items.push({ label: 'Finished', cls: 'draft-stage draft-stage--current' });
    } else if (cs === 'Rejected') {
      items.push({ label: 'Relay received', cls: 'draft-stage' });
      items.push({ label: 'Host rejected', cls: 'draft-stage draft-stage--current' });
    } else if (cs === 'Stale') {
      items.push({ label: 'Relay received', cls: 'draft-stage' });
      items.push({ label: 'State changed — review again', cls: 'draft-stage draft-stage--current' });
    } else {
      items.push({ label: 'Relay received', cls: 'draft-stage' });
      items.push({ label: 'Waiting for Host result', cls: 'draft-stage draft-stage--current' });
    }
  }
  if (draft.status === 'failed' && draft.error) {
    items.push({ label: 'Not sent — review the safety notice', cls: 'draft-stage draft-stage--current' });
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
  observedSeq: number,
  turnId: string | null,
  content: string,
  requestId: string
): PublicReplyCommandRequest {
  return {
    command_type: 'reply',
    request_id: requestId,
    session_id: sessionId,
    observed_seq: observedSeq,
    turn_id: turnId,
    content,
  };
}

export function makeStopCommand(sessionId: string, observedSeq: number, targetTurnId: string, requestId: string): PublicStopCommandRequest {
  return {
    command_type: 'stop',
    request_id: requestId,
    session_id: sessionId,
    observed_seq: observedSeq,
    target_turn_id: targetTurnId,
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
