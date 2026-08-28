import { useRef, useState } from 'react';
import type { CommandLifecycleStatus, PublicCommandResult } from '../client/types';

export function StopDialog({ open, onCancel, onConfirm, disabled = false, disabledReason }: { open: boolean; onCancel: () => void; onConfirm: () => Promise<{ status: CommandLifecycleStatus; result: PublicCommandResult }>; disabled?: boolean; disabledReason?: string }) {
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const submittingRef = useRef(false);
  if (!open) return null;

  async function stop() {
    if (disabled || submittingRef.current) return;
    submittingRef.current = true;
    setSubmitting(true);
    setStatus('Sending Stop to the Host…');
    try {
      const { status: commandStatus, result } = await onConfirm();
      setStatus(commandStatus === 'OutcomeUnknown'
        ? 'Result unknown; Stop was not retried.'
        : commandStatus === 'DispatchAcknowledged'
          ? 'The Agent endpoint acknowledged Stop. Waiting for authoritative cancellation.'
          : commandStatus === 'Dispatching' || commandStatus === 'Executing'
            ? 'The Host is dispatching Stop. The task state has not changed yet.'
            : commandStatus === 'RelayReceived'
              ? 'Relay received Stop. Waiting for the Host.'
              : commandStatus === 'HostAccepted' || commandStatus === 'Completed'
                ? 'The Host accepted Stop. Waiting for authoritative cancellation.'
                : result.error_message ?? 'The Host did not accept Stop.');
    } finally { submittingRef.current = false; setSubmitting(false); }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="stop-title">
        <span className="eyebrow">HOST COMMAND</span><h2 id="stop-title">Stop this task?</h2>
        <p>The Host will ask the active turn to stop. Files already written to disk will remain.</p>
        {(status || (disabled && disabledReason)) && <div className="command-status" role="status">{status ?? disabledReason}</div>}
        <div className="action-stack"><button className="btn btn--danger btn--block" onClick={() => void stop()} disabled={submitting || disabled}>{submitting ? 'Sending Stop…' : 'Stop task'}</button><button className="btn btn--ghost btn--block" onClick={onCancel} disabled={submitting}>Keep running</button></div>
      </div>
    </div>
  );
}
