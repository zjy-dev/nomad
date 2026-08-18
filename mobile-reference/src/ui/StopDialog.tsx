import { useState } from 'react';
import type { CommandResult, CommandStatus } from '../contracts/types';

export function StopDialog({ open, onCancel, onConfirm }: { open: boolean; onCancel: () => void; onConfirm: () => Promise<{ status: CommandStatus; result: CommandResult }> }) {
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  if (!open) return null;

  async function stop() {
    setSubmitting(true);
    setStatus('Sending Stop to the Host…');
    try {
      const { status: commandStatus, result } = await onConfirm();
      setStatus(commandStatus === 'RelayReceived'
        ? 'Relay received Stop. Waiting for the Host.'
        : commandStatus === 'HostAccepted' || commandStatus === 'Executing' || commandStatus === 'Completed'
          ? 'The Host accepted Stop. Waiting for the task to stop.'
          : result.error_message ?? 'The Host did not accept Stop.');
    } finally { setSubmitting(false); }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel(); }}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="stop-title">
        <span className="eyebrow">HOST COMMAND</span><h2 id="stop-title">Stop this task?</h2>
        <p>The Host will ask the active turn to stop. Files already written to disk will remain.</p>
        {status && <div className="command-status" role="status">{status}</div>}
        <div className="action-stack"><button className="btn btn--danger btn--block" onClick={() => void stop()} disabled={submitting}>{submitting ? 'Sending Stop…' : 'Stop task'}</button><button className="btn btn--ghost btn--block" onClick={onCancel} disabled={submitting}>Keep running</button></div>
      </div>
    </div>
  );
}
