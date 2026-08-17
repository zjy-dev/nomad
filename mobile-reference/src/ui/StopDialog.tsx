import { useState } from 'react';
import type { CommandResult } from '../contracts/types';

interface StopDialogProps {
  open: boolean;
  turnId: string | null;
  onCancel: () => void;
  onConfirm: () => Promise<CommandResult>;
  onInterruptAndSend: () => void;
}

export function StopDialog({ open, turnId, onCancel, onConfirm, onInterruptAndSend }: StopDialogProps) {
  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  if (!open) return null;

  async function handleStop() {
    setSubmitting(true);
    setStatus('Stopping…');
    try {
      const r = await onConfirm();
      if (r.error_code === 'OK') setStatus('Stop accepted by Host. New turn may start if user sends a message.');
      else setStatus(`Host rejected the Stop: ${r.error_code}`);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Stop current turn">
      <div className="modal">
        <h2>Stop current turn</h2>
        <p>
          You are about to stop <span className="inline-code">{turnId ?? '—'}</span>. The Host will transition
          <span className="inline-code">Running → Stopping → Cancelled</span>. Files already written by in-flight
          tools remain on disk; the side effect is not undone.
        </p>
        {status && (
          <div className="muted" style={{ fontSize: 12, marginTop: 8 }} role="status">
            {status}
          </div>
        )}
        <div className="btn-row" style={{ marginTop: 14 }}>
          <button className="btn btn--danger" onClick={handleStop} disabled={submitting} autoFocus>
            {submitting ? 'Stopping…' : 'Stop turn'}
          </button>
          <button className="btn btn--ghost" onClick={onInterruptAndSend} disabled={submitting}>
            Interrupt & send new message
          </button>
          <button className="btn btn--ghost" onClick={onCancel} disabled={submitting}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
