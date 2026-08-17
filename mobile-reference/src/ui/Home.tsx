import { ViewState } from '../contracts/reducer';
import { StatusChips, SafetyGateBanner } from './StatusChips';

interface HomeProps {
  state: ViewState;
  onReply: () => void;
  onStop: () => void;
  onInterruptAndSend: () => void;
  onOpenTimeline: () => void;
  onReload: () => void;
}

export function Home({ state, onReply, onStop, onInterruptAndSend, onOpenTimeline, onReload }: HomeProps) {
  const needsInput = state.session.turn_state === 'NeedsInput';
  const needsPermission = state.session.turn_state === 'NeedsPermission';
  const isRunning = state.session.turn_state === 'Running';
  const canStop = state.session.turn_state === 'Running' || state.session.turn_state === 'NeedsInput' || state.session.turn_state === 'NeedsPermission';

  return (
    <div className="stack">
      <StatusChips state={state} />
      <SafetyGateBanner state={state} />

      {(needsInput || needsPermission) && (
        <div className={`callout ${needsInput ? 'callout--input' : 'callout--permission'}`} aria-live="polite">
          <div className="callout-title">
            {needsInput ? 'NEEDS INPUT — waiting on you' : 'NEEDS PERMISSION — waiting on you'}
          </div>
          <div className="callout-body">
            {state.activePermissionId && (
              <div className="muted" style={{ fontSize: 12, fontFamily: 'var(--mono)' }}>
                permission_id: {state.activePermissionId}
              </div>
            )}
            {needsInput && (
              <div className="btn-row" style={{ marginTop: 10 }}>
                <button className="btn btn--primary" onClick={onReply}>Reply</button>
                <button className="btn btn--ghost" onClick={onStop}>Stop</button>
                <button className="btn btn--ghost" onClick={onInterruptAndSend}>Interrupt & send</button>
              </div>
            )}
            {needsPermission && (
              <div className="btn-row" style={{ marginTop: 10 }}>
                <button className="btn btn--ghost" onClick={onOpenTimeline}>Review facts</button>
              </div>
            )}
          </div>
        </div>
      )}

      {isRunning && (
        <div className="callout callout--input" aria-live="polite">
          <div className="callout-title">RUNNING</div>
          <div className="callout-body muted" style={{ fontSize: 12 }}>
            Turn <span className="code">{state.session.turn_id ?? '—'}</span> is in progress.
          </div>
          <div className="btn-row" style={{ marginTop: 10 }}>
            <button className="btn btn--primary" onClick={onOpenTimeline}>View timeline</button>
            <button className="btn btn--danger" disabled={!canStop} onClick={onStop}>Stop</button>
          </div>
        </div>
      )}

      <div className="section">
        <div className="section-header">
          <span className="section-title">Session</span>
          <div className="section-actions">
            <button className="btn btn--ghost" onClick={onReload} aria-label="Reload session">Reload</button>
          </div>
        </div>
        <div className="card">
          <div className="card-row">
            <span className="card-title">Session ID</span>
            <span className="card-sub break-all">{state.session.session_id}</span>
          </div>
          <div className="card-row">
            <span className="card-title">Turn</span>
            <span className="card-sub">{state.session.turn_id ?? '—'}</span>
          </div>
          <div className="card-row">
            <span className="card-title">Last applied seq</span>
            <span className="card-sub">{state.lastAppliedSeq}</span>
          </div>
          <div className="card-row">
            <span className="card-title">Diff files</span>
            <span className="card-sub">{state.diffFileCount}</span>
          </div>
          <div className="card-row">
            <span className="card-title">Snapshot digest</span>
            <span className="card-sub">
              {state.digestStatus === 'verified' && <span style={{ color: 'var(--ok)' }}>VERIFIED</span>}
              {state.digestStatus === 'pending' && <span style={{ color: 'var(--warn)' }}>PENDING</span>}
              {state.digestStatus === 'mismatch' && <span style={{ color: 'var(--danger)' }}>MISMATCH</span>}
              {state.digestStatus === 'none' && <span style={{ color: 'var(--text-muted)' }}>—</span>}
            </span>
          </div>
        </div>
      </div>

      <div className="section">
        <div className="section-header">
          <span className="section-title">Tools</span>
        </div>
        <div className="card">
          {state.tools.length === 0 && <div className="muted" style={{ fontSize: 13 }}>No tool activity yet.</div>}
          {state.tools.map((t) => (
            <div className="tool-row" key={t.tool_name}>
              <span>{t.tool_name}</span>
              <span className={`status-pill status-pill--${t.status.toLowerCase()}`}>
                {t.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
