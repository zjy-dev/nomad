import { ViewState, canSubmitSafeOperations } from '../contracts/reducer';

export function StatusChips({ state }: { state: ViewState }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      <HostChip value={state.session.host_connectivity} />
      <FreshnessChip value={state.session.client_freshness} />
      {state.digestStatus === 'mismatch' && (
        <span className="chip" style={{ color: 'var(--danger)', borderColor: 'rgba(255,107,107,0.4)' }} aria-label="Snapshot digest mismatch">
          <span className="dot" aria-hidden="true" /> DIGEST-MISMATCH
        </span>
      )}
      {state.versionStatus === 'incompatible' && (
        <span className="chip" style={{ color: 'var(--danger)', borderColor: 'rgba(255,107,107,0.4)' }} aria-label="Protocol version incompatible">
          <span className="dot" aria-hidden="true" /> VERSION-INCOMPATIBLE
        </span>
      )}
      {state.gapToSeq !== null && (
        <span className="chip" style={{ color: 'var(--warn)', borderColor: 'rgba(255,176,32,0.4)' }} aria-label="Event gap detected">
          <span className="dot" aria-hidden="true" /> GAP-DETECTED
        </span>
      )}
      <span className="chip" aria-label={`Turn state: ${state.session.turn_state}`}>
        <span className="dot" aria-hidden="true" /> STATE:{state.session.turn_state}
      </span>
    </div>
  );
}

function HostChip({ value }: { value: string }) {
  const cls = value === 'Online' ? 'chip chip--online' : 'chip chip--offline';
  return (
    <span className={cls} role="status" aria-label={`Host is ${value}`}>
      <span className="dot" aria-hidden="true" /> HOST:{value.toUpperCase()}
    </span>
  );
}

function FreshnessChip({ value }: { value: string }) {
  const map: Record<string, { cls: string; label: string }> = {
    Live: { cls: 'chip chip--live', label: 'LIVE' },
    Reconnecting: { cls: 'chip chip--reconnect', label: 'RECONNECTING' },
    Stale: { cls: 'chip chip--stale', label: 'STALE' },
  };
  const m = map[value] ?? map.Stale;
  return (
    <span className={m.cls} role="status" aria-label={`Client is ${value}`}>
      <span className="dot" aria-hidden="true" /> CLIENT:{m.label}
    </span>
  );
}

export function SafetyGateBanner({ state }: { state: ViewState }) {
  const gate = canSubmitSafeOperations(state);
  if (gate.ok) return null;
  return (
    <div className="perm-block" role="alert" aria-live="polite">
      <strong style={{ fontWeight: 600 }}>Safe operations blocked</strong>
      <div>{gate.reason}</div>
    </div>
  );
}
