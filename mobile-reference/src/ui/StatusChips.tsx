import type { ViewState } from '../contracts/reducer';
import { canSubmitSafeOperations } from '../contracts/reducer';

export function StatusChips({ state, readOnly = false }: { state: ViewState; readOnly?: boolean }) {
  const online = state.session.host_connectivity === 'Online';
  const freshness = state.session.client_freshness;
  return (
    <div className="status-strip" aria-label="Connection safety status">
      <span className={`status-cell status-cell--${online ? 'ok' : 'danger'}`} role="status"><b>{online ? '✓' : '×'}</b><span><strong>{online ? 'Online' : 'Offline'}</strong><small>{online ? 'Host reachable' : 'Host unreachable'}</small></span></span>
      <span className={`status-cell status-cell--${freshness === 'Live' ? 'ok' : freshness === 'Reconnecting' ? 'warn' : 'danger'}`} role="status"><b>{freshness === 'Live' ? '✓' : freshness === 'Reconnecting' ? '↻' : '!'}</b><span><strong>{freshness}</strong><small>{freshness === 'Live' ? (readOnly ? 'Read-only state verified' : 'State verified') : freshness === 'Reconnecting' ? 'Checking state' : 'State not verified'}</small></span></span>
    </div>
  );
}

export function SafetyGateBanner({ state, readOnly = false }: { state: ViewState; readOnly?: boolean }) {
  if (readOnly) return <div className="callout"><strong className="callout-title">Read-only capability</strong><div className="callout-body">This Alpha can display and refresh local session state. It cannot send commands.</div></div>;
  const gate = canSubmitSafeOperations(state);
  if (gate.ok) return null;
  return <div className="perm-block" role="alert"><strong>Actions are paused</strong><div>{friendlyGateReason(state)}</div></div>;
}

export function friendlyGateReason(state: ViewState): string {
  if (state.session.host_connectivity === 'Offline') return 'Your Mac cannot be reached. Reconnect it before sending a reply, denial, or Stop.';
  if (state.session.client_freshness === 'Reconnecting') return 'The latest state is still being checked. Actions unlock after it is verified Live.';
  if (state.session.client_freshness === 'Stale') return 'This page may be behind the Host. Refresh and wait for Live before taking action.';
  if (state.versionStatus !== 'ok') return 'The Host version is not compatible with this Pilot client.';
  return 'The latest Host snapshot could not be verified. Refresh before taking action.';
}
