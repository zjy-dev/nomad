import { ViewState } from '../contracts/reducer';
import { StatusChips, SafetyGateBanner } from './StatusChips';
import { canSubmitSafeOperations } from '../contracts/reducer';
import type { CommandResult } from '../contracts/types';

interface ApprovalProps {
  state: ViewState;
  onDeny: () => Promise<CommandResult>;
  onStop: () => void;
  onExplainAllowDisabled: () => void;
}

/**
 * Approval card per MB-011.
 *
 * `allow_once` is explicitly ABSENT / disabled in this reference client
 * with a clear, documented reason: the HC-009 live gate is not passed
 * (MB-011 gate requires Security/biometric pipeline which is out of scope
 * for the validation companion). The UI renders the Host's facts so the
 * user can inspect, deny, or Stop the turn — but cannot approve yet.
 */
export function Approval({ state, onDeny, onStop, onExplainAllowDisabled }: ApprovalProps) {
  const gate = canSubmitSafeOperations(state);
  const permId = state.activePermissionId;
  const hasPendingPermission = state.session.turn_state === 'NeedsPermission' && permId !== null;

  return (
    <div className="stack">
      <StatusChips state={state} />
      <SafetyGateBanner state={state} />

      <div className="section">
        <div className="section-header">
          <span className="section-title">Approval</span>
          {permId && <span className="muted code" style={{ fontSize: 11 }}>permission_id: {permId}</span>}
        </div>

        <div className="card card--warn" aria-live="polite">
          <div className="card-title">Host requested permission</div>
          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
            The Host is waiting for your decision on a <span className="code">permission_decision</span> request.
          </div>
          <div style={{ marginTop: 12 }}>
            <FactRow label="permission_id" value={permId ?? '—'} raw />
            <FactRow label="action_hash" value="sha256: (provided by Host in fact block)" raw />
            <FactRow label="turn_state" value={state.session.turn_state} />
            <FactRow label="host_connectivity" value={state.session.host_connectivity} />
            <FactRow label="client_freshness" value={state.session.client_freshness} />
          </div>

          <div className="perm-warning" role="note">
            <strong>`allow_once` is disabled in this build.</strong>
            The HC-009 live gate (local biometric + security envelope) is not yet
            passed for the Validation Companion. You can <em>inspect</em> the
            facts and <em>deny</em> or <em>stop</em> the turn, but you cannot
            approve until the security gate is shipped.
          </div>

          <div className="btn-row" style={{ marginTop: 14 }}>
            <button
              className="btn btn--danger"
              disabled={!gate.ok || !hasPendingPermission}
              onClick={() => {
                void onDeny();
              }}
              aria-label="Deny permission request"
            >
              Deny
            </button>
            <button
              className="btn btn--danger"
              disabled={!gate.ok || !hasPendingPermission}
              onClick={onStop}
              aria-label="Stop current turn instead of approving"
            >
              Stop turn
            </button>
            <button
              className="btn btn--ghost"
              onClick={onExplainAllowDisabled}
              aria-label="Explain why allow once is not available"
            >
              Why is allow disabled?
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function FactRow({ label, value, raw }: { label: string; value: string; raw?: boolean }) {
  return (
    <div className="perm-fact">
      <span className="label">{label}</span>
      <span className={`value${raw ? ' raw' : ''} break-all`}>{value}</span>
    </div>
  );
}
