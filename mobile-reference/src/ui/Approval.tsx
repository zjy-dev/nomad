import { useState } from 'react';
import type { CommandSubmission, SessionView } from '../client/types';
import { canSubmitSafeOperations } from '../contracts/reducer';
import { StatusChips, SafetyGateBanner } from './StatusChips';

interface ApprovalProps {
  view: SessionView;
  onDeny: () => Promise<CommandSubmission>;
  onStop: () => void;
}

export function Approval({ view, onDeny, onStop }: ApprovalProps) {
  const { state, approval } = view;
  const gate = canSubmitSafeOperations(state);
  const pending = state.session.turn_state === 'NeedsPermission' && state.activePermissionId !== null && approval !== null;
  const [status, setStatus] = useState<string | null>(null);
  const actionDisabled = !gate.ok || !pending;

  async function deny() {
    setStatus('Sending your denial…');
    const { status: commandStatus, result } = await onDeny();
    setStatus(commandStatus === 'RelayReceived'
      ? 'Relay received your denial. Waiting for the Host.'
      : commandStatus === 'HostAccepted' || commandStatus === 'Executing' || commandStatus === 'Completed'
        ? 'The Host accepted your denial.'
        : result.error_message ?? 'The denial was not accepted.');
  }

  return (
    <div className="stack">
      <StatusChips state={state} />
      <SafetyGateBanner state={state} />
      <section className="section" aria-labelledby="action-title">
        <div className="page-heading"><span className="eyebrow">PROTECTED ACTION</span><h1 id="action-title">Review request</h1><p>These are facts reported by the Host, not the agent's recommendation.</p></div>

        {!approval && <div className="empty-state"><strong>Nothing is waiting for approval</strong><p>Return here when the Host reports a protected action.</p></div>}
        {approval && (
          <>
            <div className="risk-banner"><span aria-hidden="true">!</span><div><strong>The agent wants to {approval.operation.toLowerCase()}</strong><p>The Pilot cannot approve actions from mobile. You may deny it or stop the task.</p></div></div>
            <article className="facts-card">
              <div className="facts-card-head"><span className="tool-badge">{approval.tool.slice(0, 2).toUpperCase()}</span><div><span className="eyebrow">TOOL</span><h2>{approval.tool}</h2></div></div>
              <dl>
                <Fact label="Requested action" value={approval.operation} />
                {approval.arguments.map((fact) => <Fact key={fact.label} label={fact.label} value={fact.value} />)}
                {approval.workingDirectory && <Fact label="Working area" value={approval.workingDirectory} />}
                {approval.resources.length > 0 && <Fact label="Known resources" value={approval.resources.join(', ')} />}
                {approval.expiresAt && <Fact label="Request expires" value={formatExpiry(approval.expiresAt)} />}
                <Fact label="Fact source" value={approval.source} />
              </dl>
            </article>
            <div className="explanation-card"><span className="eyebrow">WHAT THIS MEANS</span><p>Denying closes this request. Stopping asks the Host to end the current task. Neither action reverses work already written to disk.</p></div>
            {status && <div className="command-status" role="status">{status}</div>}
            <div className="action-stack">
              <button className="btn btn--danger btn--block" disabled={actionDisabled} onClick={() => void deny()}>Deny request</button>
              <button className="btn btn--danger-secondary btn--block" disabled={actionDisabled} onClick={onStop}>Stop task instead</button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function formatExpiry(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' });
}
