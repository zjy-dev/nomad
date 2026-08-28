import { useRef, useState } from 'react';
import type { ActionView, CommandSubmission, SessionView } from '../client/types';
import { canSubmitSafeOperations } from '../contracts/reducer';
import { StatusChips, SafetyGateBanner } from './StatusChips';

interface ApprovalProps {
  view: SessionView;
  onDeny: () => Promise<CommandSubmission>;
  onStop: () => void;
  denyEnabled?: boolean;
  stopEnabled?: boolean;
  disabledReason?: string;
  actionView?: ActionView;
}

export function Approval({ view, onDeny, onStop, denyEnabled = true, stopEnabled = true, disabledReason, actionView }: ApprovalProps) {
  const { state, approval } = view;
  const gate = canSubmitSafeOperations(state);
  const pending = actionView
    ? actionView.deny.visible
    : state.session.turn_state === 'NeedsPermission' && state.activePermissionId !== null && approval !== null;
  const [status, setStatus] = useState<string | null>(null);
  const submittingRef = useRef(false);
  const [submitting, setSubmitting] = useState(false);
  const actionDisabled = actionView ? !actionView.deny.enabled : !gate.ok || !pending;
  const denyReason = actionView?.deny.disabledReason ?? disabledReason;
  const stopReason = actionView?.stop.disabledReason ?? disabledReason;

  async function deny() {
    if (submittingRef.current || actionDisabled || !denyEnabled) return;
    submittingRef.current = true;
    setSubmitting(true);
    setStatus('Sending your denial…');
    try {
      const { status: commandStatus, result } = await onDeny();
      setStatus(commandStatus === 'OutcomeUnknown'
        ? 'Result unknown; the denial was not retried.'
        : commandStatus === 'DispatchAcknowledged'
          ? 'The Agent endpoint acknowledged the denial; waiting for authoritative state.'
          : commandStatus === 'Dispatching' || commandStatus === 'Executing'
            ? 'The Host is processing your denial; the outcome is not final.'
            : commandStatus === 'RelayReceived'
              ? 'Relay received your denial. Waiting for the Host.'
              : commandStatus === 'HostAccepted'
                ? 'Host accepted; waiting for Agent result.'
                : commandStatus === 'Completed'
                  ? 'The denial was completed.'
                  : result.error_message ?? 'The denial was not accepted.');
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  }

  return (
    <div className="stack">
      <StatusChips state={state} />
      <SafetyGateBanner state={state} />
      <section className="section" aria-labelledby="action-title">
        <div className="page-heading"><span className="eyebrow">PROTECTED ACTION</span><h1 id="action-title">Review request</h1><p>These are facts reported by the Host, not the agent's recommendation.</p></div>

        {actionView?.deny.visible && (
          <>
            <div className="risk-banner"><span aria-hidden="true">!</span><div><strong>{actionView.deny.summary}</strong><p>Details are withheld from this view. Denial does not approve or run the action.</p></div></div>
            <article className="facts-card">
              <div className="facts-card-head"><span className="tool-badge">01</span><div><span className="eyebrow">HOST SCOPE</span><h2>Protected action pending</h2></div></div>
              <dl>
                <Fact label="Action details" value="Withheld for content safety" />
                {actionView.deny.expiresAt && <Fact label="Request expires" value={formatExpiry(actionView.deny.expiresAt)} />}
              </dl>
            </article>
            <div className="explanation-card"><span className="eyebrow">WHAT THIS MEANS</span><p>Denying rejects this one pending action. It does not approve or run it. Stopping asks the Host to end the current Agent turn and does not reverse work already written to disk.</p></div>
            {status && <div className="command-status" role="status">{status}</div>}
            {!actionView.deny.enabled && denyReason && <div className="command-status" role="status" id="deny-disabled-reason">{denyReason}</div>}
            {actionView.stop.visible && !actionView.stop.enabled && stopReason && <div className="command-status" role="status" id="action-stop-disabled-reason">{stopReason}</div>}
            <div className="action-stack">
              <button className="btn btn--danger btn--block" disabled={actionDisabled || submitting} aria-describedby={!actionView.deny.enabled && denyReason ? 'deny-disabled-reason' : undefined} onClick={() => void deny()}>{submitting ? 'Sending denial…' : 'Deny request'}</button>
              {actionView.stop.visible && <><div className="muted">{actionView.stop.scope}</div><button className="btn btn--danger-secondary btn--block" disabled={!actionView.stop.enabled || submitting} aria-describedby={!actionView.stop.enabled && stopReason ? 'action-stop-disabled-reason' : undefined} onClick={onStop}>Stop task instead</button></>}
            </div>
          </>
        )}
        {actionView && !actionView.deny.visible && <div className="empty-state"><strong>Nothing is waiting for denial</strong><p>The Host has not reported a protected action in the current projection.</p></div>}
        {!actionView && !approval && <div className="empty-state"><strong>Nothing is waiting for approval</strong><p>Return here when the Host reports a protected action.</p></div>}
        {!actionView && approval && (
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
            {(status || disabledReason) && <div className="command-status" role="status">{status ?? disabledReason}</div>}
            <div className="action-stack">
              <button className="btn btn--danger btn--block" disabled={actionDisabled || !denyEnabled || submitting} onClick={() => void deny()}>{submitting ? 'Sending denial…' : 'Deny request'}</button>
              <button className="btn btn--danger-secondary btn--block" disabled={actionDisabled || !stopEnabled || submitting} onClick={onStop}>Stop task instead</button>
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
