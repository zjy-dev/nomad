import type { ActionView, SessionView } from '../client/types';
import { canSubmitSafeOperations } from '../contracts/reducer';
import { StatusChips, SafetyGateBanner } from './StatusChips';

interface HomeProps {
  view: SessionView;
  readOnly?: boolean;
  onStop?: () => void;
  onOpenActivity: () => void;
  onOpenAction?: () => void;
  onOpenChanges: () => void;
  onReload: () => void;
  actionView?: ActionView;
}

export function Home({ view, readOnly = false, onStop, onOpenActivity, onOpenAction, onOpenChanges, onReload, actionView }: HomeProps) {
  const { state, display } = view;
  const turn = state.session.turn_state;
  const gate = canSubmitSafeOperations(state);
  const needsInput = turn === 'NeedsInput';
  const needsPermission = turn === 'NeedsPermission';
  const needsYou = needsInput || needsPermission;
  const canStop = actionView
    ? actionView.stop.enabled
    : gate.ok && state.session.turn_id !== null && ['Running', 'NeedsInput', 'NeedsPermission'].includes(turn);
  const heading = readOnly
    ? 'Read-only Alpha'
    : !gate.ok
    ? 'Check this task'
    : needsInput
      ? actionView && !actionView.reply.enabled ? 'Reply context is not available yet' : 'The agent needs your answer'
      : needsPermission
        ? 'The agent is waiting before a change'
        : turn === 'Running'
          ? 'No action needed'
          : turn === 'Completed'
            ? 'Task finished'
            : turn === 'Cancelled'
              ? 'Task stopped'
              : 'Check this task';

  return (
    <div className="stack">
      <StatusChips state={state} readOnly={readOnly} />
      <SafetyGateBanner state={state} readOnly={readOnly} />

      <section className={`command-hero ${needsYou ? 'command-hero--attention' : ''}`} aria-labelledby="task-status-title">
        <span className="eyebrow">{readOnly ? 'LOCAL OBSERVATION' : needsYou ? 'NEEDS YOU' : 'CURRENT TASK'}</span>
        <h1 id="task-status-title">{heading}</h1>
        <p>
          {readOnly && 'Observe the latest local Host state. Reply, deny, Stop, and other command actions are not available in this Alpha.'}
          {!readOnly && needsInput && (actionView ? actionView.reply.explanation : 'A reply is required before work can continue.')}
          {!readOnly && needsPermission && (actionView ? 'The Host reports one protected action pending. Review the content-safe action scope before deciding.' : 'Review what the Host knows. This Pilot can only deny the request or stop the task.')}
          {!readOnly && turn === 'Running' && 'The agent is continuing on your Mac. You can leave it running or stop it.'}
          {!readOnly && turn === 'Completed' && 'The Host reported a completed turn. Review activity or verified changes when available.'}
          {!readOnly && turn === 'Cancelled' && 'The Host accepted the stop request. Work already written to disk was not undone.'}
          {!readOnly && !['NeedsInput', 'NeedsPermission', 'Running', 'Completed', 'Cancelled'].includes(turn) && 'Review the latest activity before deciding what to do.'}
        </p>
        <div className="hero-actions">
          {!readOnly && needsPermission && onOpenAction && <button className="btn btn--primary" onClick={onOpenAction}>Review request</button>}
          {!readOnly && needsInput && !actionView && <a className="btn btn--primary" href="#reply-title">Write a reply</a>}
          {!readOnly && needsInput && actionView && !actionView.reply.enabled && <button className="btn btn--primary" disabled aria-describedby="home-reply-disabled-reason">Reply unavailable</button>}
          {!readOnly && needsInput && actionView?.reply.enabled && <a className="btn btn--primary" href="#reply-title">Write a reply</a>}
          {(readOnly || !needsYou) && <button className="btn btn--primary" onClick={onOpenActivity}>View activity</button>}
          {!readOnly && (actionView?.stop.visible || state.session.turn_id !== null) && onStop && <button className="btn btn--danger-secondary" disabled={!canStop} aria-describedby={!canStop && actionView?.stop.disabledReason ? 'home-stop-disabled-reason' : undefined} onClick={onStop}>Stop task</button>}
        </div>
        {actionView?.reply.visible && !actionView.reply.enabled && <div className="command-status" role="status" id="home-reply-disabled-reason">{actionView.reply.disabledReason}</div>}
        {actionView?.stop.visible && <div className="muted">{actionView.stop.scope}</div>}
        {actionView?.stop.visible && !actionView.stop.enabled && actionView.stop.disabledReason && <div className="command-status" role="status" id="home-stop-disabled-reason">{actionView.stop.disabledReason}</div>}
      </section>

      <section className="section" aria-labelledby="last-activity-title">
        <div className="section-header"><h2 className="section-title" id="last-activity-title">Last activity</h2><time>{formatRelative(state.session.updated_at)}</time></div>
        <button className="activity-summary" onClick={onOpenActivity}>
          <span className="activity-glyph" aria-hidden="true">↳</span>
          <span><strong>{display.lastActivityLabel ?? lastEventLabel(state)}</strong><small>Open the user-facing progress log</small></span>
          <span aria-hidden="true">›</span>
        </button>
      </section>

      <section className="section" aria-labelledby="controls-title">
        <div className="section-header"><h2 className="section-title" id="controls-title">Now available</h2></div>
        <div className="control-grid">
          <button onClick={onOpenActivity}><span>Activity</span><small>See what happened</small></button>
          {!readOnly && onOpenAction && <button onClick={onOpenAction} disabled={!needsPermission}><span>Action</span><small>{needsPermission ? 'Deny or stop safely' : 'Nothing waiting'}</small></button>}
          <button onClick={onReload}><span>Refresh</span><small>Verify the latest state</small></button>
          {readOnly && <button onClick={onOpenChanges}><span>Changes</span><small>See availability status</small></button>}
        </div>
      </section>

      <details className="technical-details">
        <summary>Technical details</summary>
        <dl>
          <div><dt>Session</dt><dd>{state.session.session_id}</dd></div>
          <div><dt>Workspace</dt><dd>{display.workspaceLabel}</dd></div>
          <div><dt>Snapshot</dt><dd>{state.digestStatus === 'verified' ? 'Verified' : state.digestStatus}</dd></div>
          <div><dt>Contract</dt><dd>{state.session.semantics_version}</dd></div>
        </dl>
      </details>
    </div>
  );
}

function lastEventLabel(state: SessionView['state']): string {
  const event = state.events[state.events.length - 1];
  if (!event) return 'Waiting for the Host';
  const tool = event.payload.tool_name;
  switch (event.event_type) {
    case 'permission.requested': return 'Paused before a protected action';
    case 'tool.started': return `Started ${tool ?? 'a workspace step'}`;
    case 'tool.completed': return `Finished ${tool ?? 'a workspace step'}`;
    case 'tool.failed': return `${tool ?? 'A workspace step'} failed`;
    case 'turn.completed': return 'Finished the task';
    case 'turn.cancelled': return 'Stopped the task';
    default: return 'Session status updated';
  }
}

function formatRelative(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(delta) || delta < 0) return 'just now';
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}
