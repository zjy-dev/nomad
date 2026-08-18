import type { ContractEvent } from '../contracts/types';
import type { TimelineNode, ViewState } from '../contracts/reducer';
import { StatusChips } from './StatusChips';

const VISIBLE_HEAD = 30;

export function Timeline({ state }: { state: ViewState }) {
  const visible = state.timeline.length <= VISIBLE_HEAD ? state.timeline : state.timeline.slice(-VISIBLE_HEAD);
  const skipped = state.timeline.length - visible.length;

  return (
    <div className="stack">
      <StatusChips state={state} />
      <section className="section" aria-labelledby="activity-title">
        <div className="page-heading"><span className="eyebrow">PROGRESS LOG</span><h1 id="activity-title">Activity</h1><p>What the agent did, translated into task progress.</p></div>
        {skipped > 0 && <div className="history-note">{skipped} older updates are collapsed.</div>}
        <div className="timeline" role="log" aria-label="Task activity">
          {visible.map((node) => <ActivityNode key={nodeKey(node)} node={node} />)}
          {visible.length === 0 && <div className="empty-state"><strong>No activity yet</strong><p>The latest Host progress will appear here.</p></div>}
        </div>
      </section>
    </div>
  );
}

function ActivityNode({ node }: { node: TimelineNode }) {
  if (node.kind === 'gap') {
    return <article className="t-node t-node--gap"><span className="event-label">UPDATE MISSING</span><h2>Some progress could not be verified</h2><p>Refresh the session. Commands stay disabled until the complete state is restored.</p></article>;
  }
  if (node.kind === 'note') {
    return <article className="t-node t-node--gap"><span className="event-label">RECOVERY NOTE</span><h2>{node.text}</h2></article>;
  }
  const content = describeEvent(node.event);
  return (
    <article className={`t-node t-node--${content.tone}`}>
      <div className="t-node-head"><span className="event-label">{content.label}</span><time>{formatTime(node.event.timestamp)}</time></div>
      <h2>{content.title}</h2>
      <p>{content.detail}</p>
      <details><summary>Technical details</summary><dl><div><dt>Event</dt><dd>{node.event.event_type}</dd></div><div><dt>Sequence</dt><dd>{node.event.seq}</dd></div><div><dt>Recorded</dt><dd>{node.event.timestamp}</dd></div></dl></details>
    </article>
  );
}

export function describeEvent(event: ContractEvent): { label: string; title: string; detail: string; tone: string } {
  const tool = friendlyTool(event.payload.tool_name);
  switch (event.event_type) {
    case 'session.created': return { label: 'STARTED', title: 'Connected to the task', detail: 'The Host began tracking this session.', tone: 'running' };
    case 'turn.started': return { label: 'WORKING', title: 'The agent started a new step', detail: 'Work is continuing on your Mac.', tone: 'running' };
    case 'message.accepted': return { label: 'RECEIVED', title: 'Your reply reached the Host', detail: 'The Host accepted the message for this task.', tone: 'completed' };
    case 'message.completed': return { label: 'CONTINUING', title: 'The agent processed your reply', detail: 'Work can continue from your answer.', tone: 'completed' };
    case 'tool.started': return { label: 'WORKING', title: `${tool} started`, detail: event.payload.summary ?? 'The agent began a workspace step.', tone: 'running' };
    case 'tool.completed': return { label: 'DONE', title: `${tool} finished`, detail: event.payload.summary ?? 'The workspace step completed.', tone: 'completed' };
    case 'tool.failed': return { label: 'FAILED', title: `${tool} did not finish`, detail: event.payload.reason ?? 'The agent reported an error in this step.', tone: 'failed' };
    case 'permission.requested': return { label: 'NEEDS YOU', title: 'Paused before a protected action', detail: 'Review the Host facts. This Pilot only allows deny or Stop.', tone: 'waiting' };
    case 'permission.resolved': return { label: 'RESOLVED', title: 'The permission request was closed', detail: 'The agent can update its plan from the decision.', tone: 'completed' };
    case 'diff.updated': return { label: 'CHANGES', title: 'The workspace change summary was updated', detail: 'Open Changes to view it only when the Host supplies verified file data.', tone: 'completed' };
    case 'turn.stopping': return { label: 'STOPPING', title: 'The Host is stopping the task', detail: 'Wait for a final Host result before assuming it has stopped.', tone: 'waiting' };
    case 'turn.completed': return { label: 'FINISHED', title: 'The agent finished the task', detail: event.payload.summary ?? 'The Host reported a completed turn.', tone: 'completed' };
    case 'turn.cancelled': return { label: 'STOPPED', title: 'The task was stopped', detail: 'Files already written to disk were not undone.', tone: 'failed' };
    case 'turn.failed': return { label: 'FAILED', title: 'The task ended with an error', detail: event.payload.reason ?? 'Review the last successful activity before continuing.', tone: 'failed' };
    case 'turn.outcome_unknown': return { label: 'UNKNOWN', title: 'The final outcome could not be verified', detail: 'Do not retry from mobile. Check the Mac before taking another action.', tone: 'failed' };
    case 'session.compacted': return { label: 'RECOVERED', title: 'Older activity was summarized', detail: 'The current verified snapshot remains available.', tone: 'completed' };
    case 'session.updated': return { label: 'UPDATED', title: 'Session status refreshed', detail: 'The Host reported a newer state.', tone: 'running' };
  }
}

function friendlyTool(value: unknown): string {
  if (typeof value !== 'string' || !value) return 'Workspace step';
  const names: Record<string, string> = { grep: 'File search', shell: 'Command', edit: 'File edit', write: 'File write', test: 'Test run' };
  return names[value.toLowerCase()] ?? value.replaceAll('_', ' ');
}

function nodeKey(node: TimelineNode): string {
  if (node.kind === 'event') return node.event.event_id;
  if (node.kind === 'gap') return `gap-${node.fromSeq}-${node.toSeq}`;
  return `note-${node.text}`;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}
