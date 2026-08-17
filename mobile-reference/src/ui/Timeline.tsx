import { ViewState, TimelineNode } from '../contracts/reducer';
import { StatusChips } from './StatusChips';

interface TimelineProps {
  state: ViewState;
  onSelectEvent: (seq: number) => void;
}

// Virtualized / bounded rendering: render only the N most recent nodes in
// expanded form and collapse older ones into a "history" summary. This keeps
// the DOM small even at 100k-event budgets (MB-007).
const VISIBLE_HEAD = 30;

export function Timeline({ state, onSelectEvent }: TimelineProps) {
  const { timeline } = state;
  const visible = timeline.length <= VISIBLE_HEAD ? timeline : timeline.slice(-VISIBLE_HEAD);
  const skipped = timeline.length - visible.length;

  return (
    <div className="stack">
      <StatusChips state={state} />

      <div className="section">
        <div className="section-header">
          <span className="section-title">Timeline</span>
          <span className="muted" style={{ fontSize: 11, fontFamily: 'var(--mono)' }}>
            {timeline.length} nodes · last {visible.length} rendered
          </span>
        </div>

        {skipped > 0 && (
          <div className="card" style={{ marginBottom: 12 }}>
            <div className="muted" style={{ fontSize: 12 }}>
              <strong>{skipped} older node(s) collapsed.</strong> Virtualized display keeps rendering
              bounded. Use Host logs or full replay for deep history.
            </div>
          </div>
        )}

        <div className="timeline" role="log" aria-label="Session timeline">
          {visible.map((node) => (
            <TimelineNodeView key={nodeKey(node)} node={node} onSelectEvent={onSelectEvent} />
          ))}
          {visible.length === 0 && (
            <div className="muted" style={{ fontSize: 13 }}>
              No events yet. Waiting for Host to emit the first durable event…
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function nodeKey(node: TimelineNode): string {
  switch (node.kind) {
    case 'event': return `ev:${node.event.event_id}`;
    case 'gap': return `gap:${node.fromSeq}-${node.toSeq}`;
    case 'note': return `note:${node.text.slice(0, 40)}`;
  }
}

function TimelineNodeView({ node, onSelectEvent }: { node: TimelineNode; onSelectEvent: (seq: number) => void }) {
  if (node.kind === 'gap') {
    return (
      <div className="t-node t-node--gap" role="note" aria-label={`Gap detected between seq ${node.fromSeq} and ${node.toSeq}`}>
        <div className="t-node-head">
          <span className="seq">gap</span>
          <span className="type">GAP</span>
        </div>
        <div className="t-node-body">
          Events <span className="code">{node.fromSeq}</span> to <span className="code">{node.toSeq}</span> are missing. Manual recovery required.
        </div>
      </div>
    );
  }
  if (node.kind === 'note') {
    return (
      <div className="t-node t-node--gap" role="note" aria-label={node.text}>
        <div className="t-node-head">
          <span className="seq">·</span>
          <span className="type">NOTE</span>
        </div>
        <div className="t-node-body">{node.text}</div>
      </div>
    );
  }

  const ev = node.event;
  const cls = classify(ev.event_type);
  return (
    <div
      className={`t-node t-node--${cls}`}
      role="listitem"
      aria-label={`Event seq ${ev.seq}: ${ev.event_type}`}
      tabIndex={0}
      onClick={() => onSelectEvent(ev.seq)}
      onKeyDown={(e) => { if (e.key === 'Enter') onSelectEvent(ev.seq); }}
    >
      <div className="t-node-head">
        <span className="seq">#{ev.seq}</span>
        <span className="type">{ev.event_type}</span>
      </div>
      <div className="t-node-body">{summarize(ev)}</div>
      <div className="t-node-meta">
        <span>id:{ev.event_id}</span>
        {ev.turn_id && <span>turn:{ev.turn_id}</span>}
        {ev.payload?.tool_name && <span>tool:{String(ev.payload.tool_name)}</span>}
        <span>{ev.timestamp}</span>
      </div>
    </div>
  );
}

function classify(type: string): string {
  switch (type) {
    case 'turn.completed':
    case 'message.completed':
    case 'tool.completed':
      return 'completed';
    case 'turn.failed':
    case 'tool.failed':
      return 'failed';
    case 'turn.stopping':
    case 'turn.cancelled':
    case 'turn.outcome_unknown':
      return 'failed';
    case 'permission.requested':
      return 'waiting';
    case 'tool.started':
    case 'turn.started':
      return 'running';
    default:
      return 'running';
  }
}

function summarize(ev: { event_type: string; payload: Record<string, unknown> }): string {
  const p = ev.payload ?? {};
  const reason = p.state_change ?? p.summary ?? p.reason;
  if (typeof reason === 'string' && reason.length > 0) return reason;
  return ev.event_type;
}
