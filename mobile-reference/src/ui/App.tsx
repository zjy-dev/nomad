import { useEffect, useState } from 'react';
import { canSubmitSafeOperations } from '../contracts/reducer';
import type { Command, CommandResult, CommandStatus } from '../contracts/types';
import type { SessionClient, SessionView, TraceSummary } from '../client/types';
import { isTraceLabClient } from '../client/types';
import { Home } from './Home';
import { Timeline } from './Timeline';
import { Approval } from './Approval';
import { Changes } from './Changes';
import { ReplyComposer, type DraftState, makeDraft, makeReplyCommand, makeStopCommand } from './ReplyComposer';
import { StopDialog } from './StopDialog';

type Tab = 'home' | 'activity' | 'action' | 'changes';

export interface AppProps {
  client: SessionClient;
  labMode?: boolean;
}

export function App({ client, labMode = new URLSearchParams(window.location.search).get('lab') === '1' }: AppProps) {
  const [tab, setTab] = useState<Tab>('home');
  const [view, setView] = useState<SessionView | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [draft, setDraft] = useState<DraftState>(() => makeDraft(''));
  const [stopOpen, setStopOpen] = useState(false);

  useEffect(() => {
    let active = true;
    setLoadError(null);
    if (labMode && isTraceLabClient(client)) {
      void client.listTraceSessions()
        .then((items) => { if (active) setTraces(items); })
        .catch((error: unknown) => { if (active) setLoadError(toMessage(error)); });
    } else {
      void client.loadCurrentSession()
        .then((session) => { if (active) setView(session); })
        .catch((error: unknown) => { if (active) setLoadError(toMessage(error)); });
    }
    return () => { active = false; };
  }, [client, labMode]);

  async function loadTrace(traceId: string) {
    if (!isTraceLabClient(client)) return;
    setLoadError(null);
    try {
      setView(await client.loadTraceSession(traceId));
      setTab('home');
    } catch (error) {
      setLoadError(toMessage(error));
    }
  }

  async function reload() {
    if (!view) return;
    setLoadError(null);
    try {
      setView(await client.refreshSession(view.state.session.session_id));
    } catch (error) {
      setLoadError(toMessage(error));
    }
  }

  async function submitCommand(command: Command): Promise<{ status: CommandStatus; result: CommandResult }> {
    if (!view) return blocked('Session is not ready.');
    const gate = canSubmitSafeOperations(view.state);
    if (!gate.ok) return blocked(gate.reason);
    const initial = await client.submitCommand(command);
    if (initial.status !== 'RelayReceived' || !client.getCommandStatus) return initial;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await delay(250);
      try {
        const current = await client.getCommandStatus(command.session_id, command.request_id);
        if (current.status !== 'RelayReceived') return current;
      } catch {
        // Relay receipt remains the only confirmed fact; do not infer failure
        // or Host acceptance from a transient status-poll error.
      }
    }
    return initial;
  }

  async function submitReply(content: string, requestId: string): Promise<CommandResult> {
    if (!view || !content.trim()) {
      return { error_code: 'ERR_REQUEST_STALE', error_message: 'Write a reply before sending.' };
    }
    const command = makeReplyCommand(
      view.state.session.session_id,
      view.state.lastAppliedSeq + 1,
      view.state.session.turn_id,
      content,
      requestId,
    );
    setDraft((current) => ({ ...current, status: 'sending', commandStatus: null }));
    const { status, result } = await submitCommand(command);
    setDraft((current) => result.error_code === 'OK'
      ? { ...current, status: 'sent', requestId, commandStatus: status, result, sentAt: new Date().toISOString() }
      : { ...current, status: 'failed', requestId, commandStatus: status, error: result.error_code, result });
    return result;
  }

  async function handleStopConfirm(): Promise<{ status: CommandStatus; result: CommandResult }> {
    if (!view) return { status: 'Rejected', result: { error_code: 'ERR_REQUEST_STALE', error_message: 'Session is not ready.' } };
    const turnId = view.state.session.turn_id;
    if (!turnId) return { status: 'Rejected', result: { error_code: 'ERR_REQUEST_STALE', error_message: 'There is no active task to stop.' } };
    const command = makeStopCommand(
      view.state.session.session_id,
      view.state.lastAppliedSeq + 1,
      turnId,
      `cli_stop_${Date.now().toString(36)}`,
    );
    const submission = await submitCommand(command);
    if (submission.status === 'HostAccepted' || submission.status === 'Executing') {
      setView({
        ...view,
        state: {
          ...view.state,
          session: { ...view.state.session, turn_state: 'Stopping', updated_at: new Date().toISOString() },
        },
        display: { ...view.display, lastActivityLabel: 'The Host accepted Stop; waiting for cancellation' },
      });
      setStopOpen(false);
    }
    return submission;
  }

  const state = view?.state ?? null;
  const gate = state ? canSubmitSafeOperations(state) : { ok: false as const, reason: 'Session is not ready.' };
  const needsInput = state?.session.turn_state === 'NeedsInput';
  const needsPermission = state?.session.turn_state === 'NeedsPermission';

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <div className="brand"><span className="brand-mark">N</span><span>Nomad Pilot</span></div>
        <div className="topbar-context">
          <span className="environment-label">{labMode ? 'TRACE LAB' : 'CONTROLLED PILOT'}</span>
          {view && <span className="host-label">{view.display.hostLabel}</span>}
        </div>
      </header>

      <main className="app-body">
        {loadError && <div className="perm-block" role="alert"><strong>Session unavailable</strong><div>{loadError}</div></div>}
        {!loadError && labMode && !view && (
          <TraceLab traces={traces} onLoad={loadTrace} />
        )}
        {!loadError && !labMode && !view && <LoadingState />}

        {view && (
          <>
            {labMode && (
              <button className="lab-back" onClick={() => setView(null)}>← Back to trace lab</button>
            )}
            {tab === 'home' && (
              <Home
                view={view}
                onStop={() => setStopOpen(true)}
                onOpenActivity={() => setTab('activity')}
                onOpenAction={() => setTab('action')}
                onReload={reload}
              />
            )}
            {tab === 'activity' && <Timeline state={view.state} />}
            {tab === 'action' && (
              <Approval
                view={view}
                onDeny={async () => {
                  if (!view.approval || !view.state.activePermissionId) {
                    return { status: 'Stale' as const, result: { error_code: 'ERR_REQUEST_STALE' as const, error_message: 'This request is no longer pending.' } };
                  }
                  const command: Command = {
                    command_type: 'permission_decision',
                    request_id: `cli_deny_${Date.now().toString(36)}`,
                    session_id: view.state.session.session_id,
                    seq: view.state.lastAppliedSeq + 1,
                    permission_id: view.state.activePermissionId,
                    decision: 'deny',
                    action_hash: view.approval.actionHash,
                    expires_at: view.approval.expiresAt ?? new Date(Date.now() + 60_000).toISOString(),
                  };
                  return submitCommand(command);
                }}
                onStop={() => setStopOpen(true)}
              />
            )}
            {tab === 'changes' && <Changes state={view.state} changes={view.changes} />}

            {needsInput && tab === 'home' && (
              <section className="section" aria-labelledby="reply-title">
                <div className="section-header"><h2 className="section-title" id="reply-title">Your reply</h2></div>
                <ReplyComposer
                  draft={draft}
                  onChange={(text) => setDraft((current) => ({ ...current, text, status: current.status === 'idle' ? 'drafting' : current.status }))}
                  onSubmit={submitReply}
                  onClear={() => setDraft(makeDraft(''))}
                  disabled={!gate.ok}
                />
              </section>
            )}

            <StopDialog
              open={stopOpen}
              onCancel={() => setStopOpen(false)}
              onConfirm={handleStopConfirm}
            />
          </>
        )}
      </main>

      {view && (
        <nav className="app-bottombar" aria-label="Primary">
          <TabButton tab="home" current={tab} label="Home" symbol="01" onClick={() => setTab('home')} />
          <TabButton tab="activity" current={tab} label="Activity" symbol="02" onClick={() => setTab('activity')} />
          <TabButton tab="action" current={tab} label="Action" symbol={needsPermission ? '!' : '03'} onClick={() => setTab('action')} />
          <TabButton tab="changes" current={tab} label="Changes" symbol="04" onClick={() => setTab('changes')} />
        </nav>
      )}
    </div>
  );
}

function TabButton({ tab, current, label, symbol, onClick }: { tab: Tab; current: Tab; label: string; symbol: string; onClick: () => void }) {
  return (
    <button aria-current={current === tab ? 'page' : undefined} onClick={onClick} aria-label={label}>
      <span className="nav-index">{symbol}</span><span>{label}</span>
    </button>
  );
}

function TraceLab({ traces, onLoad }: { traces: TraceSummary[]; onLoad: (traceId: string) => void }) {
  return (
    <div className="stack" data-testid="trace-lab">
      <div className="callout callout--input">
        <div className="callout-title">Developer trace lab</div>
        <div className="callout-body">Contract fixtures are isolated from the default Pilot product route.</div>
      </div>
      <section className="section">
        <div className="section-header"><h1 className="section-title">Golden traces</h1><span className="muted">{traces.length} scenarios</span></div>
        {traces.map((trace) => (
          <button key={trace.id} className="list-item" onClick={() => onLoad(trace.id)} aria-label={`Load trace ${trace.id}: ${trace.description}`}>
            <span className="list-item-main"><span className="list-item-title">{trace.id}</span><span className="list-item-sub">{trace.description}</span></span>
            <span className="chip" aria-hidden="true">{trace.scenario}</span>
          </button>
        ))}
      </section>
    </div>
  );
}

function LoadingState() {
  return <div className="loading-state" role="status"><span className="loading-bar" /><strong>Connecting to your Pilot session</strong><span>Verifying the latest Host state before actions are enabled.</span></div>;
}

function blocked(reason: string) {
  return { status: 'Rejected' as const, result: { error_code: 'ERR_SAFETY_BLOCKED' as const, error_message: reason } };
}

function toMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The session could not be loaded.';
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}
