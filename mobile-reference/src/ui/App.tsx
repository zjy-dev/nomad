import { useState } from 'react';
import { ViewState, initEmptyState, recoverFromSnapshot, canSubmitSafeOperations } from '../contracts/reducer';
import { getMockHost } from '../mock/api';
import type { Command, CommandResult, CommandStatus } from '../contracts/types';
import { Home } from './Home';
import { Timeline } from './Timeline';
import { Approval } from './Approval';
import { Changes } from './Changes';
import { ReplyComposer, DraftState, makeDraft, makeReplyCommand, makeStopCommand, makeInterruptAndSendCommand } from './ReplyComposer';
import { StopDialog } from './StopDialog';

type Tab = 'home' | 'timeline' | 'approval' | 'changes' | 'setup';

export function App() {
  const [tab, setTab] = useState<Tab>('home');
  const [state, setState] = useState<ViewState>(() => initEmptyState({ sessionId: 'unloaded', contractVersion: '1.0.0' }));
  const [loaded, setLoaded] = useState(false);
  const [draft, setDraft] = useState<DraftState>(() => makeDraft(''));
  const [stopOpen, setStopOpen] = useState(false);
  const [allowDisabledInfo, setAllowDisabledInfo] = useState(false);
  const [currentTraceId, setCurrentTraceId] = useState<string | null>(null);

  async function loadTrace(traceId: string) {
    const host = getMockHost();
    const loaded = host.loadTrace(traceId);
    if (!loaded) {
      alert(`Trace ${traceId} not found in mock registry.`);
      return;
    }
    const recovered = await recoverFromSnapshot(loaded.snapshot, []);
    recovered.events = [...loaded.events];
    recovered.timeline = loaded.events.map((event) => ({ kind: 'event' as const, seq: event.seq, event }));
    setState(recovered);
    setCurrentTraceId(traceId);
    setLoaded(true);
  }

  async function reload() {
    if (currentTraceId) await loadTrace(currentTraceId);
  }

  async function submitCommand(cmd: Command): Promise<{ status: CommandStatus; result: CommandResult }> {
    const gate = canSubmitSafeOperations(state);
    if (!gate.ok) {
      return { status: 'Rejected', result: { error_code: 'ERR_SAFETY_BLOCKED', error_message: gate.reason } };
    }
    const host = getMockHost();
    return host.submitCommand(cmd);
  }

  async function submitReply(content: string, requestId: string): Promise<CommandResult> {
    if (!content.trim()) {
      return { error_code: 'ERR_REQUEST_STALE', error_message: 'Reply is empty.' };
    }
    const cmd = makeReplyCommand(
      state.session.session_id,
      state.lastAppliedSeq + 1,
      state.session.turn_id,
      content,
      requestId
    );
    setDraft({ ...draft, status: 'sending', commandStatus: null });
    const { status, result } = await submitCommand(cmd);
    if (result.error_code === 'OK' || status === 'Completed' || status === 'HostAccepted') {
      setDraft({ ...draft, status: 'sent', requestId: cmd.request_id, commandStatus: status, result, sentAt: new Date().toISOString() });
    } else {
      setDraft({ ...draft, status: 'failed', requestId: cmd.request_id, commandStatus: status, error: result.error_code, result });
    }
    return result;
  }

  async function handleStopConfirm(): Promise<CommandResult> {
    const gate = canSubmitSafeOperations(state);
    if (!gate.ok) return { error_code: 'ERR_SAFETY_BLOCKED', error_message: gate.reason };
    const turnId = state.session.turn_id;
    if (!turnId) return { error_code: 'ERR_REQUEST_STALE', error_message: 'No active turn to stop.' };
    const cmd = makeStopCommand(
      state.session.session_id,
      state.lastAppliedSeq + 1,
      turnId,
      `cli_stop_${Date.now().toString(36)}`
    );
    const { result } = await submitCommand(cmd);
    if (result.error_code === 'OK') {
      setState({
        ...state,
        session: { ...state.session, turn_state: 'Cancelled', turn_id: null, updated_at: new Date().toISOString() },
      });
    }
    setStopOpen(false);
    return result;
  }

  async function handleInterruptAndSend() {
    const turnId = state.session.turn_id;
    if (!turnId) return;
    const cmd = makeInterruptAndSendCommand(
      state.session.session_id,
      state.lastAppliedSeq + 1,
      turnId,
      draft.text || 'Please continue with the current approach.',
      `cli_int_${Date.now().toString(36)}`
    );
    setStopOpen(false);
    const { result } = await submitCommand(cmd);
    if (result.error_code === 'OK') {
      setState({
        ...state,
        session: { ...state.session, turn_state: 'Running', updated_at: new Date().toISOString() },
      });
      setDraft(makeDraft(''));
    }
  }

  const gate = canSubmitSafeOperations(state);
  const needsInput = state.session.turn_state === 'NeedsInput';
  const needsPermission = state.session.turn_state === 'NeedsPermission';

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <div className="brand">
          <span className="dot" aria-hidden="true" />
          <span>Nomad · Mobile Reference</span>
        </div>
        <div className="session-meta" aria-label="Current session">
          {state.session.session_id}
        </div>
      </header>

      <main className="app-body">
        {!loaded ? (
          <TraceLoader onLoad={loadTrace} />
        ) : (
          <>
            {tab === 'home' && (
              <Home
                state={state}
                onReply={() => setTab('home')}
                onStop={() => setStopOpen(true)}
                onInterruptAndSend={async () => { await handleInterruptAndSend(); }}
                onOpenTimeline={() => setTab('timeline')}
                onReload={reload}
              />
            )}

            {tab === 'timeline' && <Timeline state={state} onSelectEvent={() => { /* focus event details */ }} />}

            {tab === 'approval' && (
              <Approval
                state={state}
                onDeny={async () => {
                  const cmd: Command = {
                    command_type: 'permission_decision',
                    request_id: `cli_deny_${Date.now().toString(36)}`,
                    session_id: state.session.session_id,
                    seq: state.lastAppliedSeq + 1,
                    permission_id: state.activePermissionId ?? 'perm_unknown',
                    decision: 'deny',
                    action_hash: 'sha256:unverified',
                    expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
                  };
                  return (await submitCommand(cmd)).result;
                }}
                onStop={() => setStopOpen(true)}
                onExplainAllowDisabled={() => setAllowDisabledInfo(true)}
              />
            )}

            {tab === 'changes' && <Changes state={state} />}

            {needsInput && (
              <div className="stack" style={{ marginTop: 16 }}>
                <div className="section">
                  <div className="section-header">
                    <span className="section-title">Reply</span>
                  </div>
                  <ReplyComposer
                    draft={draft}
                    onChange={(text) => setDraft({ ...draft, text, status: draft.status === 'idle' ? 'drafting' : draft.status })}
                    onSubmit={submitReply}
                    onClear={() => setDraft(makeDraft(''))}
                    disabled={!gate.ok}
                  />
                </div>
              </div>
            )}

            <StopDialog
              open={stopOpen}
              turnId={state.session.turn_id}
              onCancel={() => setStopOpen(false)}
              onConfirm={handleStopConfirm}
              onInterruptAndSend={async () => {
                await handleInterruptAndSend();
              }}
            />

            {allowDisabledInfo && (
              <div className="modal-backdrop" role="dialog" aria-modal="true">
                <div className="modal">
                  <h2>Why `allow_once` is disabled</h2>
                  <p>
                    The reference client implements the <strong>MB-011</strong> approval card but cannot enable
                    the <code>allow_once</code> path until the <strong>HC-009</strong> live gate is passed.
                    That gate requires:
                  </p>
                  <ul className="muted" style={{ fontSize: 13, paddingLeft: 20 }}>
                    <li>Local biometric authentication (TouchID / FaceID) binding to the permission_decision</li>
                    <li>Verified action_hash bound to permission_id + expires_at + seq (INV-003-5)</li>
                    <li>Security envelope (SEC-003) decrypting the command on Host side</li>
                    <li>Device capability attestation (not in scope for the Validation Companion)</li>
                  </ul>
                  <p>
                    Until then, the UI renders Host facts so you can <em>inspect</em>, <em>deny</em>, or <em>stop</em>.
                    When HC-009 ships, the same component will enable <code>allow_once</code> with a feature flag.
                  </p>
                  <div className="btn-row">
                    <button className="btn btn--primary" onClick={() => setAllowDisabledInfo(false)}>Got it</button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </main>

      {loaded && (
        <nav className="app-bottombar" aria-label="Primary">
          <TabButton tab="home" current={tab} label="Home" onClick={() => setTab('home')} />
          <TabButton tab="timeline" current={tab} label="Timeline" onClick={() => setTab('timeline')} />
          <TabButton
            tab="approval"
            current={tab}
            label="Approval"
            onClick={() => setTab('approval')}
            badge={needsPermission ? '!' : undefined}
          />
          <TabButton tab="changes" current={tab} label="Changes" onClick={() => setTab('changes')} />
        </nav>
      )}
    </div>
  );
}

function TabButton({
  tab,
  current,
  label,
  onClick,
  badge,
}: {
  tab: Tab;
  current: Tab;
  label: string;
  onClick: () => void;
  badge?: string;
}) {
  return (
    <button
      aria-current={current === tab ? 'page' : undefined}
      onClick={onClick}
      aria-label={label}
    >
      <span>{label}</span>
      {badge && <span aria-hidden="true" style={{ color: 'var(--danger)', fontWeight: 700 }}>{badge}</span>}
    </button>
  );
}

function TraceLoader({ onLoad }: { onLoad: (traceId: string) => void }) {
  const traces = getMockHost().listTraces();
  return (
    <div className="stack">
      <div className="callout callout--input">
        <div className="callout-title">Load a golden trace</div>
        <div className="callout-body">
          Select a trace to load into the mock Host. The reducer will consume the snapshot + durable events and
          produce the reference client state.
        </div>
      </div>
      <div className="section">
        <div className="section-header">
          <span className="section-title">Traces</span>
          <span className="muted" style={{ fontSize: 11 }}>{traces.length} golden traces</span>
        </div>
        {traces.map((t) => (
          <button
            key={t.id}
            className="list-item"
            onClick={() => onLoad(t.id)}
            aria-label={`Load trace ${t.id}: ${t.description}`}
          >
            <div className="list-item-main">
              <div className="list-item-title">{t.id}</div>
              <div className="list-item-sub">{t.description}</div>
            </div>
            <span className="chip" aria-hidden="true">{t.scenario}</span>
          </button>
        ))}
      </div>
      <div className="muted" style={{ fontSize: 12 }}>
        Mobile Reference · <span className="code">v0.0.1</span> · contract 1.0.0 · validation companion, not a native iOS app.
      </div>
    </div>
  );
}
