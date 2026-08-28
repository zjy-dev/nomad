import { useEffect, useRef, useState } from 'react';
import { AlphaAvailabilityError, AlphaResponseError, type AlphaAvailability } from '../client/alpha-decoder';
import { canSubmitSafeOperations } from '../contracts/reducer';
import type { BrowserCommandCapability, CapabilityCommandIntent, CommandSubmission, PublicCommandRequest, PublicCommandResult, SessionClient, SessionMode, SessionView, TraceSummary } from '../client/types';
import { isTraceLabClient } from '../client/types';
import { RemoteSessionError } from '../remote/paired-session';
import { composeActionView } from '../client/action-view';
import { Home } from './Home';
import { Timeline } from './Timeline';
import { Approval } from './Approval';
import { Changes } from './Changes';
import type { DesktopPairingClient } from './pairing-api';
import { PairingConsole } from './PairingConsole';
import { ReplyComposer, type DraftState, makeDraft, makeReplyCommand, makeStopCommand } from './ReplyComposer';
import { StopDialog } from './StopDialog';
import { useReadonlyLiveRefresh } from './useReadonlyLiveRefresh';

type Tab = 'home' | 'activity' | 'action' | 'changes';

export interface AppProps {
  client: SessionClient;
  mode?: SessionMode;
  labMode?: boolean;
  desktopPairingClient?: DesktopPairingClient;
}

export function App({ client, mode, labMode, desktopPairingClient }: AppProps) {
  const resolvedMode: SessionMode = mode ?? (labMode ? 'trace-lab' : client.mode ?? 'demo');
  const isLab = resolvedMode === 'trace-lab';
  const readOnly = resolvedMode === 'readonly-alpha';
  const officialLocal = resolvedMode === 'official-local';
  const [tab, setTab] = useState<Tab>('home');
  const [view, setView] = useState<SessionView | null>(null);
  const [loadError, setLoadError] = useState<LoadFailure | null>(null);
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [draft, setDraft] = useState<DraftState>(() => makeDraft(''));
  const [stopOpen, setStopOpen] = useState(false);
  const [commandCapability, setCommandCapability] = useState<BrowserCommandCapability | null>(null);
  const [capabilityReason, setCapabilityReason] = useState('Checking command capability…');
  const [commandLocked, setCommandLocked] = useState(false);
  const [capabilityClock, setCapabilityClock] = useState(() => Date.now());
  const [capabilityEpoch, setCapabilityEpoch] = useState(0);
  const commandLockedRef = useRef(false);
  const refreshingRef = useRef(false);
  const manualRefreshRef = useRef(false);
  const displayedSnapshotRef = useRef<string | null>(null);
  const lockedSnapshotRef = useRef<string | null>(null);
  const outcomeUnknownRef = useRef(false);

  const refreshReadonly = useReadonlyLiveRefresh({
    enabled: readOnly || officialLocal,
    client,
    sessionId: view?.state.session.session_id ?? null,
    onSuccess: (session) => {
      refreshingRef.current = false;
      const nextSnapshot = snapshotKey(session);
      const snapshotChanged = displayedSnapshotRef.current !== nextSnapshot;
      displayedSnapshotRef.current = nextSnapshot;
      if (!outcomeUnknownRef.current && lockedSnapshotRef.current !== null && lockedSnapshotRef.current !== nextSnapshot) {
        lockedSnapshotRef.current = null;
        commandLockedRef.current = false;
        setCommandLocked(false);
      }
      if (snapshotChanged || manualRefreshRef.current) {
        setCommandCapability(null);
        setCapabilityReason('Refreshing command capability…');
        setCapabilityEpoch((current) => current + 1);
      }
      manualRefreshRef.current = false;
      setView(session);
      setLoadError(null);
    },
    onFailure: (error, freshness) => {
      refreshingRef.current = false;
      setCommandCapability(null);
      setCapabilityReason('Local Host is offline. Commands are disabled.');
      setView((current) => current ? {
        ...current,
        state: {
          ...current.state,
          session: {
            ...current.state.session,
            host_connectivity: 'Offline',
            client_freshness: freshness,
          },
        },
      } : null);
      setLoadError(toLoadFailure(error));
    },
  });

  useEffect(() => {
    if (!officialLocal || !view || !client.loadCommandCapability || commandLocked) return;
    const snapshotSeq = view.state.lastAppliedSeq;
    const snapshotDigest = view.state.expectedDigest;
    const session = view.state.session;
    if (session.host_connectivity !== 'Online' || session.client_freshness !== 'Live' || !snapshotDigest) {
      setCommandCapability(null);
      setCapabilityReason('The displayed snapshot is not Live. Commands are disabled.');
      return;
    }
    let active = true;
    const expiryTimers: number[] = [];
    setCommandCapability(null);
    setCapabilityReason('Checking command capability…');
    void client.loadCommandCapability().then((binding) => {
      if (!active) return;
      const reason = capabilityMismatch(binding, snapshotSeq, snapshotDigest);
      if (reason) { setCommandCapability(null); setCapabilityReason(reason); }
      else {
        const receivedAt = Date.now();
        setCapabilityClock(receivedAt);
        setCommandCapability(binding);
        setCapabilityReason('');
        if (binding!.capability.deny) {
          expiryTimers.push(window.setTimeout(() => {
            if (active) setCapabilityClock(Date.now());
          }, Math.max(0, Date.parse(binding!.capability.deny.expires_at) - receivedAt)));
        }
        expiryTimers.push(window.setTimeout(() => {
          if (!active) return;
          setCapabilityClock(Date.now());
          setCommandCapability(null);
          setCapabilityReason('The command capability expired. Refresh and review the latest state.');
        }, Math.max(0, Date.parse(binding!.capability.expires_at) - receivedAt)));
      }
    }).catch(() => {
      if (active) { setCommandCapability(null); setCapabilityReason('Command capability is unavailable. This view remains read-only.'); }
    });
    return () => {
      active = false;
      expiryTimers.forEach((timer) => window.clearTimeout(timer));
    };
  }, [capabilityEpoch, client, commandLocked, officialLocal, view]);

  useEffect(() => {
    if (view?.state.session.turn_state === 'Cancelled') setStopOpen(false);
  }, [view?.state.session.turn_state]);

  useEffect(() => {
    let active = true;
    setLoadError(null);
    if (isLab && isTraceLabClient(client)) {
      void client.listTraceSessions()
        .then((items) => { if (active) setTraces(items); })
        .catch((error: unknown) => { if (active) setLoadError(toLoadFailure(error)); });
    } else if (!readOnly && !officialLocal) {
      void client.loadCurrentSession()
        .then((session) => { if (active) setView(session); })
        .catch((error: unknown) => { if (active) setLoadError(toLoadFailure(error)); });
    }
    return () => { active = false; };
  }, [client, isLab, officialLocal, readOnly]);

  async function loadTrace(traceId: string) {
    if (!isTraceLabClient(client)) return;
    setLoadError(null);
    try {
      setView(await client.loadTraceSession(traceId));
      setTab('home');
    } catch (error) {
      setLoadError(toLoadFailure(error));
    }
  }

  async function reload() {
    if (!view) return;
    setLoadError(null);
    if (readOnly || officialLocal) {
      refreshingRef.current = true;
      manualRefreshRef.current = true;
      setCommandCapability(null);
      setCapabilityReason('Refreshing the displayed snapshot…');
      await refreshReadonly();
      return;
    }
    try {
      setView(await client.refreshSession(view.state.session.session_id));
    } catch (error) {
      setView(null);
      setLoadError(toLoadFailure(error));
    }
  }

  async function submitCommand(command: PublicCommandRequest): Promise<CommandSubmission> {
    if (!view || readOnly || !client.submitCommand) return blocked('Read-only Alpha does not allow commands.');
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

  async function submitOfficial(intent: CapabilityCommandIntent): Promise<CommandSubmission> {
    const binding = commandCapability;
    if (!officialLocal || !binding || !client.submitCapabilityCommand || commandLockedRef.current || refreshingRef.current) return blocked(capabilityReason || 'Commands are disabled.');
    const stateGate = view ? canSubmitSafeOperations(view.state) : { ok: false as const, reason: 'Session is not ready.' };
    if (!stateGate.ok) return blocked(stateGate.reason);
    const reason = view ? capabilityMismatch(binding, view.state.lastAppliedSeq, view.state.expectedDigest) : 'Session is not ready.';
    if (reason) { setCommandCapability(null); setCapabilityReason(reason); return blocked(reason); }
    commandLockedRef.current = true;
    lockedSnapshotRef.current = view ? snapshotKey(view) : null;
    setCommandLocked(true);
    setCommandCapability(null);
    setCapabilityReason('A command is in progress.');
    try {
      const receipt = await client.submitCapabilityCommand(binding, intent);
      if (receipt.status === 'OutcomeUnknown') {
        outcomeUnknownRef.current = true;
        setCapabilityReason('Result unknown; this command was not retried.');
      }
      else setCapabilityReason(commandReceiptLabel(receipt.status));
      return {
        status: receipt.status,
        result: { error_code: receipt.error_code ?? 'OK', error_message: receipt.status === 'OutcomeUnknown' ? 'Result unknown; not retried.' : null },
      };
    } catch (error) {
      if (error instanceof RemoteSessionError) {
        if (error.code === 'COMMAND_ALREADY_PENDING') {
          setCapabilityReason('A remote command for this same request is still pending. Wait for the existing request or recover it.');
          return {
            status: 'RelayReceived',
            result: { error_code: 'OK', error_message: null },
          };
        }
        if (error.code === 'REMOTE_COMMAND_PENDING') {
          setCapabilityReason('Remote command published. Waiting for authoritative Host receipt.');
          return {
            status: 'RelayReceived',
            result: { error_code: 'OK', error_message: null },
          };
        }
        if (error.code === 'REMOTE_COMMAND_OUTCOME_UNKNOWN') {
          outcomeUnknownRef.current = true;
          setCapabilityReason('Result unknown; this command was not retried.');
          return { status: 'OutcomeUnknown', result: { error_code: 'ERR_OUTCOME_UNKNOWN', error_message: 'Result unknown; not retried.' } };
        }
        if (error.code === 'REMOTE_COMMAND_UNAVAILABLE') {
          setCapabilityReason('Remote command receipt is unavailable. Refresh and review the latest state.');
          return {
            status: 'Rejected',
            result: { error_code: 'ERR_OUTCOME_UNKNOWN', error_message: 'Remote command receipt is unavailable. Refresh and review the latest state.' },
          };
        }
        if (error.code === 'DEVICE_REVOKED') {
          setCapabilityReason('This phone was revoked. Pair again from your Mac.');
          return {
            status: 'Rejected',
            result: { error_code: 'ERR_REQUEST_REVOKED', error_message: 'This phone was revoked. Pair again from your Mac.' },
          };
        }
        if (error.code === 'KEY_LOST') {
          setCapabilityReason('This browser lost its secure keys. Pair again from your Mac.');
          return {
            status: 'Rejected',
            result: { error_code: 'ERR_OUTCOME_UNKNOWN', error_message: 'This browser lost its secure keys. Pair again from your Mac.' },
          };
        }
      }
      outcomeUnknownRef.current = true;
      setCapabilityReason('Command result is unknown after a transport failure; it was not retried.');
      return { status: 'OutcomeUnknown', result: { error_code: 'ERR_OUTCOME_UNKNOWN', error_message: 'Result unknown; not retried.' } };
    }
  }

  async function submitReply(content: string, requestId: string): Promise<PublicCommandResult> {
    if (!view || !content.trim()) {
      return { error_code: 'ERR_REQUEST_STALE', error_message: 'Write a reply before sending.' };
    }
    if (officialLocal) {
      const target = commandCapability?.capability.reply;
      if (!target) return { error_code: 'ERR_SAFETY_BLOCKED', error_message: capabilityReason || 'Reply is not enabled.' };
      setDraft((current) => ({ ...current, status: 'sending', commandStatus: null }));
      const { status, result } = await submitOfficial({ action: 'reply', turn_alias: target.turn_alias, input_alias: target.input_alias, content });
      setDraft((current) => status === 'OutcomeUnknown'
        ? { ...current, status: 'unknown', requestId, commandStatus: status, result, sentAt: null }
        : result.error_code === 'OK'
          ? { ...current, status: 'sent', requestId, commandStatus: status, result, sentAt: new Date().toISOString() }
          : { ...current, status: 'failed', requestId, commandStatus: status, error: result.error_code, result });
      return result;
    }
    const command = makeReplyCommand(
      view.state.session.session_id,
      view.state.lastAppliedSeq,
      view.state.session.turn_id,
      content,
      requestId,
    );
    setDraft((current) => ({ ...current, status: 'sending', commandStatus: null }));
    const { status, result } = await submitCommand(command);
    setDraft((current) => status === 'OutcomeUnknown'
      ? { ...current, status: 'unknown', requestId, commandStatus: status, result, sentAt: null }
      : result.error_code === 'OK'
        ? { ...current, status: 'sent', requestId, commandStatus: status, result, sentAt: new Date().toISOString() }
        : { ...current, status: 'failed', requestId, commandStatus: status, error: result.error_code, result });
    return result;
  }

  async function handleStopConfirm(): Promise<CommandSubmission> {
    if (!view) return { status: 'Rejected', result: { error_code: 'ERR_REQUEST_STALE', error_message: 'Session is not ready.' } };
    if (officialLocal) {
      const target = commandCapability?.capability.stop;
      if (!target) return blocked(capabilityReason || 'Stop is not enabled.');
      return submitOfficial({ action: 'stop', turn_alias: target.turn_alias });
    }
    const turnId = view.state.session.turn_id;
    if (!turnId) return { status: 'Rejected', result: { error_code: 'ERR_REQUEST_STALE', error_message: 'There is no active task to stop.' } };
    const command = makeStopCommand(
      view.state.session.session_id,
      view.state.lastAppliedSeq,
      turnId,
      `cli_stop_${Date.now().toString(36)}`,
    );
    const submission = await submitCommand(command);
    if (submission.status === 'HostAccepted' || submission.status === 'Executing') {
      setStopOpen(false);
    }
    return submission;
  }

  const state = view?.state ?? null;
  const gate = state ? canSubmitSafeOperations(state) : { ok: false as const, reason: 'Session is not ready.' };
  const needsInput = state?.session.turn_state === 'NeedsInput';
  const needsPermission = state?.session.turn_state === 'NeedsPermission';
  const liveCapabilityReason = view ? capabilityMismatch(commandCapability, view.state.lastAppliedSeq, view.state.expectedDigest, capabilityClock) : 'Session is not ready.';
  const activeCapability = liveCapabilityReason ? null : commandCapability;
  const actionView = officialLocal && view ? composeActionView(view, activeCapability, capabilityClock) : null;
  const visibleCapabilityReason = capabilityReason || liveCapabilityReason || '';

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <div className="brand"><span className="brand-mark">N</span><span>{readOnly ? 'Nomad Alpha' : isLab ? 'Nomad Trace Lab' : officialLocal ? 'Nomad Local' : 'Nomad Pilot'}</span></div>
        <div className="topbar-context">
          <span className="environment-label">{isLab ? 'TRACE LAB' : readOnly ? 'READ-ONLY ALPHA' : officialLocal ? 'OFFICIAL LOCAL' : 'DEMO DATA'}</span>
          {view && <span className="host-label">{view.display.hostLabel}</span>}
        </div>
      </header>

      <main className="app-body">
        {loadError && <div className="perm-block" role="alert"><strong>{loadError.status === 'unknown' ? 'Session state unknown' : 'Session unavailable'}</strong><div>{loadError.message}</div></div>}
        {!loadError && isLab && !view && (
          <TraceLab traces={traces} onLoad={loadTrace} />
        )}
        {!loadError && !isLab && !view && <LoadingState readOnly={readOnly} />}

        {view && (
          <>
            {officialLocal && visibleCapabilityReason && <div className="command-status" role="status">{visibleCapabilityReason}</div>}
            {isLab && (
              <button className="lab-back" onClick={() => setView(null)}>← Back to trace lab</button>
            )}
            {tab === 'home' && (
              <>
                {officialLocal && desktopPairingClient && <PairingConsole client={desktopPairingClient} />}
                <Home
                  view={view}
                  readOnly={readOnly}
                  onStop={readOnly ? undefined : () => setStopOpen(true)}
                  onOpenActivity={() => setTab('activity')}
                  onOpenAction={readOnly ? undefined : () => setTab('action')}
                  onOpenChanges={() => setTab('changes')}
                  onReload={reload}
                  actionView={actionView ?? undefined}
                />
              </>
            )}
            {tab === 'activity' && <Timeline state={view.state} />}
            {!readOnly && tab === 'action' && (
              <Approval
                view={view}
                onDeny={async () => {
                  if (officialLocal) {
                    const target = commandCapability?.capability.deny;
                    if (!target) return blocked(capabilityReason || 'Deny is not enabled.');
                    return submitOfficial({ action: 'deny', permission_alias: target.permission_alias, action_hash: target.action_hash, permission_expires_at: target.expires_at });
                  }
                  if (!view.approval || !view.state.activePermissionId || !view.approval.actionHash || !view.approval.expiresAt) {
                    return { status: 'Stale' as const, result: { error_code: 'ERR_REQUEST_STALE' as const, error_message: 'This request is no longer pending.' } };
                  }
                  const command: PublicCommandRequest = {
                    command_type: 'deny',
                    request_id: `cli_deny_${Date.now().toString(36)}`,
                    session_id: view.state.session.session_id,
                    observed_seq: view.state.lastAppliedSeq,
                    permission_id: view.state.activePermissionId,
                    action_hash: view.approval.actionHash,
                    expires_at: view.approval.expiresAt,
                  };
                  return submitCommand(command);
                }}
                onStop={() => setStopOpen(true)}
                denyEnabled={!officialLocal || Boolean(actionView?.deny.enabled)}
                stopEnabled={!officialLocal || Boolean(actionView?.stop.enabled)}
                disabledReason={officialLocal ? visibleCapabilityReason : undefined}
                actionView={actionView ?? undefined}
              />
            )}
            {tab === 'changes' && <Changes state={view.state} changes={view.changes} />}

            {!readOnly && needsInput && tab === 'home' && !officialLocal && (
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
            {officialLocal && needsInput && tab === 'home' && actionView?.reply.visible && actionView.reply.enabled && (
              <section className="section" aria-labelledby="reply-title">
                <div className="section-header"><h2 className="section-title" id="reply-title">Your reply</h2></div>
                <div className="explanation-card"><span className="eyebrow">PENDING REQUEST</span><p>{actionView.reply.prompt}</p><p>{actionView.reply.explanation}</p></div>
                <ReplyComposer
                  draft={draft}
                  onChange={(text) => setDraft((current) => ({ ...current, text, status: current.status === 'idle' ? 'drafting' : current.status }))}
                  onSubmit={submitReply}
                  onClear={() => setDraft(makeDraft(''))}
                  disabled={!gate.ok}
                />
              </section>
            )}
            {officialLocal && needsInput && tab === 'home' && actionView?.reply.visible && !actionView.reply.enabled && (
              <section className="section" aria-labelledby="reply-title">
                <div className="section-header"><h2 className="section-title" id="reply-title">Reply unavailable</h2></div>
                <div className="explanation-card"><span className="eyebrow">CONTENT-SAFE REPLY</span><p>{actionView.reply.explanation}</p></div>
                {actionView.reply.disabledReason && <div className="command-status" role="status">{actionView.reply.disabledReason}</div>}
              </section>
            )}

            {!readOnly && <StopDialog open={stopOpen} onCancel={() => setStopOpen(false)} onConfirm={handleStopConfirm} disabled={officialLocal && !actionView?.stop.enabled} disabledReason={actionView?.stop.disabledReason ?? visibleCapabilityReason} />}
          </>
        )}
      </main>

      {view && (
        <nav className="app-bottombar" aria-label="Primary" style={readOnly ? { gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' } : undefined}>
          <TabButton tab="home" current={tab} label="Home" symbol="01" onClick={() => setTab('home')} />
          <TabButton tab="activity" current={tab} label="Activity" symbol="02" onClick={() => setTab('activity')} />
          {!readOnly && <TabButton tab="action" current={tab} label="Action" symbol={needsPermission ? '!' : '03'} onClick={() => setTab('action')} />}
          <TabButton tab="changes" current={tab} label="Changes" symbol={readOnly ? '03' : '04'} onClick={() => setTab('changes')} />
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
        <div className="callout-body">Contract fixtures are isolated from the default Read-only Alpha route.</div>
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

function LoadingState({ readOnly }: { readOnly: boolean }) {
  return <div className="loading-state" role="status"><span className="loading-bar" /><strong>{readOnly ? 'Connecting to Read-only Alpha' : 'Connecting to your demo session'}</strong><span>{readOnly ? 'Loading the latest verified local Host projection.' : 'Loading explicit local demo data.'}</span></div>;
}

function blocked(reason: string) {
  return { status: 'Rejected' as const, result: { error_code: 'ERR_SAFETY_BLOCKED' as const, error_message: reason } };
}

interface LoadFailure {
  status: AlphaAvailability;
  message: string;
}

function toLoadFailure(error: unknown): LoadFailure {
  if (error instanceof AlphaAvailabilityError || error instanceof AlphaResponseError) {
    return { status: error.status, message: error.message };
  }
  return {
    status: 'unavailable',
    message: error instanceof Error ? error.message : 'The session could not be loaded.',
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function capabilityMismatch(binding: BrowserCommandCapability | null, seq: number, digest: string | null, now = Date.now()): string | null {
  if (!binding) return 'No live command capability is available. This view remains read-only.';
  const capability = binding.capability;
  if (capability.allow_once !== false) return 'The command capability is incompatible.';
  if (binding.displaySnapshotSeq !== seq || !digest || binding.displaySnapshotDigest !== digest) return 'The displayed snapshot changed. Review it before acting.';
  if (Date.parse(capability.issued_at) > now || Date.parse(capability.expires_at) <= now) return 'The command capability expired. Refresh and review the latest state.';
  return null;
}

function commandReceiptLabel(status: string): string {
  if (status === 'HostAccepted') return 'Host accepted; waiting for Agent result.';
  if (status === 'Dispatching') return 'The Host is dispatching the command; the outcome is not final.';
  if (status === 'DispatchAcknowledged') return 'The Agent endpoint acknowledged dispatch; task state has not been changed optimistically.';
  return `Command finished with ${status}.`;
}

function snapshotKey(view: SessionView): string {
  return `${view.state.lastAppliedSeq}:${view.state.expectedDigest ?? ''}`;
}
