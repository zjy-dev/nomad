import { useEffect, useMemo, useRef, useState } from 'react';
import type { BrowserVaultSession } from '../remote/browser-vault';
import { BrowserVaultError } from '../remote/browser-vault';
import type { PairingConfirmResult, PairingJoinStartResult } from '../remote/pairing-client';
import { PairingClientError } from '../remote/pairing-client';
import { RemoteSessionError, type RemoteSessionPort as RuntimeRemoteSessionPort, type RemoteSessionSnapshot } from '../remote/paired-session';
import { RemoteSessionPanel, type RemoteSessionPort } from './RemoteSessionPanel';
import { createRemoteSessionClient, recoverPendingRemoteCommand, type RemoteSessionFactory } from './remote-session-client';

export interface PhonePairingClientPort {
  startFromCurrentLocation(): Promise<PairingJoinStartResult>;
  confirm(): Promise<PairingConfirmResult>;
  cancelPending(): void;
  abortPending(): Promise<void>;
}

export interface PhoneVaultPort {
  restorePairedDevice(): Promise<BrowserVaultSession>;
}

interface PhonePairingScreenProps {
  pairingClient: PhonePairingClientPort;
  vault: PhoneVaultPort;
  remoteSessionFactory?: RemoteSessionFactory | null;
}

type PhoneViewState =
  | { kind: 'loading' }
  | { kind: 'join-waiting' }
  | { kind: 'compare'; join: PairingJoinStartResult }
  | { kind: 'persisting'; code: string }
  | { kind: 'connecting'; session: BrowserVaultSession; message: string }
  | { kind: 'paired'; session: BrowserVaultSession; remoteClient: RemoteSessionPort | null; message: string; canRetryConnection: boolean }
  | { kind: 'expired'; message: string }
  | { kind: 'lost-key'; message: string }
  | { kind: 'revoked'; message: string }
  | { kind: 'storage-unavailable'; message: string }
  | { kind: 'error'; message: string };

const MAX_BROWSER_TIMEOUT_MS = 60_000;
const CONNECT_RETRY_DELAYS_MS = [150, 300, 600] as const;
const REMOTE_CONNECTING_MESSAGE = 'Checking the secure remote session…';
const REMOTE_NOT_CONNECTED_MESSAGE = 'Secure session not connected';
const REMOTE_RETRY_MESSAGE = 'Secure session not connected. Retry connect to check again.';

export function PhonePairingScreen({ pairingClient, vault, remoteSessionFactory = null }: PhonePairingScreenProps) {
  const [state, setState] = useState<PhoneViewState>({ kind: 'loading' });
  const [busy, setBusy] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const runtimeRef = useRef<RuntimeRemoteSessionPort | null>(null);
  const runtimeClientRef = useRef<RemoteSessionPort | null>(null);
  const runtimeSessionRef = useRef<BrowserVaultSession | null>(null);
  const runtimeUnsubscribeRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let active = true;
    void initialize();
    return () => {
      active = false;
      clearRuntimeBinding();
    };

    async function initialize() {
      try {
        const restored = await vault.restorePairedDevice();
        if (!active) return;
        setState({ kind: 'connecting', session: restored, message: REMOTE_CONNECTING_MESSAGE });
        await attachRemoteSession(restored, active);
        return;
      } catch (reason) {
        if (!active) return;
        const restoredState = mapRestoreFailure(reason);
        if (restoredState) {
          setState(restoredState);
          return;
        }
      }

      if (window.location.pathname.startsWith('/j/')) {
        setState({ kind: 'join-waiting' });
        try {
          const join = await pairingClient.startFromCurrentLocation();
          if (!active) return;
          setExpired(false);
          setState({ kind: 'compare', join });
        } catch (reason) {
          if (!active) return;
          setState(mapPairingFailure(reason));
        }
        return;
      }

      setState({ kind: 'join-waiting' });
    }
  }, [pairingClient, remoteSessionFactory, vault]);

  async function attachRemoteSession(session: BrowserVaultSession, active = true) {
    if (!remoteSessionFactory) {
      if (active) {
        setState({
          kind: 'paired',
          session,
          remoteClient: null,
          message: REMOTE_NOT_CONNECTED_MESSAGE,
          canRetryConnection: false,
        });
      }
      return;
    }
    try {
      const runtime = await remoteSessionFactory(session);
      if (!active) return;
      bindRuntime(session, runtime);
      await connectRuntime(session, runtime, active);
    } catch (reason) {
      if (!active) return;
      const remoteState = mapRemoteFailure(reason, session);
      if (remoteState) {
        setState(remoteState);
        return;
      }
      setState({
        kind: 'paired',
        session,
        remoteClient: null,
        message: REMOTE_NOT_CONNECTED_MESSAGE,
        canRetryConnection: false,
      });
    }
  }

  function clearRuntimeBinding() {
    runtimeUnsubscribeRef.current?.();
    runtimeUnsubscribeRef.current = null;
    runtimeRef.current = null;
    runtimeClientRef.current = null;
    runtimeSessionRef.current = null;
  }

  function bindRuntime(session: BrowserVaultSession, runtime: RuntimeRemoteSessionPort) {
    clearRuntimeBinding();
    runtimeRef.current = runtime;
    runtimeClientRef.current = createRemoteSessionClient(runtime);
    runtimeSessionRef.current = session;
    runtimeUnsubscribeRef.current = runtime.subscribe((snapshot) => {
      handleRuntimeSnapshot(runtime, session, snapshot);
    });
  }

  function handleRuntimeSnapshot(
    runtime: RuntimeRemoteSessionPort,
    session: BrowserVaultSession,
    snapshot: RemoteSessionSnapshot,
  ) {
    if (runtimeRef.current !== runtime) {
      return;
    }
    if (snapshot.connection === 'revoked') {
      clearRuntimeBinding();
      setState({ kind: 'revoked', message: 'Phone access removed. Pair again from your Mac to continue.' });
      return;
    }
    if (snapshot.connection === 'key_lost') {
      clearRuntimeBinding();
      setState({ kind: 'lost-key', message: 'This browser lost its secure device keys. Pair again from your Mac to continue.' });
      return;
    }
    if (snapshot.connection === 'live' && snapshot.last_good_projection !== null) {
      setState({
        kind: 'paired',
        session,
        remoteClient: runtimeClientRef.current,
        message: 'Remote session connected.',
        canRetryConnection: false,
      });
      return;
    }
    setState((current) => current.kind === 'paired'
      ? {
          kind: 'paired',
          session,
          remoteClient: null,
          message: remoteMessageForSnapshot(snapshot),
          canRetryConnection: true,
        }
      : current);
  }

  async function connectRuntime(
    session: BrowserVaultSession,
    runtime: RuntimeRemoteSessionPort,
    active = true,
  ) {
    const initial = runtime.getSnapshot();
    if (initial.pending_command !== null && initial.pending_command.status !== 'OutcomeUnknown') {
      try {
        await recoverPendingRemoteCommand(runtime);
      } catch (reason) {
        if (!active) return;
        if (!(reason instanceof RemoteSessionError) || reason.code !== 'REMOTE_COMMAND_PENDING') {
          const remoteState = mapRemoteFailure(reason, session);
          if (remoteState) {
            clearRuntimeBinding();
            setState(remoteState);
            return;
          }
        }
      }
    }
    for (let attempt = 0; attempt <= CONNECT_RETRY_DELAYS_MS.length; attempt += 1) {
      try {
        const snapshot = await runtime.poll();
        if (!active) return;
        if (snapshot.connection === 'revoked') {
          clearRuntimeBinding();
          setState({ kind: 'revoked', message: 'Phone access removed. Pair again from your Mac to continue.' });
          return;
        }
        if (snapshot.connection === 'key_lost') {
          clearRuntimeBinding();
          setState({ kind: 'lost-key', message: 'This browser lost its secure device keys. Pair again from your Mac to continue.' });
          return;
        }
        if (snapshot.connection === 'live' && snapshot.last_good_projection !== null) {
          setState({
            kind: 'paired',
            session,
            remoteClient: runtimeClientRef.current,
            message: 'Remote session connected.',
            canRetryConnection: false,
          });
          return;
        }
      } catch (reason) {
        if (!active) return;
        const remoteState = mapRemoteFailure(reason, session);
        if (remoteState) {
          clearRuntimeBinding();
          setState(remoteState);
          return;
        }
      }
      if (attempt < CONNECT_RETRY_DELAYS_MS.length) {
        await delay(CONNECT_RETRY_DELAYS_MS[attempt]);
        if (!active) return;
      }
    }
    setState({
      kind: 'paired',
      session,
      remoteClient: null,
      message: REMOTE_RETRY_MESSAGE,
      canRetryConnection: true,
    });
  }

  async function handleRetryConnect() {
    const runtime = runtimeRef.current;
    const session = runtimeSessionRef.current;
    if (runtime === null || session === null) {
      return;
    }
    setBusy('retry-connect');
    setState({ kind: 'connecting', session, message: REMOTE_CONNECTING_MESSAGE });
    try {
      await connectRuntime(session, runtime);
    } finally {
      setBusy(null);
    }
  }

  const countdownTarget = state.kind === 'compare'
    ? state.join.expiresAt
    : state.kind === 'paired' || state.kind === 'connecting'
      ? state.session.bundle.issued_at
      : null;
  const comparisonCode = state.kind === 'compare'
    ? state.join.comparisonCode
    : state.kind === 'paired' || state.kind === 'connecting'
      ? state.session.comparisonCode
      : state.kind === 'persisting'
        ? state.code
        : null;
  const pairedFacts = useMemo(() => state.kind === 'paired' || state.kind === 'connecting'
    ? [
        ['Device Alias', state.session.bundle.device_alias],
        ['Mailbox', state.session.bundle.mailbox_id],
        ['Epoch', String(state.session.bundle.pairing_epoch)],
      ]
    : [], [state]);
  const confirmDisabled = busy !== null || expired;

  useEffect(() => {
    headingRef.current?.focus();
  }, [state.kind]);

  useEffect(() => {
    if (state.kind !== 'compare') return;
    let timer: number | null = null;

    const expire = () => {
      setExpired(true);
      setState({ kind: 'expired', message: 'Pairing expired. Return to your Mac and start pairing again.' });
      void pairingClient.abortPending().catch(() => {});
    };

    const arm = () => {
      const deadline = Date.parse(state.join.expiresAt) - Date.now();
      if (!Number.isFinite(deadline) || deadline <= 0) {
        expire();
        return;
      }
      // Re-arm within the browser timeout ceiling so far-future expiries do not overflow.
      timer = window.setTimeout(arm, Math.min(deadline, MAX_BROWSER_TIMEOUT_MS));
    };

    arm();
    return () => {
      if (timer !== null) window.clearTimeout(timer);
    };
  }, [pairingClient, state]);

  async function handleConfirm() {
    if (state.kind !== 'compare') return;
    if (Date.parse(state.join.expiresAt) <= Date.now()) {
      setExpired(true);
      setState({ kind: 'expired', message: 'Pairing expired. Return to your Mac and start pairing again.' });
      await pairingClient.abortPending().catch(() => {});
      return;
    }
    setBusy('confirm');
    setState({ kind: 'persisting', code: state.join.comparisonCode });
    try {
      const confirmed = await pairingClient.confirm();
      setState({ kind: 'connecting', session: confirmed.session, message: REMOTE_CONNECTING_MESSAGE });
      await attachRemoteSession(confirmed.session);
    } catch (reason) {
      setState(mapPairingFailure(reason));
    } finally {
      setBusy(null);
    }
  }

  async function handleCancel() {
    await pairingClient.abortPending().catch(() => {});
    setState({ kind: 'expired', message: 'Pairing expired. Return to your Mac and start pairing again.' });
  }

  return (
    <main className="pairing-phone-shell">
      <section className="pairing-phone-card" aria-labelledby="phone-pairing-title">
        <span className="eyebrow">Phone Browser</span>
        <h1 id="phone-pairing-title" ref={headingRef} tabIndex={-1}>{titleForState(state)}</h1>
        <p className="pairing-phone-copy">{copyForState(state)}</p>

        {comparisonCode && (
          <div className="pairing-code-block pairing-code-block--phone" aria-live="polite" aria-atomic="true">
            <span className="eyebrow">Comparison Code</span>
            <strong>{comparisonCode}</strong>
            {state.kind === 'compare' && <small>Only confirm if this code matches your Mac</small>}
          </div>
        )}

        {state.kind === 'compare' && countdownTarget && (
          <div className="pairing-phone-expiry">
            <CountdownText expiresAt={countdownTarget} />
          </div>
        )}

        {state.kind === 'persisting' && <div className="command-status" role="status" aria-live="polite">Persisting secure browser state…</div>}
        {state.kind === 'loading' && <div className="command-status" role="status">Checking secure browser state…</div>}
        {state.kind === 'connecting' && (
          <>
            <dl className="pairing-facts">
              {pairedFacts.map(([label, value]) => (
                <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
              ))}
            </dl>
            <div className="command-status" role="status" aria-live="polite">{state.message}</div>
          </>
        )}
        {state.kind === 'paired' && (
          <>
            <dl className="pairing-facts">
              {pairedFacts.map(([label, value]) => (
                <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
              ))}
            </dl>
            {state.remoteClient ? (
              <RemoteSessionPanel port={state.remoteClient} reason={state.message} />
            ) : (
              <section className="section remote-session-shell" aria-labelledby="remote-session-title">
                <div className="section-header"><h2 className="section-title" id="remote-session-title">Remote Session</h2></div>
                <div className="perm-block" role="status" aria-live="polite">
                  <strong>Secure session not connected</strong>
                  <div>{state.message}</div>
                </div>
                {state.canRetryConnection && (
                  <div className="hero-actions">
                    <button className="btn btn--primary" onClick={() => { void handleRetryConnect(); }} disabled={busy !== null}>
                      Retry connect
                    </button>
                  </div>
                )}
              </section>
            )}
          </>
        )}

        {state.kind === 'compare' && (
          <div className="hero-actions">
            <button className="btn btn--ghost" onClick={() => { void handleCancel(); }} disabled={busy !== null}>Cancel</button>
            <button className="btn btn--primary" onClick={() => { void handleConfirm(); }} disabled={confirmDisabled} aria-disabled={confirmDisabled}>Confirm</button>
          </div>
        )}
      </section>
    </main>
  );
}

function titleForState(state: PhoneViewState): string {
  switch (state.kind) {
    case 'loading':
      return 'Checking this browser';
    case 'join-waiting':
      return 'Confirm this Mac';
    case 'compare':
      return 'Confirm this Mac';
    case 'persisting':
      return 'Persisting secure device state';
    case 'connecting':
      return 'Connecting secure session';
    case 'paired':
      return state.remoteClient ? 'Remote session connected' : 'Secure session not connected';
    case 'expired':
      return 'Pairing expired';
    case 'lost-key':
      return 'Secure keys were lost';
    case 'revoked':
      return 'Phone access removed';
    case 'storage-unavailable':
      return 'Storage unavailable';
    case 'error':
      return 'Pairing unavailable';
  }
}

function copyForState(state: PhoneViewState): string {
  switch (state.kind) {
    case 'loading':
      return 'Checking whether this browser already holds the secure device state Nomad needs.';
    case 'join-waiting':
      return 'Open the one-time pairing link from your Mac to continue.';
    case 'compare':
      return 'Only confirm if this code matches your Mac';
    case 'persisting':
      return 'This browser is writing the secure device state needed to survive refresh safely.';
    case 'connecting':
    case 'paired':
      return state.message;
    case 'expired':
    case 'lost-key':
    case 'revoked':
    case 'storage-unavailable':
    case 'error':
      return state.message;
  }
}

function CountdownText({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const seconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
  return <span>This code expires in about {Math.ceil(seconds / 60)} minutes</span>;
}

function mapRestoreFailure(reason: unknown): PhoneViewState | null {
  if (!(reason instanceof BrowserVaultError)) {
    return null;
  }
  if (reason.code === 'BROWSER_VAULT_EMPTY') {
    return null;
  }
  if (reason.code === 'BROWSER_VAULT_UNAVAILABLE') {
    return { kind: 'storage-unavailable', message: 'This browser cannot keep the secure data Nomad needs. Open in a normal Safari tab and try again.' };
  }
  if (reason.code === 'BROWSER_VAULT_KEY_LOST' || reason.code === 'BROWSER_VAULT_RESTORE_FAILED') {
    return { kind: 'lost-key', message: 'This browser lost its secure device keys. Pair again from your Mac to continue.' };
  }
  return { kind: 'error', message: reason.message };
}

function mapRemoteFailure(reason: unknown, session: BrowserVaultSession): PhoneViewState | null {
  if (!(reason instanceof RemoteSessionError)) {
    return null;
  }
  if (reason.code === 'DEVICE_REVOKED') {
    return { kind: 'revoked', message: 'Phone access removed. Pair again from your Mac to continue.' };
  }
  if (reason.code === 'KEY_LOST' || reason.code === 'VAULT_RESTORE_FAILED') {
    return { kind: 'lost-key', message: 'This browser lost its secure device keys. Pair again from your Mac to continue.' };
  }
  if (reason.code === 'REMOTE_PROJECTION_UNAVAILABLE' || reason.code === 'PAIRED_SESSION_STORE_REQUIRED') {
    return {
      kind: 'paired',
      session,
      remoteClient: null,
      message: REMOTE_RETRY_MESSAGE,
      canRetryConnection: true,
    };
  }
  return {
    kind: 'paired',
    session,
    remoteClient: null,
    message: REMOTE_NOT_CONNECTED_MESSAGE,
    canRetryConnection: false,
  };
}

function mapPairingFailure(reason: unknown): PhoneViewState {
  if (reason instanceof BrowserVaultError) {
    if (reason.code === 'BROWSER_VAULT_UNAVAILABLE') {
      return { kind: 'storage-unavailable', message: 'This browser cannot keep the secure data Nomad needs. Open in a normal Safari tab and try again.' };
    }
    if (reason.code === 'BROWSER_VAULT_KEY_LOST' || reason.code === 'BROWSER_VAULT_RESTORE_FAILED') {
      return { kind: 'lost-key', message: 'This browser lost its secure device keys. Pair again from your Mac to continue.' };
    }
  }
  if (reason instanceof PairingClientError) {
    if (['JOIN_SECRET_REQUIRED', 'INVALID_JOIN_SECRET', 'INVALID_JOIN_ID', 'PAIRING_EXPIRED'].includes(reason.code)) {
      return { kind: 'expired', message: 'Pairing expired. Return to your Mac and start pairing again.' };
    }
    if (reason.code === 'PAIRING_HTTP_ERROR') {
      return { kind: 'error', message: 'Pairing request was not accepted by the local Gateway.' };
    }
    if (reason.code === 'INVALID_PAIRING_RESPONSE' || reason.code === 'PAIRING_INVALID_RESPONSE') {
      return { kind: 'error', message: 'Pairing response was incompatible.' };
    }
  }
  return {
    kind: 'error',
    message: reason instanceof Error ? reason.message : 'Pairing is unavailable in this browser.',
  };
}

function remoteMessageForSnapshot(snapshot: RemoteSessionSnapshot): string {
  if (snapshot.connection === 'reconnecting') {
    return 'Secure session reconnecting. Retry connect to check again.';
  }
  if (snapshot.connection === 'unavailable') {
    return 'Secure session unavailable. Retry connect to check again.';
  }
  return REMOTE_RETRY_MESSAGE;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}
