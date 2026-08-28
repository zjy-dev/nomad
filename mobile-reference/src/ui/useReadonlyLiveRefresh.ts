import { useCallback, useEffect, useRef } from 'react';
import type { SessionClient, SessionView } from '../client/types';

const SUCCESS_DELAY_MS = 100;
const MAX_RETRY_DELAY_MS = 5_000;
const STALE_AFTER_MS = 60_000;

export type FailedFreshness = 'Reconnecting' | 'Stale';

export interface ReadonlyLiveRefreshOptions {
  enabled: boolean;
  client: SessionClient;
  sessionId: string | null;
  onSuccess: (view: SessionView) => void;
  onFailure: (error: unknown, freshness: FailedFreshness) => void;
}

/**
 * Runs one long-poll refresh at a time for the read-only product view.
 *
 * SessionClient does not currently accept an AbortSignal, so cleanup cannot
 * cancel bytes already in flight. It does prevent stale completions from
 * changing React state and prevents any later request from being scheduled.
 */
export function useReadonlyLiveRefresh(options: ReadonlyLiveRefreshOptions): () => Promise<void> {
  const callbacks = useRef({ onSuccess: options.onSuccess, onFailure: options.onFailure });
  callbacks.current = { onSuccess: options.onSuccess, onFailure: options.onFailure };
  const trigger = useRef<() => Promise<void>>(async () => {});

  useEffect(() => {
    if (!options.enabled) {
      trigger.current = async () => {};
      return;
    }

    let active = true;
    let timer: number | null = null;
    let inFlight: Promise<void> | null = null;
    let failures = 0;
    let firstFailureAt: number | null = null;

    const clearScheduled = () => {
      if (timer !== null) window.clearTimeout(timer);
      timer = null;
    };
    const schedule = (delayMs: number) => {
      clearScheduled();
      if (!active || document.visibilityState === 'hidden') return;
      timer = window.setTimeout(() => { void run(false); }, delayMs);
    };
    const run = (manual: boolean): Promise<void> => {
      if (!active || (!manual && document.visibilityState === 'hidden')) return Promise.resolve();
      if (inFlight) return inFlight;
      clearScheduled();
      const request = (options.sessionId
        ? options.client.refreshSession(options.sessionId)
        : options.client.loadCurrentSession())
        .then((view) => {
          if (!active) return;
          failures = 0;
          firstFailureAt = null;
          callbacks.current.onSuccess(view);
          schedule(SUCCESS_DELAY_MS);
        })
        .catch((error: unknown) => {
          if (!active) return;
          const now = Date.now();
          firstFailureAt ??= now;
          const freshness: FailedFreshness = now - firstFailureAt >= STALE_AFTER_MS ? 'Stale' : 'Reconnecting';
          callbacks.current.onFailure(error, freshness);
          const delayMs = Math.min(250 * (2 ** failures), MAX_RETRY_DELAY_MS);
          failures = Math.min(failures + 1, 16);
          schedule(delayMs);
        })
        .finally(() => {
          if (inFlight === request) inFlight = null;
        });
      inFlight = request;
      return request;
    };
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') clearScheduled();
      else schedule(0);
    };

    trigger.current = () => run(true);
    document.addEventListener('visibilitychange', onVisibility);
    void run(false);
    return () => {
      active = false;
      clearScheduled();
      trigger.current = async () => {};
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [options.client, options.enabled, options.sessionId]);

  return useCallback(() => trigger.current(), []);
}
