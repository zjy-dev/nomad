import { App } from './App';
import type { SessionClient } from '../client/types';

export interface RemoteSessionPort extends SessionClient {
  readonly mode?: 'official-local';
}

interface RemoteSessionPanelProps {
  port: RemoteSessionPort | null;
  reason?: string | null;
}

export function RemoteSessionPanel({ port, reason }: RemoteSessionPanelProps) {
  if (!port) {
    return (
      <section className="section remote-session-shell" aria-labelledby="remote-session-title">
        <div className="section-header"><h2 className="section-title" id="remote-session-title">Remote Session</h2></div>
        <div className="perm-block" role="status" aria-live="polite">
          <strong>Secure session not connected</strong>
          <div>{reason || 'Secure session not connected'}</div>
        </div>
      </section>
    );
  }

  return <App client={port} mode="official-local" />;
}
