import React from 'react';
import ReactDOM from 'react-dom/client';
import { HttpSessionClient } from './client/http-client';
import { PilotSessionClient } from './client/pilot-client';
import type { CommandSubmission, SessionView } from './client/types';
import { App } from './ui/App';
import './ui/styles.css';

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('Missing #root mount node');

const params = new URLSearchParams(window.location.search);
const localDataMode = params.get('demo') === '1' || params.get('lab') === '1';
const sessionClient = localDataMode
  ? new PilotSessionClient()
  : new HttpSessionClient({
      baseUrl: window.location.origin,
      routes: {
        currentSession: '/api/pilot/session',
        refreshSession: () => '/api/pilot/session',
        commands: '/api/pilot/commands',
        commandStatus: (_sessionId, requestId) => `/api/pilot/commands/${encodeURIComponent(requestId)}`,
      },
      decodeSession: decodeSessionView,
      decodeCommand: decodeCommandSubmission,
    });

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App client={sessionClient} />
  </React.StrictMode>,
);

function decodeSessionView(payload: unknown): SessionView {
  if (!payload || typeof payload !== 'object' || !('state' in payload) || !('changes' in payload)) {
    throw new Error('Gateway returned an incompatible Session view.');
  }
  return payload as SessionView;
}

function decodeCommandSubmission(payload: unknown): CommandSubmission {
  if (!payload || typeof payload !== 'object' || !('status' in payload) || !('result' in payload)) {
    throw new Error('Gateway returned an incompatible command result.');
  }
  return payload as CommandSubmission;
}
