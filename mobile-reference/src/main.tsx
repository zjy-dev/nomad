import React from 'react';
import ReactDOM from 'react-dom/client';
import { HttpSessionClient } from './client/http-client';
import { decodeAlphaSession } from './client/alpha-decoder';
import { App } from './ui/App';
import { BrowserVault } from './remote/browser-vault';
import { PairingClient } from './remote/pairing-client';
import { createRemoteSessionPort } from './remote/paired-session';
import { createDesktopPairingClient } from './ui/pairing-api';
import { PhonePairingScreen } from './ui/PhonePairingScreen';
import './ui/styles.css';

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('Missing #root mount node');

const sessionClient = new HttpSessionClient({
  baseUrl: window.location.origin,
  decodeSession: decodeAlphaSession,
});

const browserVault = new BrowserVault();
const pairingClient = new PairingClient({
  baseUrl: window.location.origin,
  vault: browserVault,
});

const desktopPairingClient = createDesktopPairingClient({
  baseUrl: window.location.origin,
});

const appNode = window.location.pathname.startsWith('/j/')
  ? (
    <PhonePairingScreen
      pairingClient={pairingClient}
      vault={browserVault}
      remoteSessionFactory={(session) => createRemoteSessionPort({
        session,
        vault: browserVault,
      })}
    />
  )
  : <App client={sessionClient} mode="official-local" desktopPairingClient={desktopPairingClient} />;

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    {appNode}
  </React.StrictMode>,
);
