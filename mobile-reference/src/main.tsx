/**
 * Mobile Reference client application bootstrap.
 *
 * Industrial task-control aesthetic: dense, low-chrome, mobile-first.
 * No claim to native iOS/Push/Keychain — this is a responsive web client
 * that exercises the Mobile companion contract and UI flows.
 */

import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './ui/App';
import './ui/styles.css';

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('Missing #root mount node');

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
