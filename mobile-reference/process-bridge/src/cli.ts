#!/usr/bin/env node
/**
 * Process Bridge CLI — Mobile-side process loop harness.
 *
 * Usage:
 *   node --import tsx src/cli.ts --relay-url http://127.0.0.1:8080 --token test-token-123
 *
 * Or with a compiled build:
 *   node dist/cli.js --relay-url http://127.0.0.1:8080 --token test-token-123
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ProcessBridge } from './process-bridge.js';

function parseArgs(): Record<string, string> {
  const args: Record<string, string> = {};
  const raw = process.argv.slice(2);
  for (let i = 0; i < raw.length; i++) {
    if (raw[i].startsWith('--')) {
      const key = raw[i].slice(2);
      const val = raw[i + 1]?.startsWith('--') ? 'true' : raw[++i] ?? 'true';
      args[key] = val;
    }
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseArgs();

  const relayUrl = args['relay-url'] ?? 'http://127.0.0.1:8080';
  const token = args.token ?? 'test-token';
  const channel = args.channel;
  const outPath = args.out ?? 'process-bridge-transcript.json';

  console.log(`[bridge] relay-url=${relayUrl}`);
  console.log('[bridge] token=[redacted]');
  console.log(`[bridge] output=${outPath}`);

  const bridge = new ProcessBridge({ relayUrl, token, channel });
  const transcript = await bridge.run();

  const absPath = resolve(outPath);
  writeFileSync(absPath, JSON.stringify(transcript, null, 2));
  console.log(`[bridge] transcript written to ${absPath}`);
  console.log(`[bridge] steps: ${transcript.steps.length}`);

  // Exit non-zero if any step failed
  const hasError = transcript.steps.some((s) => s.detail.result === 'error');
  process.exit(hasError ? 1 : 0);
}

main().catch((err) => {
  console.error('[bridge] fatal:', err);
  process.exit(1);
});
