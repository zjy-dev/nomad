import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AlphaStateError, AlphaStore } from './alpha-store.mjs';
import { canonicalJson, ProductHostClientError } from './product-host-client.mjs';
import { createGateway, parseArgs } from './server.mjs';
import { validateBrowserProjection } from './view.mjs';

function envelope({ instance = 'host-' + '1'.repeat(32), seq = 1, state = 'Running', count = 4 } = {}) {
  const value = {
    schema: 'nomad.product-host.snapshot.v1', host_instance_id: instance, snapshot_seq: seq, digest: 'sha256:placeholder',
    snapshot: {
      session_alias: 'sess-' + '2'.repeat(32), updated_at: '2026-08-25T12:00:00.000Z', turn_state: state,
      pending_input_alias: null, pending_permission_alias: null, diff_file_count: count, writable: false,
      evidence_class: 'official_registry_shape_only_not_provider_lifecycle',
    },
  };
  const canonical = { schema: value.schema, host_instance_id: value.host_instance_id, snapshot_seq: value.snapshot_seq, snapshot: value.snapshot };
  value.digest = 'sha256:' + createHash('sha256').update(canonicalJson(canonical)).digest('hex');
  return value;
}

function dbPath() { return join(mkdtempSync(join(tmpdir(), 'nomad-product-gateway-')), 'state.sqlite3'); }
async function gateway(client, store = new AlphaStore(dbPath())) {
  const relay = { async listFrames() { throw new Error('Relay fallback forbidden'); } };
  const server = createServer(createGateway({ mode: 'official-agent-local', productHostClient: client, relayClient: relay, store, distDir: '/missing' })).listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { store, server, base: 'http://127.0.0.1:' + server.address().port, async close() { server.close(); await once(server, 'close'); store.close(); } };
}

test('official mode needs only UDS capability and never requires Relay token', () => {
  const identity = ['--product-host-socket-parent-dev', '1', '--product-host-socket-parent-ino', '2', '--product-host-socket-dev', '3', '--product-host-socket-ino', '4'];
  const value = parseArgs(['--mode', 'official-agent-local', '--product-host-socket', '/private/tmp/product-host.sock', ...identity, '--command-key-fd', '11', '--state-db', '/tmp/gateway.db'], {});
  assert.equal(value.productHostSocket, '/private/tmp/product-host.sock'); assert.equal(value.relayToken, undefined);
  assert.equal(value.commandKeyFd, 11);
  assert.throws(() => parseArgs(['--mode', 'official-agent-local', '--state-db', '/tmp/gateway.db'], {}), /product-host-socket/);
  assert.throws(() => parseArgs(['--product-host-socket', '/private/tmp/product-host.sock', '--state-db', '/tmp/gateway.db'], { NOMAD_ALPHA_RELAY_TOKEN: 'x' }), /requires official/);
});

test('official Gateway persists exact Host envelope and exposes re-digested content-safe browser projection', async () => {
  const client = { async getCurrent() { return envelope(); }, async getStream() { throw new Error('not called'); } };
  const running = await gateway(client);
  try {
    const response = await fetch(running.base + '/api/alpha/session'); const body = await response.json();
    assert.equal(response.status, 200); validateBrowserProjection(body);
    assert.equal(body.session.session_id, 'sess-' + '2'.repeat(32)); assert.equal(body.session.turn_id, null);
    assert.equal(body.changes.aggregate_file_count, 4); assert.equal(body.provenance.source, 'local-host-direct');
    assert.notEqual(body.digest, envelope().digest); assert.equal(JSON.stringify(body).includes('host_instance_id'), false);
  } finally { await running.close(); }
});

test('204 immediately probes current; healthy duplicate remains Live', async () => {
  const calls = []; const value = envelope();
  const client = { async getCurrent() { calls.push('current'); return value; }, async getStream(seq) { calls.push('stream:' + seq); return null; } };
  const running = await gateway(client);
  try {
    assert.equal((await (await fetch(running.base + '/api/alpha/session')).json()).session.client_freshness, 'Live');
    assert.equal((await (await fetch(running.base + '/api/alpha/session')).json()).session.client_freshness, 'Live');
    assert.deepEqual(calls, ['current', 'stream:1', 'current']);
  } finally { await running.close(); }
});

test('disconnect, gap and conflict preserve last-good turn state and only degrade connectivity', async (context) => {
  for (const [name, next] of [
    ['disconnect', new Error('secret raw session')],
    ['gap', envelope({ seq: 3, state: 'Completed' })],
    ['conflict', { ...envelope(), digest: 'sha256:' + '0'.repeat(64) }],
  ]) await context.test(name, async () => {
    let first = true;
    const client = { async getCurrent() { return envelope(); }, async getStream() { if (first) { first = false; throw next; } throw next; } };
    const running = await gateway(client);
    try {
      await fetch(running.base + '/api/alpha/session'); const response = await fetch(running.base + '/api/alpha/session'); const body = await response.json();
      assert.equal(response.status, 200); assert.equal(body.session.turn_state, 'Running'); assert.equal(body.session.host_connectivity, 'Offline'); assert.equal(body.session.client_freshness, 'Reconnecting');
    } finally { await running.close(); }
  });
});

test('409 resyncs through current and accepts a new Host instance as Reconnecting', async () => {
  let current = envelope(); const calls = [];
  const client = {
    async getCurrent() { calls.push('current'); return current; },
    async getStream() { calls.push('stream'); current = envelope({ instance: 'host-' + '3'.repeat(32), seq: 1, state: 'Completed' }); throw new ProductHostClientError('PRODUCT_HOST_RESTARTED'); },
  };
  const running = await gateway(client);
  try {
    await fetch(running.base + '/api/alpha/session'); const body = await (await fetch(running.base + '/api/alpha/session')).json();
    assert.equal(body.session.turn_state, 'Completed'); assert.equal(body.session.client_freshness, 'Reconnecting'); assert.deepEqual(calls, ['current', 'stream', 'current']);
  } finally { await running.close(); }
});

test('same-instance stream gap remains last-good even when current confirms the gap', async () => {
  let current = envelope(); const calls = [];
  const client = {
    async getCurrent() { calls.push('current'); return current; },
    async getStream() { calls.push('stream'); current = envelope({ seq: 4, state: 'Completed' }); return current; },
  };
  const running = await gateway(client);
  try {
    await fetch(running.base + '/api/alpha/session'); const body = await (await fetch(running.base + '/api/alpha/session')).json();
    assert.equal(body.last_applied_seq, 1); assert.equal(body.session.turn_state, 'Running'); assert.equal(body.session.host_connectivity, 'Offline'); assert.equal(body.session.client_freshness, 'Reconnecting');
    assert.deepEqual(calls, ['current', 'stream', 'current']);
  } finally { await running.close(); }
});

test('verified current may fill exactly one missing same-instance sequence', async () => {
  let current = envelope(); const calls = [];
  const client = {
    async getCurrent() { calls.push('current'); return current; },
    async getStream() { calls.push('stream'); current = envelope({ seq: 2, state: 'Completed' }); throw new ProductHostClientError('PRODUCT_HOST_RESTARTED'); },
  };
  const running = await gateway(client);
  try {
    await fetch(running.base + '/api/alpha/session'); const body = await (await fetch(running.base + '/api/alpha/session')).json();
    assert.equal(body.last_applied_seq, 2); assert.equal(body.session.turn_state, 'Completed'); assert.equal(body.session.client_freshness, 'Live');
    assert.deepEqual(calls, ['current', 'stream', 'current']);
  } finally { await running.close(); }
});

test('store enforces duplicate, sequential advance, restart-only-current and Stale threshold', () => {
  const store = new AlphaStore(dbPath()); const first = envelope();
  try {
    assert.equal(store.persistProduct(first, { nowMs: 1 }).result, 'stored'); assert.equal(store.persistProduct(first, { nowMs: 2 }).result, 'duplicate');
    assert.throws(() => store.persistProduct(envelope({ seq: 3 })), (error) => error instanceof AlphaStateError && error.code === 'SEQ_GAP');
    assert.throws(() => store.persistProduct(envelope({ instance: 'host-' + '4'.repeat(32) })), (error) => error instanceof AlphaStateError && error.code === 'HOST_INSTANCE_SWITCH');
    assert.equal(store.productDisconnected(10).session.client_freshness, 'Reconnecting'); assert.equal(store.productDisconnected(60_010).session.client_freshness, 'Stale');
    assert.equal(store.productEnvelope().snapshot.turn_state, 'Running');
    assert.throws(() => store.persistProduct(envelope({ seq: 5, state: 'Completed' }), { source: 'current' }), (error) => error instanceof AlphaStateError && error.code === 'SEQ_GAP');
  } finally { store.close(); }
});
