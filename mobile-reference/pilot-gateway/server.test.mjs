import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createGateway, startGateway } from './server.mjs';

const capture = { snapshot: { session_id: 'pilot-session', version: '1.0.0', turn_id: 'turn-1', turn_state: 'NeedsPermission', host_connectivity: 'Online', client_freshness: 'Live', created_at: '2026-08-18T00:00:00Z', last_applied_seq: 7, digest: 'sha256:test', state_summary: { active_permission: 'perm-1', diff_file_count: 1, tool_states: [] } }, events: [], diff: [{ file: 'x', additions: 1, deletions: 0, patch: '+x' }], source: { interface: 'compat' } };

test('same-origin API keeps Relay receipt distinct from Host acceptance', async () => {
  const relay = {
    posted: [],
    async list(_channel, target) { return target === 'mobile' ? [{ message_id: 's1', payload: { type: 'pilot.session', capture, approval: null } }, { message_id: 'r1', payload: { type: 'pilot.command.result', request_id: 'req-1', status: 'HostAccepted', error_code: 'OK' } }] : []; },
    async post(...args) { this.posted.push(args); }, async ack() {},
  };
  const server = createServer(createGateway({ relayClient: relay, channel: 'c', distDir: '/missing' })).listen(0, '127.0.0.1');
  await once(server, 'listening'); const port = server.address().port;
  const session = await fetch(`http://127.0.0.1:${port}/api/pilot/session`).then((r) => r.json());
  assert.equal(session.state.session.turn_state, 'NeedsPermission');
  assert.equal(session.changes.status, 'invalid');
  const sent = await fetch(`http://127.0.0.1:${port}/api/pilot/commands`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ command_type: 'stop', request_id: 'req-1', session_id: 'pilot-session', seq: 7, target_turn_id: 'turn-1' }) }).then((r) => r.json());
  assert.equal(sent.status, 'RelayReceived');
  await fetch(`http://127.0.0.1:${port}/api/pilot/commands`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ command_type: 'stop', request_id: 'req-1', session_id: 'pilot-session', seq: 7, target_turn_id: 'turn-1' }) });
  assert.notEqual(relay.posted[0][2], relay.posted[1][2]);
  assert.equal(relay.posted[0][3].command.request_id, relay.posted[1][3].command.request_id);
  const result = await fetch(`http://127.0.0.1:${port}/api/pilot/commands/req-1`).then((r) => r.json());
  assert.equal(result.status, 'HostAccepted');
  server.close();
});

test('non-loopback bind fails without TLS material', () => {
  assert.throws(() => startGateway({ host: '0.0.0.0', port: 0, relayUrl: 'x', relayToken: 'x', channel: 'x', distDir: '/missing' }), /requires --tls-cert/);
});
