import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { chmodSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AlphaStore } from './alpha-store.mjs';
import { createHash, createSecretKey } from 'node:crypto';
import { spawn } from 'node:child_process';
import { canonicalJson, ProductHostClient, readCommandKeyFromFd, transportAuthHeaders } from './product-host-client.mjs';
import { createGateway } from './server.mjs';

const DIGEST = 'sha256:' + 'a'.repeat(64);
const now = new Date();
const HOST_ENVELOPE = {
  schema: 'nomad.product-host.snapshot.v1', host_instance_id: 'host-' + '4'.repeat(32), snapshot_seq: 7, digest: 'sha256:placeholder',
  snapshot: {
    session_alias: 'sess-' + '5'.repeat(32), updated_at: now.toISOString(), turn_state: 'NeedsPermission',
    pending_input_alias: null, pending_permission_alias: 'permission-' + '3'.repeat(32), diff_file_count: 0, writable: false,
    evidence_class: 'official_registry_shape_only_not_provider_lifecycle',
  },
};
HOST_ENVELOPE.digest = 'sha256:' + createHash('sha256').update(canonicalJson({ schema: HOST_ENVELOPE.schema, host_instance_id: HOST_ENVELOPE.host_instance_id, snapshot_seq: HOST_ENVELOPE.snapshot_seq, snapshot: HOST_ENVELOPE.snapshot })).digest('hex');
const CAPABILITY = {
  schema: 'nomad.product-host.command-capability.v1', capability_id: 'capability_00000001', snapshot_seq: 7,
  snapshot_digest: HOST_ENVELOPE.digest, next_command_seq: 2, issued_at: now.toISOString(), expires_at: new Date(now.getTime() + 30_000).toISOString(),
  view: true, reply: {
    turn_alias: 'turn-' + '1'.repeat(32), input_alias: 'input-' + '2'.repeat(32),
    summary: { schema: 'nomad.product-host.pending-question-summary.v1', question_count: 1, answer_mode: 'free_text', response_hint: 'single_short_reply', prompt: 'Provide a short reply for: deployment region.' },
  },
  deny: { permission_alias: 'permission-' + '3'.repeat(32), action_hash: DIGEST, expires_at: new Date(now.getTime() + 20_000).toISOString() },
  stop: { turn_alias: 'turn-' + '1'.repeat(32) }, allow_once: false,
};
function command(content = 'canary reply content') { return {
  schema: 'nomad.gateway.command.v1', capability_id: CAPABILITY.capability_id, request_id: 'request_00000001', nonce: 'nonce_0000000001',
  command_seq: 2, expected_snapshot_seq: 7, expected_snapshot_digest: CAPABILITY.snapshot_digest,
  issued_at: now.toISOString(), expires_at: CAPABILITY.expires_at, action: 'reply',
  turn_alias: CAPABILITY.reply.turn_alias, input_alias: CAPABILITY.reply.input_alias, content,
}; }
function receipt(request) { return { schema: 'nomad.product-host.command-receipt.v1', receipt_id: 'receipt_00000001', request_id: request.request_id, action: request.action, snapshot_seq: request.expected_snapshot_seq, snapshot_digest: request.expected_snapshot_digest, accepted_at: now.toISOString(), status: 'HostAccepted', error_code: 'OK', idempotent_replay: false }; }
function reply(response, status, value) { const body = JSON.stringify(value); response.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }); response.end(body); }

async function udsHost(handler) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'nomad-command-host-'))); chmodSync(directory, 0o700); const socketPath = join(directory, 'product-host.sock');
  const server = createServer(handler).listen(socketPath); await once(server, 'listening'); chmodSync(socketPath, 0o600);
  return { socketPath, async close() { server.close(); await once(server, 'close'); rmSync(directory, { recursive: true }); } };
}
async function freePort() { const server = createServer().listen(0, '127.0.0.1'); await once(server, 'listening'); const port = server.address().port; server.close(); await once(server, 'close'); return port; }
async function gateway(productHostClient, { seed = true } = {}) {
  const port = await freePort(); const store = new AlphaStore(join(mkdtempSync(join(tmpdir(), 'nomad-command-gateway-')), 'state.sqlite3'));
  if (seed) store.persistProduct(HOST_ENVELOPE, { source: 'current' });
  const relay = new Proxy({}, { get() { throw new Error('Relay fallback forbidden'); } });
  const server = createServer(createGateway({ mode: 'official-agent-local', host: '127.0.0.1', port, productHostClient, relayClient: relay, store, distDir: '/missing' })).listen(port, '127.0.0.1'); await once(server, 'listening');
  return { port, base: 'http://127.0.0.1:' + port, store, server, async close() { server.close(); await once(server, 'close'); store.close(); } };
}
function headers(base, csrf) { return { Host: new URL(base).host, Origin: base, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', ...(csrf ? { 'X-Nomad-CSRF': csrf } : {}) }; }
function rawGet(port, headers) { return new Promise((resolve, reject) => { const request = httpRequest({ host: '127.0.0.1', port, path: '/api/commands/capability', method: 'GET', headers }, (response) => { response.resume(); response.on('end', () => resolve(response.statusCode)); }); request.on('error', reject); request.end(); }); }
function rawHttp(port, request) { return new Promise((resolve, reject) => { let response = ''; const socket = createConnection({ host: '127.0.0.1', port }, () => socket.end(request)); socket.setEncoding('utf8'); socket.on('data', (chunk) => { response += chunk; }); socket.on('end', () => resolve(response)); socket.on('error', reject); }); }

test('ProductHostClient uses exact capability GET and forwards exact command POST', async () => {
  const seen = []; const host = await udsHost(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    seen.push({ method: request.method, url: request.url, headers: request.headers, body });
    if (request.method === 'GET') reply(response, 200, CAPABILITY); else reply(response, 200, receipt(JSON.parse(body)));
  });
  try {
    const rawKey = 'K'.repeat(32); let nonce = 7; const client = new ProductHostClient(host.socketPath, { commandKey: createSecretKey(Buffer.from(rawKey)), now: () => 1770000000, randomBytes: () => Buffer.alloc(16, ++nonce) }); assert.deepEqual(await client.getCommandCapability(), CAPABILITY); assert.deepEqual(await client.postCommand(command()), receipt(command()));
    assert.equal(seen[0].method, 'GET'); assert.equal(seen[0].url, '/internal/commands/capability'); assert.equal(seen[1].method, 'POST'); assert.equal(seen[1].url, '/internal/commands');
    assert.deepEqual(JSON.parse(seen[1].body), command()); assert.equal(seen[1].headers.authorization, undefined); assert.equal(seen[1].headers['content-type'], 'application/json');
    assert.equal(seen[0].headers['x-nomad-transport-time'], '1770000000'); assert.equal(seen[0].headers['x-nomad-transport-nonce'], '08'.repeat(16)); assert.match(seen[0].headers['x-nomad-transport-mac'], /^[0-9a-f]{64}$/);
    assert.notEqual(seen[0].headers['x-nomad-transport-nonce'], seen[1].headers['x-nomad-transport-nonce']);
    assert.equal(JSON.stringify(seen).includes(rawKey), false);
  } finally { await host.close(); }
});

test('transport HMAC matches frozen exact vector', () => {
  const key = createSecretKey(Buffer.from(Array.from({ length: 32 }, (_unused, index) => index)));
  assert.deepEqual(transportAuthHeaders(key, 'GET', '/internal/commands/capability', Buffer.alloc(0), 1770000000, Buffer.from('00112233445566778899aabbccddeeff', 'hex')), {
    'X-Nomad-Transport-Time': '1770000000', 'X-Nomad-Transport-Nonce': '00112233445566778899aabbccddeeff', 'X-Nomad-Transport-Mac': '37109e4261445a87b51a8967c30365f10ff7bedb9233db8bb1d2459d527c58ed',
  });
});

test('command key FD requires exactly 32 bytes and EOF and closes descriptor', async () => {
  const moduleUrl = new URL('./product-host-client.mjs', import.meta.url).href;
  for (const [size, expected] of [[31, 'INVALID_COMMAND_KEY'], [32, 'ok'], [33, 'INVALID_COMMAND_KEY']]) {
    const code = 'import { fstatSync } from "node:fs"; import { readCommandKeyFromFd } from ' + JSON.stringify(moduleUrl) + '; let result; try { const key=readCommandKeyFromFd(3); result={code:"ok",length:key.symmetricKeySize}; } catch(error) { result={code:error.code}; } try { fstatSync(3); result.closed=false; } catch { result.closed=true; } process.stdout.write(JSON.stringify(result));';
    const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
    child.stdio[3].end(Buffer.alloc(size, 9)); let stdout = ''; child.stdout.setEncoding('utf8'); child.stdout.on('data', (chunk) => { stdout += chunk; });
    const [exitCode] = await once(child, 'exit'); assert.equal(exitCode, 0); const result = JSON.parse(stdout); assert.equal(result.code, expected); assert.equal(result.closed, true); if (size === 32) assert.equal(result.length, 32);
  }
});

test('official Gateway wraps capability, enforces browser boundary, and changes only receipt schema', async () => {
  const calls = []; const client = { async getCommandCapability() { calls.push('capability'); return CAPABILITY; }, async postCommand(value) { calls.push(value); return receipt(value); } };
  const running = await gateway(client);
  try {
    const capabilityResponse = await fetch(running.base + '/api/commands/capability', { headers: headers(running.base) });
    assert.equal(capabilityResponse.headers.get('access-control-allow-origin'), null); const wrapper = await capabilityResponse.json();
    assert.deepEqual(Object.keys(wrapper).sort(), ['capability', 'csrf_token', 'display_snapshot_digest', 'display_snapshot_seq', 'schema']); assert.deepEqual(wrapper.capability, CAPABILITY);
    assert.equal(wrapper.display_snapshot_seq, running.store.productCurrent().last_applied_seq);
    assert.equal(wrapper.display_snapshot_digest, running.store.productCurrent().digest);
    assert.notEqual(wrapper.display_snapshot_digest, wrapper.capability.snapshot_digest);
    const canary = 'raw-content-canary-never-returned'; const request = command(canary);
    const response = await fetch(running.base + '/api/commands', { method: 'POST', headers: { ...headers(running.base, wrapper.csrf_token), 'Content-Type': 'application/json' }, body: JSON.stringify(request) });
    const body = await response.json(); assert.equal(response.status, 200); assert.deepEqual(body, { ...receipt(request), schema: 'nomad.gateway.command-receipt.v1' });
    assert.equal(JSON.stringify(body).includes(canary), false); assert.deepEqual(calls, ['capability', request]);
    assert.equal(JSON.stringify(request).includes('pending-question-summary'), false);
    assert.equal(JSON.stringify(request).includes('deployment region'), false);
  } finally { await running.close(); }
});

test('capability GET fails closed without current state or when Host capability does not bind to stored Host envelope', async (context) => {
  await context.test('no current state', async () => {
    let calls = 0;
    const running = await gateway({ async getCommandCapability() { calls += 1; return CAPABILITY; } }, { seed: false });
    try {
      const response = await fetch(running.base + '/api/commands/capability', { headers: headers(running.base) });
      assert.equal(response.status, 503);
      assert.equal(calls, 0);
    } finally { await running.close(); }
  });
  for (const [name, capability] of [
    ['sequence mismatch', { ...CAPABILITY, snapshot_seq: CAPABILITY.snapshot_seq + 1 }],
    ['digest mismatch', { ...CAPABILITY, snapshot_digest: DIGEST }],
  ]) await context.test(name, async () => {
    const running = await gateway({ async getCommandCapability() { return capability; } });
    try {
      const response = await fetch(running.base + '/api/commands/capability', { headers: headers(running.base) });
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { error: 'COMMAND_CAPABILITY_UNAVAILABLE' });
    } finally { await running.close(); }
  });
});

test('rejects Origin, Host, fetch metadata and CSRF variants before Host call', async (context) => {
  let calls = 0; const client = { async getCommandCapability() { calls += 1; return CAPABILITY; }, async postCommand() { calls += 1; return {}; } }; const running = await gateway(client);
  try {
    for (const [name, bad] of [
      ['localhost origin', { Origin: 'http://localhost:' + running.port }], ['slash origin', { Origin: running.base + '/' }], ['https origin', { Origin: 'https://127.0.0.1:' + running.port }],
      ['cross site', { 'Sec-Fetch-Site': 'cross-site' }],
    ]) await context.test(name, async () => { const response = await fetch(running.base + '/api/commands/capability', { headers: { ...headers(running.base), ...bad } }); assert.equal(response.status, 403); });
    assert.equal(await rawGet(running.port, { Host: 'localhost:' + running.port, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors' }), 403);
    assert.equal(await rawGet(running.port, { Host: new URL(running.base).host, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate' }), 403);
    assert.equal((await fetch(running.base + '/api/commands/capability', { headers: { Host: new URL(running.base).host, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors' } })).status, 200);
    const wrapper = await (await fetch(running.base + '/api/commands/capability', { headers: headers(running.base) })).json(); assert.equal(calls, 2);
    for (const csrf of [undefined, '', 'wrong-token']) {
      const response = await fetch(running.base + '/api/commands', { method: 'POST', headers: { ...headers(running.base, csrf), 'Content-Type': 'application/json' }, body: JSON.stringify(command()) }); assert.equal(response.status, 403);
    }
    assert.equal(calls, 2);
  } finally { await running.close(); }
});

test('CSRF rotates on Gateway restart and foundation exposes no commands', async () => {
  const client = { async getCommandCapability() { return CAPABILITY; } }; const first = await gateway(client); let firstToken;
  try { firstToken = (await (await fetch(first.base + '/api/commands/capability', { headers: headers(first.base) })).json()).csrf_token; } finally { await first.close(); }
  const second = await gateway(client);
  try { const secondToken = (await (await fetch(second.base + '/api/commands/capability', { headers: headers(second.base) })).json()).csrf_token; assert.notEqual(firstToken, secondToken); } finally { await second.close(); }
  const store = new AlphaStore(join(mkdtempSync(join(tmpdir(), 'nomad-foundation-command-')), 'state.sqlite3')); const relay = { async listFrames() { return []; } }; const port = await freePort(); const server = createServer(createGateway({ mode: 'foundation-readonly', relayClient: relay, store, distDir: '/missing' })).listen(port, '127.0.0.1'); await once(server, 'listening');
  try { assert.equal((await fetch('http://127.0.0.1:' + port + '/api/commands/capability')).status, 404); assert.equal((await fetch('http://127.0.0.1:' + port + '/api/pilot/session')).status, 403); } finally { server.close(); await once(server, 'close'); store.close(); }
});

test('browser command HTTP framing rejects missing or ambiguous length and Transfer-Encoding before Host', async (context) => {
  let posts = 0; const client = { async getCommandCapability() { return CAPABILITY; }, async postCommand() { posts += 1; return {}; } }; const running = await gateway(client); const canary = 'raw-browser-command-canary';
  try {
    const csrf = (await (await fetch(running.base + '/api/commands/capability', { headers: headers(running.base) })).json()).csrf_token;
    const baseHeaders = 'Host: 127.0.0.1:' + running.port + '\r\nOrigin: ' + running.base + '\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nContent-Type: application/json\r\nX-Nomad-CSRF: ' + csrf + '\r\n';
    for (const [name, framing] of [
      ['missing length', ''],
      ['duplicate length', 'Content-Length: 3\r\nContent-Length: 3\r\n'],
      ['transfer encoding', 'Transfer-Encoding: chunked\r\n'],
      ['length mismatch', 'Content-Length: 99\r\n'],
    ]) await context.test(name, async () => {
      const response = await rawHttp(running.port, 'POST /api/commands HTTP/1.1\r\n' + baseHeaders + framing + 'Connection: close\r\n\r\n' + canary);
      assert.match(response, /^HTTP\/1\.1 (?:400|403) /); assert.equal(response.includes(canary), false);
    });
    assert.equal(posts, 0);
  } finally { await running.close(); }
});
