import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AlphaStore } from './alpha-store.mjs';
import { createGateway, parseArgs } from './server.mjs';
import { canonicalJson } from './product-host-client.mjs';

const PUBLIC_ORIGIN = 'https://opaque.pair.nomad.example';
const TRUST = Buffer.alloc(32, 10).toString('base64url');
const CSRF = Buffer.alloc(32, 11).toString('base64url');
const COOKIE = Buffer.alloc(32, 12).toString('base64url');
const JOIN_ID = `join-${'1'.repeat(32)}`;
const CHALLENGE_ID = 'challenge-12345678';
const KEY_A = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString('base64url');
const KEY_B = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 2)]).toString('base64url');

function fakeHost() {
  const envelope = productEnvelope();
  return {
    calls: [],
    failCommandCapability: false,
    async getCurrent() { this.calls.push(['projection-current']); return envelope; },
    async getStream(sequence) { this.calls.push(['projection-stream', sequence]); return null; },
    async getCommandCapability() {
      this.calls.push(['command-capability']);
      if (this.failCommandCapability) throw new Error('COMMAND_CAPABILITY_UNAVAILABLE');
      return { schema: 'nomad.product-host.command-capability.v1', capability_id: 'capability_00000001', snapshot_seq: envelope.snapshot_seq, snapshot_digest: envelope.digest, next_command_seq: 1, issued_at: '2026-08-28T00:00:00Z', expires_at: '2026-08-28T00:00:30Z', view: true, reply: null, deny: null, stop: null, allow_once: false };
    },
    async postCommand(body) { this.calls.push(['command', body]); return { schema: 'nomad.product-host.command-receipt.v1', receipt_id: 'receipt_00000001', request_id: body.request_id, action: body.action, snapshot_seq: body.expected_snapshot_seq, snapshot_digest: body.expected_snapshot_digest, accepted_at: '2026-08-28T00:00:00Z', status: 'HostAccepted', error_code: 'OK', idempotent_replay: false }; },
    async createPairing(body) { this.calls.push(['create', body]); return { schema: 'nomad.m3e.pairing.created.v1', join_id: JOIN_ID, join_secret: Buffer.alloc(32, 4).toString('base64url'), expires_at: '2026-08-28T00:02:00Z' }; },
    async approvePairing(body) { this.calls.push(['approve', body]); },
    async cancelPairing(body) { this.calls.push(['cancel', body]); },
    async getPairingStatus(body) { this.calls.push(['status', body]); return { schema: 'nomad.m3e.pairing.status-response.v1', join_id: JOIN_ID, state: 'started_awaiting_desktop_approval', challenge_id: CHALLENGE_ID, expected_epoch: 1, comparison_code: '042913', expires_at: '2026-08-28T00:02:00Z' }; },
    async getCurrentDevice() { this.calls.push(['current']); return { schema: 'nomad.product-host.device-current.v1', principal_alias: 'principal_00000001', paired: false, device: null }; },
    async revokeDevice(body) { this.calls.push(['revoke', body]); return { schema: 'nomad.product-host.device-revoke.v1', principal_alias: 'principal_00000001', device_alias: body.device_alias, status: 'revoked', prior_epoch: body.expected_epoch, revoked_epoch: body.expected_epoch + 1 }; },
    async startPairing(body) { this.calls.push(['start', body]); return { schema: 'nomad.m3e.pairing.host-start.v1', join_cookie_capability: COOKIE, join_cookie_max_age_seconds: 87, browser_start: { schema: 'nomad.m3e.pairing.start-response.v1', challenge_id: CHALLENGE_ID, challenge_bytes_b64: Buffer.alloc(32, 5).toString('base64url'), prospective_epoch: 1, host_signing_public_key_sec1: KEY_A, host_agreement_public_key_sec1: KEY_B, issued_at: '2026-08-28T00:00:00Z', expires_at: '2026-08-28T00:01:27Z' } }; },
    async confirmPairing(capability, body) { this.calls.push(['confirm', capability, body]); return { schema: 'nomad.m3e.pairing.confirm-response.v1', signed_provisioning_bundle: { safe: true } }; },
    async completePairing(capability, body) { this.calls.push(['complete', capability, body]); return { schema: 'nomad.m3e.pairing.complete-response.v1', device_alias: 'device-12345678', pairing_epoch: 1 }; },
    async abortPairing(capability, body) { this.calls.push(['abort', capability, body]); },
  };
}

async function freePort() {
  const server = createServer().listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; server.close(); await once(server, 'close'); return port;
}

async function gateway(routeTable, host, distDir) {
  const port = await freePort();
  let store = null;
  if (routeTable === 'desktop') {
    const path = join(mkdtempSync(join(tmpdir(), 'nomad-desktop-combined-')), 'state.sqlite3');
    store = new AlphaStore(path);
    store.persistProduct(productEnvelope(), { source: 'current' });
  }
  const server = createServer(createGateway({ mode: 'official-agent-local', routeTable, host: '127.0.0.1', port, productHostClient: host, store, desktopCsrfToken: CSRF, publicOrigin: PUBLIC_ORIGIN, trustedIngressToken: TRUST, distDir })).listen(port, '127.0.0.1');
  await once(server, 'listening');
  return { port, origin: `http://127.0.0.1:${port}`, async close() { server.close(); await once(server, 'close'); store?.close(); } };
}

function productEnvelope() {
  const value = { schema: 'nomad.product-host.snapshot.v1', host_instance_id: `host-${'2'.repeat(32)}`, snapshot_seq: 1, digest: 'sha256:placeholder', snapshot: { session_alias: `sess-${'3'.repeat(32)}`, updated_at: '2026-08-28T00:00:00.000Z', turn_state: 'Running', pending_input_alias: null, pending_permission_alias: null, diff_file_count: 0, writable: false, evidence_class: 'official_registry_shape_only_not_provider_lifecycle' } };
  const canonical = { schema: value.schema, host_instance_id: value.host_instance_id, snapshot_seq: value.snapshot_seq, snapshot: value.snapshot };
  value.digest = 'sha256:' + createHash('sha256').update(canonicalJson(canonical)).digest('hex');
  return value;
}

function desktopHeaders(origin) {
  return { Host: new URL(origin).host, Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'X-Nomad-CSRF': CSRF, 'Content-Type': 'application/json' };
}

function joinHeaders(extra = {}) {
  return { Host: new URL(PUBLIC_ORIGIN).host, Origin: PUBLIC_ORIGIN, 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': new URL(PUBLIC_ORIGIN).host, 'X-Nomad-Trusted-Ingress': TRUST, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty', 'Content-Type': 'application/json', ...extra };
}

async function raw(port, path, { method = 'GET', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const cleanHeaders = Object.fromEntries(Object.entries(headers).filter(([, value]) => value !== undefined));
    const request = httpRequest({ host: '127.0.0.1', port, path, method, headers: { ...cleanHeaders, ...(body ? { 'Content-Length': String(Buffer.byteLength(body)) } : {}) } }, (response) => {
      const chunks = []; response.on('data', (chunk) => chunks.push(chunk)); response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    request.on('error', reject); request.end(body);
  });
}

test('desktop route table composes official projection, commands, static and pairing admin while hiding the standalone join secret', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'nomad-desktop-shell-'));
  writeFileSync(join(directory, 'index.html'), '<!doctype html><title>Nomad desktop</title>');
  const host = fakeHost(); const running = await gateway('desktop', host, directory);
  try {
    const bootstrap = await raw(running.port, '/api/desktop/security', {
      headers: {
        Host: new URL(running.origin).host,
        Origin: running.origin,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
      },
    });
    assert.equal(bootstrap.status, 200);
    assert.equal(bootstrap.headers['cache-control'], 'no-store');
    assert.deepEqual(JSON.parse(bootstrap.text), {
      schema: 'nomad.gateway.desktop-security.v1',
      csrf_token: CSRF,
    });

    const createRequest = { schema: 'nomad.m3e.pairing.create.v1' };
    const created = await raw(running.port, '/api/desktop/pairing/create', { method: 'POST', headers: desktopHeaders(running.origin), body: JSON.stringify(createRequest) });
    assert.equal(created.status, 200);
    const createdBody = JSON.parse(created.text);
    assert.deepEqual(createdBody, { schema: 'nomad.m3e.pairing.desktop-created.v1', join_id: JOIN_ID, join_url: `${PUBLIC_ORIGIN}/j/${JOIN_ID}#${Buffer.alloc(32, 4).toString('base64url')}`, expires_at: '2026-08-28T00:02:00Z' });
    assert.equal(Object.hasOwn(createdBody, 'join_secret'), false);
    assert.equal(Object.keys(createdBody).sort().join(','), 'expires_at,join_id,join_url,schema');
    const approveRequest = { schema: 'nomad.m3e.pairing.desktop-approve.v1', join_id: JOIN_ID, challenge_id: CHALLENGE_ID, expected_epoch: 1, comparison_code: '042913' };
    assert.equal((await raw(running.port, '/api/desktop/pairing/approve', { method: 'POST', headers: desktopHeaders(running.origin), body: JSON.stringify(approveRequest) })).status, 204);
    const cancelRequest = { schema: 'nomad.m3e.pairing.cancel.v1', join_id: JOIN_ID };
    assert.equal((await raw(running.port, '/api/desktop/pairing/cancel', { method: 'POST', headers: desktopHeaders(running.origin), body: JSON.stringify(cancelRequest) })).status, 204);
    const statusRequest = { schema: 'nomad.m3e.pairing.status.v1', join_id: JOIN_ID };
    const status = await raw(running.port, '/api/desktop/pairing/status', { method: 'POST', headers: desktopHeaders(running.origin), body: JSON.stringify(statusRequest) });
    assert.equal(status.status, 200);
    const response = JSON.parse(status.text);
    assert.deepEqual(Object.keys(response).sort(), ['challenge_id', 'comparison_code', 'expected_epoch', 'expires_at', 'join_id', 'schema', 'state']);
    assert.equal(JSON.stringify(response).includes('secret'), false); assert.equal(JSON.stringify(response).includes('bearer'), false);
    const current = await raw(running.port, '/api/desktop/devices/current', { method: 'POST', headers: desktopHeaders(running.origin), body: '{}' });
    assert.equal(current.status, 200); assert.equal(JSON.parse(current.text).schema, 'nomad.product-host.device-current.v1');
    const revokeRequest = { device_alias: 'device-12345678', expected_epoch: 1 };
    const revoke = await raw(running.port, '/api/desktop/devices/revoke', { method: 'POST', headers: desktopHeaders(running.origin), body: JSON.stringify(revokeRequest) });
    assert.equal(revoke.status, 200); assert.equal(JSON.parse(revoke.text).schema, 'nomad.product-host.device-revoke.v1');
    assert.deepEqual(host.calls, [['create', createRequest], ['approve', approveRequest], ['cancel', cancelRequest], ['status', statusRequest], ['current'], ['revoke', revokeRequest]]);

    const staticShell = await raw(running.port, '/');
    assert.equal(staticShell.status, 200); assert.match(staticShell.text, /Nomad desktop/);
    const projection = await raw(running.port, '/api/alpha/session');
    assert.equal(projection.status, 200); assert.equal(JSON.parse(projection.text).schema, 'nomad.alpha.readonly.v1');
    const capability = await raw(running.port, '/api/commands/capability', { headers: { Host: new URL(running.origin).host, Origin: running.origin, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors' } });
    assert.equal(capability.status, 200); assert.equal(JSON.parse(capability.text).schema, 'nomad.gateway.command-capability.v1');
    const capabilityBody = JSON.parse(capability.text);
    const commandBody = { schema: 'nomad.gateway.command.v1', capability_id: capabilityBody.capability.capability_id, request_id: 'request_00000001', nonce: 'nonce_0000000001', command_seq: 1, expected_snapshot_seq: 1, expected_snapshot_digest: productEnvelope().digest, issued_at: '2026-08-28T00:00:00Z', expires_at: '2026-08-28T00:00:30Z', action: 'stop', turn_alias: `turn-${'4'.repeat(32)}` };
    const command = await raw(running.port, '/api/commands', { method: 'POST', headers: { Host: new URL(running.origin).host, Origin: running.origin, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'X-Nomad-CSRF': capabilityBody.csrf_token, 'Content-Type': 'application/json' }, body: JSON.stringify(commandBody) });
    assert.equal(command.status, 200); assert.equal(JSON.parse(command.text).schema, 'nomad.gateway.command-receipt.v1');

    for (const path of [`/j/${JOIN_ID}`, '/api/pairing/join/start', '/api/pairing/join/confirm', '/api/pairing/join/complete', '/api/pairing/join/abort']) {
      const result = await raw(running.port, path, { method: path.startsWith('/j/') ? 'GET' : 'POST', headers: desktopHeaders(running.origin), body: path.startsWith('/j/') ? '' : '{}' });
      assert.equal(result.status, 404);
    }
    assert.deepEqual(host.calls.slice(6), [['projection-stream', 1], ['projection-current'], ['command-capability'], ['command', commandBody]]);
  } finally { await running.close(); rmSync(directory, { recursive: true }); }
});

test('desktop bootstrap rejects wrong origin and join route table does not expose it', async () => {
  const host = fakeHost();
  const desktopRunning = await gateway('desktop', host, '/missing');
  const joinRunning = await gateway('join', fakeHost(), '/missing');
  try {
    const wrongOrigin = await raw(desktopRunning.port, '/api/desktop/security', {
      headers: {
        Host: new URL(desktopRunning.origin).host,
        Origin: 'http://127.0.0.1:65535',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
      },
    });
    assert.equal(wrongOrigin.status, 403);
    assert.deepEqual(JSON.parse(wrongOrigin.text), { error: 'ORIGIN_REJECTED' });

    const joinHidden = await raw(joinRunning.port, '/api/desktop/security', {
      headers: joinHeaders(),
    });
    assert.equal(joinHidden.status, 404);
  } finally {
    await desktopRunning.close();
    await joinRunning.close();
  }
});

test('desktop pairing bootstrap is independent from command capability availability', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'nomad-desktop-capability-decouple-'));
  writeFileSync(join(directory, 'index.html'), '<!doctype html><title>Nomad desktop</title>');
  const host = fakeHost();
  host.failCommandCapability = true;
  const running = await gateway('desktop', host, directory);
  try {
    const capability = await raw(running.port, '/api/commands/capability', {
      headers: {
        Host: new URL(running.origin).host,
        Origin: running.origin,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
      },
    });
    assert.equal(capability.status, 503);
    assert.deepEqual(JSON.parse(capability.text), { error: 'COMMAND_CAPABILITY_UNAVAILABLE' });

    const bootstrap = await raw(running.port, '/api/desktop/security', {
      headers: {
        Host: new URL(running.origin).host,
        Origin: running.origin,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
      },
    });
    assert.equal(bootstrap.status, 200);
    assert.equal(JSON.parse(bootstrap.text).csrf_token, CSRF);

    const createRequest = { schema: 'nomad.m3e.pairing.create.v1' };
    const created = await raw(running.port, '/api/desktop/pairing/create', {
      method: 'POST',
      headers: desktopHeaders(running.origin),
      body: JSON.stringify(createRequest),
    });
    assert.equal(created.status, 200);
    assert.deepEqual(host.calls.filter((entry) => entry[0] === 'create'), [['create', createRequest]]);
  } finally {
    await running.close();
    rmSync(directory, { recursive: true });
  }
});

test('join route table strips Host cookie capability, emits exact cookie, and has no desktop admin routes', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'nomad-join-shell-'));
  writeFileSync(join(directory, 'index.html'), '<!doctype html><title>Nomad pair</title><script src="/assets/pair.js"></script>');
  const host = fakeHost(); const running = await gateway('join', host, directory);
  try {
    const shell = await raw(running.port, `/j/${JOIN_ID}`, { headers: { ...joinHeaders(), Origin: undefined, 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document', 'Content-Type': undefined } });
    assert.equal(shell.status, 200); assert.equal(shell.headers['cache-control'], 'no-store'); assert.equal(shell.headers['referrer-policy'], 'no-referrer'); assert.match(shell.headers['content-security-policy'], /frame-ancestors 'none'/); assert.equal(shell.text.includes(COOKIE), false);

    const startBody = { join_id: JOIN_ID, join_secret: Buffer.alloc(32, 7).toString('base64url'), device_signing_public_key_sec1: KEY_A, device_agreement_public_key_sec1: KEY_B };
    const start = await raw(running.port, '/api/pairing/join/start', { method: 'POST', headers: joinHeaders(), body: JSON.stringify(startBody) });
    assert.equal(start.status, 200); assert.equal(start.headers['set-cookie'][0], `__Host-nomad-join=${COOKIE}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=87`);
    assert.equal(start.text.includes(COOKIE), false); assert.deepEqual(JSON.parse(start.text), { schema: 'nomad.m3e.pairing.start-response.v1', challenge_id: CHALLENGE_ID, challenge_bytes_b64: Buffer.alloc(32, 5).toString('base64url'), prospective_epoch: 1, host_signing_public_key_sec1: KEY_A, host_agreement_public_key_sec1: KEY_B, issued_at: '2026-08-28T00:00:00Z', expires_at: '2026-08-28T00:01:27Z' });
    const confirmBody = { challenge_id: CHALLENGE_ID, expected_epoch: 1, device_signing_signature_p1363: Buffer.alloc(64, 6).toString('base64url'), device_agreement_mac: Buffer.alloc(32, 7).toString('base64url') };
    const confirm = await raw(running.port, '/api/pairing/join/confirm', { method: 'POST', headers: joinHeaders({ Cookie: `__Host-nomad-join=${COOKIE}` }), body: JSON.stringify(confirmBody) });
    assert.equal(confirm.status, 200); assert.equal(confirm.headers['set-cookie'], undefined); assert.equal(confirm.text.includes(COOKIE), false);

    const completeBody = { schema: 'nomad.m3e.pairing.vault-commit.v1', challenge_id: CHALLENGE_ID, expected_epoch: 1, device_vault_signature_p1363: Buffer.alloc(64, 8).toString('base64url') };
    const complete = await raw(running.port, '/api/pairing/join/complete', { method: 'POST', headers: joinHeaders({ Cookie: `__Host-nomad-join=${COOKIE}` }), body: JSON.stringify(completeBody) });
    assert.equal(complete.status, 200); assert.equal(complete.headers['set-cookie'][0], '__Host-nomad-join=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    assert.deepEqual(host.calls, [['start', startBody], ['confirm', COOKIE, confirmBody], ['complete', COOKIE, completeBody]]);

    for (const path of ['/api/desktop/pairing/create', '/api/desktop/pairing/approve', '/api/desktop/pairing/cancel', '/api/desktop/pairing/status', '/api/desktop/devices/current', '/api/desktop/devices/revoke']) {
      const result = await raw(running.port, path, { method: 'POST', headers: joinHeaders(), body: '{}' });
      assert.equal(result.status, 404);
    }
    assert.equal(host.calls.length, 3);
  } finally { await running.close(); rmSync(directory, { recursive: true }); }
});

test('join listener rejects ordinary HTTP before Host and abort clears cookie only after Host success', async () => {
  const host = fakeHost(); const running = await gateway('join', host, '/missing');
  try {
    const body = JSON.stringify({ join_id: JOIN_ID, join_secret: Buffer.alloc(32, 7).toString('base64url'), device_signing_public_key_sec1: KEY_A, device_agreement_public_key_sec1: KEY_B });
    const untrusted = await raw(running.port, '/api/pairing/join/start', { method: 'POST', headers: { ...joinHeaders(), 'X-Nomad-Trusted-Ingress': undefined }, body });
    assert.equal(untrusted.status, 403); assert.equal(host.calls.length, 0);
    const abortBody = { schema: 'nomad.m3e.pairing.abort.v1', challenge_id: CHALLENGE_ID, expected_epoch: 1 };
    const abort = await raw(running.port, '/api/pairing/join/abort', { method: 'POST', headers: joinHeaders({ Cookie: `__Host-nomad-join=${COOKIE}` }), body: JSON.stringify(abortBody) });
    assert.equal(abort.status, 204); assert.equal(abort.headers['set-cookie'][0], '__Host-nomad-join=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    assert.deepEqual(host.calls, [['abort', COOKIE, abortBody]]);
  } finally { await running.close(); }
});

test('CLI route-table contract requires explicit HTTPS public origin for desktop and join, while only join needs the private ingress FD', () => {
  const identity = ['--product-host-socket-parent-dev', '1', '--product-host-socket-parent-ino', '2', '--product-host-socket-dev', '3', '--product-host-socket-ino', '4'];
  const base = ['--mode', 'official-agent-local', '--route-table', 'join', '--product-host-socket', '/private/tmp/product-host.sock', ...identity, '--command-key-fd', '11', '--public-origin', PUBLIC_ORIGIN, '--trusted-ingress-fd', '12'];
  assert.equal(parseArgs(base, {}).routeTable, 'join');
  assert.throws(() => parseArgs(base.filter((value, index) => !(value === '--trusted-ingress-fd' || base[index - 1] === '--trusted-ingress-fd')), {}), /trusted-ingress-fd/);
  assert.throws(() => parseArgs([...base, '--state-db', '/tmp/forbidden.db'], {}), /must not use/);
  const desktop = ['--mode', 'official-agent-local', '--route-table', 'desktop', '--product-host-socket', '/private/tmp/product-host.sock', ...identity, '--command-key-fd', '11', '--public-origin', PUBLIC_ORIGIN, '--state-db', '/tmp/desktop.db'];
  assert.equal(parseArgs(desktop, {}).publicOrigin, PUBLIC_ORIGIN);
  assert.throws(() => parseArgs(desktop.filter((value, index) => !(value === '--public-origin' || desktop[index - 1] === '--public-origin')), {}), /public-origin/);
});

test('desktop create fails closed without configured public origin before calling Host', async () => {
  const host = fakeHost(); const port = await freePort();
  const store = new AlphaStore(join(mkdtempSync(join(tmpdir(), 'nomad-desktop-no-origin-')), 'state.sqlite3'));
  const server = createServer(createGateway({ mode: 'official-agent-local', routeTable: 'desktop', host: '127.0.0.1', port, productHostClient: host, store, desktopCsrfToken: CSRF, distDir: '/missing' })).listen(port, '127.0.0.1');
  await once(server, 'listening'); const origin = `http://127.0.0.1:${port}`;
  try {
    const result = await raw(port, '/api/desktop/pairing/create', { method: 'POST', headers: desktopHeaders(origin), body: JSON.stringify({ schema: 'nomad.m3e.pairing.create.v1' }) });
    assert.equal(result.status, 503); assert.deepEqual(JSON.parse(result.text), { error: 'PAIRING_PUBLIC_ORIGIN_REQUIRED' }); assert.deepEqual(host.calls, []);
  } finally { server.close(); await once(server, 'close'); store.close(); }
});
