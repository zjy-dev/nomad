import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, createSecretKey } from 'node:crypto';
import { once } from 'node:events';
import { EventEmitter } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProductHostClient, browserProjectionFromProductHost, canonicalJson, validateCommandCapability, validatePairingStatus, validateProductHostSnapshot } from './product-host-client.mjs';

function envelope({ instance = 'host-' + 'a'.repeat(32), seq = 1, state = 'Running' } = {}) {
  const snapshot = {
    session_alias: 'sess-' + 'b'.repeat(32), updated_at: '2026-08-25T12:00:00.000Z', turn_state: state,
    pending_input_alias: null, pending_permission_alias: null, diff_file_count: 2, writable: false,
    evidence_class: 'official_registry_shape_only_not_provider_lifecycle',
  };
  const value = { schema: 'nomad.product-host.snapshot.v1', host_instance_id: instance, snapshot_seq: seq, digest: 'sha256:placeholder', snapshot };
  const canonical = { schema: value.schema, host_instance_id: value.host_instance_id, snapshot_seq: value.snapshot_seq, snapshot: value.snapshot };
  value.digest = 'sha256:' + createHash('sha256').update(canonicalJson(canonical)).digest('hex');
  return value;
}

async function fixture(handler) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'nomad-product-host-'))); chmodSync(directory, 0o700);
  const socketPath = join(directory, 'product-host.sock'); const server = createServer(handler).listen(socketPath); await once(server, 'listening'); chmodSync(socketPath, 0o600);
  return { socketPath, async close() { server.close(); await once(server, 'close'); rmSync(directory, { recursive: true }); } };
}

function reply(response, status, body = '', type = 'application/json') {
  response.writeHead(status, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) }); response.end(body);
}

async function rawFixture(rawResponse) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'nomad-product-host-'))); chmodSync(directory, 0o700);
  const socketPath = join(directory, 'product-host.sock');
  const server = createNetServer((socket) => socket.once('data', () => socket.end(rawResponse))).listen(socketPath);
  await once(server, 'listening'); chmodSync(socketPath, 0o600);
  return { socketPath, async close() { server.close(); await once(server, 'close'); rmSync(directory, { recursive: true }); } };
}

test('strictly GETs current and long-poll stream over private UDS without credentials', async () => {
  const calls = []; const current = envelope(); const next = envelope({ seq: 2 });
  const host = await fixture((request, response) => {
    calls.push({ method: request.method, url: request.url, authorization: request.headers.authorization, host: request.headers.host, transportTime: request.headers['x-nomad-transport-time'], transportNonce: request.headers['x-nomad-transport-nonce'], transportMac: request.headers['x-nomad-transport-mac'] });
    if (request.url.includes('/stream')) reply(response, 200, JSON.stringify(next));
    else reply(response, 200, JSON.stringify(current));
  });
  try {
    const client = new ProductHostClient(host.socketPath); assert.equal((await client.getCurrent()).snapshot_seq, 1); assert.equal((await client.getStream(1)).snapshot_seq, 2);
    assert.deepEqual(calls, [
      { method: 'GET', url: '/internal/session/current', authorization: undefined, host: 'localhost', transportTime: undefined, transportNonce: undefined, transportMac: undefined },
      { method: 'GET', url: '/internal/session/stream?after_snapshot_seq=1', authorization: undefined, host: 'localhost', transportTime: undefined, transportNonce: undefined, transportMac: undefined },
    ]);
    for (const call of calls) {
      assert.equal(call.transportTime, undefined); assert.equal(call.transportNonce, undefined); assert.equal(call.transportMac, undefined);
    }
  } finally { await host.close(); }
});

test('accepts stream 204 and rejects non-advancing or conflict responses', async (context) => {
  await context.test('204', async () => { const host = await fixture((_request, response) => reply(response, 204)); try { assert.equal(await new ProductHostClient(host.socketPath).getStream(1), null); } finally { await host.close(); } });
  await context.test('non-advancing', async () => { const host = await fixture((_request, response) => reply(response, 200, JSON.stringify(envelope({ seq: 1 })))); try { await assert.rejects(new ProductHostClient(host.socketPath).getStream(1), { code: 'PRODUCT_HOST_STREAM_INVALID' }); } finally { await host.close(); } });
  await context.test('409', async () => { const host = await fixture((_request, response) => reply(response, 409, '{"schema":"nomad.product-host.error.v1","code":"SNAPSHOT_SEQUENCE_CONFLICT"}')); try { await assert.rejects(new ProductHostClient(host.socketPath).getStream(1), { code: 'PRODUCT_HOST_RESTARTED' }); } finally { await host.close(); } });
});

test('validates exact schema, aliases, digest and content-free browser wrapper', () => {
  const value = envelope(); assert.equal(validateProductHostSnapshot(value), value);
  const browser = browserProjectionFromProductHost(value, { hostConnectivity: 'Offline', clientFreshness: 'Reconnecting' });
  assert.equal(browser.schema, 'nomad.alpha.readonly.v1'); assert.equal(browser.provenance.source, 'local-host-direct'); assert.equal(browser.provenance.relay_ingress_verified, false); assert.equal(browser.session.host_connectivity, 'Offline');
  assert.equal(JSON.stringify(browser).includes('run_id'), false); assert.equal(JSON.stringify(browser).includes('workspace'), false);
  for (const mutate of [
    (copy) => { copy.raw_session_id = 'ses_secret'; },
    (copy) => { copy.snapshot.writable = true; },
    (copy) => { copy.snapshot.session_alias = 'ses_raw'; },
    (copy) => { copy.snapshot.turn_state = 'Failed'; },
    (copy) => { copy.snapshot.diff_file_count = 257; },
    (copy) => { copy.snapshot.evidence_class = 'other'; },
    (copy) => { copy.snapshot.updated_at = '2026-08-25T12:00:00Z'; },
    (copy) => { copy.digest = 'sha256:' + '0'.repeat(64); },
  ]) { const copy = structuredClone(value); mutate(copy); assert.throws(() => validateProductHostSnapshot(copy)); }
});

test('matches the Rust canonical-envelope digest golden', () => {
  const value = {
    schema: 'nomad.product-host.snapshot.v1', host_instance_id: 'host-0123456789abcdef0123456789abcdef', snapshot_seq: 7,
    digest: 'sha256:a4f694418d92fe0a34166e2bf633339d9add5adefcd18b645dffe38b4516e0ff',
    snapshot: {
      session_alias: 'sess-0123456789abcdef0123456789abcdef', updated_at: '2026-08-25T00:00:00.000Z', turn_state: 'Running',
      pending_input_alias: null, pending_permission_alias: null, diff_file_count: 0, writable: false,
      evidence_class: 'official_registry_shape_only_not_provider_lifecycle',
    },
  };
  const expectedCanonical = '{"host_instance_id":"host-0123456789abcdef0123456789abcdef","schema":"nomad.product-host.snapshot.v1","snapshot":{"diff_file_count":0,"evidence_class":"official_registry_shape_only_not_provider_lifecycle","pending_input_alias":null,"pending_permission_alias":null,"session_alias":"sess-0123456789abcdef0123456789abcdef","turn_state":"Running","updated_at":"2026-08-25T00:00:00.000Z","writable":false},"snapshot_seq":7}';
  assert.equal(canonicalJson({ schema: value.schema, host_instance_id: value.host_instance_id, snapshot_seq: value.snapshot_seq, snapshot: value.snapshot }), expectedCanonical);
  assert.equal(validateProductHostSnapshot(value), value);
});

test('rejects duplicate JSON, anonymous errors, oversized response and unsafe directory', async (context) => {
  await context.test('duplicate', async () => { const host = await fixture((_request, response) => reply(response, 200, '{"schema":"x","schema":"y"}')); try { await assert.rejects(new ProductHostClient(host.socketPath).getCurrent(), { code: 'PRODUCT_HOST_RESPONSE_INVALID' }); } finally { await host.close(); } });
  await context.test('503', async () => { const host = await fixture((_request, response) => reply(response, 503, '{"schema":"nomad.product-host.error.v1","code":"SNAPSHOT_UNAVAILABLE"}')); try { await assert.rejects(new ProductHostClient(host.socketPath).getCurrent(), { code: 'PRODUCT_HOST_NOT_READY', message: 'PRODUCT_HOST_NOT_READY' }); } finally { await host.close(); } });
  await context.test('oversize', async () => { const host = await fixture((_request, response) => reply(response, 200, JSON.stringify({ data: 'x'.repeat(70_000) }))); try { await assert.rejects(new ProductHostClient(host.socketPath).getCurrent(), { code: 'PRODUCT_HOST_FRAMING_INVALID' }); } finally { await host.close(); } });
  await context.test('directory', async () => { const host = await fixture((_request, response) => reply(response, 200, JSON.stringify(envelope()))); try { chmodSync(join(host.socketPath, '..'), 0o755); await assert.rejects(new ProductHostClient(host.socketPath).getCurrent(), { code: 'UNSAFE_PRODUCT_HOST_DIRECTORY' }); } finally { await host.close(); } });
});

test('post-request identity check overrides error and timeout after replacement', async (context) => {
  for (const kind of ['error', 'timeout']) await context.test(kind, async () => {
    const host = await fixture(() => {});
    const fakeRequest = (_options, callback) => {
      const outgoing = new EventEmitter(); let timeout;
      outgoing.setTimeout = (_milliseconds, handler) => { timeout = handler; };
      outgoing.destroy = (error) => outgoing.emit('error', error);
      outgoing.end = () => {
        unlinkSync(host.socketPath); writeFileSync(host.socketPath, 'replacement', { mode: 0o600 });
        if (kind === 'timeout') timeout();
        else {
          const response = new EventEmitter(); response.statusCode = 503; response.headers = {}; response.rawHeaders = [];
          response.destroy = () => {}; response.resume = () => {}; callback(response);
        }
      };
      return outgoing;
    };
    try { await assert.rejects(new ProductHostClient(host.socketPath, { request: fakeRequest }).getCurrent(), { code: 'PRODUCT_HOST_SOCKET_CHANGED' }); }
    finally { await host.close(); }
  });
});

test('post-request identity detects parent directory swap', async () => {
  const host = await fixture(() => {}); const parent = join(host.socketPath, '..'); const moved = parent + '-moved';
  const fakeRequest = () => {
    const outgoing = new EventEmitter(); outgoing.setTimeout = () => {}; outgoing.on('error', () => {});
    outgoing.end = () => { renameSync(parent, moved); mkdirSync(parent, 0o700); outgoing.emit('error', new Error('reset')); };
    return outgoing;
  };
  try { await assert.rejects(new ProductHostClient(host.socketPath, { request: fakeRequest }).getCurrent(), { code: 'PRODUCT_HOST_SOCKET_CHANGED' }); }
  finally {
    host.socketPath = join(moved, 'product-host.sock'); await host.close(); rmSync(parent, { recursive: true, force: true });
  }
});

test('rejects ambiguous and inconsistent HTTP framing', async (context) => {
  for (const [name, raw] of [
    ['chunked', 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'],
    ['duplicate length', 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}'],
    ['length mismatch', 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}'],
    ['204 body', 'HTTP/1.1 204 No Content\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\nx'],
  ]) await context.test(name, async () => {
    const host = await rawFixture(raw); try { await assert.rejects(new ProductHostClient(host.socketPath).getStream(1)); } finally { await host.close(); }
  });
});

test('fails closed before connect for invalid socket capability and cursor', async () => {
  assert.throws(() => new ProductHostClient('/tmp/other.sock'), { code: 'INVALID_PRODUCT_HOST_SOCKET' });
  const client = new ProductHostClient('/private/tmp/product-host.sock'); await assert.rejects(client.getStream(-1), { code: 'INVALID_AFTER_SEQ' });
});

test('strictly validates optional pending-question summary while preserving summary-less and null-summary capabilities', () => {
  const base = {
    schema: 'nomad.product-host.command-capability.v1', capability_id: 'capability_00000001', snapshot_seq: 7,
    snapshot_digest: 'sha256:' + 'a'.repeat(64), next_command_seq: 8, issued_at: '2026-08-26T05:00:00.000Z', expires_at: '2026-08-26T05:00:30.000Z',
    view: true, reply: { turn_alias: 'turn-' + '1'.repeat(32), input_alias: 'input-' + '2'.repeat(32) }, deny: null, stop: null, allow_once: false,
  };
  assert.doesNotThrow(() => validateCommandCapability(structuredClone(base)));
  assert.doesNotThrow(() => validateCommandCapability({ ...structuredClone(base), reply: { ...base.reply, summary: null } }));
  const valid = { ...structuredClone(base), reply: { ...base.reply, summary: { schema: 'nomad.product-host.pending-question-summary.v1', question_count: 1, answer_mode: 'free_text', response_hint: 'single_short_reply', prompt: 'Provide a short reply for: deployment region.' } } };
  assert.doesNotThrow(() => validateCommandCapability(valid));
  for (const mutate of [
    (summary) => { summary.schema = 'wrong'; },
    (summary) => { summary.question_count = 2; },
    (summary) => { summary.answer_mode = 'choices'; },
    (summary) => { summary.response_hint = 'long'; },
    (summary) => { summary.prompt = 'x'.repeat(161); },
    (summary) => { summary.prompt = 'unsafe\ntext'; },
    (summary) => { summary.unknown = true; },
  ]) {
    const malformed = structuredClone(valid); mutate(malformed.reply.summary);
    assert.throws(() => validateCommandCapability(malformed));
  }
});

test('M3-E join calls use exact internal canonical bodies and transport HMAC binds the raw Host cookie capability', async () => {
  const key = createSecretKey(Buffer.alloc(32, 11));
  const capability = Buffer.alloc(32, 12).toString('base64url');
  const challengeId = 'challenge-12345678';
  const seen = [];
  const host = await fixture((request, response) => {
    const chunks = []; request.on('data', (chunk) => chunks.push(chunk)); request.on('end', () => {
      const body = Buffer.concat(chunks); seen.push({ url: request.url, body: body.toString('utf8'), headers: request.headers });
      if (request.url.endsWith('/start')) {
        const publicA = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString('base64url');
        const publicB = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 2)]).toString('base64url');
        reply(response, 200, JSON.stringify({ schema: 'nomad.m3e.pairing.host-start.v1', join_cookie_capability: capability, join_cookie_max_age_seconds: 120, browser_start: { schema: 'nomad.m3e.pairing.start-response.v1', challenge_id: challengeId, challenge_bytes_b64: Buffer.alloc(32, 10).toString('base64url'), prospective_epoch: 1, host_signing_public_key_sec1: publicA, host_agreement_public_key_sec1: publicB, issued_at: '2026-08-28T00:00:00Z', expires_at: '2026-08-28T00:02:00Z' } }));
      } else if (request.url.endsWith('/confirm')) {
        const publicA = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]).toString('base64url');
        const publicB = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 2)]).toString('base64url');
        reply(response, 200, JSON.stringify({ schema: 'nomad.m3e.pairing.confirm-response.v1', signed_provisioning_bundle: { schema: 'nomad.m3e.signed-provisioning-bundle.v1', bundle: { schema: 'nomad.m3e.provisioning-bundle.v1', device_alias: 'device-12345678', pairing_epoch: 1, mailbox_id: `mbx-${'1'.repeat(64)}`, relay_base_url: 'https://relay.example/v2', host_signing_public_key_sec1: publicA, host_agreement_public_key_sec1: publicB, wrapped_device_bearer: Buffer.alloc(32, 3).toString('base64url'), wrap_nonce: Buffer.alloc(12, 4).toString('base64url'), issued_at: '2026-08-28T00:00:00Z' }, provisioning_signature_p1363: Buffer.alloc(64, 5).toString('base64url') } }));
      } else if (request.url.endsWith('/complete')) reply(response, 200, JSON.stringify({ schema: 'nomad.m3e.pairing.complete-response.v1', device_alias: 'device-12345678', pairing_epoch: 1 }));
      else reply(response, 204);
    });
  });
  try {
    const client = new ProductHostClient(host.socketPath, { commandKey: key, now: () => 1770000000, randomBytes: () => Buffer.alloc(16, 6) });
    const start = { join_id: `join-${'1'.repeat(32)}`, join_secret: Buffer.alloc(32, 13).toString('base64url'), device_signing_public_key_sec1: Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 14)]).toString('base64url'), device_agreement_public_key_sec1: Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 15)]).toString('base64url') };
    const confirm = { challenge_id: challengeId, expected_epoch: 1, device_signing_signature_p1363: Buffer.alloc(64, 7).toString('base64url'), device_agreement_mac: Buffer.alloc(32, 8).toString('base64url') };
    await client.startPairing(start);
    await client.confirmPairing(capability, confirm);
    await client.completePairing(capability, { schema: 'nomad.m3e.pairing.vault-commit.v1', challenge_id: challengeId, expected_epoch: 1, device_vault_signature_p1363: Buffer.alloc(64, 9).toString('base64url') });
    await client.abortPairing(capability, { schema: 'nomad.m3e.pairing.abort.v1', challenge_id: challengeId, expected_epoch: 1 });
    assert.deepEqual(seen.map(({ url }) => url), ['/internal/pairing/join/start', '/internal/pairing/join/confirm', '/internal/pairing/join/complete', '/internal/pairing/join/abort']);
    const expectedBodies = [
      { schema: 'nomad.m3e.internal.pairing-start.v1', ...start },
      { schema: 'nomad.m3e.internal.pairing-confirm.v1', join_cookie_capability: capability, ...confirm },
      { schema: 'nomad.m3e.internal.pairing-complete.v1', join_cookie_capability: capability, challenge_id: challengeId, expected_epoch: 1, device_vault_signature_p1363: Buffer.alloc(64, 9).toString('base64url') },
      { schema: 'nomad.m3e.internal.pairing-abort.v1', join_cookie_capability: capability, challenge_id: challengeId, expected_epoch: 1 },
    ];
    seen.forEach((item, index) => { assert.equal(item.body, canonicalJson(expectedBodies[index])); assert.deepEqual(JSON.parse(item.body), expectedBodies[index]); });
    for (const item of seen) {
      const material = `nomad.product-host.transport.v1\nPOST\n${item.url}\n1770000000\n${Buffer.alloc(16, 6).toString('hex')}\n${createHash('sha256').update(item.body).digest('hex')}`;
      assert.equal(item.headers['x-nomad-transport-mac'], createHmac('sha256', key).update(material).digest('hex'));
    }
  } finally { await host.close(); }
});

test('desktop pairing status requires expected_epoch and rejects secret-bearing or prospective_epoch variants', () => {
  const valid = { schema: 'nomad.m3e.pairing.status-response.v1', join_id: `join-${'1'.repeat(32)}`, state: 'created', challenge_id: null, expected_epoch: null, comparison_code: null, expires_at: '2026-08-28T00:02:00Z' };
  assert.equal(validatePairingStatus(valid), valid);
  const started = { ...valid, state: 'started_awaiting_desktop_approval', challenge_id: 'challenge-12345678', expected_epoch: 1, comparison_code: '042913' };
  assert.equal(validatePairingStatus(started), started);
  for (const malformed of [{ ...started, prospective_epoch: 1 }, { ...started, join_secret: 'forbidden' }, { ...started, join_cookie_capability: 'forbidden' }, { ...started, expected_epoch: null }, { ...started, expires_at: '2026-08-28T00:02:00.000Z' }, { ...started, expires_at: '2026-08-28T08:02:00+08:00' }]) assert.throws(() => validatePairingStatus(malformed));
});
