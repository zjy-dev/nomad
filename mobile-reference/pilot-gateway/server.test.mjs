import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AlphaStore } from './alpha-store.mjs';
import { ALPHA_LOCAL_DEVICE, RelayClient } from './relay-client.mjs';
import { createGateway, parseArgs, startGateway } from './server.mjs';
import { browserProjectionFromHost, MAX_PROJECTION_BYTES, projectionDigest } from './view.mjs';

function makeHostProjection({ sessionId = `sess-${'1'.repeat(32)}`, seq = 0, turnState = 'Running', updatedAt = '2026-08-24T10:00:00Z' } = {}) {
  const projection = {
    schema: 'nomad.alpha.readonly.host.v1',
    status: 'available',
    session: {
      session_id: sessionId,
      semantics_version: '1.0.0',
      turn_id: `turn-${'1'.repeat(32)}`,
      turn_state: turnState,
      host_connectivity: 'Online',
      client_freshness: 'Live',
      updated_at: updatedAt,
    },
    seq,
    digest: 'sha256:placeholder',
    events: [],
    changes: { status: 'unavailable', files: [] },
    provenance: {
      source: 'local-alpha-projector',
      relay_ingress_verified: false,
      gateway_schema_verified: false,
    },
  };
  projection.digest = projectionDigest(projection);
  return projection;
}

function makeFrame(projection, frameId = '0123456789abcdef') {
  return {
    frame_id: frameId,
    payload: Buffer.from(JSON.stringify(projection), 'utf8').toString('hex'),
    flags: 1,
    created: 1_777_000_000,
    expires: 1_777_003_600,
  };
}

function statePath(name = 'gateway.db') {
  return join(mkdtempSync(join(tmpdir(), 'nomad-alpha-gateway-')), name);
}

function fakeRelay(frames = []) {
  return {
    frames,
    listCalls: 0,
    acked: [],
    async listFrames() { this.listCalls += 1; return this.frames; },
    async ackFrames(ids) { this.acked.push([...ids]); return { acked: ids.length, verified: true }; },
  };
}

async function listen(options) {
  const server = createServer(createGateway(options)).listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

async function close(server) {
  server.close();
  await once(server, 'close');
}

test('RelayClient uses only fixed-device frame list and ACK routes with server-side bearer', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return new Response(init.method === 'GET' ? '[]' : '{"acked":1,"verified":true}');
  };
  const relay = new RelayClient('http://127.0.0.1:8089/', 'secret-token', fetchImpl);
  await relay.listFrames();
  await relay.ackFrames(['0123456789abcdef']);

  assert.equal(calls[0].url, `http://127.0.0.1:8089/v1/frames?device=${ALPHA_LOCAL_DEVICE}`);
  assert.equal(calls[0].init.method, 'GET');
  assert.equal(calls[1].url, 'http://127.0.0.1:8089/v1/ack');
  assert.deepEqual(JSON.parse(calls[1].init.body), { device: ALPHA_LOCAL_DEVICE, frame_ids: ['0123456789abcdef'] });
  assert.equal(calls[0].init.headers.authorization, 'Bearer secret-token');
  assert.ok(calls.every(({ url }) => !url.includes('/v1/test/')));
});

test('CLI accepts token only from environment and requires file-backed state', () => {
  const config = parseArgs(['--state-db', '/tmp/alpha-state.db'], { NOMAD_ALPHA_RELAY_TOKEN: 'env-secret' });
  assert.equal(config.relayToken, 'env-secret');
  assert.throws(() => parseArgs(['--relay-token', 'argv-secret'], { NOMAD_ALPHA_RELAY_TOKEN: 'env-secret' }), /Unsupported/);
  assert.throws(() => parseArgs([], { NOMAD_ALPHA_RELAY_TOKEN: 'env-secret' }), /explicit file-backed/);
  assert.throws(() => parseArgs(['--state-db', ':memory:'], { NOMAD_ALPHA_RELAY_TOKEN: 'env-secret' }), /file-backed/);
  assert.throws(() => parseArgs([], {}), /NOMAD_ALPHA_RELAY_TOKEN/);
  assert.throws(() => new RelayClient('http://example.com:8089', 'secret'), /loopback/);
});

test('no Relay frame and no durable state returns explicit unavailable', async () => {
  const relay = fakeRelay();
  const store = new AlphaStore(statePath());
  const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
  const response = await fetch(`${base}/api/alpha/session`);
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.equal(body.schema, 'nomad.alpha.readonly.v1');
  assert.equal(body.status, 'unavailable');
  assert.deepEqual(body.events, []);
  assert.deepEqual(relay.acked, []);
  await close(server);
  store.close();
});

test('projection is durably committed before ACK and survives Gateway restart', async () => {
  const path = statePath();
  const host = makeHostProjection({ seq: 4 });
  const browser = browserProjectionFromHost(host);
  const relay = fakeRelay([makeFrame(host)]);
  const store = new AlphaStore(path);
  relay.ackFrames = async (ids) => {
    const observer = new AlphaStore(path);
    const durable = observer.current();
    observer.close();
    assert.equal(durable.digest, browser.digest);
    relay.acked.push([...ids]);
    return { acked: 1, verified: true };
  };

  const first = await listen({ relayClient: relay, store, distDir: '/missing' });
  const firstResponse = await fetch(`${first.base}/api/alpha/session`);
  assert.equal(firstResponse.status, 200);
  const firstBody = await firstResponse.json();
  assert.deepEqual(firstBody, browser);
  assert.equal(firstBody.schema, 'nomad.alpha.readonly.v1');
  assert.equal(firstBody.last_applied_seq, host.seq);
  assert.equal(firstBody.session.turn_id, host.session.turn_id);
  assert.equal(firstBody.provenance.relay_ingress_verified, true);
  assert.equal(firstBody.provenance.gateway_schema_verified, true);
  assert.notEqual(firstBody.digest, host.digest);
  assert.equal(firstBody.digest, projectionDigest(firstBody));
  assert.deepEqual(relay.acked, [['0123456789abcdef']]);
  await close(first.server);
  store.close();

  const restartedStore = new AlphaStore(path);
  const restartedRelay = fakeRelay();
  const second = await listen({ relayClient: restartedRelay, store: restartedStore, distDir: '/missing' });
  const secondResponse = await fetch(`${second.base}/api/alpha/session/${host.session.session_id}`);
  assert.equal(secondResponse.status, 200);
  assert.deepEqual(await secondResponse.json(), browser);
  assert.deepEqual(restartedRelay.acked, []);
  await close(second.server);
  restartedStore.close();
});

test('concurrent Alpha GETs share one ingest and return the same durable projection', async () => {
  const host = makeHostProjection({ seq: 4 });
  const frame = makeFrame(host);
  let releaseList;
  let markListStarted;
  const listGate = new Promise((resolve) => { releaseList = resolve; });
  const listStarted = new Promise((resolve) => { markListStarted = resolve; });
  const relay = fakeRelay([frame]);
  relay.listFrames = async function listFrames() {
    this.listCalls += 1;
    markListStarted();
    await listGate;
    return this.frames;
  };
  const store = new AlphaStore(statePath());
  const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });

  try {
    const first = fetch(`${base}/api/alpha/session`);
    await listStarted;
    const second = fetch(`${base}/api/alpha/session`);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(relay.listCalls, 1);
    releaseList();

    const responses = await Promise.all([first, second]);
    assert.deepEqual(responses.map(({ status }) => status), [200, 200]);
    const bodies = await Promise.all(responses.map((response) => response.json()));
    assert.deepEqual(bodies[0], bodies[1]);
    assert.deepEqual(bodies[0], browserProjectionFromHost(host));
    assert.equal(relay.listCalls, 1);
    assert.deepEqual(relay.acked, [['0123456789abcdef']]);
  } finally {
    releaseList();
  }

  await close(server);
  store.close();
});

test('ACK failure leaves durable state and retry ACKs the idempotent duplicate', async () => {
  const path = statePath();
  const host = makeHostProjection({ seq: 9 });
  const browser = browserProjectionFromHost(host);
  const frame = makeFrame(host);
  const relay = fakeRelay([frame]);
  let attempts = 0;
  relay.ackFrames = async (ids) => {
    attempts += 1;
    relay.acked.push([...ids]);
    if (attempts === 1) throw new Error('temporary ACK failure');
    return { acked: 1, verified: true };
  };
  const store = new AlphaStore(path);
  const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });

  const failed = await fetch(`${base}/api/alpha/session`);
  assert.equal(failed.status, 503);
  assert.equal((await failed.json()).status, 'unavailable');
  const observer = new AlphaStore(path);
  assert.equal(observer.current().digest, browser.digest);
  observer.close();

  const retried = await fetch(`${base}/api/alpha/session`);
  assert.equal(retried.status, 200);
  assert.equal((await retried.json()).digest, browser.digest);
  assert.equal(attempts, 2);
  await close(server);
  store.close();
});

test('same-seq same-digest duplicate is ACKed after durable consistency check', async () => {
  const path = statePath();
  const host = makeHostProjection({ seq: 3 });
  const browser = browserProjectionFromHost(host);
  const store = new AlphaStore(path);
  assert.equal(store.persist(host), 'stored');
  const relay = fakeRelay([makeFrame(host, '1111111111111111')]);
  const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
  const response = await fetch(`${base}/api/alpha/session`);
  assert.equal(response.status, 200);
  assert.deepEqual(relay.acked, [['1111111111111111']]);
  assert.equal(store.current().digest, browser.digest);
  await close(server);
  store.close();
});

test('conflict, stale, gap, and session switch preserve last-good and never ACK', async (t) => {
  const cases = [
    ['same-seq conflict', makeHostProjection({ seq: 5, turnState: 'Completed', updatedAt: '2026-08-24T10:00:01Z' })],
    ['lower stale', makeHostProjection({ seq: 4 })],
    ['forward gap', makeHostProjection({ seq: 7 })],
    ['session switch', makeHostProjection({ sessionId: `sess-${'2'.repeat(32)}`, seq: 6 })],
  ];
  for (const [name, rejected] of cases) {
    await t.test(name, async () => {
      const initial = makeHostProjection({ seq: 5 });
      const initialBrowser = browserProjectionFromHost(initial);
      const store = new AlphaStore(statePath());
      store.persist(initial);
      const relay = fakeRelay([makeFrame(rejected)]);
      const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
      const response = await fetch(`${base}/api/alpha/session`);
      assert.equal(response.status, 503);
      assert.equal((await response.json()).status, 'unknown');
      assert.deepEqual(relay.acked, []);
      assert.deepEqual(store.current(), initialBrowser);
      await close(server);
      store.close();
    });
  }
});

test('bad schema, digest, event ordering, and non-UTF8 payload return unknown without ACK', async (t) => {
  const badSchema = makeHostProjection();
  badSchema.schema = 'nomad.alpha.other.v1';
  badSchema.digest = projectionDigest(badSchema);
  const badDigest = makeHostProjection();
  badDigest.digest = `sha256:${'0'.repeat(64)}`;
  const eventGap = makeHostProjection({ seq: 3 });
  eventGap.events = [
    { event_type: 'turn.started', session_id: eventGap.session.session_id, event_id: `evt-${'1'.repeat(32)}`, seq: 2, timestamp: '2026-08-24T10:00:00Z', durable: true, turn_id: `turn-${'1'.repeat(32)}` },
    { event_type: 'turn.completed', session_id: eventGap.session.session_id, event_id: `evt-${'3'.repeat(32)}`, seq: 1, timestamp: '2026-08-24T10:00:01Z', durable: true, turn_id: `turn-${'1'.repeat(32)}` },
  ];
  eventGap.digest = projectionDigest(eventGap);
  const cases = [
    ['schema', makeFrame(badSchema)],
    ['digest', makeFrame(badDigest)],
    ['event ordering', makeFrame(eventGap)],
    ['decode', { ...makeFrame(makeHostProjection()), payload: 'ff' }],
    ['oversized', { ...makeFrame(makeHostProjection()), payload: '00'.repeat(MAX_PROJECTION_BYTES + 1) }],
    ['non-request flags', { ...makeFrame(makeHostProjection()), flags: 2 }],
  ];
  for (const [name, frame] of cases) {
    await t.test(name, async () => {
      const relay = fakeRelay([frame]);
      const store = new AlphaStore(statePath());
      const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
      const response = await fetch(`${base}/api/alpha/session`);
      assert.equal(response.status, 503);
      assert.equal((await response.json()).status, 'unknown');
      assert.deepEqual(relay.acked, []);
      assert.equal(store.current(), null);
      await close(server);
      store.close();
    });
  }
});

test('metadata event subset may have sequence gaps when it remains strictly increasing and bounded by host seq', async () => {
  const host = makeHostProjection({ seq: 9 });
  host.events = [
    { event_type: 'turn.started', session_id: host.session.session_id, event_id: `evt-${'1'.repeat(32)}`, seq: 2, timestamp: '2026-08-24T10:00:00Z', durable: true, turn_id: host.session.turn_id },
    { event_type: 'turn.completed', session_id: host.session.session_id, event_id: `evt-${'8'.repeat(32)}`, seq: 8, timestamp: '2026-08-24T10:00:01Z', durable: true, turn_id: host.session.turn_id },
  ];
  host.digest = projectionDigest(host);
  const relay = fakeRelay([makeFrame(host)]);
  const store = new AlphaStore(statePath());
  const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
  const response = await fetch(`${base}/api/alpha/session`);
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).events.map(({ seq }) => seq), [2, 8]);
  assert.equal(relay.acked.length, 1);
  await close(server);
  store.close();
});

test('session turn_id is required and accepts only null or a safe turn alias', async (t) => {
  const missing = makeHostProjection();
  delete missing.session.turn_id;
  missing.digest = projectionDigest(missing);
  const unsafe = makeHostProjection();
  unsafe.session.turn_id = 'raw upstream turn id';
  unsafe.digest = projectionDigest(unsafe);
  const nullable = makeHostProjection();
  nullable.session.turn_id = null;
  nullable.digest = projectionDigest(nullable);

  for (const [name, host, expectedStatus, expectedAcks] of [
    ['missing', missing, 503, 0],
    ['unsafe', unsafe, 503, 0],
    ['null', nullable, 200, 1],
  ]) {
    await t.test(name, async () => {
      const relay = fakeRelay([makeFrame(host)]);
      const store = new AlphaStore(statePath());
      const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
      const response = await fetch(`${base}/api/alpha/session`);
      assert.equal(response.status, expectedStatus);
      const body = await response.json();
      if (expectedStatus === 200) assert.equal(body.session.turn_id, null);
      else assert.equal(body.status, 'unknown');
      assert.equal(relay.acked.length, expectedAcks);
      await close(server);
      store.close();
    });
  }
});

test('projection rejects unbounded events and any claimed changes without a verified baseline', async (t) => {
  const tooManyEvents = makeHostProjection({ seq: 33 });
  tooManyEvents.events = Array.from({ length: 33 }, (_, index) => ({
    event_type: 'session.updated',
    session_id: tooManyEvents.session.session_id,
    event_id: `evt-${(index + 1).toString(16).padStart(32, '0')}`,
    seq: index + 1,
    timestamp: '2026-08-24T10:00:00Z',
    durable: true,
    turn_id: null,
  }));
  tooManyEvents.digest = projectionDigest(tooManyEvents);
  const claimedChanges = makeHostProjection();
  claimedChanges.changes = { status: 'available', files: [] };
  claimedChanges.digest = projectionDigest(claimedChanges);

  for (const [name, projection] of [['events', tooManyEvents], ['changes', claimedChanges]]) {
    await t.test(name, async () => {
      const relay = fakeRelay([makeFrame(projection)]);
      const store = new AlphaStore(statePath());
      const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
      const response = await fetch(`${base}/api/alpha/session`);
      assert.equal(response.status, 503);
      assert.equal((await response.json()).status, 'unknown');
      assert.deepEqual(relay.acked, []);
      assert.equal(store.current(), null);
      await close(server);
      store.close();
    });
  }
});

test('all legacy pilot paths are stable READ_ONLY_ALPHA without Relay calls', async () => {
  const relay = fakeRelay();
  const store = new AlphaStore(statePath());
  const { server, base } = await listen({ relayClient: relay, store, distDir: '/missing' });
  for (const [path, method] of [
    ['/api/pilot/session', 'GET'],
    ['/api/pilot/commands', 'POST'],
    ['/api/pilot/commands/req-1', 'GET'],
    ['/api/pilot/status', 'GET'],
  ]) {
    const response = await fetch(base + path, { method });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: 'READ_ONLY_ALPHA' });
  }
  assert.equal(relay.listCalls, 0);
  assert.deepEqual(relay.acked, []);
  await close(server);
  store.close();
});

test('Gateway rejects non-loopback bind and in-memory state DB', () => {
  assert.throws(() => startGateway({ host: '0.0.0.0', port: 0, stateDb: statePath(), relayClient: fakeRelay(), distDir: '/missing' }), /loopback/);
  assert.throws(() => new AlphaStore(':memory:'), /file-backed/);
});
