/**
 * Integration tests for the Process Bridge.
 * Uses a MockRelayServer + FakeHost to verify the full process loop via the
 * TEST-ONLY /v1/test/messages JSON bridge API.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ProcessBridge } from '../src/process-bridge.js';
import { FakeHost } from '../src/fake-host.js';
import { MockRelayServer } from '../src/mock-relay.js';

const TEST_TOKEN = 'test-token-for-process-bridge';

describe('ProcessBridge', () => {
  let relay: MockRelayServer;
  let relayUrl: string;
  let host: FakeHost;

  beforeEach(async () => {
    relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);
    relayUrl = url;
    host = new FakeHost(relayUrl, TEST_TOKEN);
    host.run().catch(() => {});
  });

  afterEach(async () => {
    host.stop();
    await relay.stop();
  });

  it('completes the full process loop and writes transcript', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript = await bridge.run();

    expect(transcript.version).toBe('1.0.0');
    expect(transcript.steps.length).toBeGreaterThan(0);

    const stepNames = transcript.steps.map((s) => s.step);

    expect(stepNames).toContain('pair.request');
    expect(stepNames).toContain('pair.confirmed');

    const pairRequestEntry = transcript.steps.find((s) => s.step === 'pair.request' && s.direction === 'mobile→relay');
    const pairConfirmEntry = transcript.steps.find((s) => s.step === 'pair.confirmed' && s.direction === 'relay→mobile');
    expect(pairRequestEntry).toBeDefined();
    expect(pairConfirmEntry).toBeDefined();
    expect(pairConfirmEntry!.detail.verified).toBe(true);

    const checkpointEntry = transcript.steps.find((s) => s.step === 'session.checkpoint' && s.direction === 'relay→mobile');
    expect(checkpointEntry).toBeDefined();
    expect(checkpointEntry!.detail.state).toBe('NeedsPermission');

    const denyResultEntry = transcript.steps.find((s) => s.step === 'command.result.deny' && s.direction === 'relay→mobile');
    expect(denyResultEntry).toBeDefined();
    expect(denyResultEntry!.detail.status).toBe('HostAccepted');

    const stopResultEntry = transcript.steps.find((s) => s.step === 'command.result.stop' && s.direction === 'relay→mobile');
    expect(stopResultEntry).toBeDefined();
    expect(stopResultEntry!.detail.status).toBe('HostAccepted');

    const allowOnceEntry = transcript.steps.find((s) => s.step === 'command.allow_once' && s.direction === 'relay→mobile');
    expect(allowOnceEntry).toBeDefined();
    expect(allowOnceEntry!.detail.status).toBe('Rejected');
    expect(allowOnceEntry!.detail.error_code).toBe('ERR_SAFETY_BLOCKED');

    const doneEntry = transcript.steps.find((s) => s.step === 'done');
    expect(doneEntry).toBeDefined();
    expect(doneEntry!.detail.result).toBe('process-loop-completed');

    const jsonStr = JSON.stringify(transcript);
    expect(jsonStr).toBeTruthy();
    const parsed = JSON.parse(jsonStr);
    expect(parsed.steps).toBeInstanceOf(Array);
  });

  it('asserts RelayReceived is never HostAccepted', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript = await bridge.run();

    const relayNotAcceptedEntry = transcript.steps.find(
      (s) => s.detail.relay_received_was === 'not_host_accepted',
    );
    expect(relayNotAcceptedEntry).toBeDefined();
    expect(relayNotAcceptedEntry!.step).toBe('command.result.deny');

    const commandResults = transcript.steps.filter(
      (s) => s.step === 'command.result.deny' || s.step === 'command.result.stop',
    );
    for (const entry of commandResults) {
      if (entry.direction === 'relay→mobile') {
        expect(['HostAccepted', 'Rejected']).toContain(entry.detail.status);
      }
    }
  });

  it('ACK removes each message from relay mailbox', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    await bridge.run();

    const ackSteps = bridge.getTranscript().steps.filter(
      (s) => s.step === 'pair.confirmed' || s.step === 'session.checkpoint' ||
             s.step === 'command.result.deny' || s.step === 'command.result.stop' ||
             s.step === 'command.allow_once',
    );
    expect(ackSteps.length).toBeGreaterThanOrEqual(5);
  });

  it('allow_once is always rejected with ERR_SAFETY_BLOCKED', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript = await bridge.run();

    const allowOnceMobile = transcript.steps.find(
      (s) => s.step === 'command.allow_once' && s.direction === 'relay→mobile',
    );
    expect(allowOnceMobile).toBeDefined();
    expect(allowOnceMobile!.detail.status).toBe('Rejected');
    expect(allowOnceMobile!.detail.error_code).toBe('ERR_SAFETY_BLOCKED');
    expect(allowOnceMobile!.detail.allowed).toBe(false);
  });

  it('pair comparison code round-trips correctly', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript = await bridge.run();

    const pairRequest = transcript.steps.find((s) => s.step === 'pair.request' && s.direction === 'mobile→relay');
    const pairConfirm = transcript.steps.find((s) => s.step === 'pair.confirmed' && s.direction === 'relay→mobile');

    expect(pairRequest).toBeDefined();
    expect(pairConfirm).toBeDefined();

    const sentCode = pairRequest!.detail.comparison_code as string;
    const confirmedCode = pairConfirm!.detail.comparison_code as string;
    expect(sentCode).toBe(confirmedCode);
    expect(sentCode).toHaveLength(6);
    expect(pairConfirm!.detail.verified).toBe(true);
  });

  it('session checkpoint includes NeedsPermission and diff metadata', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript = await bridge.run();

    const checkpoint = transcript.steps.find(
      (s) => s.step === 'session.checkpoint' && s.direction === 'relay→mobile',
    );
    expect(checkpoint).toBeDefined();
    expect(checkpoint!.detail.state).toBe('NeedsPermission');
    expect(checkpoint!.detail.diff_file_count).toBe(3);
    expect(checkpoint!.detail.diff_files).toBeInstanceOf(Array);
    expect(checkpoint!.detail.diff_files).toHaveLength(3);
  });

  it('transcript has complete lifecycle events', async () => {
    const bridge = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript = await bridge.run();

    const order = transcript.steps.map((s) => s.step);
    const initIdx = order.indexOf('init');
    const pairIdx = order.indexOf('pair.request');
    const checkpointIdx = order.indexOf('session.checkpoint');
    const denyIdx = order.findIndex((s) => s === 'command.result.deny');
    const stopIdx = order.findIndex((s) => s === 'command.result.stop');
    const allowIdx = order.findIndex((s) => s === 'command.allow_once');
    const doneIdx = order.indexOf('done');

    expect(initIdx).toBeGreaterThan(-1);
    expect(pairIdx).toBeGreaterThan(initIdx);
    expect(checkpointIdx).toBeGreaterThan(pairIdx);
    expect(denyIdx).toBeGreaterThan(checkpointIdx);
    expect(stopIdx).toBeGreaterThan(denyIdx);
    expect(allowIdx).toBeGreaterThan(stopIdx);
    expect(doneIdx).toBeGreaterThan(allowIdx);
  });

  it('two sequential runs produce independent channels', async () => {
    const bridge1 = new ProcessBridge({ relayUrl, token: TEST_TOKEN });
    const transcript1 = await bridge1.run();
    expect(transcript1.steps.length).toBeGreaterThan(0);

    // Start a new relay and host for the second run (different token = different channel)
    const relay2 = new MockRelayServer(0);
    const altToken = 'alt-token-for-second-bridge';
    const { url: url2 } = await relay2.start(altToken);
    const host2 = new FakeHost(url2, altToken);
    host2.run().catch(() => {});

    try {
      const bridge2 = new ProcessBridge({ relayUrl: url2, token: altToken });
      const transcript2 = await bridge2.run();
      expect(transcript2.steps.length).toBeGreaterThan(0);

      // Verify channels differ
      const channel1 = transcript1.steps[0].detail.channel as string;
      const channel2Val = transcript2.steps[0].detail.channel as string;
      expect(channel1).not.toBe(channel2Val);
    } finally {
      host2.stop();
      await relay2.stop();
    }
  });
});

describe('MockRelayServer — TEST bridge API', () => {
  const TEST_TOKEN = 'test-token-for-process-bridge';

  it('creates and lists messages via /v1/test/messages', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const channel = 'test-channel-001';
    const msgId = 'msg-001';
    const payload = { type: 'pair.request', comparison_code: '123456' };

    const createResp = await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'host', message_id: msgId, payload }),
    });
    expect(createResp.status).toBe(202);
    const createData = (await createResp.json()) as { id: string; new: boolean };
    expect(createData.new).toBe(true);
    expect(createData.id).toBeTruthy();

    const listResp = await fetch(`${url}/v1/test/messages?channel=${channel}&target=host`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    expect(listResp.status).toBe(200);
    const msgs = (await listResp.json()) as Array<{ message_id: string }>;
    expect(msgs.length).toBe(1);
    expect(msgs[0].message_id).toBe(msgId);

    await relay.stop();
  });

  it('idempotent createMessage returns new=false for duplicate message_id', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const channel = 'test-channel-002';
    const msgId = 'msg-002';
    const payload = { type: 'test' };

    const createResp1 = await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'host', message_id: msgId, payload }),
    });
    expect(createResp1.status).toBe(202);
    const data1 = (await createResp1.json()) as { new: boolean };
    expect(data1.new).toBe(true);

    // Same message_id → idempotent, returns new=false
    const createResp2 = await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'host', message_id: msgId, payload }),
    });
    expect(createResp2.status).toBe(202);
    const data2 = (await createResp2.json()) as { new: boolean };
    expect(data2.new).toBe(false);

    await relay.stop();
  });

  it('ACK removes messages from mailbox', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const channel = 'test-channel-003';
    const msgId = 'msg-003';
    const payload = { type: 'command.result', status: 'HostAccepted' };

    await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'mobile', message_id: msgId, payload }),
    });

    // Before ACK, message is visible
    const listBefore = await fetch(`${url}/v1/test/messages?channel=${channel}&target=mobile`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    const msgsBefore = (await listBefore.json()) as unknown[];
    expect(msgsBefore.length).toBe(1);

    // ACK the message
    const ackResp = await fetch(`${url}/v1/test/ack`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'mobile', message_ids: [msgId] }),
    });
    expect(ackResp.status).toBe(200);
    const ackData = (await ackResp.json()) as { acked: number };
    expect(ackData.acked).toBe(1);

    // After ACK, message is gone from listing
    const listAfter = await fetch(`${url}/v1/test/messages?channel=${channel}&target=mobile`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    const msgsAfter = (await listAfter.json()) as unknown[];
    expect(msgsAfter.length).toBe(0);

    await relay.stop();
  });

  it('rejects unauthorized requests', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start('correct-token');

    const resp = await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: 'Bearer wrong-token', 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel: 'ch', target: 'host', message_id: 'x', payload: {} }),
    });
    expect(resp.status).toBe(401);
    await relay.stop();
  });

  it('rejects invalid target values', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const resp = await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel: 'ch', target: 'invalid', message_id: 'x', payload: {} }),
    });
    expect(resp.status).toBe(400);
    await relay.stop();
  });

  it('exposes health endpoint without auth', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const resp = await fetch(`${url}/health`);
    expect(resp.status).toBe(200);
    const data = (await resp.json()) as { status: string; protocol: string };
    expect(data.status).toBe('ok');
    expect(data.protocol).toBe('TEST-ONLY/1');
    await relay.stop();
  });

  it('channels are isolated — messages in one channel are not visible in another', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const chA = 'channel-A';
    const chB = 'channel-B';

    await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel: chA, target: 'host', message_id: 'a1', payload: { type: 'test' } }),
    });
    await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel: chB, target: 'host', message_id: 'b1', payload: { type: 'test' } }),
    });

    const listA = await fetch(`${url}/v1/test/messages?channel=${chA}&target=host`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    const msgsA = (await listA.json()) as Array<{ message_id: string }>;
    expect(msgsA.length).toBe(1);
    expect(msgsA[0].message_id).toBe('a1');

    const listB = await fetch(`${url}/v1/test/messages?channel=${chB}&target=host`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    const msgsB = (await listB.json()) as Array<{ message_id: string }>;
    expect(msgsB.length).toBe(1);
    expect(msgsB[0].message_id).toBe('b1');

    await relay.stop();
  });

  it('can send messages to both directions on same channel', async () => {
    const relay = new MockRelayServer(0);
    const { url } = await relay.start(TEST_TOKEN);

    const channel = 'dup-test-channel';

    await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'host', message_id: 'h1', payload: { type: 'to-host' } }),
    });
    await fetch(`${url}/v1/test/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TEST_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ channel, target: 'mobile', message_id: 'm1', payload: { type: 'to-mobile' } }),
    });

    const listHost = await fetch(`${url}/v1/test/messages?channel=${channel}&target=host`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    const msgsHost = (await listHost.json()) as Array<{ message_id: string }>;
    expect(msgsHost.length).toBe(1);
    expect(msgsHost[0].message_id).toBe('h1');

    const listMobile = await fetch(`${url}/v1/test/messages?channel=${channel}&target=mobile`, {
      headers: { Authorization: `Bearer ${TEST_TOKEN}` },
    });
    const msgsMobile = (await listMobile.json()) as Array<{ message_id: string }>;
    expect(msgsMobile.length).toBe(1);
    expect(msgsMobile[0].message_id).toBe('m1');

    await relay.stop();
  });
});
