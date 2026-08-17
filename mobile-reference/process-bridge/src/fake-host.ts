/**
 * FakeHost — a deterministic mock Host consumer for ProcessBridge tests.
 * Uses the TEST-ONLY /v1/test/messages JSON bridge API via TestBridgeClient.
 *
 * Runs a simple polling loop:
 *  1. Poll for pair.request from mobile → send pair.confirmed
 *  2. Send session.checkpoint to mobile
 *  3. Poll for deny command → send command.result (HostAccepted)
 *  4. Poll for stop command → send command.result (HostAccepted)
 *  5. Poll for allow_once command → send command.result (Rejected, ERR_SAFETY_BLOCKED)
 */

import { createHash } from 'node:crypto';
import { TestBridgeClient, type TestMessage } from './relay-client.js';

export class FakeHost {
  private client: TestBridgeClient;
  private channel: string;
  private _running = false;
  private _pairCompleted = false;

  constructor(relayUrl: string, token: string, channel?: string) {
    this.client = new TestBridgeClient(relayUrl, token);
    this.channel =
      channel ||
      'channel-' + createHash('sha256').update(token).digest('hex').slice(0, 16);
  }

  getChannel(): string {
    return this.channel;
  }

  /** Start the host consumer loop. */
  async run(): Promise<void> {
    this._running = true;
    try {
      // Step 1: Wait for mobile's pair.request, then confirm it
      await this.handlePair();

      // Step 2: Send session checkpoint to mobile
      await this.sendCheckpoint();

      // Steps 3-5: Handle commands sequentially
      await this.handleCommands();
    } finally {
      this._running = false;
    }
  }

  private async waitForHostMessages(
    predicate: (msgs: TestMessage[]) => boolean,
    maxWaitMs = 10_000,
  ): Promise<TestMessage[]> {
    const deadline = Date.now() + maxWaitMs;
    while (this._running && Date.now() < deadline) {
      const msgs = await this.client.listMessages(this.channel, 'host');
      if (predicate(msgs)) return msgs;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error('FakeHost: timed out waiting for host messages');
  }

  private async handlePair(): Promise<void> {
    const msgs = await this.waitForHostMessages((m) =>
      m.some((msg) => msg.payload.type === 'pair.request'),
    );
    const pairMsg = msgs.find((msg) => msg.payload.type === 'pair.request')!;
    const pairReq = pairMsg.payload as { comparison_code: string; message_id: string; channel: string };

    // Use the channel from mobile's message
    this.channel = pairReq.channel;

    // ACK the pair.request message
    await this.client.ackMessages(this.channel, 'host', [pairMsg.message_id]);

    // Send pair.confirmed back to mobile
    const confirmPayload = {
      type: 'pair.confirmed' as const,
      comparison_code: pairReq.comparison_code,
      message_id: pairReq.message_id,
      channel: pairReq.channel,
    };
    await this.client.createMessage(this.channel, 'mobile', crypto.randomUUID(), confirmPayload);
    this._pairCompleted = true;
  }

  private async sendCheckpoint(): Promise<void> {
    const checkpointPayload = {
      type: 'session.checkpoint' as const,
      channel: this.channel,
      message_id: crypto.randomUUID(),
      state: 'NeedsPermission' as const,
      diff_summary: {
        file_count: 3,
        files: ['src/main.py', 'src/utils.py', 'config.yaml'],
      },
    };
    await this.client.createMessage(this.channel, 'mobile', crypto.randomUUID(), checkpointPayload);
  }

  private async handleCommands(): Promise<void> {
    // Handle commands one at a time in sequence: deny, stop, allow_once
    const commands: Array<{ action: string; handle: (msg: TestMessage) => Promise<void> }> = [
      { action: 'deny', handle: (msg) => this.handleDeny(msg) },
      { action: 'stop', handle: (msg) => this.handleStop(msg) },
      { action: 'allow_once', handle: (msg) => this.handleAllowOnce(msg) },
    ];

    for (const cmd of commands) {
      const msgs = await this.waitForHostMessages((m) =>
        m.some((msg) => msg.payload.type === 'command' && (msg.payload as { action: string }).action === cmd.action),
      );
      const cmdMsg = msgs.find(
        (msg) => msg.payload.type === 'command' && (msg.payload as { action: string }).action === cmd.action,
      )!;
      await cmd.handle(cmdMsg);
    }
  }

  private async handleDeny(msg: TestMessage): Promise<void> {
    const denyCmd = msg.payload as { message_id: string; channel: string };

    // ACK the deny command message
    await this.client.ackMessages(this.channel, 'host', [msg.message_id]);

    // Send result back to mobile
    const resultPayload = {
      type: 'command.result' as const,
      channel: denyCmd.channel,
      message_id: denyCmd.message_id,
      status: 'HostAccepted' as const,
      result: { error_code: 'OK', error_message: null },
      accepted_at_seq: 10,
      event_id: 'evt_010',
    };
    await this.client.createMessage(this.channel, 'mobile', crypto.randomUUID(), resultPayload);
  }

  private async handleStop(msg: TestMessage): Promise<void> {
    const stopCmd = msg.payload as { message_id: string; channel: string };

    // ACK the stop command message
    await this.client.ackMessages(this.channel, 'host', [msg.message_id]);

    // Send result back to mobile
    const resultPayload = {
      type: 'command.result' as const,
      channel: stopCmd.channel,
      message_id: stopCmd.message_id,
      status: 'HostAccepted' as const,
      result: { error_code: 'OK', error_message: null },
      stopped_at_seq: 11,
      new_event_id: 'evt_011',
    };
    await this.client.createMessage(this.channel, 'mobile', crypto.randomUUID(), resultPayload);
  }

  private async handleAllowOnce(msg: TestMessage): Promise<void> {
    const allowCmd = msg.payload as { message_id: string; channel: string };

    // ACK the allow_once command message
    await this.client.ackMessages(this.channel, 'host', [msg.message_id]);

    // Send rejected result back to mobile
    const rejectPayload = {
      type: 'command.result' as const,
      channel: allowCmd.channel,
      message_id: allowCmd.message_id,
      status: 'Rejected' as const,
      result: { error_code: 'ERR_SAFETY_BLOCKED', error_message: 'allow_once is not permitted in test-only mode' },
    };
    await this.client.createMessage(this.channel, 'mobile', crypto.randomUUID(), rejectPayload);
  }

  stop(): void {
    this._running = false;
  }
}
