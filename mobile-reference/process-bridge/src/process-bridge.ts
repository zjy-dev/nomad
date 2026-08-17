/**
 * Process Bridge — the Mobile side of the Host ↔ Relay ↔ Mobile process loop.
 * Uses the TEST-ONLY /v1/test/messages JSON bridge API.
 */

import { createHash } from 'node:crypto';
import { TestBridgeClient } from './relay-client.js';

// ---------- Types ----------

export type BridgeStep =
  | 'init'
  | 'pair.request'
  | 'pair.confirmed'
  | 'session.checkpoint'
  | 'command.deny'
  | 'command.result.deny'
  | 'command.stop'
  | 'command.result.stop'
  | 'command.allow_once'
  | 'done';

export interface TranscriptEntry {
  step: BridgeStep;
  direction: 'mobile→relay' | 'host→relay' | 'relay→mobile' | 'mobile→host';
  timestamp: string;
  detail: Record<string, unknown>;
}

export interface BridgeTranscript {
  version: string;
  started_at: string;
  completed_at: string;
  steps: TranscriptEntry[];
}

export interface BridgeConfig {
  relayUrl: string;
  token: string;
  channel?: string;
  maxWaitMs?: number;
}

// ---------- Payload shapes ----------

interface PairRequestPayload {
  type: 'pair.request';
  comparison_code: string;
  message_id: string;
  channel: string;
}

interface PairConfirmedPayload {
  type: 'pair.confirmed';
  comparison_code: string;
  message_id: string;
  channel: string;
}

interface SessionCheckpointPayload {
  type: 'session.checkpoint';
  channel: string;
  message_id: string;
  state: 'NeedsPermission';
  diff_summary: {
    file_count: number;
    files: string[];
  };
}

interface CommandDenyPayload {
  type: 'command';
  action: 'deny';
  channel: string;
  message_id: string;
  permission_id: string;
  reason: string;
}

interface CommandStopPayload {
  type: 'command';
  action: 'stop';
  channel: string;
  message_id: string;
  session_id: string;
  target_turn_id: string;
}

interface CommandAllowOncePayload {
  type: 'command';
  action: 'allow_once';
  channel: string;
  message_id: string;
  permission_id: string;
  action_hash: string;
  expires_at: string;
}

interface CommandResultPayload {
  type: 'command.result';
  channel: string;
  message_id: string;
  status: 'RelayReceived' | 'HostAccepted' | 'Completed' | 'Rejected';
  result?: {
    error_code: string;
    error_message: string | null;
  };
  accepted_at_seq?: number;
  event_id?: string;
  stopped_at_seq?: number;
}

// ---------- The Bridge ----------

export class ProcessBridge {
  private client: TestBridgeClient;
  private channel: string;
  private transcript: TranscriptEntry[] = [];
  private startedAt: string;
  private maxWaitMs: number;

  constructor(config: BridgeConfig) {
    this.client = new TestBridgeClient(config.relayUrl, config.token);
    this.startedAt = new Date().toISOString();
    this.channel =
      config.channel ||
      'channel-' + createHash('sha256').update(config.token).digest('hex').slice(0, 16);
    this.maxWaitMs = config.maxWaitMs ?? 10_000;
  }

  getChannel(): string {
    return this.channel;
  }

  private log(step: BridgeStep, direction: TranscriptEntry['direction'], detail: Record<string, unknown>): void {
    this.transcript.push({ step, direction, timestamp: new Date().toISOString(), detail });
  }

  getTranscript(): BridgeTranscript {
    return {
      version: '1.0.0',
      started_at: this.startedAt,
      completed_at: new Date().toISOString(),
      steps: this.transcript,
    };
  }

  async run(): Promise<BridgeTranscript> {
    try {
      this.log('init', 'mobile→relay', { channel: this.channel });
      const comparisonCode = Math.floor(100000 + Math.random() * 900000).toString();
      await this.runPairProtocol(comparisonCode);
      await this.runSessionCheckpoint();
      await this.runDenyCommand();
      await this.runStopCommand();
      await this.runAllowOnce();
      this.log('done', 'mobile→host', { result: 'process-loop-completed' });
      return this.getTranscript();
    } catch (err) {
      this.log('done', 'mobile→host', { result: 'error', message: String(err) });
      throw err;
    }
  }

  // ---------- Pair ----------

  async runPairProtocol(comparisonCode: string): Promise<void> {
    const messageId = crypto.randomUUID();
    const payload: PairRequestPayload = {
      type: 'pair.request',
      comparison_code: comparisonCode,
      message_id: messageId,
      channel: this.channel,
    };

    const resp = await this.client.createMessage(this.channel, 'host', messageId, payload);
    this.log('pair.request', 'mobile→relay', {
      message_id: messageId,
      comparison_code: comparisonCode,
      message_id_relay: resp.id,
    });

    // Wait for host's pair.confirmed back to mobile
    const msgs = await this.client.pollMessages(
      this.channel,
      'mobile',
      (m) => m.some((msg) => msg.payload.type === 'pair.confirmed'),
      this.maxWaitMs,
    );
    const confirmMsg = msgs.find((msg) => msg.payload.type === 'pair.confirmed')!;
    const confirmed = confirmMsg.payload as unknown as PairConfirmedPayload;

    if (confirmed.comparison_code !== comparisonCode) {
      throw new Error(`pair: code mismatch — sent ${comparisonCode}, got ${confirmed.comparison_code}`);
    }

    this.log('pair.confirmed', 'relay→mobile', {
      comparison_code: confirmed.comparison_code,
      verified: true,
      message_id: confirmMsg.message_id,
      acked: true,
    });

    await this.client.ackMessages(this.channel, 'mobile', [confirmMsg.message_id]);
  }

  // ---------- Session Checkpoint ----------

  async runSessionCheckpoint(): Promise<void> {
    const msgs = await this.client.pollMessages(
      this.channel,
      'mobile',
      (m) => m.some((msg) => msg.payload.type === 'session.checkpoint'),
      this.maxWaitMs,
    );
    const cpMsg = msgs.find((msg) => msg.payload.type === 'session.checkpoint')!;
    const cp = cpMsg.payload as unknown as SessionCheckpointPayload;

    if (cp.state !== 'NeedsPermission') {
      throw new Error(`checkpoint: expected NeedsPermission, got ${cp.state}`);
    }
    if (cp.diff_summary.file_count !== 3) {
      throw new Error(`checkpoint: expected 3 files, got ${cp.diff_summary.file_count}`);
    }

    this.log('session.checkpoint', 'relay→mobile', {
      state: cp.state,
      diff_file_count: cp.diff_summary.file_count,
      diff_files: cp.diff_summary.files,
      acked: true,
    });

    await this.client.ackMessages(this.channel, 'mobile', [cpMsg.message_id]);
  }

  // ---------- Deny Command ----------

  async runDenyCommand(): Promise<void> {
    const messageId = crypto.randomUUID();
    const payload: CommandDenyPayload = {
      type: 'command',
      action: 'deny',
      channel: this.channel,
      message_id: messageId,
      permission_id: 'perm_001',
      reason: 'user denied permission',
    };

    const resp = await this.client.createMessage(this.channel, 'host', messageId, payload);
    this.log('command.deny', 'mobile→relay', { message_id: messageId, relay_id: resp.id });

    const msgs = await this.client.pollMessages(
      this.channel,
      'mobile',
      (m) => m.some((msg) => msg.payload.type === 'command.result'),
      this.maxWaitMs,
    );
    const resultMsg = msgs.find((msg) => msg.payload.type === 'command.result')!;
    const result = resultMsg.payload as unknown as CommandResultPayload;

    if (result.status !== 'HostAccepted') {
      throw new Error(`deny result: expected HostAccepted, got ${result.status}`);
    }

    this.log('command.result.deny', 'relay→mobile', {
      status: result.status,
      error_code: result.result?.error_code,
      relay_received_was: 'not_host_accepted',
      acked: true,
    });

    await this.client.ackMessages(this.channel, 'mobile', [resultMsg.message_id]);
  }

  // ---------- Stop Command ----------

  async runStopCommand(): Promise<void> {
    const messageId = crypto.randomUUID();
    const payload: CommandStopPayload = {
      type: 'command',
      action: 'stop',
      channel: this.channel,
      message_id: messageId,
      session_id: 'sess_001',
      target_turn_id: 'turn_001',
    };

    const resp = await this.client.createMessage(this.channel, 'host', messageId, payload);
    this.log('command.stop', 'mobile→relay', { message_id: messageId, relay_id: resp.id });

    const msgs = await this.client.pollMessages(
      this.channel,
      'mobile',
      (m) => m.some((msg) => msg.payload.type === 'command.result'),
      this.maxWaitMs,
    );
    const resultMsg = msgs.find((msg) => msg.payload.type === 'command.result')!;
    const result = resultMsg.payload as unknown as CommandResultPayload;

    if (result.status !== 'HostAccepted') {
      throw new Error(`stop result: expected HostAccepted, got ${result.status}`);
    }

    this.log('command.result.stop', 'relay→mobile', { status: result.status, acked: true });
    await this.client.ackMessages(this.channel, 'mobile', [resultMsg.message_id]);
  }

  // ---------- Allow Once ----------

  async runAllowOnce(): Promise<void> {
    const messageId = crypto.randomUUID();
    const payload: CommandAllowOncePayload = {
      type: 'command',
      action: 'allow_once',
      channel: this.channel,
      message_id: messageId,
      permission_id: 'perm_002',
      action_hash: createHash('sha256').update('action-bytes').digest('hex'),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    };

    const resp = await this.client.createMessage(this.channel, 'host', messageId, payload);
    this.log('command.allow_once', 'mobile→relay', { message_id: messageId, relay_id: resp.id });

    const msgs = await this.client.pollMessages(
      this.channel,
      'mobile',
      (m) => m.some((msg) => msg.payload.type === 'command.result'),
      this.maxWaitMs,
    );
    const resultMsg = msgs.find((msg) => msg.payload.type === 'command.result')!;
    const result = resultMsg.payload as unknown as CommandResultPayload;

    if (result.status !== 'Rejected') {
      throw new Error(`allow_once: expected Rejected, got ${result.status}`);
    }
    if (result.result?.error_code !== 'ERR_SAFETY_BLOCKED') {
      throw new Error(`allow_once: expected ERR_SAFETY_BLOCKED, got ${result.result?.error_code}`);
    }

    this.log('command.allow_once', 'relay→mobile', {
      status: result.status,
      error_code: result.result?.error_code,
      allowed: false,
      acked: true,
    });

    await this.client.ackMessages(this.channel, 'mobile', [resultMsg.message_id]);

    // Verify mailbox is empty after all ACKs
    const remaining = await this.client.listMessages(this.channel, 'mobile');
    if (remaining.length !== 0) {
      throw new Error(`allow_once: frames not fully ACKed (${remaining.length} remaining)`);
    }
  }

  writeTranscript(path: string): void {
    const fs = require('node:fs');
    fs.writeFileSync(path, JSON.stringify(this.getTranscript(), null, 2));
  }
}
