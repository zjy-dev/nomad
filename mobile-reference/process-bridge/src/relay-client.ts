/**
 * Relay HTTP client for the TEST-ONLY bridge API.
 * Uses /v1/test/messages (GET/POST) and /v1/test/ack (POST).
 * All payloads are JSON — no binary envelopes or crypto required.
 */

export interface TestMessage {
  id: string;
  channel: string;
  target: 'host' | 'mobile';
  message_id: string;
  payload: Record<string, unknown>;
  acked: boolean;
  created_at: string;
}

export interface TestMessageResponse {
  id: string;
  new: boolean;
  channel: string;
  target: 'host' | 'mobile';
  message_id: string;
}

export interface TestAckResponse {
  channel: string;
  target: 'host' | 'mobile';
  acked: number;
  message_ids: string[];
}

export class TestBridgeClient {
  readonly baseUrl: string;
  readonly token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.token = token;
  }

  private async request(path: string, init: RequestInit = {}): Promise<Response> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      'Content-Type': 'application/json',
      ...((init.headers as Record<string, string> | undefined) || {}),
    };
    const body = init.body instanceof Uint8Array ? undefined : init.body;
    return fetch(`${this.baseUrl}${path}`, { ...init, headers, body });
  }

  async createMessage<T extends object>(
    channel: string,
    target: 'host' | 'mobile',
    messageId: string,
    payload: T,
  ): Promise<TestMessageResponse> {
    const resp = await this.request('/v1/test/messages', {
      method: 'POST',
      body: JSON.stringify({ channel, target, message_id: messageId, payload }),
    });
    if (resp.status !== 202) {
      throw new Error(`createMessage: expected 202, got ${resp.status}: ${await resp.text()}`);
    }
    return resp.json() as Promise<TestMessageResponse>;
  }

  async listMessages(channel: string, target: 'host' | 'mobile'): Promise<TestMessage[]> {
    const resp = await this.request(`/v1/test/messages?channel=${encodeURIComponent(channel)}&target=${target}`);
    if (!resp.ok) {
      throw new Error(`listMessages: ${resp.status} ${await resp.text()}`);
    }
    return resp.json() as Promise<TestMessage[]>;
  }

  async ackMessages(
    channel: string,
    target: 'host' | 'mobile',
    messageIds: string[],
  ): Promise<TestAckResponse> {
    const resp = await this.request('/v1/test/ack', {
      method: 'POST',
      body: JSON.stringify({ channel, target, message_ids: messageIds }),
    });
    if (!resp.ok) {
      throw new Error(`ackMessages: ${resp.status} ${await resp.text()}`);
    }
    return resp.json() as Promise<TestAckResponse>;
  }

  async pollMessages(
    channel: string,
    target: 'host' | 'mobile',
    predicate: (msgs: TestMessage[]) => boolean,
    maxWaitMs = 10_000,
    intervalMs = 100,
  ): Promise<TestMessage[]> {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      const msgs = await this.listMessages(channel, target);
      if (predicate(msgs)) return msgs;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new Error(`pollMessages: timed out after ${maxWaitMs}ms`);
  }

  async health(): Promise<{ status: string; protocol: string; timestamp: number }> {
    const resp = await fetch(`${this.baseUrl}/health`);
    if (!resp.ok) throw new Error(`health: ${resp.status}`);
    return resp.json() as Promise<{ status: string; protocol: string; timestamp: number }>;
  }
}
