/**
 * Mock relay HTTP server for TEST-ONLY /v1/test/messages bridge.
 * In-memory message store. Supports POST/GET on /v1/test/messages and POST on /v1/test/ack.
 */

import { createServer, type Server } from 'node:http';
import type { TestMessage, TestMessageResponse, TestAckResponse } from './relay-client.js';

interface StoredMessage extends TestMessage {
  relay_id: string;
}

export class MockRelayServer {
  private server: Server | null = null;
  private messages: StoredMessage[] = [];
  private nextId = 1;
  readonly port: number;

  constructor(port?: number) {
    this.port = port ?? 0;
  }

  async start(token: string): Promise<{ url: string; port: number }> {
    return new Promise((resolve, reject) => {
      this.server = createServer(async (req, res) => {
        const url = new URL(req.url!, `http://${req.headers.host}`);
        const auth = req.headers.authorization;

        if (url.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', protocol: 'TEST-ONLY/1', timestamp: Math.floor(Date.now() / 1000) }));
          return;
        }

        if (!auth || auth !== `Bearer ${token}`) {
          res.writeHead(401, { 'Content-Type': 'text/plain' });
          res.end('unauthorized');
          return;
        }

        try {
          if (url.pathname === '/v1/test/messages') {
            if (req.method === 'POST') {
              await this.handleCreateMessage(req, res);
            } else if (req.method === 'GET') {
              this.handleListMessages(url, res);
            } else {
              res.writeHead(405, { 'Content-Type': 'text/plain' });
              res.end('method not allowed');
            }
          } else if (url.pathname === '/v1/test/ack' && req.method === 'POST') {
            await this.handleAck(req, res);
          } else {
            res.writeHead(404);
            res.end('not found');
          }
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end(String(err));
        }
      });

      this.server.on('error', reject);
      this.server.listen(this.port, '127.0.0.1', () => {
        const addr = this.server!.address() as { port: number };
        resolve({ url: `http://127.0.0.1:${addr.port}`, port: addr.port });
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => resolve());
      });
    }
  }

  private async readBody(req: NodeJS.IncomingMessage): Promise<any> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    return JSON.parse(Buffer.concat(chunks).toString());
  }

  private async handleCreateMessage(req: NodeJS.IncomingMessage, res: NodeJS.ServerResponse): Promise<void> {
    const body = await this.readBody(req);

    if (!body.channel) {
      res.writeHead(400);
      res.end('channel is required');
      return;
    }
    if (body.target !== 'host' && body.target !== 'mobile') {
      res.writeHead(400);
      res.end("target must be 'host' or 'mobile'");
      return;
    }
    if (!body.message_id) {
      res.writeHead(400);
      res.end('message_id is required');
      return;
    }

    // Idempotency: same channel + target + message_id → return existing
    const existing = this.messages.find(
      (m) => m.channel === body.channel && m.target === body.target && m.message_id === body.message_id,
    );
    if (existing) {
      const resp: TestMessageResponse = {
        id: existing.relay_id,
        new: false,
        channel: existing.channel,
        target: existing.target,
        message_id: existing.message_id,
      };
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(resp));
      return;
    }

    const id = `msg_${this.nextId++}_${Date.now().toString(36)}`;
    const now = new Date().toISOString();
    const msg: StoredMessage = {
      id,
      relay_id: id,
      channel: body.channel,
      target: body.target,
      message_id: body.message_id,
      payload: body.payload || {},
      acked: false,
      created_at: now,
    };
    this.messages.push(msg);

    const resp: TestMessageResponse = {
      id,
      new: true,
      channel: msg.channel,
      target: msg.target,
      message_id: msg.message_id,
    };
    res.writeHead(202, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(resp));
  }

  private handleListMessages(url: URL, res: NodeJS.ServerResponse): void {
    const channel = url.searchParams.get('channel');
    const target = url.searchParams.get('target');

    if (!channel) {
      res.writeHead(400);
      res.end('channel query required');
      return;
    }
    if (target !== 'host' && target !== 'mobile') {
      res.writeHead(400);
      res.end("target must be 'host' or 'mobile'");
      return;
    }

    const deliveries: TestMessage[] = this.messages
      .filter((m) => m.channel === channel && m.target === target && !m.acked)
      .map(({ id, channel, target, message_id, payload, acked, created_at }) => ({
        id,
        channel,
        target,
        message_id,
        payload,
        acked,
        created_at,
      }));

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(deliveries));
  }

  private async handleAck(req: NodeJS.IncomingMessage, res: NodeJS.ServerResponse): Promise<void> {
    const body = await this.readBody(req);

    if (!body.channel) {
      res.writeHead(400);
      res.end('channel is required');
      return;
    }
    if (body.target !== 'host' && body.target !== 'mobile') {
      res.writeHead(400);
      res.end("target must be 'host' or 'mobile'");
      return;
    }

    const messageIds: string[] = body.message_ids || [];
    for (const mid of messageIds) {
      const msg = this.messages.find((m) => m.message_id === mid);
      if (msg) msg.acked = true;
    }

    const resp: TestAckResponse = {
      channel: body.channel,
      target: body.target,
      acked: messageIds.length,
      message_ids: messageIds,
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(resp));
  }

  getUnackedCount(channel: string, target: 'host' | 'mobile'): number {
    return this.messages.filter((m) => m.channel === channel && m.target === target && !m.acked).length;
  }
}
