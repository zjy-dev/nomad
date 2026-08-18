import type { Command } from '../contracts/types';
import type { CommandSubmission, SessionClient, SessionView } from './types';

export interface HttpSessionClientRoutes {
  currentSession: string;
  refreshSession: (sessionId: string) => string;
  commands: string;
  commandStatus?: (sessionId: string, requestId: string) => string;
}

export interface HttpSessionClientCodecs {
  /** Host/Relay owners supply the adapter because the Pilot envelope is not frozen. */
  decodeSession: (payload: unknown) => SessionView | Promise<SessionView>;
  decodeCommand: (payload: unknown) => CommandSubmission | Promise<CommandSubmission>;
}

export interface HttpSessionClientOptions extends HttpSessionClientCodecs {
  baseUrl: string;
  routes: HttpSessionClientRoutes;
  fetchImpl?: typeof fetch;
  headers?: Record<string, string>;
}

/**
 * Replaceable JSON/HTTP transport for the product UI.
 *
 * Routes and response codecs are mandatory on purpose: Session Semantics v0
 * freezes snapshots/events/commands, not a new Mobile REST envelope. This
 * transport therefore does not silently invent one.
 */
export class HttpSessionClient implements SessionClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: HttpSessionClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async loadCurrentSession(): Promise<SessionView> {
    const payload = await this.request(this.options.routes.currentSession);
    return this.options.decodeSession(payload);
  }

  async refreshSession(sessionId: string): Promise<SessionView> {
    const payload = await this.request(this.options.routes.refreshSession(sessionId));
    return this.options.decodeSession(payload);
  }

  async submitCommand(command: Command): Promise<CommandSubmission> {
    const payload = await this.request(this.options.routes.commands, {
      method: 'POST',
      body: JSON.stringify(command),
    });
    return this.options.decodeCommand(payload);
  }

  async getCommandStatus(sessionId: string, requestId: string): Promise<CommandSubmission> {
    const route = this.options.routes.commandStatus;
    if (!route) throw new Error('Command status route is not configured.');
    const payload = await this.request(route(sessionId, requestId));
    return this.options.decodeCommand(payload);
  }

  private async request(path: string, init: RequestInit = {}): Promise<unknown> {
    const base = this.options.baseUrl.replace(/\/$/, '');
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    const response = await this.fetchImpl(`${base}${normalizedPath}`, {
      ...init,
      headers: {
        accept: 'application/json',
        ...(init.body ? { 'content-type': 'application/json' } : {}),
        ...this.options.headers,
        ...init.headers,
      },
    });
    if (!response.ok) {
      throw new Error(`Session API request failed (${response.status}).`);
    }
    return response.json() as Promise<unknown>;
  }
}
