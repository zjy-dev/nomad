import type {
  BrowserCommandCapability, CapabilityCommandIntent, CommandCapability, DenyActionCapability,
  GatewayCommandReceipt, GatewayCommandRequest, ReplyActionCapability, StopActionCapability,
  SessionClient, SessionView,
} from './types';
import { AlphaAvailabilityError, AlphaResponseError, decodeAlphaFailure } from './alpha-decoder';

export interface HttpSessionClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  decodeSession: (payload: unknown) => SessionView | Promise<SessionView>;
}

/** Same-origin session and capability-gated command client for official local mode. */
export class HttpSessionClient implements SessionClient {
  readonly mode = 'official-local' as const;
  readonly writable = true;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: HttpSessionClientOptions) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async loadCurrentSession(): Promise<SessionView> {
    return this.load();
  }

  async refreshSession(_sessionId: string): Promise<SessionView> {
    return this.load();
  }

  async loadCommandCapability(): Promise<BrowserCommandCapability | null> {
    const response = await this.fetchResponse('/api/commands/capability', {
      method: 'GET', credentials: 'same-origin', headers: { accept: 'application/json' },
    });
    if (response.status === 503 || response.status === 404) return null;
    if (!response.ok) throw new CommandResponseError('Command capability is unavailable.');
    return decodeCapability(await parseJson(response));
  }

  async submitCapabilityCommand(binding: BrowserCommandCapability, intent: CapabilityCommandIntent): Promise<GatewayCommandReceipt> {
    const now = new Date();
    const expectedTarget = binding.capability[intent.action];
    if (!expectedTarget || !intentMatchesCapability(intent, binding.capability)
        || binding.capability.allow_once !== false
        || Date.parse(binding.capability.issued_at) > now.getTime()
        || Date.parse(binding.capability.expires_at) <= now.getTime()
        || (intent.action === 'reply' && !intent.content.trim())) {
      throw new CommandResponseError('The command capability is no longer valid for this action.');
    }
    const common = {
      schema: 'nomad.gateway.command.v1' as const,
      capability_id: binding.capability.capability_id,
      request_id: randomOpaqueId('req'),
      nonce: randomOpaqueId('nonce'),
      command_seq: binding.capability.next_command_seq,
      expected_snapshot_seq: binding.capability.snapshot_seq,
      expected_snapshot_digest: binding.capability.snapshot_digest,
      issued_at: now.toISOString(),
      expires_at: binding.capability.expires_at,
    };
    const request: GatewayCommandRequest = intent.action === 'reply'
      ? { ...common, action: 'reply', turn_alias: intent.turn_alias, input_alias: intent.input_alias, content: intent.content }
      : intent.action === 'deny'
        ? { ...common, action: 'deny', permission_alias: intent.permission_alias, action_hash: intent.action_hash, permission_expires_at: intent.permission_expires_at }
        : { ...common, action: 'stop', turn_alias: intent.turn_alias };
    const response = await this.fetchResponse('/api/commands', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { accept: 'application/json', 'content-type': 'application/json', 'X-Nomad-CSRF': binding.csrfToken },
      body: JSON.stringify(request),
    });
    if (!response.ok) throw new CommandResponseError('The local Host did not accept this command.');
    const receipt = decodeReceipt(await parseJson(response));
    if (receipt.request_id !== request.request_id || receipt.action !== request.action
        || receipt.snapshot_seq !== request.expected_snapshot_seq
        || receipt.snapshot_digest !== request.expected_snapshot_digest) invalid();
    return receipt;
  }

  private async load(): Promise<SessionView> {
    let response: Response;
    try {
      response = await this.fetchResponse('/api/alpha/session', {
        method: 'GET',
        headers: { accept: 'application/json' },
      });
    } catch {
      throw new AlphaAvailabilityError('unavailable');
    }
    if (!response.ok) {
      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new AlphaResponseError();
      }
      decodeAlphaFailure(payload);
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new AlphaResponseError();
    }
    return this.options.decodeSession(payload);
  }

  private fetchResponse(path: string, init: RequestInit): Promise<Response> {
    const base = this.options.baseUrl.replace(/\/$/, '');
    return this.fetchImpl(`${base}${path}`, init);
  }
}

export class CommandResponseError extends Error {}

function decodeCapability(value: unknown): BrowserCommandCapability {
  const wrapper = exactObject(value, ['schema', 'csrf_token', 'capability', 'display_snapshot_seq', 'display_snapshot_digest']);
  if (wrapper.schema !== 'nomad.gateway.command-capability.v1' || !opaque(wrapper.csrf_token)
      || !positiveSeq(wrapper.display_snapshot_seq) || !digest(wrapper.display_snapshot_digest)) invalid();
  const raw = exactObject(wrapper.capability, [
    'schema', 'capability_id', 'snapshot_seq', 'snapshot_digest', 'next_command_seq', 'issued_at',
    'expires_at', 'view', 'reply', 'deny', 'stop', 'allow_once',
  ]);
  if (raw.schema !== 'nomad.product-host.command-capability.v1' || !opaque(raw.capability_id)
      || !positiveSeq(raw.snapshot_seq) || !digest(raw.snapshot_digest) || !positiveSeq(raw.next_command_seq)
      || !timestamp(raw.issued_at) || !timestamp(raw.expires_at) || raw.view !== true || raw.allow_once !== false) invalid();
  const capability: CommandCapability = {
    schema: raw.schema, capability_id: raw.capability_id, snapshot_seq: raw.snapshot_seq,
    snapshot_digest: raw.snapshot_digest, next_command_seq: raw.next_command_seq, issued_at: raw.issued_at,
    expires_at: raw.expires_at, view: true, reply: replyAction(raw.reply), deny: denyAction(raw.deny),
    stop: stopAction(raw.stop), allow_once: false,
  };
  const ttl = Date.parse(capability.expires_at) - Date.parse(capability.issued_at);
  const now = Date.now();
  if (ttl <= 0 || ttl > 30_000 || Date.parse(capability.issued_at) > now || Date.parse(capability.expires_at) <= now) invalid();
  return {
    capability,
    csrfToken: wrapper.csrf_token,
    displaySnapshotSeq: wrapper.display_snapshot_seq,
    displaySnapshotDigest: wrapper.display_snapshot_digest,
  };
}

function decodeReceipt(value: unknown): GatewayCommandReceipt {
  const raw = exactObject(value, ['schema', 'receipt_id', 'request_id', 'action', 'snapshot_seq', 'snapshot_digest', 'accepted_at', 'status', 'error_code', 'idempotent_replay']);
  const statuses = new Set(['HostAccepted', 'Dispatching', 'DispatchAcknowledged', 'Rejected', 'Stale', 'Expired', 'OutcomeUnknown']);
  const errors = new Set(['OK', 'ERR_REQUEST_EXPIRED', 'ERR_REQUEST_STALE', 'ERR_INCOMPATIBLE_VERSION', 'ERR_REQUEST_REVOKED', 'ERR_DUPLICATE_REQUEST', 'ERR_HOST_OFFLINE', 'ERR_SAFETY_BLOCKED', 'ERR_PERMISSION_DENIED', 'ERR_OUTCOME_UNKNOWN']);
  if (raw.schema !== 'nomad.gateway.command-receipt.v1' || !opaque(raw.receipt_id) || !opaque(raw.request_id)
      || !['reply', 'deny', 'stop'].includes(String(raw.action)) || !positiveSeq(raw.snapshot_seq) || !digest(raw.snapshot_digest)
      || (raw.accepted_at !== null && !timestamp(raw.accepted_at)) || !statuses.has(String(raw.status))
      || (raw.error_code !== null && !errors.has(String(raw.error_code))) || typeof raw.idempotent_replay !== 'boolean') invalid();
  return raw as unknown as GatewayCommandReceipt;
}

function replyAction(value: unknown): ReplyActionCapability | null {
  if (value === null) return null;
  const raw = exactObject(value, Object.prototype.hasOwnProperty.call(value, 'summary')
    ? ['turn_alias', 'input_alias', 'summary']
    : ['turn_alias', 'input_alias']);
  if (!opaque(raw.turn_alias) || !opaque(raw.input_alias)) invalid();
  return {
    turn_alias: raw.turn_alias,
    input_alias: raw.input_alias,
    ...(raw.summary === undefined ? {} : { summary: raw.summary === null ? null : pendingQuestionSummary(raw.summary) }),
  };
}

function pendingQuestionSummary(value: unknown): NonNullable<ReplyActionCapability['summary']> {
  const raw = exactObject(value, ['schema', 'question_count', 'answer_mode', 'response_hint', 'prompt']);
  if (raw.schema !== 'nomad.product-host.pending-question-summary.v1' || raw.question_count !== 1
      || raw.answer_mode !== 'free_text' || raw.response_hint !== 'single_short_reply'
      || !safePrompt(raw.prompt)) invalid();
  return raw as unknown as NonNullable<ReplyActionCapability['summary']>;
}

function denyAction(value: unknown): DenyActionCapability | null {
  if (value === null) return null;
  const raw = exactObject(value, ['permission_alias', 'action_hash', 'expires_at']);
  if (!opaque(raw.permission_alias) || !digest(raw.action_hash) || !timestamp(raw.expires_at)) invalid();
  return { permission_alias: raw.permission_alias, action_hash: raw.action_hash, expires_at: raw.expires_at };
}

function stopAction(value: unknown): StopActionCapability | null {
  if (value === null) return null;
  const raw = exactObject(value, ['turn_alias']);
  if (!opaque(raw.turn_alias)) invalid();
  return { turn_alias: raw.turn_alias };
}

function intentMatchesCapability(intent: CapabilityCommandIntent, capability: CommandCapability): boolean {
  if (intent.action === 'reply') return capability.reply?.turn_alias === intent.turn_alias && capability.reply.input_alias === intent.input_alias;
  if (intent.action === 'deny') return capability.deny?.permission_alias === intent.permission_alias
    && capability.deny.action_hash === intent.action_hash && capability.deny.expires_at === intent.permission_expires_at;
  return capability.stop?.turn_alias === intent.turn_alias;
}

function exactObject(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const raw = value as Record<string, unknown>;
  const actual = Object.keys(raw).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) invalid();
  return raw;
}
function positiveSeq(value: unknown): value is number { return Number.isSafeInteger(value) && Number(value) > 0; }
function opaque(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9_-]{8,160}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function timestamp(value: unknown): value is string { return typeof value === 'string' && Number.isFinite(Date.parse(value)); }
function safePrompt(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 160
    && /^Provide a short reply for: [a-z0-9]+(?:[ -][a-z0-9]+){0,5}\.$/.test(value);
}
function invalid(): never { throw new CommandResponseError('The local command response is incompatible.'); }
async function parseJson(response: Response): Promise<unknown> { try { return await response.json(); } catch { invalid(); } }
function randomOpaqueId(prefix: string): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `${prefix}_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}
