export interface DesktopPairingCurrentDevice {
  schema: 'nomad.product-host.device-current.v1';
  principal_alias: string;
  paired: boolean;
  device: {
    device_alias: string;
    pairing_epoch: number;
  } | null;
}

export interface DesktopPairingCreatedJoin {
  schema: 'nomad.m3e.pairing.desktop-created.v1';
  join_id: string;
  expires_at: string;
  join_url: string;
}

export type DesktopPairingJoinState =
  | 'created'
  | 'started_awaiting_desktop_approval'
  | 'desktop_approved'
  | 'provisioned_pending_vault'
  | 'active'
  | 'cancelled'
  | 'expired'
  | 'compensated'
  | 'revoked';

export interface DesktopPairingJoinStatus {
  schema: 'nomad.m3e.pairing.status-response.v1';
  join_id: string;
  state: DesktopPairingJoinState;
  challenge_id: string | null;
  expected_epoch: number | null;
  comparison_code: string | null;
  expires_at: string;
}

export interface DesktopPairingRevokeResult {
  schema: 'nomad.product-host.device-revoke.v1';
  principal_alias: string;
  device_alias: string;
  status: 'revoked' | 'already_revoked';
  prior_epoch: number | null;
  revoked_epoch: number;
}

export interface DesktopPairingClient {
  getCurrentDevice(): Promise<DesktopPairingCurrentDevice>;
  createJoin(): Promise<DesktopPairingCreatedJoin>;
  getJoinStatus(joinId: string): Promise<DesktopPairingJoinStatus>;
  approveJoin(input: {
    joinId: string;
    challengeId: string;
    expectedEpoch: number;
    comparisonCode: string;
  }): Promise<void>;
  cancelJoin(joinId: string): Promise<void>;
  revokeDevice(input: { deviceAlias: string; expectedEpoch: number }): Promise<DesktopPairingRevokeResult>;
}

export interface DesktopPairingClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

export class DesktopPairingClientError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export function createDesktopPairingClient(options: DesktopPairingClientOptions): DesktopPairingClient {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const baseUrl = options.baseUrl.replace(/\/$/, '');
  let csrfTokenFlight: Promise<string | null> | null = null;

  async function readJson(path: string, init: RequestInit, csrfErrorCode: string | null = null): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, init);
    } catch {
      throw new DesktopPairingClientError('PAIRING_NETWORK_ERROR', 'Desktop pairing request failed before an authoritative response was received.');
    }
    if (!response.ok) {
      if (csrfErrorCode !== null) {
        const errorCode = await readErrorCode(response);
        if (errorCode === csrfErrorCode) {
          throw new DesktopPairingClientError(errorCode, 'Desktop pairing CSRF protection rejected the current token.');
        }
      }
      throw new DesktopPairingClientError('PAIRING_HTTP_ERROR', `Desktop pairing request failed with HTTP ${response.status}.`);
    }
    const contentType = response.headers.get('content-type');
    if (contentType === null || !contentType.startsWith('application/json')) {
      throw new DesktopPairingClientError('PAIRING_INVALID_RESPONSE', 'Desktop pairing response content type is incompatible.');
    }
    try {
      return await response.json();
    } catch {
      throw new DesktopPairingClientError('PAIRING_INVALID_RESPONSE', 'Desktop pairing response JSON is invalid.');
    }
  }

  async function bootstrapCsrfToken(): Promise<string | null> {
    if (csrfTokenFlight) return csrfTokenFlight;
    csrfTokenFlight = (async () => {
      const value = await readJson('/api/desktop/security', {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
          accept: 'application/json',
        },
      });
      const raw = exactObject(value, ['schema', 'csrf_token']);
      if (raw.schema !== 'nomad.gateway.desktop-security.v1' || !opaque(raw.csrf_token)) invalid();
      return raw.csrf_token;
    })();
    try {
      return await csrfTokenFlight;
    } catch {
      csrfTokenFlight = null;
      return null;
    }
  }

  function invalidateCsrfToken(): void {
    csrfTokenFlight = null;
  }

  async function withCsrfRetry<T>(request: (csrf: string) => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const csrf = await bootstrapCsrfToken();
      if (!opaque(csrf)) {
        throw new DesktopPairingClientError('PAIRING_CSRF_UNAVAILABLE', 'Desktop pairing controls are unavailable until the local Host issues a same-origin CSRF token.');
      }
      try {
        return await request(csrf);
      } catch (error) {
        if (error instanceof DesktopPairingClientError && error.code === 'CSRF_REJECTED' && attempt === 0) {
          invalidateCsrfToken();
          continue;
        }
        throw error;
      }
    }
    throw new DesktopPairingClientError('PAIRING_CSRF_UNAVAILABLE', 'Desktop pairing controls are unavailable until the local Host issues a same-origin CSRF token.');
  }

  async function postJson(path: string, body: unknown): Promise<unknown> {
    return withCsrfRetry((csrf) => readJson(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'X-Nomad-CSRF': csrf,
      },
      body: JSON.stringify(body),
    }, 'CSRF_REJECTED'));
  }

  async function postNoBodyResult(path: string, body: unknown): Promise<void> {
    return withCsrfRetry(async (csrf) => {
      let response: Response;
      try {
        response = await fetchImpl(`${baseUrl}${path}`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            accept: 'application/json',
            'content-type': 'application/json',
            'X-Nomad-CSRF': csrf,
          },
          body: JSON.stringify(body),
        });
      } catch {
        throw new DesktopPairingClientError('PAIRING_NETWORK_ERROR', 'Desktop pairing request failed before an authoritative response was received.');
      }
      if (!response.ok) {
        const errorCode = await readErrorCode(response);
        if (errorCode === 'CSRF_REJECTED') {
          throw new DesktopPairingClientError('CSRF_REJECTED', 'Desktop pairing CSRF protection rejected the current token.');
        }
        throw new DesktopPairingClientError('PAIRING_HTTP_ERROR', `Desktop pairing request failed with HTTP ${response.status}.`);
      }
    });
  }

  return {
    async getCurrentDevice() {
      const value = await postJson('/api/desktop/devices/current', {});
      return decodeCurrentDevice(value);
    },

    async createJoin() {
      const value = await postJson('/api/desktop/pairing/create', {
        schema: 'nomad.m3e.pairing.create.v1',
      });
      return decodeCreatedJoin(value);
    },

    async getJoinStatus(joinId: string) {
      const value = await postJson('/api/desktop/pairing/status', {
        schema: 'nomad.m3e.pairing.status.v1',
        join_id: joinId,
      });
      return decodeJoinStatus(value);
    },

    async approveJoin(input) {
      await postNoBodyResult('/api/desktop/pairing/approve', {
        schema: 'nomad.m3e.pairing.desktop-approve.v1',
        join_id: input.joinId,
        challenge_id: input.challengeId,
        expected_epoch: input.expectedEpoch,
        comparison_code: input.comparisonCode,
      });
    },

    async cancelJoin(joinId: string) {
      await postNoBodyResult('/api/desktop/pairing/cancel', {
        schema: 'nomad.m3e.pairing.cancel.v1',
        join_id: joinId,
      });
    },

    async revokeDevice(input) {
      const value = await postJson('/api/desktop/devices/revoke', {
        device_alias: input.deviceAlias,
        expected_epoch: input.expectedEpoch,
      });
      return decodeRevoke(value);
    },
  };
}

function decodeCurrentDevice(value: unknown): DesktopPairingCurrentDevice {
  const raw = exactObject(value, ['schema', 'principal_alias', 'paired', 'device']);
  if (raw.schema !== 'nomad.product-host.device-current.v1' || typeof raw.principal_alias !== 'string' || typeof raw.paired !== 'boolean') invalid();
  if (raw.device === null) {
    if (raw.paired !== false) invalid();
    return {
      schema: raw.schema,
      principal_alias: raw.principal_alias,
      paired: raw.paired,
      device: null,
    };
  }
  const device = exactObject(raw.device, ['device_alias', 'pairing_epoch']);
  if (typeof device.device_alias !== 'string' || !positiveInt(device.pairing_epoch)) invalid();
  return {
    schema: raw.schema,
    principal_alias: raw.principal_alias,
    paired: raw.paired,
    device: {
      device_alias: device.device_alias,
      pairing_epoch: device.pairing_epoch,
    },
  };
}

function decodeCreatedJoin(value: unknown): DesktopPairingCreatedJoin {
  const raw = exactObject(value, ['schema', 'join_id', 'expires_at', 'join_url']);
  if (raw.schema !== 'nomad.m3e.pairing.desktop-created.v1' || !joinId(raw.join_id) || !timestamp(raw.expires_at) || !joinUrl(raw.join_url, raw.join_id)) invalid();
  return {
    schema: raw.schema,
    join_id: raw.join_id,
    expires_at: raw.expires_at,
    join_url: raw.join_url,
  };
}

function decodeJoinStatus(value: unknown): DesktopPairingJoinStatus {
  const raw = exactObject(value, ['schema', 'join_id', 'state', 'challenge_id', 'expected_epoch', 'comparison_code', 'expires_at']);
  if (raw.schema !== 'nomad.m3e.pairing.status-response.v1' || !joinId(raw.join_id) || !joinState(raw.state) || !timestamp(raw.expires_at)) invalid();
  if (raw.challenge_id !== null && !opaque(raw.challenge_id)) invalid();
  if (raw.expected_epoch !== null && !positiveInt(raw.expected_epoch)) invalid();
  if (raw.comparison_code !== null && (typeof raw.comparison_code !== 'string' || !/^[0-9]{6}$/.test(raw.comparison_code))) invalid();
  return {
    schema: raw.schema,
    join_id: raw.join_id,
    state: raw.state,
    challenge_id: raw.challenge_id,
    expected_epoch: raw.expected_epoch,
    comparison_code: raw.comparison_code,
    expires_at: raw.expires_at,
  };
}

function decodeRevoke(value: unknown): DesktopPairingRevokeResult {
  const raw = exactObject(value, ['schema', 'principal_alias', 'device_alias', 'status', 'prior_epoch', 'revoked_epoch']);
  if (raw.schema !== 'nomad.product-host.device-revoke.v1' || typeof raw.principal_alias !== 'string' || typeof raw.device_alias !== 'string' || !['revoked', 'already_revoked'].includes(String(raw.status)) || !positiveInt(raw.revoked_epoch)) invalid();
  if (raw.prior_epoch !== null && !positiveInt(raw.prior_epoch)) invalid();
  return {
    schema: raw.schema,
    principal_alias: raw.principal_alias,
    device_alias: raw.device_alias,
    status: raw.status === 'revoked' ? 'revoked' : 'already_revoked',
    prior_epoch: raw.prior_epoch,
    revoked_epoch: raw.revoked_epoch,
  };
}

function exactObject(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const raw = value as Record<string, unknown>;
  const actual = Object.keys(raw).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) invalid();
  return raw;
}

async function readErrorCode(response: Response): Promise<string | null> {
  const contentType = response.headers.get('content-type');
  if (contentType === null || !contentType.startsWith('application/json')) return null;
  try {
    const value = await response.json();
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const code = (value as Record<string, unknown>).error;
    return typeof code === 'string' ? code : null;
  } catch {
    return null;
  }
}

function joinId(value: unknown): value is string {
  return typeof value === 'string' && /^join-[0-9a-f]{32}$/.test(value);
}

function joinState(value: unknown): value is DesktopPairingJoinState {
  return typeof value === 'string'
    && [
      'created',
      'started_awaiting_desktop_approval',
      'desktop_approved',
      'provisioned_pending_vault',
      'active',
      'cancelled',
      'expired',
      'compensated',
      'revoked',
    ].includes(value);
}

function positiveInt(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function opaque(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{8,160}$/.test(value);
}

function joinUrl(value: unknown, expectedJoinId: string): value is string {
  if (typeof value !== 'string' || !joinId(expectedJoinId)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:'
      && url.username === ''
      && url.password === ''
      && url.search === ''
      && url.pathname === `/j/${expectedJoinId}`
      && opaque(url.hash.slice(1));
  } catch {
    return false;
  }
}

function invalid(): never {
  throw new DesktopPairingClientError('PAIRING_INVALID_RESPONSE', 'Desktop pairing response is incompatible.');
}
