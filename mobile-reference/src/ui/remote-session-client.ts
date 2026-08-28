import type {
  BrowserCommandCapability,
  CapabilityCommandIntent,
  GatewayCommandReceipt,
  SessionView,
} from '../client/types';
import type { ViewState } from '../contracts/reducer';
import type { ErrorCode, TurnState } from '../contracts/types';
import type { BrowserVaultSession } from '../remote/browser-vault';
import {
  RemoteSessionError,
  type RemotePendingCommand,
  type RemoteSessionConnection,
  type RemoteSessionPort as RuntimeRemoteSessionPort,
  type RemoteSessionSnapshot,
} from '../remote/paired-session';
import type { RemoteSessionPort as UiRemoteSessionPort } from './RemoteSessionPanel';

const REMOTE_SESSION_CSRF = 'remote-session';
const MAX_RECEIPT_POLLS = 3;

export type RemoteSessionFactory = (
  session: BrowserVaultSession,
) => Promise<RuntimeRemoteSessionPort>;

export async function recoverPendingRemoteCommand(
  port: RuntimeRemoteSessionPort,
): Promise<RemoteSessionSnapshot> {
  const snapshot = port.getSnapshot();
  if (snapshot.pending_command === null) {
    return snapshot;
  }
  if (snapshot.pending_command.status === 'OutcomeUnknown') {
    throw new RemoteSessionError(
      'REMOTE_COMMAND_OUTCOME_UNKNOWN',
      'Remote command result is unknown and was not retried.',
    );
  }
  try {
    return await port.retryPending();
  } catch (error) {
    const current = port.getSnapshot();
    if (current.pending_command?.status === 'OutcomeUnknown') {
      throw new RemoteSessionError(
        'REMOTE_COMMAND_OUTCOME_UNKNOWN',
        'Remote command result is unknown and was not retried.',
      );
    }
    if (current.pending_command !== null) {
      throw new RemoteSessionError(
        'REMOTE_COMMAND_PENDING',
        'Remote command is still waiting for an authoritative Host receipt.',
      );
    }
    throw error;
  }
}

export function createRemoteSessionClient(port: RuntimeRemoteSessionPort): UiRemoteSessionPort {
  return {
    mode: 'official-local',
    writable: true,

    async loadCurrentSession() {
      return loadRemoteView(port);
    },

    async refreshSession(_sessionId: string) {
      return loadRemoteView(port);
    },

    async loadCommandCapability() {
      return toCapabilityBinding(port.getSnapshot());
    },

    async submitCapabilityCommand(binding, intent) {
      return submitRemoteCapabilityCommand(port, binding, intent);
    },
  };
}

async function loadRemoteView(port: RuntimeRemoteSessionPort): Promise<SessionView> {
  try {
    const snapshot = await port.poll();
    if (snapshot.connection === 'revoked') {
      throw new RemoteSessionError('DEVICE_REVOKED', 'This paired browser has been revoked.');
    }
    if (snapshot.connection === 'key_lost') {
      throw new RemoteSessionError('KEY_LOST', 'Secure browser device keys were lost; re-pairing is required.');
    }
    const view = snapshotToView(snapshot);
    if (view !== null) {
      return view;
    }
  } catch (error) {
    if (error instanceof RemoteSessionError && (error.code === 'DEVICE_REVOKED' || error.code === 'KEY_LOST')) {
      throw error;
    }
    const fallbackSnapshot = port.getSnapshot();
    if (fallbackSnapshot.connection === 'revoked') {
      throw new RemoteSessionError('DEVICE_REVOKED', 'This paired browser has been revoked.');
    }
    if (fallbackSnapshot.connection === 'key_lost') {
      throw new RemoteSessionError('KEY_LOST', 'Secure browser device keys were lost; re-pairing is required.');
    }
    const fallback = snapshotToView(fallbackSnapshot);
    if (fallback !== null) {
      return fallback;
    }
    throw new RemoteSessionError(
      'REMOTE_PROJECTION_UNAVAILABLE',
      'Remote session projection is not yet available.',
    );
  }
  throw new RemoteSessionError(
    'REMOTE_PROJECTION_UNAVAILABLE',
    'Remote session projection is not yet available.',
  );
}

function snapshotToView(snapshot: RemoteSessionSnapshot): SessionView | null {
  const projection = snapshot.last_good_projection;
  if (projection === null) {
    return null;
  }
  const product = projection.snapshot;
  const capability = projection.capability;
  const activeTurn = capability?.reply?.turn_alias ?? capability?.stop?.turn_alias ?? null;
  const activePermission = capability?.deny?.permission_alias ?? product.snapshot.pending_permission_alias;
  const state: ViewState = {
    session: {
      session_id: product.snapshot.session_alias,
      semantics_version: '1.0.0',
      turn_id: activeTurn,
      turn_state: toTurnState(product.snapshot.turn_state),
      host_connectivity: snapshot.connection === 'unavailable' ? 'Offline' : 'Online',
      client_freshness: freshnessForConnection(snapshot.connection),
      updated_at: product.snapshot.updated_at,
    },
    events: [],
    timeline: [],
    tools: [],
    activePermissionId: activePermission,
    diffFileCount: product.snapshot.diff_file_count,
    lastAppliedSeq: product.snapshot_seq,
    gapToSeq: null,
    digestStatus: 'verified',
    expectedDigest: product.digest,
    actualDigest: product.digest,
    versionStatus: 'ok',
    duplicatesDropped: 0,
    outcomeUnknownTools: [],
  };

  return {
    state,
    display: {
      title: 'Remote session connected',
      hostLabel: product.host_instance_id,
      workspaceLabel: 'Paired phone session',
      lastActivityLabel: lastActivity(snapshot),
    },
    approval: null,
    changes: {
      status: 'unavailable',
      source: null,
      baseline: null,
      files: [],
      reason: 'Remote session view does not expose a verified workspace diff.',
    },
    provenance: 'captured',
    mode: 'official-local',
    writable: true,
  };
}

function toCapabilityBinding(snapshot: RemoteSessionSnapshot): BrowserCommandCapability | null {
  if (snapshot.connection !== 'live' || snapshot.last_good_projection === null || snapshot.pending_command !== null) {
    return null;
  }
  const projection = snapshot.last_good_projection;
  if (projection.capability === null) {
    return null;
  }
  return {
    capability: projection.capability,
    csrfToken: REMOTE_SESSION_CSRF,
    displaySnapshotSeq: projection.snapshot.snapshot_seq,
    displaySnapshotDigest: projection.snapshot.digest,
  };
}

function toRemoteIntent(intent: CapabilityCommandIntent) {
  if (intent.action === 'reply') {
    return { action: 'reply' as const, content: intent.content };
  }
  if (intent.action === 'deny') {
    return { action: 'deny' as const };
  }
  return { action: 'stop' as const };
}

async function submitRemoteCapabilityCommand(
  port: RuntimeRemoteSessionPort,
  binding: BrowserCommandCapability,
  intent: CapabilityCommandIntent,
): Promise<GatewayCommandReceipt> {
  const before = port.getSnapshot();
  let snapshot: RemoteSessionSnapshot;

  try {
    snapshot = await port.dispatch(toRemoteIntent(intent));
  } catch (error) {
    snapshot = await recoverPublishedCommand(port, before, binding, intent, error);
  }

  const expected = identifyExpectedCommand(before, snapshot, binding, intent);
  if (expected === null) {
    throw new RemoteSessionError(
      'REMOTE_COMMAND_UNAVAILABLE',
      'Remote command receipt is unavailable.',
    );
  }

  const immediate = receiptFromSnapshot(snapshot, expected);
  if (immediate !== null) {
    return immediate;
  }

  let current = snapshot;
  for (let attempt = 0; attempt < MAX_RECEIPT_POLLS; attempt += 1) {
    try {
      current = await port.poll();
    } catch {
      current = port.getSnapshot();
    }
    const receipt = receiptFromSnapshot(current, expected);
    if (receipt !== null) {
      return receipt;
    }
    if (current.pending_command?.status === 'OutcomeUnknown' && pendingMatchesCommand(current.pending_command, expected)) {
      throw new RemoteSessionError(
        'REMOTE_COMMAND_OUTCOME_UNKNOWN',
        'Remote command result is unknown and was not retried.',
      );
    }
    if (!pendingMatchesCommand(current.pending_command, expected)) {
      throw new RemoteSessionError(
        'REMOTE_COMMAND_UNAVAILABLE',
        'Remote command receipt is unavailable.',
      );
    }
  }

  throw new RemoteSessionError(
    'REMOTE_COMMAND_PENDING',
    'Remote command is still waiting for an authoritative Host receipt.',
  );
}

async function recoverPublishedCommand(
  port: RuntimeRemoteSessionPort,
  before: RemoteSessionSnapshot,
  binding: BrowserCommandCapability,
  intent: CapabilityCommandIntent,
  error: unknown,
): Promise<RemoteSessionSnapshot> {
  if (!(error instanceof RemoteSessionError) || error.code !== 'PUBLISH_FAILED') {
    throw error;
  }

  const snapshot = port.getSnapshot();
  const expected = identifyExpectedCommand(before, snapshot, binding, intent);
  if (expected === null || !pendingMatchesCommand(snapshot.pending_command, expected)) {
    throw new RemoteSessionError(
      'REMOTE_COMMAND_UNAVAILABLE',
      'Remote command receipt is unavailable.',
    );
  }
  if (snapshot.pending_command.status === 'OutcomeUnknown') {
    throw new RemoteSessionError(
      'REMOTE_COMMAND_OUTCOME_UNKNOWN',
      'Remote command requires authoritative reconciliation before retry.',
    );
  }

  try {
    return await port.retryPending();
  } catch (retryError) {
    const latest = port.getSnapshot();
    const retryExpected = identifyExpectedCommand(before, latest, binding, intent) ?? expected;
    if (latest.pending_command?.status === 'OutcomeUnknown' && pendingMatchesCommand(latest.pending_command, retryExpected)) {
      throw new RemoteSessionError(
        'REMOTE_COMMAND_OUTCOME_UNKNOWN',
        'Remote command result is unknown and was not retried.',
      );
    }
    if (pendingMatchesCommand(latest.pending_command, retryExpected)) {
      throw new RemoteSessionError(
        'REMOTE_COMMAND_PENDING',
        'Remote command is still waiting for an authoritative Host receipt.',
      );
    }
    throw retryError;
  }
}

function identifyExpectedCommand(
  before: RemoteSessionSnapshot,
  snapshot: RemoteSessionSnapshot,
  binding: BrowserCommandCapability,
  intent: CapabilityCommandIntent,
): RemoteCommandExpectation | null {
  const pending = snapshot.pending_command;
  if (pendingMatchesBinding(pending, binding, intent.action)) {
    return {
      requestId: pending.request_id,
      action: intent.action,
      snapshotSeq: binding.displaySnapshotSeq,
      snapshotDigest: binding.displaySnapshotDigest,
    };
  }

  const receipt = snapshot.last_receipt;
  if (
    receipt !== null
    && receipt.action === intent.action
    && receipt.snapshot_seq === binding.displaySnapshotSeq
    && receipt.snapshot_digest === binding.displaySnapshotDigest
    && receipt.request_id !== before.last_receipt?.request_id
  ) {
    return {
      requestId: receipt.request_id,
      action: intent.action,
      snapshotSeq: binding.displaySnapshotSeq,
      snapshotDigest: binding.displaySnapshotDigest,
    };
  }
  return null;
}

interface RemoteCommandExpectation {
  requestId: string;
  action: CapabilityCommandIntent['action'];
  snapshotSeq: number;
  snapshotDigest: string;
}

function receiptFromSnapshot(
  snapshot: RemoteSessionSnapshot,
  expected: RemoteCommandExpectation,
): GatewayCommandReceipt | null {
  if (!receiptMatchesCommand(snapshot.last_receipt, expected)) {
    return null;
  }
  return {
    ...snapshot.last_receipt,
    error_code: normalizeErrorCode(snapshot.last_receipt.error_code),
  };
}

function normalizeErrorCode(value: string | null): ErrorCode | null {
  if (value === null) {
    return null;
  }
  switch (value) {
    case 'OK':
    case 'ERR_REQUEST_EXPIRED':
    case 'ERR_REQUEST_STALE':
    case 'ERR_INCOMPATIBLE_VERSION':
    case 'ERR_REQUEST_REVOKED':
    case 'ERR_DUPLICATE_REQUEST':
    case 'ERR_HOST_OFFLINE':
    case 'ERR_SAFETY_BLOCKED':
    case 'ERR_PERMISSION_DENIED':
    case 'ERR_OUTCOME_UNKNOWN':
      return value;
    case 'ERR_COMMAND_REJECTED':
      return 'ERR_SAFETY_BLOCKED';
    default:
      return 'ERR_SAFETY_BLOCKED';
  }
}

function toTurnState(value: string): TurnState {
  if (isTurnState(value)) {
    return value;
  }
  return 'OutcomeUnknown';
}

function isTurnState(value: string): value is TurnState {
  switch (value) {
    case 'None':
    case 'Running':
    case 'NeedsInput':
    case 'NeedsPermission':
    case 'Stopping':
    case 'Completed':
    case 'Cancelled':
    case 'Failed':
    case 'OutcomeUnknown':
      return true;
    default:
      return false;
  }
}

function freshnessForConnection(connection: RemoteSessionConnection): 'Live' | 'Reconnecting' | 'Stale' {
  if (connection === 'live') {
    return 'Live';
  }
  if (connection === 'reconnecting') {
    return 'Reconnecting';
  }
  return 'Stale';
}

function lastActivity(snapshot: RemoteSessionSnapshot): string {
  if (snapshot.last_receipt !== null) {
    return `Remote command ${snapshot.last_receipt.status}`;
  }
  if (snapshot.pending_command !== null) {
    return `Remote command ${snapshot.pending_command.status}`;
  }
  return snapshot.connection === 'live'
    ? 'Remote state verified'
    : 'Remote state reconnecting';
}

function receiptMatchesCommand(
  receipt: RemoteSessionSnapshot['last_receipt'],
  expected: RemoteCommandExpectation,
): receipt is NonNullable<RemoteSessionSnapshot['last_receipt']> {
  return receipt !== null
    && receipt.request_id === expected.requestId
    && receipt.action === expected.action
    && receipt.snapshot_seq === expected.snapshotSeq
    && receipt.snapshot_digest === expected.snapshotDigest;
}

function pendingMatchesCommand(
  pending: RemotePendingCommand | null,
  expected: RemoteCommandExpectation,
): pending is RemotePendingCommand {
  return pending !== null
    && pending.request_id === expected.requestId
    && pending.action === expected.action
    && pending.snapshot_seq === expected.snapshotSeq
    && pending.snapshot_digest === expected.snapshotDigest;
}

function pendingMatchesBinding(
  pending: RemotePendingCommand | null,
  binding: BrowserCommandCapability,
  action: CapabilityCommandIntent['action'],
): pending is RemotePendingCommand {
  return pending !== null
    && pending.action === action
    && pending.snapshot_seq === binding.displaySnapshotSeq
    && pending.snapshot_digest === binding.displaySnapshotDigest;
}
