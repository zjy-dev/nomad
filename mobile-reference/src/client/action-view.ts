import type { ActionView, BrowserCommandCapability, SessionView } from './types';

const STOP_SCOPE = 'Stop the current Agent turn on this Mac' as const;
const DENY_SUMMARY = 'Host reports one protected action pending' as const;
const REPLY_EXPLANATION = 'Reviewable question context is not yet available.' as const;
const ACTIVE_TURN_STATES = new Set(['Running', 'NeedsInput', 'NeedsPermission']);

/** Pure, content-safe composition boundary for official-local controls. */
export function composeActionView(
  view: SessionView,
  binding: BrowserCommandCapability | null,
  now = Date.now(),
): ActionView {
  const state = view.state;
  const needsPermission = state.session.turn_state === 'NeedsPermission';
  const needsInput = state.session.turn_state === 'NeedsInput';
  const activeTurn = ACTIVE_TURN_STATES.has(state.session.turn_state);
  const capabilityReason = capabilityDisabledReason(view, binding, now);
  const capability = capabilityReason ? null : binding?.capability ?? null;
  const replySummary = safeReplySummary(capability?.reply?.summary) ? capability.reply.summary : null;
  const denyExpiry = capability?.deny ? Date.parse(capability.deny.expires_at) : Number.NaN;
  const denyFresh = Number.isFinite(denyExpiry) && denyExpiry > now;

  return {
    deny: {
      visible: needsPermission,
      enabled: needsPermission && capability?.deny !== null && capability?.deny !== undefined && denyFresh,
      disabledReason: !needsPermission
        ? 'No protected action is pending.'
        : capabilityReason
          ?? (capability?.deny == null
            ? 'The current capability does not authorize denying this protected action.'
            : !denyFresh
              ? 'The protected action expired. Refresh and review the latest state.'
              : null),
      summary: DENY_SUMMARY,
      expiresAt: needsPermission && capability?.deny && Number.isFinite(denyExpiry) ? capability.deny.expires_at : null,
    },
    stop: {
      visible: activeTurn,
      enabled: activeTurn && capability?.stop !== null && capability?.stop !== undefined,
      disabledReason: !activeTurn
        ? 'There is no active Agent turn to stop.'
        : capabilityReason
          ?? (capability?.stop == null ? 'The current capability does not authorize Stop.' : null),
      scope: STOP_SCOPE,
    },
    reply: {
      visible: needsInput,
      enabled: needsInput && replySummary !== null,
      disabledReason: needsInput && replySummary !== null
        ? null
        : needsInput
          ? capabilityReason ?? 'Reviewable question context is not yet available. Reply stays disabled until the Host provides a safe question summary.'
        : 'The Host is not waiting for a reply.',
      explanation: replySummary ? 'Your reply goes to this pending request' : REPLY_EXPLANATION,
      prompt: needsInput ? replySummary?.prompt ?? null : null,
    },
  };
}

function capabilityDisabledReason(
  view: SessionView,
  binding: BrowserCommandCapability | null,
  now: number,
): string | null {
  const { session } = view.state;
  if (session.host_connectivity !== 'Online') return 'Local Host is offline. Commands are disabled.';
  if (session.client_freshness !== 'Live') return 'The displayed snapshot is not Live. Commands are disabled.';
  if (view.state.versionStatus !== 'ok') return 'The command protocol is incompatible. Commands are disabled.';
  if (view.state.digestStatus !== 'verified' || !view.state.expectedDigest) {
    return 'The displayed snapshot is not verified. Commands are disabled.';
  }
  if (!binding) return 'No live command capability is available. This view remains read-only.';
  const capability = binding.capability;
  if (capability.allow_once !== false) return 'The command capability is incompatible.';
  if (binding.displaySnapshotSeq !== view.state.lastAppliedSeq
      || binding.displaySnapshotDigest !== view.state.expectedDigest) {
    return 'The displayed snapshot changed. Review it before acting.';
  }
  if (!validFutureWindow(capability.issued_at, capability.expires_at, now)) {
    return 'The command capability expired. Refresh and review the latest state.';
  }
  return null;
}

function validFutureWindow(issuedAt: string, expiresAt: string, now: number): boolean {
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  return Number.isFinite(issued) && Number.isFinite(expires) && issued <= now && expires > now;
}

function safeReplySummary(value: unknown): value is NonNullable<NonNullable<BrowserCommandCapability['capability']['reply']>['summary']> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const summary = value as Record<string, unknown>;
  const keys = Object.keys(summary).sort();
  const expected = ['answer_mode', 'prompt', 'question_count', 'response_hint', 'schema'];
  return keys.length === expected.length && keys.every((key, index) => key === expected[index])
    && summary.schema === 'nomad.product-host.pending-question-summary.v1'
    && summary.question_count === 1 && summary.answer_mode === 'free_text'
    && summary.response_hint === 'single_short_reply' && typeof summary.prompt === 'string'
    && summary.prompt.length > 0 && summary.prompt.length <= 160
    && /^[\x20-\x7E]+$/.test(summary.prompt) && summary.prompt.trim() === summary.prompt;
}
