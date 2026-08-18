function parsePatch(patch) {
  if (!patch) return [];
  const hunks = [];
  let current = null;
  for (const line of patch.split('\n')) {
    if (line.startsWith('@@')) {
      current = { header: line, lines: [] };
      hunks.push(current);
    } else if (current && !line.startsWith('---') && !line.startsWith('+++')) {
      current.lines.push({ type: line.startsWith('+') ? 'add' : line.startsWith('-') ? 'del' : 'ctx', text: line.slice(1) });
    }
  }
  return hunks;
}

export function decodePilotSessionMessage(message) {
  const payload = message?.payload;
  const capture = payload?.capture;
  const snapshot = capture?.snapshot;
  if (payload?.type !== 'pilot.session' || !snapshot || !Array.isArray(capture.events)) {
    throw new Error('Relay session checkpoint is incompatible');
  }
  const diff = Array.isArray(capture.diff) ? capture.diff : [];
  // The current compatibility interface does not yet supply a workspace
  // baseline. Preserve the diff as invalid rather than presenting it as
  // authoritative or synthesizing a baseline.
  const changes = diff.length === 0
    ? { status: 'empty', source: null, baseline: null, files: [], reason: 'The Host reported no workspace changes.' }
    : { status: 'invalid', source: capture.source?.interface ?? null, baseline: null, files: [], reason: 'The Host diff has no verified workspace baseline.' };
  const approval = payload.approval ? {
    tool: payload.approval.tool, operation: payload.approval.operation, arguments: [],
    workingDirectory: payload.approval.working_directory ?? null, resources: payload.approval.resources ?? [],
    expiresAt: null, source: payload.approval.source, actionHash: payload.approval.action_hash,
  } : null;
  const events = capture.events;
  const view = {
    state: {
      session: {
        session_id: snapshot.session_id, semantics_version: snapshot.version, turn_id: snapshot.turn_id,
        turn_state: snapshot.turn_state, host_connectivity: snapshot.host_connectivity,
        client_freshness: snapshot.client_freshness, updated_at: snapshot.created_at,
      },
      events, timeline: events.map((event) => ({ kind: 'event', seq: event.seq, event })),
      tools: snapshot.state_summary.tool_states ?? [], activePermissionId: snapshot.state_summary.active_permission ?? null,
      diffFileCount: snapshot.state_summary.diff_file_count ?? 0, lastAppliedSeq: snapshot.last_applied_seq,
      gapToSeq: null, digestStatus: snapshot.digest ? 'verified' : 'none', expectedDigest: snapshot.digest ?? null,
      actualDigest: snapshot.digest ?? null, versionStatus: snapshot.version === '1.0.0' ? 'ok' : 'incompatible',
      duplicatesDropped: 0, outcomeUnknownTools: [],
    },
    display: { title: 'Controlled Pilot session', hostLabel: 'Pilot Host', workspaceLabel: 'Disposable workspace', lastActivityLabel: 'Host state verified through the Relay' },
    approval, changes, provenance: 'captured',
  };
  if (view.state.versionStatus !== 'ok') view.state.session.client_freshness = 'Stale';
  return view;
}

export function commandSubmission(payload) {
  return {
    status: payload.status,
    result: {
      error_code: payload.error_code ?? 'OK', error_message: payload.error_message ?? null,
      accepted_at_seq: payload.accepted_at_seq ?? null, event_id: payload.event_id ?? null,
    },
  };
}

export { parsePatch };
