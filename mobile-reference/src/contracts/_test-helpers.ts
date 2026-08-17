/**
 * Shared helpers for loading golden snapshots into tests.
 * Mirrors the fixture data from contracts/traces/snapshot-*.json.
 *
 * Generated from canonical JSON of the actual trace files.
 * DO NOT EDIT BY HAND — re-run the generation script if traces change.
 */

export interface SnapshotFixture {
  file: string;
  snapshot: Record<string, unknown>;
}

const GOLDEN: SnapshotFixture[] = [
  {
    file: 'snapshot-001-normal-completion.json',
    snapshot: {
      session_id: 'sess_normal_001',
      snapshot_seq: 8,
      digest: 'sha256:4fb346fe6f74d1757fe55d3526004f2e5d1683b152dcbc9f72d74e81b7aae59f',
      last_applied_seq: 8,
      turn_state: 'Completed',
      turn_id: 'turn_001',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: null,
        active_permission: null,
        diff_file_count: 3,
        test_status: null,
        tool_states: [
          { tool_name: 'grep', status: 'Completed' },
          { tool_name: 'edit', status: 'Completed' },
        ],
      },
      created_at: '2026-08-17T10:00:10Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-002-reply.json',
    snapshot: {
      session_id: 'sess_reply_002',
      snapshot_seq: 12,
      digest: 'sha256:143526e3a9ad9ef174feb1dbc6d8bce3c04c97c6328df14e20d5b8042493c237',
      last_applied_seq: 12,
      turn_state: 'Completed',
      turn_id: 'turn_002',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: null,
        active_permission: null,
        diff_file_count: 1,
        test_status: null,
        tool_states: [
          { tool_name: 'grep', status: 'Completed' },
          { tool_name: 'edit', status: 'Completed' },
        ],
      },
      created_at: '2026-08-17T11:00:17Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-003-stop.json',
    snapshot: {
      session_id: 'sess_stop_003',
      snapshot_seq: 8,
      digest: 'sha256:9f4c772078dd3ac6d4567dd32c5cf50ee4ad0c3e78ff12907db3cf75572acf34',
      last_applied_seq: 8,
      turn_state: 'Cancelled',
      turn_id: 'turn_001',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: null,
        active_permission: null,
        diff_file_count: 0,
        test_status: null,
        tool_states: [
          { tool_name: 'grep', status: 'Completed' },
          { tool_name: 'edit', status: 'Failed' },
        ],
      },
      created_at: '2026-08-17T12:00:07Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-004-permission-competition.json',
    snapshot: {
      session_id: 'sess_perm_004',
      snapshot_seq: 8,
      digest: 'sha256:8f24069204370ce3575ea15ef30d33f32f9eaa24e297980fd7181a34458c5820',
      last_applied_seq: 8,
      turn_state: 'Completed',
      turn_id: 'turn_001',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: null,
        active_permission: null,
        diff_file_count: 1,
        test_status: null,
        tool_states: [{ tool_name: 'edit', status: 'Completed' }],
      },
      created_at: '2026-08-17T13:00:08Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-005-reconnect.json',
    snapshot: {
      session_id: 'sess_reconnect_005',
      snapshot_seq: 8,
      digest: 'sha256:4e0704648415b9c94cf83765487db189446a117258bb045f2d685e89abfce9da',
      last_applied_seq: 8,
      turn_state: 'Completed',
      turn_id: 'turn_001',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: null,
        active_permission: null,
        diff_file_count: 2,
        test_status: null,
        tool_states: [
          { tool_name: 'grep', status: 'Completed' },
          { tool_name: 'edit', status: 'Completed' },
        ],
      },
      created_at: '2026-08-17T14:00:07Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-006-compaction.json',
    snapshot: {
      session_id: 'sess_compact_006',
      snapshot_seq: 10,
      digest: 'sha256:0e819c22617e5698899bc7dd4c6e706037cfd4b86ce282a0de41c0525a12fcb6',
      last_applied_seq: 10,
      turn_state: 'Completed',
      turn_id: 'turn_002',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: null,
        active_permission: null,
        diff_file_count: 1,
        test_status: null,
        tool_states: [
          { tool_name: 'grep', status: 'Completed' },
          { tool_name: 'edit', status: 'Completed' },
        ],
      },
      created_at: '2026-08-17T15:00:10Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-007-version-mismatch.json',
    snapshot: {
      session_id: 'sess_ver_007',
      snapshot_seq: 2,
      digest: 'sha256:9daf098764db7769a3b42e057e2f9a50a86c0e7cb14880553497a7b18e2d18b1',
      last_applied_seq: 2,
      turn_state: 'Running',
      turn_id: 'turn_001',
      host_connectivity: 'Online',
      client_freshness: 'Stale',
      state_summary: {
        session_status: 'active',
        active_turn: 'turn_001',
        active_permission: null,
        diff_file_count: 0,
        test_status: null,
        tool_states: [],
      },
      created_at: '2026-08-17T16:00:01Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-008-outcome-unknown.json',
    snapshot: {
      session_id: 'sess_unknown_008',
      snapshot_seq: 7,
      digest: 'sha256:095f1efa581a4b466d72bcedbdbf098691dead30d4fddf3dd6e805a5d4ee7ba6',
      last_applied_seq: 7,
      turn_state: 'OutcomeUnknown',
      turn_id: 'turn_001',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: 'turn_001',
        active_permission: null,
        diff_file_count: 1,
        test_status: null,
        tool_states: [
          { tool_name: 'edit', status: 'Completed' },
          { tool_name: 'run_tests', status: 'Failed' },
        ],
      },
      created_at: '2026-08-17T17:00:30Z',
      version: '1.0.0',
    },
  },
  {
    file: 'snapshot-009-interrupt-and-send.json',
    snapshot: {
      session_id: 'sess_interrupt_009',
      snapshot_seq: 8,
      digest: 'sha256:c74049c4c79f11eba7be1c22e858c40940d69a585e6b121e8264ece2771196b1',
      last_applied_seq: 8,
      turn_state: 'Running',
      turn_id: 'turn_new',
      host_connectivity: 'Online',
      client_freshness: 'Live',
      state_summary: {
        session_status: 'active',
        active_turn: 'turn_new',
        active_permission: null,
        diff_file_count: 0,
        test_status: null,
        tool_states: [{ tool_name: 'grep', status: 'Failed' }],
      },
      created_at: '2026-08-17T18:00:07Z',
      version: '1.0.0',
    },
  },
];

export function loadAllGoldenSnapshots(): SnapshotFixture[] {
  return GOLDEN.map((g) => ({
    file: g.file,
    snapshot: JSON.parse(JSON.stringify(g.snapshot)),
  }));
}

export function loadGoldenSnapshot(file: string): SnapshotFixture {
  const hit = GOLDEN.find((g) => g.file === file);
  if (!hit) throw new Error(`Unknown golden snapshot file: ${file}`);
  return { file: hit.file, snapshot: JSON.parse(JSON.stringify(hit.snapshot)) };
}
