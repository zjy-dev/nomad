// Auto-generated from contracts/traces/*.json — do not hand-edit.

export const MANIFEST = {
  "corpus_version": "1.0.0",
  "generated_at": "2026-08-17T00:00:00Z",
  "contract_version": "1.0.0",
  "traces": [
    {
      "id": "trace-001-normal-completion",
      "title": "Normal task completion",
      "description": "Session started, turn runs, tool calls succeed, turn completes normally.",
      "scenario": "normal_completion",
      "file": "trace-001-normal-completion.json",
      "expected_snapshot": "snapshot-001-normal-completion.json",
      "covered_requirements": [
        "HC-02",
        "SP-01"
      ]
    },
    {
      "id": "trace-002-reply",
      "title": "Mobile reply to agent question",
      "description": "Agent asks for input, user replies from mobile, message accepted and completed.",
      "scenario": "reply",
      "file": "trace-002-reply.json",
      "expected_snapshot": "snapshot-002-reply.json",
      "covered_requirements": [
        "HC-02",
        "MB-05",
        "SP-03"
      ]
    },
    {
      "id": "trace-003-stop",
      "title": "Stop a running turn",
      "description": "User sends Stop while turn is Running. Host accepts, turn transitions Stopping->Cancelled.",
      "scenario": "stop",
      "file": "trace-003-stop.json",
      "expected_snapshot": "snapshot-003-stop.json",
      "covered_requirements": [
        "HC-02",
        "HC-04",
        "MB-05",
        "SP-03"
      ]
    },
    {
      "id": "trace-004-permission-competition",
      "title": "Permission request with competing decisions",
      "description": "Permission requested, two mobile decisions arrive. First valid decision wins, second is rejected as stale.",
      "scenario": "permission_competition",
      "file": "trace-004-permission-competition.json",
      "expected_snapshot": "snapshot-004-permission-competition.json",
      "covered_requirements": [
        "HC-04",
        "MB-03",
        "SP-03"
      ]
    },
    {
      "id": "trace-005-reconnect",
      "title": "Reconnect after network interruption",
      "description": "Client disconnects, reconnects with last_applied_seq, receives missing events, converges to Live.",
      "scenario": "reconnect",
      "file": "trace-005-reconnect.json",
      "expected_snapshot": "snapshot-005-reconnect.json",
      "covered_requirements": [
        "HC-02",
        "SP-02"
      ]
    },
    {
      "id": "trace-006-compaction",
      "title": "Recovery after compaction boundary",
      "description": "Old events compacted away. Client recovers from snapshot at compaction boundary without full event replay.",
      "scenario": "compaction",
      "file": "trace-006-compaction.json",
      "expected_snapshot": "snapshot-006-compaction.json",
      "covered_requirements": [
        "SP-02",
        "INV-004-4"
      ]
    },
    {
      "id": "trace-007-version-mismatch",
      "title": "Protocol version incompatibility",
      "description": "Older client attempts recovery with newer Host. ERR_VERSION_INCOMPATIBLE returned. Safe operations blocked.",
      "scenario": "version_mismatch",
      "file": "trace-007-version-mismatch.json",
      "expected_snapshot": "snapshot-007-version-mismatch.json",
      "covered_requirements": [
        "SP-07",
        "INV-004-5"
      ]
    },
    {
      "id": "trace-008-outcome-unknown",
      "title": "OutcomeUnknown after crash during writable tool",
      "description": "Host crashes after tool execution but before durable event write. On restart, tool state is OutcomeUnknown. No auto-retry.",
      "scenario": "outcome_unknown",
      "file": "trace-008-outcome-unknown.json",
      "expected_snapshot": "snapshot-008-outcome-unknown.json",
      "covered_requirements": [
        "HC-02",
        "HC-04",
        "INV-003-4"
      ]
    },
    {
      "id": "trace-009-interrupt-and-send",
      "title": "Interrupt and send new message",
      "description": "User sends interrupt_and_send: old turn goes Stopping->Cancelled, then new message accepted and new turn started.",
      "scenario": "interrupt_and_send",
      "file": "trace-009-interrupt-and-send.json",
      "expected_snapshot": "snapshot-009-interrupt-and-send.json",
      "covered_requirements": [
        "HC-02",
        "HC-04",
        "MB-05",
        "SP-03",
        "INV-003-6"
      ]
    }
  ]
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const RAW: Record<string, any> = {
  "trace-001-normal-completion": {
    trace: {
      "trace_id": "trace-001-normal-completion",
      "scenario": "normal_completion",
      "description": "Session started, turn runs, tool calls succeed, turn completes normally.",
      "contract_version": "1.0.0",
      "session_id": "sess_normal_001",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_normal_001",
                  "turn_id": null,
                  "event_id": "sess_normal_001:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T10:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T10:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T10:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T10:00:05Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T10:00:06Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T10:00:08Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "diff.updated",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T10:00:09Z",
                  "durable": true,
                  "payload": {
                        "summary": "3 files changed",
                        "state_change": "diff updated"
                  }
            },
            {
                  "event_type": "turn.completed",
                  "session_id": "sess_normal_001",
                  "turn_id": "turn_001",
                  "event_id": "sess_normal_001:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T10:00:10Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn completed"
                  }
            }
      ],
      "expected_snapshot_ref": "snapshot-001-normal-completion.json",
      "notes": "All 7 event invariants must pass: seq monotonic, durable=true, event_id unique, delta loss recoverable from durable events."
},
    snapshot: {
      "session_id": "sess_normal_001",
      "snapshot_seq": 8,
      "digest": "sha256:4fb346fe6f74d1757fe55d3526004f2e5d1683b152dcbc9f72d74e81b7aae59f",
      "last_applied_seq": 8,
      "turn_state": "Completed",
      "turn_id": "turn_001",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": null,
            "active_permission": null,
            "diff_file_count": 3,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "grep",
                        "status": "Completed"
                  },
                  {
                        "tool_name": "edit",
                        "status": "Completed"
                  }
            ]
      },
      "created_at": "2026-08-17T10:00:10Z",
      "version": "1.0.0"
}
  },
  "trace-002-reply": {
    trace: {
      "trace_id": "trace-002-reply",
      "scenario": "reply",
      "description": "Agent asks for input, user replies from mobile, message accepted and completed.",
      "contract_version": "1.0.0",
      "session_id": "sess_reply_002",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_reply_002",
                  "turn_id": null,
                  "event_id": "sess_reply_002:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T11:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_001",
                  "event_id": "sess_reply_002:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T11:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_001",
                  "event_id": "sess_reply_002:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T11:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_001",
                  "event_id": "sess_reply_002:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T11:00:03Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "turn.completed",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_001",
                  "event_id": "sess_reply_002:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T11:00:04Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn completed, agent needs input"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T11:00:10Z",
                  "durable": true,
                  "payload": {
                        "state_change": "user reply started new turn"
                  }
            },
            {
                  "event_type": "message.accepted",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T11:00:11Z",
                  "durable": true,
                  "payload": {
                        "summary": "user replied",
                        "state_change": "message accepted"
                  }
            },
            {
                  "event_type": "message.completed",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T11:00:12Z",
                  "durable": true,
                  "payload": {
                        "state_change": "message completed"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:9",
                  "seq": 9,
                  "timestamp": "2026-08-17T11:00:13Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:10",
                  "seq": 10,
                  "timestamp": "2026-08-17T11:00:15Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "diff.updated",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:11",
                  "seq": 11,
                  "timestamp": "2026-08-17T11:00:16Z",
                  "durable": true,
                  "payload": {
                        "summary": "1 file changed",
                        "state_change": "diff updated"
                  }
            },
            {
                  "event_type": "turn.completed",
                  "session_id": "sess_reply_002",
                  "turn_id": "turn_002",
                  "event_id": "sess_reply_002:12",
                  "seq": 12,
                  "timestamp": "2026-08-17T11:00:17Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn completed"
                  }
            }
      ],
      "expected_snapshot_ref": "snapshot-002-reply.json",
      "notes": "Demonstrates two turns in one session. Completed turn_001 does not prevent new turn_002. Reply command idempotency: same request_id appears only once in HostAccepted state."
},
    snapshot: {
      "session_id": "sess_reply_002",
      "snapshot_seq": 12,
      "digest": "sha256:143526e3a9ad9ef174feb1dbc6d8bce3c04c97c6328df14e20d5b8042493c237",
      "last_applied_seq": 12,
      "turn_state": "Completed",
      "turn_id": "turn_002",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": null,
            "active_permission": null,
            "diff_file_count": 1,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "grep",
                        "status": "Completed"
                  },
                  {
                        "tool_name": "edit",
                        "status": "Completed"
                  }
            ]
      },
      "created_at": "2026-08-17T11:00:17Z",
      "version": "1.0.0"
}
  },
  "trace-003-stop": {
    trace: {
      "trace_id": "trace-003-stop",
      "scenario": "stop",
      "description": "User sends Stop while turn is Running. Host accepts, turn transitions Stopping->Cancelled.",
      "contract_version": "1.0.0",
      "session_id": "sess_stop_003",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_stop_003",
                  "turn_id": null,
                  "event_id": "sess_stop_003:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T12:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T12:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T12:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T12:00:03Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T12:00:04Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "turn.stopping",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T12:00:05Z",
                  "durable": true,
                  "payload": {
                        "state_change": "stop command accepted"
                  }
            },
            {
                  "event_type": "tool.failed",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T12:00:06Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "reason": "stopped by user",
                        "state_change": "tool failed (stopped)"
                  }
            },
            {
                  "event_type": "turn.cancelled",
                  "session_id": "sess_stop_003",
                  "turn_id": "turn_001",
                  "event_id": "sess_stop_003:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T12:00:07Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn cancelled"
                  }
            }
      ],
      "expected_snapshot_ref": "snapshot-003-stop.json",
      "notes": "Stop command lifecycle: RelayReceived -> HostAccepted -> Executing -> Cancelled. tool.failed (seq 7) is not the same as turn.failed. Turn goes through Stopping (seq 6) then Cancelled (seq 8). No duplicate Host acceptance for same request_id."
},
    snapshot: {
      "session_id": "sess_stop_003",
      "snapshot_seq": 8,
      "digest": "sha256:9f4c772078dd3ac6d4567dd32c5cf50ee4ad0c3e78ff12907db3cf75572acf34",
      "last_applied_seq": 8,
      "turn_state": "Cancelled",
      "turn_id": "turn_001",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": null,
            "active_permission": null,
            "diff_file_count": 0,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "grep",
                        "status": "Completed"
                  },
                  {
                        "tool_name": "edit",
                        "status": "Failed"
                  }
            ]
      },
      "created_at": "2026-08-17T12:00:07Z",
      "version": "1.0.0"
}
  },
  "trace-004-permission-competition": {
    trace: {
      "trace_id": "trace-004-permission-competition",
      "scenario": "permission_competition",
      "description": "Permission requested, two mobile decisions arrive. First valid decision wins, second is rejected as stale.",
      "contract_version": "1.0.0",
      "session_id": "sess_perm_004",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_perm_004",
                  "turn_id": null,
                  "event_id": "sess_perm_004:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T13:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T13:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "permission.requested",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T13:00:02Z",
                  "durable": true,
                  "payload": {
                        "permission_id": "perm_001",
                        "action": "edit /src/main.py",
                        "state_change": "permission requested"
                  }
            },
            {
                  "event_type": "permission.resolved",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T13:00:03Z",
                  "durable": true,
                  "payload": {
                        "permission_id": "perm_001",
                        "action": "allow_once",
                        "state_change": "permission resolved by device_A"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T13:00:04Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started after permission allow"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T13:00:06Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "diff.updated",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T13:00:07Z",
                  "durable": true,
                  "payload": {
                        "summary": "1 file changed",
                        "state_change": "diff updated"
                  }
            },
            {
                  "event_type": "turn.completed",
                  "session_id": "sess_perm_004",
                  "turn_id": "turn_001",
                  "event_id": "sess_perm_004:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T13:00:08Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn completed"
                  }
            }
      ],
      "command_exchanges": [
            {
                  "command_type": "permission_decision",
                  "request_id": "req_perm_allow_A",
                  "session_id": "sess_perm_004",
                  "seq": 3,
                  "permission_id": "perm_001",
                  "decision": "allow_once",
                  "action_hash": "sha256:abc123",
                  "status": "Completed",
                  "result": {
                        "resolved_at_seq": 4,
                        "event_id": "sess_perm_004:4",
                        "error_code": "OK"
                  }
            },
            {
                  "command_type": "permission_decision",
                  "request_id": "req_perm_allow_B",
                  "session_id": "sess_perm_004",
                  "seq": 3,
                  "permission_id": "perm_001",
                  "decision": "deny",
                  "action_hash": "sha256:abc123",
                  "status": "Stale",
                  "result": {
                        "resolved_at_seq": null,
                        "event_id": null,
                        "error_code": "ERR_REQUEST_STALE",
                        "error_message": "Permission already resolved by another device"
                  }
            }
      ],
      "expected_snapshot_ref": "snapshot-004-permission-competition.json",
      "notes": "Second permission_decision (req_perm_allow_B) is a Stale rejection. The Host only resolved once (seq 4), demonstrating INV-003-1 (same permission_id resolved only once). The command exchange shows the rejection result explicitly."
},
    snapshot: {
      "session_id": "sess_perm_004",
      "snapshot_seq": 8,
      "digest": "sha256:8f24069204370ce3575ea15ef30d33f32f9eaa24e297980fd7181a34458c5820",
      "last_applied_seq": 8,
      "turn_state": "Completed",
      "turn_id": "turn_001",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": null,
            "active_permission": null,
            "diff_file_count": 1,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "edit",
                        "status": "Completed"
                  }
            ]
      },
      "created_at": "2026-08-17T13:00:08Z",
      "version": "1.0.0"
}
  },
  "trace-005-reconnect": {
    trace: {
      "trace_id": "trace-005-reconnect",
      "scenario": "reconnect",
      "description": "Client disconnects, reconnects with last_applied_seq, receives missing events, converges to Live.",
      "contract_version": "1.0.0",
      "session_id": "sess_reconnect_005",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_reconnect_005",
                  "turn_id": null,
                  "event_id": "sess_reconnect_005:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T14:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T14:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T14:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T14:00:03Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T14:00:04Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "diff.updated",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T14:00:05Z",
                  "durable": true,
                  "payload": {
                        "summary": "2 files changed",
                        "state_change": "diff updated"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T14:00:06Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "turn.completed",
                  "session_id": "sess_reconnect_005",
                  "turn_id": "turn_001",
                  "event_id": "sess_reconnect_005:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T14:00:07Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn completed"
                  }
            }
      ],
      "reconnect_scenarios": [
            {
                  "description": "Client disconnected after seq 4, reconnects with last_applied_seq=4. Receives events 5-8.",
                  "last_applied_seq_before": 4,
                  "events_received": [
                        5,
                        6,
                        7,
                        8
                  ],
                  "result_code": "OK",
                  "gap_from_seq": null,
                  "gap_to_seq": null,
                  "freshness_after": "Live"
            },
            {
                  "description": "Full client: already has all events 1-8. No gap. Resumes directly to Live.",
                  "last_applied_seq_before": 8,
                  "events_received": [],
                  "result_code": "OK",
                  "gap_from_seq": null,
                  "gap_to_seq": null,
                  "freshness_after": "Live"
            }
      ],
      "expected_snapshot_ref": "snapshot-005-reconnect.json",
      "notes": "Reconnect gap handling: client with last_applied_seq=4 receives events 5-8, reducer produces identical snapshot. Client with last_applied_seq=8 has empty gap and transitions to Live immediately. Both converge to the same snapshot."
},
    snapshot: {
      "session_id": "sess_reconnect_005",
      "snapshot_seq": 8,
      "digest": "sha256:4e0704648415b9c94cf83765487db189446a117258bb045f2d685e89abfce9da",
      "last_applied_seq": 8,
      "turn_state": "Completed",
      "turn_id": "turn_001",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": null,
            "active_permission": null,
            "diff_file_count": 2,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "grep",
                        "status": "Completed"
                  },
                  {
                        "tool_name": "edit",
                        "status": "Completed"
                  }
            ]
      },
      "created_at": "2026-08-17T14:00:07Z",
      "version": "1.0.0"
}
  },
  "trace-006-compaction": {
    trace: {
      "trace_id": "trace-006-compaction",
      "scenario": "compaction",
      "description": "Old events compacted away. Client recovers from snapshot at compaction boundary without full event replay.",
      "contract_version": "1.0.0",
      "session_id": "sess_compact_006",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_compact_006",
                  "turn_id": null,
                  "event_id": "sess_compact_006:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T15:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_001",
                  "event_id": "sess_compact_006:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T15:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_001",
                  "event_id": "sess_compact_006:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T15:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_001",
                  "event_id": "sess_compact_006:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T15:00:03Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "session.compacted",
                  "session_id": "sess_compact_006",
                  "turn_id": null,
                  "event_id": "sess_compact_006:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T15:00:05Z",
                  "durable": true,
                  "payload": {
                        "state_change": "compaction boundary set at seq 5",
                        "summary": "Events seq<5 removed, snapshot at seq 5 retained"
                  }
            },
            {
                  "event_type": "session.updated",
                  "session_id": "sess_compact_006",
                  "turn_id": null,
                  "event_id": "sess_compact_006:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T15:00:06Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session updated after compaction"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_002",
                  "event_id": "sess_compact_006:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T15:00:07Z",
                  "durable": true,
                  "payload": {
                        "state_change": "new turn started after compaction"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_002",
                  "event_id": "sess_compact_006:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T15:00:08Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_002",
                  "event_id": "sess_compact_006:9",
                  "seq": 9,
                  "timestamp": "2026-08-17T15:00:09Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "turn.completed",
                  "session_id": "sess_compact_006",
                  "turn_id": "turn_002",
                  "event_id": "sess_compact_006:10",
                  "seq": 10,
                  "timestamp": "2026-08-17T15:00:10Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn completed"
                  }
            }
      ],
      "compaction_scenarios": [
            {
                  "description": "Client with last_applied_seq=1 (before compaction boundary seq=5). Only events >=5 are available. Recovery uses snapshot at compaction boundary.",
                  "last_applied_seq_before": 1,
                  "events_available": [
                        5,
                        6,
                        7,
                        8,
                        9,
                        10
                  ],
                  "compaction_boundary_seq": 5,
                  "result_code": "OK",
                  "notes": "Events 1-4 are compacted. Snapshot at seq 5 is authoritative. Client recovers via snapshot + events [6..10], not via replaying events [1..4]."
            },
            {
                  "description": "Retention exceeded: client last_applied_seq=0, compaction_boundary_seq=5, retention_window=10. 0 < 5-10 is false, but 0 < 5 means event gap is beyond recovery. ERR_RETENTION_EXCEEDED should fire in extreme cases.",
                  "last_applied_seq_before": 0,
                  "events_available": [
                        5,
                        6,
                        7,
                        8,
                        9,
                        10
                  ],
                  "compaction_boundary_seq": 5,
                  "result_code": "OK",
                  "notes": "Client can still recover from snapshot at compaction boundary. ERR_RETENTION_EXCEEDED would fire if compaction_boundary_seq - last_applied_seq > retention_window, but this is a manageable case."
            }
      ],
      "expected_snapshot_ref": "snapshot-006-compaction.json",
      "notes": "INV-004-4: compaction boundary. Events seq<5 removed; snapshot at seq 5 is retained; events seq>=5 available for incremental catch-up."
},
    snapshot: {
      "session_id": "sess_compact_006",
      "snapshot_seq": 10,
      "digest": "sha256:0e819c22617e5698899bc7dd4c6e706037cfd4b86ce282a0de41c0525a12fcb6",
      "last_applied_seq": 10,
      "turn_state": "Completed",
      "turn_id": "turn_002",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": null,
            "active_permission": null,
            "diff_file_count": 1,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "grep",
                        "status": "Completed"
                  },
                  {
                        "tool_name": "edit",
                        "status": "Completed"
                  }
            ]
      },
      "created_at": "2026-08-17T15:00:10Z",
      "version": "1.0.0"
}
  },
  "trace-007-version-mismatch": {
    trace: {
      "trace_id": "trace-007-version-mismatch",
      "scenario": "version_mismatch",
      "description": "Older client attempts recovery with newer Host. ERR_VERSION_INCOMPATIBLE returned. Safe operations blocked.",
      "contract_version": "1.0.0",
      "session_id": "sess_ver_007",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_ver_007",
                  "turn_id": null,
                  "event_id": "sess_ver_007:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T16:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_ver_007",
                  "turn_id": "turn_001",
                  "event_id": "sess_ver_007:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T16:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            }
      ],
      "version_negotiation": {
            "host_semantics_version": "1.0.0",
            "client_semantics_version": "0.9.0",
            "minimum_supported": "1.0.0",
            "result": "ERR_VERSION_INCOMPATIBLE",
            "blocked_operations": [
                  "approval",
                  "stop",
                  "reply"
            ],
            "notes": "Client version 0.9.0 < minimum_supported 1.0.0. Host returns ERR_VERSION_INCOMPATIBLE. Client must upgrade before safe operations are allowed."
      },
      "recovery_result": {
            "result_code": "ERR_VERSION_INCOMPATIBLE",
            "session_id": "sess_ver_007",
            "error_message": "Protocol version 0.9.0 is incompatible. Minimum supported: 1.0.0. Please upgrade the client."
      },
      "expected_snapshot_ref": "snapshot-007-version-mismatch.json",
      "notes": "INV-004-5: version incompatibility blocks safe operations. Client transitions to read-only/stale state."
},
    snapshot: {
      "session_id": "sess_ver_007",
      "snapshot_seq": 2,
      "digest": "sha256:26200def4af099b67f3f3753d608e80008acd335c4b5b497c61c0ea3c25f99f5",
      "last_applied_seq": 2,
      "turn_state": "Running",
      "turn_id": "turn_001",
      "host_connectivity": "Online",
      "client_freshness": "Stale",
      "state_summary": {
            "session_status": "active",
            "active_turn": "turn_001",
            "active_permission": null,
            "diff_file_count": 0,
            "test_status": null,
            "tool_states": []
      },
      "created_at": "2026-08-17T16:00:01Z",
      "version": "1.0.0",
      "notes": "client_freshness=Stale because version mismatch prevents validation. Approval and Stop are blocked."
}
  },
  "trace-008-outcome-unknown": {
    trace: {
      "trace_id": "trace-008-outcome-unknown",
      "scenario": "outcome_unknown",
      "description": "Host crashes after tool execution but before durable event write. On restart, tool state is OutcomeUnknown. No auto-retry.",
      "contract_version": "1.0.0",
      "session_id": "sess_unknown_008",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_unknown_008",
                  "turn_id": null,
                  "event_id": "sess_unknown_008:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T17:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_unknown_008",
                  "turn_id": "turn_001",
                  "event_id": "sess_unknown_008:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T17:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_unknown_008",
                  "turn_id": "turn_001",
                  "event_id": "sess_unknown_008:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T17:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool started (writable)"
                  }
            },
            {
                  "event_type": "tool.completed",
                  "session_id": "sess_unknown_008",
                  "turn_id": "turn_001",
                  "event_id": "sess_unknown_008:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T17:00:03Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "edit",
                        "state_change": "tool completed"
                  }
            },
            {
                  "event_type": "diff.updated",
                  "session_id": "sess_unknown_008",
                  "turn_id": "turn_001",
                  "event_id": "sess_unknown_008:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T17:00:04Z",
                  "durable": true,
                  "payload": {
                        "summary": "file created",
                        "state_change": "diff updated"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_unknown_008",
                  "turn_id": "turn_001",
                  "event_id": "sess_unknown_008:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T17:00:05Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "run_tests",
                        "state_change": "tool started (writable, crash window)"
                  }
            },
            {
                  "event_type": "turn.outcome_unknown",
                  "session_id": "sess_unknown_008",
                  "turn_id": "turn_001",
                  "event_id": "sess_unknown_008:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T17:00:30Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "run_tests",
                        "state_change": "tool completed but result not durably recorded",
                        "reason": "host crashed in crash window; tool may have produced side effects"
                  }
            }
      ],
      "crash_recovery": {
            "description": "Host restart after crash during writable tool execution.",
            "crashed_at_seq": 6,
            "recovered_state": "OutcomeUnknown",
            "auto_retry_attempted": false,
            "user_notified": true,
            "notes": "INV-003-4: Auto-retry is FORBIDDEN. The tool may have modified the filesystem but the Host could not confirm. turn.outcome_unknown is emitted with reason explaining the crash window. User must manually inspect and decide next action."
      },
      "expected_snapshot_ref": "snapshot-008-outcome-unknown.json",
      "notes": "INV-001-6: OutcomeUnknown->Running would mean a new user-initiated turn, NOT a retry of the original side effect. No auto-retry on OutcomeUnknown."
},
    snapshot: {
      "session_id": "sess_unknown_008",
      "snapshot_seq": 7,
      "digest": "sha256:deca3af86ceffe314f7ac56552f0b34f7bf5f0ac360b7403d7277a0b81334840",
      "last_applied_seq": 7,
      "turn_state": "OutcomeUnknown",
      "turn_id": "turn_001",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": "turn_001",
            "active_permission": null,
            "diff_file_count": 1,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "edit",
                        "status": "Completed"
                  },
                  {
                        "tool_name": "run_tests",
                        "status": "Failed"
                  }
            ]
      },
      "created_at": "2026-08-17T17:00:30Z",
      "version": "1.0.0",
      "notes": "turn_state=OutcomeUnknown. The run_tests tool status shows Failed (mapped from turn.outcome_unknown). The user must manually investigate. No auto-retry."
}
  },
  "trace-009-interrupt-and-send": {
    trace: {
      "trace_id": "trace-009-interrupt-and-send",
      "scenario": "interrupt_and_send",
      "description": "User sends interrupt_and_send: old turn goes Stopping->Cancelled, then new message accepted and new turn started.",
      "contract_version": "1.0.0",
      "session_id": "sess_interrupt_009",
      "events": [
            {
                  "event_type": "session.created",
                  "session_id": "sess_interrupt_009",
                  "turn_id": null,
                  "event_id": "sess_interrupt_009:1",
                  "seq": 1,
                  "timestamp": "2026-08-17T18:00:00Z",
                  "durable": true,
                  "payload": {
                        "state_change": "session created"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_interrupt_009",
                  "turn_id": "turn_old",
                  "event_id": "sess_interrupt_009:2",
                  "seq": 2,
                  "timestamp": "2026-08-17T18:00:01Z",
                  "durable": true,
                  "payload": {
                        "state_change": "old turn started"
                  }
            },
            {
                  "event_type": "tool.started",
                  "session_id": "sess_interrupt_009",
                  "turn_id": "turn_old",
                  "event_id": "sess_interrupt_009:3",
                  "seq": 3,
                  "timestamp": "2026-08-17T18:00:02Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "state_change": "tool started"
                  }
            },
            {
                  "event_type": "turn.stopping",
                  "session_id": "sess_interrupt_009",
                  "turn_id": "turn_old",
                  "event_id": "sess_interrupt_009:4",
                  "seq": 4,
                  "timestamp": "2026-08-17T18:00:03Z",
                  "durable": true,
                  "payload": {
                        "state_change": "interrupt_and_send accepted, old turn stopping"
                  }
            },
            {
                  "event_type": "tool.failed",
                  "session_id": "sess_interrupt_009",
                  "turn_id": "turn_old",
                  "event_id": "sess_interrupt_009:5",
                  "seq": 5,
                  "timestamp": "2026-08-17T18:00:04Z",
                  "durable": true,
                  "payload": {
                        "tool_name": "grep",
                        "reason": "interrupted by user",
                        "state_change": "tool failed (interrupted)"
                  }
            },
            {
                  "event_type": "turn.cancelled",
                  "session_id": "sess_interrupt_009",
                  "turn_id": "turn_old",
                  "event_id": "sess_interrupt_009:6",
                  "seq": 6,
                  "timestamp": "2026-08-17T18:00:05Z",
                  "durable": true,
                  "payload": {
                        "state_change": "old turn cancelled"
                  }
            },
            {
                  "event_type": "message.accepted",
                  "session_id": "sess_interrupt_009",
                  "turn_id": null,
                  "event_id": "sess_interrupt_009:7",
                  "seq": 7,
                  "timestamp": "2026-08-17T18:00:06Z",
                  "durable": true,
                  "payload": {
                        "command_type": "interrupt_and_send",
                        "state_change": "new message accepted"
                  }
            },
            {
                  "event_type": "turn.started",
                  "session_id": "sess_interrupt_009",
                  "turn_id": "turn_new",
                  "event_id": "sess_interrupt_009:8",
                  "seq": 8,
                  "timestamp": "2026-08-17T18:00:07Z",
                  "durable": true,
                  "payload": {
                        "state_change": "new turn started"
                  }
            }
      ],
      "expected_snapshot_ref": "snapshot-009-interrupt-and-send.json",
      "notes": "interrupt_and_send lifecycle: old turn (turn_old) goes Running -> Stopping -> Cancelled BEFORE the new message.accepted (seq 7) and new turn.started (seq 8). INV-003-6 enforced: old and new turns never concurrently modify files."
},
    snapshot: {
      "session_id": "sess_interrupt_009",
      "snapshot_seq": 8,
      "digest": "sha256:52cb4bf658d2f1182bf84d7be13909aec8f2cd35005e870a40e780429b790ed9",
      "last_applied_seq": 8,
      "turn_state": "Running",
      "turn_id": "turn_new",
      "host_connectivity": "Online",
      "client_freshness": "Live",
      "state_summary": {
            "session_status": "active",
            "active_turn": "turn_new",
            "active_permission": null,
            "diff_file_count": 0,
            "test_status": null,
            "tool_states": [
                  {
                        "tool_name": "grep",
                        "status": "Failed"
                  }
            ]
      },
      "created_at": "2026-08-17T18:00:07Z",
      "version": "1.0.0",
      "notes": "interrupt_and_send snapshot at seq 8: old turn (turn_old) cancelled, new turn (turn_new) running. Only grep from old turn appears in tool_states; new turn has not yet produced tool events."
}
  }
};

export function getTrace(traceId: string) {
  return RAW[traceId];
}

export function listTraceIds(): string[] {
  return MANIFEST.traces.map((t) => t.id);
}