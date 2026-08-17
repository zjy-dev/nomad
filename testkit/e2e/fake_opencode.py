"""Fake OpenCode protocol implementation using Python stdlib.

This is a synthetic, test-only fake that speaks the Nomad event/command
contracts defined in the contracts/ directory. It allows the E2E harness
to drive Host/Relay/Mobile interactions without real implementations.

Key design points:
- Stdlib only (no external dependencies).
- Spawns subprocesses via manifest entries for Host/Relay/Mobile roles.
- Can also run in-process with fake implementations for early tests.
- Emits durable events conforming to the events.schema.json contract.
- Implements command lifecycle (reply, stop, interrupt_and_send, permission_decision).
- Supports record/replay of session/message/tool/permission/diff/abort/snapshot.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class EventRecord:
    event_type: str
    session_id: str
    seq: int
    event_id: str
    turn_id: Optional[str] = None
    timestamp: str = ""
    durable: bool = True
    payload: Dict[str, Any] = field(default_factory=dict)
    chunk_ref: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "event_type": self.event_type,
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "event_id": self.event_id,
            "seq": self.seq,
            "timestamp": self.timestamp or _utcnow_iso(),
            "durable": self.durable,
            "payload": self.payload,
        }
        if self.chunk_ref is not None:
            d["chunk_ref"] = self.chunk_ref
        return d


class OpenCodeSession:
    """In-memory fake session implementing Nomad event/command contracts.

    This is the core of the fake protocol. It maintains:
    - A monotonically increasing sequence counter.
    - The current session state (session_id, turn_state, etc.).
    - A reducer that produces snapshots from the event log.
    - Command handling (reply, stop, interrupt_and_send, permission_decision).
    """

    VALID_EVENT_TYPES = frozenset([
        "session.created", "session.updated",
        "turn.started", "message.accepted", "message.completed",
        "tool.started", "tool.completed", "tool.failed",
        "permission.requested", "permission.resolved",
        "diff.updated",
        "turn.stopping", "turn.completed", "turn.cancelled",
        "turn.failed", "turn.outcome_unknown",
        "session.compacted",
    ])

    VALID_TURN_STATES = frozenset([
        "None", "Running", "NeedsInput", "NeedsPermission",
        "Stopping", "Completed", "Cancelled", "Failed", "OutcomeUnknown",
    ])

    def __init__(self, session_id: str, contract_version: str = "1.0.0"):
        self.session_id = session_id
        self.contract_version = contract_version
        self._seq = 0
        self._events: List[EventRecord] = []
        self._seen_event_ids: set = set()
        self._current_turn_id: Optional[str] = None
        self._turn_state = "None"
        self._host_connectivity = "Online"
        self._client_freshness = "Live"
        self._tool_states: Dict[str, str] = {}
        self._diff_file_count = 0
        self._active_permission: Optional[str] = None
        self._request_id_to_result: Dict[str, Dict[str, Any]] = {}
        self._listeners: List[Callable[[EventRecord], None]] = []
        self._command_log: List[Dict[str, Any]] = []

    @property
    def next_seq(self) -> int:
        return self._seq + 1

    def _emit(self, event_type: str, turn_id: Optional[str] = None,
              payload: Optional[Dict[str, Any]] = None) -> EventRecord:
        seq = self.next_seq
        self._seq = seq
        eid = f"{self.session_id}:{seq}"
        if eid in self._seen_event_ids:
            raise ValueError(f"Duplicate event_id: {eid}")
        self._seen_event_ids.add(eid)
        rec = EventRecord(
            event_type=event_type,
            session_id=self.session_id,
            seq=seq,
            event_id=eid,
            turn_id=turn_id or self._current_turn_id,
            timestamp=_utcnow_iso(),
            durable=True,
            payload=payload or {},
        )
        self._events.append(rec)
        for listener in self._listeners:
            listener(rec)
        return rec

    def add_listener(self, listener: Callable[[EventRecord], None]) -> None:
        self._listeners.append(listener)

    def get_events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def get_event_count(self) -> int:
        return len(self._events)

    def create_session(self) -> EventRecord:
        return self._emit("session.created", payload={"state_change": "session created"})

    def start_turn(self, turn_id: str) -> EventRecord:
        self._current_turn_id = turn_id
        self._turn_state = "Running"
        return self._emit("turn.started", payload={"state_change": "turn started"})

    def accept_message(self, content: str, request_id: Optional[str] = None) -> EventRecord:
        if request_id and request_id in self._request_id_to_result:
            return self._events[-1]  # idempotent replay
        return self._emit("message.accepted", payload={
            "command_type": "reply",
            "state_change": "message accepted",
        })

    def start_tool(self, tool_name: str) -> EventRecord:
        self._tool_states[tool_name] = "Running"
        return self._emit("tool.started", payload={
            "tool_name": tool_name,
            "state_change": "tool started",
        })

    def complete_tool(self, tool_name: str) -> EventRecord:
        self._tool_states[tool_name] = "Completed"
        return self._emit("tool.completed", payload={
            "tool_name": tool_name,
            "state_change": "tool completed",
        })

    def fail_tool(self, tool_name: str, reason: str = "") -> EventRecord:
        self._tool_states[tool_name] = "Failed"
        return self._emit("tool.failed", payload={
            "tool_name": tool_name,
            "reason": reason,
            "state_change": "tool failed",
        })

    def update_diff(self, summary: str = "") -> EventRecord:
        self._diff_file_count += 1
        return self._emit("diff.updated", payload={
            "summary": summary or f"{self._diff_file_count} file(s) changed",
            "state_change": "diff updated",
        })

    def request_permission(self, permission_id: str, action: str) -> EventRecord:
        self._active_permission = permission_id
        self._turn_state = "NeedsPermission"
        return self._emit("permission.requested", payload={
            "permission_id": permission_id,
            "action": action,
            "state_change": "permission requested",
        })

    def resolve_permission(self, permission_id: str, decision: str) -> EventRecord:
        self._active_permission = None
        self._turn_state = "Running"
        return self._emit("permission.resolved", payload={
            "permission_id": permission_id,
            "action": decision,
            "state_change": f"permission resolved: {decision}",
        })

    def complete_turn(self) -> EventRecord:
        self._turn_state = "Completed"
        self._current_turn_id = None
        return self._emit("turn.completed", payload={"state_change": "turn completed"})

    def cancel_turn(self) -> EventRecord:
        self._turn_state = "Cancelled"
        self._current_turn_id = None
        return self._emit("turn.cancelled", payload={"state_change": "turn cancelled"})

    def stop_turn(self) -> EventRecord:
        self._turn_state = "Stopping"
        return self._emit("turn.stopping", payload={"state_change": "turn stopping"})

    def outcome_unknown(self, tool_name: str, reason: str = "") -> EventRecord:
        self._turn_state = "OutcomeUnknown"
        return self._emit("turn.outcome_unknown", payload={
            "tool_name": tool_name,
            "state_change": "tool may have succeeded but result not durably recorded",
            "reason": reason,
        })

    def compact(self) -> EventRecord:
        return self._emit("session.compacted", payload={
            "state_change": "compaction boundary set",
            "summary": "old events compacted",
        })

    def validate_event(self, event: Dict[str, Any]) -> Optional[str]:
        """Validate an event against contract invariants. Returns error or None."""
        etype = event.get("event_type", "")
        if etype not in self.VALID_EVENT_TYPES:
            return f"Unknown event_type: {etype}"
        if not event.get("durable", False):
            return "Non-durable event in durable stream"
        seq = event.get("seq", 0)
        expected_seq = self.next_seq
        if seq != expected_seq:
            return f"seq gap: expected {expected_seq}, got {seq}"
        eid = event.get("event_id", "")
        if eid in self._seen_event_ids:
            return f"Duplicate event_id: {eid}"
        return None

    def validate_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a command against contract invariants.

        Returns a result dict with status, error_code, and other fields.
        Implements INV-003-1 (idempotent request_id) and INV-003-4 (OutcomeUnknown no retry).
        """
        cmd_type = command.get("command_type", "")
        request_id = command.get("request_id", "")
        session_id = command.get("session_id", "")

        if request_id and request_id in self._request_id_to_result:
            prior = self._request_id_to_result[request_id]
            return {
                "status": prior.get("status", "Completed"),
                "result": prior.get("result", {}),
                "idempotent_replay": True,
            }

        if session_id != self.session_id:
            return {
                "status": "Rejected",
                "result": {"error_code": "ERR_REQUEST_STALE", "error_message": "Session mismatch"},
            }

        if cmd_type == "reply":
            seq = self.next_seq
            self._request_id_to_result[request_id] = {
                "status": "Completed",
                "result": {"accepted_at_seq": seq, "error_code": "OK"},
            }
            self.accept_message(command.get("content", ""), request_id=request_id)
            return self._request_id_to_result[request_id]

        elif cmd_type == "stop":
            if self._turn_state == "OutcomeUnknown":
                return {
                    "status": "Rejected",
                    "result": {"error_code": "ERR_OUTCOME_UNKNOWN", "error_message": "Cannot stop OutcomeUnknown turn"},
                }
            self.stop_turn()
            self.cancel_turn()
            return {
                "status": "Completed",
                "result": {"error_code": "OK"},
            }

        elif cmd_type == "interrupt_and_send":
            self.stop_turn()
            self.cancel_turn()
            self.accept_message(command.get("new_content", ""), request_id=request_id)
            return {
                "status": "Completed",
                "result": {"error_code": "OK"},
            }

        elif cmd_type == "permission_decision":
            perm_id = command.get("permission_id", "")
            decision = command.get("decision", "deny")
            if perm_id and self._active_permission == perm_id:
                self.resolve_permission(perm_id, decision)
                self._request_id_to_result[request_id] = {
                    "status": "Completed",
                    "result": {"error_code": "OK"},
                }
                return self._request_id_to_result[request_id]
            else:
                return {
                    "status": "Stale",
                    "result": {"error_code": "ERR_REQUEST_STALE", "error_message": "Permission already resolved"},
                }

        return {
            "status": "Rejected",
            "result": {"error_code": "ERR_INCOMPATIBLE_VERSION", "error_message": f"Unknown command type: {cmd_type}"},
        }

    def get_snapshot(self) -> Dict[str, Any]:
        """Produce a snapshot of the session state.

        Uses the reducer pattern: all durable events reduced to a single
        snapshot object with a SHA-256 digest.
        """
        snapshot_seq = self._seq
        state_summary = {
            "session_status": "active",
            "active_turn": None if self._turn_state in ("Completed", "Cancelled", "Failed") else self._current_turn_id,
            "active_permission": self._active_permission,
            "diff_file_count": self._diff_file_count,
            "test_status": None,
            "tool_states": [
                {"tool_name": name, "status": status}
                for name, status in self._tool_states.items()
            ],
        }
        snap_body = {
            "session_id": self.session_id,
            "snapshot_seq": snapshot_seq,
            "last_applied_seq": snapshot_seq,
            "turn_state": self._turn_state,
            "turn_id": self._current_turn_id,
            "host_connectivity": self._host_connectivity,
            "client_freshness": self._client_freshness,
            "state_summary": state_summary,
            "created_at": _utcnow_iso(),
            "version": self.contract_version,
        }
        snap_body["digest"] = self._compute_digest(snap_body)
        return snap_body

    @staticmethod
    def _compute_digest(snapshot: Dict[str, Any]) -> str:
        body = {k: v for k, v in snapshot.items() if k != "digest"}
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def apply_events(self, events: List[Dict[str, Any]]) -> Tuple[int, Optional[int]]:
        """Apply a list of events to the session, returning (applied_count, gap_to_seq).

        Implements INV-004-3: if events have a gap, client_freshness transitions
        to Stale and gap_to_seq is set.
        """
        applied = 0
        last_seq = self._seq
        gap_to = None
        has_gap = False
        for ev in events:
            seq = ev.get("seq", 0)
            if seq == last_seq + 1:
                self._apply_single_event(ev)
                last_seq = seq
                applied += 1
            elif seq > last_seq + 1:
                gap_to = seq
                has_gap = True
                break
            else:
                if ev.get("event_id", "") not in self._seen_event_ids:
                    self._apply_single_event(ev)
                    last_seq = seq
                    applied += 1
        if has_gap:
            self._client_freshness = "Stale"
        else:
            self._client_freshness = "Live"
        self._seq = last_seq
        return applied, gap_to

    def _apply_single_event(self, ev: Dict[str, Any]) -> None:
        etype = ev.get("event_type", "")
        payload = ev.get("payload", {})
        eid = ev.get("event_id", "")
        if eid in self._seen_event_ids:
            return
        self._seen_event_ids.add(eid)
        if etype in ("turn.completed", "turn.cancelled", "turn.failed", "turn.outcome_unknown"):
            self._current_turn_id = None
            state_map = {
                "turn.completed": "Completed",
                "turn.cancelled": "Cancelled",
                "turn.failed": "Failed",
                "turn.outcome_unknown": "OutcomeUnknown",
            }
            self._turn_state = state_map.get(etype, self._turn_state)
        elif etype == "turn.started":
            self._current_turn_id = ev.get("turn_id")
            self._turn_state = "Running"
        elif etype == "turn.stopping":
            self._turn_state = "Stopping"
        elif etype == "tool.started":
            tool = payload.get("tool_name", "")
            if tool:
                self._tool_states[tool] = "Running"
        elif etype == "tool.completed":
            tool = payload.get("tool_name", "")
            if tool:
                self._tool_states[tool] = "Completed"
        elif etype == "tool.failed":
            tool = payload.get("tool_name", "")
            if tool:
                self._tool_states[tool] = "Failed"
        elif etype == "diff.updated":
            self._diff_file_count += 1
        elif etype == "permission.requested":
            self._active_permission = payload.get("permission_id")
            self._turn_state = "NeedsPermission"
        elif etype == "permission.resolved":
            self._active_permission = None
            self._turn_state = "Running"
        elif etype == "message.accepted":
            self._turn_state = "Running"
        elif etype == "session.compacted":
            pass  # compaction boundary marker

    def replay_recorded(self, events: List[Dict[str, Any]]) -> None:
        """Replay a recorded event stream into the session.

        Useful for record/replay testing: record once, replay many times.
        """
        self.apply_events(events)
