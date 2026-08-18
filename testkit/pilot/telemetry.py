"""Content-free Pilot telemetry validation and stable aliases."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping


EVENT_FIELDS: dict[str, frozenset[str]] = {
    "pilot.invite_accepted": frozenset({"participant_alias", "cohort"}),
    "pilot.preflight_result": frozenset({"result", "error_code", "duration_bucket"}),
    "pilot.pair_result": frozenset({"result", "error_code", "duration_bucket"}),
    "pilot.session_visible": frozenset({"scenario", "freshness"}),
    "pilot.command_stage": frozenset({"action_type", "request_alias", "stage", "error_code"}),
    "pilot.recovery_result": frozenset({"fault_type", "result", "duration_bucket", "gap"}),
    "pilot.task_result": frozenset({"task_id", "result", "duration_bucket", "help_required"}),
    "pilot.retest_intent": frozenset({"intent", "reason_code"}),
}

FORBIDDEN_FIELD_PARTS = frozenset(
    {"prompt", "source", "path", "command", "diff", "token", "secret", "content", "session_id", "turn_id"}
)


class TelemetryValidationError(ValueError):
    """Raised when a Pilot event could expose content or unknown data."""


def alias_identifier(value: str, salt: str) -> str:
    """Return a one-way, domain-separated alias; caller must provide a salt."""

    if not value or not salt:
        raise TelemetryValidationError("value and caller-provided salt are required")
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"alias_{digest[:24]}"


def validate_event(event_name: str, fields: Mapping[str, Any]) -> None:
    allowed = EVENT_FIELDS.get(event_name)
    if allowed is None:
        raise TelemetryValidationError(f"unknown event: {event_name}")

    actual = frozenset(fields)
    extra = actual - allowed
    if extra:
        raise TelemetryValidationError(f"fields are not allowlisted: {', '.join(sorted(extra))}")

    for key, value in fields.items():
        normalized = key.lower()
        if any(part in normalized for part in FORBIDDEN_FIELD_PARTS):
            raise TelemetryValidationError(f"content-bearing field is forbidden: {key}")
        if isinstance(value, (dict, list, tuple, set)):
            raise TelemetryValidationError(f"nested payload is forbidden: {key}")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise TelemetryValidationError(f"unsupported value type: {key}")
