use crate::opencode_adapter::{AdapterCommandResult, PilotCommand};
use crate::ConnectorError;
use serde_json::{json, Value};

pub fn parse_pilot_command(payload: &Value) -> Result<PilotCommand, ConnectorError> {
    if payload.get("type").and_then(Value::as_str) != Some("pilot.command") {
        return Err(ConnectorError::ProtocolMismatch(
            "Relay payload type must be pilot.command".to_string(),
        ));
    }
    let command = payload.get("command").ok_or_else(|| {
        ConnectorError::ProtocolMismatch("pilot.command requires command object".to_string())
    })?;
    serde_json::from_value(command.clone()).map_err(|error| {
        ConnectorError::ProtocolMismatch(format!("invalid Pilot command: {error}"))
    })
}

pub fn result_payload(result: &AdapterCommandResult) -> Value {
    json!({
        "type": "pilot.command.result",
        "request_id": result.request_id,
        "command_type": result.command_type,
        "status": result.status,
        "error_code": result.error_code,
        "error_message": result.error_message,
        "accepted_at_seq": result.accepted_at_seq,
        "event_id": result.event_id,
        "idempotent_replay": result.idempotent_replay,
        "upstream_pending_bound": result.upstream_pending_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frozen_command_envelope() {
        let value = json!({
            "type": "pilot.command",
            "command": {
                "command_type": "stop",
                "request_id": "req-1",
                "session_id": "pilot-session",
                "seq": 7,
                "target_turn_id": "turn-1"
            }
        });
        assert!(matches!(
            parse_pilot_command(&value).unwrap(),
            PilotCommand::Stop { .. }
        ));
    }

    #[test]
    fn rejects_unknown_or_unwrapped_payload() {
        assert!(parse_pilot_command(&json!({"type": "command"})).is_err());
        assert!(parse_pilot_command(&json!({"type": "pilot.command"})).is_err());
    }
}
