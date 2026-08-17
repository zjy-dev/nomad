use nomad_connector::process_bridge::{AckPayload, BridgeDispatcher, CommandResult, RelayMessage};
use nomad_connector::*;
use serde_json::{json, Value};
use std::rc::Rc;

fn make_dispatcher() -> (Rc<CommandJournal>, BridgeDispatcher) {
    let journal = Rc::new(CommandJournal::open_memory().unwrap());
    let dispatcher = BridgeDispatcher::new(Rc::clone(&journal));
    (journal, dispatcher)
}

#[test]
fn pair_request_roundtrip() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_pair".into(),
        target: "host".into(),
        message_id: "pair_001".into(),
        payload: json!({
            "type": "pair.request",
            "comparison_code": "482913",
        }),
    };
    let result = disp.dispatch(&msg).unwrap();
    assert!(result.is_some(), "pair.request should produce a reply");
    let r = result.unwrap();
    assert_eq!(r.status, "HostAccepted");
    assert_eq!(r.comparison_code.as_deref(), Some("482913"));
    assert!(r.error_code.is_none());
    assert!(r.error_message.is_none());
}

#[test]
fn pair_request_missing_code() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_pair2".into(),
        target: "host".into(),
        message_id: "pair_no_code".into(),
        payload: json!({
            "type": "pair.request",
        }),
    };
    let result = disp.dispatch(&msg).unwrap();
    let r = result.unwrap();
    assert_eq!(r.status, "Rejected");
    assert_eq!(r.error_code.as_deref(), Some("ERR_REQUEST_STALE"));
}

#[test]
fn command_deny_creates_journal_entry() {
    let (journal, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_deny".into(),
        target: "host".into(),
        message_id: "cmd_deny_001".into(),
        payload: json!({
            "type": "command",
            "action": "deny",
            "request_id": "req_deny_001",
            "session_id": "sess_deny",
            "permission_id": "perm_001",
            "action_hash": "hash_abc",
            "expires_at": "2026-08-17T20:00:00Z",
        }),
    };
    let result = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(result.status, "HostAccepted");

    let cmd = journal.get_by_request_id("req_deny_001").unwrap();
    assert!(cmd.is_some());
    let cmd = cmd.unwrap();
    assert_eq!(cmd.command_type, "permission_decision");
    assert_eq!(cmd.status, "HostAccepted");

    let decoded: Value = serde_json::from_str(&cmd.result_json).unwrap();
    assert_eq!(decoded["decision"], json!("deny"));
}

#[test]
fn command_deny_duplicate_idempotent_error() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_dup".into(),
        target: "host".into(),
        message_id: "cmd_dup".into(),
        payload: json!({
            "type": "command",
            "action": "deny",
            "request_id": "req_dup_001",
            "session_id": "sess_dup",
            "permission_id": "perm_dup",
            "action_hash": "h",
            "expires_at": "t",
        }),
    };
    let r1 = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(r1.status, "HostAccepted");

    let r2 = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(r2.status, "Error");
    assert_eq!(r2.error_code.as_deref(), Some("ERR_DUPLICATE_REQUEST"));
}

#[test]
fn command_stop_creates_journal_entry() {
    let (journal, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_stop".into(),
        target: "host".into(),
        message_id: "cmd_stop_001".into(),
        payload: json!({
            "type": "command",
            "action": "stop",
            "request_id": "req_stop_001",
            "session_id": "sess_stop",
            "permission_id": "perm_stop",
            "target_turn_id": "turn_stop_001",
        }),
    };
    let result = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(result.status, "HostAccepted");

    let cmd = journal.get_by_request_id("req_stop_001").unwrap().unwrap();
    assert_eq!(cmd.command_type, "stop");
    assert_eq!(cmd.status, "HostAccepted");
    assert!(cmd.accepted_at_seq.is_some());
}

#[test]
fn command_allow_once_is_always_rejected() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_allow".into(),
        target: "host".into(),
        message_id: "cmd_allow_001".into(),
        payload: json!({
            "type": "command",
            "action": "allow_once",
            "request_id": "req_allow_001",
        }),
    };
    let result = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(result.status, "Rejected");
    assert_eq!(result.error_code.as_deref(), Some("ERR_SAFETY_BLOCKED"));
    assert!(result.error_message.is_some());
    assert!(result
        .error_message
        .as_ref()
        .unwrap()
        .contains("allow_once"));
}

#[test]
fn command_unknown_action_returns_error() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_unk".into(),
        target: "host".into(),
        message_id: "cmd_unk_001".into(),
        payload: json!({
            "type": "command",
            "action": "unknown_action_xyz",
            "request_id": "req_unk",
        }),
    };
    let result = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(result.status, "Error");
    assert!(result.error_code.is_some());
}

#[test]
fn unknown_message_type_is_acked_without_reply() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_unk_type".into(),
        target: "host".into(),
        message_id: "msg_unk_type".into(),
        payload: json!({
            "type": "session.heartbeat",
        }),
    };
    let result = disp.dispatch(&msg).unwrap();
    assert!(result.is_none(), "unknown types should not produce replies");
}

#[test]
fn message_id_field_from_payload_takes_precedence() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_orig_id".into(),
        target: "host".into(),
        message_id: "mid_001".into(),
        payload: json!({
            "type": "command",
            "action": "deny",
            "request_id": "req_override",
            "session_id": "sess_override",
            "permission_id": "p1",
            "action_hash": "h",
            "expires_at": "t",
        }),
    };
    let result = disp.dispatch(&msg).unwrap().unwrap();
    assert_eq!(result.status, "HostAccepted");
}

#[test]
fn multiple_command_types_in_sequence() {
    let (journal, disp) = make_dispatcher();

    let deny_msg = RelayMessage {
        channel: "ch_seq".into(),
        target: "host".into(),
        message_id: "seq_deny".into(),
        payload: json!({
            "type": "command",
            "action": "deny",
            "request_id": "seq_req_deny",
            "session_id": "sess_seq",
            "permission_id": "perm_seq",
            "action_hash": "h",
            "expires_at": "t",
        }),
    };
    let stop_msg = RelayMessage {
        channel: "ch_seq".into(),
        target: "host".into(),
        message_id: "seq_stop".into(),
        payload: json!({
            "type": "command",
            "action": "stop",
            "request_id": "seq_req_stop",
            "session_id": "sess_seq",
            "permission_id": "perm_seq",
            "target_turn_id": "turn_seq_stop",
        }),
    };

    let r1 = disp.dispatch(&deny_msg).unwrap().unwrap();
    assert_eq!(r1.status, "HostAccepted");
    let r2 = disp.dispatch(&stop_msg).unwrap().unwrap();
    assert_eq!(r2.status, "HostAccepted");

    let all = journal.get_by_session("sess_seq").unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn command_result_roundtrip_json() {
    let r = CommandResult {
        status: "HostAccepted".into(),
        error_code: None,
        error_message: None,
        comparison_code: Some("555555".into()),
    };
    let json_str = serde_json::to_string(&r).unwrap();
    let parsed: CommandResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.status, "HostAccepted");
    assert_eq!(parsed.comparison_code.as_deref(), Some("555555"));
    assert!(parsed.error_code.is_none());
}

#[test]
fn command_result_error_roundtrip_json() {
    let r = CommandResult {
        status: "Error".into(),
        error_code: Some("ERR_DUPLICATE_REQUEST".into()),
        error_message: Some("duplicate request_id".into()),
        comparison_code: None,
    };
    let json_str = serde_json::to_string(&r).unwrap();
    let parsed: CommandResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.status, "Error");
    assert_eq!(parsed.error_code.as_deref(), Some("ERR_DUPLICATE_REQUEST"));
    assert!(parsed.comparison_code.is_none());
}

#[test]
fn command_result_rejected_roundtrip_json() {
    let r = CommandResult {
        status: "Rejected".into(),
        error_code: Some("ERR_SAFETY_BLOCKED".into()),
        error_message: Some("allow_once blocked".into()),
        comparison_code: None,
    };
    let json_str = serde_json::to_string(&r).unwrap();
    assert!(!json_str.contains("comparison_code"));
    assert!(json_str.contains("ERR_SAFETY_BLOCKED"));
}

#[test]
fn relay_message_deserialization() {
    let json_str = r#"{
        "channel": "ch1",
        "target": "host",
        "message_id": "mid_001",
        "payload": {"type": "test"}
    }"#;
    let msg: RelayMessage = serde_json::from_str(json_str).unwrap();
    assert_eq!(msg.channel, "ch1");
    assert_eq!(msg.target, "host");
    assert_eq!(msg.message_id, "mid_001");
    assert_eq!(msg.payload["type"], json!("test"));
}

#[test]
fn ack_payload_deserialization() {
    let json_str = r#"{
        "channel": "ch1",
        "target": "host",
        "message_ids": ["m1", "m2", "m3"]
    }"#;
    let ack: AckPayload = serde_json::from_str(json_str).unwrap();
    assert_eq!(ack.channel, "ch1");
    assert_eq!(ack.target, "host");
    assert_eq!(ack.message_ids.len(), 3);
}

#[test]
fn dispatcher_handles_missing_payload_fields_gracefully() {
    let (_, disp) = make_dispatcher();
    let msg = RelayMessage {
        channel: "ch_minimal".into(),
        target: "host".into(),
        message_id: "minimal_msg".into(),
        payload: json!({
            "type": "command",
            "action": "deny",
        }),
    };
    let result = disp.dispatch(&msg).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();
    assert_eq!(r.status, "HostAccepted");
}

#[test]
fn dispatcher_integration_like_sequence() {
    let (journal, disp) = make_dispatcher();

    let pair_msg = RelayMessage {
        channel: "ch_integration".into(),
        target: "host".into(),
        message_id: "pair_roundtrip".into(),
        payload: json!({
            "type": "pair.request",
            "comparison_code": "123456",
        }),
    };
    let r1 = disp.dispatch(&pair_msg).unwrap().unwrap();
    assert_eq!(r1.status, "HostAccepted");
    assert_eq!(r1.comparison_code.as_deref(), Some("123456"));

    let deny_msg = RelayMessage {
        channel: "ch_integration".into(),
        target: "host".into(),
        message_id: "deny_001".into(),
        payload: json!({
            "type": "command",
            "action": "deny",
            "request_id": "int_deny",
            "session_id": "int_sess",
            "permission_id": "int_perm",
            "action_hash": "hash",
            "expires_at": "t",
        }),
    };
    let r2 = disp.dispatch(&deny_msg).unwrap().unwrap();
    assert_eq!(r2.status, "HostAccepted");

    let stop_msg = RelayMessage {
        channel: "ch_integration".into(),
        target: "host".into(),
        message_id: "stop_001".into(),
        payload: json!({
            "type": "command",
            "action": "stop",
            "request_id": "int_stop",
            "session_id": "int_sess",
            "permission_id": "int_perm",
            "target_turn_id": "turn_int_stop",
        }),
    };
    let r3 = disp.dispatch(&stop_msg).unwrap().unwrap();
    assert_eq!(r3.status, "HostAccepted");

    let allow_msg = RelayMessage {
        channel: "ch_integration".into(),
        target: "host".into(),
        message_id: "allow_001".into(),
        payload: json!({
            "type": "command",
            "action": "allow_once",
            "request_id": "int_allow",
        }),
    };
    let r4 = disp.dispatch(&allow_msg).unwrap().unwrap();
    assert_eq!(r4.status, "Rejected");
    assert_eq!(r4.error_code.as_deref(), Some("ERR_SAFETY_BLOCKED"));

    let all = journal.get_by_session("int_sess").unwrap();
    assert_eq!(all.len(), 2, "deny + stop entries expected");

    let allow_entry = journal.get_by_request_id("int_allow").unwrap();
    assert!(allow_entry.is_none());
}
