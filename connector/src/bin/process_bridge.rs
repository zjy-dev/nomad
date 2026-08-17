use nomad_connector::journal::CommandJournal;
use nomad_connector::process_bridge::{
    AckPayload, BridgeDispatcher, CommandResult, RelayClient, RelayMessage, UreqRelayClient,
};
use nomad_connector::projection::*;
use nomad_connector::snapshot;
use serde_json::json;
use std::env;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    let relay_url = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:4096".to_string());
    let token = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "test-token".to_string());
    let channel = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "default-channel".to_string());

    eprintln!("[process-bridge] starting relay_url={relay_url} channel={channel}");

    let journal = Rc::new(CommandJournal::open_memory().expect("open journal"));
    let dispatcher = BridgeDispatcher::new(Rc::clone(&journal));
    let relay = UreqRelayClient::new(relay_url.clone(), token.clone());

    publish_checkpoint(&relay, &channel);

    loop {
        match relay.poll_messages(&channel, "host") {
            Ok(messages) if !messages.is_empty() => {
                eprintln!("[process-bridge] received {} message(s)", messages.len());

                let mut ack_ids: Vec<String> = Vec::new();

                for msg in &messages {
                    eprintln!(
                        "[process-bridge] processing msg_id={} type={}",
                        msg.message_id,
                        msg.payload
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown")
                    );

                    match dispatcher.dispatch(msg) {
                        Ok(Some(result)) => {
                            post_command_result(&relay, msg, &result);
                            ack_ids.push(msg.message_id.clone());
                        }
                        Ok(None) => {
                            ack_ids.push(msg.message_id.clone());
                        }
                        Err(e) => {
                            eprintln!(
                                "[process-bridge] dispatch error for {}: {e}",
                                msg.message_id
                            );
                            let err_result = CommandResult {
                                status: "Error".to_string(),
                                error_code: Some(e.error_code().to_string()),
                                error_message: Some(e.to_string()),
                                comparison_code: None,
                            };
                            post_command_result(&relay, msg, &err_result);
                            ack_ids.push(msg.message_id.clone());
                        }
                    }
                }

                if !ack_ids.is_empty() {
                    let ack = AckPayload {
                        channel: channel.clone(),
                        target: "host".to_string(),
                        message_ids: ack_ids,
                    };
                    match relay.ack_messages(&ack) {
                        Ok(()) => eprintln!(
                            "[process-bridge] ACKed {} message(s)",
                            ack.message_ids.len()
                        ),
                        Err(e) => {
                            eprintln!("[process-bridge] ACK failed: {e}")
                        }
                    }
                }
            }
            Ok(_) => {
                thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                eprintln!("[process-bridge] poll error: {e}; retrying in 2s");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn publish_checkpoint(relay: &UreqRelayClient, channel: &str) {
    let snap = Snapshot {
        session_id: channel.to_string(),
        snapshot_seq: 1,
        digest: None,
        last_applied_seq: 1,
        turn_state: TurnState::NeedsPermission,
        turn_id: Some("turn_synthetic".to_string()),
        host_connectivity: HostConnectivity::Online,
        client_freshness: ClientFreshness::Live,
        state_summary: StateSummary {
            session_status: Some("awaiting_permission".to_string()),
            active_turn: Some("turn_synthetic".to_string()),
            active_permission: Some("perm_synthetic".to_string()),
            diff_file_count: 5,
            test_status: Some("test-only".to_string()),
            tool_states: vec![],
        },
        created_at: chrono_now(),
        version: "1.0.0".to_string(),
    };

    let v = snapshot::to_canonical_value(&snap);
    let digest = snapshot::compute_digest(&v);

    let msg = RelayMessage {
        channel: channel.to_string(),
        target: "mobile".to_string(),
        message_id: format!("checkpoint-{channel}-0"),
        payload: json!({
            "type": "session.checkpoint",
            "channel": channel,
            "message_id": format!("checkpoint-{channel}-0"),
            "state": "NeedsPermission",
            "diff_summary": {
                "file_count": 3,
                "files": ["src/main.py", "src/utils.py", "config.yaml"],
            },
            "digest": digest,
            "snapshot_seq": 1,
        }),
    };

    match relay.post_message(&msg) {
        Ok(()) => {
            eprintln!("[process-bridge] published NeedsPermission checkpoint to mobile")
        }
        Err(e) => {
            eprintln!("[process-bridge] checkpoint publish failed: {e}; continuing anyway")
        }
    }
}

fn post_command_result(
    relay: &UreqRelayClient,
    original_msg: &RelayMessage,
    result: &CommandResult,
) {
    if original_msg
        .payload
        .get("type")
        .and_then(|value| value.as_str())
        == Some("pair.request")
    {
        let reply = RelayMessage {
            channel: original_msg.channel.clone(),
            target: "mobile".to_string(),
            message_id: format!("pair.confirmed:{}", original_msg.message_id),
            payload: json!({
                "type": "pair.confirmed",
                "channel": original_msg.channel,
                "message_id": original_msg.message_id,
                "comparison_code": result.comparison_code,
            }),
        };
        if let Err(error) = relay.post_message(&reply) {
            eprintln!("[process-bridge] pair.confirmed post failed: {error}");
        }
        return;
    }

    let payload = json!({
        "type": "command.result",
        "status": result.status,
        "channel": original_msg.channel,
        "message_id": original_msg.message_id,
        "result": {
            "error_code": result.error_code.clone().unwrap_or_else(|| "OK".to_string()),
            "error_message": result.error_message,
        },
    });

    let reply = RelayMessage {
        channel: original_msg.channel.clone(),
        target: "mobile".to_string(),
        message_id: format!("command.result:{}", original_msg.message_id),
        payload,
    };

    match relay.post_message(&reply) {
        Ok(()) => eprintln!(
            "[process-bridge] posted command.result for {}",
            original_msg.message_id
        ),
        Err(e) => {
            eprintln!("[process-bridge] command.result post failed: {e}")
        }
    }
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}
