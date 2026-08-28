use nomad_connector::remote_v2_mechanical_entrypoint;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorOutput {
    ok: bool,
    error_code: String,
    error_message: String,
}

fn main() {
    match remote_v2_mechanical_entrypoint() {
        Ok(output) => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "phase": output.phase,
                    "status": output.status,
                    "mailbox_id": output.mailbox_id,
                    "epoch": output.epoch,
                    "published_sequence": output.published_sequence,
                    "message_id": output.message_id,
                    "read_sequence": output.read_sequence,
                    "applied_through_sequence": output.applied_through_sequence,
                    "acked_through_sequence": output.acked_through_sequence,
                    "request_id": output.request_id,
                    "receipt_sequence": output.receipt_sequence,
                    "receipt_message_id": output.receipt_message_id,
                    "restart_semantics": output.restart_semantics
                }))
                .unwrap()
            );
        }
        Err(error) => {
            let output = ErrorOutput {
                ok: false,
                error_code: error.error_code().to_string(),
                error_message: error.to_string(),
            };
            println!(
                "{}",
                serde_json::to_string(&output).unwrap_or_else(|_| {
                    r#"{"ok":false,"error_code":"ERR_INTERNAL","error_message":"serialization failed"}"#
                        .to_string()
                })
            );
            std::process::exit(1);
        }
    }
}
