use nomad_connector::adapters::opencode::{
    OpenCodeClient, PilotAdapter, PilotCapture, PilotCommand, UreqOpenCodeClient, EXPECTED_VERSION,
};
use nomad_connector::process_bridge::{RelayClient, RelayMessage, UreqRelayClient};
use nomad_connector::CommandJournal;
use serde::Serialize;
use serde_json::{json, Value};
use std::env;
use std::path::PathBuf;

#[derive(Serialize)]
struct ErrorOutput {
    ok: bool,
    error_code: String,
    error_message: String,
}

fn main() {
    if let Err(error) = run() {
        let output = ErrorOutput {
            ok: false,
            error_code: error.error_code().to_string(),
            error_message: error.to_string(),
        };
        println!(
            "{}",
            serde_json::to_string(&output).unwrap_or_else(|_| {
                r#"{"ok":false,"error_code":"ERR_INTERNAL","error_message":"serialization failed"}"#.to_string()
            })
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), nomad_connector::ConnectorError> {
    let mut args = env::args().skip(1);
    let subcommand = args.next().unwrap_or_else(|| "help".to_string());
    let mut session_id = "pilot-session".to_string();
    let mut journal_path = PathBuf::from("pilot-adapter.sqlite3");
    let mut relay_url = None;
    let mut relay_token = None;
    let mut relay_channel = None;
    let mut command_json = None;

    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| {
            nomad_connector::ConnectorError::Other(format!("missing value for {arg}"))
        })?;
        match arg.as_str() {
            "--session-id" => session_id = value,
            "--journal" => journal_path = PathBuf::from(value),
            "--relay-url" => relay_url = Some(value),
            "--relay-token" => relay_token = Some(value),
            "--relay-channel" => relay_channel = Some(value),
            "--command-json" => command_json = Some(value),
            _ => {
                return Err(nomad_connector::ConnectorError::Other(format!(
                    "unknown argument {arg}"
                )))
            }
        }
    }

    let client = UreqOpenCodeClient::fixed()?;
    match subcommand.as_str() {
        "preflight" => {
            let version = client.preflight()?;
            print_json(&json!({
                "ok": true,
                "opencode_version": version,
                "expected_version": EXPECTED_VERSION,
                "origin": "http://127.0.0.1:4096"
            }))
        }
        "capture" => {
            let adapter = PilotAdapter::new(client, CommandJournal::open_memory()?);
            let capture = adapter.capture(&session_id)?;
            if relay_url.is_some() || relay_token.is_some() || relay_channel.is_some() {
                publish_checkpoint(
                    &capture,
                    relay_url.ok_or_else(|| missing_relay_arg("--relay-url"))?,
                    relay_token.ok_or_else(|| missing_relay_arg("--relay-token"))?,
                    relay_channel.ok_or_else(|| missing_relay_arg("--relay-channel"))?,
                )?;
            }
            print_json(&json!({"ok": true, "capture": capture}))
        }
        "command" => {
            let raw = command_json.ok_or_else(|| {
                nomad_connector::ConnectorError::Other(
                    "command requires --command-json <JSON>".to_string(),
                )
            })?;
            let command: PilotCommand = serde_json::from_str(&raw)?;
            let adapter = PilotAdapter::new(client, CommandJournal::open(&journal_path)?);
            let result = adapter.execute(&command)?;
            print_json(&json!({"ok": true, "result": result}))
        }
        "help" | "--help" | "-h" => {
            eprintln!(
                "Usage:\n  pilot-adapter preflight\n  pilot-adapter capture [--session-id ID] [--relay-url URL --relay-token TOKEN --relay-channel CHANNEL]\n  pilot-adapter command --command-json JSON [--journal PATH]"
            );
            Ok(())
        }
        _ => Err(nomad_connector::ConnectorError::Other(format!(
            "unknown subcommand {subcommand}"
        ))),
    }
}

fn missing_relay_arg(name: &str) -> nomad_connector::ConnectorError {
    nomad_connector::ConnectorError::Other(format!("capture relay publishing requires {name}"))
}

fn print_json(value: &Value) -> Result<(), nomad_connector::ConnectorError> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

fn publish_checkpoint(
    capture: &PilotCapture,
    relay_url: String,
    relay_token: String,
    channel: String,
) -> Result<(), nomad_connector::ConnectorError> {
    let relay = UreqRelayClient::new(relay_url, relay_token);
    let message_id = format!(
        "checkpoint-{}-{}",
        capture.session.id, capture.snapshot.snapshot_seq
    );
    relay.post_message(&RelayMessage {
        channel: channel.clone(),
        target: "mobile".to_string(),
        message_id: message_id.clone(),
        payload: json!({
            "type": "session.checkpoint",
            "channel": channel,
            "message_id": message_id,
            "session_id": capture.snapshot.session_id,
            "state": capture.snapshot.turn_state.as_str(),
            "snapshot_seq": capture.snapshot.snapshot_seq,
            "digest": capture.snapshot.digest,
            "diff_file_count": capture.snapshot.state_summary.diff_file_count,
            "source": capture.source,
        }),
    })
}
