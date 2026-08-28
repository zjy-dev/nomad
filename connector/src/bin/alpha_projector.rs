use nomad_connector::adapters::opencode::{run_alpha_projector, AlphaProjectorConfig};
use nomad_connector::ConnectorError;
use serde::Serialize;
use std::env;

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
                r#"{"ok":false,"error_code":"ERR_INTERNAL","error_message":"serialization failed"}"#
                    .to_string()
            })
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), ConnectorError> {
    let config = parse_args()?;
    let receipt = run_alpha_projector(&config)?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

fn parse_args() -> Result<AlphaProjectorConfig, ConnectorError> {
    let mut relay_url = None;
    let mut session_id = "pilot-session".to_string();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| ConnectorError::Other(format!("missing value for {arg}")))?;
        match arg.as_str() {
            "--relay-url" => relay_url = Some(value),
            "--session-id" => session_id = value,
            _ => return Err(ConnectorError::Other(format!("unknown argument {arg}"))),
        }
    }
    Ok(AlphaProjectorConfig {
        relay_url: relay_url.ok_or_else(|| {
            ConnectorError::Other("alpha-projector requires --relay-url".to_string())
        })?,
        session_id,
    })
}
