use nomad_connector::{
    CommandJournal, ConnectorError, PilotAdapter, PilotCommand, UreqOpenCodeClient,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

struct FakeProcess {
    child: Child,
}

impl FakeProcess {
    fn start() -> Self {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testkit/fake-opencode/server.py");
        let mut child = Command::new("python3")
            .arg(script)
            .arg("--scenario")
            .arg("happy")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start fake OpenCode");
        let stdout = child.stdout.take().expect("fake stdout");
        let mut ready = String::new();
        BufReader::new(stdout)
            .read_line(&mut ready)
            .expect("read fake ready marker");
        assert!(
            ready.contains("\"ready\": true"),
            "unexpected marker: {ready}"
        );
        Self { child }
    }

    fn reset(&self, scenario: &str) {
        ureq::post("http://127.0.0.1:4096/__test__/reset")
            .set("Content-Type", "application/json")
            .send_string(&json!({"scenario": scenario}).to_string())
            .expect("reset fake scenario");
    }

    fn stats(&self) -> Value {
        let body = ureq::get("http://127.0.0.1:4096/__test__/stats")
            .call()
            .expect("fake stats")
            .into_string()
            .expect("read fake stats");
        serde_json::from_str(&body).expect("fake stats JSON")
    }
}

impl Drop for FakeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn memory_adapter() -> PilotAdapter<UreqOpenCodeClient> {
    PilotAdapter::new(
        UreqOpenCodeClient::fixed().unwrap(),
        CommandJournal::open_memory().unwrap(),
    )
}

#[test]
fn fixed_http_vertical_slice_and_fail_closed_gates() {
    let offline = UreqOpenCodeClient::fixed().unwrap();
    let error = nomad_connector::OpenCodeClient::preflight(&offline).unwrap_err();
    assert!(matches!(error, ConnectorError::OpenCodeUnreachable(_)));

    let fake = FakeProcess::start();
    let adapter = memory_adapter();

    let capture = adapter.capture("pilot-session").unwrap();
    assert_eq!(capture.source.transport, "http");
    assert_eq!(capture.source.opencode_version, "1.18.16");
    assert_eq!(capture.snapshot.snapshot_seq, 7);
    assert_eq!(capture.snapshot.state_summary.diff_file_count, 1);
    assert_eq!(capture.snapshot.turn_state.as_str(), "NeedsPermission");
    assert!(capture
        .snapshot
        .digest
        .as_deref()
        .unwrap()
        .starts_with("sha256:"));

    let reply = PilotCommand::Reply {
        request_id: "req-reply".into(),
        session_id: "pilot-session".into(),
        seq: 7,
        content: "run the focused test".into(),
    };
    let first = adapter.execute(&reply).unwrap();
    let replay = adapter.execute(&reply).unwrap();
    assert_eq!(first.status, "HostAccepted");
    assert!(!first.idempotent_replay);
    assert!(replay.idempotent_replay);
    assert_eq!(fake.stats()["command_counts"]["reply"], 1);

    let deny = PilotCommand::PermissionDecision {
        request_id: "req-deny".into(),
        session_id: "pilot-session".into(),
        seq: 7,
        permission_id: "perm-1".into(),
        decision: "deny".into(),
        action_hash: "sha256:test".into(),
        expires_at: "2026-08-18T09:00:00Z".into(),
    };
    let denied = adapter.execute(&deny).unwrap();
    assert_eq!(denied.status, "HostAccepted");
    assert_eq!(denied.upstream_pending_bound, Some(true));
    assert!(!fake.stats()["permission_pending"].as_bool().unwrap());

    let stale_deny = PilotCommand::PermissionDecision {
        request_id: "req-deny-stale".into(),
        session_id: "pilot-session".into(),
        seq: 7,
        permission_id: "perm-1".into(),
        decision: "deny".into(),
        action_hash: "sha256:test".into(),
        expires_at: "2026-08-18T09:00:00Z".into(),
    };
    let stale = adapter.execute(&stale_deny).unwrap();
    assert_eq!(stale.status, "Stale");
    assert_eq!(stale.error_code, "ERR_REQUEST_STALE");

    let stop = PilotCommand::Stop {
        request_id: "req-stop".into(),
        session_id: "pilot-session".into(),
        seq: 7,
        target_turn_id: "turn-1".into(),
    };
    let stopped = adapter.execute(&stop).unwrap();
    assert_eq!(stopped.status, "HostAccepted");
    assert_eq!(fake.stats()["command_counts"]["stop"], 1);

    let allow_once = PilotCommand::PermissionDecision {
        request_id: "req-allow".into(),
        session_id: "pilot-session".into(),
        seq: 7,
        permission_id: "perm-1".into(),
        decision: "allow_once".into(),
        action_hash: "sha256:test".into(),
        expires_at: "2026-08-18T09:00:00Z".into(),
    };
    let blocked = adapter.execute(&allow_once).unwrap();
    assert_eq!(blocked.status, "Rejected");
    assert_eq!(blocked.error_code, "ERR_SAFETY_BLOCKED");
    assert_eq!(fake.stats()["command_counts"]["deny"], 1);

    fake.reset("version-mismatch");
    let error = memory_adapter().capture("pilot-session").unwrap_err();
    assert!(matches!(error, ConnectorError::VersionMismatch { .. }));

    fake.reset("unknown-event");
    let error = memory_adapter().capture("pilot-session").unwrap_err();
    assert!(matches!(error, ConnectorError::ProtocolMismatch(_)));

    fake.reset("event-gap");
    let error = memory_adapter().capture("pilot-session").unwrap_err();
    assert!(matches!(error, ConnectorError::ProtocolMismatch(_)));
}

#[test]
fn exact_origin_is_rejected() {
    let error = UreqOpenCodeClient::new("http://localhost:4096")
        .err()
        .unwrap();
    assert!(matches!(error, ConnectorError::NonLoopbackUrl(_)));
    let error = UreqOpenCodeClient::new("http://192.168.1.2:4096")
        .err()
        .unwrap();
    assert!(matches!(error, ConnectorError::NonLoopbackUrl(_)));
}
