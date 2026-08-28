use nomad_connector::adapters::opencode::{
    OpenCodeClient, PilotAdapter, PilotCommand, UreqOpenCodeClient,
};
use nomad_connector::{CommandJournal, ConnectorError};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

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

    fn reset(scenario: &str) {
        ureq::post("http://127.0.0.1:4096/__test__/reset")
            .set("Content-Type", "application/json")
            .send_string(&json!({"scenario": scenario}).to_string())
            .expect("reset fake scenario");
    }

    fn stats() -> Value {
        let body = ureq::get("http://127.0.0.1:4096/__test__/stats")
            .call()
            .expect("fake stats")
            .into_string()
            .expect("read fake stats");
        serde_json::from_str(&body).expect("fake stats JSON")
    }
}

enum FakeProbe {
    Absent,
    Compatible,
    Unexpected,
}

struct FakeServiceLease {
    child: Option<FakeProcess>,
    process_guard: Option<MutexGuard<'static, ()>>,
    lock_file: File,
}

fn fake_process_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn fake_lock_path() -> std::path::PathBuf {
    std::env::temp_dir().join("nomad-fake-opencode-4096.lock")
}

fn probe_fake_service() -> FakeProbe {
    match ureq::get("http://127.0.0.1:4096/__test__/stats").call() {
        Ok(response) => {
            let body = match response.into_string() {
                Ok(body) => body,
                Err(_) => return FakeProbe::Unexpected,
            };
            match serde_json::from_str::<Value>(&body) {
                Ok(value)
                    if value.get("scenario").and_then(Value::as_str).is_some()
                        && value
                            .get("command_counts")
                            .and_then(Value::as_object)
                            .is_some()
                        && value
                            .get("permission_pending")
                            .and_then(Value::as_bool)
                            .is_some() =>
                {
                    FakeProbe::Compatible
                }
                _ => FakeProbe::Unexpected,
            }
        }
        Err(ureq::Error::Transport(_)) => FakeProbe::Absent,
        Err(_) => FakeProbe::Unexpected,
    }
}

fn wait_for_fake_service_absent() -> bool {
    for _ in 0..80 {
        if matches!(probe_fake_service(), FakeProbe::Absent) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    false
}

fn acquire_fake_service() -> FakeServiceLease {
    let process_guard = fake_process_mutex()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(fake_lock_path())
        .expect("open fake lock file");
    let result = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(result, 0, "acquire fake-opencode flock");

    match probe_fake_service() {
        FakeProbe::Absent => {}
        FakeProbe::Compatible | FakeProbe::Unexpected => {
            panic!("127.0.0.1:4096 is occupied despite the fake-opencode lease")
        }
    }
    let child = FakeProcess::start();
    FakeProcess::reset("happy");
    let _ = FakeProcess::stats();
    FakeServiceLease {
        child: Some(child),
        process_guard: Some(process_guard),
        lock_file,
    }
}

impl Drop for FakeServiceLease {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            drop(child);
        }
        let absent = wait_for_fake_service_absent();
        let _ = unsafe { libc::flock(self.lock_file.as_raw_fd(), libc::LOCK_UN) };
        let _ = self.process_guard.take();
        assert!(
            absent || std::thread::panicking(),
            "fake-opencode did not leave 127.0.0.1:4096 before lease release"
        );
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
    let offline_error = UreqOpenCodeClient::fixed()
        .unwrap()
        .preflight()
        .unwrap_err();
    assert!(matches!(
        offline_error,
        ConnectorError::OpenCodeUnreachable(_)
    ));

    let _lease = acquire_fake_service();
    let adapter = memory_adapter();
    FakeProcess::reset("happy");

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
    assert_eq!(FakeProcess::stats()["command_counts"]["reply"], 1);

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
    assert!(!FakeProcess::stats()["permission_pending"]
        .as_bool()
        .unwrap());

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
    assert_eq!(FakeProcess::stats()["command_counts"]["stop"], 1);

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
    assert_eq!(FakeProcess::stats()["command_counts"]["deny"], 1);

    FakeProcess::reset("version-mismatch");
    let error = memory_adapter().capture("pilot-session").unwrap_err();
    assert!(matches!(error, ConnectorError::VersionMismatch { .. }));

    FakeProcess::reset("unknown-event");
    let error = memory_adapter().capture("pilot-session").unwrap_err();
    assert!(matches!(error, ConnectorError::ProtocolMismatch(_)));

    FakeProcess::reset("event-gap");
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
