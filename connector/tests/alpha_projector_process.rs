use nomad_connector::adapters::opencode::{
    alpha_canonical_json, build_alpha_projection, projection_digest, projection_payload_bytes,
    PilotAdapter, UreqOpenCodeClient,
};
use nomad_connector::CommandJournal;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

const PRIVATE_KEY_ENV: &str = "NOMAD_ALPHA_DEVICE_PRIVATE_KEY_HEX";
const PRIVATE_KEY_HEX: &str =
    "8cd8ac5b730d8f625d9631bb0a6cd7e7d66f6bde56d356b8af602534fe7fc54b91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864";
const RELAY_MAGIC: u32 = 0x4E4D_4401;
const RELAY_HEADER_SIZE: usize = 48;
const RELAY_SIG_SIZE: usize = 64;

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
}

impl Drop for FakeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

fn reset_fake_service(scenario: &str) {
    ureq::post("http://127.0.0.1:4096/__test__/reset")
        .set("Content-Type", "application/json")
        .send_string(&json!({"scenario": scenario}).to_string())
        .expect("reset fake scenario");
}

fn fake_stats() -> Value {
    let body = ureq::get("http://127.0.0.1:4096/__test__/stats")
        .call()
        .expect("fake stats")
        .into_string()
        .expect("read fake stats");
    serde_json::from_str(&body).expect("fake stats JSON")
}

fn wait_for_fake_service_absent() -> bool {
    for _ in 0..80 {
        if matches!(probe_fake_service(), FakeProbe::Absent) {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
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
    reset_fake_service("happy");
    let _ = fake_stats();
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

#[derive(Default)]
struct SessionState {
    last_seq: Option<u64>,
    digest_by_seq: HashMap<u64, String>,
    frame_id_by_digest: HashMap<String, String>,
}

#[derive(Default)]
struct VerifierState {
    sessions: HashMap<String, SessionState>,
    frame_counter: u64,
}

#[derive(Clone)]
struct FrameVerifier {
    listener: Arc<TcpListener>,
    state: Arc<Mutex<VerifierState>>,
}

impl FrameVerifier {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let verifier = Self {
            listener: Arc::new(listener),
            state: Arc::new(Mutex::new(VerifierState::default())),
        };
        let acceptor = verifier.clone();
        thread::spawn(move || {
            while let Ok((stream, _)) = acceptor.listener.accept() {
                let _ = acceptor.handle(stream);
            }
        });
        verifier
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.listener.local_addr().unwrap())
    }

    fn handle(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let (request_line, headers, body) = read_http_request(&mut stream)?;
        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 || parts[0] != "POST" || parts[1] != "/v1/frame" {
            return write_json_response(&mut stream, 404, &json!({"error":"not found"}));
        }
        if headers
            .get("content-type")
            .is_none_or(|value| value != "application/octet-stream")
        {
            return write_json_response(&mut stream, 400, &json!({"error":"wrong content type"}));
        }
        match self.verify_and_store(&body) {
            Ok((status, payload)) => write_json_response(&mut stream, status, &payload),
            Err((status, payload)) => write_json_response(&mut stream, status, &payload),
        }
    }

    fn verify_and_store(&self, raw: &[u8]) -> Result<(u16, Value), (u16, Value)> {
        if raw.len() < RELAY_HEADER_SIZE + RELAY_SIG_SIZE {
            return Err((400, json!({"error":"malformed"})));
        }
        if u32::from_be_bytes(raw[0..4].try_into().unwrap()) != RELAY_MAGIC {
            return Err((400, json!({"error":"bad magic"})));
        }
        let sig_len = u16::from_be_bytes(raw[40..42].try_into().unwrap()) as usize;
        if sig_len != RELAY_SIG_SIZE || raw.len() < RELAY_HEADER_SIZE + sig_len {
            return Err((400, json!({"error":"bad signature length"})));
        }
        let payload = &raw[RELAY_HEADER_SIZE + sig_len..];
        let value: Value = serde_json::from_slice(payload)
            .map_err(|_| (400, json!({"error":"invalid payload json"})))?;
        let digest = value["digest"]
            .as_str()
            .ok_or_else(|| (400, json!({"error":"missing digest"})))?
            .to_string();
        let session_id = value["session"]["session_id"]
            .as_str()
            .ok_or_else(|| (400, json!({"error":"missing session_id"})))?
            .to_string();
        let seq = value["seq"]
            .as_u64()
            .ok_or_else(|| (400, json!({"error":"missing seq"})))?;

        let mut without_digest = value.clone();
        without_digest
            .as_object_mut()
            .ok_or_else(|| (400, json!({"error":"projection must be object"})))?
            .remove("digest");
        let expected = format!(
            "sha256:{:x}",
            Sha256::digest(
                alpha_canonical_json(&without_digest)
                    .map_err(|_| (400, json!({"error":"canonicalization failed"})))?
                    .as_bytes()
            )
        );
        if expected != digest {
            return Err((409, json!({"error":"digest mismatch"})));
        }

        let mut guard = self.state.lock().unwrap();
        {
            let state = guard.sessions.entry(session_id.clone()).or_default();
            match state.last_seq {
                None => {}
                Some(last) if seq == last + 1 => {}
                Some(last) if seq < last => {
                    return Err((409, json!({"error":"stale"})));
                }
                Some(last) if seq > last + 1 => {
                    return Err((409, json!({"error":"gap"})));
                }
                Some(last) if seq == last => {
                    if let Some(existing) = state.digest_by_seq.get(&seq) {
                        if existing == &digest {
                            let frame_id = state.frame_id_by_digest.get(existing).unwrap().clone();
                            return Ok((202, json!({"frame_id":frame_id,"new":false})));
                        }
                        return Err((409, json!({"error":"conflict"})));
                    }
                    return Err((409, json!({"error":"conflict"})));
                }
                _ => {}
            }
        }

        guard.frame_counter += 1;
        let frame_id = format!("frame-{:016x}", guard.frame_counter);
        let state = guard.sessions.entry(session_id).or_default();
        state.last_seq = Some(seq);
        state.digest_by_seq.insert(seq, digest.clone());
        state
            .frame_id_by_digest
            .insert(digest.clone(), frame_id.clone());
        Ok((202, json!({"frame_id":frame_id,"new":true})))
    }
}

fn read_http_request(
    stream: &mut TcpStream,
) -> std::io::Result<(String, HashMap<String, String>, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    loop {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .unwrap();
    let header_text = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);
    Ok((request_line, headers, body))
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    payload: &Value,
) -> std::io::Result<()> {
    let reason = match status {
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let body = serde_json::to_vec(payload).unwrap();
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn run_alpha_projector(relay_url: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_alpha-projector"))
        .arg("--relay-url")
        .arg(relay_url)
        .arg("--session-id")
        .arg("pilot-session")
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env(PRIVATE_KEY_ENV, PRIVATE_KEY_HEX)
        .output()
        .unwrap()
}

#[test]
fn alpha_projector_binary_posts_bounded_signed_projection_to_loopback_verifier() {
    let _lease = acquire_fake_service();
    let verifier = FrameVerifier::start();
    let output = run_alpha_projector(&verifier.base_url());
    assert!(
        output.status.success(),
        "stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["status"], "accepted");
    assert!(receipt["frame_id"].as_str().unwrap().starts_with("frame-"));
    assert!(receipt["digest"].as_str().unwrap().starts_with("sha256:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn alpha_projector_projection_digest_matches_canonical_rule() {
    let _lease = acquire_fake_service();
    let adapter = PilotAdapter::new(
        UreqOpenCodeClient::fixed().unwrap(),
        CommandJournal::open_memory().unwrap(),
    );
    let projection = build_alpha_projection(&adapter.capture("pilot-session").unwrap()).unwrap();
    let digest = projection.digest.clone().unwrap();
    let payload = projection_payload_bytes(&projection).unwrap();
    let value: Value = serde_json::from_slice(&payload).unwrap();
    let recomputed = projection_digest(&serde_json::from_value(value).unwrap()).unwrap();
    assert_eq!(digest, recomputed);
}

#[test]
fn verifier_accepts_exact_plus_one_and_idempotent_duplicate_but_rejects_conflict_stale_and_gap() {
    let verifier = FrameVerifier::start();
    let mut state = verifier.state.lock().unwrap();
    let session = state.sessions.entry("sess-1".to_string()).or_default();
    session.last_seq = Some(3);
    session.digest_by_seq.insert(3, "sha256:prev".to_string());
    session
        .frame_id_by_digest
        .insert("sha256:prev".to_string(), "frame-prev".to_string());
    drop(state);

    let plus_one = json!({
        "schema":"nomad.alpha.readonly.host.v1",
        "status":"available",
        "session":{"session_id":"sess-1","turn_id":"turn-1","semantics_version":"1.0.0","turn_state":"Running","host_connectivity":"Online","client_freshness":"Live","updated_at":"2026-08-18T08:00:06Z"},
        "seq":4,
        "digest":"placeholder",
        "events":[],
        "changes":{"status":"unavailable","files":[]},
        "provenance":{"source":"local-alpha-projector","relay_ingress_verified":false,"gateway_schema_verified":false}
    });
    let canonical = {
        let mut v = plus_one.clone();
        v.as_object_mut().unwrap().remove("digest");
        format!(
            "sha256:{:x}",
            Sha256::digest(alpha_canonical_json(&v).unwrap().as_bytes())
        )
    };
    let accepted = verifier.verify_and_store(&build_fake_frame(
        &plus_one
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                if k == "digest" {
                    (k.clone(), Value::String(canonical.clone()))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect(),
    ));
    assert!(accepted.is_ok());

    let duplicate = verifier.verify_and_store(&build_fake_frame(
        &plus_one
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                if k == "digest" {
                    (k.clone(), Value::String(canonical.clone()))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect(),
    ));
    assert_eq!(duplicate.unwrap().1["new"], false);

    let stale = json!({
        "schema":"nomad.alpha.readonly.host.v1",
        "status":"available",
        "session":{"session_id":"sess-1","turn_id":"turn-1","semantics_version":"1.0.0","turn_state":"Running","host_connectivity":"Online","client_freshness":"Live","updated_at":"2026-08-18T08:00:06Z"},
        "seq":2,
        "digest":"sha256:bad",
        "events":[],
        "changes":{"status":"unavailable","files":[]},
        "provenance":{"source":"local-alpha-projector","relay_ingress_verified":false,"gateway_schema_verified":false}
    });
    let stale_fixed = with_real_digest(stale);
    assert_eq!(
        verifier
            .verify_and_store(&build_fake_frame(&stale_fixed))
            .unwrap_err()
            .1["error"],
        "stale"
    );

    let gap = json!({
        "schema":"nomad.alpha.readonly.host.v1",
        "status":"available",
        "session":{"session_id":"sess-1","turn_id":"turn-1","semantics_version":"1.0.0","turn_state":"Running","host_connectivity":"Online","client_freshness":"Live","updated_at":"2026-08-18T08:00:06Z"},
        "seq":6,
        "digest":"placeholder",
        "events":[],
        "changes":{"status":"unavailable","files":[]},
        "provenance":{"source":"local-alpha-projector","relay_ingress_verified":false,"gateway_schema_verified":false}
    });
    let gap_fixed = with_real_digest(gap);
    assert_eq!(
        verifier
            .verify_and_store(&build_fake_frame(&gap_fixed))
            .unwrap_err()
            .1["error"],
        "gap"
    );

    let conflict = with_real_digest(json!({
        "schema":"nomad.alpha.readonly.host.v1",
        "status":"unknown",
        "session":{"session_id":"sess-1","turn_id":"turn-1","semantics_version":"1.0.0","turn_state":"Running","host_connectivity":"Online","client_freshness":"Live","updated_at":"2026-08-18T08:00:06Z"},
        "seq":4,
        "digest":"placeholder",
        "events":[],
        "changes":{"status":"unavailable","files":[]},
        "provenance":{"source":"local-alpha-projector","relay_ingress_verified":false,"gateway_schema_verified":false}
    }));
    assert_eq!(
        verifier
            .verify_and_store(&build_fake_frame(&conflict))
            .unwrap_err()
            .1["error"],
        "conflict"
    );
}

fn with_real_digest(mut projection: Value) -> Value {
    let mut without = projection.clone();
    without.as_object_mut().unwrap().remove("digest");
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(alpha_canonical_json(&without).unwrap().as_bytes())
    );
    projection["digest"] = Value::String(digest);
    projection
}

fn build_fake_frame(projection: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(projection).unwrap();
    let mut out = vec![0_u8; RELAY_HEADER_SIZE + RELAY_SIG_SIZE + payload.len()];
    out[0..4].copy_from_slice(&RELAY_MAGIC.to_be_bytes());
    out[40..42].copy_from_slice(&(RELAY_SIG_SIZE as u16).to_be_bytes());
    out[RELAY_HEADER_SIZE + RELAY_SIG_SIZE..].copy_from_slice(&payload);
    out
}
