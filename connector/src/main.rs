use nomad_connector::dedup::ReplyDedup;
use nomad_connector::error::ConnectorError;
use nomad_connector::journal::CommandJournal;
use nomad_connector::permission::PermissionService;
use nomad_connector::projection::*;
use nomad_connector::snapshot;
use nomad_connector::stop_interrupt::StopInterruptService;
use nomad_connector::url_gate;

fn main() {
    println!("Nomad Connector Host Core");

    // HC-003: URL/version gate
    match url_gate::validate_loopback("http://127.0.0.1:4096") {
        Ok(()) => println!("Loopback URL gate: PASS"),
        Err(e) => println!("Loopback URL gate: FAIL - {e}"),
    }
    match url_gate::check_version(url_gate::EXPECTED_VERSION) {
        Ok(()) => println!("Version check: PASS ({})", url_gate::EXPECTED_VERSION),
        Err(e) => println!("Version check: FAIL - {e}"),
    }

    // HC-007: Dedup smoke test
    let journal = CommandJournal::open_memory().expect("open journal");
    let dedup = ReplyDedup::new(&journal);

    let cmd = nomad_connector::journal::JournalCommand {
        request_id: "req_demo_001".into(),
        command_type: "reply".into(),
        session_id: "sess_demo".into(),
        seq: 1,
        status: "HostAccepted".into(),
        accepted_at_seq: Some(10),
        result_json: r#"{"error_code":"OK"}"#.into(),
        created_at: "2026-08-17T10:00:00Z".into(),
    };
    match dedup.record(&cmd) {
        Ok(()) => println!("Dedup first write: OK"),
        Err(e) => println!("Dedup first write: FAIL - {e}"),
    }
    match dedup.record(&cmd) {
        Ok(()) => println!("Dedup second write: OK (unexpected)"),
        Err(ConnectorError::DuplicateRequest(id)) => {
            println!("Dedup second write: DuplicateRequest({id}) as expected")
        }
        Err(e) => println!("Dedup second write: unexpected error - {e}"),
    }

    // HC-005: Snapshot digest smoke test
    let snap = Snapshot {
        session_id: "sess_demo".into(),
        snapshot_seq: 1,
        digest: None,
        last_applied_seq: 1,
        turn_state: TurnState::Running,
        turn_id: Some("turn_1".into()),
        host_connectivity: HostConnectivity::Online,
        client_freshness: ClientFreshness::Live,
        state_summary: StateSummary {
            session_status: Some("active".into()),
            active_turn: Some("turn_1".into()),
            active_permission: None,
            diff_file_count: 0,
            test_status: None,
            tool_states: vec![],
        },
        created_at: "2026-08-17T10:00:00Z".into(),
        version: "1.0.0".into(),
    };
    let v = snapshot::to_canonical_value(&snap);
    let digest = snapshot::compute_digest(&v);
    println!("Snapshot digest: {digest}");

    // HC-009/010: Permission smoke test
    let perm_svc = PermissionService::new(&journal);
    println!(
        "allow_once capability: {}",
        perm_svc.allow_once_capability()
    );

    // HC-008: Stop/interrupt smoke test
    let si_svc = StopInterruptService::new(&journal);
    let stop = nomad_connector::stop_interrupt::StopCommand {
        request_id: "req_stop_demo".into(),
        session_id: "sess_demo".into(),
        target_turn_id: "turn_1".into(),
    };
    match si_svc.accept_stop(&stop, 2) {
        Ok(nomad_connector::stop_interrupt::OrderingOutcome::Accepted {
            stopped_at_seq, ..
        }) => {
            println!("Stop accepted at seq {stopped_at_seq}");
        }
        Err(e) => println!("Stop: FAIL - {e}"),
        _ => {}
    }

    println!("Host core demo complete.");
}
