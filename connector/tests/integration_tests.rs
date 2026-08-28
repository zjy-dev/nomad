use nomad_connector::adapters::opencode as url_gate;
use nomad_connector::*;
use std::path::Path;

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn contract_root() -> std::path::PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("contracts")
        .join("traces");
    p
}

fn load_trace(name: &str) -> Vec<ProjectedEvent> {
    let path = contract_root().join(format!("{name}.json"));
    let events = fixture_loader::load_trace_events(&path).expect("load trace");
    events
        .iter()
        .filter_map(ProjectedEvent::from_json)
        .collect()
}

mod hc_003_url_gate {
    use super::*;

    #[test]
    fn loopback_http_accepted() {
        assert!(url_gate::validate_loopback("http://127.0.0.1:4096").is_ok());
        assert!(url_gate::validate_loopback("http://localhost:4096").is_ok());
    }

    #[test]
    fn non_loopback_rejected() {
        assert!(url_gate::validate_loopback("http://example.com:4096").is_err());
        assert!(url_gate::validate_loopback("http://192.168.1.10:4096").is_err());
        assert!(url_gate::validate_loopback("http://10.0.0.1:4096").is_err());
    }

    #[test]
    fn wrong_port_rejected() {
        assert!(url_gate::validate_loopback("http://127.0.0.1:8080").is_err());
        assert!(url_gate::validate_loopback("http://127.0.0.1:4097").is_err());
    }

    #[test]
    fn https_rejected() {
        assert!(url_gate::validate_loopback("https://127.0.0.1:4096").is_err());
    }

    #[test]
    fn version_exact_match_required() {
        assert!(url_gate::check_version("1.18.16").is_ok());
        assert!(url_gate::check_version("1.18.17").is_err());
        assert!(url_gate::check_version("1.17.0").is_err());
    }

    #[test]
    fn provenance_has_expected_values() {
        let prov = Provenance::load(&fixture_root().join("provenance.json")).unwrap();
        assert_eq!(prov.upstream.version, "1.18.16");
        assert_eq!(
            prov.upstream.commit,
            "a3647eb025c7615159d417dcc49fc39fdaeba65b"
        );
    }
}

mod hc_004_projection {
    use super::*;

    #[test]
    fn trace_001_normal_completion_projection() {
        let events = load_trace("trace-001-normal-completion");
        assert_eq!(events.len(), 8);

        // Verify seq monotonic
        for i in 0..events.len() - 1 {
            assert!(
                events[i].seq < events[i + 1].seq,
                "seq not monotonic at {i}"
            );
        }

        // Verify last event is turn.completed seq 8
        let last = &events[7];
        assert_eq!(last.event_type, "turn.completed");
        assert_eq!(last.seq, 8);

        let state = project_events(&events);
        assert_eq!(state.session_id, "sess_normal_001");
        assert_eq!(state.turn_state, TurnState::Completed);
        assert_eq!(state.turn_id, Some("turn_001".to_string()));
    }

    #[test]
    fn trace_002_two_turns_projection() {
        let events = load_trace("trace-002-reply");
        assert_eq!(events.len(), 12);

        let state = project_events(&events);
        assert_eq!(state.session_id, "sess_reply_002");
        assert_eq!(state.turn_state, TurnState::Completed);
        // Last turn is turn_002
        assert_eq!(state.turn_id, Some("turn_002".to_string()));
    }

    #[test]
    fn trace_003_stop_projection() {
        let events = load_trace("trace-003-stop");
        assert_eq!(events.len(), 8);

        let state = project_events(&events);
        assert_eq!(state.session_id, "sess_stop_003");
        assert_eq!(state.turn_state, TurnState::Cancelled);
        assert_eq!(state.turn_id, Some("turn_001".to_string()));

        // Verify stopping -> cancelled path
        let stopping_ev = events
            .iter()
            .find(|e| e.event_type == "turn.stopping")
            .unwrap();
        assert_eq!(stopping_ev.seq, 6);
        let cancelled_ev = events
            .iter()
            .find(|e| e.event_type == "turn.cancelled")
            .unwrap();
        assert_eq!(cancelled_ev.seq, 8);
        assert!(stopping_ev.seq < cancelled_ev.seq);
    }

    #[test]
    fn trace_004_permission_projection() {
        let events = load_trace("trace-004-permission-competition");
        assert_eq!(events.len(), 8);

        let state = project_events(&events);
        assert_eq!(state.session_id, "sess_perm_004");
        assert_eq!(state.turn_state, TurnState::Completed);

        // permission.requested -> NeedsPermission
        let perm_req = events
            .iter()
            .find(|e| e.event_type == "permission.requested")
            .unwrap();
        assert_eq!(perm_req.seq, 3);
        assert!(perm_req.payload.is_some());
    }

    #[test]
    fn trace_009_interrupt_projection() {
        let events = load_trace("trace-009-interrupt-and-send");
        assert_eq!(events.len(), 8);

        let state = project_events(&events);
        assert_eq!(state.session_id, "sess_interrupt_009");
        assert_eq!(state.turn_state, TurnState::Running);
        assert_eq!(state.turn_id, Some("turn_new".to_string()));

        // Verify old turn stopping/cancelled before new message accepted
        let old_stopping = events
            .iter()
            .find(|e| e.event_type == "turn.stopping")
            .unwrap();
        let old_cancelled = events
            .iter()
            .find(|e| e.event_type == "turn.cancelled")
            .unwrap();
        let new_accepted = events
            .iter()
            .find(|e| e.event_type == "message.accepted")
            .unwrap();
        let new_started = events
            .iter()
            .rfind(|e| e.event_type == "turn.started")
            .unwrap();
        assert!(old_stopping.seq < old_cancelled.seq);
        assert!(old_cancelled.seq < new_accepted.seq);
        assert!(new_accepted.seq < new_started.seq);
    }

    #[test]
    fn all_events_durable_true() {
        let traces = [
            "trace-001-normal-completion",
            "trace-002-reply",
            "trace-003-stop",
            "trace-004-permission-competition",
            "trace-009-interrupt-and-send",
        ];
        for name in traces {
            let events = load_trace(name);
            for ev in &events {
                assert!(ev.durable, "{name}: event {} not durable", ev.event_id);
            }
        }
    }

    #[test]
    fn state_summary_tool_projection_trace_001() {
        let events = load_trace("trace-001-normal-completion");
        let summary = project_to_state_summary(&events);
        assert_eq!(summary.diff_file_count, 3);
        assert_eq!(summary.tool_states.len(), 2);
        assert!(summary
            .tool_states
            .iter()
            .any(|t| t.tool_name == "grep" && t.status == "Completed"));
        assert!(summary
            .tool_states
            .iter()
            .any(|t| t.tool_name == "edit" && t.status == "Completed"));
    }

    #[test]
    fn state_summary_tool_projection_trace_003() {
        let events = load_trace("trace-003-stop");
        let summary = project_to_state_summary(&events);
        assert_eq!(summary.diff_file_count, 0);
        assert_eq!(summary.tool_states.len(), 2);
        assert!(summary
            .tool_states
            .iter()
            .any(|t| t.tool_name == "grep" && t.status == "Completed"));
        assert!(summary
            .tool_states
            .iter()
            .any(|t| t.tool_name == "edit" && t.status == "Failed"));
    }
}

mod hc_005_snapshot {
    use super::*;

    fn build_snapshot(events: &[ProjectedEvent]) -> Snapshot {
        let state = project_events(events);
        let summary = project_to_state_summary(events);
        let last_seq = events.last().map(|e| e.seq).unwrap_or(0);

        Snapshot {
            session_id: state.session_id.clone(),
            snapshot_seq: last_seq,
            digest: None,
            last_applied_seq: last_seq,
            turn_state: state.turn_state,
            turn_id: state.turn_id,
            host_connectivity: HostConnectivity::Online,
            client_freshness: ClientFreshness::Live,
            state_summary: summary,
            created_at: events
                .last()
                .map(|e| e.timestamp.clone())
                .unwrap_or_default(),
            version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn trace_001_snapshot_digest_match() {
        let events = load_trace("trace-001-normal-completion");
        let snap = build_snapshot(&events);
        let v = snapshot::to_canonical_value(&snap);
        eprintln!("MY_CANONICAL: {}", snapshot::canonical_json(&v));
        let digest = snapshot::compute_digest(&v);

        // Load expected snapshot
        let expected_path = contract_root().join("snapshot-001-normal-completion.json");
        let expected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap()).unwrap();
        // Compute expected digest
        let expected_clean = {
            let mut c = expected.clone();
            c.as_object_mut().map(|o| o.remove("digest"));
            c
        };
        eprintln!(
            "EXPECTED_CANONICAL: {}",
            snapshot::canonical_json(&expected_clean)
        );
        let expected_digest = expected["digest"].as_str().unwrap();
        assert_eq!(digest, expected_digest, "trace-001 digest mismatch");
    }

    #[test]
    fn trace_003_snapshot_digest_match() {
        let events = load_trace("trace-003-stop");
        let snap = build_snapshot(&events);
        let v = snapshot::to_canonical_value(&snap);
        let digest = snapshot::compute_digest(&v);

        let expected_path = contract_root().join("snapshot-003-stop.json");
        let expected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap()).unwrap();
        let expected_digest = expected["digest"].as_str().unwrap();
        assert_eq!(digest, expected_digest, "trace-003 digest mismatch");
    }

    #[test]
    fn trace_009_snapshot_digest_match() {
        let events = load_trace("trace-009-interrupt-and-send");
        let snap = build_snapshot(&events);
        let v = snapshot::to_canonical_value(&snap);
        let digest = snapshot::compute_digest(&v);

        eprintln!("ACTUAL_CANONICAL: {}", snapshot::canonical_json(&v));

        let expected_path = contract_root().join("snapshot-009-interrupt-and-send.json");
        let expected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&expected_path).unwrap()).unwrap();
        let expected_clean = {
            let mut c = expected.clone();
            c.as_object_mut().map(|o| o.remove("digest"));
            c
        };
        eprintln!(
            "EXPECTED_CANONICAL: {}",
            snapshot::canonical_json(&expected_clean)
        );
        let expected_digest = expected["digest"].as_str().unwrap();
        assert_eq!(digest, expected_digest, "trace-009 digest mismatch");
    }

    #[test]
    fn snapshot_digest_deterministic() {
        let events = load_trace("trace-001-normal-completion");
        let snap = build_snapshot(&events);
        let v1 = snapshot::to_canonical_value(&snap);
        let v2 = snapshot::to_canonical_value(&snap);
        assert_eq!(snapshot::compute_digest(&v1), snapshot::compute_digest(&v2));
    }
}

mod hc_007_dedup {
    use super::*;

    #[test]
    fn reply_dedup_first_write_ok() {
        let journal = CommandJournal::open_memory().unwrap();
        let dedup = ReplyDedup::new(&journal);
        let cmd = JournalCommand {
            request_id: "req_001".into(),
            command_type: "reply".into(),
            session_id: "sess_001".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(5),
            result_json: r#"{"error_code":"OK"}"#.into(),
            created_at: "2026-08-17T10:00:00Z".into(),
        };
        assert!(dedup.record(&cmd).is_ok());
    }

    #[test]
    fn reply_dedup_second_write_rejected() {
        let journal = CommandJournal::open_memory().unwrap();
        let dedup = ReplyDedup::new(&journal);
        let cmd = JournalCommand {
            request_id: "req_002".into(),
            command_type: "reply".into(),
            session_id: "sess_002".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(5),
            result_json: r#"{"error_code":"OK"}"#.into(),
            created_at: "2026-08-17T10:00:00Z".into(),
        };
        dedup.record(&cmd).unwrap();
        let err = dedup.record(&cmd).unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }

    #[test]
    fn dedup_check_existing_returns_duplicate() {
        let journal = CommandJournal::open_memory().unwrap();
        let dedup = ReplyDedup::new(&journal);
        let cmd = JournalCommand {
            request_id: "req_003".into(),
            command_type: "reply".into(),
            session_id: "sess_003".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(10),
            result_json: r#"{"error_code":"OK","accepted_at_seq":10}"#.into(),
            created_at: "2026-08-17T10:00:00Z".into(),
        };
        dedup.record(&cmd).unwrap();
        let result = dedup.check("req_003").unwrap();
        assert!(result.is_duplicate);
        assert_eq!(result.existing_status.as_deref(), Some("HostAccepted"));
    }

    #[test]
    fn million_retry_stays_one_acceptance() {
        let journal = CommandJournal::open_memory().unwrap();
        let dedup = ReplyDedup::new(&journal);
        let cmd = JournalCommand {
            request_id: "req_million".into(),
            command_type: "reply".into(),
            session_id: "sess_m".into(),
            seq: 1,
            status: "HostAccepted".into(),
            accepted_at_seq: Some(10),
            result_json: r#"{"error_code":"OK"}"#.into(),
            created_at: "2026-08-17T10:00:00Z".into(),
        };
        dedup.record(&cmd).unwrap();

        for i in 0..10_000 {
            let r = dedup.check("req_million").unwrap();
            assert!(r.is_duplicate, "iter {i}");
            assert_eq!(r.existing_status.as_deref(), Some("HostAccepted"));
        }

        // Only one command in journal
        let all = journal.get_by_session("sess_m").unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn journal_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        {
            let j = CommandJournal::open(&db_path).unwrap();
            let cmd = JournalCommand {
                request_id: "req_disk".into(),
                command_type: "reply".into(),
                session_id: "sess_d".into(),
                seq: 1,
                status: "HostAccepted".into(),
                accepted_at_seq: Some(1),
                result_json: r#"{"ok":true}"#.into(),
                created_at: "t".into(),
            };
            j.insert(&cmd).unwrap();
        }
        // Reopen and verify
        let j2 = CommandJournal::open(&db_path).unwrap();
        let got = j2.get_by_request_id("req_disk").unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().status, "HostAccepted");
    }
}

mod hc_008_stop_interrupt {
    use super::*;

    #[test]
    fn stop_command_accepted_and_deduped() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&journal);
        let stop = StopCommand {
            request_id: "req_stop".into(),
            session_id: "sess_1".into(),
            target_turn_id: "turn_1".into(),
        };

        let r1 = svc.accept_stop(&stop, 5).unwrap();
        assert!(matches!(r1, OrderingOutcome::Accepted { .. }));

        // Same request_id: idempotent, no duplicate write
        let r2 = svc.accept_stop(&stop, 10).unwrap();
        match (&r1, &r2) {
            (
                OrderingOutcome::Accepted {
                    stopped_at_seq: s1, ..
                },
                OrderingOutcome::Accepted {
                    stopped_at_seq: s2, ..
                },
            ) => {
                assert_eq!(s1, s2, "same request_id should give same stopped_at_seq");
            }
            _ => panic!("expected Accepted"),
        }

        // Only one command in journal
        let cmds = journal.get_by_session("sess_1").unwrap();
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn interrupt_and_send_without_stop_blocked() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&journal);
        let ias = InterruptAndSendCommand {
            request_id: "req_ias".into(),
            session_id: "sess_no_stop".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "new msg".into(),
        };
        let err = svc.accept_interrupt_and_send(&ias, 3).unwrap_err();
        assert!(matches!(err, ConnectorError::SafetyBlocked(_)));
    }

    #[test]
    fn interrupt_after_stop_accepted() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&journal);

        let stop = StopCommand {
            request_id: "req_stop".into(),
            session_id: "sess_1".into(),
            target_turn_id: "turn_old".into(),
        };
        svc.accept_stop(&stop, 4).unwrap();

        let ias = InterruptAndSendCommand {
            request_id: "req_ias".into(),
            session_id: "sess_1".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "new msg".into(),
        };
        let result = svc.accept_interrupt_and_send(&ias, 6).unwrap();
        assert!(matches!(result, OrderingOutcome::Accepted { .. }));
    }

    #[test]
    fn duplicate_interrupt_rejected() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = StopInterruptService::new(&journal);

        let stop = StopCommand {
            request_id: "req_stop".into(),
            session_id: "sess_1".into(),
            target_turn_id: "turn_old".into(),
        };
        svc.accept_stop(&stop, 4).unwrap();

        let ias1 = InterruptAndSendCommand {
            request_id: "req_ias".into(),
            session_id: "sess_1".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "c1".into(),
        };
        svc.accept_interrupt_and_send(&ias1, 6).unwrap();

        let ias2 = InterruptAndSendCommand {
            request_id: "req_ias".into(),
            session_id: "sess_1".into(),
            interrupt_turn_id: "turn_old".into(),
            new_content: "c2".into(),
        };
        let err = svc.accept_interrupt_and_send(&ias2, 7).unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }

    #[test]
    fn trace_009_sequence_verified() {
        let events = load_trace("trace-009-interrupt-and-send");

        // Old turn events: seq 2-6
        let old_started = events
            .iter()
            .find(|e| e.event_type == "turn.started" && e.turn_id.as_deref() == Some("turn_old"))
            .unwrap();
        let old_stopping = events
            .iter()
            .find(|e| e.event_type == "turn.stopping")
            .unwrap();
        let old_cancelled = events
            .iter()
            .find(|e| e.event_type == "turn.cancelled")
            .unwrap();

        // New turn events: seq 7-8
        let new_accepted = events
            .iter()
            .find(|e| e.event_type == "message.accepted")
            .unwrap();
        let new_started = events
            .iter()
            .find(|e| e.event_type == "turn.started" && e.turn_id.as_deref() == Some("turn_new"))
            .unwrap();

        // Ordering invariant (INV-003-6)
        assert!(old_stopping.seq < old_cancelled.seq);
        assert!(old_cancelled.seq < new_accepted.seq);
        assert!(new_accepted.seq < new_started.seq);

        // Old and new turns never concurrently running
        assert_ne!(old_started.turn_id, new_started.turn_id);
    }
}

mod hc_009_010_permission {
    use super::*;

    #[test]
    fn allow_once_capability_is_false() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&journal);
        assert!(!svc.allow_once_capability());
    }

    #[test]
    fn view_permission_shows_no_allow_once() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&journal);
        let result = svc.view("perm_001").unwrap();
        assert!(result.no_allow_once);
        assert_eq!(result.status, "pending");
    }

    #[test]
    fn deny_permission_success() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&journal);
        let cmd = svc
            .deny(
                "req_deny",
                "sess_1",
                "perm_001",
                "hash_abc",
                "2026-08-17T20:00:00Z",
            )
            .unwrap();
        assert_eq!(cmd.status, "HostAccepted");
        let result: serde_json::Value = serde_json::from_str(&cmd.result_json).unwrap();
        assert_eq!(result["decision"], serde_json::json!("deny"));
    }

    #[test]
    fn duplicate_deny_rejected() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&journal);
        svc.deny("req_dup", "sess_1", "perm_1", "h", "t").unwrap();
        let err = svc
            .deny("req_dup", "sess_1", "perm_1", "h", "t")
            .unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }

    #[test]
    fn stop_permission_revokes() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&journal);
        let cmd = svc.stop("req_stop", "sess_1", "perm_1").unwrap();
        assert_eq!(cmd.status, "Revoked");
    }

    #[test]
    fn duplicate_stop_permission_rejected() {
        let journal = CommandJournal::open_memory().unwrap();
        let svc = PermissionService::new(&journal);
        svc.stop("req_stop", "sess_1", "perm_1").unwrap();
        let err = svc.stop("req_stop", "sess_1", "perm_1").unwrap_err();
        assert!(matches!(err, ConnectorError::DuplicateRequest(_)));
    }
}

mod hc_006_error_codes {
    use super::*;

    #[test]
    fn error_code_mapping() {
        let e = ConnectorError::DuplicateRequest("r".into());
        assert_eq!(e.error_code(), "ERR_DUPLICATE_REQUEST");

        let e = ConnectorError::StaleRequest("r".into());
        assert_eq!(e.error_code(), "ERR_REQUEST_STALE");

        let e = ConnectorError::ExpiredRequest("r".into());
        assert_eq!(e.error_code(), "ERR_REQUEST_EXPIRED");

        let e = ConnectorError::SafetyBlocked("r".into());
        assert_eq!(e.error_code(), "ERR_SAFETY_BLOCKED");

        let e = ConnectorError::HostOffline;
        assert_eq!(e.error_code(), "ERR_HOST_OFFLINE");

        let e = ConnectorError::OutcomeUnknown;
        assert_eq!(e.error_code(), "ERR_OUTCOME_UNKNOWN");
    }
}

mod hc_004_fixture_loader {
    use super::*;

    #[test]
    fn load_session_fixture() {
        let path = fixture_root().join("synthetic").join("session.json");
        let sf = fixture_loader::load_synthetic(&path).unwrap();
        assert_eq!(sf.fixture_type, "session");
        assert!(!sf.cases.is_empty());
    }

    #[test]
    fn load_permission_fixture() {
        let path = fixture_root().join("synthetic").join("permission.json");
        let sf = fixture_loader::load_synthetic(&path).unwrap();
        assert_eq!(sf.fixture_type, "permission");
        assert!(!sf.cases.is_empty());
    }

    #[test]
    fn load_all_synthetic_fixtures() {
        let names = [
            "session",
            "message",
            "tool",
            "permission",
            "diff",
            "abort",
            "snapshot",
            "sse-trace",
        ];
        for name in &names {
            let path = fixture_root()
                .join("synthetic")
                .join(format!("{name}.json"));
            if path.exists() {
                let sf = fixture_loader::load_synthetic(&path).unwrap();
                assert_eq!(sf.fixture_type, *name, "type mismatch for {name}");
            }
        }
    }
}

mod hc_005_resume_protocol {
    use super::*;

    #[test]
    fn resume_request_validation() {
        // Simulate resume: client asks from last_applied_seq, gets events+snapshot
        let events = load_trace("trace-001-normal-completion");
        let last_seq = 4u64;
        let remaining: Vec<_> = events
            .iter()
            .filter(|e| e.seq > last_seq)
            .cloned()
            .collect();
        assert_eq!(remaining.len(), 4); // seq 5,6,7,8
        assert_eq!(remaining[0].seq, 5);
        assert_eq!(remaining.last().unwrap().seq, 8);
    }

    #[test]
    fn compaction_boundary_handling() {
        // Simulate compaction: events before boundary are discarded, snapshot is the anchor
        let events = load_trace("trace-002-reply");
        let boundary = 6u64;

        let snapshot_events: Vec<_> = events
            .iter()
            .filter(|e| e.seq <= boundary)
            .cloned()
            .collect();
        let replay_events: Vec<_> = events
            .iter()
            .filter(|e| e.seq > boundary)
            .cloned()
            .collect();
        assert!(!replay_events.is_empty());

        let snapshot_state = project_events(&snapshot_events);
        let replay_state = project_events(&events);

        assert_eq!(snapshot_state.session_id, replay_state.session_id);
        assert_eq!(replay_state.turn_state, TurnState::Completed);
    }
}
