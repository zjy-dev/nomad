use crate::projection::Snapshot;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn compute_digest(snapshot_without_digest: &Value) -> String {
    let canonical = canonical_json(snapshot_without_digest);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    format!("sha256:{hex}")
}

pub fn canonical_json(value: &Value) -> String {
    // Use serde_json's compact formatter which naturally sorts keys and uses compact separators
    serde_json::to_string(value)
        .unwrap_or_else(|_| "{}".to_string())
        .replace(", ", ",")
        .replace(": ", ":")
        .replace("\\\"", "\"")
}

// Proper canonical JSON: sort keys, compact separators
pub fn to_canonical_value(snapshot: &Snapshot) -> Value {
    let mut v = serde_json::to_value(snapshot).unwrap_or(Value::Null);
    // Remove digest for computation
    if let Some(obj) = v.as_object_mut() {
        obj.remove("digest");
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::StateSummary;

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            session_id: "sess_1".into(),
            snapshot_seq: 8,
            digest: None,
            last_applied_seq: 8,
            turn_state: crate::projection::TurnState::Completed,
            turn_id: Some("turn_001".into()),
            host_connectivity: crate::projection::HostConnectivity::Online,
            client_freshness: crate::projection::ClientFreshness::Live,
            state_summary: StateSummary {
                session_status: Some("active".into()),
                active_turn: None,
                active_permission: None,
                diff_file_count: 3,
                test_status: None,
                tool_states: vec![],
            },
            created_at: "2026-08-17T10:00:10Z".into(),
            version: "1.0.0".into(),
        }
    }

    #[test]
    fn digest_format() {
        let snap = sample_snapshot();
        let v = to_canonical_value(&snap);
        let digest = compute_digest(&v);
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn deterministic() {
        let snap = sample_snapshot();
        let v1 = to_canonical_value(&snap);
        let v2 = to_canonical_value(&snap);
        assert_eq!(compute_digest(&v1), compute_digest(&v2));
    }

    #[test]
    fn different_data_different_digest() {
        let snap1 = sample_snapshot();
        let mut snap2 = sample_snapshot();
        snap2.state_summary.diff_file_count = 5;
        let v1 = to_canonical_value(&snap1);
        let v2 = to_canonical_value(&snap2);
        assert_ne!(compute_digest(&v1), compute_digest(&v2));
    }

    #[test]
    fn snapshot_with_digest_roundtrip() {
        let snap = sample_snapshot();
        let v = to_canonical_value(&snap);
        let digest = compute_digest(&v);
        assert!(digest.starts_with("sha256:"));
        // Snapshot with digest field set should compute same digest when digest is stripped
        let mut snap_d = snap.clone();
        snap_d.digest = Some(digest.clone());
        let v_d = to_canonical_value(&snap_d);
        assert_eq!(compute_digest(&v_d), digest);
    }
}
