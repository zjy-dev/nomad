use nomad_connector::adapters::opencode::{
    current_release_authorization, APPROVAL_EXPIRED_OR_INVALID,
};
use nomad_connector::{
    parse_release_container, ConnectorError, HistoricalReleaseEvidence, ReleaseBundleError,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn digest_json(value: &Value) -> String {
    fn canonical(value: &Value) -> String {
        match value {
            Value::Null => "null".into(),
            Value::Bool(v) => v.to_string(),
            Value::Number(v) => v.to_string(),
            Value::String(v) => serde_json::to_string(v).unwrap(),
            Value::Array(v) => format!(
                "[{}]",
                v.iter().map(canonical).collect::<Vec<_>>().join(",")
            ),
            Value::Object(v) => {
                let mut keys: Vec<_> = v.keys().collect();
                keys.sort();
                format!(
                    "{{{}}}",
                    keys.into_iter()
                        .map(|k| format!(
                            "{}:{}",
                            serde_json::to_string(k).unwrap(),
                            canonical(&v[k])
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
        }
    }
    format!("{:x}", Sha256::digest(canonical(value).as_bytes()))
}
fn raw(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
fn seal(mut value: Value, field: &str) -> Value {
    let d = digest_json(&value);
    value
        .as_object_mut()
        .unwrap()
        .insert(field.into(), Value::String(d));
    value
}
fn container(entries: BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = b"NOMADREL".to_vec();
    out.extend(1u16.to_be_bytes());
    out.push(1);
    out.extend((entries.len() as u32).to_be_bytes());
    for (name, data) in entries {
        out.extend((name.len() as u16).to_be_bytes());
        out.extend(name.as_bytes());
        out.extend((data.len() as u32).to_be_bytes());
        out.extend(Sha256::digest(&data));
        out.extend(data);
    }
    out
}
fn reframe_entry(raw: &[u8], target: &str, replacement: Vec<u8>) -> Vec<u8> {
    let count = u32::from_be_bytes(raw[11..15].try_into().unwrap()) as usize;
    let mut cursor = 15;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let name_len = u16::from_be_bytes(raw[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        let name = String::from_utf8(raw[cursor..cursor + name_len].to_vec()).unwrap();
        cursor += name_len;
        let data_len = u32::from_be_bytes(raw[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4 + 32;
        let data = raw[cursor..cursor + data_len].to_vec();
        cursor += data_len;
        entries.insert(
            name.clone(),
            if name == target {
                replacement.clone()
            } else {
                data
            },
        );
    }
    assert_eq!(cursor, raw.len());
    container(entries)
}
fn valid_with_approval(
    approval_schema: &str,
    approval_scope: &str,
    signing_namespace: &str,
    issued_at: &str,
    expires_at: &str,
    signature_entry: &[u8],
    signature_manifest_basis: &[u8],
) -> Vec<u8> {
    let cert = br#"{"schema":"cert"}"#.to_vec();
    let shape = br#"{"schema":"shape"}"#.to_vec();
    let evidence = json!({
        "schema_version":"nomad.stock-opencode.evidence-manifest.v1",
        "certificate_digest":"1111111111111111111111111111111111111111111111111111111111111111",
        "shape_manifest_digest":"2222222222222222222222222222222222222222222222222222222222222222",
        "certificate_structural_digest":"3333333333333333333333333333333333333333333333333333333333333333",
        "source_binding_digest":"4444444444444444444444444444444444444444444444444444444444444444",
        "historical_certified_launch_provenance_digest":"5555555555555555555555555555555555555555555555555555555555555555",
        "task_spec_digest":"6666666666666666666666666666666666666666666666666666666666666666",
        "fixture_manifest_digest":"7777777777777777777777777777777777777777777777777777777777777777",
        "command_shapes_canonical_digest":"8888888888888888888888888888888888888888888888888888888888888888",
        "rule_config_digest":"9999999999999999999999999999999999999999999999999999999999999999",
        "current_committed_evidence_provenance_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reviewed_version":"v0.1.0",
        "evidence_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    let ev = serde_json::to_vec(&evidence).unwrap();
    let approval = json!({"schema_version":approval_schema,"evidence_manifest_digest":evidence["evidence_manifest_digest"],"reviewed_version":"v0.1.0","scope":approval_scope,"principal":"dri","issued_at":issued_at,"expires_at":expires_at,"trust_root_id":"root","signing_namespace":signing_namespace,"signature_file":"release-approval-record.sshsig"});
    let approval_bytes = serde_json::to_vec(&approval).unwrap();
    let sig = signature_entry.to_vec();
    let descriptors = json!({"lifecycle-certificate.json":{"raw_sha256":raw(&cert),"size_bytes":cert.len()},"lifecycle-evidence-manifest.json":{"raw_sha256":raw(&ev),"size_bytes":ev.len()},"lifecycle-shape-manifest.json":{"raw_sha256":raw(&shape),"size_bytes":shape.len()}});
    let manifest = seal(
        json!({"schema_version":"nomad.agent-evidence.bundle-manifest.v1","adapter_id":"opencode","adapter_version":"1.18.16","adapter_contract_digest":"1461500ae84735435bf448e1f74c8f4e3b5d73ba173c1895b4de46377409fa68","approval_scope":"nomad.m2.complete-evidence-bundle","reviewed_version":"v0.1.0","evidence_manifest_digest":evidence["evidence_manifest_digest"],"approval_record_digest":raw(&approval_bytes),"approval_signature_raw_digest":raw(signature_manifest_basis),"trust_root_id":"root","adapter_artifacts":descriptors}),
        "bundle_manifest_digest",
    );
    let index = seal(
        json!({"schema_version":"nomad.agent-evidence.release-index.v1","active_bundle_id":format!("sha256-{}",manifest["bundle_manifest_digest"].as_str().unwrap()),"bundle_manifest_digest":manifest["bundle_manifest_digest"],"adapter_id":"opencode","adapter_version":"1.18.16","reviewed_version":"v0.1.0","evidence_manifest_digest":evidence["evidence_manifest_digest"],"approval_record_digest":raw(&approval_bytes),"previous_release_index_digest":"0000000000000000000000000000000000000000000000000000000000000000","release_sequence":1}),
        "release_index_digest",
    );
    let meta = seal(
        json!({"schema_version":"nomad.agent-evidence.embedded-release.v1","source_commit_oid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_parent_oid":"cccccccccccccccccccccccccccccccccccccccc","release_index_digest":index["release_index_digest"],"bundle_manifest_digest":manifest["bundle_manifest_digest"],"adapter_id":"opencode","adapter_version":"1.18.16","adapter_contract_digest":"1461500ae84735435bf448e1f74c8f4e3b5d73ba173c1895b4de46377409fa68","reviewed_version":"v0.1.0","evidence_manifest_digest":evidence["evidence_manifest_digest"],"approval_record_digest":raw(&approval_bytes),"approval_signature_raw_digest":raw(&sig),"trust_root_id":"root"}),
        "metadata_digest",
    );
    let mut entries = BTreeMap::new();
    entries.insert("adapter/lifecycle-certificate.json".into(), cert);
    entries.insert("adapter/lifecycle-evidence-manifest.json".into(), ev);
    entries.insert("adapter/lifecycle-shape-manifest.json".into(), shape);
    entries.insert(
        "outer/bundle-manifest.json".into(),
        serde_json::to_vec(&manifest).unwrap(),
    );
    entries.insert(
        "outer/current.json".into(),
        serde_json::to_vec(&index).unwrap(),
    );
    entries.insert(
        "outer/embedded-meta.json".into(),
        serde_json::to_vec(&meta).unwrap(),
    );
    entries.insert("outer/release-approval-record.json".into(), approval_bytes);
    entries.insert("outer/release-approval-record.sshsig".into(), sig);
    container(entries)
}
fn valid() -> Vec<u8> {
    valid_with_approval(
        "nomad.stock-opencode.approval-record.v1",
        "nomad.m2.complete-evidence-bundle",
        "nomad-m2-release-authorization-v1",
        "2026-08-20T00:00:00Z",
        "2026-08-21T00:00:00Z",
        b"sig",
        b"sig",
    )
}
#[test]
fn embedded_default_is_unavailable() {
    assert_eq!(
        nomad_connector::embedded_release().unwrap(),
        HistoricalReleaseEvidence::Unavailable
    );
}
#[test]
fn unavailable_exact() {
    let mut x = b"NOMADREL".to_vec();
    x.extend(1u16.to_be_bytes());
    x.push(0);
    x.extend(0u32.to_be_bytes());
    assert_eq!(
        parse_release_container(&x).unwrap(),
        HistoricalReleaseEvidence::Unavailable
    );
    let mut y = x.clone();
    y.push(0);
    assert_eq!(
        parse_release_container(&y),
        Err(ReleaseBundleError::Framing)
    );
}
#[test]
fn verified_vector_parses() {
    match parse_release_container(&valid()).unwrap() {
        HistoricalReleaseEvidence::Verified(_) => {}
        _ => panic!(),
    }
}
#[test]
fn approval_policy_fields_are_exact() {
    for raw in [
        valid_with_approval(
            "wrong-schema",
            "nomad.m2.complete-evidence-bundle",
            "nomad-m2-release-authorization-v1",
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            b"sig",
            b"sig",
        ),
        valid_with_approval(
            "nomad.stock-opencode.approval-record.v1",
            "wrong-scope",
            "nomad-m2-release-authorization-v1",
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            b"sig",
            b"sig",
        ),
        valid_with_approval(
            "nomad.stock-opencode.approval-record.v1",
            "nomad.m2.complete-evidence-bundle",
            "wrong-namespace",
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            b"sig",
            b"sig",
        ),
    ] {
        assert_eq!(
            parse_release_container(&raw),
            Err(ReleaseBundleError::Schema)
        );
    }
}
#[test]
fn reframed_signature_mutation_is_rejected_by_manifest_binding() {
    let raw = valid_with_approval(
        "nomad.stock-opencode.approval-record.v1",
        "nomad.m2.complete-evidence-bundle",
        "nomad-m2-release-authorization-v1",
        "2026-08-20T00:00:00Z",
        "2026-08-21T00:00:00Z",
        b"tampered-signature",
        b"sig",
    );
    assert_eq!(
        parse_release_container(&raw),
        Err(ReleaseBundleError::Binding)
    );
}
#[test]
fn approval_exact_fields_duplicate_keys_and_raw_binding_are_enforced() {
    let base = valid();
    let target = "outer/release-approval-record.json";
    let approval = {
        let count = u32::from_be_bytes(base[11..15].try_into().unwrap()) as usize;
        let mut cursor = 15;
        let mut found = None;
        for _ in 0..count {
            let name_len =
                u16::from_be_bytes(base[cursor..cursor + 2].try_into().unwrap()) as usize;
            cursor += 2;
            let name = std::str::from_utf8(&base[cursor..cursor + name_len]).unwrap();
            cursor += name_len;
            let data_len =
                u32::from_be_bytes(base[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4 + 32;
            if name == target {
                found = Some(base[cursor..cursor + data_len].to_vec());
            }
            cursor += data_len;
        }
        found.unwrap()
    };
    let mut extra: Value = serde_json::from_slice(&approval).unwrap();
    extra
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), json!(true));
    assert_eq!(
        parse_release_container(&reframe_entry(
            &base,
            target,
            serde_json::to_vec(&extra).unwrap()
        )),
        Err(ReleaseBundleError::Schema)
    );
    let mut missing: Value = serde_json::from_slice(&approval).unwrap();
    missing.as_object_mut().unwrap().remove("issued_at");
    assert_eq!(
        parse_release_container(&reframe_entry(
            &base,
            target,
            serde_json::to_vec(&missing).unwrap()
        )),
        Err(ReleaseBundleError::Schema)
    );
    let mut duplicate = approval.clone();
    duplicate.pop();
    duplicate.extend_from_slice(br#","scope":"nomad.m2.complete-evidence-bundle"}"#);
    assert_eq!(
        parse_release_container(&reframe_entry(&base, target, duplicate)),
        Err(ReleaseBundleError::Schema)
    );
    let mut whitespace = approval;
    whitespace.push(b' ');
    assert_eq!(
        parse_release_container(&reframe_entry(&base, target, whitespace)),
        Err(ReleaseBundleError::Binding)
    );
}

fn authorization_result(issued_at: &str, expires_at: &str) -> Result<(), ConnectorError> {
    let raw = valid_with_approval(
        "nomad.stock-opencode.approval-record.v1",
        "nomad.m2.complete-evidence-bundle",
        "nomad-m2-release-authorization-v1",
        issued_at,
        expires_at,
        b"sig",
        b"sig",
    );
    let HistoricalReleaseEvidence::Verified(evidence) = parse_release_container(&raw).unwrap()
    else {
        panic!("verified fixture became unavailable");
    };
    current_release_authorization(&evidence).map(|_| ())
}

fn assert_invalid(issued_at: &str, expires_at: &str) {
    match authorization_result(issued_at, expires_at) {
        Err(ConnectorError::SafetyBlocked(message)) => {
            assert_eq!(message, APPROVAL_EXPIRED_OR_INVALID)
        }
        _ => panic!("approval unexpectedly authorized or returned an unstable error"),
    }
}

#[test]
fn caller_supplied_verified_container_cannot_authorize_current_release() {
    assert_invalid("2026-08-20T00:00:00Z", "2026-08-21T00:00:00Z");
}
#[test]
fn truncation_digest_and_order_fail() {
    let x = valid();
    assert!(parse_release_container(&x[..x.len() - 1]).is_err());
    let mut y = x.clone();
    *y.last_mut().unwrap() ^= 1;
    assert!(parse_release_container(&y).is_err());
    let mut z = x.clone();
    z[15..17].copy_from_slice(&1u16.to_be_bytes());
    z[17] = b'z';
    assert!(parse_release_container(&z).is_err());
}
