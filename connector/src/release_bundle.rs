//! Commit-bound, agent-neutral embedded release container parsing.
//! Parsing historical bytes never grants runtime command authority.
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAGIC: &[u8; 8] = b"NOMADREL";
const VERSION: u16 = 1;
const MAX_CONTAINER: usize = 2 * 1024 * 1024;
const MAX_ENTRY: usize = 512 * 1024;
const MAX_ENTRIES: usize = 64;
const OPENCODE_CONTRACT_DIGEST: &str =
    "1461500ae84735435bf448e1f74c8f4e3b5d73ba173c1895b4de46377409fa68";
const OPENCODE_APPROVAL_SCOPE: &str = "nomad.m2.complete-evidence-bundle";
const OPENCODE_APPROVAL_SCHEMA: &str = "nomad.stock-opencode.approval-record.v1";
const OPENCODE_SIGNING_NAMESPACE: &str = "nomad-m2-release-authorization-v1";
const META_FIELDS: &[&str] = &[
    "schema_version",
    "source_commit_oid",
    "expected_parent_oid",
    "release_index_digest",
    "bundle_manifest_digest",
    "adapter_id",
    "adapter_version",
    "adapter_contract_digest",
    "reviewed_version",
    "evidence_manifest_digest",
    "approval_record_digest",
    "approval_signature_raw_digest",
    "trust_root_id",
    "metadata_digest",
];
const APPROVAL_FIELDS: &[&str] = &[
    "schema_version",
    "evidence_manifest_digest",
    "reviewed_version",
    "scope",
    "principal",
    "issued_at",
    "expires_at",
    "trust_root_id",
    "signing_namespace",
    "signature_file",
];
const EVIDENCE_FIELDS: &[&str] = &[
    "schema_version",
    "certificate_digest",
    "shape_manifest_digest",
    "certificate_structural_digest",
    "source_binding_digest",
    "historical_certified_launch_provenance_digest",
    "task_spec_digest",
    "fixture_manifest_digest",
    "command_shapes_canonical_digest",
    "rule_config_digest",
    "current_committed_evidence_provenance_digest",
    "reviewed_version",
    "evidence_manifest_digest",
];

static EMBEDDED: &[u8] = include_bytes!(env!("NOMAD_EMBEDDED_RELEASE_PATH"));

#[derive(Debug, PartialEq, Eq)]
pub enum HistoricalReleaseEvidence {
    Unavailable,
    Verified(Box<VerifiedHistoricalEvidence>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedHistoricalEvidence {
    provenance: EvidenceProvenance,
    source_commit_oid: String,
    release_index_digest: String,
    bundle_manifest_digest: String,
    adapter_id: String,
    adapter_version: String,
    reviewed_version: String,
    evidence_manifest_digest: String,
    approval_schema_version: String,
    approval_record_digest: String,
    approval_signature_raw_digest: String,
    approval_scope: String,
    issued_at: String,
    expires_at: String,
    signing_namespace: String,
    trust_root_id: String,
}

#[derive(Debug, PartialEq, Eq)]
enum EvidenceProvenance {
    Embedded,
    CallerSupplied,
}

#[allow(dead_code)] // Consumed by the next stock-opencode authorization integration step.
pub(crate) struct CurrentApprovalFields<'a> {
    pub(crate) is_embedded: bool,
    pub(crate) release_index_digest: &'a str,
    pub(crate) bundle_manifest_digest: &'a str,
    pub(crate) evidence_manifest_digest: &'a str,
    pub(crate) reviewed_version: &'a str,
    pub(crate) approval_schema_version: &'a str,
    pub(crate) approval_record_digest: &'a str,
    pub(crate) approval_signature_raw_digest: &'a str,
    pub(crate) approval_scope: &'a str,
    pub(crate) issued_at: &'a str,
    pub(crate) expires_at: &'a str,
    pub(crate) signing_namespace: &'a str,
    pub(crate) trust_root_id: &'a str,
}

impl VerifiedHistoricalEvidence {
    #[allow(dead_code)] // Consumed by the next stock-opencode authorization integration step.
    pub(crate) fn current_approval_fields(&self) -> CurrentApprovalFields<'_> {
        CurrentApprovalFields {
            is_embedded: self.provenance == EvidenceProvenance::Embedded,
            release_index_digest: &self.release_index_digest,
            bundle_manifest_digest: &self.bundle_manifest_digest,
            evidence_manifest_digest: &self.evidence_manifest_digest,
            reviewed_version: &self.reviewed_version,
            approval_schema_version: &self.approval_schema_version,
            approval_record_digest: &self.approval_record_digest,
            approval_signature_raw_digest: &self.approval_signature_raw_digest,
            approval_scope: &self.approval_scope,
            issued_at: &self.issued_at,
            expires_at: &self.expires_at,
            signing_namespace: &self.signing_namespace,
            trust_root_id: &self.trust_root_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseBundleError {
    Framing,
    Digest,
    Schema,
    Binding,
}

pub fn embedded_release() -> Result<HistoricalReleaseEvidence, ReleaseBundleError> {
    parse_release_container_with_provenance(EMBEDDED, EvidenceProvenance::Embedded)
}

pub fn parse_release_container(
    raw: &[u8],
) -> Result<HistoricalReleaseEvidence, ReleaseBundleError> {
    parse_release_container_with_provenance(raw, EvidenceProvenance::CallerSupplied)
}

fn parse_release_container_with_provenance(
    raw: &[u8],
    provenance: EvidenceProvenance,
) -> Result<HistoricalReleaseEvidence, ReleaseBundleError> {
    if raw.len() < 15 || raw.len() > MAX_CONTAINER || &raw[..8] != MAGIC {
        return Err(ReleaseBundleError::Framing);
    }
    if u16::from_be_bytes([raw[8], raw[9]]) != VERSION {
        return Err(ReleaseBundleError::Framing);
    }
    let availability = raw[10];
    let count = u32::from_be_bytes([raw[11], raw[12], raw[13], raw[14]]) as usize;
    if availability == 0 {
        return if count == 0 && raw.len() == 15 {
            Ok(HistoricalReleaseEvidence::Unavailable)
        } else {
            Err(ReleaseBundleError::Framing)
        };
    }
    if availability != 1 || count == 0 || count > MAX_ENTRIES {
        return Err(ReleaseBundleError::Framing);
    }
    let mut cursor = 15usize;
    let mut entries = BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let name_len = take_u16(raw, &mut cursor)? as usize;
        if name_len == 0 || name_len > 256 || raw.len().saturating_sub(cursor) < name_len {
            return Err(ReleaseBundleError::Framing);
        }
        let name_bytes = &raw[cursor..cursor + name_len];
        cursor += name_len;
        if !name_bytes.is_ascii() {
            return Err(ReleaseBundleError::Framing);
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ReleaseBundleError::Framing)?
            .to_string();
        if !valid_name(&name) || previous.as_ref().is_some_and(|value| value >= &name) {
            return Err(ReleaseBundleError::Framing);
        }
        previous = Some(name.clone());
        let data_len = take_u32(raw, &mut cursor)? as usize;
        if data_len == 0 || data_len > MAX_ENTRY || raw.len().saturating_sub(cursor) < 32 + data_len
        {
            return Err(ReleaseBundleError::Framing);
        }
        let expected = &raw[cursor..cursor + 32];
        cursor += 32;
        let data = &raw[cursor..cursor + data_len];
        cursor += data_len;
        if Sha256::digest(data).as_slice() != expected
            || entries.insert(name, data.to_vec()).is_some()
        {
            return Err(ReleaseBundleError::Digest);
        }
    }
    if cursor != raw.len() {
        return Err(ReleaseBundleError::Framing);
    }
    validate_verified(entries, provenance)
}

#[cfg(test)]
pub(crate) fn parse_embedded_release_for_test(
    raw: &[u8],
) -> Result<HistoricalReleaseEvidence, ReleaseBundleError> {
    parse_release_container_with_provenance(raw, EvidenceProvenance::Embedded)
}

fn validate_verified(
    entries: BTreeMap<String, Vec<u8>>,
    provenance: EvidenceProvenance,
) -> Result<HistoricalReleaseEvidence, ReleaseBundleError> {
    let outer = [
        "outer/bundle-manifest.json",
        "outer/current.json",
        "outer/embedded-meta.json",
        "outer/release-approval-record.json",
        "outer/release-approval-record.sshsig",
    ];
    let manifest = json(entries.get(outer[0]).ok_or(ReleaseBundleError::Schema)?)?;
    let manifest_fields = [
        "schema_version",
        "adapter_id",
        "adapter_version",
        "adapter_contract_digest",
        "approval_scope",
        "reviewed_version",
        "evidence_manifest_digest",
        "approval_record_digest",
        "approval_signature_raw_digest",
        "trust_root_id",
        "adapter_artifacts",
        "bundle_manifest_digest",
    ];
    if manifest.as_object().map(|value| value.len()) != Some(manifest_fields.len())
        || !manifest_fields
            .iter()
            .all(|field| manifest.get(*field).is_some())
        || string(&manifest, "schema_version")? != "nomad.agent-evidence.bundle-manifest.v1"
    {
        return Err(ReleaseBundleError::Schema);
    }
    let adapter_id = string(&manifest, "adapter_id")?;
    let adapter_version = string(&manifest, "adapter_version")?;
    let artifacts = manifest
        .get("adapter_artifacts")
        .and_then(Value::as_object)
        .ok_or(ReleaseBundleError::Schema)?;
    let expected_artifacts: Vec<String> = match (adapter_id.as_str(), adapter_version.as_str()) {
        ("opencode", "1.18.16") => vec![
            "lifecycle-certificate.json".into(),
            "lifecycle-evidence-manifest.json".into(),
            "lifecycle-shape-manifest.json".into(),
        ],
        _ => return Err(ReleaseBundleError::Schema),
    };
    if string(&manifest, "adapter_contract_digest")? != OPENCODE_CONTRACT_DIGEST
        || string(&manifest, "approval_scope")? != OPENCODE_APPROVAL_SCOPE
    {
        return Err(ReleaseBundleError::Schema);
    }
    if artifacts.len() != expected_artifacts.len()
        || !expected_artifacts
            .iter()
            .all(|name| artifacts.contains_key(name))
    {
        return Err(ReleaseBundleError::Schema);
    }
    let expected_count = outer.len() + expected_artifacts.len();
    if entries.len() != expected_count
        || !outer.iter().all(|name| entries.contains_key(*name))
        || !expected_artifacts
            .iter()
            .all(|name| entries.contains_key(&format!("adapter/{name}")))
    {
        return Err(ReleaseBundleError::Schema);
    }
    let index = json(entries.get("outer/current.json").unwrap())?;
    let index_fields = [
        "schema_version",
        "active_bundle_id",
        "bundle_manifest_digest",
        "adapter_id",
        "adapter_version",
        "reviewed_version",
        "evidence_manifest_digest",
        "approval_record_digest",
        "previous_release_index_digest",
        "release_sequence",
        "release_index_digest",
    ];
    if index.as_object().map(|value| value.len()) != Some(index_fields.len())
        || !index_fields.iter().all(|field| index.get(*field).is_some())
        || string(&index, "schema_version")? != "nomad.agent-evidence.release-index.v1"
    {
        return Err(ReleaseBundleError::Schema);
    }
    let meta = json(entries.get("outer/embedded-meta.json").unwrap())?;
    if meta.as_object().map(|value| value.len()) != Some(META_FIELDS.len())
        || !META_FIELDS.iter().all(|field| meta.get(*field).is_some())
        || string(&meta, "schema_version")? != "nomad.agent-evidence.embedded-release.v1"
    {
        return Err(ReleaseBundleError::Schema);
    }
    let meta_digest = string(&meta, "metadata_digest")?;
    let mut meta_core = meta.clone();
    meta_core.as_object_mut().unwrap().remove("metadata_digest");
    if !lower_hex_64(&meta_digest) || digest_json(&meta_core)? != meta_digest {
        return Err(ReleaseBundleError::Digest);
    }
    let bundle_digest = string(&manifest, "bundle_manifest_digest")?;
    let mut manifest_core = manifest.clone();
    manifest_core
        .as_object_mut()
        .ok_or(ReleaseBundleError::Schema)?
        .remove("bundle_manifest_digest");
    if !lower_hex_64(&bundle_digest) || digest_json(&manifest_core)? != bundle_digest {
        return Err(ReleaseBundleError::Digest);
    }
    let index_digest = string(&index, "release_index_digest")?;
    let mut index_core = index.clone();
    index_core
        .as_object_mut()
        .ok_or(ReleaseBundleError::Schema)?
        .remove("release_index_digest");
    if !lower_hex_64(&index_digest) || digest_json(&index_core)? != index_digest {
        return Err(ReleaseBundleError::Digest);
    }
    let approval = json(entries.get("outer/release-approval-record.json").unwrap())?;
    if approval.as_object().map(|value| value.len()) != Some(APPROVAL_FIELDS.len())
        || !APPROVAL_FIELDS
            .iter()
            .all(|field| approval.get(*field).is_some())
        || string(&approval, "schema_version")? != OPENCODE_APPROVAL_SCHEMA
        || string(&approval, "scope")? != OPENCODE_APPROVAL_SCOPE
        || string(&approval, "signing_namespace")? != OPENCODE_SIGNING_NAMESPACE
        || string(&approval, "signature_file")? != "release-approval-record.sshsig"
    {
        return Err(ReleaseBundleError::Schema);
    }
    let approval_bytes = entries.get("outer/release-approval-record.json").unwrap();
    let signature_bytes = entries.get("outer/release-approval-record.sshsig").unwrap();
    if format!("{:x}", Sha256::digest(approval_bytes))
        != string(&manifest, "approval_record_digest")?
        || format!("{:x}", Sha256::digest(signature_bytes))
            != string(&manifest, "approval_signature_raw_digest")?
    {
        return Err(ReleaseBundleError::Binding);
    }
    let evidence_name = expected_artifacts
        .iter()
        .find(|name| name.ends_with("evidence-manifest.json"))
        .unwrap();
    let evidence = json(entries.get(&format!("adapter/{evidence_name}")).unwrap())?;
    if evidence.as_object().map(|value| value.len()) != Some(EVIDENCE_FIELDS.len())
        || !EVIDENCE_FIELDS
            .iter()
            .all(|field| evidence.get(*field).is_some())
        || string(&evidence, "schema_version")? != "nomad.stock-opencode.evidence-manifest.v1"
    {
        return Err(ReleaseBundleError::Schema);
    }
    let reviewed_version = string(&manifest, "reviewed_version")?;
    let evidence_manifest_digest = string(&manifest, "evidence_manifest_digest")?;
    let approval_record_digest = string(&manifest, "approval_record_digest")?;
    let approval_signature_raw_digest = string(&manifest, "approval_signature_raw_digest")?;
    let trust_root_id = string(&manifest, "trust_root_id")?;
    let adapter_contract_digest = string(&manifest, "adapter_contract_digest")?;
    if !lower_hex_64(&evidence_manifest_digest)
        || !lower_hex_64(&approval_record_digest)
        || !lower_hex_64(&approval_signature_raw_digest)
        || reviewed_version.is_empty()
        || trust_root_id.is_empty()
    {
        return Err(ReleaseBundleError::Schema);
    }
    let relations = [
        ("release_index_digest", index_digest.as_str()),
        ("bundle_manifest_digest", bundle_digest.as_str()),
        ("adapter_id", adapter_id.as_str()),
        ("adapter_version", adapter_version.as_str()),
        ("reviewed_version", reviewed_version.as_str()),
        (
            "evidence_manifest_digest",
            evidence_manifest_digest.as_str(),
        ),
        ("approval_record_digest", approval_record_digest.as_str()),
        (
            "approval_signature_raw_digest",
            approval_signature_raw_digest.as_str(),
        ),
        ("trust_root_id", trust_root_id.as_str()),
        ("adapter_contract_digest", adapter_contract_digest.as_str()),
    ];
    for (field, expected) in relations {
        if string(&meta, field)? != expected {
            return Err(ReleaseBundleError::Binding);
        }
    }
    if string(&index, "bundle_manifest_digest")? != bundle_digest
        || string(&index, "active_bundle_id")? != format!("sha256-{bundle_digest}")
        || string(&index, "adapter_id")? != adapter_id
        || string(&index, "adapter_version")? != adapter_version
        || string(&index, "reviewed_version")? != reviewed_version
        || string(&index, "approval_record_digest")? != approval_record_digest
        || string(&index, "evidence_manifest_digest")?
            != string(&manifest, "evidence_manifest_digest")?
        || string(&approval, "evidence_manifest_digest")?
            != string(&manifest, "evidence_manifest_digest")?
        || string(&approval, "reviewed_version")? != string(&manifest, "reviewed_version")?
        || string(&approval, "scope")? != string(&manifest, "approval_scope")?
        || string(&approval, "trust_root_id")? != string(&manifest, "trust_root_id")?
        || string(&evidence, "evidence_manifest_digest")?
            != string(&manifest, "evidence_manifest_digest")?
        || string(&evidence, "reviewed_version")? != string(&manifest, "reviewed_version")?
    {
        return Err(ReleaseBundleError::Binding);
    }
    for name in &expected_artifacts {
        let descriptor = artifacts
            .get(name)
            .and_then(Value::as_object)
            .ok_or(ReleaseBundleError::Schema)?;
        if descriptor.len() != 2
            || !descriptor.contains_key("size_bytes")
            || !descriptor.contains_key("raw_sha256")
        {
            return Err(ReleaseBundleError::Schema);
        }
        let bytes = entries.get(&format!("adapter/{name}")).unwrap();
        if descriptor.get("size_bytes").and_then(Value::as_u64) != Some(bytes.len() as u64)
            || descriptor.get("raw_sha256").and_then(Value::as_str)
                != Some(&format!("{:x}", Sha256::digest(bytes)))
        {
            return Err(ReleaseBundleError::Binding);
        }
    }
    let source_commit_oid = string(&meta, "source_commit_oid")?;
    if !(source_commit_oid.len() == 40 || source_commit_oid.len() == 64)
        || !source_commit_oid.bytes().all(lower_hex)
    {
        return Err(ReleaseBundleError::Schema);
    }
    let approval_schema_version = string(&approval, "schema_version")?;
    let approval_scope = string(&approval, "scope")?;
    let issued_at = string(&approval, "issued_at")?;
    let expires_at = string(&approval, "expires_at")?;
    let signing_namespace = string(&approval, "signing_namespace")?;
    if issued_at.is_empty()
        || expires_at.is_empty()
        || string(&approval, "principal")?.is_empty()
        || string(&approval, "trust_root_id")?.is_empty()
    {
        return Err(ReleaseBundleError::Schema);
    }
    Ok(HistoricalReleaseEvidence::Verified(Box::new(
        VerifiedHistoricalEvidence {
            provenance,
            source_commit_oid,
            release_index_digest: index_digest,
            bundle_manifest_digest: bundle_digest,
            adapter_id,
            adapter_version,
            reviewed_version,
            evidence_manifest_digest,
            approval_schema_version,
            approval_record_digest,
            approval_signature_raw_digest,
            approval_scope,
            issued_at,
            expires_at,
            signing_namespace,
            trust_root_id,
        },
    )))
}

fn take_u16(raw: &[u8], cursor: &mut usize) -> Result<u16, ReleaseBundleError> {
    if raw.len().saturating_sub(*cursor) < 2 {
        return Err(ReleaseBundleError::Framing);
    }
    let result = u16::from_be_bytes([raw[*cursor], raw[*cursor + 1]]);
    *cursor += 2;
    Ok(result)
}
fn take_u32(raw: &[u8], cursor: &mut usize) -> Result<u32, ReleaseBundleError> {
    if raw.len().saturating_sub(*cursor) < 4 {
        return Err(ReleaseBundleError::Framing);
    }
    let result = u32::from_be_bytes([
        raw[*cursor],
        raw[*cursor + 1],
        raw[*cursor + 2],
        raw[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(result)
}
fn valid_name(value: &str) -> bool {
    let Some((prefix, basename)) = value.split_once('/') else {
        return false;
    };
    matches!(prefix, "outer" | "adapter")
        && !basename.is_empty()
        && !basename.contains('/')
        && basename != "."
        && basename != ".."
        && basename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
struct StrictSeed;
impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}
struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("duplicate-free JSON")
    }
    fn visit_unit<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: DeError>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: DeError>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: DeError>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: DeError>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: DeError>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: DeError>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate key"));
            }
            values.insert(key, map.next_value_seed(StrictSeed)?);
        }
        Ok(Value::Object(values))
    }
}
fn json(raw: &[u8]) -> Result<Value, ReleaseBundleError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSeed
        .deserialize(&mut deserializer)
        .map_err(|_| ReleaseBundleError::Schema)?;
    deserializer.end().map_err(|_| ReleaseBundleError::Schema)?;
    Ok(value)
}
fn string(value: &Value, field: &str) -> Result<String, ReleaseBundleError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ReleaseBundleError::Schema)
}
fn lower_hex(value: u8) -> bool {
    value.is_ascii_digit() || (b'a'..=b'f').contains(&value)
}
fn lower_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(lower_hex)
}
fn digest_json(value: &Value) -> Result<String, ReleaseBundleError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(value)?.as_bytes())
    ))
}
fn canonical(value: &Value) -> Result<String, ReleaseBundleError> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => Ok(v.to_string()),
        Value::String(v) => {
            if v.is_ascii() {
                serde_json::to_string(v).map_err(|_| ReleaseBundleError::Schema)
            } else {
                Err(ReleaseBundleError::Schema)
            }
        }
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut out = Vec::new();
            for key in keys {
                if !key.is_ascii() {
                    return Err(ReleaseBundleError::Schema);
                }
                out.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|_| ReleaseBundleError::Schema)?,
                    canonical(&values[key])?
                ));
            }
            Ok(format!("{{{}}}", out.join(",")))
        }
    }
}

#[cfg(test)]
mod strict_tests {
    use super::*;
    use crate::error::ConnectorError;
    use crate::stock_opencode::{current_release_authorization_at, APPROVAL_EXPIRED_OR_INVALID};
    use serde_json::json;
    use time::{Date, Month, PrimitiveDateTime, Time};

    fn seal(mut value: Value, field: &str) -> Value {
        let digest = digest_json(&value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(field.into(), Value::String(digest));
        value
    }

    fn raw_digest(raw: &[u8]) -> String {
        format!("{:x}", Sha256::digest(raw))
    }

    fn embedded_container(issued_at: &str, expires_at: &str) -> Vec<u8> {
        let certificate = br#"{\"schema\":\"cert\"}"#.to_vec();
        let shape = br#"{\"schema\":\"shape\"}"#.to_vec();
        let evidence = json!({
            "schema_version":"nomad.stock-opencode.evidence-manifest.v1",
            "certificate_digest":"11".repeat(32),
            "shape_manifest_digest":"22".repeat(32),
            "certificate_structural_digest":"33".repeat(32),
            "source_binding_digest":"44".repeat(32),
            "historical_certified_launch_provenance_digest":"55".repeat(32),
            "task_spec_digest":"66".repeat(32),
            "fixture_manifest_digest":"77".repeat(32),
            "command_shapes_canonical_digest":"88".repeat(32),
            "rule_config_digest":"99".repeat(32),
            "current_committed_evidence_provenance_digest":"aa".repeat(32),
            "reviewed_version":"v0.1.0",
            "evidence_manifest_digest":"ab".repeat(32)
        });
        let evidence_raw = serde_json::to_vec(&evidence).unwrap();
        let approval = json!({
            "schema_version":OPENCODE_APPROVAL_SCHEMA,
            "evidence_manifest_digest":evidence["evidence_manifest_digest"],
            "reviewed_version":"v0.1.0",
            "scope":OPENCODE_APPROVAL_SCOPE,
            "principal":"test-dri",
            "issued_at":issued_at,
            "expires_at":expires_at,
            "trust_root_id":"test-root",
            "signing_namespace":OPENCODE_SIGNING_NAMESPACE,
            "signature_file":"release-approval-record.sshsig"
        });
        let approval_raw = serde_json::to_vec(&approval).unwrap();
        let signature = b"test-signature".to_vec();
        let artifacts = json!({
            "lifecycle-certificate.json": {"raw_sha256":raw_digest(&certificate),"size_bytes":certificate.len()},
            "lifecycle-evidence-manifest.json": {"raw_sha256":raw_digest(&evidence_raw),"size_bytes":evidence_raw.len()},
            "lifecycle-shape-manifest.json": {"raw_sha256":raw_digest(&shape),"size_bytes":shape.len()}
        });
        let manifest = seal(
            json!({
                "schema_version":"nomad.agent-evidence.bundle-manifest.v1",
                "adapter_id":"opencode",
                "adapter_version":"1.18.16",
                "adapter_contract_digest":OPENCODE_CONTRACT_DIGEST,
                "approval_scope":OPENCODE_APPROVAL_SCOPE,
                "reviewed_version":"v0.1.0",
                "evidence_manifest_digest":evidence["evidence_manifest_digest"],
                "approval_record_digest":raw_digest(&approval_raw),
                "approval_signature_raw_digest":raw_digest(&signature),
                "trust_root_id":"test-root",
                "adapter_artifacts":artifacts
            }),
            "bundle_manifest_digest",
        );
        let index = seal(
            json!({
                "schema_version":"nomad.agent-evidence.release-index.v1",
                "active_bundle_id":format!("sha256-{}", manifest["bundle_manifest_digest"].as_str().unwrap()),
                "bundle_manifest_digest":manifest["bundle_manifest_digest"],
                "adapter_id":"opencode",
                "adapter_version":"1.18.16",
                "reviewed_version":"v0.1.0",
                "evidence_manifest_digest":evidence["evidence_manifest_digest"],
                "approval_record_digest":raw_digest(&approval_raw),
                "previous_release_index_digest":"00".repeat(32),
                "release_sequence":1
            }),
            "release_index_digest",
        );
        let meta = seal(
            json!({
                "schema_version":"nomad.agent-evidence.embedded-release.v1",
                "source_commit_oid":"bb".repeat(20),
                "expected_parent_oid":"cc".repeat(20),
                "release_index_digest":index["release_index_digest"],
                "bundle_manifest_digest":manifest["bundle_manifest_digest"],
                "adapter_id":"opencode",
                "adapter_version":"1.18.16",
                "adapter_contract_digest":OPENCODE_CONTRACT_DIGEST,
                "reviewed_version":"v0.1.0",
                "evidence_manifest_digest":evidence["evidence_manifest_digest"],
                "approval_record_digest":raw_digest(&approval_raw),
                "approval_signature_raw_digest":raw_digest(&signature),
                "trust_root_id":"test-root"
            }),
            "metadata_digest",
        );
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        entries.insert("adapter/lifecycle-certificate.json".into(), certificate);
        entries.insert(
            "adapter/lifecycle-evidence-manifest.json".into(),
            evidence_raw,
        );
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
        entries.insert("outer/release-approval-record.json".into(), approval_raw);
        entries.insert("outer/release-approval-record.sshsig".into(), signature);
        let mut raw = MAGIC.to_vec();
        raw.extend(VERSION.to_be_bytes());
        raw.push(1);
        raw.extend((entries.len() as u32).to_be_bytes());
        for (name, data) in entries {
            raw.extend((name.len() as u16).to_be_bytes());
            raw.extend(name.as_bytes());
            raw.extend((data.len() as u32).to_be_bytes());
            raw.extend(Sha256::digest(&data));
            raw.extend(data);
        }
        raw
    }

    fn utc(day: u8, hour: u8) -> time::OffsetDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(2026, Month::August, day).unwrap(),
            Time::from_hms(hour, 0, 0).unwrap(),
        )
        .assume_utc()
    }

    fn embedded_authorization(
        issued_at: &str,
        expires_at: &str,
        now: time::OffsetDateTime,
    ) -> Result<(), ConnectorError> {
        let HistoricalReleaseEvidence::Verified(evidence) =
            parse_embedded_release_for_test(&embedded_container(issued_at, expires_at)).unwrap()
        else {
            panic!("test container unavailable")
        };
        current_release_authorization_at(&evidence, now).map(|_| ())
    }

    fn assert_approval_blocked(issued_at: &str, expires_at: &str, now: time::OffsetDateTime) {
        match embedded_authorization(issued_at, expires_at, now) {
            Err(ConnectorError::SafetyBlocked(reason)) => {
                assert_eq!(reason, APPROVAL_EXPIRED_OR_INVALID)
            }
            _ => panic!("embedded approval did not return the stable blocker"),
        }
    }

    #[test]
    fn duplicate_json_keys_are_rejected_recursively() {
        assert_eq!(json(br#"{"x":1,"x":2}"#), Err(ReleaseBundleError::Schema));
        assert_eq!(
            json(br#"{"outer":{"x":1,"x":2}}"#),
            Err(ReleaseBundleError::Schema)
        );
    }

    #[test]
    fn strict_json_rejects_trailing_values() {
        assert_eq!(json(br#"{}{}"#), Err(ReleaseBundleError::Schema));
    }

    #[test]
    fn embedded_provenance_authorizes_only_a_current_exact_window() {
        assert!(embedded_authorization(
            "2026-08-20T00:00:00Z",
            "2026-08-21T00:00:00Z",
            utc(20, 12)
        )
        .is_ok());
        assert_approval_blocked("2026-08-20T00:00:00Z", "2026-08-21T00:00:00Z", utc(21, 0));
        assert_approval_blocked("2026-08-20T13:00:00Z", "2026-08-21T00:00:00Z", utc(20, 12));
        assert_approval_blocked("2026-08-20T00:00:00Z", "2026-09-19T00:00:01Z", utc(20, 12));
        assert_approval_blocked(
            "2026-08-20T00:00:00+00:00",
            "2026-08-21T00:00:00Z",
            utc(20, 12),
        );
    }
}
