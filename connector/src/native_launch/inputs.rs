//! Immutable, compile-time stock inputs for the native OpenCode launcher.
//!
//! This module deliberately has no filesystem, process, environment, network,
//! credential, proxy, or Host dependency.  It validates reviewed bytes and
//! returns only crate-private facts plus a fixed materialization plan.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

const PACKAGE_JSON: &[u8] =
    include_bytes!("../../../testkit/stock-opencode/locked-runtime/package.json");
const PACKAGE_LOCK: &[u8] =
    include_bytes!("../../../testkit/stock-opencode/locked-runtime/package-lock.json");
const TASK_SPEC: &[u8] = include_bytes!("../../../testkit/stock-opencode/real-task/task-spec.json");
const FIXTURE_MANIFEST: &[u8] =
    include_bytes!("../../../testkit/stock-opencode/real-task/fixture-manifest.json");
const PROJECT_PROMPT: &[u8] =
    include_bytes!("../../../testkit/stock-opencode/real-task/project-prompt.txt");

const README: &[u8] = b"# Disposable arithmetic fixture\n";
const ARITHMETIC: &[u8] = b"export const add = (left, right) => left + right;\n";
const ARITHMETIC_TEST: &[u8] = b"import { add } from '../src/arithmetic.js';\nif (add(1, 2) !== 3) throw new Error('arithmetic');\n";

const PACKAGE_JSON_SHA256: &str =
    "e1c3f7612fafffe24bb3452c1cbd1259be05827fe836b20a72304599b1922bb5";
const PACKAGE_LOCK_SHA256: &str =
    "a8b262bae6dbbe1d2d05b1be06843e62201b2b47d879e19dd68b8613ebefd8b0";
const TASK_SPEC_RAW_SHA256: &str =
    "1071cd13ec926eaf394cdf91a63b2dda4f3ac35ffd7abc9daa7959ecb1a4c1a9";
const FIXTURE_MANIFEST_RAW_SHA256: &str =
    "8fffd74a9eec19157828b3a725850087596fb77caf097e43e7c11abc4cbd8cf2";
const PROJECT_PROMPT_SHA256: &str =
    "d49907993dcd9ee1766a0127a62d722048ec0729cedbe24abf53954108405917";
const TASK_SPEC_CANONICAL_SHA256: &str =
    "bf20fd9c3ab0f5ae2d25d50cf9505659a53cfa779d8328c6de64bef9e8d20c1c";
const FIXTURE_DIGEST: &str = "5f7bbebf2dc100357fab74eb985e49e606b3aed3c73b79f8828d3f74d874da21";
const FULL_CLOSURE_DIGEST: &str =
    "ed283da245810efed985ce51db6a1e8fc365b8bf225139b2ae567615187f1a46";
const DARWIN_ARM64_CLOSURE_DIGEST: &str =
    "70cbe968ce1d7f955b5c5e392cb15aa414243dff5c34e3f16ff81ab0ed1f7285";

const PACKAGE_LIMIT: usize = 4 * 1024;
const LOCK_LIMIT: usize = 64 * 1024;
const TASK_LIMIT: usize = 16 * 1024;
const MANIFEST_LIMIT: usize = 8 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_CONTAINER_ITEMS: usize = 256;
const MAX_STRING_BYTES: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StockInputError {
    #[error("stock input exceeds its fixed size bound")]
    Size,
    #[error("stock input JSON contains a duplicate key")]
    DuplicateKey,
    #[error("stock input is not strict bounded JSON")]
    Json,
    #[error("stock input violates its exact contract")]
    Contract,
    #[error("lockfile contains a non-registry dependency source")]
    DependencySource,
    #[error("locked dependency closure does not match the reviewed closure")]
    Closure,
    #[error("fixture bytes do not match the exact fixture manifest")]
    Fixture,
    #[error("embedded input bytes differ from the reviewed bytes")]
    RawBytes,
}

/// Content-free facts consumed by the parent native launcher.
///
/// Intentionally not `Clone`: the integration should move this proof forward.
pub(crate) struct StockInputFacts {
    pub(crate) package_json_sha256: String,
    pub(crate) package_lock_sha256: String,
    pub(crate) full_dependency_count: usize,
    pub(crate) full_dependency_digest: String,
    pub(crate) darwin_arm64_dependency_count: usize,
    pub(crate) darwin_arm64_dependency_digest: String,
    pub(crate) task_spec_digest: String,
    pub(crate) fixture_manifest_digest: String,
    pub(crate) project_prompt_sha256: String,
}

pub(crate) enum MaterializationRoot {
    Install,
    Workspace,
}

pub(crate) struct MaterializationFile {
    pub(crate) root: MaterializationRoot,
    pub(crate) relative_name: &'static str,
    pub(crate) bytes: &'static [u8],
}

/// Fixed files which N1c may create beneath its already-owned directories.
/// The prompt is intentionally separate because the task contract forbids
/// persisting it in the disposable workspace.
pub(crate) struct StockMaterializationPlan {
    pub(crate) files: [MaterializationFile; 5],
    pub(crate) project_prompt: &'static [u8],
}

/// The only successful output of this module. Intentionally not `Clone`.
pub(crate) struct VerifiedStockInputs {
    pub(crate) facts: StockInputFacts,
    pub(crate) materialization: StockMaterializationPlan,
}

pub(crate) fn verify_stock_inputs() -> Result<VerifiedStockInputs, StockInputError> {
    let facts = verify_parts(
        RawInputs {
            package: PACKAGE_JSON,
            lock: PACKAGE_LOCK,
            task: TASK_SPEC,
            manifest: FIXTURE_MANIFEST,
            prompt: PROJECT_PROMPT,
        },
        [README, ARITHMETIC, ARITHMETIC_TEST],
    )?;
    Ok(VerifiedStockInputs {
        facts,
        materialization: StockMaterializationPlan {
            files: [
                materialization(MaterializationRoot::Install, "package.json", PACKAGE_JSON),
                materialization(
                    MaterializationRoot::Install,
                    "package-lock.json",
                    PACKAGE_LOCK,
                ),
                materialization(MaterializationRoot::Workspace, "README.md", README),
                materialization(
                    MaterializationRoot::Workspace,
                    "src/arithmetic.js",
                    ARITHMETIC,
                ),
                materialization(
                    MaterializationRoot::Workspace,
                    "test/arithmetic.test.js",
                    ARITHMETIC_TEST,
                ),
            ],
            project_prompt: PROJECT_PROMPT,
        },
    })
}

fn materialization(
    root: MaterializationRoot,
    relative_name: &'static str,
    bytes: &'static [u8],
) -> MaterializationFile {
    MaterializationFile {
        root,
        relative_name,
        bytes,
    }
}

struct RawInputs<'a> {
    package: &'a [u8],
    lock: &'a [u8],
    task: &'a [u8],
    manifest: &'a [u8],
    prompt: &'a [u8],
}

fn verify_parts(
    raw: RawInputs<'_>,
    fixture_bytes: [&[u8]; 3],
) -> Result<StockInputFacts, StockInputError> {
    let package = strict_json(raw.package, PACKAGE_LIMIT)?;
    let lock = strict_json(raw.lock, LOCK_LIMIT)?;
    let task = strict_json(raw.task, TASK_LIMIT)?;
    let manifest = strict_json(raw.manifest, MANIFEST_LIMIT)?;

    validate_package(&package)?;
    let closure = validate_lock(&lock)?;
    validate_task(&task)?;
    validate_manifest(&manifest, fixture_bytes)?;

    let task_digest = canonical_digest(&task);
    if task_digest != TASK_SPEC_CANONICAL_SHA256 {
        return Err(StockInputError::Contract);
    }
    if raw.prompt.len() != 262 || sha256(raw.prompt) != PROJECT_PROMPT_SHA256 {
        return Err(StockInputError::RawBytes);
    }

    let raw_digests = [
        (raw.package, PACKAGE_JSON_SHA256),
        (raw.lock, PACKAGE_LOCK_SHA256),
        (raw.task, TASK_SPEC_RAW_SHA256),
        (raw.manifest, FIXTURE_MANIFEST_RAW_SHA256),
    ];
    if raw_digests
        .iter()
        .any(|(bytes, expected)| sha256(bytes) != *expected)
    {
        return Err(StockInputError::RawBytes);
    }

    Ok(StockInputFacts {
        package_json_sha256: PACKAGE_JSON_SHA256.to_owned(),
        package_lock_sha256: PACKAGE_LOCK_SHA256.to_owned(),
        full_dependency_count: closure.full_count,
        full_dependency_digest: closure.full_digest,
        darwin_arm64_dependency_count: closure.selected_count,
        darwin_arm64_dependency_digest: closure.selected_digest,
        task_spec_digest: task_digest,
        fixture_manifest_digest: FIXTURE_DIGEST.to_owned(),
        project_prompt_sha256: PROJECT_PROMPT_SHA256.to_owned(),
    })
}

fn validate_package(value: &Value) -> Result<(), StockInputError> {
    let expected = serde_json::json!({
        "name": "nomad-stock-opencode-locked-runtime",
        "private": true,
        "version": "1.0.0",
        "packageManager": "npm@11.12.1",
        "dependencies": {"opencode-ai": "1.18.16"}
    });
    if value == &expected {
        Ok(())
    } else {
        Err(StockInputError::Contract)
    }
}

struct ClosureFacts {
    full_count: usize,
    full_digest: String,
    selected_count: usize,
    selected_digest: String,
}

fn validate_lock(value: &Value) -> Result<ClosureFacts, StockInputError> {
    let root = object(value)?;
    exact_keys(
        root,
        &["name", "version", "lockfileVersion", "requires", "packages"],
    )?;
    if string(root, "name")? != "nomad-stock-opencode-locked-runtime"
        || string(root, "version")? != "1.0.0"
        || integer(root, "lockfileVersion")? != 3
        || !boolean(root, "requires")?
    {
        return Err(StockInputError::Contract);
    }
    let packages = object(field(root, "packages")?)?;
    let lock_root = object(field(packages, "")?)?;
    let expected_root = serde_json::json!({
        "name": "nomad-stock-opencode-locked-runtime",
        "version": "1.0.0",
        "dependencies": {"opencode-ai": "1.18.16"}
    });
    if Value::Object(lock_root.clone()) != expected_root {
        return Err(StockInputError::Contract);
    }

    let allowed: BTreeSet<&str> = [
        "version",
        "resolved",
        "integrity",
        "cpu",
        "hasInstallScript",
        "license",
        "os",
        "bin",
        "optionalDependencies",
        "optional",
        "libc",
        "link",
    ]
    .into_iter()
    .collect();
    let mut all = Vec::new();
    let mut selected = Vec::new();
    for (location, entry_value) in packages {
        if location.is_empty() {
            continue;
        }
        if !location.starts_with("node_modules/") {
            return Err(StockInputError::Contract);
        }
        let entry = object(entry_value)?;
        if entry.keys().any(|key| !allowed.contains(key.as_str())) {
            return Err(StockInputError::Contract);
        }
        if entry.contains_key("link") {
            return Err(StockInputError::DependencySource);
        }
        let name = package_name(location)?;
        let version = string(entry, "version")?;
        let integrity = string(entry, "integrity")?;
        let resolved = string(entry, "resolved")?;
        if version != "1.18.16" || !valid_integrity(integrity) {
            return Err(StockInputError::Contract);
        }
        validate_registry_url(resolved)?;
        validate_optional_types(entry)?;
        let tuple = serde_json::json!([name, version, integrity]);
        all.push(tuple.clone());
        if platform_allows(entry, "darwin", "arm64")? {
            selected.push(tuple);
        }
    }
    all.sort_by_key(canonical_bytes);
    selected.sort_by_key(canonical_bytes);
    let full_digest = canonical_digest(&Value::Array(all));
    let selected_digest = canonical_digest(&Value::Array(selected));
    if packages.len() != 14
        || full_digest != FULL_CLOSURE_DIGEST
        || selected_digest != DARWIN_ARM64_CLOSURE_DIGEST
    {
        return Err(StockInputError::Closure);
    }
    Ok(ClosureFacts {
        full_count: 13,
        full_digest,
        selected_count: 2,
        selected_digest,
    })
}

fn validate_optional_types(entry: &Map<String, Value>) -> Result<(), StockInputError> {
    for key in ["cpu", "os", "libc"] {
        if let Some(value) = entry.get(key) {
            let values = value.as_array().ok_or(StockInputError::Contract)?;
            if values.is_empty()
                || values.len() > 8
                || values.iter().any(|item| item.as_str().is_none())
            {
                return Err(StockInputError::Contract);
            }
        }
    }
    for key in ["hasInstallScript", "optional"] {
        if entry.get(key).is_some_and(|value| !value.is_boolean()) {
            return Err(StockInputError::Contract);
        }
    }
    for key in ["bin", "optionalDependencies"] {
        if let Some(value) = entry.get(key) {
            let map = value.as_object().ok_or(StockInputError::Contract)?;
            if map.is_empty() || map.len() > 32 || map.values().any(|item| item.as_str().is_none())
            {
                return Err(StockInputError::Contract);
            }
        }
    }
    if entry.get("license").is_some_and(|value| !value.is_string()) {
        return Err(StockInputError::Contract);
    }
    Ok(())
}

fn platform_allows(
    entry: &Map<String, Value>,
    os: &str,
    cpu: &str,
) -> Result<bool, StockInputError> {
    Ok(list_allows(entry.get("os"), os)? && list_allows(entry.get("cpu"), cpu)?)
}

fn list_allows(value: Option<&Value>, requested: &str) -> Result<bool, StockInputError> {
    let Some(value) = value else {
        return Ok(true);
    };
    let items = value.as_array().ok_or(StockInputError::Contract)?;
    Ok(items.iter().any(|item| item.as_str() == Some(requested)))
}

fn package_name(location: &str) -> Result<&str, StockInputError> {
    let tail = location
        .rsplit_once("node_modules/")
        .map(|(_, tail)| tail)
        .ok_or(StockInputError::Contract)?;
    if tail.is_empty() || tail.contains('/') || tail.contains('\\') || tail.contains("..") {
        return Err(StockInputError::Contract);
    }
    Ok(tail)
}

fn valid_integrity(value: &str) -> bool {
    value.starts_with("sha512-")
        && value.len() > 20
        && value
            .bytes()
            .skip(7)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

fn validate_registry_url(value: &str) -> Result<(), StockInputError> {
    let lower = value.to_ascii_lowercase();
    if ["file:", "git:", "git+", "link:"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return Err(StockInputError::DependencySource);
    }
    let url = Url::parse(value).map_err(|_| StockInputError::DependencySource)?;
    if url.scheme() != "https"
        || url.host_str() != Some("registry.npmjs.org")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with('/')
    {
        return Err(StockInputError::DependencySource);
    }
    Ok(())
}

fn validate_task(value: &Value) -> Result<(), StockInputError> {
    let expected = serde_json::json!({
        "schema": "nomad.stock-opencode.disposable-task.v1",
        "data_boundary": {
            "workspace": "harness_created_temporary_directory",
            "repository_source": "project_owned_generated_fixture",
            "personal_source_allowed": false,
            "ambient_opencode_auth_allowed": false,
            "provider_credential": "explicit_temporary_environment_variable_only",
            "cleanup_required": true
        },
        "fixture_files": [
            {"relative_name": "README.md", "content_class": "project_owned_static_fixture"},
            {"relative_name": "src/arithmetic.js", "content_class": "project_owned_static_fixture"},
            {"relative_name": "test/arithmetic.test.js", "content_class": "project_owned_static_fixture"}
        ],
        "task_flow": [
            {"step": "question", "required_observation": "question.asked", "operator_action": "answer_with_project_owned_choice"},
            {"step": "diff", "required_observation": "authoritative_workspace_diff", "expected_file_count_min": 1},
            {"step": "permission", "required_observation": "permission.asked", "operator_action": "reject"},
            {"step": "stop", "required_observation": "session_abort_or_interrupt_terminal_fact"},
            {"step": "reconnect", "required_observation": "snapshot_reconciliation_after_host_restart"}
        ],
        "forbidden_persisted_content": [
            "provider_credential", "prompt", "source_text", "filesystem_path",
            "command_body", "diff_content", "raw_session_id", "raw_question_id",
            "raw_permission_id"
        ]
    });
    if value == &expected {
        Ok(())
    } else {
        Err(StockInputError::Contract)
    }
}

fn validate_manifest(value: &Value, contents: [&[u8]; 3]) -> Result<(), StockInputError> {
    let names = ["README.md", "src/arithmetic.js", "test/arithmetic.test.js"];
    let files: Vec<Value> = names
        .iter()
        .zip(contents)
        .map(|(name, bytes)| {
            serde_json::json!({
                "content_class": "project_owned_static_fixture",
                "relative_name": name,
                "sha256": sha256(bytes),
                "size": bytes.len()
            })
        })
        .collect();
    let digest = canonical_digest(&Value::Array(files.clone()));
    let expected = serde_json::json!({
        "digest": digest,
        "files": files,
        "schema": "nomad.stock-opencode.fixture-manifest.v1"
    });
    if value != &expected || expected["digest"] != FIXTURE_DIGEST {
        return Err(StockInputError::Fixture);
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>, StockInputError> {
    value.as_object().ok_or(StockInputError::Contract)
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value, StockInputError> {
    map.get(key).ok_or(StockInputError::Contract)
}

fn string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, StockInputError> {
    field(map, key)?.as_str().ok_or(StockInputError::Contract)
}

fn integer(map: &Map<String, Value>, key: &str) -> Result<u64, StockInputError> {
    field(map, key)?.as_u64().ok_or(StockInputError::Contract)
}

fn boolean(map: &Map<String, Value>, key: &str) -> Result<bool, StockInputError> {
    field(map, key)?.as_bool().ok_or(StockInputError::Contract)
}

fn exact_keys(map: &Map<String, Value>, keys: &[&str]) -> Result<(), StockInputError> {
    if map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)) {
        Ok(())
    } else {
        Err(StockInputError::Contract)
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Python-compatible `json.dumps(sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)` for the ASCII-only reviewed contracts.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut Vec<u8>) {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
            Value::String(value) => output.extend_from_slice(
                serde_json::to_string(value)
                    .expect("string serialization")
                    .as_bytes(),
            ),
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(value, output);
                }
                output.push(b']');
            }
            Value::Object(values) => {
                output.push(b'{');
                let mut entries: Vec<_> = values.iter().collect();
                entries.sort_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(
                        serde_json::to_string(key)
                            .expect("key serialization")
                            .as_bytes(),
                    );
                    output.push(b':');
                    write(value, output);
                }
                output.push(b'}');
            }
        }
    }
    let mut bytes = Vec::new();
    write(value, &mut bytes);
    bytes
}

pub(super) fn canonical_digest(value: &Value) -> String {
    sha256(&canonical_bytes(value))
}

pub(super) fn strict_json(raw: &[u8], limit: usize) -> Result<Value, StockInputError> {
    if raw.len() > limit {
        return Err(StockInputError::Size);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

fn classify_json_error(error: serde_json::Error) -> StockInputError {
    if error.to_string().contains("duplicate stock key") {
        StockInputError::DuplicateKey
    } else {
        StockInputError::Json
    }
}

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("stock JSON depth limit"));
        }
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate keys or floating-point numbers")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }
    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point stock JSON is forbidden"))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAX_STRING_BYTES || !value.is_ascii() {
            return Err(E::custom("stock JSON string limit"));
        }
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            depth: self.depth + 1,
        })? {
            if values.len() == MAX_CONTAINER_ITEMS {
                return Err(de::Error::custom("stock JSON item limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate stock key"));
            }
            if values.len() == MAX_CONTAINER_ITEMS
                || key.len() > MAX_STRING_BYTES
                || !key.is_ascii()
            {
                return Err(de::Error::custom("stock JSON item limit"));
            }
            let value = map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current<'a>() -> RawInputs<'a> {
        RawInputs {
            package: PACKAGE_JSON,
            lock: PACKAGE_LOCK,
            task: TASK_SPEC,
            manifest: FIXTURE_MANIFEST,
            prompt: PROJECT_PROMPT,
        }
    }

    #[test]
    fn current_assets_verify_and_match_python_digests() {
        let verified = verify_stock_inputs().expect("reviewed assets must verify");
        assert_eq!(verified.facts.full_dependency_count, 13);
        assert_eq!(verified.facts.darwin_arm64_dependency_count, 2);
        assert_eq!(verified.facts.full_dependency_digest, FULL_CLOSURE_DIGEST);
        assert_eq!(
            verified.facts.darwin_arm64_dependency_digest,
            DARWIN_ARM64_CLOSURE_DIGEST
        );
        assert_eq!(verified.facts.task_spec_digest, TASK_SPEC_CANONICAL_SHA256);
        assert_eq!(verified.facts.fixture_manifest_digest, FIXTURE_DIGEST);
        assert_eq!(verified.facts.package_json_sha256, PACKAGE_JSON_SHA256);
        assert_eq!(verified.facts.package_lock_sha256, PACKAGE_LOCK_SHA256);
        assert_eq!(verified.facts.project_prompt_sha256, PROJECT_PROMPT_SHA256);
        assert_eq!(verified.materialization.files.len(), 5);
        let materialized: Vec<_> = verified
            .materialization
            .files
            .iter()
            .map(|file| {
                let root = match file.root {
                    MaterializationRoot::Install => "install",
                    MaterializationRoot::Workspace => "workspace",
                };
                (root, file.relative_name, sha256(file.bytes))
            })
            .collect();
        assert_eq!(materialized.len(), 5);
        assert_eq!(materialized[0].0, "install");
        assert_eq!(materialized[0].1, "package.json");
        assert_eq!(verified.materialization.project_prompt, PROJECT_PROMPT);
    }

    #[test]
    fn semantic_same_but_different_raw_json_is_rejected() {
        let mut package = PACKAGE_JSON.to_vec();
        package.extend_from_slice(b" ");
        let mut raw = current();
        raw.package = &package;
        assert!(matches!(
            verify_parts(raw, [README, ARITHMETIC, ARITHMETIC_TEST]),
            Err(StockInputError::RawBytes)
        ));
    }

    #[test]
    fn duplicate_keys_and_trailing_values_are_rejected() {
        let duplicate = br#"{"name":"a","name":"b"}"#;
        assert_eq!(
            strict_json(duplicate, PACKAGE_LIMIT),
            Err(StockInputError::DuplicateKey)
        );
        assert_eq!(
            strict_json(b"{} {}", PACKAGE_LIMIT),
            Err(StockInputError::Json)
        );
    }

    #[test]
    fn dependency_source_and_fixture_path_injection_are_rejected() {
        let lock = String::from_utf8(PACKAGE_LOCK.to_vec()).unwrap().replacen(
            "https://registry.npmjs.org/",
            "file:///",
            1,
        );
        let mut raw = current();
        raw.lock = lock.as_bytes();
        assert!(matches!(
            verify_parts(raw, [README, ARITHMETIC, ARITHMETIC_TEST]),
            Err(StockInputError::DependencySource)
        ));

        let task =
            String::from_utf8(TASK_SPEC.to_vec())
                .unwrap()
                .replacen("README.md", "../README.md", 1);
        let mut raw = current();
        raw.task = task.as_bytes();
        assert!(matches!(
            verify_parts(raw, [README, ARITHMETIC, ARITHMETIC_TEST]),
            Err(StockInputError::Contract)
        ));
    }

    #[test]
    fn closure_mutation_is_rejected_by_recomputed_digest() {
        let lock = String::from_utf8(PACKAGE_LOCK.to_vec()).unwrap().replacen(
            "sha512-l4nU",
            "sha512-A4nU",
            1,
        );
        let mut raw = current();
        raw.lock = lock.as_bytes();
        assert!(matches!(
            verify_parts(raw, [README, ARITHMETIC, ARITHMETIC_TEST]),
            Err(StockInputError::Closure)
        ));
    }

    #[test]
    fn fixture_size_and_hash_are_recomputed_from_exact_bytes() {
        assert!(matches!(
            verify_parts(current(), [b"changed\n", ARITHMETIC, ARITHMETIC_TEST]),
            Err(StockInputError::Fixture)
        ));
    }
}
