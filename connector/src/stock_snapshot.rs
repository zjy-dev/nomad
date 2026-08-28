//! Content-safe snapshot projection for the locked official OpenCode API.
//!
//! Raw paths, prompts, diffs, model/provider names and upstream identifiers do
//! not leave this adapter. Callers provide the exact Session ID created by the
//! current owned run; this module never lists ambient user sessions.

use crate::error::ConnectorError;
use crate::stock_event_adapter::strict_json;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ITEMS: usize = 256;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 65_536;
pub const STOCK_SNAPSHOT_EVIDENCE_CLASS: &str =
    "official_registry_shape_only_not_provider_lifecycle";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StockReadonlySnapshot {
    pub session_alias: String,
    pub updated_at: String,
    pub turn_state: String,
    pub pending_input_alias: Option<String>,
    pub pending_permission_alias: Option<String>,
    pub diff_file_count: usize,
    pub writable: bool,
    pub evidence_class: &'static str,
}

pub fn project_stock_snapshot(
    expected_session_id: &str,
    session_raw: &[u8],
    status_raw: &[u8],
    questions_raw: &[u8],
    permissions_raw: &[u8],
    diff_raw: &[u8],
) -> Result<StockReadonlySnapshot, ConnectorError> {
    if !safe_stock_id(expected_session_id, "ses") {
        return Err(mismatch());
    }
    let session = object(read(session_raw)?)?;
    exact_keys(
        &session,
        &[
            "id",
            "slug",
            "projectID",
            "workspaceID",
            "directory",
            "path",
            "parentID",
            "summary",
            "cost",
            "tokens",
            "share",
            "title",
            "agent",
            "model",
            "version",
            "metadata",
            "time",
            "permission",
            "revert",
        ],
        &[
            "id",
            "slug",
            "projectID",
            "directory",
            "title",
            "version",
            "time",
        ],
    )?;
    if session.get("id").and_then(Value::as_str) != Some(expected_session_id) {
        return Err(mismatch());
    }
    if session.get("version").and_then(Value::as_str) != Some("1.18.16") {
        return Err(mismatch());
    }
    require_string(&session, "slug")?;
    require_string(&session, "projectID")?;
    require_string(&session, "directory")?;
    require_string(&session, "title")?;
    let time = object(session.get("time").cloned().ok_or_else(mismatch)?)?;
    exact_keys(
        &time,
        &["created", "updated", "archived", "compacting"],
        &["created", "updated"],
    )?;
    if time.get("created").and_then(Value::as_u64).is_none() {
        return Err(mismatch());
    }
    let updated = time
        .get("updated")
        .and_then(Value::as_u64)
        .ok_or_else(mismatch)?;
    let updated_at = format_unix_millis(updated)?;

    let statuses = object(read(status_raw)?)?;
    if statuses.len() > MAX_ITEMS {
        return Err(mismatch());
    }
    for (session_id, status) in &statuses {
        if !safe_stock_id(session_id, "ses") {
            return Err(mismatch());
        }
        validate_status(status)?;
    }
    let state = match statuses.get(expected_session_id) {
        None => "Completed",
        Some(value) => match object(value.clone())?.get("type").and_then(Value::as_str) {
            Some("busy") => "Running",
            Some("idle") => "Completed",
            Some("retry") => "OutcomeUnknown",
            _ => return Err(mismatch()),
        },
    };
    let questions = matching_ids(read(questions_raw)?, expected_session_id, "que")?;
    let permissions = matching_ids(read(permissions_raw)?, expected_session_id, "per")?;
    let diffs = read(diff_raw)?;
    let diffs = diffs.as_array().ok_or_else(mismatch)?;
    if diffs.len() > MAX_ITEMS {
        return Err(mismatch());
    }
    for diff in diffs {
        let item = object(diff.clone())?;
        exact_keys(
            &item,
            &["file", "patch", "additions", "deletions", "status"],
            &["additions", "deletions"],
        )?;
        if item.get("additions").and_then(Value::as_u64).is_none()
            || item.get("deletions").and_then(Value::as_u64).is_none()
            || !optional_string(&item, "file")
            || !optional_string(&item, "patch")
            || !optional_string(&item, "status")
        {
            return Err(mismatch());
        }
    }
    let turn_state = if !permissions.is_empty() {
        "NeedsPermission"
    } else if !questions.is_empty() {
        "NeedsInput"
    } else {
        state
    };
    Ok(StockReadonlySnapshot {
        session_alias: alias("sess", expected_session_id),
        updated_at,
        turn_state: turn_state.into(),
        pending_input_alias: one_alias("input", questions)?,
        pending_permission_alias: one_alias("permission", permissions)?,
        diff_file_count: diffs.len(),
        writable: false,
        evidence_class: STOCK_SNAPSHOT_EVIDENCE_CLASS,
    })
}

pub(crate) fn stock_session_directory(
    session_raw: &[u8],
) -> Result<Zeroizing<String>, ConnectorError> {
    let session = object(read(session_raw)?)?;
    Ok(Zeroizing::new(
        require_string(&session, "directory")?.into(),
    ))
}

fn read(raw: &[u8]) -> Result<Value, ConnectorError> {
    if raw.is_empty() || raw.len() > MAX_RESPONSE_BYTES {
        return Err(mismatch());
    }
    lexical_json_budget(raw)?;
    strict_json(raw).map_err(|_| mismatch())
}

/// Bounds parser work before serde builds a recursive `Value`. This scanner is
/// deliberately lexical rather than a second JSON parser: serde still owns
/// grammar validation, while this pass accounts for every possible container,
/// string (including object keys), and primitive token.
fn lexical_json_budget(raw: &[u8]) -> Result<(), ConnectorError> {
    let mut stack = [0_u8; MAX_JSON_DEPTH];
    let mut depth = 0_usize;
    let mut nodes = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_primitive = false;

    for &byte in raw {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => {
                in_primitive = false;
                add_json_node(&mut nodes)?;
                in_string = true;
            }
            b'{' | b'[' => {
                in_primitive = false;
                add_json_node(&mut nodes)?;
                if depth == MAX_JSON_DEPTH {
                    return Err(mismatch());
                }
                stack[depth] = byte;
                depth += 1;
            }
            b'}' | b']' => {
                in_primitive = false;
                if depth == 0
                    || (byte == b'}' && stack[depth - 1] != b'{')
                    || (byte == b']' && stack[depth - 1] != b'[')
                {
                    return Err(mismatch());
                }
                depth -= 1;
            }
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => in_primitive = false,
            _ if !in_primitive => {
                add_json_node(&mut nodes)?;
                in_primitive = true;
            }
            _ => {}
        }
    }

    if in_string || escaped || depth != 0 {
        return Err(mismatch());
    }
    Ok(())
}

fn add_json_node(nodes: &mut usize) -> Result<(), ConnectorError> {
    *nodes = nodes.checked_add(1).ok_or_else(mismatch)?;
    if *nodes > MAX_JSON_NODES {
        Err(mismatch())
    } else {
        Ok(())
    }
}

fn object(value: Value) -> Result<Map<String, Value>, ConnectorError> {
    value.as_object().cloned().ok_or_else(mismatch)
}
fn exact_keys(
    map: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), ConnectorError> {
    if map.keys().all(|key| allowed.contains(&key.as_str()))
        && required.iter().all(|key| map.contains_key(*key))
    {
        Ok(())
    } else {
        Err(mismatch())
    }
}

fn require_string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, ConnectorError> {
    map.get(key).and_then(Value::as_str).ok_or_else(mismatch)
}

fn optional_string(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).is_none_or(Value::is_string)
}

fn format_unix_millis(value: u64) -> Result<String, ConnectorError> {
    let nanos = i128::from(value)
        .checked_mul(1_000_000)
        .ok_or_else(mismatch)?;
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| mismatch())?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        timestamp.year(),
        u8::from(timestamp.month()),
        timestamp.day(),
        timestamp.hour(),
        timestamp.minute(),
        timestamp.second(),
        timestamp.millisecond(),
    ))
}

fn validate_status(value: &Value) -> Result<(), ConnectorError> {
    let map = value.as_object().ok_or_else(mismatch)?;
    match map.get("type").and_then(Value::as_str) {
        Some("busy" | "idle") => exact_keys(map, &["type"], &["type"]),
        Some("retry") => {
            exact_keys(
                map,
                &["type", "attempt", "message", "next"],
                &["type", "attempt", "message", "next"],
            )?;
            if map.get("attempt").and_then(Value::as_u64).is_none()
                || map.get("message").and_then(Value::as_str).is_none()
                || map.get("next").and_then(Value::as_u64).is_none()
            {
                return Err(mismatch());
            }
            Ok(())
        }
        _ => Err(mismatch()),
    }
}

fn matching_ids(value: Value, session: &str, prefix: &str) -> Result<Vec<String>, ConnectorError> {
    let items = value.as_array().ok_or_else(mismatch)?;
    if items.len() > MAX_ITEMS {
        return Err(mismatch());
    }
    let mut out = Vec::new();
    for item in items {
        let map = item.as_object().ok_or_else(mismatch)?;
        if prefix == "que" {
            validate_question(map)?;
        } else {
            validate_permission(map)?;
        }
        let sid = map
            .get("sessionID")
            .and_then(Value::as_str)
            .ok_or_else(mismatch)?;
        let id = map.get("id").and_then(Value::as_str).ok_or_else(mismatch)?;
        if !safe_stock_id(sid, "ses") || !safe_stock_id(id, prefix) {
            return Err(mismatch());
        }
        if sid == session {
            out.push(id.into())
        }
    }
    Ok(out)
}

fn validate_question(map: &Map<String, Value>) -> Result<(), ConnectorError> {
    exact_keys(
        map,
        &["id", "sessionID", "questions", "tool"],
        &["id", "sessionID", "questions"],
    )?;
    let questions = map
        .get("questions")
        .and_then(Value::as_array)
        .ok_or_else(mismatch)?;
    if questions.len() > MAX_ITEMS {
        return Err(mismatch());
    }
    for question in questions {
        let question = question.as_object().ok_or_else(mismatch)?;
        exact_keys(
            question,
            &["question", "header", "options", "multiple", "custom"],
            &["question", "header", "options"],
        )?;
        require_string(question, "question")?;
        require_string(question, "header")?;
        let options = question
            .get("options")
            .and_then(Value::as_array)
            .ok_or_else(mismatch)?;
        if options.len() > MAX_ITEMS
            || question
                .get("multiple")
                .is_some_and(|value| !value.is_boolean())
            || question
                .get("custom")
                .is_some_and(|value| !value.is_boolean())
        {
            return Err(mismatch());
        }
        for option in options {
            let option = option.as_object().ok_or_else(mismatch)?;
            exact_keys(option, &["label", "description"], &["label", "description"])?;
            require_string(option, "label")?;
            require_string(option, "description")?;
        }
    }
    validate_tool(map.get("tool"))
}

fn validate_permission(map: &Map<String, Value>) -> Result<(), ConnectorError> {
    exact_keys(
        map,
        &[
            "id",
            "sessionID",
            "permission",
            "patterns",
            "metadata",
            "always",
            "tool",
        ],
        &[
            "id",
            "sessionID",
            "permission",
            "patterns",
            "metadata",
            "always",
        ],
    )?;
    require_string(map, "permission")?;
    let patterns = map
        .get("patterns")
        .and_then(Value::as_array)
        .ok_or_else(mismatch)?;
    if patterns.len() > MAX_ITEMS || patterns.iter().any(|value| !value.is_string()) {
        return Err(mismatch());
    }
    let metadata = map
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(mismatch)?;
    if metadata.len() > MAX_ITEMS || map.get("always").and_then(Value::as_bool).is_none() {
        return Err(mismatch());
    }
    validate_tool(map.get("tool"))
}

fn validate_tool(value: Option<&Value>) -> Result<(), ConnectorError> {
    let Some(value) = value else {
        return Ok(());
    };
    let tool = value.as_object().ok_or_else(mismatch)?;
    exact_keys(tool, &["messageID", "callID"], &["messageID", "callID"])?;
    require_string(tool, "messageID")?;
    require_string(tool, "callID")?;
    Ok(())
}
fn one_alias(domain: &str, values: Vec<String>) -> Result<Option<String>, ConnectorError> {
    if values.len() > 1 {
        return Err(mismatch());
    }
    Ok(values.first().map(|value| alias(domain, value)))
}
fn alias(domain: &str, value: &str) -> String {
    format!(
        "{domain}-{:x}",
        Sha256::digest(format!("{domain}:{value}").as_bytes())
    )[..domain.len() + 1 + 32]
        .into()
}
fn safe_stock_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn mismatch() -> ConnectorError {
    ConnectorError::ProtocolMismatch("invalid official stock snapshot".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum Route {
        Session,
        Status,
        Question,
        Permission,
        Diff,
    }

    fn session() -> Vec<u8> {
        br#"{"id":"ses_1","slug":"redacted","projectID":"global","directory":"/secret/path","title":"secret title","version":"1.18.16","time":{"created":1,"updated":1787650000000}}"#.to_vec()
    }

    fn assert_route_rejected(route: Route, raw: &[u8]) {
        let valid_session = session();
        let result = match route {
            Route::Session => {
                project_stock_snapshot("ses_1", raw, br#"{}"#, br#"[]"#, br#"[]"#, br#"[]"#)
            }
            Route::Status => {
                project_stock_snapshot("ses_1", &valid_session, raw, br#"[]"#, br#"[]"#, br#"[]"#)
            }
            Route::Question => {
                project_stock_snapshot("ses_1", &valid_session, br#"{}"#, raw, br#"[]"#, br#"[]"#)
            }
            Route::Permission => {
                project_stock_snapshot("ses_1", &valid_session, br#"{}"#, br#"[]"#, raw, br#"[]"#)
            }
            Route::Diff => {
                project_stock_snapshot("ses_1", &valid_session, br#"{}"#, br#"[]"#, br#"[]"#, raw)
            }
        };
        assert!(result.is_err());
    }

    fn over_depth() -> Vec<u8> {
        let mut raw = vec![b'['; MAX_JSON_DEPTH + 1];
        raw.extend(std::iter::repeat_n(b']', MAX_JSON_DEPTH + 1));
        raw
    }

    fn over_nodes() -> Vec<u8> {
        let mut raw = Vec::with_capacity(MAX_JSON_NODES * 5 + 2);
        raw.push(b'[');
        for index in 0..MAX_JSON_NODES {
            if index != 0 {
                raw.push(b',');
            }
            raw.extend_from_slice(b"null");
        }
        raw.push(b']');
        raw
    }

    #[test]
    fn projects_counts_aliases_and_no_content() {
        let value = project_stock_snapshot(
            "ses_1",
            &session(),
            br#"{"ses_1":{"type":"busy"}}"#,
            br#"[{"id":"que_1","sessionID":"ses_1","questions":[{"question":"secret question","header":"secret header","options":[{"label":"secret label","description":"secret description"}],"multiple":false,"custom":true}],"tool":{"messageID":"msg_1","callID":"call_1"}},{"id":"que_2","sessionID":"ses_other","questions":[]}]"#,
            br#"[]"#,
            br#"[{"file":"secret.rs","patch":"secret","additions":1,"deletions":0,"status":"modified"}]"#,
        )
        .unwrap();
        assert_eq!(value.turn_state, "NeedsInput");
        assert_eq!(value.diff_file_count, 1);
        assert_eq!(value.updated_at, "2026-08-25T09:26:40.000Z");
        assert!(!value.writable);
        let raw = serde_json::to_string(&value).unwrap();
        assert!(!raw.contains("secret"));
        assert!(!raw.contains("ses_1"));
        assert!(!raw.contains("que_1"));
    }

    #[test]
    fn permission_precedes_question() {
        let value = project_stock_snapshot(
            "ses_1",
            &session(),
            br#"{}"#,
            br#"[{"id":"que_1","sessionID":"ses_1","questions":[]}]"#,
            br#"[{"id":"per_1","sessionID":"ses_1","permission":"bash","patterns":["secret command"],"metadata":{"secret":"value"},"always":false}]"#,
            br#"[]"#,
        )
        .unwrap();
        assert_eq!(value.turn_state, "NeedsPermission");
        let raw = serde_json::to_string(&value).unwrap();
        assert!(!raw.contains("bash"));
        assert!(!raw.contains("command"));
    }

    #[test]
    fn rejects_wrong_session_duplicate_extra_oversize_and_ambiguous_pending() {
        for raw in [
            br#"{"id":"ses_other","slug":"s","projectID":"p","directory":"d","title":"t","version":"1.18.16","time":{"created":1,"updated":2}}"#.as_slice(),
            br#"{"id":"ses_1","id":"ses_1","slug":"s","projectID":"p","directory":"d","title":"t","version":"1.18.16","time":{"created":1,"updated":2}}"#,
            br#"{"id":"ses_1","slug":"s","projectID":"p","directory":"d","title":"t","version":"1.18.16","time":{"created":1,"updated":2},"unknown":1}"#,
            br#"{"id":"ses_1","slug":"s","projectID":"p","directory":"d","title":"t","version":"1.18.16","time":{"created":1,"updated":2,"updated":3}}"#,
            br#"{"id":"ses_1","slug":"s","projectID":"p","directory":"d","title":"t","version":"1.18.16","time":{"created":1,"updated":2}} trailing"#,
        ] {
            assert!(project_stock_snapshot(
                "ses_1", raw, br#"{}"#, br#"[]"#, br#"[]"#, br#"[]"#
            )
            .is_err());
        }
        assert!(project_stock_snapshot(
            "ses_1",
            &vec![b'x'; MAX_RESPONSE_BYTES + 1],
            br#"{}"#,
            br#"[]"#,
            br#"[]"#,
            br#"[]"#
        )
        .is_err());
        assert!(project_stock_snapshot(
            "ses_1",
            &session(),
            br#"{}"#,
            br#"[{"id":"que_1","sessionID":"ses_1","questions":[]},{"id":"que_2","sessionID":"ses_1","questions":[]}]"#,
            br#"[]"#,
            br#"[]"#
        )
        .is_err());
    }

    #[test]
    fn every_route_rejects_trailing_duplicate_unknown_and_wrong_types() {
        let invalid_status = [
            br#"{"ses_1":{"type":"busy","type":"idle"}}"#.as_slice(),
            br#"{"ses_1":{"type":"busy","detail":"secret"}}"#,
            br#"{"ses_1":{"type":1}}"#,
            br#"{} trailing"#,
        ];
        for raw in invalid_status {
            assert!(
                project_stock_snapshot("ses_1", &session(), raw, br#"[]"#, br#"[]"#, br#"[]"#)
                    .is_err()
            );
        }

        for raw in [
            br#"[{"id":"que_1","sessionID":"ses_1","questions":[],"unknown":1}]"#.as_slice(),
            br#"[{"id":"que_1","sessionID":"ses_1","questions":{},"questions":[]}]"#,
            br#"[{"id":"que_1","sessionID":"ses_1","questions":[]}] trailing"#,
        ] {
            assert!(
                project_stock_snapshot("ses_1", &session(), br#"{}"#, raw, br#"[]"#, br#"[]"#)
                    .is_err()
            );
        }

        for raw in [
            br#"[{"id":"per_1","sessionID":"ses_1","permission":"bash","patterns":[],"metadata":{},"always":false,"unknown":1}]"#.as_slice(),
            br#"[{"id":"per_1","sessionID":"ses_1","permission":"bash","patterns":{},"metadata":{},"always":false}]"#,
            br#"[{"id":"per_1","sessionID":"ses_1","permission":"bash","patterns":[],"metadata":{},"always":false}] trailing"#,
        ] {
            assert!(project_stock_snapshot(
                "ses_1", &session(), br#"{}"#, br#"[]"#, raw, br#"[]"#
            )
            .is_err());
        }

        for raw in [
            br#"[{"file":"secret","patch":"secret","additions":1,"additions":2,"deletions":0}]"#
                .as_slice(),
            br#"[{"additions":"1","deletions":0}]"#,
            br#"[{"additions":1,"deletions":0,"unknown":1}]"#,
            br#"[] trailing"#,
        ] {
            assert!(
                project_stock_snapshot("ses_1", &session(), br#"{}"#, br#"[]"#, br#"[]"#, raw)
                    .is_err()
            );
        }
    }

    #[test]
    fn every_route_is_depth_and_aggregate_node_bounded_before_parsing() {
        let depth = over_depth();
        let nodes = over_nodes();
        for route in [
            Route::Session,
            Route::Status,
            Route::Question,
            Route::Permission,
            Route::Diff,
        ] {
            assert_route_rejected(route, &depth);
            assert_route_rejected(route, &nodes);
        }
    }

    #[test]
    fn deeply_nested_permission_metadata_is_rejected_before_parsing() {
        let nested = MAX_JSON_DEPTH;
        let mut raw =
            br#"[{"id":"per_1","sessionID":"ses_1","permission":"bash","patterns":[],"metadata":"#
                .to_vec();
        for _ in 0..nested {
            raw.extend_from_slice(br#"{"x":"#);
        }
        raw.extend_from_slice(b"null");
        raw.extend(std::iter::repeat_n(b'}', nested));
        raw.extend_from_slice(b",\"always\":false}]");
        assert_route_rejected(Route::Permission, &raw);
    }

    #[test]
    fn lexical_budget_ignores_delimiters_and_escaped_quotes_inside_strings() {
        let raw = br#"{"text":"[{\"still-string\":\"]}\"}]"}"#;
        assert!(lexical_json_budget(raw).is_ok());
        assert!(strict_json(raw).is_ok());
    }
}
