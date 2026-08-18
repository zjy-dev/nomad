use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TurnState {
    None,
    Running,
    NeedsInput,
    NeedsPermission,
    Stopping,
    Completed,
    Cancelled,
    Failed,
    OutcomeUnknown,
}

impl TurnState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Running => "Running",
            Self::NeedsInput => "NeedsInput",
            Self::NeedsPermission => "NeedsPermission",
            Self::Stopping => "Stopping",
            Self::Completed => "Completed",
            Self::Cancelled => "Cancelled",
            Self::Failed => "Failed",
            Self::OutcomeUnknown => "OutcomeUnknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostConnectivity {
    Online,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFreshness {
    Live,
    Reconnecting,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub semantics_version: String,
    pub turn_id: Option<String>,
    pub turn_state: TurnState,
    pub host_connectivity: HostConnectivity,
    pub client_freshness: ClientFreshness,
    pub updated_at: String,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_id: String::new(),
            semantics_version: "1.0.0".to_string(),
            turn_id: None,
            turn_state: TurnState::None,
            host_connectivity: HostConnectivity::Online,
            client_freshness: ClientFreshness::Live,
            updated_at: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedEvent {
    pub event_type: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub event_id: String,
    pub seq: u64,
    pub timestamp: String,
    pub durable: bool,
    pub payload: Option<serde_json::Value>,
}

impl ProjectedEvent {
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            event_type: v["event_type"].as_str()?.to_string(),
            session_id: v["session_id"].as_str()?.to_string(),
            turn_id: v["turn_id"].as_str().map(|s| s.to_string()),
            event_id: v["event_id"].as_str()?.to_string(),
            seq: v["seq"].as_u64()?,
            timestamp: v["timestamp"].as_str()?.to_string(),
            durable: v["durable"].as_bool().unwrap_or(true),
            payload: Some(v["payload"].clone()).filter(|p| !p.is_null()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StateSummary {
    pub session_status: Option<String>,
    pub active_turn: Option<String>,
    pub active_permission: Option<String>,
    pub diff_file_count: u64,
    pub test_status: Option<String>,
    pub tool_states: Vec<ToolStateEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStateEntry {
    pub tool_name: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub session_id: String,
    pub snapshot_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub last_applied_seq: u64,
    pub turn_state: TurnState,
    pub turn_id: Option<String>,
    pub host_connectivity: HostConnectivity,
    pub client_freshness: ClientFreshness,
    pub state_summary: StateSummary,
    pub created_at: String,
    pub version: String,
}

impl Snapshot {
    pub fn without_digest(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        v["digest"] = serde_json::Value::Null;
        v
    }
}

pub fn project_events(events: &[ProjectedEvent]) -> SessionState {
    let mut state = SessionState {
        semantics_version: "1.0.0".to_string(),
        ..SessionState::default()
    };

    for ev in events {
        apply_event(&mut state, ev);
    }

    if !state.session_id.is_empty() {
        // session_id already set
    }
    state
}

fn apply_event(state: &mut SessionState, ev: &ProjectedEvent) {
    state.session_id = ev.session_id.clone();
    state.updated_at = ev.timestamp.clone();

    match ev.event_type.as_str() {
        "session.created" => {
            // A new session exists before its first turn.
            state.turn_id = None;
            if matches!(state.turn_state, TurnState::None) {
                // keep None
            }
        }
        "session.updated" => {
            // Connectivity/metadata updates do not end or replace the active turn.
        }
        "turn.started" => {
            state.turn_id = ev.turn_id.clone();
            state.turn_state = TurnState::Running;
        }
        "turn.stopping" => {
            state.turn_state = TurnState::Stopping;
        }
        "turn.completed" => {
            state.turn_state = TurnState::Completed;
        }
        "turn.cancelled" => {
            state.turn_state = TurnState::Cancelled;
        }
        "turn.failed" => {
            state.turn_state = TurnState::Failed;
        }
        "turn.outcome_unknown" => {
            state.turn_state = TurnState::OutcomeUnknown;
        }
        "message.accepted" | "message.completed" => {
            let is_question = ev
                .payload
                .as_ref()
                .and_then(|payload| payload["action"].as_str())
                == Some("question");
            state.turn_state = if is_question {
                TurnState::NeedsInput
            } else {
                TurnState::Running
            };
        }
        "tool.started" | "tool.completed" | "tool.failed" => {
            // tool events don't change turn_state directly
        }
        "permission.requested" => {
            state.turn_state = TurnState::NeedsPermission;
        }
        "permission.resolved" => {
            state.turn_state = TurnState::Running;
        }
        "diff.updated" => {}
        "session.compacted" => {}
        _ => {}
    }
}

pub fn project_to_state_summary(events: &[ProjectedEvent]) -> StateSummary {
    let mut summary = StateSummary {
        session_status: Some("active".to_string()),
        ..StateSummary::default()
    };
    let mut tool_map: Vec<ToolStateEntry> = Vec::new();
    let mut seen_tools: Vec<String> = Vec::new();

    for ev in events {
        match ev.event_type.as_str() {
            "turn.started" => {
                summary.active_turn = ev.turn_id.clone();
            }
            "turn.completed" | "turn.cancelled" | "turn.failed" | "turn.outcome_unknown"
                if summary.active_turn == ev.turn_id =>
            {
                summary.active_turn = None;
            }
            "permission.requested" => {
                summary.active_permission = ev
                    .payload
                    .as_ref()
                    .and_then(|payload| payload["permission_id"].as_str())
                    .map(str::to_owned);
            }
            "permission.resolved" => {
                summary.active_permission = None;
            }
            _ => {}
        }

        if let Some(ref payload) = ev.payload {
            if let Some(name) = payload["tool_name"].as_str() {
                if !seen_tools.contains(&name.to_string()) {
                    seen_tools.push(name.to_string());
                }
                let status = match ev.event_type.as_str() {
                    "tool.completed" => "Completed",
                    "tool.failed" => "Failed",
                    "tool.started" => "Running",
                    _ => continue,
                };
                if let Some(existing) = tool_map.iter_mut().find(|t| t.tool_name == name) {
                    existing.status = status.to_string();
                } else {
                    tool_map.push(ToolStateEntry {
                        tool_name: name.to_string(),
                        status: status.to_string(),
                    });
                }
            }
        }
        if ev.event_type == "diff.updated" {
            if let Some(ref payload) = ev.payload {
                if let Some(summary_str) = payload["summary"].as_str() {
                    if let Some(c) = summary_str.chars().next() {
                        if c.is_ascii_digit() {
                            if let Ok(n) = summary_str
                                .chars()
                                .take_while(|ch| ch.is_ascii_digit())
                                .collect::<String>()
                                .parse::<u64>()
                            {
                                summary.diff_file_count = n;
                            }
                        }
                    }
                }
            }
        }
    }

    if summary.diff_file_count == 0 {
        // still set to zero, which is fine
    }

    // Preserve insertion order to match the contract fixture exactly
    summary.tool_states = tool_map;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_turn_state_values() {
        assert_eq!(TurnState::None.as_str(), "None");
        assert_eq!(TurnState::Running.as_str(), "Running");
        assert_eq!(TurnState::Completed.as_str(), "Completed");
    }

    #[test]
    fn test_project_event_from_json() {
        let v = json!({
            "event_type": "turn.started",
            "session_id": "sess_1",
            "turn_id": "turn_1",
            "event_id": "sess_1:1",
            "seq": 1,
            "timestamp": "2026-08-17T10:00:00Z",
            "durable": true,
            "payload": {"state_change": "started"}
        });
        let ev = ProjectedEvent::from_json(&v).unwrap();
        assert_eq!(ev.event_type, "turn.started");
        assert_eq!(ev.seq, 1);
    }

    #[test]
    fn test_project_events_normal_completion() {
        let events = vec![
            ProjectedEvent {
                event_type: "session.created".into(),
                session_id: "s1".into(),
                turn_id: None,
                event_id: "s1:1".into(),
                seq: 1,
                timestamp: "t1".into(),
                durable: true,
                payload: None,
            },
            ProjectedEvent {
                event_type: "turn.started".into(),
                session_id: "s1".into(),
                turn_id: Some("t1".into()),
                event_id: "s1:2".into(),
                seq: 2,
                timestamp: "t2".into(),
                durable: true,
                payload: None,
            },
            ProjectedEvent {
                event_type: "turn.completed".into(),
                session_id: "s1".into(),
                turn_id: Some("t1".into()),
                event_id: "s1:8".into(),
                seq: 8,
                timestamp: "t8".into(),
                durable: true,
                payload: None,
            },
        ];

        let state = project_events(&events);
        assert_eq!(state.session_id, "s1");
        assert_eq!(state.turn_id, Some("t1".to_string()));
        assert_eq!(state.turn_state, TurnState::Completed);
    }

    #[test]
    fn test_state_summary_tools() {
        let events = vec![
            ProjectedEvent {
                event_type: "tool.started".into(),
                session_id: "s1".into(),
                turn_id: Some("t1".into()),
                event_id: "s1:1".into(),
                seq: 1,
                timestamp: "t1".into(),
                durable: true,
                payload: Some(json!({"tool_name": "grep"})),
            },
            ProjectedEvent {
                event_type: "tool.completed".into(),
                session_id: "s1".into(),
                turn_id: Some("t1".into()),
                event_id: "s1:2".into(),
                seq: 2,
                timestamp: "t2".into(),
                durable: true,
                payload: Some(json!({"tool_name": "grep"})),
            },
            ProjectedEvent {
                event_type: "diff.updated".into(),
                session_id: "s1".into(),
                turn_id: Some("t1".into()),
                event_id: "s1:3".into(),
                seq: 3,
                timestamp: "t3".into(),
                durable: true,
                payload: Some(json!({"summary": "3 files changed"})),
            },
        ];

        let summary = project_to_state_summary(&events);
        assert_eq!(summary.diff_file_count, 3);
        assert_eq!(summary.tool_states.len(), 1);
        assert_eq!(summary.tool_states[0].tool_name, "grep");
        assert_eq!(summary.tool_states[0].status, "Completed");
    }
}
