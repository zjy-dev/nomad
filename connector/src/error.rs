#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("URL {0} is not loopback-only; only 127.0.0.1 or localhost is allowed")]
    NonLoopbackUrl(String),

    #[error("OpenCode version mismatch: expected {expected}, got {actual}; repair with `npm install -g opencode-ai@{expected}`")]
    VersionMismatch { expected: String, actual: String },

    #[error("OpenCode unreachable at {0}")]
    OpenCodeUnreachable(String),

    #[error("OpenCode protocol mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("OpenCode HTTP {status}: {message}")]
    OpenCodeHttpStatus { status: u16, message: String },

    #[error("Fixture load error: {0}")]
    FixtureLoad(String),

    #[error("Projection error: {0}")]
    Projection(String),

    #[error("Journal error: {0}")]
    Journal(String),

    #[error("Duplicate request_id: {0}")]
    DuplicateRequest(String),

    #[error("Stale request: {0}")]
    StaleRequest(String),

    #[error("Request expired: {0}")]
    ExpiredRequest(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Safety blocked: {0}")]
    SafetyBlocked(String),

    #[error("Snapshot digest mismatch")]
    DigestMismatch,

    #[error("Host offline")]
    HostOffline,

    #[error("Outcome unknown, no automatic retry")]
    OutcomeUnknown,

    #[error("SQLite error: {0}")]
    Sqlite(String),

    #[error("JSON error: {0}")]
    Json(String),

    #[error("{0}")]
    Other(String),
}

impl From<rusqlite::Error> for ConnectorError {
    fn from(e: rusqlite::Error) -> Self {
        ConnectorError::Sqlite(e.to_string())
    }
}

impl From<serde_json::Error> for ConnectorError {
    fn from(e: serde_json::Error) -> Self {
        ConnectorError::Json(e.to_string())
    }
}

impl ConnectorError {
    pub fn error_code(&self) -> &'static str {
        match self {
            ConnectorError::DuplicateRequest(_) => "ERR_DUPLICATE_REQUEST",
            ConnectorError::StaleRequest(_) => "ERR_REQUEST_STALE",
            ConnectorError::ExpiredRequest(_) => "ERR_REQUEST_EXPIRED",
            ConnectorError::PermissionDenied(_) => "ERR_PERMISSION_DENIED",
            ConnectorError::SafetyBlocked(_) => "ERR_SAFETY_BLOCKED",
            ConnectorError::HostOffline => "ERR_HOST_OFFLINE",
            ConnectorError::VersionMismatch { .. } => "ERR_INCOMPATIBLE_VERSION",
            ConnectorError::ProtocolMismatch(_) => "ERR_INCOMPATIBLE_VERSION",
            ConnectorError::OpenCodeUnreachable(_) => "ERR_HOST_OFFLINE",
            ConnectorError::OutcomeUnknown => "ERR_OUTCOME_UNKNOWN",
            _ => "ERR_INTERNAL",
        }
    }
}
