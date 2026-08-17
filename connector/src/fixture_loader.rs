use crate::error::ConnectorError;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Provenance {
    pub upstream: Upstream,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Upstream {
    pub name: String,
    pub version: String,
    pub commit: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SyntheticCase {
    pub id: String,
    #[allow(dead_code)]
    pub description: Option<String>,
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SyntheticFile {
    #[serde(rename = "target")]
    pub fixture_type: String,
    pub cases: Vec<SyntheticCase>,
}

impl Provenance {
    pub fn load(path: &Path) -> Result<Self, ConnectorError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConnectorError::FixtureLoad(format!("provenance.json: {e}")))?;
        let prov: Provenance = serde_json::from_str(&content)?;
        Ok(prov)
    }
}

pub fn load_synthetic(path: &Path) -> Result<SyntheticFile, ConnectorError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConnectorError::FixtureLoad(format!("{}: {e}", path.display())))?;
    let sf: SyntheticFile = serde_json::from_str(&content)?;
    Ok(sf)
}

pub fn load_trace_events(path: &Path) -> Result<Vec<serde_json::Value>, ConnectorError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConnectorError::FixtureLoad(format!("{}: {e}", path.display())))?;
    let trace: serde_json::Value = serde_json::from_str(&content)?;
    let events = trace["events"].as_array().cloned().ok_or_else(|| {
        ConnectorError::FixtureLoad(format!("{}: missing events", path.display()))
    })?;
    Ok(events)
}
