//! Minimal product Host prerequisite boundary. No capability or command token
//! is created here; successful values are retained together and then dropped.

use crate::actual_launch::{adopt_actual_launch_from_process_args, ActualLaunchProvenance};
use crate::release_bundle::{embedded_release, HistoricalReleaseEvidence};
use crate::stock_opencode::{current_release_authorization, CurrentReleaseAuthorization};
use std::fmt;

pub const HOST_PREREQUISITES_VERIFIED: &str = "HOST_PREREQUISITES_VERIFIED";
pub const HOST_PREREQUISITES_BLOCKED: &str = "BLOCKED_HOST_PREREQUISITES_UNAVAILABLE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStartupError {
    EmbeddedRelease,
    CurrentApproval,
    ActualLaunch,
}

impl fmt::Display for HostStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(HOST_PREREQUISITES_BLOCKED)
    }
}
impl std::error::Error for HostStartupError {}

/// Private prerequisite aggregate. Its presence is not runtime execution
/// authority and no command function accepts it.
struct HostPrerequisites {
    _release: CurrentReleaseAuthorization,
    _launch: ActualLaunchProvenance,
}

pub fn nomad_host_entrypoint() -> Result<(), HostStartupError> {
    let release = embedded_release().map_err(|_| HostStartupError::EmbeddedRelease)?;
    let HistoricalReleaseEvidence::Verified(evidence) = release else {
        return Err(HostStartupError::EmbeddedRelease);
    };
    let release =
        current_release_authorization(&evidence).map_err(|_| HostStartupError::CurrentApproval)?;
    let launch =
        adopt_actual_launch_from_process_args().map_err(|_| HostStartupError::ActualLaunch)?;
    let prerequisites = HostPrerequisites {
        _release: release,
        _launch: launch,
    };
    drop(prerequisites);
    Ok(())
}
