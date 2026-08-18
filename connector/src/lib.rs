pub mod dedup;
pub mod error;
pub mod fixture_loader;
pub mod journal;
pub mod opencode_adapter;
pub mod permission;
pub mod pilot_bridge;
pub mod process_bridge;
pub mod projection;
pub mod snapshot;
pub mod stop_interrupt;
pub mod url_gate;

pub use dedup::{DedupResult, ReplyDedup};
pub use error::ConnectorError;
pub use fixture_loader::{
    load_synthetic, load_trace_events, Provenance, SyntheticCase, SyntheticFile,
};
pub use journal::{CommandJournal, JournalCommand};
pub use opencode_adapter::{
    AdapterCommandResult, CaptureSource, FileDiff, OpenCodeClient, OpenCodeCommandResponse,
    OpenCodeEvent, OpenCodeSession, PilotAdapter, PilotCapture, PilotCommand, UreqOpenCodeClient,
};
pub use permission::{PermissionDecision, PermissionService, PermissionViewResult};
pub use pilot_bridge::{parse_pilot_command, result_payload};
pub use process_bridge::{
    AckPayload, BridgeDispatcher, CommandResult, RelayClient, RelayMessage, UreqRelayClient,
};
pub use projection::{
    project_events, project_to_state_summary, ClientFreshness, HostConnectivity, ProjectedEvent,
    SessionState, Snapshot, StateSummary, TurnState,
};
pub use snapshot::{canonical_json, compute_digest, to_canonical_value};
pub use stop_interrupt::{
    InterruptAndSendCommand, OrderingOutcome, StopCommand, StopInterruptService,
};
pub use url_gate::{check_version, validate_loopback, EXPECTED_COMMIT, EXPECTED_VERSION};
