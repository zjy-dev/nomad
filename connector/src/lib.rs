mod actual_launch;
pub mod dedup;
pub mod error;
pub mod fixture_loader;
mod host_startup;
pub mod journal;
#[cfg(feature = "native_audit_proxy_test_helper")]
mod native_audit_proxy;
#[cfg(test)]
mod native_launch;
#[cfg(feature = "native_proxy_peer_test_helper")]
mod native_proxy_peer;
#[cfg(feature = "native_sse_proxy_test_helper")]
mod native_sse_proxy;
#[cfg(feature = "native_sse_reconnect_test_helper")]
mod native_sse_reconnect;
mod native_supervisor;
#[cfg(feature = "native_transport_test_helper")]
mod native_transport;
pub mod opencode_adapter;
pub mod permission;
pub mod pilot_bridge;
pub mod process_bridge;
pub mod projection;
pub mod release_bundle;
pub mod run_binding;
pub mod snapshot;
pub mod stock_opencode;
pub mod stop_interrupt;
pub mod url_gate;

#[cfg(feature = "actual_launch_test_helper")]
pub use actual_launch::{actual_launch_adopter_entrypoint, ActualLaunchError};
pub use dedup::{DedupResult, ReplyDedup};
pub use error::ConnectorError;
pub use fixture_loader::{
    load_synthetic, load_trace_events, Provenance, SyntheticCase, SyntheticFile,
};
pub use host_startup::{
    nomad_host_entrypoint, HostStartupError, HOST_PREREQUISITES_BLOCKED,
    HOST_PREREQUISITES_VERIFIED,
};
pub use journal::{CommandJournal, JournalCommand};
#[cfg(feature = "native_audit_proxy_test_helper")]
pub use native_audit_proxy::{
    native_audit_proxy_config, native_audit_proxy_entrypoint, NativeAuditProxyError,
    NATIVE_AUDIT_PROXY_BLOCKED, NATIVE_AUDIT_PROXY_READY,
};
#[cfg(feature = "native_proxy_peer_test_helper")]
pub use native_proxy_peer::{
    native_proxy_peer_entrypoint, NativeProxyPeerError, NATIVE_PROXY_PEER_BLOCKED,
    NATIVE_PROXY_PEER_READY,
};
#[cfg(feature = "native_sse_proxy_test_helper")]
pub use native_sse_proxy::{
    native_sse_proxy_config, native_sse_proxy_entrypoint, NativeSseProxyError,
    NATIVE_SSE_PROXY_BLOCKED, NATIVE_SSE_PROXY_READY,
};
#[cfg(feature = "native_sse_reconnect_test_helper")]
pub use native_sse_reconnect::{
    native_sse_reconnect_config, native_sse_reconnect_entrypoint, NativeSseReconnectError,
    NATIVE_SSE_RECONNECT_BLOCKED, NATIVE_SSE_RECONNECT_READY,
};
pub use native_supervisor::{
    native_supervisor_entrypoint, NativeSupervisorError, NATIVE_SUPERVISOR_BLOCKED,
};
#[cfg(feature = "native_composed_transport_test_helper")]
pub use native_transport::supervise_test_proxy_and_adopter;
#[cfg(feature = "native_transport_test_helper")]
pub use native_transport::{supervise_test_adopter, NativeTransportError};
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
pub use release_bundle::{
    embedded_release, parse_release_container, HistoricalReleaseEvidence, ReleaseBundleError,
    VerifiedHistoricalEvidence,
};
pub use run_binding::{
    HostRunBinding, RunBinding, RunBindingError, RunBindingHello, RUN_BINDING_VERSION,
};
pub use snapshot::{canonical_json, compute_digest, to_canonical_value};
pub use stock_opencode::{
    current_release_authorization, CurrentReleaseAuthorization, M2ActionDigests,
    M2CapabilityReceipts, RealLifecycleEvidence, StockBlockedCommandResult, StockCommand,
    StockCommandBoundary, StockCommandHttp, StockCommandRequest, StockCommandResult,
    StockCommandTransport, StockObservationOutcome, StockOpenCodeAdapter, StockReconciliation,
    StockReconciliationStatus, StockSnapshotFacts, UreqStockCommandHttp, VerifiedM2Capabilities,
    APPROVAL_EXPIRED_OR_INVALID, COMMAND_SHAPE_SOURCE, REAL_LIFECYCLE_EVIDENCE_REQUIRED,
    STOCK_VERSION,
};
pub use stop_interrupt::{
    InterruptAndSendCommand, OrderingOutcome, StopCommand, StopInterruptService,
};
pub use url_gate::{check_version, validate_loopback, EXPECTED_COMMIT, EXPECTED_VERSION};
