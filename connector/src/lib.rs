mod actual_launch;
pub mod adapters;
mod alpha_projector;
pub mod dedup;
#[allow(dead_code)] // A1 lands the authority slice before A2 integrates it.
mod device_authority;
pub mod error;
pub mod fixture_loader;
#[allow(dead_code)] // Unreachable until production pairing constructs authenticated context.
mod host_command_authority;
pub mod host_device_identity;
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
mod opencode_adapter;
#[allow(dead_code)] // E1 lands the coordinator before E2 integrates Product Host routes.
mod pairing_coordinator;
pub mod permission;
mod pilot_bridge;
pub mod process_bridge;
mod product_command_protocol;
pub mod product_host_bootstrap;
mod product_stock_projector;
pub mod projection;
mod relay_provisioning;
pub mod release_bundle;
#[allow(dead_code)] // M3 freezes the application envelope before the Host endpoint join.
mod remote_application;
mod remote_command_ingress;
#[allow(dead_code)] // M2 freezes the endpoint codec before M3 wires it into the product.
mod remote_crypto;
mod remote_mailbox;
#[cfg(feature = "remote_v2_test_helper")]
mod remote_mechanical;
pub mod run_binding;
pub mod snapshot;
mod stock_event_adapter;
mod stock_opencode;
mod stock_snapshot;
pub mod stop_interrupt;
mod url_gate;

#[cfg(feature = "actual_launch_test_helper")]
pub use actual_launch::{actual_launch_adopter_entrypoint, ActualLaunchError};
pub use dedup::{DedupResult, ReplyDedup};
pub use error::ConnectorError;
pub use fixture_loader::{
    load_synthetic, load_trace_events, Provenance, SyntheticCase, SyntheticFile,
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
#[cfg(feature = "native_composed_transport_test_helper")]
pub use native_transport::supervise_test_proxy_and_adopter;
#[cfg(feature = "native_transport_test_helper")]
pub use native_transport::{supervise_test_adopter, NativeTransportError};
pub use permission::{PermissionDecision, PermissionService, PermissionViewResult};
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
#[cfg(feature = "remote_v2_test_helper")]
pub use remote_mechanical::remote_v2_mechanical_entrypoint;
pub use run_binding::{
    HostRunBinding, RunBinding, RunBindingError, RunBindingHello, RUN_BINDING_VERSION,
};
pub use snapshot::{canonical_json, compute_digest, to_canonical_value};
pub use stop_interrupt::{
    InterruptAndSendCommand, OrderingOutcome, StopCommand, StopInterruptService,
};
