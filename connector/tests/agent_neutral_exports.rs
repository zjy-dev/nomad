use nomad_connector::adapters::opencode::{
    AlphaProjectorConfig, OpenCodeClient, PilotAdapter, StockOpenCodeAdapter, UreqOpenCodeClient,
};

#[test]
fn opencode_surface_is_available_only_below_adapter_namespace() {
    fn accepts_client<C: OpenCodeClient>() {}

    accepts_client::<UreqOpenCodeClient>();
    let _pilot_type = std::any::type_name::<PilotAdapter<UreqOpenCodeClient>>();
    let _stock_type = std::any::type_name::<StockOpenCodeAdapter>();
    let _config = AlphaProjectorConfig {
        relay_url: "http://127.0.0.1:8787".into(),
        session_id: "session".into(),
    };
}

#[test]
fn crate_root_source_remains_agent_neutral() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "pub mod alpha_projector",
        "pub mod opencode_adapter",
        "pub mod stock_opencode",
        "pub mod url_gate",
        "pub use alpha_projector",
        "pub use opencode_adapter",
        "pub use stock_opencode",
        "pub use url_gate",
        "pub use host_startup",
        "pub use native_supervisor",
        "nomad_host_entrypoint",
        "native_supervisor_entrypoint",
        "EXPECTED_VERSION",
        "EXPECTED_COMMIT",
    ] {
        assert!(
            !source.contains(forbidden),
            "crate root exposes adapter-specific surface: {forbidden}"
        );
    }
}
