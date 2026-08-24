use nomad_connector::{
    M2ActionDigests, M2CapabilityReceipts, RealLifecycleEvidence, VerifiedM2Capabilities,
    COMMAND_SHAPE_SOURCE, REAL_LIFECYCLE_EVIDENCE_REQUIRED,
};

#[test]
fn shape_only_receipts_cannot_unlock_production_execution() {
    let receipts = M2CapabilityReceipts {
        runtime_provenance_digest:
            "9c760995cccf626759067424748e39174d869822142dd045a02f8ba9d8df815a".into(),
        action_shape_digests: M2ActionDigests {
            session_prompt: "7464d11dc616519845c1fb45b8095f514f9a38b5089c2b54520e60e8b9e0ef7a"
                .into(),
            question_reply: "69a8080e9580babb8ccefdcb50cc5d122412c5dd4af52519893b757f45b2b9d6"
                .into(),
            question_reject: "94e340c12c608c06dfc39716dfe9e6aac9a642123f3dc1e14654e266b8667a13"
                .into(),
            permission_reply: "b20592d595461d06bb40d0ca97f786cefd24b524b879e0c9a7e32cd537f08275"
                .into(),
            stop: "42ab353699b0a5c7b645d9da98bd3ed0d57e758e724f97bd27077e061a9c4f8b".into(),
        },
        source_classification: COMMAND_SHAPE_SOURCE.into(),
        real_lifecycle_evidence: RealLifecycleEvidence::Unavailable,
    };
    assert!(format!(
        "{}",
        VerifiedM2Capabilities::from_receipts(receipts).unwrap_err()
    )
    .contains(REAL_LIFECYCLE_EVIDENCE_REQUIRED));
}
