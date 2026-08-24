#![cfg(all(unix, feature = "native_transport_test_helper"))]

use nomad_connector::supervise_test_adopter;
use std::path::Path;

#[test]
fn rust_parent_supervises_real_adopter_over_exact_three_fd_transport() {
    let adopter = Path::new(env!("CARGO_BIN_EXE_actual-launch-adopter"))
        .canonicalize()
        .unwrap();
    supervise_test_adopter(&adopter).unwrap();
}

#[test]
fn caller_selected_non_adopter_cannot_satisfy_transport() {
    assert!(supervise_test_adopter(Path::new("/bin/true")).is_err());
}
