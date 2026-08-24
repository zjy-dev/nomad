use nomad_connector::{HOST_PREREQUISITES_BLOCKED, HOST_PREREQUISITES_VERIFIED};
use std::fs;
use std::process::Command;

#[test]
fn normal_build_host_retains_one_unavailable_release_and_blocks() {
    let binary = env!("CARGO_BIN_EXE_nomad-host");
    let bytes = fs::read(binary).unwrap();
    let unavailable = b"NOMADREL\x00\x01\x00\x00\x00\x00\x00";
    assert_eq!(
        bytes
            .windows(unavailable.len())
            .filter(|window| *window == unavailable)
            .count(),
        1
    );
    let output = Command::new(binary).env_clear().output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("{HOST_PREREQUISITES_BLOCKED}\n").as_bytes()
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(HOST_PREREQUISITES_VERIFIED));
}

#[test]
fn normal_build_blocks_before_touching_inherited_fd_arguments() {
    let binary = env!("CARGO_BIN_EXE_nomad-host");
    let output = Command::new(binary)
        .args(["999999", "999998", "999997", &"01".repeat(32)])
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("{HOST_PREREQUISITES_BLOCKED}\n").as_bytes()
    );
}
