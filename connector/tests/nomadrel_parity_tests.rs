use nomad_connector::{parse_release_container, HistoricalReleaseEvidence};
use std::process::Command;

#[test]
fn python_and_rust_parse_the_same_reviewed_verified_container() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("testkit/agent-evidence/nomadrel_vector.py");
    let output = Command::new("/usr/bin/python3")
        .arg(script)
        .env_clear()
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .unwrap();
    assert!(output.status.success() && output.stderr.is_empty());
    let hex = std::str::from_utf8(&output.stdout).unwrap().trim();
    assert!(hex.len().is_multiple_of(2) && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    let raw: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert!(matches!(
        parse_release_container(&raw).unwrap(),
        HistoricalReleaseEvidence::Verified(_)
    ));
}
