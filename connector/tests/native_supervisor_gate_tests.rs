use nomad_connector::NATIVE_SUPERVISOR_BLOCKED;
use std::fs;
use std::process::{Command, Output};

fn run_supervisor(current_dir: &std::path::Path, overrides: &[(&str, &str)]) -> Output {
    let binary = env!("CARGO_BIN_EXE_nomad-supervisor");
    let mut command = Command::new(binary);
    command.env_clear().current_dir(current_dir);
    for (name, value) in overrides {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn assert_stably_blocked(output: &Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        format!("{NATIVE_SUPERVISOR_BLOCKED}\n").as_bytes()
    );
}

#[test]
fn default_production_gate_blocks_without_any_caller_input() {
    let root = tempfile::tempdir().unwrap();
    assert_stably_blocked(&run_supervisor(root.path(), &[]));
}

#[test]
fn python_markers_digests_and_path_overrides_have_no_authority() {
    let root = tempfile::tempdir().unwrap();
    let overrides = [
        ("PYTHONPATH", root.path().to_str().unwrap()),
        ("NOMAD_PYTHON_VERDICT", "PASS"),
        ("NOMAD_AUTHORIZATION", "NATIVE_SUPERVISOR_AUTHORITY_READY"),
        ("NOMAD_HOST_PATH", "/bin/true"),
        ("NOMAD_RELEASE_PATH", "/dev/null"),
        ("NOMAD_TRUST_ROOT", "caller-controlled"),
        ("NOMAD_PROTECTED_REF", "refs/heads/attacker"),
        ("NOMAD_HOST_DIGEST", &"0".repeat(64)),
    ];
    assert_stably_blocked(&run_supervisor(root.path(), &overrides));
}

#[test]
fn feature_build_cannot_route_test_authority_into_production() {
    let root = tempfile::tempdir().unwrap();
    let output = run_supervisor(
        root.path(),
        &[(
            "NOMAD_NATIVE_TEST_AUTHORITY",
            "NATIVE_SUPERVISOR_AUTHORITY_READY",
        )],
    );
    assert_stably_blocked(&output);
}

#[test]
fn blocked_gate_does_not_invoke_path_tools_or_create_temp_resources() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("child-spawned");
    let tool = root.path().join("python");
    fs::write(
        &tool,
        format!("#!/bin/sh\nprintf spawned > '{}'\n", marker.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for name in ["python3", "git", "ssh-keygen", "nomad-host"] {
        fs::copy(&tool, root.path().join(name)).unwrap();
    }
    let before = fs::read_dir(root.path()).unwrap().count();
    let output = run_supervisor(
        root.path(),
        &[
            ("PATH", root.path().to_str().unwrap()),
            ("TMPDIR", root.path().to_str().unwrap()),
            ("NOMAD_PYTHON_REALPATH", tool.to_str().unwrap()),
        ],
    );
    assert_stably_blocked(&output);
    assert!(!marker.exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), before);
}

#[test]
fn native_gate_source_has_no_child_or_ipc_primitive() {
    let source = include_str!("../src/native_supervisor.rs");
    for forbidden in [
        "std::process::Command",
        "Command::new",
        "UnixStream",
        "socketpair(",
        "libc::pipe",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden primitive: {forbidden}"
        );
    }
}
