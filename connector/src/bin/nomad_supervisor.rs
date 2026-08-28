use nomad_connector::adapters::opencode::startup::{
    native_supervisor_entrypoint, NATIVE_SUPERVISOR_BLOCKED,
};

fn main() {
    if native_supervisor_entrypoint().is_err() {
        eprintln!("{NATIVE_SUPERVISOR_BLOCKED}");
        std::process::exit(1);
    }
}
