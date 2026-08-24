fn main() {
    if nomad_connector::native_audit_proxy_entrypoint().is_err() {
        std::process::exit(1);
    }
}
