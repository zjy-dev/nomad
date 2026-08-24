fn main() {
    if nomad_connector::native_sse_reconnect_entrypoint().is_err() {
        std::process::exit(1);
    }
}
