fn main() {
    if nomad_connector::native_sse_proxy_entrypoint().is_err() {
        std::process::exit(1);
    }
}
