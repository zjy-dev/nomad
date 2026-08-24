fn main() {
    match nomad_connector::native_proxy_peer_entrypoint() {
        Ok(()) => println!("NATIVE_PROXY_PEER_READY"),
        Err(_) => {
            eprintln!("BLOCKED_NATIVE_PROXY_PEER");
            std::process::exit(1);
        }
    }
}
