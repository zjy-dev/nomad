use nomad_connector::{
    nomad_host_entrypoint, HOST_PREREQUISITES_BLOCKED, HOST_PREREQUISITES_VERIFIED,
};

fn main() {
    match nomad_host_entrypoint() {
        Ok(()) => println!("{HOST_PREREQUISITES_VERIFIED}"),
        Err(_) => {
            eprintln!("{HOST_PREREQUISITES_BLOCKED}");
            std::process::exit(1);
        }
    }
}
