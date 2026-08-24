fn main() {
    match nomad_connector::actual_launch_adopter_entrypoint() {
        Ok(()) => println!("ADOPTED_ACTUAL_LAUNCH_PROVENANCE"),
        Err(_) => {
            eprintln!("BLOCKED_ACTUAL_LAUNCH_ADOPTION");
            std::process::exit(1);
        }
    }
}
