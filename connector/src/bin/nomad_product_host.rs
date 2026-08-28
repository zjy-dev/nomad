use nomad_connector::host_device_identity::HostIdentityPreflightStatus;
use std::ffi::{OsStr, OsString};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Invocation {
    ProductHost,
    IdentityPreflight,
    AuthorizeHostIdentity,
    Invalid,
}

fn parse_invocation(arguments: &[OsString]) -> Invocation {
    match arguments {
        [] => Invocation::ProductHost,
        [command, flag]
            if command == OsStr::new("identity-preflight")
                && flag == OsStr::new("--non-interactive") =>
        {
            Invocation::IdentityPreflight
        }
        [command] if command == OsStr::new("authorize-host-identity") => {
            Invocation::AuthorizeHostIdentity
        }
        _ => Invocation::Invalid,
    }
}

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let invocation = parse_invocation(&arguments);
    if invocation != Invocation::ProductHost {
        let status = match invocation {
            Invocation::IdentityPreflight => {
                nomad_connector::host_device_identity::preflight_host_device_identity_noninteractive(
                )
            }
            Invocation::AuthorizeHostIdentity => {
                nomad_connector::host_device_identity::authorize_host_device_identity()
            }
            Invocation::Invalid => HostIdentityPreflightStatus::Unavailable,
            Invocation::ProductHost => unreachable!(),
        };
        println!("{}", status.canonical_json());
        std::process::exit(if status.is_ready() { 0 } else { 1 });
    }

    if nomad_connector::product_host_bootstrap::run_product_host(
        nomad_connector::product_host_bootstrap::BOOTSTRAP_FD,
    )
    .is_err()
    {
        std::process::exit(70);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn no_arguments_preserve_fd10_product_host_mode() {
        assert_eq!(parse_invocation(&[]), Invocation::ProductHost);
    }

    #[test]
    fn only_exact_identity_commands_are_accepted() {
        assert_eq!(
            parse_invocation(&args(&["identity-preflight", "--non-interactive"])),
            Invocation::IdentityPreflight
        );
        assert_eq!(
            parse_invocation(&args(&["authorize-host-identity"])),
            Invocation::AuthorizeHostIdentity
        );
        for invalid in [
            args(&["identity-preflight"]),
            args(&["identity-preflight", "--interactive"]),
            args(&["authorize-host-identity", "--non-interactive"]),
            args(&["unknown"]),
        ] {
            assert_eq!(parse_invocation(&invalid), Invocation::Invalid);
        }
    }
}
