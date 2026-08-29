use nomad_connector::host_device_identity::{HostDeviceIdentityScope, HostIdentityPreflightStatus};
use std::ffi::{OsStr, OsString};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Invocation {
    ProductHost,
    IdentityPreflight(HostDeviceIdentityScope),
    AuthorizeHostIdentity(HostDeviceIdentityScope),
    Invalid,
}

fn parse_scope(flag: &OsStr) -> Option<HostDeviceIdentityScope> {
    match flag.to_str() {
        Some("--scope=keychain") => Some(HostDeviceIdentityScope::Keychain),
        Some("--scope=local-installed") => Some(HostDeviceIdentityScope::LocalInstalled),
        _ => None,
    }
}

fn parse_invocation(arguments: &[OsString]) -> Invocation {
    match arguments {
        [] => Invocation::ProductHost,
        [command, flag, scope]
            if command == OsStr::new("identity-preflight")
                && flag == OsStr::new("--non-interactive") =>
        {
            parse_scope(scope)
                .map(Invocation::IdentityPreflight)
                .unwrap_or(Invocation::Invalid)
        }
        [command, scope] if command == OsStr::new("authorize-host-identity") => parse_scope(scope)
            .map(Invocation::AuthorizeHostIdentity)
            .unwrap_or(Invocation::Invalid),
        _ => Invocation::Invalid,
    }
}

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let invocation = parse_invocation(&arguments);
    if invocation != Invocation::ProductHost {
        let status = match invocation {
            Invocation::IdentityPreflight(scope) => {
                nomad_connector::host_device_identity::preflight_host_device_identity_noninteractive(
                    scope,
                )
            }
            Invocation::AuthorizeHostIdentity(scope) => {
                nomad_connector::host_device_identity::authorize_host_device_identity(scope)
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
            parse_invocation(&args(&[
                "identity-preflight",
                "--non-interactive",
                "--scope=keychain",
            ])),
            Invocation::IdentityPreflight(HostDeviceIdentityScope::Keychain)
        );
        assert_eq!(
            parse_invocation(&args(&[
                "identity-preflight",
                "--non-interactive",
                "--scope=local-installed",
            ])),
            Invocation::IdentityPreflight(HostDeviceIdentityScope::LocalInstalled)
        );
        assert_eq!(
            parse_invocation(&args(&["authorize-host-identity", "--scope=keychain"])),
            Invocation::AuthorizeHostIdentity(HostDeviceIdentityScope::Keychain)
        );
        assert_eq!(
            parse_invocation(&args(&[
                "authorize-host-identity",
                "--scope=local-installed",
            ])),
            Invocation::AuthorizeHostIdentity(HostDeviceIdentityScope::LocalInstalled)
        );
        for invalid in [
            args(&["identity-preflight"]),
            args(&["identity-preflight", "--interactive"]),
            args(&["identity-preflight", "--non-interactive"]),
            args(&["identity-preflight", "--non-interactive", "--scope=unknown"]),
            args(&["authorize-host-identity"]),
            args(&["authorize-host-identity", "--non-interactive"]),
            args(&["unknown"]),
        ] {
            assert_eq!(parse_invocation(&invalid), Invocation::Invalid);
        }
    }
}
