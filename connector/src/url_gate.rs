use crate::error::ConnectorError;
use url::Url;

pub const EXPECTED_VERSION: &str = "1.18.16";
pub const EXPECTED_COMMIT: &str = "a3647eb025c7615159d417dcc49fc39fdaeba65b";
pub const EXPECTED_HOSTNAME: &str = "127.0.0.1";
pub const EXPECTED_PORT: u16 = 4096;
pub const EXPECTED_BASE_URL: &str = "http://127.0.0.1:4096";

pub fn validate_loopback(url_str: &str) -> Result<(), ConnectorError> {
    let url = Url::parse(url_str)
        .map_err(|e| ConnectorError::NonLoopbackUrl(format!("{url_str}: {e}")))?;

    let host = url
        .host_str()
        .ok_or_else(|| ConnectorError::NonLoopbackUrl(format!("{url_str}: no host")))?;

    let is_loopback = host == "127.0.0.1" || host == "localhost";
    if !is_loopback {
        return Err(ConnectorError::NonLoopbackUrl(url_str.to_string()));
    }

    let port = url.port().unwrap_or(80);
    if port != EXPECTED_PORT {
        return Err(ConnectorError::NonLoopbackUrl(format!(
            "{url_str}: expected port {EXPECTED_PORT}, got {port}"
        )));
    }

    if url.scheme() != "http" {
        return Err(ConnectorError::NonLoopbackUrl(format!(
            "{url_str}: expected http scheme"
        )));
    }

    Ok(())
}

pub fn check_version(actual_version: &str) -> Result<(), ConnectorError> {
    if actual_version != EXPECTED_VERSION {
        return Err(ConnectorError::VersionMismatch {
            expected: EXPECTED_VERSION.to_string(),
            actual: actual_version.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_urls_pass() {
        assert!(validate_loopback("http://127.0.0.1:4096").is_ok());
        assert!(validate_loopback("http://localhost:4096").is_ok());
    }

    #[test]
    fn non_loopback_rejected() {
        assert!(validate_loopback("http://example.com:4096").is_err());
        assert!(validate_loopback("http://192.168.1.1:4096").is_err());
    }

    #[test]
    fn wrong_port_rejected() {
        assert!(validate_loopback("http://127.0.0.1:8080").is_err());
    }

    #[test]
    fn https_rejected() {
        assert!(validate_loopback("https://127.0.0.1:4096").is_err());
    }

    #[test]
    fn version_check_pass() {
        assert!(check_version("1.18.16").is_ok());
    }

    #[test]
    fn version_check_fail() {
        assert!(check_version("1.17.0").is_err());
        assert!(check_version("1.18.17").is_err());
    }
}
