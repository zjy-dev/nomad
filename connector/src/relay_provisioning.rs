//! Bounded Product Host client for the Relay v2 provisioning and cleanup seams.
//!
//! Provisioning uses the dedicated admin listener and only sends bearer digests
//! plus public-key commitments. Cleanup deliberately uses the role-fixed Host
//! data listener with the per-mailbox Host bearer.

use crate::pairing_coordinator::{
    PairingCoordinatorError, RelayProvisionRequest, RelayProvisioner,
};
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::time::Duration;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

const PROVISION_PATH: &str = "/v2/admin/mailboxes/provision";
const MAX_ADMIN_BEARER_BYTES: usize = 4096;
const MAX_PROVISION_REQUEST_BYTES: usize = 4096;
const MAX_PROVISION_RESPONSE_BYTES: u64 = 4096;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RelayProvisioningError {
    #[error("RELAY_PROVISIONING_INVALID_CONFIG")]
    InvalidConfig,
    #[error("RELAY_PROVISIONING_INVALID_REQUEST")]
    InvalidRequest,
    #[error("RELAY_PROVISIONING_UNAVAILABLE")]
    Unavailable,
    #[error("RELAY_PROVISIONING_PROTOCOL")]
    Protocol,
}

/// Secret accepted only from a caller-owned in-memory value or an inherited FD.
/// Its `Debug` representation and all errors are content free.
pub(crate) struct RelayAdminBearer(Zeroizing<String>);

impl fmt::Debug for RelayAdminBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayAdminBearer(<redacted>)")
    }
}

impl RelayAdminBearer {
    pub(crate) fn from_memory(bearer: Zeroizing<String>) -> Result<Self, RelayProvisioningError> {
        validate_bearer(&bearer)?;
        Ok(Self(bearer))
    }

    /// Consumes an inherited descriptor. Pipes/sockets are read once; private
    /// regular files are rewound before reading. No path or environment lookup
    /// is provided by this module.
    pub(crate) fn from_fd(fd: OwnedFd) -> Result<Self, RelayProvisioningError> {
        let mut file = File::from(fd);
        let metadata = file
            .metadata()
            .map_err(|_| RelayProvisioningError::InvalidConfig)?;
        if metadata.is_file() {
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(RelayProvisioningError::InvalidConfig);
            }
            file.seek(SeekFrom::Start(0))
                .map_err(|_| RelayProvisioningError::InvalidConfig)?;
        } else if !metadata.file_type().is_fifo() && !metadata.file_type().is_socket() {
            return Err(RelayProvisioningError::InvalidConfig);
        }
        let mut raw = Zeroizing::new(Vec::new());
        file.take((MAX_ADMIN_BEARER_BYTES + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|_| RelayProvisioningError::InvalidConfig)?;
        if raw.is_empty() || raw.len() > MAX_ADMIN_BEARER_BYTES {
            return Err(RelayProvisioningError::InvalidConfig);
        }
        let raw_text =
            std::str::from_utf8(&raw).map_err(|_| RelayProvisioningError::InvalidConfig)?;
        let bearer = raw_text
            .strip_suffix("\r\n")
            .or_else(|| raw_text.strip_suffix('\n'))
            .unwrap_or(raw_text)
            .to_owned();
        raw.zeroize();
        Self::from_memory(Zeroizing::new(bearer))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub(crate) struct UreqRelayProvisioner {
    admin_base_url: Url,
    host_role_base_url: Url,
    admin_bearer: RelayAdminBearer,
    allow_loopback_test_http: bool,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqRelayProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqRelayProvisioner")
            .field("admin_base_url", &self.admin_base_url)
            .field("host_role_base_url", &self.host_role_base_url)
            .field("admin_bearer", &"<redacted>")
            .field("allow_loopback_test_http", &self.allow_loopback_test_http)
            .finish()
    }
}

impl UreqRelayProvisioner {
    pub(crate) fn new(
        admin_base_url: &str,
        host_role_base_url: &str,
        admin_bearer: RelayAdminBearer,
        allow_loopback_test_http: bool,
    ) -> Result<Self, RelayProvisioningError> {
        let admin_base_url = parse_base_url(admin_base_url)?;
        validate_admin_url(&admin_base_url, allow_loopback_test_http)?;
        let host_role_base_url = parse_base_url(host_role_base_url)?;
        validate_host_role_url(&host_role_base_url, allow_loopback_test_http)?;
        Ok(Self {
            admin_base_url,
            host_role_base_url,
            admin_bearer,
            allow_loopback_test_http,
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(CONNECT_TIMEOUT)
                .timeout_read(READ_TIMEOUT)
                .timeout_write(WRITE_TIMEOUT)
                .build(),
        })
    }

    fn provision_inner(
        &self,
        request: &RelayProvisionRequest,
    ) -> Result<(), RelayProvisioningError> {
        validate_provision_request(request)?;
        let body =
            serde_json::to_vec(request).map_err(|_| RelayProvisioningError::InvalidRequest)?;
        if body.is_empty() || body.len() > MAX_PROVISION_REQUEST_BYTES {
            return Err(RelayProvisioningError::InvalidRequest);
        }
        // Serde struct field order is the frozen Relay canonical order.
        let url = endpoint(&self.admin_base_url, PROVISION_PATH);
        let mut authorization = Zeroizing::new(format!("Bearer {}", self.admin_bearer.as_str()));
        let response = self
            .agent
            .post(&url)
            .set("Authorization", authorization.as_str())
            .set("Accept", "application/json")
            .set("Content-Type", "application/json")
            .send_bytes(&body);
        authorization.zeroize();
        let response = response.map_err(map_ureq_error)?;
        let status = response.status();
        let result: ProvisionResult = decode_json_response(response)?;
        if result.schema != "nomad.relay.mailbox-provision-result.v1"
            || result.mailbox_id != request.mailbox_id
            || result.epoch != request.epoch
            || !matches!(
                (status, result.created, result.idempotent),
                (201, true, false) | (200, false, true)
            )
        {
            return Err(RelayProvisioningError::Protocol);
        }
        Ok(())
    }

    fn revoke_inner(
        &self,
        mailbox_id: &str,
        host_bearer: &str,
    ) -> Result<(), RelayProvisioningError> {
        validate_mailbox_id(mailbox_id)?;
        validate_bearer(host_bearer)?;
        let url = endpoint(
            &self.host_role_base_url,
            &format!("/v2/mailboxes/{mailbox_id}"),
        );
        let mut authorization = Zeroizing::new(format!("Bearer {host_bearer}"));
        let response = self
            .agent
            .delete(&url)
            .set("Authorization", authorization.as_str())
            .set("Accept", "application/json")
            .call();
        authorization.zeroize();
        let response = response.map_err(map_ureq_error)?;
        if response.status() != 204
            || response
                .header("Content-Length")
                .is_some_and(|value| value != "0")
        {
            return Err(RelayProvisioningError::Protocol);
        }
        Ok(())
    }
}

impl RelayProvisioner for UreqRelayProvisioner {
    fn provision(&self, request: &RelayProvisionRequest) -> Result<(), PairingCoordinatorError> {
        self.provision_inner(request)
            .map_err(|_| PairingCoordinatorError::Relay)
    }

    fn revoke(&self, mailbox_id: &str, host_bearer: &str) -> Result<(), PairingCoordinatorError> {
        self.revoke_inner(mailbox_id, host_bearer)
            .map_err(|_| PairingCoordinatorError::Relay)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionResult {
    schema: String,
    mailbox_id: String,
    epoch: u64,
    created: bool,
    idempotent: bool,
}

fn parse_base_url(value: &str) -> Result<Url, RelayProvisioningError> {
    let url = Url::parse(value).map_err(|_| RelayProvisioningError::InvalidConfig)?;
    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || url.host().is_none()
    {
        return Err(RelayProvisioningError::InvalidConfig);
    }
    Ok(url)
}

fn validate_admin_url(
    url: &Url,
    allow_loopback_test_http: bool,
) -> Result<(), RelayProvisioningError> {
    if !url.host().is_some_and(loopback_host)
        || !(url.scheme() == "https" || url.scheme() == "http" && allow_loopback_test_http)
    {
        return Err(RelayProvisioningError::InvalidConfig);
    }
    Ok(())
}

fn validate_host_role_url(
    url: &Url,
    allow_loopback_test_http: bool,
) -> Result<(), RelayProvisioningError> {
    if url.scheme() == "https"
        || url.scheme() == "http"
            && allow_loopback_test_http
            && url.host().is_some_and(loopback_host)
    {
        Ok(())
    } else {
        Err(RelayProvisioningError::InvalidConfig)
    }
}

fn loopback_host(host: Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => IpAddr::V4(ip).is_loopback(),
        Host::Ipv6(ip) => IpAddr::V6(ip).is_loopback(),
        Host::Domain(_) => false,
    }
}

fn endpoint(base: &Url, path: &str) -> String {
    let mut value = base.as_str().trim_end_matches('/').to_owned();
    value.push_str(path);
    value
}

fn validate_provision_request(
    request: &RelayProvisionRequest,
) -> Result<(), RelayProvisioningError> {
    if request.schema != "nomad.relay.mailbox-provision.v1"
        || request.epoch == 0
        || request.epoch > MAX_SAFE_INTEGER
        || validate_mailbox_id(&request.mailbox_id).is_err()
        || !digest(&request.host_token_digest)
        || !digest(&request.device_token_digest)
        || !digest(&request.host_identity_commitment)
        || !digest(&request.device_key_commitment)
        || request.host_token_digest == request.device_token_digest
    {
        return Err(RelayProvisioningError::InvalidRequest);
    }
    Ok(())
}

fn validate_mailbox_id(value: &str) -> Result<(), RelayProvisioningError> {
    if value.len() == 68
        && value.starts_with("mbx-")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RelayProvisioningError::InvalidRequest)
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value != "0".repeat(64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_bearer(value: &str) -> Result<(), RelayProvisioningError> {
    if value.is_empty()
        || value.len() > MAX_ADMIN_BEARER_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        Err(RelayProvisioningError::InvalidConfig)
    } else {
        Ok(())
    }
}

fn map_ureq_error(error: ureq::Error) -> RelayProvisioningError {
    match error {
        ureq::Error::Status(_, _) => RelayProvisioningError::Protocol,
        ureq::Error::Transport(_) => RelayProvisioningError::Unavailable,
    }
}

fn decode_json_response<T: for<'de> Deserialize<'de>>(
    response: ureq::Response,
) -> Result<T, RelayProvisioningError> {
    if response.header("Content-Type") != Some("application/json") {
        return Err(RelayProvisioningError::Protocol);
    }
    let mut reader = response
        .into_reader()
        .take(MAX_PROVISION_RESPONSE_BYTES + 1);
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|_| RelayProvisioningError::Unavailable)?;
    if body.is_empty() || body.len() as u64 > MAX_PROVISION_RESPONSE_BYTES {
        return Err(RelayProvisioningError::Protocol);
    }
    let mut parser = serde_json::Deserializer::from_slice(&body);
    let value = T::deserialize(&mut parser).map_err(|_| RelayProvisioningError::Protocol)?;
    parser.end().map_err(|_| RelayProvisioningError::Protocol)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::os::fd::FromRawFd;
    use std::sync::mpsc;
    use std::thread;

    fn request() -> RelayProvisionRequest {
        RelayProvisionRequest {
            schema: "nomad.relay.mailbox-provision.v1".into(),
            mailbox_id: format!("mbx-{}", "a".repeat(64)),
            epoch: 1,
            host_token_digest: "1".repeat(64),
            device_token_digest: "2".repeat(64),
            host_identity_commitment: "3".repeat(64),
            device_key_commitment: "4".repeat(64),
        }
    }

    fn client(admin_url: &str, host_url: &str) -> UreqRelayProvisioner {
        UreqRelayProvisioner::new(
            admin_url,
            host_url,
            RelayAdminBearer::from_memory(Zeroizing::new("admin-secret".into())).unwrap(),
            true,
        )
        .unwrap()
    }

    fn read_request(stream: &std::net::TcpStream) -> (String, Vec<u8>) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let length = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        (head, body)
    }

    #[test]
    fn admin_url_and_secret_sources_are_strict_and_redacted() {
        let bearer = RelayAdminBearer::from_memory(Zeroizing::new("secret-value".into())).unwrap();
        assert!(!format!("{bearer:?}").contains("secret-value"));
        assert!(UreqRelayProvisioner::new(
            "https://relay.example",
            "https://relay.example",
            bearer,
            false
        )
        .is_err());
        assert!(client("http://127.0.0.1:1", "http://127.0.0.1:2").allow_loopback_test_http);
        assert!(UreqRelayProvisioner::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            RelayAdminBearer::from_memory(Zeroizing::new("secret-value".into())).unwrap(),
            false
        )
        .is_err());

        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut writer = unsafe { File::from_raw_fd(fds[1]) };
        writer.write_all(b"fd-secret\n").unwrap();
        drop(writer);
        let owned = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let loaded = RelayAdminBearer::from_fd(owned).unwrap();
        assert_eq!(loaded.as_str(), "fd-secret");
        assert!(!format!("{loaded:?}").contains("fd-secret"));
    }

    #[test]
    fn provision_is_canonical_digest_only_and_delete_uses_host_role_bearer() {
        let admin = TcpListener::bind("127.0.0.1:0").unwrap();
        let admin_addr = admin.local_addr().unwrap();
        let host = TcpListener::bind("127.0.0.1:0").unwrap();
        let host_addr = host.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let request = request();
        let expected = serde_json::to_vec(&request).unwrap();
        let mailbox = request.mailbox_id.clone();
        let admin_thread = thread::spawn(move || {
            let (mut stream, _) = admin.accept().unwrap();
            let (head, body) = read_request(&stream);
            tx.send((head, body)).unwrap();
            let response = format!("{{\"schema\":\"nomad.relay.mailbox-provision-result.v1\",\"mailbox_id\":\"{mailbox}\",\"epoch\":1,\"created\":true,\"idempotent\":false}}");
            write!(stream, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        });
        let host_thread = thread::spawn(move || {
            let (mut stream, _) = host.accept().unwrap();
            let (head, body) = read_request(&stream);
            assert!(body.is_empty());
            assert!(head.starts_with(&format!(
                "DELETE /v2/mailboxes/mbx-{} HTTP/1.1\r\n",
                "a".repeat(64)
            )));
            assert!(head.contains("Authorization: Bearer host-secret\r\n"));
            write!(
                stream,
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let provisioner = client(
            &format!("http://{admin_addr}"),
            &format!("http://{host_addr}"),
        );
        provisioner.provision_inner(&request).unwrap();
        let (head, actual) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(actual, expected);
        assert!(head.starts_with("POST /v2/admin/mailboxes/provision HTTP/1.1\r\n"));
        assert!(head.contains("Authorization: Bearer admin-secret\r\n"));
        assert!(!actual
            .windows(b"admin-secret".len())
            .any(|part| part == b"admin-secret"));
        provisioner
            .revoke_inner(&request.mailbox_id, "host-secret")
            .unwrap();
        admin_thread.join().unwrap();
        host_thread.join().unwrap();
    }

    #[test]
    fn redirects_and_malformed_responses_fail_closed() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let target_addr = target.local_addr().unwrap();
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_addr = redirect.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = redirect.accept().unwrap();
            let _ = read_request(&stream);
            write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_addr}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let provisioner = client(&format!("http://{redirect_addr}"), "http://127.0.0.1:1");
        assert_eq!(
            provisioner.provision_inner(&request()),
            Err(RelayProvisioningError::Protocol)
        );
        worker.join().unwrap();
        thread::sleep(Duration::from_millis(25));
        assert!(target.accept().is_err());
    }
}
