use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use time::OffsetDateTime;
use url::{Host, Url};
use zeroize::Zeroizing;

pub const BOOTSTRAP_FD: RawFd = 10;
pub const RELAY_ADMIN_BEARER_FD: RawFd = 11;
pub const MAX_BOOTSTRAP_BYTES: usize = 16 * 1024;
pub const MAX_READY_BYTES: usize = 4 * 1024;
const DEVICE_REGISTRY_BASENAME: &str = "host-device-registry.sqlite3";
const PAIRING_STORE_BASENAME: &str = "pairing-coordinator.sqlite3";
const REMOTE_MAILBOX_STATE_BASENAME: &str = "remote-mailbox.sqlite3";
const REMOTE_BOOTSTRAP_SCHEMA: &str = "nomad.product-host.remote-bootstrap.v1";
const MIN_ADMIN_BEARER_BYTES: usize = 32;
const MAX_ADMIN_BEARER_BYTES: usize = 4096;
const ADMIN_BEARER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTE_MAILBOX_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError {
    #[error("BOOTSTRAP_IO")]
    Io,
    #[error("BOOTSTRAP_SIZE")]
    Size,
    #[error("BOOTSTRAP_INVALID")]
    Invalid,
}

#[derive(Deserialize)]
#[serde(tag = "schema")]
enum WireBootstrap {
    #[serde(rename = "nomad.product-host.bootstrap.v1")]
    V1(WireBootstrapV1),
    #[serde(rename = "nomad.product-host.bootstrap.v2")]
    V2(WireBootstrapV2),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBootstrapV1 {
    run_id: String,
    origin: String,
    session_id: String,
    server_password: String,
    workspace_binding_digest: String,
    product_host_socket_path: String,
    agent_pid: u32,
    agent_process_group: u32,
    agent_process_identity: String,
    product_host_socket_parent_dev: u64,
    product_host_socket_parent_ino: u64,
    command_transport_key: String,
    command_authority_key: String,
    command_journal_path: String,
    device_registry_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBootstrapV2 {
    run_id: String,
    origin: String,
    session_id: String,
    server_password: String,
    workspace_binding_digest: String,
    product_host_socket_path: String,
    agent_pid: u32,
    agent_process_group: u32,
    agent_process_identity: String,
    product_host_socket_parent_dev: u64,
    product_host_socket_parent_ino: u64,
    command_transport_key: String,
    join_transport_key: String,
    command_authority_key: String,
    command_journal_path: String,
    device_registry_path: String,
    remote: WireRemoteBootstrap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemoteBootstrap {
    schema: String,
    relay_admin_base_url: String,
    relay_host_base_url: String,
    relay_device_public_base_url: String,
    allow_loopback_test_http: bool,
    pairing_store_path: String,
    remote_mailbox_state_path: String,
}

pub struct HostBootstrap {
    pub run_id: String,
    pub origin: String,
    pub session_id: String,
    pub server_password: Zeroizing<String>,
    pub workspace_binding_digest: String,
    pub product_host_socket_path: PathBuf,
    pub agent_pid: u32,
    pub agent_process_group: u32,
    pub agent_process_identity: String,
    pub product_host_socket_parent_dev: u64,
    pub product_host_socket_parent_ino: u64,
    pub(crate) command_transport_key: Zeroizing<[u8; 32]>,
    pub(crate) command_authority_key: Zeroizing<[u8; 32]>,
    pub(crate) command_journal_path: PathBuf,
    pub(crate) device_registry_path: PathBuf,
}

pub struct DecodedBootstrap {
    pub host: HostBootstrap,
    pub(crate) remote: Option<RemoteHostBootstrap>,
}

pub(crate) struct RemoteHostBootstrap {
    pub(crate) join_transport_key: Zeroizing<[u8; 32]>,
    pub(crate) relay_admin_base_url: String,
    pub(crate) relay_host_base_url: String,
    pub(crate) relay_device_public_base_url: String,
    pub(crate) allow_loopback_test_http: bool,
    pub(crate) pairing_store_path: PathBuf,
    pub(crate) remote_mailbox_state_path: PathBuf,
}

impl std::fmt::Debug for HostBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostBootstrap(<redacted>)")
    }
}

impl std::fmt::Debug for RemoteHostBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RemoteHostBootstrap(<redacted>)")
    }
}

impl std::fmt::Debug for DecodedBootstrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedBootstrap")
            .field("host", &self.host)
            .field("remote", &self.remote)
            .finish()
    }
}

fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn decode(raw: &[u8]) -> Result<DecodedBootstrap, BootstrapError> {
    let mut parser = serde_json::Deserializer::from_slice(raw);
    let wire = WireBootstrap::deserialize(&mut parser).map_err(|_| BootstrapError::Invalid)?;
    parser.end().map_err(|_| BootstrapError::Invalid)?;
    match wire {
        WireBootstrap::V1(wire) => decode_v1(wire),
        WireBootstrap::V2(wire) => decode_v2(wire),
    }
}

fn decode_v1(wire: WireBootstrapV1) -> Result<DecodedBootstrap, BootstrapError> {
    let command_transport_key = decode_key(&wire.command_transport_key)?;
    let command_authority_key = decode_key(&wire.command_authority_key)?;
    if !lower_hex_64(&wire.run_id)
        || !lower_hex_64(&wire.workspace_binding_digest)
        || wire.origin != "http://127.0.0.1:4096" && !valid_loopback_origin(&wire.origin)
        || !valid_id(&wire.session_id)
        || wire.server_password.is_empty()
        || wire.server_password.len() > 1024
        || !wire.server_password.is_ascii()
        || !valid_socket_path(
            &wire.product_host_socket_path,
            &wire.run_id,
            &wire.session_id,
        )
        || wire.agent_pid <= 1
        || wire.agent_process_group != wire.agent_pid
        || !lower_hex_64(&wire.agent_process_identity)
        || wire.product_host_socket_parent_dev == 0
        || wire.product_host_socket_parent_ino == 0
        || command_transport_key.as_ref() == command_authority_key.as_ref()
        || !valid_journal_path(&wire.command_journal_path, &wire.run_id)
        || !valid_device_registry_path(&wire.device_registry_path)
    {
        return Err(BootstrapError::Invalid);
    }
    Ok(DecodedBootstrap {
        host: HostBootstrap {
            run_id: wire.run_id,
            origin: wire.origin,
            session_id: wire.session_id,
            server_password: Zeroizing::new(wire.server_password),
            workspace_binding_digest: wire.workspace_binding_digest,
            product_host_socket_path: PathBuf::from(wire.product_host_socket_path),
            agent_pid: wire.agent_pid,
            agent_process_group: wire.agent_process_group,
            agent_process_identity: wire.agent_process_identity,
            product_host_socket_parent_dev: wire.product_host_socket_parent_dev,
            product_host_socket_parent_ino: wire.product_host_socket_parent_ino,
            command_transport_key,
            command_authority_key,
            command_journal_path: PathBuf::from(wire.command_journal_path),
            device_registry_path: PathBuf::from(wire.device_registry_path),
        },
        remote: None,
    })
}

fn decode_v2(wire: WireBootstrapV2) -> Result<DecodedBootstrap, BootstrapError> {
    let command_transport_key = decode_key(&wire.command_transport_key)?;
    let join_transport_key = decode_key(&wire.join_transport_key)?;
    let command_authority_key = decode_key(&wire.command_authority_key)?;
    if !lower_hex_64(&wire.run_id)
        || !lower_hex_64(&wire.workspace_binding_digest)
        || wire.origin != "http://127.0.0.1:4096" && !valid_loopback_origin(&wire.origin)
        || !valid_id(&wire.session_id)
        || wire.server_password.is_empty()
        || wire.server_password.len() > 1024
        || !wire.server_password.is_ascii()
        || !valid_socket_path(
            &wire.product_host_socket_path,
            &wire.run_id,
            &wire.session_id,
        )
        || wire.agent_pid <= 1
        || wire.agent_process_group != wire.agent_pid
        || !lower_hex_64(&wire.agent_process_identity)
        || wire.product_host_socket_parent_dev == 0
        || wire.product_host_socket_parent_ino == 0
        || command_transport_key.as_ref() == join_transport_key.as_ref()
        || command_transport_key.as_ref() == command_authority_key.as_ref()
        || join_transport_key.as_ref() == command_authority_key.as_ref()
        || !valid_journal_path(&wire.command_journal_path, &wire.run_id)
    {
        return Err(BootstrapError::Invalid);
    }
    let remote = decode_remote(
        wire.remote,
        join_transport_key,
        &wire.device_registry_path,
        &wire.command_journal_path,
    )?;
    Ok(DecodedBootstrap {
        host: HostBootstrap {
            run_id: wire.run_id,
            origin: wire.origin,
            session_id: wire.session_id,
            server_password: Zeroizing::new(wire.server_password),
            workspace_binding_digest: wire.workspace_binding_digest,
            product_host_socket_path: PathBuf::from(wire.product_host_socket_path),
            agent_pid: wire.agent_pid,
            agent_process_group: wire.agent_process_group,
            agent_process_identity: wire.agent_process_identity,
            product_host_socket_parent_dev: wire.product_host_socket_parent_dev,
            product_host_socket_parent_ino: wire.product_host_socket_parent_ino,
            command_transport_key,
            command_authority_key,
            command_journal_path: PathBuf::from(wire.command_journal_path),
            device_registry_path: PathBuf::from(wire.device_registry_path),
        },
        remote: Some(remote),
    })
}

fn decode_remote(
    wire: WireRemoteBootstrap,
    join_transport_key: Zeroizing<[u8; 32]>,
    device_registry_path: &str,
    command_journal_path: &str,
) -> Result<RemoteHostBootstrap, BootstrapError> {
    if wire.schema != REMOTE_BOOTSTRAP_SCHEMA
        || !valid_remote_origins(
            &wire.relay_admin_base_url,
            &wire.relay_host_base_url,
            &wire.relay_device_public_base_url,
            wire.allow_loopback_test_http,
        )
    {
        return Err(BootstrapError::Invalid);
    }
    let device_registry_path =
        validate_private_database_path(device_registry_path, DEVICE_REGISTRY_BASENAME)?;
    let pairing_store_path =
        validate_private_database_path(&wire.pairing_store_path, PAIRING_STORE_BASENAME)?;
    let remote_mailbox_state_path = validate_private_database_path(
        &wire.remote_mailbox_state_path,
        REMOTE_MAILBOX_STATE_BASENAME,
    )?;
    let persistent_parent = device_registry_path
        .parent()
        .ok_or(BootstrapError::Invalid)?;
    if pairing_store_path.parent() != Some(persistent_parent)
        || remote_mailbox_state_path.parent() != Some(persistent_parent)
        || Path::new(command_journal_path).parent() == Some(persistent_parent)
    {
        return Err(BootstrapError::Invalid);
    }
    Ok(RemoteHostBootstrap {
        join_transport_key,
        relay_admin_base_url: wire.relay_admin_base_url,
        relay_host_base_url: wire.relay_host_base_url,
        relay_device_public_base_url: wire.relay_device_public_base_url,
        allow_loopback_test_http: wire.allow_loopback_test_http,
        pairing_store_path,
        remote_mailbox_state_path,
    })
}

fn decode_key(value: &str) -> Result<Zeroizing<[u8; 32]>, BootstrapError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| BootstrapError::Invalid)?,
    );
    if decoded.len() != 32 || STANDARD.encode(decoded.as_slice()) != value {
        return Err(BootstrapError::Invalid);
    }
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| BootstrapError::Invalid)?;
    Ok(Zeroizing::new(key))
}

fn valid_journal_path(value: &str, run_id: &str) -> bool {
    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 1024
        || !value.is_ascii()
        || value.contains(run_id)
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        || path.file_name().and_then(|name| name.to_str())
            != Some(expected_journal_filename(run_id).as_str())
        || fs::symlink_metadata(path).is_ok()
    {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(parent) else {
        return false;
    };
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o777 == 0o700
        && parent
            .canonicalize()
            .is_ok_and(|canonical| canonical == parent)
}

fn expected_journal_filename(run_id: &str) -> String {
    let run_alias = format!("{:x}", Sha256::digest(format!("state:{run_id}").as_bytes()));
    let journal_alias = format!(
        "{:x}",
        Sha256::digest(format!("journal:{run_alias}").as_bytes())
    );
    format!("command-{}.sqlite3", &journal_alias[..24])
}

fn valid_device_registry_path(value: &str) -> bool {
    validate_private_database_path(value, DEVICE_REGISTRY_BASENAME).is_ok()
}

fn validate_private_database_path(
    value: &str,
    expected_basename: &str,
) -> Result<PathBuf, BootstrapError> {
    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 1024
        || !value.is_ascii()
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_basename)
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(BootstrapError::Invalid);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o777 != 0o600 =>
        {
            return Err(BootstrapError::Invalid);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(BootstrapError::Invalid),
    }
    let parent = path.parent().ok_or(BootstrapError::Invalid)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| BootstrapError::Invalid)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
        || parent.canonicalize().map_err(|_| BootstrapError::Invalid)? != parent
    {
        return Err(BootstrapError::Invalid);
    }
    Ok(path.to_path_buf())
}

fn valid_remote_origins(
    admin: &str,
    host: &str,
    public_device: &str,
    allow_loopback_test_http: bool,
) -> bool {
    parse_origin(admin).is_some_and(|url| {
        url.host().is_some_and(literal_loopback)
            && (url.scheme() == "https" || url.scheme() == "http" && allow_loopback_test_http)
    }) && parse_origin(host).is_some_and(|url| {
        url.scheme() == "https"
            || url.scheme() == "http"
                && allow_loopback_test_http
                && url.host().is_some_and(literal_loopback)
    }) && parse_origin(public_device).is_some_and(|url| url.scheme() == "https")
}

fn parse_origin(value: &str) -> Option<Url> {
    if value.is_empty() || value.len() > 2048 || !value.is_ascii() {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || url.host().is_none()
    {
        return None;
    }
    let scheme_end = value.find("://")?.checked_add(3)?;
    let authority_end = value[scheme_end..]
        .find('/')
        .map_or(value.len(), |offset| scheme_end + offset);
    if authority_end < value.len() && &value[authority_end..] != "/" {
        return None;
    }
    Some(url)
}

fn literal_loopback(host: Host<&str>) -> bool {
    match host {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(_) => false,
    }
}

fn valid_socket_path(value: &str, run_id: &str, session_id: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && value.len() <= 100
        && value.is_ascii()
        && !value.contains(run_id)
        && !value.contains(session_id)
        && path.file_name().and_then(|name| name.to_str()) == Some("product-host.sock")
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn valid_loopback_origin(value: &str) -> bool {
    let Some(port) = value.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    port.parse::<u16>().is_ok_and(|port| port >= 1024)
}

pub fn receive_bootstrap(fd: RawFd) -> Result<(UnixStream, DecodedBootstrap), BootstrapError> {
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| BootstrapError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_BOOTSTRAP_BYTES {
        return Err(BootstrapError::Size);
    }
    let mut raw = Zeroizing::new(vec![0_u8; length]);
    stream
        .read_exact(&mut raw)
        .map_err(|_| BootstrapError::Io)?;
    let bootstrap = decode(&raw)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| BootstrapError::Io)?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).map_err(|_| BootstrapError::Io)? != 0 {
        return Err(BootstrapError::Invalid);
    }
    Ok((stream, bootstrap))
}

pub fn run_product_host(fd: RawFd) -> Result<(), BootstrapError> {
    run_product_host_with_admin_fd(fd, RELAY_ADMIN_BEARER_FD)
}

fn run_product_host_with_admin_fd(fd: RawFd, admin_bearer_fd: RawFd) -> Result<(), BootstrapError> {
    let (mut stream, decoded) = receive_bootstrap(fd)?;
    let (host, _remote_mailbox_worker) = match decoded.remote {
        None => {
            let (host, ready) =
                crate::product_stock_projector::ProductStockHost::start(decoded.host)
                    .map_err(|_| BootstrapError::Invalid)?;
            write_ready(&mut stream, &ready)?;
            (host, None)
        }
        Some(remote) => {
            let runtime = prepare_remote_runtime(&decoded.host, remote, admin_bearer_fd)?;
            let remote_lifecycle = crate::remote_command_ingress::RemoteIngressLifecycle::new();
            let dependencies = crate::product_stock_projector::RemoteProductHostDependencies {
                pairing: Arc::clone(&runtime.pairing),
                join_transport_key: runtime.join_transport_key,
                lifecycle: Arc::clone(&remote_lifecycle),
            };
            let (host, local_ready) =
                crate::product_stock_projector::ProductStockHost::start_with_pairing(
                    decoded.host,
                    Some(dependencies),
                )
                .map_err(|_| BootstrapError::Invalid)?;
            let command_authority = host
                .remote_command_authority()
                .ok_or(BootstrapError::Invalid)?;
            let ingress = crate::remote_command_ingress::RemoteCommandIngress::new(
                runtime.pairing,
                command_authority,
                runtime.mailbox_state,
                Arc::new(
                    crate::remote_command_ingress::HostRelayV2ClientFactory::new(
                        runtime.relay_host_base_url,
                        runtime.allow_loopback_test_http,
                    )
                    .map_err(|_| BootstrapError::Invalid)?,
                ),
                runtime.endpoint_keys.ok_or(BootstrapError::Invalid)?,
                Arc::new(crate::remote_command_ingress::SystemRemoteIngressClock),
                Arc::clone(&remote_lifecycle),
            );
            let (mailbox_worker, mailbox_worker_ready) =
                ingress.start().map_err(|_| BootstrapError::Invalid)?;
            await_remote_mailbox_ready(mailbox_worker_ready, REMOTE_MAILBOX_READY_TIMEOUT)?;
            let ready_permit = mailbox_worker
                .acquire_running_write_permit()
                .map_err(|_| BootstrapError::Invalid)?;
            write_remote_ready(&mut stream, remote_ready(local_ready)?)?;
            drop(ready_permit);
            (host, Some(mailbox_worker))
        }
    };
    drop(stream);
    let host_result = host.run().map_err(|_| BootstrapError::Io);
    let worker_result = match _remote_mailbox_worker {
        Some(worker) => worker
            .shutdown_and_join()
            .map_err(|_| BootstrapError::Invalid),
        None => Ok(()),
    };
    host_result.and(worker_result)
}

struct PreparedRemoteRuntime {
    pairing: Arc<crate::pairing_coordinator::PairingCoordinator>,
    join_transport_key: Zeroizing<[u8; 32]>,
    mailbox_state: crate::remote_mailbox::RemoteMailboxState,
    relay_host_base_url: String,
    allow_loopback_test_http: bool,
    endpoint_keys: Option<Arc<crate::remote_crypto::EndpointKeys>>,
}

fn prepare_remote_runtime(
    host: &HostBootstrap,
    remote: RemoteHostBootstrap,
    admin_bearer_fd: RawFd,
) -> Result<PreparedRemoteRuntime, BootstrapError> {
    use crate::host_device_identity::load_or_create_host_device_identity;

    let admin_bearer = consume_admin_bearer(admin_bearer_fd)?;
    let identity =
        Arc::new(load_or_create_host_device_identity().map_err(|_| BootstrapError::Invalid)?);
    let endpoint_keys = identity.endpoint_keys();
    build_remote_runtime_with_endpoint(host, remote, admin_bearer, identity, Some(endpoint_keys))
}

#[cfg(test)]
fn build_remote_runtime(
    host: &HostBootstrap,
    remote: RemoteHostBootstrap,
    admin_bearer: crate::relay_provisioning::RelayAdminBearer,
    identity: Arc<dyn crate::pairing_coordinator::HostPairingIdentity>,
) -> Result<PreparedRemoteRuntime, BootstrapError> {
    build_remote_runtime_with_endpoint(host, remote, admin_bearer, identity, None)
}

fn build_remote_runtime_with_endpoint(
    host: &HostBootstrap,
    remote: RemoteHostBootstrap,
    admin_bearer: crate::relay_provisioning::RelayAdminBearer,
    identity: Arc<dyn crate::pairing_coordinator::HostPairingIdentity>,
    endpoint_keys: Option<Arc<crate::remote_crypto::EndpointKeys>>,
) -> Result<PreparedRemoteRuntime, BootstrapError> {
    use crate::device_authority::DeviceAuthority;
    use crate::pairing_coordinator::{
        DeviceCommandGate, PairingCoordinator, SqliteJoinSessionStore,
    };
    use crate::relay_provisioning::UreqRelayProvisioner;
    use crate::remote_mailbox::RemoteMailboxState;

    let authority =
        DeviceAuthority::open(&host.device_registry_path).map_err(|_| BootstrapError::Invalid)?;
    let store = Arc::new(
        SqliteJoinSessionStore::open(&remote.pairing_store_path, identity.as_ref())
            .map_err(|_| BootstrapError::Invalid)?,
    );
    let relay_host_base_url = remote.relay_host_base_url.clone();
    let allow_loopback_test_http = remote.allow_loopback_test_http;
    let relay = Arc::new(
        UreqRelayProvisioner::new(
            &remote.relay_admin_base_url,
            &remote.relay_host_base_url,
            admin_bearer,
            remote.allow_loopback_test_http,
        )
        .map_err(|_| BootstrapError::Invalid)?,
    );
    let pairing = Arc::new(
        PairingCoordinator::new_with_startup_recovery(
            Arc::new(DeviceCommandGate::new()),
            authority,
            identity,
            relay,
            store,
            remote.relay_device_public_base_url,
            OffsetDateTime::now_utc(),
        )
        .map_err(|_| BootstrapError::Invalid)?,
    );
    let mailbox_state = RemoteMailboxState::open(&remote.remote_mailbox_state_path)
        .map_err(|_| BootstrapError::Invalid)?;
    Ok(PreparedRemoteRuntime {
        pairing,
        join_transport_key: remote.join_transport_key,
        mailbox_state,
        relay_host_base_url,
        allow_loopback_test_http,
        endpoint_keys,
    })
}

fn consume_admin_bearer(
    fd: RawFd,
) -> Result<crate::relay_provisioning::RelayAdminBearer, BootstrapError> {
    consume_admin_bearer_with_timeout(fd, ADMIN_BEARER_READ_TIMEOUT)
}

fn consume_admin_bearer_with_timeout(
    fd: RawFd,
    timeout: Duration,
) -> Result<crate::relay_provisioning::RelayAdminBearer, BootstrapError> {
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(BootstrapError::Invalid);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut file = File::from(owned);
    let metadata = file.metadata().map_err(|_| BootstrapError::Invalid)?;
    if !metadata.file_type().is_fifo() && !metadata.file_type().is_socket() {
        return Err(BootstrapError::Invalid);
    }
    let access_mode = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if access_mode < 0 || access_mode & libc::O_ACCMODE == libc::O_WRONLY {
        return Err(BootstrapError::Invalid);
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(BootstrapError::Invalid)?;
    let mut raw = Zeroizing::new(Vec::new());
    let mut buffer = [0_u8; 512];
    loop {
        wait_until_readable(file.as_raw_fd(), deadline)?;
        let count = file
            .read(&mut buffer)
            .map_err(|_| BootstrapError::Invalid)?;
        if count == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..count]);
        if raw.len() > MAX_ADMIN_BEARER_BYTES {
            return Err(BootstrapError::Invalid);
        }
    }
    if raw.len() < MIN_ADMIN_BEARER_BYTES
        || !raw.is_ascii()
        || raw
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || *byte == 0x7f)
    {
        return Err(BootstrapError::Invalid);
    }
    let (mut writer, reader) = UnixStream::pair().map_err(|_| BootstrapError::Invalid)?;
    writer
        .write_all(raw.as_slice())
        .map_err(|_| BootstrapError::Invalid)?;
    writer
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| BootstrapError::Invalid)?;
    drop(file);
    crate::relay_provisioning::RelayAdminBearer::from_fd(reader.into())
        .map_err(|_| BootstrapError::Invalid)
}

fn wait_until_readable(fd: RawFd, deadline: Instant) -> Result<(), BootstrapError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(BootstrapError::Invalid);
        }
        let remaining = deadline.saturating_duration_since(now);
        let timeout_ms = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0
            && descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0
            && descriptor.revents & libc::POLLNVAL == 0
        {
            return Ok(());
        }
        if result == 0 {
            return Err(BootstrapError::Invalid);
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(BootstrapError::Invalid);
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductHostReady {
    pub schema: &'static str,
    pub parent_dev: u64,
    pub parent_ino: u64,
    pub socket_dev: u64,
    pub socket_ino: u64,
    pub snapshot_seq: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteProductHostReady {
    pub schema: &'static str,
    pub parent_dev: u64,
    pub parent_ino: u64,
    pub socket_dev: u64,
    pub socket_ino: u64,
    pub snapshot_seq: u64,
    pub pairing_ready: bool,
    pub remote_mailbox_ready: bool,
}

fn remote_ready(ready: ProductHostReady) -> Result<RemoteProductHostReady, BootstrapError> {
    if ready.schema != "nomad.product-host.ready.v1" {
        return Err(BootstrapError::Invalid);
    }
    Ok(RemoteProductHostReady {
        schema: "nomad.product-host.ready.v2",
        parent_dev: ready.parent_dev,
        parent_ino: ready.parent_ino,
        socket_dev: ready.socket_dev,
        socket_ino: ready.socket_ino,
        snapshot_seq: ready.snapshot_seq,
        pairing_ready: true,
        remote_mailbox_ready: true,
    })
}

fn await_remote_mailbox_ready(
    ready: std::sync::mpsc::Receiver<()>,
    timeout: Duration,
) -> Result<(), BootstrapError> {
    ready
        .recv_timeout(timeout)
        .map_err(|_| BootstrapError::Invalid)
}

fn write_ready(stream: &mut UnixStream, ready: &ProductHostReady) -> Result<(), BootstrapError> {
    write_ready_value(stream, ready)
}

fn write_remote_ready(
    stream: &mut UnixStream,
    ready: RemoteProductHostReady,
) -> Result<(), BootstrapError> {
    write_ready_value(stream, &ready)
}

fn write_ready_value(
    stream: &mut UnixStream,
    ready: &impl Serialize,
) -> Result<(), BootstrapError> {
    let raw = serde_json::to_vec(ready).map_err(|_| BootstrapError::Invalid)?;
    if raw.is_empty() || raw.len() > MAX_READY_BYTES {
        return Err(BootstrapError::Size);
    }
    let length = u32::try_from(raw.len()).map_err(|_| BootstrapError::Size)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(&raw))
        .map_err(|_| BootstrapError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use p256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{mpsc, Arc};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    struct TestHostIdentity {
        signing: SigningKey,
        agreement: SecretKey,
    }

    impl TestHostIdentity {
        fn new() -> Self {
            Self {
                signing: SigningKey::from_bytes((&[41_u8; 32]).into()).unwrap(),
                agreement: SecretKey::from_slice(&[42_u8; 32]).unwrap(),
            }
        }
    }

    impl crate::pairing_coordinator::HostPairingIdentity for TestHostIdentity {
        fn signing_public_sec1(&self) -> [u8; 65] {
            self.signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        fn agreement_public_sec1(&self) -> [u8; 65] {
            self.agreement
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        }

        fn signing_commitment(&self) -> [u8; 32] {
            Sha256::digest(self.signing_public_sec1()).into()
        }

        fn agreement_commitment(&self) -> [u8; 32] {
            Sha256::digest(self.agreement_public_sec1()).into()
        }

        fn sign_p1363(
            &self,
            _message: &[u8],
        ) -> Result<[u8; 64], crate::pairing_coordinator::PairingCoordinatorError> {
            Ok([17_u8; 64])
        }

        fn derive_agreement_shared(
            &self,
            peer_public_sec1: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>, crate::pairing_coordinator::PairingCoordinatorError>
        {
            let digest = Sha256::digest(peer_public_sec1);
            Ok(Zeroizing::new(digest.into()))
        }
    }

    fn frame(raw: &[u8]) -> Vec<u8> {
        let mut out = (raw.len() as u32).to_be_bytes().to_vec();
        out.extend(raw);
        out
    }
    fn valid() -> (TempDir, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run_id = "a".repeat(64);
        let journal = directory
            .path()
            .canonicalize()
            .unwrap()
            .join(expected_journal_filename(&run_id));
        let raw = serde_json::json!({
            "schema": "nomad.product-host.bootstrap.v1",
            "run_id": run_id,
            "origin": "http://127.0.0.1:4096",
            "session_id": "ses_1",
            "server_password": "secret",
            "workspace_binding_digest": "b".repeat(64),
            "product_host_socket_path": "/private/tmp/nomad/run/product-host.sock",
            "agent_pid": 4242,
            "agent_process_group": 4242,
            "agent_process_identity": "c".repeat(64),
            "product_host_socket_parent_dev": 1,
            "product_host_socket_parent_ino": 2,
            "command_transport_key": STANDARD.encode([7_u8; 32]),
            "command_authority_key": STANDARD.encode([9_u8; 32]),
            "command_journal_path": journal,
            "device_registry_path": directory
                .path()
                .canonicalize()
                .unwrap()
                .join(DEVICE_REGISTRY_BASENAME),
        });
        (directory, frame(&serde_json::to_vec(&raw).unwrap()))
    }
    fn valid_value() -> (TempDir, serde_json::Value) {
        let (directory, bytes) = valid();
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        (
            directory,
            serde_json::from_slice(&bytes[4..4 + length]).unwrap(),
        )
    }
    fn valid_v2_value() -> (TempDir, serde_json::Value) {
        let (directory, mut value) = valid_value();
        let run_directory = directory.path().join("run");
        let persistent_directory = directory.path().join("persistent");
        fs::create_dir(&run_directory).unwrap();
        fs::create_dir(&persistent_directory).unwrap();
        fs::set_permissions(&run_directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&persistent_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let run_id = value["run_id"].as_str().unwrap().to_owned();
        value["schema"] = "nomad.product-host.bootstrap.v2".into();
        value["command_journal_path"] = run_directory
            .canonicalize()
            .unwrap()
            .join(expected_journal_filename(&run_id))
            .to_string_lossy()
            .into_owned()
            .into();
        value["device_registry_path"] = persistent_directory
            .canonicalize()
            .unwrap()
            .join(DEVICE_REGISTRY_BASENAME)
            .to_string_lossy()
            .into_owned()
            .into();
        value["join_transport_key"] = STANDARD.encode([8_u8; 32]).into();
        value["remote"] = serde_json::json!({
            "schema": REMOTE_BOOTSTRAP_SCHEMA,
            "relay_admin_base_url": "http://127.0.0.1:4201",
            "relay_host_base_url": "http://[::1]:4202",
            "relay_device_public_base_url": "https://pair.example",
            "allow_loopback_test_http": true,
            "pairing_store_path": persistent_directory
                .canonicalize().unwrap().join(PAIRING_STORE_BASENAME),
            "remote_mailbox_state_path": persistent_directory
                .canonicalize().unwrap().join(REMOTE_MAILBOX_STATE_BASENAME),
        });
        (directory, value)
    }
    fn receive(bytes: &[u8]) -> Result<DecodedBootstrap, BootstrapError> {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent.write_all(bytes).unwrap();
        parent.shutdown(std::net::Shutdown::Write).unwrap();
        let result = receive_bootstrap(child.into_raw_fd()).map(|(_, value)| value);
        let mut ack = Vec::new();
        let _ = parent.read_to_end(&mut ack);
        result
    }
    #[test]
    fn accepts_exact_frame() {
        let (_directory, bytes) = valid();
        let bootstrap = receive(&bytes).unwrap().host;
        assert_eq!(bootstrap.session_id, "ses_1");
        assert_eq!(bootstrap.command_transport_key.as_ref(), &[7_u8; 32]);
        assert_eq!(bootstrap.command_authority_key.as_ref(), &[9_u8; 32]);
        assert!(!bootstrap.command_journal_path.exists());
        assert_eq!(
            bootstrap
                .device_registry_path
                .file_name()
                .and_then(|name| name.to_str()),
            Some(DEVICE_REGISTRY_BASENAME)
        );
    }

    #[test]
    fn accepts_exact_v2_and_keeps_remote_values_out_of_v1_host() {
        let (_directory, value) = valid_v2_value();
        let decoded = receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap();
        assert_eq!(decoded.host.command_transport_key.as_ref(), &[7_u8; 32]);
        assert_eq!(decoded.host.command_authority_key.as_ref(), &[9_u8; 32]);
        let remote = decoded.remote.unwrap();
        assert_eq!(remote.join_transport_key.as_ref(), &[8_u8; 32]);
        assert_eq!(remote.relay_admin_base_url, "http://127.0.0.1:4201");
        assert_eq!(remote.relay_host_base_url, "http://[::1]:4202");
        assert_eq!(remote.relay_device_public_base_url, "https://pair.example");
        assert!(remote.allow_loopback_test_http);
    }

    #[test]
    fn v1_rejects_each_v2_only_key() {
        for key in ["join_transport_key", "remote"] {
            let (_directory, mut value) = valid_value();
            value[key] = if key == "remote" {
                serde_json::json!({})
            } else {
                STANDARD.encode([8_u8; 32]).into()
            };
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid
            );
        }
    }

    #[test]
    fn v2_rejects_every_missing_or_unknown_key() {
        let top_level = [
            "schema",
            "run_id",
            "origin",
            "session_id",
            "server_password",
            "workspace_binding_digest",
            "product_host_socket_path",
            "agent_pid",
            "agent_process_group",
            "agent_process_identity",
            "product_host_socket_parent_dev",
            "product_host_socket_parent_ino",
            "command_transport_key",
            "join_transport_key",
            "command_authority_key",
            "command_journal_path",
            "device_registry_path",
            "remote",
        ];
        for key in top_level {
            let (_directory, mut value) = valid_v2_value();
            value.as_object_mut().unwrap().remove(key);
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid,
                "accepted missing top-level key {key}"
            );
        }
        let remote_keys = [
            "schema",
            "relay_admin_base_url",
            "relay_host_base_url",
            "relay_device_public_base_url",
            "allow_loopback_test_http",
            "pairing_store_path",
            "remote_mailbox_state_path",
        ];
        for key in remote_keys {
            let (_directory, mut value) = valid_v2_value();
            value["remote"].as_object_mut().unwrap().remove(key);
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid,
                "accepted missing remote key {key}"
            );
        }
        for target in ["top", "remote"] {
            let (_directory, mut value) = valid_v2_value();
            if target == "top" {
                value["extra"] = true.into();
            } else {
                value["remote"]["extra"] = true.into();
            }
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid
            );
        }
    }

    #[test]
    fn v2_rejects_duplicate_top_level_and_remote_keys() {
        let top_level = [
            "schema",
            "run_id",
            "origin",
            "session_id",
            "server_password",
            "workspace_binding_digest",
            "product_host_socket_path",
            "agent_pid",
            "agent_process_group",
            "agent_process_identity",
            "product_host_socket_parent_dev",
            "product_host_socket_parent_ino",
            "command_transport_key",
            "join_transport_key",
            "command_authority_key",
            "command_journal_path",
            "device_registry_path",
            "remote",
        ];
        for key in top_level {
            let (_directory, value) = valid_v2_value();
            let raw = duplicate_json_field(&value, key, &value[key]);
            assert_eq!(
                receive(&frame(raw.as_bytes())).unwrap_err(),
                BootstrapError::Invalid,
                "accepted duplicate top-level key {key}"
            );
        }
        let remote_keys = [
            "schema",
            "relay_admin_base_url",
            "relay_host_base_url",
            "relay_device_public_base_url",
            "allow_loopback_test_http",
            "pairing_store_path",
            "remote_mailbox_state_path",
        ];
        for key in remote_keys {
            let (_directory, value) = valid_v2_value();
            let raw = duplicate_json_field(&value, key, &value["remote"][key]);
            assert_eq!(
                receive(&frame(raw.as_bytes())).unwrap_err(),
                BootstrapError::Invalid,
                "accepted duplicate remote key {key}"
            );
        }
    }

    fn duplicate_json_field(
        value: &serde_json::Value,
        key: &str,
        field: &serde_json::Value,
    ) -> String {
        let raw = serde_json::to_string(value).unwrap();
        let needle = format!("{key:?}:{}", serde_json::to_string(field).unwrap());
        assert_eq!(raw.matches(&needle).count(), 1);
        raw.replacen(&needle, &format!("{needle},{needle}"), 1)
    }
    #[test]
    fn rejects_partial() {
        assert!(matches!(
            receive(&[0, 0, 0, 9, b'{']),
            Err(BootstrapError::Io)
        ));
    }
    #[test]
    fn rejects_oversize() {
        assert!(matches!(
            receive(&(MAX_BOOTSTRAP_BYTES as u32 + 1).to_be_bytes()),
            Err(BootstrapError::Size)
        ));
    }
    #[test]
    fn rejects_trailing_json() {
        let raw = br#"{"schema":"x"} {}"#;
        assert!(matches!(receive(&frame(raw)), Err(BootstrapError::Invalid)));
    }
    #[test]
    fn rejects_byte_after_declared_frame() {
        let (_directory, mut bytes) = valid();
        bytes.push(b'x');
        assert!(matches!(receive(&bytes), Err(BootstrapError::Invalid)));
    }

    #[test]
    fn rejects_noncanonical_wrong_length_equal_or_malformed_keys() {
        for (transport, authority) in [
            (STANDARD.encode([1_u8; 31]), STANDARD.encode([2_u8; 32])),
            (STANDARD.encode([1_u8; 32]), STANDARD.encode([1_u8; 32])),
            ("not-base64".into(), STANDARD.encode([2_u8; 32])),
        ] {
            let (_directory, bytes) = valid();
            let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            let mut value: serde_json::Value =
                serde_json::from_slice(&bytes[4..4 + length]).unwrap();
            value["command_transport_key"] = transport.into();
            value["command_authority_key"] = authority.into();
            assert!(matches!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())),
                Err(BootstrapError::Invalid)
            ));
        }
    }

    #[test]
    fn v2_requires_three_canonical_pairwise_distinct_keys() {
        for (command, join, authority) in [
            ([1_u8; 32], [1_u8; 32], [3_u8; 32]),
            ([1_u8; 32], [2_u8; 32], [1_u8; 32]),
            ([1_u8; 32], [2_u8; 32], [2_u8; 32]),
        ] {
            let (_directory, mut value) = valid_v2_value();
            value["command_transport_key"] = STANDARD.encode(command).into();
            value["join_transport_key"] = STANDARD.encode(join).into();
            value["command_authority_key"] = STANDARD.encode(authority).into();
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid
            );
        }
        for key in [
            "command_transport_key",
            "join_transport_key",
            "command_authority_key",
        ] {
            for invalid in [STANDARD.encode([1_u8; 31]), "not-base64".into()] {
                let (_directory, mut value) = valid_v2_value();
                value[key] = invalid.into();
                assert_eq!(
                    receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                    BootstrapError::Invalid
                );
            }
        }
    }

    #[test]
    fn v2_rejects_non_origin_or_unsafe_transport_urls() {
        let cases = [
            ("relay_admin_base_url", "https://user@127.0.0.1:4201"),
            ("relay_admin_base_url", "https://127.0.0.1:4201/v2"),
            ("relay_admin_base_url", "https://127.0.0.1:4201?x=1"),
            ("relay_admin_base_url", "https://127.0.0.1:4201#x"),
            ("relay_admin_base_url", "https://localhost:4201"),
            ("relay_host_base_url", "http://relay.example:4202"),
            ("relay_host_base_url", "https://relay.example/v2"),
            ("relay_device_public_base_url", "http://127.0.0.1:4203"),
            ("relay_device_public_base_url", "https://pair.example/v2"),
        ];
        for (key, invalid) in cases {
            let (_directory, mut value) = valid_v2_value();
            value["remote"][key] = invalid.into();
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid,
                "accepted {key}={invalid}"
            );
        }
        let (_directory, mut value) = valid_v2_value();
        value["remote"]["allow_loopback_test_http"] = false.into();
        assert_eq!(
            receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
            BootstrapError::Invalid
        );
    }

    #[test]
    fn v2_requires_three_private_database_paths_in_one_directory() {
        for case in [
            "wrong-basename",
            "other-parent",
            "public-parent",
            "symlink",
            "hardlink",
        ] {
            let (directory, mut value) = valid_v2_value();
            let persistent = PathBuf::from(value["device_registry_path"].as_str().unwrap())
                .parent()
                .unwrap()
                .to_path_buf();
            let pairing = PathBuf::from(value["remote"]["pairing_store_path"].as_str().unwrap());
            match case {
                "wrong-basename" => {
                    value["remote"]["pairing_store_path"] = persistent
                        .join("other.sqlite3")
                        .to_string_lossy()
                        .into_owned()
                        .into();
                }
                "other-parent" => {
                    let other = directory.path().join("other");
                    fs::create_dir(&other).unwrap();
                    fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
                    value["remote"]["pairing_store_path"] = other
                        .canonicalize()
                        .unwrap()
                        .join(PAIRING_STORE_BASENAME)
                        .to_string_lossy()
                        .into_owned()
                        .into();
                }
                "public-parent" => {
                    fs::set_permissions(&persistent, fs::Permissions::from_mode(0o755)).unwrap();
                }
                "symlink" => {
                    let target = persistent.join("target.sqlite3");
                    fs::write(&target, b"x").unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
                    symlink(&target, &pairing).unwrap();
                }
                "hardlink" => {
                    let target = persistent.join("target.sqlite3");
                    fs::write(&target, b"x").unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::hard_link(&target, &pairing).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap_err(),
                BootstrapError::Invalid,
                "accepted unsafe path case {case}"
            );
        }
    }

    fn consume_from_socket(raw: &[u8]) -> Result<(), BootstrapError> {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.write_all(raw).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let reader_fd = reader.into_raw_fd();
        let high_fd = unsafe { libc::fcntl(reader_fd, libc::F_DUPFD_CLOEXEC, 512) };
        assert!(high_fd >= 512);
        unsafe { libc::close(reader_fd) };
        let before = fd_identity(high_fd).unwrap();
        let result =
            consume_admin_bearer_with_timeout(high_fd, Duration::from_millis(100)).map(drop);
        assert_ne!(fd_identity(high_fd), Some(before));
        result
    }

    #[test]
    fn fd11_accepts_exact_ascii_token_and_closes_the_adopted_fd() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.write_all(&[b'a'; MIN_ADMIN_BEARER_BYTES]).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let reader_fd = reader.into_raw_fd();
        let raw_fd = unsafe { libc::fcntl(reader_fd, libc::F_DUPFD_CLOEXEC, 512) };
        assert!(raw_fd >= 512);
        unsafe { libc::close(reader_fd) };
        let before = fd_identity(raw_fd).unwrap();
        let bearer = consume_admin_bearer_with_timeout(raw_fd, Duration::from_millis(100)).unwrap();
        assert_ne!(fd_identity(raw_fd), Some(before));
        let debug = format!("{bearer:?}");
        assert!(!debug.contains(&"a".repeat(MIN_ADMIN_BEARER_BYTES)));
    }

    fn fd_identity(fd: RawFd) -> Option<(u64, u64, libc::mode_t)> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return None;
        }
        let stat = unsafe { stat.assume_init() };
        Some((stat.st_dev as u64, stat.st_ino, stat.st_mode))
    }

    #[test]
    fn fd11_rejects_missing_short_overlong_non_ascii_whitespace_and_non_eof() {
        let missing = unsafe { libc::dup(-1) };
        assert_eq!(
            consume_admin_bearer_with_timeout(missing, Duration::from_millis(10)).unwrap_err(),
            BootstrapError::Invalid
        );
        for invalid in [
            vec![b'a'; MIN_ADMIN_BEARER_BYTES - 1],
            vec![b'a'; MAX_ADMIN_BEARER_BYTES + 1],
            [vec![b'a'; MIN_ADMIN_BEARER_BYTES], vec![0xff]].concat(),
            [vec![b'a'; MIN_ADMIN_BEARER_BYTES], vec![b' ']].concat(),
            [vec![b'a'; MIN_ADMIN_BEARER_BYTES], vec![b'\n']].concat(),
        ] {
            assert_eq!(
                consume_from_socket(&invalid).unwrap_err(),
                BootstrapError::Invalid
            );
        }
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer.write_all(&[b'a'; MIN_ADMIN_BEARER_BYTES]).unwrap();
        let reader_fd = reader.into_raw_fd();
        let high_fd = unsafe { libc::fcntl(reader_fd, libc::F_DUPFD_CLOEXEC, 512) };
        assert!(high_fd >= 512);
        unsafe { libc::close(reader_fd) };
        let before = fd_identity(high_fd).unwrap();
        assert_eq!(
            consume_admin_bearer_with_timeout(high_fd, Duration::from_millis(10)).unwrap_err(),
            BootstrapError::Invalid
        );
        assert_ne!(fd_identity(high_fd), Some(before));
    }

    #[test]
    fn fd11_rejects_regular_file_and_write_only_pipe_and_closes_each_fd() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin-token");
        fs::write(&path, [b'a'; MIN_ADMIN_BEARER_BYTES]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let fd = File::open(&path).unwrap().into_raw_fd();
        assert_eq!(
            consume_admin_bearer_with_timeout(fd, Duration::from_millis(10)).unwrap_err(),
            BootstrapError::Invalid
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);

        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let read_end = pipe_fds[0];
        let write_end = pipe_fds[1];
        assert_eq!(
            consume_admin_bearer_with_timeout(write_end, Duration::from_millis(10)).unwrap_err(),
            BootstrapError::Invalid
        );
        assert_eq!(unsafe { libc::fcntl(write_end, libc::F_GETFD) }, -1);
        unsafe { libc::close(read_end) };
    }

    #[test]
    fn missing_fd11_fails_before_persistent_state_or_socket_publication() {
        let (_directory, value) = valid_v2_value();
        let decoded = receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap();
        let remote = decoded.remote.unwrap();
        let pairing_path = remote.pairing_store_path.clone();
        let mailbox_path = remote.remote_mailbox_state_path.clone();
        let registry_path = decoded.host.device_registry_path.clone();
        let socket_path = decoded.host.product_host_socket_path.clone();
        assert!(matches!(
            prepare_remote_runtime(&decoded.host, remote, -1),
            Err(BootstrapError::Invalid)
        ));
        assert!(!pairing_path.exists());
        assert!(!mailbox_path.exists());
        assert!(!registry_path.exists());
        assert!(!socket_path.exists());
    }

    #[test]
    fn v2_missing_fd11_emits_no_ready_frame_and_leaves_no_artifacts() {
        let (_directory, value) = valid_v2_value();
        let pairing_path = PathBuf::from(value["remote"]["pairing_store_path"].as_str().unwrap());
        let mailbox_path = PathBuf::from(
            value["remote"]["remote_mailbox_state_path"]
                .as_str()
                .unwrap(),
        );
        let registry_path = PathBuf::from(value["device_registry_path"].as_str().unwrap());
        let socket_path = PathBuf::from(value["product_host_socket_path"].as_str().unwrap());
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .write_all(&frame(&serde_json::to_vec(&value).unwrap()))
            .unwrap();
        parent.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            run_product_host_with_admin_fd(child.into_raw_fd(), -1).unwrap_err(),
            BootstrapError::Invalid
        );
        let mut response = Vec::new();
        parent.read_to_end(&mut response).unwrap();
        assert!(response.is_empty());
        for path in [pairing_path, mailbox_path, registry_path, socket_path] {
            assert!(!path.exists());
        }
    }

    fn admin_bearer_for_test() -> crate::relay_provisioning::RelayAdminBearer {
        crate::relay_provisioning::RelayAdminBearer::from_memory(Zeroizing::new(
            "a".repeat(MIN_ADMIN_BEARER_BYTES),
        ))
        .unwrap()
    }

    #[test]
    fn remote_constructor_opens_all_durable_state_before_host_start() {
        let (_directory, value) = valid_v2_value();
        let decoded = receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap();
        let remote = decoded.remote.unwrap();
        let pairing_store_path = remote.pairing_store_path.clone();
        let mailbox_path = remote.remote_mailbox_state_path.clone();
        let registry_path = decoded.host.device_registry_path.clone();
        let runtime = build_remote_runtime(
            &decoded.host,
            remote,
            admin_bearer_for_test(),
            Arc::new(TestHostIdentity::new()),
        )
        .unwrap();
        for path in [registry_path, pairing_store_path, mailbox_path] {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_eq!(runtime.join_transport_key.as_ref(), &[8_u8; 32]);
    }

    #[test]
    fn corrupt_encrypted_coordinator_store_fails_before_mailbox_creation() {
        let (_directory, value) = valid_v2_value();
        let first = receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap();
        let pairing_path = first.remote.as_ref().unwrap().pairing_store_path.clone();
        let mailbox_path = first
            .remote
            .as_ref()
            .unwrap()
            .remote_mailbox_state_path
            .clone();
        drop(
            build_remote_runtime(
                &first.host,
                first.remote.unwrap(),
                admin_bearer_for_test(),
                Arc::new(TestHostIdentity::new()),
            )
            .unwrap(),
        );
        fs::remove_file(&mailbox_path).unwrap();
        let connection = rusqlite::Connection::open(&pairing_path).unwrap();
        connection
            .execute(
                "INSERT INTO pairing_coordinator_state (singleton, version, payload) \
                 VALUES (1, 'nomad.m3e.pairing-store.v1', ?1)",
                rusqlite::params![vec![0_u8; 48]],
            )
            .unwrap();
        drop(connection);

        let second = receive(&frame(&serde_json::to_vec(&value).unwrap())).unwrap();
        assert!(build_remote_runtime(
            &second.host,
            second.remote.unwrap(),
            admin_bearer_for_test(),
            Arc::new(TestHostIdentity::new()),
        )
        .is_err());
        assert!(!mailbox_path.exists());
    }

    #[test]
    fn disconnected_mailbox_worker_fails_external_ready_fast_without_socket_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("product-host.sock");
        let (ready_tx, ready_rx) = mpsc::channel();
        drop(ready_tx);
        let started = Instant::now();

        assert_eq!(
            await_remote_mailbox_ready(ready_rx, Duration::from_secs(1)),
            Err(BootstrapError::Invalid)
        );
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(!socket.exists());
    }

    #[test]
    fn rejects_existing_or_unsafe_or_cross_run_journal_path() {
        for case in ["existing", "mode", "cross-run"] {
            let (directory, bytes) = valid();
            let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            let mut value: serde_json::Value =
                serde_json::from_slice(&bytes[4..4 + length]).unwrap();
            let path = PathBuf::from(value["command_journal_path"].as_str().unwrap());
            match case {
                "existing" => fs::write(&path, b"occupied").unwrap(),
                "mode" => fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
                    .unwrap(),
                "cross-run" => {
                    value["command_journal_path"] = directory
                        .path()
                        .canonicalize()
                        .unwrap()
                        .join(expected_journal_filename(&"d".repeat(64)))
                        .to_string_lossy()
                        .into_owned()
                        .into();
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                receive(&frame(&serde_json::to_vec(&value).unwrap())),
                Err(BootstrapError::Invalid)
            ));
        }
    }

    #[test]
    fn rejects_missing_or_non_fixed_basename_device_registry_path() {
        let (_directory, bytes) = valid();
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes[4..4 + length]).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("device_registry_path");
        assert!(matches!(
            receive(&frame(&serde_json::to_vec(&value).unwrap())),
            Err(BootstrapError::Invalid)
        ));

        let (directory, bytes) = valid();
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes[4..4 + length]).unwrap();
        value["device_registry_path"] = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("other.sqlite3")
            .to_string_lossy()
            .into_owned()
            .into();
        assert!(matches!(
            receive(&frame(&serde_json::to_vec(&value).unwrap())),
            Err(BootstrapError::Invalid)
        ));
    }
    #[test]
    fn rejects_invalid_utf8() {
        assert!(matches!(
            receive(&frame(&[0xff])),
            Err(BootstrapError::Invalid)
        ));
    }
    #[test]
    fn rejects_excessive_depth() {
        let raw = format!("{}0{}", "[".repeat(130), "]".repeat(130));
        assert!(matches!(
            receive(&frame(raw.as_bytes())),
            Err(BootstrapError::Invalid)
        ));
    }
    #[test]
    fn rejects_duplicate() {
        let raw = br#"{"schema":"x","schema":"x"}"#;
        assert!(matches!(receive(&frame(raw)), Err(BootstrapError::Invalid)));
    }
    #[test]
    fn rejects_unknown() {
        let raw = br#"{"schema":"x","extra":1}"#;
        assert!(matches!(receive(&frame(raw)), Err(BootstrapError::Invalid)));
    }
    #[test]
    fn rejects_noncanonical_or_identity_bearing_socket_path() {
        for value in [
            "run/product-host.sock",
            "/private/tmp/nomad/run/../product-host.sock",
            "/private/tmp/nomad/run/other.sock",
            "/private/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/product-host.sock",
            "/private/tmp/ses_1/product-host.sock",
        ] {
            let (_directory, mut raw) = valid_value();
            raw["product_host_socket_path"] = value.into();
            assert!(matches!(
                receive(&frame(&serde_json::to_vec(&raw).unwrap())),
                Err(BootstrapError::Invalid)
            ));
        }
    }

    #[test]
    fn rejects_invalid_agent_process_binding() {
        for (pid, process_group, identity, parent_dev, parent_ino) in [
            (1, 1, "c".repeat(64), 1, 2),
            (4242, 4242, "C".repeat(64), 1, 2),
            (4242, 4243, "c".repeat(64), 1, 2),
            (4242, 4242, "c".repeat(64), 0, 2),
            (4242, 4242, "c".repeat(64), 1, 0),
        ] {
            let (_directory, mut raw) = valid_value();
            raw["agent_pid"] = pid.into();
            raw["agent_process_group"] = process_group.into();
            raw["agent_process_identity"] = identity.into();
            raw["product_host_socket_parent_dev"] = parent_dev.into();
            raw["product_host_socket_parent_ino"] = parent_ino.into();
            assert!(matches!(
                receive(&frame(&serde_json::to_vec(&raw).unwrap())),
                Err(BootstrapError::Invalid)
            ));
        }
    }

    #[test]
    fn ready_v1_is_length_prefixed_exact_json() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let ready = ProductHostReady {
            schema: "nomad.product-host.ready.v1",
            parent_dev: 11,
            parent_ino: 12,
            socket_dev: 21,
            socket_ino: 22,
            snapshot_seq: 1,
        };
        write_ready(&mut writer, &ready).unwrap();
        drop(writer);
        let mut length = [0_u8; 4];
        reader.read_exact(&mut length).unwrap();
        let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "{\"schema\":\"nomad.product-host.ready.v1\",\"parent_dev\":11,\"parent_ino\":12,\"socket_dev\":21,\"socket_ino\":22,\"snapshot_seq\":1}"
        );
        let mut trailing = [0_u8; 1];
        assert_eq!(reader.read(&mut trailing).unwrap(), 0);
    }

    #[test]
    fn ready_v2_is_length_prefixed_exact_json_only_after_remote_barrier() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let ready = remote_ready(ProductHostReady {
            schema: "nomad.product-host.ready.v1",
            parent_dev: 11,
            parent_ino: 12,
            socket_dev: 21,
            socket_ino: 22,
            snapshot_seq: 1,
        })
        .unwrap();
        write_remote_ready(&mut writer, ready).unwrap();
        drop(writer);
        let mut length = [0_u8; 4];
        reader.read_exact(&mut length).unwrap();
        let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "{\"schema\":\"nomad.product-host.ready.v2\",\"parent_dev\":11,\"parent_ino\":12,\"socket_dev\":21,\"socket_ino\":22,\"snapshot_seq\":1,\"pairing_ready\":true,\"remote_mailbox_ready\":true}"
        );
        let mut trailing = [0_u8; 1];
        assert_eq!(reader.read(&mut trailing).unwrap(), 0);
    }
}
