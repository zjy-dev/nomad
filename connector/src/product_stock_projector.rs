//! Product Host stock-session projector and private UDS read API.
//!
//! The Host is the only owner of `snapshot_seq`. Upstream reads form a fenced,
//! complete stable-observation window; a rejected route leaves the last-good
//! snapshot untouched. The official routes expose no common revision, so this
//! is deliberately not described as a transactional instant.

use crate::adapters::opencode::{
    OpenCodeCommand, OpenCodeCommandCapability, OpenCodeCommandDispatcher, OpenCodeCommandFacts,
    OpenCodeCommandFactsBinding, OpenCodeDispatchOutcome, OpenCodeFiveRouteBatch,
};
use crate::alpha_projector::canonical_json;
use crate::device_authority::{
    AuthenticatedDeviceFact, CurrentActiveDevice, DeviceAuthority, DeviceAuthorityError,
    RevokeOutcome,
};
use crate::error::ConnectorError;
use crate::host_command_authority::{
    AdapterOutcome, AgentCommandAdapter, AuthenticatedDeviceSession, AuthorizedHostCommand,
    CurrentCommandState, CurrentPermission, HostCommandReceipt, OwnedHostCommandAuthority,
    TrustedCommandState,
};
use crate::host_device_identity::HostDeviceIdentity;
use crate::journal::CommandJournal;
use crate::pairing_coordinator::{
    AbortJoinRequest, ActiveRemoteBinding, CancelJoinRequest, DeviceCommandGate,
    DeviceCommandGuard, HostPairingIdentity, PairingCoordinator, PairingCoordinatorError,
    PairingStatusRequest,
};
use crate::product_command_protocol::{
    map_connector_error, read_product_request, write_capability, write_device_current,
    write_no_content, write_pairing_challenge, write_pairing_completed, write_pairing_confirm,
    write_pairing_confirmed, write_pairing_created, write_pairing_error, write_pairing_started,
    write_pairing_status, write_protocol_error, write_receipt, write_revoke, CommandProtocolError,
    CommandTransportAuthenticator, ParsedDeviceRevokeRequest, ParsedPairingChallengeRequest,
    ParsedPairingConfirmRequest, ParsedProductCommand, ProductHostRequest,
};
use crate::product_host_bootstrap::{HostBootstrap, ProductHostReady};
use crate::remote_application::{
    CommandCapability as RemoteCommandCapability, CommandReceipt as RemoteCommandReceipt,
    DenyCapability as RemoteDenyCapability, PendingQuestionSummary as RemotePendingQuestionSummary,
    ProjectionPayload, ReceiptAction as RemoteReceiptAction,
    ReceiptErrorCode as RemoteReceiptErrorCode, ReceiptStatus as RemoteReceiptStatus,
    ReplyCapability as RemoteReplyCapability, StopCapability as RemoteStopCapability,
};
use crate::remote_command_ingress::{
    ProductRemoteCommandAuthority as RemoteCommandAuthorityContract, RemoteAdmissionCoordinator,
    RemoteAuthorityFailure, RemoteCommandDisposition, RemoteIngressLifecycle,
    RemoteIngressLifecycleSnapshot, RemoteIngressStatus, RemoteWritePermit,
};
use crate::stock_snapshot::{
    project_stock_snapshot, stock_session_directory, StockReadonlySnapshot,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use getrandom::getrandom;
use serde::Serialize;
use serde_json::json;
#[cfg(test)]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

const SNAPSHOT_SCHEMA: &str = "nomad.product-host.snapshot.v1";
const ERROR_SCHEMA: &str = "nomad.product-host.error.v1";
const CURRENT_ROUTE: &str = "/internal/session/current";
const STREAM_ROUTE: &str = "/internal/session/stream?after_snapshot_seq=";
const MAX_UPSTREAM_BODY: u64 = 4 * 1024 * 1024;
const MAX_REQUEST_HEAD: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const SOURCE_HEALTH_LEASE: Duration = Duration::from_secs(60);
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(25);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(27);
const MAX_CLIENTS: usize = 16;
const MAX_SAFE_SNAPSHOT_SEQ: u64 = 9_007_199_254_740_991;
const PROCESS_IDENTITY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PROCESS_IDENTITY_BYTES: usize = 4 * 1024;
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(60);
const ALIAS_NAMESPACE: &[u8] = b"nomad.product.alias.v1\0";
const LOCAL_RUN_PRINCIPAL_ALIAS: &str = "local-run-gateway";
const LOCAL_RUN_DEVICE_ALIAS: &str = "local-gateway-device";
const REMOTE_PAIRED_PRINCIPAL_ALIAS: &str = "remote-paired-device";
const REMOTE_REGISTRY_PRINCIPAL_ALIAS: &str =
    "principal-c013cb434103a3b3206ccfa30788602d3865b70019ddbec32e461207eb430554";

impl HostPairingIdentity for HostDeviceIdentity {
    fn signing_public_sec1(&self) -> [u8; 65] {
        HostDeviceIdentity::signing_public_sec1(self)
    }

    fn agreement_public_sec1(&self) -> [u8; 65] {
        HostDeviceIdentity::agreement_public_sec1(self)
    }

    fn signing_commitment(&self) -> [u8; 32] {
        HostDeviceIdentity::signing_commitment(self)
    }

    fn agreement_commitment(&self) -> [u8; 32] {
        HostDeviceIdentity::agreement_commitment(self)
    }

    fn sign_p1363(&self, message: &[u8]) -> Result<[u8; 64], PairingCoordinatorError> {
        HostDeviceIdentity::sign_p1363(self, message).map_err(|_| PairingCoordinatorError::Crypto)
    }

    fn derive_agreement_shared(
        &self,
        peer_public_sec1: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PairingCoordinatorError> {
        HostDeviceIdentity::derive_agreement_shared(self, peer_public_sec1)
            .map_err(|_| PairingCoordinatorError::Crypto)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductSnapshotEnvelope {
    pub schema: &'static str,
    pub host_instance_id: String,
    pub snapshot_seq: u64,
    pub digest: String,
    pub snapshot: StockReadonlySnapshot,
}

impl std::fmt::Debug for ProductSnapshotEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductSnapshotEnvelope")
            .field("schema", &self.schema)
            .field("host_instance_id", &self.host_instance_id)
            .field("snapshot_seq", &self.snapshot_seq)
            .field("digest", &self.digest)
            .field("snapshot", &"<content-safe-stock-projection>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProductHostError;

impl std::fmt::Debug for ProductHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductHostError(<redacted>)")
    }
}

impl std::fmt::Display for ProductHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PRODUCT_HOST_FAILED")
    }
}

impl std::error::Error for ProductHostError {}

struct StoreState {
    current: Option<ProductSnapshotEnvelope>,
    lease_started: Instant,
    last_success: Option<Instant>,
}

struct ProductSnapshotStore {
    host_instance_id: String,
    state: Mutex<StoreState>,
    changed: Condvar,
}

enum WaitResult {
    Snapshot(Box<ProductSnapshotEnvelope>),
    Timeout,
    Conflict,
    Offline,
}

enum WaitDecision {
    Snapshot(Box<ProductSnapshotEnvelope>),
    Pending,
    Conflict,
    Offline,
}

impl ProductSnapshotStore {
    fn new() -> Result<Self, ProductHostError> {
        let mut random = [0_u8; 16];
        getrandom(&mut random).map_err(|_| ProductHostError)?;
        let host_instance_id = format!("host-{}", lower_hex(&random));
        random.zeroize();
        Ok(Self {
            host_instance_id,
            state: Mutex::new(StoreState {
                current: None,
                lease_started: Instant::now(),
                last_success: None,
            }),
            changed: Condvar::new(),
        })
    }

    #[cfg(test)]
    fn with_host_instance_id(host_instance_id: &str) -> Self {
        Self {
            host_instance_id: host_instance_id.into(),
            state: Mutex::new(StoreState {
                current: None,
                lease_started: Instant::now(),
                last_success: None,
            }),
            changed: Condvar::new(),
        }
    }

    fn commit(&self, snapshot: StockReadonlySnapshot) -> Result<bool, ProductHostError> {
        self.commit_at(snapshot, Instant::now())
    }

    fn commit_at(
        &self,
        snapshot: StockReadonlySnapshot,
        now: Instant,
    ) -> Result<bool, ProductHostError> {
        let mut state = self.state.lock().map_err(|_| ProductHostError)?;
        if state
            .current
            .as_ref()
            .is_some_and(|current| current.snapshot == snapshot)
        {
            state.last_success = Some(now);
            self.changed.notify_all();
            return Ok(false);
        }
        let snapshot_seq = match state.current.as_ref() {
            None => 1,
            Some(current) => current
                .snapshot_seq
                .checked_add(1)
                .filter(|value| *value <= MAX_SAFE_SNAPSHOT_SEQ)
                .ok_or(ProductHostError)?,
        };
        let next = build_envelope(&self.host_instance_id, snapshot_seq, snapshot)?;
        state.current = Some(next);
        state.last_success = Some(now);
        self.changed.notify_all();
        Ok(true)
    }

    #[cfg(test)]
    fn source_available_at(&self, now: Instant) -> Result<bool, ProductHostError> {
        self.state
            .lock()
            .map(|state| source_available(&state, now))
            .map_err(|_| ProductHostError)
    }

    fn current_if_available(
        &self,
    ) -> Result<Option<Result<ProductSnapshotEnvelope, ProductHostError>>, ProductHostError> {
        self.current_if_available_at(Instant::now())
    }

    fn current_if_available_at(
        &self,
        now: Instant,
    ) -> Result<Option<Result<ProductSnapshotEnvelope, ProductHostError>>, ProductHostError> {
        let state = self.state.lock().map_err(|_| ProductHostError)?;
        Ok(match &state.current {
            None if source_available(&state, now) => None,
            None => Some(Err(ProductHostError)),
            Some(current) if source_available(&state, now) => Some(Ok(current.clone())),
            Some(_) => Some(Err(ProductHostError)),
        })
    }

    #[cfg(test)]
    fn current(&self) -> Result<Option<ProductSnapshotEnvelope>, ProductHostError> {
        self.state
            .lock()
            .map(|state| state.current.clone())
            .map_err(|_| ProductHostError)
    }

    fn wait_after(&self, after: u64, timeout: Duration) -> Result<WaitResult, ProductHostError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ProductHostError)?;
        let mut state = self.state.lock().map_err(|_| ProductHostError)?;
        loop {
            let now = Instant::now();
            match wait_decision(&state, after, now) {
                WaitDecision::Snapshot(snapshot) => return Ok(WaitResult::Snapshot(snapshot)),
                WaitDecision::Conflict => return Ok(WaitResult::Conflict),
                WaitDecision::Offline => return Ok(WaitResult::Offline),
                WaitDecision::Pending => {}
            }
            if now >= deadline {
                return Ok(WaitResult::Timeout);
            }
            let lease_deadline = state
                .last_success
                .unwrap_or(state.lease_started)
                .checked_add(SOURCE_HEALTH_LEASE);
            let wake_deadline = lease_deadline.map_or(deadline, |lease| lease.min(deadline));
            let remaining = wake_deadline.saturating_duration_since(now);
            let (next, result) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| ProductHostError)?;
            state = next;
            if result.timed_out() && wake_deadline == deadline {
                return Ok(WaitResult::Timeout);
            }
        }
    }
}

fn source_available(state: &StoreState, now: Instant) -> bool {
    now.checked_duration_since(state.last_success.unwrap_or(state.lease_started))
        .is_some_and(|elapsed| elapsed < SOURCE_HEALTH_LEASE)
}

fn wait_decision(state: &StoreState, after: u64, now: Instant) -> WaitDecision {
    if !source_available(state, now) {
        return WaitDecision::Offline;
    }
    let Some(expected) = after
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_SNAPSHOT_SEQ)
    else {
        return WaitDecision::Conflict;
    };
    match &state.current {
        Some(current) if current.snapshot_seq == expected => {
            WaitDecision::Snapshot(Box::new(current.clone()))
        }
        Some(current) if current.snapshot_seq != after => WaitDecision::Conflict,
        None if after > 0 => WaitDecision::Conflict,
        _ => WaitDecision::Pending,
    }
}

pub(crate) struct ProductStockHost {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    store: Arc<ProductSnapshotStore>,
    fatal_process_mismatch: Arc<AtomicBool>,
    commands: Arc<ProductCommandService>,
    devices: Arc<ProductDeviceRegistryService>,
    pairing: Option<Arc<ProductPairingService>>,
    join_transport: Option<Arc<CommandTransportAuthenticator>>,
    remote_commands: Option<Arc<ProductRemoteCommandAuthority>>,
    remote_lifecycle: Option<Arc<RemoteIngressLifecycle>>,
}

struct ProductHostServices {
    commands: Arc<ProductCommandService>,
    devices: Arc<ProductDeviceRegistryService>,
    pairing: Option<Arc<ProductPairingService>>,
    join_transport: Option<Arc<CommandTransportAuthenticator>>,
    remote_commands: Option<Arc<ProductRemoteCommandAuthority>>,
    remote_lifecycle: Option<Arc<RemoteIngressLifecycle>>,
}

/// Remote-only dependencies needed to construct the Host-final authority.
/// Mailbox-worker startup and its external readiness barrier are deliberately
/// owned by the bootstrap layer after this Host exposes the facade.
pub(crate) struct RemoteProductHostDependencies {
    pub(crate) pairing: Arc<PairingCoordinator>,
    pub(crate) join_transport_key: Zeroizing<[u8; 32]>,
    pub(crate) lifecycle: Arc<RemoteIngressLifecycle>,
}

impl std::fmt::Debug for ProductStockHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductStockHost(<private-uds>)")
    }
}

impl ProductStockHost {
    fn bind(
        socket_path: &Path,
        expected_parent: (u64, u64),
        store: Arc<ProductSnapshotStore>,
        services: ProductHostServices,
    ) -> Result<Self, ProductHostError> {
        validate_and_prepare_socket_path(socket_path)?;
        if parent_identity(socket_path)? != expected_parent {
            return Err(ProductHostError);
        }
        let _umask = UmaskGuard::restrict();
        let listener = UnixListener::bind(socket_path).map_err(|_| ProductHostError)?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| ProductHostError)?;
        let socket_identity = validate_bound_socket(socket_path)?;
        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
            socket_identity,
            store,
            fatal_process_mismatch: Arc::new(AtomicBool::new(false)),
            commands: services.commands,
            devices: services.devices,
            pairing: services.pairing,
            join_transport: services.join_transport,
            remote_commands: services.remote_commands,
            remote_lifecycle: services.remote_lifecycle,
        })
    }

    pub(crate) fn start(
        bootstrap: HostBootstrap,
    ) -> Result<(Self, ProductHostReady), ProductHostError> {
        Self::start_impl(bootstrap, None)
    }

    /// Composition seam for the reviewed Relay/bootstrap owner. The exact same
    /// gate is derived from the coordinator rather than accepted independently.
    pub(crate) fn start_with_pairing(
        bootstrap: HostBootstrap,
        remote: Option<RemoteProductHostDependencies>,
    ) -> Result<(Self, ProductHostReady), ProductHostError> {
        Self::start_impl(bootstrap, remote)
    }

    fn start_impl(
        bootstrap: HostBootstrap,
        remote: Option<RemoteProductHostDependencies>,
    ) -> Result<(Self, ProductHostReady), ProductHostError> {
        let (pairing, join_transport, remote_lifecycle) = match remote {
            Some(remote) => {
                if crate::run_binding::constant_time_eq(
                    bootstrap.command_transport_key.as_ref(),
                    remote.join_transport_key.as_ref(),
                ) {
                    return Err(ProductHostError);
                }
                (
                    Some(remote.pairing),
                    Some(Arc::new(CommandTransportAuthenticator::new(
                        remote.join_transport_key,
                    ))),
                    Some(remote.lifecycle),
                )
            }
            None => (None, None, None),
        };
        let store = Arc::new(ProductSnapshotStore::new()?);
        let process = AgentProcessBinding::new(
            bootstrap.agent_pid,
            bootstrap.agent_process_group,
            bootstrap.agent_process_identity.clone(),
        )?;
        let client = Arc::new(StockSnapshotClient::new(
            &bootstrap.origin,
            &bootstrap.session_id,
            bootstrap.server_password.clone(),
        )?);
        let run_binding = RunProjectionBinding::new(
            bootstrap.run_id.clone(),
            bootstrap.workspace_binding_digest.clone(),
        );
        let device_command_gate = pairing
            .as_ref()
            .map(|coordinator| coordinator.device_command_gate())
            .unwrap_or_else(|| Arc::new(DeviceCommandGate::new()));
        if let Some(coordinator) = &pairing {
            coordinator
                .recover_expired_pending(OffsetDateTime::now_utc())
                .map_err(|_| ProductHostError)?;
        }
        let devices = Arc::new(ProductDeviceRegistryService::open(
            &bootstrap.device_registry_path,
            REMOTE_PAIRED_PRINCIPAL_ALIAS,
            REMOTE_REGISTRY_PRINCIPAL_ALIAS,
            Arc::clone(&device_command_gate),
        )?);
        first_snapshot(
            &client,
            &process,
            &run_binding,
            &store,
            INITIAL_SNAPSHOT_TIMEOUT,
        )?;
        let commands = Arc::new(ProductCommandService::new(
            Arc::clone(&client),
            process.clone(),
            run_binding.clone(),
            Arc::clone(&store),
            &bootstrap,
            device_command_gate,
        )?);
        let remote_enabled = pairing.is_some();
        let remote_commands = pairing.as_ref().map(|coordinator| {
            Arc::new(ProductRemoteCommandAuthority::new(
                Arc::clone(coordinator),
                Arc::clone(&commands),
                Arc::clone(&devices),
            ))
        });
        let host = Self::bind(
            &bootstrap.product_host_socket_path,
            (
                bootstrap.product_host_socket_parent_dev,
                bootstrap.product_host_socket_parent_ino,
            ),
            store,
            ProductHostServices {
                commands,
                devices,
                pairing: pairing.map(|coordinator| Arc::new(ProductPairingService { coordinator })),
                join_transport,
                remote_commands,
                remote_lifecycle,
            },
        )?;
        if remote_enabled
            && (host.remote_command_authority().is_none()
                || !matches!(
                    host.remote_lifecycle_snapshot(),
                    Some(snapshot)
                        if snapshot.status == RemoteIngressStatus::Starting
                            && !snapshot.accepting_writes
                            && snapshot.active_permits == 0
                ))
        {
            return Err(ProductHostError);
        }
        let poll_store = Arc::clone(&host.store);
        let fatal_process_mismatch = Arc::clone(&host.fatal_process_mismatch);
        let poll_process = process.clone();
        let poll_run_binding = run_binding.clone();
        thread::Builder::new()
            .name("product-stock-poller".into())
            .spawn(move || loop {
                if !continue_after_poll(
                    poll_once(&client, &poll_process, &poll_run_binding, &poll_store, None),
                    &fatal_process_mismatch,
                ) {
                    return;
                }
                thread::sleep(POLL_INTERVAL);
            })
            .map_err(|_| ProductHostError)?;
        process.verify().map_err(|_| ProductHostError)?;
        if host.fatal_process_mismatch.load(Ordering::Acquire) {
            return Err(ProductHostError);
        }
        let ready = ProductHostReady {
            schema: "nomad.product-host.ready.v1",
            parent_dev: bootstrap.product_host_socket_parent_dev,
            parent_ino: bootstrap.product_host_socket_parent_ino,
            socket_dev: host.socket_identity.0,
            socket_ino: host.socket_identity.1,
            snapshot_seq: 1,
        };
        Ok((host, ready))
    }

    /// Returns the opaque Host-final remote command facade for the mailbox
    /// worker. It is absent on the local-only startup path.
    pub(crate) fn remote_command_authority(&self) -> Option<Arc<ProductRemoteCommandAuthority>> {
        self.remote_commands.clone()
    }

    pub(crate) fn remote_lifecycle_snapshot(&self) -> Option<RemoteIngressLifecycleSnapshot> {
        self.remote_lifecycle
            .as_ref()
            .map(|lifecycle| lifecycle.snapshot())
    }

    pub(crate) fn run(self) -> Result<(), ProductHostError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| ProductHostError)?;
        let clients = Arc::new(AtomicUsize::new(0));
        loop {
            if self.fatal_process_mismatch.load(Ordering::Acquire) {
                return Err(ProductHostError);
            }
            if validate_bound_socket(&self.socket_path)? != self.socket_identity {
                return Err(ProductHostError);
            }
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(_) => return Err(ProductHostError),
            };
            if verify_peer_uid(&stream).is_err()
                || clients
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < MAX_CLIENTS).then_some(count + 1)
                    })
                    .is_err()
            {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let store = Arc::clone(&self.store);
            let commands = Arc::clone(&self.commands);
            let devices = Arc::clone(&self.devices);
            let pairing = self.pairing.clone();
            let join_transport = self.join_transport.clone();
            let remote_lifecycle = self.remote_lifecycle.clone();
            let worker_clients = Arc::clone(&clients);
            if thread::Builder::new()
                .name("product-host-client".into())
                .spawn(move || {
                    let _guard = ClientGuard(worker_clients);
                    let _ = serve_connection(
                        stream,
                        &store,
                        &commands,
                        &devices,
                        pairing.as_deref(),
                        join_transport.as_deref(),
                        remote_lifecycle.as_ref(),
                    );
                })
                .is_err()
            {
                clients.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

fn poll_once(
    client: &StockSnapshotClient,
    process: &AgentProcessBinding,
    run_binding: &RunProjectionBinding,
    store: &ProductSnapshotStore,
    deadline: Option<Instant>,
) -> Result<bool, PollError> {
    let mut snapshot = client.poll_complete_batch(process, run_binding, deadline)?;
    run_binding.realias(&mut snapshot);
    store.commit(snapshot).map_err(|_| PollError::Source)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollError {
    Process,
    Binding,
    Source,
}

fn continue_after_poll(result: Result<bool, PollError>, fatal: &AtomicBool) -> bool {
    match result {
        Ok(_) | Err(PollError::Source) => true,
        Err(PollError::Process | PollError::Binding) => {
            fatal.store(true, Ordering::Release);
            false
        }
    }
}

fn first_snapshot(
    client: &StockSnapshotClient,
    process: &AgentProcessBinding,
    run_binding: &RunProjectionBinding,
    store: &ProductSnapshotStore,
    timeout: Duration,
) -> Result<(), ProductHostError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ProductHostError)?;
    loop {
        match poll_once(client, process, run_binding, store, Some(deadline)) {
            Ok(true) => return Ok(()),
            Ok(false) => return Err(ProductHostError),
            Err(PollError::Process | PollError::Binding) => return Err(ProductHostError),
            Err(PollError::Source) => {
                let Some(next_start) = Instant::now().checked_add(POLL_INTERVAL) else {
                    return Err(ProductHostError);
                };
                if next_start > deadline {
                    return Err(ProductHostError);
                }
                thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

impl Drop for ProductStockHost {
    fn drop(&mut self) {
        if validate_bound_socket(&self.socket_path) == Ok(self.socket_identity) {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

struct ClientGuard(Arc<AtomicUsize>);
impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct UmaskGuard {
    previous: libc::mode_t,
    _lock: MutexGuard<'static, ()>,
}
impl UmaskGuard {
    fn restrict() -> Self {
        static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = UMASK_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = unsafe { libc::umask(0o077) };
        Self {
            previous,
            _lock: lock,
        }
    }
}
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.previous);
        }
    }
}

struct StockSnapshotClient {
    origin: String,
    session_id: String,
    authorization: Zeroizing<String>,
    agent: ureq::Agent,
}

#[derive(Clone)]
struct ProductCommandState {
    client: Arc<StockSnapshotClient>,
    process: AgentProcessBinding,
    run_binding: RunProjectionBinding,
    store: Arc<ProductSnapshotStore>,
    session_id: String,
    authority_run_id: String,
    authority_session_id: String,
    remote_authority_session_id: String,
    issued: Arc<Mutex<Option<IssuedCommandCapability>>>,
    remote_issued: Arc<Mutex<Option<IssuedCommandCapability>>>,
}

impl ProductCommandState {
    fn fresh_facts(
        &self,
        original: Option<&OpenCodeCommandFacts>,
        next_command_seq: u64,
    ) -> Result<OpenCodeCommandFacts, ConnectorError> {
        let envelope = self
            .store
            .current_if_available()
            .map_err(|_| ConnectorError::HostOffline)?
            .ok_or(ConnectorError::HostOffline)?
            .map_err(|_| ConnectorError::HostOffline)?;
        let (batch, mut projected) = self
            .client
            .command_batch(&self.process, &self.run_binding)
            .map_err(|_| ConnectorError::HostOffline)?;
        self.run_binding.realias(&mut projected);
        if projected != envelope.snapshot {
            return Err(ConnectorError::StaleRequest(
                "authoritative command facts are ahead of the projected snapshot".into(),
            ));
        }
        let binding = OpenCodeCommandFactsBinding::new(
            self.process.identity.clone(),
            self.run_binding.run_id.to_string(),
            self.session_id.clone(),
            next_command_seq,
            envelope.digest,
            envelope.snapshot_seq,
        )
        .map_err(|_| ConnectorError::HostOffline)?;
        match original {
            Some(original) => original.refresh_stable(binding, batch),
            None => OpenCodeCommandFacts::parse_stable(binding, batch),
        }
        .map_err(|_| ConnectorError::HostOffline)
    }
}

#[derive(Clone)]
struct IssuedCommandCapability {
    original: OpenCodeCommandFacts,
    capability: OpenCodeCommandCapability,
}

impl TrustedCommandState for ProductCommandState {
    fn refresh_current(&self, session_id: &str) -> Result<CurrentCommandState, ConnectorError> {
        let issued_slot = if session_id == self.authority_session_id {
            &self.issued
        } else if session_id == self.remote_authority_session_id {
            &self.remote_issued
        } else {
            return Err(ConnectorError::StaleRequest("session changed".into()));
        };
        let issued = issued_slot
            .lock()
            .map_err(|_| ConnectorError::HostOffline)?
            .clone()
            .ok_or_else(|| ConnectorError::StaleRequest("capability not issued".into()))?;
        let fresh = self.fresh_facts(Some(&issued.original), issued.capability.next_command_seq)?;
        let fresh_capability = fresh
            .capability()
            .map_err(|_| ConnectorError::StaleRequest("capability expired".into()))?;
        if fresh_capability != issued.capability {
            return Err(ConnectorError::StaleRequest("command facts changed".into()));
        }
        let capability = issued.capability;
        Ok(CurrentCommandState {
            run_id: self.authority_run_id.clone(),
            session_id: session_id.to_owned(),
            snapshot_seq: capability.snapshot_seq,
            snapshot_digest: capability.snapshot_digest,
            next_command_seq: capability.next_command_seq,
            online: true,
            live: true,
            reconciliation_pending: false,
            active_turn_id: capability
                .reply
                .as_ref()
                .map(|reply| reply.turn_alias.clone())
                .or_else(|| capability.stop.as_ref().map(|stop| stop.turn_alias.clone())),
            active_input_id: capability.reply.map(|reply| reply.input_alias),
            active_permission: capability.deny.map(|deny| CurrentPermission {
                permission_id: deny.permission_alias,
                action_hash: deny.action_hash,
                expires_at: deny.expires_at,
            }),
        })
    }
}

#[derive(Clone)]
struct ProductOpenCodeAdapter {
    dispatcher: OpenCodeCommandDispatcher,
    selected: Arc<Mutex<Option<(String, u64, OpenCodeCommand)>>>,
}

impl AgentCommandAdapter for ProductOpenCodeAdapter {
    fn execute_once(
        &self,
        authorized: AuthorizedHostCommand,
    ) -> Result<AdapterOutcome, ConnectorError> {
        let request_id = authorized.request_id().to_string();
        let (selected_request, accepted_at_seq, command) = self
            .selected
            .lock()
            .map_err(|_| ConnectorError::HostOffline)?
            .take()
            .filter(|(selected_request, _, _)| selected_request == &request_id)
            .ok_or_else(|| ConnectorError::StaleRequest("resolved command missing".into()))?;
        drop(selected_request);
        Ok(match self.dispatcher.dispatch_once(command) {
            OpenCodeDispatchOutcome::DispatchAcknowledged => {
                AdapterOutcome::Completed { accepted_at_seq }
            }
            OpenCodeDispatchOutcome::Rejected { error_code } => {
                AdapterOutcome::Rejected { error_code }
            }
            OpenCodeDispatchOutcome::OutcomeUnknown => AdapterOutcome::OutcomeUnknown,
        })
    }
}

struct ProductCommandService {
    state: ProductCommandState,
    authority: OwnedHostCommandAuthority<ProductCommandState, ProductOpenCodeAdapter>,
    device: AuthenticatedDeviceSession,
    selected: Arc<Mutex<Option<(String, u64, OpenCodeCommand)>>>,
    command_authority_key: Zeroizing<[u8; 32]>,
    transport: CommandTransportAuthenticator,
    execution: Arc<DeviceCommandGate>,
}

struct ProductDeviceRegistryService {
    authority: DeviceAuthority,
    principal_alias: &'static str,
    registry_principal_alias: &'static str,
    gate: Arc<DeviceCommandGate>,
}

struct ProductPairingService {
    coordinator: Arc<PairingCoordinator>,
}

/// Narrow boundary handed to the authenticated mailbox worker. Callers cannot
/// access the journal, dispatcher, device registry, or command keys directly.
pub(crate) struct ProductRemoteCommandAuthority {
    coordinator: Arc<PairingCoordinator>,
    commands: Arc<ProductCommandService>,
    devices: Arc<ProductDeviceRegistryService>,
}

impl std::fmt::Debug for ProductRemoteCommandAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductRemoteCommandAuthority(<redacted>)")
    }
}

impl ProductRemoteCommandAuthority {
    fn new(
        coordinator: Arc<PairingCoordinator>,
        commands: Arc<ProductCommandService>,
        devices: Arc<ProductDeviceRegistryService>,
    ) -> Self {
        Self {
            coordinator,
            commands,
            devices,
        }
    }

    fn issue_current_capability(
        &self,
        guard: &DeviceCommandGuard<'_>,
    ) -> Result<OpenCodeCommandCapability, CommandProtocolError> {
        let binding = self.require_current_binding(guard, None)?;
        self.commands.capability_remote_locked(&binding)
    }

    fn require_current_binding(
        &self,
        guard: &DeviceCommandGuard<'_>,
        expected: Option<&ActiveRemoteBinding>,
    ) -> Result<ActiveRemoteBinding, CommandProtocolError> {
        let binding = self
            .coordinator
            .active_binding_locked(guard)
            .map_err(CommandProtocolError::from)?
            .ok_or(CommandProtocolError::Stale)?;
        let current = self
            .devices
            .authority
            .current_active()
            .map_err(map_device_authority_error)?;
        let CurrentActiveDevice::Active(device) = current else {
            return Err(CommandProtocolError::Stale);
        };
        if !binding.matches_authority_device(&device)
            || expected.is_some_and(|expected| !same_remote_binding(expected, &binding))
        {
            return Err(CommandProtocolError::Stale);
        }
        Ok(binding)
    }
}

fn same_remote_binding(left: &ActiveRemoteBinding, right: &ActiveRemoteBinding) -> bool {
    left.device_alias == right.device_alias
        && left.pairing_epoch == right.pairing_epoch
        && left.mailbox_id == right.mailbox_id
        && left.host_signing_commitment == right.host_signing_commitment
        && left.host_agreement_commitment == right.host_agreement_commitment
        && left.device_signing_commitment == right.device_signing_commitment
        && left.device_agreement_commitment == right.device_agreement_commitment
}

impl RemoteCommandAuthorityContract<PairingCoordinator> for ProductRemoteCommandAuthority {
    fn projection_locked(
        &self,
        guard: &<PairingCoordinator as RemoteAdmissionCoordinator>::Guard<'_>,
        binding: &ActiveRemoteBinding,
    ) -> Result<ProjectionPayload, RemoteAuthorityFailure> {
        self.require_current_binding(guard, Some(binding))
            .map_err(map_remote_authority_failure)?;
        let snapshot = self
            .commands
            .state
            .store
            .current_if_available()
            .map_err(|_| RemoteAuthorityFailure::Fatal)?
            .ok_or(RemoteAuthorityFailure::Retryable)?
            .map_err(|_| RemoteAuthorityFailure::Retryable)?;
        if snapshot.snapshot.pending_input_alias.is_none()
            && snapshot.snapshot.pending_permission_alias.is_none()
        {
            *self
                .commands
                .state
                .remote_issued
                .lock()
                .map_err(|_| RemoteAuthorityFailure::Fatal)? = None;
            return Ok(ProjectionPayload {
                snapshot: remote_snapshot(snapshot),
                capability: None,
            });
        }
        let capability = self
            .issue_current_capability(guard)
            .map_err(map_remote_authority_failure)?;
        Ok(ProjectionPayload {
            snapshot: remote_snapshot(snapshot),
            capability: Some(remote_capability(capability)),
        })
    }

    fn execute_locked(
        &self,
        guard: &<PairingCoordinator as RemoteAdmissionCoordinator>::Guard<'_>,
        binding: &ActiveRemoteBinding,
        command: ParsedProductCommand,
    ) -> RemoteCommandDisposition {
        let request_id = command.request_id().to_owned();
        let snapshot_seq = command.snapshot_seq();
        let snapshot_digest = command.snapshot_digest().to_owned();
        let action = remote_command_action(&command);
        if let Err(error) = self.require_current_binding(guard, Some(binding)) {
            return remote_error_disposition(
                error,
                request_id,
                action,
                snapshot_seq,
                snapshot_digest,
                true,
            );
        }
        match self.commands.execute_remote_locked(command, binding) {
            Ok((receipt, snapshot_seq, snapshot_digest)) => RemoteCommandDisposition::Receipt(
                remote_receipt(receipt, snapshot_seq, snapshot_digest),
            ),
            Err(error) => remote_error_disposition(
                error,
                request_id,
                action,
                snapshot_seq,
                snapshot_digest,
                false,
            ),
        }
    }
}

fn remote_error_disposition(
    error: CommandProtocolError,
    request_id: String,
    action: RemoteReceiptAction,
    snapshot_seq: u64,
    snapshot_digest: String,
    binding_rejected: bool,
) -> RemoteCommandDisposition {
    let (status, code) = match error {
        CommandProtocolError::InvalidRequest | CommandProtocolError::Unauthorized => {
            (RemoteReceiptStatus::Rejected, "ERR_SAFETY_BLOCKED")
        }
        CommandProtocolError::Stale if binding_rejected => {
            (RemoteReceiptStatus::Stale, "ERR_REQUEST_REVOKED")
        }
        CommandProtocolError::Stale => (RemoteReceiptStatus::Stale, "ERR_REQUEST_STALE"),
        CommandProtocolError::Expired => (RemoteReceiptStatus::Expired, "ERR_REQUEST_EXPIRED"),
        CommandProtocolError::OutcomeUnknown => {
            (RemoteReceiptStatus::OutcomeUnknown, "ERR_OUTCOME_UNKNOWN")
        }
        CommandProtocolError::Unavailable => return RemoteCommandDisposition::RetryableNoAck,
        CommandProtocolError::Internal => return RemoteCommandDisposition::Fatal,
    };
    deterministic_remote_receipt(
        request_id,
        action,
        snapshot_seq,
        snapshot_digest,
        status,
        code,
    )
}

fn remote_command_action(command: &ParsedProductCommand) -> RemoteReceiptAction {
    match command.safe_command() {
        crate::adapters::opencode::OpenCodeSafeCommand::Reply { .. } => RemoteReceiptAction::Reply,
        crate::adapters::opencode::OpenCodeSafeCommand::Deny { .. } => RemoteReceiptAction::Deny,
        crate::adapters::opencode::OpenCodeSafeCommand::Stop { .. } => RemoteReceiptAction::Stop,
    }
}

fn deterministic_remote_receipt(
    request_id: String,
    action: RemoteReceiptAction,
    snapshot_seq: u64,
    snapshot_digest: String,
    status: RemoteReceiptStatus,
    error_code: &'static str,
) -> RemoteCommandDisposition {
    let mut random = [0_u8; 16];
    if getrandom(&mut random).is_err() {
        return RemoteCommandDisposition::Fatal;
    }
    let accepted_at = match whole_second_utc_now() {
        Some(value) => value,
        None => return RemoteCommandDisposition::Fatal,
    };
    RemoteCommandDisposition::Receipt(RemoteCommandReceipt {
        schema: "nomad.gateway.command-receipt.v1".into(),
        receipt_id: format!("rcpt_{}", lower_hex(&random)),
        request_id,
        action,
        snapshot_seq,
        snapshot_digest,
        accepted_at,
        status,
        error_code: RemoteReceiptErrorCode(error_code.into()),
        idempotent_replay: false,
    })
}

fn whole_second_utc_now() -> Option<String> {
    let value = OffsetDateTime::now_utc().replace_nanosecond(0).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    ))
}

fn map_remote_authority_failure(error: CommandProtocolError) -> RemoteAuthorityFailure {
    match error {
        CommandProtocolError::Unavailable | CommandProtocolError::OutcomeUnknown => {
            RemoteAuthorityFailure::Retryable
        }
        CommandProtocolError::InvalidRequest
        | CommandProtocolError::Unauthorized
        | CommandProtocolError::Stale
        | CommandProtocolError::Expired
        | CommandProtocolError::Internal => RemoteAuthorityFailure::Fatal,
    }
}

fn remote_snapshot(
    snapshot: ProductSnapshotEnvelope,
) -> crate::remote_application::ProductSnapshotEnvelope {
    crate::remote_application::ProductSnapshotEnvelope {
        schema: snapshot.schema.to_owned(),
        host_instance_id: snapshot.host_instance_id,
        snapshot_seq: snapshot.snapshot_seq,
        digest: snapshot.digest,
        snapshot: crate::remote_application::ProductSnapshot {
            session_alias: snapshot.snapshot.session_alias,
            updated_at: snapshot.snapshot.updated_at,
            turn_state: match snapshot.snapshot.turn_state.as_str() {
                "Running" => crate::remote_application::SnapshotTurnState::Running,
                "NeedsInput" => crate::remote_application::SnapshotTurnState::NeedsInput,
                "NeedsPermission" => crate::remote_application::SnapshotTurnState::NeedsPermission,
                "Completed" => crate::remote_application::SnapshotTurnState::Completed,
                _ => crate::remote_application::SnapshotTurnState::OutcomeUnknown,
            },
            pending_input_alias: snapshot.snapshot.pending_input_alias,
            pending_permission_alias: snapshot.snapshot.pending_permission_alias,
            diff_file_count: snapshot.snapshot.diff_file_count,
            writable: false,
            evidence_class: snapshot.snapshot.evidence_class.to_owned(),
        },
    }
}

fn remote_capability(capability: OpenCodeCommandCapability) -> RemoteCommandCapability {
    RemoteCommandCapability {
        schema: capability.schema.to_owned(),
        capability_id: capability.capability_id,
        snapshot_seq: capability.snapshot_seq,
        snapshot_digest: capability.snapshot_digest,
        next_command_seq: capability.next_command_seq,
        issued_at: capability.issued_at,
        expires_at: capability.expires_at,
        view: capability.view,
        reply: capability.reply.map(|value| RemoteReplyCapability {
            turn_alias: value.turn_alias,
            input_alias: value.input_alias,
            summary: value.summary.map(|summary| RemotePendingQuestionSummary {
                schema: summary.schema.to_owned(),
                question_count: summary.question_count,
                answer_mode: summary.answer_mode.to_owned(),
                response_hint: summary.response_hint.to_owned(),
                prompt: summary.prompt,
            }),
        }),
        deny: capability.deny.map(|value| RemoteDenyCapability {
            permission_alias: value.permission_alias,
            action_hash: value.action_hash,
            expires_at: value.expires_at,
        }),
        stop: capability.stop.map(|value| RemoteStopCapability {
            turn_alias: value.turn_alias,
        }),
        allow_once: false,
    }
}

fn remote_receipt(
    receipt: HostCommandReceipt,
    snapshot_seq: u64,
    snapshot_digest: String,
) -> RemoteCommandReceipt {
    let action = match receipt.kind.as_str() {
        "reply" => RemoteReceiptAction::Reply,
        "deny" => RemoteReceiptAction::Deny,
        _ => RemoteReceiptAction::Stop,
    };
    let status = match receipt.status.as_str() {
        "HostAccepted" => RemoteReceiptStatus::HostAccepted,
        "Dispatching" => RemoteReceiptStatus::Dispatching,
        "DispatchAcknowledged" => RemoteReceiptStatus::DispatchAcknowledged,
        "Rejected" => RemoteReceiptStatus::Rejected,
        "Stale" => RemoteReceiptStatus::Stale,
        "Expired" => RemoteReceiptStatus::Expired,
        _ => RemoteReceiptStatus::OutcomeUnknown,
    };
    RemoteCommandReceipt {
        schema: "nomad.gateway.command-receipt.v1".into(),
        receipt_id: receipt.receipt_id,
        request_id: receipt.request_id,
        action,
        snapshot_seq,
        snapshot_digest,
        accepted_at: receipt.accepted_at,
        status,
        error_code: RemoteReceiptErrorCode(receipt.error_code.unwrap_or_else(|| "OK".into())),
        idempotent_replay: receipt.idempotent_replay,
    }
}

impl ProductPairingService {
    fn create(&self) -> Result<crate::pairing_coordinator::CreatedJoin, PairingCoordinatorError> {
        self.coordinator.create_join(OffsetDateTime::now_utc())
    }

    fn approve(
        &self,
        request: crate::product_command_protocol::ParsedPairingApproveRequest,
    ) -> Result<(), PairingCoordinatorError> {
        self.coordinator.approve_join(
            &request.join_id,
            &request.challenge_id,
            request.expected_epoch,
            &request.comparison_code,
            OffsetDateTime::now_utc(),
        )
    }

    fn cancel(
        &self,
        request: crate::product_command_protocol::ParsedPairingCancelRequest,
    ) -> Result<(), PairingCoordinatorError> {
        self.coordinator.cancel_join(&CancelJoinRequest {
            schema: "nomad.m3e.pairing.cancel.v1".into(),
            join_id: request.join_id,
        })
    }

    fn status(
        &self,
        request: crate::product_command_protocol::ParsedPairingStatusRequest,
    ) -> Result<crate::pairing_coordinator::PairingStatusResponse, PairingCoordinatorError> {
        self.coordinator.pairing_status(
            &PairingStatusRequest {
                schema: "nomad.m3e.pairing.status.v1".into(),
                join_id: request.join_id,
            },
            OffsetDateTime::now_utc(),
        )
    }

    fn start(
        &self,
        request: crate::product_command_protocol::ParsedPairingStartRequest,
    ) -> Result<crate::pairing_coordinator::StartedJoin, PairingCoordinatorError> {
        self.coordinator.start_join(
            &request.join_id,
            request.join_secret.as_str(),
            &request.device_signing_public_key_sec1,
            &request.device_agreement_public_key_sec1,
            OffsetDateTime::now_utc(),
        )
    }

    fn confirm(
        &self,
        request: crate::product_command_protocol::ParsedM3ePairingConfirmRequest,
    ) -> Result<crate::pairing_coordinator::SignedProvisioningBundle, PairingCoordinatorError> {
        self.coordinator.confirm_join(
            request.join_cookie_capability.as_str(),
            &request.challenge_id,
            request.expected_epoch,
            &request.device_signing_signature_p1363,
            &request.device_agreement_mac,
            OffsetDateTime::now_utc(),
        )
    }

    fn complete(
        &self,
        request: crate::product_command_protocol::ParsedPairingCompleteRequest,
    ) -> Result<ActiveRemoteBinding, PairingCoordinatorError> {
        self.coordinator.complete_join(
            request.join_cookie_capability.as_str(),
            &request.challenge_id,
            request.expected_epoch,
            &request.device_vault_signature_p1363,
            OffsetDateTime::now_utc(),
        )
    }

    fn abort(
        &self,
        request: crate::product_command_protocol::ParsedPairingAbortRequest,
    ) -> Result<(), PairingCoordinatorError> {
        self.coordinator.abort_join(
            request.join_cookie_capability.as_str(),
            &AbortJoinRequest {
                schema: "nomad.m3e.pairing.abort.v1".into(),
                challenge_id: request.challenge_id,
                expected_epoch: request.expected_epoch,
            },
            OffsetDateTime::now_utc(),
        )
    }

    fn current(&self) -> Result<Option<ActiveRemoteBinding>, PairingCoordinatorError> {
        let guard = self.coordinator.command_guard()?;
        self.coordinator.active_binding_locked(&guard)
    }

    fn revoke(
        &self,
        request: &ParsedDeviceRevokeRequest,
    ) -> Result<RevokeOutcome, PairingCoordinatorError> {
        self.coordinator.revoke_device(
            request.device_alias(),
            request.expected_epoch(),
            OffsetDateTime::now_utc(),
        )
    }
}

impl ProductDeviceRegistryService {
    fn open(
        path: &Path,
        principal_alias: &'static str,
        registry_principal_alias: &'static str,
        gate: Arc<DeviceCommandGate>,
    ) -> Result<Self, ProductHostError> {
        Ok(Self {
            authority: DeviceAuthority::open(path).map_err(|_| ProductHostError)?,
            principal_alias,
            registry_principal_alias,
            gate,
        })
    }

    fn principal_alias(&self) -> &'static str {
        self.principal_alias
    }

    fn current(&self) -> Result<CurrentActiveDevice, CommandProtocolError> {
        self.authority
            .current_active()
            .map_err(map_device_authority_error)
    }

    fn begin_pairing(
        &self,
        request: ParsedPairingChallengeRequest,
    ) -> Result<crate::device_authority::PairingChallenge, CommandProtocolError> {
        self.authority
            .begin_pairing(
                self.registry_principal_alias,
                request.signing_public_key(),
                request.agreement_public_key(),
                OffsetDateTime::now_utc(),
            )
            .map_err(map_device_authority_error)
    }

    fn confirm_pairing(
        &self,
        request: ParsedPairingConfirmRequest,
    ) -> Result<AuthenticatedDeviceFact, CommandProtocolError> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?;
        self.authority
            .confirm_pairing(
                request.challenge_id(),
                request.challenge(),
                request.signature(),
                OffsetDateTime::now_utc(),
            )
            .map_err(map_device_authority_error)
    }

    fn revoke(
        &self,
        request: ParsedDeviceRevokeRequest,
    ) -> Result<RevokeOutcome, CommandProtocolError> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?;
        self.authority
            .revoke(
                request.device_alias(),
                request.expected_epoch(),
                OffsetDateTime::now_utc(),
            )
            .map_err(map_device_authority_error)
    }
}

impl ProductCommandService {
    fn new(
        client: Arc<StockSnapshotClient>,
        process: AgentProcessBinding,
        run_binding: RunProjectionBinding,
        store: Arc<ProductSnapshotStore>,
        bootstrap: &HostBootstrap,
        execution: Arc<DeviceCommandGate>,
    ) -> Result<Self, ProductHostError> {
        let dispatcher =
            OpenCodeCommandDispatcher::new(&bootstrap.origin, bootstrap.server_password.clone())
                .map_err(|_| ProductHostError)?;
        Self::new_with_dispatcher(
            client,
            process,
            run_binding,
            store,
            bootstrap,
            dispatcher,
            execution,
        )
    }

    fn new_with_dispatcher(
        client: Arc<StockSnapshotClient>,
        process: AgentProcessBinding,
        run_binding: RunProjectionBinding,
        store: Arc<ProductSnapshotStore>,
        bootstrap: &HostBootstrap,
        dispatcher: OpenCodeCommandDispatcher,
        execution: Arc<DeviceCommandGate>,
    ) -> Result<Self, ProductHostError> {
        let journal_parent = bootstrap
            .command_journal_path
            .parent()
            .ok_or(ProductHostError)?;
        let _parent = open_directory_no_follow(journal_parent).map_err(|_| ProductHostError)?;
        // SQLite creates the main DB and WAL/SHM sidecars during initialization.
        // Hold the process-wide umask guard before any command worker threads
        // exist so every journal artifact is private from first creation.
        let journal = {
            let _umask = UmaskGuard::restrict();
            CommandJournal::open(&bootstrap.command_journal_path).map_err(|_| ProductHostError)?
        };
        let metadata =
            fs::symlink_metadata(&bootstrap.command_journal_path).map_err(|_| ProductHostError)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(ProductHostError);
        }
        fs::set_permissions(
            &bootstrap.command_journal_path,
            fs::Permissions::from_mode(0o600),
        )
        .map_err(|_| ProductHostError)?;
        let state = ProductCommandState {
            client,
            process,
            run_binding,
            store,
            session_id: bootstrap.session_id.clone(),
            authority_run_id: format!("run-{}", &bootstrap.run_id[..32]),
            authority_session_id: format!(
                "session-{}",
                &format!("{:x}", Sha256::digest(bootstrap.session_id.as_bytes()))[..32]
            ),
            remote_authority_session_id: format!(
                "session-{}",
                &format!(
                    "{:x}",
                    Sha256::digest(format!("remote:{}", bootstrap.session_id).as_bytes())
                )[..32]
            ),
            issued: Arc::new(Mutex::new(None)),
            remote_issued: Arc::new(Mutex::new(None)),
        };
        let selected = Arc::new(Mutex::new(None));
        let adapter = ProductOpenCodeAdapter {
            dispatcher,
            selected: Arc::clone(&selected),
        };
        let device = AuthenticatedDeviceSession::new_local(
            LOCAL_RUN_PRINCIPAL_ALIAS.into(),
            LOCAL_RUN_DEVICE_ALIAS.into(),
            state.authority_run_id.clone(),
            state.authority_session_id.clone(),
            1,
            *bootstrap.command_authority_key,
        )
        .map_err(|_| ProductHostError)?;
        Ok(Self {
            state: state.clone(),
            authority: OwnedHostCommandAuthority::new(state, adapter, journal),
            device,
            selected,
            command_authority_key: bootstrap.command_authority_key.clone(),
            transport: CommandTransportAuthenticator::new(bootstrap.command_transport_key.clone()),
            execution,
        })
    }

    fn capability(&self) -> Result<OpenCodeCommandCapability, CommandProtocolError> {
        let _execution = self
            .execution
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?;
        let next_command_seq = self
            .authority
            .next_command_sequence(&self.device)
            .map_err(|error| map_connector_error(&error))?;
        let original = self
            .state
            .fresh_facts(None, next_command_seq)
            .map_err(|error| map_connector_error(&error))?;
        let capability = original
            .capability()
            .map_err(|_| CommandProtocolError::Unavailable)?;
        *self
            .state
            .issued
            .lock()
            .map_err(|_| CommandProtocolError::Internal)? = Some(IssuedCommandCapability {
            original,
            capability: capability.clone(),
        });
        Ok(capability)
    }

    fn execute(
        &self,
        request: ParsedProductCommand,
    ) -> Result<(HostCommandReceipt, u64, String), CommandProtocolError> {
        let snapshot_seq = request.snapshot_seq();
        let snapshot_digest = request.snapshot_digest().to_string();
        let _execution = self
            .execution
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?;
        let replay = self
            .authority
            .contains_request(request.request_id())
            .map_err(|error| map_connector_error(&error))?;
        if replay {
            return self
                .authority
                .execute_resolved_local(&self.device, request.into_resolved()?)
                .map(|receipt| (receipt, snapshot_seq, snapshot_digest))
                .map_err(|error| map_connector_error(&error));
        }
        let issued = self
            .state
            .issued
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?
            .clone()
            .ok_or(CommandProtocolError::Stale)?;
        let capability = &issued.capability;
        if request.capability_id() != capability.capability_id
            || request.command_seq() != capability.next_command_seq
            || request.snapshot_seq() != capability.snapshot_seq
            || request.snapshot_digest() != capability.snapshot_digest
            || request.issued_at() != capability.issued_at
            || request.expires_at() != capability.expires_at
        {
            return Err(CommandProtocolError::Stale);
        }
        let fresh = self
            .state
            .fresh_facts(Some(&issued.original), capability.next_command_seq)
            .map_err(|error| map_connector_error(&error))?;
        let command = issued
            .original
            .resolve_fresh(&fresh, capability, request.safe_command())
            .map_err(|_| CommandProtocolError::Stale)?;
        *self
            .selected
            .lock()
            .map_err(|_| CommandProtocolError::Internal)? =
            Some((request.request_id().to_string(), snapshot_seq, command));
        let resolved = request.into_resolved()?;
        let result = self
            .authority
            .execute_resolved_local(&self.device, resolved)
            .map_err(|error| map_connector_error(&error));
        if result.is_err() {
            self.selected
                .lock()
                .map_err(|_| CommandProtocolError::Internal)?
                .take();
        }
        result.map(|receipt| (receipt, snapshot_seq, snapshot_digest))
    }

    fn capability_remote_locked(
        &self,
        binding: &ActiveRemoteBinding,
    ) -> Result<OpenCodeCommandCapability, CommandProtocolError> {
        let device = self.remote_device_session(binding)?;
        let next_command_seq = self
            .authority
            .next_command_sequence(&device)
            .map_err(|error| map_connector_error(&error))?;
        let original = self
            .state
            .fresh_facts(None, next_command_seq)
            .map_err(|error| map_connector_error(&error))?;
        let capability = original
            .capability()
            .map_err(|_| CommandProtocolError::Unavailable)?;
        *self
            .state
            .remote_issued
            .lock()
            .map_err(|_| CommandProtocolError::Internal)? = Some(IssuedCommandCapability {
            original,
            capability: capability.clone(),
        });
        Ok(capability)
    }

    fn execute_remote_locked(
        &self,
        request: ParsedProductCommand,
        binding: &ActiveRemoteBinding,
    ) -> Result<(HostCommandReceipt, u64, String), CommandProtocolError> {
        let snapshot_seq = request.snapshot_seq();
        let snapshot_digest = request.snapshot_digest().to_owned();
        let device = self.remote_device_session(binding)?;
        let replay = self
            .authority
            .contains_request(request.request_id())
            .map_err(|error| map_connector_error(&error))?;
        if replay {
            return self
                .authority
                .execute_resolved_local(&device, request.into_resolved()?)
                .map(|receipt| (receipt, snapshot_seq, snapshot_digest))
                .map_err(|error| map_connector_error(&error));
        }
        let issued = self
            .state
            .remote_issued
            .lock()
            .map_err(|_| CommandProtocolError::Internal)?
            .clone()
            .ok_or(CommandProtocolError::Stale)?;
        let capability = &issued.capability;
        if request.capability_id() != capability.capability_id
            || request.command_seq() != capability.next_command_seq
            || request.snapshot_seq() != capability.snapshot_seq
            || request.snapshot_digest() != capability.snapshot_digest
            || request.issued_at() != capability.issued_at
            || request.expires_at() != capability.expires_at
        {
            return Err(CommandProtocolError::Stale);
        }
        let fresh = self
            .state
            .fresh_facts(Some(&issued.original), capability.next_command_seq)
            .map_err(|error| map_connector_error(&error))?;
        let command = issued
            .original
            .resolve_fresh(&fresh, capability, request.safe_command())
            .map_err(|_| CommandProtocolError::Stale)?;
        *self
            .selected
            .lock()
            .map_err(|_| CommandProtocolError::Internal)? =
            Some((request.request_id().to_owned(), snapshot_seq, command));
        let result = self
            .authority
            .execute_resolved_local(&device, request.into_resolved()?)
            .map_err(|error| map_connector_error(&error));
        if result.is_err() {
            self.selected
                .lock()
                .map_err(|_| CommandProtocolError::Internal)?
                .take();
        }
        result.map(|receipt| (receipt, snapshot_seq, snapshot_digest))
    }

    fn remote_device_session(
        &self,
        binding: &ActiveRemoteBinding,
    ) -> Result<AuthenticatedDeviceSession, CommandProtocolError> {
        let mut material = Vec::from(b"nomad.product-host.remote-command-key.v1\n".as_slice());
        material.extend_from_slice(binding.device_alias.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(binding.pairing_epoch.to_string().as_bytes());
        material.push(b'\n');
        material.extend_from_slice(&binding.device_signing_commitment);
        material.extend_from_slice(&binding.device_agreement_commitment);
        let command_key =
            crate::run_binding::hmac_sha256(self.command_authority_key.as_ref(), &material);
        material.zeroize();
        AuthenticatedDeviceSession::new_local(
            REMOTE_PAIRED_PRINCIPAL_ALIAS.into(),
            binding.device_alias.clone(),
            self.state.authority_run_id.clone(),
            self.state.remote_authority_session_id.clone(),
            binding.pairing_epoch,
            command_key,
        )
        .map_err(|_| CommandProtocolError::Internal)
    }
}

#[derive(Clone)]
struct RunProjectionBinding {
    run_id: Zeroizing<String>,
    workspace_binding_digest: String,
}

impl std::fmt::Debug for RunProjectionBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RunProjectionBinding(<redacted>)")
    }
}

impl RunProjectionBinding {
    fn new(run_id: String, workspace_binding_digest: String) -> Self {
        Self {
            run_id: Zeroizing::new(run_id),
            workspace_binding_digest,
        }
    }

    fn verify_workspace(&self, session_raw: &[u8]) -> Result<(), PollError> {
        let directory = stock_session_directory(session_raw).map_err(|_| PollError::Source)?;
        verify_workspace_binding(
            Path::new(directory.as_str()),
            &self.workspace_binding_digest,
        )
    }

    fn realias(&self, snapshot: &mut StockReadonlySnapshot) {
        snapshot.session_alias = scoped_alias(&self.run_id, "sess", &snapshot.session_alias);
        snapshot.pending_input_alias = snapshot
            .pending_input_alias
            .as_deref()
            .map(|alias| scoped_alias(&self.run_id, "input", alias));
        snapshot.pending_permission_alias = snapshot
            .pending_permission_alias
            .as_deref()
            .map(|alias| scoped_alias(&self.run_id, "permission", alias));
    }
}

#[derive(Clone)]
struct AgentProcessBinding {
    pid: u32,
    process_group: u32,
    identity: String,
}

impl std::fmt::Debug for AgentProcessBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AgentProcessBinding(<redacted>)")
    }
}

impl AgentProcessBinding {
    fn new(pid: u32, process_group: u32, identity: String) -> Result<Self, ProductHostError> {
        let binding = Self {
            pid,
            process_group,
            identity,
        };
        binding.verify().map_err(|_| ProductHostError)?;
        Ok(binding)
    }

    fn verify(&self) -> Result<(), PollError> {
        self.verify_before(None)
    }

    fn verify_before(&self, deadline: Option<Instant>) -> Result<(), PollError> {
        let pid = libc::pid_t::try_from(self.pid).map_err(|_| PollError::Process)?;
        if unsafe { libc::kill(pid, 0) } != 0
            || unsafe { libc::getpgid(pid) }
                != libc::pid_t::try_from(self.process_group).map_err(|_| PollError::Process)?
        {
            return Err(PollError::Process);
        }
        let pid_string = self.pid.to_string();
        let mut child = Command::new("/bin/ps")
            .args(["-p", &pid_string, "-o", "lstart=", "-o", "command="])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| PollError::Process)?;
        let stdout = bounded_child_stdout(
            &mut child,
            bounded_timeout(deadline, PROCESS_IDENTITY_TIMEOUT).ok_or(PollError::Process)?,
            MAX_PROCESS_IDENTITY_BYTES,
        )?;
        let measured = format!("{:x}", Sha256::digest(&stdout));
        if stdout.iter().any(|byte| !byte.is_ascii_whitespace()) && measured == self.identity {
            Ok(())
        } else {
            Err(PollError::Process)
        }
    }
}

fn bounded_child_stdout(
    child: &mut std::process::Child,
    timeout: Duration,
    maximum: usize,
) -> Result<Vec<u8>, PollError> {
    let mut stdout = child.stdout.take().ok_or(PollError::Process)?;
    if set_nonblocking(stdout.as_raw_fd()).is_err() {
        kill_and_reap(child);
        return Err(PollError::Process);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(PollError::Process)?;
    let mut output = Vec::new();
    let mut buffer = [0_u8; 512];
    let mut eof = false;
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => eof = true,
            Ok(count) => {
                output.extend_from_slice(&buffer[..count]);
                if output.len() > maximum {
                    kill_and_reap(child);
                    return Err(PollError::Process);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                kill_and_reap(child);
                return Err(PollError::Process);
            }
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => {
                kill_and_reap(child);
                return Err(PollError::Process);
            }
        };
        match status {
            Some(status) if eof && status.success() => return Ok(output),
            Some(_) if eof => return Err(PollError::Process),
            _ => {}
        }
        if Instant::now() >= deadline {
            kill_and_reap(child);
            return Err(PollError::Process);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn set_nonblocking(fd: RawFd) -> Result<(), PollError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(PollError::Process)
    } else {
        Ok(())
    }
}

fn kill_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl std::fmt::Debug for StockSnapshotClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StockSnapshotClient(<redacted>)")
    }
}

impl StockSnapshotClient {
    fn new(
        origin: &str,
        session_id: &str,
        password: Zeroizing<String>,
    ) -> Result<Self, ProductHostError> {
        let mut userinfo = Zeroizing::new(String::from("opencode:"));
        userinfo.push_str(password.as_str());
        let mut authorization = Zeroizing::new(String::from("Basic "));
        BASE64_STANDARD.encode_string(userinfo.as_bytes(), &mut authorization);
        drop(userinfo);
        drop(password);
        Ok(Self {
            origin: origin.trim_end_matches('/').into(),
            session_id: session_id.into(),
            authorization,
            agent: ureq::AgentBuilder::new()
                .try_proxy_from_env(false)
                .redirects(0)
                .timeout_connect(Duration::from_secs(2))
                .timeout_read(Duration::from_secs(5))
                .timeout_write(Duration::from_secs(5))
                .build(),
        })
    }

    fn poll_complete_batch(
        &self,
        process: &AgentProcessBinding,
        run_binding: &RunProjectionBinding,
        deadline: Option<Instant>,
    ) -> Result<StockReadonlySnapshot, PollError> {
        let second = stable_observation(
            || process.verify_before(deadline),
            || self.read_batch(deadline).map_err(|_| PollError::Source),
        )?;
        run_binding.verify_workspace(second.session.as_slice())?;
        project_stock_snapshot(
            &self.session_id,
            second.session.as_slice(),
            second.status.as_slice(),
            second.question.as_slice(),
            second.permission.as_slice(),
            second.diff.as_slice(),
        )
        .map_err(|_| PollError::Source)
    }

    fn command_batch(
        &self,
        process: &AgentProcessBinding,
        run_binding: &RunProjectionBinding,
    ) -> Result<(OpenCodeFiveRouteBatch, StockReadonlySnapshot), PollError> {
        process.verify()?;
        let first = self.read_batch(None).map_err(|_| PollError::Source)?;
        process.verify()?;
        let second = self.read_batch(None).map_err(|_| PollError::Source)?;
        process.verify()?;
        run_binding.verify_workspace(second.session.as_slice())?;
        let projected = project_stock_snapshot(
            &self.session_id,
            second.session.as_slice(),
            second.status.as_slice(),
            second.question.as_slice(),
            second.permission.as_slice(),
            second.diff.as_slice(),
        )
        .map_err(|_| PollError::Source)?;
        let batch = OpenCodeFiveRouteBatch::stable(
            [
                first.session.as_slice(),
                first.status.as_slice(),
                first.question.as_slice(),
                first.permission.as_slice(),
                first.diff.as_slice(),
            ],
            [
                second.session.as_slice(),
                second.status.as_slice(),
                second.question.as_slice(),
                second.permission.as_slice(),
                second.diff.as_slice(),
            ],
        )
        .map_err(|_| PollError::Source)?;
        Ok((batch, projected))
    }

    fn read_batch(&self, deadline: Option<Instant>) -> Result<RawSnapshotBatch, ProductHostError> {
        let session_path = format!("/session/{}", self.session_id);
        Ok(RawSnapshotBatch {
            session: Zeroizing::new(self.get(&session_path, deadline)?),
            status: Zeroizing::new(self.get("/session/status", deadline)?),
            question: Zeroizing::new(self.get("/question", deadline)?),
            permission: Zeroizing::new(self.get("/permission", deadline)?),
            diff: Zeroizing::new(self.get(&format!("{session_path}/diff"), deadline)?),
        })
    }

    fn get(&self, path: &str, deadline: Option<Instant>) -> Result<Vec<u8>, ProductHostError> {
        let request = self.agent.get(&format!("{}{path}", self.origin));
        let request = match deadline {
            Some(deadline) => request.timeout(
                bounded_timeout(Some(deadline), Duration::from_secs(5)).ok_or(ProductHostError)?,
            ),
            None => request,
        };
        let response = request
            .set("Authorization", self.authorization.as_str())
            .call()
            .map_err(|_| ProductHostError)?;
        if response.status() != 200
            || response
                .header("Content-Type")
                .and_then(|value| value.split(';').next())
                .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(ProductHostError);
        }
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_UPSTREAM_BODY + 1)
            .read_to_end(&mut body)
            .map_err(|_| ProductHostError)?;
        if body.is_empty() || body.len() as u64 > MAX_UPSTREAM_BODY {
            return Err(ProductHostError);
        }
        Ok(body)
    }
}

fn bounded_timeout(deadline: Option<Instant>, maximum: Duration) -> Option<Duration> {
    match deadline {
        Some(deadline) => deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| remaining.min(maximum)),
        None => Some(maximum),
    }
}

fn scoped_alias(run_id: &str, kind: &str, existing_alias: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(ALIAS_NAMESPACE);
    digest.update(run_id.as_bytes());
    digest.update(b"\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(existing_alias.as_bytes());
    format!("{kind}-{:x}", digest.finalize())
        .chars()
        .take(kind.len() + 1 + 32)
        .collect()
}

fn verify_workspace_binding(path: &Path, expected_digest: &str) -> Result<(), PollError> {
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(PollError::Binding);
    }
    let descriptor = open_directory_no_follow(path)?;
    let mut raw = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
        return Err(PollError::Binding);
    }
    let stat = unsafe { raw.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o022 != 0
    {
        return Err(PollError::Binding);
    }
    let canonical = path.canonicalize().map_err(|_| PollError::Binding)?;
    let canonical_text = canonical.to_str().ok_or(PollError::Binding)?;
    let observed = fs::metadata(&canonical).map_err(|_| PollError::Binding)?;
    if (observed.dev(), observed.ino()) != (stat.st_dev as u64, stat.st_ino) {
        return Err(PollError::Binding);
    }
    let material = format!("{}:{}:{}", canonical_text, stat.st_dev, stat.st_ino);
    let actual = format!("{:x}", Sha256::digest(material.as_bytes()));
    if actual == expected_digest {
        Ok(())
    } else {
        Err(PollError::Binding)
    }
}

fn open_directory_no_follow(path: &Path) -> Result<OwnedFd, PollError> {
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root < 0 {
        return Err(PollError::Binding);
    }
    let mut descriptor = unsafe { OwnedFd::from_raw_fd(root) };
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => {
                let name = CString::new(part.as_bytes()).map_err(|_| PollError::Binding)?;
                let next = unsafe {
                    libc::openat(
                        descriptor.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                if next < 0 {
                    return Err(PollError::Binding);
                }
                descriptor = unsafe { OwnedFd::from_raw_fd(next) };
            }
            _ => return Err(PollError::Binding),
        }
    }
    Ok(descriptor)
}

fn stable_observation<V, R>(
    mut verify_process: V,
    mut read_batch: R,
) -> Result<RawSnapshotBatch, PollError>
where
    V: FnMut() -> Result<(), PollError>,
    R: FnMut() -> Result<RawSnapshotBatch, PollError>,
{
    verify_process()?;
    let first = read_batch()?;
    verify_process()?;
    let second = read_batch()?;
    verify_process()?;
    if first == second {
        Ok(second)
    } else {
        Err(PollError::Source)
    }
}

#[derive(PartialEq, Eq)]
struct RawSnapshotBatch {
    session: Zeroizing<Vec<u8>>,
    status: Zeroizing<Vec<u8>>,
    question: Zeroizing<Vec<u8>>,
    permission: Zeroizing<Vec<u8>>,
    diff: Zeroizing<Vec<u8>>,
}

fn build_envelope(
    host_instance_id: &str,
    snapshot_seq: u64,
    snapshot: StockReadonlySnapshot,
) -> Result<ProductSnapshotEnvelope, ProductHostError> {
    let mut envelope = ProductSnapshotEnvelope {
        schema: SNAPSHOT_SCHEMA,
        host_instance_id: host_instance_id.into(),
        snapshot_seq,
        digest: String::new(),
        snapshot,
    };
    let mut value = serde_json::to_value(&envelope).map_err(|_| ProductHostError)?;
    value
        .as_object_mut()
        .ok_or(ProductHostError)?
        .remove("digest");
    let canonical = canonical_json(&value).map_err(|_| ProductHostError)?;
    envelope.digest = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    Ok(envelope)
}

fn serve_connection(
    mut stream: UnixStream,
    store: &ProductSnapshotStore,
    commands: &ProductCommandService,
    devices: &ProductDeviceRegistryService,
    pairing: Option<&ProductPairingService>,
    join_transport: Option<&CommandTransportAuthenticator>,
    remote_lifecycle: Option<&Arc<RemoteIngressLifecycle>>,
) -> Result<(), ProductHostError> {
    serve_connection_with_pairing_timeout(
        &mut stream,
        ProductRequestContext {
            store,
            commands: Some(commands),
            devices: Some(devices),
            pairing,
            join_transport,
            remote_lifecycle,
            long_poll_timeout: LONG_POLL_TIMEOUT,
        },
    )
}

struct ProductRequestContext<'a> {
    store: &'a ProductSnapshotStore,
    commands: Option<&'a ProductCommandService>,
    devices: Option<&'a ProductDeviceRegistryService>,
    pairing: Option<&'a ProductPairingService>,
    join_transport: Option<&'a CommandTransportAuthenticator>,
    remote_lifecycle: Option<&'a Arc<RemoteIngressLifecycle>>,
    long_poll_timeout: Duration,
}

#[cfg(test)]
fn serve_connection_with_timeout(
    stream: &mut UnixStream,
    store: &ProductSnapshotStore,
    commands: Option<&ProductCommandService>,
    devices: Option<&ProductDeviceRegistryService>,
    long_poll_timeout: Duration,
) -> Result<(), ProductHostError> {
    serve_connection_with_pairing_timeout(
        stream,
        ProductRequestContext {
            store,
            commands,
            devices,
            pairing: None,
            join_transport: None,
            remote_lifecycle: None,
            long_poll_timeout,
        },
    )
}

fn serve_connection_with_pairing_timeout(
    stream: &mut UnixStream,
    context: ProductRequestContext<'_>,
) -> Result<(), ProductHostError> {
    stream
        .set_read_timeout(Some(CLIENT_IO_TIMEOUT))
        .map_err(|_| ProductHostError)?;
    stream
        .set_write_timeout(Some(CLIENT_IO_TIMEOUT))
        .map_err(|_| ProductHostError)?;
    let request = match context.commands {
        Some(commands) => {
            match read_product_request(stream, &commands.transport, context.join_transport) {
                Ok(request) => request,
                Err(error) => {
                    return write_protocol_error(stream, error).map_err(|_| ProductHostError)
                }
            }
        }
        None => match read_request(stream) {
            Ok(Request::Current) => ProductHostRequest::ReadCurrent,
            Ok(Request::Stream(after)) => ProductHostRequest::ReadStream(after),
            Err(_) => return write_error(stream, 400, "INVALID_REQUEST"),
        },
    };
    let _remote_write_permit = if is_remote_mutation(&request) {
        match acquire_remote_write_permit(context.remote_lifecycle) {
            Ok(permit) => permit,
            Err(()) => {
                return write_error(stream, 503, "REMOTE_INGRESS_UNAVAILABLE");
            }
        }
    } else {
        None
    };
    match request {
        ProductHostRequest::ReadCurrent => match context.store.current_if_available()? {
            None => write_error(stream, 503, "SNAPSHOT_UNAVAILABLE"),
            Some(Err(_)) => write_error(stream, 503, "SNAPSHOT_SOURCE_OFFLINE"),
            Some(Ok(snapshot)) => write_json(stream, 200, &snapshot),
        },
        ProductHostRequest::ReadStream(after) => {
            match context.store.wait_after(after, context.long_poll_timeout)? {
                WaitResult::Snapshot(snapshot) => write_json(stream, 200, &snapshot),
                WaitResult::Timeout => write_empty(stream, 204),
                WaitResult::Conflict => write_error(stream, 409, "SNAPSHOT_SEQUENCE_CONFLICT"),
                WaitResult::Offline => write_error(stream, 503, "SNAPSHOT_SOURCE_OFFLINE"),
            }
        }
        ProductHostRequest::CommandCapability => {
            let commands = context.commands.ok_or(ProductHostError)?;
            match commands.capability() {
                Ok(capability) => {
                    write_capability(stream, &capability).map_err(|_| ProductHostError)
                }
                Err(error) => write_protocol_error(stream, error).map_err(|_| ProductHostError),
            }
        }
        ProductHostRequest::Command(request) => {
            let commands = context.commands.ok_or(ProductHostError)?;
            match commands.execute(*request) {
                Ok((receipt, seq, digest)) => {
                    write_receipt(stream, &receipt, seq, &digest).map_err(|_| ProductHostError)
                }
                Err(error) => write_protocol_error(stream, error).map_err(|_| ProductHostError),
            }
        }
        ProductHostRequest::DeviceCurrent => {
            let devices = context.devices.ok_or(ProductHostError)?;
            let current = match context.pairing {
                Some(pairing) => pairing.current().map(|binding| match binding {
                    Some(binding) => CurrentActiveDevice::Active(AuthenticatedDeviceFact {
                        principal_alias: REMOTE_REGISTRY_PRINCIPAL_ALIAS.into(),
                        device_alias: binding.device_alias,
                        pairing_epoch: binding.pairing_epoch,
                        signing_commitment: binding.device_signing_commitment,
                        agreement_commitment: binding.device_agreement_commitment,
                    }),
                    None => CurrentActiveDevice::Unpaired,
                }),
                None => devices
                    .current()
                    .map_err(|_| PairingCoordinatorError::Storage),
            };
            match current {
                Ok(current) => write_device_current(stream, devices.principal_alias(), &current)
                    .map_err(|_| ProductHostError),
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            }
        }
        ProductHostRequest::DevicePairingChallenge(request) => {
            let devices = context.devices.ok_or(ProductHostError)?;
            match devices.begin_pairing(*request) {
                Ok(challenge) => {
                    write_pairing_challenge(stream, devices.principal_alias(), &challenge)
                        .map_err(|_| ProductHostError)
                }
                Err(error) => write_protocol_error(stream, error).map_err(|_| ProductHostError),
            }
        }
        ProductHostRequest::DevicePairingConfirm(request) => {
            let devices = context.devices.ok_or(ProductHostError)?;
            match devices.confirm_pairing(*request) {
                Ok(fact) => write_pairing_confirm(stream, devices.principal_alias(), &fact)
                    .map_err(|_| ProductHostError),
                Err(error) => write_protocol_error(stream, error).map_err(|_| ProductHostError),
            }
        }
        ProductHostRequest::DeviceRevoke(request) => {
            let devices = context.devices.ok_or(ProductHostError)?;
            let device_alias = request.device_alias().to_string();
            let outcome = match context.pairing {
                Some(pairing) => pairing.revoke(&request),
                None => devices
                    .revoke(*request)
                    .map_err(|_| PairingCoordinatorError::Storage),
            };
            match outcome {
                Ok(outcome) => {
                    write_revoke(stream, devices.principal_alias(), &device_alias, outcome)
                        .map_err(|_| ProductHostError)
                }
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            }
        }
        ProductHostRequest::PairingCreate => match context.pairing {
            Some(pairing) => match pairing.create() {
                Ok(created) => {
                    write_pairing_created(stream, &created).map_err(|_| ProductHostError)
                }
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingApprove(request) => match context.pairing {
            Some(pairing) => match pairing.approve(*request) {
                Ok(()) => write_no_content(stream).map_err(|_| ProductHostError),
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingCancel(request) => match context.pairing {
            Some(pairing) => match pairing.cancel(*request) {
                Ok(()) => write_no_content(stream).map_err(|_| ProductHostError),
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingStatus(request) => match context.pairing {
            Some(pairing) => match pairing.status(*request) {
                Ok(status) => write_pairing_status(stream, &status).map_err(|_| ProductHostError),
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingStart(request) => match context.pairing {
            Some(pairing) => match pairing.start(*request) {
                Ok(started) => {
                    write_pairing_started(stream, &started).map_err(|_| ProductHostError)
                }
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingConfirm(request) => match context.pairing {
            Some(pairing) => match pairing.confirm(*request) {
                Ok(bundle) => {
                    write_pairing_confirmed(stream, &bundle).map_err(|_| ProductHostError)
                }
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingComplete(request) => match context.pairing {
            Some(pairing) => match pairing.complete(*request) {
                Ok(binding) => {
                    write_pairing_completed(stream, &binding).map_err(|_| ProductHostError)
                }
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
        ProductHostRequest::PairingAbort(request) => match context.pairing {
            Some(pairing) => match pairing.abort(*request) {
                Ok(()) => write_no_content(stream).map_err(|_| ProductHostError),
                Err(error) => write_pairing_error(stream, error).map_err(|_| ProductHostError),
            },
            None => write_pairing_error(stream, PairingCoordinatorError::Relay)
                .map_err(|_| ProductHostError),
        },
    }
}

fn is_remote_mutation(request: &ProductHostRequest) -> bool {
    matches!(
        request,
        ProductHostRequest::DevicePairingChallenge(_)
            | ProductHostRequest::DevicePairingConfirm(_)
            | ProductHostRequest::DeviceRevoke(_)
            | ProductHostRequest::PairingCreate
            | ProductHostRequest::PairingApprove(_)
            | ProductHostRequest::PairingCancel(_)
            | ProductHostRequest::PairingStart(_)
            | ProductHostRequest::PairingConfirm(_)
            | ProductHostRequest::PairingComplete(_)
            | ProductHostRequest::PairingAbort(_)
    )
}

fn acquire_remote_write_permit(
    lifecycle: Option<&Arc<RemoteIngressLifecycle>>,
) -> Result<Option<RemoteWritePermit>, ()> {
    let permit = lifecycle
        .map(|lifecycle| lifecycle.acquire_write_permit().map_err(|_| ()))
        .transpose()?;
    if permit.as_ref().is_some_and(|permit| !permit.is_current()) {
        return Err(());
    }
    Ok(permit)
}

fn map_device_authority_error(error: DeviceAuthorityError) -> CommandProtocolError {
    match error {
        DeviceAuthorityError::InvalidInput | DeviceAuthorityError::InvalidProof => {
            CommandProtocolError::InvalidRequest
        }
        DeviceAuthorityError::ChallengeExpired
        | DeviceAuthorityError::ChallengeConsumed
        | DeviceAuthorityError::Conflict
        | DeviceAuthorityError::EpochMismatch
        | DeviceAuthorityError::Unpaired => CommandProtocolError::Stale,
        DeviceAuthorityError::Safety | DeviceAuthorityError::Storage => {
            CommandProtocolError::Unavailable
        }
    }
}

enum Request {
    Current,
    Stream(u64),
}

fn read_request(stream: &mut UnixStream) -> Result<Request, ProductHostError> {
    let mut raw = Vec::new();
    let mut byte = [0_u8; 1];
    while raw.len() < MAX_REQUEST_HEAD {
        if stream.read(&mut byte).map_err(|_| ProductHostError)? == 0 {
            return Err(ProductHostError);
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !raw.ends_with(b"\r\n\r\n")
        || raw
            .iter()
            .any(|byte| !matches!(*byte, b'\r' | b'\n' | b' '..=b'~'))
    {
        return Err(ProductHostError);
    }
    let head = std::str::from_utf8(&raw).map_err(|_| ProductHostError)?;
    let mut lines = head[..head.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(ProductHostError)?;
    let mut parts = request_line.split(' ');
    if parts.next() != Some("GET") || parts.clone().count() != 2 {
        return Err(ProductHostError);
    }
    let target = parts.next().ok_or(ProductHostError)?;
    if parts.next() != Some("HTTP/1.1") {
        return Err(ProductHostError);
    }
    let mut host_seen = false;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(ProductHostError);
        }
        let (name, value) = line.split_once(':').ok_or(ProductHostError)?;
        let lower = name.to_ascii_lowercase();
        let value = value.trim_matches(' ');
        match lower.as_str() {
            "host" if !host_seen && !value.is_empty() => host_seen = true,
            "connection" if value.eq_ignore_ascii_case("close") => {}
            "accept" if value == "application/json" || value == "*/*" => {}
            _ => return Err(ProductHostError),
        }
    }
    if !host_seen {
        return Err(ProductHostError);
    }
    if target == CURRENT_ROUTE {
        return Ok(Request::Current);
    }
    let raw_after = target.strip_prefix(STREAM_ROUTE).ok_or(ProductHostError)?;
    if raw_after.is_empty() || !raw_after.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProductHostError);
    }
    let after = raw_after.parse::<u64>().map_err(|_| ProductHostError)?;
    Ok(Request::Stream(after))
}

fn write_json<T: Serialize>(
    stream: &mut UnixStream,
    status: u16,
    value: &T,
) -> Result<(), ProductHostError> {
    let body = serde_json::to_vec(value).map_err(|_| ProductHostError)?;
    write_response(stream, status, "application/json", &body)
}

fn write_error(
    stream: &mut UnixStream,
    status: u16,
    code: &'static str,
) -> Result<(), ProductHostError> {
    write_json(
        stream,
        status,
        &json!({"schema": ERROR_SCHEMA, "code": code}),
    )
}

fn write_empty(stream: &mut UnixStream, status: u16) -> Result<(), ProductHostError> {
    write_response(stream, status, "application/json", &[])
}

fn write_response(
    stream: &mut UnixStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), ProductHostError> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => return Err(ProductHostError),
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|_| ProductHostError)
}

fn validate_and_prepare_socket_path(path: &Path) -> Result<(), ProductHostError> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 100
        || path.file_name().and_then(|name| name.to_str()) != Some("product-host.sock")
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(ProductHostError);
    }
    reject_symlink_components(path.parent().ok_or(ProductHostError)?)?;
    let parent = fs::symlink_metadata(path.parent().ok_or(ProductHostError)?)
        .map_err(|_| ProductHostError)?;
    if !parent.is_dir()
        || parent.file_type().is_symlink()
        || parent.uid() != unsafe { libc::geteuid() }
        || parent.mode() & 0o7777 != 0o700
        || path
            .parent()
            .ok_or(ProductHostError)?
            .canonicalize()
            .map_err(|_| ProductHostError)?
            != path.parent().ok_or(ProductHostError)?
    {
        return Err(ProductHostError);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(ProductHostError),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ProductHostError),
    }
    Ok(())
}

fn parent_identity(path: &Path) -> Result<(u64, u64), ProductHostError> {
    let parent = fs::symlink_metadata(path.parent().ok_or(ProductHostError)?)
        .map_err(|_| ProductHostError)?;
    if parent.is_dir()
        && !parent.file_type().is_symlink()
        && parent.uid() == unsafe { libc::geteuid() }
        && parent.mode() & 0o7777 == 0o700
    {
        Ok((parent.dev(), parent.ino()))
    } else {
        Err(ProductHostError)
    }
}

fn reject_symlink_components(path: &Path) -> Result<(), ProductHostError> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => return Err(ProductHostError),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| ProductHostError)?;
        if metadata.file_type().is_symlink() {
            return Err(ProductHostError);
        }
    }
    Ok(())
}

fn validate_bound_socket(path: &Path) -> Result<(u64, u64), ProductHostError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProductHostError)?;
    if metadata.file_type().is_socket()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
    {
        Ok((metadata.dev(), metadata.ino()))
    } else {
        Err(ProductHostError)
    }
}

fn verify_peer_uid(stream: &UnixStream) -> Result<(), ProductHostError> {
    #[cfg(target_os = "macos")]
    unsafe {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        if libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0
            && peer_uid_allowed(uid, libc::geteuid())
        {
            Ok(())
        } else {
            Err(ProductHostError)
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut credentials: libc::ucred = std::mem::zeroed();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        ) == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && peer_uid_allowed(credentials.uid, libc::geteuid())
        {
            Ok(())
        } else {
            Err(ProductHostError)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = stream;
        Err(ProductHostError)
    }
}

fn peer_uid_allowed(peer_uid: libc::uid_t, effective_uid: libc::uid_t) -> bool {
    peer_uid == effective_uid
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing_coordinator::{
        HostPairingIdentity, MemoryJoinSessionStore, RelayProvisionRequest, RelayProvisioner,
        SignedProvisioningBundle,
    };
    use crate::remote_application::GatewayCommand;
    use hkdf::Hkdf;
    use p256::{
        ecdh::diffie_hellman,
        ecdsa::{signature::Signer, SigningKey, VerifyingKey},
        elliptic_curve::sec1::ToEncodedPoint,
        PublicKey, SecretKey,
    };
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicUsize;

    fn receipt_from_disposition(disposition: RemoteCommandDisposition) -> RemoteCommandReceipt {
        match disposition {
            RemoteCommandDisposition::Receipt(receipt) => receipt,
            other => panic!("expected receipt disposition, got {other:?}"),
        }
    }

    fn assert_rejection(
        disposition: RemoteCommandDisposition,
        status: RemoteReceiptStatus,
        code: &str,
    ) {
        let receipt = receipt_from_disposition(disposition);
        assert_eq!(receipt.schema, "nomad.gateway.command-receipt.v1");
        assert_eq!(receipt.status, status);
        assert_eq!(receipt.error_code.0, code);
        assert!(!receipt.idempotent_replay);
        assert!(receipt.receipt_id.starts_with("rcpt_"));
        assert!(OffsetDateTime::parse(
            &receipt.accepted_at,
            &time::format_description::well_known::Rfc3339
        )
        .is_ok());
    }

    struct ProductPairingTestIdentity {
        signing: SigningKey,
        agreement: SecretKey,
    }

    impl ProductPairingTestIdentity {
        fn new() -> Self {
            Self {
                signing: SigningKey::from_bytes((&[71_u8; 32]).into()).unwrap(),
                agreement: SecretKey::from_slice(&[72_u8; 32]).unwrap(),
            }
        }
    }

    impl HostPairingIdentity for ProductPairingTestIdentity {
        fn signing_public_sec1(&self) -> [u8; 65] {
            signing_public_bytes(&self.signing)
        }

        fn agreement_public_sec1(&self) -> [u8; 65] {
            agreement_public_bytes(&self.agreement)
        }

        fn signing_commitment(&self) -> [u8; 32] {
            Sha256::digest(self.signing_public_sec1()).into()
        }

        fn agreement_commitment(&self) -> [u8; 32] {
            Sha256::digest(self.agreement_public_sec1()).into()
        }

        fn sign_p1363(&self, message: &[u8]) -> Result<[u8; 64], PairingCoordinatorError> {
            let signature: p256::ecdsa::Signature = self.signing.sign(message);
            Ok(signature.to_bytes().into())
        }

        fn derive_agreement_shared(
            &self,
            peer_public_sec1: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>, PairingCoordinatorError> {
            let peer = PublicKey::from_sec1_bytes(peer_public_sec1)
                .map_err(|_| PairingCoordinatorError::Invalid)?;
            let shared = diffie_hellman(self.agreement.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(
                shared
                    .raw_secret_bytes()
                    .as_slice()
                    .try_into()
                    .map_err(|_| PairingCoordinatorError::Crypto)?,
            ))
        }
    }

    #[derive(Default)]
    struct ProductPairingTestRelay {
        provisions: Mutex<Vec<RelayProvisionRequest>>,
        revocations: Mutex<Vec<String>>,
    }

    impl RelayProvisioner for ProductPairingTestRelay {
        fn provision(
            &self,
            request: &RelayProvisionRequest,
        ) -> Result<(), PairingCoordinatorError> {
            self.provisions.lock().unwrap().push(request.clone());
            Ok(())
        }

        fn revoke(
            &self,
            mailbox_id: &str,
            _host_bearer: &str,
        ) -> Result<(), PairingCoordinatorError> {
            self.revocations.lock().unwrap().push(mailbox_id.to_owned());
            Ok(())
        }
    }

    struct FakeOpenCode {
        origin: String,
        question: Arc<Mutex<Option<String>>>,
        permission: Arc<Mutex<Option<String>>>,
        busy: Arc<AtomicBool>,
        posts: Arc<AtomicUsize>,
        outcome_unknown: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        address: std::net::SocketAddr,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl FakeOpenCode {
        fn start(workspace: &Path) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let question = Arc::new(Mutex::new(Some("que_secret".to_string())));
            let permission = Arc::new(Mutex::new(None));
            let busy = Arc::new(AtomicBool::new(true));
            let posts = Arc::new(AtomicUsize::new(0));
            let outcome_unknown = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let worker_question = Arc::clone(&question);
            let worker_permission = Arc::clone(&permission);
            let worker_busy = Arc::clone(&busy);
            let worker_posts = Arc::clone(&posts);
            let worker_outcome_unknown = Arc::clone(&outcome_unknown);
            let worker_stop = Arc::clone(&stop);
            let directory = workspace.to_string_lossy().into_owned();
            let worker = thread::spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            serve_fake_opencode(
                                &mut stream,
                                &directory,
                                &worker_question,
                                &worker_permission,
                                &worker_busy,
                                &worker_posts,
                                &worker_outcome_unknown,
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => return,
                    }
                }
            });
            Self {
                origin: format!("http://{address}"),
                question,
                permission,
                busy,
                posts,
                outcome_unknown,
                stop,
                address,
                worker: Some(worker),
            }
        }
    }

    impl Drop for FakeOpenCode {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn serve_fake_opencode(
        stream: &mut TcpStream,
        workspace: &str,
        question: &Mutex<Option<String>>,
        permission: &Mutex<Option<String>>,
        busy: &AtomicBool,
        posts: &AtomicUsize,
        outcome_unknown: &AtomicBool,
    ) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut raw = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = match stream.read(&mut buffer) {
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            };
            if count == 0 {
                return;
            }
            raw.extend_from_slice(&buffer[..count]);
        }
        let end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let head = std::str::from_utf8(&raw[..end]).unwrap();
        let request_line = head.lines().next().unwrap();
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap().to_string();
        let path = parts.next().unwrap().to_string();
        let content_length = head
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .or_else(|| line.strip_prefix("content-length: "))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while raw.len() < end + content_length {
            let count = match stream.read(&mut buffer) {
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            };
            if count == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..count]);
        }
        let body = match (method.as_str(), path.as_str()) {
            ("GET", "/session/ses_secret") => format!(
                r#"{{"id":"ses_secret","slug":"s","projectID":"p","directory":{},"title":"t","version":"1.18.16","time":{{"created":1,"updated":2}}}}"#,
                serde_json::to_string(workspace).unwrap()
            ),
            ("GET", "/session/status") if busy.load(Ordering::Acquire) => {
                r#"{"ses_secret":{"type":"busy"}}"#.into()
            }
            ("GET", "/session/status") => "{}".into(),
            ("GET", "/question") => match question.lock().unwrap().as_deref() {
                Some(question) => format!(
                    r#"[{{"id":{},"sessionID":"ses_secret","questions":[{{"question":"private","header":"private","options":[]}}],"tool":{{"messageID":"msg_secret","callID":"call_secret"}}}}]"#,
                    serde_json::to_string(question).unwrap()
                ),
                None => "[]".into(),
            },
            ("GET", "/permission") => match permission.lock().unwrap().as_deref() {
                Some(permission) => format!(
                    r#"[{{"id":{},"sessionID":"ses_secret","permission":"bash","patterns":["safe"],"metadata":{{}},"always":false,"tool":{{"messageID":"msg_secret","callID":"call_secret"}}}}]"#,
                    serde_json::to_string(permission).unwrap()
                ),
                None => "[]".into(),
            },
            ("GET", "/session/ses_secret/diff") => "[]".into(),
            ("POST", path)
                if path.starts_with("/api/session/ses_secret/question/")
                    && path.ends_with("/reply") =>
            {
                posts.fetch_add(1, Ordering::AcqRel);
                if outcome_unknown.load(Ordering::Acquire) {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                        .unwrap();
                    return;
                }
                "{}".into()
            }
            _ => {
                let response = b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
                stream.write_all(response).unwrap();
                return;
            }
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    fn snapshot(state: &str) -> StockReadonlySnapshot {
        StockReadonlySnapshot {
            session_alias: "sess-0123456789abcdef0123456789abcdef".into(),
            updated_at: "2026-08-25T00:00:00.000Z".into(),
            turn_state: state.into(),
            pending_input_alias: None,
            pending_permission_alias: None,
            diff_file_count: 0,
            writable: false,
            evidence_class: crate::stock_snapshot::STOCK_SNAPSHOT_EVIDENCE_CLASS,
        }
    }

    struct CommandFixture {
        _temporary: tempfile::TempDir,
        upstream: FakeOpenCode,
        service: Arc<ProductCommandService>,
        devices: Arc<ProductDeviceRegistryService>,
    }

    fn command_fixture() -> CommandFixture {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let upstream = FakeOpenCode::start(&workspace);
        let workspace_metadata = fs::metadata(&workspace).unwrap();
        let workspace_digest = format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}:{}",
                    workspace.to_string_lossy(),
                    workspace_metadata.dev(),
                    workspace_metadata.ino()
                )
                .as_bytes()
            )
        );
        let run_id = "a".repeat(64);
        let run_binding = RunProjectionBinding::new(run_id.clone(), workspace_digest);
        let process = AgentProcessBinding {
            pid: std::process::id(),
            process_group: unsafe { libc::getpgid(0) } as u32,
            identity: process_identity_for_test(std::process::id()),
        };
        let client = Arc::new(
            StockSnapshotClient::new(
                &upstream.origin,
                "ses_secret",
                Zeroizing::new("secret".into()),
            )
            .unwrap(),
        );
        let store = Arc::new(ProductSnapshotStore::with_host_instance_id(
            "host-0123456789abcdef0123456789abcdef",
        ));
        let mut projected = client
            .poll_complete_batch(&process, &run_binding, None)
            .unwrap();
        run_binding.realias(&mut projected);
        store.commit(projected).unwrap();
        let bootstrap = HostBootstrap {
            run_id,
            origin: upstream.origin.clone(),
            session_id: "ses_secret".into(),
            server_password: Zeroizing::new("secret".into()),
            workspace_binding_digest: "unused".into(),
            product_host_socket_path: root.join("product-host.sock"),
            agent_pid: process.pid,
            agent_process_group: process.process_group,
            agent_process_identity: process.identity.clone(),
            product_host_socket_parent_dev: 1,
            product_host_socket_parent_ino: 1,
            command_transport_key: Zeroizing::new([7; 32]),
            command_authority_key: Zeroizing::new([9; 32]),
            command_journal_path: root.join("command.sqlite3"),
            device_registry_path: root.join("host-device-registry.sqlite3"),
        };
        let dispatcher =
            OpenCodeCommandDispatcher::for_test(&upstream.origin, Zeroizing::new("secret".into()))
                .unwrap();
        let device_registry_path = root.join("host-device-registry.sqlite3");
        let device_command_gate = Arc::new(DeviceCommandGate::new());
        let service = Arc::new(
            ProductCommandService::new_with_dispatcher(
                client,
                process,
                run_binding,
                store,
                &bootstrap,
                dispatcher,
                Arc::clone(&device_command_gate),
            )
            .unwrap(),
        );
        let devices = Arc::new(
            ProductDeviceRegistryService::open(
                &device_registry_path,
                REMOTE_PAIRED_PRINCIPAL_ALIAS,
                REMOTE_REGISTRY_PRINCIPAL_ALIAS,
                device_command_gate,
            )
            .unwrap(),
        );
        CommandFixture {
            _temporary: temporary,
            upstream,
            service,
            devices,
        }
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn agreement_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn signing_public_bytes(key: &SigningKey) -> [u8; 65] {
        VerifyingKey::from(key)
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn agreement_public_bytes(key: &SecretKey) -> [u8; 65] {
        key.public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn device_public_key_digest(public_key: &[u8]) -> [u8; 32] {
        let material = crate::run_binding::canonical(&[
            b"nomad.device-authority.public-key-digest.v2",
            public_key,
        ]);
        Sha256::digest(material).into()
    }

    fn device_alias_for_test(signing_public_key: &[u8], agreement_public_key: &[u8]) -> String {
        let signing_commitment = device_public_key_digest(signing_public_key);
        let agreement_commitment = device_public_key_digest(agreement_public_key);
        let material = crate::run_binding::canonical(&[
            b"nomad.device-authority.device-alias.v2",
            b"device",
            &signing_commitment,
            &agreement_commitment,
        ]);
        let digest = Sha256::digest(material);
        let digest_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("device-{}", &digest_hex[..32])
    }

    struct PairingTranscriptTestInput<'a> {
        challenge: &'a [u8],
        signing_public_key: &'a [u8],
        agreement_public_key: &'a [u8],
        principal_alias: &'a str,
        device_alias: &'a str,
        prospective_epoch: u64,
        issued_at_unix: i64,
        expires_at_unix: i64,
    }

    fn pairing_transcript_for_test(input: PairingTranscriptTestInput<'_>) -> Vec<u8> {
        let signing_digest = device_public_key_digest(input.signing_public_key);
        let agreement_digest = device_public_key_digest(input.agreement_public_key);
        crate::run_binding::canonical(&[
            b"nomad.device-authority.pairing.v2",
            input.challenge,
            &signing_digest,
            &agreement_digest,
            input.principal_alias.as_bytes(),
            input.device_alias.as_bytes(),
            &input.prospective_epoch.to_be_bytes(),
            &input.issued_at_unix.to_be_bytes(),
            &input.expires_at_unix.to_be_bytes(),
        ])
    }

    fn signed_request_with_key(
        key: &[u8; 32],
        method: &str,
        path: &str,
        body: &[u8],
        nonce: &str,
    ) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let digest = format!("{:x}", Sha256::digest(body));
        let material =
            format!("nomad.product-host.transport.v1\n{method}\n{path}\n{now}\n{nonce}\n{digest}");
        let mac = crate::run_binding::hmac_sha256(key, material.as_bytes());
        let mac: String = mac.iter().map(|byte| format!("{byte:02x}")).collect();
        let content = if method == "POST" {
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
        } else {
            String::new()
        };
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n{content}X-Nomad-Transport-Time: {now}\r\nX-Nomad-Transport-Nonce: {nonce}\r\nX-Nomad-Transport-Mac: {mac}\r\n\r\n"
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    fn admin_signed_request(method: &str, path: &str, body: &[u8], nonce: &str) -> Vec<u8> {
        signed_request_with_key(&[7; 32], method, path, body, nonce)
    }

    fn serve_admin_once(
        fixture: &CommandFixture,
        request: &[u8],
    ) -> Result<String, ProductHostError> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        serve_connection_with_timeout(
            &mut server,
            &fixture.service.state.store,
            Some(&fixture.service),
            Some(&fixture.devices),
            Duration::ZERO,
        )?;
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        Ok(response)
    }

    fn serve_pairing_once(
        fixture: &CommandFixture,
        pairing: Option<&ProductPairingService>,
        request: &[u8],
    ) -> Result<String, ProductHostError> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        serve_connection_with_pairing_timeout(
            &mut server,
            ProductRequestContext {
                store: &fixture.service.state.store,
                commands: Some(&fixture.service),
                devices: Some(&fixture.devices),
                pairing,
                join_transport: pairing.map(|_| &fixture.service.transport),
                remote_lifecycle: None,
                long_poll_timeout: Duration::ZERO,
            },
        )?;
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        Ok(response)
    }

    fn serve_pairing_with_lifecycle_once(
        fixture: &CommandFixture,
        pairing: Option<&ProductPairingService>,
        lifecycle: Option<&Arc<RemoteIngressLifecycle>>,
        request: &[u8],
    ) -> Result<String, ProductHostError> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        serve_connection_with_pairing_timeout(
            &mut server,
            ProductRequestContext {
                store: &fixture.service.state.store,
                commands: Some(&fixture.service),
                devices: Some(&fixture.devices),
                pairing,
                join_transport: pairing.map(|_| &fixture.service.transport),
                remote_lifecycle: lifecycle,
                long_poll_timeout: Duration::ZERO,
            },
        )?;
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        Ok(response)
    }

    fn serve_pairing_with_join_auth(
        fixture: &CommandFixture,
        pairing: &ProductPairingService,
        join_transport: &CommandTransportAuthenticator,
        request: &[u8],
    ) -> Result<String, ProductHostError> {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        serve_connection_with_pairing_timeout(
            &mut server,
            ProductRequestContext {
                store: &fixture.service.state.store,
                commands: Some(&fixture.service),
                devices: Some(&fixture.devices),
                pairing: Some(pairing),
                join_transport: Some(join_transport),
                remote_lifecycle: None,
                long_poll_timeout: Duration::ZERO,
            },
        )?;
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        Ok(response)
    }

    fn response_json(response: &str) -> Value {
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
    }

    fn product_pairing_service(
        fixture: &CommandFixture,
    ) -> (
        ProductPairingService,
        Arc<ProductPairingTestIdentity>,
        Arc<ProductPairingTestRelay>,
    ) {
        let identity = Arc::new(ProductPairingTestIdentity::new());
        let relay = Arc::new(ProductPairingTestRelay::default());
        let coordinator = Arc::new(
            PairingCoordinator::new(
                Arc::clone(&fixture.devices.gate),
                fixture.devices.authority.clone(),
                identity.clone(),
                relay.clone(),
                Arc::new(MemoryJoinSessionStore::default()),
                "https://relay.example/v2".into(),
            )
            .unwrap(),
        );
        (ProductPairingService { coordinator }, identity, relay)
    }

    fn m3e_transcript(
        join_id: &str,
        challenge_id: &str,
        challenge: &[u8],
        epoch: u64,
        identity: &ProductPairingTestIdentity,
        device_signing_public: &[u8],
        device_agreement_public: &[u8],
    ) -> [u8; 32] {
        let mut bytes = Vec::from(b"nomad.m3e.pairing.v1\n".as_slice());
        for part in [
            join_id.as_bytes(),
            challenge_id.as_bytes(),
            format!("{:x}", Sha256::digest(challenge)).as_bytes(),
            epoch.to_string().as_bytes(),
            format!("{:x}", Sha256::digest(identity.signing_public_sec1())).as_bytes(),
            format!("{:x}", Sha256::digest(identity.agreement_public_sec1())).as_bytes(),
            format!("{:x}", Sha256::digest(device_signing_public)).as_bytes(),
            format!("{:x}", Sha256::digest(device_agreement_public)).as_bytes(),
        ] {
            bytes.extend_from_slice(part);
            bytes.push(b'\n');
        }
        bytes.pop();
        Sha256::digest(bytes).into()
    }

    fn m3e_proofs(
        transcript: &[u8; 32],
        identity: &ProductPairingTestIdentity,
        signing: &SigningKey,
        agreement: &SecretKey,
    ) -> ([u8; 64], [u8; 32]) {
        let mut sign_material = Vec::from(b"nomad.m3e.signing-proof.v1\n".as_slice());
        sign_material.extend_from_slice(transcript);
        let signature: p256::ecdsa::Signature = signing.sign(&Sha256::digest(sign_material));
        let host_public = PublicKey::from_sec1_bytes(&identity.agreement_public_sec1()).unwrap();
        let shared = diffie_hellman(agreement.to_nonzero_scalar(), host_public.as_affine());
        let mut agreement_key = [0_u8; 32];
        Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_slice())
            .expand(b"nomad.m3e.agreement-proof.v1", &mut agreement_key)
            .unwrap();
        (
            signature.to_bytes().into(),
            crate::run_binding::hmac_sha256(&agreement_key, transcript),
        )
    }

    fn pairing_post(
        fixture: &CommandFixture,
        pairing: Option<&ProductPairingService>,
        path: &str,
        value: Value,
        nonce: &str,
    ) -> String {
        let body = canonical_json(&value).unwrap();
        serve_pairing_once(
            fixture,
            pairing,
            &admin_signed_request("POST", path, body.as_bytes(), nonce),
        )
        .unwrap()
    }

    fn activate_remote_binding(
        pairing: &ProductPairingService,
        identity: &ProductPairingTestIdentity,
        signing: &SigningKey,
        agreement: &SecretKey,
    ) -> ActiveRemoteBinding {
        let now = OffsetDateTime::now_utc();
        let created = pairing.coordinator.create_join(now).unwrap();
        let signing_public = signing_public_bytes(signing);
        let agreement_public = agreement_public_bytes(agreement);
        let started = pairing
            .coordinator
            .start_join(
                &created.join_id,
                &created.join_secret,
                &signing_public,
                &agreement_public,
                now,
            )
            .unwrap();
        pairing
            .coordinator
            .approve_join(
                &created.join_id,
                &started.challenge_id,
                started.prospective_epoch,
                &started.comparison_code,
                now,
            )
            .unwrap();
        let transcript = m3e_transcript(
            &created.join_id,
            &started.challenge_id,
            &started.challenge_bytes,
            started.prospective_epoch,
            identity,
            &signing_public,
            &agreement_public,
        );
        let (signature, agreement_mac) = m3e_proofs(&transcript, identity, signing, agreement);
        let bundle = pairing
            .coordinator
            .confirm_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &signature,
                &agreement_mac,
                now,
            )
            .unwrap();
        let canonical = canonical_json(&serde_json::to_value(&bundle).unwrap()).unwrap();
        let mut material = Vec::from(b"nomad.m3e.vault-commit.v1\n".as_slice());
        material.extend_from_slice(&Sha256::digest(canonical));
        let vault_signature: p256::ecdsa::Signature = signing.sign(&Sha256::digest(material));
        pairing
            .coordinator
            .complete_join(
                &started.cookie_capability,
                &started.challenge_id,
                started.prospective_epoch,
                &vault_signature.to_bytes(),
                now,
            )
            .unwrap()
    }

    fn process_identity_for_test(pid: u32) -> String {
        let output = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart=", "-o", "command="])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .output()
            .unwrap();
        format!("{:x}", Sha256::digest(output.stdout))
    }

    fn reply_request(
        capability: &OpenCodeCommandCapability,
        request_id: &str,
        nonce: &str,
    ) -> ParsedProductCommand {
        let reply = capability.reply.as_ref().unwrap();
        ParsedProductCommand::reply_for_test(
            capability.capability_id.clone(),
            request_id.into(),
            nonce.into(),
            capability.next_command_seq,
            capability.snapshot_seq,
            capability.snapshot_digest.clone(),
            capability.issued_at.clone(),
            capability.expires_at.clone(),
            reply.turn_alias.clone(),
            reply.input_alias.clone(),
            "mechanical reply".into(),
        )
    }

    fn refresh_fixture_snapshot(fixture: &CommandFixture) {
        let mut snapshot = fixture
            .service
            .state
            .client
            .poll_complete_batch(
                &fixture.service.state.process,
                &fixture.service.state.run_binding,
                None,
            )
            .unwrap();
        fixture.service.state.run_binding.realias(&mut snapshot);
        fixture.service.state.store.commit(snapshot).unwrap();
    }

    #[test]
    fn issued_capability_get_then_post_dispatches_and_exact_replay_is_one_call() {
        let fixture = command_fixture();
        let capability = fixture.service.capability().unwrap();
        let request = reply_request(&capability, "request_00000001", "nonce_0000000001");
        let mut changed_binding = request.clone();
        changed_binding.replace_snapshot_digest_for_test(format!("sha256:{}", "f".repeat(64)));
        let receipt = fixture.service.execute(request.clone()).unwrap().0;
        assert_eq!(receipt.status, "DispatchAcknowledged");
        assert!(!receipt.idempotent_replay);
        fixture
            .service
            .state
            .issued
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .original
            .expire_for_test();
        let replay = fixture.service.execute(request).unwrap().0;
        assert_eq!(replay.receipt_id, receipt.receipt_id);
        assert!(replay.idempotent_replay);
        assert_eq!(
            fixture.service.execute(changed_binding).err(),
            Some(CommandProtocolError::Stale)
        );
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 1);
    }

    #[test]
    fn changed_fresh_target_and_mutated_binding_dispatch_zero_calls() {
        let fixture = command_fixture();
        let capability = fixture.service.capability().unwrap();
        *fixture.upstream.question.lock().unwrap() = Some("que_changed".into());
        let stale = fixture.service.execute(reply_request(
            &capability,
            "request_00000002",
            "nonce_0000000002",
        ));
        assert_eq!(stale.err(), Some(CommandProtocolError::Stale));
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 0);

        let fixture = command_fixture();
        let capability = fixture.service.capability().unwrap();
        let mut changed = reply_request(&capability, "request_00000003", "nonce_0000000003");
        changed.replace_snapshot_digest_for_test(format!("sha256:{}", "f".repeat(64)));
        assert_eq!(
            fixture.service.execute(changed).err(),
            Some(CommandProtocolError::Stale)
        );
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn expired_issued_capability_dispatches_zero_calls() {
        let fixture = command_fixture();
        let capability = fixture.service.capability().unwrap();
        fixture
            .service
            .state
            .issued
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .original
            .expire_for_test();
        assert_eq!(
            fixture
                .service
                .execute(reply_request(
                    &capability,
                    "request_00000004",
                    "nonce_0000000004"
                ))
                .err(),
            Some(CommandProtocolError::Stale)
        );
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn concurrent_different_commands_share_one_serial_authority() {
        let fixture = command_fixture();
        let capability = fixture.service.capability().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [
            ("request_00000005", "nonce_0000000005"),
            ("request_00000006", "nonce_0000000006"),
        ]
        .into_iter()
        .map(|(request_id, nonce)| {
            let service = Arc::clone(&fixture.service);
            let barrier = Arc::clone(&barrier);
            let request = reply_request(&capability, request_id, nonce);
            thread::spawn(move || {
                barrier.wait();
                service.execute(request)
            })
        })
        .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 1);
    }

    #[test]
    fn store_advances_only_for_changed_complete_projection() {
        let store =
            ProductSnapshotStore::with_host_instance_id("host-0123456789abcdef0123456789abcdef");
        assert!(store.commit(snapshot("Running")).unwrap());
        assert!(!store.commit(snapshot("Running")).unwrap());
        assert!(store.commit(snapshot("Completed")).unwrap());
        assert_eq!(store.current().unwrap().unwrap().snapshot_seq, 2);
    }

    #[test]
    fn health_lease_duplicate_refresh_expiry_and_same_seq_recovery() {
        let store =
            ProductSnapshotStore::with_host_instance_id("host-0123456789abcdef0123456789abcdef");
        let start = Instant::now();
        assert!(store.commit_at(snapshot("Running"), start).unwrap());
        assert!(store
            .source_available_at(start + SOURCE_HEALTH_LEASE - Duration::from_nanos(1))
            .unwrap());
        assert!(!store
            .source_available_at(start + SOURCE_HEALTH_LEASE)
            .unwrap());
        assert!(matches!(
            store.current_if_available_at(start + SOURCE_HEALTH_LEASE),
            Ok(Some(Err(_)))
        ));
        assert!(!store
            .commit_at(snapshot("Running"), start + SOURCE_HEALTH_LEASE)
            .unwrap());
        assert!(store
            .source_available_at(start + SOURCE_HEALTH_LEASE * 2 - Duration::from_nanos(1))
            .unwrap());
        assert_eq!(store.current().unwrap().unwrap().snapshot_seq, 1);
        assert!(matches!(
            wait_decision(
                &store.state.lock().unwrap(),
                1,
                start + SOURCE_HEALTH_LEASE * 2
            ),
            WaitDecision::Offline
        ));
        assert!(!store
            .commit_at(snapshot("Running"), start + SOURCE_HEALTH_LEASE * 2)
            .unwrap());
        assert!(matches!(
            store.current_if_available_at(
                start + SOURCE_HEALTH_LEASE * 3 - Duration::from_nanos(1)
            ),
            Ok(Some(Ok(value))) if value.snapshot_seq == 1
        ));
    }

    #[test]
    fn digest_covers_envelope_except_digest_itself() {
        let envelope = build_envelope(
            "host-0123456789abcdef0123456789abcdef",
            7,
            snapshot("Running"),
        )
        .unwrap();
        let mut value = serde_json::to_value(&envelope).unwrap();
        let digest = value.as_object_mut().unwrap().remove("digest").unwrap();
        let canonical = canonical_json(&value).unwrap();
        assert_eq!(
            canonical,
            "{\"host_instance_id\":\"host-0123456789abcdef0123456789abcdef\",\"schema\":\"nomad.product-host.snapshot.v1\",\"snapshot\":{\"diff_file_count\":0,\"evidence_class\":\"official_registry_shape_only_not_provider_lifecycle\",\"pending_input_alias\":null,\"pending_permission_alias\":null,\"session_alias\":\"sess-0123456789abcdef0123456789abcdef\",\"turn_state\":\"Running\",\"updated_at\":\"2026-08-25T00:00:00.000Z\",\"writable\":false},\"snapshot_seq\":7}"
        );
        let expected = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
        assert_eq!(digest, Value::String(expected.clone()));
        // Cross-language golden generated independently with Node.js
        // `crypto.createHash("sha256")` over the same canonical UTF-8 bytes.
        assert_eq!(
            expected,
            "sha256:a4f694418d92fe0a34166e2bf633339d9add5adefcd18b645dffe38b4516e0ff"
        );
    }

    #[test]
    fn long_poll_sequence_rules_are_exact() {
        let store =
            ProductSnapshotStore::with_host_instance_id("host-0123456789abcdef0123456789abcdef");
        assert!(matches!(
            store.wait_after(1, Duration::ZERO).unwrap(),
            WaitResult::Conflict
        ));
        store.commit(snapshot("Running")).unwrap();
        assert!(matches!(
            store.wait_after(0, Duration::ZERO).unwrap(),
            WaitResult::Snapshot(value) if value.snapshot_seq == 1
        ));
        assert!(matches!(
            store.wait_after(1, Duration::ZERO).unwrap(),
            WaitResult::Timeout
        ));
        assert!(matches!(
            store.wait_after(2, Duration::ZERO).unwrap(),
            WaitResult::Conflict
        ));
        store.commit(snapshot("Completed")).unwrap();
        assert!(matches!(
            store.wait_after(0, Duration::ZERO).unwrap(),
            WaitResult::Conflict
        ));
        assert!(matches!(
            store
                .wait_after(MAX_SAFE_SNAPSHOT_SEQ, Duration::ZERO)
                .unwrap(),
            WaitResult::Conflict
        ));
    }

    #[test]
    fn request_parser_accepts_only_exact_current_and_stream() {
        for (raw, expected) in [
            (
                b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".as_slice(),
                None,
            ),
            (
                b"GET /internal/session/stream?after_snapshot_seq=12 HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n".as_slice(),
                Some(12),
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(raw).unwrap();
            match (read_request(&mut server).unwrap(), expected) {
                (Request::Current, None) | (Request::Stream(12), Some(12)) => {}
                _ => panic!("wrong request"),
            }
        }
        for raw in [
            b"GET /internal/session/current?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET /internal/session/stream?after_snapshot_seq=-1 HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"POST /internal/session/current HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nAuthorization: secret\r\n\r\n".as_slice(),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(raw).unwrap();
            assert!(read_request(&mut server).is_err());
        }
    }

    #[test]
    fn private_socket_path_requires_private_owned_parent() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temporary
            .path()
            .canonicalize()
            .unwrap()
            .join("product-host.sock");
        let expected_parent = parent_identity(&socket).unwrap();
        let listener = {
            validate_and_prepare_socket_path(&socket).unwrap();
            let _umask = UmaskGuard::restrict();
            UnixListener::bind(&socket).unwrap()
        };
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let identity = validate_bound_socket(&socket).unwrap();
        let metadata = fs::symlink_metadata(&socket).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_ne!(identity, expected_parent);
        drop(listener);
        fs::remove_file(&socket).unwrap();

        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_and_prepare_socket_path(&socket).is_err());
    }

    #[test]
    fn socket_path_rejects_symlink_parent_and_non_socket_leaf() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = root.join("linked");
        symlink(&real, &linked).unwrap();
        assert!(validate_and_prepare_socket_path(&linked.join("product-host.sock")).is_err());

        let leaf = root.join("product-host.sock");
        fs::write(&leaf, b"not a socket").unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_and_prepare_socket_path(&leaf).is_err());
        assert_eq!(fs::read(&leaf).unwrap(), b"not a socket");
    }

    #[test]
    fn current_response_is_anonymous_and_exact() {
        let store = Arc::new(ProductSnapshotStore::with_host_instance_id(
            "host-0123456789abcdef0123456789abcdef",
        ));
        store.commit(snapshot("Running")).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let worker_store = Arc::clone(&store);
        let worker = thread::spawn(move || {
            serve_connection_with_timeout(&mut server, &worker_store, None, None, LONG_POLL_TIMEOUT)
        });
        client
            .write_all(
                b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        worker.join().unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("nomad.product-host.snapshot.v1"));
        for forbidden in ["server_password", "run_id", "workspace", "ses_raw"] {
            assert!(!response.contains(forbidden));
        }
    }

    #[test]
    fn unavailable_conflict_and_timeout_responses_are_content_free() {
        let store = Arc::new(ProductSnapshotStore::with_host_instance_id(
            "host-0123456789abcdef0123456789abcdef",
        ));
        for (request, status, code) in [
            (
                "GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\n\r\n",
                503,
                Some("SNAPSHOT_UNAVAILABLE"),
            ),
            (
                "GET /internal/session/stream?after_snapshot_seq=1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                409,
                Some("SNAPSHOT_SEQUENCE_CONFLICT"),
            ),
            (
                "GET /internal/session/stream?after_snapshot_seq=0 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                204,
                None,
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(request.as_bytes()).unwrap();
            serve_connection_with_timeout(&mut server, &store, None, None, Duration::ZERO)
                .unwrap();
            drop(server);
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {status} ")));
            assert!(!response.contains("session_id"));
            assert!(!response.contains("run_id"));
            assert!(!response.contains("workspace"));
            match code {
                Some(code) => {
                    let body = response.split_once("\r\n\r\n").unwrap().1;
                    assert_eq!(
                        serde_json::from_str::<Value>(body).unwrap(),
                        json!({"schema": ERROR_SCHEMA, "code": code})
                    );
                }
                None => assert!(response.ends_with("\r\n\r\n")),
            }
        }
    }

    #[test]
    fn peer_uid_requires_exact_effective_uid() {
        assert!(peer_uid_allowed(501, 501));
        assert!(!peer_uid_allowed(502, 501));
    }

    #[test]
    fn process_replacement_or_unstable_window_is_zero_commit() {
        fn batch(marker: u8) -> RawSnapshotBatch {
            RawSnapshotBatch {
                session: Zeroizing::new(vec![marker]),
                status: Zeroizing::new(vec![marker]),
                question: Zeroizing::new(vec![marker]),
                permission: Zeroizing::new(vec![marker]),
                diff: Zeroizing::new(vec![marker]),
            }
        }

        let store =
            ProductSnapshotStore::with_host_instance_id("host-0123456789abcdef0123456789abcdef");
        let mut verifies = 0;
        let mut reads = 0;
        let replaced = stable_observation(
            || {
                verifies += 1;
                (verifies == 1).then_some(()).ok_or(PollError::Process)
            },
            || {
                reads += 1;
                Ok(batch(1))
            },
        );
        assert!(replaced.is_err());
        assert!(store.current().unwrap().is_none());

        let mut reads = 0;
        let unstable = stable_observation(
            || Ok(()),
            || {
                reads += 1;
                Ok(batch(reads))
            },
        );
        assert!(unstable.is_err());
        assert!(store.current().unwrap().is_none());
    }

    #[test]
    fn process_failure_is_fatal_but_source_failure_is_retryable() {
        let fatal = AtomicBool::new(false);
        assert!(continue_after_poll(Err(PollError::Source), &fatal));
        assert!(!fatal.load(Ordering::Acquire));
        assert!(!continue_after_poll(Err(PollError::Process), &fatal));
        assert!(fatal.load(Ordering::Acquire));
        let fatal = AtomicBool::new(false);
        assert!(!continue_after_poll(Err(PollError::Binding), &fatal));
        assert!(fatal.load(Ordering::Acquire));
    }

    #[test]
    fn run_scoped_aliases_preserve_shape_and_separate_runs_and_domains() {
        let raw = "sess-0123456789abcdef0123456789abcdef";
        let first = scoped_alias(&"a".repeat(64), "sess", raw);
        let second = scoped_alias(&"b".repeat(64), "sess", raw);
        let other_domain = scoped_alias(&"a".repeat(64), "input", raw);
        assert_ne!(first, second);
        assert_ne!(
            first.split_once('-').unwrap().1,
            other_domain.split_once('-').unwrap().1
        );
        assert!(first.starts_with("sess-"));
        assert_eq!(first.len(), "sess-".len() + 32);

        let mut projected = snapshot("Running");
        projected.pending_input_alias = Some("input-rawalias".into());
        projected.pending_permission_alias = Some("permission-rawalias".into());
        RunProjectionBinding::new("c".repeat(64), "d".repeat(64)).realias(&mut projected);
        let encoded = serde_json::to_string(&projected).unwrap();
        assert!(!encoded.contains(&"c".repeat(64)));
        assert!(projected.pending_input_alias.unwrap().starts_with("input-"));
        assert!(projected
            .pending_permission_alias
            .unwrap()
            .starts_with("permission-"));
    }

    #[test]
    fn workspace_binding_matches_c1_and_rejects_wrong_or_replaced_path() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let canonical = workspace.canonicalize().unwrap();
        let metadata = fs::metadata(&canonical).unwrap();
        let digest = format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}:{}",
                    canonical.to_string_lossy(),
                    metadata.dev(),
                    metadata.ino()
                )
                .as_bytes()
            )
        );
        assert_eq!(verify_workspace_binding(&canonical, &digest), Ok(()));
        assert_eq!(
            verify_workspace_binding(&canonical, &"0".repeat(64)),
            Err(PollError::Binding)
        );

        let moved = temporary.path().join("moved");
        fs::rename(&workspace, &moved).unwrap();
        fs::create_dir(&workspace).unwrap();
        assert_eq!(
            verify_workspace_binding(&canonical, &digest),
            Err(PollError::Binding)
        );
    }

    #[test]
    fn workspace_binding_rejects_symlink_component() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let real = temporary.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked = temporary.path().join("linked");
        symlink(&real, &linked).unwrap();
        assert_eq!(
            verify_workspace_binding(&linked, &"0".repeat(64)),
            Err(PollError::Binding)
        );
    }

    #[test]
    fn device_registry_is_opened_without_auto_pairing_and_current_reports_unpaired() {
        let fixture = command_fixture();
        assert_eq!(
            fixture.devices.current().unwrap(),
            CurrentActiveDevice::Unpaired
        );
        let response = serve_admin_once(
            &fixture,
            &admin_signed_request(
                "GET",
                "/internal/devices/current",
                b"",
                "50112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"schema\":\"nomad.product-host.device-current.v1\""));
        assert!(response.contains("\"principal_alias\":\"remote-paired-device\""));
        assert!(response.contains("\"paired\":false"));
        assert!(!response.contains("local-run-gateway"));
    }

    #[test]
    fn fd11_local_admin_routes_pair_confirm_revoke_with_fixed_principal() {
        let fixture = command_fixture();
        let signing_key = signing_key(3);
        let agreement_key = agreement_key(4);
        let challenge_response = serve_admin_once(
            &fixture,
            &admin_signed_request(
                "POST",
                "/internal/devices/pairing/challenge",
                format!(
                    "{{\"signing_public_key\":\"{}\",\"agreement_public_key\":\"{}\"}}",
                    {
                        use base64::engine::general_purpose::STANDARD;
                        use base64::Engine as _;
                        STANDARD.encode(signing_public_bytes(&signing_key))
                    },
                    {
                        use base64::engine::general_purpose::STANDARD;
                        use base64::Engine as _;
                        STANDARD.encode(agreement_public_bytes(&agreement_key))
                    }
                )
                .as_bytes(),
                "60112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        let challenge_body = challenge_response.split_once("\r\n\r\n").unwrap().1;
        let challenge_json: Value = serde_json::from_str(challenge_body).unwrap();
        assert_eq!(challenge_json["principal_alias"], "remote-paired-device");
        let challenge = {
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine as _;
            STANDARD
                .decode(challenge_json["challenge"].as_str().unwrap())
                .unwrap()
        };
        let signing_public_key = signing_public_bytes(&signing_key);
        let agreement_public_key = agreement_public_bytes(&agreement_key);
        let device_alias = device_alias_for_test(&signing_public_key, &agreement_public_key);
        let issued_at_unix = time::OffsetDateTime::parse(
            challenge_json["issued_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
        .unix_timestamp();
        let expires_at_unix = time::OffsetDateTime::parse(
            challenge_json["expires_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
        .unix_timestamp();
        let transcript = pairing_transcript_for_test(PairingTranscriptTestInput {
            challenge: &challenge,
            signing_public_key: &signing_public_key,
            agreement_public_key: &agreement_public_key,
            principal_alias: REMOTE_REGISTRY_PRINCIPAL_ALIAS,
            device_alias: &device_alias,
            prospective_epoch: challenge_json["prospective_epoch"].as_u64().unwrap(),
            issued_at_unix,
            expires_at_unix,
        });
        let signature: p256::ecdsa::Signature = signing_key.sign(&transcript);
        let confirm_response = serve_admin_once(
            &fixture,
            &admin_signed_request(
                "POST",
                "/internal/devices/pairing/confirm",
                format!(
                    "{{\"challenge_id\":\"{}\",\"challenge\":\"{}\",\"signature\":\"{}\"}}",
                    challenge_json["challenge_id"].as_str().unwrap(),
                    {
                        use base64::engine::general_purpose::STANDARD;
                        use base64::Engine as _;
                        STANDARD.encode(&challenge)
                    },
                    {
                        use base64::engine::general_purpose::STANDARD;
                        use base64::Engine as _;
                        STANDARD.encode(signature.to_bytes())
                    }
                )
                .as_bytes(),
                "70112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        let confirm_json: Value =
            serde_json::from_str(confirm_response.split_once("\r\n\r\n").unwrap().1).unwrap();
        let device_alias = confirm_json["device_alias"].as_str().unwrap().to_string();
        assert_eq!(confirm_json["principal_alias"], "remote-paired-device");
        assert_eq!(confirm_json["pairing_epoch"], 1);

        let revoke_response = serve_admin_once(
            &fixture,
            &admin_signed_request(
                "POST",
                "/internal/devices/revoke",
                format!(
                    "{{\"device_alias\":\"{}\",\"expected_epoch\":1}}",
                    device_alias
                )
                .as_bytes(),
                "80112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        let revoke_json: Value =
            serde_json::from_str(revoke_response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(revoke_json["principal_alias"], "remote-paired-device");
        assert_eq!(revoke_json["status"], "revoked");
        assert_eq!(revoke_json["prior_epoch"], 1);
        assert_eq!(revoke_json["revoked_epoch"], 2);
    }

    #[test]
    fn m3e_handlers_run_exact_create_start_approve_confirm_complete_current_revoke() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let fixture = command_fixture();
        let (pairing, identity, relay) = product_pairing_service(&fixture);
        let created_response = pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_CREATE_PATH,
            json!({"schema":"nomad.m3e.pairing.create.v1"}),
            "c0112233445566778899aabbccddeeff",
        );
        assert!(created_response.starts_with("HTTP/1.1 200 OK\r\n"));
        let created = response_json(&created_response);
        assert_eq!(
            created
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ["schema", "join_id", "join_secret", "expires_at"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );

        let device_signing = signing_key(73);
        let device_agreement = agreement_key(74);
        let signing_public = signing_public_bytes(&device_signing);
        let agreement_public = agreement_public_bytes(&device_agreement);
        let started_response = pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_START_PATH,
            json!({
                "schema":"nomad.m3e.internal.pairing-start.v1",
                "join_id":created["join_id"],
                "join_secret":created["join_secret"],
                "device_signing_public_key_sec1":URL_SAFE_NO_PAD.encode(signing_public),
                "device_agreement_public_key_sec1":URL_SAFE_NO_PAD.encode(agreement_public),
            }),
            "c1112233445566778899aabbccddeeff",
        );
        let started = response_json(&started_response);
        assert_eq!(started["schema"], "nomad.m3e.pairing.host-start.v1");
        assert_eq!(started["join_cookie_max_age_seconds"], 120);
        let browser = &started["browser_start"];
        let challenge = URL_SAFE_NO_PAD
            .decode(browser["challenge_bytes_b64"].as_str().unwrap())
            .unwrap();
        let epoch = browser["prospective_epoch"].as_u64().unwrap();
        let transcript = m3e_transcript(
            created["join_id"].as_str().unwrap(),
            browser["challenge_id"].as_str().unwrap(),
            &challenge,
            epoch,
            &identity,
            &signing_public,
            &agreement_public,
        );
        let digest =
            Sha256::digest([b"nomad.m3e.compare.v1\n".as_slice(), transcript.as_slice()].concat());
        let code = format!(
            "{:06}",
            (((u32::from(digest[0]) << 16) | (u32::from(digest[1]) << 8) | u32::from(digest[2]))
                % 1_000_000)
        );
        let status = response_json(&pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_STATUS_PATH,
            json!({"schema":"nomad.m3e.pairing.status.v1","join_id":created["join_id"]}),
            "c2112233445566778899aabbccddeeff",
        ));
        assert_eq!(status["comparison_code"], code);

        let approved = pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_APPROVE_PATH,
            json!({
                "schema":"nomad.m3e.pairing.desktop-approve.v1",
                "join_id":created["join_id"],
                "challenge_id":browser["challenge_id"],
                "expected_epoch":epoch,
                "comparison_code":code,
            }),
            "c3112233445566778899aabbccddeeff",
        );
        assert!(approved.starts_with("HTTP/1.1 204 No Content\r\n"));
        let (signature, agreement_mac) =
            m3e_proofs(&transcript, &identity, &device_signing, &device_agreement);
        let confirmed = response_json(&pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_CONFIRM_PATH,
            json!({
                "schema":"nomad.m3e.internal.pairing-confirm.v1",
                "join_cookie_capability":started["join_cookie_capability"],
                "challenge_id":browser["challenge_id"],
                "expected_epoch":epoch,
                "device_signing_signature_p1363":URL_SAFE_NO_PAD.encode(signature),
                "device_agreement_mac":URL_SAFE_NO_PAD.encode(agreement_mac),
            }),
            "c4112233445566778899aabbccddeeff",
        ));
        assert_eq!(confirmed["schema"], "nomad.m3e.pairing.confirm-response.v1");
        assert_eq!(relay.provisions.lock().unwrap().len(), 1);
        let signed_bundle: SignedProvisioningBundle =
            serde_json::from_value(confirmed["signed_provisioning_bundle"].clone()).unwrap();
        let canonical_signed =
            canonical_json(&serde_json::to_value(&signed_bundle).unwrap()).unwrap();
        let mut vault_material = Vec::from(b"nomad.m3e.vault-commit.v1\n".as_slice());
        vault_material.extend_from_slice(&Sha256::digest(canonical_signed));
        let vault_signature: p256::ecdsa::Signature =
            device_signing.sign(&Sha256::digest(vault_material));
        let completed = response_json(&pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_COMPLETE_PATH,
            json!({
                "schema":"nomad.m3e.internal.pairing-complete.v1",
                "join_cookie_capability":started["join_cookie_capability"],
                "challenge_id":browser["challenge_id"],
                "expected_epoch":epoch,
                "device_vault_signature_p1363":URL_SAFE_NO_PAD.encode(vault_signature.to_bytes()),
            }),
            "c5112233445566778899aabbccddeeff",
        ));
        assert_eq!(
            completed["schema"],
            "nomad.m3e.pairing.complete-response.v1"
        );

        let remote_authority = ProductRemoteCommandAuthority::new(
            Arc::clone(&pairing.coordinator),
            Arc::clone(&fixture.service),
            Arc::clone(&fixture.devices),
        );
        let guard = pairing.coordinator.command_guard().unwrap();
        let active = pairing
            .coordinator
            .active_binding_locked(&guard)
            .unwrap()
            .unwrap();
        let projection = RemoteCommandAuthorityContract::<PairingCoordinator>::projection_locked(
            &remote_authority,
            &guard,
            &active,
        )
        .unwrap();
        let capability = projection.capability.as_ref().unwrap();
        assert_eq!(projection.snapshot.snapshot_seq, capability.snapshot_seq);
        assert_eq!(projection.snapshot.digest, capability.snapshot_digest);
        let reply = capability.reply.as_ref().unwrap();
        let command = GatewayCommand::Reply(crate::remote_application::ReplyCommand {
            capability_id: capability.capability_id.clone(),
            request_id: "request_remote_facade_0001".into(),
            nonce: "nonce_remote_facade_000001".into(),
            command_seq: capability.next_command_seq,
            expected_snapshot_seq: capability.snapshot_seq,
            expected_snapshot_digest: capability.snapshot_digest.clone(),
            issued_at: capability.issued_at.clone(),
            expires_at: capability.expires_at.clone(),
            turn_alias: reply.turn_alias.clone(),
            input_alias: reply.input_alias.clone(),
            content: "mechanical remote reply".into(),
        });
        let parsed = ParsedProductCommand::try_from(command).unwrap();
        let receipt = receipt_from_disposition(
            RemoteCommandAuthorityContract::<PairingCoordinator>::execute_locked(
                &remote_authority,
                &guard,
                &active,
                parsed.clone(),
            ),
        );
        assert_eq!(receipt.schema, "nomad.gateway.command-receipt.v1");
        assert_eq!(receipt.request_id, "request_remote_facade_0001");
        assert_eq!(receipt.action, RemoteReceiptAction::Reply);
        assert_eq!(receipt.snapshot_seq, projection.snapshot.snapshot_seq);
        assert_eq!(receipt.snapshot_digest, projection.snapshot.digest);
        assert_eq!(receipt.status, RemoteReceiptStatus::DispatchAcknowledged);
        assert_eq!(receipt.error_code.0, "OK");
        assert!(!receipt.idempotent_replay);
        let replay = receipt_from_disposition(
            RemoteCommandAuthorityContract::<PairingCoordinator>::execute_locked(
                &remote_authority,
                &guard,
                &active,
                parsed,
            ),
        );
        assert_eq!(replay.receipt_id, receipt.receipt_id);
        assert!(replay.idempotent_replay);
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 1);
        drop(guard);

        let current = serve_pairing_once(
            &fixture,
            Some(&pairing),
            &admin_signed_request(
                "GET",
                crate::product_command_protocol::DEVICE_CURRENT_PATH,
                b"",
                "c6112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        assert!(current.contains("\"paired\":true"));
        let revoked = response_json(&pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::DEVICE_REVOKE_PATH,
            json!({"device_alias":completed["device_alias"],"expected_epoch":epoch}),
            "c7112233445566778899aabbccddeeff",
        ));
        assert_eq!(revoked["status"], "revoked");
        assert_eq!(relay.revocations.lock().unwrap().len(), 1);
        assert!(pairing.coordinator.active_binding().unwrap().is_none());
    }

    #[test]
    fn m3e_handlers_cancel_abort_and_missing_coordinator_fail_closed() {
        let fixture = command_fixture();
        let unavailable = pairing_post(
            &fixture,
            None,
            crate::product_command_protocol::PAIRING_CREATE_PATH,
            json!({"schema":"nomad.m3e.pairing.create.v1"}),
            "d0112233445566778899aabbccddeeff",
        );
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert_eq!(
            response_json(&unavailable)["code"],
            "PAIRING_RELAY_UNAVAILABLE"
        );

        let (pairing, _identity, _) = product_pairing_service(&fixture);
        let created = response_json(&pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_CREATE_PATH,
            json!({"schema":"nomad.m3e.pairing.create.v1"}),
            "d1112233445566778899aabbccddeeff",
        ));
        let cancelled = pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_CANCEL_PATH,
            json!({"schema":"nomad.m3e.pairing.cancel.v1","join_id":created["join_id"]}),
            "d2112233445566778899aabbccddeeff",
        );
        assert!(cancelled.starts_with("HTTP/1.1 204 No Content\r\n"));
        let cancelled_status = response_json(&pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_STATUS_PATH,
            json!({"schema":"nomad.m3e.pairing.status.v1","join_id":created["join_id"]}),
            "d3112233445566778899aabbccddeeff",
        ));
        assert_eq!(cancelled_status["state"], "cancelled");

        let created_join = pairing
            .coordinator
            .create_join(OffsetDateTime::now_utc())
            .unwrap();
        let signing = signing_key(75);
        let agreement = agreement_key(76);
        let signing_public = signing_public_bytes(&signing);
        let agreement_public = agreement_public_bytes(&agreement);
        let started_join = pairing
            .coordinator
            .start_join(
                &created_join.join_id,
                &created_join.join_secret,
                &signing_public,
                &agreement_public,
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        pairing
            .coordinator
            .approve_join(
                &created_join.join_id,
                &started_join.challenge_id,
                started_join.prospective_epoch,
                &started_join.comparison_code,
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        let transcript = m3e_transcript(
            &created_join.join_id,
            &started_join.challenge_id,
            &started_join.challenge_bytes,
            started_join.prospective_epoch,
            &_identity,
            &signing_public,
            &agreement_public,
        );
        let (proof, mac) = m3e_proofs(&transcript, &_identity, &signing, &agreement);
        pairing
            .coordinator
            .confirm_join(
                &started_join.cookie_capability,
                &started_join.challenge_id,
                started_join.prospective_epoch,
                &proof,
                &mac,
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        let aborted = pairing_post(
            &fixture,
            Some(&pairing),
            crate::product_command_protocol::PAIRING_ABORT_PATH,
            json!({
                "schema":"nomad.m3e.internal.pairing-abort.v1",
                "join_cookie_capability":started_join.cookie_capability.as_str(),
                "challenge_id":started_join.challenge_id,
                "expected_epoch":started_join.prospective_epoch,
            }),
            "d6112233445566778899aabbccddeeff",
        );
        assert!(aborted.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(pairing.coordinator.active_binding().unwrap().is_none());
    }

    #[test]
    fn m3e_cross_key_requests_return_401_before_pairing_handlers() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let fixture = command_fixture();
        let (pairing, _, _) = product_pairing_service(&fixture);
        let join_transport = CommandTransportAuthenticator::new(Zeroizing::new([8_u8; 32]));
        let created = pairing
            .coordinator
            .create_join(OffsetDateTime::now_utc())
            .unwrap();
        let signing = signing_public_bytes(&signing_key(81));
        let agreement = agreement_public_bytes(&agreement_key(82));
        let start_body = canonical_json(&json!({
            "schema":"nomad.m3e.internal.pairing-start.v1",
            "join_id":created.join_id,
            "join_secret":created.join_secret.as_str(),
            "device_signing_public_key_sec1":URL_SAFE_NO_PAD.encode(signing),
            "device_agreement_public_key_sec1":URL_SAFE_NO_PAD.encode(agreement),
        }))
        .unwrap();
        let response = serve_pairing_with_join_auth(
            &fixture,
            &pairing,
            &join_transport,
            &signed_request_with_key(
                &[7; 32],
                "POST",
                crate::product_command_protocol::PAIRING_START_PATH,
                start_body.as_bytes(),
                "f0112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        let status = pairing
            .coordinator
            .pairing_status(
                &PairingStatusRequest {
                    schema: "nomad.m3e.pairing.status.v1".into(),
                    join_id: created.join_id.clone(),
                },
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        assert_eq!(status.state, "created");

        let response = serve_pairing_with_join_auth(
            &fixture,
            &pairing,
            &join_transport,
            &signed_request_with_key(
                &[8; 32],
                "POST",
                crate::product_command_protocol::PAIRING_CREATE_PATH,
                br#"{"schema":"nomad.m3e.pairing.create.v1"}"#,
                "f1112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert_eq!(
            pairing
                .coordinator
                .pairing_status(
                    &PairingStatusRequest {
                        schema: "nomad.m3e.pairing.status.v1".into(),
                        join_id: created.join_id,
                    },
                    OffsetDateTime::now_utc(),
                )
                .unwrap()
                .state,
            "created"
        );
    }

    #[test]
    fn start_with_pairing_does_not_wait_or_signal_and_exposes_authority_before_worker_ready() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let upstream = FakeOpenCode::start(&workspace);
        let workspace_metadata = fs::metadata(&workspace).unwrap();
        let workspace_digest = format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{}:{}:{}",
                    workspace.to_string_lossy(),
                    workspace_metadata.dev(),
                    workspace_metadata.ino()
                )
                .as_bytes()
            )
        );
        let process = AgentProcessBinding {
            pid: std::process::id(),
            process_group: unsafe { libc::getpgid(0) } as u32,
            identity: process_identity_for_test(std::process::id()),
        };
        let socket_path = root.join("product-host.sock");
        let parent = parent_identity(&socket_path).unwrap();
        let registry_path = root.join("host-device-registry.sqlite3");
        let gate = Arc::new(DeviceCommandGate::new());
        let coordinator = Arc::new(
            PairingCoordinator::new(
                Arc::clone(&gate),
                DeviceAuthority::open(&registry_path).unwrap(),
                Arc::new(ProductPairingTestIdentity::new()),
                Arc::new(ProductPairingTestRelay::default()),
                Arc::new(MemoryJoinSessionStore::default()),
                "https://relay.example/v2".into(),
            )
            .unwrap(),
        );
        let bootstrap = HostBootstrap {
            run_id: "a".repeat(64),
            origin: upstream.origin.clone(),
            session_id: "ses_secret".into(),
            server_password: Zeroizing::new("secret".into()),
            workspace_binding_digest: workspace_digest,
            product_host_socket_path: socket_path,
            agent_pid: process.pid,
            agent_process_group: process.process_group,
            agent_process_identity: process.identity,
            product_host_socket_parent_dev: parent.0,
            product_host_socket_parent_ino: parent.1,
            command_transport_key: Zeroizing::new([7; 32]),
            command_authority_key: Zeroizing::new([9; 32]),
            command_journal_path: root.join("command.sqlite3"),
            device_registry_path: registry_path,
        };
        let (_not_ready_tx, not_ready_rx) = std::sync::mpsc::channel::<()>();
        let started = Instant::now();
        let lifecycle = RemoteIngressLifecycle::new();
        let (host, _) = ProductStockHost::start_with_pairing(
            bootstrap,
            Some(RemoteProductHostDependencies {
                pairing: coordinator,
                join_transport_key: Zeroizing::new([8; 32]),
                lifecycle: Arc::clone(&lifecycle),
            }),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(host.remote_command_authority().is_some());
        assert_eq!(
            host.remote_lifecycle_snapshot().unwrap().status,
            RemoteIngressStatus::Starting
        );
        assert_eq!(
            not_ready_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        );
    }

    #[test]
    fn blocked_remote_lifecycle_rejects_every_remote_mutation_but_preserves_reads() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let fixture = command_fixture();
        let (pairing, _, _) = product_pairing_service(&fixture);
        let lifecycle = RemoteIngressLifecycle::new();
        lifecycle.ready_for_test();
        lifecycle.blocked_for_test(crate::remote_command_ingress::RemoteIngressReason::Protocol);
        let join_id = format!("join-{}", "a".repeat(32));
        let challenge_id = format!("challenge-{}", "b".repeat(32));
        let capability = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let signing_public = URL_SAFE_NO_PAD.encode(signing_public_bytes(&signing_key(91)));
        let agreement_public = URL_SAFE_NO_PAD.encode(agreement_public_bytes(&agreement_key(92)));
        let mutations = [
            (
                crate::product_command_protocol::DEVICE_CHALLENGE_PATH,
                json!({
                    "signing_public_key":base64::engine::general_purpose::STANDARD.encode(signing_public_bytes(&signing_key(93))),
                    "agreement_public_key":base64::engine::general_purpose::STANDARD.encode(agreement_public_bytes(&agreement_key(94)))
                }),
            ),
            (
                crate::product_command_protocol::DEVICE_CONFIRM_PATH,
                json!({
                    "challenge_id":"challenge-00000000000000000000000000000000",
                    "challenge":base64::engine::general_purpose::STANDARD.encode([1_u8;32]),
                    "signature":base64::engine::general_purpose::STANDARD.encode([2_u8;64])
                }),
            ),
            (
                crate::product_command_protocol::PAIRING_CREATE_PATH,
                json!({"schema":"nomad.m3e.pairing.create.v1"}),
            ),
            (
                crate::product_command_protocol::PAIRING_APPROVE_PATH,
                json!({"schema":"nomad.m3e.pairing.desktop-approve.v1","join_id":join_id,"challenge_id":challenge_id,"expected_epoch":1,"comparison_code":"042913"}),
            ),
            (
                crate::product_command_protocol::PAIRING_CANCEL_PATH,
                json!({"schema":"nomad.m3e.pairing.cancel.v1","join_id":join_id}),
            ),
            (
                crate::product_command_protocol::PAIRING_START_PATH,
                json!({"schema":"nomad.m3e.internal.pairing-start.v1","join_id":join_id,"join_secret":capability,"device_signing_public_key_sec1":signing_public,"device_agreement_public_key_sec1":agreement_public}),
            ),
            (
                crate::product_command_protocol::PAIRING_CONFIRM_PATH,
                json!({"schema":"nomad.m3e.internal.pairing-confirm.v1","join_cookie_capability":capability,"challenge_id":challenge_id,"expected_epoch":1,"device_signing_signature_p1363":URL_SAFE_NO_PAD.encode([5_u8;64]),"device_agreement_mac":URL_SAFE_NO_PAD.encode([6_u8;32])}),
            ),
            (
                crate::product_command_protocol::PAIRING_COMPLETE_PATH,
                json!({"schema":"nomad.m3e.internal.pairing-complete.v1","join_cookie_capability":capability,"challenge_id":challenge_id,"expected_epoch":1,"device_vault_signature_p1363":URL_SAFE_NO_PAD.encode([8_u8;64])}),
            ),
            (
                crate::product_command_protocol::PAIRING_ABORT_PATH,
                json!({"schema":"nomad.m3e.internal.pairing-abort.v1","join_cookie_capability":capability,"challenge_id":challenge_id,"expected_epoch":1}),
            ),
            (
                crate::product_command_protocol::DEVICE_REVOKE_PATH,
                json!({"device_alias":"device-00000000000000000000000000000000","expected_epoch":1}),
            ),
        ];
        for (index, (path, value)) in mutations.into_iter().enumerate() {
            let body = canonical_json(&value).unwrap();
            let response = serve_pairing_with_lifecycle_once(
                &fixture,
                Some(&pairing),
                Some(&lifecycle),
                &admin_signed_request("POST", path, body.as_bytes(), &format!("a{index:031x}")),
            )
            .unwrap();
            assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
            assert_eq!(
                response_json(&response)["code"],
                "REMOTE_INGRESS_UNAVAILABLE"
            );
        }

        let current = serve_pairing_with_lifecycle_once(
            &fixture,
            Some(&pairing),
            Some(&lifecycle),
            b"GET /internal/session/current HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(current.starts_with("HTTP/1.1 200 OK\r\n"), "{current}");
        let stream = serve_pairing_with_lifecycle_once(
            &fixture,
            Some(&pairing),
            Some(&lifecycle),
            b"GET /internal/session/stream?after_snapshot_seq=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        assert!(stream.starts_with("HTTP/1.1 204 No Content\r\n"));
        let device = serve_pairing_with_lifecycle_once(
            &fixture,
            Some(&pairing),
            Some(&lifecycle),
            &admin_signed_request(
                "GET",
                crate::product_command_protocol::DEVICE_CURRENT_PATH,
                b"",
                "b0112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        assert!(device.starts_with("HTTP/1.1 200 OK\r\n"));
        let status_body =
            canonical_json(&json!({"schema":"nomad.m3e.pairing.status.v1","join_id":join_id}))
                .unwrap();
        let status = serve_pairing_with_lifecycle_once(
            &fixture,
            Some(&pairing),
            Some(&lifecycle),
            &admin_signed_request(
                "POST",
                crate::product_command_protocol::PAIRING_STATUS_PATH,
                status_body.as_bytes(),
                "b1112233445566778899aabbccddeeff",
            ),
        )
        .unwrap();
        assert!(!status.contains("REMOTE_INGRESS_UNAVAILABLE"));
    }

    #[test]
    fn lifecycle_transition_waits_for_projector_write_permit_and_local_only_is_unchanged() {
        let lifecycle = RemoteIngressLifecycle::new();
        lifecycle.ready_for_test();
        let permit = acquire_remote_write_permit(Some(&lifecycle))
            .unwrap()
            .unwrap();
        let worker_lifecycle = Arc::clone(&lifecycle);
        let transition = thread::spawn(move || {
            worker_lifecycle
                .blocked_for_test(crate::remote_command_ingress::RemoteIngressReason::Protocol);
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while lifecycle.snapshot().accepting_writes && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(!lifecycle.snapshot().accepting_writes);
        assert!(!transition.is_finished());
        assert!(!permit.is_current());
        drop(permit);
        transition.join().unwrap();
        assert_eq!(
            lifecycle.snapshot().status,
            RemoteIngressStatus::Blocked(
                crate::remote_command_ingress::RemoteIngressReason::Protocol
            )
        );
        assert_eq!(lifecycle.snapshot().active_permits, 0);
        assert!(acquire_remote_write_permit(None).unwrap().is_none());
    }

    #[test]
    fn remote_command_facade_uses_active_binding_and_dispatches_exactly_once() {
        let fixture = command_fixture();
        let (pairing, identity, _) = product_pairing_service(&fixture);
        let binding =
            activate_remote_binding(&pairing, &identity, &signing_key(83), &agreement_key(84));
        let authority = ProductRemoteCommandAuthority::new(
            Arc::clone(&pairing.coordinator),
            Arc::clone(&fixture.service),
            Arc::clone(&fixture.devices),
        );
        let guard = pairing.coordinator.command_guard().unwrap();
        let projection = authority.projection_locked(&guard, &binding).unwrap();
        let capability = projection.capability.as_ref().unwrap();
        let reply = capability.reply.as_ref().unwrap();
        let command = GatewayCommand::Reply(crate::remote_application::ReplyCommand {
            capability_id: capability.capability_id.clone(),
            request_id: "remote-request-0001".into(),
            nonce: "remote-nonce-0001".into(),
            command_seq: capability.next_command_seq,
            expected_snapshot_seq: capability.snapshot_seq,
            expected_snapshot_digest: capability.snapshot_digest.clone(),
            issued_at: capability.issued_at.clone(),
            expires_at: capability.expires_at.clone(),
            turn_alias: reply.turn_alias.clone(),
            input_alias: reply.input_alias.clone(),
            content: "remote mechanical reply".into(),
        });
        let first = receipt_from_disposition(authority.execute_locked(
            &guard,
            &binding,
            ParsedProductCommand::try_from(command.clone()).unwrap(),
        ));
        let replay = receipt_from_disposition(authority.execute_locked(
            &guard,
            &binding,
            ParsedProductCommand::try_from(command).unwrap(),
        ));
        assert_eq!(first.status, RemoteReceiptStatus::DispatchAcknowledged);
        assert_eq!(first.snapshot_seq, projection.snapshot.snapshot_seq);
        assert_eq!(first.snapshot_digest, projection.snapshot.digest);
        assert!(!first.idempotent_replay);
        assert!(replay.idempotent_replay);
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 1);
    }

    #[test]
    fn remote_projection_keeps_view_without_actionable_capability() {
        let fixture = command_fixture();
        let (pairing, identity, _) = product_pairing_service(&fixture);
        let binding =
            activate_remote_binding(&pairing, &identity, &signing_key(95), &agreement_key(96));
        let authority = ProductRemoteCommandAuthority::new(
            Arc::clone(&pairing.coordinator),
            Arc::clone(&fixture.service),
            Arc::clone(&fixture.devices),
        );
        let guard = pairing.coordinator.command_guard().unwrap();

        let input_projection = authority.projection_locked(&guard, &binding).unwrap();
        let input_capability = input_projection.capability.as_ref().unwrap();
        assert!(input_capability.reply.is_some());
        assert!(input_capability.deny.is_none());
        let reply = input_capability.reply.as_ref().unwrap();
        let stale_command = ParsedProductCommand::try_from(GatewayCommand::Reply(
            crate::remote_application::ReplyCommand {
                capability_id: input_capability.capability_id.clone(),
                request_id: "remote-no-action-command".into(),
                nonce: "remote-no-action-nonce".into(),
                command_seq: input_capability.next_command_seq,
                expected_snapshot_seq: input_capability.snapshot_seq,
                expected_snapshot_digest: input_capability.snapshot_digest.clone(),
                issued_at: input_capability.issued_at.clone(),
                expires_at: input_capability.expires_at.clone(),
                turn_alias: reply.turn_alias.clone(),
                input_alias: reply.input_alias.clone(),
                content: "must not dispatch".into(),
            },
        ))
        .unwrap();

        *fixture.upstream.question.lock().unwrap() = None;
        fixture.upstream.busy.store(false, Ordering::Release);
        refresh_fixture_snapshot(&fixture);
        let completed = authority.projection_locked(&guard, &binding).unwrap();
        assert_eq!(
            completed.snapshot.snapshot.turn_state,
            crate::remote_application::SnapshotTurnState::Completed
        );
        assert!(completed.capability.is_none());

        fixture.upstream.busy.store(true, Ordering::Release);
        refresh_fixture_snapshot(&fixture);
        let running = authority.projection_locked(&guard, &binding).unwrap();
        assert_eq!(
            running.snapshot.snapshot.turn_state,
            crate::remote_application::SnapshotTurnState::Running
        );
        assert!(running.capability.is_none());

        let rejected =
            receipt_from_disposition(authority.execute_locked(&guard, &binding, stale_command));
        assert_eq!(rejected.status, RemoteReceiptStatus::Stale);
        assert_eq!(rejected.error_code.0, "ERR_REQUEST_STALE");
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 0);

        fixture.upstream.busy.store(false, Ordering::Release);
        *fixture.upstream.permission.lock().unwrap() = Some("per_secret".into());
        refresh_fixture_snapshot(&fixture);
        let permission = authority.projection_locked(&guard, &binding).unwrap();
        let permission_capability = permission.capability.unwrap();
        assert!(permission_capability.reply.is_none());
        assert!(permission_capability.deny.is_some());
    }

    #[test]
    fn remote_command_facade_rejects_unpaired_stale_and_revoked_before_agent() {
        let fixture = command_fixture();
        let (pairing, identity, _) = product_pairing_service(&fixture);
        let authority = ProductRemoteCommandAuthority::new(
            Arc::clone(&pairing.coordinator),
            Arc::clone(&fixture.service),
            Arc::clone(&fixture.devices),
        );
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 0);

        let binding =
            activate_remote_binding(&pairing, &identity, &signing_key(85), &agreement_key(86));
        let command = {
            let guard = pairing.coordinator.command_guard().unwrap();
            let capability = authority
                .projection_locked(&guard, &binding)
                .unwrap()
                .capability
                .unwrap();
            let reply = capability.reply.as_ref().unwrap();
            GatewayCommand::Reply(crate::remote_application::ReplyCommand {
                capability_id: capability.capability_id,
                request_id: "remote-request-stale".into(),
                nonce: "remote-nonce-stale".into(),
                command_seq: capability.next_command_seq,
                expected_snapshot_seq: capability.snapshot_seq,
                expected_snapshot_digest: capability.snapshot_digest,
                issued_at: capability.issued_at,
                expires_at: capability.expires_at,
                turn_alias: reply.turn_alias.clone(),
                input_alias: reply.input_alias.clone(),
                content: "must not dispatch".into(),
            })
        };
        pairing
            .coordinator
            .revoke_device(
                &binding.device_alias,
                binding.pairing_epoch,
                OffsetDateTime::now_utc(),
            )
            .unwrap();
        let guard = pairing.coordinator.command_guard().unwrap();
        let rejected = authority.execute_locked(
            &guard,
            &binding,
            ParsedProductCommand::try_from(command).unwrap(),
        );
        assert_rejection(rejected, RemoteReceiptStatus::Stale, "ERR_REQUEST_REVOKED");
        assert!(!fixture
            .service
            .authority
            .contains_request("remote-request-stale")
            .unwrap());
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 0);
    }

    #[test]
    fn remote_disposition_matrix_returns_receipts_retry_or_fatal_without_agent() {
        for (error, status, code, revoked) in [
            (
                CommandProtocolError::InvalidRequest,
                RemoteReceiptStatus::Rejected,
                "ERR_SAFETY_BLOCKED",
                false,
            ),
            (
                CommandProtocolError::Stale,
                RemoteReceiptStatus::Stale,
                "ERR_REQUEST_STALE",
                false,
            ),
            (
                CommandProtocolError::Stale,
                RemoteReceiptStatus::Stale,
                "ERR_REQUEST_REVOKED",
                true,
            ),
            (
                CommandProtocolError::Expired,
                RemoteReceiptStatus::Expired,
                "ERR_REQUEST_EXPIRED",
                false,
            ),
            (
                CommandProtocolError::OutcomeUnknown,
                RemoteReceiptStatus::OutcomeUnknown,
                "ERR_OUTCOME_UNKNOWN",
                false,
            ),
        ] {
            assert_rejection(
                remote_error_disposition(
                    error,
                    "remote-matrix-request".into(),
                    RemoteReceiptAction::Reply,
                    7,
                    format!("sha256:{}", "a".repeat(64)),
                    revoked,
                ),
                status,
                code,
            );
        }
        assert_eq!(
            remote_error_disposition(
                CommandProtocolError::Unavailable,
                "remote-matrix-request".into(),
                RemoteReceiptAction::Reply,
                7,
                format!("sha256:{}", "a".repeat(64)),
                false,
            ),
            RemoteCommandDisposition::RetryableNoAck
        );
        assert_eq!(
            remote_error_disposition(
                CommandProtocolError::Internal,
                "remote-matrix-request".into(),
                RemoteReceiptAction::Reply,
                7,
                format!("sha256:{}", "a".repeat(64)),
                false,
            ),
            RemoteCommandDisposition::Fatal
        );
    }

    #[test]
    fn remote_outcome_unknown_is_receipted_and_exact_replay_never_redispatches() {
        let fixture = command_fixture();
        fixture
            .upstream
            .outcome_unknown
            .store(true, Ordering::Release);
        let (pairing, identity, _) = product_pairing_service(&fixture);
        let binding =
            activate_remote_binding(&pairing, &identity, &signing_key(87), &agreement_key(88));
        let authority = ProductRemoteCommandAuthority::new(
            Arc::clone(&pairing.coordinator),
            Arc::clone(&fixture.service),
            Arc::clone(&fixture.devices),
        );
        let guard = pairing.coordinator.command_guard().unwrap();
        let capability = authority
            .projection_locked(&guard, &binding)
            .unwrap()
            .capability
            .unwrap();
        let reply = capability.reply.as_ref().unwrap();
        let command = GatewayCommand::Reply(crate::remote_application::ReplyCommand {
            capability_id: capability.capability_id,
            request_id: "remote-outcome-unknown".into(),
            nonce: "remote-outcome-nonce".into(),
            command_seq: capability.next_command_seq,
            expected_snapshot_seq: capability.snapshot_seq,
            expected_snapshot_digest: capability.snapshot_digest,
            issued_at: capability.issued_at,
            expires_at: capability.expires_at,
            turn_alias: reply.turn_alias.clone(),
            input_alias: reply.input_alias.clone(),
            content: "mechanical unknown reply".into(),
        });
        let parsed = ParsedProductCommand::try_from(command).unwrap();
        let first =
            receipt_from_disposition(authority.execute_locked(&guard, &binding, parsed.clone()));
        assert_eq!(first.status, RemoteReceiptStatus::OutcomeUnknown);
        assert_eq!(first.error_code.0, "ERR_OUTCOME_UNKNOWN");
        assert!(!first.idempotent_replay);
        let replay = receipt_from_disposition(authority.execute_locked(&guard, &binding, parsed));
        assert_eq!(replay.receipt_id, first.receipt_id);
        assert!(replay.idempotent_replay);
        assert_eq!(fixture.upstream.posts.load(Ordering::Acquire), 1);
    }
}
