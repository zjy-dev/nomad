//! Host-role Relay v2 command ingress.
//!
//! This module owns the E2c state machine, but not the Product Host command
//! implementation.  The latter is injected through `ProductRemoteCommandAuthority`
//! so the only production implementation remains the frozen E2 facade.

use crate::pairing_coordinator::{
    ActiveRemoteBinding, DeviceCommandGuard, PairingCoordinator, PairingCoordinatorError,
};
use crate::product_command_protocol::{CommandProtocolError, ParsedProductCommand};
use crate::remote_application::{
    canonical_encode_application_envelope, parse_application_envelope, ApplicationEnvelope,
    ApplicationPayload, CommandReceipt, EnvelopeCommon, EnvelopeKind, FrameBinding, FrameDirection,
    ProjectionPayload, ReceiptPayload,
};
use crate::remote_crypto::{
    encrypt, Direction, EndpointKeys, FrameMetadata, OpaqueFrame, RemoteCryptoError, SharedContext,
};
use crate::remote_mailbox::{
    parse_canonical_frame, DurablePoisonDisposition, HostRelayV2Client, PoisonReasonCode,
    RelayOpaqueFrame, RemoteDirection, RemoteMailboxError, RemoteMailboxState,
};
use getrandom::getrandom;
use serde_json::Value;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const FRAME_SCHEMA: &str = "nomad.relay.opaque-frame.v2";
const FRAME_SUITE: &str = "p256-hkdf-sha256-aes256gcm-v1";
const APPLICATION_SCHEMA: &str = "nomad.remote.application-envelope.v1";
const OUTBOUND_TTL_SECONDS: i64 = 600;
const ID_RANDOM_BYTES: usize = 16;
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const ERROR_BACKOFF: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteIngressReason {
    Unavailable,
    State,
    Internal,
    Protocol,
    Authentication,
    Binding,
    WorkerPanic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteIngressStatus {
    Starting,
    Ready,
    Degraded(RemoteIngressReason),
    Blocked(RemoteIngressReason),
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RemoteIngressLifecycleSnapshot {
    pub(crate) status: RemoteIngressStatus,
    pub(crate) generation: u64,
    pub(crate) changed_at: Instant,
    pub(crate) accepting_writes: bool,
    pub(crate) active_permits: u64,
}

pub(crate) struct RemoteIngressLifecycle {
    snapshot: Mutex<RemoteIngressLifecycleSnapshot>,
    changed: Condvar,
    transition_serial: Mutex<()>,
}

impl RemoteIngressLifecycle {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot: Mutex::new(RemoteIngressLifecycleSnapshot {
                status: RemoteIngressStatus::Starting,
                generation: 0,
                changed_at: Instant::now(),
                accepting_writes: false,
                active_permits: 0,
            }),
            changed: Condvar::new(),
            transition_serial: Mutex::new(()),
        })
    }

    pub(crate) fn snapshot(&self) -> RemoteIngressLifecycleSnapshot {
        *self
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    pub(crate) fn acquire_write_permit(
        self: &Arc<Self>,
    ) -> Result<RemoteWritePermit, RemoteIngressError> {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if snapshot.status != RemoteIngressStatus::Ready || !snapshot.accepting_writes {
            return Err(RemoteIngressError::Unavailable);
        }
        snapshot.active_permits = snapshot
            .active_permits
            .checked_add(1)
            .ok_or(RemoteIngressError::State)?;
        Ok(RemoteWritePermit {
            lifecycle: Arc::clone(self),
            generation: snapshot.generation,
        })
    }

    fn transition_to_non_ready(&self, status: RemoteIngressStatus) {
        debug_assert!(!matches!(status, RemoteIngressStatus::Ready));
        let _transition = self
            .transition_serial
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if matches!(snapshot.status, RemoteIngressStatus::Blocked(_)) {
            return;
        }
        if snapshot.status == RemoteIngressStatus::Stopped
            && !matches!(status, RemoteIngressStatus::Blocked(_))
        {
            return;
        }
        snapshot.accepting_writes = false;
        snapshot.generation = snapshot.generation.saturating_add(1);
        self.changed.notify_all();
        while snapshot.active_permits != 0 {
            snapshot = self
                .changed
                .wait(snapshot)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        if matches!(snapshot.status, RemoteIngressStatus::Blocked(_)) {
            return;
        }
        snapshot.status = status;
        snapshot.changed_at = Instant::now();
        self.changed.notify_all();
    }

    fn ready(&self) {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if matches!(
            snapshot.status,
            RemoteIngressStatus::Blocked(_) | RemoteIngressStatus::Stopped
        ) || snapshot.status == RemoteIngressStatus::Ready && !snapshot.accepting_writes
        {
            return;
        }
        if snapshot.status != RemoteIngressStatus::Ready || !snapshot.accepting_writes {
            snapshot.status = RemoteIngressStatus::Ready;
            snapshot.accepting_writes = true;
            snapshot.generation = snapshot.generation.saturating_add(1);
            snapshot.changed_at = Instant::now();
            self.changed.notify_all();
        }
    }

    fn degraded(&self, reason: RemoteIngressReason) {
        self.transition_to_non_ready(RemoteIngressStatus::Degraded(reason));
    }

    fn blocked(&self, reason: RemoteIngressReason) {
        self.transition_to_non_ready(RemoteIngressStatus::Blocked(reason));
    }

    fn stopped(&self) {
        self.transition_to_non_ready(RemoteIngressStatus::Stopped);
    }

    #[cfg(test)]
    pub(crate) fn ready_for_test(&self) {
        self.ready();
    }

    #[cfg(test)]
    pub(crate) fn blocked_for_test(&self, reason: RemoteIngressReason) {
        self.blocked(reason);
    }
}

impl fmt::Debug for RemoteIngressLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteIngressLifecycle(<redacted>)")
    }
}

pub(crate) struct RemoteWritePermit {
    lifecycle: Arc<RemoteIngressLifecycle>,
    generation: u64,
}

impl RemoteWritePermit {
    /// Diagnostic only. Safety comes from the active-permit count drained by
    /// non-ready transitions, not from callers polling this value.
    pub(crate) fn is_current(&self) -> bool {
        let snapshot = self.lifecycle.snapshot();
        snapshot.status == RemoteIngressStatus::Ready && snapshot.generation == self.generation
    }
}

impl Drop for RemoteWritePermit {
    fn drop(&mut self) {
        let mut snapshot = self
            .lifecycle
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        snapshot.active_permits = snapshot.active_permits.saturating_sub(1);
        self.lifecycle.changed.notify_all();
    }
}

impl fmt::Debug for RemoteWritePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteWritePermit(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RemoteIngressError {
    #[error("REMOTE_INGRESS_STATE")]
    State,
    #[error("REMOTE_INGRESS_CLIENT")]
    Client,
    #[error("REMOTE_INGRESS_UNAVAILABLE")]
    Unavailable,
    #[error("REMOTE_INGRESS_PROTOCOL")]
    Protocol,
    #[error("REMOTE_INGRESS_CRYPTO")]
    Crypto,
    #[error("REMOTE_INGRESS_APPLICATION")]
    Application,
    #[error("REMOTE_INGRESS_BINDING")]
    Binding,
    #[error("REMOTE_INGRESS_AUTHORITY")]
    Authority,
}

impl From<PairingCoordinatorError> for RemoteIngressError {
    fn from(_: PairingCoordinatorError) -> Self {
        Self::Binding
    }
}

impl From<RemoteCryptoError> for RemoteIngressError {
    fn from(_: RemoteCryptoError) -> Self {
        Self::Crypto
    }
}

impl From<RemoteMailboxError> for RemoteIngressError {
    fn from(error: RemoteMailboxError) -> Self {
        match error {
            RemoteMailboxError::Unavailable | RemoteMailboxError::HttpStatus(_) => {
                Self::Unavailable
            }
            RemoteMailboxError::InvalidConfig => Self::Client,
            RemoteMailboxError::InvalidState
            | RemoteMailboxError::StateConflict
            | RemoteMailboxError::Sqlite(_)
            | RemoteMailboxError::Io(_) => Self::State,
            RemoteMailboxError::InvalidFrame
            | RemoteMailboxError::InvalidAck
            | RemoteMailboxError::Protocol
            | RemoteMailboxError::Json(_) => Self::Protocol,
        }
    }
}

/// A durable pending Host-to-device frame. A receipt records the inbound
/// sequence it answers; a projection has no inbound association.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingIngressFrame {
    pub(crate) outbound_sequence: u64,
    pub(crate) inbound_sequence: Option<u64>,
    pub(crate) canonical_frame_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InboundCursor {
    pub(crate) read_through_sequence: u64,
    pub(crate) applied_through_sequence: u64,
    pub(crate) acked_through_sequence: u64,
}

/// E2c's storage contract. The eventual SQLite adapter must make each method a
/// single FULL-synchronous transaction. In particular, a response association
/// is durable before publish, and marking it applied verifies that association.
pub(crate) trait RemoteIngressState: Send + 'static {
    fn validate(&mut self) -> Result<(), RemoteIngressError>;

    fn inbound_cursor(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<InboundCursor, RemoteIngressError>;

    fn persist_read_through(
        &mut self,
        binding: &ActiveRemoteBinding,
        sequence: u64,
    ) -> Result<(), RemoteIngressError>;

    fn pending_host_frame(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<Option<PendingIngressFrame>, RemoteIngressError>;

    fn reserve_host_sequence(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<u64, RemoteIngressError>;

    fn store_pending_projection(
        &mut self,
        binding: &ActiveRemoteBinding,
        outbound_sequence: u64,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteIngressError>;

    fn store_pending_response(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        outbound_sequence: u64,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteIngressError>;

    fn mark_response_applied(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        outbound_sequence: u64,
    ) -> Result<(), RemoteIngressError>;

    fn complete_response_ack(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        outbound_sequence: u64,
    ) -> Result<(), RemoteIngressError>;

    fn clear_published_projection(
        &mut self,
        binding: &ActiveRemoteBinding,
        outbound_sequence: u64,
    ) -> Result<(), RemoteIngressError>;

    fn persist_poison(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        reason_code: PoisonReasonCode,
    ) -> Result<(), RemoteIngressError>;

    fn pending_poison(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<Option<DurablePoisonDisposition>, RemoteIngressError>;

    fn complete_poison_ack(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
    ) -> Result<(), RemoteIngressError>;
}

impl RemoteIngressState for RemoteMailboxState {
    fn validate(&mut self) -> Result<(), RemoteIngressError> {
        self.validate_ingress_state().map_err(Into::into)
    }

    fn inbound_cursor(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<InboundCursor, RemoteIngressError> {
        self.cursor(
            &binding.mailbox_id,
            RemoteDirection::DeviceToHost,
            binding.pairing_epoch,
        )
        .map(|cursor| InboundCursor {
            read_through_sequence: cursor.read_through_sequence,
            applied_through_sequence: cursor.applied_through_sequence,
            acked_through_sequence: cursor.acked_through_sequence,
        })
        .map_err(Into::into)
    }

    fn persist_read_through(
        &mut self,
        binding: &ActiveRemoteBinding,
        sequence: u64,
    ) -> Result<(), RemoteIngressError> {
        self.persist_read_through_sequence(
            &binding.mailbox_id,
            RemoteDirection::DeviceToHost,
            binding.pairing_epoch,
            sequence,
        )
        .map_err(Into::into)
    }

    fn pending_host_frame(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<Option<PendingIngressFrame>, RemoteIngressError> {
        self.pending_outbound_frame(
            &binding.mailbox_id,
            RemoteDirection::HostToDevice,
            binding.pairing_epoch,
        )
        .map(|pending| {
            pending.map(|frame| PendingIngressFrame {
                outbound_sequence: frame.sequence,
                inbound_sequence: frame.inbound_sequence,
                canonical_frame_bytes: frame.canonical_frame_bytes,
            })
        })
        .map_err(Into::into)
    }

    fn reserve_host_sequence(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<u64, RemoteIngressError> {
        self.reserve_outbound_sequence(
            &binding.mailbox_id,
            RemoteDirection::HostToDevice,
            binding.pairing_epoch,
        )
        .map_err(Into::into)
    }

    fn store_pending_projection(
        &mut self,
        binding: &ActiveRemoteBinding,
        outbound_sequence: u64,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteIngressError> {
        self.store_pending_outbound_frame(
            &binding.mailbox_id,
            RemoteDirection::HostToDevice,
            binding.pairing_epoch,
            outbound_sequence,
            canonical_frame_bytes,
        )
        .map_err(Into::into)
    }

    fn store_pending_response(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        outbound_sequence: u64,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteIngressError> {
        self.store_pending_response_frame(
            &binding.mailbox_id,
            binding.pairing_epoch,
            inbound_sequence,
            outbound_sequence,
            canonical_frame_bytes,
        )
        .map_err(Into::into)
    }

    fn mark_response_applied(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        outbound_sequence: u64,
    ) -> Result<(), RemoteIngressError> {
        RemoteMailboxState::mark_response_applied(
            self,
            &binding.mailbox_id,
            binding.pairing_epoch,
            inbound_sequence,
            outbound_sequence,
        )
        .map_err(Into::into)
    }

    fn complete_response_ack(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        outbound_sequence: u64,
    ) -> Result<(), RemoteIngressError> {
        RemoteMailboxState::complete_response_ack(
            self,
            &binding.mailbox_id,
            binding.pairing_epoch,
            inbound_sequence,
            outbound_sequence,
        )
        .map_err(Into::into)
    }

    fn clear_published_projection(
        &mut self,
        binding: &ActiveRemoteBinding,
        outbound_sequence: u64,
    ) -> Result<(), RemoteIngressError> {
        self.clear_pending_outbound_frame(
            &binding.mailbox_id,
            RemoteDirection::HostToDevice,
            binding.pairing_epoch,
            outbound_sequence,
        )
        .map_err(Into::into)
    }

    fn persist_poison(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
        reason_code: PoisonReasonCode,
    ) -> Result<(), RemoteIngressError> {
        self.persist_poison_disposition(
            &binding.mailbox_id,
            binding.pairing_epoch,
            inbound_sequence,
            reason_code,
        )
        .map_err(Into::into)
    }

    fn pending_poison(
        &mut self,
        binding: &ActiveRemoteBinding,
    ) -> Result<Option<DurablePoisonDisposition>, RemoteIngressError> {
        self.pending_poison_disposition(&binding.mailbox_id, binding.pairing_epoch)
            .map_err(Into::into)
    }

    fn complete_poison_ack(
        &mut self,
        binding: &ActiveRemoteBinding,
        inbound_sequence: u64,
    ) -> Result<(), RemoteIngressError> {
        RemoteMailboxState::complete_poison_ack(
            self,
            &binding.mailbox_id,
            binding.pairing_epoch,
            inbound_sequence,
        )
        .map_err(Into::into)
    }
}

/// Host-role only Relay data-plane operations. Relay ACK is deliberately not
/// represented as command success.
pub(crate) trait RemoteMailboxClient: Send {
    fn read_device_to_host(
        &mut self,
        mailbox_id: &str,
        epoch: u64,
        after_sequence: u64,
    ) -> Result<Vec<Vec<u8>>, RemoteIngressError>;

    fn publish_host_to_device(
        &mut self,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteIngressError>;

    fn ack_device_to_host(
        &mut self,
        mailbox_id: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<(), RemoteIngressError>;
}

impl RemoteMailboxClient for HostRelayV2Client {
    fn read_device_to_host(
        &mut self,
        mailbox_id: &str,
        epoch: u64,
        after_sequence: u64,
    ) -> Result<Vec<Vec<u8>>, RemoteIngressError> {
        self.read_device_to_host_frames(mailbox_id, epoch, after_sequence)
            .map_err(Into::into)
    }

    fn publish_host_to_device(
        &mut self,
        canonical_frame_bytes: &[u8],
    ) -> Result<(), RemoteIngressError> {
        self.publish_frame(canonical_frame_bytes)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn ack_device_to_host(
        &mut self,
        mailbox_id: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<(), RemoteIngressError> {
        HostRelayV2Client::ack_device_to_host(self, mailbox_id, epoch, sequence)
            .map(|_| ())
            .map_err(Into::into)
    }
}

pub(crate) trait RemoteMailboxClientFactory: Send + Sync + 'static {
    fn validate(&self) -> Result<(), RemoteIngressError>;

    fn connect(
        &self,
        binding: &ActiveRemoteBinding,
    ) -> Result<Box<dyn RemoteMailboxClient>, RemoteIngressError>;
}

pub(crate) struct HostRelayV2ClientFactory {
    relay_host_origin: String,
    allow_loopback_test_http: bool,
}

impl HostRelayV2ClientFactory {
    pub(crate) fn new(
        relay_host_origin: String,
        allow_loopback_test_http: bool,
    ) -> Result<Self, RemoteIngressError> {
        let factory = Self {
            relay_host_origin,
            allow_loopback_test_http,
        };
        factory.validate()?;
        Ok(factory)
    }
}

impl fmt::Debug for HostRelayV2ClientFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRelayV2ClientFactory")
            .field("relay_host_origin", &"<redacted-origin>")
            .field("allow_loopback_test_http", &self.allow_loopback_test_http)
            .finish()
    }
}

impl RemoteMailboxClientFactory for HostRelayV2ClientFactory {
    fn validate(&self) -> Result<(), RemoteIngressError> {
        // The production client owns the authoritative URL validator. A fixed
        // non-secret placeholder bearer lets startup validate the origin before
        // any active binding exists.
        HostRelayV2Client::new(
            &self.relay_host_origin,
            "host-client-origin-validation-placeholder",
            self.allow_loopback_test_http,
        )
        .map(|_| ())
        .map_err(Into::into)
    }

    fn connect(
        &self,
        binding: &ActiveRemoteBinding,
    ) -> Result<Box<dyn RemoteMailboxClient>, RemoteIngressError> {
        HostRelayV2Client::new(
            &self.relay_host_origin,
            binding.host_bearer.as_str(),
            self.allow_loopback_test_http,
        )
        .map(|client| Box::new(client) as Box<dyn RemoteMailboxClient>)
        .map_err(Into::into)
    }
}

pub(crate) trait RemoteIngressIdentity: Send + Sync + 'static {
    fn decrypt_from_device(
        &self,
        frame: &OpaqueFrame,
        context: &SharedContext,
    ) -> Result<Value, RemoteIngressError>;

    fn encrypt_for_device(
        &self,
        metadata: FrameMetadata,
        plaintext: &Value,
        device_agreement_public_sec1: &[u8; 65],
        context: &SharedContext,
        padding: &[u8],
    ) -> Result<OpaqueFrame, RemoteIngressError>;
}

impl RemoteIngressIdentity for EndpointKeys {
    fn decrypt_from_device(
        &self,
        frame: &OpaqueFrame,
        context: &SharedContext,
    ) -> Result<Value, RemoteIngressError> {
        EndpointKeys::decrypt_from_device(self, frame, context).map_err(Into::into)
    }

    fn encrypt_for_device(
        &self,
        metadata: FrameMetadata,
        plaintext: &Value,
        device_agreement_public_sec1: &[u8; 65],
        context: &SharedContext,
        padding: &[u8],
    ) -> Result<OpaqueFrame, RemoteIngressError> {
        encrypt(
            metadata,
            plaintext,
            self,
            device_agreement_public_sec1,
            context,
            padding,
        )
        .map_err(Into::into)
    }
}

/// Generic only to let focused tests prove the revoke/replacement race. The
/// production implementation delegates directly to `PairingCoordinator`.
pub(crate) trait RemoteAdmissionCoordinator: Send + Sync + 'static {
    type Guard<'a>
    where
        Self: 'a;

    fn command_guard(&self) -> Result<Self::Guard<'_>, RemoteIngressError>;

    fn active_binding_locked(
        &self,
        guard: &Self::Guard<'_>,
    ) -> Result<Option<ActiveRemoteBinding>, RemoteIngressError>;
}

impl RemoteAdmissionCoordinator for PairingCoordinator {
    type Guard<'a> = DeviceCommandGuard<'a>;

    fn command_guard(&self) -> Result<Self::Guard<'_>, RemoteIngressError> {
        PairingCoordinator::command_guard(self).map_err(Into::into)
    }

    fn active_binding_locked(
        &self,
        guard: &Self::Guard<'_>,
    ) -> Result<Option<ActiveRemoteBinding>, RemoteIngressError> {
        PairingCoordinator::active_binding_locked(self, guard).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteAuthorityFailure {
    /// No durable journal claim exists; retrying the exact frame is safe.
    Retryable,
    /// The facade detected an invariant or storage failure.
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteCommandDisposition {
    Receipt(CommandReceipt),
    RetryableNoAck,
    Fatal,
}

/// Frozen E2 facade contract. It receives the already-held coordinator guard,
/// so it must call its locked core and must not reacquire the non-reentrant gate.
pub(crate) trait ProductRemoteCommandAuthority<C: RemoteAdmissionCoordinator>:
    Send + Sync + 'static
{
    fn projection_locked(
        &self,
        guard: &C::Guard<'_>,
        binding: &ActiveRemoteBinding,
    ) -> Result<ProjectionPayload, RemoteAuthorityFailure>;

    fn execute_locked(
        &self,
        guard: &C::Guard<'_>,
        binding: &ActiveRemoteBinding,
        command: ParsedProductCommand,
    ) -> RemoteCommandDisposition;
}

pub(crate) trait RemoteIngressClock: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Default)]
pub(crate) struct SystemRemoteIngressClock;

impl RemoteIngressClock for SystemRemoteIngressClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub(crate) struct RemoteCommandIngress<C, A, S, F, I, T>
where
    C: RemoteAdmissionCoordinator,
    A: ProductRemoteCommandAuthority<C>,
    S: RemoteIngressState,
    F: RemoteMailboxClientFactory,
    I: RemoteIngressIdentity,
    T: RemoteIngressClock,
{
    coordinator: Arc<C>,
    authority: Arc<A>,
    state: S,
    clients: Arc<F>,
    identity: Arc<I>,
    clock: Arc<T>,
    lifecycle: Arc<RemoteIngressLifecycle>,
    last_projection: Option<(String, u64, u64, String)>,
}

impl<C, A, S, F, I, T> fmt::Debug for RemoteCommandIngress<C, A, S, F, I, T>
where
    C: RemoteAdmissionCoordinator,
    A: ProductRemoteCommandAuthority<C>,
    S: RemoteIngressState,
    F: RemoteMailboxClientFactory,
    I: RemoteIngressIdentity,
    T: RemoteIngressClock,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteCommandIngress")
            .field("coordinator", &"<redacted>")
            .field("authority", &"<redacted>")
            .field("state", &"<redacted>")
            .field("client_factory", &"<redacted>")
            .field("identity", &"<redacted>")
            .finish()
    }
}

impl<C, A, S, F, I, T> RemoteCommandIngress<C, A, S, F, I, T>
where
    C: RemoteAdmissionCoordinator,
    A: ProductRemoteCommandAuthority<C>,
    S: RemoteIngressState,
    F: RemoteMailboxClientFactory,
    I: RemoteIngressIdentity,
    T: RemoteIngressClock,
{
    pub(crate) fn new(
        coordinator: Arc<C>,
        authority: Arc<A>,
        state: S,
        clients: Arc<F>,
        identity: Arc<I>,
        clock: Arc<T>,
        lifecycle: Arc<RemoteIngressLifecycle>,
    ) -> Self {
        Self {
            coordinator,
            authority,
            state,
            clients,
            identity,
            clock,
            lifecycle,
            last_projection: None,
        }
    }

    /// Opens the worker and returns a one-shot ready barrier. Success is sent
    /// only after state/client validation, active-binding reconciliation, and
    /// entry into the live polling thread.
    pub(crate) fn start(
        mut self,
    ) -> Result<(RemoteCommandIngressHandle, Receiver<()>), RemoteIngressError> {
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker_stop = Arc::clone(&stop);
        let worker_lifecycle = Arc::clone(&self.lifecycle);
        let handle_lifecycle = Arc::clone(&self.lifecycle);
        let worker = thread::Builder::new()
            .name("m3e-remote-command-ingress".into())
            .spawn(move || {
                let result =
                    catch_unwind(AssertUnwindSafe(|| self.run_worker(&worker_stop, ready_tx)));
                match result {
                    Ok(Ok(())) => worker_lifecycle.stopped(),
                    Ok(Err(error)) => worker_lifecycle.blocked(blocked_reason(error)),
                    Err(_) => worker_lifecycle.blocked(RemoteIngressReason::WorkerPanic),
                }
            })
            .map_err(|_| RemoteIngressError::State)?;
        Ok((
            RemoteCommandIngressHandle {
                stop,
                lifecycle: handle_lifecycle,
                worker: Some(worker),
            },
            ready_rx,
        ))
    }

    fn run_worker(
        &mut self,
        stop: &AtomicBool,
        ready: mpsc::SyncSender<()>,
    ) -> Result<(), RemoteIngressError> {
        self.initial_reconciliation()?;
        let mut ready_sent = false;
        while !stop.load(Ordering::Acquire) {
            match self.poll_once() {
                Ok(RemotePollOutcome::Idle | RemotePollOutcome::Applied) => {
                    self.lifecycle.ready();
                    if !ready_sent {
                        ready.send(()).map_err(|_| RemoteIngressError::State)?;
                        ready_sent = true;
                    }
                    thread::sleep(IDLE_POLL_INTERVAL);
                }
                Err(RemoteIngressError::Unavailable) => {
                    self.lifecycle.degraded(RemoteIngressReason::Unavailable);
                    thread::sleep(ERROR_BACKOFF);
                }
                Err(RemoteIngressError::Binding) => {
                    self.lifecycle.degraded(RemoteIngressReason::Binding);
                    thread::sleep(ERROR_BACKOFF);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn initial_reconciliation(&mut self) -> Result<(), RemoteIngressError> {
        self.state.validate()?;
        self.clients.validate()?;
        let binding = self.current_binding()?;
        if let Some(binding) = binding {
            let cursor = self.state.inbound_cursor(&binding)?;
            let pending = self.state.pending_host_frame(&binding)?;
            let poison = self.state.pending_poison(&binding)?;
            validate_pending_recovery(&binding, cursor, pending.as_ref(), poison.as_ref())?;
            // Constructing the client validates the active bearer without making
            // remote readiness depend on Relay reachability. The polling loop
            // performs byte-exact recovery on its first iteration.
            let _client = self.clients.connect(&binding)?;
        }
        Ok(())
    }

    fn poll_once(&mut self) -> Result<RemotePollOutcome, RemoteIngressError> {
        let Some(binding) = self.current_binding()? else {
            self.last_projection = None;
            return Ok(RemotePollOutcome::Idle);
        };
        let mut client = self.clients.connect(&binding)?;
        if self.recover_poison(&binding, client.as_mut())? {
            return Ok(RemotePollOutcome::Applied);
        }
        if self.recover_pending(&binding, client.as_mut())? {
            return Ok(RemotePollOutcome::Applied);
        }
        let cursor = self.state.inbound_cursor(&binding)?;
        if cursor.applied_through_sequence > cursor.acked_through_sequence {
            return Err(RemoteIngressError::State);
        }
        let frames = client.read_device_to_host(
            &binding.mailbox_id,
            binding.pairing_epoch,
            cursor.acked_through_sequence,
        )?;
        if let Some(raw) = frames.first() {
            self.consume_frame(&binding, client.as_mut(), raw)?;
            return Ok(RemotePollOutcome::Applied);
        }
        self.publish_projection_if_changed(&binding, client.as_mut())
    }

    fn current_binding(&self) -> Result<Option<ActiveRemoteBinding>, RemoteIngressError> {
        let guard = self.coordinator.command_guard()?;
        self.coordinator.active_binding_locked(&guard)
    }

    fn recover_pending(
        &mut self,
        binding: &ActiveRemoteBinding,
        client: &mut dyn RemoteMailboxClient,
    ) -> Result<bool, RemoteIngressError> {
        let cursor = self.state.inbound_cursor(binding)?;
        let pending = self.state.pending_host_frame(binding)?;
        match pending {
            Some(pending) => {
                let parsed = parse_canonical_frame(&pending.canonical_frame_bytes)?;
                if parsed.mailbox_id != binding.mailbox_id
                    || parsed.epoch != binding.pairing_epoch
                    || parsed.direction != RemoteDirection::HostToDevice
                    || parsed.sequence != pending.outbound_sequence
                {
                    return Err(RemoteIngressError::State);
                }
                client.publish_host_to_device(&pending.canonical_frame_bytes)?;
                match pending.inbound_sequence {
                    Some(inbound) => {
                        if inbound < cursor.acked_through_sequence
                            || inbound < cursor.applied_through_sequence
                        {
                            return Err(RemoteIngressError::State);
                        }
                        if inbound > cursor.applied_through_sequence {
                            self.state.mark_response_applied(
                                binding,
                                inbound,
                                pending.outbound_sequence,
                            )?;
                        }
                        client.ack_device_to_host(
                            &binding.mailbox_id,
                            binding.pairing_epoch,
                            inbound,
                        )?;
                        self.state.complete_response_ack(
                            binding,
                            inbound,
                            pending.outbound_sequence,
                        )?;
                    }
                    None => self
                        .state
                        .clear_published_projection(binding, pending.outbound_sequence)?,
                }
                Ok(true)
            }
            None if cursor.applied_through_sequence > cursor.acked_through_sequence => {
                Err(RemoteIngressError::State)
            }
            None => Ok(false),
        }
    }

    fn recover_poison(
        &mut self,
        binding: &ActiveRemoteBinding,
        client: &mut dyn RemoteMailboxClient,
    ) -> Result<bool, RemoteIngressError> {
        let Some(poison) = self.state.pending_poison(binding)? else {
            return Ok(false);
        };
        client.ack_device_to_host(
            &binding.mailbox_id,
            binding.pairing_epoch,
            poison.inbound_sequence,
        )?;
        self.state
            .complete_poison_ack(binding, poison.inbound_sequence)?;
        Ok(true)
    }

    fn poison_and_ack(
        &mut self,
        binding: &ActiveRemoteBinding,
        client: &mut dyn RemoteMailboxClient,
        inbound_sequence: u64,
        reason_code: PoisonReasonCode,
    ) -> Result<(), RemoteIngressError> {
        self.state
            .persist_poison(binding, inbound_sequence, reason_code)?;
        client.ack_device_to_host(&binding.mailbox_id, binding.pairing_epoch, inbound_sequence)?;
        self.state.complete_poison_ack(binding, inbound_sequence)
    }

    fn consume_frame(
        &mut self,
        candidate: &ActiveRemoteBinding,
        client: &mut dyn RemoteMailboxClient,
        raw: &[u8],
    ) -> Result<(), RemoteIngressError> {
        let relay_frame = parse_canonical_frame(raw)?;
        if relay_frame.mailbox_id != candidate.mailbox_id
            || relay_frame.epoch != candidate.pairing_epoch
            || relay_frame.direction != RemoteDirection::DeviceToHost
        {
            return self.poison_and_ack(
                candidate,
                client,
                relay_frame.sequence,
                PoisonReasonCode::AuthenticationFailed,
            );
        }
        let cursor = self.state.inbound_cursor(candidate)?;
        if relay_frame.sequence <= cursor.acked_through_sequence
            || relay_frame.sequence < cursor.read_through_sequence
        {
            return Err(RemoteIngressError::Protocol);
        }
        self.state
            .persist_read_through(candidate, relay_frame.sequence)?;

        let context = shared_context(candidate);
        let crypto_frame = relay_to_crypto(&relay_frame);
        let plaintext = match self.identity.decrypt_from_device(&crypto_frame, &context) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                return self.poison_and_ack(
                    candidate,
                    client,
                    relay_frame.sequence,
                    PoisonReasonCode::AuthenticationFailed,
                );
            }
        };
        let canonical_plaintext = match canonical_value_bytes(&plaintext) {
            Ok(canonical) => canonical,
            Err(_) => {
                return self.poison_and_ack(
                    candidate,
                    client,
                    relay_frame.sequence,
                    PoisonReasonCode::ApplicationInvalid,
                );
            }
        };
        let envelope =
            match parse_application_envelope(&canonical_plaintext, &frame_binding(&relay_frame)) {
                Ok(envelope) => envelope,
                Err(_) => {
                    return self.poison_and_ack(
                        candidate,
                        client,
                        relay_frame.sequence,
                        PoisonReasonCode::ApplicationInvalid,
                    );
                }
            };
        let command = match envelope.payload {
            ApplicationPayload::Command(command) => command.command,
            _ => {
                return self.poison_and_ack(
                    candidate,
                    client,
                    relay_frame.sequence,
                    PoisonReasonCode::CommandInvalid,
                );
            }
        };
        let mapped = match ParsedProductCommand::try_from(command) {
            Ok(mapped) => mapped,
            Err(_) => {
                return self.poison_and_ack(
                    candidate,
                    client,
                    relay_frame.sequence,
                    PoisonReasonCode::CommandInvalid,
                );
            }
        };
        let guard = self.coordinator.command_guard()?;
        let current = self
            .coordinator
            .active_binding_locked(&guard)?
            .ok_or(RemoteIngressError::Binding)?;
        if !same_binding(candidate, &current) {
            return Err(RemoteIngressError::Binding);
        }
        let disposition = self.authority.execute_locked(&guard, &current, mapped);
        drop(guard);
        let receipt = match disposition {
            RemoteCommandDisposition::Receipt(receipt) => receipt,
            RemoteCommandDisposition::RetryableNoAck => {
                return Err(RemoteIngressError::Unavailable);
            }
            RemoteCommandDisposition::Fatal => return Err(RemoteIngressError::Authority),
        };

        let outbound_sequence = self.state.reserve_host_sequence(&current)?;
        let message_id = random_message_id()?;
        let receipt_envelope = ApplicationEnvelope {
            common: EnvelopeCommon {
                schema: APPLICATION_SCHEMA.into(),
                kind: EnvelopeKind::Receipt,
                mailbox_id: current.mailbox_id.clone(),
                direction: FrameDirection::HostToDevice,
                epoch: current.pairing_epoch,
                sequence: outbound_sequence,
                message_id: message_id.clone(),
            },
            payload: ApplicationPayload::Receipt(ReceiptPayload { receipt }),
        };
        let canonical_application = canonical_encode_application_envelope(&receipt_envelope)
            .map_err(|_| RemoteIngressError::Application)?;
        let frame = self.encrypt_host_frame(
            &current,
            outbound_sequence,
            &message_id,
            &canonical_application,
        )?;
        let canonical_frame =
            serde_json::to_vec(&frame).map_err(|_| RemoteIngressError::Protocol)?;
        self.state.store_pending_response(
            &current,
            relay_frame.sequence,
            outbound_sequence,
            &canonical_frame,
        )?;
        client.publish_host_to_device(&canonical_frame)?;
        self.state
            .mark_response_applied(&current, relay_frame.sequence, outbound_sequence)?;
        client.ack_device_to_host(
            &current.mailbox_id,
            current.pairing_epoch,
            relay_frame.sequence,
        )?;
        self.state
            .complete_response_ack(&current, relay_frame.sequence, outbound_sequence)?;
        self.last_projection = None;
        Ok(())
    }

    fn publish_projection_if_changed(
        &mut self,
        binding: &ActiveRemoteBinding,
        client: &mut dyn RemoteMailboxClient,
    ) -> Result<RemotePollOutcome, RemoteIngressError> {
        let guard = self.coordinator.command_guard()?;
        let current = self
            .coordinator
            .active_binding_locked(&guard)?
            .ok_or(RemoteIngressError::Binding)?;
        if !same_binding(binding, &current) {
            return Err(RemoteIngressError::Binding);
        }
        let projection = self
            .authority
            .projection_locked(&guard, &current)
            .map_err(|failure| match failure {
                RemoteAuthorityFailure::Retryable => RemoteIngressError::Unavailable,
                RemoteAuthorityFailure::Fatal => RemoteIngressError::Authority,
            })?;
        let projection_key = (
            current.mailbox_id.clone(),
            current.pairing_epoch,
            projection.snapshot.snapshot_seq,
            projection.snapshot.digest.clone(),
        );
        if self.last_projection.as_ref() == Some(&projection_key) {
            return Ok(RemotePollOutcome::Idle);
        }
        let outbound_sequence = self.state.reserve_host_sequence(&current)?;
        let message_id = random_message_id()?;
        let envelope = ApplicationEnvelope {
            common: EnvelopeCommon {
                schema: APPLICATION_SCHEMA.into(),
                kind: EnvelopeKind::Projection,
                mailbox_id: current.mailbox_id.clone(),
                direction: FrameDirection::HostToDevice,
                epoch: current.pairing_epoch,
                sequence: outbound_sequence,
                message_id: message_id.clone(),
            },
            payload: ApplicationPayload::Projection(Box::new(projection)),
        };
        let canonical_application = canonical_encode_application_envelope(&envelope)
            .map_err(|_| RemoteIngressError::Application)?;
        let frame = self.encrypt_host_frame(
            &current,
            outbound_sequence,
            &message_id,
            &canonical_application,
        )?;
        let canonical_frame =
            serde_json::to_vec(&frame).map_err(|_| RemoteIngressError::Protocol)?;
        self.state
            .store_pending_projection(&current, outbound_sequence, &canonical_frame)?;
        client.publish_host_to_device(&canonical_frame)?;
        self.state
            .clear_published_projection(&current, outbound_sequence)?;
        self.last_projection = Some(projection_key);
        Ok(RemotePollOutcome::Applied)
    }

    fn encrypt_host_frame(
        &self,
        binding: &ActiveRemoteBinding,
        sequence: u64,
        message_id: &str,
        canonical_application: &[u8],
    ) -> Result<RelayOpaqueFrame, RemoteIngressError> {
        let value: Value = serde_json::from_slice(canonical_application)
            .map_err(|_| RemoteIngressError::Application)?;
        let padding = random_padding(canonical_application.len())?;
        let now = self.clock.now().unix_timestamp();
        let expires_at = now
            .checked_add(OUTBOUND_TTL_SECONDS)
            .ok_or(RemoteIngressError::State)?;
        let frame = self.identity.encrypt_for_device(
            FrameMetadata {
                schema: FRAME_SCHEMA.into(),
                crypto_suite: FRAME_SUITE.into(),
                mailbox_id: binding.mailbox_id.clone(),
                direction: Direction::HostToDevice,
                epoch: binding.pairing_epoch,
                sequence,
                message_id: message_id.into(),
                issued_at: now,
                expires_at,
                nonce: String::new(),
            },
            &value,
            &binding.device_agreement_public_sec1,
            &shared_context(binding),
            &padding,
        )?;
        Ok(crypto_to_relay(frame))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePollOutcome {
    Idle,
    Applied,
}

pub(crate) struct RemoteCommandIngressHandle {
    stop: Arc<AtomicBool>,
    lifecycle: Arc<RemoteIngressLifecycle>,
    worker: Option<JoinHandle<()>>,
}

impl RemoteCommandIngressHandle {
    #[cfg(test)]
    pub(crate) fn lifecycle(&self) -> Arc<RemoteIngressLifecycle> {
        Arc::clone(&self.lifecycle)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub(crate) fn acquire_running_write_permit(
        &self,
    ) -> Result<RemoteWritePermit, RemoteIngressError> {
        let permit = self.lifecycle.acquire_write_permit()?;
        if self.is_finished() || !permit.is_current() {
            return Err(RemoteIngressError::Unavailable);
        }
        Ok(permit)
    }

    pub(crate) fn shutdown_and_join(mut self) -> Result<(), RemoteIngressError> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| RemoteIngressError::Authority)?;
        }
        match self.lifecycle.snapshot().status {
            RemoteIngressStatus::Stopped => Ok(()),
            RemoteIngressStatus::Blocked(reason) => Err(reason_error(reason)),
            _ => Err(RemoteIngressError::State),
        }
    }
}

impl fmt::Debug for RemoteCommandIngressHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteCommandIngressHandle")
            .field("lifecycle", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn blocked_reason(error: RemoteIngressError) -> RemoteIngressReason {
    match error {
        RemoteIngressError::State => RemoteIngressReason::State,
        RemoteIngressError::Client | RemoteIngressError::Authority => RemoteIngressReason::Internal,
        RemoteIngressError::Unavailable => RemoteIngressReason::Unavailable,
        RemoteIngressError::Protocol | RemoteIngressError::Application => {
            RemoteIngressReason::Protocol
        }
        RemoteIngressError::Crypto => RemoteIngressReason::Authentication,
        RemoteIngressError::Binding => RemoteIngressReason::Binding,
    }
}

fn reason_error(reason: RemoteIngressReason) -> RemoteIngressError {
    match reason {
        RemoteIngressReason::Unavailable => RemoteIngressError::Unavailable,
        RemoteIngressReason::State => RemoteIngressError::State,
        RemoteIngressReason::Internal | RemoteIngressReason::WorkerPanic => {
            RemoteIngressError::Authority
        }
        RemoteIngressReason::Protocol => RemoteIngressError::Protocol,
        RemoteIngressReason::Authentication => RemoteIngressError::Crypto,
        RemoteIngressReason::Binding => RemoteIngressError::Binding,
    }
}

impl Drop for RemoteCommandIngressHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn same_binding(left: &ActiveRemoteBinding, right: &ActiveRemoteBinding) -> bool {
    left.device_alias == right.device_alias
        && left.pairing_epoch == right.pairing_epoch
        && left.mailbox_id == right.mailbox_id
        && crate::run_binding::constant_time_eq(
            left.host_bearer.as_bytes(),
            right.host_bearer.as_bytes(),
        )
        && crate::run_binding::constant_time_eq(
            &left.host_signing_commitment,
            &right.host_signing_commitment,
        )
        && crate::run_binding::constant_time_eq(
            &left.host_agreement_commitment,
            &right.host_agreement_commitment,
        )
        && crate::run_binding::constant_time_eq(
            &left.device_signing_commitment,
            &right.device_signing_commitment,
        )
        && crate::run_binding::constant_time_eq(
            &left.device_agreement_commitment,
            &right.device_agreement_commitment,
        )
        && crate::run_binding::constant_time_eq(
            &left.device_signing_public_sec1,
            &right.device_signing_public_sec1,
        )
        && crate::run_binding::constant_time_eq(
            &left.device_agreement_public_sec1,
            &right.device_agreement_public_sec1,
        )
}

fn validate_pending_recovery(
    binding: &ActiveRemoteBinding,
    cursor: InboundCursor,
    pending: Option<&PendingIngressFrame>,
    poison: Option<&DurablePoisonDisposition>,
) -> Result<(), RemoteIngressError> {
    if cursor.read_through_sequence < cursor.applied_through_sequence
        || cursor.applied_through_sequence < cursor.acked_through_sequence
    {
        return Err(RemoteIngressError::State);
    }
    if pending.is_some() && poison.is_some() {
        return Err(RemoteIngressError::State);
    }
    match pending {
        Some(pending) => {
            let frame = parse_canonical_frame(&pending.canonical_frame_bytes)?;
            if frame.mailbox_id != binding.mailbox_id
                || frame.epoch != binding.pairing_epoch
                || frame.direction != RemoteDirection::HostToDevice
                || frame.sequence != pending.outbound_sequence
                || pending.inbound_sequence.is_some_and(|inbound| {
                    inbound < cursor.applied_through_sequence
                        || inbound <= cursor.acked_through_sequence
                        || inbound > cursor.read_through_sequence
                })
            {
                return Err(RemoteIngressError::State);
            }
        }
        None if cursor.applied_through_sequence > cursor.acked_through_sequence
            && poison
                .is_none_or(|value| value.inbound_sequence != cursor.applied_through_sequence) =>
        {
            return Err(RemoteIngressError::State);
        }
        None => {}
    }
    Ok(())
}

fn shared_context(binding: &ActiveRemoteBinding) -> SharedContext {
    SharedContext {
        mailbox_id: binding.mailbox_id.clone(),
        epoch: binding.pairing_epoch,
        host_signing_commitment: binding.host_signing_commitment,
        host_agreement_commitment: binding.host_agreement_commitment,
        device_signing_commitment: binding.device_signing_commitment,
        device_agreement_commitment: binding.device_agreement_commitment,
    }
}

fn relay_to_crypto(frame: &RelayOpaqueFrame) -> OpaqueFrame {
    OpaqueFrame {
        schema: frame.schema.clone(),
        crypto_suite: frame.crypto_suite.clone(),
        mailbox_id: frame.mailbox_id.clone(),
        direction: match frame.direction {
            RemoteDirection::HostToDevice => Direction::HostToDevice,
            RemoteDirection::DeviceToHost => Direction::DeviceToHost,
        },
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id.clone(),
        issued_at: frame.issued_at,
        expires_at: frame.expires_at,
        nonce: frame.nonce.clone(),
        ciphertext: frame.ciphertext.clone(),
    }
}

fn crypto_to_relay(frame: OpaqueFrame) -> RelayOpaqueFrame {
    RelayOpaqueFrame {
        schema: frame.schema,
        crypto_suite: frame.crypto_suite,
        mailbox_id: frame.mailbox_id,
        direction: match frame.direction {
            Direction::HostToDevice => RemoteDirection::HostToDevice,
            Direction::DeviceToHost => RemoteDirection::DeviceToHost,
        },
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id,
        issued_at: frame.issued_at,
        expires_at: frame.expires_at,
        nonce: frame.nonce,
        ciphertext: frame.ciphertext,
    }
}

fn frame_binding(frame: &RelayOpaqueFrame) -> FrameBinding {
    FrameBinding {
        schema: frame.schema.clone(),
        crypto_suite: frame.crypto_suite.clone(),
        mailbox_id: frame.mailbox_id.clone(),
        direction: match frame.direction {
            RemoteDirection::HostToDevice => FrameDirection::HostToDevice,
            RemoteDirection::DeviceToHost => FrameDirection::DeviceToHost,
        },
        epoch: frame.epoch,
        sequence: frame.sequence,
        message_id: frame.message_id.clone(),
    }
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, RemoteIngressError> {
    // `remote_crypto` already rejected duplicate/non-canonical plaintext. The
    // serde_json map representation uses lexical key order in this build, so
    // this recreates the exact canonical bytes required by the application parser.
    serde_json::to_vec(value).map_err(|_| RemoteIngressError::Application)
}

fn random_message_id() -> Result<String, RemoteIngressError> {
    let mut random = [0_u8; ID_RANDOM_BYTES];
    getrandom(&mut random).map_err(|_| RemoteIngressError::State)?;
    Ok(format!("msg-{}", lower_hex(&random)))
}

fn random_padding(canonical_json_len: usize) -> Result<Vec<u8>, RemoteIngressError> {
    let bucket = [512_usize, 2048, 8192, 32768, 65536]
        .into_iter()
        .find(|bucket| *bucket >= canonical_json_len.saturating_add(4))
        .ok_or(RemoteIngressError::Application)?;
    let mut padding = vec![0_u8; bucket - canonical_json_len - 4];
    getrandom(&mut padding).map_err(|_| RemoteIngressError::State)?;
    Ok(padding)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn _assert_protocol_error_is_content_free(error: CommandProtocolError) -> RemoteIngressError {
    match error {
        CommandProtocolError::Unavailable | CommandProtocolError::Internal => {
            RemoteIngressError::Unavailable
        }
        _ => RemoteIngressError::Application,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_application::{ReceiptAction, ReceiptErrorCode, ReceiptStatus};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use std::sync::{Mutex, MutexGuard};

    const APPLICATION_VECTORS: &str =
        include_str!("../../contracts/vectors/remote-application-v1.json");

    #[derive(Default)]
    struct FakeCoordinator {
        binding: Mutex<Option<ActiveRemoteBinding>>,
    }

    impl FakeCoordinator {
        fn new(binding: Option<ActiveRemoteBinding>) -> Self {
            Self {
                binding: Mutex::new(binding),
            }
        }

        fn replace(&self, binding: Option<ActiveRemoteBinding>) {
            *self.binding.lock().unwrap() = binding;
        }
    }

    impl RemoteAdmissionCoordinator for FakeCoordinator {
        type Guard<'a> = MutexGuard<'a, Option<ActiveRemoteBinding>>;

        fn command_guard(&self) -> Result<Self::Guard<'_>, RemoteIngressError> {
            self.binding.lock().map_err(|_| RemoteIngressError::State)
        }

        fn active_binding_locked(
            &self,
            guard: &Self::Guard<'_>,
        ) -> Result<Option<ActiveRemoteBinding>, RemoteIngressError> {
            Ok((*guard).clone())
        }
    }

    #[derive(Default)]
    struct FakeStateInner {
        validate_fails: bool,
        cursor: InboundCursor,
        next_outbound: u64,
        pending: Option<PendingIngressFrame>,
        poison: Option<DurablePoisonDisposition>,
        events: Vec<String>,
    }

    #[derive(Clone, Default)]
    struct FakeState {
        inner: Arc<Mutex<FakeStateInner>>,
    }

    impl RemoteIngressState for FakeState {
        fn validate(&mut self) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            inner.events.push("state.validate".into());
            if inner.validate_fails {
                Err(RemoteIngressError::State)
            } else {
                if inner.next_outbound == 0 {
                    inner.next_outbound = 1;
                }
                Ok(())
            }
        }

        fn inbound_cursor(
            &mut self,
            _binding: &ActiveRemoteBinding,
        ) -> Result<InboundCursor, RemoteIngressError> {
            Ok(self.inner.lock().unwrap().cursor)
        }

        fn persist_read_through(
            &mut self,
            _binding: &ActiveRemoteBinding,
            sequence: u64,
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            if sequence < inner.cursor.read_through_sequence {
                return Err(RemoteIngressError::State);
            }
            inner.cursor.read_through_sequence = sequence;
            inner.events.push(format!("state.read:{sequence}"));
            Ok(())
        }

        fn pending_host_frame(
            &mut self,
            _binding: &ActiveRemoteBinding,
        ) -> Result<Option<PendingIngressFrame>, RemoteIngressError> {
            Ok(self.inner.lock().unwrap().pending.clone())
        }

        fn reserve_host_sequence(
            &mut self,
            _binding: &ActiveRemoteBinding,
        ) -> Result<u64, RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            if inner.pending.is_some() {
                return Err(RemoteIngressError::State);
            }
            if inner.next_outbound == 0 {
                inner.next_outbound = 1;
            }
            let current = inner.next_outbound;
            inner.next_outbound += 1;
            inner.events.push(format!("state.reserve:{current}"));
            Ok(current)
        }

        fn store_pending_projection(
            &mut self,
            _binding: &ActiveRemoteBinding,
            outbound_sequence: u64,
            canonical_frame_bytes: &[u8],
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            inner.pending = Some(PendingIngressFrame {
                outbound_sequence,
                inbound_sequence: None,
                canonical_frame_bytes: canonical_frame_bytes.to_vec(),
            });
            inner
                .events
                .push(format!("state.store_projection:{outbound_sequence}"));
            Ok(())
        }

        fn store_pending_response(
            &mut self,
            _binding: &ActiveRemoteBinding,
            inbound_sequence: u64,
            outbound_sequence: u64,
            canonical_frame_bytes: &[u8],
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            inner.pending = Some(PendingIngressFrame {
                outbound_sequence,
                inbound_sequence: Some(inbound_sequence),
                canonical_frame_bytes: canonical_frame_bytes.to_vec(),
            });
            inner.events.push(format!(
                "state.store_response:{inbound_sequence}:{outbound_sequence}"
            ));
            Ok(())
        }

        fn mark_response_applied(
            &mut self,
            _binding: &ActiveRemoteBinding,
            inbound_sequence: u64,
            outbound_sequence: u64,
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            if inner.pending.as_ref().is_none_or(|pending| {
                pending.inbound_sequence != Some(inbound_sequence)
                    || pending.outbound_sequence != outbound_sequence
            }) {
                return Err(RemoteIngressError::State);
            }
            inner.cursor.applied_through_sequence = inbound_sequence;
            inner.events.push(format!(
                "state.applied:{inbound_sequence}:{outbound_sequence}"
            ));
            Ok(())
        }

        fn complete_response_ack(
            &mut self,
            _binding: &ActiveRemoteBinding,
            inbound_sequence: u64,
            outbound_sequence: u64,
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            if inner.cursor.applied_through_sequence != inbound_sequence
                || inner.pending.as_ref().is_none_or(|pending| {
                    pending.inbound_sequence != Some(inbound_sequence)
                        || pending.outbound_sequence != outbound_sequence
                })
            {
                return Err(RemoteIngressError::State);
            }
            inner.cursor.acked_through_sequence = inbound_sequence;
            inner.pending = None;
            inner.events.push(format!(
                "state.acked:{inbound_sequence}:{outbound_sequence}"
            ));
            Ok(())
        }

        fn clear_published_projection(
            &mut self,
            _binding: &ActiveRemoteBinding,
            outbound_sequence: u64,
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            if inner
                .pending
                .as_ref()
                .is_none_or(|pending| pending.outbound_sequence != outbound_sequence)
            {
                return Err(RemoteIngressError::State);
            }
            inner.pending = None;
            inner
                .events
                .push(format!("state.clear_projection:{outbound_sequence}"));
            Ok(())
        }

        fn persist_poison(
            &mut self,
            _binding: &ActiveRemoteBinding,
            inbound_sequence: u64,
            reason_code: PoisonReasonCode,
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            let poison = DurablePoisonDisposition {
                inbound_sequence,
                reason_code,
            };
            if inner.poison.is_some_and(|saved| saved != poison) {
                return Err(RemoteIngressError::State);
            }
            inner.poison = Some(poison);
            inner.cursor.applied_through_sequence = inbound_sequence;
            inner.events.push(format!(
                "state.poison:{inbound_sequence}:{}",
                reason_code.as_str()
            ));
            Ok(())
        }

        fn pending_poison(
            &mut self,
            _binding: &ActiveRemoteBinding,
        ) -> Result<Option<DurablePoisonDisposition>, RemoteIngressError> {
            let inner = self.inner.lock().unwrap();
            Ok(inner
                .poison
                .filter(|poison| poison.inbound_sequence > inner.cursor.acked_through_sequence))
        }

        fn complete_poison_ack(
            &mut self,
            _binding: &ActiveRemoteBinding,
            inbound_sequence: u64,
        ) -> Result<(), RemoteIngressError> {
            let mut inner = self.inner.lock().unwrap();
            if inner.cursor.applied_through_sequence != inbound_sequence
                || inner
                    .poison
                    .is_none_or(|poison| poison.inbound_sequence != inbound_sequence)
            {
                return Err(RemoteIngressError::State);
            }
            inner.cursor.acked_through_sequence = inbound_sequence;
            inner
                .events
                .push(format!("state.poison_acked:{inbound_sequence}"));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeMailboxData {
        frames: Vec<Vec<u8>>,
        published: Vec<Vec<u8>>,
        acks: Vec<u64>,
        events: Vec<String>,
        fail_publish_once: bool,
        fail_ack_once: bool,
        read_failures_remaining: usize,
        panic_on_read: bool,
    }

    struct FakeMailboxClient {
        data: Arc<Mutex<FakeMailboxData>>,
        replacement: Option<(Arc<FakeCoordinator>, ActiveRemoteBinding)>,
    }

    impl RemoteMailboxClient for FakeMailboxClient {
        fn read_device_to_host(
            &mut self,
            _mailbox_id: &str,
            _epoch: u64,
            after_sequence: u64,
        ) -> Result<Vec<Vec<u8>>, RemoteIngressError> {
            if let Some((coordinator, replacement)) = self.replacement.take() {
                coordinator.replace(Some(replacement));
            }
            let mut data = self.data.lock().unwrap();
            assert!(!data.panic_on_read, "injected ingress worker panic");
            if data.read_failures_remaining != 0 {
                data.read_failures_remaining -= 1;
                return Err(RemoteIngressError::Unavailable);
            }
            Ok(data
                .frames
                .iter()
                .filter(|raw| {
                    serde_json::from_slice::<RelayOpaqueFrame>(raw)
                        .is_ok_and(|frame| frame.sequence > after_sequence)
                })
                .cloned()
                .collect())
        }

        fn publish_host_to_device(
            &mut self,
            canonical_frame_bytes: &[u8],
        ) -> Result<(), RemoteIngressError> {
            let mut data = self.data.lock().unwrap();
            data.events.push("client.publish".into());
            data.published.push(canonical_frame_bytes.to_vec());
            if data.fail_publish_once {
                data.fail_publish_once = false;
                return Err(RemoteIngressError::Unavailable);
            }
            Ok(())
        }

        fn ack_device_to_host(
            &mut self,
            _mailbox_id: &str,
            _epoch: u64,
            sequence: u64,
        ) -> Result<(), RemoteIngressError> {
            let mut data = self.data.lock().unwrap();
            data.events.push(format!("client.ack:{sequence}"));
            if data.fail_ack_once {
                data.fail_ack_once = false;
                return Err(RemoteIngressError::Unavailable);
            }
            data.acks.push(sequence);
            Ok(())
        }
    }

    struct FakeClientFactory {
        data: Arc<Mutex<FakeMailboxData>>,
        validate_fails: bool,
        replacement: Mutex<Option<(Arc<FakeCoordinator>, ActiveRemoteBinding)>>,
    }

    impl RemoteMailboxClientFactory for FakeClientFactory {
        fn validate(&self) -> Result<(), RemoteIngressError> {
            if self.validate_fails {
                Err(RemoteIngressError::Client)
            } else {
                Ok(())
            }
        }

        fn connect(
            &self,
            _binding: &ActiveRemoteBinding,
        ) -> Result<Box<dyn RemoteMailboxClient>, RemoteIngressError> {
            Ok(Box::new(FakeMailboxClient {
                data: Arc::clone(&self.data),
                replacement: self.replacement.lock().unwrap().take(),
            }))
        }
    }

    #[derive(Default)]
    struct FakeIdentity {
        decrypted: Mutex<Option<Value>>,
        observed_contexts: Mutex<Vec<SharedContext>>,
        fail_decrypt: AtomicBool,
    }

    impl RemoteIngressIdentity for FakeIdentity {
        fn decrypt_from_device(
            &self,
            _frame: &OpaqueFrame,
            context: &SharedContext,
        ) -> Result<Value, RemoteIngressError> {
            self.observed_contexts.lock().unwrap().push(context.clone());
            if self.fail_decrypt.load(Ordering::Acquire) {
                return Err(RemoteIngressError::Crypto);
            }
            self.decrypted
                .lock()
                .unwrap()
                .clone()
                .ok_or(RemoteIngressError::Crypto)
        }

        fn encrypt_for_device(
            &self,
            metadata: FrameMetadata,
            plaintext: &Value,
            _device_agreement_public_sec1: &[u8; 65],
            context: &SharedContext,
            _padding: &[u8],
        ) -> Result<OpaqueFrame, RemoteIngressError> {
            self.observed_contexts.lock().unwrap().push(context.clone());
            Ok(OpaqueFrame {
                schema: metadata.schema,
                crypto_suite: metadata.crypto_suite,
                mailbox_id: metadata.mailbox_id,
                direction: metadata.direction,
                epoch: metadata.epoch,
                sequence: metadata.sequence,
                message_id: metadata.message_id,
                issued_at: metadata.issued_at,
                expires_at: metadata.expires_at,
                nonce: "AAAAAAAAAAAAAAAA".into(),
                ciphertext: URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(plaintext).map_err(|_| RemoteIngressError::Application)?,
                ),
            })
        }
    }

    struct FakeAuthority {
        executions: Arc<Mutex<Vec<String>>>,
        projections: Arc<Mutex<u32>>,
        disposition: RemoteCommandDisposition,
    }

    impl ProductRemoteCommandAuthority<FakeCoordinator> for FakeAuthority {
        fn projection_locked(
            &self,
            _guard: &<FakeCoordinator as RemoteAdmissionCoordinator>::Guard<'_>,
            _binding: &ActiveRemoteBinding,
        ) -> Result<ProjectionPayload, RemoteAuthorityFailure> {
            *self.projections.lock().unwrap() += 1;
            Ok(projection_from_vector())
        }

        fn execute_locked(
            &self,
            _guard: &<FakeCoordinator as RemoteAdmissionCoordinator>::Guard<'_>,
            _binding: &ActiveRemoteBinding,
            command: ParsedProductCommand,
        ) -> RemoteCommandDisposition {
            self.executions
                .lock()
                .unwrap()
                .push(command.request_id().to_owned());
            match &self.disposition {
                RemoteCommandDisposition::Receipt(receipt) => {
                    let mut receipt = receipt.clone();
                    receipt.request_id = command.request_id().into();
                    receipt.snapshot_seq = command.snapshot_seq();
                    receipt.snapshot_digest = command.snapshot_digest().into();
                    RemoteCommandDisposition::Receipt(receipt)
                }
                RemoteCommandDisposition::RetryableNoAck => {
                    RemoteCommandDisposition::RetryableNoAck
                }
                RemoteCommandDisposition::Fatal => RemoteCommandDisposition::Fatal,
            }
        }
    }

    struct FakeClock;

    impl RemoteIngressClock for FakeClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(1_788_000_001).unwrap()
        }
    }

    type TestIngress = RemoteCommandIngress<
        FakeCoordinator,
        FakeAuthority,
        FakeState,
        FakeClientFactory,
        FakeIdentity,
        FakeClock,
    >;

    fn outcome_unknown_receipt() -> RemoteCommandDisposition {
        RemoteCommandDisposition::Receipt(CommandReceipt {
            schema: "nomad.gateway.command-receipt.v1".into(),
            receipt_id: "receipt_00000001".into(),
            request_id: "request_00000001".into(),
            action: ReceiptAction::Reply,
            snapshot_seq: 7,
            snapshot_digest:
                "sha256:8d9d416e75ebcd7f0d94f0b9d722bb95b4ea8b087b8672e937bc75e0759b62bf".into(),
            accepted_at: "2026-08-27T00:00:01Z".into(),
            status: ReceiptStatus::OutcomeUnknown,
            error_code: ReceiptErrorCode("ERR_OUTCOME_UNKNOWN".into()),
            idempotent_replay: false,
        })
    }

    #[test]
    fn replacement_before_claim_has_zero_authority_and_zero_ack_effects() {
        let old = active_binding(7, 1);
        let replacement = active_binding(8, 2);
        let coordinator = Arc::new(FakeCoordinator::new(Some(old.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&old)],
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress(
            Arc::clone(&coordinator),
            &old,
            state.clone(),
            Arc::clone(&mailbox),
            Some((Arc::clone(&coordinator), replacement)),
            Arc::clone(&executions),
        );

        assert_eq!(ingress.poll_once(), Err(RemoteIngressError::Binding));
        assert!(executions.lock().unwrap().is_empty());
        assert!(mailbox.lock().unwrap().published.is_empty());
        assert!(mailbox.lock().unwrap().acks.is_empty());
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.read_through_sequence, 22);
        assert_eq!(state.cursor.applied_through_sequence, 0);
        assert!(state.pending.is_none());
    }

    #[test]
    fn valid_command_persists_receipt_before_publish_and_applied_before_ack() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
        );

        assert_eq!(ingress.poll_once(), Ok(RemotePollOutcome::Applied));
        assert_eq!(executions.lock().unwrap().as_slice(), ["request_00000001"]);
        assert_eq!(mailbox.lock().unwrap().acks, [22]);
        assert_eq!(mailbox.lock().unwrap().published.len(), 1);
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.applied_through_sequence, 22);
        assert_eq!(state.cursor.acked_through_sequence, 22);
        assert!(state.pending.is_none());
        assert_eq!(
            state.events,
            [
                "state.read:22",
                "state.reserve:1",
                "state.store_response:22:1",
                "state.applied:22:1",
                "state.acked:22:1",
            ]
        );
    }

    #[test]
    fn restart_republishes_exact_pending_receipt_then_acks_without_execution() {
        let binding = active_binding(7, 1);
        let pending_bytes = pending_receipt_frame(&binding, 9);
        let state = FakeState::default();
        {
            let mut inner = state.inner.lock().unwrap();
            inner.next_outbound = 10;
            inner.cursor = InboundCursor {
                read_through_sequence: 22,
                applied_through_sequence: 22,
                acked_through_sequence: 21,
            };
            inner.pending = Some(PendingIngressFrame {
                outbound_sequence: 9,
                inbound_sequence: Some(22),
                canonical_frame_bytes: pending_bytes.clone(),
            });
        }
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let mailbox = Arc::new(Mutex::new(FakeMailboxData::default()));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
        );

        assert_eq!(ingress.poll_once(), Ok(RemotePollOutcome::Applied));
        assert!(executions.lock().unwrap().is_empty());
        let mailbox = mailbox.lock().unwrap();
        assert_eq!(mailbox.published, [pending_bytes]);
        assert_eq!(mailbox.acks, [22]);
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.acked_through_sequence, 22);
        assert!(state.pending.is_none());
    }

    #[test]
    fn outcome_unknown_publish_ambiguity_reuses_exact_frame_without_redispatch() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            fail_publish_once: true,
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
        );

        assert_eq!(ingress.poll_once(), Err(RemoteIngressError::Unavailable));
        assert_eq!(executions.lock().unwrap().len(), 1);
        let first = mailbox.lock().unwrap().published[0].clone();
        let frame: RelayOpaqueFrame = serde_json::from_slice(&first).unwrap();
        let application: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(frame.ciphertext.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(
            application["payload"]["receipt"]["status"],
            "OutcomeUnknown"
        );
        assert_eq!(
            application["payload"]["receipt"]["error_code"],
            "ERR_OUTCOME_UNKNOWN"
        );
        let pending = state.inner.lock().unwrap().pending.clone().unwrap();
        assert_eq!(pending.canonical_frame_bytes, first);
        assert_eq!(pending.inbound_sequence, Some(22));

        assert_eq!(ingress.poll_once(), Ok(RemotePollOutcome::Applied));
        assert_eq!(executions.lock().unwrap().len(), 1);
        let mailbox = mailbox.lock().unwrap();
        assert_eq!(mailbox.published, [first.clone(), first]);
        assert_eq!(mailbox.acks, [22]);
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.applied_through_sequence, 22);
        assert_eq!(state.cursor.acked_through_sequence, 22);
        assert!(state.pending.is_none());
    }

    #[test]
    fn ambiguous_ack_keeps_exact_receipt_and_never_redispatches() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            fail_ack_once: true,
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
        );

        assert_eq!(ingress.poll_once(), Err(RemoteIngressError::Unavailable));
        assert_eq!(executions.lock().unwrap().len(), 1);
        let first = mailbox.lock().unwrap().published[0].clone();
        {
            let state = state.inner.lock().unwrap();
            assert_eq!(state.cursor.applied_through_sequence, 22);
            assert_eq!(state.cursor.acked_through_sequence, 0);
            assert_eq!(state.pending.as_ref().unwrap().canonical_frame_bytes, first);
        }

        assert_eq!(ingress.poll_once(), Ok(RemotePollOutcome::Applied));
        assert_eq!(executions.lock().unwrap().len(), 1);
        let mailbox = mailbox.lock().unwrap();
        assert_eq!(mailbox.published, [first.clone(), first]);
        assert_eq!(mailbox.acks, [22]);
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.acked_through_sequence, 22);
        assert!(state.pending.is_none());
    }

    #[test]
    fn retryable_no_ack_preserves_frame_for_exact_repoll_without_outbox() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress_with(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
            RemoteCommandDisposition::RetryableNoAck,
            false,
        );

        assert_eq!(ingress.poll_once(), Err(RemoteIngressError::Unavailable));
        assert_eq!(ingress.poll_once(), Err(RemoteIngressError::Unavailable));
        assert_eq!(executions.lock().unwrap().len(), 2);
        let mailbox = mailbox.lock().unwrap();
        assert!(mailbox.published.is_empty());
        assert!(mailbox.acks.is_empty());
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.read_through_sequence, 22);
        assert_eq!(state.cursor.applied_through_sequence, 0);
        assert_eq!(state.cursor.acked_through_sequence, 0);
        assert!(state.pending.is_none());
        assert!(state.poison.is_none());
    }

    #[test]
    fn fatal_disposition_has_no_receipt_or_ack_and_stops_worker() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress_with(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
            RemoteCommandDisposition::Fatal,
            false,
        );
        let (handle, ready) = ingress.start().unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        mailbox.lock().unwrap().published.clear();
        mailbox
            .lock()
            .unwrap()
            .frames
            .push(command_relay_frame(&binding));
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !matches!(
            handle.lifecycle().snapshot().status,
            RemoteIngressStatus::Blocked(_)
        ) && std::time::Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert!(matches!(
            handle.lifecycle().snapshot().status,
            RemoteIngressStatus::Blocked(_)
        ));
        assert_eq!(executions.lock().unwrap().len(), 1);
        assert!(mailbox.lock().unwrap().published.is_empty());
        assert!(mailbox.lock().unwrap().acks.is_empty());
        let state = state.inner.lock().unwrap();
        assert_eq!(state.cursor.applied_through_sequence, 0);
        assert!(state.pending.is_none());
        drop(state);
        drop(handle);
    }

    #[test]
    fn unauthenticated_frame_persists_content_free_poison_before_ack() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress_with(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
            outcome_unknown_receipt(),
            true,
        );

        assert_eq!(ingress.poll_once(), Ok(RemotePollOutcome::Applied));
        assert!(executions.lock().unwrap().is_empty());
        assert!(mailbox.lock().unwrap().published.is_empty());
        assert_eq!(mailbox.lock().unwrap().acks, [22]);
        let state = state.inner.lock().unwrap();
        assert_eq!(
            state.poison,
            Some(DurablePoisonDisposition {
                inbound_sequence: 22,
                reason_code: PoisonReasonCode::AuthenticationFailed,
            })
        );
        assert_eq!(state.cursor.applied_through_sequence, 22);
        assert_eq!(state.cursor.acked_through_sequence, 22);
        assert_eq!(
            state.events,
            [
                "state.read:22",
                "state.poison:22:AUTHENTICATION_FAILED",
                "state.poison_acked:22",
            ]
        );
    }

    #[test]
    fn malformed_application_is_durably_poisoned_without_authority_or_receipt() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress_with(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
            outcome_unknown_receipt(),
            false,
        );
        *ingress.identity.decrypted.lock().unwrap() = Some(serde_json::json!({
            "schema": "nomad.remote.application-envelope.v1",
            "kind": "command"
        }));

        assert_eq!(ingress.poll_once(), Ok(RemotePollOutcome::Applied));
        assert!(executions.lock().unwrap().is_empty());
        assert!(mailbox.lock().unwrap().published.is_empty());
        assert_eq!(mailbox.lock().unwrap().acks, [22]);
        let state = state.inner.lock().unwrap();
        assert_eq!(
            state.poison,
            Some(DurablePoisonDisposition {
                inbound_sequence: 22,
                reason_code: PoisonReasonCode::ApplicationInvalid,
            })
        );
        assert_eq!(state.cursor.acked_through_sequence, 22);
    }

    #[test]
    fn poison_ack_ambiguity_recovers_after_restart_without_authority_call() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            fail_ack_once: true,
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let mut ingress = ingress_with(
            Arc::clone(&coordinator),
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
            outcome_unknown_receipt(),
            true,
        );

        assert_eq!(ingress.poll_once(), Err(RemoteIngressError::Unavailable));
        assert!(executions.lock().unwrap().is_empty());
        assert_eq!(
            state.inner.lock().unwrap().cursor.applied_through_sequence,
            22
        );
        drop(ingress);

        let mut restarted = ingress_with(
            coordinator,
            &binding,
            state.clone(),
            Arc::clone(&mailbox),
            None,
            Arc::clone(&executions),
            outcome_unknown_receipt(),
            false,
        );
        assert_eq!(restarted.poll_once(), Ok(RemotePollOutcome::Applied));
        assert!(executions.lock().unwrap().is_empty());
        assert_eq!(mailbox.lock().unwrap().acks, [22]);
        assert_eq!(
            state.inner.lock().unwrap().cursor.acked_through_sequence,
            22
        );
    }

    #[test]
    fn ready_is_not_signalled_when_state_validation_fails() {
        let coordinator = Arc::new(FakeCoordinator::new(None));
        let state = FakeState::default();
        state.inner.lock().unwrap().validate_fails = true;
        let mailbox = Arc::new(Mutex::new(FakeMailboxData::default()));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress(
            coordinator,
            &active_binding(7, 1),
            state,
            mailbox,
            None,
            executions,
        );

        let (handle, ready) = ingress.start().unwrap();
        assert!(ready.recv_timeout(Duration::from_secs(1)).is_err());
        assert!(matches!(
            handle.lifecycle().snapshot().status,
            RemoteIngressStatus::Blocked(_)
        ));
        drop(handle);
    }

    #[test]
    fn ready_is_signalled_after_state_client_and_binding_reconciliation() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData::default()));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress(
            coordinator,
            &binding,
            state.clone(),
            mailbox,
            None,
            executions,
        );

        let (handle, ready) = ingress.start().unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            handle.lifecycle().snapshot().status,
            RemoteIngressStatus::Ready | RemoteIngressStatus::Degraded(_)
        ));
        assert_eq!(state.inner.lock().unwrap().events[0], "state.validate");
        drop(handle);
    }

    #[test]
    fn first_poll_fatal_never_signals_ready() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            frames: vec![command_relay_frame(&binding)],
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress_with(
            coordinator,
            &binding,
            state,
            mailbox,
            None,
            executions,
            RemoteCommandDisposition::Fatal,
            false,
        );
        let (handle, ready) = ingress.start().unwrap();
        assert!(ready.recv_timeout(Duration::from_secs(1)).is_err());
        assert!(matches!(
            handle.lifecycle().snapshot().status,
            RemoteIngressStatus::Blocked(RemoteIngressReason::Internal)
        ));
        let deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(handle.is_finished());
        drop(handle);
    }

    #[test]
    fn unavailable_first_poll_degrades_then_recovers_and_signals_ready_once() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData {
            read_failures_remaining: 1,
            ..FakeMailboxData::default()
        }));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress(coordinator, &binding, state, mailbox, None, executions);
        let lifecycle = Arc::clone(&ingress.lifecycle);
        let (handle, ready) = ingress.start().unwrap();
        assert!(ready.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(
            lifecycle.snapshot().status,
            RemoteIngressStatus::Degraded(RemoteIngressReason::Unavailable)
        );
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(lifecycle.snapshot().status, RemoteIngressStatus::Ready);
        handle.shutdown_and_join().unwrap();
        assert_eq!(lifecycle.snapshot().status, RemoteIngressStatus::Stopped);
    }

    #[test]
    fn worker_panic_after_ready_is_blocked_and_not_overwritten_by_shutdown() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData::default()));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress(
            coordinator,
            &binding,
            state,
            Arc::clone(&mailbox),
            None,
            executions,
        );
        let lifecycle = Arc::clone(&ingress.lifecycle);
        let (handle, ready) = ingress.start().unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        mailbox.lock().unwrap().panic_on_read = true;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !handle.is_finished() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(
            lifecycle.snapshot().status,
            RemoteIngressStatus::Blocked(RemoteIngressReason::WorkerPanic)
        );
        assert!(handle.shutdown_and_join().is_err());
        assert_eq!(
            lifecycle.snapshot().status,
            RemoteIngressStatus::Blocked(RemoteIngressReason::WorkerPanic)
        );
    }

    #[test]
    fn non_ready_transition_drains_existing_write_permit_and_rejects_new_ones() {
        let lifecycle = RemoteIngressLifecycle::new();
        lifecycle.ready_for_test();
        let permit = lifecycle.acquire_write_permit().unwrap();
        assert!(permit.is_current());
        let transition_lifecycle = Arc::clone(&lifecycle);
        let transition = thread::spawn(move || {
            transition_lifecycle.blocked_for_test(RemoteIngressReason::Internal);
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while lifecycle.snapshot().accepting_writes && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(!lifecycle.snapshot().accepting_writes);
        assert!(lifecycle.acquire_write_permit().is_err());
        assert!(!transition.is_finished());
        drop(permit);
        transition.join().unwrap();
        assert_eq!(
            lifecycle.snapshot().status,
            RemoteIngressStatus::Blocked(RemoteIngressReason::Internal)
        );
    }

    #[test]
    fn debug_and_errors_do_not_expose_binding_secrets() {
        let binding = active_binding(7, 1);
        let coordinator = Arc::new(FakeCoordinator::new(Some(binding.clone())));
        let state = FakeState::default();
        let mailbox = Arc::new(Mutex::new(FakeMailboxData::default()));
        let executions = Arc::new(Mutex::new(Vec::new()));
        let ingress = ingress(coordinator, &binding, state, mailbox, None, executions);

        let rendered = format!("{ingress:?} {:?}", RemoteIngressError::Binding);
        assert!(!rendered.contains("host-secret-bearer"));
        assert!(!rendered.contains("request_00000001"));
        assert!(!rendered.contains("hello from device"));
    }

    fn ingress(
        coordinator: Arc<FakeCoordinator>,
        binding: &ActiveRemoteBinding,
        state: FakeState,
        mailbox: Arc<Mutex<FakeMailboxData>>,
        replacement: Option<(Arc<FakeCoordinator>, ActiveRemoteBinding)>,
        executions: Arc<Mutex<Vec<String>>>,
    ) -> TestIngress {
        ingress_with(
            coordinator,
            binding,
            state,
            mailbox,
            replacement,
            executions,
            outcome_unknown_receipt(),
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn ingress_with(
        coordinator: Arc<FakeCoordinator>,
        binding: &ActiveRemoteBinding,
        state: FakeState,
        mailbox: Arc<Mutex<FakeMailboxData>>,
        replacement: Option<(Arc<FakeCoordinator>, ActiveRemoteBinding)>,
        executions: Arc<Mutex<Vec<String>>>,
        disposition: RemoteCommandDisposition,
        fail_decrypt: bool,
    ) -> TestIngress {
        let vectors: Value = serde_json::from_str(APPLICATION_VECTORS).unwrap();
        let mut command: Value =
            serde_json::from_str(vectors["command"]["canonical_json"].as_str().unwrap()).unwrap();
        command["mailbox_id"] = Value::String(binding.mailbox_id.clone());
        command["epoch"] = Value::Number(binding.pairing_epoch.into());
        RemoteCommandIngress::new(
            coordinator,
            Arc::new(FakeAuthority {
                executions,
                projections: Arc::new(Mutex::new(0)),
                disposition,
            }),
            state,
            Arc::new(FakeClientFactory {
                data: mailbox,
                validate_fails: false,
                replacement: Mutex::new(replacement),
            }),
            Arc::new(FakeIdentity {
                decrypted: Mutex::new(Some(command)),
                observed_contexts: Mutex::new(Vec::new()),
                fail_decrypt: AtomicBool::new(fail_decrypt),
            }),
            Arc::new(FakeClock),
            RemoteIngressLifecycle::new(),
        )
    }

    fn active_binding(epoch: u64, marker: u8) -> ActiveRemoteBinding {
        ActiveRemoteBinding {
            device_alias: format!("device-{marker}"),
            pairing_epoch: epoch,
            mailbox_id: format!("mbx-{}", format!("{marker:02x}").repeat(32)),
            host_bearer: zeroize::Zeroizing::new("host-secret-bearer-0123456789abcdef".into()),
            host_signing_commitment: [marker; 32],
            host_agreement_commitment: [marker.wrapping_add(1); 32],
            device_signing_commitment: [marker.wrapping_add(2); 32],
            device_agreement_commitment: [marker.wrapping_add(3); 32],
            device_signing_public_sec1: [marker.wrapping_add(4); 65],
            device_agreement_public_sec1: [marker.wrapping_add(5); 65],
        }
    }

    fn command_relay_frame(binding: &ActiveRemoteBinding) -> Vec<u8> {
        let vectors: Value = serde_json::from_str(APPLICATION_VECTORS).unwrap();
        let vector_binding = &vectors["command"]["frame_binding"];
        serde_json::to_vec(&RelayOpaqueFrame {
            schema: FRAME_SCHEMA.into(),
            crypto_suite: FRAME_SUITE.into(),
            mailbox_id: binding.mailbox_id.clone(),
            direction: RemoteDirection::DeviceToHost,
            epoch: binding.pairing_epoch,
            sequence: vector_binding["sequence"].as_u64().unwrap(),
            message_id: vector_binding["message_id"].as_str().unwrap().into(),
            issued_at: 1_788_000_000,
            expires_at: 1_788_000_600,
            nonce: "AAAAAAAAAAAAAAAA".into(),
            ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        })
        .unwrap()
    }

    fn pending_receipt_frame(binding: &ActiveRemoteBinding, sequence: u64) -> Vec<u8> {
        serde_json::to_vec(&RelayOpaqueFrame {
            schema: FRAME_SCHEMA.into(),
            crypto_suite: FRAME_SUITE.into(),
            mailbox_id: binding.mailbox_id.clone(),
            direction: RemoteDirection::HostToDevice,
            epoch: binding.pairing_epoch,
            sequence,
            message_id: "msg-01010101010101010101010101010101".into(),
            issued_at: 1_788_000_001,
            expires_at: 1_788_000_601,
            nonce: "AAAAAAAAAAAAAAAA".into(),
            ciphertext: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        })
        .unwrap()
    }

    fn projection_from_vector() -> ProjectionPayload {
        let vectors: Value = serde_json::from_str(APPLICATION_VECTORS).unwrap();
        let raw = vectors["projection"]["canonical_json"].as_str().unwrap();
        let frame = &vectors["projection"]["frame_binding"];
        let envelope = parse_application_envelope(
            raw.as_bytes(),
            &FrameBinding {
                schema: FRAME_SCHEMA.into(),
                crypto_suite: FRAME_SUITE.into(),
                mailbox_id: frame["mailbox_id"].as_str().unwrap().into(),
                direction: FrameDirection::HostToDevice,
                epoch: frame["epoch"].as_u64().unwrap(),
                sequence: frame["sequence"].as_u64().unwrap(),
                message_id: frame["message_id"].as_str().unwrap().into(),
            },
        )
        .unwrap();
        match envelope.payload {
            ApplicationPayload::Projection(projection) => *projection,
            _ => unreachable!(),
        }
    }
}
