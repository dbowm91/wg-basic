//! The single bounded blocking worker that owns [`ManagementRuntime`].
//!
//! # Why one thread
//!
//! [`StateStore`] is synchronous on purpose and `netd` requests block. Letting
//! an async HTTP task call either would block a Tokio worker thread on disk I/O
//! or on a Unix socket round trip. The worker makes that cost explicit and
//! serial: exactly one OS thread owns the runtime, and the only way to reach it
//! is a **bounded** [`tokio::sync::mpsc`] queue of typed commands with one-shot
//! replies.
//!
//! Bounded is the load-bearing word. There is deliberately no unbounded channel
//! and no `spawn_blocking` escape hatch, so a flood of requests cannot turn into
//! an unbounded queue of pending commands: admission is refused instead.
//!
//! # Startup semantics
//!
//! Opening the runtime validates the path, ownership, and migrations. A failure
//! there is **fatal** — the service has no authoritative application state, so
//! there is nothing to administer and [`spawn`] returns the error.
//!
//! Attempting the mandatory ADR-002 startup reconciliation is different. A netd
//! outage, refusal, or ownership conflict is recorded as a category and reported
//! as *degraded*, because the operator needs the HTTP surface up in order to see
//! and fix it. Only a state or projection failure during that attempt is fatal.
//!
//! # Command vocabulary
//!
//! # Why authentication belongs behind this queue
//!
//! Argon2id at the management policy costs tens of milliseconds and 19 MiB per
//! verification. That is the work factor that makes an offline attack on a
//! stolen verifier expensive, and it is far too expensive to run on a Tokio
//! worker thread. Worse, unbounded concurrent verification is exactly the CPU
//! denial of service the management roadmap warns about. Routing authentication
//! through the same bounded queue as everything else is what makes both
//! properties true rather than aspirational.
//!
//! # Closed vocabulary
//!
//! The command set and every reply type are closed enums, so adding an
//! operation is a visible, deliberate change rather than a new stringly-typed
//! channel message. Credentials cross the queue as owned `String`s, never as
//! references into a caller's frame.

use super::{
    auth::{AdminStatus, AuthError, AuthService, IssuedSession},
    error::ManagementError,
    health::{BackendProbe, ManagementHealth},
    runtime::ManagementRuntime,
};
use crate::{
    domain::{DesiredGeneration, PrincipalId},
    product::{
        ClientCreateCommand, ClientDeleteCommand, ClientUpdateCommand, CreatedEnrollmentLink,
        EnrollmentCapabilityId, EnrollmentToken, ProductClient, ProductMutationReceipt,
        ProductServer, ProductService, SecretArtifact, ServerSetupCommand, SetClientEnabledCommand,
    },
    state::{AttemptDisposition, StoredSession},
};
use std::{
    path::{Path, PathBuf},
    sync::mpsc as std_mpsc,
    thread,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

/// Default number of commands that may wait for the worker.
///
/// Small on purpose: this is an appliance administration surface, not a queue.
pub const DEFAULT_QUEUE_CAPACITY: usize = 32;

/// Default deadline for one command/reply round trip.
pub const DEFAULT_REPLY_DEADLINE: Duration = Duration::from_secs(5);

/// The typed commands the worker accepts.
#[derive(Debug)]
pub enum WorkerCommand {
    /// Project the safe management health snapshot.
    Health {
        reply: oneshot::Sender<Result<ManagementHealth, ManagementError>>,
    },
    /// Ask the authorized backend whether it is answering right now.
    ///
    /// A read-only `Ping`. Separate from `Health` because `Health` must stay
    /// cheap and socket-free for the unauthenticated liveness route, while this
    /// one costs a round trip and is therefore only for an authenticated caller.
    ProbeBackend {
        reply: oneshot::Sender<BackendProbe>,
    },
    /// Provision or reset the local administrator, revoking every session.
    SetAdminPassword {
        username: String,
        password: String,
        reply: oneshot::Sender<Result<AdminStatus, AuthFailure>>,
    },
    /// Verify credentials and issue a session.
    ///
    /// The only command whose reply ever carries a raw session token, and it
    /// carries it exactly once.
    Authenticate {
        username: String,
        password: String,
        reply: oneshot::Sender<Result<IssuedSession, AuthFailure>>,
    },
    /// Resolve a presented bearer token to a live session.
    ResolveSession {
        presented: String,
        reply: oneshot::Sender<Result<StoredSession, AuthFailure>>,
    },
    /// Revoke one session (logout).
    RevokeSession {
        presented: String,
        reply: oneshot::Sender<Result<(), AuthFailure>>,
    },
    /// Revoke every session belonging to one principal.
    RevokeAllSessions {
        principal_id: PrincipalId,
        reply: oneshot::Sender<Result<usize, AuthFailure>>,
    },
    /// Delete expired sessions, reporting how many went.
    PurgeExpiredSessions {
        reply: oneshot::Sender<Result<usize, AuthFailure>>,
    },
    /// The safe operator-facing projection of the local administrator.
    AdminStatus {
        reply: oneshot::Sender<Result<Option<AdminStatus>, AuthFailure>>,
    },
    /// The safe product snapshot: the managed server and its clients.
    ///
    /// Read-only, and secret-free by construction: the reply type has no field
    /// that could hold a private or preshared key.
    ProductSnapshot {
        reply: oneshot::Sender<Result<ProductSnapshotReply, ProductFailure>>,
    },
    /// Configure the one managed server.
    SetupServer {
        command: ServerSetupCommand,
        reply: oneshot::Sender<Result<SetupReply, ProductFailure>>,
    },
    /// Create one managed client.
    CreateClient {
        command: ClientCreateCommand,
        reply: oneshot::Sender<Result<ClientMutationReply, ProductFailure>>,
    },
    /// Apply the present fields of an update to one managed client.
    UpdateClient {
        command: ClientUpdateCommand,
        reply: oneshot::Sender<Result<ClientMutationReply, ProductFailure>>,
    },
    /// Enable or disable one managed client.
    SetClientEnabled {
        command: SetClientEnabledCommand,
        reply: oneshot::Sender<Result<ClientMutationReply, ProductFailure>>,
    },
    /// Delete one managed client.
    DeleteClient {
        command: ClientDeleteCommand,
        reply: oneshot::Sender<Result<ProductMutationReceipt, ProductFailure>>,
    },
    /// Return one explicit secret-bearing client export artifact.
    ClientConfig {
        client_id: crate::domain::ClientId,
        reply: oneshot::Sender<Result<SecretArtifact, ProductFailure>>,
    },
    /// Create one digest-only, expiring share capability.
    CreateEnrollmentLink {
        principal_id: PrincipalId,
        client_id: crate::domain::ClientId,
        ttl_seconds: u64,
        reply: oneshot::Sender<Result<CreatedEnrollmentLink, ProductFailure>>,
    },
    /// Revoke an unused capability.
    RevokeEnrollmentLink {
        principal_id: PrincipalId,
        capability_id: EnrollmentCapabilityId,
        reply: oneshot::Sender<Result<bool, ProductFailure>>,
    },
    /// Consume a one-time capability, if it remains available.
    ConsumeEnrollment {
        capability_id: EnrollmentCapabilityId,
        token: EnrollmentToken,
        reply: oneshot::Sender<Result<Option<SecretArtifact>, ProductFailure>>,
    },
    /// Stop the worker; the reply confirms the stop was observed.
    Shutdown { reply: oneshot::Sender<()> },
}

/// The safe product snapshot returned by [`WorkerCommand::ProductSnapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductSnapshotReply {
    pub generation: DesiredGeneration,
    pub server: Option<ProductServer>,
    pub clients: Vec<ProductClient>,
}

/// The result of configuring the managed server.
///
/// A safe summary and a receipt. No private key: the server's identity is
/// generated internally and is reachable only through M003's explicit export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupReply {
    pub server: ProductServer,
    pub receipt: ProductMutationReceipt,
}

/// A client mutation's safe summary together with its receipt.
///
/// The receipt is the *reconciled* one, produced by the worker after the commit
/// rather than by the product service before it. That split is the whole point:
/// the worker is the only place that can talk to the kernel, and only it can
/// answer whether a committed change was enforced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientMutationReply {
    pub client: ProductClient,
    pub receipt: ProductMutationReceipt,
}

/// Why a product command was refused.
///
/// Deliberately a closed set of categories rather than an error string: these
/// replies cross the same boundary an HTTP body would, and a formatted internal
/// error is exactly the kind of thing that should not become operator-facing
/// text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductFailure {
    #[error("no managed server is configured yet")]
    ServerNotConfigured,
    #[error("a managed server is already configured")]
    ServerAlreadyConfigured,
    #[error("the named interface or client does not exist")]
    NotFound,
    #[error("the requested address cannot be allocated")]
    AddressUnavailable,
    #[error("the mutation conflicts with a newer desired generation")]
    StaleGeneration,
    #[error("the requested change is not valid")]
    Invalid,
    #[error("durable state rejected the mutation")]
    StateUnavailable,
    #[error("client export material is unavailable")]
    SecretUnavailable,
    #[error("enrollment capability is not available")]
    EnrollmentUnavailable,
}

impl ProductFailure {
    /// Maps a product-layer error onto a bounded category.
    ///
    /// Every other cause collapses into one of these rather than carrying its
    /// text outward.
    pub(crate) fn classify(error: &crate::product::ProductError) -> Self {
        use crate::product::ProductError;
        match error {
            ProductError::ServerAlreadyConfigured => Self::ServerAlreadyConfigured,
            ProductError::ServerNotConfigured => Self::ServerNotConfigured,
            ProductError::UnknownInterface(_)
            | ProductError::UnknownClient(_)
            | ProductError::ClientMissingAfterMutation(_)
            | ProductError::ServerMissingAfterSetup => Self::NotFound,
            ProductError::ClientPrivateKeyUnavailable => Self::SecretUnavailable,
            ProductError::Artifact(_) => Self::Invalid,
            ProductError::InvalidEnrollmentLifetime | ProductError::EnrollmentToken(_) => {
                Self::Invalid
            }
            ProductError::Key(_) => Self::Invalid,
            ProductError::Allocation(_) => Self::AddressUnavailable,
            ProductError::State(crate::state::StateError::StaleGeneration { .. }) => {
                Self::StaleGeneration
            }
            ProductError::State(crate::state::StateError::Validation(_)) => Self::Invalid,
            ProductError::State(_) => Self::StateUnavailable,
        }
    }

    /// Maps a post-commit reconcile failure onto a bounded category.
    ///
    /// A reconcile that cannot even be attempted is a state or projection
    /// problem, not something the operator caused and not something a retry of
    /// the same request fixes.
    pub(crate) fn classify_runtime(error: &ManagementError) -> Self {
        match error {
            ManagementError::BackendUnavailable
            | ManagementError::PartialFailure
            | ManagementError::Unauthorized
            | ManagementError::Rejected
            | ManagementError::Conflict => Self::StateUnavailable,
            _ => Self::StateUnavailable,
        }
    }
}

/// Why a command was refused.
///
/// A separate type from [`ManagementError`] on purpose: an authentication
/// failure is an answer about a credential, and a management failure is an
/// answer about the appliance. Collapsing them would make every route handler
/// decide which of the two it is looking at before it can pick a status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthFailure {
    /// The credentials were not accepted, or the session was not valid.
    #[error("the credentials were not accepted")]
    Rejected,
    /// The credentials were accepted but the session could not be issued.
    #[error("a session could not be issued")]
    Unavailable,
    /// An administrative credential operation failed.
    #[error("the credential store is unavailable")]
    Storage,
}

impl From<AuthError> for AuthFailure {
    fn from(error: AuthError) -> Self {
        use AuthError as Error;
        match error {
            Error::CredentialsRejected | Error::SessionInvalid | Error::UsernameInvalid => {
                Self::Rejected
            }
            Error::SessionUnavailable | Error::RandomUnavailable | Error::MalformedVerifier => {
                Self::Unavailable
            }
            Error::PrincipalExists | Error::NoPrincipal | Error::StorageUnavailable => {
                Self::Storage
            }
        }
    }
}

/// Why a command did not produce its reply.
///
/// Every variant is an admission or lifetime decision made by the caller; none
/// carries state content, so an HTTP surface can render them as a single bounded
/// status without leaking diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// The bounded queue was full. Backpressure, not a server fault.
    #[error("the management worker is saturated")]
    Saturated,
    /// The worker did not answer within the configured deadline.
    #[error("the management worker did not answer in time")]
    TimedOut,
    /// The worker is gone: it stopped, or never started successfully.
    #[error("the management worker is not running")]
    Stopped,
    /// The worker answered, and the operation itself failed.
    #[error(transparent)]
    Failed(#[from] ManagementError),
    /// The credentials were not accepted, or the session was not valid.
    ///
    /// A refusal, not a fault. It arrives as an error only because the caller has
    /// to do something with it; a retry will not help.
    #[error("the credentials were not accepted")]
    Rejected,
    /// The credentials were accepted but the session could not be issued.
    #[error("a session could not be issued")]
    Unavailable,
    /// A product command was refused.
    ///
    /// Kept distinct from [`Self::Rejected`]: that variant means credentials
    /// were not accepted, and answering a product refusal with it would tell an
    /// operator their client was refused for an authentication reason.
    #[error("product command refused: {0}")]
    Product(#[from] ProductFailure),
    /// An administrative credential operation failed.
    #[error("the credential store is unavailable")]
    Storage,
}

impl WorkerError {
    /// Whether the failure is transient from the caller's point of view.
    ///
    /// Saturation and a missed deadline are both overload answers rather than
    /// product failures, so an HTTP surface maps them to 503.
    pub fn is_overload(&self) -> bool {
        matches!(self, Self::Saturated | Self::TimedOut | Self::Stopped)
    }

    /// Whether this failure is a refusal rather than a fault.
    ///
    /// A caller must not retry a refusal, and must not present it as an outage.
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Rejected)
    }
}

/// What the mandatory startup reconciliation attempt concluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupReconcile {
    /// The installation manages no interface; there was nothing to apply.
    NothingToApply,
    /// The current desired generation was applied and converged.
    Converged { generation: DesiredGeneration },
    /// The attempt did not converge. The listener still starts.
    Degraded { category: AttemptDisposition },
}

impl StartupReconcile {
    /// Whether the service is serving while the network is not converged.
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    /// A single operator-readable word for startup logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NothingToApply => "nothing to apply",
            Self::Converged { .. } => "converged",
            Self::Degraded { .. } => "degraded",
        }
    }
}

/// Everything the worker needs to start.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Path to the authoritative state database.
    pub state_path: PathBuf,
    /// Path to the authorized local netd socket.
    pub socket: PathBuf,
    /// Maximum commands that may wait for the worker.
    pub queue_capacity: usize,
    /// Deadline applied to one command/reply round trip.
    pub reply_deadline: Duration,
}

impl WorkerConfig {
    /// Builds a configuration from the operator-visible paths, using the
    /// documented default bound and deadline.
    pub fn new(state_path: impl AsRef<Path>, socket: impl AsRef<Path>) -> Self {
        Self {
            state_path: state_path.as_ref().to_path_buf(),
            socket: socket.as_ref().to_path_buf(),
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            reply_deadline: DEFAULT_REPLY_DEADLINE,
        }
    }
}

/// The async-side handle to the worker.
///
/// Cheap to clone and safe to share: every clone submits through the same
/// bounded queue, so cloning cannot widen the bound.
#[derive(Clone, Debug)]
pub struct WorkerClient {
    sender: mpsc::Sender<WorkerCommand>,
    deadline: Duration,
}

impl WorkerClient {
    /// Asks the authorized backend whether it is answering right now.
    ///
    /// Never reports an error: "the backend did not answer" *is* the answer, and
    /// turning it into a failure would make an outage indistinguishable from a
    /// caller mistake.
    pub async fn probe_backend(&self) -> Result<BackendProbe, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::ProbeBackend { reply }).await?;
        // A dropped reply means the worker exited mid-probe, which `await_reply`
        // already reports as `WorkerError::Stopped`; the caller's problem, not an
        // outage, so it propagates rather than being flattened into "not
        // answering".
        self.await_reply(answer).await
    }

    /// Projects the safe management health snapshot.
    ///
    /// This is the only way a request handler can observe management state, and
    /// it returns a projection that carries no receipt, error string, or key
    /// material.
    pub async fn health(&self) -> Result<ManagementHealth, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::Health { reply }).await?;
        match self.await_reply(answer).await? {
            Ok(health) => Ok(health),
            Err(failed) => Err(WorkerError::Failed(failed)),
        }
    }

    /// Provisions or resets the local administrator, revoking every session.
    ///
    /// Takes owned `String`s so no borrow of a request frame outlives the await.
    pub async fn set_admin_password(
        &self,
        username: String,
        password: String,
    ) -> Result<AdminStatus, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::SetAdminPassword {
            username,
            password,
            reply,
        })
        .await?;
        self.auth_reply(answer).await
    }

    /// Verifies credentials and issues a session.
    ///
    /// This is the only call that ever returns a raw session token, and it
    /// returns it exactly once. A caller that drops the reply without reading it
    /// has minted a session nobody can use, which is the correct failure mode:
    /// the alternative -- handing back the token on a retry -- would make a lost
    /// reply into a credential leak.
    pub async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> Result<IssuedSession, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::Authenticate {
            username,
            password,
            reply,
        })
        .await?;
        self.auth_reply(answer).await
    }

    /// Resolves a presented bearer token to a live session.
    pub async fn resolve_session(&self, presented: String) -> Result<StoredSession, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::ResolveSession { presented, reply })
            .await?;
        self.auth_reply(answer).await
    }

    /// Revokes one session (logout).
    pub async fn revoke_session(&self, presented: String) -> Result<(), WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::RevokeSession { presented, reply })
            .await?;
        self.auth_reply(answer).await
    }

    /// Revokes every session belonging to one principal.
    pub async fn revoke_all_sessions(
        &self,
        principal_id: PrincipalId,
    ) -> Result<usize, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::RevokeAllSessions {
            principal_id,
            reply,
        })
        .await?;
        self.auth_reply(answer).await
    }

    /// Deletes expired sessions, reporting how many went.
    pub async fn purge_expired_sessions(&self) -> Result<usize, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::PurgeExpiredSessions { reply })
            .await?;
        self.auth_reply(answer).await
    }

    /// The safe operator-facing projection of the local administrator.
    pub async fn admin_status(&self) -> Result<Option<AdminStatus>, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::AdminStatus { reply }).await?;
        self.auth_reply(answer).await
    }

    /// The safe product snapshot: the managed server and its clients.
    pub async fn product_snapshot(&self) -> Result<ProductSnapshotReply, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::ProductSnapshot { reply }).await?;
        self.product_reply(answer).await
    }

    /// Renders one client configuration through the state-owning worker.
    pub async fn client_config(
        &self,
        client_id: crate::domain::ClientId,
    ) -> Result<SecretArtifact, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::ClientConfig { client_id, reply })
            .await?;
        self.product_reply(answer).await
    }

    pub async fn create_enrollment_link(
        &self,
        principal_id: PrincipalId,
        client_id: crate::domain::ClientId,
        ttl_seconds: u64,
    ) -> Result<CreatedEnrollmentLink, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::CreateEnrollmentLink {
            principal_id,
            client_id,
            ttl_seconds,
            reply,
        })
        .await?;
        self.product_reply(answer).await
    }
    pub async fn revoke_enrollment_link(
        &self,
        principal_id: PrincipalId,
        capability_id: EnrollmentCapabilityId,
    ) -> Result<bool, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::RevokeEnrollmentLink {
            principal_id,
            capability_id,
            reply,
        })
        .await?;
        self.product_reply(answer).await
    }
    pub async fn consume_enrollment(
        &self,
        capability_id: EnrollmentCapabilityId,
        token: EnrollmentToken,
    ) -> Result<Option<SecretArtifact>, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::ConsumeEnrollment {
            capability_id,
            token,
            reply,
        })
        .await?;
        self.product_reply(answer).await
    }

    /// Configures the managed server exactly once.
    pub async fn setup_server(
        &self,
        command: ServerSetupCommand,
    ) -> Result<SetupReply, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::SetupServer { command, reply })
            .await?;
        self.product_reply(answer).await
    }

    /// Creates one managed client.
    pub async fn create_client(
        &self,
        command: ClientCreateCommand,
    ) -> Result<ClientMutationReply, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::CreateClient { command, reply })
            .await?;
        self.product_reply(answer).await
    }

    /// Applies an update to one managed client.
    pub async fn update_client(
        &self,
        command: ClientUpdateCommand,
    ) -> Result<ClientMutationReply, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::UpdateClient { command, reply })
            .await?;
        self.product_reply(answer).await
    }

    /// Enables or disables one managed client.
    pub async fn set_client_enabled(
        &self,
        command: SetClientEnabledCommand,
    ) -> Result<ClientMutationReply, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::SetClientEnabled { command, reply })
            .await?;
        self.product_reply(answer).await
    }

    /// Deletes one managed client.
    pub async fn delete_client(
        &self,
        command: ClientDeleteCommand,
    ) -> Result<ProductMutationReceipt, WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::DeleteClient { command, reply })
            .await?;
        self.product_reply(answer).await
    }

    /// Awaits a product reply under the configured deadline.
    ///
    /// Mirrors [`Self::auth_reply`]: a refusal is a completed round trip
    /// carrying a refusal, so it is surfaced as `Ok(Err(..))` rather than being
    /// flattened into a transport failure.
    async fn product_reply<T>(
        &self,
        answer: oneshot::Receiver<Result<T, ProductFailure>>,
    ) -> Result<T, WorkerError> {
        match self.await_reply(answer).await? {
            Ok(value) => Ok(value),
            Err(failure) => Err(WorkerError::Product(failure)),
        }
    }

    /// Awaits an authentication reply under the configured deadline.
    ///
    /// `WorkerError::Failed` is deliberately never produced here: an
    /// authentication refusal is a successful round trip carrying a refusal, not
    /// a transport failure. Collapsing the two would make a caller retry a
    /// rejected password.
    async fn auth_reply<T>(
        &self,
        answer: oneshot::Receiver<Result<T, AuthFailure>>,
    ) -> Result<T, WorkerError> {
        match self.await_reply(answer).await? {
            Ok(value) => Ok(value),
            Err(AuthFailure::Rejected) => Err(WorkerError::Rejected),
            Err(AuthFailure::Unavailable) => Err(WorkerError::Unavailable),
            Err(AuthFailure::Storage) => Err(WorkerError::Storage),
        }
    }

    /// Asks the worker to stop, bounded by the same deadline as any command.
    pub async fn shutdown(&self) -> Result<(), WorkerError> {
        let (reply, answer) = oneshot::channel();
        self.admit(WorkerCommand::Shutdown { reply }).await?;
        self.await_reply(answer).await?;
        Ok(())
    }

    /// Admits one command against the bounded queue.
    ///
    /// Admission never blocks: a full queue is reported as
    /// [`WorkerError::Saturated`] rather than awaited, so overload cannot
    /// accumulate as pending requests waiting for the worker to catch up.
    async fn admit(&self, command: WorkerCommand) -> Result<(), WorkerError> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => WorkerError::Saturated,
            mpsc::error::TrySendError::Closed(_) => WorkerError::Stopped,
        })
    }

    /// Awaits one reply under the configured deadline.
    ///
    /// A dropped reply means the worker exited without answering, which is a
    /// lifetime failure rather than a silent success.
    async fn await_reply<T>(&self, answer: oneshot::Receiver<T>) -> Result<T, WorkerError> {
        match tokio::time::timeout(self.deadline, answer).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(WorkerError::Stopped),
            Err(_) => Err(WorkerError::TimedOut),
        }
    }
}

/// The synchronous owner of the worker thread.
#[derive(Debug)]
pub struct WorkerHandle {
    join: Option<thread::JoinHandle<()>>,
}

impl WorkerHandle {
    /// Waits for the worker thread to finish, which is what actually releases
    /// the state store.
    pub fn join(mut self) -> thread::Result<()> {
        match self.join.take() {
            Some(join) => join.join(),
            None => Ok(()),
        }
    }
}

/// A started worker: its client, its thread, and what startup concluded.
#[derive(Debug)]
pub struct WorkerStartup {
    client: WorkerClient,
    handle: Option<WorkerHandle>,
    reconcile: StartupReconcile,
}

impl WorkerStartup {
    /// The async handle used by request handlers.
    pub fn client(&self) -> &WorkerClient {
        &self.client
    }

    /// What the mandatory startup reconciliation attempt concluded.
    pub fn reconcile(&self) -> StartupReconcile {
        self.reconcile
    }

    /// Stops the worker and joins its thread, releasing the state store.
    ///
    /// The join happens even when the stop request failed, so a saturated queue
    /// cannot leave the database open.
    pub async fn stop(mut self) -> Result<(), WorkerError> {
        let outcome = self.client.shutdown().await;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        outcome
    }
}

/// What the worker thread reports back through the startup handshake.
enum StartupOutcome {
    Ready { reconcile: StartupReconcile },
    Fatal(ManagementError),
}

/// Starts the dedicated worker thread and waits for its startup result.
///
/// Returns only once the runtime is open and the startup reconciliation attempt
/// has been made, so a caller can never publish a listener whose backing
/// authority failed to load.
pub fn spawn(config: WorkerConfig) -> Result<WorkerStartup, ManagementError> {
    let capacity = config.queue_capacity.max(1);
    let deadline = config.reply_deadline;
    let (sender, receiver) = mpsc::channel(capacity);
    let (startup_tx, startup_rx) = std_mpsc::sync_channel(1);

    let join = thread::Builder::new()
        .name("wg-basic-management-worker".to_owned())
        .spawn(move || run(config, receiver, startup_tx))
        .map_err(|_| ManagementError::WorkerStartFailed)?;

    let client = WorkerClient { sender, deadline };

    match startup_rx.recv() {
        Ok(StartupOutcome::Ready { reconcile }) => Ok(WorkerStartup {
            client,
            handle: Some(WorkerHandle { join: Some(join) }),
            reconcile,
        }),
        Ok(StartupOutcome::Fatal(error)) => {
            // The thread has already returned; joining here releases the join
            // handle instead of leaving it to the destructor.
            let _ = join.join();
            Err(error)
        }
        // A handshake that never arrives means the thread died before it could
        // report. That is a fatal authority failure by construction.
        Err(_) => {
            let _ = join.join();
            Err(ManagementError::WorkerStartFailed)
        }
    }
}

/// The worker body: open the runtime, attempt reconciliation, then serve.
fn run(
    config: WorkerConfig,
    mut receiver: mpsc::Receiver<WorkerCommand>,
    startup: std_mpsc::SyncSender<StartupOutcome>,
) {
    let runtime = match ManagementRuntime::open(&config.state_path, &config.socket) {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = startup.send(StartupOutcome::Fatal(error));
            return;
        }
    };

    // ADR-002 requires an unconditional startup attempt. It is deliberately not
    // conditional on stored convergence evidence, and a degraded result is
    // reported rather than raised: the listener must come up either way.
    let reconcile = match runtime.reconcile_current() {
        Ok(None) => StartupReconcile::NothingToApply,
        Ok(Some(outcome)) if outcome.converged => StartupReconcile::Converged {
            generation: outcome.applied_generation,
        },
        Ok(Some(outcome)) => StartupReconcile::Degraded {
            category: outcome.disposition,
        },
        Err(error) if error.is_fatal_without_authority() => {
            let _ = startup.send(StartupOutcome::Fatal(error));
            return;
        }
        Err(error) => StartupReconcile::Degraded {
            category: error
                .evidence_category()
                .unwrap_or(AttemptDisposition::BackendUnavailable),
        },
    };

    if startup.send(StartupOutcome::Ready { reconcile }).is_err() {
        // The caller gave up on the handshake. Nothing is waiting for this
        // worker, so drop the runtime instead of serving nobody.
        return;
    }

    serve(runtime, &mut receiver);
}

/// Builds the safe product snapshot from durable state.
///
/// A store failure becomes a `StateUnavailable` category rather than an error
/// string, because this reply is what an operator-facing surface would render.
fn product_snapshot(runtime: &ManagementRuntime) -> Result<ProductSnapshotReply, ProductFailure> {
    let store = runtime.store();
    let service = ProductService::new(store);
    let generation = store
        .current_generation()
        .map_err(|_| ProductFailure::StateUnavailable)?;
    let server = service
        .server()
        .map_err(|_| ProductFailure::StateUnavailable)?;
    let clients = service
        .list_clients()
        .map_err(|_| ProductFailure::StateUnavailable)?;
    Ok(ProductSnapshotReply {
        generation,
        server,
        clients,
    })
}

/// A product command can fail before its commit or after it.
///
/// The two are different facts and are kept apart: a pre-commit failure means
/// nothing changed, while a post-commit failure means the mutation *did* land
/// and only its enforcement is unconfirmed. Collapsing them would turn a
/// degraded receipt back into a failed request.
enum ProductCommandError {
    Product(crate::product::ProductError),
    Runtime(ManagementError),
}

impl From<crate::product::ProductError> for ProductCommandError {
    fn from(error: crate::product::ProductError) -> Self {
        Self::Product(error)
    }
}

impl From<ManagementError> for ProductCommandError {
    fn from(error: ManagementError) -> Self {
        Self::Runtime(error)
    }
}

fn run_product_mutation<T>(
    runtime: &ManagementRuntime,
    commit: impl FnOnce() -> Result<(T, ProductMutationReceipt), crate::product::ProductError>,
) -> Result<(T, ProductMutationReceipt), ProductCommandError> {
    let (value, pending) = commit()?;
    let receipt = runtime
        .reconcile_after_commit(pending.generation)
        .map_err(ProductCommandError::Runtime)?;
    Ok((value, receipt))
}

fn product_failure(error: ProductCommandError) -> ProductFailure {
    match error {
        ProductCommandError::Product(error) => ProductFailure::classify(&error),
        ProductCommandError::Runtime(error) => ProductFailure::classify_runtime(&error),
    }
}

/// The command loop. The runtime is the only thing this thread owns.
///
/// The loop is exhaustive over [`WorkerCommand`] on purpose: adding a command
/// without deciding how it is served is a compile error, so the bounded queue
/// can never grow a path that quietly does something else.
fn serve(runtime: ManagementRuntime, receiver: &mut mpsc::Receiver<WorkerCommand>) {
    while let Some(command) = receiver.blocking_recv() {
        match command {
            WorkerCommand::Health { reply } => {
                // The projection cannot fail: it is derived from stored
                // evidence, and an unreadable store degrades the projection
                // rather than raising.
                let _ = reply.send(Ok(runtime.health()));
            }
            WorkerCommand::ProbeBackend { reply } => {
                // Cannot fail by construction: the probe reports non-answer as a
                // value, so a backend outage is not a worker fault.
                let _ = reply.send(runtime.probe_backend());
            }
            WorkerCommand::SetAdminPassword {
                username,
                password,
                reply,
            } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(
                    auth.set_password(&username, &password)
                        .map(|principal| {
                            auth.status()
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| status_from(&principal))
                        })
                        .map_err(AuthFailure::from),
                );
            }
            WorkerCommand::Authenticate {
                username,
                password,
                reply,
            } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(
                    auth.authenticate(&username, &password)
                        .map_err(AuthFailure::from),
                );
            }
            WorkerCommand::ResolveSession { presented, reply } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(auth.resolve_session(&presented).map_err(AuthFailure::from));
            }
            WorkerCommand::RevokeSession { presented, reply } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(auth.revoke_session(&presented).map_err(AuthFailure::from));
            }
            WorkerCommand::RevokeAllSessions {
                principal_id,
                reply,
            } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(
                    auth.revoke_all_sessions(principal_id)
                        .map_err(AuthFailure::from),
                );
            }
            WorkerCommand::PurgeExpiredSessions { reply } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(auth.purge_expired_sessions().map_err(AuthFailure::from));
            }
            WorkerCommand::AdminStatus { reply } => {
                let auth = AuthService::new(runtime.store());
                let _ = reply.send(auth.status().map_err(AuthFailure::from));
            }
            WorkerCommand::ProductSnapshot { reply } => {
                let _ = reply.send(product_snapshot(&runtime));
            }
            WorkerCommand::SetupServer { command, reply } => {
                let service = ProductService::new(runtime.store());
                let _ = reply.send(
                    run_product_mutation(&runtime, || service.setup_server(command))
                        .map(|(server, receipt)| SetupReply { server, receipt })
                        .map_err(product_failure),
                );
            }
            WorkerCommand::CreateClient { command, reply } => {
                let service = ProductService::new(runtime.store());
                let _ = reply.send(
                    run_product_mutation(&runtime, || service.create_client(command))
                        .map(|(client, receipt)| ClientMutationReply { client, receipt })
                        .map_err(product_failure),
                );
            }
            WorkerCommand::UpdateClient { command, reply } => {
                let service = ProductService::new(runtime.store());
                let _ = reply.send(
                    run_product_mutation(&runtime, || service.update_client(command))
                        .map(|(client, receipt)| ClientMutationReply { client, receipt })
                        .map_err(product_failure),
                );
            }
            WorkerCommand::SetClientEnabled { command, reply } => {
                let service = ProductService::new(runtime.store());
                let _ = reply.send(
                    run_product_mutation(&runtime, || service.set_client_enabled(command))
                        .map(|(client, receipt)| ClientMutationReply { client, receipt })
                        .map_err(product_failure),
                );
            }
            WorkerCommand::DeleteClient { command, reply } => {
                let service = ProductService::new(runtime.store());
                let _ = reply.send(
                    (|| -> Result<ProductMutationReceipt, ProductCommandError> {
                        let pending = service.delete_client(command)?;
                        runtime
                            .reconcile_after_commit(pending.generation)
                            .map_err(ProductCommandError::Runtime)
                    })()
                    .map_err(product_failure),
                );
            }
            WorkerCommand::ClientConfig { client_id, reply } => {
                let result = ProductService::new(runtime.store())
                    .client_config_material(client_id)
                    .and_then(|material| {
                        crate::product::render_config(&material)
                            .map_err(crate::product::ProductError::Artifact)
                    })
                    .map_err(|error| ProductFailure::classify(&error));
                let _ = reply.send(result);
            }
            WorkerCommand::CreateEnrollmentLink {
                principal_id,
                client_id,
                ttl_seconds,
                reply,
            } => {
                let result = ProductService::new(runtime.store())
                    .create_enrollment_link(principal_id, client_id, ttl_seconds)
                    .map_err(|error| ProductFailure::classify(&error));
                let _ = reply.send(result);
            }
            WorkerCommand::RevokeEnrollmentLink {
                principal_id,
                capability_id,
                reply,
            } => {
                let result = ProductService::new(runtime.store())
                    .revoke_enrollment_link(principal_id, capability_id)
                    .map_err(|error| ProductFailure::classify(&error));
                let _ = reply.send(result);
            }
            WorkerCommand::ConsumeEnrollment {
                capability_id,
                token,
                reply,
            } => {
                let result = ProductService::new(runtime.store())
                    .consume_enrollment_link(capability_id, &token)
                    .map_err(|error| ProductFailure::classify(&error));
                let _ = reply.send(result);
            }
            WorkerCommand::Shutdown { reply } => {
                let _ = reply.send(());
                break;
            }
        }
    }
    // Falling out of the loop drops `runtime`, which closes the state store.
}

/// Projects a principal that was just written into an [`AdminStatus`].
///
/// Used only when the re-read after a write is somehow unavailable, so the
/// caller still gets the identity and username it just stored rather than
/// nothing at all.
fn status_from(principal: &crate::state::PrincipalRecord) -> AdminStatus {
    AdminStatus {
        principal_id: principal.id,
        username: principal.username.clone(),
        enabled: principal.enabled,
        live_sessions: 0,
        created_at: principal.created_at,
        updated_at: principal.updated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateStore;
    use std::{fs, os::unix::fs::PermissionsExt};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wg-basic-worker-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn db(&self) -> PathBuf {
            self.path.join("state.db")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A socket path that cannot exist, so startup reconciliation is guaranteed
    /// to degrade rather than depend on a running netd.
    fn absent_socket(temp: &TempDir) -> PathBuf {
        temp.path.join("no-such-netd.sock")
    }

    #[tokio::test]
    async fn a_started_worker_answers_health_and_shuts_down() {
        let temp = TempDir::new();
        let config = WorkerConfig::new(temp.db(), absent_socket(&temp));
        let startup = spawn(config).expect("a fresh store and an absent netd still start");

        // The installation manages no interface, so there is nothing to apply.
        assert_eq!(startup.reconcile(), StartupReconcile::NothingToApply);

        let health = startup
            .client()
            .health()
            .await
            .expect("health is answerable without netd");
        assert!(health.database_healthy, "an opened store is healthy");

        startup.stop().await.expect("a clean shutdown");
    }

    #[tokio::test]
    async fn a_degraded_startup_still_serves_health() {
        let temp = TempDir::new();
        // Commit a real desired state so startup reconciliation has work to do
        // and fails against the absent socket.
        let store = StateStore::initialize(temp.db()).unwrap();
        store
            .mutate(crate::domain::INITIAL_DESIRED_GENERATION, |_| {
                Ok(minimal_managed_state())
            })
            .unwrap();
        drop(store);

        let startup = spawn(WorkerConfig::new(temp.db(), absent_socket(&temp)))
            .expect("an absent netd is degraded, not fatal");
        assert!(
            startup.reconcile().is_degraded(),
            "{:?}",
            startup.reconcile()
        );
        assert_eq!(
            startup.reconcile(),
            StartupReconcile::Degraded {
                category: AttemptDisposition::BackendUnavailable
            }
        );

        // The listener-relevant promise: health is still answerable, because the
        // operator needs the surface to diagnose the outage.
        let health = startup.client().health().await.expect("degraded health");
        assert!(!health.netd_reachable);
        assert!(!health.is_healthy());

        startup.stop().await.expect("a clean shutdown");
    }

    #[tokio::test]
    async fn an_unusable_state_path_is_fatal() {
        let temp = TempDir::new();
        // A directory where the database should be cannot be opened.
        let bogus = temp.path.join("not-a-database");
        fs::create_dir(&bogus).unwrap();

        let error = spawn(WorkerConfig::new(&bogus, absent_socket(&temp)))
            .expect_err("an unopenable store has no authority to administer");
        assert!(error.is_fatal_without_authority(), "{error}");
    }

    #[tokio::test]
    async fn a_full_queue_is_refused_rather_than_queued() {
        // A hand-built channel makes the bound observable without depending on
        // worker drain timing, which is the property actually under test.
        let (sender, mut receiver) = mpsc::channel(1);
        let client = WorkerClient {
            sender,
            deadline: Duration::from_secs(5),
        };

        // Occupy the only slot with a command nobody will ever answer.
        let (stranded, _unanswered) = oneshot::channel();
        client
            .admit(WorkerCommand::Shutdown { reply: stranded })
            .await
            .expect("the first command fits in the bound");

        // The next one is refused, not queued: this is what stops a flood from
        // becoming an unbounded backlog.
        let (refused, _unanswered) = oneshot::channel();
        let refusal = client
            .admit(WorkerCommand::Shutdown { reply: refused })
            .await
            .expect_err("a full queue refuses admission");
        assert!(
            matches!(refusal, WorkerError::Saturated),
            "{refusal} must be a saturation answer"
        );
        assert!(
            refusal.is_overload(),
            "saturation is an overload answer, not a product failure"
        );

        // Only draining the slot widens admission again.
        assert!(
            receiver.try_recv().is_ok(),
            "the worker drained one command"
        );
        let (admitted, _unanswered) = oneshot::channel();
        client
            .admit(WorkerCommand::Shutdown { reply: admitted })
            .await
            .expect("admission resumes after a drain");
    }

    #[tokio::test]
    async fn a_closed_queue_reports_a_stopped_worker() {
        let temp = TempDir::new();
        let startup = spawn(WorkerConfig::new(temp.db(), absent_socket(&temp))).unwrap();
        let client = startup.client().clone();
        startup.stop().await.expect("a clean shutdown");

        let error = client
            .health()
            .await
            .expect_err("a stopped worker answers nothing");
        assert!(matches!(error, WorkerError::Stopped), "{error}");
        assert!(error.is_overload());
    }

    #[tokio::test]
    async fn a_missed_reply_deadline_is_overload_not_success() {
        let temp = TempDir::new();
        let mut config = WorkerConfig::new(temp.db(), absent_socket(&temp));
        // A deadline this short cannot be met by a healthy round trip, which is
        // the point: the caller is bounded even if the worker misbehaves.
        config.reply_deadline = Duration::ZERO;
        let startup = spawn(config).expect("worker starts");
        let client = startup.client().clone();

        // Either the reply beat the zero deadline or it did not; both are
        // truthful. What must never happen is a silent success on a dropped
        // channel.
        match client.health().await {
            Ok(_) => {}
            Err(error) => assert!(error.is_overload(), "{error}"),
        }
        let _ = startup.stop().await;
    }

    fn minimal_managed_state() -> crate::domain::DesiredState {
        use crate::domain::{
            DesiredInterface, DesiredState, InterfaceId, LinkLifecycle, OwnershipDeclaration,
            PrivateKey,
        };
        DesiredState {
            interfaces: vec![DesiredInterface {
                id: InterfaceId::new(),
                name: "wg0".parse().unwrap(),
                ownership: OwnershipDeclaration::Managed,
                lifecycle: LinkLifecycle::Present,
                admin_up: Some(true),
                private_key: PrivateKey::new("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into())
                    .unwrap(),
                listen_port: Some(51820),
                manage_all_peers: false,
                tunnel_prefixes: Vec::new(),
                addresses: Vec::new(),
                routes: Vec::new(),
                peers: Vec::new(),
                clients: Vec::new(),
            }],
            client_routes: Default::default(),
            network_policy: None,
        }
    }
}
