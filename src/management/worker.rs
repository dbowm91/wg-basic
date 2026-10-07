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
//! M001 ships exactly two commands, [`WorkerCommand::Health`] and
//! [`WorkerCommand::Shutdown`]. Both the command set and the reply types are
//! closed enums, so adding an operation is a visible, deliberate change rather
//! than a new stringly-typed channel message.

use super::{error::ManagementError, health::ManagementHealth, runtime::ManagementRuntime};
use crate::{domain::DesiredGeneration, state::AttemptDisposition};
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
    /// Stop the worker; the reply confirms the stop was observed.
    Shutdown { reply: oneshot::Sender<()> },
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
}

impl WorkerError {
    /// Whether the failure is transient from the caller's point of view.
    ///
    /// Saturation and a missed deadline are both overload answers rather than
    /// product failures, so an HTTP surface maps them to 503.
    pub fn is_overload(&self) -> bool {
        matches!(self, Self::Saturated | Self::TimedOut | Self::Stopped)
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

/// The command loop. The runtime is the only thing this thread owns.
fn serve(runtime: ManagementRuntime, receiver: &mut mpsc::Receiver<WorkerCommand>) {
    while let Some(command) = receiver.blocking_recv() {
        match command {
            WorkerCommand::Health { reply } => {
                // The projection cannot fail: it is derived from stored
                // evidence, and an unreadable store degrades the projection
                // rather than raising.
                let _ = reply.send(Ok(runtime.health()));
            }
            WorkerCommand::Shutdown { reply } => {
                let _ = reply.send(());
                break;
            }
        }
    }
    // Falling out of the loop drops `runtime`, which closes the state store.
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
