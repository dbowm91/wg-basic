//! The unprivileged management runtime.
//!
//! The management role owns the state store, the current desired generation,
//! projection into network intent, aggregate netd requests, and convergence
//! evidence. It does **not** host HTTP: this milestone adds recovery and
//! reconcile-on-write, not a web surface.
//!
//! # Startup
//!
//! [`ManagementRuntime::start`] always follows the same sequence: open the
//! hardened store, load the current desired snapshot and generation, project it
//! to an [`InstallationNetworkIntent`], connect to authorized netd, apply the
//! current generation, and conditionally record convergence evidence.
//!
//! Startup reconciles **unconditionally**. Even when `last_converged_generation
//! == desired_generation`, the kernel may have drifted while the service was
//! stopped, so the evidence is a hint, not a reason to skip work.
//!
//! # Retry policy
//!
//! Transient failures get a small bounded retry. Ownership and state conflicts
//! are not retryable without an operator or state change, so they fail fast and
//! preserve the desired state. The same is true for refusals: an unauthorized
//! caller or an unsupported backend is diagnosed, not retried. There is
//! deliberately no permanent high-frequency reconciliation loop.
//!
//! # Privilege
//!
//! Management never escalates privileges and never mutates the kernel directly.
//! It reaches the network only through the authorized netd socket, and it never
//! spawns netd itself.

use crate::{
    aggregate::{AggregateStatus, InstallationNetworkIntent},
    domain::{DesiredGeneration, DesiredState, InstallationId, OwnerTag},
    protocol::{InstallationNetworkApplyBody, ProtocolError, RequestOperation, ResponseBody},
    state::{AttemptDisposition, ConvergenceRecord, StateError, StateStore},
};
use std::{
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use crate::state::{project, ResolvedNetworkIntent};

/// Whether the last reconcile reached the desired state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergenceState {
    /// The kernel matches the current desired generation.
    Converged,
    /// A newer desired generation exists than the last converged one.
    Pending,
    /// The last attempt did not converge and a retry may help.
    Retryable,
    /// The last attempt failed in a way that needs an operator or state change.
    Failed,
}

/// A safe, non-secret projection of management health for a future Phase 7.
///
/// This is exactly what a future Phase 7 surface may render: identifiers,
/// generations, and categories. It deliberately has no field for a receipt, an
/// error string, or key material.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ManagementHealth {
    pub database_healthy: bool,
    pub netd_reachable: bool,
    pub installation_id: Option<InstallationId>,
    pub current_desired_generation: Option<DesiredGeneration>,
    pub last_converged_generation: Option<DesiredGeneration>,
    pub convergence: ConvergenceState,
    /// A category only, never an error string.
    pub last_failure_category: Option<AttemptDisposition>,
}

impl ManagementHealth {
    /// The projection is safe to expose: it carries no receipt internals and no
    /// secret-bearing values.
    pub fn is_healthy(&self) -> bool {
        self.database_healthy
            && self.netd_reachable
            && self.convergence == ConvergenceState::Converged
    }
}

/// How a management operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error(transparent)]
    State(#[from] StateError),

    #[error("the desired state cannot be projected into network intent: {0}")]
    Projection(ProjectionFailure),

    #[error("this installation currently manages no interface, so there is nothing to reconcile")]
    NothingToReconcile,

    #[error("could not contact the authorized network service")]
    BackendUnavailable,

    #[error("an earlier network layer changed state and a later one failed; a fresh attempt may converge")]
    PartialFailure,

    #[error("the network service refused the request; operator or state change required")]
    Conflict,

    #[error("the network service rejected this caller")]
    Unauthorized,

    #[error("the network service refused the request; operator or state change required")]
    Rejected,

    #[error("the network service returned an unexpected response")]
    UnexpectedResponse,
}

/// The outcome of one reconcile cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileOutcome {
    /// The generation that was applied. It may be stale relative to the store.
    pub applied_generation: DesiredGeneration,
    /// Whether the store still holds this generation.
    pub still_current: bool,
    pub converged: bool,
    pub disposition: AttemptDisposition,
}

/// A bounded, single-slot coordinator.
///
/// Several writes before an apply begins coalesce to the latest generation.
/// Once an apply begins, a newer generation waits, and after completion the
/// latest state is reconciled immediately. There is no unbounded per-write task
/// and no background scheduler.
#[derive(Debug, Default)]
pub struct ReconcileCoordinator {
    pending: Option<DesiredGeneration>,
    applying: bool,
}

/// What the coordinator decided to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorAction {
    /// No work: either nothing is pending or an apply is already running.
    Idle,
    /// Apply the given generation now.
    Apply(DesiredGeneration),
}

impl ReconcileCoordinator {
    /// Notes that `generation` needs reconciling.
    ///
    /// Repeated calls before an apply starts collapse into one: only the latest
    /// generation is retained.
    pub fn enqueue(&mut self, generation: DesiredGeneration) {
        self.pending = Some(generation);
    }

    /// Claims the pending generation, if one exists and no apply is running.
    pub fn next_action(&mut self) -> CoordinatorAction {
        if self.applying {
            return CoordinatorAction::Idle;
        }
        match self.pending.take() {
            Some(generation) => {
                self.applying = true;
                CoordinatorAction::Apply(generation)
            }
            None => CoordinatorAction::Idle,
        }
    }

    /// Ends the running apply.
    pub fn finish(&mut self) {
        self.applying = false;
    }

    pub fn is_idle(&self) -> bool {
        !self.applying && self.pending.is_none()
    }
}

/// How many times a transient failure is retried, and how long to wait.
const MAX_TRANSIENT_RETRIES: u32 = 3;
const TRANSIENT_BACKOFF: Duration = Duration::from_millis(250);

/// The unprivileged management runtime.
pub struct ManagementRuntime {
    store: StateStore,
    socket: PathBuf,
    coordinator: std::sync::Mutex<ReconcileCoordinator>,
}

impl std::fmt::Debug for ManagementRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagementRuntime")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl ManagementRuntime {
    /// Opens the hardened store and prepares the runtime.
    ///
    /// This validates the state path and runs migrations; it does not touch the
    /// kernel.
    pub fn open(state_path: &Path, socket: impl AsRef<Path>) -> Result<Self, ManagementError> {
        let store = open_store(state_path)?;
        Ok(Self {
            store,
            socket: socket.as_ref().to_path_buf(),
            coordinator: std::sync::Mutex::new(ReconcileCoordinator::default()),
        })
    }

    /// The store this runtime owns.
    pub fn store(&self) -> &StateStore {
        &self.store
    }

    /// Projects the current durable state into the intent netd expects.
    pub fn current_intent(&self) -> Result<Option<InstallationNetworkIntent>, ManagementError> {
        let metadata = self.store.installation_metadata()?;
        let persisted = self.store.load()?;
        build_intent(
            metadata.installation_id,
            persisted.generation,
            &persisted.state,
        )
    }

    /// Loads, projects, and applies the current desired generation once.
    ///
    /// Used by startup and by reconcile-on-write. Returns `None` when the
    /// installation manages no interface, which is a normal empty installation
    /// rather than a failure.
    pub fn reconcile_current(&self) -> Result<Option<ReconcileOutcome>, ManagementError> {
        let Some(intent) = self.current_intent()? else {
            return Ok(None);
        };
        self.apply_intent(&intent).map(Some)
    }

    /// Applies one generation with bounded retry on transient failures.
    pub fn apply_intent(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<ReconcileOutcome, ManagementError> {
        let generation = intent.generation;

        self.store.record_attempt_start(generation)?;

        let mut attempt = 0u32;
        loop {
            match self.submit(intent) {
                Ok(body) => {
                    let disposition = disposition_for(&body);
                    self.store.record_attempt_result(generation, &disposition)?;
                    // A late receipt for an older generation must never mark a
                    // newer desired state converged.
                    let still_current = self.store.record_converged_if_current(generation)?;
                    let converged = disposition == AttemptDisposition::Converged;
                    if !converged
                        && still_current
                        && disposition == AttemptDisposition::PartialFailure
                    {
                        // A partial apply is expected to converge on a fresh retry.
                        attempt += 1;
                        if attempt < MAX_TRANSIENT_RETRIES {
                            thread::sleep(TRANSIENT_BACKOFF);
                            continue;
                        }
                    }
                    return Ok(ReconcileOutcome {
                        applied_generation: generation,
                        still_current,
                        converged,
                        disposition,
                    });
                }
                Err(ManagementError::BackendUnavailable) => {
                    self.store.record_attempt_result(
                        generation,
                        &AttemptDisposition::BackendUnavailable,
                    )?;
                    attempt += 1;
                    if attempt >= MAX_TRANSIENT_RETRIES {
                        return Err(ManagementError::BackendUnavailable);
                    }
                    thread::sleep(TRANSIENT_BACKOFF);
                }
                Err(ManagementError::PartialFailure) => {
                    // netd reported that one layer changed and another failed.
                    // Re-observing on a fresh attempt is expected to converge.
                    self.store
                        .record_attempt_result(generation, &AttemptDisposition::PartialFailure)?;
                    attempt += 1;
                    if attempt >= MAX_TRANSIENT_RETRIES {
                        return Err(ManagementError::PartialFailure);
                    }
                    thread::sleep(TRANSIENT_BACKOFF);
                }
                Err(ManagementError::Conflict) => {
                    // Ownership and state conflicts need an operator or a state
                    // change; retrying cannot help and desired state is preserved.
                    self.store
                        .record_attempt_result(generation, &AttemptDisposition::StateConflict)?;
                    return Err(ManagementError::Conflict);
                }
                Err(ManagementError::Unauthorized) => {
                    self.store
                        .record_attempt_result(generation, &AttemptDisposition::Unauthorized)?;
                    return Err(ManagementError::Unauthorized);
                }
                Err(ManagementError::Rejected | ManagementError::UnexpectedResponse) => {
                    // Unsupported backend, invalid input, a kernel rejection, or
                    // a malformed reply. None of these improve by resubmitting.
                    self.store
                        .record_attempt_result(generation, &AttemptDisposition::Rejected)?;
                    return Err(ManagementError::Rejected);
                }
                Err(other) => return Err(other),
            }
        }
    }

    fn submit(
        &self,
        intent: &InstallationNetworkIntent,
    ) -> Result<InstallationNetworkApplyBody, ManagementError> {
        let response = crate::protocol::request(
            &self.socket,
            RequestOperation::ApplyInstallationNetworkIntent {
                intent: intent.clone(),
            },
            request_id(generation_of(intent)),
        )
        .map_err(classify_io)?;

        match response {
            ResponseBody::InstallationNetworkApplied(body) => Ok(body),
            _ => Err(ManagementError::UnexpectedResponse),
        }
    }

    /// Commits a desired-state mutation and immediately reconciles it.
    ///
    /// Returns the commit result and the reconciliation outcome separately: a
    /// committed database transaction does not mean the kernel converged.
    pub fn commit_and_reconcile(
        &self,
        expected: DesiredGeneration,
        update: impl FnOnce(&DesiredState) -> Result<DesiredState, StateError>,
    ) -> Result<(DesiredGeneration, Option<ReconcileOutcome>), ManagementError> {
        let committed = self.store.mutate(expected, update)?;
        let mut coordinator = self
            .coordinator
            .lock()
            .map_err(|_| ManagementError::Conflict)?;
        coordinator.enqueue(committed.generation);
        drop(coordinator);

        let outcome = self.reconcile_current()?;
        Ok((committed.generation, outcome))
    }

    /// Projects current health without contacting netd.
    pub fn health(&self) -> ManagementHealth {
        let metadata = self.store.installation_metadata().ok();
        let convergence = self.store.convergence().unwrap_or_default();
        let (state, category) = convergence_state(&convergence, metadata.as_ref());
        ManagementHealth {
            database_healthy: metadata.is_some(),
            netd_reachable: matches!(state, ConvergenceState::Converged)
                || matches!(state, ConvergenceState::Retryable),
            installation_id: metadata.map(|m| m.installation_id),
            current_desired_generation: metadata.map(|m| m.desired_generation),
            last_converged_generation: convergence.last_converged_generation,
            convergence: state,
            last_failure_category: category,
        }
    }
}

fn request_id(generation: DesiredGeneration) -> u64 {
    generation.to_storage() as u64
}

fn generation_of(intent: &InstallationNetworkIntent) -> DesiredGeneration {
    intent.generation
}

fn disposition_for(body: &InstallationNetworkApplyBody) -> AttemptDisposition {
    match body.status {
        AggregateStatus::Applied => AttemptDisposition::Converged,
        AggregateStatus::NoChange => AttemptDisposition::Converged,
        AggregateStatus::PartialFailure => AttemptDisposition::PartialFailure,
        AggregateStatus::VerificationFailed => AttemptDisposition::VerificationFailed,
        AggregateStatus::FailedBeforeMutation => AttemptDisposition::FailedBeforeMutation,
    }
}

/// Maps a transport error onto a retry decision.
///
/// When the error came from a netd reply, the [`ProtocolError`] is preserved as
/// the payload and classification is exact. Only genuine transport failures —
/// a missing or refused connection, which is normal while netd starts — fall
/// back to the lossy [`std::io::ErrorKind`].
///
/// Collapsing every failure into "unavailable" would both retry genuine
/// ownership conflicts and record a misleading health category.
fn classify_io(error: std::io::Error) -> ManagementError {
    use std::io::ErrorKind as Kind;
    if let Some(protocol_error) = error
        .get_ref()
        .and_then(|payload| payload.downcast_ref::<ProtocolError>())
    {
        return classify_protocol(*protocol_error);
    }
    match error.kind() {
        Kind::NotFound
        | Kind::ConnectionRefused
        | Kind::ConnectionReset
        | Kind::ConnectionAborted
        | Kind::BrokenPipe
        | Kind::TimedOut
        | Kind::Interrupted
        | Kind::WouldBlock => ManagementError::BackendUnavailable,
        Kind::PermissionDenied => ManagementError::Unauthorized,
        _ => ManagementError::Rejected,
    }
}

/// Classifies a refusal netd actually returned.
fn classify_protocol(error: ProtocolError) -> ManagementError {
    match error {
        ProtocolError::Conflict => ManagementError::Conflict,
        ProtocolError::Unauthorized | ProtocolError::PermissionDenied => {
            ManagementError::Unauthorized
        }
        // netd uses BackendFailure to report that an earlier layer already
        // mutated state and a later layer failed. A fresh attempt is expected
        // to converge, so this stays retryable under a bound.
        ProtocolError::BackendFailure => ManagementError::PartialFailure,
        ProtocolError::UnsupportedVersion
        | ProtocolError::MalformedRequest
        | ProtocolError::InternalFailure
        | ProtocolError::InvalidInput
        | ProtocolError::NotFound
        | ProtocolError::UnsupportedBackend
        | ProtocolError::KernelRejected => ManagementError::Rejected,
    }
}

fn convergence_state(
    record: &ConvergenceRecord,
    metadata: Option<&crate::state::InstallationMetadata>,
) -> (ConvergenceState, Option<AttemptDisposition>) {
    let category = record
        .last_outcome
        .as_deref()
        .and_then(AttemptDisposition::parse_category);
    let Some(metadata) = metadata else {
        return (ConvergenceState::Failed, category);
    };
    let current = metadata.desired_generation;
    match category {
        Some(AttemptDisposition::StateConflict)
        | Some(AttemptDisposition::Unauthorized)
        | Some(AttemptDisposition::Rejected) => (ConvergenceState::Failed, category),
        Some(AttemptDisposition::BackendUnavailable)
        | Some(AttemptDisposition::PartialFailure)
        | Some(AttemptDisposition::VerificationFailed)
        | Some(AttemptDisposition::FailedBeforeMutation) => (ConvergenceState::Retryable, category),
        _ => match record.last_converged_generation {
            Some(converged) if converged == current => (ConvergenceState::Converged, category),
            _ => (ConvergenceState::Pending, category),
        },
    }
}

/// A projection problem, reported as a category rather than a message.
///
/// Carrying only a category keeps diagnostics free of state content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProjectionFailure {
    #[error("durable state does not project into a valid network intent")]
    Invalid,
    #[error("projected owner tag does not match the durable interface identity")]
    OwnerTagMismatch,
}

impl From<crate::state::ProjectionError> for ProjectionFailure {
    fn from(_: crate::state::ProjectionError) -> Self {
        Self::Invalid
    }
}

/// Projects a persisted snapshot into one installation intent.
///
/// Returns `None` for an installation that manages no interface, which is a
/// normal empty state rather than an error.
/// The retry decision implied by a management error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// netd was unreachable; a bounded retry may help.
    BackendUnavailable,
    /// An earlier layer changed state and a later one failed; a bounded retry may
    /// help.
    PartialFailure,
    /// Ownership or state conflict; an operator or state change is required.
    Conflict,
    /// netd refused the request; an operator or state change is required.
    Refused,
    /// Anything else; surfaced without retrying.
    Other,
}

impl ManagementError {
    /// Classifies an error for retry policy and health projection.
    pub fn classify(&self) -> FailureClass {
        match self {
            Self::BackendUnavailable => FailureClass::BackendUnavailable,
            Self::PartialFailure => FailureClass::PartialFailure,
            Self::Conflict => FailureClass::Conflict,
            Self::Unauthorized | Self::Rejected => FailureClass::Refused,
            _ => FailureClass::Other,
        }
    }
}

#[cfg(target_os = "linux")]
fn build_intent(
    installation_id: InstallationId,
    generation: DesiredGeneration,
    state: &DesiredState,
) -> Result<Option<InstallationNetworkIntent>, ManagementError> {
    let resolved: ResolvedNetworkIntent = project(state, installation_id)
        .map_err(|error| ManagementError::Projection(error.into()))?;

    let Some(desired) = resolved.interfaces.into_iter().next() else {
        return Ok(None);
    };
    let interface_id = match state.interfaces.first() {
        Some(interface) => interface.id,
        None => return Ok(None),
    };
    let owner_tag = OwnerTag::new(installation_id, interface_id);
    if desired.owner_tag != owner_tag {
        // The projection derives the tag; a mismatch would mean durable state
        // and projection disagree, which must not reach netd.
        return Err(ManagementError::Projection(
            ProjectionFailure::OwnerTagMismatch,
        ));
    }

    Ok(Some(InstallationNetworkIntent::new(
        installation_id,
        generation,
        interface_id,
        desired,
        resolved.network_policy,
    )))
}

#[cfg(not(target_os = "linux"))]
fn build_intent(
    _installation_id: InstallationId,
    _generation: DesiredGeneration,
    _state: &DesiredState,
) -> Result<Option<InstallationNetworkIntent>, ManagementError> {
    Err(ManagementError::BackendUnavailable)
}

/// Opens the store, initializing it when it does not exist yet.
fn open_store(path: &Path) -> Result<StateStore, StateError> {
    match StateStore::open(path) {
        Ok(store) => Ok(store),
        Err(StateError::MissingParent { .. }) => {
            // A first start initializes the store; migrations run inside the
            // canonical initializer either way.
            StateStore::initialize(path)
        }
        Err(StateError::DatabaseAlreadyExists { .. }) => StateStore::open(path),
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::InterfaceId;

    #[test]
    fn the_coordinator_coalesces_writes_before_an_apply_starts() {
        let mut coordinator = ReconcileCoordinator::default();
        coordinator.enqueue(DesiredGeneration::new(1).unwrap());
        coordinator.enqueue(DesiredGeneration::new(2).unwrap());
        coordinator.enqueue(DesiredGeneration::new(3).unwrap());

        match coordinator.next_action() {
            CoordinatorAction::Apply(generation) => {
                assert_eq!(
                    generation,
                    DesiredGeneration::new(3).unwrap(),
                    "several writes before an apply must collapse to the latest generation"
                );
            }
            CoordinatorAction::Idle => panic!("an apply should be claimable"),
        }
    }

    #[test]
    fn a_newer_generation_waits_while_an_apply_is_running() {
        let mut coordinator = ReconcileCoordinator::default();
        coordinator.enqueue(DesiredGeneration::new(1).unwrap());
        assert!(matches!(
            coordinator.next_action(),
            CoordinatorAction::Apply(_)
        ));

        coordinator.enqueue(DesiredGeneration::new(2).unwrap());
        assert_eq!(
            coordinator.next_action(),
            CoordinatorAction::Idle,
            "a newer generation must wait for the running apply"
        );

        coordinator.finish();
        assert!(matches!(
            coordinator.next_action(),
            CoordinatorAction::Apply(_)
        ));
    }

    #[test]
    fn an_idle_coordinator_does_no_work() {
        let mut coordinator = ReconcileCoordinator::default();
        assert_eq!(coordinator.next_action(), CoordinatorAction::Idle);
        assert!(coordinator.is_idle());
    }

    #[test]
    fn transient_transport_errors_are_treated_as_backend_unavailable() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::TimedOut,
        ] {
            let error = classify_io(std::io::Error::new(kind, "x"));
            assert_eq!(
                error.classify(),
                FailureClass::BackendUnavailable,
                "{kind:?}"
            );
        }
        assert_eq!(
            ManagementError::Conflict.classify(),
            FailureClass::Conflict,
            "ownership conflicts must not be retried"
        );
    }

    #[test]
    fn refusals_are_not_mistaken_for_an_unavailable_backend() {
        for (error, expected) in [
            (ProtocolError::Conflict, FailureClass::Conflict),
            (ProtocolError::Unauthorized, FailureClass::Refused),
            (ProtocolError::PermissionDenied, FailureClass::Refused),
            (ProtocolError::UnsupportedBackend, FailureClass::Refused),
            (ProtocolError::MalformedRequest, FailureClass::Refused),
            (ProtocolError::InternalFailure, FailureClass::Refused),
            (ProtocolError::InvalidInput, FailureClass::Refused),
            (ProtocolError::KernelRejected, FailureClass::Refused),
            // A partial apply stays retryable under a bound.
            (ProtocolError::BackendFailure, FailureClass::PartialFailure),
        ] {
            let classified = classify_protocol(error).classify();
            assert_eq!(classified, expected, "{error:?}");
            assert_ne!(
                classified,
                FailureClass::BackendUnavailable,
                "{error:?} must not be retried as a transient outage"
            );
        }
    }

    /// The client keeps the wire refusal as the io error payload, so an exact
    /// classification survives the transport boundary.
    #[test]
    fn a_preserved_protocol_error_outranks_the_transport_kind() {
        let wrapped = std::io::Error::other(ProtocolError::BackendFailure);
        assert_eq!(
            classify_io(wrapped).classify(),
            FailureClass::PartialFailure,
            "a partial apply must not be confused with a hard refusal"
        );
    }

    #[test]
    fn non_retryable_categories_never_project_as_retryable() {
        let metadata = crate::state::InstallationMetadata {
            installation_id: InstallationId::new(),
            desired_generation: DesiredGeneration::new(2).unwrap(),
            created_at: 0,
            updated_at: 0,
        };
        for category in ["state_conflict", "unauthorized", "rejected"] {
            let record = ConvergenceRecord {
                last_attempted_generation: Some(DesiredGeneration::new(2).unwrap()),
                last_converged_generation: Some(DesiredGeneration::new(2).unwrap()),
                last_attempt_timestamp: Some(0),
                last_outcome: Some(category.into()),
            };
            assert_eq!(
                convergence_state(&record, Some(&metadata)).0,
                ConvergenceState::Failed,
                "{category} needs an operator, not a retry"
            );
        }
    }

    #[test]
    fn attempt_dispositions_are_categories_not_messages() {
        for disposition in [
            AttemptDisposition::Converged,
            AttemptDisposition::PartialFailure,
            AttemptDisposition::VerificationFailed,
            AttemptDisposition::FailedBeforeMutation,
            AttemptDisposition::Superseded,
            AttemptDisposition::StateConflict,
            AttemptDisposition::BackendUnavailable,
            AttemptDisposition::Unauthorized,
            AttemptDisposition::Rejected,
        ] {
            let rendered = disposition.as_str();
            assert!(!rendered.is_empty());
            assert_eq!(
                AttemptDisposition::parse_category(rendered),
                Some(disposition)
            );
        }
        assert_eq!(
            AttemptDisposition::parse_category("secret-looking-string"),
            None
        );
    }

    #[test]
    fn health_reports_pending_when_convergence_lags_the_desired_generation() {
        let metadata = crate::state::InstallationMetadata {
            installation_id: InstallationId::new(),
            desired_generation: DesiredGeneration::new(4).unwrap(),
            created_at: 0,
            updated_at: 0,
        };
        let record = ConvergenceRecord {
            last_attempted_generation: Some(DesiredGeneration::new(4).unwrap()),
            last_converged_generation: Some(DesiredGeneration::new(3).unwrap()),
            last_attempt_timestamp: Some(0),
            last_outcome: Some("converged".into()),
        };
        assert_eq!(
            convergence_state(&record, Some(&metadata)).0,
            ConvergenceState::Pending
        );

        let record = ConvergenceRecord {
            last_converged_generation: Some(DesiredGeneration::new(4).unwrap()),
            ..record
        };
        assert_eq!(
            convergence_state(&record, Some(&metadata)).0,
            ConvergenceState::Converged
        );

        let record = ConvergenceRecord {
            last_outcome: Some("state_conflict".into()),
            ..record
        };
        assert_eq!(
            convergence_state(&record, Some(&metadata)).0,
            ConvergenceState::Failed
        );
    }

    #[test]
    fn health_projection_never_carries_a_receipt_or_secret() {
        let health = ManagementHealth {
            database_healthy: true,
            netd_reachable: true,
            installation_id: Some(InstallationId::new()),
            current_desired_generation: DesiredGeneration::new(2),
            last_converged_generation: DesiredGeneration::new(2),
            convergence: ConvergenceState::Converged,
            last_failure_category: None,
        };
        let rendered = format!("{health:?}");
        for forbidden in ["PrivateKey", "PresharedKey", "REDACTED"] {
            assert!(!rendered.contains(forbidden), "{forbidden} in {rendered}");
        }
    }

    #[test]
    fn intent_projection_requires_a_usable_installation_state() {
        let empty = DesiredState::default();
        let intent = build_intent(
            InstallationId::new(),
            DesiredGeneration::new(1).unwrap(),
            &empty,
        );
        assert!(
            intent.is_ok(),
            "an installation with no interfaces projects to no intent, not an error"
        );
        assert_eq!(intent.unwrap(), None);
    }

    #[test]
    fn a_projected_intent_carries_a_matching_owner_tag_and_generation() {
        let state = crate::domain::validate_desired_state;
        let _ = state;
        let installation = InstallationId::new();
        let interface_id = InterfaceId::new();
        let snapshot = sample_state(interface_id);
        let generation = DesiredGeneration::new(7).unwrap();
        let intent = build_intent(installation, generation, &snapshot)
            .expect("valid snapshot projects")
            .expect("one interface yields one intent");

        assert_eq!(intent.installation_id, installation);
        assert_eq!(intent.generation, generation);
        assert_eq!(intent.interface_id, interface_id);
        assert_eq!(intent.owner_tag(), intent.desired_interface.owner_tag);
        assert!(intent.validate().is_ok());
        assert!(intent.is_present());
    }

    fn sample_state(interface_id: InterfaceId) -> DesiredState {
        let peer_id = crate::domain::PeerId::new();
        let address: ipnet::IpNet = "10.8.0.2/32".parse().unwrap();
        DesiredState {
            interfaces: vec![crate::domain::DesiredInterface {
                id: interface_id,
                name: "wg0".parse().unwrap(),
                ownership: crate::domain::OwnershipDeclaration::Managed,
                lifecycle: crate::domain::LinkLifecycle::Present,
                admin_up: Some(true),
                private_key: crate::domain::PrivateKey::new(
                    "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".into(),
                )
                .unwrap(),
                listen_port: Some(51820),
                manage_all_peers: true,
                tunnel_prefixes: vec![crate::domain::NetworkPrefix::new(
                    "10.8.0.0/24".parse().unwrap(),
                )],
                addresses: vec![crate::domain::DesiredAddress {
                    address: "10.8.0.1/24".parse().unwrap(),
                    presence: crate::domain::ResourcePresence::Present,
                }],
                routes: Vec::new(),
                peers: vec![crate::domain::DesiredPeer {
                    id: peer_id,
                    public_key: crate::domain::PublicKey::new(
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    )
                    .unwrap(),
                    private_key: None,
                    preshared_key: None,
                    allowed_ips: vec![crate::domain::NetworkPrefix::new(address)],
                    persistent_keepalive_seconds: None,
                    endpoint: None,
                }],
                clients: vec![crate::domain::DesiredClient {
                    id: crate::domain::ClientId::new(),
                    peer_id,
                    assigned_address: address,
                    route_policy: Default::default(),
                }],
            }],
            client_routes: Default::default(),
            network_policy: None,
        }
    }
}
