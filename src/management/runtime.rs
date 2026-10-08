//! The startup sequence, the apply/retry loop, and the health snapshot.
//!
//! This is the only management module that touches the state store or the
//! authorized netd socket. Everything it needs from the rest of the role arrives
//! as a value: an intent built from durable state, a retry decision from
//! [`super::error`], and a coalescing decision from [`super::coordinator`].

use super::{
    coordinator::ReconcileCoordinator,
    error::{classify_io, ManagementError, ProjectionFailure},
    health::{convergence_state, netd_reachability, BackendProbe, ManagementHealth},
};
use crate::{
    aggregate::{AggregateStatus, InstallationNetworkIntent},
    domain::{DesiredGeneration, DesiredState, InstallationId, OwnerTag},
    protocol::{InstallationNetworkApplyBody, RequestOperation, ResponseBody},
    state::{AttemptDisposition, StateError, StateStore},
};
use std::{
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use crate::{
    domain::PrincipalId,
    product::{DegradedCategory, ProductMutationReceipt},
    state::{
        project, ClientVisibility, CommittedProductState, ProductAudit, ProductState,
        ResolvedNetworkIntent,
    },
};

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
    ///
    /// Deliberately `pub(super)`: reachable from exactly one place, the worker
    /// thread in [`super::worker`]. That is the ADR-003 boundary enforced by the
    /// compiler rather than by a review comment — no other module in the crate
    /// can reach SQLite through this accessor, and the HTTP boundary cannot
    /// reach it at all. It was public before Phase 7 M002 had any caller; with
    /// none, public was a promise the type system did not need to make.
    pub(super) fn store(&self) -> &StateStore {
        &self.store
    }

    /// Projects the current durable state into the intent netd expects.
    pub fn current_intent(&self) -> Result<Option<InstallationNetworkIntent>, ManagementError> {
        let metadata = self.store.installation_metadata()?;
        let persisted = self.store.load()?;
        // A disabled managed client's peer must be absent from the intent the
        // kernel is asked to hold, so the product snapshot is read here rather
        // than projected from desired state alone.
        let product = self.store.load_product()?;
        project_diagnostic_intent(
            metadata.installation_id,
            persisted.generation,
            &persisted.state,
            &product.state,
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
        let generation = intent.generation;
        crate::operational::emit(
            "reconcile.started",
            crate::operational::Severity::Info,
            "serve",
            "reconcile",
            "started",
            Some(("interface", intent.desired_interface.interface.as_str())),
            Some(generation.to_storage() as u64),
            Some("aggregate_apply"),
        );
        match self.apply_intent(&intent) {
            Ok(outcome) => {
                crate::operational::emit(
                    if outcome.converged {
                        "reconcile.completed"
                    } else {
                        "reconcile.degraded"
                    },
                    if outcome.converged {
                        crate::operational::Severity::Info
                    } else {
                        crate::operational::Severity::Warn
                    },
                    "serve",
                    "reconcile",
                    if outcome.converged {
                        "converged"
                    } else {
                        "not_converged"
                    },
                    Some(("interface", intent.desired_interface.interface.as_str())),
                    Some(outcome.applied_generation.to_storage() as u64),
                    Some("aggregate_apply"),
                );
                Ok(Some(outcome))
            }
            Err(error) => {
                crate::operational::emit(
                    "reconcile.degraded",
                    crate::operational::Severity::Warn,
                    "serve",
                    "reconcile",
                    "attempt_failed",
                    Some(("interface", intent.desired_interface.interface.as_str())),
                    Some(generation.to_storage() as u64),
                    Some("aggregate_apply"),
                );
                Err(error)
            }
        }
    }

    /// Applies one already-committed product mutation and reports the two
    /// outcomes separately.
    ///
    /// This exists because `apply_intent` cannot answer the question a product
    /// mutation has to answer. A commit either succeeded or it did not, and a
    /// reconcile either enforced it or it did not -- but a *committed* mutation
    /// whose reconcile failed is not a failure of the mutation, and returning it
    /// as one would tell an operator their client was not created when it very
    /// much was.
    ///
    /// So the two facts are kept apart. The generation is durable and is
    /// returned whatever happened; `enforcement` says only whether the kernel
    /// has caught up. A `Degraded` receipt is not a pending request: the
    /// reconciler will converge it on a later pass, and the operator's change is
    /// already recorded.
    pub fn reconcile_after_commit(
        &self,
        generation: DesiredGeneration,
    ) -> Result<ProductMutationReceipt, ManagementError> {
        match self.reconcile_current() {
            Ok(outcome) => Ok(receipt_for(generation, outcome)),
            // A backend that is unreachable, refusing, or rejecting produces a
            // degraded receipt rather than an error. That is the whole reason
            // this method exists: reporting "the backend is down" to a caller
            // that has *already committed* would tell the operator their change
            // did not happen when it did. Only a failure to even attempt the
            // reconcile -- a state or projection problem -- is still an error,
            // and it is an error about the reconcile, not about the commit.
            Err(error) if is_backend_outcome(&error) => Ok(ProductMutationReceipt::degraded(
                generation,
                degraded_category(&error),
            )),
            Err(error) => Err(error),
        }
    }

    /// Commits a product mutation and reconciles it, returning one receipt.
    ///
    /// `mutate` runs inside the store's transaction, so an error it returns is a
    /// pre-commit refusal and nothing is reconciled. Once it returns `Ok`, the
    /// commit is durable and `reconcile_after_commit` can only ever add an
    /// enforcement fact to it.
    pub fn commit_product_and_reconcile(
        &self,
        expected_generation: DesiredGeneration,
        principal_id: Option<PrincipalId>,
        mutate: impl FnOnce(
            &DesiredState,
            &mut ProductState,
        ) -> Result<(DesiredState, ProductAudit), StateError>,
    ) -> Result<(ProductMutationReceipt, CommittedProductState), ManagementError> {
        let committed = self
            .store
            .mutate_product(expected_generation, principal_id, mutate)?;
        let receipt = self.reconcile_after_commit(committed.generation)?;
        Ok((receipt, committed))
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
            netd_reachable: netd_reachability(&convergence, metadata.as_ref()),
            installation_id: metadata.map(|m| m.installation_id),
            current_desired_generation: metadata.map(|m| m.desired_generation),
            last_converged_generation: convergence.last_converged_generation,
            convergence: state,
            last_failure_category: category,
        }
    }

    /// Asks the authorized netd whether it is answering *right now*.
    ///
    /// [`ManagementRuntime::health`] deliberately contacts nothing: it reports
    /// what is recorded, which is cheap and safe to serve to an unauthenticated
    /// `/healthz`. That is the right answer for a liveness probe and the wrong
    /// answer for an operator, because a fresh installation with nothing applied
    /// records no evidence at all and is indistinguishable from an installation
    /// whose backend is down. Both report `netd_reachable: false`.
    ///
    /// This is the live half: one `Ping` over the authorized socket, carrying no
    /// request that could mutate anything. It costs a socket round trip, which is
    /// exactly why only the authenticated route calls it — an unauthenticated
    /// caller must not be able to make this process dial the backend.
    ///
    /// Never fails as an error: the *answer* is "not answering", which is the
    /// information an operator asked for. A panic would be the one thing a health
    /// check must never do.
    pub fn probe_backend(&self) -> BackendProbe {
        // A request id that cannot collide with a reconcile's: those are
        // generation numbers, and a probe is not one of them.
        const PROBE_REQUEST_ID: u64 = u64::MAX;
        let answer =
            crate::protocol::request(&self.socket, RequestOperation::Ping, PROBE_REQUEST_ID);
        match answer {
            Ok(ResponseBody::Pong { service, .. }) => BackendProbe {
                answered: true,
                service: Some(service),
            },
            // Something answered, but not with a pong. The backend is *up* and
            // behaving unexpectedly, which is a different fault from being down
            // and an operator needs to be able to tell them apart.
            Ok(_) => BackendProbe {
                answered: false,
                service: None,
            },
            Err(_) => BackendProbe {
                answered: false,
                service: None,
            },
        }
    }

    /// Makes one fresh, read-only WireGuard device observation for the worker.
    /// HTTP never sees the protocol response or talks to netd directly.
    #[cfg(target_os = "linux")]
    pub fn observe_wireguard_device(
        &self,
        interface: crate::domain::InterfaceName,
    ) -> Result<crate::wireguard::ObservedWireGuardDevice, ManagementError> {
        let response = crate::protocol::request(
            &self.socket,
            RequestOperation::ObserveWireGuardDevice { interface },
            u64::MAX - 1,
        )
        .map_err(classify_io)?;
        match response {
            ResponseBody::WireGuardDevice(device) => Ok(device),
            _ => Err(ManagementError::UnexpectedResponse),
        }
    }
}

fn request_id(generation: DesiredGeneration) -> u64 {
    generation.to_storage() as u64
}

fn generation_of(intent: &InstallationNetworkIntent) -> DesiredGeneration {
    intent.generation
}

/// Turns a reconcile outcome into the enforcement half of a receipt.
///
/// `None` means the installation projects no intent at all -- an empty
/// installation, where "converged" and "nothing to enforce" are the same fact.
/// A failed reconcile is reported as `Degraded` with the category that actually
/// caused it, so an operator learns whether the backend was unreachable,
/// refused, or rejected without the internal error text ever becoming a
/// user-facing string.
fn receipt_for(
    generation: DesiredGeneration,
    outcome: Option<ReconcileOutcome>,
) -> ProductMutationReceipt {
    let Some(outcome) = outcome else {
        return ProductMutationReceipt::converged(generation);
    };
    if outcome.converged {
        return ProductMutationReceipt::converged(generation);
    }
    let category = match outcome.disposition {
        AttemptDisposition::BackendUnavailable => DegradedCategory::BackendUnreachable,
        AttemptDisposition::Unauthorized => DegradedCategory::BackendRefused,
        AttemptDisposition::Converged
        | AttemptDisposition::PartialFailure
        | AttemptDisposition::VerificationFailed
        | AttemptDisposition::FailedBeforeMutation
        | AttemptDisposition::Superseded
        | AttemptDisposition::StateConflict
        | AttemptDisposition::Rejected => DegradedCategory::BackendRefused,
    };
    ProductMutationReceipt::degraded(generation, category)
}

/// Whether a reconcile failure is the kernel's answer rather than a fault in
/// applying the intent at all.
///
/// A backend that refused, rejected, or went away means the kernel does not
/// currently hold the committed generation. A state or projection failure means
/// the intent could not even be formed, which is a different problem entirely.
fn is_backend_outcome(error: &ManagementError) -> bool {
    matches!(
        error,
        ManagementError::BackendUnavailable
            | ManagementError::PartialFailure
            | ManagementError::Unauthorized
            | ManagementError::Rejected
            | ManagementError::Conflict
            | ManagementError::UnexpectedResponse
    )
}

/// The bounded category an operator sees for a failed enforcement.
fn degraded_category(error: &ManagementError) -> DegradedCategory {
    match error {
        ManagementError::BackendUnavailable => DegradedCategory::BackendUnreachable,
        _ => DegradedCategory::BackendRefused,
    }
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

/// Projects a persisted snapshot into one installation intent.
///
/// Returns `None` for an installation that manages no interface, which is a
/// normal empty state rather than an error.
#[cfg(target_os = "linux")]
fn build_intent(
    installation_id: InstallationId,
    generation: DesiredGeneration,
    state: &DesiredState,
    visibility: &ClientVisibility,
) -> Result<Option<InstallationNetworkIntent>, ManagementError> {
    let resolved: ResolvedNetworkIntent = project(state, installation_id, visibility)
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

/// Projects a coherent read-only state snapshot into the exact typed intent
/// sent to netd. Doctor uses this to request a plan without opening the
/// migrating management store or applying anything.
#[cfg(target_os = "linux")]
pub fn project_diagnostic_intent(
    installation_id: InstallationId,
    generation: DesiredGeneration,
    state: &DesiredState,
    product: &ProductState,
) -> Result<Option<InstallationNetworkIntent>, ManagementError> {
    let visibility = ClientVisibility::from_product(state, product);
    let mut effective = state.clone();
    if let Some(interface) = effective.interfaces.first_mut() {
        if product
            .network_operational_enabled
            .get(&interface.id)
            .is_some_and(|enabled| !enabled)
        {
            interface.lifecycle = crate::domain::LinkLifecycle::Absent;
            interface.admin_up = None;
            for address in &mut interface.addresses {
                address.presence = crate::domain::ResourcePresence::Absent;
            }
            for route in &mut interface.routes {
                route.presence = crate::domain::ResourcePresence::Absent;
            }
            effective.network_policy = None;
        }
    }
    build_intent(installation_id, generation, &effective, &visibility)
}

#[cfg(not(target_os = "linux"))]
fn build_intent(
    _installation_id: InstallationId,
    _generation: DesiredGeneration,
    _state: &DesiredState,
    _visibility: &ClientVisibility,
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
    fn intent_projection_requires_a_usable_installation_state() {
        let empty = DesiredState::default();
        let intent = build_intent(
            InstallationId::new(),
            DesiredGeneration::new(1).unwrap(),
            &empty,
            &ClientVisibility::all_enabled(),
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
        let intent = build_intent(
            installation,
            generation,
            &snapshot,
            &ClientVisibility::all_enabled(),
        )
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
