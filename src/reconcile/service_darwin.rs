//! The Darwin reconciliation service (C001).
//!
//! The service is the same portable object as the Linux one: it validates the
//! desired state, observes the host, plans with the portable planner, applies
//! the plan through the Darwin backend, and re-observes to verify.
//!
//! Only the backend differs. See [`super::backend_darwin`] for the Darwin
//! kernel boundary and [`crate::wireguard::darwin_backend`] for the ownership
//! contract.

use super::apply::{apply_with_backend, plan_with_backend};
use super::backend_darwin::DarwinNetworkBackend;
use super::model::{ApplyReceipt, DesiredManagedInterface, ReconcileError, ReconcilePlanSummary};
use std::sync::Mutex;

/// The Darwin reconciliation service.
///
/// One installation-wide lock serializes observe/plan/apply/verify sequences.
/// The socket service also handles requests sequentially, so this lock makes
/// the invariant hold for in-process callers that use this controller
/// directly.
pub struct ReconciliationService {
    backend: DarwinNetworkBackend,
    mutation_lock: Mutex<()>,
}

impl Default for ReconciliationService {
    fn default() -> Self {
        Self::new(DarwinNetworkBackend::production())
    }
}

impl ReconciliationService {
    /// Builds the service over an explicit Darwin backend.
    pub fn new(backend: DarwinNetworkBackend) -> Self {
        Self {
            backend,
            mutation_lock: Mutex::new(()),
        }
    }

    /// The Darwin backend this service drives.
    pub fn backend(&self) -> &DarwinNetworkBackend {
        &self.backend
    }

    /// Plans the mutations needed to reach the desired state.
    ///
    /// The plan is a pure function of the desired state and the observation;
    /// it never touches the host.
    pub fn plan(
        &self,
        desired: &DesiredManagedInterface,
    ) -> Result<ReconcilePlanSummary, ReconcileError> {
        desired.validate()?;
        plan_with_backend(desired, &self.backend)
    }

    /// Applies the plan and verifies the result.
    pub fn apply(&self, desired: &DesiredManagedInterface) -> Result<ApplyReceipt, ReconcileError> {
        desired.validate()?;
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| ReconcileError::BackendFailure)?;
        apply_with_backend(desired, &self.backend)
    }
}
