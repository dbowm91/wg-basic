//! Windows reconciliation service. The portable planner decides the mutations.
//! This service only supplies the wireguard-nt and IP Helper backend.

use super::apply::{apply_with_backend, plan_with_backend};
use super::backend_windows::WindowsNetworkBackend;
use super::model::{ApplyReceipt, DesiredManagedInterface, ReconcileError, ReconcilePlanSummary};
use std::sync::Mutex;

pub struct ReconciliationService {
    backend: WindowsNetworkBackend,
    mutation_lock: Mutex<()>,
}

impl Default for ReconciliationService {
    fn default() -> Self {
        Self {
            backend: WindowsNetworkBackend,
            mutation_lock: Mutex::new(()),
        }
    }
}

impl ReconciliationService {
    pub fn plan(
        &self,
        desired: &DesiredManagedInterface,
    ) -> Result<ReconcilePlanSummary, ReconcileError> {
        desired.validate()?;
        plan_with_backend(desired, &self.backend)
    }

    pub fn apply(&self, desired: &DesiredManagedInterface) -> Result<ApplyReceipt, ReconcileError> {
        desired.validate()?;
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| ReconcileError::BackendFailure)?;
        apply_with_backend(desired, &self.backend)
    }
}
