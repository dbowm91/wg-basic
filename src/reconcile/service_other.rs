//! Stub reconciliation service for platforms that are neither Linux nor macOS.
//!
//! These platforms are not a supported deployment target. The service exists
//! only so the crate still compiles, and every operation fails closed as
//! unsupported rather than pretending convergence.

use super::model::{ApplyReceipt, DesiredManagedInterface, ReconcileError, ReconcilePlanSummary};
use crate::domain::{InterfaceName, OwnerTag};
use crate::reconcile::planner::Mutation;

/// Darwin placeholder. Never mutates host state.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReconciliationService;

impl ReconciliationService {
    pub fn new() -> Self {
        Self
    }

    pub fn plan(
        &self,
        _desired: &DesiredManagedInterface,
    ) -> Result<ReconcilePlanSummary, ReconcileError> {
        Err(ReconcileError::BackendFailure)
    }

    pub fn apply(
        &self,
        _desired: &DesiredManagedInterface,
    ) -> Result<ApplyReceipt, ReconcileError> {
        Err(ReconcileError::BackendFailure)
    }
}

pub(crate) trait ReconcileBackend {
    fn observe(
        &self,
        _interface: &InterfaceName,
        _owner_tag: &OwnerTag,
    ) -> Result<super::model::ObservedManagedInterface, ReconcileError> {
        Err(ReconcileError::BackendFailure)
    }

    fn apply(&self, _interface: &InterfaceName, _mutation: Mutation) -> Result<(), ReconcileError> {
        Err(ReconcileError::BackendFailure)
    }
}
