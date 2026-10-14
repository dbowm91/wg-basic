//! M001 Darwin stub for the reconciliation service.
//!
//! The Darwin address/route backend lands in M004. This stub compiles on
//! Darwin so portable intent, protocol, and management code can target both
//! OSes, but every operation fails closed as unsupported. No false-success
//! receipt is ever produced.

use super::model::{
    ApplyReceipt, DesiredManagedInterface, ObservedManagedInterface, ReconcileError,
    ReconcilePlanSummary,
};
use crate::domain::{InterfaceName, OwnerTag};

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
    ) -> Result<ObservedManagedInterface, ReconcileError> {
        Err(ReconcileError::BackendFailure)
    }

    fn apply(
        &self,
        _interface: &InterfaceName,
        _mutation: super::planner::Mutation,
    ) -> Result<(), ReconcileError> {
        Err(ReconcileError::BackendFailure)
    }
}
