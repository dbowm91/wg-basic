//! Typed desired/observed reconciliation for one explicitly managed Linux interface.
//!
//! Ownership is split into four units:
//!
//! - [`model`] holds the serialized desired/observed vocabulary;
//! - [`planner`] turns desired versus observed into a deterministic mutation plan;
//! - [`service`] serializes and applies that plan, then re-observes and verifies;
//! - [`linux`] is the isolated RTNETLINK backend.

mod linux;
mod model;
mod planner;
mod service;

pub use linux::LinuxNetworkBackend;
pub use model::{
    ApplyReceipt, ApplyStatus, DesiredAddress, DesiredManagedInterface, DesiredManagedPeer,
    DesiredWireGuardConfiguration, LinkLifecycle, ManagedRoute, MutationKind, ObservedLinkKind,
    ObservedManagedInterface, ObservedRoute, OwnershipDeclaration, PlannedAction, ReconcileError,
    ReconcilePlanSummary, ResourcePresence, SafeFailureCategory,
};
pub use planner::plan_managed_interface;
pub use service::ReconciliationService;

pub(crate) use planner::Mutation;
pub(crate) use service::ReconcileBackend;
