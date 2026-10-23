//! Typed desired/observed reconciliation for one explicitly managed interface.
//!
//! Ownership is split into units:
//!
//! - [`model`] holds the serialized desired/observed vocabulary (portable;
//!   M001 separates the Linux-only `ifindex`/`interface_alias` observation
//!   metadata from the portable [`OwnerTag`] ownership proof);
//! - [`planner`] turns desired versus observed into a deterministic mutation plan
//!   (portable, pure);
//! - [`apply`] serializes and applies that plan, then re-observes and verifies
//!   (portable; both platforms execute the same sequence);
//! - [`service`] owns the Linux backend that observes and mutates the host;
//! - [`linux`] is the isolated RTNETLINK backend (Linux only; Darwin gains its
//!   address/route backend in M004).
//!
//! The OS-assigned locator (`ifindex`, kernel device name, and on Darwin the
//! ephemeral `utunN` name) is observation metadata only. Ownership is proven by
//! the [`OwnerTag`] derived from the logical [`InterfaceId`], never by a name
//! or index alone.

mod apply;
#[cfg(target_os = "macos")]
mod backend_darwin;
/// Darwin address/route observation + pure planning (M004 modeling scope;
/// the privileged route-socket backend lands with the live helper).
#[cfg(target_os = "macos")]
pub mod darwin;
#[cfg(target_os = "linux")]
mod linux;
mod model;
mod planner;
#[cfg(target_os = "linux")]
mod service;
#[cfg(target_os = "macos")]
mod service_darwin;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod service_other;

#[cfg(target_os = "linux")]
pub use linux::LinuxNetworkBackend;
pub use model::{
    ApplyReceipt, ApplyStatus, DesiredAddress, DesiredManagedInterface, DesiredManagedPeer,
    DesiredWireGuardConfiguration, LinkLifecycle, ManagedRoute, MutationKind, ObservedLinkKind,
    ObservedManagedInterface, ObservedRoute, OwnershipDeclaration, PlannedAction, ReconcileError,
    ReconcilePlanSummary, ResourcePresence, SafeFailureCategory,
};
pub use planner::plan_managed_interface;
#[cfg(target_os = "linux")]
pub use service::ReconciliationService;
#[cfg(not(target_os = "linux"))]
pub use service_darwin::ReconciliationService;

pub(crate) use apply::ReconcileBackend;
pub(crate) use planner::Mutation;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use service_other::ReconcileBackend;
