//! The unprivileged management runtime.
//!
//! The management role owns the state store, the current desired generation,
//! projection into network intent, aggregate netd requests, and convergence
//! evidence. It does **not** host HTTP: [`crate::http`] owns every byte of the
//! wire protocol, and reaches this role only through [`WorkerClient`].
//!
//! # Module boundaries
//!
//! Each concern below is owned by exactly one module, and the layering is
//! one-directional so a future surface cannot reach sideways into internals:
//!
//! - [`health`] owns the safe, non-secret health projection and how a recorded
//!   convergence state is derived. It is the only module that describes what an
//!   operator would see, so the Phase 7 surface has one subject to bind to.
//! - [`error`] owns the failure taxonomy and the one rule that maps a failure
//!   onto a retry decision. Retry policy is not spread across call sites.
//! - [`coordinator`] owns the bounded single-slot coalescing rule: when writes
//!   collapse, and when a newer generation waits for a running apply.
//! - [`runtime`] owns the startup sequence and the apply/retry loop, and is the
//!   only module that talks to the state store or to netd.
//! - [`worker`] owns the single blocking thread that holds [`runtime`], plus the
//!   bounded command queue that is the *only* way into it. It is the ADR-003
//!   boundary between synchronous authority and the async HTTP surface.
//!
//! # Startup
//!
//! [`ManagementRuntime::start`] always follows the same sequence: open the
//! hardened store, load the current desired snapshot and generation, project it
//! to an [`crate::aggregate::InstallationNetworkIntent`], connect to authorized
//! netd, apply the current generation, and conditionally record convergence
//! evidence.
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

mod auth;
mod coordinator;
mod error;
mod health;
mod runtime;
mod worker;

pub use auth::{
    set_password_at, status_at, AdminStatus, AuthError, AuthService, IssuedSession,
    VerificationCost,
};
pub use coordinator::{CoordinatorAction, ReconcileCoordinator};
pub use error::{FailureClass, ManagementError, ProjectionFailure};
pub use health::{ConvergenceState, ManagementHealth};
pub use runtime::{ManagementRuntime, ReconcileOutcome};
pub use worker::{
    spawn, StartupReconcile, WorkerClient, WorkerCommand, WorkerConfig, WorkerError, WorkerStartup,
};
