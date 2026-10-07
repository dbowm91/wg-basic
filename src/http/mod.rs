//! The management HTTP application boundary.
//!
//! This module is the only place in the tree that speaks HTTP. It owns routing,
//! status selection, and the EggServe [`Service`] implementation, and it reaches
//! management state exclusively through the bounded
//! [`WorkerClient`](crate::management::worker::WorkerClient).
//!
//! # What the surface may say
//!
//! Everything rendered here is bounded by construction. Bodies are fixed
//! literals, never formatted from an error, a path, or an internal type. M001
//! additionally reduces `/healthz` to a two-state liveness answer, so it cannot
//! disclose an installation ID, a generation, a filesystem path, a desired-state
//! fact, or a backend failure detail.
//!
//! # EggServe, directly
//!
//! Per ADR-003 the service embeds `eggserve-server` and `eggserve-primitives`
//! directly. There is deliberately no `eggserve-core`, no `eggserve-static`, and
//! no router framework: assets are embedded by this crate, and routing is a
//! closed match over the routes M001–M004 define.

pub mod config;
pub mod response;
pub mod serve;
pub mod service;

pub use config::{HttpError, HttpLimits, ManagementHttpConfig};
pub use response::{Liveness, MAX_MANAGEMENT_BODY_BYTES};
pub use serve::{run, run_blocking, ServeConfig, ServeError, ServeReport};
pub use service::ManagementService;
