//! The management HTTP application boundary.
//!
//! This module is the only place in the tree that speaks HTTP. It owns routing,
//! status selection, and the EggServe [`Service`] implementation, and it reaches
//! management state exclusively through the bounded
//! [`WorkerClient`](crate::management::worker::WorkerClient).
//!
//! # Readiness is one lossy projection
//!
//! [`Readiness`] distinguishes process liveness, a fatal state store, an
//! unhealthy dependency, and authenticated detailed health. It deliberately
//! projects down to two anonymous tokens: adding a reason changes what the
//! operator's log says, and cannot change what `/healthz` returns.
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

pub mod api;
pub mod assets;
pub mod config;
pub mod headers;
pub mod origin;
pub mod ratelimit;
pub mod readiness;
pub mod response;
pub mod serve;
pub mod service;
pub mod session_cookie;

pub use api::{AuthenticatedApi, RequestGuard, RequestRejection, LOGIN_BODY_LIMIT};
pub use assets::{asset, Asset, INVENTORY};
pub use config::{HttpError, HttpLimits, ManagementHttpConfig};
pub use origin::{
    CanonicalOrigin, ExposureMode, OriginConfigError, OriginPolicy, CSRF_HEADER,
    SESSION_COOKIE_NAME, SESSION_COOKIE_SECURE_NAME,
};
pub use ratelimit::{Admission, Bucket, LoginLimiter};
pub use readiness::{Dependency, Readiness};
pub use response::{Liveness, MAX_MANAGEMENT_BODY_BYTES};
pub use serve::{run, run_blocking, run_publishing, ServeConfig, ServeError, ServeReport};
pub use service::ManagementService;
pub use session_cookie::{CookieProfile, SessionCookieError};
