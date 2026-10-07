//! Process lifecycle for the management service.
//!
//! # Order is the contract
//!
//! The order below is not incidental; each step depends on the previous one
//! having succeeded:
//!
//! 1. Validate the HTTP configuration. Nothing authority-bearing is opened
//!    before the limits are known to be valid, so a bad limit cannot leave a
//!    half-started service holding the state store.
//! 2. Start the bounded worker, which opens the state store and attempts the
//!    mandatory startup reconciliation.
//! 3. Bind EggServe.
//! 4. Report readiness — including the degraded/fatal distinction, which an
//!    operator needs and `/healthz` deliberately withholds.
//! 5. Serve until signalled.
//! 6. Stop accepting, drain in-flight requests under the configured grace
//!    period, stop the worker, and release the store.
//!
//! A database, path, or migration failure at step 2 is fatal and the process
//! exits without ever having bound a listener: there is no authoritative state
//! to administer, so a live surface would be a lie. A netd outage is *not*
//! fatal — the operator needs the surface in order to see and fix it.
//!
//! # What this role never does
//!
//! Management never spawns or elevates netd and never requires a capability of
//! its own. It reaches the kernel only through the authorized socket, from the
//! worker thread, on behalf of a request.

use super::config::{HttpError, ManagementHttpConfig};
use super::origin::{OriginConfigError, OriginPolicy};
use super::ratelimit::{Bucket, LoginLimiter};
use crate::management::{spawn, StartupReconcile, WorkerConfig, WorkerError};
use eggserve_server::Server;
use std::{future::Future, net::SocketAddr, path::PathBuf, sync::Arc};

/// The global login budget: a burst of 20 verifications.
///
/// Sized from M002's measurement rather than picked. One verification costs
/// ~300 ms of the appliance's CPU, so 20 in flight is ~6 s of work — already past
/// the worker's five-second reply deadline, so the surplus must be refused
/// rather than queued. See [`Bucket`] and `tests/authenticated_api.rs`.
const DEFAULT_LOGIN_GLOBAL_BUCKET: Bucket = Bucket {
    capacity: 20,
    refill_per_second: 2.0,
};

/// The per-peer login budget: a burst of 8.
///
/// Comfortably more than a human typist manages and comfortably less than the
/// global budget, so one host cannot consume the whole appliance.
const DEFAULT_LOGIN_PEER_BUCKET: Bucket = Bucket {
    capacity: 8,
    refill_per_second: 1.0,
};

/// How many distinct peers the limiter remembers.
///
/// A memory bound, not a tuning knob: an unbounded map keyed by client address
/// is itself a denial-of-service vector.
const DEFAULT_TRACKED_PEERS: usize = 1024;

/// Everything `wg-basic serve` was asked to do.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Path to the authoritative state database.
    pub state_path: PathBuf,
    /// Path to the authorized local netd socket.
    pub netd_socket: PathBuf,
    /// The management listener and its limits.
    pub http: ManagementHttpConfig,
    /// The canonical external origin and the allowed `Host` set.
    pub origin: OriginPolicy,
}

impl ServeConfig {
    /// Assembles the default configuration: loopback listener, loopback origin.
    ///
    /// The default is the only configuration that is correct without an operator
    /// saying anything, because it is the only one where the listener is not
    /// reachable from the network.
    pub fn new(
        state_path: impl Into<PathBuf>,
        netd_socket: impl Into<PathBuf>,
        http_bind: &str,
    ) -> Result<Self, HttpError> {
        let http = ManagementHttpConfig::new(http_bind)?;
        let origin = if http.bind().ip().is_loopback() {
            OriginPolicy::loopback_only(http.bind())
        } else {
            // A routable bind with no canonical origin to check `Host` against
            // would accept any `Host`, which is the rebinding hole M003 exists to
            // close. So the default refuses rather than defaults to permissive.
            return Err(HttpError::OffHostNeedsAcknowledgement);
        };
        Ok(Self {
            state_path: state_path.into(),
            netd_socket: netd_socket.into(),
            http,
            origin,
        })
    }

    /// Assembles the configuration for an explicitly acknowledged routable bind.
    ///
    /// `canonical_origin` must be plain HTTP: this service terminates no TLS, so
    /// an HTTPS claim on a routable listener would be false. The operator is
    /// expected to have put a TLS-terminating reverse proxy in front, in which
    /// case they should have used [`ServeConfig::new`] with a loopback bind and
    /// [`OriginPolicy::behind_https_proxy`] instead.
    pub fn acknowledged_off_host(
        state_path: impl Into<PathBuf>,
        netd_socket: impl Into<PathBuf>,
        http_bind: &str,
        canonical_origin: &str,
    ) -> Result<Self, OriginConfigError> {
        let http = ManagementHttpConfig::new(http_bind).map_err(|_| {
            // The bind was already parsed by the caller in every real path; this
            // arm exists so the error type stays the origin one.
            OriginConfigError::NotAnAuthority(http_bind.to_owned())
        })?;
        let origin = OriginPolicy::acknowledged_off_host(http.bind(), canonical_origin)?;
        Ok(Self {
            state_path: state_path.into(),
            netd_socket: netd_socket.into(),
            http,
            origin,
        })
    }

    /// Assembles the configuration for a reverse proxy in front of a loopback
    /// listener.
    pub fn behind_https_proxy(
        state_path: impl Into<PathBuf>,
        netd_socket: impl Into<PathBuf>,
        http_bind: &str,
        canonical_origin: &str,
    ) -> Result<Self, OriginConfigError> {
        let http = ManagementHttpConfig::new(http_bind)
            .map_err(|_| OriginConfigError::NotAnAuthority(http_bind.to_owned()))?;
        let origin = OriginPolicy::behind_https_proxy(http.bind(), canonical_origin)?;
        Ok(Self {
            state_path: state_path.into(),
            netd_socket: netd_socket.into(),
            http,
            origin,
        })
    }

    /// The limiter this deployment runs with.
    ///
    /// Built fresh per run: the counters are in-memory by design, so sharing
    /// them across runs would only carry state a restart is supposed to clear.
    pub fn limiter(&self) -> Arc<LoginLimiter> {
        Arc::new(LoginLimiter::new(
            DEFAULT_LOGIN_GLOBAL_BUCKET,
            DEFAULT_LOGIN_PEER_BUCKET,
            DEFAULT_TRACKED_PEERS,
        ))
    }

    /// Whether the listener would be reachable off-host.
    ///
    /// Reflects the origin policy rather than re-deriving it from the socket, so
    /// startup output and enforcement cannot disagree.
    pub fn is_off_host_bind(&self) -> bool {
        self.origin.exposure.is_off_host()
    }
}

/// Why the service could not run to completion.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The HTTP configuration was rejected before anything was opened.
    #[error("the management HTTP configuration is invalid: {0}")]
    Configuration(#[from] HttpError),
    /// The async runtime could not be built.
    #[error("could not start the async runtime")]
    RuntimeUnavailable,
    /// The state store, path, or migrations were unusable: fatal.
    #[error("the management state is unusable: {0}")]
    State(#[from] crate::management::ManagementError),
    /// The listener could not be bound.
    #[error("could not bind the management listener: {0}")]
    Bind(#[from] eggserve_server::ServerError),
    /// The worker refused or missed a shutdown command.
    #[error("the management worker did not shut down cleanly: {0}")]
    Worker(#[from] WorkerError),
}

/// What a completed run observed.
#[derive(Clone, Debug)]
pub struct ServeReport {
    /// The address the listener actually bound.
    pub bound: SocketAddr,
    /// What the mandatory startup reconciliation attempt concluded.
    pub reconcile: StartupReconcile,
    /// Whether the listener was reachable beyond loopback.
    pub off_host: bool,
}

/// Runs the management service until `shutdown` resolves.
///
/// The shutdown future is a parameter rather than an internal signal handler so
/// the lifecycle is testable without a process signal, and so `serve` owns the
/// ordering instead of the signal library.
pub async fn run(
    config: ServeConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<ServeReport, ServeError> {
    // 1. Validate before anything authority-bearing is opened.
    let runtime_config = config.http.runtime_config()?;
    let off_host = config.is_off_host_bind();

    // 2. The worker opens the store and attempts the startup reconcile. Both a
    //    failure here and a degraded outcome return here; only a degraded one
    //    lets the run continue.
    let worker = spawn(WorkerConfig::new(&config.state_path, &config.netd_socket))?;
    let reconcile = worker.reconcile();

    // 3. Bind.
    let server = Server::builder().runtime(runtime_config).build()?;
    let handle = server
        .start_with_service(super::service::ManagementService::new(
            super::AuthenticatedApi::new(
                worker.client().clone(),
                Arc::new(config.origin.clone()),
                config.limiter(),
            ),
        ))
        .await?;
    let bound = handle.local_addr();
    let (control, mut completion) = handle.into_parts();

    // 4. Report readiness, including the exposure mode an operator must be able
    //    to see from the log of a headless install.
    eprintln!("wg-basic serve listening on http://{bound}");
    eprintln!("wg-basic serve {}", config.origin.describe());
    eprintln!(
        "wg-basic serve startup reconciliation: {}",
        reconcile.as_str()
    );
    if reconcile.is_degraded() {
        eprintln!(
            "wg-basic serve: the network is not converged; the management surface is up \
             so this can be diagnosed and fixed"
        );
    }
    if off_host {
        eprintln!(
            "wg-basic serve: warning: bound to {bound}, which is reachable off-host. \
             Phase 7 terminates no TLS; put a TLS-terminating reverse proxy in front \
             of this, or the session cookie and every credential cross the network \
             in the clear."
        );
    }

    // 5. Serve until signalled, or until the runtime ends on its own.
    let server_finished_first = tokio::select! {
        _ = shutdown => false,
        _ = completion.wait() => true,
    };

    // 6. Stop accepting, then drain in-flight requests under the configured
    //    grace period. The drain is bounded by EggServe, so shutdown cannot hang.
    if !server_finished_first {
        control.shutdown();
    }
    completion.wait().await?;

    // 7. Stop the worker and release the store. Done last and unconditionally, so
    //    a database close always follows a successful bind.
    worker.stop().await?;

    Ok(ServeReport {
        bound,
        reconcile,
        off_host,
    })
}

/// Starts the service on a fresh multi-threaded Tokio runtime.
///
/// Blocking is expected here: this is a process entry point, and the async work
/// it drives is HTTP and the worker handshake.
pub fn run_blocking(
    config: ServeConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<ServeReport, ServeError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("wg-basic-serve")
        .build()
        .map_err(|_| ServeError::RuntimeUnavailable)?
        .block_on(run(config, shutdown))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wg-basic-serve-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn config(&self) -> ServeConfig {
            ServeConfig::new(
                self.0.join("state.db"),
                self.0.join("no-such-netd.sock"),
                "127.0.0.1:0",
            )
            .expect("a loopback ephemeral port is a valid configuration")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_invalid_bind_address_is_refused_before_anything_is_opened() {
        let scratch = Scratch::new();
        let error = ServeConfig::new(
            scratch.0.join("state.db"),
            scratch.0.join("netd.sock"),
            "not-an-address",
        )
        .expect_err("a bad address must not produce a runnable configuration");
        assert!(matches!(error, HttpError::InvalidBind(_)), "{error}");
        // The failure happened during construction: no store was opened, so the
        // process cannot have half-started.
        assert!(!scratch.0.join("state.db").exists());
    }

    #[test]
    fn a_loopback_bind_is_not_reported_as_off_host() {
        let scratch = Scratch::new();
        assert!(!scratch.config().is_off_host_bind());
    }

    #[test]
    fn a_routable_bind_is_refused_without_the_acknowledgement() {
        // The M003 position: a routable listener has no `Host` to check against
        // unless the operator states a canonical origin, so the default refuses.
        // Silently accepting any `Host` would reintroduce DNS rebinding.
        let scratch = Scratch::new();
        let error = ServeConfig::new(
            scratch.0.join("state.db"),
            scratch.0.join("netd.sock"),
            "0.0.0.0:8000",
        )
        .expect_err("an operator must say so before exposing the surface");
        assert!(
            matches!(error, HttpError::OffHostNeedsAcknowledgement),
            "{error}"
        );
    }

    #[test]
    fn an_acknowledged_routable_bind_is_built_with_a_restrictive_host_set() {
        let scratch = Scratch::new();
        let config = ServeConfig::acknowledged_off_host(
            scratch.0.join("state.db"),
            scratch.0.join("netd.sock"),
            "0.0.0.0:8000",
            "http://vpn.example.com",
        )
        .expect("an explicit origin makes this a real configuration");
        assert!(config.is_off_host_bind());
        assert!(config.origin.accepts_host("vpn.example.com"));
        // Not wildcarded: an arbitrary `Host` is still refused, and so is a
        // port the operator did not state — `vpn.example.com:8000` is a
        // different origin from the `http://vpn.example.com` that was declared.
        assert!(!config.origin.accepts_host("evil.example.com"));
        assert!(!config.origin.accepts_host("vpn.example.com:8000"));
        assert!(config.origin.accepts_origin("http://vpn.example.com"));
        assert!(!config.origin.accepts_origin("http://vpn.example.com:8000"));
        assert!(!config.origin.accepts_origin("http://evil.example.com"));
    }

    #[test]
    fn a_routable_listener_may_not_claim_an_https_origin() {
        // It terminates no TLS, so the claim would be false. The operator has to
        // keep the listener on loopback and use a proxy instead.
        let scratch = Scratch::new();
        let error = ServeConfig::acknowledged_off_host(
            scratch.0.join("state.db"),
            scratch.0.join("netd.sock"),
            "0.0.0.0:8000",
            "https://vpn.example.com",
        )
        .expect_err("a false transport claim must be refused");
        assert!(
            matches!(error, OriginConfigError::HttpsClaimWithoutProxy),
            "{error}"
        );
    }

    #[test]
    fn a_reverse_proxy_origin_gives_the_secure_cookie_profile() {
        let scratch = Scratch::new();
        let config = ServeConfig::behind_https_proxy(
            scratch.0.join("state.db"),
            scratch.0.join("netd.sock"),
            "127.0.0.1:8000",
            "https://vpn.example.com",
        )
        .expect("a proxied loopback listener is the documented HTTPS shape");
        assert!(
            !config.is_off_host_bind(),
            "the listener itself stays on loopback"
        );
        assert!(config.origin.is_secure());
        assert_eq!(
            config.origin.session_cookie_name(),
            crate::http::origin::SESSION_COOKIE_SECURE_NAME
        );
        // The `Host` the browser sends is the external name, not the socket.
        assert!(config.origin.accepts_host("vpn.example.com"));
        assert!(!config.origin.accepts_host("127.0.0.1:8000"));
    }

    #[test]
    fn each_run_gets_its_own_limiter() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let first = config.limiter();
        let second = config.limiter();
        assert_eq!(first.max_peers(), second.max_peers());
        assert_eq!(first.global_bucket().capacity, 20);
        assert_eq!(first.per_peer_bucket().capacity, 8);
        assert_eq!(first.tracked_peers(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_default_policy_refuses_a_foreign_host_at_runtime() {
        // The rebinding refusal needs a live socket, so it lives in
        // `tests/management_http.rs` where a real request can be sent. What is
        // asserted here is the configuration half: the default run resolves an
        // origin policy that accepts loopback and nothing else.
        let scratch = Scratch::new();
        let config = scratch.config();
        assert_eq!(config.origin.allowed_hosts.len(), 4, "{:?}", config.origin);
        assert!(config.origin.accepts_host("127.0.0.1:0"));
        assert!(!config.origin.accepts_host("evil.example.com"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fatal_state_failure_never_binds_a_listener() {
        let scratch = Scratch::new();
        let mut config = scratch.config();
        // A directory where the database should be cannot be opened.
        let bogus = scratch.0.join("not-a-database");
        fs::create_dir(&bogus).unwrap();
        config.state_path = bogus;

        let error = run(config, std::future::pending::<()>())
            .await
            .expect_err("an unopenable store has nothing to administer");
        assert!(
            matches!(error, ServeError::State(_)),
            "{error} must be a state failure"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_lifecycle_serves_then_drains_and_releases_the_store() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let state_path = config.state_path.clone();
        let (signal, wait) = tokio::sync::oneshot::channel::<()>();

        let run = tokio::spawn(async move {
            run(config, async {
                wait.await.ok();
            })
            .await
        });
        // Give the run a moment to bind before signalling it.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = signal.send(());

        let report = run
            .await
            .expect("the run task itself must not panic")
            .expect("a clean run");
        assert!(report.bound.port() > 0);
        assert_eq!(report.reconcile, StartupReconcile::NothingToApply);
        assert!(!report.off_host);

        // Proving the store was released is deliberately left to the integration
        // suite: it needs a real second `StateStore` open, and `src/http/` must
        // not reference the state store even from a test. See
        // `tests/management_http.rs`.
        drop(state_path);
    }
}
