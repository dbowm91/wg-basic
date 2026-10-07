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
use crate::management::{spawn, StartupReconcile, WorkerConfig, WorkerError};
use eggserve_server::Server;
use std::{future::Future, net::SocketAddr, path::PathBuf};

/// Everything `wg-basic serve` was asked to do.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Path to the authoritative state database.
    pub state_path: PathBuf,
    /// Path to the authorized local netd socket.
    pub netd_socket: PathBuf,
    /// The management listener and its limits.
    pub http: ManagementHttpConfig,
}

impl ServeConfig {
    /// Assembles a configuration from operator-supplied paths.
    pub fn new(
        state_path: impl Into<PathBuf>,
        netd_socket: impl Into<PathBuf>,
        http_bind: &str,
    ) -> Result<Self, HttpError> {
        Ok(Self {
            state_path: state_path.into(),
            netd_socket: netd_socket.into(),
            http: ManagementHttpConfig::new(http_bind)?,
        })
    }

    /// Whether the listener would be reachable off-host.
    ///
    /// Reported, never prevented: refusing to start would make an operator who
    /// genuinely needs a proxied listener unable to proceed, and silently
    /// allowing it would be worse. The warning names the risk.
    pub fn is_off_host_bind(&self) -> bool {
        !self.http.bind().ip().is_loopback()
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
            worker.client().clone(),
        ))
        .await?;
    let bound = handle.local_addr();
    let (control, mut completion) = handle.into_parts();

    // 4. Report readiness.
    eprintln!("wg-basic serve listening on http://{bound}");
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
             Phase 7 serves no TLS and no authentication on unauthenticated routes; \
             put a TLS-terminating reverse proxy in front of this."
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
    fn a_non_loopback_bind_is_reported_but_not_refused() {
        let scratch = Scratch::new();
        let config = ServeConfig::new(
            scratch.0.join("state.db"),
            scratch.0.join("netd.sock"),
            "0.0.0.0:8000",
        )
        .expect("an operator may deliberately expose the listener");
        // Refusing would block a legitimately proxied deployment; staying silent
        // would hide that Phase 7 serves no TLS.
        assert!(config.is_off_host_bind());
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
