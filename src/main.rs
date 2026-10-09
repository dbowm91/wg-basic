use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const DEFAULT_SOCKET: &str = "/run/wg-basic/netd.sock";

/// The Phase 7 local administrator's login name.
const DEFAULT_ADMIN_USERNAME: &str = "admin";

#[derive(Parser)]
#[command(
    name = "wg-basic",
    version = wg_basic::release::PACKAGE_VERSION,
    about = "Linux-native WireGuard appliance"
)]
struct Cli {
    /// Format for long-running operational events written to stderr.
    #[arg(long, global = true, value_enum, default_value_t = CliLogFormat::Human)]
    log_format: CliLogFormat,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliLogFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Unprivileged management role: serves the loopback management HTTP surface
    /// and owns the bounded worker that holds the durable state.
    ///
    /// This role never escalates privileges and never spawns or elevates netd.
    /// It reaches the network only through the authorized socket, from the
    /// worker thread, on behalf of a request.
    Serve {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        /// Management listener address. Loopback only by default.
        #[arg(long, default_value = wg_basic::http::config::DEFAULT_BIND)]
        http_bind: String,
        /// The canonical external origin, as `scheme://host[:port]`.
        ///
        /// Required whenever the listener is not loopback, and optional otherwise.
        /// An `https` origin means a TLS-terminating reverse proxy sits in front
        /// of this listener: Phase 7 terminates no TLS of its own. The value
        /// decides the allowed `Host` set, the exact `Origin` an unsafe request
        /// must carry, and whether the session cookie is `Secure`.
        #[arg(long)]
        canonical_origin: Option<String>,
        /// Acknowledge that `--http-bind` is a routable address.
        ///
        /// Binding off-host serves the management surface to the network. Phase 7
        /// serves no TLS, so this is only acceptable behind a proxy the operator
        /// has configured — which is why it takes an explicit acknowledgement
        /// rather than being merely permitted.
        #[arg(long)]
        allow_non_loopback: bool,
    },
    /// Privileged local network service; exposes typed WireGuard, network, and firewall operations.
    Netd {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        /// Additional management-service UID permitted by SO_PEERCRED.
        #[arg(long = "allow-uid")]
        allowed_uids: Vec<u32>,
        /// Additional local account permitted by SO_PEERCRED.
        #[arg(long = "allow-user")]
        allowed_users: Vec<String>,
    },
    /// Read-only service capability check.
    Doctor {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        json: bool,
        /// Allow advisory diagnostics while still rejecting required failures.
        #[arg(long)]
        allow_warnings: bool,
        #[arg(long)]
        http_bind: Option<String>,
        #[arg(long)]
        canonical_origin: Option<String>,
        #[arg(long)]
        allow_non_loopback: bool,
    },
    /// Unprivileged management runtime: opens the durable store and reconciles
    /// the current desired generation against the local network service.
    ///
    /// This role never escalates privileges and never mutates the kernel
    /// directly; it reaches the network only through the authorized socket.
    Reconcile {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Local administrator credentials.
    ///
    /// Neither action accepts a password as an argument or from the
    /// environment. A credential in `argv` is visible to every process on the
    /// host through `/proc`, and one in the environment is inherited by every
    /// child; the only acceptable input is this process's own standard input.
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Prints the durable management health projection and exits.
    Health {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Durable state inspection, backup, and restore.
    ///
    /// Every one of these operates on the secret-bearing database directly. None
    /// of them contacts the kernel: after a restore, ordinary `reconcile` does
    /// that, under the ordinary owner-tag rules.
    State {
        #[command(subcommand)]
        action: StateCommand,
    },
    /// Inspect or change the whole server's network availability.
    Network {
        #[command(subcommand)]
        action: NetworkCommand,
    },
    /// Install the current local executable or inspect its system registration.
    System {
        #[command(subcommand)]
        action: SystemCommand,
    },
    /// Fail-closed authenticated update commands; mutation requires effective root.
    Update {
        #[command(subcommand)]
        action: UpdateCommand,
    },
}

#[derive(Subcommand)]
enum UpdateCommand {
    /// Read-only check for a newer authenticated stable release.
    Check,
    /// Install the selected newer authenticated stable release.
    Run,
    /// Recover an interrupted update transaction.
    Recover,
}

#[derive(Subcommand)]
enum SystemCommand {
    /// Install this local executable into the canonical system layout.
    Install {
        /// Optional staging executable; defaults to this running executable.
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
    /// Read-only installation ownership and service status.
    Status,
    /// Remove owned system files and units while preserving VPN state.
    Uninstall,
}

#[derive(Subcommand)]
enum AdminAction {
    /// Creates the local administrator, or resets an existing password.
    ///
    /// A reset revokes every existing session in the same transaction: a
    /// password changed in order to lock someone out must not leave their cookie
    /// working.
    SetPassword {
        /// The administrator's login name.
        #[arg(long, default_value = DEFAULT_ADMIN_USERNAME)]
        username: String,
        /// Read the password from standard input.
        ///
        /// Required, and explicit. Without the flag this command does nothing,
        /// so a password can never arrive by accident through a pipe that some
        /// other tool happened to provide.
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Prints the safe administrator projection: identity, enabled state, and
    /// live session count. Never a verifier, token, or password.
    Status {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
}

#[derive(Subcommand)]
enum StateCommand {
    /// Create an empty schema or validate and migrate an existing owned state database.
    Init {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Prints a safe status projection: identifiers, generations, and integrity.
    ///
    /// Never prints private keys, preshared keys, or any row contents.
    Status {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Emit the updater's secret-free typed compatibility identity as JSON.
    Identity {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Writes a consistent snapshot of the database to <destination>.
    ///
    /// The destination must not already exist. The snapshot contains VPN
    /// credentials and is created owner-only.
    Backup {
        destination: PathBuf,
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Validates <candidate> and installs it as the live database.
    ///
    /// The candidate is fully checked before anything is replaced, and the
    /// previous database is retained as `<state>.pre-restore`. Stop the
    /// management service first: a cross-process lease refuses an active serve
    /// and this process's open-handle check remains as defense in depth.
    Restore {
        candidate: PathBuf,
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    /// Verify a candidate without migrating or modifying it.
    Verify { candidate: PathBuf },
    /// Purge only verified wg-basic state after proving owned networking is gone.
    Purge {
        #[arg(long)]
        confirm_installation_id: wg_basic::domain::InstallationId,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Subcommand)]
enum NetworkCommand {
    Status {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
    Disable {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    Enable {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    wg_basic::operational::set_format(match cli.log_format {
        CliLogFormat::Human => wg_basic::operational::LogFormat::Human,
        CliLogFormat::Json => wg_basic::operational::LogFormat::Json,
    });
    #[cfg(target_os = "linux")]
    let result = run_linux(cli.command);
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), String> = {
        let _ = cli.command;
        Err("network service roles require Linux".into())
    };
    if let Err(message) = result {
        wg_basic::operational::command_failure(&message);
        std::process::exit(2);
    }
}

#[cfg(target_os = "linux")]
fn run_linux(command: Option<Command>) -> Result<(), String> {
    use std::sync::{atomic::AtomicBool, Arc};
    use wg_basic::protocol::{
        request, AuthorizationPolicy, RequestOperation, ResponseBody, SocketServer,
    };

    match command {
        None => {
            println!(
                "wg-basic {}: use --help for runtime roles",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some(Command::Serve {
            state,
            socket,
            http_bind,
            canonical_origin,
            allow_non_loopback,
        }) => serve(
            state,
            socket,
            http_bind,
            canonical_origin,
            allow_non_loopback,
        ),
        Some(Command::Reconcile { state, socket }) => {
            let runtime = wg_basic::management::ManagementRuntime::open(&state, &socket)
                .map_err(|error| error.to_string())?;
            match runtime
                .reconcile_current()
                .map_err(|error| error.to_string())?
            {
                // An installation with no managed interface is a normal empty
                // state, not a failure.
                None => println!("no managed interface; nothing to reconcile"),
                Some(outcome) => println!(
                    "generation {} -> {} ({:?})",
                    outcome.applied_generation,
                    if outcome.converged {
                        "converged"
                    } else {
                        "not converged"
                    },
                    outcome.disposition
                ),
            }
            Ok(())
        }
        Some(Command::System { action }) => match action {
            SystemCommand::Install { candidate } => {
                let candidate = match candidate {
                    Some(path) => path,
                    None => wg_basic::distribution::current_executable()
                        .map_err(|_| "could not identify the running executable".to_owned())?,
                };
                wg_basic::distribution::install_local(&candidate)
            }
            SystemCommand::Status => wg_basic::distribution::install_status(),
            SystemCommand::Uninstall => wg_basic::distribution::uninstall_local(),
        },
        Some(Command::Update { action }) => {
            match action {
                UpdateCommand::Check => wg_basic::update::check(),
                UpdateCommand::Run => {
                    if nix::unistd::Uid::effective().is_root() {
                        wg_basic::update::apply()
                    } else {
                        Err(
                            "system update requires effective root; no automatic sudo is performed"
                                .into(),
                        )
                    }
                }
                UpdateCommand::Recover => {
                    if nix::unistd::Uid::effective().is_root() {
                        wg_basic::update::recover()
                    } else {
                        Err("update recovery requires effective root; no automatic sudo is performed".into())
                    }
                }
            }
        }
        Some(Command::Health { state, socket }) => {
            let runtime = wg_basic::management::ManagementRuntime::open(&state, &socket)
                .map_err(|error| error.to_string())?;
            // The health projection carries categories only, never receipts.
            println!(
                "{}",
                serde_json::to_string_pretty(&runtime.health())
                    .map_err(|_| "could not format management health".to_owned())?
            );
            Ok(())
        }
        Some(Command::Doctor {
            state,
            socket,
            json,
            allow_warnings,
            http_bind,
            canonical_origin,
            allow_non_loopback,
        }) => {
            #[cfg(all(target_os = "linux", feature = "update-test-fixtures"))]
            delay_fixture_candidate_doctor_start(&state)?;
            let (mut checks, state_snapshot) = doctor_state_checks(&state);
            match request(&socket, RequestOperation::InspectCapabilities, 2) {
                Ok(ResponseBody::Capabilities(snapshot)) => {
                    let netd_ready =
                        snapshot.runtime_directory_safe && snapshot.cap_net_admin == Some(true);
                    checks.push(wg_basic::doctor::DoctorCheck::new(
                        wg_basic::doctor::DoctorCheckId::Netd,
                        if netd_ready {
                            wg_basic::doctor::DoctorDisposition::Pass
                        } else {
                            wg_basic::doctor::DoctorDisposition::Fail
                        },
                        if netd_ready {
                            "netd answered and its runtime/capability checks passed"
                        } else {
                            "netd runtime directory or CAP_NET_ADMIN check failed"
                        },
                        format!(
                            "uid {}; gid {}; CAP_NET_ADMIN {}; runtime directory {}; kernel {} ({})",
                            snapshot.effective_uid,
                            snapshot.effective_gid,
                            snapshot.cap_net_admin.map_or("unknown", |value| if value { "present" } else { "absent" }),
                            if snapshot.runtime_directory_safe { "safe" } else { "unsafe" },
                            snapshot.kernel_release.as_deref().unwrap_or("unknown"),
                            snapshot.architecture,
                        ),
                        if netd_ready { "none" } else { "review netd privilege and runtime-directory ownership/mode" },
                    ));
                }
                _ => checks.push(wg_basic::doctor::DoctorCheck::new(
                    wg_basic::doctor::DoctorCheckId::Netd,
                    wg_basic::doctor::DoctorDisposition::Unknown,
                    "netd capability state is unavailable",
                    "no safe capability response was received",
                    "start netd and verify its socket path and peer permissions",
                )),
            }
            if let Some(snapshot) = state_snapshot.as_ref() {
                append_network_plan_checks(&mut checks, &socket, snapshot);
                append_forwarding_check(&mut checks, snapshot);
            } else {
                checks.push(wg_basic::doctor::DoctorCheck::new(
                    wg_basic::doctor::DoctorCheckId::NetworkOwnership,
                    wg_basic::doctor::DoctorDisposition::Unknown,
                    "managed network ownership has not been inspected",
                    "a validated state snapshot is unavailable",
                    "resolve the state diagnostic first, then rerun doctor",
                ));
                checks.push(wg_basic::doctor::DoctorCheck::new(
                    wg_basic::doctor::DoctorCheckId::Forwarding,
                    wg_basic::doctor::DoctorDisposition::Unknown,
                    "forwarding requirement is unknown",
                    "the state snapshot is unavailable",
                    "resolve the state diagnostic first, then rerun doctor",
                ));
            }
            let lease = wg_basic::state::ServiceLease::is_held(&state);
            checks.push(wg_basic::doctor::DoctorCheck::new(
                wg_basic::doctor::DoctorCheckId::ServiceLease,
                match lease {
                    Ok(true) => wg_basic::doctor::DoctorDisposition::Warn,
                    Ok(false) => wg_basic::doctor::DoctorDisposition::Pass,
                    Err(_) => wg_basic::doctor::DoctorDisposition::Unknown,
                },
                match lease {
                    Ok(true) => "a serve process currently holds the state lease",
                    Ok(false) => "the state service lease is free",
                    Err(_) => "the state service lease could not be inspected safely",
                },
                "advisory lock state was checked without trusting PID metadata",
                "stop the active serve process before offline maintenance",
            ));
            if let Some(bind) = http_bind {
                use wg_basic::http::ServeConfig;
                let valid = match (canonical_origin.as_deref(), allow_non_loopback) {
                    (Some(origin), false) if origin.starts_with("https://") => {
                        ServeConfig::behind_https_proxy(
                            state.clone(),
                            socket.clone(),
                            &bind,
                            origin,
                        )
                        .is_ok()
                    }
                    (Some(origin), true) => ServeConfig::acknowledged_off_host(
                        state.clone(),
                        socket.clone(),
                        &bind,
                        origin,
                    )
                    .is_ok(),
                    (None, false) => ServeConfig::new(state.clone(), socket.clone(), &bind).is_ok(),
                    _ => false,
                };
                checks.push(match valid {
                    true => wg_basic::doctor::DoctorCheck::new(
                        wg_basic::doctor::DoctorCheckId::HttpPolicy,
                        wg_basic::doctor::DoctorDisposition::Pass,
                        "HTTP bind and origin policy are valid",
                        "same ServeConfig policy as serve",
                        "none",
                    ),
                    false => wg_basic::doctor::DoctorCheck::new(
                        wg_basic::doctor::DoctorCheckId::HttpPolicy,
                        wg_basic::doctor::DoctorDisposition::Fail,
                        "HTTP bind and origin policy are invalid",
                        "ServeConfig rejected the supplied policy",
                        "correct the bind/origin and exposure acknowledgement",
                    ),
                });
            }
            let report = wg_basic::doctor::DoctorReport::new(checks);
            wg_basic::operational::emit(
                "doctor.completed",
                wg_basic::operational::Severity::Info,
                "doctor",
                "diagnose",
                "report_ready",
                None,
                state_snapshot
                    .as_ref()
                    .map(|s| s.metadata.desired_generation.to_storage() as u64),
                Some("checks"),
            );
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|_| "could not format diagnostic report")?
                );
            } else {
                print!("{}", report.render_human());
            }
            let exit_code =
                if allow_warnings && report.overall == wg_basic::doctor::DoctorDisposition::Warn {
                    0
                } else {
                    report.exit_code()
                };
            std::process::exit(exit_code);
        }
        Some(Command::Netd {
            socket,
            allowed_uids,
            allowed_users,
        }) => {
            #[cfg(all(target_os = "linux", feature = "update-test-fixtures"))]
            fail_fixture_netd_start()?;
            let mut policy = AuthorizationPolicy::current_user_and_root();
            policy.extend(allowed_uids);
            let resolved = wg_basic::distribution::resolve_allowed_user_uids(&allowed_users)
                .map_err(|_| "could not resolve a configured local netd user".to_owned())?;
            policy.extend(resolved);
            let server = SocketServer::bind(&socket, policy)
                .map_err(|_| "could not safely bind the configured netd socket path".to_owned())?;
            let shutdown = Arc::new(AtomicBool::new(false));
            let signal_shutdown = shutdown.clone();
            ctrlc::set_handler(move || {
                signal_shutdown.store(true, std::sync::atomic::Ordering::Release)
            })
            .map_err(|_| "could not install graceful shutdown handler".to_owned())?;
            wg_basic::operational::emit(
                "netd.started",
                wg_basic::operational::Severity::Info,
                "netd",
                "startup",
                "ready",
                None,
                None,
                Some("uds_listener"),
            );
            let result = server
                .run_until_shutdown(&shutdown)
                .map_err(|_| "netd listener stopped after a runtime error".to_owned());
            wg_basic::operational::emit(
                "netd.stopping",
                wg_basic::operational::Severity::Info,
                "netd",
                "shutdown",
                if result.is_ok() {
                    "graceful"
                } else {
                    "runtime_error"
                },
                None,
                None,
                Some("uds_listener"),
            );
            result
        }
        Some(Command::Admin { action }) => run_admin_action(action),
        Some(Command::State { action }) => run_state_action(action),
        Some(Command::Network { action }) => run_network_action(action),
    }
}

/// Runs the local administrator credential surface.
///
/// This path does not go through the worker: it is a one-shot operator command
/// that opens the store directly, before any service is running. It still obeys
/// the two rules that matter -- the password arrives only on stdin, and nothing
/// here ever prints a verifier or a token.
#[cfg(target_os = "linux")]
fn run_admin_action(action: AdminAction) -> Result<(), String> {
    use wg_basic::management;

    match action {
        AdminAction::SetPassword {
            username,
            password_stdin,
            state,
        } => {
            if !password_stdin {
                return Err(
                    "--password-stdin is required: a password is never read from an argument \
                     or from the environment"
                        .to_owned(),
                );
            }
            let password = read_password_from_stdin()?;
            let status = management::set_password_at(&state, &username, &password)
                .map_err(|error| error.to_string())?;
            println!(
                "administrator `{}` enabled; {} live session(s) remain",
                status.username, status.live_sessions
            );
            Ok(())
        }
        AdminAction::Status { state } => {
            match management::status_at(&state).map_err(|error| error.to_string())? {
                Some(status) => println!(
                    "administrator `{}` ({}) {}; {} live session(s)",
                    status.username,
                    status.principal_id,
                    if status.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    status.live_sessions
                ),
                None => println!("no local administrator has been provisioned"),
            }
            Ok(())
        }
    }
}

/// Performs only read-only checks. In particular this deliberately avoids
/// `StateStore::open`, whose normal contract is to apply pending migrations.
#[cfg(target_os = "linux")]
fn doctor_state_checks(
    path: &std::path::Path,
) -> (
    Vec<wg_basic::doctor::DoctorCheck>,
    Option<wg_basic::state::StateDiagnostic>,
) {
    use wg_basic::doctor::{DoctorCheck, DoctorCheckId as Id, DoctorDisposition as D};

    let mut checks = Vec::new();
    let version = rusqlite::Connection::open_in_memory().and_then(|connection| {
        connection.query_row("SELECT sqlite_version(), sqlite_source_id()", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
    });
    let (version_text, source_id) =
        version.unwrap_or_else(|_| ("unknown".into(), "unavailable".into()));
    let sqlite_ok = wg_basic::doctor::sqlite_version_at_least(&version_text, (3, 51, 3));
    checks.push(DoctorCheck::new(
        Id::Sqlite,
        if sqlite_ok { D::Pass } else { D::Fail },
        if sqlite_ok {
            "bundled SQLite runtime meets the WAL safety floor"
        } else {
            "SQLite runtime is below the supported WAL safety floor"
        },
        format!("SQLite {version_text}; source {source_id}"),
        if sqlite_ok {
            "none"
        } else {
            "use the bundled SQLite runtime at version 3.51.3 or newer"
        },
    ));

    let inspection = wg_basic::state::inspect_readonly(path);
    let snapshot = inspection.as_ref().ok();
    let missing = std::fs::symlink_metadata(path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    let busy = matches!(&inspection, Err(wg_basic::state::StateError::Busy));
    checks.push(match snapshot {
        Some(_) => DoctorCheck::new(
            Id::State,
            D::Pass,
            "state file passed immutable ownership, integrity, and schema checks",
            "quick_check, foreign-key check, and typed snapshot validation passed",
            "none",
        ),
        None if missing => DoctorCheck::new(
            Id::State,
            D::Warn,
            "state database is not initialized",
            "configured path does not exist",
            "initialize the state database with the documented setup flow",
        ),
        None if busy => DoctorCheck::new(
            Id::State,
            D::Unknown,
            "state has live WAL sidecars and cannot be inspected immutably",
            "immutable inspection refuses to ignore WAL contents",
            "stop the management service and rerun doctor",
        ),
        None => DoctorCheck::new(
            Id::State,
            D::Fail,
            "state database failed a read-only safety or validation check",
            "path ownership, schema, integrity, or typed state validation failed",
            "correct state ownership or restore a verified backup",
        ),
    });
    if let Some(snapshot) = snapshot.as_ref() {
        checks.push(DoctorCheck::new(
            Id::State,
            D::Pass,
            "authoritative state decoded and validated read-only",
            format!(
                "schema {}; installation {}; desired generation {}",
                snapshot.schema_version,
                snapshot.metadata.installation_id,
                snapshot.metadata.desired_generation
            ),
            "none",
        ));
        checks.push(DoctorCheck::new(
            Id::Product,
            D::Pass,
            "desired and product snapshots decoded and validated",
            format!(
                "{} managed interface(s); {} client(s)",
                snapshot.desired.state.interfaces.len(),
                snapshot.product.clients.len()
            ),
            "none",
        ));
        let no_managed_interfaces = snapshot.desired.state.interfaces.is_empty();
        let converged = no_managed_interfaces
            || snapshot.convergence.last_converged_generation
                == Some(snapshot.metadata.desired_generation);
        checks.push(DoctorCheck::new(
            Id::Convergence,
            if converged { D::Pass } else { D::Warn },
            if no_managed_interfaces {
                "no managed interface is configured; network convergence is not required"
            } else if converged {
                "current desired generation has convergence evidence"
            } else {
                "current desired generation lacks convergence evidence"
            },
            format!(
                "desired {}; attempted {:?}; converged {:?}; outcome {}",
                snapshot.metadata.desired_generation,
                snapshot.convergence.last_attempted_generation,
                snapshot.convergence.last_converged_generation,
                snapshot
                    .convergence
                    .last_outcome
                    .as_deref()
                    .unwrap_or("none")
            ),
            if converged {
                "none"
            } else {
                "start netd and management service, then inspect the reconcile result"
            },
        ));
        let unsafe_artifact = snapshot
            .recovery_artifacts
            .iter()
            .any(|artifact| artifact.present && !artifact.safe);
        let artifacts = snapshot
            .recovery_artifacts
            .iter()
            .filter(|artifact| artifact.present)
            .map(|artifact| format!("v{}", artifact.source_schema))
            .collect::<Vec<_>>()
            .join(", ");
        checks.push(DoctorCheck::new(
            Id::RecoveryArtifacts,
            if unsafe_artifact { D::Fail } else { D::Pass },
            if unsafe_artifact { "a recovery artifact has unsafe path, owner, or mode" } else { "automatic recovery artifacts are safe" },
            if artifacts.is_empty() { "no pre-migration snapshots found".to_owned() } else { format!("pre-migration snapshots: {artifacts}") },
            if unsafe_artifact { "inspect the specific pre-migration snapshot and restore safe ownership/mode without deleting it" } else { "none" },
        ));
    }
    (checks, inspection.ok())
}

#[cfg(target_os = "linux")]
fn append_network_plan_checks(
    checks: &mut Vec<wg_basic::doctor::DoctorCheck>,
    socket: &std::path::Path,
    snapshot: &wg_basic::state::StateDiagnostic,
) {
    use wg_basic::doctor::{DoctorCheck, DoctorCheckId as Id, DoctorDisposition as D};
    use wg_basic::protocol::{RequestOperation, ResponseBody};

    let intent = match wg_basic::management::project_diagnostic_intent(
        snapshot.metadata.installation_id,
        snapshot.desired.generation,
        &snapshot.desired.state,
        &snapshot.product,
    ) {
        Ok(intent) => intent,
        Err(_) => {
            checks.push(DoctorCheck::new(
                Id::NetworkOwnership,
                D::Fail,
                "desired network intent could not be projected",
                "typed desired/product state failed projection validation",
                "correct the desired network configuration before applying it",
            ));
            return;
        }
    };
    let Some(intent) = intent else {
        for (id, name) in [
            (Id::NetworkOwnership, "network ownership"),
            (Id::Rtnetlink, "RTNETLINK"),
            (Id::WireGuard, "WireGuard"),
            (Id::Nftables, "nftables"),
        ] {
            checks.push(DoctorCheck::new(
                id,
                D::Pass,
                format!("{name} probe is not required for an empty installation"),
                "no managed network interface is configured",
                "none",
            ));
        }
        return;
    };

    let interface = intent.desired_interface.interface.clone();
    let intended_port = intent
        .desired_interface
        .wireguard
        .as_ref()
        .map(|wireguard| wireguard.listen_port);
    match wg_basic::protocol::request(
        socket,
        RequestOperation::PlanInstallationNetworkIntent { intent },
        3,
    ) {
        Ok(ResponseBody::InstallationNetworkPlanned(plan)) => {
            append_plan_outcome(checks, &plan);
            checks.push(DoctorCheck::new(
                Id::Rtnetlink,
                D::Pass,
                "bounded RTNETLINK observation completed through the aggregate plan",
                "plan-only request observed managed link/address/route state",
                "none",
            ));
            checks.push(DoctorCheck::new(
                Id::Nftables,
                D::Pass,
                "read-only nftables plan completed",
                "the aggregate planner completed its table observation without applying",
                "none",
            ));
        }
        Err(error) => {
            let protocol_error = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<wg_basic::protocol::ProtocolError>())
                .copied();
            let conflict = protocol_error == Some(wg_basic::protocol::ProtocolError::Conflict);
            let invalid = protocol_error == Some(wg_basic::protocol::ProtocolError::InvalidInput);
            checks.push(DoctorCheck::new(
                Id::NetworkOwnership,
                if conflict || invalid { D::Fail } else { D::Unknown },
                if conflict {
                    "network plan found an ownership conflict"
                } else if invalid {
                    "network plan rejected the desired state"
                } else {
                    "network plan could not complete"
                },
                match protocol_error {
                    Some(wg_basic::protocol::ProtocolError::Conflict) => "netd returned a typed ownership conflict",
                    Some(wg_basic::protocol::ProtocolError::InvalidInput) => "netd refused the typed desired intent",
                    Some(wg_basic::protocol::ProtocolError::UnsupportedBackend) => "a required backend is unsupported",
                    Some(wg_basic::protocol::ProtocolError::PermissionDenied | wg_basic::protocol::ProtocolError::Unauthorized) => "netd denied the diagnostic peer",
                    _ => "no classified plan result was received",
                },
                if conflict {
                    "inspect and resolve the foreign network resource manually; doctor did not mutate it"
                } else if invalid {
                    "correct the desired network state and rerun doctor"
                } else {
                    "check netd availability and permissions, then rerun doctor"
                },
            ));
            for id in [Id::Rtnetlink, Id::Nftables] {
                checks.push(DoctorCheck::new(
                    id,
                    D::Unknown,
                    "read-only backend probe did not complete",
                    "aggregate plan request returned no successful plan",
                    "resolve the network plan issue and rerun doctor",
                ));
            }
        }
        _ => checks.push(DoctorCheck::new(
            Id::NetworkOwnership,
            D::Unknown,
            "netd returned an unexpected plan response",
            "response did not match the requested aggregate plan operation",
            "check protocol compatibility and rerun doctor",
        )),
    }
    match wg_basic::protocol::request(
        socket,
        RequestOperation::ObserveWireGuardDevice { interface },
        4,
    ) {
        Ok(ResponseBody::WireGuardDevice(device)) => {
            checks.push(DoctorCheck::new(
                Id::WireGuard,
                D::Pass,
                "WireGuard Generic Netlink observation succeeded",
                format!(
                    "managed interface observed; listen port {:?}",
                    device.listen_port
                ),
                "none",
            ));
            append_listen_port_check(checks, intended_port, device.listen_port);
        }
        _ => {
            checks.push(DoctorCheck::new(
                Id::WireGuard,
                D::Unknown,
                "WireGuard device observation is unavailable",
                "the interface is absent or the Generic Netlink probe did not complete",
                "check netd and kernel WireGuard support; ownership planning remains read-only",
            ));
            append_listen_port_check(checks, intended_port, None);
        }
    }
}

#[cfg(target_os = "linux")]
fn append_plan_outcome(
    checks: &mut Vec<wg_basic::doctor::DoctorCheck>,
    plan: &wg_basic::protocol::InstallationNetworkPlanBody,
) {
    use wg_basic::doctor::{DoctorCheck, DoctorCheckId as Id, DoctorDisposition as D};
    let interface_actions = plan.interface_plan.actions.len();
    let firewall_actions = plan.firewall_plan.actions.len();
    let changed = interface_actions + firewall_actions > 0;
    checks.push(DoctorCheck::new(
        Id::NetworkOwnership,
        if changed { D::Warn } else { D::Pass },
        if changed {
            "owned network drift is repairable by normal reconciliation"
        } else {
            "managed network state is converged"
        },
        format!(
            "{} interface action(s); {} firewall action(s); no apply was requested",
            interface_actions, firewall_actions
        ),
        if changed {
            "run the normal management reconciliation after reviewing the planned changes"
        } else {
            "none"
        },
    ));
}

#[cfg(target_os = "linux")]
fn append_listen_port_check(
    checks: &mut Vec<wg_basic::doctor::DoctorCheck>,
    intended: Option<u16>,
    observed: Option<u16>,
) {
    use wg_basic::doctor::{DoctorCheck, DoctorCheckId as Id, DoctorDisposition as D};
    let (disposition, summary, evidence, remediation) = match (intended, observed) {
        (Some(wanted), Some(actual)) if wanted == actual => (
            D::Pass,
            "owned WireGuard interface uses the configured listen port",
            format!("configured and observed UDP port {wanted}"),
            "none",
        ),
        (Some(wanted), Some(actual)) => (
            D::Warn,
            "managed listen port differs from desired state",
            format!("configured UDP port {wanted}; observed {actual}"),
            "review the desired configuration and reconcile through wg-basic",
        ),
        (Some(wanted), None) => (
            D::Unknown,
            "listen-port availability is ambiguous",
            format!("configured UDP port {wanted}; no active managed interface was observed"),
            "check other host UDP/WireGuard users manually; doctor did not bind or mutate the port",
        ),
        _ => (
            D::Unknown,
            "no configured listen port was available to check",
            "desired state has no active WireGuard listen-port value".to_owned(),
            "review server configuration if this installation should expose WireGuard",
        ),
    };
    checks.push(DoctorCheck::new(
        Id::ListenPort,
        disposition,
        summary,
        evidence,
        remediation,
    ));
}

#[cfg(target_os = "linux")]
fn append_forwarding_check(
    checks: &mut Vec<wg_basic::doctor::DoctorCheck>,
    snapshot: &wg_basic::state::StateDiagnostic,
) {
    use wg_basic::doctor::{DoctorCheck, DoctorCheckId as Id, DoctorDisposition as D};
    let required = snapshot
        .desired
        .state
        .network_policy
        .as_ref()
        .is_some_and(|policy| policy.ipv4_forwarding_required);
    let value = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward");
    let (disposition, summary, evidence, remediation) = match (required, value) {
        (false, Ok(setting)) => (
            D::Pass,
            "IPv4 forwarding is not required by desired state",
            format!("read-only procfs value {}", setting.trim()),
            "none",
        ),
        (true, Ok(setting)) if setting.trim() == "1" => (
            D::Pass,
            "required IPv4 forwarding is enabled",
            "read-only procfs value 1".to_owned(),
            "none",
        ),
        (true, Ok(_)) => (
            D::Fail,
            "desired network policy requires IPv4 forwarding, but it is disabled",
            "read-only procfs value 0".to_owned(),
            "enable IPv4 forwarding through host configuration; doctor did not write the setting",
        ),
        (_, Err(_)) => (
            D::Unknown,
            "IPv4 forwarding state could not be read",
            "the expected procfs setting is unavailable".to_owned(),
            "run doctor on the Linux host that owns the WireGuard network",
        ),
    };
    checks.push(DoctorCheck::new(
        Id::Forwarding,
        disposition,
        summary,
        evidence,
        remediation,
    ));
}

/// Reads a password from standard input, trimming exactly one trailing newline.
///
/// Only the trailing newline a terminal or `echo` adds is removed; every other
/// byte is preserved, because a silently altered password is a credential the
/// operator did not choose and would have to debug by guessing. A password that
/// genuinely ends in a newline can still be supplied through a pipe that does not
/// append one.
#[cfg(target_os = "linux")]
fn read_password_from_stdin() -> Result<String, String> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    std::io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read the password from standard input".to_owned())?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map_err(|_| "the password on standard input is not valid UTF-8".to_owned())
}

/// Runs the unprivileged management service role.
///
/// The signal is delivered by a one-shot rather than an `AtomicBool` so the
/// ordering — stop accepting, drain, stop the worker, release the store — lives
/// in one place instead of being re-implemented here.
#[cfg(target_os = "linux")]
fn serve(
    state: PathBuf,
    socket: PathBuf,
    http_bind: String,
    canonical_origin: Option<String>,
    allow_non_loopback: bool,
) -> Result<(), String> {
    use wg_basic::http::ServeConfig;

    #[cfg(feature = "update-test-fixtures")]
    fail_fixture_candidate_start()?;

    // Three shapes, and only three. Each is chosen by what the operator stated,
    // never inferred:
    //
    //   * a canonical HTTPS origin → a loopback listener behind a TLS proxy;
    //   * an acknowledged routable bind → the operator has said the exposure;
    //   * neither → the default loopback deployment, which is the only shape
    //     that is correct without anyone having to decide anything.
    let config = match (canonical_origin.as_deref(), allow_non_loopback) {
        (Some(origin), false) if origin.starts_with("https://") => {
            ServeConfig::behind_https_proxy(state, socket, &http_bind, origin)
                .map_err(|error| error.to_string())?
        }
        (Some(origin), true) => {
            ServeConfig::acknowledged_off_host(state, socket, &http_bind, origin)
                .map_err(|error| error.to_string())?
        }
        (Some(origin), false) => {
            return Err(format!(
                "`{origin}` is not an https origin, and the listener is loopback. Either drop \
                 --canonical-origin to use the loopback origin, or pass \
                 --allow-non-loopback to say the bind is routable."
            ));
        }
        (None, true) => {
            return Err(
                "--allow-non-loopback also needs --canonical-origin, so there is something to \
                 check Host and Origin against."
                    .to_owned(),
            );
        }
        (None, false) => {
            ServeConfig::new(state, socket, &http_bind).map_err(|error| error.to_string())?
        }
    };
    let _lease = wg_basic::state::ServiceLease::acquire(&config.state_path)
        .map_err(|error| error.to_string())?;
    let (signal, wait) = tokio::sync::oneshot::channel::<()>();
    // The handler may fire more than once, so the sender lives behind a mutex:
    // the first Ctrl-C consumes it, and later ones find nothing to do.
    let signal = std::sync::Mutex::new(Some(signal));
    ctrlc::set_handler(move || {
        if let Ok(mut slot) = signal.lock() {
            if let Some(sender) = slot.take() {
                let _ = sender.send(());
            }
        }
    })
    .map_err(|_| "could not install graceful shutdown handler".to_owned())?;
    wg_basic::http::run_blocking(config, async {
        wait.await.ok();
    })
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "update-test-fixtures"))]
fn fail_fixture_candidate_start() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let marker =
        std::path::Path::new(wg_basic::distribution::STATE_DIR).join(".update-fixture-fail-start");
    let metadata = match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("fixture startup marker is unsafe".into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("fixture startup marker is unsafe".into());
    }
    let version =
        std::fs::read_to_string(&marker).map_err(|_| "fixture startup marker cannot be read")?;
    if version.trim() == wg_basic::release::PACKAGE_VERSION {
        return Err("test fixture requested candidate startup failure".into());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "update-test-fixtures"))]
fn delay_fixture_candidate_doctor_start(state: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let marker = state
        .parent()
        .ok_or("fixture state path has no parent")?
        .join(".update-fixture-start-timeout");
    let metadata = match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("fixture startup timeout marker is unsafe".into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 128
    {
        return Err("fixture startup timeout marker is unsafe".into());
    }
    let version = std::fs::read_to_string(marker)
        .map_err(|_| "fixture startup timeout marker cannot be read")?;
    if version.trim() == wg_basic::release::PACKAGE_VERSION {
        std::thread::sleep(std::time::Duration::from_secs(32));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "update-test-fixtures"))]
fn fail_fixture_netd_start() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    // `/run/wg-basic` is a systemd RuntimeDirectory and is removed when netd
    // stops during update. Keep this fixture-only switch outside that tree so
    // it persists across the candidate stop/start boundary.
    let marker = std::path::Path::new("/run/.wg-basic-update-fixture-fail-netd");
    let metadata = match std::fs::symlink_metadata(marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("fixture network startup marker is unsafe".into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o644
    {
        return Err("fixture network startup marker is unsafe".into());
    }
    let version = std::fs::read_to_string(marker)
        .map_err(|_| "fixture network startup marker cannot be read")?;
    if version.trim() == wg_basic::release::PACKAGE_VERSION {
        return Err("test fixture requested network service startup failure".into());
    }
    Ok(())
}

/// Runs the state-focused operator surface.
///
/// None of these paths ever contacts the kernel, and none of them prints row
/// contents. A backup is a second copy of the VPN secrets, and the output says
/// so rather than leaving the operator to guess.
fn run_state_action(action: StateCommand) -> Result<(), String> {
    use wg_basic::state::{restore, validate_candidate, verify_candidate_readonly, StateStore};

    match action {
        StateCommand::Init { state } => {
            if state.exists() {
                let store = StateStore::open(&state).map_err(|error| error.to_string())?;
                println!(
                    "state ready: {} (schema {})",
                    store.path().display(),
                    store.schema_version().map_err(|error| error.to_string())?
                );
            } else {
                let store = StateStore::initialize(&state).map_err(|error| error.to_string())?;
                println!("state initialized: {}", store.path().display());
            }
            Ok(())
        }
        StateCommand::Status { state } => {
            let store = StateStore::open(&state).map_err(|error| error.to_string())?;
            let metadata = store
                .installation_metadata()
                .map_err(|error| error.to_string())?;
            let convergence = store.convergence().map_err(|error| error.to_string())?;
            let schema_version = store.schema_version().map_err(|error| error.to_string())?;
            println!("database:           {}", store.path().display());
            println!("schema version:     {schema_version}");
            println!("installation id:    {}", metadata.installation_id);
            println!("desired generation: {}", metadata.desired_generation);
            println!(
                "last attempted:     {}",
                convergence
                    .last_attempted_generation
                    .map_or_else(|| "none".to_owned(), |g| g.to_string())
            );
            println!(
                "last converged:     {}",
                convergence
                    .last_converged_generation
                    .map_or_else(|| "none".to_owned(), |g| g.to_string())
            );
            println!(
                "last outcome:       {}",
                convergence.last_outcome.as_deref().unwrap_or("none")
            );
            println!("integrity:          ok");
            println!("\nThis projection never includes private or preshared keys.");
            Ok(())
        }
        StateCommand::Identity { state } => {
            let identity = wg_basic::update::state_identity(&state)?;
            println!(
                "{}",
                serde_json::to_string(&identity)
                    .map_err(|_| "could not format state identity".to_owned())?
            );
            Ok(())
        }
        StateCommand::Backup { destination, state } => {
            let store = StateStore::open(&state).map_err(|error| error.to_string())?;
            let receipt = store
                .backup(&destination)
                .map_err(|error| error.to_string())?;
            wg_basic::operational::emit(
                "state.backup_completed",
                wg_basic::operational::Severity::Info,
                "operator",
                "backup",
                "verified",
                None,
                Some(receipt.generation.to_storage() as u64),
                Some("promotion"),
            );
            println!(
                "backup complete: {} (generation {}, schema version {})",
                receipt.destination.display(),
                receipt.generation,
                receipt.schema_version
            );
            println!("installation id:    {}", receipt.installation_id);
            println!("\nThis file contains VPN private and preshared keys.");
            println!("Store it as securely as the live state database and never commit it.");
            Ok(())
        }
        StateCommand::Restore { candidate, state } => {
            // Validate first and report clearly, then install. The library
            // repeats the validation internally before replacing anything, so
            // this early check is a better error message, not the safety net.
            validate_candidate(&candidate).map_err(|error| error.to_string())?;
            let receipt = restore(&candidate, &state).map_err(|error| error.to_string())?;
            wg_basic::operational::emit(
                "state.restore_completed",
                wg_basic::operational::Severity::Info,
                "operator",
                "restore",
                "installed",
                None,
                Some(receipt.generation.to_storage() as u64),
                Some("replacement"),
            );
            println!(
                "restored: {} (generation {}, schema version {})",
                receipt.target.display(),
                receipt.generation,
                receipt.schema_version
            );
            println!("installation id:    {}", receipt.installation_id);
            if let Some(previous) = &receipt.previous_retained_at {
                println!("previous database retained at: {}", previous.display());
            }
            println!("\nRestore did not touch the kernel. Start the management service to");
            println!("reconcile the restored desired state.");
            println!("A restored database is not authority over unrelated host state:");
            println!("startup still fails closed on foreign or untagged resources.");
            Ok(())
        }
        StateCommand::Verify { candidate } => {
            let result =
                verify_candidate_readonly(&candidate).map_err(|error| error.to_string())?;
            println!("candidate:          {}", result.path.display());
            println!("installation id:    {}", result.installation_id);
            println!("desired generation: {}", result.generation);
            println!("schema version:     {}", result.schema_version);
            println!(
                "integrity:          {}",
                if result.integrity_ok { "ok" } else { "failed" }
            );
            println!(
                "foreign keys:       {}",
                if result.foreign_keys_ok {
                    "ok"
                } else {
                    "failed"
                }
            );
            println!("would migrate:      {}", result.would_migrate);
            println!("too new:            {}", result.too_new);
            println!("warning: this candidate contains VPN private and preshared keys");
            Ok(())
        }
        StateCommand::Purge {
            confirm_installation_id,
            dry_run,
            state,
            socket,
        } => purge_state(state, socket, confirm_installation_id, dry_run),
    }
}

#[cfg(target_os = "linux")]
fn purge_state(
    state: PathBuf,
    socket: PathBuf,
    confirmation: wg_basic::domain::InstallationId,
    dry_run: bool,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use wg_basic::{
        management::project_diagnostic_intent,
        protocol::{request, RequestOperation, ResponseBody},
        state::{inspect_readonly, MaintenanceLease, ServiceLease},
    };
    let lease = ServiceLease::acquire(&state).map_err(|error| error.to_string())?;
    let _maintenance = MaintenanceLease::exclusive(&state).map_err(|error| error.to_string())?;
    let snapshot = inspect_readonly(&state).map_err(|error| error.to_string())?;
    if snapshot.metadata.installation_id != confirmation {
        return Err("installation ID confirmation does not match this state".to_owned());
    }
    let mut unmet = Vec::new();
    match snapshot.desired.state.interfaces.first() {
        Some(interface)
            if snapshot
                .product
                .network_operational_enabled
                .get(&interface.id)
                .copied()
                .unwrap_or(true) =>
        {
            unmet.push("network must be disabled")
        }
        Some(_) => {}
        None => unmet.push("a configured server is required"),
    }
    if snapshot.convergence.last_converged_generation != Some(snapshot.desired.generation) {
        unmet.push("the current desired generation must be recorded as converged");
    }
    if !unmet.is_empty() {
        if dry_run {
            let paths = purge_paths(&state, snapshot.schema_version)?;
            print_purge_report(&state, snapshot.metadata.installation_id, &paths, &unmet);
        }
        return Err(unmet.join("; "));
    }
    let intent = project_diagnostic_intent(
        snapshot.metadata.installation_id,
        snapshot.desired.generation,
        &snapshot.desired.state,
        &snapshot.product,
    )
    .map_err(|_| "disabled desired state could not be projected".to_owned())?
    .ok_or_else(|| "disabled network intent is unavailable".to_owned())?;
    let planned = request(
        &socket,
        RequestOperation::PlanInstallationNetworkIntent { intent },
        19,
    );
    let plan = match planned {
        Ok(ResponseBody::InstallationNetworkPlanned(plan)) => plan,
        Ok(_) | Err(_) => {
            let unmet = ["netd did not prove owned network resources are absent"];
            if dry_run {
                let paths = purge_paths(&state, snapshot.schema_version)?;
                print_purge_report(&state, snapshot.metadata.installation_id, &paths, &unmet);
            }
            return Err(unmet[0].to_owned());
        }
    };
    if !plan.interface_plan.actions.is_empty() || !plan.firewall_plan.actions.is_empty() {
        let unmet = ["the fresh netd plan still contains owned network changes"];
        if dry_run {
            let paths = purge_paths(&state, snapshot.schema_version)?;
            print_purge_report(&state, snapshot.metadata.installation_id, &paths, &unmet);
        }
        return Err(
            "netd plan still contains owned network changes; reconcile and retry".to_owned(),
        );
    }
    let paths = purge_paths(&state, snapshot.schema_version)?;
    print_purge_report(&state, snapshot.metadata.installation_id, &paths, &[]);
    if dry_run {
        println!("dry run: no paths removed");
        return Ok(());
    }
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == nix::unistd::geteuid().as_raw()
                    && metadata.mode() & 0o077 == 0 =>
            {
                std::fs::remove_file(&path)
                    .map_err(|_| format!("could not safely remove {}", path.display()))?;
            }
            Ok(_) => return Err(format!("unsafe purge artifact: {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(format!(
                    "could not inspect purge artifact: {}",
                    path.display()
                ))
            }
        }
    }
    drop(lease);
    println!("purge complete; the advisory lease file was preserved to prevent lock-inode races");
    Ok(())
}

#[cfg(target_os = "linux")]
fn print_purge_report(
    state: &std::path::Path,
    installation_id: wg_basic::domain::InstallationId,
    paths: &[PathBuf],
    unmet: &[&str],
) {
    println!("installation id: {installation_id}");
    println!("network state:   operational flag inspected; see preconditions");
    println!("preconditions:");
    if unmet.is_empty() {
        println!("  all passed");
    } else {
        for requirement in unmet {
            println!("  unmet: {requirement}");
        }
    }
    println!("removal paths:");
    for path in paths {
        println!("  {}", path.display());
    }
    let lease = wg_basic::state::ServiceLease::path_for_state(state)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "state service lease path unavailable".to_owned());
    println!("preserved paths:");
    println!("  {lease} (kept to prevent lock-inode races)");
    let maintenance = wg_basic::state::MaintenanceLease::path_for_state(state)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "state maintenance lease path unavailable".to_owned());
    println!("  {maintenance} (kept to coordinate online backups)");
    println!("  other files in the state directory, including operator backups/configuration");
}

#[cfg(target_os = "linux")]
fn purge_paths(state: &std::path::Path, schema_version: i64) -> Result<Vec<PathBuf>, String> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = vec![state.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut name = state.as_os_str().to_os_string();
        name.push(suffix);
        paths.push(PathBuf::from(name));
    }
    paths.push(wg_basic::state::retained_previous_path(state));
    for source_schema in 1..schema_version {
        paths.push(wg_basic::state::recovery_snapshot_path(
            state,
            source_schema,
        ));
    }
    let parent = state
        .parent()
        .ok_or_else(|| "state path has no parent".to_owned())?;
    let file_name = state
        .file_name()
        .ok_or_else(|| "state path has no file name".to_owned())?
        .to_string_lossy();
    for entry in std::fs::read_dir(parent).map_err(|_| "state directory could not be inspected")? {
        let entry = entry.map_err(|_| "state directory entry could not be inspected")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let known_temporary = [
            format!(".{file_name}.backup."),
            format!(".{file_name}.restore."),
        ]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
        });
        if known_temporary {
            paths.push(entry.path());
        }
    }
    paths.sort();
    paths.dedup();
    for path in &paths {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(format!("unsafe purge artifact: {}", path.display()));
            }
        }
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn run_network_action(action: NetworkCommand) -> Result<(), String> {
    use wg_basic::state::ServiceLease;
    match action {
        NetworkCommand::Status { state } => {
            let snapshot =
                wg_basic::state::inspect_readonly(&state).map_err(|error| error.to_string())?;
            let Some(interface) = snapshot.desired.state.interfaces.first() else {
                println!("no managed server is configured");
                return Ok(());
            };
            let enabled = snapshot
                .product
                .network_operational_enabled
                .get(&interface.id)
                .copied()
                .unwrap_or(true);
            let lease = match ServiceLease::is_held(&state) {
                Ok(true) => "active",
                Ok(false) => "free",
                Err(_) => "unknown",
            };
            println!("installation id:    {}", snapshot.metadata.installation_id);
            println!("desired generation: {}", snapshot.desired.generation);
            println!(
                "network:            {}",
                if enabled { "enabled" } else { "disabled" }
            );
            println!(
                "last converged:     {}",
                snapshot
                    .convergence
                    .last_converged_generation
                    .map_or_else(|| "none".to_owned(), |value| value.to_string())
            );
            println!("serve lease:        {lease}");
            println!("server interface:   {}", interface.name);
            println!("configured clients: {}", snapshot.product.clients.len());
            Ok(())
        }
        NetworkCommand::Disable { state, socket } => set_network_enabled(state, socket, false),
        NetworkCommand::Enable { state, socket } => set_network_enabled(state, socket, true),
    }
}

#[cfg(target_os = "linux")]
fn set_network_enabled(state: PathBuf, socket: PathBuf, enabled: bool) -> Result<(), String> {
    use wg_basic::{
        management::ManagementRuntime,
        product::ProductService,
        state::{ServiceLease, StateStore},
    };
    let _lease = ServiceLease::acquire(&state).map_err(|error| error.to_string())?;
    let store = StateStore::open(&state).map_err(|error| error.to_string())?;
    let metadata = store
        .installation_metadata()
        .map_err(|error| error.to_string())?;
    let desired = store.load().map_err(|error| error.to_string())?;
    let product = store.load_product().map_err(|error| error.to_string())?;
    let interface = desired
        .state
        .interfaces
        .first()
        .ok_or_else(|| "no managed server is configured".to_owned())?;
    let was_enabled = product
        .state
        .network_operational_enabled
        .get(&interface.id)
        .copied()
        .unwrap_or(true);
    if was_enabled == enabled {
        println!(
            "network is already {}; no mutation was committed",
            if enabled { "enabled" } else { "disabled" }
        );
        return Ok(());
    }
    let generation = ProductService::new(&store)
        .set_network_enabled(metadata.desired_generation, enabled)
        .map_err(|error| error.to_string())?;
    drop(store);

    let outcome = match ManagementRuntime::open(&state, &socket)
        .and_then(|runtime| runtime.reconcile_after_commit(generation))
    {
        Ok(receipt) if receipt.is_enforced() => {
            println!(
                "network {} committed at generation {} and enforced",
                if enabled { "enable" } else { "disable" },
                generation
            );
            "enforced"
        }
        Ok(receipt) => {
            println!("network {} committed at generation {} but not yet enforced ({:?}); check netd and rerun `wg-basic reconcile`", if enabled { "enable" } else { "disable" }, generation, receipt.enforcement);
            "degraded"
        }
        Err(_) => {
            println!("network {} committed at generation {} but reconciliation could not be confirmed; check netd and rerun `wg-basic reconcile`", if enabled { "enable" } else { "disable" }, generation);
            "unknown"
        }
    };
    wg_basic::operational::emit(
        if enabled {
            "network.enabled"
        } else {
            "network.disabled"
        },
        if outcome == "enforced" {
            wg_basic::operational::Severity::Info
        } else {
            wg_basic::operational::Severity::Warn
        },
        "operator",
        if enabled { "enable" } else { "disable" },
        outcome,
        None,
        Some(generation.to_storage() as u64),
        Some("reconcile"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_roles_parse_without_starting_services() {
        Cli::command().debug_assert();
        assert!(Cli::try_parse_from(["wg-basic", "serve"]).is_ok());
        assert!(Cli::try_parse_from(["wg-basic", "netd"]).is_ok());
        assert!(Cli::try_parse_from(["wg-basic", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["wg-basic", "reconcile"]).is_ok());
        assert!(Cli::try_parse_from(["wg-basic", "health"]).is_ok());
    }

    #[test]
    fn the_state_roles_require_their_paths() {
        Cli::command().debug_assert();
        assert!(Cli::try_parse_from(["wg-basic", "state", "status"]).is_ok());
        assert!(Cli::try_parse_from(["wg-basic", "state", "backup", "/tmp/x.db"]).is_ok());
        assert!(Cli::try_parse_from(["wg-basic", "state", "restore", "/tmp/x.db"]).is_ok());
        // Backup and restore name a file; there is no implicit destination.
        assert!(Cli::try_parse_from(["wg-basic", "state", "backup"]).is_err());
        assert!(Cli::try_parse_from(["wg-basic", "state", "restore"]).is_err());
        assert!(Cli::try_parse_from(["wg-basic", "state"]).is_err());
    }

    /// The state surface must never be a general SQL or shell escape hatch.
    #[test]
    fn the_state_cli_offers_no_sql_or_shell_access() {
        let help = Cli::command().render_long_help().to_string();
        let state_help = help
            .split("state")
            .nth(1)
            .expect("the state command group is documented");
        for forbidden in ["sql", "sqlite", "query", "exec", "shell"] {
            assert!(
                !state_help.to_lowercase().contains(forbidden),
                "state CLI must not advertise {forbidden}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn doctor_state_check_does_not_change_the_database_or_create_sidecars() {
        use std::{os::unix::fs::PermissionsExt, time::SystemTime};
        let root = std::path::Path::new("/tmp").join(format!(
            "wg-basic-doctor-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("state.db");
        drop(wg_basic::state::StateStore::initialize(&path).unwrap());
        let before = std::fs::read(&path).unwrap();
        let entries_before = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();

        let (checks, _snapshot) = doctor_state_checks(&path);
        let state = checks
            .iter()
            .find(|check| check.id == wg_basic::doctor::DoctorCheckId::State)
            .unwrap();
        let sqlite = checks
            .iter()
            .find(|check| check.id == wg_basic::doctor::DoctorCheckId::Sqlite)
            .unwrap();
        assert_eq!(state.disposition, wg_basic::doctor::DoctorDisposition::Pass);
        assert_eq!(
            sqlite.disposition,
            wg_basic::doctor::DoctorDisposition::Pass
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let entries_after = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries_after, entries_before);
        std::fs::remove_dir_all(root).unwrap();
    }
}
