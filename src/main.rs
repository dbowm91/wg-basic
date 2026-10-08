use clap::{Parser, Subcommand};
use std::path::PathBuf;

const DEFAULT_SOCKET: &str = "/run/wg-basic/netd.sock";

/// The Phase 7 local administrator's login name.
const DEFAULT_ADMIN_USERNAME: &str = "admin";

#[derive(Parser)]
#[command(name = "wg-basic", version, about = "Linux-native WireGuard appliance")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
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
    },
    /// Read-only service capability check.
    Doctor {
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
        #[arg(long)]
        json: bool,
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
    /// Prints a safe status projection: identifiers, generations, and integrity.
    ///
    /// Never prints private keys, preshared keys, or any row contents.
    Status {
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
    /// management service first: this refuses to run against a database this
    /// process still holds open.
    Restore {
        candidate: PathBuf,
        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]
        state: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    #[cfg(target_os = "linux")]
    let result = run_linux(cli.command);
    #[cfg(not(target_os = "linux"))]
    let result: Result<(), String> = {
        let _ = cli.command;
        Err("network service roles require Linux".into())
    };
    if let Err(message) = result {
        eprintln!("wg-basic: {message}");
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
            http_bind,
            canonical_origin,
            allow_non_loopback,
        }) => {
            let mut checks = doctor_state_checks(&state);
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
                    checks.push(wg_basic::doctor::DoctorCheck::new(
                        wg_basic::doctor::DoctorCheckId::WireGuard,
                        capability_disposition(snapshot.wireguard_control),
                        "WireGuard Generic Netlink probe",
                        format!("netd capability snapshot: {:?}", snapshot.wireguard_control),
                        "verify kernel WireGuard support and netd permissions if unavailable",
                    ));
                    checks.push(wg_basic::doctor::DoctorCheck::new(
                        wg_basic::doctor::DoctorCheckId::Nftables,
                        capability_disposition(snapshot.nftables),
                        "nftables probe",
                        format!("netd capability snapshot: {:?}", snapshot.nftables),
                        "verify nftables availability and netd execution policy if unavailable",
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
            checks.push(wg_basic::doctor::DoctorCheck::new(
                wg_basic::doctor::DoctorCheckId::Rtnetlink,
                wg_basic::doctor::DoctorDisposition::Unknown,
                "RTNETLINK read-only observation was not requested",
                "the capability protocol does not currently expose a harmless link observation without desired state",
                "no host-state mutation was attempted",
            ));
            checks.push(wg_basic::doctor::DoctorCheck::new(
                wg_basic::doctor::DoctorCheckId::ServiceLease,
                wg_basic::doctor::DoctorDisposition::Unknown,
                "service singleton lease is not available in this milestone",
                "serve lease support is implemented in Phase 9 M002",
                "ensure only one serve process uses this state database",
            ));
            checks.push(match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
                Ok(value) if value.trim() == "1" => wg_basic::doctor::DoctorCheck::new(
                    wg_basic::doctor::DoctorCheckId::Forwarding,
                    wg_basic::doctor::DoctorDisposition::Pass,
                    "IPv4 forwarding is enabled",
                    "read-only kernel setting is 1",
                    "none",
                ),
                Ok(_) => wg_basic::doctor::DoctorCheck::new(
                    wg_basic::doctor::DoctorCheckId::Forwarding,
                    wg_basic::doctor::DoctorDisposition::Unknown,
                    "IPv4 forwarding is disabled",
                    "read-only kernel setting is 0; the product snapshot is unavailable",
                    "check whether this installation routes traffic, then enable forwarding through host configuration if required",
                ),
                Err(_) => wg_basic::doctor::DoctorCheck::new(
                    wg_basic::doctor::DoctorCheckId::Forwarding,
                    wg_basic::doctor::DoctorDisposition::Unknown,
                    "IPv4 forwarding state could not be read",
                    "the expected procfs setting is unavailable",
                    "run doctor on the Linux host that owns the WireGuard network",
                ),
            });
            checks.push(wg_basic::doctor::DoctorCheck::new(
                wg_basic::doctor::DoctorCheckId::NetworkOwnership,
                wg_basic::doctor::DoctorDisposition::Unknown,
                "managed network ownership has not been inspected",
                "the diagnostic did not issue a plan-only aggregate network request",
                "review network ownership with the normal read-only network inspection tools",
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
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|_| "could not format diagnostic report")?
                );
            } else {
                print!("{}", report.render_human());
            }
            std::process::exit(report.exit_code());
        }
        Some(Command::Netd {
            socket,
            allowed_uids,
        }) => {
            let mut policy = AuthorizationPolicy::current_user_and_root();
            policy.extend(allowed_uids);
            let server = SocketServer::bind(&socket, policy)
                .map_err(|_| "could not safely bind the configured netd socket path".to_owned())?;
            let shutdown = Arc::new(AtomicBool::new(false));
            let signal_shutdown = shutdown.clone();
            ctrlc::set_handler(move || {
                signal_shutdown.store(true, std::sync::atomic::Ordering::Release)
            })
            .map_err(|_| "could not install graceful shutdown handler".to_owned())?;
            eprintln!(
                "wg-basic netd listening on {} (typed local protocol)",
                server.socket_path().display()
            );
            server
                .run_until_shutdown(&shutdown)
                .map_err(|_| "netd listener stopped after a runtime error".to_owned())
        }
        Some(Command::Admin { action }) => run_admin_action(action),
        Some(Command::State { action }) => run_state_action(action),
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
fn doctor_state_checks(path: &std::path::Path) -> Vec<wg_basic::doctor::DoctorCheck> {
    use rusqlite::OpenFlags;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use wg_basic::doctor::{DoctorCheck, DoctorCheckId as Id, DoctorDisposition as D};

    let mut checks = Vec::new();
    let version = rusqlite::Connection::open_in_memory().and_then(|connection| {
        connection.query_row("SELECT sqlite_version(), sqlite_source_id()", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
    });
    let (version_text, source_id) =
        version.unwrap_or_else(|_| ("unknown".into(), "unavailable".into()));
    let supported = version_text
        .split('.')
        .map(|part| part.parse::<u32>().unwrap_or(0))
        .collect::<Vec<_>>();
    let sqlite_ok = supported.as_slice() >= &[3, 51, 3];
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

    let result = (|| -> Result<(i64, String), &'static str> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "state file does not exist or cannot be inspected")?;
        if !metadata.file_type().is_file() {
            return Err("state path is not a regular non-symlink file");
        }
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let parent_meta =
            std::fs::metadata(parent).map_err(|_| "state parent cannot be inspected")?;
        let uid = std::fs::metadata("/proc/self")
            .map_err(|_| "effective uid cannot be inspected")?
            .uid();
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || parent_meta.uid() != uid
            || parent_meta.permissions().mode() & 0o022 != 0
        {
            return Err("state ownership or permissions are broader than the store policy");
        }
        let wal_path = sidecar_path(path, "-wal");
        let shm_path = sidecar_path(path, "-shm");
        if wal_path.exists() || shm_path.exists() {
            return Err(
                "SQLite WAL sidecars are present; safe immutable inspection is unavailable",
            );
        }
        let uri = immutable_sqlite_uri(path)?;
        let connection = rusqlite::Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|_| "state database could not be opened in immutable read-only mode")?;
        let quick: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|_| "SQLite quick_check could not complete")?;
        if quick != "ok" {
            return Err("SQLite quick_check reported an integrity failure");
        }
        let fk: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .map_err(|_| "foreign-key check could not complete")?;
        if fk != 0 {
            return Err("SQLite foreign-key check reported inconsistent rows");
        }
        let schema: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| "schema version could not be read")?;
        if !(1..=4).contains(&schema) {
            return Err("schema version is unsupported by this binary");
        }
        if wal_path.exists() || shm_path.exists() {
            return Err(
                "SQLite WAL sidecars appeared during inspection; result is not authoritative",
            );
        }
        Ok((schema, quick))
    })();
    checks.push(match result {
        Ok((schema, _)) => DoctorCheck::new(
            Id::State,
            D::Pass,
            "state file passed read-only safety and integrity checks",
            format!("schema {schema}; SQLite quick_check and foreign-key check passed"),
            "none",
        ),
        Err(reason) if reason == "state file does not exist or cannot be inspected" => {
            DoctorCheck::new(
                Id::State,
                D::Warn,
                "state database is not initialized",
                reason,
                "initialize the state database with the documented setup flow",
            )
        }
        Err(reason) if reason.starts_with("SQLite WAL sidecars") => DoctorCheck::new(
            Id::State,
            D::Unknown,
            "state database integrity was not inspected",
            reason,
            "stop the service before offline inspection, or rerun doctor when no WAL sidecars exist",
        ),
        Err(reason) => DoctorCheck::new(
            Id::State,
            D::Fail,
            "state database failed a read-only safety check",
            reason,
            "correct the path/ownership or restore a verified backup",
        ),
    });
    checks
}

#[cfg(target_os = "linux")]
fn capability_disposition(
    state: wg_basic::protocol::CapabilityState,
) -> wg_basic::doctor::DoctorDisposition {
    match state {
        wg_basic::protocol::CapabilityState::Available => wg_basic::doctor::DoctorDisposition::Pass,
        wg_basic::protocol::CapabilityState::Unavailable => {
            wg_basic::doctor::DoctorDisposition::Fail
        }
        wg_basic::protocol::CapabilityState::Unknown => {
            wg_basic::doctor::DoctorDisposition::Unknown
        }
    }
}

#[cfg(target_os = "linux")]
fn sidecar_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

/// Builds a percent-encoded immutable URI so inspection neither creates WAL
/// shared-memory files nor writes database metadata. Existing WAL sidecars are
/// refused by the caller because immutable mode intentionally ignores them.
#[cfg(target_os = "linux")]
fn immutable_sqlite_uri(path: &std::path::Path) -> Result<String, &'static str> {
    use std::os::unix::ffi::OsStrExt;
    let absolute = std::path::absolute(path).map_err(|_| "path could not be made absolute")?;
    let mut uri = String::from("file:");
    for byte in absolute.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(*byte));
        } else {
            uri.push('%');
            uri.push_str(&format!("{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
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

/// Runs the state-focused operator surface.
///
/// None of these paths ever contacts the kernel, and none of them prints row
/// contents. A backup is a second copy of the VPN secrets, and the output says
/// so rather than leaving the operator to guess.
fn run_state_action(action: StateCommand) -> Result<(), String> {
    use wg_basic::state::{restore, validate_candidate, StateStore};

    match action {
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
        StateCommand::Backup { destination, state } => {
            let store = StateStore::open(&state).map_err(|error| error.to_string())?;
            let receipt = store
                .backup(&destination)
                .map_err(|error| error.to_string())?;
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
    }
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

        let checks = doctor_state_checks(&path);
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
