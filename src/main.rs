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
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
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
        Some(Command::Doctor { socket }) => {
            let result = request(&socket, RequestOperation::InspectCapabilities, 2)
                .map_err(|_| "could not inspect capabilities through local netd".to_owned())?;
            match result {
                ResponseBody::Capabilities(snapshot) => println!(
                    "{}",
                    serde_json::to_string_pretty(&snapshot)
                        .map_err(|_| "could not format capability snapshot")?
                ),
                ResponseBody::Pong { .. } => {
                    return Err("netd returned an unexpected protocol response".into())
                }
                ResponseBody::WireGuardDevice(_)
                | ResponseBody::WireGuardApplied(_)
                | ResponseBody::ManagedInterfacePlan(_)
                | ResponseBody::ManagedInterfaceApplied(_)
                | ResponseBody::NetworkPolicyPlan(_)
                | ResponseBody::NetworkPolicyApplied(_)
                | ResponseBody::InstallationNetworkPlanned(_)
                | ResponseBody::InstallationNetworkApplied(_) => {
                    return Err("netd returned an unexpected protocol response".into())
                }
            }
            Ok(())
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
}
