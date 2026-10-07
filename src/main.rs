use clap::{Parser, Subcommand};
use std::path::PathBuf;

const DEFAULT_SOCKET: &str = "/run/wg-basic/netd.sock";

#[derive(Parser)]
#[command(name = "wg-basic", version, about = "Linux-native WireGuard appliance")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Unprivileged management role; currently verifies the local netd protocol.
    Serve {
        #[arg(long, default_value = DEFAULT_SOCKET)]
        socket: PathBuf,
    },
    /// Privileged local network service. M002 performs read-only operations only.
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
        Some(Command::Serve { socket }) => {
            let result = request(&socket, RequestOperation::Ping, 1).map_err(|_| {
                "could not contact local netd using the authorized protocol".to_owned()
            })?;
            match result {
                ResponseBody::Pong { service, version } => {
                    println!("management role connected to {service} {version}")
                }
                ResponseBody::Capabilities(_) => {
                    return Err("netd returned an unexpected protocol response".into())
                }
                ResponseBody::WireGuardDevice(_) | ResponseBody::WireGuardApplied(_) => {
                    return Err("netd returned an unexpected protocol response".into())
                }
            }
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
                ResponseBody::WireGuardDevice(_) | ResponseBody::WireGuardApplied(_) => {
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
    }
}
