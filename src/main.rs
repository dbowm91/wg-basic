use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "wg-basic",
    version,
    about = "Linux-native WireGuard appliance foundation"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Netd,
    Doctor,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        None => {
            println!(
                "wg-basic {}: planning-stage network roles",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some(Command::Doctor) => {
            println!("doctor: read-only foundation; checks are not implemented");
            Ok(())
        }
        Some(Command::Serve) => Err("serve role is not implemented"),
        Some(Command::Netd) => Err("netd role is not implemented"),
    };
    if let Err(message) = result {
        eprintln!("wg-basic: {message}");
        std::process::exit(2);
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
