#![cfg(target_os = "linux")]

//! Stable CLI contract for the implemented, fail-closed update commands.

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

#[test]
fn update_commands_are_explicit_and_mutations_refuse_without_root() {
    let help = Command::new(BINARY)
        .args(["update", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    for command in ["check", "run", "recover"] {
        assert!(help.contains(command), "missing `update {command}` in help");
    }

    if nix::unistd::geteuid().is_root() {
        return;
    }

    for command in ["run", "recover"] {
        let output = Command::new(BINARY)
            .args(["update", command])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            diagnostic.contains("requires effective root"),
            "`update {command}` must refuse without root and never elevate: {diagnostic}"
        );
    }
}
