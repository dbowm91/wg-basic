#!/usr/bin/env python3
"""Add the minimal M002 unit CLI compatibility to the pre-v5 fixture source."""

from pathlib import Path
import sys


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"expected one old-fixture source anchor, found {count}: {old!r}")
    return source.replace(old, new, 1)


if len(sys.argv) != 2:
    raise SystemExit("usage: patch-update-old-fixture.py <old-source>/src/main.rs")

path = Path(sys.argv[1])
source = path.read_text()
source = replace_once(
    source,
    '        allowed_uids: Vec<u32>,\n    },\n    /// Read-only service capability check.',
    '        allowed_uids: Vec<u32>,\n'
    '        /// Additional local account permitted by SO_PEERCRED.\n'
    '        #[arg(long = "allow-user")]\n'
    '        allowed_users: Vec<String>,\n'
    '    },\n'
    '    /// Read-only service capability check.',
)
source = replace_once(
    source,
    '        #[arg(long)]\n        json: bool,\n',
    '        #[arg(long)]\n        json: bool,\n'
    '        /// Treat warnings as successful for pre-start diagnostics.\n'
    '        #[arg(long)]\n        allow_warnings: bool,\n',
)
source = replace_once(
    source,
    'enum StateCommand {\n    /// Prints a safe status projection:',
    'enum StateCommand {\n'
    '    /// Emit the updater\'s secret-free typed v4 compatibility identity.\n'
    '    Identity {\n'
    '        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]\n'
    '        state: PathBuf,\n'
    '    },\n'
    '    /// Validate a recovery database without installing it.\n'
    '    Verify { candidate: PathBuf },\n'
    '    /// Create an empty schema or validate and migrate existing owned state.\n'
    '    Init {\n'
    '        #[arg(long, default_value = wg_basic::state::DEFAULT_STATE_PATH)]\n'
    '        state: PathBuf,\n'
    '    },\n'
    '    /// Prints a safe status projection:',
)
source = replace_once(
    source,
    '            json,\n            http_bind,',
    '            json,\n            allow_warnings,\n            http_bind,',
)
source = replace_once(
    source,
    '            std::process::exit(report.exit_code());',
    '            let exit_code = if allow_warnings\n'
    '                && matches!(report.overall,\n'
    '                    wg_basic::doctor::DoctorDisposition::Warn\n'
    '                        | wg_basic::doctor::DoctorDisposition::Unknown\n'
    '                )\n'
    '            {\n                0\n            } else {\n                report.exit_code()\n            };\n'
    '            std::process::exit(exit_code);',
)
source = replace_once(
    source,
    '        Some(Command::Netd {\n            socket,\n            allowed_uids,\n        }) => {\n'
    '            let mut policy = AuthorizationPolicy::current_user_and_root();\n'
    '            policy.extend(allowed_uids);',
    '        Some(Command::Netd {\n'
    '            socket,\n'
    '            allowed_uids,\n'
    '            allowed_users,\n'
    '        }) => {\n'
    '            let mut policy = AuthorizationPolicy::current_user_and_root();\n'
    '            policy.extend(allowed_uids);\n'
    '            for username in allowed_users {\n'
    '                let user = nix::unistd::User::from_name(&username)\n'
    '                    .map_err(|_| "could not resolve an allowed netd user")?\n'
    '                    .ok_or("allowed netd user is missing")?;\n'
    '                policy.extend([user.uid.as_raw()]);\n'
    '            }',
)
source = replace_once(
    source,
    '    match action {\n        StateCommand::Status { state } => {',
    '    match action {\n'
    '        StateCommand::Init { state } => {\n'
    '            if state.exists() {\n'
    '                let store = StateStore::open(&state).map_err(|error| error.to_string())?;\n'
    '                println!("state ready: {} (schema {})", store.path().display(),\n'
    '                    store.schema_version().map_err(|error| error.to_string())?);\n'
    '            } else {\n'
    '                let store = StateStore::initialize(&state).map_err(|error| error.to_string())?;\n'
    '                println!("state initialized: {}", store.path().display());\n'
    '            }\n'
    '            Ok(())\n'
    '        }\n'
    '        StateCommand::Status { state } => {',
)
source = replace_once(
    source,
    '        StateCommand::Backup { destination, state } => {',
    '        StateCommand::Verify { candidate } => {\n'
    '            validate_candidate(&candidate).map_err(|error| error.to_string())?;\n'
    '            println!("candidate valid: {}", candidate.display());\n'
    '            Ok(())\n'
    '        }\n'
    '        StateCommand::Identity { state } => {\n'
    '            use sha2::{Digest, Sha256};\n'
    '            let store = StateStore::open(&state).map_err(|error| error.to_string())?;\n'
    '            let metadata = store.installation_metadata().map_err(|error| error.to_string())?;\n'
    '            let product = store.load_product().map_err(|error| error.to_string())?;\n'
    '            let identifiers = serde_json::json!({\n'
    '                "interfaces": product.state.interfaces.keys().map(ToString::to_string).collect::<Vec<_>>(),\n'
    '                "clients": product.state.clients.keys().map(ToString::to_string).collect::<Vec<_>>(),\n'
    '            });\n'
    '            let digest = Sha256::digest(serde_json::to_vec(&identifiers)\n'
    '                .map_err(|_| "state product identity could not be encoded".to_owned())?);\n'
    '            let identity = serde_json::json!({\n'
    '                "installation_id": metadata.installation_id.to_string(),\n'
    '                "schema_version": store.schema_version().map_err(|error| error.to_string())?,\n'
    '                "desired_generation": metadata.desired_generation.to_storage(),\n'
    '                "network_enabled": !product.state.interfaces.is_empty(),\n'
    '                "product_identity_sha256": digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),\n'
    '            });\n'
    '            println!("{}", serde_json::to_string(&identity).map_err(|_| "could not format state identity".to_owned())?);\n'
    '            Ok(())\n'
    '        }\n'
    '        StateCommand::Backup { destination, state } => {',
)
path.write_text(source)

# Keep the destructive restore interruption point inside the actual v4
# restore implementation. The old fixture does not carry this repository's
# `update-test-fixtures` feature, so patch its scratch-only backup module with
# the same private-file gate used by the candidate implementation.
backup_path = path.parent / "state" / "backup.rs"
backup = backup_path.read_text()
backup = replace_once(
    backup,
    "            sync_directory(&parent_of(target)?)?;\n            Some(retained)",
    "            sync_directory(&parent_of(target)?)?;\n"
    "            wait_fixture_restore_gate(target)?;\n"
    "            Some(retained)",
)
backup = replace_once(
    backup,
    "fn current_uid() -> u32 {",
    "fn wait_fixture_restore_gate(target: &Path) -> Result<(), StateError> {\n"
    "    use std::os::unix::fs::MetadataExt;\n"
    "    let parent = parent_of(target)?;\n"
    "    let gate = parent.join(\".update-fixture-restore-gate\");\n"
    "    let metadata = match fs::symlink_metadata(&gate) {\n"
    "        Ok(metadata) => metadata,\n"
    "        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),\n"
    "        Err(_) => return Err(StateError::Corrupt(\"fixture restore gate is unsafe\")),\n"
    "    };\n"
    "    if !metadata.is_file() || metadata.file_type().is_symlink()\n"
    "        || metadata.uid() != current_uid() || metadata.mode() & 0o777 != 0o600\n"
    "        || fs::read(&gate).map_err(|_| StateError::Corrupt(\"fixture restore gate is unsafe\"))? != b\"pause\"\n"
    "    {\n"
    "        return Err(StateError::Corrupt(\"fixture restore gate is unsafe\"));\n"
    "    }\n"
    "    let entered = parent.join(\".update-fixture-restore-entered\");\n"
    "    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(entered)\n"
    "        .map_err(|_| StateError::Corrupt(\"fixture restore gate is unsafe\"))?;\n"
    "    while gate.exists() { std::thread::sleep(std::time::Duration::from_millis(10)); }\n"
    "    Ok(())\n"
    "}\n\n"
    "fn current_uid() -> u32 {",
)
backup_path.write_text(backup)

state_path = path.parent / "state" / "mod.rs"
state = state_path.read_text()
state = replace_once(state, "mod schema;\nmod store;", "mod schema;\nmod service_lease;\nmod store;")
state = replace_once(
    state,
    "pub use error::StateError;",
    "pub use error::StateError;\npub use service_lease::ServiceLease;",
)
state_path.write_text(state)

source = path.read_text()
source = replace_once(
    source,
    "    };\n    let (signal, wait) = tokio::sync::oneshot::channel::<()>();",
    "    };\n"
    "    let _lease = wg_basic::state::ServiceLease::acquire(&config.state_path)\n"
    "        .map_err(|error| error.to_string())?;\n"
    "    let (signal, wait) = tokio::sync::oneshot::channel::<()>();",
)
path.write_text(source)
