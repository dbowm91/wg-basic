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
path.write_text(source)

migrations_path = path.parent / "state" / "schema" / "migrations.rs"
migrations = migrations_path.read_text()
migrations = replace_once(
    migrations,
    "pub(crate) fn supported_version() -> i64 {\n"
    "    MIGRATIONS.last().map_or(0, |m| m.version)\n"
    "}",
    "pub(crate) fn supported_version() -> i64 {\n"
    "    4 // The disposable old-release fixture intentionally models schema v4.\n"
    "}",
)
migrations_path.write_text(migrations)
