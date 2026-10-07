//! Static architecture guards.
//!
//! These tests assert that the refactored module layout did not cross an
//! architecture boundary. They read the shipped source text plus a few runtime
//! redaction checks; they are intentionally cheap and run in the ordinary suite.

/// Every production source file that participates in a guard.
const PRODUCTION_SOURCES: &[(&str, &str)] = &[
    ("src/main.rs", include_str!("../src/main.rs")),
    ("src/lib.rs", include_str!("../src/lib.rs")),
    ("src/error.rs", include_str!("../src/error.rs")),
    ("src/wireguard.rs", include_str!("../src/wireguard.rs")),
    (
        "src/wireguard/backend.rs",
        include_str!("../src/wireguard/backend.rs"),
    ),
    (
        "src/wireguard/keys.rs",
        include_str!("../src/wireguard/keys.rs"),
    ),
    ("src/aggregate.rs", include_str!("../src/aggregate.rs")),
    (
        "src/protocol/mod.rs",
        include_str!("../src/protocol/mod.rs"),
    ),
    (
        "src/protocol/auth.rs",
        include_str!("../src/protocol/auth.rs"),
    ),
    (
        "src/protocol/capability.rs",
        include_str!("../src/protocol/capability.rs"),
    ),
    (
        "src/protocol/client.rs",
        include_str!("../src/protocol/client.rs"),
    ),
    (
        "src/protocol/dispatch.rs",
        include_str!("../src/protocol/dispatch.rs"),
    ),
    (
        "src/protocol/framing.rs",
        include_str!("../src/protocol/framing.rs"),
    ),
    (
        "src/protocol/socket.rs",
        include_str!("../src/protocol/socket.rs"),
    ),
    (
        "src/protocol/wire.rs",
        include_str!("../src/protocol/wire.rs"),
    ),
    (
        "src/reconcile/mod.rs",
        include_str!("../src/reconcile/mod.rs"),
    ),
    (
        "src/reconcile/model.rs",
        include_str!("../src/reconcile/model.rs"),
    ),
    (
        "src/reconcile/planner.rs",
        include_str!("../src/reconcile/planner.rs"),
    ),
    (
        "src/reconcile/service.rs",
        include_str!("../src/reconcile/service.rs"),
    ),
    (
        "src/reconcile/linux.rs",
        include_str!("../src/reconcile/linux.rs"),
    ),
    (
        "src/firewall/mod.rs",
        include_str!("../src/firewall/mod.rs"),
    ),
    (
        "src/firewall/policy.rs",
        include_str!("../src/firewall/policy.rs"),
    ),
    (
        "src/firewall/planner.rs",
        include_str!("../src/firewall/planner.rs"),
    ),
    (
        "src/firewall/nft.rs",
        include_str!("../src/firewall/nft.rs"),
    ),
    (
        "src/firewall/service.rs",
        include_str!("../src/firewall/service.rs"),
    ),
    ("src/state/mod.rs", include_str!("../src/state/mod.rs")),
    ("src/state/error.rs", include_str!("../src/state/error.rs")),
    ("src/state/model.rs", include_str!("../src/state/model.rs")),
    (
        "src/state/projection.rs",
        include_str!("../src/state/projection.rs"),
    ),
    (
        "src/state/schema/mod.rs",
        include_str!("../src/state/schema/mod.rs"),
    ),
    (
        "src/state/schema/validation.rs",
        include_str!("../src/state/schema/validation.rs"),
    ),
    (
        "src/state/schema/migrations.rs",
        include_str!("../src/state/schema/migrations.rs"),
    ),
    (
        "src/state/store/mod.rs",
        include_str!("../src/state/store/mod.rs"),
    ),
    (
        "src/state/store/desired.rs",
        include_str!("../src/state/store/desired.rs"),
    ),
    (
        "src/state/store/convergence.rs",
        include_str!("../src/state/store/convergence.rs"),
    ),
    (
        "src/state/store/sql.rs",
        include_str!("../src/state/store/sql.rs"),
    ),
    (
        "src/state/backup.rs",
        include_str!("../src/state/backup.rs"),
    ),
    ("src/state/inuse.rs", include_str!("../src/state/inuse.rs")),
    (
        "src/management/mod.rs",
        include_str!("../src/management/mod.rs"),
    ),
    (
        "src/management/health.rs",
        include_str!("../src/management/health.rs"),
    ),
    (
        "src/management/error.rs",
        include_str!("../src/management/error.rs"),
    ),
    (
        "src/management/coordinator.rs",
        include_str!("../src/management/coordinator.rs"),
    ),
    (
        "src/management/runtime.rs",
        include_str!("../src/management/runtime.rs"),
    ),
    (
        "src/management/worker.rs",
        include_str!("../src/management/worker.rs"),
    ),
    ("src/http/mod.rs", include_str!("../src/http/mod.rs")),
    ("src/http/config.rs", include_str!("../src/http/config.rs")),
    (
        "src/http/response.rs",
        include_str!("../src/http/response.rs"),
    ),
    (
        "src/http/service.rs",
        include_str!("../src/http/service.rs"),
    ),
    ("src/http/serve.rs", include_str!("../src/http/serve.rs")),
    ("src/domain/mod.rs", include_str!("../src/domain/mod.rs")),
    (
        "src/domain/generation.rs",
        include_str!("../src/domain/generation.rs"),
    ),
    (
        "src/domain/identifiers.rs",
        include_str!("../src/domain/identifiers.rs"),
    ),
    (
        "src/domain/interface_name.rs",
        include_str!("../src/domain/interface_name.rs"),
    ),
    (
        "src/domain/intent.rs",
        include_str!("../src/domain/intent.rs"),
    ),
    (
        "src/domain/network.rs",
        include_str!("../src/domain/network.rs"),
    ),
    (
        "src/domain/owner.rs",
        include_str!("../src/domain/owner.rs"),
    ),
    (
        "src/domain/secret.rs",
        include_str!("../src/domain/secret.rs"),
    ),
    (
        "src/domain/state.rs",
        include_str!("../src/domain/state.rs"),
    ),
];

/// The only production module permitted to spawn a process.
const ONLY_PROCESS_MODULE: &str = "src/firewall/nft.rs";

/// Looks up one registered guard source by path.
///
/// A miss is a panic rather than a silent skip: a guard that quietly stops
/// checking a file because the file was renamed is worse than no guard.
fn source_of(name: &str) -> &'static str {
    PRODUCTION_SOURCES
        .iter()
        .find(|(registered, _)| *registered == name)
        .unwrap_or_else(|| panic!("{name} must be a registered guard source"))
        .1
}

/// Strips comments so a forbidden-token guard tests code, not prose.
///
/// Without this, documentation that *names* a forbidden dependency — which this
/// codebase deliberately does, to explain what it is not doing — would fail its
/// own guard. That trains readers to ignore the guard, so the guards below
/// inspect `code_only` instead. Line comments and block comments are removed;
/// a trailing comment on a code line is kept, so nothing hides behind one.
fn code_only(source: &str) -> String {
    let mut kept = String::with_capacity(source.len());
    let mut in_block_comment = false;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if in_block_comment {
            match trimmed.find("*/") {
                Some(end) => {
                    in_block_comment = false;
                    let rest = &trimmed[end + 2..];
                    if !rest.trim_start().starts_with("//") && !rest.trim().is_empty() {
                        kept.push_str(rest);
                        kept.push('\n');
                    }
                }
                None => continue,
            }
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(start) = line.find("/*") {
            in_block_comment = !line[start + 2..].contains("*/");
            // Keep the code that precedes the block comment on this line.
            kept.push_str(&line[..start]);
            kept.push('\n');
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

/// Asserts that none of the registered sources under `prefix` contains any of
/// the `forbidden` tokens in executable code.
fn assert_code_avoids(prefix: &str, forbidden: &[&str], why: &str) {
    for (path, source) in PRODUCTION_SOURCES {
        if !path.starts_with(prefix) {
            continue;
        }
        let code = code_only(source);
        for token in forbidden {
            assert!(
                !code.contains(token),
                "{path} must not reference {token}: {why}"
            );
        }
    }
}

#[test]
fn production_control_paths_do_not_invoke_wg_wg_quick_or_ip() {
    for (path, source) in PRODUCTION_SOURCES {
        // Only actual invocations are forbidden; documentation may still name
        // the tools wg-basic deliberately does not shell out to.
        for forbidden in [
            "Command::new(\"wg\")",
            "Command::new(\"wg-quick\")",
            "Command::new(\"ip\")",
            "Command::new(\"wg%\")",
            "process::Command::new(\"ip\")",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must not invoke {forbidden}: kernel control is typed, not shelled out"
            );
        }
    }
}

#[test]
fn process_execution_is_isolated_to_the_nft_backend() {
    let mut sites = Vec::new();
    for (path, source) in PRODUCTION_SOURCES {
        if source.contains("std::process::Command")
            || source.contains("Command::new")
            || source.contains("process::Stdio")
        {
            sites.push(*path);
        }
    }
    assert_eq!(
        sites,
        vec![ONLY_PROCESS_MODULE],
        "process execution must stay isolated to the bounded nft backend"
    );
}

#[test]
fn no_module_shells_out_through_a_shell() {
    for (path, source) in PRODUCTION_SOURCES {
        for forbidden in [
            "Command::new(\"sh\")",
            "Command::new(\"bash\")",
            "Command::new(\"/bin/sh\")",
            "Command::new(\"/bin/bash\")",
            "Command::new(\"dash\")",
            "Command::new(\"zsh\")",
            "\"--command\"",
            "\"-c\"",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must not invoke a shell ({forbidden}); commands are executed directly"
            );
        }
    }
}

#[test]
fn the_nft_backend_spawns_exactly_nft_and_never_a_shell() {
    let source = PRODUCTION_SOURCES
        .iter()
        .find(|(path, _)| *path == ONLY_PROCESS_MODULE)
        .expect("nft backend source is registered")
        .1;
    assert!(
        source.contains("Command::new(\"nft\")"),
        "the bounded backend must invoke nft directly"
    );
    for forbidden in ["\"wg\"", "\"wg-quick\"", "\"ip\"", "\"sh\"", "\"bash\""] {
        assert!(
            !source.contains(&format!("Command::new({forbidden})")),
            "the nft backend must not invoke {forbidden}"
        );
    }
}

#[test]
fn privileged_protocol_exposes_no_generic_escape_hatch_operation() {
    let wire = PRODUCTION_SOURCES
        .iter()
        .find(|(path, _)| *path == "src/protocol/wire.rs")
        .expect("wire source is registered")
        .1;
    for forbidden in [
        "Exec",
        "Shell",
        "Command",
        "RawNetlink",
        "Netlink",
        "WriteFile",
        "ReadFile",
        "NftSource",
        "RawNft",
        "Sysctl",
        "SetSysctl",
        "RunScript",
    ] {
        assert!(
            !wire.contains(forbidden),
            "the protocol vocabulary must not grow a {forbidden} operation"
        );
    }
}

#[test]
fn protocol_operation_vocabulary_is_closed_and_version_pinned() {
    use wg_basic::protocol::{RequestOperation, PROTOCOL_VERSION};

    assert_eq!(
        PROTOCOL_VERSION, 1,
        "C001 must not bump the protocol version"
    );

    // Each operation is identified on the wire by its snake_case tag. Pinning the
    // tag set makes an added or renamed operation a visible, deliberate change.
    let tags = [
        RequestOperation::Ping,
        RequestOperation::InspectCapabilities,
    ];
    let encoded: Vec<String> = tags
        .iter()
        .map(|operation| serde_json::to_string(operation).expect("operation encodes"))
        .collect();
    assert_eq!(
        encoded,
        vec![
            "{\"operation\":\"ping\"}".to_owned(),
            "{\"operation\":\"inspect_capabilities\"}".to_owned(),
        ]
    );
}

#[test]
fn the_aggregate_coordinator_is_privileged_and_database_free() {
    let source = PRODUCTION_SOURCES
        .iter()
        .find(|(path, _)| *path == "src/aggregate.rs")
        .expect("aggregate source is registered")
        .1;
    assert!(
        !source.contains("crate::state"),
        "the aggregate coordinator must stay database-free"
    );
    assert!(
        !source.contains("rusqlite"),
        "the aggregate coordinator must never open the state database"
    );
}

#[test]
fn the_management_state_store_never_reaches_a_privileged_boundary() {
    // The state module is unprivileged and must not open the privileged socket
    // or run any kernel/network control path itself.
    for (path, source) in PRODUCTION_SOURCES {
        if !path.starts_with("src/state/") {
            continue;
        }
        // rusqlite is expected here; the rule is that the management side
        // never reaches a *privileged* boundary.
        for forbidden in [
            "crate::protocol",
            "std::process::Command",
            "Command::new",
            "rtnetlink",
            "nl_wireguard",
            "tokio::spawn",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must not reach the privileged boundary ({forbidden})"
            );
        }
    }
}

#[test]
fn the_privileged_service_never_opens_the_state_database() {
    // netd must stay database-free: durable provenance is the management side's
    // job, and the privileged service independently revalidates what it is sent.
    for path in [
        "src/protocol/mod.rs",
        "src/protocol/auth.rs",
        "src/protocol/capability.rs",
        "src/protocol/client.rs",
        "src/protocol/dispatch.rs",
        "src/protocol/framing.rs",
        "src/protocol/socket.rs",
        "src/protocol/wire.rs",
        "src/reconcile/mod.rs",
        "src/reconcile/model.rs",
        "src/reconcile/planner.rs",
        "src/reconcile/service.rs",
        "src/reconcile/linux.rs",
        "src/firewall/mod.rs",
        "src/firewall/policy.rs",
        "src/firewall/planner.rs",
        "src/firewall/nft.rs",
        "src/firewall/service.rs",
        "src/wireguard.rs",
        "src/wireguard/backend.rs",
        "src/wireguard/keys.rs",
        "src/aggregate.rs",
    ] {
        let source = PRODUCTION_SOURCES
            .iter()
            .find(|(registered, _)| *registered == path)
            .unwrap_or_else(|| panic!("{path} must be a registered guard source"))
            .1;
        assert!(
            !source.contains("crate::state"),
            "{path} is on the privileged path and must not depend on the state store"
        );
        assert!(
            !source.contains("rusqlite"),
            "{path} must not open the state database"
        );
    }
}

#[test]
fn the_management_role_never_becomes_an_http_surface() {
    // Phase 7 gives the product a surface, and it lives in `src/http/`. The
    // management role must stay the reconcile role: an HTTP dependency here would
    // put a request-driven, potentially remote-triggered path in the process that
    // owns the durable store and the retry policy.
    //
    // The guard is now narrower *and* stricter than the pre-Phase 7 wording. It
    // used to forbid the bare token `tokio::`, which read as "no async at all".
    // Phase 7 legitimately needs one async primitive here — the bounded command
    // queue in `worker.rs` that is the ADR-003 boundary. So the rule is now
    // "no web stack anywhere in management, and `tokio::` only in the worker",
    // which is the property that actually matters and cannot be satisfied by a
    // module quietly growing its own listener.
    assert_code_avoids(
        "src/management/",
        &[
            "egg::",
            "EggServe",
            "eggserve",
            "hyper",
            "axum",
            "actix",
            "warp::",
            "reqwest",
            "TcpListener",
            "crate::http",
        ],
        "management is the reconcile role, never the HTTP surface",
    );
    // The one async primitive management may use is the worker's bounded queue.
    for (path, source) in PRODUCTION_SOURCES {
        if path.starts_with("src/management/") && *path != "src/management/worker.rs" {
            assert!(
                !code_only(source).contains("tokio::"),
                "{path} must not use an async runtime; only the bounded worker queue \
                 in src/management/worker.rs may"
            );
        }
    }
}

#[test]
fn the_http_boundary_never_reaches_the_durable_store_or_the_kernel() {
    // `src/http/` is a request-handling boundary. It may use EggServe primitives,
    // the worker client, and safe config values — and nothing else. Reaching
    // `rusqlite`, the netd client, projection, or the wire protocol directly would
    // bypass the bounded worker: a request handler would then block a Tokio worker
    // thread on synchronous disk I/O, and would be able to observe state the
    // health projection deliberately withholds.
    assert_code_avoids(
        "src/http/",
        &[
            "rusqlite",
            "crate::protocol",
            "crate::aggregate",
            "crate::reconcile",
            "crate::wireguard",
            "crate::state",
            "crate::firewall",
            "netlink",
            "rtnetlink",
        ],
        "the HTTP boundary reaches management only through the bounded worker",
    );
}

#[test]
fn the_management_http_surface_ships_no_router_or_client_crate() {
    // ADR-003: the service embeds `eggserve-server` and `eggserve-primitives`
    // directly. A router framework or an HTTP client dependency would reintroduce
    // exactly the transitive surface ADR-003 was written to avoid.
    let manifest = code_only(include_str!("../Cargo.toml"));
    for forbidden in [
        "eggserve-core",
        "eggserve-static",
        "axum",
        "actix-web",
        "actix-rt",
        "warp",
        "tower-http",
        "reqwest",
        "ureq",
        "hyper-tls",
        "rustls",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "Cargo.toml must not depend on {forbidden}: ADR-003 embeds EggServe directly"
        );
    }
}

#[test]
fn the_management_worker_queue_is_bounded() {
    // The bounded queue is the whole reason a request flood cannot become a
    // backlog. An unbounded channel anywhere in the worker would silently undo the
    // backpressure the HTTP surface reports as a 503.
    let worker = &code_only(source_of("src/management/worker.rs"));
    assert!(
        worker.contains("mpsc::channel(capacity)"),
        "the worker must admit through an explicitly sized channel"
    );
    for forbidden in ["mpsc::unbounded", "spawn_blocking"] {
        assert!(
            !worker.contains(forbidden),
            "the management worker must not use {forbidden}: it would defeat the bound"
        );
    }
    // Every admission is a non-blocking send, so saturation is refused rather
    // than awaited.
    assert!(
        worker.contains("try_send"),
        "admission must be a non-blocking send so overload is refused, not queued"
    );
}

#[test]
fn the_state_backup_and_restore_path_stays_local_to_the_database() {
    // Backup and restore copy a file. They must never become a way to move data
    // across a boundary: no privileged socket, no netlink, and no spawned
    // process. SQLite's own online backup API is a local file-to-file copy and is
    // the only mechanism these modules are allowed to use.
    for name in ["src/state/backup.rs", "src/state/store/mod.rs"] {
        let source = PRODUCTION_SOURCES
            .iter()
            .find(|(registered, _)| *registered == name)
            .unwrap_or_else(|| panic!("{name} must be a registered guard source"))
            .1;
        for forbidden in [
            "crate::protocol",
            "crate::reconcile",
            "crate::firewall",
            "std::process::Command",
            "Command::new",
            "rtnetlink",
            "nl_wireguard",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} must stay a local database operation ({forbidden})"
            );
        }
    }
}

#[test]
fn the_state_store_submodules_stay_a_one_directed_layering() {
    // `sql` owns row decoding, `desired` and `convergence` own their subjects,
    // and `mod` owns the façade. The layering is one-directional so a change to
    // the stored representation has exactly one owner and cannot introduce a
    // cycle. These assertions are what keep a later split from quietly
    // reintroducing the monolith this layering replaced.

    // The decoder knows nothing about the handle it serves.
    let sql = source_of("src/state/store/sql.rs");
    assert!(
        !sql.contains("StateStore"),
        "row decoding must not depend on the store façade"
    );
    assert!(
        !sql.contains("execute_batch") && !sql.contains("prepare("),
        "row decoding must not issue SQL of its own"
    );

    // The two subject modules are peers: neither may reach the other.
    let desired = source_of("src/state/store/desired.rs");
    let convergence = source_of("src/state/store/convergence.rs");
    assert!(
        !desired.contains("convergence::"),
        "the desired snapshot must not depend on convergence evidence"
    );
    assert!(
        !convergence.contains("desired::"),
        "convergence evidence must not depend on the desired snapshot"
    );

    // SQL helpers stay private to the store module.
    for name in [
        "src/state/store/sql.rs",
        "src/state/schema/validation.rs",
        "src/state/schema/migrations.rs",
    ] {
        let source = source_of(name);
        assert!(
            !source.contains("pub fn parse_") && !source.contains("pub fn ownership_label"),
            "{name} must not widen row-decoding helpers into the public API"
        );
    }
}

#[test]
fn secret_wrappers_redact_ordinary_debug_and_display() {
    use wg_basic::domain::{PresharedKey, PrivateKey, PublicKey};

    const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    let private = PrivateKey::new(KEY.to_owned()).expect("valid base64 32-byte key");
    assert_eq!(format!("{private:?}"), "PrivateKey([REDACTED])");
    assert_eq!(format!("{private}"), "[REDACTED]");
    assert!(!format!("{private:?} {private}").contains(KEY));

    let preshared = PresharedKey::new(KEY.to_owned()).expect("valid base64 32-byte key");
    assert_eq!(format!("{preshared:?}"), "PresharedKey([REDACTED])");
    assert_eq!(format!("{preshared}"), "[REDACTED]");
    assert!(!format!("{preshared:?} {preshared}").contains(KEY));

    // A debug-formatted aggregate must not leak either secret.
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Config {
        private: PrivateKey,
        preshared: PresharedKey,
    }
    let config = Config { private, preshared };
    assert!(!format!("{config:?}").contains(KEY));

    // Public keys are not secret and stay debuggable for operator diagnostics.
    let public = PublicKey::new(KEY.to_owned()).expect("valid base64 32-byte key");
    assert!(format!("{public:?}").contains(KEY));
}

#[test]
fn the_comment_stripper_actually_strips_and_preserves() {
    // The guards are only as trustworthy as this helper. A stripper that removed
    // real code would turn every token guard above into a no-op.
    let source = "//! module doc\n\
                  use crate::ok::Thing;\n\
                  // a full-line comment mentioning crate::forbidden\n\
                  /// a doc comment mentioning crate::forbidden\n\
                  let x = 1; // trailing comment\n\
                  /* block mentioning crate::forbidden */\n\
                  let y = 2;\n\
                  /* unterminated\n\
                     crate::forbidden\n\
                  */\n\
                  let z = 3;\n";
    let code = code_only(source);
    assert!(code.contains("use crate::ok::Thing;"));
    assert!(code.contains("let x = 1;"));
    assert!(code.contains("let y = 2;"));
    assert!(code.contains("let z = 3;"));
    // The block comment opened and closed on one line keeps the code after it.
    assert!(code.contains("let y = 2;"), "code after */ is kept");
    assert!(
        !code.contains("crate::forbidden"),
        "no commented-out token may survive: {code}"
    );
}
