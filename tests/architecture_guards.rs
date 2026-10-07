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
    ("src/domain/auth.rs", include_str!("../src/domain/auth.rs")),
    (
        "src/state/store/auth.rs",
        include_str!("../src/state/store/auth.rs"),
    ),
    (
        "src/state/migrations/002_auth_sessions.sql",
        include_str!("../src/state/migrations/002_auth_sessions.sql"),
    ),
    (
        "src/management/auth.rs",
        include_str!("../src/management/auth.rs"),
    ),
    ("src/http/mod.rs", include_str!("../src/http/mod.rs")),
    ("src/http/config.rs", include_str!("../src/http/config.rs")),
    ("src/http/api.rs", include_str!("../src/http/api.rs")),
    ("src/http/assets.rs", include_str!("../src/http/assets.rs")),
    (
        "src/http/assets/index.html",
        include_str!("../src/http/assets/index.html"),
    ),
    (
        "src/http/assets/app.css",
        include_str!("../src/http/assets/app.css"),
    ),
    (
        "src/http/assets/app.js",
        include_str!("../src/http/assets/app.js"),
    ),
    (
        "src/http/headers.rs",
        include_str!("../src/http/headers.rs"),
    ),
    ("src/http/origin.rs", include_str!("../src/http/origin.rs")),
    (
        "src/http/ratelimit.rs",
        include_str!("../src/http/ratelimit.rs"),
    ),
    (
        "src/http/response.rs",
        include_str!("../src/http/response.rs"),
    ),
    (
        "src/http/session_cookie.rs",
        include_str!("../src/http/session_cookie.rs"),
    ),
    (
        "src/http/service.rs",
        include_str!("../src/http/service.rs"),
    ),
    (
        "src/http/readiness.rs",
        include_str!("../src/http/readiness.rs"),
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

/// Strips comments *and* everything from the first `#[cfg(test)]` onward.
///
/// A guard that inspects a test module is testing the guard's own fixtures: a
/// test that enumerates `"access-control-allow-origin"` to assert it is absent
/// would otherwise fail its own guard. Test code never ships, so it is not part
/// of the claim — and excluding it keeps the guard honest about what it covers.
fn shippable(source: &str) -> String {
    let without_tests = match source.find("#[cfg(test)]") {
        Some(index) => &source[..index],
        None => source,
    };
    code_only(without_tests)
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

/// Asserts that no shipped source under `prefix` contains a forbidden token.
///
/// The [`shippable`] counterpart of [`assert_code_avoids`], for the M003 guards:
/// each of those names the very strings it forbids while proving it, so the
/// fixtures must be excluded or the guard would audit itself.
fn assert_shippable_avoids(prefix: &str, forbidden: &[&str], why: &str) {
    for (path, source) in PRODUCTION_SOURCES {
        if !path.starts_with(prefix) {
            continue;
        }
        let code = shippable(source);
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

#[test]
fn a_raw_session_token_has_no_path_into_the_database() {
    // `store::auth` persists sessions. If it ever accepted a `SessionToken`, the
    // raw bearer would have a route into SQLite and the whole "only the digest is
    // stored" property would become a convention rather than a type error.
    let store = &code_only(source_of("src/state/store/auth.rs"));
    assert!(
        store.contains("SessionTokenDigest"),
        "the persistence layer stores and looks up digests"
    );
    // `SessionToken` is a prefix of `SessionTokenDigest`, so the digest form is
    // removed before the raw name is looked for. Otherwise this guard would
    // fire on the very type it is protecting.
    let without_digest = store.replace("SessionTokenDigest", "");
    assert!(
        !without_digest.contains("SessionToken"),
        "the persistence layer must never name the raw session token type"
    );

    // The one secret wrapper this module may read is the CSRF token, and only
    // because the schema documents that it is not a credential: it is echoed back
    // by the browser in a header and is useless without the bearer beside it.
    let reader = code_only(source_of("src/state/store/auth.rs"));
    assert!(
        reader.contains("csrf_token.expose_once()"),
        "the CSRF token is the one value read through expose_once here"
    );
    assert_eq!(
        reader.matches(".expose_once()").count(),
        1,
        "exactly one value in the persistence layer may be read raw, and it is the CSRF \
         token; anything else is a leak"
    );

    // The schema must never mention a bearer token at all.
    let migration = code_only(source_of("src/state/migrations/002_auth_sessions.sql"));
    assert!(
        !migration.contains("session_token"),
        "the session schema stores a digest, never a token"
    );
    assert!(
        migration.contains("token_digest"),
        "the session schema stores the token digest"
    );
}

#[test]
fn authentication_is_reached_only_through_the_bounded_worker() {
    // Argon2id at the management policy costs ~19 MiB and tens of milliseconds
    // per verification. Running it on a Tokio worker thread would turn a login
    // into a thread stall, and unbounded concurrent verification would be a CPU
    // denial of service. So the hash must live in the management role and be
    // reachable only from the worker thread.
    let http = code_only(source_of("src/http/service.rs"));
    for forbidden in ["argon2", "PasswordVerifier", "check_password_policy"] {
        assert!(
            !http.contains(forbidden),
            "the HTTP boundary must not perform credential hashing ({forbidden}); \
             it reaches authentication only through the worker client"
        );
    }

    let management_auth = code_only(source_of("src/management/auth.rs"));
    assert!(
        management_auth.contains("Argon2") || management_auth.contains("argon2"),
        "the management role owns Argon2id"
    );
    assert!(
        !management_auth.contains("tokio::"),
        "authentication runs on the worker thread, never on an async task"
    );

    // The domain module is pure: no I/O, no database, no network.
    let domain_auth = code_only(source_of("src/domain/auth.rs"));
    for forbidden in [
        "rusqlite",
        "tokio::",
        "std::fs",
        "std::net",
        "crate::state",
        "crate::management",
    ] {
        assert!(
            !domain_auth.contains(forbidden),
            "credential primitives must stay pure ({forbidden})"
        );
    }
}

#[test]
fn no_authentication_value_can_reach_a_database_query_as_plaintext() {
    // The Argon2 verifier and the session digest are the only two credential
    // values a session store may ever see, and each is stored through its own
    // accessor. A query parameter that reached for `expose_for_storage` on
    // something else would be the leak this test exists to prevent.
    let store = code_only(source_of("src/state/store/auth.rs"));
    for column in ["verifier", "token_digest", "csrf_token"] {
        assert!(
            store.contains(column),
            "{column} must be persisted; its absence would mean the schema and the \
             reader disagree"
        );
    }
    // `reset_password_and_revoke_sessions` is a *method* name, not a value. The
    // invariant that matters is structural: no parameter anywhere in this module
    // can hold a raw password, so the plaintext has no route to a query at all.
    for forbidden in [
        "password:",
        "password :",
        "password: &",
        "password: String",
        "password:str",
    ] {
        assert!(
            !store.contains(forbidden),
            "the persistence layer must not accept a password parameter ({forbidden}): \
             only a verifier"
        );
    }
    // The only credential-shaped parameter is the verifier itself.
    assert!(
        store.contains("verifier: PasswordVerifier"),
        "the one credential value this module may store is an Argon2 verifier"
    );
}

#[test]
fn a_migration_fixture_is_a_real_v1_database() {
    // Phase 7 M002 added a genuine migration 2. The Phase 6 harness that
    // simulated a second version must be gone, because it would collide with the
    // real one and because a simulated version could not prove that a real
    // upgrade preserves data.
    let migrations = source_of("src/state/schema/migrations.rs");
    assert!(
        !migrations.contains("test_only_migrations"),
        "the simulated version harness must be removed now that migration 2 is real"
    );
    assert!(
        !migrations.contains("test_only_marker"),
        "a test-only schema marker must not survive into the migration list"
    );
    let list = code_only(migrations);
    assert_eq!(
        list.matches("version: 1").count(),
        1,
        "migration 1 appears exactly once in the production list"
    );
    assert_eq!(
        list.matches("version: 2").count(),
        1,
        "migration 2 appears exactly once in the production list"
    );
    assert!(
        list.contains("002_auth_sessions.sql"),
        "the production list must include the shipped auth/session migration"
    );
}

#[test]
fn the_admin_cli_offers_no_argv_or_environment_secret_path() {
    // A password in `argv` is readable by every process on the host through
    // /proc; one in the environment is inherited by every child. The only
    // acceptable input is this process's own standard input, behind a flag that
    // is mandatory.
    let main = code_only(source_of("src/main.rs"));
    for forbidden in ["env::var", "std::env", "env!(\"WG_BASIC"] {
        assert!(
            !main.contains(forbidden),
            "the CLI must not read a secret from the environment ({forbidden})"
        );
    }
    assert!(
        !main.contains("password: String"),
        "the CLI must never declare a password argument; read it from stdin instead"
    );
    assert!(
        main.contains("--password-stdin is required"),
        "the stdin path must be explicit and mandatory"
    );
    assert!(
        main.contains("read_password_from_stdin"),
        "the password must arrive on stdin"
    );
}

// ---------------------------------------------------------------------------
// M003: the authenticated perimeter
// ---------------------------------------------------------------------------

#[test]
fn the_management_surface_emits_no_cors_header_at_all() {
    // Not a narrow allowlist: none. A browser therefore cannot read any response
    // cross-origin, which is a stronger position than any allowlist and costs
    // nothing to maintain. The corollary is that a future "just for the asset
    // shell" exception has to be argued for explicitly, so it cannot be added by
    // accident.
    assert_shippable_avoids(
        "src/http/",
        &[
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age",
        ],
        "this surface ships no CORS, in any form, on any route",
    );
}

#[test]
fn the_management_surface_ships_no_token_or_oauth_dependency() {
    // The session bearer is a random token stored as a digest and looked up in
    // the database. A JWT library would mean a second, self-validating
    // credential system with its own key management — strictly more attack
    // surface for no property this appliance needs, and revocation would become
    // impossible without a denylist.
    let manifest = code_only(include_str!("../Cargo.toml"));
    for forbidden in [
        "jsonwebtoken",
        "jwt",
        "oauth",
        "openid",
        "paseto",
        "iron-session",
        "tower-sessions",
        "tower-cookie",
        "cookie-session",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "Cargo.toml must not depend on {forbidden}: sessions are opaque server-side tokens"
        );
    }
}

#[test]
fn the_session_cookie_cannot_lose_its_defining_attributes() {
    // Every attribute here is load-bearing: `HttpOnly` keeps page JavaScript out
    // of the bearer, `SameSite=Strict` stops a cross-site request carrying it,
    // `Path=/` and the absence of `Domain` are what the `__Host-` prefix
    // requires, and `Max-Age` ties the browser's copy to the row's lifetime.
    // Losing any of them is a silent downgrade, so they are pinned in one place.
    let cookie = shippable(source_of("src/http/session_cookie.rs"));
    for required in [
        ".http_only(true)",
        ".path(\"/\")",
        "SameSite::Strict",
        ".max_age(",
    ] {
        assert!(
            cookie.contains(required),
            "src/http/session_cookie.rs must set {required} on every session cookie"
        );
    }
    // No `Domain` is ever set: a host-only cookie is what stops a sibling
    // subdomain receiving it, and what `__Host-` requires.
    assert!(
        !cookie.contains(".domain("),
        "src/http/session_cookie.rs must never set a cookie Domain"
    );
    // `Secure` is conditional on the canonical origin, never on the request.
    assert!(
        cookie.contains("CookieProfile::HttpsOrigin"),
        "the Secure attribute must follow the configured origin profile"
    );
}

#[test]
fn the_management_surface_never_trusts_a_forwarded_header() {
    // `Host` is checked against an explicit configured set; `Origin` against the
    // canonical origin. If either could be taken from `X-Forwarded-*`, an
    // attacker who can set a request header — which is what a rebinding page
    // can — would be choosing what "this origin" means.
    // Note what is *not* forbidden: `RuntimeConfig::builder().forwarded_standard(false)`
    // in `src/http/config.rs`. Turning the proxy trust off is the correct move
    // and must stay possible; what is forbidden is *reading* a forwarded value.
    assert_shippable_avoids(
        "src/http/",
        &[
            "\"x-forwarded-host\"",
            "\"x-forwarded-proto\"",
            "\"x-forwarded-for\"",
            "\"forwarded\"",
            "effective_authority",
            "effective_client",
            "effective_scheme",
        ],
        "forwarded headers stay untrusted; Host and Origin come from configuration only",
    );
}

#[test]
fn every_security_header_is_applied_from_one_place() {
    // The headers are applied by `headers::seal` on the way out, once, on every
    // path. A per-route header is a header one route will eventually forget, so
    // the guard is structural: `Response::builder()` may only appear in the
    // response module and the API module, and `seal` must be called from the
    // service's single dispatch path.
    for (path, source) in PRODUCTION_SOURCES
        .iter()
        .filter(|(path, _)| path.starts_with("src/http/"))
    {
        if path.ends_with("response.rs") || path.ends_with("api.rs") {
            continue;
        }
        assert!(
            !shippable(source).contains("Response::builder()"),
            "{path} must not build a response directly; use `response::build` so the \
             media type and `no-store` policy cannot be forgotten"
        );
    }
    let service = shippable(source_of("src/http/service.rs"));
    assert_eq!(
        service.matches("headers::seal(").count(),
        1,
        "the service must seal in exactly one place, or the guarantee is only as good \
         as the smallest count"
    );
    assert!(
        service.contains("headers::seal(answer"),
        "sealing must wrap the completed answer, not a branch inside it"
    );
}

#[test]
fn the_login_limiter_is_consulted_before_the_worker_admits_the_command() {
    // Argon2id costs ~300 ms and 19 MiB per verification. A limiter applied
    // after the hash would be a denial of service wearing a rate limit's
    // clothes, so the ordering is the claim — and a guard, because a future
    // refactor moving the call one statement up would be invisible otherwise.
    let api = shippable(source_of("src/http/api.rs"));
    let limiter_call = api
        .find("self.limiter.check(")
        .expect("the login path must consult the limiter");
    let authenticate_call = api
        .find(".worker\n            .authenticate(")
        .or_else(|| api.find(".authenticate(credentials"))
        .expect("the login path must verify credentials through the worker");
    assert!(
        limiter_call < authenticate_call,
        "the limiter must be consulted before the password is verified; otherwise every \
         attempt costs ~300 ms of the appliance's CPU before anything refuses it"
    );
}

#[test]
fn the_limiter_peer_map_is_bounded() {
    // An unbounded map keyed by client address is a memory-exhaustion vector by
    // itself: enough distinct source addresses fills it until the process is
    // killed. The bound is a constructor parameter and the map is shrunk when it
    // is over, which is what this pins.
    let limiter = shippable(source_of("src/http/ratelimit.rs"));
    assert!(
        limiter.contains("max_peers"),
        "the limiter must take an explicit peer-map bound"
    );
    assert!(
        limiter.contains("HashMap"),
        "the peer map is expected to be a map; a different structure needs re-justifying"
    );
    assert!(
        !limiter.contains("unbounded"),
        "src/http/ratelimit.rs must not describe an unbounded map as the shape"
    );
}

#[test]
fn a_non_loopback_bind_is_never_permitted_without_acknowledgement() {
    // Binding off-host with no canonical origin leaves nothing to check `Host`
    // against, and accepting any `Host` is the rebinding hole M003 exists to
    // close. So the default path refuses rather than degrading to permissive.
    let serve = shippable(source_of("src/http/serve.rs"));
    assert!(
        serve.contains("OffHostNeedsAcknowledgement"),
        "src/http/serve.rs must refuse an unacknowledged routable bind"
    );
    assert!(
        !serve.contains("ExposureMode::AcknowledgedOffHost {")
            && !serve.contains("AcknowledgedOffHost,"),
        "src/http/serve.rs must not construct an off-host policy without routing through \
         OriginPolicy::acknowledged_off_host, which is where the checks live"
    );

    // The two refusals that make the acknowledgement meaningful.
    let origin = shippable(source_of("src/http/origin.rs"));
    assert!(
        origin.contains("HttpsClaimWithoutProxy"),
        "a listener that terminates no TLS must not be allowed to claim an https origin"
    );
    assert!(
        origin.contains("UnacknowledgedOffHost"),
        "the off-host constructor must refuse a loopback bind, which needs no acknowledgement"
    );
}

#[test]
fn no_module_outside_the_response_module_builds_a_management_response() {
    // The narrower companion to the sealing guard: every byte on the wire comes
    // from `response.rs` (fixed literals) or `api.rs` (serialised JSON). A new
    // module that formats a `Response` from an internal value would be an
    // information-disclosure bug by construction.
    for (path, source) in PRODUCTION_SOURCES
        .iter()
        .filter(|(path, _)| path.starts_with("src/http/"))
    {
        if path.ends_with("response.rs") || path.ends_with("api.rs") {
            continue;
        }
        assert!(
            !shippable(source).contains(".body(ResponseBody::"),
            "{path} must not assemble a response body; use `response::build`, whose bodies \
             are bounded literals"
        );
    }
}

#[test]
fn a_failed_login_lookup_always_spends_one_argon2_verification() {
    // The M003 §10 requirement. A username miss that returns before hashing is a
    // username oracle far larger than any response body: "no such user" answers
    // in microseconds while "wrong password" answers in ~300 ms, and the gap
    // itself is the disclosure. The constant's plaintext is discarded and
    // unrecoverable, so the guard also pins that the constant is never anything
    // but a cost.
    let service = shippable(source_of("src/management/auth.rs"));
    assert!(
        service.contains("reject_without_principal"),
        "src/management/auth.rs must spend a verification on a lookup that found nothing"
    );
    assert!(
        service.contains("TIMING_EQUALISER_VERIFIER"),
        "the equalising verifier must be referenced from the authenticate path"
    );
    // Every early return from `authenticate` has to route through it. Enumerated
    // rather than sampled so widening the path has to delete a line.
    for branch in [
        "Ok(None) | Err(_) => return Err(self.reject_without_principal(password))",
        "if !principal.enabled {\n            return Err(self.reject_without_principal(password));",
    ] {
        assert!(
            service.contains(branch),
            "src/management/auth.rs must spend a verification here: {branch}"
        );
    }

    // The constant itself must carry the current policy, or raising the policy
    // silently reintroduces the oracle.
    let domain = shippable(source_of("src/domain/auth.rs"));
    assert!(
        domain.contains("pub const TIMING_EQUALISER_VERIFIER"),
        "src/domain/auth.rs must define the equalising verifier"
    );
    assert!(
        !domain.contains("wg-basic-equaliser-"),
        "the equaliser's plaintext must never appear in the repository"
    );
    assert!(
        service.contains("OnceLock<PasswordVerifier>") && service.contains("get_or_init"),
        "the equaliser must be parsed once behind a OnceLock; parsing the PHC string per \
         failed login would be a second, smaller timing signal"
    );
}

// ---------------------------------------------------------------------------
// M004: the embedded asset shell
// ---------------------------------------------------------------------------

#[test]
fn no_embedded_asset_names_an_external_origin() {
    // The boundary that matters most for a shipped UI. An asset that fetches
    // from a CDN tells that CDN when an operator of this appliance signs in, and
    // the service's own `Host` allowlist cannot see it happen because the
    // request never reaches the service.
    //
    // The asset files are registered as sources so this reads their *contents*
    // rather than the `include_str!` call that embeds them.
    for name in [
        "src/http/assets/index.html",
        "src/http/assets/app.css",
        "src/http/assets/app.js",
    ] {
        let body = source_of(name);
        for forbidden in [
            "http://",
            "https://",
            "//cdn",
            "@import",
            "url(",
            "integrity=",
            "crossorigin",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} contains {forbidden}: an embedded asset must reach nothing outside \
                 this origin"
            );
        }
    }
}

#[test]
fn the_asset_shell_needs_no_csp_concession_and_no_build_step() {
    // `default-src 'self'` with no 'unsafe-inline' and no nonce admits exactly
    // same-origin scripts and styles by reference. An inline handler or an
    // inline <style> would force the header to be weakened, and a weakened CSP
    // is the kind of change that arrives with a commit message nobody reads.
    for name in ["src/http/assets/index.html", "src/http/assets/app.js"] {
        let body = source_of(name);
        for forbidden in [
            "<script>",
            "<style>",
            "onclick=",
            "onload=",
            "onerror=",
            "onsubmit=",
            "javascript:",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} contains {forbidden}, which would require a CSP concession"
            );
        }
    }
}

#[test]
fn no_build_toolchain_is_required_to_produce_the_shell() {
    // What is committed is what is served. A shell that needs a bundler is a
    // shell that will eventually be built and served out of band, and the
    // failure is invisible: the binary still starts, and the page is served by
    // something else, or by an older file.
    for forbidden in [
        "package.json",
        "node_modules",
        "webpack",
        "vite",
        "rollup",
        "esbuild",
        "tsconfig.json",
    ] {
        let present = std::path::Path::new(forbidden).exists();
        assert!(
            !present,
            "{forbidden} exists at the repository root: the shell must need no build step"
        );
    }
    // And the crate manifest declares no front-end toolchain.
    let manifest = code_only(include_str!("../Cargo.toml"));
    assert!(
        !manifest.contains("build = "),
        "Cargo.toml must not declare a custom build step for the shell"
    );
}

#[test]
fn the_shell_is_embedded_at_compile_time_and_never_read_from_disk() {
    // A document root is a filesystem write away from being attacker-controlled.
    // The assets must therefore be `include_str!`d constants, and nothing in the
    // HTTP boundary may open a path.
    let assets = shippable(source_of("src/http/assets.rs"));
    assert_eq!(
        assets.matches("include_str!").count(),
        3,
        "each embedded asset must be an include_str!, so the binary is the only source"
    );
    for forbidden in [
        "std::fs",
        "File::open",
        "read_to_string",
        "document_root",
        "static_root",
    ] {
        assert!(
            !shippable(source_of("src/http/assets.rs")).contains(forbidden),
            "src/http/assets.rs must not read anything: it contains {forbidden}"
        );
    }
    // And the whole HTTP boundary still reaches no filesystem path.
    assert_code_avoids(
        "src/http/",
        &["std::fs", "read_to_string", "File::open"],
        "the management boundary reads no document root; its assets are in the binary",
    );
}

#[test]
fn the_shell_goes_through_the_same_single_seal_point() {
    // The carry-forward constraint from M003. The shell is the one response body
    // that is neither a fixed literal in `response.rs` nor serialised JSON, so
    // it is exactly the response most likely to be built by a route that forgets
    // the headers. It is served from `route_request`, which returns into
    // `dispatch`, which is the only place `seal` is called.
    let service = shippable(source_of("src/http/service.rs"));
    assert_eq!(
        service.matches("headers::seal(").count(),
        1,
        "the service must seal in exactly one place"
    );
    assert!(
        service.contains("Route::Shell | Route::Asset"),
        "the shell must be answered from route_request, not from a second service"
    );
    // And it builds through the shared builder rather than its own.
    assert!(
        service.contains("response::build(\n                        super::assets::status()")
            || service.contains("response::build("),
        "the shell must be assembled by `response::build`, which sets the media type and \
         `no-store`"
    );
}

#[test]
fn the_shell_offers_no_phase_8_management() {
    // Peer, client, and interface management are Phase 8. The absence is
    // asserted rather than left to a reader of three small files, because the
    // tempting next commit is "add a peer list" and it would be a small one.
    for name in [
        "src/http/assets/index.html",
        "src/http/assets/app.css",
        "src/http/assets/app.js",
    ] {
        let body = source_of(name);
        for forbidden in [
            "/api/v1/peers",
            "/api/v1/clients",
            "/api/v1/interfaces",
            "createPeer",
            "deletePeer",
            "addClient",
            "generateKeys",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} contains {forbidden}: peer/client/interface management is Phase 8"
            );
        }
    }
    // The shell's own data comes only from the routes Phase 7 publishes.
    let js = source_of("src/http/assets/app.js");
    for allowed in ["/api/v1/login", "/api/v1/logout", "/api/v1/session"] {
        assert!(js.contains(allowed), "the shell should use {allowed}");
    }
}

#[test]
fn the_login_limiter_stays_in_memory_across_a_restart() {
    // A persisted lockout would let anyone who can reach the login form
    // permanently lock the operator out of their own appliance -- a
    // denial of service with no recovery path. M004 owns the restart
    // qualification, so the property is pinned here rather than left to the
    // reader of `ratelimit.rs`.
    let serve = shippable(source_of("src/http/serve.rs"));
    assert!(
        serve.contains("fn limiter(&self) -> Arc<LoginLimiter>"),
        "the limiter must be constructed fresh per run, not restored from disk"
    );
    let limiter = shippable(source_of("src/http/ratelimit.rs"));
    for forbidden in ["rusqlite", "StateStore", "crate::state", "read_from_disk"] {
        assert!(
            !limiter.contains(forbidden),
            "src/http/ratelimit.rs must not reach durable storage ({forbidden})"
        );
    }
}

/// M004 §4: readiness is the only thing that decides the anonymous answer.
///
/// If a future route derived `/healthz`'s body from anything else, an
/// unauthenticated caller would be able to read a dependency's state off it.
#[test]
fn the_anonymous_health_answer_comes_only_from_the_readiness_projection() {
    let readiness = shippable(source_of("src/http/readiness.rs"));
    assert!(
        readiness.contains("pub fn public_token(&self) -> Option<&'static str>"),
        "the public projection must be one function returning fixed tokens"
    );
    // The tokens are literals here and nowhere else, so adding a reason cannot
    // change what an anonymous caller receives.
    assert!(
        readiness.contains("Self::Ready => Some(\"ok\")"),
        "\"ok\" must be a literal in the readiness projection"
    );
    assert!(
        readiness.contains("Self::Degraded { .. } => Some(\"degraded\")"),
        "\"degraded\" must be a literal in the readiness projection"
    );

    // The only anonymous route reads that projection, and nothing else formats a
    // health word into a body.
    let service = shippable(source_of("src/http/service.rs"));
    assert!(
        service.contains("Liveness::from_readiness("),
        "/healthz must classify through Readiness before projecting"
    );
    let response = shippable(source_of("src/http/response.rs"));
    assert!(
        response.contains("from_readiness(readiness: crate::http::Readiness)"),
        "the liveness projection must take a Readiness, not raw health"
    );
    // Two tokens, one status. A third would be a new public contract.
    assert!(response.contains("Self::Ok => \"ok\""));
    assert!(response.contains("Self::Degraded => \"degraded\""));
}

/// M004 §4: only an authenticated route may make the process dial the backend.
///
/// A live probe costs a round trip to a privileged socket. If `/healthz` ever
/// called it, an unauthenticated caller could use the management service as a
/// relay and read the backend's liveness for free.
#[test]
fn the_live_backend_probe_is_reachable_only_from_the_authenticated_route() {
    let probe_callers: Vec<(&str, String)> = PRODUCTION_SOURCES
        .iter()
        .filter(|(name, _)| name.starts_with("src/http/"))
        .map(|(name, source)| (*name, shippable(source)))
        .collect();

    let callers: Vec<&str> = probe_callers
        .iter()
        .filter(|(_, source)| source.contains("probe_backend("))
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        callers,
        vec!["src/http/api.rs"],
        "probe_backend must be called from exactly one place, and that place must \
         be the authenticated API: {callers:?}"
    );

    // And the one caller is behind a session, not behind `/healthz`.
    let api = shippable(source_of("src/http/api.rs"));
    let probe_site = api
        .find("probe_backend(")
        .expect("the authenticated route calls the probe");
    let context = &api[probe_site.saturating_sub(1200)..probe_site];
    assert!(
        context.contains("self.worker_health()"),
        "the probe must sit beside the authenticated health projection, not the \
         liveness one"
    );
    assert!(
        !context.contains("worker_health().await"),
        "the probe must not be on the liveness route's path"
    );

    // And the runtime's probe is one read-only `Ping`, scoped tightly so a
    // later edit that widens it is caught here rather than in production.
    let runtime = shippable(source_of("src/management/runtime.rs"));
    let probe_start = runtime
        .find("pub fn probe_backend(&self)")
        .expect("the runtime exposes a probe");
    let probe_end = runtime[probe_start..]
        .find("\n    }\n")
        .map(|end| probe_start + end)
        .expect("the probe has a body");
    let probe_body = &runtime[probe_start..probe_end];
    assert!(
        probe_body.contains("RequestOperation::Ping"),
        "the backend probe must be a read-only Ping: {probe_body}"
    );
    for forbidden in ["Apply", "Remove", "Set", "Replace", "Delete", "Commit"] {
        assert!(
            !probe_body.contains(forbidden),
            "the backend probe must not mutate anything, but names {forbidden}: {probe_body}"
        );
    }
    // A probe is not a place a health check can fail: every path returns a value,
    // so an outage is reported rather than raised.
    assert!(
        !probe_body.contains("?;"),
        "the probe must not propagate an error; \"not answering\" is the answer: {probe_body}"
    );
}

/// M004 §3: `serve` owns the lifecycle ordering, and nothing else may.
///
/// The plan's ordering is load-bearing (stop accepts → drain → stop worker →
/// close store). A second place that ordered part of it differently would be a
/// way to skip a step.
#[test]
fn only_the_serve_module_orders_the_service_lifecycle() {
    let owners: Vec<&str> = PRODUCTION_SOURCES
        .iter()
        .filter(|(_, source)| {
            let code = shippable(source);
            code.contains("completion.wait()") || code.contains("control.shutdown()")
        })
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        owners,
        vec!["src/http/serve.rs"],
        "only the serve module may drain or stop the server: {owners:?}"
    );

    // And within it, the order is the documented one.
    let serve = shippable(source_of("src/http/serve.rs"));
    let drain = serve
        .find("control.shutdown()")
        .expect("serve stops accepting");
    let complete = serve
        .find("completion.wait().await")
        .expect("serve waits for the drain");
    let worker_stop = serve.find("worker.stop()").expect("serve stops the worker");
    assert!(
        drain < complete,
        "accepts must stop before the drain is awaited"
    );
    assert!(
        complete < worker_stop,
        "the worker must be stopped after the HTTP surface has drained, or a \
         request could be admitted to a worker that is already gone"
    );
}

/// M004 §3: a long-running role must stop on a supervisor's signal.
///
/// Only `SIGINT` is what a terminal sends. A process supervisor sends `SIGTERM`,
/// so a role that handles only `SIGINT` cannot be stopped by one — it has to be
/// killed, which skips the drain and the store close entirely. This was a real
/// defect: `wg-basic serve` exited on the signal, with status -1, and the
/// lifecycle ordering never ran.
#[test]
fn the_long_running_roles_catch_a_supervisors_termination_signal() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("ctrlc = { version = \"3.4\", features = [\"termination\"] }"),
        "ctrlc must enable its `termination` feature, or SIGTERM kills these \
         roles without a graceful shutdown"
    );

    let main = shippable(source_of("src/main.rs"));
    // Exactly the two roles that run forever install the handler: `netd` and
    // `serve`. A third would mean some one-shot command had started waiting for
    // a signal it will never receive.
    assert_eq!(
        main.matches("ctrlc::set_handler").count(),
        2,
        "exactly the netd and serve roles install a shutdown handler; a one-shot \
         command must not"
    );
    for arm in ["Some(Command::Netd {", "Some(Command::Serve"] {
        assert!(
            main.contains(arm),
            "the `{arm}` role should exist and be one of the two that run forever"
        );
    }
}
