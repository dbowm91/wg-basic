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
    // Phase 7 adds a surface. Until it does, management is a reconcile role, and
    // the one thing it must not quietly grow is a web stack: an HTTP dependency
    // here would put a request-driven, potentially remote-triggered path in the
    // process that owns the durable store and the retry policy.
    for (path, source) in PRODUCTION_SOURCES {
        if !path.starts_with("src/management/") {
            continue;
        }
        for forbidden in [
            "egg::",
            "EggServe",
            "hyper",
            "axum",
            "actix",
            "warp::",
            "reqwest",
            "tokio::",
            "TcpListener",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} must not import an HTTP or async server surface ({forbidden})"
            );
        }
    }
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
    let source_of = |name: &str| -> &str {
        PRODUCTION_SOURCES
            .iter()
            .find(|(registered, _)| *registered == name)
            .unwrap_or_else(|| panic!("{name} must be a registered guard source"))
            .1
    };

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
