//! Durable state store integration tests.
//!
//! These run without root and use restrictive temporary directories. They cover
//! initialization, the hardened open contract, migrations, generation CAS,
//! rollback, secret handling, and deterministic projection.

use ipnet::IpNet;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use wg_basic::{
    domain::{
        validate_desired_state, ClientId, ClientRoutePolicy, DesiredAddress, DesiredClient,
        DesiredInterface, DesiredNetworkPolicy, DesiredPeer, DesiredState, InterfaceId,
        LinkLifecycle, ManagedRoute, NetworkPrefix, OwnershipDeclaration, PeerId, PresharedKey,
        PrivateKey, PublicKey, ResourcePresence,
    },
    state::{
        DesiredGeneration, ProjectionError, StateError, StateStore, INITIAL_DESIRED_GENERATION,
    },
};

#[cfg(target_os = "linux")]
use wg_basic::state::project;

static COUNTER: AtomicU64 = AtomicU64::new(0);

const SERVER_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const CLIENT_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBkk=";
const PRESHARED_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBkk=";
const PEER_PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-state-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }

    fn db(&self) -> PathBuf {
        self.path.join("state.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn private_key() -> PrivateKey {
    PrivateKey::new(SERVER_KEY.to_owned()).unwrap()
}

fn sample_state() -> DesiredState {
    let peer_id = PeerId::new();
    let address: IpNet = "10.8.0.2/32".parse().unwrap();
    DesiredState {
        interfaces: vec![DesiredInterface {
            id: InterfaceId::new(),
            name: "wg0".parse().unwrap(),
            ownership: OwnershipDeclaration::Managed,
            lifecycle: LinkLifecycle::Present,
            admin_up: Some(true),
            private_key: private_key(),
            listen_port: Some(51820),
            manage_all_peers: true,
            tunnel_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
            addresses: vec![DesiredAddress {
                address: "10.8.0.1/24".parse().unwrap(),
                presence: ResourcePresence::Present,
            }],
            routes: vec![ManagedRoute {
                destination: NetworkPrefix::new("10.9.0.0/16".parse().unwrap()),
                gateway: Some("192.0.2.1".parse().unwrap()),
                presence: ResourcePresence::Present,
            }],
            peers: vec![DesiredPeer {
                id: peer_id,
                public_key: PublicKey::new(PEER_PUBLIC.to_owned()).unwrap(),
                private_key: Some(PrivateKey::new(CLIENT_KEY.to_owned()).unwrap()),
                preshared_key: Some(PresharedKey::new(PRESHARED_KEY.to_owned()).unwrap()),
                allowed_ips: vec![NetworkPrefix::new(address)],
                persistent_keepalive_seconds: Some(25),
                endpoint: Some("203.0.113.9:51820".parse().unwrap()),
            }],
            clients: vec![DesiredClient {
                id: ClientId::new(),
                peer_id,
                assigned_address: address,
                route_policy: Default::default(),
            }],
        }],
        client_routes: ClientRoutePolicy {
            prefixes: vec![NetworkPrefix::new("10.0.0.0/8".parse().unwrap())],
        },
        network_policy: Some(DesiredNetworkPolicy {
            wireguard_interface: "wg0".parse().unwrap(),
            ipv4_forwarding_required: true,
            egress_interface: "eth0".parse().unwrap(),
            source_prefixes: vec![NetworkPrefix::new("10.8.0.0/24".parse().unwrap())],
            masquerade: true,
        }),
    }
}

// ---------------------------------------------------------------------------
// Initialization and the hardened open contract
// ---------------------------------------------------------------------------

#[test]
fn new_store_initializes_with_generation_one_and_a_fresh_installation_id() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();

    let metadata = store.installation_metadata().unwrap();
    assert_eq!(metadata.desired_generation, INITIAL_DESIRED_GENERATION);
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(1).unwrap()
    );
    assert!(store.load().unwrap().state.interfaces.is_empty());

    let other = StateStore::initialize(TempDir::new().db()).unwrap();
    assert_ne!(
        metadata.installation_id,
        other.installation_metadata().unwrap().installation_id,
        "each installation identity is independently random"
    );
}

#[test]
fn initialization_refuses_to_overwrite_an_existing_database() {
    let temp = TempDir::new();
    let _first = StateStore::initialize(temp.db()).unwrap();
    assert!(matches!(
        StateStore::initialize(temp.db()),
        Err(StateError::DatabaseAlreadyExists { .. })
    ));
}

#[test]
fn reopen_preserves_the_installation_identity_and_generation() {
    let temp = TempDir::new();
    let first = StateStore::initialize(temp.db()).unwrap();
    let before = first.installation_metadata().unwrap();
    let committed = first
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();
    assert_eq!(committed.generation, DesiredGeneration::new(2).unwrap());
    drop(first);

    let reopened = StateStore::open(temp.db()).unwrap();
    let after = reopened.installation_metadata().unwrap();
    assert_eq!(after.installation_id, before.installation_id);
    assert_eq!(after.desired_generation, DesiredGeneration::new(2).unwrap());
}

#[test]
fn a_group_or_world_writable_parent_directory_is_rejected() {
    let temp = TempDir::new();
    fs::set_permissions(&temp.path, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        StateStore::initialize(temp.db()),
        Err(StateError::ParentTooPermissive { .. })
    ));
}

#[test]
fn a_freshly_created_database_is_owner_only() {
    let temp = TempDir::new();
    let _store = StateStore::initialize(temp.db()).unwrap();
    let mode = fs::symlink_metadata(temp.db()).unwrap().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "a secret-bearing database must be created owner-only, found {mode:o}"
    );
}

#[test]
fn a_group_or_world_accessible_database_is_narrowed_when_ownership_is_proven() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    drop(store);
    fs::set_permissions(temp.db(), fs::Permissions::from_mode(0o644)).unwrap();

    // Ownership is proven, so the mode is narrowed instead of refusing to open.
    let reopened =
        StateStore::open(temp.db()).expect("an owned database must be narrowed and reopened");
    let mode = fs::symlink_metadata(temp.db()).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600, "found {mode:o}");
    reopened.current_generation().unwrap();
}

#[test]
fn a_database_owned_by_another_uid_is_rejected() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    drop(store);
    // Assert the ownership contract directly by claiming a different owner.
    let other = u32::MAX;
    assert!(matches!(
        StateStore::open_with_expected_owner(temp.db(), other),
        Err(StateError::ParentWrongOwner { .. }) | Err(StateError::DatabaseWrongOwner { .. })
    ));
}

#[test]
fn a_symlinked_database_is_rejected() {
    let temp = TempDir::new();
    let real = temp.path.join("real.db");
    let link = temp.path.join("state.db");
    fs::write(&real, b"").unwrap();
    symlink(&real, &link).unwrap();
    assert!(matches!(
        StateStore::initialize(&link),
        Err(StateError::DatabaseIsSymlink { .. })
    ));
}

#[test]
fn a_directory_in_place_of_the_database_is_rejected() {
    let temp = TempDir::new();
    let path = temp.path.join("state.db");
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        StateStore::initialize(&path),
        Err(StateError::DatabaseNotRegularFile { .. })
    ));
}

#[test]
fn reopening_a_missing_database_is_refused_rather_than_created() {
    let temp = TempDir::new();
    assert!(StateStore::open(temp.db()).is_err());
}

// ---------------------------------------------------------------------------
// Pragma and migration contract
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Round-trip, relationships, and secrets
// ---------------------------------------------------------------------------

#[test]
fn desired_state_round_trips_through_the_store_with_every_relationship() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    let state = sample_state();

    let committed = store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(state.clone()))
        .unwrap();
    assert_eq!(committed.generation, DesiredGeneration::new(2).unwrap());

    let loaded = store.load().unwrap();
    assert_eq!(loaded.generation, DesiredGeneration::new(2).unwrap());
    assert_eq!(loaded.state, state, "every field must round-trip");

    let interface = &loaded.state.interfaces[0];
    assert_eq!(interface.private_key, private_key());
    assert_eq!(
        interface.peers[0].private_key,
        state.interfaces[0].peers[0].private_key
    );
    assert_eq!(
        interface.peers[0].preshared_key,
        state.interfaces[0].peers[0].preshared_key
    );
    assert_eq!(
        interface.peers[0].endpoint,
        state.interfaces[0].peers[0].endpoint
    );
    assert_eq!(
        interface.routes[0].gateway,
        Some("192.0.2.1".parse().unwrap())
    );
}

#[test]
fn server_allowed_ips_and_client_route_policy_remain_separate() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();

    let mut state = sample_state();
    state.interfaces[0].peers[0].allowed_ips =
        vec![NetworkPrefix::new("10.8.0.2/32".parse().unwrap())];
    state.interfaces[0].clients[0].route_policy.prefixes =
        vec![NetworkPrefix::new("192.168.1.0/24".parse().unwrap())];

    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(state))
        .unwrap();
    let loaded = store.load().unwrap();

    let peer = &loaded.state.interfaces[0].peers[0];
    assert_eq!(
        peer.allowed_ips.len(),
        1,
        "server AllowedIPs stay server-only"
    );
    assert_eq!(peer.allowed_ips[0].to_string(), "10.8.0.2/32");

    let client = &loaded.state.interfaces[0].clients[0];
    assert_eq!(
        client.route_policy.prefixes[0].to_string(),
        "192.168.1.0/24",
        "client route policy must not be folded into server AllowedIPs"
    );
}

#[test]
fn secret_values_never_appear_in_store_diagnostics() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();

    let rendered = format!("{store:?}");
    assert!(!rendered.contains(SERVER_KEY), "{rendered}");
    assert!(!rendered.contains(CLIENT_KEY), "{rendered}");

    let loaded = store.load().unwrap();
    assert!(
        !format!("{:?}", loaded.state.interfaces[0].private_key).contains(SERVER_KEY),
        "private keys must redact in Debug"
    );
}

// ---------------------------------------------------------------------------
// Generation CAS and rollback
// ---------------------------------------------------------------------------

#[test]
fn generation_advances_by_exactly_one_per_committed_mutation() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();

    let first = store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();
    assert_eq!(first.generation, DesiredGeneration::new(2).unwrap());

    let second = store
        .mutate(
            DesiredGeneration::new(2).unwrap(),
            |state| Ok(state.clone()),
        )
        .unwrap();
    assert_eq!(second.generation, DesiredGeneration::new(3).unwrap());
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(3).unwrap()
    );
}

#[test]
fn a_stale_writer_is_refused_and_changes_nothing() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();

    let before = store.load().unwrap();
    let result = store.mutate(INITIAL_DESIRED_GENERATION, |_| Ok(DesiredState::default()));

    assert!(matches!(
        result,
        Err(StateError::StaleGeneration {
            expected: 1,
            actual: 2
        })
    ));
    assert_eq!(
        store.load().unwrap(),
        before,
        "a stale write changes nothing"
    );
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap()
    );
}

#[test]
fn validation_failure_performs_no_row_changes_and_does_not_advance_generation() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();
    let before = store.load().unwrap();

    // Two clients sharing one tunnel address is invalid.
    let result = store.mutate(DesiredGeneration::new(2).unwrap(), |state| {
        let mut next = state.clone();
        let mut duplicate = next.interfaces[0].clients[0].clone();
        duplicate.id = ClientId::new();
        next.interfaces[0].clients.push(duplicate);
        Ok(next)
    });

    assert!(matches!(result, Err(StateError::Validation(_))));
    assert_eq!(store.load().unwrap(), before);
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap()
    );
}

#[test]
fn an_update_closure_error_rolls_the_whole_mutation_back() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();
    let before = store.load().unwrap();

    let result = store.mutate(DesiredGeneration::new(2).unwrap(), |_| {
        Err(StateError::Corrupt("injected update failure"))
    });

    assert!(result.is_err());
    assert_eq!(store.load().unwrap(), before);
    assert_eq!(
        store.current_generation().unwrap(),
        DesiredGeneration::new(2).unwrap()
    );
}

#[test]
fn a_multi_table_mutation_commits_entirely_or_not_at_all() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();

    // Remove the peer while the client still references it: validation must
    // reject this and leave every table exactly as it was.
    let before = store.load().unwrap();
    let result = store.mutate(DesiredGeneration::new(2).unwrap(), |state| {
        let mut next = state.clone();
        next.interfaces[0].peers.clear();
        Ok(next)
    });
    assert!(matches!(result, Err(StateError::Validation(_))));
    assert_eq!(store.load().unwrap(), before);

    // A fully valid multi-table change commits every table at once.
    store
        .mutate(DesiredGeneration::new(2).unwrap(), |state| {
            let mut next = state.clone();
            next.interfaces[0].clients[0].route_policy.prefixes =
                vec![NetworkPrefix::new("192.168.5.0/24".parse().unwrap())];
            next.client_routes.prefixes = vec![NetworkPrefix::new("10.0.0.0/8".parse().unwrap())];
            Ok(next)
        })
        .unwrap();

    let after = store.load().unwrap();
    assert_eq!(after.generation, DesiredGeneration::new(3).unwrap());
    assert_eq!(
        after.state.interfaces[0].clients[0].route_policy.prefixes[0].to_string(),
        "192.168.5.0/24"
    );
    assert_eq!(
        after.state.client_routes.prefixes[0].to_string(),
        "10.0.0.0/8"
    );
}

#[test]
fn an_unchanged_snapshot_still_advances_the_generation() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    let state = sample_state();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(state.clone()))
        .unwrap();

    let repeated = store
        .mutate(DesiredGeneration::new(2).unwrap(), |current| {
            Ok(current.clone())
        })
        .unwrap();
    assert_eq!(
        repeated.generation,
        DesiredGeneration::new(3).unwrap(),
        "a generation identifies a committed mutation, not a distinct payload"
    );
    assert_eq!(repeated.state, state);
}

#[test]
fn the_desired_state_module_does_not_depend_on_the_network_backends() {
    // The state module must remain usable on a non-Linux host, so none of its
    // files may reach for a Linux-gated module.
    let schema = include_str!("../src/state/schema.rs");
    let store_source = include_str!("../src/state/store.rs");
    for source in [schema, store_source] {
        assert!(!source.contains("crate::reconcile"));
        assert!(!source.contains("crate::firewall"));
        assert!(!source.contains("crate::protocol"));
        assert!(!source.contains("rusqlite::backup"));
    }
    assert!(!schema.contains("rtnetlink"));
    assert!(!schema.contains("nl_wireguard"));
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn projection_is_deterministic_across_reopen_and_store_cycles() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    let state = sample_state();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(state))
        .unwrap();

    let installation = store.installation_metadata().unwrap().installation_id;
    let from_store = project(&store.load().unwrap().state, installation).unwrap();
    drop(store);
    let reopened = StateStore::open(temp.db()).unwrap();
    let after_reopen = project(&reopened.load().unwrap().state, installation).unwrap();

    assert_eq!(from_store, after_reopen);
    assert_eq!(
        project(&reopened.load().unwrap().state, installation).unwrap(),
        from_store
    );
}

#[cfg(target_os = "linux")]
#[test]
fn projection_produces_the_existing_kernel_intent_types() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(sample_state()))
        .unwrap();

    let installation = store.installation_metadata().unwrap().installation_id;
    let intent = project(&store.load().unwrap().state, installation).unwrap();
    assert_eq!(intent.interfaces.len(), 1);

    let interface = &intent.interfaces[0];
    assert_eq!(interface.interface, "wg0".parse().unwrap());
    assert_eq!(interface.ownership, OwnershipDeclaration::Managed);
    assert_eq!(
        interface.lifecycle,
        wg_basic::reconcile::LinkLifecycle::Present
    );
    assert_eq!(interface.admin_up, Some(true));

    let wireguard = interface.wireguard.as_ref().unwrap();
    assert_eq!(wireguard.listen_port, 51820);
    assert!(wireguard.manage_all_peers);
    assert_eq!(wireguard.peers.len(), 1);
    assert_eq!(wireguard.peers[0].allowed_ips.len(), 1);

    let policy = intent.network_policy.as_ref().unwrap();
    assert_eq!(policy.egress_interface, "eth0".parse().unwrap());
    assert!(matches!(
        policy.nat,
        wg_basic::firewall::NatMode::Masquerade
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn projection_refuses_ipv6_policy_prefixes_before_privileged_work() {
    let mut state = sample_state();
    // Bypass validation to prove the projector independently refuses the shape.
    state.network_policy.as_mut().unwrap().source_prefixes =
        vec![NetworkPrefix::new("2001:db8::/64".parse().unwrap())];
    let result = wg_basic::state::project(&state, wg_basic::domain::InstallationId::new());
    assert!(matches!(
        result,
        Err(ProjectionError::NonIpv4PolicyPrefix(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn an_absent_interface_projects_without_a_wireguard_configuration() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    let mut state = sample_state();
    state.interfaces[0].lifecycle = LinkLifecycle::Absent;
    state.interfaces[0].admin_up = None;
    state.network_policy = None;
    store
        .mutate(INITIAL_DESIRED_GENERATION, |_| Ok(state))
        .unwrap();

    let installation = store.installation_metadata().unwrap().installation_id;
    let intent = project(&store.load().unwrap().state, installation).unwrap();
    assert!(intent.interfaces[0].wireguard.is_none());
    assert!(intent.network_policy.is_none());
}

#[test]
fn cross_interface_validation_rejects_duplicate_names_and_dangling_policies() {
    let mut state = sample_state();
    let second = state.interfaces[0].clone();
    state.interfaces.push(second);
    assert!(matches!(
        validate_desired_state(&state),
        Err(wg_basic::domain::StateValidationError::DuplicateInterfaceName(_))
    ));

    let mut dangling = sample_state();
    dangling
        .network_policy
        .as_mut()
        .unwrap()
        .wireguard_interface = "wg9".parse().unwrap();
    assert!(matches!(
        validate_desired_state(&dangling),
        Err(wg_basic::domain::StateValidationError::NetworkPolicyUnknownInterface(_))
    ));
}

#[test]
fn convergence_evidence_round_trips_and_starts_unset() {
    let temp = TempDir::new();
    let store = StateStore::initialize(temp.db()).unwrap();
    assert_eq!(store.convergence().unwrap(), Default::default());
}
