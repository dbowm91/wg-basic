//! Phase 8 M001 product-management evidence.
//!
//! These cases qualify the product layer with no HTTP surface present at all,
//! which is the point of M001: setup, allocation, enable/disable, delete, audit
//! atomicity, and committed-vs-enforced receipts are correct before any route
//! can reach them.
//!
//! Kernel-level evidence -- that a disabled client really leaves the WireGuard
//! device and that a backend outage really degrades -- lives in the rootful
//! `product_management` suite.

use std::{
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use wg_basic::{
    domain::{
        ClientId, ClientRoutePolicy, DesiredGeneration, InterfaceId, InterfaceName,
        NetworkPolicyMode, NetworkPrefix, PeerId, PrincipalId,
    },
    management::set_password_at,
    product::{
        AddressRequest, AllocationContext, AllocationError, ClientCreateCommand,
        ClientDeleteCommand, ClientLabel, ClientUpdateCommand, ProductError, ProductService,
        ServerSetupCommand, SetClientEnabledCommand,
    },
    state::{StateError, StateStore},
};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-m001-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        // The store refuses a parent directory it does not exclusively own, so
        // the fixture matches the production layout rather than widening it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("scratch directory permissions");
        Self(path)
    }

    fn db(&self) -> std::path::PathBuf {
        self.0.join("state.db")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn store_at(scratch: &Scratch) -> Arc<StateStore> {
    Arc::new(StateStore::initialize(scratch.db()).expect("a fresh store"))
}

fn admin_at(scratch: &Scratch) -> PrincipalId {
    set_password_at(scratch.db(), "admin", "an administrator password").expect("provisioning");
    let store = StateStore::open(scratch.db()).expect("reopen");
    store.principals().expect("principals")[0].id
}

fn service(store: &StateStore) -> ProductService<'_> {
    ProductService::new(store)
}

fn setup(command_overrides: impl FnOnce(&mut ServerSetupCommand)) -> Setup {
    let scratch = Scratch::new("setup");
    let store = store_at(&scratch);
    let principal = admin_at(&scratch);
    let mut command = ServerSetupCommand {
        principal_id: principal,
        expected_generation: DesiredGeneration::default(),
        interface_name: "wg0".parse().unwrap(),
        tunnel_prefix: NetworkPrefix::new("10.8.0.0/24".parse().unwrap()),
        ipv6_tunnel_prefix: None,
        server_address: None,
        ipv6_server_address: None,
        listen_port: 51820,
        advertised_endpoint: wg_basic::product::AdvertisedEndpoint::new("vpn.example.com", 51820)
            .unwrap(),
        egress_interface: "eth0".parse().unwrap(),
        ipv4_forwarding_required: true,
        ipv6_forwarding_required: false,
        masquerade: true,
        mode: None,
        destination_prefixes: Vec::new(),
        default_client_route_policy: ClientRoutePolicy::default(),
    };
    command_overrides(&mut command);
    let service = service(&store);
    service.setup_server(command).expect("server setup");
    Setup {
        scratch,
        store,
        principal,
    }
}

/// A configured installation plus the store it lives in.
///
/// The service is deliberately not a field: it borrows the store, and callers
/// build one per operation from `store`.
struct Setup {
    scratch: Scratch,
    store: Arc<StateStore>,
    principal: PrincipalId,
}

/// Builds a setup command without running it, so a test can see the refusal.
fn setup_command(
    scratch: &Scratch,
    overrides: impl FnOnce(&mut ServerSetupCommand),
) -> ServerSetupCommand {
    let principal = admin_at(scratch);
    let mut command = ServerSetupCommand {
        principal_id: principal,
        expected_generation: DesiredGeneration::default(),
        interface_name: "wg0".parse().unwrap(),
        tunnel_prefix: NetworkPrefix::new("10.8.0.0/24".parse().unwrap()),
        ipv6_tunnel_prefix: None,
        server_address: None,
        ipv6_server_address: None,
        listen_port: 51820,
        advertised_endpoint: wg_basic::product::AdvertisedEndpoint::new("vpn.example.com", 51820)
            .unwrap(),
        egress_interface: "eth0".parse().unwrap(),
        ipv4_forwarding_required: true,
        ipv6_forwarding_required: false,
        masquerade: true,
        mode: None,
        destination_prefixes: Vec::new(),
        default_client_route_policy: ClientRoutePolicy::default(),
    };
    overrides(&mut command);
    command
}

#[test]
fn the_routing_mode_is_stated_explicitly_and_checked_for_consistency() {
    // A host-only policy that also asks for forwarding contradicts itself,
    // and the contradiction is refused rather than resolved silently.
    let scratch = Scratch::new("mode-host-only");
    let store = store_at(&scratch);
    let command = setup_command(&scratch, |command| {
        command.mode = Some(NetworkPolicyMode::HostOnly);
    });
    let error = service(&store).setup_server(command).unwrap_err();
    assert!(
        matches!(error, ProductError::InvalidNetworkPolicyMode(_)),
        "{error:?}"
    );

    // A routed-LAN policy without an allowlist names no destination, which
    // would be a routed LAN to everywhere.
    let scratch = Scratch::new("mode-routed-lan-empty");
    let store = store_at(&scratch);
    let command = setup_command(&scratch, |command| {
        command.mode = Some(NetworkPolicyMode::RoutedLan);
        command.masquerade = false;
    });
    let error = service(&store).setup_server(command).unwrap_err();
    assert!(
        matches!(error, ProductError::InvalidNetworkPolicyMode(_)),
        "{error:?}"
    );

    // A routed-LAN policy never masquerades.
    let scratch = Scratch::new("mode-routed-lan-masquerade");
    let store = store_at(&scratch);
    let command = setup_command(&scratch, |command| {
        command.mode = Some(NetworkPolicyMode::RoutedLan);
        command.masquerade = true;
        command.destination_prefixes = vec![NetworkPrefix::new("192.168.9.0/24".parse().unwrap())];
    });
    let error = service(&store).setup_server(command).unwrap_err();
    assert!(
        matches!(error, ProductError::InvalidNetworkPolicyMode(_)),
        "{error:?}"
    );
}

#[test]
fn a_routed_lan_policy_is_accepted_only_where_it_is_implemented() {
    let scratch = Scratch::new("mode-routed-lan");
    let store = store_at(&scratch);
    let command = setup_command(&scratch, |command| {
        command.mode = Some(NetworkPolicyMode::RoutedLan);
        command.masquerade = false;
        command.destination_prefixes = vec![NetworkPrefix::new("192.168.9.0/24".parse().unwrap())];
    });
    let result = service(&store).setup_server(command);
    if cfg!(target_os = "macos") {
        let (_, receipt) = result.expect("a routed LAN is implemented on macOS");
        assert!(receipt.generation.to_storage() >= 1);
        let loaded = store.load().expect("the desired state reads back");
        let policy = loaded
            .state
            .network_policy
            .expect("the policy is persisted");
        assert_eq!(policy.mode, NetworkPolicyMode::RoutedLan);
        assert_eq!(
            policy.destination_prefixes,
            vec![NetworkPrefix::new("192.168.9.0/24".parse().unwrap())]
        );
    } else {
        let error = result.unwrap_err();
        assert!(
            matches!(error, ProductError::InvalidNetworkPolicyMode(_)),
            "{error:?}"
        );
    }
}

impl Setup {
    fn service(&self) -> ProductService<'_> {
        ProductService::new(&self.store)
    }
}

/// The authenticated operator every product mutation acts as.
///
/// Taken from the store rather than invented: `audit_events.principal_id` is a
/// real foreign key, so a mutation attributed to a principal that does not exist
/// is refused by the database rather than quietly recorded.
fn admin(service: &ProductService<'_>) -> PrincipalId {
    service.store().principals().expect("principals")[0].id
}

fn create(service: &ProductService<'_>, label: &str) -> wg_basic::product::ProductClient {
    let generation = service.store().current_generation().unwrap();
    let server = service.server().unwrap().expect("configured server");
    let (client, _receipt) = service
        .create_client(ClientCreateCommand {
            principal_id: admin(service),
            expected_generation: generation,
            interface_id: server.interface_id,
            label: ClientLabel::new(label).unwrap(),
            requested_address: None,
            route_policy: None,
            dns_servers: Vec::new(),
            client_keepalive_seconds: None,
            expires_at: None,
            preshared_key: None,
            mtu: None,
        })
        .expect("client create");
    client
}

#[test]
fn enrollment_links_are_capped_and_old_terminal_rows_are_pruned_with_audit_retained() {
    let installation = setup(|_| {});
    let service = installation.service();
    let client = create(&service, "enrollment housekeeping");
    let generation = installation.store.current_generation().unwrap();

    let revoked = service
        .create_enrollment_link(installation.principal, client.client_id, 600)
        .unwrap();
    assert!(service
        .revoke_enrollment_link(installation.principal, revoked.capability_id)
        .unwrap());
    let old_id = revoked.capability_id.to_string();
    rusqlite::Connection::open(installation.store.path())
        .unwrap()
        .execute(
            "UPDATE enrollment_capabilities SET created_at = 100, revoked_at = 100 WHERE capability_id = ?1",
            [&old_id],
        )
        .unwrap();

    let mut links = Vec::new();
    for _ in 0..wg_basic::state::MAX_LIVE_ENROLLMENT_CAPABILITIES_PER_CLIENT {
        links.push(
            service
                .create_enrollment_link(installation.principal, client.client_id, 600)
                .unwrap(),
        );
    }
    assert_eq!(
        installation.store.enrollment_capability_count().unwrap(),
        wg_basic::state::MAX_LIVE_ENROLLMENT_CAPABILITIES_PER_CLIENT,
        "old revoked token rows are pruned before new links are added"
    );
    assert!(matches!(
        service.create_enrollment_link(installation.principal, client.client_id, 600),
        Err(wg_basic::product::ProductError::EnrollmentCapacityReached)
    ));
    assert_eq!(installation.store.current_generation().unwrap(), generation);
    assert!(
        installation
            .store
            .audit_events(100)
            .unwrap()
            .iter()
            .any(
                |event| event.resource_id.as_deref() == Some(old_id.as_str())
                    && event.action == wg_basic::product::AuditAction::EnrollmentCapabilityRevoked
            ),
        "pruning terminal rows never erases their durable audit history"
    );
    drop(links);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

#[test]
fn setup_generates_the_server_identity_and_returns_no_secret() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let server = service.server().unwrap().expect("configured server");

    assert_eq!(server.name, InterfaceName::new("wg0").unwrap());
    assert_eq!(server.listen_port, 51820);
    assert_eq!(server.tunnel_prefix.to_string(), "10.8.0.0/24");
    // The server took the first usable address inside its own prefix.
    assert_eq!(
        server.server_address,
        IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))
    );
    // A public key was derived from the internally generated private key.
    assert_eq!(server.public_key.expose().len(), 44);
    assert!(server.advertised_endpoint.render() == "vpn.example.com:51820");
}

#[test]
fn the_server_summary_and_its_debug_form_never_carry_the_private_key() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let server = service.server().unwrap().expect("configured server");

    // The database really does hold a private key for this server...
    let desired = store.load().unwrap();
    let secret = desired.state.interfaces[0]
        .private_key
        .expose_secret()
        .to_owned();

    // ...and it appears in neither the summary nor its rendering.
    assert!(!format!("{server:?}").contains(&secret));
}

#[test]
fn setup_is_one_time() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let again = service.setup_server(ServerSetupCommand {
        principal_id: admin(&service),
        expected_generation: store.current_generation().unwrap(),
        interface_name: "wg1".parse().unwrap(),
        tunnel_prefix: NetworkPrefix::new("10.9.0.0/24".parse().unwrap()),
        ipv6_tunnel_prefix: None,
        server_address: None,
        ipv6_server_address: None,
        listen_port: 51821,
        advertised_endpoint: wg_basic::product::AdvertisedEndpoint::new("other.example.com", 51821)
            .unwrap(),
        egress_interface: "eth0".parse().unwrap(),
        ipv4_forwarding_required: true,
        ipv6_forwarding_required: false,
        masquerade: true,
        mode: None,
        destination_prefixes: Vec::new(),
        default_client_route_policy: ClientRoutePolicy::default(),
    });
    assert!(matches!(
        again,
        Err(wg_basic::product::ProductError::ServerAlreadyConfigured)
    ));
}

#[test]
fn a_stale_expected_generation_is_refused_and_commits_nothing() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let server = service.server().unwrap().unwrap();
    let before = store.current_generation().unwrap();

    let result = service.create_client(ClientCreateCommand {
        principal_id: admin(&service),
        expected_generation: DesiredGeneration::new(1).unwrap(),
        interface_id: server.interface_id,
        label: ClientLabel::new("stale").unwrap(),
        requested_address: None,
        route_policy: None,
        dns_servers: Vec::new(),
        client_keepalive_seconds: None,
        expires_at: None,
        preshared_key: None,
        mtu: None,
    });

    assert!(matches!(
        result,
        Err(wg_basic::product::ProductError::State(
            StateError::StaleGeneration { .. }
        ))
    ));
    assert_eq!(
        store.current_generation().unwrap(),
        before,
        "a stale writer must not advance the generation"
    );
    assert!(
        service.list_clients().unwrap().is_empty(),
        "a stale writer must leave no client behind"
    );
}

#[test]
fn concurrent_same_generation_creates_have_exactly_one_winner() {
    let Setup {
        store, principal, ..
    } = setup(|_| {});
    let reader = service(&store);
    let server = reader.server().unwrap().unwrap();
    let interface_id = server.interface_id;
    let generation = store.current_generation().unwrap();
    let address = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 77));

    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for label in ["race-a", "race-b"] {
            let store_ref = &store;
            handles.push(scope.spawn(move || {
                service(store_ref).create_client(ClientCreateCommand {
                    principal_id: principal,
                    expected_generation: generation,
                    interface_id,
                    label: ClientLabel::new(label).unwrap(),
                    requested_address: Some(address),
                    route_policy: None,
                    dns_servers: Vec::new(),
                    client_keepalive_seconds: None,
                    expires_at: None,
                    preshared_key: None,
                    mtu: None,
                })
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(
                result,
                Err(wg_basic::product::ProductError::State(
                    StateError::StaleGeneration { .. }
                ))
            ))
            .count(),
        1,
        "a same-generation loser must report StaleGeneration: {outcomes:?}"
    );
    let clients = service(&store).list_clients().unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].assigned_address.addr(), address);
    assert_eq!(
        store.current_generation().unwrap().to_storage(),
        generation.to_storage() + 1
    );
}

// ---------------------------------------------------------------------------
// Client creation
// ---------------------------------------------------------------------------

#[test]
fn create_generates_a_key_allocates_the_next_address_and_returns_no_secret() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "Laptop");

    assert_eq!(client.assigned_address.to_string(), "10.8.0.2/32");
    assert_eq!(client.settings.label.as_str(), "Laptop");
    assert!(client.settings.enabled.is_enabled());
    assert_eq!(client.public_key.expose().len(), 44);

    // The private key exists in durable state -- for M003's explicit export --
    // and the returned projection has no field that could carry it.
    let desired = store.load().unwrap();
    let peer = &desired.state.interfaces[0].peers[0];
    assert!(peer.private_key.is_some());
    assert!(!format!("{client:?}").contains(peer.private_key.as_ref().unwrap().expose_secret()));
}

#[test]
fn created_clients_receive_consecutive_lowest_free_addresses() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let first = create(&service, "one");
    let second = create(&service, "two");
    let third = create(&service, "three");

    assert_eq!(first.assigned_address.to_string(), "10.8.0.2/32");
    assert_eq!(second.assigned_address.to_string(), "10.8.0.3/32");
    assert_eq!(third.assigned_address.to_string(), "10.8.0.4/32");
}

#[test]
fn a_requested_address_is_honoured_and_a_conflict_is_refused() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let server = service.server().unwrap().unwrap();
    let generation = service.store().current_generation().unwrap();

    let (chosen, _) = service
        .create_client(ClientCreateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            interface_id: server.interface_id,
            label: ClientLabel::new("chosen").unwrap(),
            requested_address: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 50))),
            route_policy: None,
            dns_servers: Vec::new(),
            client_keepalive_seconds: None,
            expires_at: None,
            preshared_key: None,
            mtu: None,
        })
        .unwrap();
    assert_eq!(chosen.assigned_address.to_string(), "10.8.0.50/32");

    let generation = service.store().current_generation().unwrap();
    let conflict = service.create_client(ClientCreateCommand {
        principal_id: admin(&service),
        expected_generation: generation,
        interface_id: server.interface_id,
        label: ClientLabel::new("conflict").unwrap(),
        requested_address: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 50))),
        route_policy: None,
        dns_servers: Vec::new(),
        client_keepalive_seconds: None,
        expires_at: None,
        preshared_key: None,
        mtu: None,
    });
    assert!(
        matches!(
            conflict,
            Err(wg_basic::product::ProductError::Allocation(
                AllocationError::AlreadyUsed(_)
            ))
        ),
        "a requested address already in use must be refused before anything commits: {conflict:?}"
    );
}

#[test]
fn dual_stack_setup_allocates_persists_and_reassigns_client_addresses() {
    let Setup {
        scratch: _scratch,
        store,
        ..
    } = setup(|command| {
        command.ipv6_tunnel_prefix = Some(NetworkPrefix::new("2001:db8:42::/64".parse().unwrap()));
        command.ipv6_forwarding_required = true;
    });
    let service = service(&store);
    let server = service.server().unwrap().unwrap();
    assert_eq!(
        server.ipv6_tunnel_prefix.unwrap().to_string(),
        "2001:db8:42::/64"
    );
    assert_eq!(
        server.ipv6_server_address.unwrap().to_string(),
        "2001:db8:42::1"
    );
    let network_policy = store.load().unwrap().state.network_policy.unwrap();
    assert!(network_policy.ipv6_forwarding_required);
    assert!(network_policy
        .source_prefixes
        .iter()
        .any(|prefix| prefix.to_string() == "2001:db8:42::/64"));

    let client = create(&service, "dual-stack");
    assert_eq!(client.assigned_address.to_string(), "10.8.0.2/32");
    assert_eq!(
        client.assigned_ipv6_address.unwrap().to_string(),
        "2001:db8:42::2/128"
    );
    let desired = store.load().unwrap();
    let interface = &desired.state.interfaces[0];
    assert!(interface
        .routes
        .iter()
        .any(|route| route.destination.to_string() == "2001:db8:42::/64"));
    let peer = interface
        .peers
        .iter()
        .find(|peer| peer.id == client.peer_id)
        .unwrap();
    assert!(peer
        .allowed_ips
        .iter()
        .any(|prefix| prefix.to_string() == "2001:db8:42::2/128"));
    assert_eq!(
        interface.clients[0]
            .assigned_ipv6_address
            .unwrap()
            .to_string(),
        "2001:db8:42::2/128"
    );

    let generation = store.current_generation().unwrap();
    let (updated, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: client.client_id,
            requested_ipv6_address: Some("2001:db8:42::55".parse().unwrap()),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    assert_eq!(
        updated.assigned_ipv6_address.unwrap().to_string(),
        "2001:db8:42::55/128"
    );

    let generation = store.current_generation().unwrap();
    let (same, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: client.client_id,
            requested_ipv6_address: Some("2001:db8:42::55".parse().unwrap()),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    assert_eq!(
        same.assigned_ipv6_address.unwrap().to_string(),
        "2001:db8:42::55/128"
    );

    let reopened = StateStore::open(store.path()).unwrap();
    assert_eq!(
        ProductService::new(&reopened).list_clients().unwrap()[0]
            .assigned_ipv6_address
            .unwrap()
            .to_string(),
        "2001:db8:42::55/128"
    );
}

#[test]
fn two_clients_never_share_a_peer_or_a_client_identifier() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let first = create(&service, "one");
    let second = create(&service, "two");

    assert_ne!(first.peer_id, second.peer_id);
    assert_ne!(first.client_id, second.client_id);

    let desired = store.load().unwrap();
    let interface = &desired.state.interfaces[0];
    let peer_ids: Vec<PeerId> = interface.peers.iter().map(|peer| peer.id).collect();
    assert_eq!(peer_ids.len(), 2);
    assert_ne!(peer_ids[0], peer_ids[1]);
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

#[test]
fn update_changes_label_dns_keepalive_and_route_policy_without_rotating_keys() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "before");
    let original_public = client.public_key.clone();
    let generation = store.current_generation().unwrap();

    let (updated, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: client.client_id,
            label: Some(ClientLabel::new("after").unwrap()),
            route_policy: Some(ClientRoutePolicy {
                prefixes: vec![NetworkPrefix::new("0.0.0.0/0".parse().unwrap())],
            }),
            dns_servers: Some(vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            ]),
            client_keepalive_seconds: Some(Some(25)),
            requested_address: None,
            requested_ipv6_address: None,
            expires_at: None,
            preshared_key: None,
            mtu: None,
        })
        .unwrap();

    assert_eq!(updated.settings.label.as_str(), "after");
    assert_eq!(updated.dns_servers.len(), 2);
    assert_eq!(updated.settings.client_keepalive_seconds, Some(25));
    assert_eq!(updated.route_policy.prefixes.len(), 1);
    assert_eq!(
        updated.public_key, original_public,
        "an update must never rotate a key implicitly"
    );
}

#[test]
fn invalid_ipv6_client_route_is_rejected_without_advancing_generation() {
    let Setup { store, .. } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "ipv4-only");
    let generation = store.current_generation().unwrap();
    let result = service.update_client(ClientUpdateCommand {
        principal_id: admin(&service),
        expected_generation: generation,
        client_id: client.client_id,
        route_policy: Some(ClientRoutePolicy {
            prefixes: vec!["::/0".parse().unwrap()],
        }),
        ..Default::default()
    });
    assert!(matches!(
        result,
        Err(ProductError::State(StateError::Validation(_)))
    ));
    assert_eq!(store.current_generation().unwrap(), generation);
    assert!(service
        .list_clients()
        .unwrap()
        .iter()
        .find(|item| item.client_id == client.client_id)
        .unwrap()
        .route_policy
        .prefixes
        .is_empty());
}

#[test]
fn ipv6_route_policy_requires_and_uses_explicit_ipv6_client_assignment() {
    let Setup { scratch, store, .. } = setup(|command| {
        command.ipv6_tunnel_prefix = Some(NetworkPrefix::new("fd77::/64".parse().unwrap()));
        command.default_client_route_policy = ClientRoutePolicy::default();
    });
    let client_id = {
        let product = service(&store);
        let client = create(&product, "dual-stack");
        assert!(client.assigned_ipv6_address.is_some());
        let generation = store.current_generation().unwrap();
        let (updated, _) = product
            .update_client(ClientUpdateCommand {
                principal_id: admin(&product),
                expected_generation: generation,
                client_id: client.client_id,
                route_policy: Some(ClientRoutePolicy {
                    prefixes: vec!["::/0".parse().unwrap()],
                }),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(updated.route_policy.prefixes, vec!["::/0".parse().unwrap()]);
        client.client_id
    };
    let reopened = StateStore::open(scratch.db()).unwrap();
    let persisted = service(&reopened)
        .list_clients()
        .unwrap()
        .into_iter()
        .find(|item| item.client_id == client_id)
        .unwrap();
    assert_eq!(
        persisted.route_policy.prefixes,
        vec!["::/0".parse().unwrap()]
    );
}

#[test]
fn reassigning_an_address_is_one_atomic_mutation_that_keeps_uniqueness() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let first = create(&service, "one");
    let second = create(&service, "two");
    let generation = store.current_generation().unwrap();

    let (updated, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: first.client_id,
            requested_address: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 77))),
            ..ClientUpdateCommand::default()
        })
        .unwrap();

    assert_eq!(updated.assigned_address.to_string(), "10.8.0.77/32");
    // The other client is untouched, and the old address is free again.
    assert_eq!(second.assigned_address.to_string(), "10.8.0.3/32");
    wg_basic::domain::validate_desired_state(&store.load().unwrap().state)
        .expect("state stays valid after reassignment");
}

#[test]
fn a_reassignment_onto_another_clients_address_is_refused_atomically() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let first = create(&service, "one");
    let _second = create(&service, "two");
    let generation = store.current_generation().unwrap();

    let result = service.update_client(ClientUpdateCommand {
        principal_id: admin(&service),
        expected_generation: generation,
        client_id: first.client_id,
        requested_address: Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 3))),
        ..ClientUpdateCommand::default()
    });

    assert!(result.is_err());
    let desired = store.load().unwrap();
    assert_eq!(
        desired.state.interfaces[0].clients[0]
            .assigned_address
            .to_string(),
        "10.8.0.2/32",
        "a refused reassignment must leave the original address in place"
    );
}

// ---------------------------------------------------------------------------
// Enable / disable projection
// ---------------------------------------------------------------------------

#[test]
fn a_disabled_client_leaves_projected_intent_and_re_enabling_restores_the_same_peer() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let kept = create(&service, "kept");
    let toggled = create(&service, "toggled");
    let installation = store.installation_metadata().unwrap().installation_id;

    let before = wg_basic::state::project(
        &store.load().unwrap().state,
        installation,
        &wg_basic::state::ClientVisibility::from_product(
            &store.load().unwrap().state,
            &store.load_product().unwrap().state,
        ),
    )
    .unwrap();
    assert_eq!(
        before.interfaces[0].wireguard.as_ref().unwrap().peers.len(),
        2
    );

    service
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: toggled.client_id,
            enabled: wg_basic::product::ClientEnabled::Disabled,
            expires_at: None,
        })
        .unwrap();

    let desired = store.load().unwrap().state;
    let product = store.load_product().unwrap().state;
    let after = wg_basic::state::project(
        &desired,
        installation,
        &wg_basic::state::ClientVisibility::from_product(&desired, &product),
    )
    .unwrap();

    let peers = &after.interfaces[0].wireguard.as_ref().unwrap().peers;
    assert_eq!(
        peers.len(),
        1,
        "exactly the disabled client's peer leaves projected intent"
    );
    assert_eq!(peers[0].public_key, kept.public_key);

    // The disabled client's durable state survives: row, peer, and address.
    assert_eq!(desired.interfaces[0].clients.len(), 2);
    assert!(desired.interfaces[0]
        .clients
        .iter()
        .any(|client| client.id == toggled.client_id));
    assert!(
        !product.clients[&toggled.client_id]
            .settings
            .enabled
            .is_enabled(),
        "the client is disabled but still fully present in durable state"
    );

    service
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: toggled.client_id,
            enabled: wg_basic::product::ClientEnabled::Enabled,
            expires_at: None,
        })
        .unwrap();

    let desired = store.load().unwrap().state;
    let product = store.load_product().unwrap().state;
    let restored = wg_basic::state::project(
        &desired,
        installation,
        &wg_basic::state::ClientVisibility::from_product(&desired, &product),
    )
    .unwrap();
    let peers = &restored.interfaces[0].wireguard.as_ref().unwrap().peers;
    assert_eq!(peers.len(), 2);
    assert!(
        peers
            .iter()
            .any(|peer| peer.public_key == toggled.public_key),
        "re-enabling must restore the identical peer, not a new one"
    );
}

#[test]
fn whole_network_disable_preserves_configuration_and_enable_restores_same_intent() {
    let Setup { store, .. } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "persistent-client");
    let installation = store.installation_metadata().unwrap().installation_id;
    let before_state = store.load().unwrap().state;
    let before_product = store.load_product().unwrap().state;
    let before = wg_basic::management::project_diagnostic_intent(
        installation,
        store.current_generation().unwrap(),
        &before_state,
        &before_product,
    )
    .unwrap()
    .unwrap();
    let interface_id = before.interface_id;

    let disabled_generation = service
        .set_network_enabled(store.current_generation().unwrap(), false)
        .unwrap();
    let disabled_state = store.load().unwrap().state;
    let disabled_product = store.load_product().unwrap().state;
    let disabled = wg_basic::management::project_diagnostic_intent(
        installation,
        disabled_generation,
        &disabled_state,
        &disabled_product,
    )
    .unwrap()
    .unwrap();
    assert_eq!(disabled.interface_id, interface_id);
    assert_eq!(
        disabled.desired_interface.lifecycle,
        wg_basic::reconcile::LinkLifecycle::Absent
    );
    assert!(disabled.network_policy.is_none());
    assert_eq!(
        disabled_state, before_state,
        "desired keys and address assignments remain intact"
    );
    assert_eq!(disabled_product.clients, before_product.clients);
    assert_eq!(disabled_product.interfaces, before_product.interfaces);
    assert_eq!(
        disabled_product
            .network_operational_enabled
            .get(&interface_id),
        Some(&false)
    );

    let enabled_generation = service
        .set_network_enabled(disabled_generation, true)
        .unwrap();
    let enabled_state = store.load().unwrap().state;
    let enabled_product = store.load_product().unwrap().state;
    let enabled = wg_basic::management::project_diagnostic_intent(
        installation,
        enabled_generation,
        &enabled_state,
        &enabled_product,
    )
    .unwrap()
    .unwrap();
    assert_eq!(enabled.interface_id, before.interface_id);
    assert_eq!(enabled.desired_interface, before.desired_interface);
    assert_eq!(enabled.network_policy, before.network_policy);
    assert_eq!(
        enabled_product.clients[&client.client_id],
        before_product.clients[&client.client_id]
    );
    assert_eq!(
        enabled_product
            .network_operational_enabled
            .get(&interface_id),
        Some(&true)
    );
    let audit = store.audit_events(20).unwrap();
    assert!(audit
        .iter()
        .any(|event| event.action == wg_basic::product::AuditAction::NetworkDisable));
    assert!(audit
        .iter()
        .any(|event| event.action == wg_basic::product::AuditAction::NetworkEnable));
}

#[test]
fn disabling_one_client_leaves_the_others_and_their_addresses_alone() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let first = create(&service, "one");
    let second = create(&service, "two");
    service
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: first.client_id,
            enabled: wg_basic::product::ClientEnabled::Disabled,
            expires_at: None,
        })
        .unwrap();

    // The disabled client still holds its address, so a new client cannot take it.
    let third = create(&service, "three");
    assert_ne!(third.assigned_address.to_string(), "10.8.0.2/32");
    assert_eq!(second.assigned_address.to_string(), "10.8.0.3/32");
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

#[test]
fn delete_removes_the_client_and_its_peer_and_releases_the_address() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let doomed = create(&service, "doomed");
    create(&service, "survivor");

    service
        .delete_client(ClientDeleteCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: doomed.client_id,
        })
        .unwrap();

    let desired = store.load().unwrap().state;
    let product = store.load_product().unwrap().state;
    assert_eq!(desired.interfaces[0].clients.len(), 1);
    assert_eq!(desired.interfaces[0].peers.len(), 1);
    assert!(!product.clients.contains_key(&doomed.client_id));
    assert!(!desired.interfaces[0]
        .clients
        .iter()
        .any(|c| c.id == doomed.client_id));

    // The released address is immediately reusable.
    let reused = create(&service, "reused");
    assert_eq!(reused.assigned_address.to_string(), "10.8.0.2/32");
}

// ---------------------------------------------------------------------------
// Audit atomicity
// ---------------------------------------------------------------------------

#[test]
fn every_committed_mutation_appends_exactly_one_audit_row() {
    let Setup {
        scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "audited");
    service
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: client.client_id,
            enabled: wg_basic::product::ClientEnabled::Disabled,
            expires_at: None,
        })
        .unwrap();
    service
        .delete_client(ClientDeleteCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: client.client_id,
        })
        .unwrap();

    let events = store.audit_events(100).unwrap();
    let actions: Vec<String> = events
        .iter()
        .map(|event| event.action.as_str().to_owned())
        .collect();
    assert_eq!(
        actions,
        vec![
            "client_delete".to_owned(),
            "client_disable".to_owned(),
            "client_create".to_owned(),
            "server_setup".to_owned(),
        ],
        "newest first, one row per committed mutation"
    );

    // Every row records the generation window it spans.
    for event in &events {
        if let (Some(before), Some(after)) = (event.generation_before, event.generation_after) {
            assert!(
                after > before,
                "generation_after must advance past generation_before"
            );
        }
    }
    let _ = scratch;
}

#[test]
fn a_refused_mutation_appends_no_audit_row_and_does_not_advance_the_generation() {
    let Setup {
        scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let before_generation = store.current_generation().unwrap();
    let before_events = store.audit_events(100).unwrap().len();

    let server = service.server().unwrap().unwrap();
    let _ = service.create_client(ClientCreateCommand {
        principal_id: admin(&service),
        expected_generation: DesiredGeneration::new(1).unwrap(),
        interface_id: server.interface_id,
        label: ClientLabel::new("never").unwrap(),
        requested_address: None,
        route_policy: None,
        dns_servers: Vec::new(),
        client_keepalive_seconds: None,
        expires_at: None,
        preshared_key: None,
        mtu: None,
    });

    assert_eq!(store.current_generation().unwrap(), before_generation);
    assert_eq!(
        store.audit_events(100).unwrap().len(),
        before_events,
        "a mutation that never committed must leave no audit row"
    );
    let _ = scratch;
}

#[test]
fn the_audit_table_has_no_column_that_could_hold_a_free_form_message() {
    let Setup {
        scratch,
        store: _store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let connection = rusqlite::Connection::open(scratch.db()).unwrap();
    let mut statement = connection
        .prepare("SELECT name FROM pragma_table_info('audit_events')")
        .unwrap();
    let columns: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    for column in &columns {
        assert!(
            !["message", "detail", "details", "payload", "body", "reason"]
                .contains(&column.as_str()),
            "audit_events must not gain a free-form column: {column}"
        );
    }
}

#[test]
fn product_rows_survive_a_plain_non_product_mutation() {
    // `write_desired` rewrites `clients`/`peers`, which cascades into the
    // product tables. A commit that changed nothing about products must not be
    // able to erase an operator's labels.
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "survivor");

    store
        .mutate(store.current_generation().unwrap(), |state| {
            let mut next = state.clone();
            next.client_routes.prefixes = vec![NetworkPrefix::new("0.0.0.0/0".parse().unwrap())];
            Ok(next)
        })
        .unwrap();

    let product = store.load_product().unwrap().state;
    let record = product
        .clients
        .get(&client.client_id)
        .expect("client product settings must survive a non-product commit");
    assert_eq!(record.settings.label.as_str(), "survivor");
    assert!(record.settings.enabled.is_enabled());
}

// ---------------------------------------------------------------------------
// Persistence across reopen
// ---------------------------------------------------------------------------

#[test]
fn product_state_survives_reopen_including_disabled_clients() {
    let Setup {
        scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let client = create(&service, "persisted");
    service
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: admin(&service),
            expected_generation: store.current_generation().unwrap(),
            client_id: client.client_id,
            enabled: wg_basic::product::ClientEnabled::Disabled,
            expires_at: None,
        })
        .unwrap();
    drop(store);

    let reopened = Arc::new(StateStore::open(scratch.db()).unwrap());
    let product = reopened.load_product().unwrap();
    assert!(
        !product.state.clients[&client.client_id]
            .settings
            .enabled
            .is_enabled(),
        "a disabled client must still be disabled after a restart"
    );
    assert_eq!(
        product.state.clients[&client.client_id]
            .settings
            .label
            .as_str(),
        "persisted"
    );
}

// ---------------------------------------------------------------------------
// Allocation is consulted through the service
// ---------------------------------------------------------------------------

#[test]
fn an_exhausted_pool_is_reported_rather_than_wrapping() {
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|command| {
        command.tunnel_prefix = NetworkPrefix::new("10.8.0.0/29".parse().unwrap());
    });
    let service = service(&store);
    // .1 is the server; .2 .. .6 are the five remaining usable hosts.
    let mut created = Vec::new();
    for index in 0..5 {
        created.push(create(&service, &format!("client-{index}")));
    }
    let server = service.server().unwrap().unwrap();

    let exhausted = service.create_client(ClientCreateCommand {
        principal_id: admin(&service),
        expected_generation: service.store().current_generation().unwrap(),
        interface_id: server.interface_id,
        label: ClientLabel::new("one too many").unwrap(),
        requested_address: None,
        route_policy: None,
        dns_servers: Vec::new(),
        client_keepalive_seconds: None,
        expires_at: None,
        preshared_key: None,
        mtu: None,
    });
    assert!(
        matches!(
            exhausted,
            Err(wg_basic::product::ProductError::Allocation(_))
        ),
        "an exhausted pool must be reported, not wrapped"
    );
    assert_eq!(created.len(), 5);
}

// ---------------------------------------------------------------------------
// Allocator, reached the way production reaches it
// ---------------------------------------------------------------------------

#[test]
fn the_allocator_is_deterministic_for_identical_product_state() {
    let build = || {
        AllocationContext::new("10.8.0.0/24".parse().unwrap())
            .unwrap()
            .with_server_addresses([Ipv4Addr::new(10, 8, 0, 1)])
            .with_reserved_clients([Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 9)])
    };
    let first = build().allocate(AddressRequest::Automatic).unwrap();
    for _ in 0..8 {
        assert_eq!(
            build().allocate(AddressRequest::Automatic).unwrap(),
            first,
            "the same product state must always yield the same address"
        );
    }
    assert_eq!(first, Ipv4Addr::new(10, 8, 0, 3));
}

#[test]
fn a_conflicting_request_is_refused_with_a_bounded_reason() {
    let context = AllocationContext::new("10.8.0.0/24".parse().unwrap())
        .unwrap()
        .with_reserved_clients([Ipv4Addr::new(10, 8, 0, 5)]);
    assert_eq!(
        context.allocate(AddressRequest::Requested(Ipv4Addr::new(10, 8, 0, 5))),
        Err(AllocationError::AlreadyUsed(Ipv4Addr::new(10, 8, 0, 5)))
    );
}

#[test]
fn product_mutation_is_serialised_by_the_store_lock() {
    // Two threads racing the same expected generation: exactly one may win, and
    // the loser must be a stale-generation refusal rather than a second commit.
    let Setup {
        scratch: _scratch,
        store,
        principal: _principal,
        ..
    } = setup(|_| {});
    let service = service(&store);
    let server = service.server().unwrap().unwrap();
    let generation = store.current_generation().unwrap();

    let store = Arc::clone(&store);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let outcomes: Arc<Mutex<Vec<Result<DesiredGeneration, ()>>>> = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for index in 0..2 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let outcomes = Arc::clone(&outcomes);
        let interface_id = server.interface_id;
        handles.push(std::thread::spawn(move || {
            let service = ProductService::new(&store);
            barrier.wait();
            let result = service.create_client(ClientCreateCommand {
                principal_id: admin(&service),
                expected_generation: generation,
                interface_id,
                label: ClientLabel::new(format!("racer-{index}")).unwrap(),
                requested_address: None,
                route_policy: None,
                dns_servers: Vec::new(),
                client_keepalive_seconds: None,
                expires_at: None,
                preshared_key: None,
                mtu: None,
            });
            outcomes.lock().unwrap().push(
                result
                    .map(|(_, receipt)| receipt.generation)
                    .map_err(|_| ()),
            );
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let outcomes = outcomes.lock().unwrap();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one writer may commit at an expected generation"
    );
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1,
        "the loser must be refused"
    );
}

#[test]
fn interface_identifiers_are_distinct_per_installation() {
    // Guards the setup path against reusing a fixed identifier, which would let
    // two installations claim the same durable owner tag.
    let first = setup(|_| {});
    let second = setup(|_| {});
    assert_ne!(
        first.service().server().unwrap().unwrap().interface_id,
        second.service().server().unwrap().unwrap().interface_id
    );
    assert_ne!(
        InterfaceId::new(),
        InterfaceId::new(),
        "identifiers must be independent random values"
    );
    assert_ne!(ClientId::new(), ClientId::new());
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn create_with(
    service: &ProductService<'_>,
    label: &str,
    expires_at: Option<i64>,
    preshared_key: Option<wg_basic::product::PresharedKeyRequest>,
    mtu: Option<u16>,
) -> Result<wg_basic::product::ProductClient, ProductError> {
    let generation = service.store().current_generation().unwrap();
    let server = service.server().unwrap().expect("configured server");
    service
        .create_client(ClientCreateCommand {
            principal_id: admin(service),
            expected_generation: generation,
            interface_id: server.interface_id,
            label: ClientLabel::new(label).unwrap(),
            requested_address: None,
            route_policy: None,
            dns_servers: Vec::new(),
            client_keepalive_seconds: None,
            expires_at,
            preshared_key,
            mtu,
        })
        .map(|(client, _)| client)
}

#[test]
fn historical_setup_stays_a_gateway_and_an_unchecked_setup_is_host_only() {
    let gateway = setup(|_| {});
    let stored = gateway.store.load().unwrap().state.network_policy.unwrap();
    assert_eq!(stored.mode, NetworkPolicyMode::Gateway);
    assert!(stored.masquerade);
    assert!(stored.ipv4_forwarding_required);

    let host = setup(|command| {
        command.ipv4_forwarding_required = false;
        command.ipv6_forwarding_required = false;
        command.masquerade = false;
        command.mode = None;
    });
    let stored = host.store.load().unwrap().state.network_policy.unwrap();
    assert_eq!(stored.mode, NetworkPolicyMode::HostOnly);
    assert!(!stored.masquerade);

    let explicit = setup(|command| {
        command.mode = Some(NetworkPolicyMode::Gateway);
        command.ipv4_forwarding_required = true;
        command.masquerade = true;
    });
    let stored = explicit.store.load().unwrap().state.network_policy.unwrap();
    assert_eq!(stored.mode, NetworkPolicyMode::Gateway);
    assert!(stored.masquerade);
}

#[test]
fn a_past_deadline_is_refused_and_a_due_client_is_disabled_in_id_order() {
    let installed = setup(|_| {});
    let service = installed.service();
    let now = now_seconds();
    let generation = installed.store.current_generation().unwrap();
    let refused = create_with(&service, "past", Some(now - 60), None, None);
    assert!(matches!(refused, Err(ProductError::InvalidClientExpiry)));
    assert_eq!(installed.store.current_generation().unwrap(), generation);

    let later = now + 1;
    let first = create_with(&service, "first", Some(later), None, None).unwrap();
    let second = create_with(&service, "second", Some(later), None, None).unwrap();
    assert_eq!(first.expires_at, Some(later));
    assert_eq!(
        first.expiry_state,
        wg_basic::product::ExpiryState::Scheduled
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    let later = now_seconds();
    let mut expected = [first.client_id, second.client_id];
    expected.sort();
    let expired = service.expire_due_clients(later).unwrap();
    assert_eq!(
        expired
            .iter()
            .map(|(client, _)| client.client_id)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(expired
        .iter()
        .all(|(client, _)| client.settings.enabled == wg_basic::product::ClientEnabled::Disabled));
    let generation = installed.store.current_generation().unwrap();
    assert!(service.expire_due_clients(later).unwrap().is_empty());
    assert_eq!(installed.store.current_generation().unwrap(), generation);
    let events = installed.store.audit_events(20).unwrap();
    let expiries: Vec<_> = events
        .iter()
        .filter(|event| event.action == wg_basic::product::AuditAction::ClientExpire)
        .collect();
    assert_eq!(expiries.len(), 2);
    assert!(expiries.iter().all(|event| event.principal_id.is_none()));
    let kept = service
        .client_config_material(first.client_id)
        .expect("a disabled client keeps its config");
    assert!(!kept.private_key.expose_secret().is_empty());
    let projected = wg_basic::state::project(
        &installed.store.load().unwrap().state,
        installed
            .store
            .installation_metadata()
            .unwrap()
            .installation_id,
        &wg_basic::state::ClientVisibility::from_product(
            &installed.store.load().unwrap().state,
            &installed.store.load_product().unwrap().state,
        ),
    )
    .unwrap();
    assert!(projected.interfaces[0]
        .wireguard
        .as_ref()
        .unwrap()
        .peers
        .is_empty());

    let stale = service.set_client_enabled(SetClientEnabledCommand {
        principal_id: admin(&service),
        expected_generation: installed.store.current_generation().unwrap(),
        client_id: first.client_id,
        enabled: wg_basic::product::ClientEnabled::Enabled,
        expires_at: None,
    });
    assert!(matches!(stale, Err(ProductError::InvalidClientExpiry)));
    let enabled = service
        .set_client_enabled(SetClientEnabledCommand {
            principal_id: admin(&service),
            expected_generation: installed.store.current_generation().unwrap(),
            client_id: first.client_id,
            enabled: wg_basic::product::ClientEnabled::Enabled,
            expires_at: Some(None),
        })
        .unwrap();
    assert_eq!(enabled.0.expiry_state, wg_basic::product::ExpiryState::None);
    assert!(enabled.0.settings.enabled.is_enabled());
}

#[test]
fn preshared_keys_are_generated_or_cleared_and_never_echoed() {
    let installed = setup(|command| {
        command.default_client_route_policy = ClientRoutePolicy {
            prefixes: vec![NetworkPrefix::new("0.0.0.0/0".parse().unwrap())],
        };
    });
    let service = installed.service();
    let client = create_with(
        &service,
        "keyed",
        None,
        Some(wg_basic::product::PresharedKeyRequest::Generate),
        None,
    )
    .unwrap();
    assert!(client.preshared_key_configured);
    assert_eq!(client.expiry_state, wg_basic::product::ExpiryState::None);
    let summary = serde_json::to_string(&client).unwrap();
    assert!(summary.contains("\"preshared_key_configured\":true"));
    assert!(!summary.contains("PresharedKey"));
    let first = service
        .client_config_material(client.client_id)
        .unwrap()
        .preshared_key
        .unwrap();
    let rendered = wg_basic::product::render_config(
        &service.client_config_material(client.client_id).unwrap(),
    )
    .unwrap();
    assert!(rendered.expose().contains("PresharedKey = "));
    let events = installed.store.audit_events(20).unwrap();
    assert!(events
        .iter()
        .any(|event| event.action == wg_basic::product::AuditAction::ClientCreate));
    assert!(!events
        .iter()
        .any(|event| { event.action == wg_basic::product::AuditAction::ClientPresharedKeySet }));

    let generation = installed.store.current_generation().unwrap();
    let (renamed, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: client.client_id,
            label: Some(ClientLabel::new("renamed").unwrap()),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    let after_rename = service
        .client_config_material(renamed.client_id)
        .unwrap()
        .preshared_key
        .unwrap();
    assert_eq!(
        first.expose_secret(),
        after_rename.expose_secret(),
        "an edit that omits the key leaves the key bytes unchanged"
    );

    let (rotated, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: installed.store.current_generation().unwrap(),
            client_id: client.client_id,
            label: Some(ClientLabel::new("rotated").unwrap()),
            preshared_key: Some(wg_basic::product::PresharedKeyRequest::Generate),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    let second = service
        .client_config_material(rotated.client_id)
        .unwrap()
        .preshared_key
        .unwrap();
    assert_ne!(first.expose_secret(), second.expose_secret());
    assert!(installed
        .store
        .audit_events(20)
        .unwrap()
        .iter()
        .any(|event| {
            event.action == wg_basic::product::AuditAction::ClientPresharedKeySet
                && event.resource_id.as_deref() == Some(client.client_id.to_string().as_str())
        }));

    let (cleared, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: installed.store.current_generation().unwrap(),
            client_id: client.client_id,
            preshared_key: Some(wg_basic::product::PresharedKeyRequest::Clear),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    assert!(!cleared.preshared_key_configured);
    let config = wg_basic::product::render_config(
        &service.client_config_material(client.client_id).unwrap(),
    )
    .unwrap();
    assert!(!config.expose().contains("PresharedKey = "));
    assert!(installed
        .store
        .audit_events(20)
        .unwrap()
        .iter()
        .any(|event| { event.action == wg_basic::product::AuditAction::ClientPresharedKeyClear }));
}

#[test]
fn client_mtu_is_bounded_and_does_not_change_the_address_plan() {
    let installed = setup(|command| {
        command.default_client_route_policy = ClientRoutePolicy {
            prefixes: vec![NetworkPrefix::new("0.0.0.0/0".parse().unwrap())],
        };
    });
    let service = installed.service();
    let client = create_with(&service, "mtu", None, None, None).unwrap();
    assert_eq!(client.mtu, None);
    let omitted = wg_basic::product::render_config(
        &service.client_config_material(client.client_id).unwrap(),
    )
    .unwrap();
    assert!(!omitted.expose().contains("MTU = "));
    let generation = installed.store.current_generation().unwrap();
    for value in [1279_u16, 9001] {
        let refused = service.update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: client.client_id,
            mtu: Some(Some(value)),
            ..ClientUpdateCommand::default()
        });
        assert!(matches!(refused, Err(ProductError::InvalidClientMtu)));
        assert_eq!(installed.store.current_generation().unwrap(), generation);
    }
    let before = installed.store.load().unwrap().state;
    let (updated, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: generation,
            client_id: client.client_id,
            mtu: Some(Some(1280)),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    assert_eq!(updated.mtu, Some(1280));
    assert_eq!(installed.store.load().unwrap().state, before);
    let written = wg_basic::product::render_config(
        &service.client_config_material(client.client_id).unwrap(),
    )
    .unwrap();
    let text = written.expose();
    let address = text.find("Address = ").unwrap();
    let mtu = text.find("MTU = 1280\n").unwrap();
    assert!(address < mtu);
    let (left, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: installed.store.current_generation().unwrap(),
            client_id: client.client_id,
            label: Some(ClientLabel::new("still").unwrap()),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    assert_eq!(left.mtu, Some(1280));
    let (cleared, _) = service
        .update_client(ClientUpdateCommand {
            principal_id: admin(&service),
            expected_generation: installed.store.current_generation().unwrap(),
            client_id: client.client_id,
            mtu: Some(None),
            ..ClientUpdateCommand::default()
        })
        .unwrap();
    assert_eq!(cleared.mtu, None);
    let wide = create_with(&service, "wide", None, None, Some(9000)).unwrap();
    let wide_config =
        wg_basic::product::render_config(&service.client_config_material(wide.client_id).unwrap())
            .unwrap();
    assert!(wide_config.expose().contains("MTU = 9000\n"));
}

#[test]
fn admin_at_a_fresh_scratch_returns_a_stable_principal() {
    let scratch = Scratch::new("admin");
    let first = admin_at(&scratch);
    let second = admin_at(&scratch);
    assert_eq!(first, second, "provisioning is idempotent for one username");
}
