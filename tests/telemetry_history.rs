#![cfg(unix)]
//! Bounded telemetry history (observability M003).

use std::{
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use wg_basic::{
    domain::{ClientId, ClientRoutePolicy, DesiredGeneration, NetworkPrefix, PrincipalId},
    http::{Bucket, LoginLimiter, ManagementHttpConfig, ManagementService, OriginPolicy},
    management::spawn,
    observability::TELEMETRY_SAMPLES_PER_CLIENT,
    product::{
        ClientCreateCommand, ClientDeleteCommand, ClientLabel, ProductService, ServerSetupCommand,
    },
    state::{StateStore, TelemetrySampleInsert},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const ADMIN_PASSWORD: &str = "an administrator password";

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-telemetry-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }

    fn absent_socket(&self) -> PathBuf {
        self.0.join("no-netd.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sample_at(client_id: ClientId, at: u64, tag: u8) -> TelemetrySampleInsert {
    TelemetrySampleInsert {
        client_id,
        observed_at_unix: at,
        rx_bytes: u64::from(tag) * 1_000,
        tx_bytes: u64::from(tag) * 2_000,
        handshake_age_seconds: Some(u64::from(tag)),
    }
}

fn history_len(store: &StateStore, client_id: ClientId) -> usize {
    store
        .telemetry_history(Some(&[client_id]))
        .unwrap()
        .clients
        .into_iter()
        .find(|client| client.client_id == client_id)
        .map(|client| client.points.len())
        .unwrap_or(0)
}

fn oldest_observed_at(store: &StateStore, client_id: ClientId) -> Option<u64> {
    store
        .telemetry_history(Some(&[client_id]))
        .unwrap()
        .clients
        .into_iter()
        .find(|client| client.client_id == client_id)
        .and_then(|client| client.points.first().map(|point| point.observed_at_unix))
}

fn provisioned_store(scratch: &Scratch) -> (Arc<StateStore>, PrincipalId, ClientId) {
    let store = Arc::new(StateStore::initialize(scratch.db()).unwrap());
    wg_basic::management::set_password_at(scratch.db(), "admin", ADMIN_PASSWORD).unwrap();
    let principal = store.principals().unwrap()[0].id;
    let service = ProductService::new(&store);
    let setup = ServerSetupCommand {
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
    let (server, receipt) = service.setup_server(setup).unwrap();
    let (client, _) = service
        .create_client(ClientCreateCommand {
            principal_id: principal,
            expected_generation: receipt.generation,
            interface_id: server.interface_id,
            label: ClientLabel::new("a client").unwrap(),
            requested_address: None,
            route_policy: None,
            dns_servers: Vec::<IpAddr>::new(),
            client_keepalive_seconds: None,
            preshared_key: None,
            expires_at: None,
            mtu: None,
        })
        .unwrap();
    (store, principal, client.client_id)
}

#[test]
fn the_121st_sample_drops_the_oldest_for_one_client() {
    let scratch = Scratch::new("cap");
    let (store, _, client_id) = provisioned_store(&scratch);
    let gen_before = store.current_generation().unwrap();
    let samples: Vec<_> = (0..121)
        .map(|index| sample_at(client_id, index as u64, index as u8))
        .collect();
    store.insert_telemetry_samples(&samples).unwrap();
    let gen_after = store.current_generation().unwrap();
    assert_eq!(gen_before, gen_after);
    assert_eq!(history_len(&store, client_id), TELEMETRY_SAMPLES_PER_CLIENT);
    assert_eq!(oldest_observed_at(&store, client_id), Some(1));
}

#[test]
fn client_delete_removes_telemetry_samples() {
    let scratch = Scratch::new("delete");
    let (store, principal, client_id) = provisioned_store(&scratch);
    store
        .insert_telemetry_samples(&[sample_at(client_id, 1, 1)])
        .unwrap();
    assert_eq!(history_len(&store, client_id), 1);
    let generation = store.current_generation().unwrap();
    ProductService::new(&store)
        .delete_client(ClientDeleteCommand {
            principal_id: principal,
            expected_generation: generation,
            client_id,
        })
        .unwrap();
    assert_eq!(history_len(&store, client_id), 0);
}

#[test]
fn startup_prune_enforces_the_per_client_cap() {
    let scratch = Scratch::new("prune");
    let (store, _, client_id) = provisioned_store(&scratch);
    let samples: Vec<_> = (0..130)
        .map(|index| sample_at(client_id, index as u64, 1))
        .collect();
    store.insert_telemetry_samples(&samples).unwrap();
    store.prune_all_telemetry_samples().unwrap();
    assert_eq!(history_len(&store, client_id), TELEMETRY_SAMPLES_PER_CLIENT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_get_requires_a_session() {
    let scratch = Scratch::new("session");
    let startup = spawn(wg_basic::management::WorkerConfig::new(
        scratch.db(),
        scratch.absent_socket(),
    ))
    .unwrap();
    let client = startup.client().clone();
    drop(startup);
    let api = wg_basic::http::AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only("127.0.0.1:0".parse().unwrap())),
        Arc::new(LoginLimiter::new(
            Bucket::per_second(100, 100),
            Bucket::per_second(100, 100),
            8,
        )),
    );
    let config = ManagementHttpConfig::new("127.0.0.1:0")
        .unwrap()
        .runtime_config()
        .unwrap();
    let server = eggserve_server::Server::builder()
        .runtime(config)
        .build()
        .unwrap();
    let handle = server
        .start_with_service(ManagementService::new(api))
        .await
        .unwrap();
    let addr = handle.local_addr();
    let (control, mut completion) = handle.into_parts();
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    use std::io::{Read, Write};
    stream
        .write_all(
            format!(
                "GET /api/v1/clients/telemetry-history HTTP/1.1\r\n\
                 Host: 127.0.0.1:{}\r\n\
                 Connection: close\r\n\r\n",
                addr.port()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert!(body.starts_with("HTTP/1.1 401"), "{body}");
    control.shutdown();
    completion.wait().await.unwrap();
}

#[tokio::test]
async fn worker_history_lists_chronological_points() {
    let scratch = Scratch::new("api");
    let (store, _, client_id) = provisioned_store(&scratch);
    store
        .insert_telemetry_samples(&[sample_at(client_id, 10, 1), sample_at(client_id, 20, 2)])
        .unwrap();
    drop(store);
    let startup = spawn(wg_basic::management::WorkerConfig::new(
        scratch.db(),
        scratch.absent_socket(),
    ))
    .unwrap();
    let response = startup.client().telemetry_history().await.unwrap();
    assert_eq!(response.clients.len(), 1);
    assert_eq!(response.clients[0].client_id, client_id);
    assert_eq!(response.clients[0].points.len(), 2);
    assert_eq!(response.clients[0].points[0].observed_at_unix, 10);
    assert_eq!(response.clients[0].points[1].observed_at_unix, 20);
    let _ = startup.stop().await;
}
