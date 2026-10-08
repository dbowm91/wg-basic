#![cfg(all(target_os = "linux", feature = "linux-integration"))]

//! Rootful Phase 9 upgrade rehearsal with real v4/v5 binaries and WireGuard
//! traffic. All network links live in disposable namespaces.
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{
    domain::{InterfaceName, NetworkPrefix, PrivateKey, PublicKey},
    protocol::{request, RequestOperation, ResponseBody},
    wireguard::{DesiredWireGuardPeer, FieldUpdate, PeerMutation, WireGuardDevicePatch},
};

const CANDIDATE_TEST: &str = env!("CARGO_BIN_EXE_wg-basic");
const PASSWORD: &str = "phase nine upgrade test password";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-upgrade-rootful-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state.db")
    }
    fn server_socket(&self) -> PathBuf {
        self.0.join("server-netd.sock")
    }
    fn client_socket(&self) -> PathBuf {
        self.0.join("client-netd.sock")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Namespace(String);
impl Namespace {
    fn new(name: &str) -> Self {
        let name = format!("wgu-{}-{}", std::process::id() % 10000, name);
        run_ip(&["netns", "add", &name]);
        run_ip(&["-n", &name, "link", "set", "lo", "up"]);
        Self(name)
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

struct ChildGuard(Child);
impl ChildGuard {
    fn stop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_ip(args: &[&str]) {
    let output = Command::new("ip")
        .args(args)
        .output()
        .expect("iproute2 runs");
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn free_bind() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start_netd(binary: &str, namespace: &Namespace, socket: &Path) -> ChildGuard {
    let child = Command::new("ip")
        .args(["netns", "exec", &namespace.0, binary, "netd", "--socket"])
        .arg(socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "netd did not bind {}",
            socket.display()
        );
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("netd exited before binding: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    child
}

fn start_serve(binary: &str, state: &Path, socket: &Path) -> (ChildGuard, SocketAddr) {
    let addr = free_bind();
    let child = Command::new(binary)
        .args(["serve", "--state"])
        .arg(state)
        .arg("--socket")
        .arg(socket)
        .args(["--http-bind", &addr.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(30)).is_ok() {
            return (child, addr);
        }
        assert!(Instant::now() < deadline, "serve did not bind");
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("serve exited before binding: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}
impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let origin = format!("http://{addr}");
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    if method != "GET" {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Origin"))
        {
            raw.push_str(&format!("Origin: {origin}\r\n"));
        }
    }
    raw.push_str("\r\n");
    raw.push_str(body);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let response = String::from_utf8(bytes).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_owned(),
    }
}

fn post(addr: SocketAddr, cookie: &str, csrf: &str, path: &str, body: &str) -> Reply {
    let origin = format!("http://{addr}");
    http(
        addr,
        "POST",
        path,
        &[
            ("Origin", &origin),
            ("Cookie", cookie),
            ("x-wg-basic-csrf", csrf),
            ("Content-Type", "application/json"),
        ],
        body,
    )
}

fn authenticate(addr: SocketAddr) -> (String, String) {
    let origin = format!("http://{addr}");
    let reply = http(
        addr,
        "POST",
        "/api/v1/login",
        &[("Origin", &origin), ("Content-Type", "application/json")],
        &format!(r#"{{"username":"admin","password":{PASSWORD:?}}}"#),
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    let cookie = reply
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let session = http(addr, "GET", "/api/v1/session", &[("Cookie", &cookie)], "");
    assert_eq!(session.status, 200, "{}", session.body);
    let csrf = serde_json::from_str::<serde_json::Value>(&session.body).unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    (cookie, csrf)
}

fn config_text(addr: SocketAddr, cookie: &str, client_id: &str) -> String {
    let reply = http(
        addr,
        "GET",
        &format!("/api/v1/clients/{client_id}/config"),
        &[("Cookie", cookie)],
        "",
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    reply.body
}

fn exported_fields(config: &str) -> std::collections::HashMap<&str, &str> {
    config
        .lines()
        .filter_map(|line| line.split_once(" = "))
        .collect()
}

fn install_client(
    namespace: &Namespace,
    socket: &Path,
    config: &str,
) -> (InterfaceName, SocketAddr) {
    let fields = exported_fields(config);
    let address = fields["Address"].parse::<NetworkPrefix>().unwrap();
    let endpoint = fields["Endpoint"].parse::<SocketAddr>().unwrap();
    let private_key = PrivateKey::new(fields["PrivateKey"].to_owned()).unwrap();
    let public_key = PublicKey::new(fields["PublicKey"].to_owned()).unwrap();
    let allowed_ips = fields["AllowedIPs"]
        .split(", ")
        .map(|entry| entry.parse::<NetworkPrefix>().unwrap())
        .collect();
    let psk = fields
        .get("PresharedKey")
        .map(|value| wg_basic::domain::PresharedKey::new((*value).to_owned()).unwrap());
    let keepalive = fields
        .get("PersistentKeepalive")
        .map(|value| value.parse::<u16>().unwrap());
    run_ip(&[
        "-n",
        &namespace.0,
        "link",
        "add",
        "wg-client",
        "type",
        "wireguard",
    ]);
    run_ip(&[
        "-n",
        &namespace.0,
        "addr",
        "add",
        &address.to_string(),
        "dev",
        "wg-client",
    ]);
    run_ip(&["-n", &namespace.0, "link", "set", "wg-client", "up"]);
    let interface: InterfaceName = "wg-client".parse().unwrap();
    let response = request(
        socket,
        RequestOperation::ApplyWireGuardDevice {
            interface: interface.clone(),
            patch: WireGuardDevicePatch {
                private_key: FieldUpdate::Set(private_key),
                listen_port: FieldUpdate::Set(51821),
                peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
                    public_key,
                    preshared_key: psk,
                    allowed_ips,
                    persistent_keepalive_seconds: keepalive,
                    endpoint: Some(endpoint),
                })),
            },
        },
        9701,
    )
    .unwrap();
    assert!(matches!(response, ResponseBody::WireGuardApplied(_)));
    run_ip(&[
        "-n",
        &namespace.0,
        "route",
        "add",
        "10.77.0.1/32",
        "dev",
        "wg-client",
    ]);
    (interface, endpoint)
}

fn require_handshake(namespace: &Namespace, socket: &Path) {
    let baseline_response = request(
        socket,
        RequestOperation::ObserveWireGuardDevice {
            interface: "wg-client".parse().unwrap(),
        },
        9702,
    )
    .unwrap();
    let ResponseBody::WireGuardDevice(baseline_device) = baseline_response else {
        panic!("expected client WireGuard baseline: {baseline_response:?}");
    };
    let baseline_peer = baseline_device
        .peers
        .first()
        .expect("the configured client peer is observable");
    let baseline_tx = baseline_peer.tx_bytes.unwrap_or_default();
    let baseline_rx = baseline_peer.rx_bytes.unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = request(
            socket,
            RequestOperation::ObserveWireGuardDevice {
                interface: "wg-client".parse().unwrap(),
            },
            9702,
        )
        .unwrap();
        let ResponseBody::WireGuardDevice(device) = response else {
            panic!("expected client WireGuard observation: {response:?}");
        };
        if device.peers.iter().any(|peer| {
            peer.latest_handshake.is_some()
                && peer.rx_bytes.unwrap_or_default() > baseline_rx
                && peer.tx_bytes.unwrap_or_default() > baseline_tx
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "client handshake/traffic did not converge"
        );
        let _ = Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespace.0,
                "ping",
                "-n",
                "-c",
                "1",
                "-W",
                "1",
                "-I",
                "wg-client",
                "10.77.0.1",
            ])
            .output();
        thread::sleep(Duration::from_millis(100));
    }
}

fn assert_healthy_service(addr: SocketAddr, cookie: &str) {
    assert_eq!(http(addr, "GET", "/healthz", &[], "").body, "ok");
    let health = http(addr, "GET", "/api/v1/health", &[("Cookie", cookie)], "");
    assert_eq!(health.status, 200, "{}", health.body);
    let value: serde_json::Value = serde_json::from_str(&health.body).unwrap();
    assert_eq!(value["health"]["database_healthy"], true, "{}", health.body);
    assert_eq!(value["health"]["netd_reachable"], true, "{}", health.body);
    assert_eq!(value["backend"]["answered"], true, "{}", health.body);
}

fn assert_doctor_has_no_required_failure(output: &std::process::Output, label: &str) {
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{label} doctor JSON: {error}"));
    let checks = report["checks"].as_array().expect("doctor checks array");
    assert!(
        checks.iter().all(|check| check["disposition"] != "fail"),
        "{label} doctor has a failed required check: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    for required in ["sqlite", "state", "netd"] {
        assert!(
            checks
                .iter()
                .any(|check| check["id"] == required && check["disposition"] == "pass"),
            "{label} doctor did not pass required check {required}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

fn checkpoint_state(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    connection.close().unwrap();
}

fn start_network_pair(server: &Namespace, client: &Namespace) {
    run_ip(&[
        "link", "add", "wgu-srv", "type", "veth", "peer", "name", "wgu-cli",
    ]);
    run_ip(&["link", "set", "wgu-srv", "netns", &server.0]);
    run_ip(&["link", "set", "wgu-cli", "netns", &client.0]);
    run_ip(&[
        "-n",
        &server.0,
        "addr",
        "add",
        "198.18.77.1/24",
        "dev",
        "wgu-srv",
    ]);
    run_ip(&[
        "-n",
        &client.0,
        "addr",
        "add",
        "198.18.77.2/24",
        "dev",
        "wgu-cli",
    ]);
    run_ip(&["-n", &server.0, "link", "set", "wgu-srv", "up"]);
    run_ip(&["-n", &client.0, "link", "set", "wgu-cli", "up"]);
}

fn seed_from_old_api(
    old: &str,
    state: &Path,
    server_socket: &Path,
) -> (String, String, String, String, Vec<String>) {
    let mut admin = Command::new(old)
        .args(["admin", "set-password", "--password-stdin", "--state"])
        .arg(state)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    admin
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let output = admin.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "old admin bootstrap: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let (serve, addr) = start_serve(old, state, server_socket);
    let (cookie, csrf) = authenticate(addr);
    let setup = post(
        addr,
        &cookie,
        &csrf,
        "/api/v1/setup",
        r#"{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"10.77.0.0/24","listen_port":51820,"advertised_endpoint":"198.18.77.1:51820","egress_interface":"wgu-srv","ipv4_forwarding_required":false,"masquerade":false,"default_client_route_policy":{"prefixes":["10.77.0.0/24"]}}"#,
    );
    assert_eq!(setup.status, 200, "{}", setup.body);
    let setup_json: serde_json::Value = serde_json::from_str(&setup.body).unwrap();
    let interface_id = setup_json["data"]["interface_id"].as_str().unwrap();
    let mut generation = setup_json["generation"].as_u64().unwrap();
    let mut ids = Vec::new();
    for label in ["rollback-client-a", "rollback-client-b"] {
        let body = format!(
            r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"{label}"}}"#
        );
        let created = post(addr, &cookie, &csrf, "/api/v1/clients", &body);
        assert_eq!(created.status, 201, "{}", created.body);
        let json: serde_json::Value = serde_json::from_str(&created.body).unwrap();
        ids.push(json["data"]["client_id"].as_str().unwrap().to_owned());
        generation = json["generation"].as_u64().unwrap();
    }
    let config = config_text(addr, &cookie, &ids[0]);
    drop(serve);
    (cookie, csrf, ids[0].clone(), config, ids)
}

#[test]
#[ignore = "requires root, iproute2, and separately built old/candidate binaries"]
fn v4_product_traffic_rolls_back_and_reupgrades_as_one_transaction() {
    let old = std::env::var("WGB_OLD_BINARY").unwrap();
    let old = fs::canonicalize(old).unwrap();
    let old = old.to_str().unwrap();
    let candidate =
        std::env::var("WGB_CANDIDATE_BINARY").unwrap_or_else(|_| CANDIDATE_TEST.to_owned());
    let candidate = fs::canonicalize(candidate).unwrap();
    let candidate = candidate.to_str().unwrap();
    let scratch = Scratch::new();
    let server_ns = Namespace::new("server");
    let client_ns = Namespace::new("client");
    start_network_pair(&server_ns, &client_ns);
    let state = scratch.state();
    let backup = scratch.0.join("pre-update-v4.db");

    let old_netd = start_netd(old, &server_ns, &scratch.server_socket());
    let (old_cookie, _old_csrf, first_client_id, old_config, client_ids) =
        seed_from_old_api(old, &state, &scratch.server_socket());
    let mut client_netd = start_netd(old, &client_ns, &scratch.client_socket());
    let (_wg_interface, _endpoint) =
        install_client(&client_ns, &scratch.client_socket(), &old_config);
    require_handshake(&client_ns, &scratch.client_socket());
    let old_backup = Command::new(old)
        .args(["state", "backup", "--state"])
        .arg(&state)
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        old_backup.status.success(),
        "old backup: {}",
        String::from_utf8_lossy(&old_backup.stderr)
    );
    let backup_verify = Command::new(candidate)
        .args(["state", "verify"])
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        backup_verify.status.success(),
        "old backup verify: {}",
        String::from_utf8_lossy(&backup_verify.stderr)
    );
    // Candidate migrates only after old roles stop. Withhold candidate netd to
    // force the release health gate to fail after the v4→v5 migration.
    drop(old_netd);

    let migration = Command::new(candidate)
        .args(["state", "status", "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(
        migration.status.success(),
        "{}",
        String::from_utf8_lossy(&migration.stderr)
    );
    assert!(String::from_utf8_lossy(&migration.stdout).contains("schema version:     5"));
    checkpoint_state(&state);
    let migrated_snapshot = wg_basic::state::inspect_readonly(&state).unwrap();
    let migrated_interface = migrated_snapshot.desired.state.interfaces[0].id;
    assert_eq!(
        migrated_snapshot
            .product
            .network_operational_enabled
            .get(&migrated_interface),
        Some(&true),
        "v4→v5 migration must preserve the prior enabled network behavior"
    );
    let auto_snapshot = state.with_file_name("state.db.pre-migration-v4");
    assert!(auto_snapshot.exists());
    let snapshot_verify = Command::new(candidate)
        .args(["state", "verify"])
        .arg(&auto_snapshot)
        .output()
        .unwrap();
    assert!(
        snapshot_verify.status.success(),
        "automatic snapshot verify: {}",
        String::from_utf8_lossy(&snapshot_verify.stderr)
    );
    let old_refusal = Command::new(old)
        .args(["state", "status", "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(!old_refusal.status.success());

    let (mut degraded_candidate, degraded_addr) =
        start_serve(candidate, &state, &scratch.server_socket());
    let degraded = http(degraded_addr, "GET", "/healthz", &[], "");
    assert_eq!(degraded.body, "degraded");
    assert!(degraded_candidate.0.try_wait().unwrap().is_none());
    let failed_doctor = Command::new(candidate)
        .args(["doctor", "--state"])
        .arg(&state)
        .args(["--socket"])
        .arg(scratch.server_socket())
        .args(["--json"])
        .output()
        .unwrap();
    assert_ne!(
        failed_doctor.status.code(),
        Some(0),
        "missing netd must fail release health"
    );
    let failed_report: serde_json::Value = serde_json::from_slice(&failed_doctor.stdout).unwrap();
    assert_ne!(failed_report["overall"], "pass");
    // State rollback must happen before old roles resume.
    degraded_candidate.stop();
    let restore = Command::new(old)
        .args(["state", "restore", "--state"])
        .arg(&state)
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );

    let restored_server_netd = start_netd(old, &server_ns, &scratch.server_socket());
    let (restored_serve, restored_addr) = start_serve(old, &state, &scratch.server_socket());
    assert_eq!(
        http(
            restored_addr,
            "GET",
            "/api/v1/clients",
            &[("Cookie", &old_cookie)],
            ""
        )
        .status,
        200
    );
    assert_healthy_service(restored_addr, &old_cookie);
    require_handshake(&client_ns, &scratch.client_socket());
    drop(restored_serve);
    checkpoint_state(&state);
    assert!(
        wg_basic::state::inspect_readonly(&state).is_ok(),
        "restored v4 immutable inspection error: {:?}",
        wg_basic::state::inspect_readonly(&state).err()
    );
    // Phase 8 predates the doctor command, so Phase 9's read-only doctor checks
    // the restored v4 state before the old service resumes.
    let restored_doctor = Command::new(candidate)
        .args(["doctor", "--state"])
        .arg(&state)
        .args(["--socket"])
        .arg(scratch.server_socket())
        .args(["--json"])
        .output()
        .unwrap();
    assert_doctor_has_no_required_failure(&restored_doctor, "restored-v4");
    drop(restored_server_netd);
    client_netd.stop();

    let reupgrade = Command::new(candidate)
        .args(["state", "status", "--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(reupgrade.status.success());
    let candidate_netd = start_netd(candidate, &server_ns, &scratch.server_socket());
    let candidate_client_netd = start_netd(candidate, &client_ns, &scratch.client_socket());
    let (candidate_serve, candidate_addr) =
        start_serve(candidate, &state, &scratch.server_socket());
    let candidate_clients = http(
        candidate_addr,
        "GET",
        "/api/v1/clients",
        &[("Cookie", &old_cookie)],
        "",
    );
    assert_eq!(candidate_clients.status, 200, "{}", candidate_clients.body);
    let candidate_json: serde_json::Value = serde_json::from_str(&candidate_clients.body).unwrap();
    let candidate_ids: Vec<&str> = candidate_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|client| client["client_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        candidate_ids,
        client_ids.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_healthy_service(candidate_addr, &old_cookie);
    let candidate_config = config_text(candidate_addr, &old_cookie, &first_client_id);
    assert_eq!(candidate_config, old_config);
    require_handshake(&client_ns, &scratch.client_socket());
    drop(candidate_serve);
    checkpoint_state(&state);
    let candidate_doctor = Command::new(candidate)
        .args(["doctor", "--state"])
        .arg(&state)
        .args(["--socket"])
        .arg(scratch.server_socket())
        .args(["--json"])
        .output()
        .unwrap();
    assert_doctor_has_no_required_failure(&candidate_doctor, "candidate-v5");
    drop(candidate_client_netd);
    drop(candidate_netd);
}
