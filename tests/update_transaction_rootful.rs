#![cfg(all(
    target_os = "linux",
    feature = "linux-integration",
    feature = "update-test-fixtures"
))]

//! Destructive updater qualification. Run only on a clean disposable systemd VM.

use std::{
    fs,
    io::{Cursor, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::{fs::symlink, fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};
use wg_basic::{
    domain::{InterfaceName, NetworkPrefix, PrivateKey, PublicKey},
    protocol::{request, RequestOperation, ResponseBody},
    wireguard::{DesiredWireGuardPeer, FieldUpdate, PeerMutation, WireGuardDevicePatch},
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");
const FIXTURE: &str = "/run/wg-basic-update-fixture";
const CANDIDATE_VERSION: &str = "0.1.1";
const ADMIN_PASSWORD: &str = "C002 disposable update qualification password";

fn command(args: &[&str]) -> Output {
    Command::new(BINARY).args(args).output().unwrap()
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn database_identity() -> (i64, String, i64, i64) {
    let connection = rusqlite::Connection::open_with_flags(
        distribution_state_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let schema: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let (installation, generation): (String, i64) = connection
        .query_row(
            "SELECT installation_id, desired_generation FROM installation WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let clients: i64 = connection
        .query_row("SELECT count(*) FROM clients", [], |row| row.get(0))
        .unwrap();
    (schema, installation, generation, clients)
}

fn typed_state_identity() -> serde_json::Value {
    let identity = Command::new("/usr/sbin/runuser")
        .args([
            "--user",
            "wg-basic",
            "--",
            wg_basic::distribution::BINARY_PATH,
            "state",
            "identity",
            "--state",
            distribution_state_path(),
        ])
        .output()
        .unwrap();
    assert!(identity.status.success(), "{}", output_text(&identity));
    serde_json::from_slice(&identity.stdout).unwrap()
}

fn qualification_environment() -> String {
    let kernel = Command::new("/usr/bin/uname").arg("-r").output().unwrap();
    let systemd = Command::new("/usr/bin/systemctl")
        .arg("--version")
        .output()
        .unwrap();
    format!(
        "kernel={} systemd={} architecture={}",
        String::from_utf8_lossy(&kernel.stdout)
            .lines()
            .next()
            .unwrap_or("unknown"),
        String::from_utf8_lossy(&systemd.stdout)
            .lines()
            .next()
            .unwrap_or("unknown"),
        std::env::consts::ARCH
    )
}

fn distribution_state_path() -> &'static str {
    wg_basic::distribution::STATE_PATH
}

fn kill_update_at_phase(phase: &str, expected_identity: &(i64, String, i64, i64)) {
    interrupt_update_at_phase(phase);

    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "recovery after {phase} failed: {}\n{}",
            output_text(&recovery),
            recovery_diagnostics()
        );
    }
    assert_eq!(database_identity(), *expected_identity);
    assert!(
        eggup_core::MutationLock::observe(Path::new("/usr/local/bin"))
            .unwrap()
            .is_none(),
        "recovery must resolve its journal-proven Eggup lock record"
    );
}

fn interrupt_update_at_phase(phase: &str) {
    use std::{
        os::unix::process::CommandExt,
        thread,
        time::{Duration, Instant},
    };

    let gate = format!("/run/wg-basic-update-gate-{phase}");
    fs::create_dir(&gate).unwrap();
    let mut child = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .env("WGB_UPDATE_TEST_GATE_PHASE", phase)
        .env("WGB_UPDATE_TEST_GATE_DIR", &gate)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let entered = Path::new(&gate).join(format!("{phase}.entered"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while !entered.exists() && Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "updater exited before {phase}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        entered.exists(),
        "updater did not reach durable phase {phase}"
    );
    kill_process_group(&mut child);
    let _ = fs::remove_dir_all(gate);
}

fn assert_recovery_refuses_tampering(label: &str) {
    let recovery = command(&["update", "recover"]);
    assert!(
        !recovery.status.success(),
        "recovery must refuse tampered {label}: {}",
        output_text(&recovery)
    );
    for service in ["wg-basic.service", "wg-basic-netd.service"] {
        let active = Command::new("/usr/bin/systemctl")
            .args(["is-active", service])
            .output()
            .unwrap();
        assert_ne!(
            String::from_utf8_lossy(&active.stdout).trim(),
            "active",
            "tampered {label} must not leave {service} running"
        );
    }
}

fn qualify_tampered_recovery_refusal(expected_identity: &(i64, String, i64, i64)) {
    interrupt_update_at_phase("BinaryCommitted");
    let journal_path = Path::new(wg_basic::update::UPDATE_JOURNAL_PATH);
    let journal_bytes = fs::read(journal_path).unwrap();
    let journal: serde_json::Value = serde_json::from_slice(&journal_bytes).unwrap();
    let transaction = Path::new(journal["transaction_dir"].as_str().unwrap());
    let stale_restore = Path::new(wg_basic::distribution::STATE_DIR).join(format!(
        ".wg-basic-restore-{}.db",
        journal["transaction_id"].as_str().unwrap()
    ));
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    private_file(
        &stale_restore,
        b"stale restore staging sentinel",
        management.uid.as_raw(),
    );

    for artifact in ["old-wg-basic", "state-pre-update.db"] {
        let path = transaction.join(artifact);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"tampered recovery evidence").unwrap();
        assert_recovery_refuses_tampering(artifact);
        fs::write(&path, original).unwrap();
        fs::File::open(&path).unwrap().sync_all().unwrap();
    }

    let unit = Path::new(wg_basic::distribution::SERVE_UNIT_PATH);
    let original_unit = fs::read(unit).unwrap();
    let original_text = String::from_utf8(original_unit.clone()).unwrap();
    let mut changed_exec_start = false;
    let changed_unit = original_text
        .lines()
        .map(|line| {
            if line.starts_with("ExecStart=") {
                changed_exec_start = true;
                "ExecStart=/bin/false"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(changed_exec_start, "owned unit must declare ExecStart");
    fs::write(unit, changed_unit).unwrap();
    fs::File::open(unit).unwrap().sync_all().unwrap();
    let reload = Command::new("/usr/bin/systemctl")
        .args(["daemon-reload"])
        .status()
        .unwrap();
    assert!(reload.success());
    assert_recovery_refuses_tampering("service unit");
    fs::write(unit, original_unit).unwrap();
    let reload = Command::new("/usr/bin/systemctl")
        .args(["daemon-reload"])
        .status()
        .unwrap();
    assert!(reload.success());

    let valid_journal = fs::read(journal_path).unwrap();
    let nobody = nix::unistd::User::from_name("nobody")
        .unwrap()
        .expect("disposable Ubuntu host has nobody account");
    nix::unistd::chown(journal_path, Some(nobody.uid), None).unwrap();
    assert_recovery_refuses_tampering("journal owner");
    nix::unistd::chown(journal_path, Some(nix::unistd::Uid::from_raw(0)), None).unwrap();

    fs::set_permissions(journal_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_recovery_refuses_tampering("journal mode");
    fs::set_permissions(journal_path, fs::Permissions::from_mode(0o600)).unwrap();

    let journal_sidecar = journal_path.with_extension("json.saved");
    fs::rename(journal_path, &journal_sidecar).unwrap();
    symlink(&journal_sidecar, journal_path).unwrap();
    assert_recovery_refuses_tampering("journal symlink");
    fs::remove_file(journal_path).unwrap();
    fs::rename(&journal_sidecar, journal_path).unwrap();

    fs::write(journal_path, b"{").unwrap();
    assert_recovery_refuses_tampering("journal");
    fs::write(journal_path, valid_journal).unwrap();
    fs::File::open(journal_path).unwrap().sync_all().unwrap();

    let receipt_path = Path::new(wg_basic::distribution::SYSTEM_DIR).join("install.json");
    let valid_receipt = fs::read(&receipt_path).unwrap();
    fs::write(&receipt_path, b"{}").unwrap();
    assert_recovery_refuses_tampering("install receipt");
    fs::write(&receipt_path, valid_receipt).unwrap();
    fs::File::open(receipt_path).unwrap().sync_all().unwrap();

    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "{}\n{}",
            output_text(&recovery),
            recovery_diagnostics()
        );
    }
    assert_eq!(database_identity(), *expected_identity);
    assert_eq!(
        fs::read(&stale_restore).unwrap(),
        b"stale restore staging sentinel"
    );
    fs::remove_file(stale_restore).unwrap();
}

fn recovery_diagnostics() -> String {
    let status = Command::new("/usr/bin/systemctl")
        .args([
            "status",
            "--no-pager",
            "-l",
            "wg-basic.service",
            "wg-basic-netd.service",
        ])
        .output()
        .unwrap();
    let journal = Command::new("/usr/bin/journalctl")
        .args([
            "-u",
            "wg-basic.service",
            "-u",
            "wg-basic-netd.service",
            "--no-pager",
            "-n",
            "100",
        ])
        .output()
        .unwrap();
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    let uid = management.uid.to_string();
    let gid = group.gid.to_string();
    let doctor = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            uid.as_str(),
            "--regid",
            gid.as_str(),
            "--clear-groups",
            BINARY,
            "doctor",
            "--state",
            distribution_state_path(),
            "--socket",
            wg_basic::distribution::SOCKET_PATH,
            "--json",
            "--allow-warnings",
        ])
        .output()
        .unwrap();
    let identity = Command::new("/usr/sbin/runuser")
        .args([
            "--user",
            "wg-basic",
            "--",
            wg_basic::distribution::BINARY_PATH,
            "state",
            "identity",
            "--state",
            distribution_state_path(),
        ])
        .output()
        .unwrap();
    let installed_version = Command::new(wg_basic::distribution::BINARY_PATH)
        .arg("--version")
        .output()
        .unwrap();
    let old_version = fs::read(wg_basic::update::UPDATE_JOURNAL_PATH)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|journal| {
            journal
                .get("transaction_dir")
                .and_then(serde_json::Value::as_str)
                .map(|path| Path::new(path).join("old-wg-basic"))
        })
        .and_then(|path| Command::new(path).arg("--version").output().ok());
    format!(
        "systemctl={}\njournalctl={}\ndoctor={}\nidentity={}\ninstalled_version={}\nold_artifact_version={}",
        output_text(&status),
        output_text(&journal),
        output_text(&doctor),
        output_text(&identity),
        output_text(&installed_version),
        old_version
            .as_ref()
            .map(output_text)
            .unwrap_or_else(|| "unavailable".to_owned())
    )
}

fn kill_process_group(child: &mut std::process::Child) {
    let killed = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .status()
        .unwrap();
    assert!(killed.success(), "could not SIGKILL updater process group");
    let _ = child.wait();
}

fn private_file(path: &Path, bytes: &[u8], owner: u32) {
    fs::write(path, bytes).unwrap();
    nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(owner)), None).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn set_admin_password_as_service_user() {
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    let mut child = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            &management.uid.to_string(),
            "--regid",
            &group.gid.to_string(),
            "--clear-groups",
            BINARY,
            "admin",
            "set-password",
            "--password-stdin",
            "--state",
            distribution_state_path(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{ADMIN_PASSWORD}\n").as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success(), "{}", output_text(&result));
}

fn api_request(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: &str,
) -> (u16, std::collections::HashMap<String, String>, String) {
    let address: SocketAddr = "127.0.0.1:8000".parse().unwrap();
    let origin = format!("http://{address}");
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(cookie) = cookie {
        request.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    if let Some(csrf) = csrf {
        request.push_str(&format!("Origin: {origin}\r\nx-wg-basic-csrf: {csrf}\r\n"));
    } else if method == "POST" {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    if method == "POST" {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(body);

    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
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
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    (status, headers, body.to_owned())
}

struct TrafficClient {
    namespace: String,
    host_link: String,
    runtime: std::path::PathBuf,
    netd: std::process::Child,
    admin_cookie: Option<String>,
    client_private_key: Option<String>,
}

impl TrafficClient {
    fn new() -> Self {
        let suffix = std::process::id() % 10_000;
        let namespace = format!("wgu{suffix}c");
        let host_link = format!("wgu{suffix}s");
        let client_link = format!("wgu{suffix}e");
        let runtime = std::path::PathBuf::from(format!("/run/wgb-update-traffic-{suffix}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("netd.sock");
        let run_ip = |args: &[&str]| {
            let result = Command::new("/usr/sbin/ip").args(args).output().unwrap();
            assert!(
                result.status.success(),
                "ip {args:?}: {}",
                output_text(&result)
            );
        };
        run_ip(&["netns", "add", &namespace]);
        run_ip(&[
            "link",
            "add",
            &host_link,
            "type",
            "veth",
            "peer",
            "name",
            &client_link,
        ]);
        run_ip(&["link", "set", &client_link, "netns", &namespace]);
        run_ip(&["addr", "add", "198.18.77.1/24", "dev", &host_link]);
        run_ip(&["link", "set", &host_link, "up"]);
        run_ip(&[
            "-n",
            &namespace,
            "addr",
            "add",
            "198.18.77.2/24",
            "dev",
            &client_link,
        ]);
        run_ip(&["-n", &namespace, "link", "set", "lo", "up"]);
        run_ip(&["-n", &namespace, "link", "set", &client_link, "up"]);

        let mut netd = Command::new("/usr/sbin/ip")
            .args(["netns", "exec", &namespace, BINARY, "netd", "--socket"])
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "client netd did not bind socket");
            assert!(
                netd.try_wait().unwrap().is_none(),
                "client netd exited early"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            namespace,
            host_link,
            runtime,
            netd,
            admin_cookie: None,
            client_private_key: None,
        }
    }

    fn configure(&mut self, config: &str) {
        let socket = self.runtime.join("netd.sock");
        let fields: std::collections::HashMap<_, _> = config
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .collect();
        let address: NetworkPrefix = fields["Address"].parse().unwrap();
        let endpoint: SocketAddr = fields["Endpoint"].parse().unwrap();
        let private_key = PrivateKey::new(fields["PrivateKey"].to_owned()).unwrap();
        self.client_private_key = Some(fields["PrivateKey"].to_owned());
        let public_key = PublicKey::new(fields["PublicKey"].to_owned()).unwrap();
        let allowed_ips = fields["AllowedIPs"]
            .split(", ")
            .map(|prefix| prefix.parse::<NetworkPrefix>().unwrap())
            .collect();
        let interface: InterfaceName = "wg-client".parse().unwrap();
        let run_ip = |args: &[&str]| {
            let result = Command::new("/usr/sbin/ip").args(args).output().unwrap();
            assert!(
                result.status.success(),
                "ip {args:?}: {}",
                output_text(&result)
            );
        };
        run_ip(&[
            "-n",
            &self.namespace,
            "link",
            "add",
            "wg-client",
            "type",
            "wireguard",
        ]);
        run_ip(&[
            "-n",
            &self.namespace,
            "addr",
            "add",
            &address.to_string(),
            "dev",
            "wg-client",
        ]);
        run_ip(&["-n", &self.namespace, "link", "set", "wg-client", "up"]);
        let result = request(
            &socket,
            RequestOperation::ApplyWireGuardDevice {
                interface,
                patch: WireGuardDevicePatch {
                    private_key: FieldUpdate::Set(private_key),
                    listen_port: FieldUpdate::Set(51821),
                    peer: Some(PeerMutation::Add(DesiredWireGuardPeer {
                        public_key,
                        preshared_key: fields.get("PresharedKey").map(|key| {
                            wg_basic::domain::PresharedKey::new((*key).to_owned()).unwrap()
                        }),
                        allowed_ips,
                        persistent_keepalive_seconds: fields
                            .get("PersistentKeepalive")
                            .map(|seconds| seconds.parse().unwrap()),
                        endpoint: Some(endpoint),
                    })),
                },
            },
            9801,
        )
        .unwrap();
        assert!(matches!(result, ResponseBody::WireGuardApplied(_)));
        run_ip(&[
            "-n",
            &self.namespace,
            "route",
            "add",
            "10.77.0.1/32",
            "dev",
            "wg-client",
        ]);
    }

    fn require_handshake_and_traffic(&self) {
        let socket = self.runtime.join("netd.sock");
        let interface: InterfaceName = "wg-client".parse().unwrap();
        let baseline = request(
            &socket,
            RequestOperation::ObserveWireGuardDevice {
                interface: interface.clone(),
            },
            9802,
        )
        .unwrap();
        let ResponseBody::WireGuardDevice(device) = baseline else {
            panic!("expected client WireGuard observation: {baseline:?}");
        };
        let peer = device.peers.first().unwrap();
        let tx = peer.tx_bytes.unwrap_or_default();
        let rx = peer.rx_bytes.unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let _ = Command::new("/usr/bin/ip")
                .args([
                    "netns",
                    "exec",
                    &self.namespace,
                    "/usr/bin/ping",
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
            let observation = request(
                &socket,
                RequestOperation::ObserveWireGuardDevice {
                    interface: interface.clone(),
                },
                9802,
            )
            .unwrap();
            let ResponseBody::WireGuardDevice(device) = observation else {
                panic!("expected client WireGuard observation: {observation:?}");
            };
            if device.peers.iter().any(|peer| {
                peer.latest_handshake.is_some()
                    && peer.tx_bytes.unwrap_or_default() > tx
                    && peer.rx_bytes.unwrap_or_default() > rx
            }) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "WireGuard traffic did not resume"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for TrafficClient {
    fn drop(&mut self) {
        if self.netd.try_wait().ok().flatten().is_none() {
            let _ = self.netd.kill();
            let _ = self.netd.wait();
        }
        let _ = Command::new("/usr/sbin/ip")
            .args(["netns", "del", &self.namespace])
            .status();
        let _ = fs::remove_dir_all(&self.runtime);
    }
}

fn configure_enabled_product_and_client() -> TrafficClient {
    let mut traffic = TrafficClient::new();
    let (login_status, login_headers, login_body) = api_request(
        "POST",
        "/api/v1/login",
        None,
        None,
        &format!(r#"{{"username":"admin","password":{ADMIN_PASSWORD:?}}}"#),
    );
    assert_eq!(login_status, 200, "{login_body}");
    assert_eq!(
        login_headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let cookie = login_headers["set-cookie"]
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    traffic.admin_cookie = Some(cookie.clone());
    let (_, _, session_body) = api_request("GET", "/api/v1/session", Some(&cookie), None, "");
    let session: serde_json::Value = serde_json::from_str(&session_body).unwrap();
    let csrf = session["csrf_token"].as_str().unwrap();
    let (setup_status, _, setup_body) = api_request(
        "POST",
        "/api/v1/setup",
        Some(&cookie),
        Some(csrf),
        &format!(
            r#"{{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"10.77.0.0/24","listen_port":51820,"advertised_endpoint":"198.18.77.1:51820","egress_interface":"{}","ipv4_forwarding_required":false,"masquerade":false,"default_client_route_policy":{{"prefixes":["10.77.0.0/24"]}}}}"#,
            traffic.host_link
        ),
    );
    assert_eq!(setup_status, 200, "{setup_body}");
    let setup: serde_json::Value = serde_json::from_str(&setup_body).unwrap();
    let generation = setup["generation"].as_u64().unwrap();
    let interface_id = setup["data"]["interface_id"].as_str().unwrap();
    let (client_status, _, client_body) = api_request(
        "POST",
        "/api/v1/clients",
        Some(&cookie),
        Some(csrf),
        &format!(
            r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"c002-update-traffic"}}"#
        ),
    );
    assert_eq!(client_status, 201, "{client_body}");
    let client: serde_json::Value = serde_json::from_str(&client_body).unwrap();
    let client_id = client["data"]["client_id"].as_str().unwrap();
    let (config_status, _, config) = api_request(
        "GET",
        &format!("/api/v1/clients/{client_id}/config"),
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(
        config_status, 200,
        "authenticated client configuration export failed"
    );
    let health_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (_, _, health_body) = api_request("GET", "/api/v1/health", Some(&cookie), None, "");
        if serde_json::from_str::<serde_json::Value>(&health_body)
            .map(|health| {
                health["health"]["netd_reachable"] == true && health["backend"]["answered"] == true
            })
            .unwrap_or(false)
        {
            break;
        }
        assert!(
            Instant::now() < health_deadline,
            "enabled product did not become healthy"
        );
        thread::sleep(Duration::from_millis(100));
    }
    traffic.configure(&config);
    traffic.require_handshake_and_traffic();
    traffic
}

fn assert_enabled_product_healthy(cookie: &str) {
    let (liveness_status, _, liveness) = api_request("GET", "/healthz", None, None, "");
    assert_eq!(liveness_status, 200);
    assert_eq!(liveness, "ok");
    let (health_status, _, health_body) =
        api_request("GET", "/api/v1/health", Some(cookie), None, "");
    assert_eq!(health_status, 200, "{health_body}");
    let health: serde_json::Value = serde_json::from_str(&health_body).unwrap();
    assert_eq!(health["health"]["database_healthy"], true, "{health_body}");
    assert_eq!(health["health"]["netd_reachable"], true, "{health_body}");
    assert_eq!(health["backend"]["answered"], true, "{health_body}");
    let (clients_status, _, clients_body) =
        api_request("GET", "/api/v1/clients", Some(cookie), None, "");
    assert_eq!(clients_status, 200, "client list unavailable after update");
    assert!(!clients_body.contains("PrivateKey"));
}

fn assert_private_key_not_in_service_logs(private_key: &str) {
    let logs = Command::new("/usr/bin/journalctl")
        .args([
            "-u",
            "wg-basic.service",
            "-u",
            "wg-basic-netd.service",
            "--no-pager",
            "-n",
            "1000",
        ])
        .output()
        .unwrap();
    assert!(
        logs.status.success(),
        "could not read disposable service logs"
    );
    assert!(
        !String::from_utf8_lossy(&logs.stdout).contains(private_key),
        "service logs exposed a client private key"
    );
}

fn fail_candidate_after_health_and_restore(
    expected_state: &(i64, String, i64, i64),
    expected_identity: &serde_json::Value,
    secret: Option<&str>,
) {
    let result = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .env("WGB_UPDATE_TEST_FAIL_AFTER_HEALTH", "1")
        .output()
        .unwrap();
    let failure = output_text(&result);
    if let Some(secret) = secret {
        assert!(
            !failure.contains(secret),
            "update diagnostics exposed a client key"
        );
    }
    assert!(!result.status.success(), "{failure}");
    assert!(
        failure.contains("candidate health passed with state schema 5"),
        "candidate must reach healthy migrated state before the forced failure: {failure}"
    );
    assert!(
        failure.contains("previous binary and state were restored"),
        "{failure}"
    );
    assert_eq!(database_identity(), *expected_state);
    assert_eq!(typed_state_identity(), *expected_identity);
    let recovery = command(&["update", "recover"]);
    assert!(
        recovery.status.success(),
        "{}\n{}",
        output_text(&recovery),
        recovery_diagnostics()
    );
}

fn make_signed_fixture() {
    use sha2::{Digest, Sha256};
    let candidate = std::env::var("WGB_CANDIDATE_BINARY").expect("candidate binary");
    let artifact = fs::read(candidate).unwrap();
    let target = if std::env::consts::ARCH == "x86_64" {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-unknown-linux-gnu"
    };
    let name = format!("wg-basic-{target}");
    let digest = Sha256::digest(&artifact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/release-auth/release-manifest.json"
    ))
    .unwrap();
    manifest["release_id"] = CANDIDATE_VERSION.into();
    manifest["targets"] = serde_json::json!([{
        "target": target,
        "form": { "kind": "direct", "artifact": {
            "name": name, "size": artifact.len(), "sha256": digest
        }, "install": "wg-basic" }
    }]);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let minisign::KeyPair { pk, sk } = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let signature = minisign::sign(
        Some(&pk),
        &sk,
        Cursor::new(&bytes),
        Some("wg-basic C001a disposable fixture"),
        Some("ephemeral qualification key"),
    )
    .unwrap()
    .to_string();
    fs::create_dir(FIXTURE).unwrap();
    fs::set_permissions(FIXTURE, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        Path::new(FIXTURE).join("discovery.json"),
        format!(r#"{{"tag_name":"v{CANDIDATE_VERSION}","prerelease":false,"draft":false}}"#),
    )
    .unwrap();
    fs::write(Path::new(FIXTURE).join("release-manifest.json"), bytes).unwrap();
    fs::write(
        Path::new(FIXTURE).join("release-manifest.json.minisig"),
        signature,
    )
    .unwrap();
    fs::write(
        Path::new(FIXTURE).join("public.key"),
        pk.to_box().unwrap().into_string(),
    )
    .unwrap();
    fs::write(Path::new(FIXTURE).join(name), artifact).unwrap();
    for entry in fs::read_dir(FIXTURE).unwrap() {
        fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
#[ignore = "mutates canonical installation paths and systemd; disposable systemd VM only"]
fn signed_systemd_update_rolls_back_and_retries() {
    use wg_basic::distribution;

    assert_eq!(nix::unistd::geteuid().as_raw(), 0, "run as root");
    println!(
        "C001a qualification environment: {}",
        qualification_environment()
    );
    assert!(
        Path::new("/run/systemd/system").is_dir(),
        "systemd is required"
    );
    let curl = wg_basic::update::system_transport()
        .expect("supported systemd runner needs a safe allowlisted curl executable");
    println!(
        "qualified update transport executable: {}",
        curl.executable().display()
    );
    for path in [
        distribution::BINARY_PATH,
        distribution::SYSTEM_DIR,
        distribution::STATE_DIR,
        distribution::SYSUSERS_PATH,
        distribution::SERVE_UNIT_PATH,
        distribution::NETD_UNIT_PATH,
        FIXTURE,
        "/run/.wg-basic-update-fixture-fail-netd",
    ] {
        assert!(
            !Path::new(path).exists(),
            "disposable host is not clean: {path}"
        );
    }
    make_signed_fixture();

    if !Path::new("/etc/sysusers.d").exists() {
        fs::create_dir("/etc/sysusers.d").unwrap();
        fs::set_permissions("/etc/sysusers.d", fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write("/etc/sysusers.d/wg-basic.conf", distribution::SYSUSERS).unwrap();
    fs::set_permissions(
        "/etc/sysusers.d/wg-basic.conf",
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let sysusers = Command::new("/usr/bin/systemd-sysusers")
        .arg(distribution::SYSUSERS_PATH)
        .output()
        .unwrap();
    assert!(sysusers.status.success(), "{}", output_text(&sysusers));
    let management = nix::unistd::User::from_name("wg-basic").unwrap().unwrap();
    let group = nix::unistd::Group::from_name("wg-basic").unwrap().unwrap();
    fs::create_dir(distribution::STATE_DIR).unwrap();
    nix::unistd::chown(
        distribution::STATE_DIR,
        Some(management.uid),
        Some(group.gid),
    )
    .unwrap();
    fs::set_permissions(distribution::STATE_DIR, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-schema-v4"),
        b"0.1.0\n",
        management.uid.as_raw(),
    );
    let init = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            &management.uid.to_string(),
            "--regid",
            &group.gid.to_string(),
            "--clear-groups",
            BINARY,
            "state",
            "init",
            "--state",
            distribution::STATE_PATH,
        ])
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", output_text(&init));
    set_admin_password_as_service_user();

    let install = command(&["system", "install", "--candidate", BINARY]);
    assert!(install.status.success(), "{}", output_text(&install));
    let disabled_before = database_identity();
    let disabled_identity = typed_state_identity();
    assert_eq!(disabled_before.0, 4);
    assert_eq!(
        disabled_identity
            .get("network_enabled")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "fixture explicitly qualifies an intentionally disabled healthy profile"
    );
    let disabled_doctor = Command::new("/usr/bin/setpriv")
        .args([
            "--reuid",
            &management.uid.to_string(),
            "--regid",
            &group.gid.to_string(),
            "--clear-groups",
            BINARY,
            "doctor",
            "--state",
            distribution::STATE_PATH,
            "--socket",
            distribution::SOCKET_PATH,
            "--json",
            "--allow-warnings",
        ])
        .output()
        .unwrap();
    assert!(
        disabled_doctor.status.success(),
        "intentionally disabled profile must pass required doctor checks: {}",
        output_text(&disabled_doctor)
    );
    fail_candidate_after_health_and_restore(&disabled_before, &disabled_identity, None);

    // Keep the empty/disabled profile as an explicit healthy baseline, then
    // configure an enabled server and real namespace client for all updater
    // cutpoints, rollback, and the final committed retry.
    let traffic = configure_enabled_product_and_client();
    let client_private_key = traffic.client_private_key.as_deref().unwrap();
    let before = database_identity();
    let typed_before = typed_state_identity();
    assert_eq!(before.0, 4);
    assert_eq!(
        typed_before
            .get("network_enabled")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "enabled transaction fixture must be network-enabled"
    );
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());

    // The candidate ExecStartPre doctor deliberately exceeds Eggup's bounded
    // 30-second service-start deadline. The marker only matches the candidate
    // version, so rollback's old service can start and resume the same tunnel.
    let startup_timeout = Path::new(distribution::STATE_DIR).join(".update-fixture-start-timeout");
    private_file(
        &startup_timeout,
        format!("{CANDIDATE_VERSION}\n").as_bytes(),
        management.uid.as_raw(),
    );
    let timed_out_start = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .output()
        .unwrap();
    fs::remove_file(&startup_timeout).unwrap();
    let timeout_result = output_text(&timed_out_start);
    assert!(
        !timeout_result.contains(client_private_key),
        "startup timeout diagnostics exposed a client key"
    );
    assert!(!timed_out_start.status.success(), "{timeout_result}");
    assert!(
        timeout_result.contains("could not start product service"),
        "candidate startup timeout must classify as a bounded service-start failure: {timeout_result}"
    );
    assert_eq!(database_identity(), before);
    assert_eq!(typed_state_identity(), typed_before);
    let timeout_recovery = command(&["update", "recover"]);
    assert!(
        timeout_recovery.status.success(),
        "{}\n{}",
        output_text(&timeout_recovery),
        recovery_diagnostics()
    );
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());

    let serve_lease =
        wg_basic::state::ServiceLease::path_for_state(Path::new(distribution::STATE_PATH)).unwrap();
    let hidden_serve_lease = serve_lease.with_file_name("state.db.serve.lock.hidden");
    fs::rename(&serve_lease, &hidden_serve_lease).unwrap();
    let missing_lease_update = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .output()
        .unwrap();
    fs::rename(&hidden_serve_lease, &serve_lease).unwrap();
    assert!(!missing_lease_update.status.success());
    assert!(
        output_text(&missing_lease_update).contains("lease"),
        "missing live service lease must block update: {}",
        output_text(&missing_lease_update)
    );
    assert!(
        fs::symlink_metadata(&serve_lease).is_ok(),
        "restoring the hidden live lease path must preserve its locked inode"
    );

    for phase in [
        "Prepared",
        "BackupVerified",
        "ServicesStopped",
        "BinaryCommitted",
        "CandidateStarted",
        "CandidateHealthy",
    ] {
        kill_update_at_phase(phase, &before);
    }
    let netd_failure = Path::new("/run/.wg-basic-update-fixture-fail-netd");
    fs::write(netd_failure, format!("{CANDIDATE_VERSION}\n")).unwrap();
    fs::set_permissions(netd_failure, fs::Permissions::from_mode(0o644)).unwrap();
    let failed_netd_update = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .output()
        .unwrap();
    assert!(
        !failed_netd_update.status.success(),
        "candidate netd startup failure must roll the update back: {}",
        output_text(&failed_netd_update)
    );
    assert!(
        !output_text(&failed_netd_update).contains(client_private_key),
        "failed update diagnostics exposed a client key"
    );
    assert_eq!(database_identity(), before);
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());
    for service in ["wg-basic-netd.service", "wg-basic.service"] {
        let active = Command::new("/usr/bin/systemctl")
            .args(["is-active", service])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&active.stdout).trim(),
            "active",
            "old service pair must recover after candidate netd failure: {}",
            output_text(&failed_netd_update)
        );
    }
    fs::remove_file(netd_failure).unwrap();

    // Force a post-health failure after the real candidate serve process has
    // opened and migrated the v4 database. The fixture receipt proves that the
    // candidate was healthy on schema 5 before rollback restores schema 4.
    fail_candidate_after_health_and_restore(&before, &typed_before, Some(client_private_key));
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());

    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-fail-start"),
        format!("{CANDIDATE_VERSION}\n").as_bytes(),
        management.uid.as_raw(),
    );
    kill_update_at_phase("RollingBack", &before);
    fs::remove_file(Path::new(distribution::STATE_DIR).join(".update-fixture-fail-start")).unwrap();
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());
    qualify_tampered_recovery_refusal(&before);
    traffic.require_handshake_and_traffic();

    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-fail-start"),
        format!("{CANDIDATE_VERSION}\n").as_bytes(),
        management.uid.as_raw(),
    );
    private_file(
        &Path::new(distribution::STATE_DIR).join(".update-fixture-restore-gate"),
        b"pause",
        management.uid.as_raw(),
    );
    let mut interrupted_restore = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let restore_entered =
        Path::new(distribution::STATE_DIR).join(".update-fixture-restore-entered");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !restore_entered.exists() && std::time::Instant::now() < deadline {
        assert!(
            interrupted_restore.try_wait().unwrap().is_none(),
            "update exited before restore staging paused"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        restore_entered.exists(),
        "rollback did not enter SQLite restore staging"
    );
    kill_process_group(&mut interrupted_restore);
    fs::remove_file(Path::new(distribution::STATE_DIR).join(".update-fixture-restore-gate"))
        .unwrap();
    fs::remove_file(restore_entered).unwrap();
    for _ in 0..2 {
        let recovery = command(&["update", "recover"]);
        assert!(
            recovery.status.success(),
            "{}\n{}",
            output_text(&recovery),
            recovery_diagnostics()
        );
    }
    let after = database_identity();
    assert_eq!(after, before, "rollback must restore exact state identity");
    assert_eq!(typed_state_identity(), typed_before);
    assert!(Path::new(distribution::BINARY_PATH).exists());
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());

    fs::remove_file(Path::new(distribution::STATE_DIR).join(".update-fixture-fail-start")).unwrap();
    let retry = Command::new(BINARY)
        .args(["update", "run"])
        .env("WGB_UPDATE_FIXTURE_DIR", FIXTURE)
        .output()
        .unwrap();
    assert!(retry.status.success(), "{}", output_text(&retry));
    let committed = command(&["update", "recover"]);
    assert!(committed.status.success(), "{}", output_text(&committed));
    let after_retry = database_identity();
    assert_eq!(after_retry.0, 5);
    assert_eq!(after_retry.1, before.1);
    assert_eq!(after_retry.2, before.2);
    assert_eq!(after_retry.3, before.3);
    let typed_after_retry = typed_state_identity();
    for field in [
        "installation_id",
        "desired_generation",
        "network_enabled",
        "product_identity_sha256",
    ] {
        assert_eq!(
            typed_after_retry.get(field),
            typed_before.get(field),
            "successful migration must preserve typed state field {field}"
        );
    }
    assert_eq!(
        typed_after_retry
            .get("schema_version")
            .and_then(serde_json::Value::as_i64),
        Some(5)
    );
    traffic.require_handshake_and_traffic();
    assert_enabled_product_healthy(traffic.admin_cookie.as_deref().unwrap());
    assert_private_key_not_in_service_logs(client_private_key);

    let stop = Command::new("/usr/bin/systemctl")
        .args([
            "disable",
            "--now",
            "wg-basic.service",
            "wg-basic-netd.service",
        ])
        .status()
        .unwrap();
    assert!(stop.success());
}
