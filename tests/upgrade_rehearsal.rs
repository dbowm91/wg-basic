//! State-compatibility portion of the Phase 9 old/new binary rehearsal.
//!
//! The dedicated CI job builds the immutable Phase 8 binary separately and
//! passes its absolute path in `WGB_OLD_BINARY`. Rootful product/traffic
//! qualification remains a separate fixture because this test owns no host
//! networking.
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CANDIDATE_FROM_TEST_BUILD: &str = env!("CARGO_BIN_EXE_wg-basic");

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-upgrade-rehearsal-{}-{}",
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
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(binary: &str, args: &[&str]) -> std::process::Output {
    Command::new(binary).args(args).output().unwrap()
}

fn status_text(binary: &str, state: &std::path::Path) -> String {
    let output = Command::new(binary)
        .args(["state", "status", "--state"])
        .arg(state)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} state status failed: {}",
        binary,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn run_state(
    binary: &str,
    command: &str,
    state: &std::path::Path,
    extra: &[&str],
) -> std::process::Output {
    let mut args = vec!["state", command, "--state"];
    let state_text = state.to_str().unwrap();
    args.push(state_text);
    args.extend_from_slice(extra);
    run(binary, &args)
}

struct ServeChild(Child);

impl Drop for ServeChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug)]
struct HttpReply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpReply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn free_bind() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start_serve(
    binary: &str,
    state: &std::path::Path,
    socket: &std::path::Path,
) -> (ServeChild, SocketAddr) {
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
    let mut child = ServeChild(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(30)).is_ok() {
            return (child, addr);
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("{binary} serve exited before binding: {status}");
        }
        assert!(Instant::now() < deadline, "{binary} serve did not bind");
        thread::sleep(Duration::from_millis(10));
    }
}

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpReply {
    let host = addr.to_string();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if method != "GET" {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(body);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let response = String::from_utf8(response).unwrap();
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
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    HttpReply {
        status,
        headers,
        body: body.to_owned(),
    }
}

fn login(
    binary: &str,
    state: &std::path::Path,
    socket: &std::path::Path,
) -> (ServeChild, SocketAddr, String, String) {
    let (child, addr) = start_serve(binary, state, socket);
    let origin = format!("http://{addr}");
    let login = http(
        addr,
        "POST",
        "/api/v1/login",
        &[("Origin", &origin), ("Content-Type", "application/json")],
        r#"{"username":"admin","password":"phase nine upgrade test password"}"#,
    );
    assert_eq!(login.status, 200, "{}", login.body);
    let cookie = login
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
    (child, addr, cookie, csrf)
}

fn authenticated_post(
    addr: SocketAddr,
    cookie: &str,
    csrf: &str,
    path: &str,
    body: &str,
) -> HttpReply {
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

fn consume_enrollment(addr: SocketAddr, path: &str, body: &str) -> HttpReply {
    let origin = format!("http://{addr}");
    http(
        addr,
        "POST",
        path,
        &[("Origin", &origin), ("Content-Type", "application/json")],
        body,
    )
}

fn config_digest(addr: SocketAddr, cookie: &str, client_id: &str) -> String {
    let reply = http(
        addr,
        "GET",
        &format!("/api/v1/clients/{client_id}/config"),
        &[("Cookie", cookie)],
        "",
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    use sha2::Digest;
    sha2::Sha256::digest(reply.body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
#[ignore = "requires a separately built immutable Phase 8 binary; run in upgrade-rehearsal CI"]
fn real_v4_state_migrates_refuses_old_binary_and_rolls_back_with_v4_artifact() {
    let old = std::env::var("WGB_OLD_BINARY").expect("CI provides WGB_OLD_BINARY");
    let old = std::fs::canonicalize(old).unwrap();
    let old = old.to_str().unwrap();
    let candidate = std::env::var("WGB_CANDIDATE_BINARY")
        .unwrap_or_else(|_| CANDIDATE_FROM_TEST_BUILD.to_owned());
    let candidate = std::fs::canonicalize(candidate).unwrap();
    let candidate = candidate.to_str().unwrap();
    let scratch = Scratch::new();
    let state = scratch.state();
    let backup = scratch.0.join("pre-update-v4.db");

    let mut provision = Command::new(old)
        .args(["admin", "set-password", "--password-stdin", "--state"])
        .arg(&state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    provision
        .stdin
        .take()
        .unwrap()
        .write_all(b"phase nine upgrade test password\n")
        .unwrap();
    let provision = provision.wait_with_output().unwrap();
    assert!(
        provision.status.success(),
        "old binary could not initialize schema v4: {}",
        String::from_utf8_lossy(&provision.stderr)
    );

    // Use the old binary to create real schema-v4 product, session, audit and
    // enrollment state through its own management surface.
    let socket = scratch.0.join("netd.sock");
    let (old_serve, old_addr, cookie, csrf) = login(old, &state, &socket);
    let setup = authenticated_post(
        old_addr,
        &cookie,
        &csrf,
        "/api/v1/setup",
        r#"{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"10.77.0.0/24","listen_port":51820,"advertised_endpoint":"vpn.example.test:51820","egress_interface":"lo","ipv4_forwarding_required":false,"masquerade":false,"default_client_route_policy":{"prefixes":["10.77.0.0/24"]}}"#,
    );
    assert_eq!(setup.status, 202, "{}", setup.body);
    let setup_json: serde_json::Value = serde_json::from_str(&setup.body).unwrap();
    let interface_id = setup_json["data"]["interface_id"].as_str().unwrap();
    let mut generation = setup_json["generation"].as_u64().unwrap();
    let mut client_ids = Vec::new();
    let mut old_config_hashes = Vec::new();
    for label in ["upgrade-client-a", "upgrade-client-b"] {
        let body = format!(
            r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"{label}"}}"#
        );
        let created = authenticated_post(old_addr, &cookie, &csrf, "/api/v1/clients", &body);
        assert_eq!(created.status, 202, "{}", created.body);
        let json: serde_json::Value = serde_json::from_str(&created.body).unwrap();
        let id = json["data"]["client_id"].as_str().unwrap().to_owned();
        generation = json["generation"].as_u64().unwrap();
        old_config_hashes.push(config_digest(old_addr, &cookie, &id));
        client_ids.push(id);
    }
    let link = authenticated_post(
        old_addr,
        &cookie,
        &csrf,
        &format!("/api/v1/clients/{}/enrollment-links", client_ids[0]),
        "{}",
    );
    assert_eq!(link.status, 201, "{}", link.body);
    let link_json: serde_json::Value = serde_json::from_str(&link.body).unwrap();
    let share_url = link_json["share_url"].as_str().unwrap();
    let enrollment_token = share_url.split("#token=").nth(1).unwrap();
    let capability_id = link_json["capability_id"].as_str().unwrap();
    let consume_path = format!("/api/v1/enroll/{capability_id}/consume");
    let consume_body = format!(r#"{{"token":{enrollment_token:?}}}"#);
    let consumed = consume_enrollment(old_addr, &consume_path, &consume_body);
    assert_eq!(consumed.status, 200, "{}", consumed.body);
    assert_eq!(
        consume_enrollment(old_addr, &consume_path, &consume_body).status,
        410,
        "consumed enrollment must not replay"
    );
    let revoked_link = authenticated_post(
        old_addr,
        &cookie,
        &csrf,
        &format!("/api/v1/clients/{}/enrollment-links", client_ids[1]),
        "{}",
    );
    assert_eq!(revoked_link.status, 201, "{}", revoked_link.body);
    let revoked_json: serde_json::Value = serde_json::from_str(&revoked_link.body).unwrap();
    let revoked_token = revoked_json["share_url"]
        .as_str()
        .unwrap()
        .split("#token=")
        .nth(1)
        .unwrap()
        .to_owned();
    let revoked_id = revoked_json["capability_id"].as_str().unwrap();
    let revoked_consume_path = format!("/api/v1/enroll/{revoked_id}/consume");
    let revoked_consume_body = format!(r#"{{"token":{revoked_token:?}}}"#);
    let origin = format!("http://{old_addr}");
    let revoke = http(
        old_addr,
        "DELETE",
        &format!("/api/v1/enrollment-links/{revoked_id}"),
        &[
            ("Origin", &origin),
            ("Cookie", &cookie),
            ("x-wg-basic-csrf", &csrf),
        ],
        "",
    );
    assert_eq!(revoke.status, 200, "{}", revoke.body);
    let revoked_consume =
        consume_enrollment(old_addr, &revoked_consume_path, &revoked_consume_body);
    assert_eq!(revoked_consume.status, 410);
    let old_clients = http(
        old_addr,
        "GET",
        "/api/v1/clients",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(old_clients.status, 200, "{}", old_clients.body);
    let old_clients_json: serde_json::Value = serde_json::from_str(&old_clients.body).unwrap();
    let old_session = http(
        old_addr,
        "GET",
        "/api/v1/session",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(old_session.status, 200, "{}", old_session.body);
    let old_audit = http(old_addr, "GET", "/api/v1/audit", &[("Cookie", &cookie)], "");
    assert_eq!(old_audit.status, 200, "{}", old_audit.body);
    assert!(!old_audit.body.contains(enrollment_token));
    drop(old_serve);

    let old_status = status_text(old, &state);
    assert!(old_status.contains("schema version:     4"), "{old_status}");
    let installation_line = old_status
        .lines()
        .find(|line| line.starts_with("installation id:"))
        .unwrap()
        .to_owned();
    let generation_line = old_status
        .lines()
        .find(|line| line.starts_with("desired generation:"))
        .unwrap()
        .to_owned();

    let backup_output = run_state(old, "backup", &state, &[backup.to_str().unwrap()]);
    assert!(
        backup_output.status.success(),
        "old binary backup failed: {}",
        String::from_utf8_lossy(&backup_output.stderr)
    );
    assert!(backup.exists());

    // Starting candidate serve against the v4 file is the real migration path.
    let (candidate_serve, candidate_addr) = start_serve(candidate, &state, &socket);
    let migrated = status_text(candidate, &state);
    assert!(migrated.contains("schema version:     6"), "{migrated}");
    assert!(migrated.contains(&installation_line));
    assert!(migrated.contains(&generation_line));
    assert!(state.with_file_name("state.db.pre-migration-v4").exists());

    let candidate_liveness = http(candidate_addr, "GET", "/healthz", &[], "");
    assert_eq!(candidate_liveness.status, 200);
    assert_eq!(
        candidate_liveness.body, "degraded",
        "withheld netd must fail the candidate health decision after migration"
    );
    let candidate_clients = http(
        candidate_addr,
        "GET",
        "/api/v1/clients",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(candidate_clients.status, 200, "{}", candidate_clients.body);
    let candidate_json: serde_json::Value = serde_json::from_str(&candidate_clients.body).unwrap();
    let candidate_ids: Vec<String> = candidate_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|client| client["client_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(candidate_ids, client_ids);
    assert_eq!(candidate_json["clients"], old_clients_json["clients"]);
    let candidate_session = http(
        candidate_addr,
        "GET",
        "/api/v1/session",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(candidate_session.body, old_session.body);
    for (id, expected_hash) in client_ids.iter().zip(&old_config_hashes) {
        assert_eq!(config_digest(candidate_addr, &cookie, id), *expected_hash);
    }
    let candidate_audit = http(
        candidate_addr,
        "GET",
        "/api/v1/audit",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(candidate_audit.status, 200, "{}", candidate_audit.body);
    assert!(!candidate_audit.body.contains(enrollment_token));
    assert!(!candidate_audit.body.contains(&revoked_token));
    let candidate_audit_json: serde_json::Value =
        serde_json::from_str(&candidate_audit.body).unwrap();
    let old_audit_json: serde_json::Value = serde_json::from_str(&old_audit.body).unwrap();
    assert_eq!(candidate_audit_json["events"], old_audit_json["events"]);
    assert_eq!(
        consume_enrollment(candidate_addr, &consume_path, &consume_body).status,
        410,
        "consumed enrollment must stay consumed after migration"
    );
    assert_eq!(
        consume_enrollment(candidate_addr, &revoked_consume_path, &revoked_consume_body).status,
        410,
        "revoked enrollment must stay revoked after migration"
    );
    drop(candidate_serve);

    let old_refusal = run_state(old, "status", &state, &[]);
    assert!(!old_refusal.status.success());
    assert!(
        String::from_utf8_lossy(&old_refusal.stderr).contains("newer than this binary supports")
    );

    let rollback = run_state(old, "restore", &state, &[backup.to_str().unwrap()]);
    assert!(
        rollback.status.success(),
        "old-compatible restore failed: {}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    let restored = status_text(old, &state);
    assert!(restored.contains("schema version:     4"), "{restored}");
    assert!(restored.contains(&installation_line));
    assert!(restored.contains(&generation_line));

    let (restored_serve, restored_addr, _, _) = login(old, &state, &socket);
    let restored_clients = http(
        restored_addr,
        "GET",
        "/api/v1/clients",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(restored_clients.status, 200, "{}", restored_clients.body);
    let restored_json: serde_json::Value = serde_json::from_str(&restored_clients.body).unwrap();
    let restored_ids: Vec<String> = restored_json["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|client| client["client_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(restored_ids, client_ids);
    assert_eq!(restored_json["clients"], old_clients_json["clients"]);
    let restored_replay = consume_enrollment(restored_addr, &consume_path, &consume_body);
    assert_eq!(restored_replay.status, 410);
    assert_eq!(
        consume_enrollment(restored_addr, &revoked_consume_path, &revoked_consume_body).status,
        410
    );
    drop(restored_serve);

    let reupgraded = status_text(candidate, &state);
    assert!(reupgraded.contains("schema version:     6"), "{reupgraded}");
    assert!(reupgraded.contains(&installation_line));
    assert!(reupgraded.contains(&generation_line));
    let (reupgraded_serve, reupgraded_addr) = start_serve(candidate, &state, &socket);
    let final_clients = http(
        reupgraded_addr,
        "GET",
        "/api/v1/clients",
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(final_clients.status, 200, "{}", final_clients.body);
    let final_json: serde_json::Value = serde_json::from_str(&final_clients.body).unwrap();
    assert_eq!(final_json["clients"], old_clients_json["clients"]);
    assert_eq!(
        consume_enrollment(reupgraded_addr, &consume_path, &consume_body).status,
        410
    );
    assert_eq!(
        consume_enrollment(
            reupgraded_addr,
            &revoked_consume_path,
            &revoked_consume_body
        )
        .status,
        410
    );
    drop(reupgraded_serve);
}
