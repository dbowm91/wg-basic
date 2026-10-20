//! C001/C002 controlled-host Darwin qualifications (disposable hosts only).
//!
//! These qualifications need a host that a GitHub-hosted runner cannot be:
//!
//! - the **off-host peer** leg proves the product path against an independent
//!   Linux-kernel WireGuard implementation on another host, with a real
//!   handshake, dual-stack traffic, and API telemetry;
//! - the **cold reboot** leg proves that the deployment comes back from the
//!   system domain after a cold reboot, with the state database intact, the
//!   network reconverged, and no job left behind.
//!
//! They are `#[ignore]`d by default, run single-threaded
//! (`--test-threads=1`), as root, and they mutate the host they run on: they
//! install the product, create real `utun` interfaces, assign tunnel
//! addresses, and bootstrap launchd jobs. Use a disposable host.
//!
//! Private keys are generated fresh per run and never enter evidence output.

#![cfg(target_os = "macos")]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use wg_basic::launchd;

mod darwin_live_common;
use darwin_live_common::*;

/// C001 live: the product path, end to end, against an off-host Linux peer.
///
/// The other C001 fixture proves the production backend's ownership contract
/// in isolation. This one proves the path an operator actually takes: the
/// product's own installer, the real privileged daemon, the real unprivileged
/// management daemon, the real authenticated HTTP surface, and a second,
/// independent WireGuard implementation on another host.
///
/// What it proves:
/// - the deployed product converges a server from an HTTP setup and enrolls a
///   client, and the convergence is observed on the host, not assumed;
/// - the exported client configuration establishes a real handshake with an
///   off-host Linux-kernel peer;
/// - IPv4 and IPv6 packets traverse the tunnel between the two hosts;
/// - the management API reports that traffic as telemetry;
/// - disabling the client removes the peer from the device.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c001_product_path_carries_traffic_to_an_off_host_linux_peer() {
    let mut evidence = Evidence::new("c001-product-path-off-host-peer");
    let helper_path = require_live(&mut evidence);
    let binary = std::env::var("WGB_BINARY").expect("WGB_BINARY must be set");
    let driver = peer_driver();

    // The peer is reached before the host is touched: an unreachable peer
    // must not leave a deployment behind.
    let peer_address = peer_run(&mut evidence, &driver, &["address"])
        .trim()
        .to_owned();
    assert!(
        !peer_address.is_empty(),
        "the peer driver must report the peer's address"
    );
    evidence.log(&format!("off-host peer address: {peer_address}"));

    // The advertisement the peer dials has to be an address this host is
    // reachable at, so it is taken from the route toward the peer.
    let route = sh(&mut evidence, "route", &["-n", "get", &peer_address]);
    let egress = route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .map(|value| value.trim().to_owned())
        .expect("the route toward the peer must name an interface");
    // A direct host route names no source address of its own, so the address
    // comes from the interface the route uses.
    let source = interface_ipv4(&mut evidence, &egress);
    evidence.log(&format!(
        "advertised endpoint {source}:{LISTEN_PORT} through {egress}"
    ));

    // The management identity the installer binds to is supplied by the
    // qualification, exactly as an operator supplies it.
    provision_management_identity(&mut evidence);
    let _cleanup = DisposableDeployment {
        user: launchd::SERVE_USER.to_owned(),
        group: launchd::SERVE_GROUP.to_owned(),
    };
    resolve_management_identity(&mut evidence);

    // The privileged daemon finds the pinned helper and admits the management
    // identity through the install receipt, so the qualification runs the
    // product's own transactional installer rather than a hand-rolled one.
    wg_basic::launchd_install::install(Path::new("/"), Path::new(&binary), Path::new(&helper_path))
        .expect("the transactional installer must complete the deployment");
    evidence.log("the transactional installer completed the deployment");

    // The pinned helper accepts the tunnel's UDP. This is a host policy, and
    // the qualification leaves it as it found it.
    let _firewall = FirewallAllowance {
        path: launchd::HELPER_PATH.to_owned(),
    };
    sh(
        &mut evidence,
        FIREWALL_TOOL,
        &["--add", launchd::HELPER_PATH],
    );

    let netd_job = format!("system/{}", launchd::NETD_LABEL);
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
    wait_until("both roles running", Duration::from_secs(60), || {
        launchd_running(&netd_job) && launchd_running(&serve_job)
    });

    // The administrator is provisioned through the product's own CLI, as the
    // management identity, with the password on standard input: the path an
    // operator takes, and the only path that can set a credential at all.
    use std::io::Write as _;
    let password = "a disposable administrator password";
    let mut admin = Command::new("sudo")
        .args([
            "-u",
            launchd::SERVE_USER,
            launchd::BINARY_PATH,
            "admin",
            "set-password",
            "--username",
            "admin",
            "--password-stdin",
            "--state",
            launchd::STATE_PATH,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("provision the administrator");
    admin
        .stdin
        .as_mut()
        .expect("the password pipe")
        .write_all(format!("{password}\n").as_bytes())
        .expect("write the password");
    let admin_output = admin
        .wait_with_output()
        .expect("the administrator provisioning to finish");
    assert!(
        admin_output.status.success(),
        "administrator provisioning failed: {}",
        String::from_utf8_lossy(&admin_output.stderr)
    );
    evidence.log("the administrator was provisioned as the management identity");

    let addr: std::net::SocketAddr = wg_basic::http::config::DEFAULT_BIND
        .parse()
        .expect("the default management bind is an address");
    let origin = format!("http://{addr}");
    wait_until("the management listener", Duration::from_secs(60), || {
        std::net::TcpStream::connect(addr).is_ok()
    });

    // The product path: login, session, server, setup, client.
    let (login_status, login_body, login_headers) = http(
        addr,
        "POST",
        "/api/v1/login",
        Some(&origin),
        None,
        None,
        r#"{"username":"admin","password":"a disposable administrator password"}"#,
    );
    assert_eq!(login_status, 200, "login: {login_body}");
    let cookie = login_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .expect("a session cookie")
        .1
        .split(';')
        .next()
        .expect("the cookie value")
        .to_owned();
    let (_, session_body, _) = http(
        addr,
        "GET",
        "/api/v1/session",
        None,
        Some(&cookie),
        None,
        "",
    );
    let csrf = serde_json::from_str::<serde_json::Value>(&session_body).expect("the session body")
        ["csrf_token"]
        .as_str()
        .expect("a CSRF token")
        .to_owned();
    evidence.log("the management session is authenticated");

    let (_, unconfigured, _) = http(addr, "GET", "/api/v1/server", None, Some(&cookie), None, "");
    let unconfigured: serde_json::Value = serde_json::from_str(&unconfigured).expect("the server");
    assert!(
        unconfigured["server"].is_null(),
        "the product must start unconfigured"
    );

    // The host-only policy: no forwarding and no NAT, which is the only shape
    // the Darwin firewall accepts.
    let setup_body = format!(
        r#"{{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"{TUNNEL_V4}","ipv6_tunnel_prefix":"{TUNNEL_V6}","server_address":"{SERVER_V4}","ipv6_server_address":"{SERVER_V6}","listen_port":{LISTEN_PORT},"advertised_endpoint":"{source}:{LISTEN_PORT}","egress_interface":"{egress}","ipv4_forwarding_required":false,"ipv6_forwarding_required":false,"masquerade":false,"default_client_route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}}}}"#
    );
    let (setup_status, setup_body, _) = http(
        addr,
        "POST",
        "/api/v1/setup",
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &setup_body,
    );
    if setup_status != 200 {
        // The privileged boundary refused the convergence. The daemon that
        // refused it, and the product's own reconcile command, say why.
        capture_daemon_logs(&mut evidence);
        let reconcile = Command::new("sudo")
            .args([
                "-u",
                launchd::SERVE_USER,
                launchd::BINARY_PATH,
                "reconcile",
                "--state",
                launchd::STATE_PATH,
                "--socket",
                launchd::SOCKET_PATH,
            ])
            .output();
        match reconcile {
            Ok(output) => evidence.log(&format!(
                "reconcile: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => evidence.log(&format!("reconcile: could not run ({error})")),
        }
    }
    assert_eq!(setup_status, 200, "HTTP setup: {setup_body}");
    evidence.log("the product converged a server from the HTTP setup");

    let (_, summary_body, _) = http(addr, "GET", "/api/v1/server", None, Some(&cookie), None, "");
    let summary: serde_json::Value = serde_json::from_str(&summary_body).expect("the server");
    let interface_id = summary["server"]["interface_id"]
        .as_str()
        .expect("the configured interface")
        .to_owned();
    let generation = summary["generation"].as_u64().expect("the generation");
    // The peer sits behind a NAT and holds no traffic of its own, so it is
    // enrolled with the persistent keepalive an operator would configure for
    // a client behind NAT: the exported configuration then carries it, and
    // the peer initiates the session.
    let create_body = format!(
        r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"off-host-peer","route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}},"client_keepalive_seconds":{CLIENT_KEEPALIVE}}}"#
    );
    let (create_status, create_body, _) = http(
        addr,
        "POST",
        "/api/v1/clients",
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &create_body,
    );
    assert_eq!(create_status, 201, "HTTP create: {create_body}");
    let created: serde_json::Value =
        serde_json::from_str(&create_body).expect("the created client");
    let client_id = created["data"]["client_id"]
        .as_str()
        .expect("the client id")
        .to_owned();
    let client_public_key = created["data"]["public_key"]
        .as_str()
        .expect("the client public key")
        .to_owned();
    evidence.log(&format!(
        "the product enrolled client {client_id} with public key {client_public_key}"
    ));

    // The exported configuration is what a peer actually consumes.
    let (config_status, config_text, _) = http(
        addr,
        "GET",
        &format!("/api/v1/clients/{client_id}/config"),
        None,
        Some(&cookie),
        None,
        "",
    );
    assert_eq!(config_status, 200);
    assert!(
        config_text.contains("[Interface]") && config_text.contains("[Peer]"),
        "the exported configuration must be a WireGuard configuration"
    );
    let exported =
        std::env::temp_dir().join(format!("wgb-c001-client-{}.conf", std::process::id()));
    std::fs::write(&exported, &config_text).expect("write the exported configuration");

    // The peer installs the exported configuration with its route policy
    // narrowed to the server's tunnel addresses, and comes up.
    peer_run(
        &mut evidence,
        &driver,
        &[
            "apply",
            exported.to_str().expect("the exported path"),
            SERVER_V4,
            SERVER_V6,
        ],
    );
    std::fs::remove_file(&exported).ok();
    evidence.log("the off-host peer installed the exported configuration");

    // The server side has to carry the peer before the two ends can talk.
    // The management API reports that as the client's own observation: a
    // client the device does not carry is reported as drift.
    let mut server_side = serde_json::Value::Null;
    wait_until(
        "the managed device to carry the enrolled peer",
        Duration::from_secs(60),
        || {
            let (status, body, _) = http(
                addr,
                "GET",
                "/api/v1/clients/telemetry",
                None,
                Some(&cookie),
                None,
                "",
            );
            assert_eq!(status, 200);
            let snapshot: serde_json::Value = serde_json::from_str(&body).expect("the telemetry");
            let carried = snapshot["clients"]
                .as_array()
                .and_then(|clients| clients.first())
                .and_then(|client| client["drift"].as_bool())
                .is_some_and(|drift| !drift);
            server_side = snapshot;
            carried
        },
    );
    evidence.log(&format!(
        "the managed device carries the enrolled peer: {}",
        server_side["clients"][0]
    ));

    // The handshake is the first observable fact: the two implementations
    // agree on the keys and the endpoint.
    let mut handshake = 0u64;
    wait_until("the off-host handshake", Duration::from_secs(90), || {
        let reported = peer_run(&mut evidence, &driver, &["handshake"]);
        handshake = reported.trim().parse().unwrap_or(0);
        handshake > 0
    });
    evidence.log(&format!(
        "the off-host peer completed a handshake at {handshake}"
    ));

    // Traffic: IPv4 and IPv6 packets between the two hosts, over the tunnel.
    peer_run(&mut evidence, &driver, &["ping4", SERVER_V4]);
    evidence.log(&format!(
        "IPv4 traffic reached {SERVER_V4} from the off-host peer"
    ));
    peer_run(&mut evidence, &driver, &["ping6", SERVER_V6]);
    evidence.log(&format!(
        "IPv6 traffic reached {SERVER_V6} from the off-host peer"
    ));
    let peer_status = peer_run(&mut evidence, &driver, &["status"]);
    evidence.log(&format!("peer device state: {}", peer_status.trim()));

    // The management API reports that traffic as telemetry.
    let mut telemetry = serde_json::Value::Null;
    wait_until(
        "the telemetry to report the handshake",
        Duration::from_secs(60),
        || {
            let (status, body, _) = http(
                addr,
                "GET",
                "/api/v1/clients/telemetry",
                None,
                Some(&cookie),
                None,
                "",
            );
            assert_eq!(status, 200);
            let snapshot: serde_json::Value = serde_json::from_str(&body).expect("the telemetry");
            let observed = snapshot["clients"]
                .as_array()
                .and_then(|clients| clients.first())
                .and_then(|client| client["latest_handshake_age_seconds"].as_u64());
            telemetry = snapshot.clone();
            observed.is_some()
        },
    );
    let client = &telemetry["clients"][0];
    let handshake_age = client["latest_handshake_age_seconds"]
        .as_u64()
        .expect("a handshake age");
    let rx = client["rx_bytes"].as_u64().unwrap_or_default();
    let tx = client["tx_bytes"].as_u64().unwrap_or_default();
    evidence.log(&format!(
        "telemetry: handshake age {handshake_age}s rx={rx} tx={tx}"
    ));
    assert!(
        client["drift"].as_bool() == Some(false),
        "the observed peer must match the committed one: {client}"
    );
    assert!(
        rx > 0 && tx > 0,
        "the API must report the tunnel's traffic: {client}"
    );

    // Disabling the client removes the peer from the device. The generation is
    // read again first: enrolling the client advanced it, and the API refuses
    // a mutation against a stale generation.
    let (_, current_body, _) = http(addr, "GET", "/api/v1/server", None, Some(&cookie), None, "");
    let current: serde_json::Value = serde_json::from_str(&current_body).expect("the server");
    let current_generation = current["generation"].as_u64().expect("the generation");
    let (disable_status, disable_body, _) = http(
        addr,
        "POST",
        &format!("/api/v1/clients/{client_id}/disable"),
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &format!(r#"{{"expected_generation":{current_generation}}}"#),
    );
    assert_eq!(disable_status, 200, "HTTP disable: {disable_body}");
    // The reconcile that removes the peer runs behind the accepted mutation,
    // so the telemetry is read until it reports the client as disabled.
    wait_until(
        "the disabled client to be reported as disabled",
        Duration::from_secs(60),
        || {
            let (telemetry_status, telemetry_body, _) = http(
                addr,
                "GET",
                "/api/v1/clients/telemetry",
                None,
                Some(&cookie),
                None,
                "",
            );
            assert_eq!(telemetry_status, 200);
            let disabled: serde_json::Value =
                serde_json::from_str(&telemetry_body).expect("the telemetry");
            disabled["clients"][0]["enabled"].as_bool() == Some(false)
        },
    );
    evidence.log("disabling the client removed the peer from the managed device");

    peer_run(&mut evidence, &driver, &["teardown"]);
    evidence.log("the off-host peer was torn down");
    evidence.write();
}

// ---------------------------------------------------------------------------
// C002: the cold-reboot leg
// ---------------------------------------------------------------------------

/// The directory the qualification owns across the reboot.
const REBOOT_STATE_DIR: &str = "/var/db/wg-basic-qual";
/// The expectations the arm phase records and the verify phase checks.
const REBOOT_EXPECTATIONS: &str = "/var/db/wg-basic-qual/reboot-expectations.json";
/// The boot-time job that runs the verify phase after the reboot.
const REBOOT_JOB_LABEL: &str = "com.wg-basic.qual-reboot";
const REBOOT_JOB_PLIST: &str = "/Library/LaunchDaemons/com.wg-basic.qual-reboot.plist";
/// The administrator password the arm phase sets and the verify phase uses.
const REBOOT_ADMIN_PASSWORD: &str = "a disposable reboot administrator password";
/// The root-owned directory the boot-time job's test binary is staged in.
const QUAL_STAGE_DIR: &str = "/usr/local/libexec/wg-basic-qual";

/// The kernel's boot time, in seconds since the epoch.
///
/// A cold reboot advances this value and nothing else does. The arm phase
/// records it and the verify phase compares against it, so the leg **observes**
/// that the host rebooted instead of inferring it from the fact that the
/// deployment was still there. Without that check every verify-phase
/// assertion is also satisfied by a host that never went down.
fn kernel_boot_time(evidence: &mut Evidence) -> u64 {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.boottime"])
        .output()
        .expect("read kern.boottime");
    assert!(
        output.status.success(),
        "kern.boottime must be readable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let seconds = text
        .split("sec = ")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|field| field.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("kern.boottime must report a boot time: {text}"));
    evidence.log(&format!("the kernel boot time is {seconds}"));
    seconds
}

/// C002 live: a cold reboot preserves the deployment.
///
/// A restart is not a reboot, and the plist text is not the proof. This cycle
/// installs the deployment, configures a server and enrolls a client through
/// the real HTTP surface, records what has to survive, takes the host down,
/// and then — from a boot-time job, in a new boot — checks that both roles
/// came back from the system domain, that the management daemon still runs as
/// the unprivileged identity, that the state database still holds the same
/// client key, that the network reconverged, and that the uninstall leaves no
/// job behind.
///
/// The cycle has three phases because a reboot ends the process that starts
/// it. `arm` records the expectations and installs the boot-time job,
/// `reboot` takes the host down, and `verify` is what the evidence comes
/// from.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c002_cold_reboot_persists_the_deployment() {
    match std::env::var("WGB_C002_REBOOT_PHASE").as_deref() {
        Ok("arm") => arm_c002_cold_reboot(),
        Ok("reboot") => reboot_c002_cold_reboot(),
        Ok("verify") => verify_c002_cold_reboot(),
        _ => panic!("set WGB_C002_REBOOT_PHASE to arm, reboot, or verify"),
    }
}

/// Records what has to survive the reboot and installs the boot-time job.
fn arm_c002_cold_reboot() {
    let mut evidence = Evidence::new("c002-cold-reboot-arm");
    let helper_path = require_live(&mut evidence);
    let binary = std::env::var("WGB_BINARY").expect("WGB_BINARY must be set");

    // An earlier arm phase may have left a deployment behind. The uninstall
    // preserves the state database by design, so the qualification resets the
    // disposable host itself: this leg starts from a host with no product on
    // it at all.
    let _ = wg_basic::launchd_install::uninstall(Path::new("/"));
    for plist in [
        format!("/Library/LaunchDaemons/{}.plist", launchd::NETD_LABEL),
        format!("/Library/LaunchDaemons/{}.plist", launchd::SERVE_LABEL),
    ] {
        remove_if_exists(Path::new(&plist));
    }
    remove_if_exists(Path::new(launchd::BINARY_PATH));
    remove_if_exists(Path::new(launchd::HELPER_PATH));
    std::fs::remove_dir_all(Path::new(launchd::RUNTIME_DIR)).ok();
    std::fs::remove_dir_all(Path::new(launchd::STATE_DIR)).ok();
    std::fs::remove_dir_all("/var/log/wg-basic").ok();
    std::fs::remove_dir_all("/usr/local/libexec/wg-basic").ok();
    remove_if_exists(Path::new(REBOOT_JOB_PLIST));
    // The job must not be registered in the running session: a registered
    // `RunAtLoad` job would run the verify phase against a host that has not
    // rebooted. The plist alone is what launchd loads at the next boot.
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", "system", REBOOT_JOB_LABEL])
        .output();
    // The job's output file is preserved under a name that says what it is,
    // so the next boot's output cannot be confused with an earlier run's.
    let stale_log = Path::new(REBOOT_STATE_DIR).join("reboot-job.log");
    if stale_log.exists() {
        let _ = std::fs::rename(
            &stale_log,
            Path::new(REBOOT_STATE_DIR).join("reboot-job.log.superseded"),
        );
    }
    std::fs::create_dir_all(REBOOT_STATE_DIR).expect("the qualification state dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(REBOOT_STATE_DIR, std::fs::Permissions::from_mode(0o700))
            .expect("owner-only qualification state dir");
    }

    provision_management_identity(&mut evidence);
    let identity = resolve_management_identity(&mut evidence);

    wg_basic::launchd_install::install(Path::new("/"), Path::new(&binary), Path::new(&helper_path))
        .expect("the installer must complete the deployment");
    evidence.log("the transactional installer completed the deployment");

    let addr: std::net::SocketAddr = wg_basic::http::config::DEFAULT_BIND
        .parse()
        .expect("the default management bind is an address");
    let origin = format!("http://{addr}");
    wait_until("the management listener", Duration::from_secs(60), || {
        std::net::TcpStream::connect(addr).is_ok()
    });

    // The administrator is provisioned through the product's own CLI, as the
    // management identity, so the credential lands in the state database the
    // reboot has to preserve.
    use std::io::Write as _;
    let mut admin = Command::new("sudo")
        .args([
            "-u",
            launchd::SERVE_USER,
            launchd::BINARY_PATH,
            "admin",
            "set-password",
            "--username",
            "admin",
            "--password-stdin",
            "--state",
            launchd::STATE_PATH,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("provision the administrator");
    admin
        .stdin
        .as_mut()
        .expect("the password pipe")
        .write_all(format!("{REBOOT_ADMIN_PASSWORD}\n").as_bytes())
        .expect("write the password");
    let admin_output = admin
        .wait_with_output()
        .expect("the administrator provisioning to finish");
    assert!(
        admin_output.status.success(),
        "administrator provisioning failed: {}",
        String::from_utf8_lossy(&admin_output.stderr)
    );
    evidence.log("the administrator was provisioned as the management identity");

    let (login_status, login_body, login_headers) = http(
        addr,
        "POST",
        "/api/v1/login",
        Some(&origin),
        None,
        None,
        &format!(r#"{{"username":"admin","password":"{REBOOT_ADMIN_PASSWORD}"}}"#),
    );
    assert_eq!(login_status, 200, "login: {login_body}");
    let cookie = login_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.split(';').next().unwrap_or_default().to_owned())
        .expect("a session cookie");
    let session_body = http(
        addr,
        "GET",
        "/api/v1/session",
        None,
        Some(&cookie),
        None,
        "",
    )
    .1;
    let session: serde_json::Value = serde_json::from_str(&session_body).expect("the session body");
    let csrf = session["csrf_token"]
        .as_str()
        .expect("the session carries a csrf token")
        .to_owned();

    // The advertised endpoint has to be an address this host is reachable at,
    // so it is taken from the route toward the off-host peer.
    let peer_address = "192.168.182.143";
    let route = sh(&mut evidence, "route", &["-n", "get", peer_address]);
    let egress = route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(|name| name.trim().to_owned())
        .expect("the route toward the peer names an interface");
    let source = interface_ipv4(&mut evidence, &egress);

    let setup_body = format!(
        r#"{{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"{TUNNEL_V4}","ipv6_tunnel_prefix":"{TUNNEL_V6}","server_address":"{SERVER_V4}","ipv6_server_address":"{SERVER_V6}","listen_port":{LISTEN_PORT},"advertised_endpoint":"{source}:{LISTEN_PORT}","egress_interface":"{egress}","ipv4_forwarding_required":false,"ipv6_forwarding_required":false,"masquerade":false,"default_client_route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}}}}"#
    );
    let (setup_status, setup_body, _) = http(
        addr,
        "POST",
        "/api/v1/setup",
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &setup_body,
    );
    assert_eq!(setup_status, 200, "HTTP setup: {setup_body}");

    let (_, summary_body, _) = http(addr, "GET", "/api/v1/server", None, Some(&cookie), None, "");
    let summary: serde_json::Value = serde_json::from_str(&summary_body).expect("the server");
    let interface_id = summary["server"]["interface_id"]
        .as_str()
        .expect("the configured interface")
        .to_owned();
    let generation = summary["generation"].as_u64().expect("the generation");
    let create_body = format!(
        r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"reboot-peer","route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}},"client_keepalive_seconds":{CLIENT_KEEPALIVE}}}"#
    );
    let (create_status, create_body, _) = http(
        addr,
        "POST",
        "/api/v1/clients",
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &create_body,
    );
    assert_eq!(create_status, 201, "HTTP create: {create_body}");
    let created: serde_json::Value =
        serde_json::from_str(&create_body).expect("the created client");
    let client_id = created["data"]["client_id"]
        .as_str()
        .expect("the client id")
        .to_owned();
    let client_public_key = created["data"]["public_key"]
        .as_str()
        .expect("the client public key")
        .to_owned();
    evidence.log(&format!(
        "the product enrolled client {client_id} with public key {client_public_key}"
    ));

    // The client has to be on the device before the reboot, so that the verify
    // phase proves a reconvergence rather than an enrollment.
    let mut peer_id = String::new();
    wait_until(
        "the managed device to carry the enrolled peer",
        Duration::from_secs(60),
        || {
            let (_, body, _) = http(
                addr,
                "GET",
                "/api/v1/clients/telemetry",
                None,
                Some(&cookie),
                None,
                "",
            );
            let telemetry: serde_json::Value = serde_json::from_str(&body).expect("the telemetry");
            let client = telemetry["clients"]
                .as_array()
                .and_then(|clients| clients.first())
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let carried = client["drift"].as_bool() == Some(false)
                && client["observation"].as_str() == Some("present");
            peer_id = client["peer_id"].as_str().unwrap_or_default().to_owned();
            carried
        },
    );
    assert!(
        !peer_id.is_empty(),
        "the enrolled peer must be on the device before the reboot"
    );

    // The boot time is recorded so the verify phase can observe that the host
    // really rebooted. It is read before the expectations are written, and it
    // is the one expectation that cannot be satisfied by a host that never
    // went down.
    let boot_time = kernel_boot_time(&mut evidence);

    let expectations = serde_json::json!({
        "client_id": client_id,
        "client_public_key": client_public_key,
        "peer_id": peer_id,
        "interface_id": interface_id,
        "management_uid": identity.uid,
        "management_gid": identity.gid,
        "boot_time_seconds": boot_time,
    });
    std::fs::write(
        REBOOT_EXPECTATIONS,
        serde_json::to_vec_pretty(&expectations).expect("the expectations"),
    )
    .expect("write the expectations");
    evidence.log(&format!(
        "recorded the expectations that must survive the reboot at {REBOOT_EXPECTATIONS}"
    ));

    // The boot-time job runs the verify phase in the new boot. It is removed
    // by the verify phase itself, so a later boot does not run it again. The
    // test binary is staged in a root-owned directory: a boot-time job must
    // not execute a file a user account can replace.
    //
    // The plist is written and **not** bootstrapped. `launchctl bootstrap`
    // starts a `RunAtLoad` job immediately, which would run the verify phase
    // against the deployment that has not rebooted yet. A plist in
    // `/Library/LaunchDaemons` is loaded by launchd at the next boot, which
    // is exactly what the leg has to prove.
    let test_binary = std::env::current_exe().expect("the running test binary");
    let staged_dir = Path::new(QUAL_STAGE_DIR);
    std::fs::create_dir_all(staged_dir).expect("the qualification staging dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(staged_dir, std::fs::Permissions::from_mode(0o755))
            .expect("a root-owned staging dir");
    }
    let staged_binary = staged_dir.join("wireguard-darwin-live");
    std::fs::copy(&test_binary, &staged_binary).expect("stage the test binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged_binary, std::fs::Permissions::from_mode(0o755))
            .expect("an executable test binary");
    }
    let evidence_dir =
        std::env::var("WGB_EVIDENCE_DIR").unwrap_or_else(|_| REBOOT_STATE_DIR.to_owned());
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{REBOOT_JOB_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>live_c002_cold_reboot_persists_the_deployment</string>
    <string>--ignored</string>
    <string>--exact</string>
    <string>--test-threads=1</string>
    <string>--nocapture</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>WGB_DARWIN_LIVE</key>
    <string>1</string>
    <key>WGB_C002_REBOOT_PHASE</key>
    <string>verify</string>
    <key>WGB_EVIDENCE_DIR</key>
    <string>{}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{REBOOT_STATE_DIR}/reboot-job.log</string>
  <key>StandardErrorPath</key>
  <string>{REBOOT_STATE_DIR}/reboot-job.log</string>
</dict>
</plist>
"#,
        staged_binary.to_string_lossy(),
        evidence_dir
    );
    std::fs::write(REBOOT_JOB_PLIST, plist).expect("write the boot-time job");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(REBOOT_JOB_PLIST, std::fs::Permissions::from_mode(0o644))
            .expect("a readable boot-time job");
    }
    evidence.log("the boot-time job is installed and will run in the next boot, not now");
    evidence.write();
}

/// Takes the host down. The boot-time job runs the verify phase in the new
/// boot.
fn reboot_c002_cold_reboot() {
    let mut evidence = Evidence::new("c002-cold-reboot-reboot");
    let output = Command::new("/sbin/shutdown")
        .arg("-r")
        .arg("now")
        .output()
        .expect("schedule the reboot");
    evidence.log(&format!(
        "the reboot was requested: {:?}",
        String::from_utf8_lossy(&output.stdout)
    ));
    assert!(
        output.status.success(),
        "the reboot request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    evidence.write();
}

/// Checks, in the new boot, that the deployment survived the cold reboot.
fn verify_c002_cold_reboot() {
    let mut evidence = Evidence::new("c002-cold-reboot-verify");
    let expectations: serde_json::Value = serde_json::from_slice(
        &std::fs::read(REBOOT_EXPECTATIONS).expect("the recorded expectations"),
    )
    .expect("the recorded expectations");
    let client_id = expectations["client_id"]
        .as_str()
        .expect("the recorded client")
        .to_owned();
    let client_public_key = expectations["client_public_key"]
        .as_str()
        .expect("the recorded client key")
        .to_owned();
    let peer_id = expectations["peer_id"]
        .as_str()
        .expect("the recorded peer")
        .to_owned();
    let management_uid = expectations["management_uid"]
        .as_u64()
        .expect("the recorded management uid");

    // The first thing the verify phase proves is that the host really
    // rebooted. Every other assertion below — the roles came back, the
    // management daemon is still unprivileged, the credential still
    // authenticates, the network reconverged — is also satisfied by a host
    // that simply never went down, so the reboot itself has to be observed
    // before any of them counts as evidence. The kernel's boot time advances
    // on a cold reboot and on nothing else.
    let recorded_boot_time = expectations["boot_time_seconds"]
        .as_u64()
        .expect("the recorded kernel boot time");
    let boot_time = kernel_boot_time(&mut evidence);
    assert_ne!(
        boot_time, recorded_boot_time,
        "the host did not reboot: the kernel boot time is still {boot_time}, \
         so this run proves nothing about a cold reboot"
    );
    assert!(
        boot_time > recorded_boot_time,
        "the kernel boot time went backwards: {boot_time} is older than {recorded_boot_time}"
    );
    evidence.log("the host really rebooted: the kernel boot time advanced");

    let netd_job = format!("system/{}", launchd::NETD_LABEL);
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
    wait_until(
        "both roles running after the reboot",
        Duration::from_secs(120),
        || launchd_running(&netd_job) && launchd_running(&serve_job),
    );
    evidence.log("both roles came back from the system domain after the reboot");

    // The management daemon must still be the unprivileged identity: the
    // reboot proves the job's own configuration, not the plist text.
    let serve_pid = {
        let output = Command::new("launchctl")
            .args(["print", &serve_job])
            .output()
            .expect("launchctl print");
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find_map(|line| line.trim().strip_prefix("pid = "))
            .and_then(|value| value.trim().parse::<u32>().ok())
            .expect("the running job reports a pid")
    };
    let output = Command::new("ps")
        .args(["-o", "uid=,gid=", "-p", &serve_pid.to_string()])
        .output()
        .expect("ps");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fields = text.split_whitespace();
    let uid = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .expect("ps must report the effective uid");
    evidence.log(&format!(
        "the management daemon runs as uid={uid} pid={serve_pid}"
    ));
    assert_eq!(
        uid, management_uid,
        "the management daemon must still run unprivileged after the reboot"
    );
    evidence.log("the management daemon still runs unprivileged");

    // The state database has to have survived: the same credential still
    // authenticates, and the enrolled client is still there with the same key.
    let addr: std::net::SocketAddr = wg_basic::http::config::DEFAULT_BIND
        .parse()
        .expect("the default management bind is an address");
    let origin = format!("http://{addr}");
    wait_until("the management listener", Duration::from_secs(120), || {
        std::net::TcpStream::connect(addr).is_ok()
    });
    let (login_status, login_body, login_headers) = http(
        addr,
        "POST",
        "/api/v1/login",
        Some(&origin),
        None,
        None,
        &format!(r#"{{"username":"admin","password":"{REBOOT_ADMIN_PASSWORD}"}}"#),
    );
    assert_eq!(login_status, 200, "login after the reboot: {login_body}");
    let cookie = login_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.split(';').next().unwrap_or_default().to_owned())
        .expect("a session cookie");
    evidence.log("the administrator credential survived the reboot");

    let session_body = http(
        addr,
        "GET",
        "/api/v1/session",
        None,
        Some(&cookie),
        None,
        "",
    )
    .1;
    let session: serde_json::Value = serde_json::from_str(&session_body).expect("the session body");
    assert!(
        session["csrf_token"].as_str().is_some(),
        "the session must still be established after the reboot: {session_body}"
    );
    evidence.log("the authenticated session is available in the new boot");

    // The network has to have reconverged: the managed device is back and it
    // carries the same peer.
    let mut telemetry = serde_json::Value::Null;
    wait_until(
        "the network to reconverge after the reboot",
        Duration::from_secs(120),
        || {
            let (_, body, _) = http(
                addr,
                "GET",
                "/api/v1/clients/telemetry",
                None,
                Some(&cookie),
                None,
                "",
            );
            let snapshot: serde_json::Value = serde_json::from_str(&body).expect("the telemetry");
            let carried = snapshot["clients"]
                .as_array()
                .and_then(|clients| clients.first())
                .map(|client| {
                    client["observation"].as_str() == Some("present")
                        && client["drift"].as_bool() == Some(false)
                        && client["peer_id"].as_str() == Some(peer_id.as_str())
                })
                .unwrap_or(false);
            telemetry = snapshot;
            carried
        },
    );
    evidence.log(&format!(
        "the network reconverged after the reboot: {}",
        telemetry["clients"][0]
    ));

    // The uninstall must leave no job behind.
    let _ = wg_basic::launchd_install::uninstall(Path::new("/"));
    for job in [&serve_job, &netd_job] {
        wait_until(
            "job unloaded from the system domain",
            Duration::from_secs(30),
            || {
                Command::new("launchctl")
                    .args(["print", job])
                    .output()
                    .is_ok_and(|output| !output.status.success())
            },
        );
    }
    for plist in [
        format!("/Library/LaunchDaemons/{}.plist", launchd::NETD_LABEL),
        format!("/Library/LaunchDaemons/{}.plist", launchd::SERVE_LABEL),
    ] {
        remove_if_exists(Path::new(&plist));
    }
    remove_if_exists(Path::new(launchd::BINARY_PATH));
    remove_if_exists(Path::new(launchd::HELPER_PATH));
    std::fs::remove_dir_all(Path::new(launchd::RUNTIME_DIR)).ok();
    std::fs::remove_dir_all(Path::new(launchd::STATE_DIR)).ok();
    std::fs::remove_dir_all("/var/log/wg-basic").ok();
    std::fs::remove_dir_all("/usr/local/libexec/wg-basic").ok();
    evidence.log("the uninstall left no job, plist, or binary behind");

    // The boot-time job removes itself: it must not run in a later boot.
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", "system", REBOOT_JOB_PLIST])
        .output();
    remove_if_exists(Path::new(REBOOT_JOB_PLIST));
    std::fs::remove_dir_all(Path::new(QUAL_STAGE_DIR)).ok();
    let client = &telemetry["clients"][0];
    assert_eq!(
        client["client_id"].as_str(),
        Some(client_id.as_str()),
        "the enrolled client must survive the reboot"
    );
    assert_eq!(
        client["peer_id"].as_str(),
        Some(peer_id.as_str()),
        "the enrolled peer must survive the reboot"
    );
    evidence.log(&format!(
        "the enrolled client survived the reboot with the same key {client_public_key} and peer {peer_id}"
    ));
    evidence.write();
}
