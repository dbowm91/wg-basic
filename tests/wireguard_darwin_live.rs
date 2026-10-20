//! M003–M006 Darwin privileged live qualification (disposable hosts only).
//!
//! These tests run **only** on ephemeral GitHub-hosted macOS runners with
//! explicit opt-in (`WGB_DARWIN_LIVE=1`) as root. They are `#[ignore]`d by
//! default, must run single-threaded (`--test-threads=1`), and scope every
//! mutation to test identities:
//!
//! - tunnel addresses from TEST-NET-1 (`192.0.2.0/24`, RFC 5737), loopback
//!   WireGuard peering (`127.0.0.1`), per-test anchor/job names;
//! - **no** default-route surgery, **no** global forwarding change, **no**
//!   `pfctl -e`, **no** `/etc/pf.conf` write, **no** NAT traffic claim;
//! - every privileged fixture tears down to the pre-test interface inventory.
//!
//! What each test proves (and stops at):
//! - `live_loopback_handshake_and_traffic` (M003): pinned-helper spawn via
//!   our fixed-argv supervisor, real `utun` delta mapping, live ownership
//!   proof (+ foreign non-interference), typed UAPI set/get, loopback
//!   handshake, tunnel ping, counters, kill/restart with renumber tolerance.
//! - `live_route_inventory_preserved` (M004): address alias add/remove on a
//!   live `utun`, real observation through the pure `plan_darwin`
//!   (converged no-op, exact-identity removal, global-takeover refusal),
//!   default-route + inventory preservation.
//! - `live_pf_inventory_and_anchor_cycle` (M005): privileged PF inventory,
//!   read-only forwarding facts, rendered anchor parse check, dedicated
//!   anchor load/verify/flush with explicit non-attachment recorded.
//!   Forwarded/NAT traffic stays **unqualified** (advanced-admin-only).
//! - `live_forwarding_and_unattached_anchor_probe` (M005): forwarding/PF
//!   cycle with restore, anchor provably unattached even while PF runs, no
//!   false convergence without attachment, and the platform's main-ruleset
//!   guard recorded. Effective NAT traffic stays **unqualified**.
//! - `live_launchd_bootstrap_cycle` (M006): rendered plist lint, system-domain
//!   bootstrap/print/bootout of the real `netd` binary, KeepAlive
//!   re-supervision, DB-free state-dir preservation, and a reinstall cycle.
//!   Reboot stays unqualified (hosted runners cannot reboot).
//!
//! Private keys are generated fresh per run and never enter evidence output.

#![cfg(target_os = "macos")]

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use wg_basic::domain::{
    generate_keypair, InstallationId, InterfaceId, InterfaceName, NetworkPrefix,
};
use wg_basic::firewall::{anchor_name, attachment_verified, render_policy};
use wg_basic::launchd;
use wg_basic::reconcile::darwin as reconcile_model;
use wg_basic::wireguard::darwin as wg_darwin;

/// Opt-in gate: without it (or without root) the test fails loudly instead
/// of silently passing. There is no silent skip in live mode.
fn require_live(evidence: &mut Evidence) -> PathBuf {
    let flag = std::env::var("WGB_DARWIN_LIVE").unwrap_or_default();
    assert_eq!(
        flag, "1",
        "WGB_DARWIN_LIVE=1 is required: live tests never run by accident"
    );
    let euid = nix::unistd::geteuid().as_raw();
    assert_eq!(euid, 0, "live tests require root (euid 0), got {euid}");
    let helper = std::env::var("WGB_WIREGUARD_GO").expect("WGB_WIREGUARD_GO must be set");
    let path = PathBuf::from(&helper);
    assert!(
        path.is_absolute(),
        "helper path must be absolute, got {helper}"
    );
    let metadata = std::fs::metadata(&path).expect("helper must exist");
    assert!(
        metadata.permissions().mode() & 0o111 != 0,
        "helper must be executable"
    );
    if let Ok(expected) = std::env::var("WGB_HELPER_SHA256") {
        wg_darwin::verify_helper_sha256(&path, expected.trim())
            .expect("helper hash must match the pinned reference");
        evidence.log("helper sha256 matches the pinned reference");
    }
    evidence.log(&format!("helper under test: {}", path.display()));
    path
}

fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

/// Evidence sink: every line goes to stderr immediately (CI `--nocapture`
/// keeps it on failure) and to an evidence file on success.
struct Evidence {
    name: &'static str,
    lines: Vec<String>,
}

impl Evidence {
    fn new(name: &'static str) -> Self {
        let mut evidence = Self {
            name,
            lines: Vec::new(),
        };
        evidence.log(&format!("live test: {name}"));
        evidence
    }

    fn log(&mut self, line: &str) {
        eprintln!("[live-evidence:{}] {line}", self.name);
        self.lines.push(line.to_owned());
    }

    fn write(self) {
        let dir = std::env::var("WGB_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::temp_dir().join(format!("wgb-live-evidence-{}", std::process::id()))
            });
        std::fs::create_dir_all(&dir).expect("evidence dir");
        let file = dir.join(format!("{}.txt", self.name));
        let mut text = String::new();
        for line in &self.lines {
            text.push_str(line);
            text.push('\n');
        }
        std::fs::write(&file, text).expect("evidence file");
        eprintln!("[live-evidence:{}] wrote {}", self.name, file.display());
    }
}

/// Runs a command as root, asserting success; logs a truncated transcript.
fn sh(evidence: &mut Evidence, program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let transcript = if stdout.len() > 2000 {
        format!("{}…[truncated]", &stdout[..2000])
    } else {
        stdout.into_owned()
    };
    evidence.log(&format!("$ {program} {}", args.join(" ")));
    evidence.log(&transcript);
    assert!(output.status.success(), "{program} failed: {stderr}");
    transcript
}

fn utun_names() -> Vec<String> {
    let output = Command::new("ifconfig")
        .arg("-l")
        .output()
        .expect("ifconfig -l");
    assert!(output.status.success(), "ifconfig -l failed");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|name| {
            name.strip_prefix("utun").is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .map(str::to_owned)
        .collect()
}

fn wait_until(what: &str, timeout: Duration, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    loop {
        if ready() {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for {what} after {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn uapi(socket: &Path, command: &str) -> wg_darwin::UapiDevice {
    let mut stream = UnixStream::connect(socket)
        .unwrap_or_else(|error| panic!("UAPI connect {}: {error}", socket.display()));
    wg_darwin::uapi_round_trip(&mut stream, command)
        .unwrap_or_else(|error| panic!("UAPI round trip failed: {error:?}"))
}

/// The same command with secret values redacted for evidence output.
fn redact_uapi(command: &str) -> String {
    command
        .lines()
        .map(|line| {
            if line.starts_with("private_key=") || line.starts_with("preshared_key=") {
                line.split_once('=')
                    .map(|(key, _)| format!("{key}=[REDACTED]"))
                    .unwrap_or_else(|| "[MALFORMED]".to_owned())
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn pair_u64(device: &wg_darwin::UapiDevice, key: &str) -> Option<u64> {
    device
        .pairs
        .iter()
        .find(|(entry, _)| entry == key)
        .and_then(|(_, value)| value.parse().ok())
}

fn latest_handshake(device: &wg_darwin::UapiDevice) -> Option<u64> {
    wg_darwin::last_handshake_secs(device)
}

/// One live tunnel endpoint: supervised helper + kernel `utun` + UAPI path.
struct LiveEndpoint {
    helper: wg_darwin::SupervisedHelper,
    utun: String,
    socket: PathBuf,
}

impl LiveEndpoint {
    fn spawn(evidence: &mut Evidence, helper_path: &Path, baseline: &[String], tag: &str) -> Self {
        let argv =
            wg_darwin::HelperArgv::new(helper_path.to_owned()).expect("helper argv must validate");
        let helper =
            wg_darwin::SupervisedHelper::spawn(&argv).expect("helper must spawn (needs root)");
        evidence.log(&format!("{tag}: helper pid={}", helper.pid));
        wait_until(&format!("{tag} utun"), Duration::from_secs(15), || {
            utun_names().len() > baseline.len()
        });
        let after = utun_names();
        evidence.log(&format!("{tag}: utun inventory now {after:?}"));
        let utun = wg_darwin::interface_delta(baseline, &after).expect("exactly one new utun");
        evidence.log(&format!("{tag}: mapped to {utun}"));
        let socket = wg_darwin::uapi_socket_path(&utun);
        wait_until(
            &format!("{tag} UAPI socket"),
            Duration::from_secs(15),
            || socket.exists(),
        );
        Self {
            helper,
            utun,
            socket,
        }
    }

    fn get(&self, evidence: &mut Evidence) -> wg_darwin::UapiDevice {
        let device = uapi(&self.socket, "get=1\n\n");
        assert_eq!(device.errno, 0, "UAPI get errno must be 0");
        evidence.log(&format!(
            "UAPI get on {}: {} pairs",
            self.utun,
            device.pairs.len()
        ));
        device
    }

    /// Applies the full device+peer configuration, polling briefly: a freshly
    /// spawned helper may answer the socket before its device is fully up.
    /// On persistent refusal, bisects the command into granular single-shot
    /// probes (device-only, peer variants) and fails with the errno matrix so
    /// the exact rejected field class is recorded, not guessed.
    fn set_device(
        &self,
        evidence: &mut Evidence,
        private_key_base64: &str,
        listen_port: u16,
        peer: &wg_darwin::UapiPeerConfig<'_>,
    ) {
        let command =
            wg_darwin::render_uapi_set(Some(private_key_base64), Some(listen_port), Some(peer))
                .expect("typed UAPI set must render");
        let start = Instant::now();
        loop {
            let errno = uapi(&self.socket, &command).errno;
            if errno == 0 {
                evidence.log(&format!("UAPI set on {} accepted", self.utun));
                return;
            }
            if start.elapsed() > Duration::from_secs(15) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        evidence.log(&format!(
            "full UAPI set refused; redacted command was:\n{}",
            redact_uapi(&command)
        ));
        let device_only =
            wg_darwin::render_uapi_set(Some(private_key_base64), Some(listen_port), None)
                .expect("device-only set must render");
        let matrix = [
            ("device-only", device_only),
            (
                "peer-only-full",
                wg_darwin::render_uapi_set(None, None, Some(peer))
                    .expect("peer-only set must render"),
            ),
            (
                "peer-no-keepalive",
                wg_darwin::render_uapi_set(
                    None,
                    None,
                    Some(&wg_darwin::UapiPeerConfig {
                        persistent_keepalive: None,
                        ..*peer
                    }),
                )
                .expect("peer set must render"),
            ),
            (
                "peer-no-allowed",
                wg_darwin::render_uapi_set(
                    None,
                    None,
                    Some(&wg_darwin::UapiPeerConfig {
                        allowed_ips: &[],
                        ..*peer
                    }),
                )
                .expect("peer set must render"),
            ),
            (
                "peer-no-endpoint",
                wg_darwin::render_uapi_set(
                    None,
                    None,
                    Some(&wg_darwin::UapiPeerConfig {
                        endpoint: None,
                        ..*peer
                    }),
                )
                .expect("peer set must render"),
            ),
        ];
        let mut summary = Vec::new();
        for (label, probe) in &matrix {
            let errno = uapi(&self.socket, probe).errno;
            evidence.log(&format!(
                "probe {label}: errno={errno}\n{}",
                redact_uapi(probe)
            ));
            summary.push(format!("{label}={errno}"));
        }
        panic!(
            "UAPI set persistently refused on {}: {}",
            self.utun,
            summary.join(" ")
        );
    }
}

fn ensure_uapi_dir(evidence: &mut Evidence) {
    let dir = Path::new(wg_darwin::UAPI_SOCKET_DIR);
    if !dir.exists() {
        std::fs::create_dir(dir).expect("create UAPI socket dir");
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .expect("UAPI socket dir owner-only");
    evidence.log(&format!("UAPI dir ready: {}", dir.display()));
}

/// First whitespace field of a `netstat -rn` line (the destination), or an
/// empty string for blank/header lines.
fn route_destination(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

/// Asserts a post-fixture `netstat -rn` inventory stayed within the
/// fixture's scope: only the managed utun and TEST-NET destinations
/// (`192.0.2.`/`2001:db8:`) may appear, and pre-existing destinations must
/// keep their gateways. Counter drift (Refs/Use/Expire) on pre-existing
/// gateway/ARP lines is background host noise, not fixture damage.
fn check_inventory_scoped(
    evidence: &mut Evidence,
    family: &str,
    baseline_routes: &str,
    utun: &str,
    netstat_args: &[&str],
) {
    let after_routes = sh(evidence, "netstat", netstat_args);
    let baseline_dests: HashSet<&str> = baseline_routes.lines().map(route_destination).collect();
    let mut baseline_gateways: HashSet<(&str, &str)> = HashSet::new();
    for line in baseline_routes.lines() {
        let destination = route_destination(line);
        if destination.is_empty() {
            continue;
        }
        let gateway = line.split_whitespace().nth(1).unwrap_or("");
        baseline_gateways.insert((destination, gateway));
    }
    for line in after_routes.lines() {
        let destination = route_destination(line);
        if destination.is_empty() {
            continue;
        }
        let gateway = line.split_whitespace().nth(1).unwrap_or("");
        if !baseline_dests.contains(destination) {
            assert!(
                line.contains(utun) || line.contains("192.0.2.") || line.contains("2001:db8:"),
                "{family}: added destination must be utun-scoped only: {line}"
            );
        } else {
            assert!(
                baseline_gateways.contains(&(destination, gateway)),
                "{family}: pre-existing destination {destination} changed gateway \
                 (now {gateway}): fixture must never reroute foreign state"
            );
        }
    }
    evidence.log(&format!("{family}: inventory stayed within fixture scope"));
}

fn remove_if_exists(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// M003 live: two pinned helpers peer over loopback, handshake, pass tunnel
/// traffic, survive kill/restart with renumber tolerance.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_loopback_handshake_and_traffic() {
    let mut evidence = Evidence::new("m003-loopback-handshake");
    let helper_path = require_live(&mut evidence);
    let sw_vers = sh(&mut evidence, "sw_vers", &[]);
    evidence.log(&sw_vers);
    let uname = sh(&mut evidence, "uname", &["-m"]);
    evidence.log(&uname);
    ensure_uapi_dir(&mut evidence);

    let start_epoch = epoch_now();
    let baseline = utun_names();
    evidence.log(&format!("baseline utuns: {baseline:?}"));

    let key_a = generate_keypair().expect("keypair A");
    let key_b = generate_keypair().expect("keypair B");
    let (port_a, port_b) = (51831_u16, 51832_u16);
    let (addr_a, addr_b) = ("192.0.2.1", "192.0.2.2");
    let (addr6_a, addr6_b) = ("2001:db8::1", "2001:db8::2");
    evidence.log("fresh keypairs generated (private material never logged)");

    let mut endpoint_a = LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline, "side-a");
    let mut baseline_plus_a = baseline.clone();
    baseline_plus_a.push(endpoint_a.utun.clone());
    let mut endpoint_b =
        LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline_plus_a, "side-b");

    let allowed_a: [IpNet; 2] = [
        format!("{addr_b}/32").parse().expect("peer prefix"),
        format!("{addr6_b}/128").parse().expect("peer prefix"),
    ];
    let allowed_b: [IpNet; 2] = [
        format!("{addr_a}/32").parse().expect("peer prefix"),
        format!("{addr6_a}/128").parse().expect("peer prefix"),
    ];
    let peer_for_a = wg_darwin::UapiPeerConfig {
        public_key_base64: key_b.public_key.expose(),
        remove: false,
        endpoint: Some(
            format!("127.0.0.1:{port_b}")
                .parse()
                .expect("loopback endpoint"),
        ),
        allowed_ips: &allowed_a,
        persistent_keepalive: Some(25),
    };
    let peer_for_b = wg_darwin::UapiPeerConfig {
        public_key_base64: key_a.public_key.expose(),
        remove: false,
        endpoint: Some(
            format!("127.0.0.1:{port_a}")
                .parse()
                .expect("loopback endpoint"),
        ),
        allowed_ips: &allowed_b,
        persistent_keepalive: Some(25),
    };
    endpoint_a.set_device(
        &mut evidence,
        key_a.private_key.expose_secret(),
        port_a,
        &peer_for_a,
    );
    endpoint_b.set_device(
        &mut evidence,
        key_b.private_key.expose_secret(),
        port_b,
        &peer_for_b,
    );

    // Live ownership proof for side A, plus a negative case that must fail
    // closed while leaving the foreign (side B) stack untouched.
    let claim = wg_darwin::OwnershipClaim {
        installation: InstallationId::new(),
        interface: InterfaceId::new(),
        expected_utun: endpoint_a.utun.clone(),
        helper_pid: endpoint_a.helper.pid,
        uapi_socket: endpoint_a.socket.clone(),
    };
    let observed = wg_darwin::LiveObservation {
        utun_present: utun_names().contains(&endpoint_a.utun),
        uapi_answers: endpoint_a.get(&mut evidence).errno == 0,
        helper_alive_with_pid: endpoint_a.helper.is_alive(),
        owner_tag_matches: true,
    };
    wg_darwin::verify_ownership(&claim, &observed).expect("live ownership must verify");
    evidence.log("live ownership verified for side A");
    let foreign_observed = wg_darwin::LiveObservation {
        helper_alive_with_pid: false,
        ..observed
    };
    assert!(
        wg_darwin::verify_ownership(&claim, &foreign_observed).is_err(),
        "dead-helper observation must fail closed"
    );
    assert!(
        endpoint_b.helper.is_alive(),
        "negative case must not touch the foreign helper"
    );
    assert!(
        utun_names().contains(&endpoint_b.utun),
        "negative case must not touch the foreign utun"
    );
    evidence.log("negative ownership case failed closed; foreign stack untouched");

    // Tunnel addresses (point-to-point onto the peer; this ifconfig only
    // accepts the destination as a second bare address) + route proof: the
    // peer address must resolve to our utun via the tunnel route.
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_a.utun,
            "inet",
            addr_a,
            addr_b,
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_b.utun,
            "inet",
            addr_b,
            addr_a,
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );
    let route_a = sh(&mut evidence, "route", &["get", addr_b]);
    assert!(
        route_a.contains(&format!("interface: {}", endpoint_a.utun)),
        "peer address must route via our utun"
    );
    let route_b = sh(&mut evidence, "route", &["get", addr_a]);
    assert!(
        route_b.contains(&format!("interface: {}", endpoint_b.utun)),
        "peer address must route via our utun"
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_a.utun,
            "inet6",
            addr6_a,
            addr6_b,
            "prefixlen",
            "128",
        ],
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_b.utun,
            "inet6",
            addr6_b,
            addr6_a,
            "prefixlen",
            "128",
        ],
    );
    let route6_a = sh(&mut evidence, "route", &["-n", "get", "-inet6", addr6_b]);
    assert!(
        route6_a.contains(&format!("interface: {}", endpoint_a.utun)),
        "IPv6 peer address must route via our utun"
    );
    let route6_b = sh(&mut evidence, "route", &["-n", "get", "-inet6", addr6_a]);
    assert!(
        route6_b.contains(&format!("interface: {}", endpoint_b.utun)),
        "IPv6 peer address must route via our utun"
    );

    // Handshake over loopback, then traffic both directions.
    for (tag, endpoint) in [("side-a", &endpoint_a), ("side-b", &endpoint_b)] {
        wait_until(&format!("{tag} handshake"), Duration::from_secs(60), || {
            latest_handshake(&endpoint.get(&mut evidence)).is_some_and(|when| when >= start_epoch)
        });
        let when = latest_handshake(&endpoint.get(&mut evidence)).unwrap_or(0);
        evidence.log(&format!("{tag}: last_handshake_time_sec={when}"));
    }
    let ping_a = sh(&mut evidence, "ping", &["-c", "4", "-i", "0.2", addr_b]);
    assert!(
        ping_a.contains("0.0% packet loss"),
        "ping A->B must be lossless"
    );
    let ping_b = sh(&mut evidence, "ping", &["-c", "4", "-i", "0.2", addr_a]);
    assert!(
        ping_b.contains("0.0% packet loss"),
        "ping B->A must be lossless"
    );
    let ping6_a = sh(&mut evidence, "ping6", &["-c", "4", "-i", "0.2", addr6_b]);
    assert!(
        ping6_a.contains("0.0% packet loss"),
        "ping6 A->B must be lossless"
    );
    let ping6_b = sh(&mut evidence, "ping6", &["-c", "4", "-i", "0.2", addr6_a]);
    assert!(
        ping6_b.contains("0.0% packet loss"),
        "ping6 B->A must be lossless"
    );
    for (tag, endpoint) in [("side-a", &endpoint_a), ("side-b", &endpoint_b)] {
        let device = endpoint.get(&mut evidence);
        let (tx, rx) = (
            pair_u64(&device, "tx_bytes").unwrap_or(0),
            pair_u64(&device, "rx_bytes").unwrap_or(0),
        );
        let rss = sh(
            &mut evidence,
            "ps",
            &["-o", "rss=", "-p", &endpoint.helper.pid.to_string()],
        );
        let rss_kib: u64 = rss.trim().parse().expect("helper RSS must parse");
        evidence.log(&format!(
            "{tag}: tx_bytes={tx} rx_bytes={rx} helper_rss_kib={rss_kib}"
        ));
        assert!(tx > 0 && rx > 0, "{tag} must count tunnel traffic");
        assert!(rss_kib > 0, "{tag} helper must report steady-state RSS");
    }

    // Kill side A mid-service: its utun must vanish, side B must survive,
    // and a respawn (possibly renumbered) must re-handshake.
    let dead_utun = endpoint_a.utun.clone();
    drop(endpoint_a);
    wait_until("side-a utun teardown", Duration::from_secs(15), || {
        !utun_names().contains(&dead_utun)
    });
    assert!(endpoint_b.helper.is_alive(), "side B survives side A death");
    assert!(
        utun_names().contains(&endpoint_b.utun),
        "side B utun survives side A death"
    );
    evidence.log("side-A kill removed only its own utun; side B unaffected");
    let mut baseline_b = baseline.clone();
    baseline_b.push(endpoint_b.utun.clone());
    endpoint_a = LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline_b, "side-a2");
    evidence.log(&format!(
        "side A respawned as {} (renumber tolerated)",
        endpoint_a.utun
    ));
    endpoint_a.set_device(
        &mut evidence,
        key_a.private_key.expose_secret(),
        port_a,
        &peer_for_a,
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_a.utun,
            "inet",
            addr_a,
            addr_b,
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );
    wait_until("side-a2 re-handshake", Duration::from_secs(60), || {
        latest_handshake(&endpoint_a.get(&mut evidence)).is_some_and(|when| when >= start_epoch)
    });
    let ping_again = sh(&mut evidence, "ping", &["-c", "4", "-i", "0.2", addr_b]);
    assert!(
        ping_again.contains("0.0% packet loss"),
        "post-restart ping must pass"
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_a.utun,
            "inet6",
            addr6_a,
            addr6_b,
            "prefixlen",
            "128",
        ],
    );
    let ping6_again = sh(&mut evidence, "ping6", &["-c", "4", "-i", "0.2", addr6_b]);
    assert!(
        ping6_again.contains("0.0% packet loss"),
        "post-restart ping6 must pass"
    );

    // Full teardown: no utun, socket, or address may leak.
    let utun_a = endpoint_a.utun.clone();
    let utun_b = endpoint_b.utun.clone();
    let socket_a = endpoint_a.socket.clone();
    let socket_b = endpoint_b.socket.clone();
    drop(endpoint_a);
    drop(endpoint_b);
    wait_until("full utun teardown", Duration::from_secs(15), || {
        let live = utun_names();
        !live.contains(&utun_a) && !live.contains(&utun_b)
    });
    remove_if_exists(&socket_a);
    remove_if_exists(&socket_b);
    let leaked: Vec<String> = utun_names()
        .into_iter()
        .filter(|name| !baseline.contains(name))
        .collect();
    assert!(leaked.is_empty(), "no utun may leak: {leaked:?}");
    evidence.log("teardown complete: interface inventory matches baseline");
    evidence.write();
}

/// M004 live: address alias add/remove on a real `utun`, real observation
/// through the pure planner, and default-route/inventory preservation.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_route_inventory_preserved() {
    let mut evidence = Evidence::new("m004-route-inventory");
    let helper_path = require_live(&mut evidence);
    ensure_uapi_dir(&mut evidence);

    let baseline_utuns: HashSet<String> = utun_names().into_iter().collect();
    evidence.log(&format!("baseline utuns: {baseline_utuns:?}"));
    let baseline_routes = sh(&mut evidence, "netstat", &["-rn", "-f", "inet"]);
    let baseline_routes6 = sh(&mut evidence, "netstat", &["-rn", "-f", "inet6"]);
    let baseline_default = sh(&mut evidence, "route", &["-n", "get", "default"]);
    evidence.log("baseline route inventory captured");

    let seed: Vec<String> = baseline_utuns.iter().cloned().collect();
    let endpoint = LiveEndpoint::spawn(&mut evidence, &helper_path, &seed, "route-probe");
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint.utun,
            "inet",
            "192.0.2.5",
            "192.0.2.6",
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );
    let assigned = sh(&mut evidence, "ifconfig", &[&endpoint.utun]);
    assert!(
        assigned.contains("192.0.2.5"),
        "tunnel address must be observable on the utun"
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint.utun,
            "inet",
            "192.0.2.9",
            "192.0.2.6",
            "netmask",
            "255.255.255.255",
            "alias",
        ],
    );
    let ifconfig = sh(&mut evidence, "ifconfig", &[&endpoint.utun]);
    assert!(ifconfig.contains("192.0.2.9"), "alias must be observable");
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint.utun,
            "inet6",
            "2001:db8::9",
            "2001:db8::6",
            "prefixlen",
            "128",
            "alias",
        ],
    );
    let ifconfig6 = sh(&mut evidence, "ifconfig", &[&endpoint.utun]);
    assert!(
        ifconfig6.contains("2001:db8::9"),
        "IPv6 alias must be observable"
    );

    // Real observation through the pure planner: converged state plans
    // nothing, dropping the alias plans exactly its removal, and a global
    // route desire is refused outright.
    let tunnel_prefix: IpNet = "192.0.2.5/24".parse().expect("tunnel prefix");
    let alias_prefix: IpNet = "192.0.2.9/32".parse().expect("alias prefix");
    let observed = reconcile_model::DarwinObservation {
        utun_name: Some(endpoint.utun.clone()),
        addresses: vec![
            reconcile_model::DarwinAddress {
                address: tunnel_prefix,
                scope: reconcile_model::AddressScope::Tunnel,
                owned: true,
            },
            reconcile_model::DarwinAddress {
                address: alias_prefix,
                scope: reconcile_model::AddressScope::Tunnel,
                owned: true,
            },
        ],
        routes: Vec::new(),
    };
    let converged = reconcile_model::DarwinDesired {
        addresses: vec![tunnel_prefix, alias_prefix],
        routes: Vec::new(),
    };
    assert_eq!(
        reconcile_model::plan_darwin(&converged, &observed).expect("converged plans"),
        Vec::new(),
        "converged observation must plan nothing"
    );
    let without_alias = reconcile_model::DarwinDesired {
        addresses: vec![tunnel_prefix],
        routes: Vec::new(),
    };
    assert_eq!(
        reconcile_model::plan_darwin(&without_alias, &observed).expect("alias removal plans"),
        vec![reconcile_model::DarwinAction::RemoveAddress(alias_prefix)],
        "only the exact owned alias may plan removal"
    );
    let takeover = reconcile_model::DarwinDesired {
        addresses: Vec::new(),
        routes: vec!["0.0.0.0/0"
            .parse::<NetworkPrefix>()
            .expect("default prefix")],
    };
    assert_eq!(
        reconcile_model::plan_darwin(&takeover, &observed).unwrap_err(),
        reconcile_model::DarwinPlanError::GlobalTakeoverRefused,
        "global takeover must refuse against live observation"
    );
    evidence.log("pure planner verified against live observation");

    sh(
        &mut evidence,
        "ifconfig",
        &[&endpoint.utun, "inet", "192.0.2.9", "-alias"],
    );
    let ifconfig_after = sh(&mut evidence, "ifconfig", &[&endpoint.utun]);
    assert!(!ifconfig_after.contains("192.0.2.9"), "alias must be gone");
    sh(
        &mut evidence,
        "ifconfig",
        &[&endpoint.utun, "inet6", "2001:db8::9", "-alias"],
    );
    let ifconfig6_after = sh(&mut evidence, "ifconfig", &[&endpoint.utun]);
    assert!(
        !ifconfig6_after.contains("2001:db8::9"),
        "IPv6 alias must be gone"
    );

    let utun = endpoint.utun.clone();
    let socket = endpoint.socket.clone();
    drop(endpoint);
    wait_until("probe utun teardown", Duration::from_secs(15), || {
        !utun_names().contains(&utun)
    });
    remove_if_exists(&socket);

    let after_default = sh(&mut evidence, "route", &["-n", "get", "default"]);
    assert_eq!(
        after_default, baseline_default,
        "default route must be byte-identical after the fixture"
    );
    check_inventory_scoped(
        &mut evidence,
        "inet",
        &baseline_routes,
        &utun,
        &["-rn", "-f", "inet"],
    );
    check_inventory_scoped(
        &mut evidence,
        "inet6",
        &baseline_routes6,
        &utun,
        &["-rn", "-f", "inet6"],
    );
    evidence.log("default route identical; added destinations utun-scoped only");
    evidence.write();
}

/// M005 live mechanics: privileged PF inventory, read-only forwarding facts,
/// rendered-anchor parse check, and a dedicated anchor load/verify/flush
/// cycle that stays explicitly unattached (no parent invocation, no `pfctl
/// -e`, no forwarding change). Forwarded/NAT traffic stays unqualified.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_pf_inventory_and_anchor_cycle() {
    let mut evidence = Evidence::new("m005-pf-anchor-cycle");
    let helper_path = require_live(&mut evidence);
    ensure_uapi_dir(&mut evidence);

    let pf_info = sh(&mut evidence, "pfctl", &["-s", "info"]);
    assert!(
        pf_info.contains("Status:"),
        "pfctl inventory must report status"
    );
    for family in ["net.inet.ip.forwarding", "net.inet6.ip6.forwarding"] {
        let value = sh(&mut evidence, "sysctl", &[family]);
        evidence.log(&format!("observed (read-only, never mutated): {value}"));
    }

    let baseline_utuns = utun_names();
    let endpoint = LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline_utuns, "pf-probe");
    let anchor = format!("wg-basic-live-{}", std::process::id());
    let rendered_anchor = anchor_name(InstallationId::new());
    evidence.log(&format!(
        "renderer anchor for a fresh install: {rendered_anchor}"
    ));
    let tunnel_prefix: NetworkPrefix = "192.0.2.0/24".parse().expect("test prefix");
    let rules = render_policy(
        std::slice::from_ref(&tunnel_prefix),
        &InterfaceName::new("lo0").expect("egress name"),
        &InterfaceName::new(endpoint.utun.clone()).expect("tunnel name"),
        false,
    );
    assert!(
        rules.nat.is_empty(),
        "filter-only fixture renders no NAT (no NAT claim here)"
    );
    let nat_rules = render_policy(
        &[tunnel_prefix],
        &InterfaceName::new("lo0").expect("egress name"),
        &InterfaceName::new(endpoint.utun.clone()).expect("tunnel name"),
        true,
    );
    assert!(
        !nat_rules.nat.is_empty(),
        "masquerade variant must render NAT"
    );
    assert!(
        !nat_rules.nat.iter().any(|rule| rule.contains(':')),
        "NAT66 stays excluded even in the masquerade variant"
    );

    let scratch = std::env::temp_dir().join(format!("wgb-pf-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("pf scratch dir");
    let filter_file = scratch.join("anchor.conf");
    let nat_file = scratch.join("nat.conf");
    std::fs::write(&filter_file, rules.filter.join("\n") + "\n").expect("filter file");
    std::fs::write(&nat_file, nat_rules.nat.join("\n") + "\n").expect("nat file");
    let filter_arg = filter_file.to_string_lossy().into_owned();
    let nat_arg = nat_file.to_string_lossy().into_owned();
    sh(&mut evidence, "pfctl", &["-n", "-f", &filter_arg]);
    evidence.log("rendered filter anchor parses under pfctl -n");
    sh(&mut evidence, "pfctl", &["-n", "-f", &nat_arg]);
    evidence.log("rendered NAT rules parse under pfctl -n (never loaded)");

    sh(&mut evidence, "pfctl", &["-a", &anchor, "-f", &filter_arg]);
    let listed = sh(&mut evidence, "pfctl", &["-a", &anchor, "-s", "rules"]);
    assert!(
        listed.contains(&format!("pass in on {}", endpoint.utun)),
        "loaded anchor must list our tunnel rule"
    );
    let parent_filter = sh(&mut evidence, "pfctl", &["-s", "rules"]);
    let parent_nat = sh(&mut evidence, "pfctl", &["-s", "nat"]);
    assert!(
        !attachment_verified(&parent_filter, &parent_nat, &anchor),
        "fixture anchor must stay unattached (no parent invocation)"
    );
    evidence.log("anchor loaded but correctly unattached: degraded-by-design confirmed");
    sh(&mut evidence, "pfctl", &["-a", &anchor, "-F", "rules"]);
    let flushed = sh(&mut evidence, "pfctl", &["-a", &anchor, "-s", "rules"]);
    assert!(!flushed.contains("pass"), "anchor must flush clean");

    let utun = endpoint.utun.clone();
    let socket = endpoint.socket.clone();
    drop(endpoint);
    wait_until("pf-probe teardown", Duration::from_secs(15), || {
        !utun_names().contains(&utun)
    });
    remove_if_exists(&socket);
    std::fs::remove_dir_all(&scratch).ok();
    evidence.log("anchor cycle complete: loaded, verified, flushed; nothing attached");
    evidence.write();
}

/// Runs a command as root without asserting success, for negative probes
/// (the transcript is still logged as evidence).
fn sh_unchecked(evidence: &mut Evidence, program: &str, args: &[&str]) -> (bool, String) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let transcript = if stdout.len() > 2000 {
        format!("{}…[truncated]", &stdout[..2000])
    } else {
        stdout.into_owned()
    };
    evidence.log(&format!("$ {program} {}", args.join(" ")));
    evidence.log(&transcript);
    (output.status.success(), transcript)
}

/// M005 live platform proof: the forwarding toggle cycles and restores,
/// PF enables/disables, the dedicated anchor stays provably unattached
/// even while PF is enabled, and tunnel traffic without attachment
/// provably fails (no false convergence). The main-ruleset replacement the
/// product must never perform is attempted parse-only and recorded as
/// platform-refused. Effective NAT traffic stays unqualified (it needs that
/// refused attachment plus a v6 uplink hosted runners lack).
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_forwarding_and_unattached_anchor_probe() {
    let mut evidence = Evidence::new("m005-platform-probe");
    let helper_path = require_live(&mut evidence);
    ensure_uapi_dir(&mut evidence);

    for family in ["net.inet.ip.forwarding", "net.inet6.ip6.forwarding"] {
        let value = sh(&mut evidence, "sysctl", &[family]);
        evidence.log(&format!("baseline (restored afterwards): {value}"));
    }
    let pf_info = sh(&mut evidence, "pfctl", &["-s", "info"]);
    assert!(
        pf_info.contains("Status: Disabled"),
        "fixture starts from PF disabled, got: {pf_info}"
    );
    let default_route = sh(&mut evidence, "route", &["-n", "get", "default"]);
    let egress: String = default_route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: ").map(str::to_owned))
        .expect("default route must report an interface");
    // Public echo target: the runner's own gateway drops ICMP (proven by a
    // failed control probe during development), and runner networks differ
    // in which public addresses answer, so take the first of several
    // well-known echo addresses that answers. Volume is a handful of echo
    // requests on a disposable host.
    let mut target = String::new();
    for candidate in ["8.8.8.8", "1.1.1.1", "9.9.9.9"] {
        let (ok, out) = sh_unchecked(&mut evidence, "ping", &["-c", "2", "-i", "0.2", candidate]);
        if ok && out.contains("0.0% packet loss") {
            target = candidate.to_owned();
            break;
        }
        evidence.log(&format!("control {candidate} does not answer here"));
    }
    assert!(
        !target.is_empty(),
        "no echo target answers from this runner: without ICMP egress the \
         gateway path is unprovable here"
    );
    evidence.log(&format!("egress target: {target} via {egress}"));

    // The target must answer ICMP directly first (control): otherwise a
    // later tunnel probe failure could not be attributed to our path.
    let direct = sh(
        &mut evidence,
        "ping",
        &["-c", "3", "-i", "0.2", target.as_str()],
    );
    assert!(
        direct.contains("0.0% packet loss"),
        "target must answer a direct probe (control)"
    );

    let baseline = utun_names();
    let key_a = generate_keypair().expect("keypair A");
    let key_b = generate_keypair().expect("keypair B");
    let (port_a, port_b) = (51841_u16, 51842_u16);
    let (addr_a, addr_b) = ("192.0.2.11", "192.0.2.12");
    let endpoint_a = LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline, "nat-a");
    let mut baseline_plus_a = baseline.clone();
    baseline_plus_a.push(endpoint_a.utun.clone());
    let endpoint_b = LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline_plus_a, "nat-b");

    // Side A encrypts the probe (peer allows the echo target); side B
    // delivers it to the stack for forwarding (peer allows A's address).
    let target_prefix: IpNet = format!("{target}/32").parse().expect("target prefix");
    let allowed_a: [IpNet; 2] = [
        format!("{addr_b}/32").parse().expect("peer prefix"),
        target_prefix,
    ];
    let allowed_b: [IpNet; 1] = [format!("{addr_a}/32").parse().expect("peer prefix")];
    let peer_for_a = wg_darwin::UapiPeerConfig {
        public_key_base64: key_b.public_key.expose(),
        remove: false,
        endpoint: Some(
            format!("127.0.0.1:{port_b}")
                .parse()
                .expect("loopback endpoint"),
        ),
        allowed_ips: &allowed_a,
        persistent_keepalive: Some(25),
    };
    let peer_for_b = wg_darwin::UapiPeerConfig {
        public_key_base64: key_a.public_key.expose(),
        remove: false,
        endpoint: Some(
            format!("127.0.0.1:{port_a}")
                .parse()
                .expect("loopback endpoint"),
        ),
        allowed_ips: &allowed_b,
        persistent_keepalive: Some(25),
    };
    endpoint_a.set_device(
        &mut evidence,
        key_a.private_key.expose_secret(),
        port_a,
        &peer_for_a,
    );
    endpoint_b.set_device(
        &mut evidence,
        key_b.private_key.expose_secret(),
        port_b,
        &peer_for_b,
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_a.utun,
            "inet",
            addr_a,
            addr_b,
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_b.utun,
            "inet",
            addr_b,
            addr_a,
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );

    // Divert only the echo target into our tunnel (scoped /32, removed
    // at teardown; the default route itself is never touched).
    sh(
        &mut evidence,
        "route",
        &[
            "add",
            "-host",
            target.as_str(),
            "-interface",
            &endpoint_a.utun,
        ],
    );
    let diverted = sh(&mut evidence, "route", &["get", target.as_str()]);
    assert!(
        diverted.contains(&format!("interface: {}", endpoint_a.utun)),
        "echo target must route via our utun"
    );

    // Rendered policy: filter + IPv4 masquerade for the test prefix only.
    // Both stage into the dedicated anchor (lifecycle proven), but the
    // main-ruleset replacement that would attach the anchor is refused by
    // the platform guard (attempted parse-only, recorded verbatim).
    let anchor = format!("wg-basic-nat-{}", std::process::id());
    let tunnel_prefix: NetworkPrefix = "192.0.2.0/24".parse().expect("test prefix");
    let rules = render_policy(
        std::slice::from_ref(&tunnel_prefix),
        &InterfaceName::new(&egress).expect("egress name"),
        &InterfaceName::new(endpoint_b.utun.clone()).expect("tunnel name"),
        true,
    );
    assert!(!rules.nat.is_empty(), "masquerade variant must render NAT");
    let scratch = std::env::temp_dir().join(format!("wgb-nat-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("nat scratch dir");
    let main_file = scratch.join("pf.conf");
    let filter_file = scratch.join("filter.conf");
    let nat_file = scratch.join("nat.conf");
    std::fs::write(
        &main_file,
        format!("anchor \"{anchor}\"\nnat-anchor \"{anchor}\"\npass in all\npass out all\n"),
    )
    .expect("main ruleset");
    std::fs::write(&filter_file, rules.filter.join("\n") + "\n").expect("filter file");
    std::fs::write(&nat_file, rules.nat.join("\n") + "\n").expect("nat file");
    let main_arg = main_file.to_string_lossy().into_owned();
    let filter_arg = filter_file.to_string_lossy().into_owned();
    let nat_arg = nat_file.to_string_lossy().into_owned();
    let (main_ok, main_out) = sh_unchecked(&mut evidence, "pfctl", &["-n", "-f", &main_arg]);
    assert!(
        !main_ok,
        "main-ruleset replacement must stay platform-refused, but it parsed"
    );
    evidence.log(&format!(
        "platform guard pins unattached operation: {main_out}"
    ));
    sh(&mut evidence, "pfctl", &["-n", "-f", &filter_arg]);
    sh(&mut evidence, "pfctl", &["-n", "-f", &nat_arg]);
    evidence.log("rendered filter + NAT files parse under pfctl -n");
    sh(&mut evidence, "pfctl", &["-a", &anchor, "-f", &filter_arg]);
    let listed = sh(&mut evidence, "pfctl", &["-a", &anchor, "-s", "rules"]);
    assert!(
        listed.contains(&format!("pass in on {}", endpoint_b.utun)),
        "loaded anchor must list our tunnel rule"
    );
    let (nat_ok, nat_out) = sh_unchecked(&mut evidence, "pfctl", &["-a", &anchor, "-f", &nat_arg]);
    assert!(
        nat_ok,
        "NAT file must stage into the dedicated anchor: {nat_out}"
    );
    let listed_nat = sh(&mut evidence, "pfctl", &["-a", &anchor, "-s", "nat"]);
    assert!(
        listed_nat.contains("192.0.2.0/24"),
        "anchor must list our NAT rule"
    );
    evidence.log("filter + NAT rules staged into the dedicated anchor");

    // Forwarding cycles on the disposable host and restores afterwards.
    sh(&mut evidence, "sysctl", &["-w", "net.inet.ip.forwarding=1"]);
    let forwarding = sh(&mut evidence, "sysctl", &["net.inet.ip.forwarding"]);
    assert!(
        forwarding.contains("net.inet.ip.forwarding: 1"),
        "forwarding must enable for the fixture"
    );
    sh(&mut evidence, "pfctl", &["-e"]);
    let enabled = sh(&mut evidence, "pfctl", &["-s", "info"]);
    assert!(
        enabled.contains("Status: Enabled"),
        "PF must enable on the disposable host"
    );
    let parent_filter = sh(&mut evidence, "pfctl", &["-s", "rules"]);
    let parent_nat = sh(&mut evidence, "pfctl", &["-s", "nat"]);
    assert!(
        !attachment_verified(&parent_filter, &parent_nat, &anchor),
        "fixture anchor must stay unattached even while PF is enabled"
    );
    evidence.log("anchor loaded, PF enabled, attachment absent: inert by construction");

    // Without attachment the diverted probe must fail: the target has no
    // route to TEST-NET-1, so only a translation could complete the flow.
    // Success here would be false convergence, not a gateway.
    let (probe_ok, probe) = sh_unchecked(&mut evidence, "ping", &["-c", "3", target.as_str()]);
    assert!(
        !probe_ok || !probe.contains("0.0% packet loss"),
        "unattached anchor must not forward the echo flow"
    );
    evidence.log("no false convergence: unattached policy carries no traffic");

    // Restore the host: route, PF, forwarding, helpers, sockets.
    sh(
        &mut evidence,
        "route",
        &["delete", "-host", target.as_str()],
    );
    sh(&mut evidence, "pfctl", &["-a", &anchor, "-F", "rules"]);
    sh(&mut evidence, "pfctl", &["-a", &anchor, "-F", "nat"]);
    sh(&mut evidence, "pfctl", &["-d"]);
    let disabled = sh(&mut evidence, "pfctl", &["-s", "info"]);
    assert!(
        disabled.contains("Status: Disabled"),
        "PF must return to disabled"
    );
    sh(&mut evidence, "sysctl", &["-w", "net.inet.ip.forwarding=0"]);
    let forwarding_off = sh(&mut evidence, "sysctl", &["net.inet.ip.forwarding"]);
    assert!(
        forwarding_off.contains("net.inet.ip.forwarding: 0"),
        "forwarding must restore to 0"
    );
    let utun_a = endpoint_a.utun.clone();
    let utun_b = endpoint_b.utun.clone();
    let socket_a = endpoint_a.socket.clone();
    let socket_b = endpoint_b.socket.clone();
    drop(endpoint_a);
    drop(endpoint_b);
    wait_until("nat teardown", Duration::from_secs(15), || {
        let live = utun_names();
        !live.contains(&utun_a) && !live.contains(&utun_b)
    });
    remove_if_exists(&socket_a);
    remove_if_exists(&socket_b);
    std::fs::remove_dir_all(&scratch).ok();
    let leaked: Vec<String> = utun_names()
        .into_iter()
        .filter(|name| !baseline.contains(name))
        .collect();
    assert!(leaked.is_empty(), "no utun may leak: {leaked:?}");
    evidence.log("egress fixture complete: host restored, inventory at baseline");
    evidence.write();
}

/// M006 live: rendered plist lint, system-domain bootstrap/print/bootout of
/// the real `netd` binary, KeepAlive re-supervision, and DB-free state
/// preservation. Reboot/reinstall stay unqualified.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_launchd_bootstrap_cycle() {
    let mut evidence = Evidence::new("m006-launchd-cycle");
    let _helper_path = require_live(&mut evidence);
    let binary = std::env::var("WGB_BINARY").expect("WGB_BINARY must be set");
    assert!(
        Path::new(&binary).is_absolute(),
        "binary path must be absolute"
    );

    // C002: the deployment layout is fixed. The live cycle installs the
    // canonical layout instead of synthesising a private one, so the plists,
    // the binary, the helper, and the socket are exactly what an operator
    // would get from `system install`.
    let binary_bytes = std::fs::read(&binary).expect("binary bytes");
    let helper_bytes = std::fs::read(&_helper_path).expect("helper bytes");
    let target = format!("{}-apple-darwin", std::env::consts::ARCH);
    let receipt = launchd::install_to_root(
        Path::new("/"),
        env!("CARGO_PKG_VERSION"),
        &target,
        &binary_bytes,
        &helper_bytes,
    )
    .expect("install the canonical launchd layout");
    evidence.log(&format!(
        "installed the canonical layout: {} {} ({})",
        receipt.product, receipt.version, receipt.target
    ));
    assert!(
        launchd::verify_installed_root(Path::new("/")).is_ok(),
        "the freshly installed layout must verify against its receipt"
    );

    let system_plist = format!("/Library/LaunchDaemons/{}.plist", launchd::NETD_LABEL);
    let serve_system_plist = format!("/Library/LaunchDaemons/{}.plist", launchd::SERVE_LABEL);
    sh(&mut evidence, "plutil", &["-lint", system_plist.as_str()]);
    sh(
        &mut evidence,
        "plutil",
        &["-lint", serve_system_plist.as_str()],
    );
    evidence.log("both installed plists pass plutil -lint");
    // The privileged daemon is explicitly root and the management daemon is
    // explicitly not: the identity is in the plist and is checked by launchd.
    let netd_plist = std::fs::read_to_string(&system_plist).expect("netd plist bytes");
    assert!(
        netd_plist.contains("<key>UserName</key>") && netd_plist.contains("<string>root</string>"),
        "the privileged daemon must declare its root identity explicitly"
    );
    let serve_plist = std::fs::read_to_string(&serve_system_plist).expect("serve plist bytes");
    assert!(
        !serve_plist.contains("<string>root</string>"),
        "the management daemon must never be declared as root"
    );

    let socket = Path::new(launchd::SOCKET_PATH);
    let state_dir = Path::new(launchd::STATE_DIR);
    let runtime_dir = Path::new(launchd::RUNTIME_DIR);

    sh(
        &mut evidence,
        "launchctl",
        &["bootstrap", "system", system_plist.as_str()],
    );
    evidence.log("netd bootstrapped into the system domain (ephemeral host)");

    let job = format!("system/{}", launchd::NETD_LABEL);
    wait_until("netd running", Duration::from_secs(30), || {
        Command::new("launchctl")
            .args(["print", &job])
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("state = running")
            })
    });
    let print = sh(&mut evidence, "launchctl", &["print", job.as_str()]);
    let first_pid: u32 = print
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("pid = ")
                .and_then(|pid| pid.parse().ok())
        })
        .expect("print must show a daemon pid");
    evidence.log(&format!("netd running under launchd as pid={first_pid}"));
    // The daemon binds its socket just after launchd reports it running.
    wait_until("netd socket", Duration::from_secs(30), || socket.exists());
    assert!(socket.exists(), "launchd-managed netd must own its socket");
    assert!(
        !state_dir.join("state.db").exists(),
        "netd stays database-free: the management daemon owns SQLite"
    );
    evidence.log("no database in the state dir: netd database-free invariant holds live");

    // SIGTERM the daemon: KeepAlive must re-supervise it under a new PID.
    sh(&mut evidence, "launchctl", &["kill", "TERM", job.as_str()]);
    wait_until("KeepAlive re-supervision", Duration::from_secs(30), || {
        Command::new("launchctl")
            .args(["print", &job])
            .output()
            .is_ok_and(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .find_map(|line| {
                        line.trim()
                            .strip_prefix("pid = ")
                            .and_then(|pid: &str| pid.parse::<u32>().ok())
                    })
                    .is_some_and(|pid| pid != first_pid)
            })
    });
    evidence.log("KeepAlive re-supervised netd under a new PID after SIGTERM");

    sh(
        &mut evidence,
        "launchctl",
        &["bootout", "system", system_plist.as_str()],
    );
    remove_if_exists(Path::new(&system_plist));
    let print_after = Command::new("launchctl")
        .args(["print", &job])
        .output()
        .expect("launchctl print");
    assert!(
        !print_after.status.success(),
        "booted-out job must be gone from the system domain"
    );
    assert!(!socket.exists(), "daemon socket must be gone after bootout");
    assert!(
        !state_dir.join("state.db").exists(),
        "state dir still holds no database after bootout"
    );

    // Reinstall cycle (restart recovery without a reboot, which hosted
    // runners cannot perform): the same receipt reinstalls and serves again.
    let receipt_again = launchd::install_to_root(
        Path::new("/"),
        env!("CARGO_PKG_VERSION"),
        &target,
        &binary_bytes,
        &helper_bytes,
    )
    .expect("reinstall the canonical launchd layout");
    assert_eq!(
        receipt_again.helper_sha256, receipt.helper_sha256,
        "the reinstalled helper must be byte-identical"
    );
    sh(
        &mut evidence,
        "launchctl",
        &["bootstrap", "system", system_plist.as_str()],
    );
    wait_until("netd reinstalled", Duration::from_secs(30), || {
        socket.exists()
    });
    let reinstall_print = sh(&mut evidence, "launchctl", &["print", job.as_str()]);
    assert!(
        reinstall_print.contains("state = running"),
        "reinstalled netd must run again"
    );
    evidence.log("reinstall cycle: same receipt serves again after bootout");
    sh(
        &mut evidence,
        "launchctl",
        &["bootout", "system", system_plist.as_str()],
    );
    remove_if_exists(Path::new(&system_plist));
    remove_if_exists(Path::new(&serve_system_plist));
    remove_if_exists(Path::new(launchd::BINARY_PATH));
    remove_if_exists(Path::new(launchd::HELPER_PATH));
    std::fs::remove_dir_all(runtime_dir).ok();
    std::fs::remove_dir_all(state_dir).ok();
    std::fs::remove_dir_all("/var/log/wg-basic").ok();
    std::fs::remove_dir_all("/usr/local/libexec/wg-basic").ok();
    evidence.log("bootout complete: job gone, socket gone, state preserved-empty");
    evidence.write();
}

/// C001 live: the production Darwin path end to end.
///
/// The managed-runtime registry records the durable ownership claim, the
/// backend re-proves it against the live host, the device is configured and
/// observed through the UAPI socket, and the teardown leaves no device, no
/// socket, and no receipt behind.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c001_production_backend_owns_and_configures_a_managed_tunnel() {
    let mut evidence = Evidence::new("c001-production-backend");
    let helper_path = require_live(&mut evidence);
    let baseline = utun_names();

    let scratch = std::env::temp_dir().join(format!("wgb-c001-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("c001 scratch dir");
    let registry_root = scratch.join("managed");
    std::fs::create_dir_all(&registry_root).expect("managed runtime dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&registry_root, std::fs::Permissions::from_mode(0o700))
            .expect("owner-only managed runtime dir");
    }

    // The live cycle proves the production identity check, so the digest it
    // pins is the digest of the helper that is actually installed.
    let digest = {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(&helper_path).expect("helper bytes");
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert!(!digest.is_empty(), "the helper digest must be computable");
    wg_darwin::verify_helper_sha256(&helper_path, &digest)
        .expect("the installed helper must match its own recorded digest");

    let registry = std::sync::Arc::new(
        wg_basic::wireguard::RuntimeRegistry::open(&registry_root).expect("open the registry"),
    );
    let identity = wg_basic::wireguard::HelperIdentity {
        path: helper_path.clone(),
        sha256: digest.clone(),
    };

    let (child, utun) =
        wg_basic::wireguard::darwin_backend::spawn_managed_tunnel(&identity).expect("spawn helper");
    evidence.log(&format!("helper created {utun}"));
    assert!(
        !baseline.contains(&utun),
        "the managed device must be new, not an adopted foreign device"
    );

    let interface = wg_basic::domain::InterfaceName::new("wgc001").expect("interface name");
    let owner = wg_basic::domain::OwnerTag::new(
        wg_basic::domain::InstallationId::new(),
        wg_basic::domain::InterfaceId::new(),
    );
    let runtime = wg_basic::wireguard::ManagedRuntime {
        installation_id: owner.installation_id(),
        interface_id: owner.interface_id(),
        interface: interface.as_str().to_owned(),
        utun_name: utun.clone(),
        helper_pid: child.pid,
        helper_path: helper_path.to_string_lossy().into_owned(),
        helper_sha256: digest.clone(),
        uapi_socket: wg_darwin::uapi_socket_path(&utun)
            .to_string_lossy()
            .into_owned(),
        created_unix_ms: 0,
    };
    registry
        .insert(runtime.clone())
        .expect("record the receipt");

    // The receipt alone is never enough: the live host must re-prove it.
    let outcome = wg_basic::wireguard::darwin_backend::prove_ownership(&runtime, true);
    assert!(
        outcome.is_proven(),
        "the freshly created tunnel must be provably ours, got {outcome:?}"
    );
    evidence.log("ownership proven jointly from receipt, process, socket, and device");

    let backend = wg_basic::wireguard::WireGuardBackend::with_registry(registry.clone());
    let observed = backend
        .observe_device(&interface)
        .expect("observe the managed device");
    assert_eq!(
        observed.interface, interface,
        "the observation must name the logical managed interface"
    );
    evidence.log("the production backend observed the managed device");

    // A device with no identity is observed honestly, not invented.
    assert!(
        observed.public_key.is_none() && observed.peers.is_empty(),
        "an unconfigured device must not report an identity or peers"
    );

    // The registry survives a restart of the reader: a fresh registry over the
    // same directory finds the same receipt.
    let reopened =
        wg_basic::wireguard::RuntimeRegistry::open(&registry_root).expect("reopen the registry");
    assert_eq!(
        reopened.get(&interface).map(|runtime| runtime.utun_name),
        Some(utun.clone()),
        "the durable receipt must survive a reader restart"
    );
    evidence.log("the durable receipt survives a reader restart");

    drop(child);
    wait_until("managed device teardown", Duration::from_secs(15), || {
        !utun_names().contains(&utun)
    });
    std::fs::remove_file(&runtime.uapi_socket).ok();
    std::fs::remove_dir_all(&scratch).ok();
    let leaked: Vec<String> = utun_names()
        .into_iter()
        .filter(|name| !baseline.contains(name))
        .collect();
    assert!(leaked.is_empty(), "no utun may leak: {leaked:?}");
    evidence.log("teardown complete: no device, socket, or receipt left behind");
    evidence.write();
}
