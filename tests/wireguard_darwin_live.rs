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
//! - `live_launchd_bootstrap_cycle` (M006): rendered plist lint, system-domain
//!   bootstrap/print/bootout of the real `netd` binary, KeepAlive
//!   re-supervision, DB-free state-dir preservation. Reboot/reinstall stay
//!   **unqualified** (no reboot on hosted runners).
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
    pair_u64(device, "latest_handshake")
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
    evidence.log("fresh keypairs generated (private material never logged)");

    let mut endpoint_a = LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline, "side-a");
    let mut baseline_plus_a = baseline.clone();
    baseline_plus_a.push(endpoint_a.utun.clone());
    let mut endpoint_b =
        LiveEndpoint::spawn(&mut evidence, &helper_path, &baseline_plus_a, "side-b");

    let allowed_a: [IpNet; 1] = [format!("{addr_b}/32").parse().expect("peer prefix")];
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

    // Tunnel addresses (connected /24 onto each utun) + route proof: the
    // peer address must resolve to our utun via the connected route.
    sh(
        &mut evidence,
        "ifconfig",
        &[
            &endpoint_a.utun,
            "inet",
            addr_a,
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

    // Handshake over loopback, then traffic both directions.
    for (tag, endpoint) in [("side-a", &endpoint_a), ("side-b", &endpoint_b)] {
        wait_until(&format!("{tag} handshake"), Duration::from_secs(60), || {
            latest_handshake(&endpoint.get(&mut evidence)).is_some_and(|when| when >= start_epoch)
        });
        let when = latest_handshake(&endpoint.get(&mut evidence)).unwrap_or(0);
        evidence.log(&format!("{tag}: latest_handshake={when}"));
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
    for (tag, endpoint) in [("side-a", &endpoint_a), ("side-b", &endpoint_b)] {
        let device = endpoint.get(&mut evidence);
        let (tx, rx) = (
            pair_u64(&device, "tx_bytes").unwrap_or(0),
            pair_u64(&device, "rx_bytes").unwrap_or(0),
        );
        evidence.log(&format!("{tag}: tx_bytes={tx} rx_bytes={rx}"));
        assert!(tx > 0 && rx > 0, "{tag} must count tunnel traffic");
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
            "netmask",
            "255.255.255.0",
            "up",
        ],
    );
    sh(
        &mut evidence,
        "ifconfig",
        &[&endpoint.utun, "inet", "192.0.2.9/32", "alias"],
    );
    let ifconfig = sh(&mut evidence, "ifconfig", &[&endpoint.utun]);
    assert!(ifconfig.contains("192.0.2.9"), "alias must be observable");

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
    let after_routes = sh(&mut evidence, "netstat", &["-rn", "-f", "inet"]);
    let baseline_set: HashSet<&str> = baseline_routes.lines().collect();
    let foreign: Vec<&str> = after_routes
        .lines()
        .filter(|line| {
            !baseline_set.contains(line) && !line.contains(&utun) && !line.contains("192.0.2.")
        })
        .collect();
    assert!(
        foreign.is_empty(),
        "inventory diff must be utun-scoped only: {foreign:?}"
    );
    evidence.log("default route identical; inventory diff utun-scoped only");
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

    let root = std::env::temp_dir().join(format!("wgb-launchd-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("launchd scratch dir");
    let state_dir = root.join("state");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    let socket = root.join("netd.sock");
    let socket_arg = socket.to_string_lossy().into_owned();
    let log_path = root.join("netd.log");
    let log_arg = log_path.to_string_lossy().into_owned();

    let argv = launchd::netd_argv(&binary, &socket_arg);
    let plist = launchd::render_plist(launchd::NETD_LABEL, &argv, &log_arg);
    let serve_plist = launchd::render_plist(
        launchd::SERVE_LABEL,
        &launchd::serve_argv(
            &binary,
            &state_dir.to_string_lossy(),
            &root.join("serve.sock").to_string_lossy(),
        ),
        &root.join("serve.log").to_string_lossy(),
    );
    let plist_file = root.join("netd.plist");
    let serve_plist_file = root.join("serve.plist");
    std::fs::write(&plist_file, &plist).expect("netd plist");
    std::fs::write(&serve_plist_file, &serve_plist).expect("serve plist");
    let plist_arg = plist_file.to_string_lossy().into_owned();
    let serve_plist_arg = serve_plist_file.to_string_lossy().into_owned();
    sh(&mut evidence, "plutil", &["-lint", &plist_arg]);
    sh(&mut evidence, "plutil", &["-lint", &serve_plist_arg]);
    evidence.log("both rendered plists pass plutil -lint");

    let system_plist = format!("/Library/LaunchDaemons/{}.plist", launchd::NETD_LABEL);
    sh(
        &mut evidence,
        "cp",
        &[plist_arg.as_str(), system_plist.as_str()],
    );
    sh(
        &mut evidence,
        "chown",
        &["root:wheel", system_plist.as_str()],
    );
    sh(&mut evidence, "chmod", &["644", system_plist.as_str()]);
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
    let state_entries: Vec<_> = std::fs::read_dir(&state_dir).expect("state dir").collect();
    assert!(
        state_entries.is_empty(),
        "netd stays database-free: state dir untouched"
    );
    evidence.log("state dir untouched: netd database-free invariant holds live");

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
    let state_after: Vec<_> = std::fs::read_dir(&state_dir).expect("state dir").collect();
    assert!(
        state_after.is_empty(),
        "state dir still untouched after bootout"
    );
    std::fs::remove_dir_all(&root).ok();
    evidence.log("bootout complete: job gone, socket gone, state preserved-empty");
    evidence.write();
}
