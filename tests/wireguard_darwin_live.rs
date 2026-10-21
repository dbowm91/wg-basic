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
//! - `live_c001_production_backend_owns_and_configures_a_managed_tunnel` (C001):
//!   the production backend's ownership contract — registry receipt, joint
//!   ownership proof, production observe, reader restart, and a teardown that
//!   leaves no device, socket, or receipt behind.
//! - `live_c002_management_daemon_runs_unprivileged` (C002): the management
//!   daemon runs as the unprivileged `_wg-basic-serve` principal, the
//!   privileged daemon runs as root, and the privileged socket is not readable
//!   by anyone else.
//! - `live_c001_darwin_backend_converges_a_product_shaped_desired_state` (C001):
//!   the Darwin backend converges a product-shaped desired state and the
//!   managed device is observed with its addresses and routes.
//!
//! The controlled-host legs (an off-host Linux-kernel peer, a cold reboot) are
//! **not** in this target: the hosted job runs every `#[ignore]`d test here, so
//! a fixture that needs a host a hosted runner cannot be would be picked up
//! where it must not run. They live in `tests/wireguard_darwin_controlled.rs`,
//! and the shared helpers in `tests/darwin_live_common/mod.rs`.
//!
//! Private keys are generated fresh per run and never enter evidence output.

#![cfg(target_os = "macos")]

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ipnet::IpNet;
use wg_basic::domain::{
    generate_keypair, InstallationId, InterfaceId, InterfaceName, NetworkPrefix,
};
use wg_basic::firewall::{
    anchor_name, attachment_verified, observe_attachments, render_policy, Attachment,
    RequiredAttachments,
};
use wg_basic::launchd;
use wg_basic::reconcile::darwin as reconcile_model;
use wg_basic::reconcile::DesiredManagedInterface;
use wg_basic::wireguard::darwin as wg_darwin;

mod darwin_live_common;
use darwin_live_common::*;

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

/// The first anchor name the observed ruleset invokes, if any.
///
/// The fixture reads the host's **real** ruleset to learn a name the host
/// itself invokes, so the positive control proves the matcher against output
/// this product did not write.
fn first_invoked_anchor(ruleset: &str, keyword: &str) -> Option<String> {
    ruleset.lines().find_map(|line| {
        let mut tokens = line.split_whitespace();
        let first = tokens.next()?;
        let second = tokens.next()?;
        if first != keyword {
            return None;
        }
        let name = second.trim_matches('"');
        if name.is_empty() {
            return None;
        }
        Some(name.to_string())
    })
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

    // C007: the attachment verifier is per rule class and token-exact, so the
    // fixture proves it against real `pfctl` output in both directions.
    //
    // Control A (negative): the main ruleset does not invoke the managed
    // anchor, in either class.
    let parent_filter = sh(&mut evidence, "pfctl", &["-s", "rules"]);
    let parent_nat = sh(&mut evidence, "pfctl", &["-s", "nat"]);
    let observation = observe_attachments(&parent_filter, &parent_nat, &anchor);
    assert_eq!(
        observation.filter,
        Attachment::Missing,
        "the main ruleset must not invoke the managed anchor in the filter class"
    );
    assert_eq!(
        observation.nat,
        Attachment::Missing,
        "the main ruleset must not invoke the managed anchor in the NAT class"
    );
    assert!(
        !attachment_verified(
            &parent_filter,
            &parent_nat,
            &anchor,
            RequiredAttachments::FILTER_ONLY
        ),
        "an uninvoiced anchor verifies nothing"
    );
    assert!(
        !attachment_verified(
            &parent_filter,
            &parent_nat,
            &anchor,
            RequiredAttachments::FILTER_AND_NAT
        ),
        "an uninvoiced anchor verifies nothing"
    );
    evidence.log("control A (negative): the managed anchor is invoked by neither class");

    // Control B (positive): the matcher finds a real invocation the host
    // itself printed, in each class, and does not confuse it with the managed
    // anchor.
    match first_invoked_anchor(&parent_filter, "anchor") {
        Some(host_anchor) => {
            let found = observe_attachments(&parent_filter, &parent_nat, &host_anchor);
            assert_eq!(
                found.filter,
                Attachment::Invoked,
                "a real filter invocation the host printed must be recognized"
            );
            evidence.log(&format!(
                "control B (positive): the host's own filter invocation of {host_anchor} is recognized"
            ));
        }
        None => evidence.log(
            "control B (positive): the host's main ruleset invokes no filter anchor; this control is not exercised on this host",
        ),
    }
    match first_invoked_anchor(&parent_nat, "nat-anchor") {
        Some(host_anchor) => {
            let found = observe_attachments(&parent_filter, &parent_nat, &host_anchor);
            assert_eq!(
                found.nat,
                Attachment::Invoked,
                "a real NAT invocation the host printed must be recognized"
            );
            evidence.log(&format!(
                "control B (positive): the host's own NAT invocation of {host_anchor} is recognized"
            ));
        }
        None => evidence.log(
            "control B (positive): the host's NAT ruleset invokes no anchor; this control is not exercised on this host",
        ),
    }

    // Control C (positive, scoped fixture): a parent anchor that invokes the
    // managed anchor, observed through real `pfctl` output. The parent is
    // itself never invoked by the main ruleset, so the chain is inert.
    let parent_anchor = format!("{anchor}-parent");
    let parent_file = scratch.join("parent.conf");
    std::fs::write(&parent_file, format!("anchor \"{anchor}\" all\n")).expect("parent file");
    let parent_arg = parent_file.to_string_lossy().into_owned();
    sh(
        &mut evidence,
        "pfctl",
        &["-a", &parent_anchor, "-f", &parent_arg],
    );
    let parent_rules = sh(
        &mut evidence,
        "pfctl",
        &["-a", &parent_anchor, "-s", "rules"],
    );
    let parent_observation = observe_attachments(&parent_rules, "", &anchor);
    assert_eq!(
        parent_observation.filter,
        Attachment::Invoked,
        "a real parent invocation must verify the filter class"
    );
    assert_eq!(
        parent_observation.nat,
        Attachment::Missing,
        "a filter-table parent does not attach the NAT class"
    );
    assert!(
        attachment_verified(&parent_rules, "", &anchor, RequiredAttachments::FILTER_ONLY),
        "the filter class alone satisfies a filter-only requirement"
    );
    assert!(
        !attachment_verified(
            &parent_rules,
            "",
            &anchor,
            RequiredAttachments::FILTER_AND_NAT
        ),
        "one attached class never satisfies a requirement for two"
    );
    evidence.log(
        "control C (positive): a real parent invocation verifies the filter class, and the NAT class stays independently missing",
    );

    // Control D (collision): a parent that invokes a *longer* anchor name
    // must not verify the managed anchor.
    let collision_anchor = format!("{anchor}-collision");
    let collision_parent = format!("{anchor}-collision-parent");
    let collision_file = scratch.join("collision.conf");
    std::fs::write(
        &collision_file,
        format!("anchor \"{collision_anchor}\" all\n"),
    )
    .expect("collision file");
    let collision_arg = collision_file.to_string_lossy().into_owned();
    sh(
        &mut evidence,
        "pfctl",
        &["-a", &collision_parent, "-f", &collision_arg],
    );
    let collision_rules = sh(
        &mut evidence,
        "pfctl",
        &["-a", &collision_parent, "-s", "rules"],
    );
    let collision_observation = observe_attachments(&collision_rules, "", &anchor);
    assert_eq!(
        collision_observation.filter,
        Attachment::Missing,
        "a name that merely contains the managed name is not an invocation"
    );
    assert!(
        !attachment_verified(
            &collision_rules,
            "",
            &anchor,
            RequiredAttachments::FILTER_ONLY
        ),
        "a colliding name verifies nothing"
    );
    evidence.log("control D (collision): a longer anchor name does not verify the managed anchor");

    // The fixture must not have touched the main ruleset.
    let parent_filter_after = sh(&mut evidence, "pfctl", &["-s", "rules"]);
    assert_eq!(
        parent_filter_after, parent_filter,
        "the fixture must leave the main ruleset exactly as it found it"
    );

    sh(
        &mut evidence,
        "pfctl",
        &["-a", &collision_parent, "-F", "all"],
    );
    sh(&mut evidence, "pfctl", &["-a", &parent_anchor, "-F", "all"]);
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

/// Probes an echo target and reports whether it answered without any loss.
///
/// A public internet path drops the occasional ICMP echo, so a single probe
/// cannot decide whether a target is reachable: one lost reply would be
/// mistaken for an unreachable target, or — worse — for a fixture defect.
/// The probe is repeated within a small budget, and only a run with **no**
/// loss counts as an answer. The claim the fixture makes is therefore
/// unchanged — the target answered cleanly — it is just no longer decided by
/// a single sample of a lossy path.
fn echo_answers_cleanly(evidence: &mut Evidence, target: &str, attempts: usize) -> bool {
    for attempt in 1..=attempts {
        let (ok, out) = sh_unchecked(evidence, "ping", &["-c", "3", "-i", "0.2", target]);
        if ok && out.contains("0.0% packet loss") {
            evidence.log(&format!("{target} answered cleanly on attempt {attempt}"));
            return true;
        }
        evidence.log(&format!(
            "{target} did not answer cleanly on attempt {attempt}"
        ));
    }
    false
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
        if echo_answers_cleanly(&mut evidence, candidate, 3) {
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
    assert!(
        echo_answers_cleanly(&mut evidence, &target, 3),
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
    let observation = observe_attachments(&parent_filter, &parent_nat, &anchor);
    assert_eq!(
        observation.filter,
        Attachment::Missing,
        "fixture anchor must stay unattached in the filter class even while PF is enabled"
    );
    assert_eq!(
        observation.nat,
        Attachment::Missing,
        "fixture anchor must stay unattached in the NAT class even while PF is enabled"
    );
    assert!(
        !attachment_verified(
            &parent_filter,
            &parent_nat,
            &anchor,
            RequiredAttachments::FILTER_ONLY
        ),
        "fixture anchor must stay unattached even while PF is enabled"
    );
    assert!(
        !attachment_verified(
            &parent_filter,
            &parent_nat,
            &anchor,
            RequiredAttachments::FILTER_AND_NAT
        ),
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

    // A job left registered by an earlier test would make the bootstrap fail
    // with an opaque I/O error, so the label is cleared first. Foreign jobs
    // are never touched: only this deployment's own label is unloaded.
    let job = format!("system/{}", launchd::NETD_LABEL);
    let _ = Command::new("launchctl")
        .args(["bootout", "system", job.as_str()])
        .output();
    sh(
        &mut evidence,
        "launchctl",
        &["bootstrap", "system", system_plist.as_str()],
    );
    evidence.log("netd bootstrapped into the system domain (ephemeral host)");

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
    // `bootout` is asynchronous: launchd unloads the job and then asks the
    // daemon to stop. The socket is unlinked by the daemon itself as it drains,
    // so its disappearance is observed rather than assumed.
    wait_until(
        "netd socket removal after bootout",
        Duration::from_secs(30),
        || !socket.exists(),
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

/// C002 live: the management daemon really runs unprivileged.
///
/// The plist text is not the proof. This cycle preprovisiones a disposable
/// management account, installs the canonical layout, bootstraps both roles,
/// and then reads the **real** effective UID of each running daemon and the
/// real owner and mode of the privileged socket.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c002_management_daemon_runs_unprivileged() {
    let mut evidence = Evidence::new("c002-unprivileged-serve");
    let helper_path = require_live(&mut evidence);
    let binary = std::env::var("WGB_BINARY").expect("WGB_BINARY must be set");

    // A disposable management account. The installer never creates accounts;
    // the qualification supplies one, exactly as an operator would.
    let group = launchd::SERVE_GROUP;
    let user = launchd::SERVE_USER;
    provision_management_identity(&mut evidence);
    // The cleanup guard is armed before anything else can fail, so a failed
    // test still leaves the host clean for the next one.
    let _cleanup = DisposableDeployment {
        user: user.to_owned(),
        group: group.to_owned(),
    };

    let identity = resolve_management_identity(&mut evidence);

    // The product's own transactional installer runs here, not a hand-rolled
    // equivalent: the live evidence must describe the path an operator
    // actually takes.
    wg_basic::launchd_install::install(Path::new("/"), Path::new(&binary), Path::new(&helper_path))
        .expect("the installer must complete the deployment");
    evidence.log("the transactional installer completed the deployment");

    let netd_plist = format!("/Library/LaunchDaemons/{}.plist", launchd::NETD_LABEL);
    let serve_plist = format!("/Library/LaunchDaemons/{}.plist", launchd::SERVE_LABEL);
    let netd_job = format!("system/{}", launchd::NETD_LABEL);
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
    let running = |job: &str| {
        Command::new("launchctl")
            .args(["print", job])
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("state = running")
            })
    };
    wait_until("both roles running", Duration::from_secs(60), || {
        running(&netd_job) && running(&serve_job)
    });
    // The job description carries the reason a role is not running, so a
    // failure here explains itself instead of timing out silently.
    for job in [&netd_job, &serve_job] {
        let print = Command::new("launchctl")
            .args(["print", job])
            .output()
            .expect("launchctl print");
        let text = String::from_utf8_lossy(&print.stdout);
        let interesting: Vec<&str> = text
            .lines()
            .filter(|line| {
                line.contains("state = ")
                    || line.contains("last exit code")
                    || line.contains("path = ")
                    || line.contains("reason")
            })
            .collect();
        evidence.log(&format!("{job}: {}", interesting.join(" | ")));
    }

    let pid_of = |job: &str| -> u32 {
        let print = Command::new("launchctl")
            .args(["print", job])
            .output()
            .expect("launchctl print");
        String::from_utf8_lossy(&print.stdout)
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("pid = ")
                    .and_then(|pid| pid.parse().ok())
            })
            .unwrap_or_else(|| panic!("{job} must report a daemon pid"))
    };
    let netd_pid = pid_of(&netd_job);
    let serve_pid = pid_of(&serve_job);

    // The real effective UID and GID of the running process, not the plist
    // text: the plist only states what launchd was asked for. BSD `ps` reports
    // the effective identifiers under `uid`/`gid`; it has no `euid`/`egid`.
    let identity_of = |pid: u32| -> (u32, u32) {
        let output = Command::new("ps")
            .args(["-o", "uid=,gid=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        let text = String::from_utf8_lossy(&output.stdout);
        let mut fields = text.split_whitespace();
        let uid = fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("ps must report the effective uid of {pid}"));
        let gid = fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("ps must report the effective gid of {pid}"));
        (uid, gid)
    };
    let (netd_euid, netd_egid) = identity_of(netd_pid);
    let (serve_euid, serve_egid) = identity_of(serve_pid);
    evidence.log(&format!(
        "netd pid={netd_pid} euid={netd_euid} egid={netd_egid}; \
         serve pid={serve_pid} euid={serve_euid} egid={serve_egid}"
    ));
    assert_eq!(netd_euid, 0, "the privileged daemon must run as root");
    assert_eq!(
        serve_euid, identity.uid,
        "the management daemon must run as the dedicated unprivileged account"
    );
    assert_ne!(
        serve_euid, 0,
        "the management daemon must never run as root"
    );

    // The privileged socket is the whole path to the privileged daemon: it
    // must be owned by root and the management group, and nobody else.
    let socket = Path::new(launchd::SOCKET_PATH);
    wait_until("netd socket", Duration::from_secs(30), || socket.exists());
    let stat = sh(
        &mut evidence,
        "stat",
        &["-f", "%Su %Sg %u %g %Lp", socket.to_string_lossy().as_ref()],
    );
    let mut fields = stat.split_whitespace();
    let owner = fields.next().unwrap_or_default().to_owned();
    let socket_group = fields.next().unwrap_or_default().to_owned();
    let owner_uid = fields.next().unwrap_or_default().to_owned();
    let socket_gid = fields.next().unwrap_or_default().to_owned();
    let mode = fields.next().unwrap_or_default().to_owned();
    evidence.log(&format!(
        "socket owner={owner}({owner_uid}) group={socket_group}({socket_gid}) mode={mode}"
    ));
    assert_eq!(owner, "root", "the privileged socket must be root-owned");
    assert_eq!(
        socket_group, group,
        "the privileged socket must be reachable by the management group only"
    );
    assert_eq!(
        socket_gid,
        identity.gid.to_string(),
        "the privileged socket's group must be the management group"
    );
    assert_eq!(
        mode, "660",
        "the privileged socket must not be reachable by other identities"
    );

    // The receipt the management daemon reads for the helper digest and its
    // own identity has to be readable by the management identity.
    let receipt = Path::new(launchd::STATE_DIR).join(launchd::RECEIPT_NAME);
    let receipt_metadata = std::fs::symlink_metadata(&receipt).expect("the install receipt");
    let receipt_uid = {
        use std::os::unix::fs::MetadataExt as _;
        receipt_metadata.uid()
    };
    evidence.log(&format!(
        "install receipt uid={receipt_uid} (management uid={})",
        identity.uid
    ));
    assert_eq!(
        receipt_uid, identity.uid,
        "the management daemon must own the receipt it reads"
    );

    // Teardown: the product's own uninstall stops both roles and preserves the
    // state, then the disposable account is removed. The drop guard repeats the
    // cleanup so a failed assertion cannot leave a job registered.
    wg_basic::launchd_install::uninstall(Path::new("/")).expect("uninstall the deployment");
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
    remove_if_exists(Path::new(&netd_plist));
    remove_if_exists(Path::new(&serve_plist));
    remove_if_exists(Path::new(launchd::BINARY_PATH));
    remove_if_exists(Path::new(launchd::HELPER_PATH));
    std::fs::remove_dir_all(Path::new(launchd::RUNTIME_DIR)).ok();
    std::fs::remove_dir_all(Path::new(launchd::STATE_DIR)).ok();
    std::fs::remove_dir_all("/var/log/wg-basic").ok();
    std::fs::remove_dir_all("/usr/local/libexec/wg-basic").ok();
    // The identity is disposable and may already be gone: a host that is
    // reused across qualification runs has no record left to delete.
    for record in [format!("/Users/{user}"), format!("/Groups/{group}")] {
        let _ = Command::new("dscl")
            .args([".", "-delete", &record])
            .output();
    }
    evidence.log("teardown complete: roles stopped, account removed");
    evidence.write();
}

/// C001 live: the Darwin backend converges a product-shaped desired state.
///
/// The product builds this shape: one managed interface with a private key, a
/// listen port, host addresses, and the tunnel-pool route. The portable
/// planner and the Darwin backend have to converge it on a live host — the
/// backend fixture above proves the ownership contract in isolation, and this
/// one proves the planner and the backend agree on a real convergence.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c001_darwin_backend_converges_a_product_shaped_desired_state() {
    use wg_basic::domain::OwnerTag;
    use wg_basic::reconcile::{
        DesiredAddress, DesiredWireGuardConfiguration, LinkLifecycle, ManagedRoute,
        OwnershipDeclaration, ResourcePresence,
    };

    let mut evidence = Evidence::new("c001-darwin-backend-convergence");
    let helper_path = require_live(&mut evidence);
    let binary = std::env::var("WGB_BINARY").expect("WGB_BINARY must be set");

    // The production backend reads the pinned helper from the install
    // receipt, so the deployment has to exist before it may act.
    provision_management_identity(&mut evidence);
    let _cleanup = DisposableDeployment {
        user: launchd::SERVE_USER.to_owned(),
        group: launchd::SERVE_GROUP.to_owned(),
    };
    resolve_management_identity(&mut evidence);
    wg_basic::launchd_install::install(Path::new("/"), Path::new(&binary), Path::new(&helper_path))
        .expect("the transactional installer must complete the deployment");

    let keys = generate_keypair().expect("a keypair");
    let interface = InterfaceName::new("wgc001b").expect("an interface name");
    let desired = DesiredManagedInterface {
        interface: interface.clone(),
        ownership: OwnershipDeclaration::Managed,
        lifecycle: LinkLifecycle::Present,
        admin_up: Some(true),
        owner_tag: OwnerTag::new(InstallationId::new(), InterfaceId::new()),
        wireguard: Some(DesiredWireGuardConfiguration {
            private_key: keys.private_key,
            listen_port: LISTEN_PORT,
            peers: Vec::new(),
            manage_all_peers: true,
        }),
        addresses: vec![
            DesiredAddress {
                address: "10.78.0.1/32".parse().expect("an address"),
                presence: ResourcePresence::Present,
            },
            DesiredAddress {
                address: "2001:db8:78::1/128".parse().expect("an address"),
                presence: ResourcePresence::Present,
            },
        ],
        routes: vec![ManagedRoute {
            destination: "2001:db8:78::/64".parse().expect("a destination"),
            gateway: None,
            presence: ResourcePresence::Present,
        }],
    };

    let service = wg_basic::reconcile::ReconciliationService::default();
    let receipt = match service.apply(&desired) {
        Ok(receipt) => receipt,
        Err(error) => {
            evidence.log(&format!("the Darwin backend refused: {error}"));
            panic!("the Darwin backend must converge a product-shaped state: {error}");
        }
    };
    if receipt.status != wg_basic::reconcile::ApplyStatus::Applied
        && receipt.status != wg_basic::reconcile::ApplyStatus::NoChange
    {
        // The kernel's own answer, so a refusal says which syscall refused
        // and why.
        if let Some(observed) = receipt.observed_after.as_ref() {
            for candidate in wg_basic_darwin_sys::interfaces().unwrap_or_default() {
                if observed.ifindex != Some(candidate.index) {
                    continue;
                }
                evidence.log(&format!(
                    "the managed device is {} (index {}, flags {:#x})",
                    candidate.name, candidate.index, candidate.flags
                ));
                // The route the convergence wanted, added directly, so the
                // kernel's own answer says why it refused.
                let v6_route: ipnet::IpNet = "2001:db8:78::/64".parse().expect("a route");
                match wg_basic_darwin_sys::add_route(v6_route, None, &candidate.name) {
                    Ok(()) => evidence.log("a direct IPv6 route addition succeeded"),
                    Err(error) => {
                        evidence.log(&format!("a direct IPv6 route addition failed: {error:?}"))
                    }
                }
                let v4_route: ipnet::IpNet = "10.78.0.0/24".parse().expect("a route");
                match wg_basic_darwin_sys::add_route(v4_route, None, &candidate.name) {
                    Ok(()) => evidence.log("a direct IPv4 route addition succeeded"),
                    Err(error) => {
                        evidence.log(&format!("a direct IPv4 route addition failed: {error:?}"))
                    }
                }
                // The routes the dump reports, once they exist.
                let observed = wg_basic_darwin_sys::routes().unwrap_or_default();
                evidence.log(&format!("the dump reports {} route(s)", observed.len()));
                for route in observed
                    .iter()
                    .filter(|route| route.interface_index == candidate.index)
                {
                    evidence.log(&format!(
                        "observed route: {}/{} via {:?} dev {}",
                        route.destination,
                        route.destination.prefix_len(),
                        route.gateway,
                        route.interface_name
                    ));
                }
            }
        }
    }
    evidence.log(&format!(
        "the Darwin backend converged: status={:?} planned={:?} completed={} failed={:?}",
        receipt.status, receipt.planned_actions, receipt.completed_actions, receipt.failed_action
    ));
    assert!(
        receipt.status == wg_basic::reconcile::ApplyStatus::Applied
            || receipt.status == wg_basic::reconcile::ApplyStatus::NoChange,
        "the convergence must verify: {receipt:?}"
    );
    let observed = receipt
        .observed_after
        .expect("the convergence must observe the managed device");
    assert_eq!(observed.interface, interface);
    evidence.log(&format!(
        "the managed device is observed with {} address(es) and {} route(s)",
        observed.addresses.len(),
        observed.routes.len()
    ));
    assert!(
        observed
            .addresses
            .iter()
            .any(|address| *address == "10.78.0.1/32".parse().unwrap()),
        "the server address must be on the managed device: {observed:?}"
    );
    evidence.write();
}

/// C006 limitation probe: does a launchd job that removes its own plist and
/// then boots itself out leave a registration behind?
///
/// The controlled cold-reboot fixture removes its own plist and spawns a
/// detached `launchctl bootout`, and the registration was observed to linger.
/// This probe runs the same two mechanics on a disposable runner — the
/// fixture's form, and a form where the detached child waits for the job to
/// be gone before it boots out — and records what each one leaves behind.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_self_removing_job_leaves_no_registration() {
    let mut evidence = Evidence::new("m006-self-removal-probe");
    require_live(&mut evidence);
    let scratch = std::env::temp_dir().join(format!("wgb-bootout-probe-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch dir");

    for variant in ["a", "b"] {
        let label = format!("com.wg-basic.probe-{variant}");
        let plist = format!("/Library/LaunchDaemons/{label}.plist");
        let marker = scratch.join(format!("{variant}.marker"));
        let outcome = scratch.join(format!("{variant}.outcome"));
        let marker_path = marker.display().to_string();
        let outcome_path = outcome.display().to_string();
        // Variant A is the controlled fixture's form: the job removes its
        // plist and spawns the detached bootout immediately. Variant B waits
        // for the job to be gone before booting out.
        let body = if variant == "a" {
            format!(
                "rm -f '{plist}'; touch '{marker_path}'; \
                 /usr/bin/python3 -c 'import os;os.setpgrp();os.execv(\"/bin/launchctl\",\
                 [\"launchctl\",\"bootout\",\"system\",\"system/{label}\"])' </dev/null >/dev/null 2>&1 &"
            )
        } else {
            format!(
                "rm -f '{plist}'; touch '{marker_path}'; \
                 /usr/bin/python3 -c 'import os,time;os.setpgrp();time.sleep(3);\
                 rc=os.spawnv(os.P_WAIT,\"/bin/launchctl\",\
                 [\"launchctl\",\"bootout\",\"system\",\"system/{label}\"]);\
                 open(\"{outcome_path}\",\"w\").write(\"bootout exit %d\\n\"%rc)' </dev/null >/dev/null 2>&1 &"
            )
        };
        let document = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
             <plist version=\"1.0\"><dict>\
             <key>Label</key><string>{label}</string>\
             <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>\
             <string>{body}</string></array>\
             <key>RunAtLoad</key><true/>\
             <key>StandardOutPath</key><string>{}</string>\
             <key>StandardErrorPath</key><string>{}</string>\
             </dict></plist>",
            scratch.join(format!("{variant}.out")).display(),
            scratch.join(format!("{variant}.err")).display()
        );
        std::fs::write(&plist, document).expect("write probe plist");
        let (bootstrapped, output) =
            sh_unchecked(&mut evidence, "launchctl", &["bootstrap", "system", &plist]);
        evidence.log(&format!(
            "variant {variant}: bootstrap {} -> {output}",
            if bootstrapped { "ok" } else { "failed" }
        ));

        wait_until(
            &format!("the variant {variant} probe job to run"),
            Duration::from_secs(30),
            || marker.exists(),
        );
        // Give the detached child time to run its bootout.
        std::thread::sleep(Duration::from_secs(8));
        let (registered, _) = sh_unchecked(
            &mut evidence,
            "launchctl",
            &["print", &format!("system/{label}")],
        );
        evidence.log(&format!(
            "variant {variant}: the service is {} after the job removed its own plist",
            if registered {
                "STILL REGISTERED"
            } else {
                "not registered"
            }
        ));
        if let Ok(text) = std::fs::read_to_string(&outcome) {
            evidence.log(&format!("variant {variant}: {text}"));
        }

        // Leave nothing behind, whatever the outcome was.
        sh_unchecked(
            &mut evidence,
            "launchctl",
            &["bootout", &format!("system/{label}")],
        );
        remove_if_exists(Path::new(&plist));
        let (left, _) = sh_unchecked(
            &mut evidence,
            "launchctl",
            &["print", &format!("system/{label}")],
        );
        assert!(
            !left,
            "variant {variant}: the probe label must not survive the test"
        );
    }
    evidence.log("the probe cleaned up every label it created");
    evidence.write();
}
