//! The C003 controlled-host qualification: a routed LAN on macOS.
//!
//! C003 proves that the managed tunnel can carry authorized client traffic to
//! an approved downstream LAN prefix, and that the product refuses to claim a
//! routed LAN it cannot prove.
//!
//! The leg runs on a disposable macOS host and needs three independent
//! pieces: the product's own installer and daemons, a second WireGuard
//! implementation (the Linux kernel module, never the helper the product
//! supervises), and a downstream LAN host that is reachable only through the
//! tunnel. The peer fixture supplies the last two and keeps them apart, so
//! the traffic cannot take a shortcut around the routing path under test.
//!
//! What it proves:
//! - a routed-LAN policy is refused until the host's forwarding, the
//!   operator-managed filter, and the routes are actually in place, and each
//!   missing prerequisite is named;
//! - once the operator installs the rules the product reported, the product
//!   converges and says so;
//! - real IPv4 and IPv6 packets traverse the tunnel, the host's forwarding
//!   path, and the approved downstream prefix, and come back through the
//!   same tunnel;
//! - a destination outside the approved prefix is not delivered, and a
//!   spoofed source is not delivered;
//! - removing the filter, drifting the filter, turning forwarding off, and
//!   adding a competing route each produce their own refusal;
//! - losing the route to an approved destination produces a refusal, and the
//!   operator's route restores it;
//! - killing the helper is recovered: the privileged authority replaces the
//!   helper it lost, the tunnel carries the policy again, on whichever device
//!   the kernel assigns, and the peer establishes a new session with the
//!   replacement and its traffic flows again.
//!
//! Private keys are generated fresh per run and never enter evidence output.

#![cfg(target_os = "macos")]

use std::any::Any;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use wg_basic::launchd;

mod darwin_live_common;
use darwin_live_common::*;

/// The approved downstream IPv4 prefix the routed LAN forwards to.
const LAN_PREFIX: &str = "10.20.20.0/24";
/// A competing route that covers part of the approved destination.
const COMPETING_PREFIX: &str = "10.20.20.0/25";
/// The downstream host inside that prefix.
const LAN_HOST: &str = "10.20.20.2";
/// The approved downstream IPv6 prefix.
const LAN_PREFIX6: &str = "2001:db8:20::/64";
/// The downstream host's IPv6 address.
const LAN_HOST6: &str = "2001:db8:20::2";
/// The wider IPv4 range the peer sends into the tunnel.
///
/// The peer is deliberately configured with a wider range than the server
/// approved, so an unapproved destination really does enter the tunnel and
/// the server's own filter is what has to reject it. A peer that only ever
/// sent the approved prefix would prove nothing about the filter.
const ATTEMPTED_PREFIX: &str = "10.20.0.0/16";
/// The wider IPv6 range the peer sends into the tunnel.
const ATTEMPTED_PREFIX6: &str = "2001:db8::/32";
/// The tunnel address the first enrolled client receives.
///
/// The server holds the first address of the pool, so the first client gets
/// the second one. The leg removes it from the loopback interface before it
/// starts: an alias carrying the pool's client address would answer the
/// return-path probe locally instead of through the tunnel, which would make
/// that probe pass for the wrong reason.
const CLIENT_TUNNEL_ADDRESS: &str = "10.77.0.2";

/// The window a peer needs to re-key after the server's helper is replaced.
///
/// A WireGuard session is not restored by recreating a helper: the
/// replacement helper holds no session, and a peer whose own session is
/// still valid keeps sending packets the replacement cannot decrypt. The
/// peer re-keys 120 s after its last handshake and rejects its session
/// 180 s after it, so the window below covers both with margin. A shorter
/// wait would fail on the protocol's own schedule and say nothing about
/// the recovery.
const PEER_REKEY_WINDOW: Duration = Duration::from_secs(210);

/// The shell listing of the management-service processes.
///
/// The listing is a shell pipeline rather than a bare `ps`, so the harness's
/// own pipeline does not match its own pattern.
const SERVE_PROCESS_LISTING: &str = "ps -o pid,ppid,stat,command -ax | grep '[w]g-basic serve'";

/// The host directory the packet-filter anchors live in.
///
/// macOS keeps its own anchors here, `com.apple/filter` among them, and the
/// leg's own anchor is one more file in the same directory. The restoration
/// touches the leg's file and nothing else in it.
const PF_ANCHORS_DIR: &str = "/etc/pf.anchors";

/// The host's own packet-filter configuration file.
///
/// The leg attaches its anchor by adding two lines here and the restoration
/// takes them out again. The file is the host's own: the leg never writes a
/// policy of its own into it.
const PF_CONF: &str = "/etc/pf.conf";

/// The process identifiers of the running management-service processes.
fn serve_process_ids() -> Vec<u32> {
    Command::new("sh")
        .args(["-c", SERVE_PROCESS_LISTING])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter_map(|field| field.parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether no management-service process is left running.
///
/// The process list is the direct evidence, and it is what the diagnosis
/// waits for: a process that is still draining holds the write-ahead log,
/// and the doctor's immutable inspection refuses a log that carries
/// transactions.
fn serve_process_is_gone() -> bool {
    Command::new("sh")
        .args(["-c", SERVE_PROCESS_LISTING])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().is_empty())
        .unwrap_or(true)
}

/// Whether the state directory's write-ahead log still carries transactions.
///
/// A writer fills the log; a database that was closed cleanly leaves it
/// empty. The doctor's immutable inspection can only read a database whose
/// log carries nothing, so the diagnosis waits for exactly that rather than
/// for launchd's opinion of the job's state.
fn state_log_is_empty() -> bool {
    let log = std::path::Path::new(launchd::STATE_DIR).join("state.db-wal");
    std::fs::metadata(&log)
        .map(|metadata| metadata.len() == 0)
        .unwrap_or(true)
}

/// Reads the routed-LAN verdict the product reports for the managed policy.
///
/// The verdict is what names the missing prerequisite, so the qualification
/// reads it rather than inferring the reason from a failure.
///
/// The doctor's state inspection is immutable by contract: it refuses to read
/// a database that still has live write-ahead sidecars, and the management
/// service is what holds them. The doctor's own remediation says to stop the
/// management service and rerun it, so the qualification does exactly that,
/// and it reconciles with the service stopped for the same reason: the
/// service holds the state lease.
fn diagnose(evidence: &mut Evidence, reconcile: bool) -> Verdict {
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
    // The state directory's contents are part of the evidence: the doctor's
    // immutable inspection refuses a database that still has write-ahead
    // sidecars.
    let state_listing = sh(evidence, "sudo", &["ls", "-la", launchd::STATE_DIR]);
    evidence.log(&format!(
        "the state directory before the stop:\n{state_listing}"
    ));
    // `launchctl stop` is not accepted for a bootstrapped system service, so
    // the job's process is asked to terminate.
    //
    // Disabling the job first does **not** keep launchd from restarting it:
    // the job carries `KeepAlive`, so launchd brings the daemon back when its
    // process exits, and a disabled job is registered but never starts. The
    // disable is therefore only part of the sequence, and the *unload* below
    // is what actually keeps the service down for the diagnosis.
    //
    // The term is sent first and its outcome is asserted against the process
    // that was running before it. A process that is still there afterwards is
    // either the same process that ignored the term, or a successor that
    // launchd started because the term worked: only the identifier tells the
    // two apart, and reading "a process is running" as "the service did not
    // stop" is exactly the misreading this assertion exists to prevent.
    let before = serve_process_ids();
    evidence.log(&format!("the serve processes before the term: {before:?}"));
    sh(evidence, "launchctl", &["disable", &serve_job]);
    sh(evidence, "launchctl", &["kill", "SIGTERM", &serve_job]);
    // The service has to actually be gone. Launchd's job state is not a
    // proof: the job can be marked stopped while a process is still
    // draining, and a draining process still holds the write-ahead log,
    // which is what the doctor's immutable inspection refuses.
    // The service has to be really gone for the offline diagnosis: a live
    // management service holds the write-ahead log, and the doctor's
    // immutable inspection refuses a log that carries transactions.
    //
    // `launchctl disable` on its own is not enough. The job carries
    // `KeepAlive`, so launchd brings the daemon back when its process
    // exits, and a restart that was already scheduled still runs after the
    // job is disabled. The job is therefore *unloaded*, which is the same
    // operation the product's own uninstall performs, and it is registered
    // again once the diagnosis is done.
    sh_unchecked(evidence, "launchctl", &["kill", "SIGTERM", &serve_job]);
    let mut honoured = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(1));
        let after = serve_process_ids();
        if !after.iter().any(|pid| before.contains(pid)) {
            honoured = true;
            evidence.log(&format!(
                "the term was honoured: the process {before:?} is gone, {after:?} remain"
            ));
            break;
        }
    }
    assert!(
        honoured,
        "the management service did not act on SIGTERM within 30s: {before:?} is still running"
    );
    let processes = sh_unchecked(evidence, "sh", &["-c", SERVE_PROCESS_LISTING]);
    evidence.log(&format!(
        "the serve processes after the term:\n{}",
        processes.1
    ));
    let holders = sh_unchecked(
        evidence,
        "sh",
        &[
            "-c",
            &format!("lsof {}/state.db.serve.lock 2>&1", launchd::STATE_DIR),
        ],
    );
    evidence.log(&format!("the state lease holders:\n{}", holders.1));
    // The job is unloaded with the process killed outright: the process did
    // not act on the term, and the unload is what stops launchd from
    // bringing it back. The job is *not* disabled: a disabled job is
    // registered but never starts, which is the wrong shape for a service
    // that has to come back afterwards.
    sh_unchecked(evidence, "launchctl", &["kill", "SIGKILL", &serve_job]);
    sh_unchecked(evidence, "launchctl", &["bootout", &serve_job]);
    wait_until(
        "the management service stopped",
        Duration::from_secs(30),
        serve_process_is_gone,
    );
    // The management service's exit leaves the write-ahead sidecars behind,
    // and the doctor's immutable inspection refuses them. The operator closes
    // the database cleanly before diagnosing it offline, which is what the
    // state status command does when it opens and closes the store.
    let status = Command::new("sudo")
        .args([
            "-u",
            launchd::SERVE_USER,
            launchd::BINARY_PATH,
            "state",
            "status",
            "--state",
            launchd::STATE_PATH,
        ])
        .output()
        .expect("the state status must run");
    evidence.log(&format!(
        "the state status after the stop: {}{}",
        String::from_utf8_lossy(&status.stdout).trim(),
        String::from_utf8_lossy(&status.stderr).trim()
    ));
    // The write-ahead log only empties when the last writer closes the
    // database, and the doctor's immutable inspection needs exactly that. The
    // state status command above is what closes it.
    wait_until(
        "the state write-ahead log drained",
        Duration::from_secs(60),
        state_log_is_empty,
    );
    let state_listing = sh(evidence, "sudo", &["ls", "-la", launchd::STATE_DIR]);
    evidence.log(&format!(
        "the state directory after the stop:\n{state_listing}"
    ));

    let mut converged = false;
    let mut reconcile_failure = None;
    if reconcile {
        let outcome = Command::new("sudo")
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
            .output()
            .expect("the reconcile must run");
        let text = String::from_utf8_lossy(&outcome.stdout).trim().to_owned();
        let errors = String::from_utf8_lossy(&outcome.stderr).trim().to_owned();
        evidence.log(&format!("reconcile: {text}"));
        evidence.log(&format!("reconcile diagnostics: {errors}"));
        // The reconcile's own exit status is asserted by the caller, not here:
        // the verdict below names the prerequisite that made it degrade, and
        // that naming is the evidence a failing run has to carry.
        converged = text.contains("converged");
        if !outcome.status.success() {
            reconcile_failure = Some(errors);
        }
    }

    let mut verdict: Option<Verdict> = None;
    // The doctor's own state inspection is immutable by contract, so it
    // refuses while the service still holds the write-ahead log. The service
    // is asked to stop first, and launchd's own job state is not a reliable
    // proof that it did: the job can be marked stopped while the process is
    // still draining. The product's state lease is the authoritative signal,
    // and the doctor reports it, so the diagnosis waits for the lease to be
    // free before it believes a refusal.
    for _ in 0..60 {
        let output = Command::new("sudo")
            .args([
                "-u",
                launchd::SERVE_USER,
                launchd::BINARY_PATH,
                "doctor",
                "--json",
                "--state",
                launchd::STATE_PATH,
                "--socket",
                launchd::SOCKET_PATH,
            ])
            .output()
            .expect("the doctor must run");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        evidence.log(&format!("doctor: {stdout}{stderr}"));
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
            if let Some(check) = parsed["checks"]
                .as_array()
                .and_then(|checks| checks.iter().find(|check| check["id"] == "routed_lan"))
            {
                verdict = Some(Verdict {
                    summary: check["summary"].as_str().unwrap_or_default().to_owned(),
                    evidence: check["evidence"].as_str().unwrap_or_default().to_owned(),
                    rules: check["required_filter_rules"]
                        .as_array()
                        .map(|rules| {
                            rules
                                .iter()
                                .filter_map(|rule| rule.as_str().map(|rule| rule.to_owned()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    converged,
                    reconcile_failure,
                });
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    // The job was unloaded for the offline diagnosis, so it is registered
    // again before the leg carries on.
    sh(evidence, "launchctl", &["enable", &serve_job]);
    let registered = sh(
        evidence,
        "launchctl",
        &[
            "bootstrap",
            "system",
            &format!("/Library/LaunchDaemons/{}.plist", launchd::SERVE_LABEL),
        ],
    );
    evidence.log(&format!(
        "the management service was registered again: {registered}"
    ));
    if !wait_until_or_false(
        "the management service running",
        Duration::from_secs(60),
        || launchd_running(&serve_job),
    ) {
        let job = sh_unchecked(evidence, "launchctl", &["print", &serve_job]);
        evidence.log(&format!("the job state after the registration:\n{}", job.1));
        let serve_log = sh_unchecked(
            evidence,
            "sudo",
            &[
                "sh",
                "-c",
                &format!("tail -n 40 {} 2>&1", launchd::SERVE_LOG),
            ],
        );
        evidence.log(&format!("the serve log:\n{}", serve_log.1));
    }
    wait_until(
        "the management service running",
        Duration::from_secs(60),
        || launchd_running(&serve_job),
    );

    if verdict.is_none() {
        // The doctor never reported the routed-LAN verdict, so the run has to
        // say why. The service's own state, the holder of the state lease,
        // the product's processes, and its logs are the evidence a failing
        // run has to carry.
        let listing = sh_unchecked(evidence, "sudo", &["ls", "-la", launchd::STATE_DIR]);
        evidence.log(&format!(
            "the state directory at the failure:\n{}",
            listing.1
        ));
        let processes = sh_unchecked(
            evidence,
            "sh",
            &[
                "-c",
                "ps -o pid,ppid,stat,wchan,command -ax | grep -E 'wg-basic|wireguard-go' | grep -v grep",
            ],
        );
        evidence.log(&format!("the product's processes:\n{}", processes.1));
        // The holder of the state lease is the process that keeps the
        // write-ahead log alive, so it names the cause of the refusal.
        let holders = sh_unchecked(
            evidence,
            "sh",
            &[
                "-c",
                &format!("lsof {}/state.db.serve.lock 2>&1", launchd::STATE_DIR),
            ],
        );
        evidence.log(&format!("the state lease holders:\n{}", holders.1));
        for log in [launchd::SERVE_LOG, launchd::NETD_LOG] {
            let contents = sh_unchecked(
                evidence,
                "sudo",
                &["sh", "-c", &format!("tail -n 60 {log} 2>&1")],
            );
            evidence.log(&format!("the tail of {log}:\n{}", contents.1));
        }
    }

    verdict.expect("the doctor reports the routed-LAN verdict")
}

/// The installation's own packet-filter anchor name.
///
/// The anchor is installation-scoped, so it is this installation's and nothing
/// else on the host.
fn anchor_name(evidence: &mut Evidence) -> String {
    let status = sh(
        evidence,
        "sudo",
        &[
            "-u",
            launchd::SERVE_USER,
            launchd::BINARY_PATH,
            "state",
            "status",
            "--state",
            launchd::STATE_PATH,
        ],
    );
    let installation = status
        .lines()
        .find_map(|line| line.trim().strip_prefix("installation id:"))
        .expect("the state reports the installation id")
        .trim()
        .to_owned();
    evidence.log(&format!("the installation id is {installation}"));
    format!("{}-{installation}", wg_basic::firewall::ANCHOR_PREFIX)
}

/// What the doctor reports about the routed LAN.
struct Verdict {
    /// The verdict's own summary.
    summary: String,
    /// The verdict's evidence.
    evidence: String,
    /// The exact rules the operator has to install.
    rules: Vec<String>,
    /// Whether the reconcile converged.
    converged: bool,
    /// Why the reconcile failed, when it did.
    reconcile_failure: Option<String>,
}

/// The upstream router's addresses as this host reaches them.
///
/// The upstream router is the host that sits between this machine and the
/// downstream LAN, and the routes it holds back to the tunnel pool are the
/// return path this machine cannot see for itself.
fn upstream_gateways(evidence: &mut Evidence) -> (String, String) {
    let ipv4 = sh(evidence, "route", &["-n", "get", "default"]);
    let ipv4_gateway = ipv4
        .lines()
        .find_map(|line| line.trim().strip_prefix("gateway: "))
        .map(|value| value.trim().to_owned())
        .expect("the default route names an IPv4 gateway");
    let ipv6_routes = sh(evidence, "netstat", &["-rn", "-f", "inet6"]);
    let ipv6_gateway = ipv6_routes
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("default") {
                return None;
            }
            fields.next().map(|value| value.to_owned())
        })
        .expect("the default route names an IPv6 gateway");
    evidence.log(&format!(
        "the upstream router is {ipv4_gateway} (IPv4) and {ipv6_gateway} (IPv6)"
    ));
    (ipv4_gateway, ipv6_gateway)
}

/// Puts the host's shared state back into the pre-test shape.
///
/// The forwarding sysctls, the approved-prefix routes and the loopback alias
/// that can carry the pool's client address are host state, not product
/// state. A run that stopped between them leaves them behind, and a
/// qualification that only ever runs on a pristine host is not a
/// qualification: the leg restores them itself before it starts, and the
/// inventory it captures is the inventory of that restored state.
fn reset_host_preconditions(evidence: &mut Evidence) {
    // The helper has to bind the listen port. A foreign process that already
    // holds it makes the helper's own configuration fail, and the product's
    // refusal then names the helper rather than the port, so the leg checks
    // the port itself before it starts.
    let (held, holders) = sh_unchecked(
        evidence,
        "sudo",
        &["lsof", "-nP", &format!("-iUDP:{LISTEN_PORT}")],
    );
    assert!(
        !held || holders.trim().is_empty(),
        "the listen port must be free before the qualification runs: {holders}"
    );
    // A diagnosis disables the management job so it stays down while the
    // database is inspected. A run that stopped before it re-enabled the job
    // leaves the job disabled, and the installer cannot bootstrap a disabled
    // job, so the leg re-enables it first.
    sh_unchecked(
        evidence,
        "launchctl",
        &["enable", &format!("system/{}", launchd::SERVE_LABEL)],
    );
    // The forwarding sysctls are shared with everything else that routes on
    // this host, so the product only ever reads them. The leg restores them
    // to the disabled state its first assertion expects.
    sh_unchecked(evidence, "sysctl", &["-w", "net.inet.ip.forwarding=0"]);
    sh_unchecked(evidence, "sysctl", &["-w", "net.inet6.ip6.forwarding=0"]);
    // The approved-prefix routes are the operator's to install, so the leg
    // removes any an earlier run left behind. A competing route is removed
    // as well: a run that stopped before it took its own competing route
    // away would otherwise leave the host reporting a route conflict that
    // the operator never installed.
    sh_unchecked(evidence, "route", &["-n", "delete", "-net", LAN_PREFIX]);
    sh_unchecked(
        evidence,
        "route",
        &[
            "-n",
            "delete",
            "-net",
            COMPETING_PREFIX,
            "-interface",
            "lo0",
        ],
    );
    sh_unchecked(
        evidence,
        "route",
        &["-n", "delete", "-inet6", "-net", LAN_PREFIX6],
    );
    // A loopback alias carrying the pool's client address would answer the
    // return-path probe on this host instead of through the tunnel.
    sh_unchecked(
        evidence,
        "ifconfig",
        &["lo0", "-alias", CLIENT_TUNNEL_ADDRESS],
    );
}

/// The managed tunnel device the product's own reported rules name.
///
/// The rules are the product's own statement about which device carries the
/// managed tunnel, so the qualification reads the device from them rather
/// than guessing it from the host's `utun` inventory.
fn managed_device(rules: &[String]) -> Option<String> {
    let first = rules.first()?;
    let tokens: Vec<&str> = first.split_whitespace().collect();
    let position = tokens.iter().position(|token| *token == "on")?;
    tokens.get(position + 1).map(|name| (*name).to_owned())
}

/// Installs the operator-managed filter exactly as the product reported it.
///
/// This is the administrator's action under TN3165: the product never writes
/// PF state, so the anchor content and its attachment are the operator's.
fn install_operator_filter(evidence: &mut Evidence, anchor: &str, rules: &[String]) -> String {
    let path = anchor_file_path(anchor);
    sh(evidence, "sudo", &["mkdir", "-p", "/etc/pf.anchors"]);
    let mut tee = Command::new("sudo")
        .args(["tee", path.as_str()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("install the filter rules");
    {
        use std::io::Write as _;
        // The anchor file has to end with a newline: PF's parser rejects a
        // file whose last rule is not terminated, and it reports that as a
        // syntax error in the `load anchor` line that pulled the file in.
        tee.stdin
            .as_mut()
            .expect("the rules pipe")
            .write_all(format!("{}\n", rules.join("\n")).as_bytes())
            .expect("write the rules");
    }
    let _ = tee.wait_with_output();
    sh(evidence, "sudo", &["chmod", "644", &path]);
    sh(
        evidence,
        "sudo",
        &[
            "sh",
            "-c",
            &format!(
                "printf '%s\\n' 'anchor \"{anchor}\"' 'load anchor \"{anchor}\" from \"{path}\"' >> /etc/pf.conf"
            ),
        ],
    );
    sh(evidence, "sudo", &["pfctl", "-f", "/etc/pf.conf"]);
    // `pfctl -e` exits non-zero when PF is already enabled, which is the
    // normal state of a host that was already filtering. The qualification
    // wants PF enabled either way.
    let (enabled, output) = sh_unchecked(evidence, "sudo", &["pfctl", "-e"]);
    evidence.log(&format!(
        "the packet filter enable reported: {output} (ok: {enabled})"
    ));
    let ruleset = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    evidence.log(&format!("the packet filter ruleset now:\n{ruleset}"));
    path
}

/// The file the managed anchor's rules live in.
///
/// The anchor is named after the installation, and this is the one file the
/// leg writes for it and the one the restoration removes.
fn anchor_file_path(anchor: &str) -> String {
    format!("{PF_ANCHORS_DIR}/{anchor}")
}

/// What one anchor of the host's packet filter holds.
///
/// macOS keeps an anchor's rules loaded even after the main ruleset stops
/// referring to it, so an anchor's own rulesets are read separately from the
/// main ruleset. A rule that names a `utun` device is the hazard this
/// inventory exists to catch: macOS recycles `utun` indices, so rules left
/// behind can match a later tunnel's device.
struct AnchorInventory {
    /// The anchor's name.
    name: String,
    /// The anchor's loaded filter rules.
    filter_rules: String,
    /// The anchor's loaded NAT rules.
    nat_rules: String,
}

/// What the host's packet filter holds, captured as a whole.
///
/// The inventory is what the leg's restoration is measured against. The claim
/// that the leg left the host's filter as it found it has to be checked
/// against a measurement of the host's filter, because an unchecked claim is
/// what made the residue invisible in the first place.
struct FilterInventory {
    /// Whether the packet filter is enabled.
    pf_enabled: bool,
    /// The main filter ruleset.
    parent_filter: String,
    /// The main NAT ruleset.
    parent_nat: String,
    /// The anchors the inventory read.
    anchors: Vec<AnchorInventory>,
    /// The files in the host's anchors directory.
    anchor_files: Vec<String>,
}

/// What the leg needs to put the host's packet filter back.
///
/// The context is recorded before the leg installs its filter, so a leg that
/// fails between the install and the end is restored as well.
struct FilterContext {
    /// The anchor the leg created.
    anchor: String,
    /// The anchor's file.
    anchor_path: String,
    /// The host's filter state before the leg installed anything.
    baseline: FilterInventory,
}

/// Reads one anchor's own loaded rulesets.
///
/// An anchor that was never loaded cannot be read, and PF reports that as a
/// failure rather than as an empty ruleset. The failure is logged and the
/// anchor is recorded as holding nothing, because an anchor that does not
/// exist holds no rules.
fn anchor_inventory(evidence: &mut Evidence, name: &str) -> AnchorInventory {
    let (filter_readable, filter_rules) =
        sh_unchecked(evidence, "sudo", &["pfctl", "-a", name, "-s", "rules"]);
    let (nat_readable, nat_rules) =
        sh_unchecked(evidence, "sudo", &["pfctl", "-a", name, "-s", "nat"]);
    if !filter_readable || !nat_readable {
        evidence.log(&format!(
            "the anchor {name} could not be read in full (its filter rules were readable: {filter_readable}, its NAT rules were readable: {nat_readable}); it is recorded as holding no rules"
        ));
    }
    AnchorInventory {
        name: name.to_owned(),
        filter_rules,
        nat_rules,
    }
}

/// The anchors the host's main ruleset refers to.
///
/// The listing is the host's own view of its anchors. The managed anchor is
/// read whether or not it appears here, because an anchor whose rules are
/// still loaded no longer has to be referred to by the main ruleset.
fn pfctl_anchors(evidence: &mut Evidence) -> Vec<String> {
    let (readable, listing) = sh_unchecked(evidence, "/sbin/pfctl", &["-s", "Anchors"]);
    if !readable {
        evidence.log("the host's anchor listing could not be read");
        return Vec::new();
    }
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The files in the host's anchors directory.
///
/// The listing is what the residue is looked for in: the leg's own anchor
/// file and the drift control's `.drift` sibling are files in here, and a
/// file that is left behind is residue.
fn anchor_directory_listing(evidence: &mut Evidence) -> Vec<String> {
    let (readable, listing) = sh_unchecked(evidence, "ls", &["-1", PF_ANCHORS_DIR]);
    if !readable {
        evidence.log("the host's anchors directory could not be listed");
        return Vec::new();
    }
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|name| format!("{PF_ANCHORS_DIR}/{name}"))
        .collect()
}

/// Captures what the host's packet filter holds.
///
/// The capture is read-only. It is taken before the leg installs anything, so
/// the baseline is the host's own state and not the leg's, and it is taken
/// again after the teardown, so the two can be compared.
fn capture_filter_inventory(evidence: &mut Evidence, anchor: &str) -> FilterInventory {
    let status = sh(evidence, "/sbin/pfctl", &["-s", "info"]);
    let pf_enabled = status
        .lines()
        .any(|line| line.trim_start().starts_with("Status: Enabled"));
    let parent_filter = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    let parent_nat = sh_unchecked(evidence, "/sbin/pfctl", &["-s", "nat"]).1;
    let mut anchors = vec![anchor_inventory(evidence, anchor)];
    for name in pfctl_anchors(evidence) {
        if !anchors.iter().any(|candidate| candidate.name == name) {
            anchors.push(anchor_inventory(evidence, &name));
        }
    }
    let anchor_files = anchor_directory_listing(evidence);
    let inventory = FilterInventory {
        pf_enabled,
        parent_filter,
        parent_nat,
        anchors,
        anchor_files,
    };
    evidence.log(&format!(
        "the packet filter inventory:\n{}",
        describe_inventory(&inventory)
    ));
    inventory
}

/// The inventory as the evidence file carries it.
fn describe_inventory(inventory: &FilterInventory) -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "the packet filter is {}\n",
        if inventory.pf_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    text.push_str(&format!(
        "the main filter ruleset:\n{}",
        inventory.parent_filter
    ));
    text.push_str(&format!("the main NAT ruleset:\n{}", inventory.parent_nat));
    for anchor in &inventory.anchors {
        text.push_str(&format!(
            "the anchor {} holds these filter rules:\n{}",
            anchor.name, anchor.filter_rules
        ));
        text.push_str(&format!(
            "the anchor {} holds these NAT rules:\n{}",
            anchor.name, anchor.nat_rules
        ));
    }
    text.push_str(&format!(
        "the anchors directory holds: {:?}\n",
        inventory.anchor_files
    ));
    text
}

/// The commands that put the host's packet filter back the way the leg found
/// it.
///
/// The list is the teardown's exact argv, so it can be asserted on without a
/// host and so the teardown cannot drift away from what the qualification
/// claims it does.
///
/// The order is the order the operations depend on:
///
/// 1. The anchor's own rules are flushed first, and in two steps. macOS
///    keeps a loaded anchor's rules across `pfctl -f` and across a bare
///    `pfctl -F all`: reloading the main ruleset without the anchor's
///    `load anchor` line removes the *reference*, not the anchor's ruleset.
///    Emptying an anchor takes one flush per class, `pfctl -a <anchor> -F
///    rules` for the filter rules and `pfctl -a <anchor> -F nat` for the NAT
///    rules. A bare `pfctl -F all` flushes the **main** ruleset, which the
///    leg does not own and never flushes.
/// 2. The anchor's lines come out of the host's own configuration and the
///    main ruleset is reloaded, so the reload no longer pulls the anchor's
///    file in.
/// 3. The anchor's file and its `.drift` sibling are removed. They come last
///    because `pfctl` reads an anchor's file when it flushes it.
/// 4. The filter's enable state is put back last. The leg enables the filter
///    to make the operator's rules effective, and the host's own state is
///    what is restored: a host that was filtering keeps filtering, and a
///    host that was not filtering stops filtering. `pfctl -d` is emitted
///    only when the baseline had the filter disabled. `pfctl -e` is emitted
///    when the baseline had it enabled, because the leg's own `pfctl -e` is
///    what made it enabled and the teardown cannot tell whether the reload
///    or anything else turned it off again; the verb changes nothing when
///    the filter is already enabled — it exits non-zero and says so — so the
///    teardown runs it unchecked and the measured residue check is what
///    proves the final state. It comes after the reload because a reload
///    that enabled the filter must not be able to undo the restoration.
fn restoration_commands(anchor: &str, anchor_path: &str, pf_was_enabled: bool) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    // The anchor's own filter rules.
    commands.push(vec![
        "sudo".to_owned(),
        "/sbin/pfctl".to_owned(),
        "-a".to_owned(),
        anchor.to_owned(),
        "-F".to_owned(),
        "rules".to_owned(),
    ]);
    // The anchor's own NAT rules.
    commands.push(vec![
        "sudo".to_owned(),
        "/sbin/pfctl".to_owned(),
        "-a".to_owned(),
        anchor.to_owned(),
        "-F".to_owned(),
        "nat".to_owned(),
    ]);
    // The anchor's attachment leaves the host's own configuration.
    commands.push(vec![
        "sudo".to_owned(),
        "sh".to_owned(),
        "-c".to_owned(),
        format!("sed -i '' '/{anchor}/d' {PF_CONF}"),
    ]);
    // The main ruleset is reloaded without the anchor's lines.
    commands.push(vec![
        "sudo".to_owned(),
        "/sbin/pfctl".to_owned(),
        "-f".to_owned(),
        PF_CONF.to_owned(),
    ]);
    // The anchor's file goes, and so does the drift control's file.
    commands.push(vec![
        "sudo".to_owned(),
        "rm".to_owned(),
        "-f".to_owned(),
        anchor_path.to_owned(),
    ]);
    commands.push(vec![
        "sudo".to_owned(),
        "rm".to_owned(),
        "-f".to_owned(),
        format!("{anchor_path}.drift"),
    ]);
    // The filter's own enable state goes back to what the leg found.
    commands.push(vec![
        "sudo".to_owned(),
        "/sbin/pfctl".to_owned(),
        if pf_was_enabled { "-e" } else { "-d" }.to_owned(),
    ]);
    commands
}

/// The residue the leg left on the host's packet filter.
///
/// The check is scoped to the leg's own anchor and its own files, because a
/// concurrent installation's anchor is not the leg's residue and a
/// restoration that could flush one is not acceptable. The main rulesets are
/// compared as a whole, because the leg's own attachment lines were in the
/// host's configuration and the main ruleset has to be what it was.
///
/// The baseline is the state *before* the leg, not the state in the middle
/// of it: the leg legitimately adds its attachment lines to the host's
/// configuration and reloads, so the main ruleset before the leg and after
/// the teardown are the ones that have to match.
fn residue_found(baseline: &FilterInventory, after: &FilterInventory, anchor: &str) -> Vec<String> {
    let mut residue = Vec::new();
    match after
        .anchors
        .iter()
        .find(|candidate| candidate.name == anchor)
    {
        Some(managed) => {
            let filter = managed.filter_rules.trim();
            if !filter.is_empty() {
                residue.push(format!(
                    "the anchor {anchor} still holds {} loaded filter rules",
                    filter.lines().count()
                ));
            }
            let nat = managed.nat_rules.trim();
            if !nat.is_empty() {
                residue.push(format!(
                    "the anchor {anchor} still holds {} loaded NAT rules",
                    nat.lines().count()
                ));
            }
        }
        None => residue.push(format!("the anchor {anchor} could not be read")),
    }
    let anchor_file = anchor_file_path(anchor);
    if after.anchor_files.iter().any(|file| file == &anchor_file) {
        residue.push(format!("the anchor file {anchor_file} was left behind"));
    }
    let drift_file = format!("{anchor_file}.drift");
    if after.anchor_files.iter().any(|file| file == &drift_file) {
        residue.push(format!("the drift file {drift_file} was left behind"));
    }
    if baseline.pf_enabled != after.pf_enabled {
        residue.push(format!(
            "the packet filter's enable state changed from {} to {}",
            if baseline.pf_enabled {
                "enabled"
            } else {
                "disabled"
            },
            if after.pf_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
    }
    if baseline.parent_filter != after.parent_filter {
        residue.push("the main filter ruleset differs from the baseline".to_owned());
    }
    if baseline.parent_nat != after.parent_nat {
        residue.push("the main NAT ruleset differs from the baseline".to_owned());
    }
    residue
}

/// Puts the host's packet filter back the way the leg found it.
///
/// The restoration runs the planner's commands and then measures what is
/// left, so the leg's claim is a measurement rather than an assertion. The
/// commands are run unchecked on purpose: a restoration that stops at the
/// first failure leaves more behind, and the residue check is what reports
/// what is left.
fn restore_the_filter(evidence: &mut Evidence, context: &FilterContext) -> Vec<String> {
    let commands = restoration_commands(
        &context.anchor,
        &context.anchor_path,
        context.baseline.pf_enabled,
    );
    for command in &commands {
        let (program, arguments) = command
            .split_first()
            .expect("the planner's commands are never empty");
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let (ok, output) = sh_unchecked(evidence, program, arguments.as_slice());
        evidence.log(&format!(
            "the restoration command reported ok: {ok}: {}",
            output.trim()
        ));
    }
    let after = capture_filter_inventory(evidence, &context.anchor);
    let residue = residue_found(&context.baseline, &after, &context.anchor);
    evidence.log(&format!(
        "the residue the leg left on the host's packet filter: {residue:?}"
    ));
    residue
}

/// The message a caught panic carries.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "the leg panicked".to_owned()
    }
}

/// Reloads the operator-managed filter after the managed device was replaced.
///
/// The rendered rules name the tunnel device, and PF binds an interface name
/// to its index when the ruleset is loaded. A replacement device has a new
/// index, and the state table still holds the flows of the device that is
/// gone. Loading the ruleset again is what an operator does after any device
/// change, and it is what makes the rules apply to the live device.
fn refresh_operator_filter(evidence: &mut Evidence, path: &str, rules: &[String]) {
    let mut tee = Command::new("sudo")
        .args(["tee", path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("refresh the filter rules");
    {
        use std::io::Write as _;
        tee.stdin
            .as_mut()
            .expect("the rules pipe")
            .write_all(format!("{}\n", rules.join("\n")).as_bytes())
            .expect("write the rules");
    }
    let _ = tee.wait_with_output();
    sh(evidence, "sudo", &["chmod", "644", path]);
    sh(evidence, "sudo", &["pfctl", "-f", "/etc/pf.conf"]);
    let ruleset = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    evidence.log(&format!(
        "the packet filter ruleset after the refresh:\n{ruleset}"
    ));
}

/// Collects what the host's forwarding path looks like when the routed LAN
/// does not carry traffic.
///
/// The evidence has to say where the packets stopped: the routes, the managed
/// device's addresses and index, the filter's rules and state, the neighbour
/// cache, and the host's own reachability of the approved destination. A
/// verdict that says the prerequisites are in place does not say any of that.
fn forwarding_diagnostics(evidence: &mut Evidence, device: Option<&str>) {
    let Some(device) = device else {
        evidence.log("there is no managed device to diagnose");
        return;
    };
    for (label, args) in [
        ("the routes", vec!["netstat", "-rn", "-f", "inet"]),
        ("the managed device", vec!["ifconfig", device]),
        ("the filter rules", vec!["pfctl", "-s", "rules", "-v"]),
        ("the filter state", vec!["pfctl", "-s", "state"]),
        ("the neighbour cache", vec!["arp", "-an"]),
        (
            "the forwarding setting",
            vec!["sysctl", "-n", "net.inet.ip.forwarding"],
        ),
    ] {
        let (_ok, output) = sh_unchecked(evidence, "sudo", &args);
        evidence.log(&format!("{label}:\n{output}"));
    }
    // The host's own reachability of the approved destination: if this fails,
    // the tunnel was never the thing that was broken.
    let direct = sh_unchecked(
        evidence,
        "sudo",
        &["ping", "-c", "2", "-W", "2000", LAN_HOST],
    );
    evidence.log(&format!(
        "the host's own probe of the approved destination: {}",
        direct.1
    ));
}

/// Whether a ping transcript shows that the target answered.
///
/// The transcript prints one `bytes from` line per reply, so the presence of
/// that line is the answer. The packet-loss summary alone is **not** a safe
/// signal: the string `100% packet loss` contains `0% packet loss`, so a
/// transcript in which every packet was lost satisfies a check for
/// `0% packet loss`. A qualification that reads the loss summary that way
/// proves nothing at all.
fn answered(transcript: &str) -> bool {
    transcript.contains("bytes from")
}

/// The C003 live leg: a routed LAN that forwards to an approved prefix.
///
/// The leg's body is a function of its own, because the host's packet filter
/// has to be restored whether the leg reached its end or failed part-way
/// through it. A leg that panicked half-way through used to leave the
/// operator's filter loaded, the filter enabled, and the drift control's file
/// behind, and a later tunnel that was handed the same `utun` index would
/// have inherited the previous leg's rules.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c003_routed_lan_forwards_to_an_approved_downstream_prefix() {
    let mut evidence = Evidence::new("c003-routed-lan-approved-prefix");
    // The leg's own filter context, so the restoration knows what to put
    // back even when the leg never reached its own teardown.
    let mut context: Option<FilterContext> = None;
    // The panic is caught here so the restoration runs after it rather than
    // being skipped by it, and the leg's own failure is re-raised once the
    // host is back the way it was found.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        run_routed_lan_leg(&mut evidence, &mut context);
    }));
    // The leg's own failure is recorded before the restoration's verdict, so
    // the evidence carries both of them whatever the outcome.
    if let Err(payload) = &outcome {
        evidence.log(&format!(
            "the leg failed: {}",
            panic_message(payload.as_ref())
        ));
    }
    // The restoration runs whatever the leg did.
    let residue = match &context {
        Some(context) => restore_the_filter(&mut evidence, context),
        None => {
            evidence.log("the leg never installed a filter, so there is nothing to restore");
            Vec::new()
        }
    };
    let residue = residue.join("; ");
    assert!(
        residue.is_empty(),
        "the leg must leave the host's packet filter as it found it, and it left: {residue}"
    );
    if let Err(payload) = outcome {
        resume_unwind(payload);
    }
}

/// The C003 live leg's body.
///
/// The body installs the operator's filter, proves the routed LAN carries
/// traffic, and takes the peer down again. The host's packet filter is
/// restored by the caller, so that the restoration also happens when the leg
/// fails part-way through.
fn run_routed_lan_leg(evidence: &mut Evidence, context: &mut Option<FilterContext>) {
    let helper_path = require_live(evidence);
    let binary = std::env::var("WGB_BINARY").expect("WGB_BINARY must be set");
    let driver = peer_driver();

    // The peer host is prepared before this host is touched: an unreachable
    // peer must not leave a deployment behind.
    peer_run(evidence, &driver, &["setup"]);
    let peer_address = peer_run(evidence, &driver, &["peer-address"])
        .trim()
        .to_owned();
    assert!(
        !peer_address.is_empty(),
        "the peer driver must report the peer host's address"
    );
    evidence.log(&format!("peer host address: {peer_address}"));

    // The advertisement the peer dials has to be an address this host is
    // reachable at, so it is taken from the route toward the peer.
    let route = sh(evidence, "route", &["-n", "get", &peer_address]);
    let egress = route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .map(|value| value.trim().to_owned())
        .expect("the route toward the peer must name an interface");
    let source = interface_ipv4(evidence, &egress);
    evidence.log(&format!(
        "advertised endpoint {source}:{LISTEN_PORT} through {egress}"
    ));

    // The management identity the installer binds to is supplied by the
    // qualification, exactly as an operator supplies it.
    provision_management_identity(evidence);
    let _cleanup = DisposableDeployment {
        user: launchd::SERVE_USER.to_owned(),
        group: launchd::SERVE_GROUP.to_owned(),
    };
    resolve_management_identity(evidence);

    // The host's shared state is put back into the pre-test shape before
    // anything is installed, so the installer meets a host the way it would
    // meet one that had never run this leg.
    reset_host_preconditions(evidence);

    wg_basic::launchd_install::install(Path::new("/"), Path::new(&binary), Path::new(&helper_path))
        .expect("the transactional installer must complete the deployment");
    evidence.log("the transactional installer completed the deployment");

    let _firewall = FirewallAllowance {
        path: launchd::HELPER_PATH.to_owned(),
    };
    sh(evidence, FIREWALL_TOOL, &["--add", launchd::HELPER_PATH]);

    let netd_job = format!("system/{}", launchd::NETD_LABEL);
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
    wait_until("both roles running", Duration::from_secs(60), || {
        launchd_running(&netd_job) && launchd_running(&serve_job)
    });
    // The management service has to stay up, not just come up: a service
    // that exits immediately would leave the leg diagnosing a host whose
    // service is not running at all.
    std::thread::sleep(Duration::from_secs(8));
    assert!(
        launchd_running(&serve_job),
        "the management service must stay running once it has started"
    );

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
        .expect("the provisioning to finish");
    assert!(
        admin_output.status.success(),
        "administrator provisioning failed: {}",
        String::from_utf8_lossy(&admin_output.stderr)
    );

    let addr: std::net::SocketAddr = wg_basic::http::config::DEFAULT_BIND
        .parse()
        .expect("the default management bind is an address");
    let origin = format!("http://{addr}");
    wait_until("the management listener", Duration::from_secs(60), || {
        std::net::TcpStream::connect(addr).is_ok()
    });

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

    // The tunnel device inventory before the managed tunnel exists, so the
    // qualification can tell the managed tunnel from the host's own utun
    // devices.
    let utun_before = utun_names().len();

    // The inventory before the routed LAN exists: the host's routes and the
    // packet filter's rulesets, so the qualification can show what it
    // changed and what it did not.
    let routes_before = sh(evidence, "netstat", &["-rn", "-f", "inet"]);
    let routes6_before = sh(evidence, "netstat", &["-rn", "-f", "inet6"]);
    let pf_before = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    let forwarding_before = sh(evidence, "sysctl", &["-n", "net.inet.ip.forwarding"]);
    let forwarding6_before = sh(evidence, "sysctl", &["-n", "net.inet6.ip6.forwarding"]);
    evidence.log(&format!(
        "forwarding before: {forwarding_before} / {forwarding6_before}"
    ));

    // The routed-LAN policy. The downstream prefixes are approved explicitly,
    // and the policy never masquerades.
    let setup_body = format!(
        r#"{{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"{TUNNEL_V4}","ipv6_tunnel_prefix":"{TUNNEL_V6}","server_address":"{SERVER_V4}","ipv6_server_address":"{SERVER_V6}","listen_port":{LISTEN_PORT},"advertised_endpoint":"{source}:{LISTEN_PORT}","egress_interface":"{egress}","ipv4_forwarding_required":true,"ipv6_forwarding_required":true,"masquerade":false,"mode":"routed_lan","destination_prefixes":["{LAN_PREFIX}","{LAN_PREFIX6}"],"default_client_route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}}}}"#
    );
    let (setup_status, setup_text, _) = http(
        addr,
        "POST",
        "/api/v1/setup",
        Some(&origin),
        Some(&cookie),
        Some(&csrf),
        &setup_body,
    );
    evidence.log(&format!(
        "the routed-LAN setup answered {setup_status}: {setup_text}"
    ));
    assert!(
        setup_status == 200 || setup_status == 202,
        "the policy itself is valid and must be accepted: {setup_text}"
    );
    // The policy is accepted, but the routed LAN itself is not converged:
    // the prerequisites are not in place yet, and the receipt says so
    // instead of claiming a convergence that did not happen.
    let receipt: serde_json::Value = serde_json::from_str(&setup_text).expect("the setup receipt");
    assert_eq!(
        receipt["degraded_category"], "backend_refused",
        "the routed LAN must be refused while its prerequisites are missing: {setup_text}"
    );
    assert_eq!(
        receipt["enforcement"], "degraded",
        "the refusal must be reported as degraded enforcement: {setup_text}"
    );

    // The managed tunnel comes up even though the routed LAN cannot be
    // proven yet: the interface is created first, and the filter contract is
    // checked afterwards.
    wait_until("the managed tunnel", Duration::from_secs(90), || {
        utun_names().len() > utun_before
    });
    // The managed tunnel's own addresses and routes. The pool route the
    // return path depends on is part of the evidence, and so is every
    // interface the host already had, so that a later reader can tell the
    // managed device from the host's own tunnels.
    let mut tunnel_inventory = String::new();
    for name in utun_names() {
        tunnel_inventory.push_str(&sh(evidence, "ifconfig", &[&name]));
        tunnel_inventory.push('\n');
    }
    evidence.log(&format!("the tunnel interfaces:\n{tunnel_inventory}"));
    let tunnel_routes = sh(evidence, "netstat", &["-rn", "-f", "inet"]);
    let tunnel_routes6 = sh(evidence, "netstat", &["-rn", "-f", "inet6"]);
    evidence.log(&format!(
        "the routes with the managed tunnel up:\n{tunnel_routes}\n{tunnel_routes6}"
    ));
    let verdict = diagnose(evidence, false);
    evidence.log(&format!("the routed-LAN verdict: {}", verdict.summary));
    assert!(
        verdict.summary.contains("forwarding"),
        "the first missing prerequisite is the host's forwarding: {}",
        verdict.summary
    );

    // The administrator enables the host's global forwarding. It is shared
    // with everything else that routes on this host, so the product reads it
    // and never writes it.
    sh(evidence, "sysctl", &["-w", "net.inet.ip.forwarding=1"]);
    sh(evidence, "sysctl", &["-w", "net.inet6.ip6.forwarding=1"]);

    // With forwarding enabled, the next missing prerequisite is the
    // operator-managed filter, and the product names the rules it needs.
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the routed-LAN verdict after forwarding was enabled: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("filter"),
        "the verdict must name the missing filter, got: {}",
        verdict.summary
    );
    let rules = verdict.rules.clone();
    assert!(
        !rules.is_empty(),
        "the product must report the rules the operator has to install: {}",
        verdict.evidence
    );
    evidence.log(&format!(
        "the product requires these rules: {}",
        rules.join(" | ")
    ));

    // The administrator also installs the routes the policy needs: one
    // specific route per approved prefix, through the upstream router.
    let (ipv4_gateway, ipv6_gateway) = upstream_gateways(evidence);
    sh(
        evidence,
        "route",
        &["-n", "add", "-net", LAN_PREFIX, &ipv4_gateway],
    );
    sh(
        evidence,
        "route",
        &["-n", "add", "-inet6", "-net", LAN_PREFIX6, &ipv6_gateway],
    );
    let routes_installed = sh(evidence, "netstat", &["-rn", "-f", "inet"]);
    let routes6_installed = sh(evidence, "netstat", &["-rn", "-f", "inet6"]);
    evidence.log(&format!(
        "routes with the downstream prefixes:\n{routes_installed}\n{routes6_installed}"
    ));
    // The route to the approved prefix has to name a *gateway*. A link-level
    // route on the router's own interface makes it look for the address on
    // that interface, where it does not exist, so it caches a rejection and
    // the return path never leaves the router. The failure is silent, so the
    // shape is asserted rather than inferred from traffic that happened to
    // flow.
    let route_to_lan = sh(evidence, "route", &["-n", "get", LAN_HOST]);
    assert!(
        route_to_lan.contains(&format!("gateway: {ipv4_gateway}")),
        "the approved prefix must be reached through a gateway, not a link: {}",
        route_to_lan
    );

    // The rules go into the installation's own anchor and the anchor is
    // attached from the host's own pf configuration. Neither is written by
    // the product.
    let anchor = anchor_name(evidence);
    let anchor_path = anchor_file_path(&anchor);
    // The host's filter state is captured before the leg installs anything,
    // so the restoration has a baseline to put back and the claim that the
    // leg left the host's filter as it found it can be measured rather than
    // asserted.
    let baseline = capture_filter_inventory(evidence, &anchor);
    // The context is recorded before the filter is installed, so a leg that
    // fails between the install and the end is restored too.
    *context = Some(FilterContext {
        anchor: anchor.clone(),
        anchor_path: anchor_path.clone(),
        baseline,
    });
    let rules_path = install_operator_filter(evidence, &anchor, &rules);

    // The product's own reconcile converges now that the prerequisites are
    // in place, and the doctor says the routed LAN is available.
    let verdict = diagnose(evidence, true);
    evidence.log(&format!(
        "the routed-LAN verdict after the operator's action: {}",
        verdict.summary
    ));
    assert!(
        verdict.converged,
        "the reconcile must converge once the operator's filter is in place: {}",
        verdict.summary
    );
    assert!(
        verdict.reconcile_failure.is_none(),
        "the reconcile must run to completion: {}",
        verdict.reconcile_failure.clone().unwrap_or_default()
    );
    assert!(
        verdict.summary.contains("in place"),
        "the product must report the routed LAN as available: {}",
        verdict.summary
    );

    // The client is enrolled and its exported configuration is what the peer
    // consumes.
    let (_, server_body, _) = http(addr, "GET", "/api/v1/server", None, Some(&cookie), None, "");
    let server: serde_json::Value = serde_json::from_str(&server_body).expect("the server");
    let interface_id = server["server"]["interface_id"]
        .as_str()
        .expect("the configured interface")
        .to_owned();
    let generation = server["generation"].as_u64().expect("the generation");
    let create_body = format!(
        r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"routed-peer","route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}},"client_keepalive_seconds":{CLIENT_KEEPALIVE}}}"#
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
    let client_address = created["data"]["assigned_address"]
        .as_str()
        .expect("the client's tunnel address")
        .split('/')
        .next()
        .expect("the client's tunnel address without a prefix length")
        .to_owned();
    let client_address6 = created["data"]["assigned_ipv6_address"]
        .as_str()
        .expect("the client's IPv6 tunnel address")
        .split('/')
        .next()
        .expect("the client's IPv6 tunnel address without a prefix length")
        .to_owned();
    evidence.log(&format!(
        "the enrolled client's tunnel addresses are {client_address} and {client_address6}"
    ));
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
    let exported =
        std::env::temp_dir().join(format!("wgb-c003-client-{}.conf", std::process::id()));
    std::fs::write(&exported, &config_text).expect("write the exported configuration");

    // The peer installs the configuration with the approved downstream prefix
    // in its AllowedIPs, so the downstream traffic goes into the tunnel.
    peer_run(
        evidence,
        &driver,
        &[
            "apply",
            exported.to_str().expect("the exported path"),
            SERVER_V4,
            SERVER_V6,
            ATTEMPTED_PREFIX,
            ATTEMPTED_PREFIX6,
        ],
    );
    std::fs::remove_file(&exported).ok();

    let mut handshake = 0u64;
    wait_until("the off-host handshake", Duration::from_secs(90), || {
        let reported = peer_run(evidence, &driver, &["handshake"]);
        handshake = reported.trim().parse().unwrap_or(0);
        handshake > 0
    });
    evidence.log(&format!(
        "the off-host peer completed a handshake at {handshake}"
    ));

    // The routed LAN itself: the peer's traffic to the approved downstream
    // prefix traverses the tunnel and the host's forwarding path.
    let downstream = peer_run(evidence, &driver, &["ping-lan", LAN_HOST]);
    evidence.log(&format!("the downstream probe: {downstream}"));
    assert!(
        answered(&downstream),
        "the approved downstream host must answer through the tunnel: {downstream}"
    );

    let downstream6 = peer_run(evidence, &driver, &["ping-lan6", LAN_HOST6]);
    evidence.log(&format!("the IPv6 downstream probe: {downstream6}"));
    assert!(
        answered(&downstream6),
        "the approved downstream host must answer IPv6 through the tunnel: {downstream6}"
    );

    // The return path: the downstream host reaches the peer's tunnel
    // address, which only works when the upstream route back to the pool is
    // in place.
    let returning = peer_run(evidence, &driver, &["lan-host-ping", &client_address]);
    evidence.log(&format!("the return probe: {returning}"));
    assert!(
        answered(&returning),
        "the downstream host must reach the tunnel through the upstream route: {returning}"
    );

    // The IPv6 return path, which depends on the upstream IPv6 route back to
    // the pool just as the IPv4 one does.
    let returning6 = peer_run(evidence, &driver, &["lan-host-ping6", &client_address6]);
    evidence.log(&format!("the IPv6 return probe: {returning6}"));
    assert!(
        answered(&returning6),
        "the downstream host must reach the tunnel over IPv6 through the upstream route: {returning6}"
    );

    // The negative cases. A destination outside the approved prefix is not
    // delivered, and a spoofed source is not delivered either.
    let refused = peer_run(evidence, &driver, &["ping-lan", "10.20.21.2"]);
    evidence.log(&format!("the unapproved destination probe: {refused}"));
    assert!(
        !answered(&refused),
        "a destination outside the approved prefix must not be delivered: {refused}"
    );

    let spoofed = peer_run(evidence, &driver, &["spoof", LAN_HOST]);
    evidence.log(&format!("the spoofed source probe: {spoofed}"));
    assert!(
        !answered(&spoofed),
        "a spoofed source must not be delivered: {spoofed}"
    );

    // Each missing prerequisite has its own refusal.
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the verdict before the negative cases: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("in place"),
        "the routed LAN must be available before the negative cases: {}",
        verdict.summary
    );

    // The filter drifts: one rule is changed, and the product notices.
    //
    // The drifting rules are written to their own file. The installed anchor
    // file holds the rules the product reported, and the filter is restored
    // from it afterwards: a restore that read the drifting file would put
    // the drift back rather than take it away.
    let drift_path = format!("{rules_path}.drift");
    sh(
        evidence,
        "sudo",
        &[
            "sh",
            "-c",
            &format!("printf '%s\\n' 'pass in on utun0 from any to any keep state' > {drift_path}"),
        ],
    );
    sh(
        evidence,
        "sudo",
        &["pfctl", "-a", &anchor, "-f", &drift_path],
    );
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the verdict after the filter drifted: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("does not match"),
        "a drifted filter must be reported as drift: {}",
        verdict.summary
    );

    // The filter is missing: the anchor is flushed.
    sh(evidence, "sudo", &["pfctl", "-a", &anchor, "-F", "all"]);
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the verdict after the filter was removed: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("absent") || verdict.summary.contains("filter"),
        "a removed filter must be reported as missing: {}",
        verdict.summary
    );

    // The filter is restored from the rules the product reported, and
    // forwarding is turned off.
    sh(
        evidence,
        "sudo",
        &["pfctl", "-a", &anchor, "-f", &rules_path],
    );
    sh(evidence, "sysctl", &["-w", "net.inet.ip.forwarding=0"]);
    sh(evidence, "sysctl", &["-w", "net.inet6.ip6.forwarding=0"]);
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the verdict after forwarding was turned off: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("forwarding"),
        "a host without forwarding must be reported as such: {}",
        verdict.summary
    );
    sh(evidence, "sysctl", &["-w", "net.inet.ip.forwarding=1"]);
    sh(evidence, "sysctl", &["-w", "net.inet6.ip6.forwarding=1"]);

    // A competing route covers an approved destination.
    sh(
        evidence,
        "route",
        &["-n", "add", "-net", COMPETING_PREFIX, "-interface", "lo0"],
    );
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the verdict after a competing route appeared: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("route") || verdict.summary.contains("competing"),
        "a competing route must be reported as a conflict: {}",
        verdict.summary
    );
    sh(
        evidence,
        "route",
        &[
            "-n",
            "delete",
            "-net",
            COMPETING_PREFIX,
            "-interface",
            "lo0",
        ],
    );

    // No route reaches the approved destination any more: the product must
    // refuse rather than fall back to the default route, which is the one
    // route a routed LAN may never depend on.
    sh(evidence, "route", &["-n", "delete", "-net", LAN_PREFIX]);
    let verdict = diagnose(evidence, false);
    evidence.log(&format!(
        "the verdict after the approved destination lost its route: {}",
        verdict.summary
    ));
    assert!(
        verdict.summary.contains("not reachable") || verdict.summary.contains("route"),
        "a destination without a specific route must be reported: {}",
        verdict.summary
    );
    assert!(
        !verdict.summary.contains("in place"),
        "a destination without a specific route must not be reported as available: {}",
        verdict.summary
    );
    // The operator restores the route.
    sh(
        evidence,
        "route",
        &["-n", "add", "-net", LAN_PREFIX, &ipv4_gateway],
    );

    // The helper is killed. The managed tunnel goes with it: the kernel
    // releases the device, the pool route with it, and the operator's filter
    // names a device that no longer carries the tunnel.
    //
    // The privileged authority that owns the helper replaces it: the helper is
    // its own child process, and a child that dies is replaced with the state
    // that was already applied, not left down until an operator intervenes.
    // The product never reports the convergence it proved for the *previous*
    // device in the meantime: the observation re-proves the receipt, so a
    // tunnel that is gone is never a tunnel that is available.
    //
    // The device may come back renumbered, because the kernel assigns the
    // `utunN` name. The contract is that the tunnel is there and carries the
    // policy again, not that it kept its number.
    let device_before = managed_device(&verdict.rules);
    evidence.log(&format!(
        "the managed device before the helper restart: {device_before:?}"
    ));
    // The peer's handshake as it stands immediately before the kill. A
    // handshake the peer still holds from before the kill is not a session
    // the replacement helper shares, so the recovery has to be shown to
    // produce a *new* one.
    let handshake_before = peer_run(evidence, &driver, &["handshake"])
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    evidence.log(&format!(
        "the off-host peer's handshake before the kill: {handshake_before}"
    ));
    // The capture runs across the whole recovery, so the evidence says where
    // the packets stopped rather than only that they did. The filter keeps
    // the tunnel's own transport and the inner traffic, and leaves the
    // host's unrelated background traffic out.
    sh_unchecked(
        evidence,
        "sudo",
        &[
            "sh",
            "-c",
            "rm -f /tmp/c011-capture.pcap; nohup tcpdump -i any -n -w /tmp/c011-capture.pcap 'udp port 51820 or icmp' >/dev/null 2>&1 & sleep 1",
        ],
    );
    let killed_at = Instant::now();
    sh(
        evidence,
        "sudo",
        &["pkill", "-f", "libexec/wg-basic/wireguard-go"],
    );
    let mut recovered = false;
    for _ in 0..60 {
        std::thread::sleep(Duration::from_secs(1));
        let helpers = sh_unchecked(
            evidence,
            "sh",
            &["-c", "ps -o pid,command -ax | grep '[w]ireguard-go'"],
        )
        .1;
        if !helpers.trim().is_empty() {
            recovered = true;
            evidence.log(&format!("the helper was replaced: {}", helpers.trim()));
            break;
        }
    }
    assert!(
        recovered,
        "the privileged authority must replace the helper it lost: {}",
        verdict.summary
    );
    let verdict = diagnose(evidence, true);
    let device_after = managed_device(&verdict.rules);
    evidence.log(&format!(
        "the managed device after the helper restart: {device_after:?}"
    ));
    evidence.log(&format!(
        "the routed-LAN verdict after the helper restart: {}",
        verdict.summary
    ));
    assert!(
        device_after.is_some(),
        "the helper's replacement must carry the tunnel again: {}",
        verdict.summary
    );
    assert!(
        verdict.summary.contains("in place"),
        "the recovered tunnel must carry the routed LAN again: {}",
        verdict.summary
    );

    // The product's own account of the peer, right after the recovery.
    //
    // The replacement helper is a new process: it holds no session with any
    // peer, and it has never seen a handshake initiation, so it has no
    // endpoint to send one to. The product observes exactly that, and the
    // observation is the product's own rather than the harness's inference.
    let (telemetry_status, telemetry_body, _) = http(
        addr,
        "GET",
        "/api/v1/clients/telemetry",
        None,
        Some(&cookie),
        None,
        "",
    );
    evidence.log(&format!(
        "the client telemetry after the recovery (HTTP {telemetry_status}): {telemetry_body}"
    ));

    // The operator's filter names the tunnel device, and PF binds an
    // interface name to its index when the ruleset is loaded. A replacement
    // device carries a new index even when the kernel hands back the same
    // name, so the rules have to be loaded again. Reloading the ruleset is
    // the operator's step after any device change, and the leg takes it here
    // for the same reason an operator would.
    refresh_operator_filter(evidence, &rules_path, &verdict.rules);

    // A WireGuard session is not restored by recreating a helper.
    //
    // The replacement helper holds no session, and a peer whose own session
    // is still valid keeps sending packets the replacement cannot decrypt.
    // The peer re-keys on its own schedule, and the handshake that follows is
    // the proof that the two sides share a session again.
    //
    // The handshake has to be a NEW one. A check that only asks for a
    // non-zero handshake is satisfied by the value the peer reported before
    // the kill, and would say the recovered tunnel works while proving
    // nothing at all about the replacement helper.
    let mut handshake_after = 0u64;
    wait_until(
        "a new off-host handshake after the recovery",
        PEER_REKEY_WINDOW,
        || {
            let reported = peer_run(evidence, &driver, &["handshake"]);
            handshake_after = reported.trim().parse().unwrap_or(0);
            handshake_after > handshake_before
        },
    );
    evidence.log(&format!(
        "the off-host peer completed a new handshake at {handshake_after} (the handshake before the kill was {handshake_before}), {:?} after the helper was killed",
        killed_at.elapsed()
    ));

    // The traffic says the recovered tunnel is the same tunnel: the approved
    // downstream host answers through it again. A verdict alone would not show
    // that the replacement carries packets.
    let downstream_after = peer_run(evidence, &driver, &["ping-lan", LAN_HOST]);
    evidence.log(&format!(
        "the downstream probe after the recovery: {downstream_after}"
    ));
    assert!(
        answered(&downstream_after),
        "the recovered tunnel must carry traffic to the approved prefix again: {downstream_after}"
    );
    let downstream6_after = peer_run(evidence, &driver, &["ping-lan6", LAN_HOST6]);
    evidence.log(&format!(
        "the IPv6 downstream probe after the recovery: {downstream6_after}"
    ));
    assert!(
        answered(&downstream6_after),
        "the recovered tunnel must carry IPv6 traffic to the approved prefix again: {downstream6_after}"
    );
    let returning_after = peer_run(evidence, &driver, &["lan-host-ping", &client_address]);
    evidence.log(&format!(
        "the return probe after the recovery: {returning_after}"
    ));
    assert!(
        answered(&returning_after),
        "the downstream host must reach the recovered tunnel through the upstream route: {returning_after}"
    );
    // The negative still holds after the recovery: the replacement is bound by
    // the same policy, not by a looser one.
    let refused_after = peer_run(evidence, &driver, &["ping-lan", "10.20.21.2"]);
    evidence.log(&format!(
        "the unapproved destination probe after the recovery: {refused_after}"
    ));
    assert!(
        !answered(&refused_after),
        "the recovered tunnel must still refuse an unapproved destination: {refused_after}"
    );
    let capture = sh_unchecked(
        evidence,
        "sudo",
        &[
            "sh",
            "-c",
            "pkill -f 'tcpdump -i any' ; sleep 1; tcpdump -r /tmp/c011-capture.pcap -n 'udp port 51820 or icmp' 2>/dev/null | head -60",
        ],
    );
    evidence.log(&format!(
        "the packets captured across the recovery:\n{}",
        capture.1
    ));
    forwarding_diagnostics(evidence, device_after.as_deref());

    // The inventory after: the host's routes and the filter's rulesets.
    let routes_after = sh(evidence, "netstat", &["-rn", "-f", "inet"]);
    let routes6_after = sh(evidence, "netstat", &["-rn", "-f", "inet6"]);
    let pf_after = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    let forwarding_after = sh(evidence, "sysctl", &["-n", "net.inet.ip.forwarding"]);
    evidence.log(&format!("routes after:\n{routes_after}"));
    evidence.log(&format!("routes before:\n{routes_before}"));
    evidence.log(&format!("routes IPv6 after:\n{routes6_after}"));
    evidence.log(&format!("routes IPv6 before:\n{routes6_before}"));
    evidence.log(&format!("packet filter before:\n{pf_before}"));
    evidence.log(&format!("packet filter after:\n{pf_after}"));
    evidence.log(&format!(
        "forwarding before: {forwarding_before} / {forwarding6_before}"
    ));
    evidence.log(&format!("forwarding after: {forwarding_after}"));

    // The teardown: the peer is taken down and the host is left as it was
    // found. The host's packet filter is restored by the caller, which does
    // it whether the leg reached this point or failed before it.
    peer_run(evidence, &driver, &["teardown"]);
    evidence.log("the off-host peer was torn down");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchor the leg's own filter lives in.
    const ANCHOR: &str = "wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163";

    /// The anchor's file.
    const ANCHOR_PATH: &str = "/etc/pf.anchors/wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163";

    /// The `pfctl` arguments of a command, if the command is a `pfctl` one.
    ///
    /// The program itself is `sudo`, so the arguments are what is left after
    /// the program and the `pfctl` path.
    fn pfctl_arguments(command: &[String]) -> Option<&[String]> {
        let start = command
            .iter()
            .position(|argument| argument.ends_with("pfctl"))?;
        Some(&command[start + 1..])
    }

    /// The arguments of a command that removes a file.
    ///
    /// The privilege wrapper and the program come first, so the arguments are
    /// what is left after them.
    fn removal_arguments(command: &[String]) -> Option<&[String]> {
        let start = command.iter().position(|argument| argument == "rm")?;
        Some(&command[start + 1..])
    }

    /// Whether a command's arguments are exactly the expected ones.
    fn arguments_are(arguments: &[String], expected: &[&str]) -> bool {
        arguments.len() == expected.len()
            && arguments
                .iter()
                .zip(expected)
                .all(|(argument, expected)| argument == expected)
    }

    /// An inventory of a host whose filter the leg left as it found it.
    fn clean_inventory() -> FilterInventory {
        FilterInventory {
            pf_enabled: false,
            parent_filter: "scrub-anchor \"com.apple/filter\"\nblock-anchor \"com.apple/filter\"\n"
                .to_owned(),
            parent_nat: String::new(),
            anchors: vec![AnchorInventory {
                name: ANCHOR.to_owned(),
                filter_rules: String::new(),
                nat_rules: String::new(),
            }],
            anchor_files: vec![format!("{PF_ANCHORS_DIR}/com.apple/filter")],
        }
    }

    #[test]
    fn the_restoration_flushes_the_managed_anchor_and_never_the_main_ruleset() {
        let commands = restoration_commands(ANCHOR, ANCHOR_PATH, false);
        // The anchor's own filter rules and its own NAT rules are flushed
        // separately: one flush per class, each scoped to the anchor.
        let flushes: Vec<&[String]> = commands
            .iter()
            .filter_map(|command| pfctl_arguments(command))
            .filter(|arguments| arguments.contains(&"-F".to_owned()))
            .collect();
        assert!(
            flushes
                .iter()
                .any(|arguments| arguments_are(arguments, &["-a", ANCHOR, "-F", "rules"])),
            "the anchor's own filter rules must be flushed: {flushes:?}"
        );
        assert!(
            flushes
                .iter()
                .any(|arguments| arguments_are(arguments, &["-a", ANCHOR, "-F", "nat"])),
            "the anchor's own NAT rules must be flushed: {flushes:?}"
        );
        // A bare `-F all` flushes the **main** ruleset, which the leg does
        // not own, and it never empties an anchor.
        for command in &commands {
            let Some(arguments) = pfctl_arguments(command) else {
                continue;
            };
            let Some(position) = arguments.iter().position(|argument| argument == "-F") else {
                continue;
            };
            assert_ne!(
                arguments[position + 1],
                "all",
                "the restoration must never flush the main ruleset: {command:?}"
            );
            assert!(
                arguments.contains(&"-a".to_owned()),
                "a flush must be scoped to an anchor: {command:?}"
            );
        }
    }

    #[test]
    fn the_restoration_removes_the_anchor_file_and_its_drift_sibling() {
        let commands = restoration_commands(ANCHOR, ANCHOR_PATH, false);
        let drift = format!("{ANCHOR_PATH}.drift");
        let removals: Vec<&[String]> = commands
            .iter()
            .filter_map(|command| removal_arguments(command))
            .collect();
        assert!(
            removals
                .iter()
                .any(|arguments| arguments_are(arguments, &["-f", ANCHOR_PATH])),
            "the anchor's own file must be removed: {removals:?}"
        );
        assert!(
            removals
                .iter()
                .any(|arguments| arguments_are(arguments, &["-f", drift.as_str()])),
            "the drift control's file must be removed: {removals:?}"
        );
    }

    #[test]
    fn the_restoration_restores_the_filters_enable_state() {
        // A host whose filter was disabled must not be left with the filter
        // enabled: the leg enabled it, and the restoration puts it back.
        let disabled = restoration_commands(ANCHOR, ANCHOR_PATH, false);
        assert!(
            disabled
                .iter()
                .filter_map(|command| pfctl_arguments(command))
                .any(|arguments| arguments_are(arguments, &["-d"])),
            "a host whose filter was disabled must have it disabled again"
        );
        assert!(
            !disabled
                .iter()
                .filter_map(|command| pfctl_arguments(command))
                .any(|arguments| arguments_are(arguments, &["-e"])),
            "a host whose filter was disabled must not have it enabled"
        );
        // A host that was already filtering keeps filtering.
        let enabled = restoration_commands(ANCHOR, ANCHOR_PATH, true);
        assert!(
            enabled
                .iter()
                .filter_map(|command| pfctl_arguments(command))
                .any(|arguments| arguments_are(arguments, &["-e"])),
            "a host that was already filtering must keep filtering"
        );
        assert!(
            !enabled
                .iter()
                .filter_map(|command| pfctl_arguments(command))
                .any(|arguments| arguments_are(arguments, &["-d"])),
            "a host that was already filtering must not have the filter disabled"
        );
    }

    #[test]
    fn the_restoration_names_only_the_legs_own_anchor() {
        let allowed = [
            ANCHOR_PATH.to_owned(),
            format!("{ANCHOR_PATH}.drift"),
            PF_CONF.to_owned(),
        ];
        for pf_was_enabled in [true, false] {
            let commands = restoration_commands(ANCHOR, ANCHOR_PATH, pf_was_enabled);
            for command in &commands {
                // The only anchor the restoration names is the leg's own.
                for (position, argument) in command.iter().enumerate() {
                    if argument == "-a" {
                        assert_eq!(
                            command[position + 1],
                            ANCHOR,
                            "the restoration must not name a foreign anchor: {command:?}"
                        );
                    }
                    assert!(
                        !argument.contains("com.apple"),
                        "the restoration must not touch Apple's own anchors: {command:?}"
                    );
                }
                // The only paths the restoration names are the leg's own
                // anchor file, its drift sibling, and the host's own
                // configuration file. The privilege wrapper and the program
                // come first and are not host paths.
                for argument in command.iter().skip(2) {
                    for token in argument.split_whitespace() {
                        if !token.starts_with('/') {
                            continue;
                        }
                        assert!(
                            allowed.iter().any(|path| path == token),
                            "the restoration must not name {token}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_residue_check_reports_an_anchor_that_still_holds_loaded_rules() {
        let baseline = clean_inventory();
        // The residue the defect left: the anchor's rules were still loaded,
        // and two of them named the tunnel's device.
        let mut after = clean_inventory();
        after.anchors[0].filter_rules =
            "pass in on utun0 inet from 10.77.0.0/24 to 10.20.20.0/24 keep state\n".to_owned();
        let residue = residue_found(&baseline, &after, ANCHOR);
        assert!(
            residue.iter().any(|entry| entry.contains("filter rules")),
            "an anchor that still holds filter rules must be reported: {residue:?}"
        );
        let mut after_nat = clean_inventory();
        after_nat.anchors[0].nat_rules = "match in on utun0 inet to any -> 10.20.20.2\n".to_owned();
        let residue = residue_found(&baseline, &after_nat, ANCHOR);
        assert!(
            residue.iter().any(|entry| entry.contains("NAT rules")),
            "an anchor that still holds NAT rules must be reported: {residue:?}"
        );
    }

    #[test]
    fn the_residue_check_reports_a_leftover_file_and_a_changed_enable_state() {
        let baseline = clean_inventory();
        let mut after = clean_inventory();
        after.anchor_files.push(ANCHOR_PATH.to_owned());
        after.anchor_files.push(format!("{ANCHOR_PATH}.drift"));
        after.pf_enabled = !baseline.pf_enabled;
        let residue = residue_found(&baseline, &after, ANCHOR);
        assert!(
            residue.iter().any(|entry| entry.contains("anchor file")),
            "a leftover anchor file must be reported: {residue:?}"
        );
        assert!(
            residue.iter().any(|entry| entry.contains("drift file")),
            "a leftover drift file must be reported: {residue:?}"
        );
        assert!(
            residue.iter().any(|entry| entry.contains("enable state")),
            "a changed enable state must be reported: {residue:?}"
        );
    }

    #[test]
    fn the_residue_check_reports_nothing_for_a_clean_inventory() {
        let baseline = clean_inventory();
        let after = clean_inventory();
        let residue = residue_found(&baseline, &after, ANCHOR);
        assert!(
            residue.is_empty(),
            "a host the leg left as it found it must hold no residue: {residue:?}"
        );
    }

    #[test]
    fn the_residue_check_reports_a_main_ruleset_that_differs_from_the_baseline() {
        let baseline = clean_inventory();
        let mut after = clean_inventory();
        after.parent_filter = "pass out on en0 inet from any to any\n".to_owned();
        let residue = residue_found(&baseline, &after, ANCHOR);
        assert!(
            residue
                .iter()
                .any(|entry| entry.contains("main filter ruleset")),
            "a main filter ruleset that differs from the baseline must be reported: {residue:?}"
        );
        let mut after_nat = clean_inventory();
        after_nat.parent_nat = "match in on en0 inet to any -> 10.20.20.2\n".to_owned();
        let residue = residue_found(&baseline, &after_nat, ANCHOR);
        assert!(
            residue
                .iter()
                .any(|entry| entry.contains("main NAT ruleset")),
            "a main NAT ruleset that differs from the baseline must be reported: {residue:?}"
        );
    }
}
