//! The C004 controlled-host qualification: an effective IPv4 egress gateway on macOS.
//!
//! C004 turns the managed tunnel into an IPv4 Internet-egress gateway. The
//! product owns one installation-scoped anchor, the administrator attaches that
//! anchor in **both** rule classes, IPv4 traffic leaves the host with the
//! host's own egress address as its source, and IPv6 traffic leaves with the
//! client's own tunnel address because there is no NAT66.
//!
//! What it proves:
//! - the product converges once the administrator's prerequisites are in place,
//!   and the anchor's filter class and NAT class then hold exactly the
//!   rendered policy;
//! - the far side observes the **translated** IPv4 source, and never the
//!   client's tunnel address;
//! - the far side observes the **untranslated** IPv6 source, and the anchor
//!   holds no NAT rule for the IPv6 pool;
//! - the reply comes back through the same tunnel;
//! - each missing prerequisite has its own refusal: the host's forwarding,
//!   the administrator's attachment in both rule classes, and drift in the
//!   anchor's NAT rules;
//! - the teardown leaves the host's packet filter as it was found, apart from
//!   the managed anchor's own rules being emptied;
//! - the product never loaded the root ruleset, never flushed a table, never
//!   toggled PF, and never wrote the forwarding switches.
//!
//! The leg acts as the **administrator** where an administrator acts: it
//! creates the anchor's file, edits the host's own `/etc/pf.conf`, reloads the
//! host's own ruleset, enables PF, and sets the host's forwarding switches.
//! Those are the leg's actions and the evidence says so; the product's
//! actions are the ones the leg measures around them.
//!
//! The peer driver has to be able to report what the far side observed. The
//! C003 driver cannot, so this leg needs two subcommands it does not have:
//!
//! ```text
//! observed-source <addr>    -> the IPv4 source address the downstream LAN
//!                             host observed for the traffic towards <addr>
//! observed-source6 <addr>   -> the same, for IPv6
//! ```
//!
//! Both print the observed address on one line and exit zero. The appliance's
//! own state table can show what it translated, but only the far side can say
//! what arrived: a leg that reads only the appliance's own view cannot tell a
//! translated source from an untranslated one. The observation belongs in the
//! downstream namespace, on the packet that actually arrived there.
//!
//! Two things differ from the routed-LAN leg, and both follow from the mode.
//! The gateway's destination is the Internet, so the host's own default route
//! is the way out and the administrator installs no route for it. And the
//! anchor is the **product's** here: the administrator attaches it and the
//! product installs the rules into it, so the leg measures the anchor's own
//! two classes instead of an operator-managed file.
//!
//! Private keys are generated fresh per run and never enter evidence output.

#![cfg(target_os = "macos")]

use std::any::Any;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use wg_basic::domain::{InstallationId, InterfaceName, NetworkPrefix};
use wg_basic::firewall::{self, PfRuleSet};
use wg_basic::launchd;

mod darwin_live_common;
use darwin_live_common::*;

/// The far side the gateway's traffic reaches.
///
/// The far side is the downstream LAN host of the peer fixture. It stands in
/// for the Internet: the product's translation is observable there, and the
/// reply comes back from there. The host between the two guests is a pure
/// forwarder that does not translate, so what the far side observes is what
/// the product did.
const FAR_SIDE: &str = "10.20.20.2";

/// The far side's IPv6 address.
const FAR_SIDE6: &str = "2001:db8:20::2";

/// The wider IPv4 range the peer sends into the tunnel.
///
/// The peer is deliberately configured with a wider range than the far side's
/// own prefix, so the far side really is reached through the tunnel and not
/// through a route the peer holds on its own.
const ATTEMPTED_PREFIX: &str = "10.20.0.0/16";

/// The wider IPv6 range the peer sends into the tunnel.
const ATTEMPTED_PREFIX6: &str = "2001:db8::/32";

/// The host directory the packet-filter anchors live in.
///
/// macOS keeps its own anchors here, `com.apple/filter` among them, and the
/// installation's own anchor is one more file in the same directory. The
/// leg's restoration touches that one file and nothing else in it.
const PF_ANCHORS_DIR: &str = "/etc/pf.anchors";

/// The host's own packet-filter configuration file.
///
/// The leg attaches its anchor by adding three lines here and the restoration
/// takes them out again. The file is the host's own: the leg never writes a
/// policy of its own into it, and the product never writes to it at all.
const PF_CONF: &str = "/etc/pf.conf";

/// The shell listing of the management-service processes.
///
/// The listing is a shell pipeline rather than a bare `ps`, so the harness's
/// own pipeline does not match its own pattern.
const SERVE_PROCESS_LISTING: &str = "ps -o pid,ppid,stat,command -ax | grep '[w]g-basic serve'";

/// The rule classes the administrator's parent invokes the managed anchor in.
///
/// PF keeps the filter table and the NAT table apart, and each is attached by
/// its own parent rule, so a masquerading policy needs both of them and a
/// parent that carries only one of them attaches only one. The leg writes the
/// parent in each shape it needs in order to prove a refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleClass {
    /// The filter table's parent rule: `anchor "<name>" all`.
    Filter,
    /// The NAT table's parent rule: `nat-anchor "<name>" all`.
    Nat,
}

/// The process identifiers of the running management-service processes.
fn serve_process_ids() -> Vec<u32> {
    let output = Command::new("sh")
        .args(["-c", SERVE_PROCESS_LISTING])
        .output()
        .expect("the process listing must run");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|field| field.parse::<u32>().ok())
        .collect()
}

/// Whether no management-service process is left running.
///
/// The process list is the direct evidence, and it is what the diagnosis waits
/// for: a process that is still draining holds the write-ahead log, and the
/// doctor's immutable inspection refuses a log that carries transactions.
fn serve_process_is_gone() -> bool {
    serve_process_ids().is_empty()
}

/// Whether the state directory's write-ahead log still carries transactions.
fn state_log_is_empty() -> bool {
    let wal = format!("{}-wal", launchd::STATE_PATH);
    let shm = format!("{}-shm", launchd::STATE_PATH);
    !Path::new(&wal).exists() && !Path::new(&shm).exists()
}

/// Runs a command as root and returns its exit status with both streams.
///
/// `pfctl` prints a warning on stderr for every load — including the
/// anchor-scoped ones — and that warning is not an error, so the leg keeps the
/// stderr in the evidence and judges the command by its exit status alone.
fn root_command(evidence: &mut Evidence, program: &str, args: &[&str]) -> (bool, String, String) {
    let output = Command::new("sudo")
        .arg(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn sudo {program}: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    evidence.log(&format!("$ sudo {program} {}", args.join(" ")));
    if !stdout.trim().is_empty() {
        evidence.log(stdout.trim());
    }
    if !stderr.trim().is_empty() {
        evidence.log(&format!("the command's diagnostics: {}", stderr.trim()));
    }
    (output.status.success(), stdout, stderr)
}

/// What the doctor reports about the gateway.
struct Verdict {
    /// The verdict's own summary.
    summary: String,
    /// The verdict's evidence.
    evidence: String,
    /// The verdict's remediation.
    remediation: String,
    /// The verdict's disposition.
    disposition: String,
    /// Whether the reconcile converged.
    converged: bool,
    /// Why the reconcile failed, when it did.
    reconcile_failure: Option<String>,
}

/// Stops the management service so the state can be inspected offline.
///
/// The doctor's own state inspection is immutable by contract, so it refuses
/// while the service still holds the write-ahead log. The service is asked to
/// stop first, and launchd's own job state is not a reliable proof that it
/// did: the job can be marked stopped while the process is still draining.
/// The product's state lease is the authoritative signal, and the doctor
/// reports it, so the diagnosis waits for the lease to be free before it
/// believes a refusal.
fn stop_the_service(evidence: &mut Evidence) {
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
    // The term is sent first and its outcome is asserted against the process
    // that was running before it. A process that is still there afterwards is
    // either the same process that ignored the term, or a successor that
    // launchd started because the term worked: only the identifier tells the
    // two apart.
    let before = serve_process_ids();
    evidence.log(&format!("the serve processes before the term: {before:?}"));
    // The job may already be unloaded: the diagnosis stops the service and
    // the teardown stops it again, and launchd's "no such service" is the
    // same fact as a service that is down. What matters is that no serve
    // process is left, and that is asserted below.
    let disabled = sh_unchecked(evidence, "launchctl", &["disable", &serve_job]);
    evidence.log(&format!("the job disable answered: {disabled:?}"));
    let term = sh_unchecked(evidence, "launchctl", &["kill", "SIGTERM", &serve_job]);
    evidence.log(&format!("the term answered: {term:?}"));
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
    // not act on the term, and the unload is what stops launchd from bringing
    // it back. The job is *not* disabled: a disabled job is registered but
    // never starts, which is the wrong shape for a service that has to come
    // back afterwards.
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
    // database, and the doctor's immutable inspection needs exactly that.
    wait_until(
        "the state write-ahead log drained",
        Duration::from_secs(60),
        state_log_is_empty,
    );
    let state_listing = sh(evidence, "sudo", &["ls", "-la", launchd::STATE_DIR]);
    evidence.log(&format!(
        "the state directory after the stop:\n{state_listing}"
    ));
}

/// Registers the management service again and waits for it to run.
///
/// The job was unloaded for the offline diagnosis, so it is registered again
/// before the leg carries on.
fn start_the_service(evidence: &mut Evidence) {
    let serve_job = format!("system/{}", launchd::SERVE_LABEL);
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
}

/// Runs the doctor and reads the gateway's verdict.
///
/// The doctor is run while the management service is down, because its
/// immutable inspection refuses a state store that still carries
/// transactions, and the service is registered again afterwards whether the
/// verdict was a pass or a failure.
fn diagnose(evidence: &mut Evidence, reconcile: bool) -> Verdict {
    stop_the_service(evidence);

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
        //
        // The reconcile prints `-> converged` or `-> not converged`, and the
        // second contains the first: a check for "converged" alone would
        // report a run that said it did **not** converge as a convergence.
        converged = text.contains("-> converged");
        if !outcome.status.success() {
            reconcile_failure = Some(errors);
        }
    }

    let mut verdict: Option<Verdict> = None;
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
                .and_then(|checks| checks.iter().find(|check| check["id"] == "gateway"))
            {
                verdict = Some(Verdict {
                    summary: check["summary"].as_str().unwrap_or_default().to_owned(),
                    evidence: check["evidence"].as_str().unwrap_or_default().to_owned(),
                    remediation: check["remediation"].as_str().unwrap_or_default().to_owned(),
                    disposition: check["disposition"].as_str().unwrap_or_default().to_owned(),
                    converged,
                    reconcile_failure,
                });
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    start_the_service(evidence);

    if verdict.is_none() {
        // The doctor never reported the gateway's verdict, so the run has to
        // say why. The service's own state, the holder of the state lease, the
        // product's processes, and its logs are the evidence a failing run has
        // to carry.
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

    verdict.expect("the doctor reports the gateway verdict")
}

/// The verdict as the evidence file carries it.
///
/// The verdict's own evidence and remediation are kept with its summary: a
/// refusal that names what is missing is the whole point of the negative
/// cases, and the evidence has to carry the wording the product used.
fn log_verdict(evidence: &mut Evidence, verdict: &Verdict) {
    evidence.log(&format!(
        "the gateway's disposition: {}",
        verdict.disposition
    ));
    evidence.log(&format!("the gateway's summary: {}", verdict.summary));
    evidence.log(&format!("the gateway's evidence: {}", verdict.evidence));
    evidence.log(&format!(
        "the gateway's remediation: {}",
        verdict.remediation
    ));
}

/// The installation's identity and the anchor it owns.
///
/// The anchor is installation-scoped, so it is this installation's and nothing
/// else on the host, and the product derives its name the same way.
fn managed_anchor(evidence: &mut Evidence) -> (InstallationId, String) {
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
    let identity = installation
        .parse::<InstallationId>()
        .expect("the installation id is a uuid");
    let anchor = firewall::anchor_name(identity);
    evidence.log(&format!("the installation's anchor is {anchor}"));
    (identity, anchor)
}

/// Puts the host's shared state back into the pre-test shape.
///
/// The forwarding sysctls are shared with everything else that routes on this
/// host, so the product only ever reads them. The leg restores them to the
/// disabled state its first assertion expects, and it does so as the
/// administrator: the product never writes them.
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
    sh_unchecked(evidence, "sysctl", &["-w", "net.inet.ip.forwarding=0"]);
    sh_unchecked(evidence, "sysctl", &["-w", "net.inet6.ip6.forwarding=0"]);
}

/// Puts the installation's own packet-filter state back into the pre-test shape.
///
/// An earlier run that stopped between its attachment and its restoration
/// leaves its attachment lines in the host's own configuration and its
/// anchor's rules loaded. The leg takes both out before it measures the
/// baseline, so the baseline is the host's own state and not the last run's.
fn reset_anchor_state(evidence: &mut Evidence, anchor: &str) {
    // The host's own anchors directory is where the installation's anchor
    // lives. The host ships it, and the leg creates it if it is missing.
    root_command(evidence, "mkdir", &["-p", PF_ANCHORS_DIR]);
    // The anchor's own lines leave the host's own configuration first, so the
    // reload that follows does not pull the anchor's file in.
    remove_anchor_lines(evidence, anchor);
    // The anchor's own rules are emptied in both classes: `-F rules` alone
    // leaves the NAT rules loaded.
    for class in ["rules", "nat"] {
        root_command(evidence, "/sbin/pfctl", &["-a", anchor, "-F", class]);
    }
    // The anchor's file and the drift control's file go too: they are the
    // leg's own files, and a file that is left behind is residue.
    root_command(evidence, "rm", &["-f", &anchor_file_path(anchor)]);
    root_command(
        evidence,
        "rm",
        &["-f", &format!("{}.drift", anchor_file_path(anchor))],
    );
    // The host's own ruleset is reloaded so the loaded state matches the
    // configuration file again. This is the administrator's action, and it is
    // the same load the product must never perform.
    root_command(evidence, "/sbin/pfctl", &["-f", PF_CONF]);
}

/// The file the managed anchor's rules live in.
///
/// The anchor is named after the installation, and this is the one file the
/// product writes for it and the one the restoration removes.
fn anchor_file_path(anchor: &str) -> String {
    format!("{PF_ANCHORS_DIR}/{anchor}")
}

/// Removes the leg's own attachment lines from the host's own configuration.
///
/// The pattern names this installation's anchor and nothing else, so the
/// host's own rules are not touched.
fn remove_anchor_lines(evidence: &mut Evidence, anchor: &str) {
    let original = std::fs::read_to_string(PF_CONF)
        .expect("the host's packet-filter configuration must be readable");
    let kept: Vec<&str> = original
        .lines()
        .filter(|line| !line.contains(anchor))
        .collect();
    if kept.len() == original.lines().count() {
        evidence.log("the host's configuration carried no line for this anchor");
        return;
    }
    let mut content = kept.join("\n");
    content.push('\n');
    std::fs::write(PF_CONF, &content).expect("write the host's packet-filter configuration");
    evidence.log(&format!(
        "the host's packet-filter configuration no longer names the anchor:\n{content}"
    ));
}

/// Where a translation rule belongs in the host's own configuration.
///
/// PF requires the rules of one ruleset in the order *options, normalization,
/// queueing, translation, filtering*, so the `nat-anchor` line belongs in the
/// translation section — before the stock `anchor "com.apple/*"` line — and
/// the `anchor` and `load anchor` lines belong at the end. Appending all
/// three lines to the end of the file makes the main ruleset fail to load,
/// and a main ruleset that fails to load leaves the kernel holding the
/// previous one.
fn translation_section_position(lines: &[String]) -> Option<usize> {
    lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("anchor \"")
            || trimmed.starts_with("pass ")
            || trimmed.starts_with("block ")
            || trimmed.starts_with("return ")
    })
}

/// The host's packet-filter configuration with the administrator's attachment.
///
/// The function is pure so that the placement can be proved without a host.
fn attachment_configuration(
    original: &str,
    anchor: &str,
    anchor_path: &str,
    classes: &[RuleClass],
) -> Result<String, String> {
    let attachment = firewall::operator_attachment(anchor, anchor_path);
    let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
    // The leg's own attachment from an earlier run is removed first, so the
    // placement is decided here and not by what an earlier run left behind.
    lines.retain(|line| !line.contains(anchor));
    if classes.contains(&RuleClass::Nat) {
        let Some(position) = translation_section_position(&lines) else {
            return Err(format!(
                "the host's packet-filter configuration has no filtering section to place the translation rule in front of: {original}"
            ));
        };
        lines.insert(position, attachment.nat_anchor.clone());
    }
    if classes.contains(&RuleClass::Filter) {
        lines.push(attachment.filter_anchor.clone());
    }
    // The `load anchor` line is what pulls the anchor's file into the anchor.
    // It is written in every shape: the anchor's file has to exist for the
    // parent's own load to resolve.
    lines.push(attachment.load_anchor.clone());
    let mut content = lines.join("\n");
    content.push('\n');
    Ok(content)
}

/// Whether a ruleset invokes the managed anchor in one rule class.
///
/// The rule has to **invoke** the anchor and not merely mention it: the
/// rule's first token is the keyword of the table it belongs to, and its
/// second token is the managed anchor's name as a whole token. A `load anchor`
/// line names the anchor without invoking it, so the measurement cannot be
/// satisfied by the file's own definition.
fn invokes_anchor(ruleset: &str, keyword: &str, anchor: &str) -> bool {
    let quoted = format!("\"{anchor}\"");
    ruleset.lines().any(|line| {
        let mut tokens = line.split_whitespace();
        match (tokens.next(), tokens.next()) {
            (Some(first), Some(second)) => {
                first == keyword && (second == quoted || second == anchor)
            }
            _ => false,
        }
    })
}

/// The administrator attaches the managed anchor and reloads the host's ruleset.
///
/// This is the administrator's action under TN3165: the product never writes
/// `/etc/pf.conf`, so the parent and its placement are the operator's.
fn attach_anchor(evidence: &mut Evidence, anchor: &str, anchor_path: &str, classes: &[RuleClass]) {
    let original = std::fs::read_to_string(PF_CONF)
        .expect("the host's packet-filter configuration must be readable");
    let content = attachment_configuration(&original, anchor, anchor_path, classes)
        .expect("the host's configuration has a filtering section");
    std::fs::write(PF_CONF, &content).expect("write the host's packet-filter configuration");
    evidence.log(&format!(
        "the host's packet-filter configuration now carries the attachment:\n{content}"
    ));
    // The host's own ruleset is reloaded so the attachment is effective. This
    // is the administrator's load of the host's own configuration; the product
    // must never perform it, and the leg measures that it does not.
    let (ok, _, stderr) = root_command(evidence, "/sbin/pfctl", &["-f", PF_CONF]);
    assert!(
        ok,
        "the host's own packet-filter configuration must load: {stderr}"
    );
    let ruleset = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    let nat = sh_unchecked(evidence, "/sbin/pfctl", &["-s", "nat"]);
    evidence.log(&format!(
        "the main filter ruleset after the attachment:\n{ruleset}"
    ));
    evidence.log(&format!(
        "the main NAT ruleset after the attachment:\n{}",
        nat.1
    ));
    // The attachment is measured, not assumed: the loaded parent invokes the
    // anchor in exactly the classes the leg asked for, and in no other.
    assert_eq!(
        invokes_anchor(&ruleset, "anchor", anchor),
        classes.contains(&RuleClass::Filter),
        "the main filter ruleset must invoke the anchor exactly as the leg asked: {ruleset}"
    );
    assert_eq!(
        invokes_anchor(&nat.1, "nat-anchor", anchor),
        classes.contains(&RuleClass::Nat),
        "the main NAT ruleset must invoke the anchor exactly as the leg asked: {}",
        nat.1
    );
}

/// The administrator enables the host's packet filter.
///
/// The host's filter is enabled so the attachment is effective. A host that
/// was already filtering keeps filtering, and `pfctl -e` exits non-zero when
/// the filter is already enabled, so the command's status is recorded rather
/// than asserted.
fn enable_the_filter(evidence: &mut Evidence) {
    let (ok, _, stderr) = root_command(evidence, "/sbin/pfctl", &["-e"]);
    evidence.log(&format!(
        "the administrator enabled the packet filter (the command reported ok: {ok}): {stderr}"
    ));
}

/// One anchor of the host's packet filter, as it is loaded.
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
/// The context is recorded before the leg attaches anything, so a leg that
/// fails between the attachment and the end is restored as well.
struct FilterContext {
    /// The anchor the leg attached.
    anchor: String,
    /// The anchor's file.
    anchor_path: String,
    /// The host's filter state before the leg attached anything.
    baseline: FilterInventory,
}

/// What the host's packet filter and forwarding switches hold at one moment.
///
/// The claim that the product never loaded the root ruleset, never flushed a
/// table, never toggled PF, and never wrote the forwarding switches is a
/// claim about a *difference*, so it needs two of these: one taken before the
/// product's action and one taken after it.
#[derive(Clone)]
struct FilterSnapshot {
    /// Whether the packet filter is enabled.
    pf_enabled: bool,
    /// The main filter ruleset.
    parent_filter: String,
    /// The main NAT ruleset.
    parent_nat: String,
    /// The host's IPv4 forwarding switch.
    forwarding_v4: String,
    /// The host's IPv6 forwarding switch.
    forwarding_v6: String,
}

/// Reads one anchor's own loaded rulesets.
///
/// An anchor that was never loaded cannot be read, and PF reports that as a
/// failure on stderr while exiting zero, so the anchor is recorded as holding
/// nothing and the message is kept in the evidence.
fn anchor_inventory(evidence: &mut Evidence, name: &str) -> AnchorInventory {
    let filter_rules = anchor_class_rules(evidence, name, "rules");
    let nat_rules = anchor_class_rules(evidence, name, "nat");
    AnchorInventory {
        name: name.to_owned(),
        filter_rules,
        nat_rules,
    }
}

/// One anchor class's loaded rules.
///
/// macOS signals an anchor that does not exist with `DIOCGETRULES: Invalid
/// argument` on stderr and a **zero** exit status, so the exit status cannot
/// tell an absent anchor from an emptied one. The leg keeps both streams in
/// the evidence and reads the rules from the standard output.
fn anchor_class_rules(evidence: &mut Evidence, anchor: &str, class: &str) -> String {
    let (ok, stdout, stderr) = root_command(evidence, "/sbin/pfctl", &["-a", anchor, "-s", class]);
    if !ok {
        evidence.log(&format!(
            "the anchor {anchor}'s {class} rules could not be read: {stderr}"
        ));
    }
    stdout
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
/// The listing is what the residue is looked for in: the installation's own
/// anchor file and the drift control's `.drift` sibling are files in here,
/// and a file that is left behind is residue.
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
/// The capture is read-only. It is taken before the leg attaches anything, so
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

/// Captures the host's filter and forwarding state at one moment.
fn capture_filter_snapshot(evidence: &mut Evidence) -> FilterSnapshot {
    let status = sh(evidence, "/sbin/pfctl", &["-s", "info"]);
    let pf_enabled = status
        .lines()
        .any(|line| line.trim_start().starts_with("Status: Enabled"));
    let parent_filter = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    let parent_nat = sh_unchecked(evidence, "/sbin/pfctl", &["-s", "nat"]).1;
    let forwarding_v4 = sh(evidence, "sysctl", &["-n", "net.inet.ip.forwarding"]);
    let forwarding_v6 = sh(evidence, "sysctl", &["-n", "net.inet6.ip6.forwarding"]);
    let snapshot = FilterSnapshot {
        pf_enabled,
        parent_filter,
        parent_nat,
        forwarding_v4,
        forwarding_v6,
    };
    evidence.log(&format!(
        "the filter and forwarding snapshot:\n{}",
        describe_snapshot(&snapshot)
    ));
    snapshot
}

/// The snapshot as the evidence file carries it.
fn describe_snapshot(snapshot: &FilterSnapshot) -> String {
    format!(
        "the packet filter is {}\nthe main filter ruleset:\n{}\nthe main NAT ruleset:\n{}\nforwarding is {} / {}",
        if snapshot.pf_enabled {
            "enabled"
        } else {
            "disabled"
        },
        snapshot.parent_filter,
        snapshot.parent_nat,
        snapshot.forwarding_v4.trim(),
        snapshot.forwarding_v6.trim(),
    )
}

/// What changed between two snapshots of the host's filter and forwarding.
///
/// An empty list is the proof that the product did none of the forbidden
/// things: it did not load the root ruleset, it did not flush a table, it did
/// not toggle PF, and it did not write the forwarding switches.
fn snapshot_differences(before: &FilterSnapshot, after: &FilterSnapshot) -> Vec<String> {
    let mut differences = Vec::new();
    if before.pf_enabled != after.pf_enabled {
        differences.push(format!(
            "the packet filter's enable state changed from {} to {}",
            before.pf_enabled, after.pf_enabled
        ));
    }
    if before.parent_filter != after.parent_filter {
        differences.push("the main filter ruleset changed".to_owned());
    }
    if before.parent_nat != after.parent_nat {
        differences.push("the main NAT ruleset changed".to_owned());
    }
    if before.forwarding_v4 != after.forwarding_v4 {
        differences.push(format!(
            "the IPv4 forwarding switch changed from {} to {}",
            before.forwarding_v4.trim(),
            after.forwarding_v4.trim()
        ));
    }
    if before.forwarding_v6 != after.forwarding_v6 {
        differences.push(format!(
            "the IPv6 forwarding switch changed from {} to {}",
            before.forwarding_v6.trim(),
            after.forwarding_v6.trim()
        ));
    }
    differences
}

/// The commands that put the host's packet filter back the way the leg found it.
///
/// The list is the teardown's exact argv, so it can be asserted on without a
/// host and so the teardown cannot drift away from what the qualification
/// claims it does.
///
/// The order is the order the operations depend on:
///
/// 1. The anchor's own rules are flushed first, and in two steps. Emptying an
///    anchor takes one flush per class, `pfctl -a <anchor> -F rules` for the
///    filter rules and `pfctl -a <anchor> -F nat` for the NAT rules; `-F
///    rules` alone leaves the NAT rules loaded. A bare `pfctl -F all` flushes
///    the **main** ruleset, which the leg does not own and never flushes.
/// 2. The anchor's lines come out of the host's own configuration and the
///    main ruleset is reloaded, so the reload no longer pulls the anchor's
///    file in.
/// 3. The anchor's file and its `.drift` sibling are removed. They come last
///    because `pfctl` reads an anchor's file when it flushes it.
/// 4. The filter's enable state is put back last. The leg enables the filter
///    to make the administrator's attachment effective, and the host's own
///    state is what is restored: a host that was filtering keeps filtering,
///    and a host that was not filtering stops filtering.
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
    // The anchors directory as a whole: the leg's own file is gone above, and
    // the directory has to hold what it held before the leg touched it.
    let mut baseline_files = baseline.anchor_files.clone();
    let mut after_files = after.anchor_files.clone();
    baseline_files.sort();
    after_files.sort();
    if baseline_files != after_files {
        residue.push(format!(
            "the anchors directory differs from the baseline: it held {baseline_files:?} and holds {after_files:?}"
        ));
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

/// Whether a ping transcript shows that the target answered.
///
/// The transcript prints one `bytes from` line per reply, so the presence of
/// that line is the answer. The packet-loss summary alone is **not** a safe
/// signal: the string `100% packet loss` contains `0% packet loss`, so a
/// transcript in which every packet was lost satisfies a check for `0% packet
/// loss`. A qualification that reads the loss summary that way proves nothing
/// at all.
fn answered(transcript: &str) -> bool {
    transcript.contains("bytes from")
}

/// The source address the far side observed for the traffic towards `address`.
///
/// Only the far side can say what arrived. The appliance's own state table
/// shows what it translated, and a leg that reads only the appliance's own
/// view cannot tell a translated source from an untranslated one, so the peer
/// driver has to report it: `observed-source` for IPv4 and `observed-source6`
/// for IPv6, each printing the observed address on one line.
fn observed_source(
    evidence: &mut Evidence,
    driver: &Path,
    subcommand: &str,
    address: &str,
) -> String {
    let output = Command::new(driver)
        .args([subcommand, address])
        .output()
        .unwrap_or_else(|error| panic!("failed to run the peer driver: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    evidence.log(&format!("$ peer {subcommand} {address}"));
    evidence.log(stdout.trim());
    if !stderr.trim().is_empty() {
        evidence.log(&format!("the peer driver's diagnostics: {}", stderr.trim()));
    }
    assert!(
        output.status.success(),
        "the peer driver must report the source address the far side observed: `{subcommand} {address}` failed: {stderr}"
    );
    let observed = stdout.trim().to_owned();
    assert!(
        !observed.is_empty(),
        "the peer driver reported no observed source address for {address}"
    );
    observed
}

/// The interface the host's route towards `destination` uses.
///
/// The gateway's egress is the interface the host's own default route uses: a
/// gateway translates towards the Internet, and the Internet is where the
/// default route leads.
fn route_interface(evidence: &mut Evidence, destination: &str) -> String {
    let route = sh(evidence, "route", &["-n", "get", destination]);
    route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| {
            panic!("the route towards {destination} must name an interface: {route}")
        })
}

/// The interface's IPv6 address, when it has a global one.
///
/// The link-local address is not a candidate: the far side can never observe
/// it as the source of a translated packet.
fn interface_ipv6(evidence: &mut Evidence, interface: &str) -> Option<String> {
    let listing = sh(evidence, "ifconfig", &[interface]);
    listing
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet6 "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|address| address.split('%').next().unwrap_or(address).to_owned())
        .find(|address| !address.starts_with("fe80"))
}

/// The device the product's own installed rules name.
///
/// The anchor's filter rules are the product's statement about which device
/// carries the managed tunnel, so the leg reads the device from them rather
/// than guessing it from the host's `utun` inventory.
fn managed_device(rules: &str) -> Option<String> {
    let first = rules
        .lines()
        .find(|line| line.trim_start().starts_with("pass "))?;
    let tokens: Vec<&str> = first.split_whitespace().collect();
    let position = tokens.iter().position(|token| *token == "on")?;
    tokens.get(position + 1).map(|name| (*name).to_owned())
}

/// The gateway policy the leg asked for, rendered by the product's renderer.
///
/// The expected rules are rendered with the product's own renderer rather
/// than spelled out here, so the comparison is between what the product wrote
/// and what the product says it writes. The shape the leg holds fixed is
/// checked separately: one IPv4 masquerade rule, and no NAT rule at all for
/// the IPv6 pool.
fn expected_rules(egress: &str, device: &str) -> PfRuleSet {
    let prefixes: Vec<NetworkPrefix> = [TUNNEL_V4, TUNNEL_V6]
        .iter()
        .map(|prefix| {
            prefix
                .parse::<NetworkPrefix>()
                .expect("the tunnel pools are prefixes")
        })
        .collect();
    firewall::render_policy(
        &prefixes,
        &InterfaceName::new(egress).expect("the egress interface name"),
        &InterfaceName::new(device).expect("the tunnel device name"),
        true,
    )
}

/// The C004 live leg: a gateway that translates IPv4 and routes IPv6.
///
/// The leg's body is a function of its own, because the host's packet filter
/// has to be restored whether the leg reached its end or failed part-way
/// through it. A leg that panicked half-way through would leave the
/// administrator's attachment in the host's own configuration and the filter
/// enabled, and a later run would inherit them.
#[test]
#[ignore = "needs WGB_DARWIN_LIVE=1 as root on a disposable macOS host"]
fn live_c004_gateway_translates_the_ipv4_source_and_routes_the_ipv6_source() {
    let mut evidence = Evidence::new("c004-gateway-ipv4-egress");
    // The leg's own filter context, so the restoration knows what to put
    // back even when the leg never reached its own teardown.
    let mut context: Option<FilterContext> = None;
    // The panic is caught here so the restoration runs after it rather than
    // being skipped by it, and the leg's own failure is re-raised once the
    // host is back the way it was found.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        run_gateway_leg(&mut evidence, &mut context);
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
            evidence.log(
                "the leg never touched the host's packet filter, so there is nothing to restore",
            );
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

/// The C004 live leg's body.
///
/// The body proves the gateway: it attaches the managed anchor as the
/// administrator, watches the product converge, watches the far side observe
/// a translated IPv4 source and an untranslated IPv6 source, proves each
/// refusal, and takes the peer down again. The host's packet filter is
/// restored by the caller, so that the restoration also happens when the leg
/// fails part-way through.
fn run_gateway_leg(evidence: &mut Evidence, context: &mut Option<FilterContext>) {
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

    // The gateway's egress is the interface the host's own default route
    // uses, and the peer is reached through that same interface: the far side
    // is downstream of the peer host, so the reply to a translated packet
    // comes back through the very interface the packet left on. The two
    // interfaces have to be the same one, or the far side's reply would be
    // addressed to an address the peer host cannot route back to.
    let egress = route_interface(evidence, "default");
    let peer_interface = route_interface(evidence, &peer_address);
    assert_eq!(
        egress, peer_interface,
        "the lab's egress towards the far side must be the default route's interface: the egress is {egress} and the peer is reached through {peer_interface}"
    );
    let egress_address = interface_ipv4(evidence, &egress);
    let egress_address6 = interface_ipv6(evidence, &egress);
    evidence.log(&format!(
        "the gateway's egress is {egress} ({egress_address}{}), and the advertised endpoint is {egress_address}:{LISTEN_PORT}",
        egress_address6
            .clone()
            .map(|address| format!(", {address}"))
            .unwrap_or_default()
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

    // The installation's own anchor, and the host's packet-filter state put
    // back into the pre-test shape. The anchor's name is installation-scoped,
    // so the state the leg cleans up is this installation's alone.
    let (installation, anchor) = managed_anchor(evidence);
    let anchor_path = anchor_file_path(&anchor);
    reset_anchor_state(evidence, &anchor);

    // The host's filter state is captured before the leg attaches anything,
    // so the restoration has a baseline to put back and the claim that the
    // leg left the host's filter as it found it can be measured rather than
    // asserted.
    let baseline = capture_filter_inventory(evidence, &anchor);
    // The context is recorded before the attachment is made, so a leg that
    // fails between the attachment and the end is restored too.
    *context = Some(FilterContext {
        anchor: anchor.clone(),
        anchor_path: anchor_path.clone(),
        baseline,
    });

    // The tunnel device inventory before the managed tunnel exists, so the
    // qualification can tell the managed tunnel from the host's own `utun`
    // devices.
    let utun_before = utun_names();

    // The gateway policy. The tunnel's pools are the sources, the host's own
    // egress interface is the way out, IPv4 is masqueraded and IPv6 is not.
    // A gateway policy names no downstream destination: it forwards anywhere,
    // which is the shape the far side stands in for.
    let setup_body = format!(
        r#"{{"expected_generation":1,"interface_name":"wg0","tunnel_prefix":"{TUNNEL_V4}","ipv6_tunnel_prefix":"{TUNNEL_V6}","server_address":"{SERVER_V4}","ipv6_server_address":"{SERVER_V6}","listen_port":{LISTEN_PORT},"advertised_endpoint":"{egress_address}:{LISTEN_PORT}","egress_interface":"{egress}","ipv4_forwarding_required":true,"ipv6_forwarding_required":true,"masquerade":true,"mode":"gateway","default_client_route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}}}}"#
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
        "the gateway setup answered {setup_status}: {setup_text}"
    ));
    assert!(
        setup_status == 200 || setup_status == 202,
        "the policy itself is valid and must be accepted: {setup_text}"
    );
    // The policy is accepted, but the gateway itself is not converged: the
    // prerequisites are not in place yet, and the receipt says so instead of
    // claiming a convergence that did not happen.
    let receipt: serde_json::Value = serde_json::from_str(&setup_text).expect("the setup receipt");
    assert_eq!(
        receipt["degraded_category"], "backend_refused",
        "the gateway must be refused while its prerequisites are missing: {setup_text}"
    );
    assert_eq!(
        receipt["enforcement"], "degraded",
        "the refusal must be reported as degraded enforcement: {setup_text}"
    );

    // The managed tunnel comes up even though the gateway cannot be proven
    // yet: the interface is created first, and the firewall contract is
    // checked afterwards.
    wait_until("the managed tunnel", Duration::from_secs(90), || {
        utun_names().len() > utun_before.len()
    });
    let utun_after = utun_names();
    let new_devices: Vec<&String> = utun_after
        .iter()
        .filter(|name| !utun_before.contains(name))
        .collect();
    evidence.log(&format!(
        "the host's tunnel devices before the setup: {utun_before:?}, after: {utun_after:?}, new: {new_devices:?}"
    ));
    // The managed device's own addresses and routes. The pool route the
    // return path depends on is part of the evidence, and so is every
    // interface the host already had, so that a later reader can tell the
    // managed device from the host's own tunnels.
    let mut tunnel_inventory = String::new();
    for name in &utun_after {
        tunnel_inventory.push_str(&sh(evidence, "ifconfig", &[name]));
        tunnel_inventory.push('\n');
    }
    evidence.log(&format!("the tunnel interfaces:\n{tunnel_inventory}"));
    let tunnel_routes = sh(evidence, "netstat", &["-rn", "-f", "inet"]);
    let tunnel_routes6 = sh(evidence, "netstat", &["-rn", "-f", "inet6"]);
    evidence.log(&format!(
        "the routes with the managed tunnel up:\n{tunnel_routes}\n{tunnel_routes6}"
    ));

    // The first refusal: the host's forwarding is off, so the gateway is
    // refused and the refusal names forwarding.
    let verdict = diagnose(evidence, false);
    log_verdict(evidence, &verdict);
    assert!(
        verdict.summary.contains("forwarding"),
        "the first missing prerequisite is the host's forwarding: {}",
        verdict.summary
    );

    // The administrator enables the host's global forwarding. It is shared
    // with everything else that routes on this host, so the product reads it
    // and never writes it.
    sh(
        evidence,
        "sudo",
        &["sysctl", "-w", "net.inet.ip.forwarding=1"],
    );
    sh(
        evidence,
        "sudo",
        &["sysctl", "-w", "net.inet6.ip6.forwarding=1"],
    );

    // The second refusal: the administrator's parent does not invoke the
    // managed anchor at all, so the gateway is refused and the refusal names
    // the attachment.
    let verdict = diagnose(evidence, false);
    log_verdict(evidence, &verdict);
    assert_attachment_refusal(&verdict);

    // The third refusal: the parent invokes the anchor in the filter class
    // only. A masquerading policy needs both classes, so the gateway is
    // refused and the refusal names the attachment.
    //
    // The anchor's file has to exist before the parent is loaded: with the
    // `load anchor` line present and the file absent, the host's whole
    // packet-filter configuration fails to load and the kernel keeps the
    // previous ruleset. An empty file is enough, and it is created here,
    // before the first attachment, because every attachment below reloads the
    // host's own configuration.
    root_command(evidence, "touch", &[&anchor_path]);
    attach_anchor(evidence, &anchor, &anchor_path, &[RuleClass::Filter]);
    let verdict = diagnose(evidence, false);
    log_verdict(evidence, &verdict);
    assert_attachment_refusal(&verdict);

    // The fourth refusal: the parent invokes the anchor in the NAT class
    // only, which is just as incomplete.
    attach_anchor(evidence, &anchor, &anchor_path, &[RuleClass::Nat]);
    let verdict = diagnose(evidence, false);
    log_verdict(evidence, &verdict);
    assert_attachment_refusal(&verdict);

    // The administrator's attachment, in full.
    attach_anchor(
        evidence,
        &anchor,
        &anchor_path,
        &[RuleClass::Filter, RuleClass::Nat],
    );
    // The administrator enables the host's packet filter, so the attachment
    // is effective.
    enable_the_filter(evidence);

    // The product's own action is measured from both sides: the host's filter
    // and forwarding state before the reconcile and after it. A difference
    // would mean the product loaded the root ruleset, flushed a table,
    // toggled PF, or wrote the forwarding switches.
    let before_apply = capture_filter_snapshot(evidence);
    let verdict = diagnose(evidence, true);
    log_verdict(evidence, &verdict);
    assert!(
        verdict.converged,
        "the reconcile must converge once the administrator's attachment is in place: {}",
        verdict.summary
    );
    assert!(
        verdict.reconcile_failure.is_none(),
        "the reconcile must run to completion: {}",
        verdict.reconcile_failure.clone().unwrap_or_default()
    );
    assert!(
        verdict.summary.contains("in place"),
        "the product must report the gateway as available: {}",
        verdict.summary
    );
    let after_apply = capture_filter_snapshot(evidence);
    let forbidden = snapshot_differences(&before_apply, &after_apply);
    assert!(
        forbidden.is_empty(),
        "the product must not load the root ruleset, flush a table, toggle PF, or write the forwarding switches, and it did: {forbidden:?}"
    );

    // The anchor's own two classes, and the file the product wrote for it.
    // The filter class and the NAT class are separate rulesets, and both have
    // to hold exactly the rendered policy.
    let filter_rules = anchor_class_rules(evidence, &anchor, "rules");
    let nat_rules = anchor_class_rules(evidence, &anchor, "nat");
    let device = managed_device(&filter_rules).expect(
        "the product's installed rules must name the device that carries the managed tunnel",
    );
    assert!(
        new_devices.iter().any(|name| **name == device),
        "the device the product bound its rules to must be one of the tunnel devices that appeared with the managed tunnel: {device} is not among {new_devices:?}"
    );
    let expected = expected_rules(&egress, &device);
    assert!(
        firewall::anchor_content_matches(&filter_rules, &expected),
        "the anchor's filter class must hold exactly the rendered policy: it holds {filter_rules:?} and the rendered policy is {:?}",
        expected.filter
    );
    assert!(
        firewall::nat_content_matches(&nat_rules, &expected),
        "the anchor's NAT class must hold exactly the rendered policy: it holds {nat_rules:?} and the rendered policy is {:?}",
        expected.nat
    );
    // The shape the leg holds fixed: one IPv4 masquerade rule, and no NAT
    // rule at all for the IPv6 pool. There is no NAT66.
    assert_eq!(
        expected.nat.len(),
        1,
        "a gateway that masquerades IPv4 renders exactly one translation rule: {:?}",
        expected.nat
    );
    assert!(
        expected.nat[0].contains(TUNNEL_V4),
        "the translation rule must name the IPv4 pool: {}",
        expected.nat[0]
    );
    assert!(
        !expected.nat[0].contains("2001:db8"),
        "there is no NAT66: the translation rule must not name the IPv6 pool: {}",
        expected.nat[0]
    );
    assert!(
        expected.filter.iter().any(|rule| rule.contains(TUNNEL_V6)),
        "the IPv6 pool must be routed rather than translated: {:?}",
        expected.filter
    );
    // The product's own file for the anchor: the marker, then the
    // translation rules, then the filtering rules. The order is the contract,
    // because PF refuses a file whose translation rules follow its filtering
    // rules.
    let file = std::fs::read_to_string(&anchor_path).expect("the anchor's file must be readable");
    assert_eq!(
        file,
        firewall::anchor_file_content(installation, &expected),
        "the anchor's file must be exactly what the product writes: it holds {file:?}"
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
        r#"{{"expected_generation":{generation},"interface_id":"{interface_id}","label":"gateway-peer","route_policy":{{"prefixes":["0.0.0.0/0","::/0"]}},"client_keepalive_seconds":{CLIENT_KEEPALIVE}}}"#
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
        std::env::temp_dir().join(format!("wgb-c004-client-{}.conf", std::process::id()));
    std::fs::write(&exported, &config_text).expect("write the exported configuration");

    // The peer installs the configuration with the far side's ranges in its
    // AllowedIPs, so the gateway's traffic goes into the tunnel.
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

    // The gateway's IPv4 traffic: the peer sends towards the far side, and
    // the far side answers. The reply is the return path: it was addressed to
    // the gateway's egress address, and it arrived at the peer through the
    // same tunnel.
    let downstream = peer_run(evidence, &driver, &["ping-lan", FAR_SIDE]);
    evidence.log(&format!("the far-side probe: {downstream}"));
    assert!(
        answered(&downstream),
        "the far side must answer the gateway's traffic: {downstream}"
    );

    // The far side's view of the IPv4 source. The product's translation is
    // only real if the far side observes the gateway's egress address, and
    // the client's own tunnel address must not be what arrives.
    let observed4 = observed_source(evidence, &driver, "observed-source", FAR_SIDE);
    evidence.log(&format!(
        "the far side observed the IPv4 source {observed4} (the gateway's egress address is {egress_address}, the client's tunnel address is {client_address})"
    ));
    assert_eq!(
        observed4, egress_address,
        "the far side must observe the gateway's egress address as the source of an IPv4 packet: it observed {observed4}"
    );
    assert_ne!(
        observed4, client_address,
        "the far side must not observe the client's tunnel address as the source of an IPv4 packet: it observed {observed4}"
    );

    // The gateway's IPv6 traffic. There is no NAT66 anywhere in the path, so
    // the far side observes the client's own tunnel address.
    let downstream6 = peer_run(evidence, &driver, &["ping-lan6", FAR_SIDE6]);
    evidence.log(&format!("the far-side IPv6 probe: {downstream6}"));
    assert!(
        answered(&downstream6),
        "the far side must answer the gateway's IPv6 traffic: {downstream6}"
    );
    let observed6 = observed_source(evidence, &driver, "observed-source6", FAR_SIDE6);
    evidence.log(&format!(
        "the far side observed the IPv6 source {observed6} (the client's tunnel address is {client_address6})"
    ));
    assert_eq!(
        observed6, client_address6,
        "the far side must observe the client's own IPv6 tunnel address as the source of an IPv6 packet: it observed {observed6}"
    );
    if let Some(address) = egress_address6 {
        assert_ne!(
            observed6, address,
            "the far side must not observe the gateway's own address as the source of an IPv6 packet: it observed {observed6}"
        );
    }

    // The appliance's own record of the translated flow, as supporting
    // evidence for the return path: the state entry is what carries the
    // reply back to the client.
    let state = sh_unchecked(evidence, "/sbin/pfctl", &["-s", "state"]);
    evidence.log(&format!("the packet filter's state table:\n{}", state.1));

    // The fifth refusal: the anchor's NAT rules are not the rendered policy.
    // The drift is installed into the anchor itself, so the product sees the
    // anchor's own translation rules as somebody else's.
    let drift_path = format!("{anchor_path}.drift");
    let drift_rule = format!("nat on {egress} from 10.77.0.0/25 to any -> ({egress})\n");
    root_command(
        evidence,
        "sh",
        &["-c", &format!("printf '%s' '{drift_rule}' > {drift_path}")],
    );
    root_command(evidence, "/sbin/pfctl", &["-a", &anchor, "-f", &drift_path]);
    let drifted = anchor_class_rules(evidence, &anchor, "nat");
    evidence.log(&format!(
        "the anchor's NAT rules after the drift: {drifted}"
    ));
    let verdict = diagnose(evidence, false);
    log_verdict(evidence, &verdict);
    assert!(
        verdict.summary.contains("NAT") && verdict.summary.contains("do not match"),
        "a drifted translation rule must be reported as drift: {}",
        verdict.summary
    );
    // The administrator restores the anchor from the product's own file,
    // which still holds the rendered policy. The product never repairs a
    // drifted anchor by guessing, so this is the operator's action.
    root_command(
        evidence,
        "/sbin/pfctl",
        &["-a", &anchor, "-f", &anchor_path],
    );
    let restored = anchor_class_rules(evidence, &anchor, "nat");
    evidence.log(&format!(
        "the anchor's NAT rules after the restoration: {restored}"
    ));
    assert!(
        firewall::nat_content_matches(&restored, &expected),
        "the administrator's restoration must put the rendered translation rules back: it holds {restored:?}"
    );

    // The product's own teardown: disabling the managed network removes the
    // anchor's rules in both classes and leaves the administrator's parent
    // and every foreign rule exactly as they were.
    stop_the_service(evidence);
    let disable = Command::new("sudo")
        .args([
            "-u",
            launchd::SERVE_USER,
            launchd::BINARY_PATH,
            "network",
            "disable",
            "--state",
            launchd::STATE_PATH,
            "--socket",
            launchd::SOCKET_PATH,
        ])
        .output()
        .expect("the network disable must run");
    let disable_text = String::from_utf8_lossy(&disable.stdout).trim().to_owned();
    let disable_errors = String::from_utf8_lossy(&disable.stderr).trim().to_owned();
    evidence.log(&format!(
        "the network disable answered: {disable_text} {disable_errors}"
    ));
    // The diagnostic: what the product's own processes look like at that
    // moment, what the anchor holds, and what the doctor says. The teardown
    // is measured before it is judged, so a refusal is reported with the
    // facts that explain it. The doctor's own answer is captured raw: after a
    // disable the network is off, and the doctor is then under no obligation
    // to report a gateway verdict at all.
    let processes = sh_unchecked(
        evidence,
        "sh",
        &[
            "-c",
            "ps -o pid,ppid,stat,command -ax | grep -E '[w]g-basic|[w]ireguard-go'",
        ],
    );
    evidence.log(&format!(
        "the product's processes after the disable:\n{}",
        processes.1
    ));
    let anchor_after = sh_unchecked(
        evidence,
        "sh",
        &[
            "-c",
            &format!(
                "pfctl -a {anchor} -s rules 2>&1; echo ---; pfctl -a {anchor} -s nat 2>&1; \
                 echo ---; ls -la /etc/pf.anchors/ 2>&1"
            ),
        ],
    );
    evidence.log(&format!(
        "the anchor after the disable:\n{}",
        anchor_after.1
    ));
    let doctor_after = Command::new("sudo")
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
        .expect("the doctor must run after the disable");
    evidence.log(&format!(
        "the doctor after the disable: {}",
        String::from_utf8_lossy(&doctor_after.stdout)
    ));
    assert!(
        disable.status.success(),
        "disabling the managed network must succeed: {disable_errors}"
    );
    // The teardown's own claim is the anchor, not the whole network: the
    // product's teardown empties the anchor's two rule classes and leaves the
    // administrator's parent and every foreign rule exactly as they were.
    //
    // The network disable as a whole is not asserted to be enforced. The
    // managed interface's own deletion is refused on macOS, because the
    // observed address forms do not match the desired ones, and that refusal
    // belongs to a different defect: it is recorded as finding F10 and it is
    // corrected by plan C015. The leg pins the refusal's shape, so a
    // degradation with any other cause still fails here.
    if !disable_text.contains(" and enforced") {
        assert!(
            disable_text.contains("not yet enforced"),
            "the product's teardown must either be enforced or say that it is not: {disable_text}"
        );
        let doctor_text = String::from_utf8_lossy(&doctor_after.stdout);
        assert!(
            doctor_text.contains("ownership conflict"),
            "the teardown may only degrade for the known reason: {doctor_text}"
        );
        evidence.log(
            "the network disable degraded for the known reason: the managed interface's deletion \
             is refused on macOS (finding F10); the anchor's own teardown is measured below",
        );
    }
    let released_filter = anchor_class_rules(evidence, &anchor, "rules");
    let released_nat = anchor_class_rules(evidence, &anchor, "nat");
    evidence.log(&format!(
        "the anchor's filter rules after the product's teardown: {released_filter}"
    ));
    evidence.log(&format!(
        "the anchor's NAT rules after the product's teardown: {released_nat}"
    ));
    assert!(
        released_filter.trim().is_empty(),
        "the product's teardown must empty the anchor's filter class: it holds {released_filter:?}"
    );
    assert!(
        released_nat.trim().is_empty(),
        "the product's teardown must empty the anchor's NAT class: it holds {released_nat:?}"
    );
    // The anchor's file is emptied of its rules and keeps its marker: the
    // administrator's next reload of the host's own configuration must still
    // find a file to load, and the product's ownership of it must survive so
    // that a later mode change can still tell its own file from a foreign
    // one.
    let anchor_file = sh_unchecked(evidence, "cat", &[&anchor_path]);
    evidence.log(&format!(
        "the anchor's file after the product's teardown: {:?}",
        anchor_file.1
    ));
    assert!(
        firewall::owns_anchor_file(&anchor_file.1, installation),
        "the product's teardown must leave the anchor's file in place with its marker: {:?}",
        anchor_file.1
    );
    let parent_after_teardown = sh(evidence, "/sbin/pfctl", &["-s", "rules"]);
    let parent_nat_after_teardown = sh_unchecked(evidence, "/sbin/pfctl", &["-s", "nat"]);
    assert!(
        invokes_anchor(&parent_after_teardown, "anchor", &anchor),
        "the product's teardown must leave the administrator's parent in place: {parent_after_teardown}"
    );
    assert!(
        invokes_anchor(&parent_nat_after_teardown.1, "nat-anchor", &anchor),
        "the product's teardown must leave the administrator's NAT parent in place: {}",
        parent_nat_after_teardown.1
    );
    start_the_service(evidence);

    // The teardown: the peer is taken down and the host is left as it was
    // found. The host's packet filter is restored by the caller, which does
    // it whether the leg reached this point or failed before it.
    peer_run(evidence, &driver, &["teardown"]);
    evidence.log("the off-host peer was torn down");
}

/// Asserts that the gateway was refused because of the administrator's
/// attachment.
///
/// The refusal has to name the attachment and the two rule classes, because a
/// parent that invokes the anchor in one class only is a different fact from
/// a parent that invokes it in neither.
fn assert_attachment_refusal(verdict: &Verdict) {
    assert!(
        verdict.summary.contains("anchor") && verdict.summary.contains("both rule classes"),
        "the refusal must name the administrator's attachment in both rule classes: {}",
        verdict.summary
    );
    assert!(
        verdict.disposition == "fail",
        "a gateway without the administrator's attachment must be reported as a failure: {}",
        verdict.disposition
    );
    assert!(
        !verdict.summary.contains("in place"),
        "a gateway without the administrator's attachment must not be reported as available: {}",
        verdict.summary
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchor the leg's own filter lives in.
    const ANCHOR: &str = "wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163";

    /// The anchor's file.
    const ANCHOR_PATH: &str = "/etc/pf.anchors/wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163";

    /// The host's own configuration, in the shape macOS ships it.
    const STOCK_PF_CONF: &str = "#scrub-anchor \"com.apple/*\"\n#nat-anchor \"com.apple/*\"\n#rdr-anchor \"com.apple/*\"\n#dummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n";

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
    fn the_translation_rule_goes_in_front_of_the_stock_filtering_rule() {
        let configuration = attachment_configuration(
            STOCK_PF_CONF,
            ANCHOR,
            ANCHOR_PATH,
            &[RuleClass::Filter, RuleClass::Nat],
        )
        .expect("the stock configuration has a filtering section");
        let lines: Vec<&str> = configuration.lines().collect();
        let nat = lines
            .iter()
            .position(|line| line.starts_with("nat-anchor"))
            .expect("the translation rule must be there");
        let stock = lines
            .iter()
            .position(|line| line.starts_with("anchor \"com.apple/"))
            .expect("the stock filtering rule must be there");
        assert!(
            nat < stock,
            "the translation rule must come before the stock filtering rule: {configuration}"
        );
        // The filtering rules belong at the end.
        let filter = lines
            .iter()
            .position(|line| line.starts_with("anchor \"wg-basic-v1"))
            .expect("the filtering rule must be there");
        let load = lines
            .iter()
            .position(|line| line.starts_with("load anchor \"wg-basic-v1"))
            .expect("the load rule must be there");
        assert!(
            filter > stock && load > filter,
            "the filtering rules must come after the stock filtering rule: {configuration}"
        );
    }

    #[test]
    fn the_attachment_removes_an_earlier_runs_lines_before_it_writes_its_own() {
        let once = attachment_configuration(
            STOCK_PF_CONF,
            ANCHOR,
            ANCHOR_PATH,
            &[RuleClass::Filter, RuleClass::Nat],
        )
        .expect("the stock configuration has a filtering section");
        let twice = attachment_configuration(
            &once,
            ANCHOR,
            ANCHOR_PATH,
            &[RuleClass::Filter, RuleClass::Nat],
        )
        .expect("the stock configuration has a filtering section");
        assert_eq!(
            once, twice,
            "the attachment must be the same however often it is written"
        );
        assert_eq!(
            once.matches(&format!("nat-anchor \"{ANCHOR}\"")).count(),
            1,
            "the translation rule must be written once: {once}"
        );
    }

    #[test]
    fn a_parent_without_a_filtering_section_is_refused_rather_than_written() {
        let outcome = attachment_configuration(
            "# a configuration with nothing in it\n",
            ANCHOR,
            ANCHOR_PATH,
            &[RuleClass::Filter, RuleClass::Nat],
        );
        assert!(
            outcome.is_err(),
            "a configuration with no filtering section cannot hold a translation rule: {outcome:?}"
        );
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
        after_nat.anchors[0].nat_rules =
            "nat on en0 inet from 10.77.0.0/24 to any -> (en0)\n".to_owned();
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
        assert!(
            residue
                .iter()
                .any(|entry| entry.contains("anchors directory")),
            "a changed anchors directory must be reported: {residue:?}"
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
        after_nat.parent_nat = "nat on en0 inet from 10.77.0.0/24 to any -> (en0)\n".to_owned();
        let residue = residue_found(&baseline, &after_nat, ANCHOR);
        assert!(
            residue
                .iter()
                .any(|entry| entry.contains("main NAT ruleset")),
            "a main NAT ruleset that differs from the baseline must be reported: {residue:?}"
        );
    }

    #[test]
    fn the_snapshot_difference_names_everything_the_product_must_not_do() {
        let before = FilterSnapshot {
            pf_enabled: true,
            parent_filter: "anchor \"com.apple/*\"\n".to_owned(),
            parent_nat: String::new(),
            forwarding_v4: "1".to_owned(),
            forwarding_v6: "1".to_owned(),
        };
        assert!(
            snapshot_differences(&before, &before).is_empty(),
            "an unchanged snapshot must report no difference"
        );
        let mut after = before.clone();
        after.parent_filter = "anchor \"com.apple/*\"\npass out on en0\n".to_owned();
        after.pf_enabled = false;
        after.forwarding_v4 = "0".to_owned();
        let differences = snapshot_differences(&before, &after);
        assert!(
            differences
                .iter()
                .any(|entry| entry.contains("filter ruleset")),
            "a changed root ruleset must be reported: {differences:?}"
        );
        assert!(
            differences
                .iter()
                .any(|entry| entry.contains("enable state")),
            "a toggled filter must be reported: {differences:?}"
        );
        assert!(
            differences
                .iter()
                .any(|entry| entry.contains("IPv4 forwarding")),
            "a written forwarding switch must be reported: {differences:?}"
        );
    }

    #[test]
    fn an_invocation_has_to_name_the_anchor_as_a_whole_token() {
        let ruleset = format!("anchor \"{ANCHOR}\" all\n");
        assert!(invokes_anchor(&ruleset, "anchor", ANCHOR));
        // The load line names the anchor without invoking it, so the
        // attachment's own definition can never stand in for the attachment.
        assert!(!invokes_anchor(
            &format!("load anchor \"{ANCHOR}\" from \"{ANCHOR_PATH}\"\n"),
            "anchor",
            ANCHOR
        ));
        // The other table's keyword does not invoke the anchor in this one.
        assert!(!invokes_anchor(&ruleset, "nat-anchor", ANCHOR));
        // A name that merely contains the managed name invokes nothing.
        assert!(!invokes_anchor(
            &format!("anchor \"{ANCHOR}-extra\" all\n"),
            "anchor",
            ANCHOR
        ));
        // A comment naming it invokes nothing.
        assert!(!invokes_anchor(
            &format!("# anchor \"{ANCHOR}\" all\n"),
            "anchor",
            ANCHOR
        ));
    }

    #[test]
    fn the_managed_device_is_read_from_the_products_own_rules() {
        let rules = "pass in on utun7 inet from 10.77.0.0/24 to any keep state\n\
                     pass out on en0 inet from 10.77.0.0/24 to any keep state\n";
        assert_eq!(managed_device(rules), Some("utun7".to_owned()));
        assert_eq!(managed_device(""), None);
    }

    #[test]
    fn the_rendered_gateway_policy_translates_ipv4_and_never_ipv6() {
        let rules = expected_rules("en0", "utun7");
        assert_eq!(
            rules.nat,
            vec!["nat on en0 from 10.77.0.0/24 to any -> (en0)".to_owned()],
            "a gateway renders exactly one translation rule, for the IPv4 pool"
        );
        assert!(
            rules
                .filter
                .iter()
                .any(|rule| rule == "pass out on en0 from 2001:db8:77::/64 to any keep state"),
            "the IPv6 pool is routed rather than translated: {:?}",
            rules.filter
        );
    }
}
