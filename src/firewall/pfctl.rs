//! Read-only observation of the host's packet filter (C003).
//!
//! This module is the only place in the product that asks the host's packet
//! filter what it currently enforces, and it is strictly read-only: it never
//! loads a ruleset, never flushes an anchor, never edits `/etc/pf.conf`, and
//! never enables or disables PF. Every invocation is a fixed argument vector
//! with no shell, a bounded output, and a bounded runtime.
//!
//! The filter policy for a routed LAN is **operator-managed** under Apple
//! TN3165: the administrator installs the rules and attaches the installation
//! anchor from their own PF configuration. The product observes what is
//! actually in effect and refuses to claim convergence when the observed rules
//! differ from the rendered policy. It never repairs a drift by guessing.
//!
//! Reading PF requires root, which the privileged daemon has and the
//! unprivileged management side does not. A host that denies the read is
//! reported as a permission failure, never as an absent filter.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The packet filter control utility, at its fixed system path.
const PFCTL: &str = "/sbin/pfctl";
/// The largest output the product reads from one invocation.
const MAX_PFCTL_OUTPUT: usize = 256 * 1024;
/// The longest one invocation may run.
const PFCTL_TIMEOUT: Duration = Duration::from_secs(10);

/// One observation of the host's packet filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfObservation {
    /// The main filter ruleset, as `pfctl -s rules` printed it.
    pub parent_filter: String,
    /// The main NAT ruleset, as `pfctl -s nat` printed it.
    pub parent_nat: String,
    /// The managed anchor's filter rules, when the anchor exists.
    pub anchor_filter: Option<String>,
}

/// Why an observation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObservationError {
    #[error("the packet filter control utility could not be run")]
    Unavailable,
    #[error("the packet filter control utility produced more output than the product reads")]
    OutputTooLarge,
    #[error("the packet filter control utility did not finish in time")]
    TimedOut,
    #[error("the named anchor does not exist")]
    AnchorAbsent,
}

/// Reads the host's packet-filter state without changing it.
///
/// The anchor is read separately from the parent rulesets because the two
/// answer different questions: the parent rulesets say whether the managed
/// anchor is attached at all, and the anchor's own content says whether the
/// attached rules are the ones this policy needs.
pub fn observe(anchor: &str) -> Result<PfObservation, ObservationError> {
    let parent_filter = run(&["-s", "rules"])?;
    let parent_nat = run(&["-s", "nat"])?;
    let anchor_filter = match run(&["-a", anchor, "-s", "rules"]) {
        Ok(output) => Some(output),
        Err(ObservationError::AnchorAbsent) => None,
        Err(error) => return Err(error),
    };
    Ok(PfObservation {
        parent_filter,
        parent_nat,
        anchor_filter,
    })
}

/// Runs one fixed-argument invocation and returns its standard output.
fn run(args: &[&str]) -> Result<String, ObservationError> {
    let mut child = Command::new(PFCTL)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ObservationError::Unavailable)?;
    let mut stdout = child.stdout.take().ok_or(ObservationError::Unavailable)?;
    let mut stderr = child.stderr.take().ok_or(ObservationError::Unavailable)?;
    let stdout_reader = std::thread::spawn(move || read_limited(&mut stdout));
    let stderr_reader = std::thread::spawn(move || read_limited(&mut stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => return Err(ObservationError::Unavailable),
        }
        if started.elapsed() >= PFCTL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(ObservationError::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| ObservationError::Unavailable)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ObservationError::Unavailable)??;
    if !status.success() {
        // A missing anchor is an ordinary observation, not a failure: the
        // administrator has not installed the managed anchor yet.
        let stderr = String::from_utf8_lossy(&stderr);
        if stderr.contains("does not exist") {
            return Err(ObservationError::AnchorAbsent);
        }
        return Err(ObservationError::Unavailable);
    }
    String::from_utf8(stdout).map_err(|_| ObservationError::Unavailable)
}

/// Reads at most the bounded output of one stream.
fn read_limited(reader: &mut impl Read) -> Result<Vec<u8>, ObservationError> {
    let mut output = Vec::new();
    reader
        .take((MAX_PFCTL_OUTPUT + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| ObservationError::Unavailable)?;
    if output.len() > MAX_PFCTL_OUTPUT {
        return Err(ObservationError::OutputTooLarge);
    }
    Ok(output)
}
