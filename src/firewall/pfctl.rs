//! Scoped observation and application of the host's packet filter (C003, C004).
//!
//! This module is the only place in the product that asks the host's packet
//! filter what it enforces, and the only place that writes to it. Its write
//! path is narrow by construction: the product owns exactly one
//! installation-scoped anchor and exactly one anchor file, both named for the
//! installation, and nothing else on the host.
//!
//! What the module may do:
//!
//! - observe the host's parent filter and NAT rulesets, and the managed
//!   anchor's own filter and NAT rulesets;
//! - write the installation's own anchor file under `/etc/pf.anchors/` and
//!   load it into the installation's own anchor;
//! - empty the installation's own anchor in both rule classes, and rewrite or
//!   remove its own file.
//!
//! What the module may never do:
//!
//! - write `/etc/pf.conf` — the administrator's parent attachment is
//!   foreign state;
//! - load the root ruleset: every load is scoped to the installation's own
//!   anchor;
//! - flush a table: every flush is scoped to the installation's own anchor;
//! - enable or disable PF;
//! - name a foreign anchor, or enumerate the anchors that exist.
//!
//! Every invocation is a fixed argument vector to the fixed system path
//! `/sbin/pfctl`, with no shell, a bounded output, and a bounded runtime.
//!
//! The apply path is fail-closed. A refused load leaves the anchor's
//! previously loaded content intact (measured on a disposable macOS guest on
//! 2026-10-23), so the product reports the refusal instead of repairing
//! anything by guessing.
//!
//! Reading and writing PF require root, which the privileged daemon has and
//! the unprivileged management side does not. A host that denies either is
//! reported as a failure, never as an absent filter.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::pf;

/// The packet filter control utility, at its fixed system path.
const PFCTL: &str = "/sbin/pfctl";
/// The largest output the product reads from one invocation.
const MAX_PFCTL_OUTPUT: usize = 256 * 1024;
/// The longest one invocation may run.
const PFCTL_TIMEOUT: Duration = Duration::from_secs(10);

/// The directory macOS PF reads anchor rules from.
///
/// The path itself is the pure sibling's model, so the write path and the
/// operator-facing prompt cannot name two different directories.
pub const ANCHOR_DIRECTORY: &str = pf::ANCHOR_FILE_DIRECTORY;

/// The longest anchor name the product will use.
///
/// The name becomes a file name under the anchor directory and an argument
/// to `pfctl`, so it is bounded in length as well as in shape.
const MAX_ANCHOR_NAME_BYTES: usize = 200;

/// The rule class the removal flushes first: the anchor's filter rules.
const FILTER_CLASS: &str = "rules";
/// The rule class the removal flushes second: the anchor's NAT rules.
///
/// Both classes are flushed because `pfctl -a <anchor> -F rules` clears the
/// filter class only; the NAT rules stay loaded unless they are flushed too
/// (measured 2026-10-23).
const NAT_CLASS: &str = "nat";

/// One observation of the host's packet filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfObservation {
    /// The main filter ruleset, as `pfctl -s rules` printed it.
    pub parent_filter: String,
    /// The main NAT ruleset, as `pfctl -s nat` printed it.
    pub parent_nat: String,
    /// The managed anchor's filter rules; `None` when the anchor does not
    /// exist.
    pub anchor_filter: Option<String>,
    /// The managed anchor's NAT rules; `None` when the anchor does not exist.
    pub anchor_nat: Option<String>,
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
    /// The named anchor does not exist.
    ///
    /// This variant is produced on the path where an anchor-scoped read exits
    /// **non-zero** and its stderr says that the anchor does not exist. macOS
    /// does not take that path: it answers an absent anchor with a **zero**
    /// exit status and the kernel's `DIOCGETRULES: Invalid argument` on
    /// stderr, so on macOS the absence is reported as `anchor_filter: None`
    /// and `anchor_nat: None` instead of as this error.
    ///
    /// The variant stays because another module matches on it.
    #[error("the named anchor does not exist")]
    AnchorAbsent,
}

/// Why an apply failed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApplyError {
    /// The utility could not be run at all.
    #[error("the packet filter control utility could not be run")]
    Unavailable,
    /// The utility, or the installation's anchor file, produced more content
    /// than the product reads.
    #[error("the packet filter control utility produced more output than the product reads")]
    OutputTooLarge,
    /// The utility did not finish in time.
    #[error("the packet filter control utility did not finish in time")]
    TimedOut,
    /// The utility refused the request; the message is the utility's own
    /// stderr.
    ///
    /// A refused load leaves the anchor's previously loaded content intact,
    /// so the refusal is a safe place to stop.
    #[error("the packet filter control utility refused the request: {0}")]
    Refused(String),
    /// The installation's anchor file could not be written, renamed, read, or
    /// removed.
    #[error("the installation's anchor file could not be written, renamed, read, or removed")]
    WriteFailed,
    /// The file on disk does not match what was written.
    #[error("the installation's anchor file does not match the content that was written")]
    DigestMismatch,
    /// The anchor name is not a name this module may use.
    #[error("the anchor name is not a plain name this installation may use")]
    InvalidAnchor,
}

/// Why one bounded invocation could not produce an answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunError {
    Unavailable,
    OutputTooLarge,
    TimedOut,
}

/// Maps an invocation failure onto the observation's vocabulary.
impl From<RunError> for ObservationError {
    fn from(error: RunError) -> Self {
        match error {
            RunError::Unavailable => ObservationError::Unavailable,
            RunError::OutputTooLarge => ObservationError::OutputTooLarge,
            RunError::TimedOut => ObservationError::TimedOut,
        }
    }
}

/// Maps an invocation failure onto the apply's vocabulary.
impl From<RunError> for ApplyError {
    fn from(error: RunError) -> Self {
        match error {
            RunError::Unavailable => ApplyError::Unavailable,
            RunError::OutputTooLarge => ApplyError::OutputTooLarge,
            RunError::TimedOut => ApplyError::TimedOut,
        }
    }
}

/// The outcome of one bounded invocation.
///
/// Both streams are kept because the exit status alone cannot answer every
/// question PF asks: an absent anchor is reported with a **zero** exit status
/// and a message on stderr, so the caller has to be able to read stderr.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandOutput {
    /// What the invocation printed on standard output.
    stdout: String,
    /// What the invocation printed on standard error.
    stderr: String,
    /// Whether the invocation exited zero.
    success: bool,
}

/// The answer to one anchor-scoped ruleset read.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AnchorRead {
    /// The anchor object does not exist; the kernel said so.
    Absent,
    /// The anchor object exists; the text is its ruleset, possibly empty.
    Present(String),
}

/// Reads the host's packet-filter state without changing it.
///
/// The anchor is read separately from the parent rulesets because the two
/// answer different questions: the parent rulesets say whether the managed
/// anchor is attached at all, and the anchor's own content says whether the
/// attached rules are the ones this policy needs. The anchor's filter and
/// NAT rulesets are read separately for the same reason: PF holds them as
/// two rulesets, and a gateway policy needs both of them verified.
pub fn observe(anchor: &str) -> Result<PfObservation, ObservationError> {
    let parent_filter = parent_ruleset(run(&["-s", "rules"]).map_err(ObservationError::from)?)?;
    let parent_nat = parent_ruleset(run(&["-s", "nat"]).map_err(ObservationError::from)?)?;
    let anchor_filter = run(&["-a", anchor, "-s", "rules"])?;
    let anchor_nat = run(&["-a", anchor, "-s", "nat"])?;
    assemble_observation(parent_filter, parent_nat, &anchor_filter, &anchor_nat)
}

/// The parent ruleset as `pfctl -s rules` or `pfctl -s nat` printed it.
///
/// The parent rulesets have no "absent" state: the root ruleset either
/// printed or the host refused the read, and a refusal is a failure.
fn parent_ruleset(output: CommandOutput) -> Result<String, ObservationError> {
    if !output.success {
        return Err(ObservationError::Unavailable);
    }
    Ok(output.stdout)
}

/// Assembles one observation from the four bounded reads.
///
/// The two anchor-scoped reads are classified together because the anchor is
/// one object: an anchor object that does not exist has neither a filter
/// ruleset nor a NAT ruleset, so one absent class makes the anchor absent as
/// a whole. An anchor that exists but is empty is a different fact — the
/// administrator installed it and its rules were removed — and it stays
/// distinguishable from an anchor that was never installed.
fn assemble_observation(
    parent_filter: String,
    parent_nat: String,
    anchor_filter: &CommandOutput,
    anchor_nat: &CommandOutput,
) -> Result<PfObservation, ObservationError> {
    let filter = classify_anchor_read(anchor_filter)?;
    let nat = classify_anchor_read(anchor_nat)?;
    let (anchor_filter, anchor_nat) = match (filter, nat) {
        (AnchorRead::Absent, _) | (_, AnchorRead::Absent) => (None, None),
        (AnchorRead::Present(filter), AnchorRead::Present(nat)) => (Some(filter), Some(nat)),
    };
    Ok(PfObservation {
        parent_filter,
        parent_nat,
        anchor_filter,
        anchor_nat,
    })
}

/// Classifies one anchor-scoped ruleset read.
///
/// macOS signals an absent anchor with the ioctl's `Invalid argument` and a
/// **zero** exit status, so the exit status cannot carry the distinction and
/// the message is the only signal. The ioctl's name differs between the
/// filter and the NAT table, so the match is on the `DIOCGET` prefix.
fn classify_anchor_read(output: &CommandOutput) -> Result<AnchorRead, ObservationError> {
    if reports_absent_anchor(&output.stderr) {
        return Ok(AnchorRead::Absent);
    }
    if !output.success {
        // A missing anchor is an ordinary observation, not a failure: the
        // administrator has not installed the managed anchor yet.
        if output.stderr.contains("does not exist") {
            return Err(ObservationError::AnchorAbsent);
        }
        return Err(ObservationError::Unavailable);
    }
    Ok(AnchorRead::Present(output.stdout.clone()))
}

/// Whether `stderr` carries the kernel's signal that the named anchor object
/// does not exist.
///
/// The kernel answers an absent anchor with `Invalid argument` from the
/// ruleset ioctl, and `pfctl` prefixes it with the ioctl's own name
/// (`DIOCGETRULES` for the filter table). The ioctl differs between the
/// filter and the NAT table, so the match is on the `DIOCGET` prefix rather
/// than on one exact name.
fn reports_absent_anchor(stderr: &str) -> bool {
    stderr.contains("DIOCGET") && stderr.contains("Invalid argument")
}

/// The installation's own anchor file's path, derived from the anchor name.
///
/// The path is never caller-supplied: no public function accepts one, and
/// the file always sits in the anchor directory under the anchor's own
/// name. This is a pure derivation; only a validated anchor name reaches the
/// write path.
pub fn anchor_file_path(anchor: &str) -> PathBuf {
    pf::anchor_file_path(anchor)
}

/// Writes the installation's own anchor file and loads it into the
/// installation's own anchor.
///
/// The content is written whole — a staged file in the same directory,
/// flushed, then renamed over the destination — and then read back and
/// compared by digest. A mismatch stops the apply before the load, so the
/// content that is loaded is always the content that was written and
/// verified.
///
/// A refusal from `pfctl` leaves the anchor's previously loaded content
/// intact (PF keeps the existing rules when a load fails), so the refusal is
/// a safe place to stop. The written file is **left in place** on a refusal:
/// it is the installation's own file, it records what was intended, and
/// removing it would discard the evidence of the attempt. The caller decides
/// what a refusal means.
///
/// The anchor name is the installation-scoped name derived by
/// `pf::anchor_name`; this module validates its shape and never chooses an
/// anchor of its own.
pub fn install_anchor(anchor: &str, content: &str) -> Result<(), ApplyError> {
    if !anchor_name_is_valid(anchor) {
        return Err(ApplyError::InvalidAnchor);
    }
    let verification = write_and_verify(anchor, content);
    load_after_verification(anchor, verification, &mut |arguments| {
        let output = run(arguments).map_err(ApplyError::from)?;
        if output.success {
            Ok(())
        } else {
            // `pfctl` prints a `Use of -f option …` warning on stderr for
            // every load, even an anchor-scoped one. It is not an error: only
            // the exit status decides, so a zero exit is a success and the
            // warning is never reported as a refusal.
            Err(ApplyError::Refused(output.stderr))
        }
    })
}

/// The install's second phase: load the verified content into the anchor.
///
/// The verification result is an argument rather than a statement inside
/// this function so that the ordering contract is testable without a host:
/// a digest mismatch must stop the load, and the only way to prove that is
/// to make the load a step that can be observed.
fn load_after_verification(
    anchor: &str,
    verification: Result<(), ApplyError>,
    load: &mut dyn FnMut(&[String]) -> Result<(), ApplyError>,
) -> Result<(), ApplyError> {
    verification?;
    load(&install_arguments(anchor))
}

/// Empties the installation's own anchor in both rule classes and rewrites
/// its file.
///
/// The file is **not** removed: the administrator's `load anchor` line names
/// it, and a missing file makes the next reload of the host's own ruleset
/// fail outright, which would break the host's whole packet-filter
/// configuration. The file is rewritten to the content the caller supplies —
/// the marker line alone, which is a valid, empty rules file — so the
/// installation's ownership stays provable from the host's state alone.
///
/// The anchor is emptied first and the file is rewritten second, so a
/// refusal leaves the file describing what the anchor still enforces.
pub fn clear_anchor(anchor: &str, content: &str) -> Result<(), ApplyError> {
    if !anchor_name_is_valid(anchor) {
        return Err(ApplyError::InvalidAnchor);
    }
    flush_anchor(anchor)?;
    write_and_verify(anchor, content)
}

/// Reads the installation's own anchor file's content, when it exists.
///
/// The file is the installation's own file, and reading it is how the
/// product proves that it owns it: the product's own file carries the
/// product's marker, and a file without it belongs to somebody else. A file
/// that is not there at all is reported as absent, not as a failure.
pub fn read_anchor_file(anchor: &str) -> Result<Option<String>, ApplyError> {
    if !anchor_name_is_valid(anchor) {
        return Err(ApplyError::InvalidAnchor);
    }
    let file = match File::open(anchor_file_path(anchor)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ApplyError::WriteFailed),
    };
    let mut content = Vec::new();
    file.take((MAX_PFCTL_OUTPUT + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|_| ApplyError::WriteFailed)?;
    if content.len() > MAX_PFCTL_OUTPUT {
        return Err(ApplyError::OutputTooLarge);
    }
    String::from_utf8(content)
        .map(Some)
        .map_err(|_| ApplyError::WriteFailed)
}

/// Flushes the installation's own anchor in both rule classes.
///
/// Both classes are flushed because `pfctl -a <anchor> -F rules` clears the
/// filter class only, and the NAT rules stay loaded unless they are flushed
/// too (measured 2026-10-23). A refusal stops here: the rest of the
/// teardown waits until the firewall cleanup is safe.
fn flush_anchor(anchor: &str) -> Result<(), ApplyError> {
    for arguments in remove_argument_vectors(anchor) {
        let output = run(arguments.as_slice()).map_err(ApplyError::from)?;
        if !output.success {
            return Err(ApplyError::Refused(output.stderr));
        }
    }
    Ok(())
}

/// The argument vector that loads the installation's own anchor file into the
/// installation's own anchor.
///
/// The vector is fixed: the anchor's own name, and the anchor's own file.
/// The root ruleset is never named, so the load cannot replace it.
fn install_arguments(anchor: &str) -> Vec<String> {
    vec![
        "-a".to_string(),
        anchor.to_string(),
        "-f".to_string(),
        anchor_file_path(anchor).to_string_lossy().into_owned(),
    ]
}

/// The argument vector that flushes one rule class of the installation's own
/// anchor.
fn remove_arguments(anchor: &str, class: &str) -> Vec<String> {
    vec![
        "-a".to_string(),
        anchor.to_string(),
        "-F".to_string(),
        class.to_string(),
    ]
}

/// The two flush invocations, in order: the filter class first, then the NAT
/// class.
fn remove_argument_vectors(anchor: &str) -> [Vec<String>; 2] {
    [
        remove_arguments(anchor, FILTER_CLASS),
        remove_arguments(anchor, NAT_CLASS),
    ]
}

/// Writes the anchor file whole and proves the bytes on disk are the bytes
/// that were written.
///
/// The content is staged in the same directory under a hidden name, flushed,
/// and then renamed over the destination, so a reader never observes a
/// half-written file and a failed write leaves the previous content intact.
/// The file is then read back and compared by digest: the product installs
/// what it wrote, or it refuses.
fn write_and_verify(anchor: &str, content: &str) -> Result<(), ApplyError> {
    let directory = Path::new(ANCHOR_DIRECTORY);
    let staged = directory.join(format!(".{anchor}.tmp"));
    let destination = anchor_file_path(anchor);
    {
        let mut file = File::create(&staged).map_err(|_| ApplyError::WriteFailed)?;
        file.write_all(content.as_bytes())
            .map_err(|_| ApplyError::WriteFailed)?;
        file.sync_all().map_err(|_| ApplyError::WriteFailed)?;
    }
    if let Err(_error) = std::fs::rename(&staged, &destination) {
        // The staged file is the installation's own debris; removing it keeps
        // a failed install from leaving a stray file in the anchor directory.
        let _ = std::fs::remove_file(&staged);
        return Err(ApplyError::WriteFailed);
    }
    let written = std::fs::read(&destination).map_err(|_| ApplyError::WriteFailed)?;
    verify_digest(&written, content)
}

/// Compares the bytes read back from the anchor file with the bytes that
/// were written.
fn verify_digest(written: &[u8], intended: &str) -> Result<(), ApplyError> {
    if sha256_hex(written) == sha256_hex(intended.as_bytes()) {
        Ok(())
    } else {
        Err(ApplyError::DigestMismatch)
    }
}

/// Removes the installation's own anchor file.
///
/// Whether `anchor` is a plain name this module may use.
///
/// The name becomes a file name under the anchor directory and an argument
/// to `pfctl`, so it is restricted to a plain, single-component name: the
/// characters `[A-Za-z0-9._-]` only, at most
/// [`MAX_ANCHOR_NAME_BYTES`] long, never empty, and never `.` or `..`. A
/// name that carries a separator, a wildcard, or a traversal component
/// could name a file outside the anchor directory or an anchor the product
/// does not own, so it is refused before any I/O happens.
fn anchor_name_is_valid(anchor: &str) -> bool {
    if anchor.is_empty() || anchor.len() > MAX_ANCHOR_NAME_BYTES {
        return false;
    }
    if anchor == "." || anchor == ".." {
        return false;
    }
    anchor
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The SHA-256 of `bytes`, as lowercase hexadecimal.
///
/// The product compares the installed content by exact digest, so the digest
/// is taken over the raw bytes: the file on disk must be the bytes that were
/// written, byte for byte.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Runs one fixed-argument invocation and returns both of its streams.
///
/// The utility is addressed by its fixed system path, the argument vector is
/// passed without a shell, standard input is closed, and both output streams
/// are bounded. The runtime is bounded too, so a hung utility cannot hold
/// the daemon.
fn run<S: AsRef<OsStr>>(args: &[S]) -> Result<CommandOutput, RunError> {
    let mut child = Command::new(PFCTL)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| RunError::Unavailable)?;
    let mut stdout = child.stdout.take().ok_or(RunError::Unavailable)?;
    let mut stderr = child.stderr.take().ok_or(RunError::Unavailable)?;
    let stdout_reader = std::thread::spawn(move || read_limited(&mut stdout));
    let stderr_reader = std::thread::spawn(move || read_limited(&mut stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => return Err(RunError::Unavailable),
        }
        if started.elapsed() >= PFCTL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(RunError::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader.join().map_err(|_| RunError::Unavailable)??;
    let stderr = stderr_reader.join().map_err(|_| RunError::Unavailable)??;
    Ok(CommandOutput {
        stdout: String::from_utf8(stdout).map_err(|_| RunError::Unavailable)?,
        stderr: String::from_utf8(stderr).map_err(|_| RunError::Unavailable)?,
        success: status.success(),
    })
}

/// Reads at most the bounded output of one stream.
fn read_limited(reader: &mut impl Read) -> Result<Vec<u8>, RunError> {
    let mut output = Vec::new();
    reader
        .take((MAX_PFCTL_OUTPUT + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| RunError::Unavailable)?;
    if output.len() > MAX_PFCTL_OUTPUT {
        return Err(RunError::OutputTooLarge);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's answer for an anchor object that does not exist: a zero
    /// exit status and the ioctl's complaint on stderr.
    ///
    /// Measured on a disposable macOS guest on 2026-10-23: the exit status
    /// does not distinguish an absent anchor, so the message is the only
    /// signal.
    const ABSENT_ANCHOR_STDERR: &str = "pfctl: DIOCGETRULES: Invalid argument\n";

    /// A ruleset read that the host answered.
    fn read(stdout: &str, stderr: &str, success: bool) -> CommandOutput {
        CommandOutput {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            success,
        }
    }

    #[test]
    fn the_observation_reports_an_absent_anchor_as_absent_not_as_empty_content() {
        // macOS exits zero for an absent anchor, so the exit status cannot
        // carry the absence and the stderr message must.
        let observation = assemble_observation(
            "anchor \"com.apple/*\" all\n".to_string(),
            String::new(),
            &read("", ABSENT_ANCHOR_STDERR, true),
            &read("", ABSENT_ANCHOR_STDERR, true),
        )
        .expect("an absent anchor is an observation, not a failure");
        assert_eq!(observation.anchor_filter, None);
        assert_eq!(observation.anchor_nat, None);
        assert_ne!(observation.anchor_filter, Some(String::new()));
    }

    #[test]
    fn the_observation_distinguishes_an_existing_but_empty_anchor_from_an_absent_one() {
        let absent = assemble_observation(
            String::new(),
            String::new(),
            &read("", ABSENT_ANCHOR_STDERR, true),
            &read("", ABSENT_ANCHOR_STDERR, true),
        )
        .expect("an absent anchor is an observation, not a failure");
        let emptied = assemble_observation(
            String::new(),
            String::new(),
            &read("", "", true),
            &read("", "", true),
        )
        .expect("an emptied anchor is an observation, not a failure");
        assert_eq!(absent.anchor_filter, None);
        assert_eq!(emptied.anchor_filter, Some(String::new()));
        assert_ne!(absent.anchor_filter, emptied.anchor_filter);
        assert_ne!(absent.anchor_nat, emptied.anchor_nat);
    }

    #[test]
    fn the_observation_reads_the_anchor_nat_ruleset_as_well_as_its_filter_ruleset() {
        let observation = assemble_observation(
            String::new(),
            String::new(),
            &read(
                "pass in on utun4 from 10.8.0.0/24 to any keep state\n",
                "",
                true,
            ),
            &read(
                "nat on en0 inet from 10.8.0.0/24 to any -> (en0) round-robin\n",
                "",
                true,
            ),
        )
        .expect("a populated anchor is an observation, not a failure");
        assert!(observation
            .anchor_filter
            .as_deref()
            .is_some_and(|content| content.contains("pass in on utun4")));
        assert!(observation
            .anchor_nat
            .as_deref()
            .is_some_and(|content| content.contains("nat on en0")));
    }

    #[test]
    fn the_install_argument_vector_is_anchor_scoped_and_never_loads_the_root_ruleset() {
        let anchor = "wg-basic-v1-1c0ffee";
        let arguments = install_arguments(anchor);
        assert_eq!(
            arguments,
            vec!["-a", anchor, "-f", "/etc/pf.anchors/wg-basic-v1-1c0ffee",]
        );
        // The root ruleset is never named: the file the invocation names is
        // the installation's own anchor file, and only that file.
        assert!(!arguments.iter().any(|argument| argument == "/etc/pf.conf"));
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| argument.as_str() == "-f")
                .count(),
            1
        );
        assert_eq!(arguments.first().map(String::as_str), Some("-a"));
    }

    #[test]
    fn the_install_refuses_a_name_that_is_not_a_plain_name() {
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "wg-basic/../escape",
            "/etc/passwd",
            "wg basic",
            "wg-basic\n",
            "com.apple/*",
            "anchor\"wg-basic\"",
        ] {
            assert!(
                !anchor_name_is_valid(name),
                "{name:?} is not a name this module may use"
            );
        }
        let too_long = "a".repeat(MAX_ANCHOR_NAME_BYTES + 1);
        assert!(!anchor_name_is_valid(&too_long));
        assert!(anchor_name_is_valid("wg-basic-v1-1c0ffee"));
        assert!(anchor_name_is_valid(&"a".repeat(MAX_ANCHOR_NAME_BYTES)));

        // The refusal happens before any I/O: an accepted name can only ever
        // produce a path inside the anchor directory.
        assert_eq!(
            install_anchor("../escape", "pass in on utun4\n"),
            Err(ApplyError::InvalidAnchor)
        );
        assert_eq!(
            clear_anchor("../escape", "# marker\n"),
            Err(ApplyError::InvalidAnchor)
        );
        let path = anchor_file_path("wg-basic-v1-1c0ffee");
        assert_eq!(path.parent(), Some(Path::new(ANCHOR_DIRECTORY)));
        assert_eq!(path, PathBuf::from("/etc/pf.anchors/wg-basic-v1-1c0ffee"));
    }

    #[test]
    fn the_install_rejects_a_digest_mismatch_before_it_loads() {
        let loaded = std::cell::Cell::new(false);
        let mut loader = |_arguments: &[String]| {
            loaded.set(true);
            Ok(())
        };
        let result = load_after_verification(
            "wg-basic-v1-1c0ffee",
            Err(ApplyError::DigestMismatch),
            &mut loader,
        );
        assert_eq!(result, Err(ApplyError::DigestMismatch));
        assert!(
            !loaded.get(),
            "a digest mismatch must stop the load before the utility runs"
        );
        assert_eq!(
            verify_digest(b"tampered", "intended"),
            Err(ApplyError::DigestMismatch)
        );
        assert_eq!(verify_digest(b"intended", "intended"), Ok(()));
    }

    #[test]
    fn the_remove_flushes_both_rule_classes() {
        let vectors = remove_argument_vectors("wg-basic-v1-1c0ffee");
        assert_eq!(vectors.len(), 2);
        assert_eq!(
            vectors[0],
            vec!["-a", "wg-basic-v1-1c0ffee", "-F", "rules"],
            "the filter class is flushed"
        );
        assert_eq!(
            vectors[1],
            vec!["-a", "wg-basic-v1-1c0ffee", "-F", "nat"],
            "the NAT class is flushed too, or its rules stay loaded"
        );
    }

    #[test]
    fn the_remove_argument_vectors_name_only_the_installations_own_anchor() {
        let anchor = "wg-basic-v1-1c0ffee";
        for arguments in remove_argument_vectors(anchor) {
            assert_eq!(arguments.first().map(String::as_str), Some("-a"));
            assert_eq!(arguments.get(1).map(String::as_str), Some(anchor));
            assert_eq!(
                arguments
                    .iter()
                    .filter(|argument| argument.as_str() == anchor)
                    .count(),
                1,
                "exactly one anchor is named, and it is the installation's own"
            );
            // No table is flushed and no anchor is enumerated.
            assert!(!arguments.iter().any(|argument| argument == "all"));
            assert!(!arguments.iter().any(|argument| argument == "Anchors"));
        }
    }
}
