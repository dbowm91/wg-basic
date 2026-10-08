//! Fail-closed update policy and crash-durable transaction journal.
//!
//! Release authenticity is always verified before manifest projection. The
//! production trust root is intentionally absent until a maintainer provisions
//! it; update entrypoints therefore refuse to discover or acquire releases.

use eggup_acquisition::{
    AcquisitionRequest, AcquisitionTransport, CancelFlag, FetchLimits, FetchOutcome,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub const UPDATE_JOURNAL_PATH: &str = "/var/lib/wg-basic-system/update-journal.json";
pub const ROLLBACK_DIR: &str = "/var/lib/wg-basic-system/rollback";
const JOURNAL_SCHEMA: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
const RELEASE_ORIGIN: &str = "https://github.com/dbowm91/wg-basic/releases/download";
const RELEASE_DISCOVERY_URL: &str = "https://api.github.com/repos/dbowm91/wg-basic/releases/latest";

/// Stable release identity selected from untrusted GitHub discovery metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ReleaseSelection {
    /// Unprefixed stable version.
    #[serde(skip)]
    pub version: String,
    /// Exact canonical Git tag.
    pub tag_name: String,
    /// GitHub release prerelease flag.
    pub prerelease: bool,
    /// GitHub draft flag.
    pub draft: bool,
}

/// Signed metadata bytes and policy-checked target projection.
#[derive(Clone, Debug)]
pub struct AuthenticatedRelease {
    /// Selected stable version.
    pub version: String,
    /// Exact manifest bytes, retained for transaction provenance.
    pub manifest: Vec<u8>,
    /// Exact detached signature bytes.
    pub signature: Vec<u8>,
    /// Projection produced by Eggup only after signature verification.
    pub projection: eggup_eggpack::ManifestProjection,
    /// SHA-256 of exact signed manifest bytes.
    pub manifest_sha256: String,
}

/// Exact signed artifact bytes after Eggup integrity and candidate checks.
#[derive(Clone, Debug)]
pub struct ValidatedCandidate {
    /// Private staging path; this is never an installation destination.
    pub path: PathBuf,
    /// Exact signed artifact digest.
    pub sha256: String,
    /// Exact signed artifact size.
    pub size: u64,
}

/// Parse bounded GitHub latest-release JSON. The response only selects a
/// candidate; it cannot authorize release bytes.
pub fn parse_latest_release(bytes: &[u8]) -> Result<ReleaseSelection, &'static str> {
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err("release discovery response is outside the permitted size");
    }
    let mut selection: ReleaseSelection =
        serde_json::from_slice(bytes).map_err(|_| "release discovery response is invalid")?;
    let version = selection
        .tag_name
        .strip_prefix('v')
        .ok_or("release tag is not canonical")?;
    crate::release::parse_stable_version(version)
        .map_err(|_| "release tag is not stable SemVer")?;
    if selection.tag_name != format!("v{version}") {
        return Err("release tag is not canonical");
    }
    selection.version = version.to_owned();
    validate_selection(&selection)?;
    Ok(selection)
}

fn validate_selection(selection: &ReleaseSelection) -> Result<(), &'static str> {
    if selection.draft || selection.prerelease {
        return Err("release discovery did not select a stable published release");
    }
    crate::release::parse_stable_version(&selection.version)
        .map_err(|_| "selected release version is not stable SemVer")?;
    if selection.tag_name != format!("v{}", selection.version) {
        return Err("selected release tag does not match its stable version");
    }
    Ok(())
}

/// Discover one stable release using the exact canonical API URL.
pub fn discover_latest(transport: &dyn AcquisitionTransport) -> Result<ReleaseSelection, String> {
    let request =
        AcquisitionRequest::new(RELEASE_DISCOVERY_URL).map_err(|_| "invalid release URL")?;
    let response = transport
        .fetch_metadata(&request, metadata_limits(), &CancelFlag::new())
        .map_err(|_| "could not acquire bounded release discovery metadata")?;
    match response {
        FetchOutcome::Success(bytes) => parse_latest_release(bytes.bytes()).map_err(str::to_owned),
        FetchOutcome::NotFound => Err("release discovery endpoint returned not found".into()),
    }
}

/// Acquire, authenticate, and project the exact selected release manifest.
pub fn acquire_authenticated_release(
    transport: &dyn AcquisitionTransport,
    selection: &ReleaseSelection,
    current_version: &str,
    target: crate::release::LinuxTarget,
    public_key: &str,
) -> Result<AuthenticatedRelease, String> {
    validate_selection(selection).map_err(str::to_owned)?;
    crate::release::require_newer(current_version, &selection.version).map_err(str::to_owned)?;
    let base = format!("{RELEASE_ORIGIN}/{}", selection.tag_name);
    let manifest_url = format!("{base}/release-manifest.json");
    let signature_url = format!("{manifest_url}.minisig");
    let manifest = fetch_metadata(transport, &manifest_url)?;
    let signature = fetch_metadata(transport, &signature_url)?;
    let signature_text =
        std::str::from_utf8(&signature).map_err(|_| "release signature is not valid UTF-8")?;
    let projection = crate::release::authenticate_release_manifest(
        &manifest,
        signature_text,
        public_key,
        &selection.version,
        current_version,
        target,
    )
    .map_err(str::to_owned)?;
    let digest = sha2::Sha256::digest(&manifest);
    Ok(AuthenticatedRelease {
        version: selection.version.clone(),
        manifest,
        signature,
        projection,
        manifest_sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    })
}

fn fetch_metadata(transport: &dyn AcquisitionTransport, url: &str) -> Result<Vec<u8>, String> {
    let request = AcquisitionRequest::new(url).map_err(|_| "invalid release metadata URL")?;
    match transport
        .fetch_metadata(&request, metadata_limits(), &CancelFlag::new())
        .map_err(|_| "could not acquire bounded release metadata")?
    {
        FetchOutcome::Success(bytes) => Ok(bytes.bytes().to_vec()),
        FetchOutcome::NotFound => Err("selected release metadata is unavailable".into()),
    }
}

/// Acquire only the single manifest-selected binary for the canonical host.
/// The destination must already be inside a root-owned private transaction
/// directory and must not exist.
pub fn acquire_candidate(
    transport: &dyn AcquisitionTransport,
    release: &AuthenticatedRelease,
    target: crate::release::LinuxTarget,
    transaction_dir: &Path,
) -> Result<ValidatedCandidate, String> {
    let directory = fs::symlink_metadata(transaction_dir)
        .map_err(|_| "update staging directory is unavailable")?;
    if !directory.file_type().is_dir() || directory.uid() != 0 || directory.mode() & 0o777 != 0o700
    {
        return Err("update staging directory is unsafe".into());
    }
    let (artifacts, manifest_target) = match &release.projection {
        eggup_eggpack::ManifestProjection::Installable {
            target, artifacts, ..
        } => (artifacts, target),
        _ => return Err("signed release is not a direct installable binary".into()),
    };
    if manifest_target != target.triple() || artifacts.len() != 1 {
        return Err("signed release target inventory is not exact".into());
    }
    let artifact = &artifacts[0];
    let expected_name = format!("wg-basic-{}", target.triple());
    if artifact.artifact_name != expected_name || artifact.destination != "wg-basic" {
        return Err("signed release artifact identity is invalid".into());
    }
    if artifact.exact_size == 0 || artifact.exact_size > 128 * 1024 * 1024 {
        return Err("signed release artifact size is outside the permitted bound".into());
    }
    let url = format!(
        "{RELEASE_ORIGIN}/v{}/{}",
        release.version, artifact.artifact_name
    );
    let request = AcquisitionRequest::new(url).map_err(|_| "invalid release artifact URL")?;
    let path = transaction_dir.join("candidate-wg-basic");
    let limits = FetchLimits::new(
        256 * 1024,
        artifact.exact_size,
        Duration::from_secs(10),
        Duration::from_secs(300),
    )
    .map_err(|_| "release artifact acquisition policy is invalid")?;
    match transport
        .fetch_artifact(&request, &path, limits, &CancelFlag::new())
        .map_err(|_| "could not acquire the exact signed release artifact")?
    {
        FetchOutcome::Success(evidence) if evidence.bytes_written() == artifact.exact_size => {}
        FetchOutcome::Success(_) => {
            return Err("release artifact size does not match manifest".into())
        }
        FetchOutcome::NotFound => return Err("selected release artifact is unavailable".into()),
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| "acquired release artifact is unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.len() != artifact.exact_size
    {
        let _ = fs::remove_file(&path);
        return Err("acquired release artifact is unsafe or has the wrong size".into());
    }
    let digest = eggup_core::hash_file(&path).map_err(|_| "release artifact digest failed")?;
    if digest != artifact.sha256 {
        let _ = fs::remove_file(&path);
        return Err("release artifact digest does not match signed manifest".into());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "could not set candidate executable permission")?;
    let output = eggup_core::run_bounded(
        &eggup_core::CommandSpec::new(&path)
            .arg("--version")
            .timeout(Duration::from_secs(5))
            .max_output_bytes(1024),
    )
    .map_err(|_| "candidate identity check failed")?;
    if !output.success()
        || !output.stderr().is_empty()
        || output.stdout() != format!("wg-basic {}\n", release.version).as_bytes()
    {
        let _ = fs::remove_file(&path);
        return Err("candidate identity does not match the signed release".into());
    }
    let sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(ValidatedCandidate {
        path,
        sha256,
        size: artifact.exact_size,
    })
}

/// Commit one verified candidate through Eggup Core and run wg-basic's
/// product-health/commit-marker callback while Eggup retains rollback evidence.
/// Service quiescence and the durable state backup are caller prerequisites.
#[allow(dead_code)] // Called by the M004 transaction entrypoint after trust-root provisioning.
pub(crate) fn eggup_commit_binary<F>(
    install_root: &Path,
    destination_name: &str,
    candidate: &Path,
    version: &str,
    expected_old_sha256: [u8; 32],
    expected_candidate_sha256: [u8; 32],
    post_commit: F,
) -> Result<eggup_core::TransactionReceipt, String>
where
    F: FnOnce() -> Result<(), String>,
{
    use eggup_core::{
        AbsentPolicy, ArtifactMember, ArtifactSet, CommitOwnership, ExactDigestVerifier,
        InstallPlan, IntegrityRequirement, MemberId, PermissionsIntent, ProductId, ReleaseId,
        TransactionDisposition,
    };

    crate::release::parse_stable_version(version).map_err(str::to_owned)?;
    let member_id = MemberId::new("wg-basic").map_err(|_| "invalid binary member identity")?;
    let product = ProductId::new(crate::release::PRODUCT_ID)
        .map_err(|_| "invalid update product identity")?;
    let release = ReleaseId::new(version).map_err(|_| "invalid update release identity")?;
    let member = ArtifactMember::new(member_id.clone(), candidate, destination_name)
        .map_err(|_| "invalid candidate destination")?
        .with_permissions(PermissionsIntent::Executable)
        .with_integrity(IntegrityRequirement::Sha256(expected_candidate_sha256));
    let plan = InstallPlan::new(
        product,
        release,
        install_root,
        ArtifactSet::single(member).map_err(|_| "invalid candidate artifact set")?,
    )
    .map_err(|_| "could not prepare Eggup binary transaction")?;
    let validator =
        eggup_core::ExactIdentityValidator::new(member_id.clone(), format!("wg-basic {version}\n"))
            .args(["--version"])
            .timeout(Duration::from_secs(5))
            .max_output_bytes(1024);
    let validated = plan
        .prepare()
        .and_then(|prepared| prepared.verify_integrity())
        .and_then(|verified| verified.validate(&validator))
        .map_err(|_| "Eggup candidate integrity or identity validation failed")?;
    let verifier = ExactDigestVerifier::new(vec![(member_id, expected_old_sha256)]);
    let receipt = validated
        .commit_with_post_commit(
            CommitOwnership::new(&verifier, AbsentPolicy::DenyCreate),
            eggup_core::PostCommitFailurePolicy::RollBack,
            post_commit,
        )
        .map_err(|_| "Eggup binary transaction could not prove a terminal result")?;
    if receipt.disposition() == TransactionDisposition::RecoveryRequired {
        return Err("Eggup binary rollback requires operator recovery".into());
    }
    Ok(receipt)
}

fn metadata_limits() -> FetchLimits {
    FetchLimits::new(
        256 * 1024,
        256 * 1024,
        Duration::from_secs(10),
        Duration::from_secs(30),
    )
    .expect("fixed release metadata bounds are valid")
}

/// A durable update or recovery phase.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    /// Transaction identity recorded before backup work.
    Prepared,
    /// State and old-binary recovery artifacts are durable and verified.
    BackupVerified,
    /// Both services have stopped and released their resources.
    ServicesStopped,
    /// The candidate binary is installed; the old binary is retained.
    BinaryCommitted,
    /// Candidate services have started.
    CandidateStarted,
    /// Product health passed; commit is not yet durable.
    CandidateHealthy,
    /// Durable commit marker; candidate pair is authoritative.
    Committed,
    /// Rollback is in progress.
    RollingBack,
    /// Old binary and compatible state have been restored and validated.
    RolledBack,
    /// Recovery could not prove a safe compatible pair.
    RecoveryRequired,
}

/// Safe, secret-free journal data. Paths are constrained to the product's
/// rollback directory when loaded; no field is an executable or arbitrary URL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateJournal {
    pub schema: u32,
    pub transaction_id: String,
    pub version_from: String,
    pub version_to: String,
    pub target: String,
    pub phase: UpdatePhase,
    pub transaction_dir: PathBuf,
    pub old_binary_sha256: String,
    pub candidate_sha256: String,
    pub state_backup_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub signing_key_id: Option<String>,
}

impl UpdateJournal {
    /// Validate every identity and path field before it can guide recovery.
    pub fn validate(&self, rollback_root: &Path) -> io::Result<()> {
        if self.schema != JOURNAL_SCHEMA
            || !valid_token(&self.transaction_id, 64)
            || self.transaction_dir != rollback_root.join(&self.transaction_id)
            || !crate::release::LinuxTarget::ALL
                .iter()
                .any(|target| target.triple() == self.target)
        {
            return Err(invalid_journal());
        }
        crate::release::parse_stable_version(&self.version_from).map_err(|_| invalid_journal())?;
        crate::release::parse_stable_version(&self.version_to).map_err(|_| invalid_journal())?;
        crate::release::require_newer(&self.version_from, &self.version_to)
            .map_err(|_| invalid_journal())?;
        for digest in [
            Some(self.old_binary_sha256.as_str()),
            Some(self.candidate_sha256.as_str()),
            self.state_backup_sha256.as_deref(),
            self.manifest_sha256.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid_journal());
            }
        }
        if self
            .signing_key_id
            .as_deref()
            .is_some_and(|value| !valid_token(value, 64))
        {
            return Err(invalid_journal());
        }
        Ok(())
    }
}

/// Atomically persist a root-owned 0600 journal and fsync its parent directory.
pub fn write_journal(path: &Path, journal: &UpdateJournal) -> io::Result<()> {
    write_journal_owned_by(path, journal, 0)
}

fn write_journal_owned_by(
    path: &Path,
    journal: &UpdateJournal,
    expected_uid: u32,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(invalid_journal)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(invalid_journal());
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > MAX_JOURNAL_BYTES
        {
            return Err(invalid_journal());
        }
    }
    let rollback_root = parent.join("rollback");
    journal.validate(&rollback_root)?;
    let bytes = serde_json::to_vec(journal).map_err(|_| invalid_journal())?;
    let temp = parent.join(format!(".update-journal.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

/// Read and strictly validate an existing root-owned journal.
pub fn read_journal(path: &Path) -> io::Result<UpdateJournal> {
    read_journal_owned_by(path, 0)
}

/// Persist one legal state-machine transition after revalidating the current
/// durable journal. The caller must perform the next irreversible action only
/// after this function returns successfully.
pub fn advance_journal(
    path: &Path,
    expected: &UpdateJournal,
    next: UpdatePhase,
) -> io::Result<UpdateJournal> {
    let current = read_journal(path)?;
    if current != *expected || !transition_allowed(current.phase, next) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "update journal phase transition is invalid",
        ));
    }
    let mut updated = current;
    updated.phase = next;
    write_journal(path, &updated)?;
    Ok(updated)
}

fn transition_allowed(from: UpdatePhase, to: UpdatePhase) -> bool {
    use UpdatePhase::*;
    matches!(
        (from, to),
        (Prepared, BackupVerified | RecoveryRequired)
            | (
                BackupVerified,
                ServicesStopped | RollingBack | RecoveryRequired
            )
            | (
                ServicesStopped,
                BinaryCommitted | RollingBack | RecoveryRequired
            )
            | (
                BinaryCommitted,
                CandidateStarted | RollingBack | RecoveryRequired
            )
            | (
                CandidateStarted,
                CandidateHealthy | RollingBack | RecoveryRequired
            )
            | (CandidateHealthy, Committed | RollingBack | RecoveryRequired)
            | (RollingBack, RolledBack | RecoveryRequired)
    )
}

fn read_journal_owned_by(path: &Path, expected_uid: u32) -> io::Result<UpdateJournal> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(invalid_journal());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file()
        || opened_metadata.uid() != expected_uid
        || opened_metadata.mode() & 0o777 != 0o600
        || opened_metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(invalid_journal());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(invalid_journal());
    }
    let journal: UpdateJournal = serde_json::from_slice(&bytes).map_err(|_| invalid_journal())?;
    let parent = path.parent().ok_or_else(invalid_journal)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != expected_uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(invalid_journal());
    }
    journal.validate(&parent.join("rollback"))?;
    Ok(journal)
}

/// Refuse all release operations when production authenticity is unavailable.
/// The fixture key is never returned from this function.
pub fn require_production_key() -> Result<&'static str, String> {
    crate::release::PRODUCTION_PUBLIC_KEY.ok_or_else(|| {
        "release updates are unavailable: the production Minisign trust root is not provisioned"
            .into()
    })
}

/// `update --check`: read-only and fail-closed until the production trust root
/// is provisioned. No network request is made in this state.
pub fn check() -> Result<(), String> {
    let install = crate::distribution::validate_owned_installation()?;
    if install.version != crate::release::PACKAGE_VERSION {
        return Err("installed version does not match updater binary identity".into());
    }
    let public_key = require_production_key()?;
    let transport = system_transport()?;
    let _ = check_with(&transport, public_key)?;
    Ok(())
}

/// Read-only authenticated check with an explicitly supplied trust root and
/// transport. The production CLI does not expose either injection point.
pub fn check_with(
    transport: &dyn AcquisitionTransport,
    public_key: &str,
) -> Result<Option<AuthenticatedRelease>, String> {
    let target =
        crate::release::LinuxTarget::from_host(std::env::consts::OS, std::env::consts::ARCH)
            .map_err(str::to_owned)?;
    let selection = discover_latest(transport)?;
    match crate::release::require_newer(crate::release::PACKAGE_VERSION, &selection.version) {
        Ok(()) => {
            let release = acquire_authenticated_release(
                transport,
                &selection,
                crate::release::PACKAGE_VERSION,
                target,
                public_key,
            )?;
            println!(
                "installed: {}\ntarget: {}\nlatest: {}\nupdate available: yes\nmanifest: authenticated",
                crate::release::PACKAGE_VERSION,
                target.triple(),
                selection.version
            );
            Ok(Some(release))
        }
        Err(_) => {
            println!(
                "installed: {}\ntarget: {}\nlatest: {}\nupdate available: no",
                crate::release::PACKAGE_VERSION,
                target.triple(),
                selection.version
            );
            Ok(None)
        }
    }
}

/// Resolve only a qualified, absolute curl binary. PATH is never consulted.
pub fn system_transport() -> Result<eggup_curl::CurlTransport, String> {
    use eggup_curl::{CurlConfig, CurlTransport};
    for candidate in ["/usr/bin/curl", "/bin/curl"] {
        let path = Path::new(candidate);
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        if metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
        {
            return CurlTransport::with_executable(
                path,
                CurlConfig::strict()
                    .allowed_protocols(vec!["https".into()])
                    .follow_redirects(true)
                    .max_redirects(5)
                    .timeouts(Duration::from_secs(10), Duration::from_secs(300)),
            )
            .map_err(|_| "curl transport policy could not be configured".into());
        }
    }
    Err("no safe allowlisted curl executable is available".into())
}

/// `update`: no mutation is possible without authenticated release metadata.
pub fn apply() -> Result<(), String> {
    let _ = require_production_key()?;
    Err("transactional update is unavailable until M004 recovery qualification is complete".into())
}

/// `update recover`: never guess while the production recovery machinery is
/// unavailable. An absent journal is a safe no-op; a present journal requires
/// an operator-visible fail-closed refusal until the full recovery engine is
/// enabled.
pub fn recover() -> Result<(), String> {
    match fs::symlink_metadata(UPDATE_JOURNAL_PATH) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err("no update recovery journal is present".into())
        }
        Err(_) => return Err("update journal cannot be inspected safely".into()),
        Ok(_) => {}
    }
    let _ = read_journal(Path::new(UPDATE_JOURNAL_PATH))
        .map_err(|_| "update journal is unsafe or invalid".to_owned())?;
    Err("update recovery requires a qualified production trust root and recovery engine".into())
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn invalid_journal() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "update journal is invalid or unsafe",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eggup_acquisition::{FixtureResponse, FixtureTransport};
    use std::os::unix::fs::PermissionsExt;

    fn journal(root: &Path) -> UpdateJournal {
        UpdateJournal {
            schema: JOURNAL_SCHEMA,
            transaction_id: "test-transaction_1".into(),
            version_from: "0.1.0".into(),
            version_to: "0.1.1".into(),
            target: crate::release::LinuxTarget::from_host(
                std::env::consts::OS,
                std::env::consts::ARCH,
            )
            .unwrap()
            .triple()
            .into(),
            phase: UpdatePhase::Prepared,
            transaction_dir: root.join("test-transaction_1"),
            old_binary_sha256: "a".repeat(64),
            candidate_sha256: "b".repeat(64),
            state_backup_sha256: None,
            manifest_sha256: None,
            signing_key_id: None,
        }
    }

    #[test]
    fn journal_rejects_invalid_version_path_and_digest() {
        let root = Path::new("/var/lib/wg-basic-system/rollback");
        let mut value = journal(root);
        assert!(value.validate(root).is_ok());
        value.transaction_dir = PathBuf::from("/tmp/attacker");
        assert!(value.validate(root).is_err());
        let mut value = journal(root);
        value.version_to = "0.0.9".into();
        assert!(value.validate(root).is_err());
        let mut value = journal(root);
        value.candidate_sha256 = "not-a-digest".into();
        assert!(value.validate(root).is_err());
    }

    #[test]
    fn journal_state_machine_rejects_skipped_and_terminal_transitions() {
        assert!(transition_allowed(
            UpdatePhase::Prepared,
            UpdatePhase::BackupVerified
        ));
        assert!(!transition_allowed(
            UpdatePhase::Prepared,
            UpdatePhase::BinaryCommitted
        ));
        assert!(transition_allowed(
            UpdatePhase::CandidateHealthy,
            UpdatePhase::Committed
        ));
        assert!(transition_allowed(
            UpdatePhase::CandidateHealthy,
            UpdatePhase::RollingBack
        ));
        assert!(!transition_allowed(
            UpdatePhase::Committed,
            UpdatePhase::RollingBack
        ));
        assert!(!transition_allowed(
            UpdatePhase::RolledBack,
            UpdatePhase::CandidateStarted
        ));
    }

    #[test]
    fn journal_round_trip_is_atomic_and_private() {
        let temp = std::env::temp_dir().join(format!("wg-basic-update-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(temp.join("rollback")).unwrap();
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(temp.join("rollback"), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.join("update-journal.json");
        let value = journal(&temp.join("rollback"));
        let owner = nix::unistd::Uid::effective().as_raw();
        write_journal_owned_by(&path, &value, owner).unwrap();
        assert_eq!(read_journal_owned_by(&path, owner).unwrap(), value);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn update_operations_refuse_without_a_production_key() {
        assert!(require_production_key()
            .unwrap_err()
            .contains("production Minisign trust root"));
        assert!(apply()
            .unwrap_err()
            .contains("production Minisign trust root"));
        assert!(check().is_err());
    }

    #[test]
    fn discovery_accepts_only_exact_published_stable_tags() {
        let accepted = br#"{"tag_name":"v1.2.3","prerelease":false,"draft":false}"#;
        assert_eq!(parse_latest_release(accepted).unwrap().version, "1.2.3");
        for rejected in [
            br#"{"tag_name":"1.2.3","prerelease":false,"draft":false}"#.as_slice(),
            br#"{"tag_name":"v1.2.3-rc1","prerelease":false,"draft":false}"#,
            br#"{"tag_name":"v1.2.3","prerelease":true,"draft":false}"#,
            br#"{"tag_name":"v1.2.3","prerelease":false,"draft":true}"#,
            br#"{"tag_name":"v01.2.3","prerelease":false,"draft":false}"#,
        ] {
            assert!(parse_latest_release(rejected).is_err());
        }
    }

    #[test]
    fn acquisition_uses_exact_tag_and_authenticates_before_projection() {
        let fixture = FixtureTransport::new();
        let base = format!("{RELEASE_ORIGIN}/v0.2.0");
        let manifest_url = format!("{base}/release-manifest.json");
        fixture.route(
            &manifest_url,
            FixtureResponse::body(
                include_bytes!("../tests/fixtures/release-auth/release-manifest.json").to_vec(),
            ),
        );
        let signature_url = format!("{base}/release-manifest.json.minisig");
        fixture.route(
            &signature_url,
            FixtureResponse::body(
                include_bytes!("../tests/fixtures/release-auth/release-manifest.json.minisig")
                    .to_vec(),
            ),
        );
        let selection = ReleaseSelection {
            version: "0.2.0".into(),
            tag_name: "v0.2.0".into(),
            prerelease: false,
            draft: false,
        };
        let release = acquire_authenticated_release(
            &fixture,
            &selection,
            "0.1.0",
            crate::release::LinuxTarget::X86_64,
            include_str!("../tests/fixtures/release-auth/minisign.fixture.pub"),
        )
        .unwrap();
        assert_eq!(release.version, "0.2.0");
        assert_eq!(release.manifest_sha256.len(), 64);
        assert!(matches!(
            release.projection,
            eggup_eggpack::ManifestProjection::Installable { .. }
        ));
    }

    #[test]
    fn authenticated_check_uses_untrusted_discovery_only_for_exact_signed_urls() {
        let fixture = FixtureTransport::new();
        fixture.route(
            RELEASE_DISCOVERY_URL,
            FixtureResponse::body(
                br#"{"tag_name":"v0.2.0","prerelease":false,"draft":false}"#.to_vec(),
            ),
        );
        let base = format!("{RELEASE_ORIGIN}/v0.2.0");
        let manifest_url = format!("{base}/release-manifest.json");
        fixture.route(
            &manifest_url,
            FixtureResponse::body(
                include_bytes!("../tests/fixtures/release-auth/release-manifest.json").to_vec(),
            ),
        );
        let signature_url = format!("{base}/release-manifest.json.minisig");
        fixture.route(
            &signature_url,
            FixtureResponse::body(
                include_bytes!("../tests/fixtures/release-auth/release-manifest.json.minisig")
                    .to_vec(),
            ),
        );
        let release = check_with(
            &fixture,
            include_str!("../tests/fixtures/release-auth/minisign.fixture.pub"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(release.version, "0.2.0");

        let tampered = FixtureTransport::new();
        tampered.route(
            RELEASE_DISCOVERY_URL,
            FixtureResponse::body(
                br#"{"tag_name":"v0.2.0","prerelease":false,"draft":false}"#.to_vec(),
            ),
        );
        tampered.route(
            &manifest_url,
            FixtureResponse::body(b"unsigned attacker manifest".to_vec()),
        );
        tampered.route(
            &signature_url,
            FixtureResponse::body(
                include_bytes!("../tests/fixtures/release-auth/release-manifest.json.minisig")
                    .to_vec(),
            ),
        );
        assert!(check_with(
            &tampered,
            include_str!("../tests/fixtures/release-auth/minisign.fixture.pub"),
        )
        .is_err());
    }

    #[test]
    fn eggup_commit_keeps_old_binary_until_product_check_and_rolls_back_on_failure() {
        use eggup_core::TransactionDisposition;
        use std::os::unix::fs::PermissionsExt;

        let base =
            std::env::temp_dir().join(format!("wg-basic-eggup-update-{}", uuid::Uuid::new_v4()));
        let install = base.join("install");
        let stage = base.join("stage");
        fs::create_dir_all(&install).unwrap();
        fs::create_dir_all(&stage).unwrap();
        let installed = install.join("wg-basic");
        let candidate = stage.join("candidate");
        fs::write(&installed, b"old binary bytes").unwrap();
        fs::write(
            &candidate,
            b"#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'wg-basic 0.2.0\\n'; exit 0; fi\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        let old_digest = eggup_core::hash_file(&installed).unwrap();
        let candidate_digest = eggup_core::hash_file(&candidate).unwrap();
        let passed = std::cell::Cell::new(false);
        let receipt = eggup_commit_binary(
            &install,
            "wg-basic",
            &candidate,
            "0.2.0",
            old_digest,
            candidate_digest,
            || {
                passed.set(true);
                assert_eq!(fs::read(&installed).unwrap(), fs::read(&candidate).unwrap());
                Ok(())
            },
        )
        .unwrap();
        assert!(passed.get());
        assert_eq!(receipt.disposition(), TransactionDisposition::Committed);
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&candidate).unwrap());

        fs::write(&installed, b"old binary bytes").unwrap();
        let failed = eggup_commit_binary(
            &install,
            "wg-basic",
            &candidate,
            "0.2.0",
            old_digest,
            candidate_digest,
            || Err("product health failed".to_owned()),
        )
        .unwrap();
        assert_eq!(failed.disposition(), TransactionDisposition::RolledBack);
        assert_eq!(fs::read(&installed).unwrap(), b"old binary bytes");
        let _ = fs::remove_dir_all(base);
    }
}
