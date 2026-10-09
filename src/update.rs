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
    eggup_commit_binary_inner(
        install_root,
        destination_name,
        candidate,
        version,
        expected_old_sha256,
        expected_candidate_sha256,
        post_commit,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Mirrors the typed Eggup transaction inputs.
fn eggup_commit_binary_inner<F>(
    install_root: &Path,
    destination_name: &str,
    candidate: &Path,
    version: &str,
    expected_old_sha256: [u8; 32],
    expected_candidate_sha256: [u8; 32],
    post_commit: F,
    stale_lock_verifier: Option<&dyn eggup_core::StaleLockVerifier>,
) -> Result<eggup_core::TransactionReceipt, String>
where
    F: FnOnce() -> Result<(), String>,
{
    use eggup_core::{
        AbsentPolicy, ArtifactMember, ArtifactSet, CommitOwnership, ExactDigestVerifier,
        InstallPlan, IntegrityRequirement, MemberId, PermissionsIntent, ProductId, ReleaseId,
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
    let ownership = CommitOwnership::new(&verifier, AbsentPolicy::DenyCreate);
    let commit_callback = || {
        ensure_installed_executable(&expected_candidate_sha256)?;
        post_commit()
    };
    let receipt = match stale_lock_verifier {
        Some(stale_lock_verifier) => validated.commit_with_post_commit_and_stale_lock_recovery(
            ownership,
            eggup_core::PostCommitFailurePolicy::RollBack,
            stale_lock_verifier,
            commit_callback,
        ),
        None => validated
            .commit_with_post_commit(
                ownership,
                eggup_core::PostCommitFailurePolicy::RollBack,
                commit_callback,
            )
            .map_err(Into::into),
    }
    .map_err(|_| "Eggup binary transaction could not prove a terminal result")?;
    Ok(receipt)
}

#[allow(dead_code)] // Used by the M004 mutating transaction orchestration.
fn stop_management_service() -> Result<(), String> {
    stop_owned_service(service_endpoint("wg-basic.service", true)?)
}

fn stop_network_service() -> Result<(), String> {
    stop_owned_service(service_endpoint("wg-basic-netd.service", false)?)
}

fn stop_owned_services() -> Result<(), String> {
    use eggup_service::{Ownership, ServiceManager};
    for endpoint in [
        service_endpoint("wg-basic.service", true)?,
        service_endpoint("wg-basic-netd.service", false)?,
    ] {
        let snapshot = endpoint
            .0
            .inspect(&endpoint.1)
            .map_err(|_| "could not inspect product services before stop")?;
        if snapshot.ownership != Ownership::Owned || !stop_preflight_state_allowed(snapshot.state) {
            return Err("product service ownership or lifecycle is ambiguous".into());
        }
    }
    stop_owned_service(service_endpoint("wg-basic.service", true)?)?;
    stop_owned_service(service_endpoint("wg-basic-netd.service", false)?)
}

#[allow(dead_code)] // Used by M004 preflight before backup or service mutation.
fn require_running_owned_services() -> Result<(), String> {
    use eggup_service::{LifecycleState, Ownership, ServiceManager};
    for endpoint in [
        service_endpoint("wg-basic-netd.service", false)?,
        service_endpoint("wg-basic.service", true)?,
    ] {
        let snapshot = endpoint
            .0
            .inspect(&endpoint.1)
            .map_err(|_| "could not inspect product services before update")?;
        if snapshot.ownership != Ownership::Owned || snapshot.state != LifecycleState::Running {
            return Err("both owned product services must be running before update".into());
        }
    }
    Ok(())
}

#[allow(dead_code)] // Used by the M004 mutating transaction orchestration.
fn start_owned_services() -> Result<(), String> {
    start_owned_service(service_endpoint("wg-basic-netd.service", false)?)?;
    start_owned_service(service_endpoint("wg-basic.service", true)?)
}

fn service_endpoint(
    name: &str,
    management: bool,
) -> Result<
    (
        eggup_service::SystemdManager<eggup_service::SystemExecutor>,
        eggup_service::ServiceSpec,
    ),
    String,
> {
    use eggup_service::{
        ServiceId, ServiceSpec, SystemExecutor, SystemdInstall, SystemdManager, SystemdScope,
    };
    let (path, definition, args) = if management {
        (
            crate::distribution::SERVE_UNIT_PATH,
            crate::distribution::SERVE_UNIT,
            vec![
                "serve".to_owned(),
                "--state".to_owned(),
                crate::distribution::STATE_PATH.to_owned(),
                "--socket".to_owned(),
                crate::distribution::SOCKET_PATH.to_owned(),
            ],
        )
    } else {
        (
            crate::distribution::NETD_UNIT_PATH,
            crate::distribution::NETD_UNIT,
            vec![
                "netd".to_owned(),
                "--socket".to_owned(),
                crate::distribution::SOCKET_PATH.to_owned(),
                "--allow-user".to_owned(),
                "wg-basic".to_owned(),
            ],
        )
    };
    let install = SystemdInstall::new(
        name.to_owned(),
        SystemdScope::System,
        path.into(),
        definition.as_bytes().to_vec(),
        false,
        false,
        Duration::from_secs(20),
    )
    .map_err(|_| "invalid product service definition")?;
    let spec = ServiceSpec::new(
        ServiceId::new(name).map_err(|_| "invalid product service id")?,
        crate::distribution::BINARY_PATH.into(),
        args,
        None,
    )
    .map_err(|_| "invalid product service specification")?;
    Ok((
        SystemdManager::new(SystemExecutor::default(), install),
        spec,
    ))
}

fn stop_owned_service(
    (mut manager, spec): (
        eggup_service::SystemdManager<eggup_service::SystemExecutor>,
        eggup_service::ServiceSpec,
    ),
) -> Result<(), String> {
    use eggup_service::{LifecycleState, Ownership, ServiceManager};
    let before = manager
        .inspect(&spec)
        .map_err(|_| "could not inspect product service before stop")?;
    if before.ownership != Ownership::Owned {
        return Err("product service registration is not owned".into());
    }
    let stop_completed = if matches!(
        before.state,
        LifecycleState::Running | LifecycleState::Unknown
    ) {
        let result = manager
            .stop(&spec, Duration::from_secs(30))
            .map_err(|_| "could not stop product service")?;
        if !result.completed() {
            return Err("product service stop did not prove quiescence".into());
        }
        true
    } else {
        false
    };
    let after = manager
        .inspect(&spec)
        .map_err(|_| "could not confirm product service stop")?;
    if after.ownership != Ownership::Owned
        || !stop_postcondition_allowed(before.state, stop_completed, after.state)
    {
        return Err("product service did not stop cleanly".into());
    }
    match spec.id().as_str() {
        "wg-basic.service" => confirm_serve_lease_released()?,
        "wg-basic-netd.service" => confirm_netd_socket_inactive()?,
        _ => return Err("unexpected product service identity".into()),
    }
    Ok(())
}

fn stop_preflight_state_allowed(state: eggup_service::LifecycleState) -> bool {
    use eggup_service::LifecycleState;
    matches!(
        state,
        LifecycleState::Running | LifecycleState::Stopped | LifecycleState::Unknown
    )
}

/// Recovery-only authorization for the exact Eggup lock an interrupted,
/// journaled updater can leave behind while its binary callback is running.
/// `update recover` holds wg-basic's exclusive install lock before constructing
/// this verifier and has already validated the journal, installed candidate,
/// old-binary copy, and backup.
struct UpdateJournalStaleLockVerifier {
    expected_release: String,
}

impl eggup_core::StaleLockVerifier for UpdateJournalStaleLockVerifier {
    fn classify(&self, observed: &eggup_core::LockObservation) -> eggup_core::StaleLockDecision {
        use eggup_core::StaleLockDecision;

        let expected_path = Path::new(crate::distribution::BINARY_PATH)
            .parent()
            .unwrap_or_else(|| Path::new("/usr/local/bin"))
            .join(".eggup-mutation.lock");
        if observed.path() != expected_path
            || !observed.format_known()
            || observed.product() != Some(crate::release::PRODUCT_ID)
            || observed.release() != Some(self.expected_release.as_str())
        {
            return StaleLockDecision::Unknown;
        }
        match fs::symlink_metadata(observed.path()) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o777 == 0o600
                    && metadata.nlink() == 1 => {}
            _ => return StaleLockDecision::Unknown,
        }
        let Some(pid) = observed.pid() else {
            return StaleLockDecision::Unknown;
        };
        match fs::symlink_metadata(Path::new("/proc").join(pid.to_string())) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => StaleLockDecision::ProvenStale,
            Ok(_) => StaleLockDecision::Active,
            Err(_) => StaleLockDecision::Unknown,
        }
    }
}

fn stop_postcondition_allowed(
    before: eggup_service::LifecycleState,
    stop_completed: bool,
    after: eggup_service::LifecycleState,
) -> bool {
    use eggup_service::LifecycleState;
    (after == LifecycleState::Stopped
        && ((before == LifecycleState::Running && stop_completed)
            || (before == LifecycleState::Stopped && !stop_completed)))
        || (before == LifecycleState::Unknown && stop_completed && after == LifecycleState::Unknown)
}

fn confirm_serve_lease_released() -> Result<(), String> {
    let owner = nix::unistd::User::from_name("wg-basic")
        .map_err(|_| "management account lookup failed")?
        .ok_or("management account is missing")?;
    match crate::state::ServiceLease::is_held_by_uid(
        Path::new(crate::distribution::STATE_PATH),
        owner.uid.as_raw(),
    ) {
        Ok(false) => Ok(()),
        Ok(true) => Err("management service still holds its state lease".into()),
        Err(_) => Err("management service lease state is ambiguous".into()),
    }
}

fn confirm_netd_socket_inactive() -> Result<(), String> {
    use std::os::unix::net::UnixStream;
    match UnixStream::connect(crate::distribution::SOCKET_PATH) {
        Ok(_stream) => Err("network service socket is still accepting connections".into()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(_) => Err("network service socket state is ambiguous".into()),
    }
}

fn start_owned_service(
    (mut manager, spec): (
        eggup_service::SystemdManager<eggup_service::SystemExecutor>,
        eggup_service::ServiceSpec,
    ),
) -> Result<(), String> {
    use eggup_service::{LifecycleState, Ownership, ServiceManager};
    let before = manager
        .inspect(&spec)
        .map_err(|_| "could not inspect product service before start")?;
    if before.ownership != Ownership::Owned {
        return Err("product service registration is not owned".into());
    }
    if before.state != LifecycleState::Running {
        manager
            .start(&spec, Duration::from_secs(30))
            .map_err(|_| "could not start product service")?;
    }
    let after = manager
        .inspect(&spec)
        .map_err(|_| "could not confirm product service start")?;
    if after.ownership != Ownership::Owned || after.state != LifecycleState::Running {
        return Err("product service did not start cleanly".into());
    }
    Ok(())
}

#[allow(dead_code)] // Used by the M004 candidate-health callback.
fn validate_candidate_health(expected: &StateIdentity) -> Result<(), String> {
    use eggup_service::{LifecycleState, Ownership, ServiceManager};
    for endpoint in [
        service_endpoint("wg-basic-netd.service", false)?,
        service_endpoint("wg-basic.service", true)?,
    ] {
        let snapshot = endpoint
            .0
            .inspect(&endpoint.1)
            .map_err(|_| "could not inspect product service health")?;
        if snapshot.ownership != Ownership::Owned || snapshot.state != LifecycleState::Running {
            return Err("candidate product service is not owned and running".into());
        }
    }
    // ExecStartPre runs doctor before serve acquires the database lease.
    // Doctor correctly marks immutable inspection of live WAL sidecars Unknown,
    // so use the live health projection below for candidate validation.
    let health = run_as_management(&[
        "health",
        "--state",
        crate::distribution::STATE_PATH,
        "--socket",
        crate::distribution::SOCKET_PATH,
    ])?;
    if !health.success() {
        return Err("candidate management health command failed".into());
    }
    let health: serde_json::Value = serde_json::from_slice(health.stdout())
        .map_err(|_| "candidate management health projection is invalid")?;
    if !health_projection_healthy(&health, expected) {
        return Err("candidate management state or backend is not healthy".into());
    }
    let observed = read_state_identity(Path::new(crate::distribution::STATE_PATH))?;
    if observed.installation_id != expected.installation_id
        || observed.desired_generation != expected.desired_generation
        || observed.product_identity_sha256 != expected.product_identity_sha256
        || observed.network_enabled != expected.network_enabled
        || observed.schema_version < expected.schema_version
    {
        return Err("candidate state identity is incompatible with the pre-update state".into());
    }
    let endpoint = health_endpoint_token()?;
    if endpoint != "ok" && (expected.network_enabled || endpoint != "degraded") {
        return Err("candidate /healthz is not healthy".into());
    }
    #[cfg(feature = "update-test-fixtures")]
    if std::env::var_os("WGB_UPDATE_TEST_FAIL_AFTER_HEALTH").is_some() {
        return Err("test fixture requested failure after candidate health".into());
    }
    Ok(())
}

fn health_projection_healthy(value: &serde_json::Value, expected: &StateIdentity) -> bool {
    let identity_matches = value
        .get("installation_id")
        .and_then(serde_json::Value::as_str)
        == Some(expected.installation_id.as_str())
        && value
            .get("current_desired_generation")
            .and_then(serde_json::Value::as_i64)
            == Some(expected.desired_generation);
    identity_matches
        && value
            .get("database_healthy")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        && (!expected.network_enabled
            || (value
                .get("netd_reachable")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
                && value.get("convergence").and_then(serde_json::Value::as_str)
                    == Some("converged")))
}

fn read_state_identity(path: &Path) -> Result<StateIdentity, String> {
    read_state_identity_program(Path::new(crate::distribution::BINARY_PATH), path)
}

fn read_state_identity_program(program: &Path, path: &Path) -> Result<StateIdentity, String> {
    let path = path.to_str().ok_or("state path is invalid")?;
    let output = run_as_management_program(program, &["state", "identity", "--state", path])?;
    if !output.success() {
        let detail = String::from_utf8_lossy(output.stderr())
            .chars()
            .take(256)
            .collect::<String>();
        return Err(format!(
            "management state identity command failed: {detail}"
        ));
    }
    serde_json::from_slice(output.stdout())
        .map_err(|_| "management state identity projection is invalid".into())
}

fn run_as_management(arguments: &[&str]) -> Result<eggup_core::CommandOutput, String> {
    run_as_management_program(Path::new(crate::distribution::BINARY_PATH), arguments)
}

fn run_as_management_program(
    program: &Path,
    arguments: &[&str],
) -> Result<eggup_core::CommandOutput, String> {
    let program_metadata = fs::symlink_metadata(program)
        .map_err(|_| "management command executable is unavailable")?;
    if !program_metadata.file_type().is_file()
        || program_metadata.uid() != 0
        || program_metadata.mode() & 0o022 != 0
        || program_metadata.mode() & 0o111 == 0
    {
        return Err("management command executable is unsafe".into());
    }
    let runuser = ["/usr/sbin/runuser", "/sbin/runuser"]
        .into_iter()
        .find(|candidate| {
            let path = Path::new(candidate);
            fs::symlink_metadata(path).is_ok_and(|metadata| {
                metadata.file_type().is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
                    && metadata.mode() & 0o111 != 0
            })
        })
        .ok_or("safe runuser executable is unavailable")?;
    let output = eggup_core::run_bounded(
        &eggup_core::CommandSpec::new(runuser)
            .args([
                "--user",
                "wg-basic",
                "--",
                program
                    .to_str()
                    .ok_or("management executable path is invalid")?,
            ])
            .args(arguments.iter().copied())
            .timeout(Duration::from_secs(60))
            .max_output_bytes(64 * 1024),
    )
    .map_err(|_| "could not run a bounded management health command")?;
    Ok(output)
}

fn ensure_root_private_directory(path: &Path, parent: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && metadata.uid() == 0
                && metadata.mode() & 0o777 == 0o700 =>
        {
            Ok(())
        }
        Ok(_) => Err("update recovery directory is unsafe".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| "could not create update recovery directory")?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| "could not secure update recovery directory")?;
            File::open(path)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "could not persist update recovery directory")?;
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "could not persist recovery directory entry")?;
            Ok(())
        }
        Err(_) => Err("update recovery directory cannot be inspected".into()),
    }
}

fn durable_copy(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    let mut input = File::open(source).map_err(|_| "recovery source is unavailable")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(destination)
        .map_err(|_| "recovery destination could not be created without replacement")?;
    io::copy(&mut input, &mut output).map_err(|_| "recovery artifact copy failed")?;
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|_| output.sync_all())
        .map_err(|_| "recovery artifact could not be made durable")?;
    let parent = destination
        .parent()
        .ok_or("recovery destination has no parent")?;
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "recovery directory entry could not be made durable")?;
    Ok(())
}

fn minisign_key_id(public_key: &str) -> Result<String, String> {
    use base64::Engine;
    let encoded = public_key
        .lines()
        .nth(1)
        .ok_or("production release key is invalid")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "production release key is invalid")?;
    if bytes.len() != 42 {
        return Err("production release key is invalid".into());
    }
    Ok(bytes[2..10]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect())
}

fn reject_unresolved_journal() -> Result<Option<PathBuf>, String> {
    let path = Path::new(UPDATE_JOURNAL_PATH);
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("update journal cannot be inspected safely".into()),
        Ok(_) => {
            let journal = read_journal(path)
                .map_err(|_| "an unsafe or invalid update journal requires operator recovery")?;
            if !matches!(
                journal.phase,
                UpdatePhase::Committed | UpdatePhase::RolledBack
            ) {
                return Err("an unresolved update transaction requires `update recover`".into());
            }
            let directory = fs::symlink_metadata(&journal.transaction_dir)
                .map_err(|_| "terminal update evidence directory is unavailable")?;
            if !directory.file_type().is_dir()
                || directory.uid() != 0
                || directory.mode() & 0o777 != 0o700
            {
                return Err("terminal update evidence directory is unsafe".into());
            }
            validate_transaction_artifacts(&journal)?;
            if journal.state_backup_sha256.is_some() {
                validate_state_backup(&journal)?;
            } else if journal.phase != UpdatePhase::RolledBack {
                return Err("terminal update lacks its required state backup".into());
            }
            let old_metadata = load_old_install_metadata(&journal)?;
            let expected_version = if journal.phase == UpdatePhase::Committed {
                &journal.version_to
            } else {
                &journal.version_from
            };
            let expected_digest = if journal.phase == UpdatePhase::Committed {
                &journal.candidate_sha256
            } else {
                &journal.old_binary_sha256
            };
            let installed = crate::distribution::validate_owned_installation()
                .map_err(|_| "terminal installation receipt is invalid")?;
            let actual_digest = installed_binary_digest()?;
            if installed.version != *expected_version
                || installed.binary_sha256 != *expected_digest
                || actual_digest != parse_digest(expected_digest)?
            {
                return Err(
                    "terminal installed binary and receipt do not match journal evidence".into(),
                );
            }
            if old_metadata.version != journal.version_from
                || old_metadata.binary_sha256 != journal.old_binary_sha256
            {
                return Err("pre-update installation evidence does not match the journal".into());
            }
            if journal.phase == UpdatePhase::RolledBack {
                let expected_state = journal.old_state_identity.as_ref()
                    .ok_or("terminal rollback lacks typed pre-update state evidence; manual recovery required")?;
                let actual_state = read_state_identity(Path::new(crate::distribution::STATE_PATH))?;
                if &actual_state != expected_state {
                    return Err(
                        "rolled-back state identity does not match its pre-update receipt".into(),
                    );
                }
                validate_running_product_health(expected_state)?;
            } else {
                let actual_state = read_state_identity(Path::new(crate::distribution::STATE_PATH))?;
                let previous = journal.old_state_identity.as_ref()
                    .ok_or("committed transaction lacks typed pre-update identity; manual recovery required")?;
                if actual_state.schema_version < old_state_schema_minimum(&journal)?
                    || actual_state.installation_id != previous.installation_id
                    || actual_state.desired_generation != previous.desired_generation
                    || actual_state.network_enabled != previous.network_enabled
                    || actual_state.product_identity_sha256 != previous.product_identity_sha256
                {
                    return Err(
                        "committed state schema is older than its pre-update identity".into(),
                    );
                }
                validate_running_product_health(&actual_state)?;
            }
            let archive = journal.transaction_dir.join("journal.json");
            if !matches!(fs::symlink_metadata(&archive), Err(error) if error.kind() == io::ErrorKind::NotFound)
            {
                return Err("committed update evidence archive is already occupied".into());
            }
            fs::rename(path, &archive)
                .map_err(|_| "committed update journal could not be archived")?;
            File::open(Path::new(crate::distribution::SYSTEM_DIR))
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "committed journal removal could not be made durable")?;
            File::open(&journal.transaction_dir)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "committed journal archive could not be made durable")?;
            Ok(Some(journal.transaction_dir))
        }
    }
}

fn old_state_schema_minimum(journal: &UpdateJournal) -> Result<i64, String> {
    journal
        .old_state_identity
        .as_ref()
        .map(|identity| identity.schema_version)
        .ok_or_else(|| {
            "terminal transaction lacks typed state evidence; manual recovery required".into()
        })
}

fn validate_running_product_health(expected: &StateIdentity) -> Result<(), String> {
    require_running_owned_services()?;
    // This runs with serve active. Its WAL sidecars make doctor’s immutable
    // inspection Unknown by design; live health and typed identity are used.
    let output = run_as_management(&[
        "health",
        "--state",
        crate::distribution::STATE_PATH,
        "--socket",
        crate::distribution::SOCKET_PATH,
    ])?;
    if !output.success() {
        return Err("terminal product health command failed".into());
    }
    let value: serde_json::Value = serde_json::from_slice(output.stdout())
        .map_err(|_| "terminal product health projection is invalid")?;
    if !health_projection_healthy(&value, expected) {
        return Err("terminal installed product health does not match its state identity".into());
    }
    let endpoint = health_endpoint_token()?;
    if expected.network_enabled && endpoint != "ok" {
        return Err("terminal enabled product health endpoint is degraded".into());
    }
    Ok(())
}

fn fail_before_services(journal: &UpdateJournal, cause: String) -> Result<(), String> {
    let path = Path::new(UPDATE_JOURNAL_PATH);
    let current = read_journal(path)
        .map_err(|_| "update journal is unavailable; manual recovery is required")?;
    let rolling = if current.phase == UpdatePhase::RollingBack {
        current
    } else {
        advance_journal(path, &current, UpdatePhase::RollingBack)
            .map_err(|_| "could not persist pre-update rollback phase")?
    };
    let expected = journal
        .old_state_identity
        .as_ref()
        .ok_or("pre-update rollback lacks state identity evidence")?;
    let old_binary = crate::distribution::verify_owned_file(
        Path::new(crate::distribution::BINARY_PATH),
        &journal.old_binary_sha256,
        0,
    )
    .is_ok();
    let state = read_state_identity(Path::new(crate::distribution::STATE_PATH));
    if !old_binary || state.as_ref() != Ok(expected) {
        mark_recovery_required(path);
        return Err(
            "pre-update failure left an unproven binary/state pair; operator recovery is required"
                .into(),
        );
    }
    if let Err(error) =
        start_owned_services().and_then(|_| validate_running_product_health(expected))
    {
        let _ = stop_owned_services();
        mark_recovery_required(path);
        return Err(format!(
            "pre-update failure could not restore healthy services: {error}"
        ));
    }
    advance_journal(path, &rolling, UpdatePhase::RolledBack)
        .map_err(|_| "pre-update rollback result could not be persisted")?;
    let _ = journal;
    Err(cause)
}

fn mark_recovery_required(path: &Path) {
    if let Ok(current) = read_journal(path) {
        if current.phase != UpdatePhase::RecoveryRequired {
            let _ = advance_journal(path, &current, UpdatePhase::RecoveryRequired);
        }
    }
}

fn save_old_binary(
    metadata: &crate::distribution::InstallMetadata,
    transaction_dir: &Path,
    transaction_id: &str,
) -> Result<PathBuf, String> {
    crate::distribution::verify_owned_file(
        Path::new(crate::distribution::BINARY_PATH),
        &metadata.binary_sha256,
        0,
    )
    .map_err(|_| "installed binary is not the exact owned release")?;
    let destination = transaction_dir.join("old-wg-basic");
    durable_copy(
        Path::new(crate::distribution::BINARY_PATH),
        &destination,
        // Eggup installs the source mode on rollback. Keep the recovery
        // executable usable by the unprivileged management identity after
        // it is moved back to /usr/local/bin; the containing transaction
        // directory remains root-only (0700).
        0o755,
    )?;
    if eggup_core::hash_file(&destination).map_err(|_| "old binary digest failed")?
        != parse_digest(&metadata.binary_sha256)?
    {
        return Err("old binary recovery copy does not match installation receipt".into());
    }
    let accessible_copy = runtime_old_binary_path(transaction_id);
    durable_copy(&destination, &accessible_copy, 0o755)?;
    Ok(destination)
}

fn save_old_install_metadata(
    metadata: &crate::distribution::InstallMetadata,
    transaction_dir: &Path,
) -> Result<String, String> {
    metadata
        .validate()
        .map_err(|_| "installation metadata is invalid before update")?;
    let path = transaction_dir.join("install-pre-update.json");
    let bytes = serde_json::to_vec_pretty(metadata)
        .map_err(|_| "installation metadata snapshot could not be encoded")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&path)
        .map_err(|_| "installation metadata snapshot could not be created")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "installation metadata snapshot could not be made durable")?;
    File::open(transaction_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "installation metadata directory entry could not be made durable")?;
    Ok(sha256_hex(&bytes))
}

fn load_old_install_metadata(
    journal: &UpdateJournal,
) -> Result<crate::distribution::InstallMetadata, String> {
    let path = journal.transaction_dir.join("install-pre-update.json");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| "pre-update installation metadata snapshot is unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 64 * 1024
    {
        return Err("pre-update installation metadata snapshot is unsafe".into());
    }
    let bytes = fs::read(path).map_err(|_| "pre-update installation metadata could not be read")?;
    if sha256_hex(&bytes) != journal.old_install_metadata_sha256 {
        return Err("pre-update installation metadata snapshot digest is invalid".into());
    }
    let old: crate::distribution::InstallMetadata = serde_json::from_slice(&bytes)
        .map_err(|_| "pre-update installation metadata is invalid")?;
    old.validate()
        .map_err(|_| "pre-update installation metadata identity is invalid")?;
    if old.version != journal.version_from || old.binary_sha256 != journal.old_binary_sha256 {
        return Err("pre-update installation metadata does not match the journal".into());
    }
    Ok(old)
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(&sha2::Sha256::digest(bytes))
}

fn digest_hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn runtime_old_binary_path(transaction_id: &str) -> PathBuf {
    Path::new("/usr/local/bin").join(format!(".wg-basic-old-{transaction_id}"))
}

fn create_state_backup(
    transaction_id: &str,
    transaction_dir: &Path,
    expected_identity: &StateIdentity,
) -> Result<PathBuf, String> {
    let state_dir = Path::new(crate::distribution::STATE_DIR);
    let source = state_dir.join(format!(".wg-basic-update-{transaction_id}.db"));
    if fs::symlink_metadata(&source).is_ok() {
        return Err("state backup temporary path is already occupied".into());
    }
    let source_text = source.to_str().ok_or("state backup path is invalid")?;
    let backup = run_as_management(&[
        "state",
        "backup",
        source_text,
        "--state",
        crate::distribution::STATE_PATH,
    ])?;
    if !backup.success() {
        return Err("management service could not create a consistent state backup".into());
    }
    let verify = run_as_management(&["state", "verify", source_text])?;
    if !verify.success() {
        let _ = fs::remove_file(&source);
        return Err("pre-update state backup did not validate".into());
    }
    if read_state_identity(&source)? != *expected_identity {
        let _ = fs::remove_file(&source);
        return Err("pre-update backup identity differs from the locked state".into());
    }
    let user = nix::unistd::User::from_name("wg-basic")
        .map_err(|_| "management account lookup failed")?
        .ok_or("management account is missing")?;
    let metadata =
        fs::symlink_metadata(&source).map_err(|_| "pre-update state backup is missing")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != user.uid.as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        let _ = fs::remove_file(&source);
        return Err("pre-update state backup ownership or mode is unsafe".into());
    }
    let destination = transaction_dir.join("state-pre-update.db");
    if let Err(error) = durable_copy(&source, &destination, 0o600) {
        let _ = fs::remove_file(&source);
        return Err(error);
    }
    let copied_digest =
        eggup_core::hash_file(&destination).map_err(|_| "pre-update backup digest failed")?;
    let source_digest =
        eggup_core::hash_file(&source).map_err(|_| "pre-update backup source digest failed")?;
    if copied_digest != source_digest {
        let _ = fs::remove_file(&destination);
        let _ = fs::remove_file(&source);
        return Err("pre-update backup copy changed bytes".into());
    }
    fs::remove_file(&source).map_err(|_| "temporary state backup could not be removed")?;
    File::open(state_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "state backup cleanup could not be made durable")?;
    Ok(destination)
}

fn restore_state_backup(
    old_binary: &Path,
    backup: &Path,
    transaction_id: &str,
) -> Result<(), String> {
    let state_dir = Path::new(crate::distribution::STATE_DIR);
    let restore_path = state_dir.join(format!(
        ".wg-basic-restore-{transaction_id}-{}.db",
        uuid::Uuid::new_v4()
    ));
    durable_copy(backup, &restore_path, 0o600)?;
    let user = nix::unistd::User::from_name("wg-basic")
        .map_err(|_| "management account lookup failed")?
        .ok_or("management account is missing")?;
    let group = nix::unistd::Group::from_name("wg-basic")
        .map_err(|_| "management group lookup failed")?
        .ok_or("management group is missing")?;
    nix::unistd::chown(&restore_path, Some(user.uid), Some(group.gid))
        .map_err(|_| "state restore file ownership could not be assigned")?;
    let staged = fs::symlink_metadata(&restore_path)
        .map_err(|_| "state restore staging file cannot be inspected")?;
    if !staged.file_type().is_file()
        || staged.uid() != user.uid.as_raw()
        || staged.mode() & 0o777 != 0o600
        || staged.nlink() != 1
    {
        return Err("state restore staging file ownership or mode is unsafe".into());
    }
    let restore_text = restore_path
        .to_str()
        .ok_or("state restore path is invalid")?;
    let backup_verification =
        run_as_management_program(old_binary, &["state", "verify", restore_text])?;
    if !backup_verification.success() {
        return Err("pre-update state backup failed offline validation".into());
    }
    let backup_identity = read_state_identity_program(old_binary, &restore_path)?;
    let restored = run_as_management_program(
        old_binary,
        &[
            "state",
            "restore",
            restore_text,
            "--state",
            crate::distribution::STATE_PATH,
        ],
    )?;
    if !restored.success() {
        return Err("compatible pre-update state could not be restored".into());
    }
    let restored_identity =
        read_state_identity_program(old_binary, Path::new(crate::distribution::STATE_PATH))?;
    if restored_identity != backup_identity {
        return Err("restored pre-update state did not pass integrity validation".into());
    }
    fs::remove_file(&restore_path)
        .map_err(|_| "state restore staging file could not be removed")?;
    File::open(state_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "state restore staging cleanup could not be made durable")?;
    Ok(())
}

fn parse_digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("installation digest is invalid".into());
    }
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "installation digest is invalid")?;
        digest[index] =
            u8::from_str_radix(text, 16).map_err(|_| "installation digest is invalid")?;
    }
    Ok(digest)
}

fn health_endpoint_token() -> Result<String, String> {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
        thread,
        time::Instant,
    };
    let address = SocketAddr::from(([127, 0, 0, 1], 8000));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(500)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(250)),
            Err(_) => return Err("candidate /healthz endpoint is unavailable".into()),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "could not bound candidate health response")?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n")
        .map_err(|_| "candidate health request failed")?;
    let mut response = [0; 4096];
    let count = stream
        .read(&mut response)
        .map_err(|_| "candidate health response failed")?;
    let response = std::str::from_utf8(&response[..count])
        .map_err(|_| "candidate health response was invalid")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("candidate health response was incomplete")?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err("candidate health endpoint returned a non-success status".into());
    }
    if body != "ok" && body != "degraded" {
        return Err("candidate health endpoint returned an invalid liveness token".into());
    }
    Ok(body.to_owned())
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
    pub old_install_metadata_sha256: String,
    pub candidate_sha256: String,
    pub state_backup_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub signing_key_id: Option<String>,
    /// Secret-free identity captured while the old schema is still live.
    /// Missing on historical schema-1 journals, which then require manual
    /// review before terminal success can be claimed.
    #[serde(default)]
    pub old_state_identity: Option<StateIdentity>,
}

/// Typed, non-secret compatibility evidence for the authoritative state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateIdentity {
    pub installation_id: String,
    pub schema_version: i64,
    pub desired_generation: i64,
    pub network_enabled: bool,
    pub product_identity_sha256: String,
}

/// Return a typed identity for one current state database without exposing
/// desired rows, keys, credentials, or session data.
pub fn state_identity(path: &Path) -> Result<StateIdentity, String> {
    use crate::state::StateStore;
    let store = StateStore::open(path).map_err(|_| "state identity could not be read")?;
    let metadata = store
        .installation_metadata()
        .map_err(|_| "state installation identity could not be read")?;
    let product = store
        .load_product()
        .map_err(|_| "state product identity could not be read")?;
    let mut identities = serde_json::json!({
        "interfaces": product.state.interfaces.keys().map(ToString::to_string).collect::<Vec<_>>(),
        "clients": product.state.clients.keys().map(ToString::to_string).collect::<Vec<_>>(),
    });
    // JSON objects are deterministic here: keys and IDs are ordered maps.
    let encoded = serde_json::to_vec(&identities)
        .map_err(|_| "state product identity could not be encoded")?;
    let product_identity_sha256 = sha256_hex(&encoded);
    // Drop the value before returning so this projection has no accidental
    // future path to secret-bearing product rows.
    identities = serde_json::Value::Null;
    let _ = identities;
    Ok(StateIdentity {
        installation_id: metadata.installation_id.to_string(),
        schema_version: store
            .schema_version()
            .map_err(|_| "state schema identity could not be read")?,
        desired_generation: metadata.desired_generation.to_storage(),
        network_enabled: product
            .state
            .network_operational_enabled
            .values()
            .any(|enabled| *enabled),
        product_identity_sha256,
    })
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
            Some(self.old_install_metadata_sha256.as_str()),
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
        if self.old_state_identity.as_ref().is_some_and(|identity| {
            uuid::Uuid::parse_str(&identity.installation_id).is_err()
                || identity.schema_version <= 0
                || crate::domain::DesiredGeneration::from_storage(identity.desired_generation)
                    .is_none()
                || identity.product_identity_sha256.len() != 64
                || !identity
                    .product_identity_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
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
    let mut updated = expected.clone();
    updated.phase = next;
    let updated = replace_journal(path, expected, updated)?;
    #[cfg(feature = "update-test-fixtures")]
    wait_at_update_test_gate(next);
    Ok(updated)
}

#[cfg(feature = "update-test-fixtures")]
fn wait_at_update_test_gate(phase: UpdatePhase) {
    let Ok(expected) = std::env::var("WGB_UPDATE_TEST_GATE_PHASE") else {
        return;
    };
    if expected != format!("{phase:?}") {
        return;
    }
    let Some(directory) = std::env::var_os("WGB_UPDATE_TEST_GATE_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let entered = directory.join(format!("{expected}.entered"));
    let release = directory.join(format!("{expected}.release"));
    let _ = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(entered);
    while !release.exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn replace_journal(
    path: &Path,
    expected: &UpdateJournal,
    updated: UpdateJournal,
) -> io::Result<UpdateJournal> {
    let current = read_journal(path)?;
    if current != *expected
        || current.transaction_id != updated.transaction_id
        || current.transaction_dir != updated.transaction_dir
        || (current.phase != updated.phase && !transition_allowed(current.phase, updated.phase))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "update journal phase transition is invalid",
        ));
    }
    write_journal(path, &updated)?;
    Ok(updated)
}

fn transition_allowed(from: UpdatePhase, to: UpdatePhase) -> bool {
    use UpdatePhase::*;
    matches!(
        (from, to),
        (Prepared, BackupVerified | RollingBack | RecoveryRequired)
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
            | (RecoveryRequired, RollingBack)
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

#[cfg(feature = "update-test-fixtures")]
type FixtureUpdateInputs = (Box<dyn AcquisitionTransport>, String);

#[cfg(feature = "update-test-fixtures")]
fn fixture_update_inputs() -> Result<Option<FixtureUpdateInputs>, String> {
    use eggup_acquisition::{FixtureResponse, FixtureTransport};

    let Some(directory) = std::env::var_os("WGB_UPDATE_FIXTURE_DIR") else {
        return Ok(None);
    };
    let directory = PathBuf::from(directory);
    let metadata =
        fs::symlink_metadata(&directory).map_err(|_| "update fixture directory is unavailable")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err("update fixture directory is unsafe".into());
    }
    let read_fixture = |name: &str, limit: u64| -> Result<Vec<u8>, String> {
        let path = directory.join(name);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "update fixture input is unavailable")?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.len() > limit
        {
            return Err("update fixture input is unsafe or outside its size bound".into());
        }
        fs::read(path).map_err(|_| "update fixture input could not be read".into())
    };

    let discovery = read_fixture("discovery.json", 256 * 1024)?;
    let selection = parse_latest_release(&discovery).map_err(str::to_owned)?;
    let manifest = read_fixture("release-manifest.json", 256 * 1024)?;
    let signature = read_fixture("release-manifest.json.minisig", 16 * 1024)?;
    let public_key = String::from_utf8(read_fixture("public.key", 16 * 1024)?)
        .map_err(|_| "update fixture public key is invalid")?;
    let target =
        crate::release::LinuxTarget::from_host(std::env::consts::OS, std::env::consts::ARCH)
            .map_err(str::to_owned)?;
    let artifact_name = format!("wg-basic-{}", target.triple());
    let artifact = read_fixture(&artifact_name, 128 * 1024 * 1024)?;

    let transport = FixtureTransport::new();
    transport.route(RELEASE_DISCOVERY_URL, FixtureResponse::body(discovery));
    let release_base = format!("{RELEASE_ORIGIN}/v{}", selection.version);
    transport.route(
        &format!("{release_base}/release-manifest.json"),
        FixtureResponse::body(manifest),
    );
    transport.route(
        &format!("{release_base}/release-manifest.json.minisig"),
        FixtureResponse::body(signature),
    );
    transport.route(
        &format!("{release_base}/{artifact_name}"),
        FixtureResponse::body(artifact),
    );
    Ok(Some((Box::new(transport), public_key)))
}

/// `update`: no mutation is possible without authenticated release metadata.
pub fn apply() -> Result<(), String> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err("system update requires effective root; no automatic sudo is performed".into());
    }
    let install = crate::distribution::validate_owned_installation()?;
    if install.version != crate::release::PACKAGE_VERSION {
        return Err("installed version does not match updater binary identity".into());
    }
    #[cfg(feature = "update-test-fixtures")]
    let fixture_inputs = fixture_update_inputs()?;
    #[cfg(feature = "update-test-fixtures")]
    let (transport, fixture_public_key): (Box<dyn AcquisitionTransport>, Option<String>) =
        match fixture_inputs {
            Some((transport, public_key)) => (transport, Some(public_key)),
            None => (Box::new(system_transport()?), None),
        };
    #[cfg(not(feature = "update-test-fixtures"))]
    let transport: Box<dyn AcquisitionTransport> = Box::new(system_transport()?);
    let public_key = {
        #[cfg(feature = "update-test-fixtures")]
        if let Some(public_key) = fixture_public_key.as_deref() {
            public_key
        } else {
            require_production_key()?
        }
        #[cfg(not(feature = "update-test-fixtures"))]
        {
            require_production_key()?
        }
    };
    let selection = discover_latest(transport.as_ref())?;
    crate::release::require_newer(&install.version, &selection.version).map_err(str::to_owned)?;
    let target =
        crate::release::LinuxTarget::from_host(std::env::consts::OS, std::env::consts::ARCH)
            .map_err(str::to_owned)?;
    if install.target != target.triple() {
        return Err("installed target does not match this host".into());
    }
    let release = acquire_authenticated_release(
        transport.as_ref(),
        &selection,
        &install.version,
        target,
        public_key,
    )?;
    let signing_key_id = minisign_key_id(public_key)?;

    let system_dir = Path::new(crate::distribution::SYSTEM_DIR);
    let lock_path = system_dir.join("install.lock");
    let _lock = crate::distribution::InstallLock::acquire(&lock_path)
        .map_err(|_| "another system transaction is active or the lock is unsafe")?;
    let _previous_recovery = reject_unresolved_journal()?;
    let current_install = crate::distribution::validate_owned_installation()?;
    if current_install != install {
        return Err("installation changed during release acquisition; retry update".into());
    }
    require_running_owned_services()?;
    let old_state_identity = read_state_identity(Path::new(crate::distribution::STATE_PATH))?;
    let rollback_root = Path::new(ROLLBACK_DIR);
    ensure_root_private_directory(rollback_root, system_dir)?;
    let transaction_id = uuid::Uuid::new_v4().to_string();
    let transaction_dir = rollback_root.join(&transaction_id);
    ensure_root_private_directory(&transaction_dir, rollback_root)?;

    let candidate = acquire_candidate(transport.as_ref(), &release, target, &transaction_dir)?;
    let _old_binary = save_old_binary(&install, &transaction_dir, &transaction_id)?;
    let old_install_metadata_sha256 = save_old_install_metadata(&install, &transaction_dir)?;
    let mut journal = UpdateJournal {
        schema: JOURNAL_SCHEMA,
        transaction_id: transaction_id.clone(),
        version_from: install.version.clone(),
        version_to: release.version.clone(),
        target: target.triple().to_owned(),
        phase: UpdatePhase::Prepared,
        transaction_dir: transaction_dir.clone(),
        old_binary_sha256: install.binary_sha256.clone(),
        old_install_metadata_sha256,
        candidate_sha256: candidate.sha256.clone(),
        state_backup_sha256: None,
        manifest_sha256: Some(release.manifest_sha256.clone()),
        signing_key_id: Some(signing_key_id.clone()),
        old_state_identity: Some(old_state_identity.clone()),
    };
    write_journal(Path::new(UPDATE_JOURNAL_PATH), &journal)
        .map_err(|_| "could not persist update transaction journal")?;

    // Stop the only state writer before taking the snapshot. A live online
    // backup followed by a later service stop could lose accepted writes if
    // the candidate subsequently rolled back.
    if let Err(error) = stop_management_service() {
        return fail_before_services(&journal, error);
    }
    let backup = match create_state_backup(&transaction_id, &transaction_dir, &old_state_identity) {
        Ok(path) => path,
        Err(error) => return fail_before_services(&journal, error),
    };
    let backup_digest = match eggup_core::hash_file(&backup) {
        Ok(digest) => digest,
        Err(_) => {
            return fail_before_services(&journal, "pre-update state backup digest failed".into())
        }
    };
    journal.state_backup_sha256 = Some(digest_hex(&backup_digest));
    journal.phase = UpdatePhase::BackupVerified;
    match replace_journal(
        Path::new(UPDATE_JOURNAL_PATH),
        &read_journal(Path::new(UPDATE_JOURNAL_PATH))
            .map_err(|_| "update journal could not be revalidated")?,
        journal.clone(),
    ) {
        Ok(_) => {}
        Err(_) => {
            return fail_before_services(
                &journal,
                "could not persist verified update backups".into(),
            )
        }
    }
    #[cfg(feature = "update-test-fixtures")]
    wait_at_update_test_gate(UpdatePhase::BackupVerified);

    if let Err(error) = stop_network_service() {
        return fail_before_services(&journal, error);
    }
    journal = match advance_journal(
        Path::new(UPDATE_JOURNAL_PATH),
        &journal,
        UpdatePhase::ServicesStopped,
    ) {
        Ok(updated) => updated,
        Err(_) => {
            return fail_before_services(&journal, "could not persist stopped-service phase".into())
        }
    };

    let old_digest = parse_digest(&install.binary_sha256)?;
    let new_digest = parse_digest(&candidate.sha256)?;
    let old_install = install.clone();
    let mut new_install = install.clone();
    new_install.version = release.version.clone();
    new_install.binary_sha256 = candidate.sha256.clone();
    new_install.source_release = Some(selection.tag_name.clone());
    new_install.release_manifest_sha256 = Some(release.manifest_sha256.clone());
    new_install.signing_key_id = Some(signing_key_id);
    let journal_path = PathBuf::from(UPDATE_JOURNAL_PATH);
    let old_binary_for_restore = runtime_old_binary_path(&transaction_id);
    let backup_for_restore = backup.clone();
    let restore_succeeded = std::cell::Cell::new(false);
    let callback = || -> Result<(), String> {
        let transaction = (|| {
            journal = advance_journal(&journal_path, &journal, UpdatePhase::BinaryCommitted)
                .map_err(|_| "could not persist committed candidate binary phase")?;
            start_owned_services()?;
            journal = advance_journal(&journal_path, &journal, UpdatePhase::CandidateStarted)
                .map_err(|_| "could not persist candidate startup phase")?;
            validate_candidate_health(&old_state_identity)?;
            journal = advance_journal(&journal_path, &journal, UpdatePhase::CandidateHealthy)
                .map_err(|_| "could not persist candidate health phase")?;
            crate::distribution::write_metadata(system_dir, &new_install)
                .map_err(|_| "new installation receipt could not be persisted")?;
            journal = advance_journal(&journal_path, &journal, UpdatePhase::Committed)
                .map_err(|_| "durable update commit marker could not be persisted")?;
            Ok(())
        })();
        if transaction.is_ok() {
            return Ok(());
        }
        let cause = transaction.unwrap_err();
        let mut recovery_ok = true;
        if journal.phase != UpdatePhase::RollingBack {
            match advance_journal(&journal_path, &journal, UpdatePhase::RollingBack) {
                Ok(updated) => journal = updated,
                Err(_) => recovery_ok = false,
            }
        }
        if stop_owned_services().is_err() {
            recovery_ok = false;
        }
        if restore_state_backup(
            &old_binary_for_restore,
            &backup_for_restore,
            &transaction_id,
        )
        .is_err()
        {
            recovery_ok = false;
        }
        if crate::distribution::write_metadata(system_dir, &old_install).is_err() {
            recovery_ok = false;
        }
        if recovery_ok {
            restore_succeeded.set(true);
            Err(cause)
        } else {
            if journal.phase != UpdatePhase::RecoveryRequired {
                if let Ok(updated) =
                    advance_journal(&journal_path, &journal, UpdatePhase::RecoveryRequired)
                {
                    journal = updated;
                }
            }
            Err("candidate failed and automatic database rollback needs operator recovery".into())
        }
    };
    let transaction = eggup_commit_binary(
        Path::new("/usr/local/bin"),
        "wg-basic",
        &candidate.path,
        &release.version,
        old_digest,
        new_digest,
        callback,
    );
    match transaction {
        Ok(receipt) if receipt.disposition() == eggup_core::TransactionDisposition::Committed => {
            let _ = fs::remove_file(&old_binary_for_restore);
            println!("updated wg-basic to {}", release.version);
            Ok(())
        }
        Ok(receipt) if receipt.disposition() == eggup_core::TransactionDisposition::RolledBack => {
            ensure_installed_executable(&old_digest)?;
            if restore_succeeded.get() {
                let healthy = start_owned_services()
                    .and_then(|_| validate_running_product_health(&old_state_identity));
                if let Err(error) = healthy {
                    let _ = stop_owned_services();
                    mark_recovery_required(&journal_path);
                    return Err(format!(
                        "old generation was restored but product health is unproven: {error}"
                    ));
                }
                advance_journal(&journal_path, &journal, UpdatePhase::RolledBack)
                    .map_err(|_| "rolled-back update journal could not be persisted")?;
                let _ = fs::remove_file(&old_binary_for_restore);
                Err(
                    "candidate failed health checks; previous binary and state were restored"
                        .into(),
                )
            } else {
                Err("update rollback requires operator recovery; services remain stopped".into())
            }
        }
        Ok(_) => {
            mark_recovery_required(&journal_path);
            Err("update rollback could not be proven; services remain stopped".into())
        }
        Err(_) => {
            let old_binary_live = crate::distribution::verify_owned_file(
                Path::new(crate::distribution::BINARY_PATH),
                &old_install.binary_sha256,
                0,
            )
            .is_ok();
            let old_state_valid = old_binary_live
                && read_state_identity(Path::new(crate::distribution::STATE_PATH))
                    .is_ok_and(|identity| identity == old_state_identity);
            if old_binary_live
                && old_state_valid
                && start_owned_services()
                    .and_then(|_| validate_running_product_health(&old_state_identity))
                    .is_ok()
            {
                let current =
                    read_journal(&journal_path).map_err(|_| "update journal is unavailable")?;
                let rolling = advance_journal(&journal_path, &current, UpdatePhase::RollingBack)
                    .map_err(|_| "update rollback phase could not be persisted")?;
                advance_journal(&journal_path, &rolling, UpdatePhase::RolledBack)
                    .map_err(|_| "update rollback completion could not be persisted")?;
                let _ = fs::remove_file(&old_binary_for_restore);
                return Err(
                    "candidate was not committed; previous installation was restarted".into(),
                );
            }
            mark_recovery_required(&journal_path);
            Err(
                "Eggup could not prove the prior binary and state pair; services remain stopped"
                    .into(),
            )
        }
    }
}

/// `update recover`: reconcile an interrupted transaction only from the
/// root-owned journal, exact binary digests, and verified recovery artifacts.
pub fn recover() -> Result<(), String> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(
            "update recovery requires effective root; no automatic sudo is performed".into(),
        );
    }
    match fs::symlink_metadata(UPDATE_JOURNAL_PATH) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!("no update recovery journal is present");
            return Ok(());
        }
        Err(_) => return Err("update journal cannot be inspected safely".into()),
        Ok(_) => {}
    }
    let journal_path = Path::new(UPDATE_JOURNAL_PATH);
    let initial =
        read_journal(journal_path).map_err(|_| "update journal is unsafe or invalid".to_owned())?;
    let _lock = crate::distribution::InstallLock::acquire(
        &Path::new(crate::distribution::SYSTEM_DIR).join("install.lock"),
    )
    .map_err(|_| "another system transaction is active or the lock is unsafe")?;
    let mut journal =
        read_journal(journal_path).map_err(|_| "update journal changed or became unsafe")?;
    if journal != initial {
        return Err("update journal changed while acquiring the transaction lock".into());
    }
    if journal.phase == UpdatePhase::Committed || journal.phase == UpdatePhase::RolledBack {
        let expected_version = if journal.phase == UpdatePhase::Committed {
            &journal.version_to
        } else {
            &journal.version_from
        };
        let expected_binary = if journal.phase == UpdatePhase::Committed {
            &journal.candidate_sha256
        } else {
            &journal.old_binary_sha256
        };
        if let Err(error) = validate_transaction_artifacts(&journal)
            .and_then(|_| load_old_install_metadata(&journal).map(|_| ()))
            .and_then(|_| {
                if journal.state_backup_sha256.is_some() {
                    validate_state_backup(&journal)
                } else if journal.phase == UpdatePhase::RolledBack {
                    Ok(())
                } else {
                    Err("terminal update lacks its required state backup".into())
                }
            })
        {
            let _ = stop_owned_services();
            return Err(format!(
                "terminal recovery artifacts are invalid; services were stopped: {error}"
            ));
        }
        let receipt = match crate::distribution::validate_owned_installation() {
            Ok(receipt) => receipt,
            Err(_) => {
                stop_owned_services()?;
                return Err("terminal update receipt is invalid; services remain stopped".into());
            }
        };
        let current_digest = match installed_binary_digest() {
            Ok(digest) => digest,
            Err(_) => {
                stop_owned_services()?;
                return Err("terminal update binary is unsafe; services remain stopped".into());
            }
        };
        let expected_digest = match parse_digest(expected_binary) {
            Ok(digest) => digest,
            Err(_) => {
                stop_owned_services()?;
                return Err("terminal update digest is invalid; services remain stopped".into());
            }
        };
        if receipt.version != *expected_version
            || receipt.binary_sha256 != *expected_binary
            || current_digest != expected_digest
        {
            stop_owned_services()?;
            return Err(
                "terminal release identity does not match installed bytes; services remain stopped"
                    .into(),
            );
        }
        let previous = journal
            .old_state_identity
            .as_ref()
            .ok_or("terminal transaction lacks typed state evidence; manual recovery required")?;
        let identity = read_state_identity(Path::new(crate::distribution::STATE_PATH))?;
        if (journal.phase == UpdatePhase::RolledBack && identity != *previous)
            || (journal.phase == UpdatePhase::Committed
                && (identity.installation_id != previous.installation_id
                    || identity.desired_generation != previous.desired_generation
                    || identity.network_enabled != previous.network_enabled
                    || identity.product_identity_sha256 != previous.product_identity_sha256
                    || identity.schema_version < previous.schema_version))
        {
            let _ = stop_owned_services();
            return Err(
                "terminal state identity is incompatible with its journal; services were stopped"
                    .into(),
            );
        }
        if let Err(error) = validate_running_product_health(&identity) {
            let _ = stop_owned_services();
            return Err(format!(
                "terminal product health is unproven; services were stopped: {error}"
            ));
        }
        println!(
            "update transaction {} is already {}",
            journal.transaction_id,
            if journal.phase == UpdatePhase::Committed {
                "committed"
            } else {
                "rolled back"
            }
        );
        return Ok(());
    }

    // An interrupted transaction must not leave a possibly unknown generation
    // serving while its bytes and recovery artifacts are classified.
    if let Err(error) = stop_owned_services() {
        mark_recovery_required(journal_path);
        return Err(format!(
            "could not establish stopped owned services; recovery classification required: {error}"
        ));
    }
    if let Err(error) = validate_transaction_directory(&journal)
        .and_then(|_| validate_transaction_artifacts(&journal))
        .and_then(|_| load_old_install_metadata(&journal).map(|_| ()))
    {
        mark_recovery_required(journal_path);
        return Err(format!(
            "update recovery artifacts are invalid; services remain stopped: {error}"
        ));
    }
    let current_digest = match installed_binary_digest() {
        Ok(digest) => digest,
        Err(_) => {
            mark_recovery_required(journal_path);
            return Err("installed binary is unsafe; services remain stopped".into());
        }
    };
    let old_digest = parse_digest(&journal.old_binary_sha256)?;
    let candidate_digest = parse_digest(&journal.candidate_sha256)?;
    if current_digest != old_digest && current_digest != candidate_digest {
        mark_recovery_required(journal_path);
        return Err(
            "installed binary matches neither journaled generation; services remain stopped".into(),
        );
    }

    let needs_state_restore =
        recovery_requires_state_restore(journal.phase, current_digest == candidate_digest);
    if needs_state_restore {
        if let Err(error) = validate_state_backup(&journal)
            .and_then(|_| ensure_runtime_old_binary(&journal).map(|_| ()))
        {
            mark_recovery_required(journal_path);
            return Err(format!(
                "rollback artifacts are invalid; services remain stopped: {error}"
            ));
        }
        if journal.phase != UpdatePhase::RollingBack {
            journal = advance_journal(journal_path, &journal, UpdatePhase::RollingBack)
                .map_err(|_| "could not persist recovery rollback phase")?;
        }
        let backup = journal.transaction_dir.join("state-pre-update.db");
        let old_runtime = runtime_old_binary_path(&journal.transaction_id);
        if let Err(error) = restore_state_backup(&old_runtime, &backup, &journal.transaction_id) {
            mark_recovery_required(journal_path);
            return Err(format!(
                "pre-update database restore failed; services remain stopped: {error}"
            ));
        }
        let old_install = load_old_install_metadata(&journal)?;
        crate::distribution::write_metadata(
            Path::new(crate::distribution::SYSTEM_DIR),
            &old_install,
        )
        .map_err(|_| {
            mark_recovery_required(journal_path);
            "pre-update installation receipt could not be restored"
        })?;
        if current_digest == candidate_digest {
            let old_binary = journal.transaction_dir.join("old-wg-basic");
            let stale_lock_verifier = UpdateJournalStaleLockVerifier {
                expected_release: journal.version_to.clone(),
            };
            let receipt = eggup_commit_binary_inner(
                Path::new("/usr/local/bin"),
                "wg-basic",
                &old_binary,
                &journal.version_from,
                candidate_digest,
                old_digest,
                || ensure_installed_executable(&old_digest),
                Some(&stale_lock_verifier),
            )?;
            if receipt.disposition() != eggup_core::TransactionDisposition::Committed {
                mark_recovery_required(journal_path);
                return Err(
                    "old binary could not be restored through Eggup; services remain stopped"
                        .into(),
                );
            }
        }
        if installed_binary_digest()? != old_digest {
            mark_recovery_required(journal_path);
            return Err("restored binary digest does not match the prior generation".into());
        }
    } else {
        if current_digest != old_digest {
            mark_recovery_required(journal_path);
            return Err("prior binary could not be proven".into());
        }
        if journal.phase != UpdatePhase::RollingBack {
            journal = advance_journal(journal_path, &journal, UpdatePhase::RollingBack)
                .map_err(|_| "could not persist recovery rollback phase")?;
        }
    }
    if ensure_installed_executable(&old_digest).is_err() {
        mark_recovery_required(journal_path);
        return Err("restored binary permissions could not be safely repaired".into());
    }

    let old_identity = journal
        .old_state_identity
        .as_ref()
        .ok_or("update journal lacks typed pre-update state evidence")?;
    let restored_identity = match read_state_identity(Path::new(crate::distribution::STATE_PATH)) {
        Ok(identity) => identity,
        Err(error) => {
            mark_recovery_required(journal_path);
            return Err(format!(
                "restored state identity could not be verified: {error}"
            ));
        }
    };
    if &restored_identity != old_identity {
        mark_recovery_required(journal_path);
        return Err(
            "restored state identity differs from the pre-update record; services remain stopped"
                .into(),
        );
    }
    let old_install = match load_old_install_metadata(&journal) {
        Ok(metadata) => metadata,
        Err(error) => {
            mark_recovery_required(journal_path);
            return Err(format!(
                "pre-update installation receipt is unavailable: {error}"
            ));
        }
    };
    match crate::distribution::validate_owned_installation() {
        Ok(receipt) if receipt == old_install => {}
        _ => {
            mark_recovery_required(journal_path);
            return Err("installed receipt does not match the pre-update generation; services remain stopped".into());
        }
    }
    if let Err(error) =
        start_owned_services().and_then(|_| validate_running_product_health(old_identity))
    {
        let _ = stop_owned_services();
        mark_recovery_required(journal_path);
        return Err(format!(
            "prior generation was restored but failed recovery health: {error}"
        ));
    }
    journal = advance_journal(journal_path, &journal, UpdatePhase::RolledBack)
        .map_err(|_| "recovered rollback completion could not be persisted")?;
    let _ = fs::remove_file(runtime_old_binary_path(&journal.transaction_id));
    println!(
        "recovered update transaction {} to {}",
        journal.transaction_id, journal.version_from
    );
    Ok(())
}

/// Whether recovery must restore the pre-update database before starting the
/// old generation. The journal phase is authoritative even when Eggup already
/// restored the old binary: a candidate may have migrated state before the
/// updater was killed.
fn recovery_requires_state_restore(phase: UpdatePhase, candidate_is_installed: bool) -> bool {
    candidate_is_installed
        || matches!(
            phase,
            UpdatePhase::BinaryCommitted
                | UpdatePhase::CandidateStarted
                | UpdatePhase::CandidateHealthy
                | UpdatePhase::RollingBack
                | UpdatePhase::RecoveryRequired
        )
}

fn validate_transaction_directory(journal: &UpdateJournal) -> Result<(), String> {
    let metadata = fs::symlink_metadata(&journal.transaction_dir)
        .map_err(|_| "update recovery directory is unavailable")?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("update recovery directory is unsafe".into());
    }
    Ok(())
}

fn validate_transaction_artifacts(journal: &UpdateJournal) -> Result<(), String> {
    let old = journal.transaction_dir.join("old-wg-basic");
    let candidate = journal.transaction_dir.join("candidate-wg-basic");
    for (path, expected, label, mode) in [
        (&old, &journal.old_binary_sha256, "old binary", 0o755),
        (
            &candidate,
            &journal.candidate_sha256,
            "candidate binary",
            0o700,
        ),
    ] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| format!("{label} recovery artifact is unavailable"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != mode
            || metadata.nlink() != 1
            || eggup_core::hash_file(path)
                .map_err(|_| format!("{label} recovery artifact digest failed"))?
                != parse_digest(expected)?
        {
            return Err(format!("{label} recovery artifact is unsafe or mismatched"));
        }
    }
    Ok(())
}

fn installed_binary_digest() -> Result<[u8; 32], String> {
    let path = Path::new(crate::distribution::BINARY_PATH);
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "installed binary cannot be inspected")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.nlink() != 1
    {
        return Err("installed binary is unsafe".into());
    }
    eggup_core::hash_file(path).map_err(|_| "installed binary digest could not be read".into())
}

fn ensure_installed_executable(expected_digest: &[u8; 32]) -> Result<(), String> {
    let path = Path::new(crate::distribution::BINARY_PATH);
    if installed_binary_digest()? != *expected_digest {
        return Err("installed binary digest changed before permission repair".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|_| "installed binary permissions could not be assigned")?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| "installed binary permissions could not be made durable")?;
    File::open(
        Path::new(crate::distribution::BINARY_PATH)
            .parent()
            .unwrap(),
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| "installed binary directory could not be made durable")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "installed binary permissions could not be verified")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
        || metadata.nlink() != 1
        || eggup_core::hash_file(path).map_err(|_| "installed binary digest could not be read")?
            != *expected_digest
    {
        return Err("installed executable permissions or identity are unsafe".into());
    }
    Ok(())
}

fn validate_state_backup(journal: &UpdateJournal) -> Result<(), String> {
    let path = journal.transaction_dir.join("state-pre-update.db");
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| "pre-update state backup is unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("pre-update state backup is unsafe".into());
    }
    let expected = journal
        .state_backup_sha256
        .as_deref()
        .ok_or("update journal does not bind a state backup")?;
    let digest = eggup_core::hash_file(&path).map_err(|_| "pre-update backup digest failed")?;
    if digest_hex(&digest) != expected {
        return Err("pre-update state backup digest does not match the journal".into());
    }
    Ok(())
}

fn ensure_runtime_old_binary(journal: &UpdateJournal) -> Result<PathBuf, String> {
    let old = journal.transaction_dir.join("old-wg-basic");
    let metadata =
        fs::symlink_metadata(&old).map_err(|_| "old binary recovery artifact is unavailable")?;
    let expected = parse_digest(&journal.old_binary_sha256)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
        || eggup_core::hash_file(&old).map_err(|_| "old binary digest failed")? != expected
    {
        return Err("old binary recovery artifact is unsafe".into());
    }
    let accessible = runtime_old_binary_path(&journal.transaction_id);
    match fs::symlink_metadata(&accessible) {
        Ok(meta)
            if meta.file_type().is_file()
                && meta.uid() == 0
                && meta.mode() & 0o777 == 0o755
                && eggup_core::hash_file(&accessible).is_ok_and(|digest| digest == expected) =>
        {
            Ok(accessible)
        }
        Ok(_) => Err("management-accessible old binary copy is unsafe".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            durable_copy(&old, &accessible, 0o755)?;
            Ok(accessible)
        }
        Err(_) => Err("management-accessible old binary copy cannot be inspected".into()),
    }
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
            old_install_metadata_sha256: "c".repeat(64),
            candidate_sha256: "b".repeat(64),
            state_backup_sha256: None,
            manifest_sha256: None,
            signing_key_id: None,
            old_state_identity: None,
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
    fn historical_schema_one_journals_remain_parseable_without_typed_identity() {
        let root = Path::new("/var/lib/wg-basic-system/rollback");
        let value = journal(root);
        let mut encoded = serde_json::to_value(&value).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .remove("old_state_identity");
        let parsed: UpdateJournal = serde_json::from_value(encoded).unwrap();
        assert_eq!(parsed.schema, JOURNAL_SCHEMA);
        assert_eq!(parsed.old_state_identity, None);
        assert!(parsed.validate(root).is_ok());
    }

    #[test]
    fn journal_rejects_malformed_typed_state_identity() {
        let root = Path::new("/var/lib/wg-basic-system/rollback");
        let mut value = journal(root);
        value.old_state_identity = Some(StateIdentity {
            installation_id: "not-a-uuid".into(),
            schema_version: 5,
            desired_generation: 4,
            network_enabled: true,
            product_identity_sha256: "d".repeat(64),
        });
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
    fn failed_service_stop_requires_eggup_quiescence_receipt_and_stable_owned_state() {
        use eggup_service::LifecycleState::{Running, Stopped, Transitioning, Unknown};

        assert!(stop_preflight_state_allowed(Running));
        assert!(stop_preflight_state_allowed(Stopped));
        // Eggup 0.1.3 keeps a proven systemd failed state classified Unknown;
        // only its typed stop result can distinguish it from other ambiguity.
        assert!(stop_preflight_state_allowed(Unknown));
        assert!(!stop_preflight_state_allowed(Transitioning));

        assert!(stop_postcondition_allowed(Running, true, Stopped));
        assert!(stop_postcondition_allowed(Stopped, false, Stopped));
        assert!(stop_postcondition_allowed(Unknown, true, Unknown));
        assert!(!stop_postcondition_allowed(Unknown, false, Unknown));
        assert!(!stop_postcondition_allowed(Unknown, true, Running));
        assert!(!stop_postcondition_allowed(Running, true, Unknown));
        assert!(!stop_postcondition_allowed(Transitioning, true, Stopped));
    }

    #[test]
    fn recovery_restores_state_for_every_phase_that_may_follow_migration() {
        for phase in [
            UpdatePhase::BinaryCommitted,
            UpdatePhase::CandidateStarted,
            UpdatePhase::CandidateHealthy,
            UpdatePhase::RollingBack,
            UpdatePhase::RecoveryRequired,
        ] {
            assert!(recovery_requires_state_restore(phase, false), "{phase:?}");
        }
        for phase in [
            UpdatePhase::Prepared,
            UpdatePhase::BackupVerified,
            UpdatePhase::ServicesStopped,
            UpdatePhase::Committed,
            UpdatePhase::RolledBack,
        ] {
            assert!(!recovery_requires_state_restore(phase, false), "{phase:?}");
        }
        // Eggup can restore the old binary before the outer journal advances;
        // candidate identity still requires restoring state.
        assert!(recovery_requires_state_restore(
            UpdatePhase::ServicesStopped,
            true
        ));
    }

    #[test]
    fn journal_writer_child_waits_for_kill() {
        let Ok(path) = std::env::var("WGB_UPDATE_JOURNAL_KILL_FIXTURE") else {
            return;
        };
        let phase = match std::env::var("WGB_UPDATE_JOURNAL_KILL_PHASE").as_deref() {
            Ok("backup_verified") => UpdatePhase::BackupVerified,
            Ok("services_stopped") => UpdatePhase::ServicesStopped,
            Ok("binary_committed") => UpdatePhase::BinaryCommitted,
            Ok("candidate_started") => UpdatePhase::CandidateStarted,
            Ok("candidate_healthy") => UpdatePhase::CandidateHealthy,
            _ => panic!("unknown child journal phase"),
        };
        let path = PathBuf::from(path);
        let mut value = journal(path.parent().unwrap().join("rollback").as_path());
        value.phase = phase;
        write_journal_owned_by(&path, &value, nix::unistd::Uid::effective().as_raw()).unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn killed_journal_writer_child_leaves_a_durable_candidate_healthy_phase() {
        use std::{
            os::unix::fs::PermissionsExt,
            process::{Command, Stdio},
            time::Instant,
        };

        let temp =
            std::env::temp_dir().join(format!("wg-basic-update-kill-{}", uuid::Uuid::new_v4()));
        let rollback = temp.join("rollback");
        let transaction = rollback.join("test-transaction_1");
        fs::create_dir_all(&transaction).unwrap();
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&rollback, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = temp.join("update-journal.json");

        for (phase_name, expected) in [
            ("backup_verified", UpdatePhase::BackupVerified),
            ("services_stopped", UpdatePhase::ServicesStopped),
            ("binary_committed", UpdatePhase::BinaryCommitted),
            ("candidate_started", UpdatePhase::CandidateStarted),
            ("candidate_healthy", UpdatePhase::CandidateHealthy),
        ] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "update::tests::journal_writer_child_waits_for_kill",
                    "--nocapture",
                ])
                .env("WGB_UPDATE_JOURNAL_KILL_FIXTURE", &journal_path)
                .env("WGB_UPDATE_JOURNAL_KILL_PHASE", phase_name)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let observed = loop {
                match read_journal_owned_by(&journal_path, nix::unistd::Uid::effective().as_raw()) {
                    Ok(value) if value.phase == expected => break value,
                    Ok(_) | Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Ok(value) => panic!("child published unexpected phase: {:?}", value.phase),
                    Err(error) => panic!("child did not durably publish its phase: {error}"),
                }
            };
            child.kill().unwrap();
            let _ = child.wait();
            assert_eq!(
                read_journal_owned_by(&journal_path, nix::unistd::Uid::effective().as_raw())
                    .unwrap(),
                observed
            );
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn product_health_projection_requires_database_backend_identity_and_convergence() {
        let identity = StateIdentity {
            installation_id: "fixture-installation".into(),
            schema_version: 5,
            desired_generation: 4,
            network_enabled: true,
            product_identity_sha256: "d".repeat(64),
        };
        let healthy = serde_json::json!({
            "database_healthy": true,
            "netd_reachable": true,
            "installation_id": "fixture-installation",
            "current_desired_generation": 4,
            "convergence": "converged"
        });
        assert!(health_projection_healthy(&healthy, &identity));
        for altered in [
            serde_json::json!({"database_healthy": false, "netd_reachable": true, "installation_id": "x", "convergence": "converged"}),
            serde_json::json!({"database_healthy": true, "netd_reachable": false, "installation_id": "x", "convergence": "converged"}),
            serde_json::json!({"database_healthy": true, "netd_reachable": true, "installation_id": null, "convergence": "converged"}),
            serde_json::json!({"database_healthy": true, "netd_reachable": true, "installation_id": "x", "convergence": "pending"}),
        ] {
            assert!(!health_projection_healthy(&altered, &identity));
        }
    }

    #[test]
    fn intentionally_disabled_product_health_does_not_require_live_convergence() {
        let identity = StateIdentity {
            installation_id: "fixture-installation".into(),
            schema_version: 5,
            desired_generation: 4,
            network_enabled: false,
            product_identity_sha256: "d".repeat(64),
        };
        let healthy_disabled = serde_json::json!({
            "database_healthy": true,
            "netd_reachable": false,
            "installation_id": "fixture-installation",
            "current_desired_generation": 4,
            "convergence": "pending"
        });
        assert!(health_projection_healthy(&healthy_disabled, &identity));
        let wrong_generation = serde_json::json!({
            "database_healthy": true,
            "netd_reachable": false,
            "installation_id": "fixture-installation",
            "current_desired_generation": 3,
            "convergence": "pending"
        });
        assert!(!health_projection_healthy(&wrong_generation, &identity));
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
        assert!(apply().is_err());
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
