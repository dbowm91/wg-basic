//! Product-owned native system installation contracts.
//!
//! This module contains immutable systemd/sysusers material and the small,
//! typed pieces of installation identity shared by the CLI and tests.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const BINARY_PATH: &str = "/usr/local/bin/wg-basic";
pub const NETD_UNIT_PATH: &str = "/etc/systemd/system/wg-basic-netd.service";
pub const SERVE_UNIT_PATH: &str = "/etc/systemd/system/wg-basic.service";
pub const SYSUSERS_PATH: &str = "/etc/sysusers.d/wg-basic.conf";
pub const SYSTEM_DIR: &str = "/var/lib/wg-basic-system";
pub const STATE_DIR: &str = "/var/lib/wg-basic";
pub const STATE_PATH: &str = "/var/lib/wg-basic/state.db";
pub const RUNTIME_DIR: &str = "/run/wg-basic";
pub const SOCKET_PATH: &str = "/run/wg-basic/netd.sock";
pub const PRODUCT_ID: &str = "wg-basic";

pub fn current_executable() -> io::Result<PathBuf> {
    std::env::current_exe()
}

pub const SYSUSERS: &str = "# Managed by wg-basic. Local changes prevent owned refresh.\ng wg-basic -\nu wg-basic - \"wg-basic\" /var/lib/wg-basic -\nu wg-basic-netd - \"wg-basic\" / -\n";

pub const NETD_UNIT: &str = "[Unit]\nDescription=wg-basic privileged network service\nAfter=local-fs.target\nStartLimitIntervalSec=60s\nStartLimitBurst=5\n\n[Service]\nType=simple\nUser=wg-basic-netd\nGroup=wg-basic\nExecStart=/usr/local/bin/wg-basic netd --socket /run/wg-basic/netd.sock --allow-user wg-basic\nRuntimeDirectory=wg-basic\nRuntimeDirectoryMode=0750\nRuntimeDirectoryUser=wg-basic-netd\nRuntimeDirectoryGroup=wg-basic\nCapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_NET_ADMIN\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nReadWritePaths=/run/wg-basic /proc/sys/net/ipv4/ip_forward\nLimitCORE=0\nTasksMax=32\nMemoryMax=128M\nRestart=on-failure\nRestartSec=2s\n\n[Install]\nWantedBy=multi-user.target\n";

pub const SERVE_UNIT: &str = "[Unit]\nDescription=wg-basic management service\nRequires=wg-basic-netd.service\nAfter=wg-basic-netd.service network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60s\nStartLimitBurst=5\n\n[Service]\nType=simple\nUser=wg-basic\nGroup=wg-basic\nExecStartPre=/usr/local/bin/wg-basic state init --state /var/lib/wg-basic/state.db\nExecStart=/usr/local/bin/wg-basic serve --state /var/lib/wg-basic/state.db --socket /run/wg-basic/netd.sock\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths=/var/lib/wg-basic /run/wg-basic\nStateDirectory=wg-basic\nStateDirectoryMode=0700\nLimitCORE=0\nTasksMax=64\nMemoryMax=256M\nRestart=on-failure\nRestartSec=2s\n\n[Install]\nWantedBy=multi-user.target\n";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallMetadata {
    pub schema: u32,
    pub product_id: String,
    pub version: String,
    pub target: String,
    pub binary_path: PathBuf,
    pub binary_sha256: String,
    pub netd_unit_path: PathBuf,
    pub netd_unit_sha256: String,
    pub serve_unit_path: PathBuf,
    pub serve_unit_sha256: String,
    pub sysusers_path: PathBuf,
    pub sysusers_sha256: String,
    pub state_dir: PathBuf,
    pub state_path: PathBuf,
    pub system_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub socket_path: PathBuf,
    pub netd_service_id: String,
    pub serve_service_id: String,
    pub source_release: Option<String>,
    pub release_manifest_sha256: Option<String>,
    pub signing_key_id: Option<String>,
}

impl InstallMetadata {
    pub fn new(version: String, target: String, binary_sha256: String) -> Self {
        Self {
            schema: 1,
            product_id: PRODUCT_ID.into(),
            version,
            target,
            binary_path: BINARY_PATH.into(),
            binary_sha256,
            netd_unit_path: NETD_UNIT_PATH.into(),
            netd_unit_sha256: sha256(NETD_UNIT.as_bytes()),
            serve_unit_path: SERVE_UNIT_PATH.into(),
            serve_unit_sha256: sha256(SERVE_UNIT.as_bytes()),
            sysusers_path: SYSUSERS_PATH.into(),
            sysusers_sha256: sha256(SYSUSERS.as_bytes()),
            state_dir: STATE_DIR.into(),
            state_path: STATE_PATH.into(),
            system_dir: SYSTEM_DIR.into(),
            runtime_dir: RUNTIME_DIR.into(),
            socket_path: SOCKET_PATH.into(),
            netd_service_id: "wg-basic-netd.service".into(),
            serve_service_id: "wg-basic.service".into(),
            source_release: None,
            release_manifest_sha256: None,
            signing_key_id: None,
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.schema != 1
            || self.product_id != PRODUCT_ID
            || self.binary_path != Path::new(BINARY_PATH)
            || self.netd_unit_path != Path::new(NETD_UNIT_PATH)
            || self.serve_unit_path != Path::new(SERVE_UNIT_PATH)
            || self.sysusers_path != Path::new(SYSUSERS_PATH)
            || self.state_dir != Path::new(STATE_DIR)
            || self.state_path != Path::new(STATE_PATH)
            || self.system_dir != Path::new(SYSTEM_DIR)
            || self.runtime_dir != Path::new(RUNTIME_DIR)
            || self.socket_path != Path::new(SOCKET_PATH)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install metadata identity or layout mismatch",
            ));
        }
        crate::release::parse_stable_version(&self.version).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "install metadata version is not stable SemVer",
            )
        })?;
        if !crate::release::LinuxTarget::ALL
            .iter()
            .any(|target| target.triple() == self.target)
            || self.netd_service_id != "wg-basic-netd.service"
            || self.serve_service_id != "wg-basic.service"
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install metadata target or service identity mismatch",
            ));
        }
        for digest in [
            &self.binary_sha256,
            &self.netd_unit_sha256,
            &self.serve_unit_sha256,
            &self.sysusers_sha256,
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "install metadata contains an invalid digest",
                ));
            }
        }
        if self.netd_unit_sha256 != sha256(NETD_UNIT.as_bytes())
            || self.serve_unit_sha256 != sha256(SERVE_UNIT.as_bytes())
            || self.sysusers_sha256 != sha256(SYSUSERS.as_bytes())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install metadata product material digest mismatch",
            ));
        }
        Ok(())
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn verify_owned_file(path: &Path, expected_sha256: &str, expected_uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed file ownership or mode is unsafe",
        ));
    }
    let bytes = fs::read(path)?;
    if sha256(&bytes) != expected_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed file bytes were modified",
        ));
    }
    Ok(())
}

pub fn write_metadata(directory: &Path, metadata: &InstallMetadata) -> io::Result<()> {
    metadata.validate()?;
    create_private_root_dir(directory)?;
    let destination = directory.join("install.json");
    let temporary = directory.join(format!(".install.json.{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(metadata).map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn create_private_root_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta)
            if meta.file_type().is_dir() && meta.uid() == 0 && meta.mode() & 0o777 == 0o700 =>
        {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "system metadata directory is not root-owned mode 0700",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if nix::unistd::geteuid().as_raw() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "system metadata directory requires effective root",
                ));
            }
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            File::open(path)?.sync_all()?;
            File::open(path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "metadata directory has no parent",
                )
            })?)?
            .sync_all()
        }
        Err(error) => Err(error),
    }
}

/// Crash-released lock for install/update/uninstall orchestration.
#[derive(Debug)]
pub struct InstallLock {
    _file: nix::fcntl::Flock<File>,
}

impl InstallLock {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        Self::acquire_owned_by(path, 0)
    }

    fn acquire_owned_by(path: &Path, expected_uid: u32) -> io::Result<Self> {
        use nix::fcntl::{Flock, FlockArg};
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "system transaction lock is not root-owned and private",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)?;
        let locked = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, _)| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "another system transaction is active",
            )
        })?;
        Ok(Self { _file: locked })
    }
}

pub fn resolve_username_uid(name: &str) -> io::Result<u32> {
    resolve_username_uid_with(name, |name| {
        nix::unistd::User::from_name(name)
            .map_err(io::Error::other)
            .map(|user| user.map(|entry| entry.uid.as_raw()))
    })
}

pub fn resolve_username_uid_with(
    name: &str,
    lookup: impl FnOnce(&str) -> io::Result<Option<u32>>,
) -> io::Result<u32> {
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "username must be 1–32 ASCII letters, digits, '_' or '-'",
        ));
    }
    lookup(name)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "configured local user does not exist",
        )
    })
}

pub fn resolve_allowed_user_uids(names: &[String]) -> io::Result<Vec<u32>> {
    let mut uids = std::collections::BTreeSet::new();
    for name in names {
        uids.insert(resolve_username_uid(name)?);
    }
    Ok(uids.into_iter().collect())
}

pub fn install_status() -> Result<(), String> {
    use eggup_service::{
        LifecycleState, Ownership, ServiceId, ServiceManager, ServiceSpec, SystemExecutor,
        SystemdInstall, SystemdManager, SystemdScope,
    };
    let Some(receipt) = read_metadata(Path::new(SYSTEM_DIR))? else {
        println!("installation: absent");
        return Err("wg-basic system installation is not registered".into());
    };
    verify_owned_file(Path::new(BINARY_PATH), &receipt.binary_sha256, 0)
        .map_err(|_| "installed executable is modified or unsafe")?;
    verify_owned_file(Path::new(NETD_UNIT_PATH), &receipt.netd_unit_sha256, 0)
        .map_err(|_| "netd unit is modified or unsafe")?;
    verify_owned_file(Path::new(SERVE_UNIT_PATH), &receipt.serve_unit_sha256, 0)
        .map_err(|_| "serve unit is modified or unsafe")?;
    verify_owned_file(Path::new(SYSUSERS_PATH), &receipt.sysusers_sha256, 0)
        .map_err(|_| "sysusers definition is modified or unsafe")?;
    println!("installation: owned");
    println!("version:       {}", receipt.version);
    println!("target:        {}", receipt.target);
    println!(
        "binary:        {} ({})",
        receipt.binary_path.display(),
        receipt.binary_sha256
    );
    for (name, path, definition, args) in [
        (
            "wg-basic-netd.service",
            NETD_UNIT_PATH,
            NETD_UNIT,
            vec![
                "netd".into(),
                "--socket".into(),
                SOCKET_PATH.into(),
                "--allow-user".into(),
                "wg-basic".into(),
            ],
        ),
        (
            "wg-basic.service",
            SERVE_UNIT_PATH,
            SERVE_UNIT,
            vec![
                "serve".into(),
                "--state".into(),
                STATE_PATH.into(),
                "--socket".into(),
                SOCKET_PATH.into(),
            ],
        ),
    ] {
        let install = SystemdInstall::new(
            name.into(),
            SystemdScope::System,
            path.into(),
            definition.as_bytes().to_vec(),
            false,
            false,
            std::time::Duration::from_secs(5),
        )
        .map_err(|_| "invalid product systemd definition")?;
        let id = ServiceId::new(name).map_err(|_| "invalid service id")?;
        let spec = ServiceSpec::new(id, BINARY_PATH.into(), args, None)
            .map_err(|_| "invalid service specification")?;
        let manager = SystemdManager::new(SystemExecutor::default(), install);
        let snapshot = manager
            .inspect(&spec)
            .map_err(|_| "systemd service inspection failed")?;
        println!(
            "service {name}: ownership={:?} state={:?}",
            snapshot.ownership, snapshot.state
        );
        if snapshot.ownership != Ownership::Owned || snapshot.state != LifecycleState::Running {
            return Err("one or more managed systemd services need attention".into());
        }
    }
    let state_meta = fs::symlink_metadata(STATE_DIR).map_err(|_| "state directory is missing")?;
    let management = nix::unistd::User::from_name("wg-basic")
        .map_err(|_| "management account lookup failed")?
        .ok_or("management account is missing")?;
    if !state_meta.file_type().is_dir()
        || state_meta.uid() != management.uid.as_raw()
        || state_meta.mode() & 0o777 != 0o700
    {
        return Err("state directory ownership or mode needs attention".into());
    }
    println!("state directory: owned mode 0700");
    let database = fs::symlink_metadata(STATE_PATH).map_err(|_| "state database is missing")?;
    if !database.file_type().is_file()
        || database.uid() != management.uid.as_raw()
        || database.mode() & 0o777 != 0o600
    {
        return Err("state database ownership or mode needs attention".into());
    }
    let netd = nix::unistd::User::from_name("wg-basic-netd")
        .map_err(|_| "netd account lookup failed")?
        .ok_or("netd account is missing")?;
    let group = nix::unistd::Group::from_name("wg-basic")
        .map_err(|_| "service group lookup failed")?
        .ok_or("service group is missing")?;
    let runtime = fs::symlink_metadata(RUNTIME_DIR).map_err(|_| "runtime directory is missing")?;
    if !runtime.file_type().is_dir()
        || runtime.uid() != netd.uid.as_raw()
        || runtime.gid() != group.gid.as_raw()
        || runtime.mode() & 0o777 != 0o750
    {
        return Err("runtime directory ownership or mode needs attention".into());
    }
    let socket = fs::symlink_metadata(SOCKET_PATH).map_err(|_| "netd socket is missing")?;
    use std::os::unix::fs::FileTypeExt;
    if !socket.file_type().is_socket()
        || socket.uid() != netd.uid.as_raw()
        || socket.gid() != group.gid.as_raw()
        || socket.mode() & 0o777 != 0o660
    {
        return Err("netd socket ownership or mode needs attention".into());
    }
    println!("state database: owned mode 0600");
    println!("runtime/socket: owned mode 0750/0660");
    run_install_health_smoke()?;
    println!("health:          doctor pass; /healthz returned HTTP 200");
    Ok(())
}

/// Performs the local, explicitly privileged installation transaction.
/// Release authenticity is supplied only by a future release-aware entry point;
/// this command identifies its source honestly as a local candidate.
pub fn install_local(candidate: &Path) -> Result<(), String> {
    use eggup_core::{
        AbsentPolicy, AllValidators, ArtifactMember, ArtifactSet, CommitOwnership,
        ExactDigestVerifier, InstallPlan, IntegrityRequirement, MemberId, PermissionsIntent,
        ProductId, ReleaseId,
    };
    use std::time::Duration;

    require_effective_root(nix::unistd::geteuid().as_raw())?;
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("system installation requires the systemd system manager".into());
    }
    for directory in [
        "/usr/local/bin",
        "/etc/systemd/system",
        "/etc",
        "/var/lib",
        "/run",
    ] {
        verify_root_directory(Path::new(directory)).map_err(|error| {
            format!("canonical system destination parent {directory} is unsafe: {error}")
        })?;
    }
    ensure_system_directory(Path::new("/etc/sysusers.d"), 0o755)?;
    let candidate_meta =
        fs::symlink_metadata(candidate).map_err(|_| "candidate is not readable")?;
    if !candidate_meta.file_type().is_file() || candidate_meta.mode() & 0o111 == 0 {
        return Err("candidate must be a regular executable file".into());
    }
    let candidate = fs::canonicalize(candidate).map_err(|_| "candidate path is invalid")?;
    let version_output = eggup_core::run_bounded(
        &eggup_core::CommandSpec::new(&candidate)
            .arg("--version")
            .timeout(Duration::from_secs(3))
            .max_output_bytes(1024),
    )
    .map_err(|_| "candidate identity check failed")?;
    let identity = String::from_utf8(version_output.stdout().to_vec())
        .map_err(|_| "candidate identity is invalid")?;
    let version = identity
        .trim()
        .strip_prefix("wg-basic ")
        .ok_or("candidate product identity mismatch")?;
    if !version_output.success() || version != crate::release::PACKAGE_VERSION {
        return Err("candidate version does not match this installer's release identity".into());
    }
    crate::release::parse_stable_version(version).map_err(str::to_owned)?;
    let target =
        crate::release::LinuxTarget::from_host(std::env::consts::OS, std::env::consts::ARCH)
            .map_err(str::to_owned)?
            .triple();

    let system_dir = Path::new(SYSTEM_DIR);
    if !system_dir.exists() {
        fs::create_dir(system_dir).map_err(|_| "could not create system metadata directory")?;
        fs::set_permissions(system_dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| "could not secure system metadata directory")?;
    }
    create_private_root_dir(system_dir)
        .map_err(|_| "system metadata directory ownership or mode is unsafe")?;
    let lock_path = system_dir.join("install.lock");
    if !symlink_metadata_exists(&lock_path)? {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| "could not create the system transaction lock")?;
        File::open(system_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not persist system transaction lock")?;
    }
    let _lock = InstallLock::acquire(&lock_path).map_err(|error| error.to_string())?;

    let old = read_metadata(system_dir)?;
    if old
        .as_ref()
        .is_some_and(|receipt| receipt.version != version)
    {
        return Err(
            "M002 supports exact-version repair only; version changes require the updater".into(),
        );
    }
    let binary_sha256 = sha256(&fs::read(&candidate).map_err(|_| "candidate cannot be read")?);
    // An existing destination is replaceable only after the receipt and the
    // current bytes agree, or when an interrupted first install left the exact
    // same root-owned candidate bytes in place.
    let current_binary = Path::new(BINARY_PATH);
    if symlink_metadata_exists(current_binary)? {
        let expected = old
            .as_ref()
            .map(|receipt| receipt.binary_sha256.as_str())
            .unwrap_or(binary_sha256.as_str());
        verify_owned_file(current_binary, expected, 0)
            .map_err(|_| "installed binary is foreign or modified")?;
    }
    let metadata =
        InstallMetadata::new(version.to_owned(), target.to_owned(), binary_sha256.clone());
    if let Some(previous) = &old {
        for (path, digest) in [
            (&metadata.netd_unit_path, &previous.netd_unit_sha256),
            (&metadata.serve_unit_path, &previous.serve_unit_sha256),
            (&metadata.sysusers_path, &previous.sysusers_sha256),
        ] {
            verify_owned_file(path, digest, 0)
                .map_err(|_| "an installed product definition was modified or replaced")?;
        }
    } else {
        for (path, expected) in [
            (Path::new(NETD_UNIT_PATH), sha256(NETD_UNIT.as_bytes())),
            (Path::new(SERVE_UNIT_PATH), sha256(SERVE_UNIT.as_bytes())),
            (Path::new(SYSUSERS_PATH), sha256(SYSUSERS.as_bytes())),
        ] {
            if symlink_metadata_exists(path)? {
                verify_owned_file(path, &expected, 0)
                    .map_err(|_| "a product destination is occupied by an unowned file")?;
            }
        }
    }

    install_definition(
        Path::new(SYSUSERS_PATH),
        SYSUSERS.as_bytes(),
        old.as_ref().map(|m| m.sysusers_sha256.as_str()),
    )?;
    let sysusers = ["/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or("systemd-sysusers is unavailable")?;
    let result = eggup_core::run_bounded(
        &eggup_core::CommandSpec::new(sysusers)
            .arg(SYSUSERS_PATH)
            .timeout(Duration::from_secs(10))
            .max_output_bytes(4096),
    )
    .map_err(|_| "system identity setup failed")?;
    if !result.success() {
        return Err("system identity setup failed; systemd-sysusers returned an error".into());
    }
    let management = nix::unistd::User::from_name("wg-basic")
        .map_err(|_| "management account lookup failed")?
        .ok_or("management account was not created")?;
    let netd = nix::unistd::User::from_name("wg-basic-netd")
        .map_err(|_| "netd account lookup failed")?
        .ok_or("netd account was not created")?;
    let group = nix::unistd::Group::from_name("wg-basic")
        .map_err(|_| "service group lookup failed")?
        .ok_or("service group was not created")?;
    ensure_owned_dir(
        Path::new(STATE_DIR),
        management.uid.as_raw(),
        group.gid.as_raw(),
        0o700,
    )?;

    let bin_dir = Path::new(BINARY_PATH)
        .parent()
        .ok_or("invalid binary path")?;
    if !bin_dir.is_dir() {
        return Err("/usr/local/bin must exist before installation".into());
    }
    if candidate != Path::canonicalize(current_binary).unwrap_or_default() {
        let member = ArtifactMember::new(
            MemberId::new("main").map_err(|_| "invalid binary member id")?,
            &candidate,
            "wg-basic",
        )
        .map_err(|_| "invalid binary install member")?
        .with_permissions(PermissionsIntent::Executable)
        .with_integrity(IntegrityRequirement::Sha256(
            eggup_core::hash_file(&candidate).map_err(|_| "candidate digest failed")?,
        ));
        let plan = InstallPlan::new(
            ProductId::new(PRODUCT_ID).map_err(|_| "invalid product id")?,
            ReleaseId::new(version).map_err(|_| "invalid release id")?,
            bin_dir,
            ArtifactSet::single(member).map_err(|_| "invalid binary artifact set")?,
        )
        .map_err(|_| "invalid binary installation plan")?;
        if old.is_some() {
            let digest = eggup_core::hash_file(current_binary)
                .map_err(|_| "installed binary digest failed")?;
            let verifier = ExactDigestVerifier::new(vec![(
                MemberId::new("main").map_err(|_| "invalid binary member id")?,
                digest,
            )]);
            plan.prepare()
                .map_err(|_| "binary installation preparation failed")?
                .verify_integrity()
                .map_err(|_| "binary integrity verification failed")?
                .validate(&AllValidators::new())
                .map_err(|_| "binary candidate validation failed")?
                .commit(CommitOwnership::new(&verifier, AbsentPolicy::DenyCreate))
                .map_err(|_| "owned binary refresh failed")?;
        } else {
            let digest =
                eggup_core::hash_file(&candidate).map_err(|_| "candidate digest failed")?;
            let verifier = ExactDigestVerifier::new(vec![(
                MemberId::new("main").map_err(|_| "invalid binary member id")?,
                digest,
            )]);
            plan.prepare()
                .map_err(|_| "binary installation preparation failed")?
                .verify_integrity()
                .map_err(|_| "binary integrity verification failed")?
                .validate(&AllValidators::new())
                .map_err(|_| "binary candidate validation failed")?
                .commit(CommitOwnership::new(&verifier, AbsentPolicy::AllowCreate))
                .map_err(|_| "binary installation failed")?;
        }
        fs::set_permissions(current_binary, fs::Permissions::from_mode(0o755))
            .map_err(|_| "could not set installed executable mode")?;
        File::open(current_binary)
            .and_then(|file| file.sync_all())
            .map_err(|_| "could not persist installed executable mode")?;
        File::open(bin_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not persist installed executable directory entry")?;
    }

    install_unit(
        NETD_UNIT_PATH,
        "wg-basic-netd.service",
        NETD_UNIT,
        vec![
            "netd".into(),
            "--socket".into(),
            SOCKET_PATH.into(),
            "--allow-user".into(),
            "wg-basic".into(),
        ],
        symlink_metadata_exists(Path::new(NETD_UNIT_PATH))?,
    )?;
    install_unit(
        SERVE_UNIT_PATH,
        "wg-basic.service",
        SERVE_UNIT,
        vec![
            "serve".into(),
            "--state".into(),
            STATE_PATH.into(),
            "--socket".into(),
            SOCKET_PATH.into(),
        ],
        symlink_metadata_exists(Path::new(SERVE_UNIT_PATH))?,
    )?;
    run_install_health_smoke()?;
    write_metadata(system_dir, &metadata)
        .map_err(|_| "could not durably write the installation receipt")?;
    println!("wg-basic {} installed for {target}", version);
    println!("Management UI: http://127.0.0.1:8080");
    println!("Create/reset admin:\n  sudo -u wg-basic /usr/local/bin/wg-basic admin set-password --password-stdin");
    let _ = netd;
    Ok(())
}

fn run_install_health_smoke() -> Result<(), String> {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
        time::Duration,
    };
    let doctor = eggup_core::run_bounded(
        &eggup_core::CommandSpec::new(BINARY_PATH)
            .args([
                "doctor",
                "--state",
                STATE_PATH,
                "--socket",
                SOCKET_PATH,
                "--json",
            ])
            .timeout(Duration::from_secs(15))
            .max_output_bytes(32 * 1024),
    )
    .map_err(|_| "post-install doctor smoke failed")?;
    if doctor.exit_code() != Some(0) {
        return Err("post-install doctor reported a required failure or attention".into());
    }
    let report: crate::doctor::DoctorReport = serde_json::from_slice(doctor.stdout())
        .map_err(|_| "post-install doctor report was invalid")?;
    if report.overall != crate::doctor::DoctorDisposition::Pass {
        return Err("post-install doctor did not pass".into());
    }
    let address = SocketAddr::from(([127, 0, 0, 1], 8000));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .map_err(|_| "post-install management health endpoint is unavailable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "could not bound management health read")?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nConnection: close\r\n\r\n")
        .map_err(|_| "post-install health request failed")?;
    let mut response = [0u8; 4096];
    let count = stream
        .read(&mut response)
        .map_err(|_| "post-install health response failed")?;
    let response = std::str::from_utf8(&response[..count])
        .map_err(|_| "post-install health response was invalid")?;
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        return Err("post-install management health endpoint did not return HTTP 200".into());
    }
    Ok(())
}

fn require_effective_root(uid: u32) -> Result<(), String> {
    if uid == 0 {
        Ok(())
    } else {
        Err("system install requires effective root; no automatic sudo is performed".into())
    }
}

fn read_metadata(directory: &Path) -> Result<Option<InstallMetadata>, String> {
    let path = directory.join("install.json");
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("installation receipt cannot be inspected".into()),
    };
    if !meta.file_type().is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 {
        return Err("installation receipt ownership or mode is unsafe".into());
    }
    let receipt: InstallMetadata =
        serde_json::from_slice(&fs::read(path).map_err(|_| "installation receipt cannot be read")?)
            .map_err(|_| "installation receipt is invalid")?;
    receipt
        .validate()
        .map_err(|_| "installation receipt identity is invalid")?;
    Ok(Some(receipt))
}

fn install_definition(
    path: &Path,
    contents: &[u8],
    previous_digest: Option<&str>,
) -> Result<(), String> {
    if symlink_metadata_exists(path)? {
        let expected = previous_digest
            .map(str::to_owned)
            .unwrap_or_else(|| sha256(contents));
        verify_owned_file(path, &expected, 0).map_err(|_| "product definition was modified")?;
        return Ok(());
    }
    atomic_root_file(path, contents, 0o644)
}

fn symlink_metadata_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("destination cannot be safely inspected".into()),
    }
}

fn atomic_root_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid product file path")?;
    let temp = parent.join(format!(".wg-basic-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)
        .map_err(|_| "could not create a product definition")?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode))
        .map_err(|_| "could not set product definition mode")?;
    let result = (|| -> io::Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
        return Err("could not durably install a product definition".into());
    }
    Ok(())
}

fn install_unit(
    path: &str,
    name: &str,
    definition: &str,
    args: Vec<String>,
    refresh: bool,
) -> Result<(), String> {
    use eggup_service::{
        ServiceId, ServiceManager, ServiceSpec, SystemExecutor, SystemdInstall, SystemdManager,
        SystemdScope,
    };
    let install = SystemdInstall::new(
        name.into(),
        SystemdScope::System,
        PathBuf::from(path),
        definition.as_bytes().to_vec(),
        true,
        true,
        std::time::Duration::from_secs(15),
    )
    .map_err(|_| "invalid product systemd definition")?;
    let id = ServiceId::new(name).map_err(|_| "invalid systemd service identity")?;
    let spec = ServiceSpec::new(id, PathBuf::from(BINARY_PATH), args, None)
        .map_err(|_| "invalid systemd service specification")?;
    let mut manager = SystemdManager::new(SystemExecutor::default(), install);
    if refresh {
        verify_owned_file(Path::new(path), &sha256(definition.as_bytes()), 0)
            .map_err(|_| "modified systemd unit refused")?;
        manager
            .stop(&spec, std::time::Duration::from_secs(15))
            .map_err(|_| "owned service could not be stopped")?;
    }
    manager
        .install(&spec)
        .map_err(|_| "systemd refused the owned unit installation")?;
    manager
        .start(&spec, std::time::Duration::from_secs(20))
        .map_err(|_| "systemd could not start the product service")?;
    Ok(())
}

fn ensure_owned_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    if !symlink_metadata_exists(path)? {
        fs::create_dir(path).map_err(|_| "could not create product state directory")?;
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .map_err(|_| "could not assign product state ownership")?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| "could not secure product state directory")?;
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "product state directory cannot be inspected")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != mode
    {
        return Err("product state directory ownership or mode is unsafe".into());
    }
    Ok(())
}

fn verify_root_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "expected root-owned non-writable directory, observed uid={} mode={:o}",
                metadata.uid(),
                metadata.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

fn ensure_system_directory(path: &Path, mode: u32) -> Result<(), String> {
    if !symlink_metadata_exists(path)? {
        fs::create_dir(path).map_err(|_| "could not create a system definition directory")?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| "could not secure a system definition directory")?;
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not persist a system definition directory")?;
        File::open(path.parent().ok_or("invalid system definition directory")?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not persist system definition directory entry")?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "system definition directory cannot be inspected")?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("system definition directory ownership or mode is unsafe".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_material_pins_hardening_and_identity() {
        assert!(NETD_UNIT.contains("CapabilityBoundingSet=CAP_NET_ADMIN\n"));
        assert!(NETD_UNIT.contains("AmbientCapabilities=CAP_NET_ADMIN\n"));
        assert!(NETD_UNIT.contains("RestrictAddressFamilies=AF_UNIX AF_NETLINK\n"));
        assert!(!NETD_UNIT.contains("ProtectKernelTunables=yes"));
        assert!(SERVE_UNIT.contains("CapabilityBoundingSet=\n"));
        assert!(SERVE_UNIT.contains("ExecStartPre=/usr/local/bin/wg-basic state init"));
        assert!(SYSUSERS.contains("wg-basic-netd"));
    }

    #[test]
    fn metadata_rejects_digest_or_layout_tampering() {
        let mut data = InstallMetadata::new(
            "0.1.0".into(),
            "x86_64-unknown-linux-gnu".into(),
            "a".repeat(64),
        );
        assert!(data.validate().is_ok());
        data.netd_unit_sha256 = "b".repeat(64);
        assert!(data.validate().is_err());
    }

    #[test]
    fn username_syntax_is_bounded_before_lookup() {
        assert!(resolve_username_uid("bad\nname").is_err());
        assert!(resolve_username_uid(&"a".repeat(33)).is_err());
        assert!(resolve_username_uid("root").is_ok());
    }

    #[test]
    fn username_lookup_seam_handles_fixture_and_missing_accounts() {
        assert_eq!(
            resolve_username_uid_with("fixture-user", |_| Ok(Some(4242))).unwrap(),
            4242
        );
        assert_eq!(
            resolve_username_uid_with("fixture-user", |_| Ok(None))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn username_uid_resolution_deduplicates_aliases() {
        let names = vec!["root".to_owned(), "root".to_owned()];
        assert_eq!(resolve_allowed_user_uids(&names).unwrap().len(), 1);
    }

    #[test]
    fn install_lock_is_exclusive_and_released_on_drop() {
        let path =
            std::env::temp_dir().join(format!("wg-basic-install-lock-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let first = InstallLock::acquire_owned_by(&path, uid).unwrap();
        assert_eq!(
            InstallLock::acquire_owned_by(&path, uid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first);
        assert!(InstallLock::acquire_owned_by(&path, uid).is_ok());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn exact_file_ownership_rejects_changed_bytes_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let parent =
            std::env::temp_dir().join(format!("wg-basic-owned-file-{}", std::process::id()));
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        let path = parent.join("unit.service");
        fs::write(&path, b"unit bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        assert!(verify_owned_file(&path, &sha256(b"unit bytes"), uid).is_ok());
        assert!(verify_owned_file(&path, &sha256(b"modified"), uid).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(parent.join("missing"), &path).unwrap();
        assert!(verify_owned_file(&path, &sha256(b"unit bytes"), uid).is_err());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn non_root_install_refuses_before_any_install_action() {
        assert!(require_effective_root(1000).is_err());
        assert!(require_effective_root(0).is_ok());
    }
}
