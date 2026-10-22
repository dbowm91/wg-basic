//! Darwin userspace WireGuard backend (M003): pinned `wireguard-go` helper,
//! UAPI codec, supervised foreground lifecycle, and utun ownership proof.
//!
//! Only the parts that are safe without privilege live here yet: helper
//! provenance constants, fixed-argv supervision config, the bounded UAPI
//! text codec, and the pure ownership verifier. Live `observe`/`apply`
//! against a real `utun` stay `UnsupportedBackend` until a disposable,
//! explicitly opted-in privileged host qualifies the handshake (M003 stop
//! gate); no mock traffic is ever presented as a handshake.
//!
//! Upstream facts (pinned, verified from source at the pinned revision):
//! - argv is exactly `["<absolute-helper>", "utun"]`; the Darwin `tun`
//!   backend requires `utun`/`utunN` and the kernel assigns the number.
//! - `WG_PROCESS_FOREGROUND=1` keeps the helper supervised (no daemonize).
//! - UAPI is a Unix socket at `/var/run/wireguard/<real-utun>.sock`
//!   (owner-only via `077` umask); the real name is learned by
//!   before/after interface delta plus UAPI verification, never by trusting
//!   a name file alone.
//! - Wire-format deviations from the kernel UAPI (read from
//!   `device/uapi.go` at the pinned commit, proven live on hosted macOS):
//!   `private_key`/`public_key` travel as lowercase hex (64 chars), never
//!   base64; observation reports `last_handshake_time_sec`/`nsec`, never
//!   `latest_handshake`. The codec converts and documents both; anything
//!   else on the wire is field-for-field identical.

use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use ipnet::IpNet;

/// Pinned upstream helper provenance (M003).
pub const HELPER_UPSTREAM: &str = "https://github.com/WireGuard/wireguard-go";
pub const HELPER_VERSION_TAG: &str = "0.0.20250522";
/// Peeled commit of the version tag (`git rev-parse 0.0.20250522^{}`).
pub const HELPER_COMMIT: &str = "f333402bd9cbe0f3eeb02507bd14e23d7d639280";
/// Upstream license, verified in the pinned tree (`LICENSE` + SPDX headers).
pub const HELPER_LICENSE: &str = "MIT";
/// Dev-built reference hash (darwin/arm64, `go build` at the pinned tag).
/// Production bundling, reproducibility, and signing land in M006; this hash
/// pins the M003 design reference, not a release artifact.
pub const HELPER_DEV_REFERENCE_SHA256: &str =
    "1339b938a4c2d5553faf02229ea229f355f4b9426e17c75fecaa2f393cb04da9";
/// Fixed helper interface argument: the kernel assigns the `utunN` number.
pub const HELPER_INTERFACE_ARG: &str = "utun";
/// Foreground env that keeps the helper supervised (never daemonized).
pub const HELPER_FOREGROUND_ENV: (&str, &str) = ("WG_PROCESS_FOREGROUND", "1");
/// Upstream UAPI socket directory (symlinked via `/var` on macOS).
pub const UAPI_SOCKET_DIR: &str = "/var/run/wireguard";
/// UAPI frame bound: requests are small typed renders; responses are capped.
pub const MAX_UAPI_REQUEST: usize = 16 * 1024;
pub const MAX_UAPI_RESPONSE: usize = 256 * 1024;
/// UAPI round-trip bound.
pub const UAPI_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum allowed-IP entries rendered for one peer (same order as the
/// plan's 256-entry peer bound; each line is a typed `IpNet`, never text).
pub const MAX_UAPI_ALLOWED_IPS: usize = 256;

/// Typed peer section of a UAPI `set` command. `SocketAddr::Display`
/// renders `ip:port` (bracketed for IPv6), matching the UAPI endpoint form.
#[derive(Clone, Copy, Debug)]
pub struct UapiPeerConfig<'a> {
    pub public_key_base64: &'a str,
    pub remove: bool,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: &'a [IpNet],
    pub persistent_keepalive: Option<u16>,
}

/// The exact argv netd mayexec for the helper. No PATH lookup, no caller
/// flags, no shell: the path is absolute and hash-pinned, the only argument
/// is `utun`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperArgv {
    pub helper: PathBuf,
}

impl HelperArgv {
    pub fn new(helper: PathBuf) -> Result<Self, HelperError> {
        validate_helper_path(&helper)?;
        Ok(Self { helper })
    }

    /// Exactly `[helper, "utun"]`.
    pub fn as_argv(&self) -> Vec<String> {
        vec![
            self.helper.to_string_lossy().into_owned(),
            HELPER_INTERFACE_ARG.into(),
        ]
    }
}

/// Controlled helper environment: exactly the foreground marker plus no
/// caller-controlled entries. `PATH` is deliberately absent.
pub fn helper_env() -> Vec<(String, String)> {
    vec![(
        HELPER_FOREGROUND_ENV.0.into(),
        HELPER_FOREGROUND_ENV.1.into(),
    )]
}

/// Refuses relative paths, PATH-basename lookup, non-files, symlinks, and
/// non-executable helpers before any spawn is attempted.
pub fn validate_helper_path(path: &Path) -> Result<(), HelperError> {
    use std::os::unix::fs::PermissionsExt;

    if !path.is_absolute() {
        return Err(HelperError::RelativePath);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| HelperError::NotFound)?;
    if metadata.file_type().is_symlink() {
        return Err(HelperError::Symlink);
    }
    if !metadata.is_file() {
        return Err(HelperError::NotRegularFile);
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(HelperError::NotExecutable);
    }
    Ok(())
}

/// Verifies the helper binary identity against the pinned receipt before a
/// privileged spawn. Any mismatch is a non-retryable conflict.
pub fn verify_helper_sha256(path: &Path, expected_hex: &str) -> Result<(), HelperError> {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path).map_err(|_| HelperError::NotFound)?;
    let digest = Sha256::digest(&bytes);
    let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != expected_hex {
        return Err(HelperError::IdentityMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HelperError {
    #[error("helper path must be absolute; PATH lookup is never used")]
    RelativePath,
    #[error("helper binary was not found")]
    NotFound,
    #[error("helper path must not be a symlink")]
    Symlink,
    #[error("helper path is not a regular file")]
    NotRegularFile,
    #[error("helper binary is not executable")]
    NotExecutable,
    #[error("helper binary identity does not match the pinned receipt")]
    IdentityMismatch,
    #[error("helper exited or failed before the interface was proven")]
    StartupFailed,
    #[error("the host's interface inventory could not be read")]
    ObservationFailed,
    #[error("more than one new device appeared, so the managed device is not identifiable")]
    DeviceAmbiguous,
    #[error("UAPI transport failed")]
    UapiTransport,
    #[error("UAPI response was malformed or exceeded its bound")]
    UapiMalformed,
    #[error("the helper refused the UAPI request")]
    UapiRefused,
}

impl HelperError {
    /// The stable, lowercase name of the helper failure.
    ///
    /// The name is what a diagnostic event carries, so that a refused helper
    /// call says which failure it was rather than only that the call failed.
    pub fn as_str(&self) -> &'static str {
        match self {
            HelperError::RelativePath => "helper_path_not_absolute",
            HelperError::NotFound => "helper_not_found",
            HelperError::Symlink => "helper_path_is_a_symlink",
            HelperError::NotRegularFile => "helper_not_a_regular_file",
            HelperError::NotExecutable => "helper_not_executable",
            HelperError::IdentityMismatch => "helper_identity_mismatch",
            HelperError::StartupFailed => "helper_startup_failed",
            HelperError::ObservationFailed => "interface_inventory_unreadable",
            HelperError::DeviceAmbiguous => "managed_device_ambiguous",
            HelperError::UapiTransport => "uapi_transport_failed",
            HelperError::UapiMalformed => "uapi_malformed",
            HelperError::UapiRefused => "uapi_refused",
        }
    }
}

/// A supervised foreground helper child. Killed on drop if still running.
#[derive(Debug)]
pub struct SupervisedHelper {
    child: std::process::Child,
    pub pid: u32,
}

impl SupervisedHelper {
    /// Spawns the pinned helper in the foreground with exactly
    /// `[helper, "utun"]` and `WG_PROCESS_FOREGROUND=1`. No shell, no PATH
    /// lookup, no caller flags, no inherited environment beyond the marker:
    /// `env_clear` + the single foreground entry. Stdout/stderr are piped
    /// with bounded drains owned by the caller.
    pub fn spawn(argv: &HelperArgv) -> Result<Self, HelperError> {
        use std::process::{Command, Stdio};

        let mut command = Command::new(&argv.helper);
        command
            .arg(HELPER_INTERFACE_ARG)
            .env_clear()
            .env(HELPER_FOREGROUND_ENV.0, HELPER_FOREGROUND_ENV.1)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|_| HelperError::StartupFailed)?;
        let pid = child.id();
        // Fail fast when the helper exits immediately (bad binary, missing
        // privilege, occupied UAPI socket): never leave a zombie behind.
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(Some(status)) = child.try_wait() {
            let _ = status;
            return Err(HelperError::StartupFailed);
        }
        Ok(Self { child, pid })
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for SupervisedHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Converts a portable base64 WireGuard key (the domain key encoding) to
/// the lowercase hex the pinned helper speaks on its UAPI socket. Rejects
/// anything that does not decode to exactly 32 bytes.
pub fn base64_key_to_hex(base64_key: &str) -> Result<String, HelperError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let bytes = STANDARD
        .decode(base64_key)
        .map_err(|_| HelperError::UapiMalformed)?;
    if bytes.len() != 32 {
        return Err(HelperError::UapiMalformed);
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Renders a `set` UAPI command from typed fields. Keys arrive as base64
/// (domain encoding, as the kernel UAPI specifies) and are converted to the
/// helper's hex wire form by [`base64_key_to_hex`]; endpoint, allowed IPs,
/// and keepalive are typed too — nothing raw reaches the socket.
pub fn render_uapi_set(
    private_key_base64: Option<&str>,
    listen_port: Option<u16>,
    peer: Option<&UapiPeerConfig<'_>>,
) -> Result<String, HelperError> {
    let mut out = String::from("set=1\n");
    if let Some(key) = private_key_base64 {
        let hex = base64_key_to_hex(key)?;
        out.push_str(&format!("private_key={hex}\n"));
    }
    if let Some(port) = listen_port {
        if port == 0 {
            return Err(HelperError::UapiMalformed);
        }
        out.push_str(&format!("listen_port={port}\n"));
    }
    if let Some(peer) = peer {
        let peer_hex = base64_key_to_hex(peer.public_key_base64)?;
        out.push_str(&format!("public_key={peer_hex}\n"));
        if peer.remove {
            out.push_str("remove=true\n");
        } else {
            if let Some(endpoint) = peer.endpoint {
                if endpoint.port() == 0 {
                    return Err(HelperError::UapiMalformed);
                }
                out.push_str(&format!("endpoint={endpoint}\n"));
            }
            if peer.allowed_ips.len() > MAX_UAPI_ALLOWED_IPS {
                return Err(HelperError::UapiMalformed);
            }
            for allowed in peer.allowed_ips {
                out.push_str(&format!("allowed_ip={allowed}\n"));
            }
            if let Some(keepalive) = peer.persistent_keepalive {
                out.push_str(&format!("persistent_keepalive_interval={keepalive}\n"));
            }
        }
    }
    out.push('\n');
    if out.len() > MAX_UAPI_REQUEST {
        return Err(HelperError::UapiMalformed);
    }
    Ok(out)
}

/// Minimal typed UAPI `get` observation (errno line + key/value section).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UapiDevice {
    pub errno: i64,
    pub pairs: Vec<(String, String)>,
}

/// Parses one UAPI `get=1` response in the helper's wire shape: `key=value`
/// dump lines followed by an `errno=N` status trailer and a blank
/// terminator (`device/uapi.go` `IpcHandle`: the dump comes first, the
/// status last — the reverse of the kernel UAPI). Bounded and
/// secret-agnostic (callers redact before logging; this parser never logs).
/// A missing trailer, a trailer anywhere but last, or a nonzero status all
/// fail; callers distinguish transport/parse failure from helper refusal via
/// the returned `errno`.
pub fn parse_uapi_get(response: &str) -> Result<UapiDevice, HelperError> {
    if response.len() > MAX_UAPI_RESPONSE {
        return Err(HelperError::UapiMalformed);
    }
    let mut lines = response.split('\n').peekable();
    let mut pairs = Vec::new();
    let mut errno: Option<i64> = None;
    loop {
        let line = lines.next().ok_or(HelperError::UapiMalformed)?;
        if line.is_empty() {
            break;
        }
        if pairs.len() > 4096 {
            return Err(HelperError::UapiMalformed);
        }
        if let Some(status) = line.strip_prefix("errno=") {
            if errno.is_some() || lines.peek().is_none_or(|next| !next.is_empty()) {
                return Err(HelperError::UapiMalformed);
            }
            errno = Some(status.parse().map_err(|_| HelperError::UapiMalformed)?);
            continue;
        }
        if errno.is_some() {
            return Err(HelperError::UapiMalformed);
        }
        let (key, value) = line.split_once('=').ok_or(HelperError::UapiMalformed)?;
        if key.is_empty() || key.len() > 128 || value.len() > 4096 {
            return Err(HelperError::UapiMalformed);
        }
        pairs.push((key.to_owned(), value.to_owned()));
    }
    let errno = errno.ok_or(HelperError::UapiMalformed)?;
    Ok(UapiDevice { errno, pairs })
}

/// Last-handshake epoch seconds from a UAPI `get` observation. The pinned
/// helper reports `last_handshake_time_sec` (the kernel reports
/// `latest_handshake`); absent or zero means no handshake has completed.
pub fn last_handshake_secs(device: &UapiDevice) -> Option<u64> {
    device
        .pairs
        .iter()
        .find(|(key, _)| key == "last_handshake_time_sec")
        .and_then(|(_, value)| value.parse().ok())
        .filter(|seconds| *seconds > 0)
}

/// One bounded UAPI round trip over an already-connected socket.
pub fn uapi_round_trip(stream: &mut UnixStream, command: &str) -> Result<UapiDevice, HelperError> {
    if command.len() > MAX_UAPI_REQUEST {
        return Err(HelperError::UapiMalformed);
    }
    stream
        .set_read_timeout(Some(UAPI_TIMEOUT))
        .map_err(|_| HelperError::UapiTransport)?;
    stream
        .set_write_timeout(Some(UAPI_TIMEOUT))
        .map_err(|_| HelperError::UapiTransport)?;
    stream
        .write_all(command.as_bytes())
        .map_err(|_| HelperError::UapiTransport)?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if response.len() > MAX_UAPI_RESPONSE {
            return Err(HelperError::UapiMalformed);
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                break
            }
            Err(_) => return Err(HelperError::UapiTransport),
        }
        if response.ends_with(b"\n\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&response).map_err(|_| HelperError::UapiMalformed)?;
    parse_uapi_get(text)
}

/// UAPI socket path for one kernel-assigned `utunN` name.
pub fn uapi_socket_path(utun_name: &str) -> PathBuf {
    PathBuf::from(format!("{UAPI_SOCKET_DIR}/{utun_name}.sock"))
}

/// Before/after interface-name delta: exactly one new `utunN` must appear
/// after the helper spawn. Zero or several is a fail-closed conflict (never
/// adopt or kill by numeric guess).
///
/// Zero and several are different facts and are reported as different
/// failures: zero means the helper never published a device, while several
/// means the host's device namespace was not quiescent when the helper
/// started, so the managed device cannot be told apart from the devices the
/// host created on its own. A caller that retries a contention must not be
/// told the helper died.
pub fn interface_delta(before: &[String], after: &[String]) -> Result<String, HelperError> {
    let mut new_names: Vec<&String> = after
        .iter()
        .filter(|name| !before.contains(name) && is_utun_name(name))
        .collect();
    new_names.sort();
    new_names.dedup();
    match new_names.as_slice() {
        [single] => Ok((*single).clone()),
        [] => Err(HelperError::StartupFailed),
        _ => Err(HelperError::DeviceAmbiguous),
    }
}

/// Whether a name is a kernel-assigned `utunN` device.
pub fn is_utun_name(name: &str) -> bool {
    let rest = name.strip_prefix("utun").unwrap_or_default();
    !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
}

/// The ownership claim netd must prove before any mutation or teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipClaim {
    pub installation: crate::domain::InstallationId,
    pub interface: crate::domain::InterfaceId,
    pub expected_utun: String,
    pub helper_pid: u32,
    pub uapi_socket: PathBuf,
}

/// Live observation gathered for one verification attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveObservation {
    pub utun_present: bool,
    pub uapi_answers: bool,
    pub helper_alive_with_pid: bool,
    pub owner_tag_matches: bool,
}

/// Proves helper + socket + device consistency. Any mismatch, stale receipt,
/// PID reuse, renumbering, or foreign `utun` is a non-retryable conflict:
/// never adopt or terminate a foreign interface, process, or socket.
pub fn verify_ownership(
    claim: &OwnershipClaim,
    observed: &LiveObservation,
) -> Result<(), OwnershipError> {
    if !observed.utun_present {
        return Err(OwnershipError::InterfaceAbsent);
    }
    if !observed.helper_alive_with_pid {
        return Err(OwnershipError::HelperMismatch);
    }
    if !observed.uapi_answers {
        return Err(OwnershipError::SocketMismatch);
    }
    if !observed.owner_tag_matches {
        return Err(OwnershipError::OwnerMismatch);
    }
    let _ = &claim.uapi_socket;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipError {
    #[error("managed utun is absent")]
    InterfaceAbsent,
    #[error("helper process identity does not match the claim (crash or PID reuse)")]
    HelperMismatch,
    #[error("UAPI socket does not answer for the claimed interface")]
    SocketMismatch,
    #[error("observed owner tag is foreign or missing")]
    OwnerMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_provenance_is_pinned() {
        assert_eq!(HELPER_VERSION_TAG, "0.0.20250522");
        assert_eq!(HELPER_COMMIT.len(), 40);
        assert_eq!(HELPER_LICENSE, "MIT");
        assert_eq!(HELPER_DEV_REFERENCE_SHA256.len(), 64);
    }

    #[test]
    fn helper_argv_is_fixed_with_no_path_lookup() {
        // `/bin/echo` stands in for the absolute helper path shape only;
        // identity is proven separately against the pinned hash.
        let argv = HelperArgv::new(PathBuf::from("/bin/echo")).unwrap();
        assert_eq!(
            argv.as_argv(),
            vec!["/bin/echo".to_owned(), "utun".to_owned()]
        );
        assert_eq!(
            HelperArgv::new(PathBuf::from("wireguard-go")).unwrap_err(),
            HelperError::RelativePath
        );
        assert_eq!(helper_env().len(), 1);
    }

    #[test]
    fn helper_identity_verification_rejects_mismatch() {
        let dir = std::env::temp_dir().join(format!("wgm3-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("helper");
        std::fs::write(&file, b"not the helper").unwrap();
        assert_eq!(
            verify_helper_sha256(&file, &"0".repeat(64)).unwrap_err(),
            HelperError::IdentityMismatch
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uapi_keys_convert_from_base64_to_helper_hex() {
        assert_eq!(
            base64_key_to_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap(),
            "00".repeat(32)
        );
        assert_eq!(
            base64_key_to_hex("6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=").unwrap(),
            "e8b4c7880338be0284822e6f9b7d1ffc40481161439b24a44dcf44582708a84b"
        );
        assert!(base64_key_to_hex("short").is_err());
        assert!(base64_key_to_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(base64_key_to_hex("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!").is_err());
    }

    #[test]
    fn uapi_set_renders_typed_fields_with_bounds() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let peer = UapiPeerConfig {
            public_key_base64: key,
            remove: false,
            endpoint: None,
            allowed_ips: &[],
            persistent_keepalive: None,
        };
        let rendered = render_uapi_set(Some(key), Some(51820), Some(&peer)).unwrap();
        assert!(rendered.starts_with("set=1\n"));
        assert!(rendered.contains("private_key="));
        assert!(rendered.contains(&format!("private_key={}", "00".repeat(32))));
        assert!(
            !rendered.contains("AAAA"),
            "base64 must never reach the helper wire"
        );
        assert!(rendered.contains("listen_port=51820\n"));
        assert!(rendered.ends_with("\n\n"));
        assert!(render_uapi_set(Some(key), Some(0), None).is_err());
        assert!(render_uapi_set(Some("short"), None, None).is_err());
        assert!(!format!("{rendered:?}").contains("nft"));

        let removal = UapiPeerConfig {
            remove: true,
            ..peer
        };
        let rendered_removal = render_uapi_set(None, None, Some(&removal)).unwrap();
        assert!(rendered_removal.contains("remove=true\n"));
        assert!(!rendered_removal.contains("endpoint="));

        let endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();
        let allowed: IpNet = "10.200.0.2/32".parse().unwrap();
        let full = UapiPeerConfig {
            endpoint: Some(endpoint),
            allowed_ips: std::slice::from_ref(&allowed),
            persistent_keepalive: Some(25),
            ..peer
        };
        let rendered_full = render_uapi_set(None, None, Some(&full)).unwrap();
        assert!(rendered_full.contains("endpoint=127.0.0.1:51821\n"));
        assert!(rendered_full.contains("allowed_ip=10.200.0.2/32\n"));
        assert!(rendered_full.contains("persistent_keepalive_interval=25\n"));

        let bad_port = UapiPeerConfig {
            endpoint: Some("127.0.0.1:0".parse().unwrap()),
            ..peer
        };
        assert!(render_uapi_set(None, None, Some(&bad_port)).is_err());
        let too_many = vec![allowed; MAX_UAPI_ALLOWED_IPS + 1];
        let overflowing = UapiPeerConfig {
            allowed_ips: &too_many,
            ..peer
        };
        assert!(render_uapi_set(None, None, Some(&overflowing)).is_err());
    }

    #[test]
    fn uapi_get_parses_errno_and_pairs_with_terminator() {
        let device =
            parse_uapi_get("private_key=e8b4c7880338be0284822e6f9b7d1ffc40481161439b24a44dcf44582708a84b\nlisten_port=51820\nerrno=0\n\n")
                .unwrap();
        assert_eq!(device.errno, 0);
        assert!(device.pairs.iter().any(|(key, _)| key == "listen_port"));
        assert!(parse_uapi_get("garbage\n\n").is_err());
        assert!(parse_uapi_get("errno=0\nno-equals-here\n\n").is_err());
        assert!(parse_uapi_get("listen_port=1\n\n").is_err());
        let refused = parse_uapi_get("listen_port=1\nerrno=-22\n\n").unwrap();
        assert_eq!(refused.errno, -22);
    }

    #[test]
    fn uapi_handshake_reads_helper_epoch_not_kernel_name() {
        let device = parse_uapi_get(
            "public_key=e8b4c7880338be0284822e6f9b7d1ffc40481161439b24a44dcf44582708a84b\nlast_handshake_time_sec=1720000000\nlast_handshake_time_nsec=123\ntx_bytes=100\nrx_bytes=200\nerrno=0\n\n",
        )
        .unwrap();
        assert_eq!(last_handshake_secs(&device), Some(1_720_000_000));
        let fresh = parse_uapi_get("last_handshake_time_sec=0\nerrno=0\n\n").unwrap();
        assert_eq!(last_handshake_secs(&fresh), None);
        let kernel_shaped = parse_uapi_get("latest_handshake=1720000000\nerrno=0\n\n").unwrap();
        assert_eq!(
            last_handshake_secs(&kernel_shaped),
            None,
            "kernel field names must not satisfy the helper observation"
        );
    }

    #[test]
    fn uapi_round_trip_works_over_a_socketpair() {
        use std::os::unix::net::UnixStream;

        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let command = render_uapi_set(Some(key), Some(51820), None).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let responder = std::thread::spawn(move || {
            // Read the command through its `\n\n` terminator, then answer.
            let mut seen = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                use std::io::Read as _;
                server.read_exact(&mut byte).unwrap();
                seen.push(byte[0]);
                if seen.ends_with(b"\n\n") {
                    break;
                }
            }
            let text = std::str::from_utf8(&seen).unwrap();
            assert!(text.starts_with("set=1\n"));
            use std::io::Write as _;
            server.write_all(b"listen_port=51820\nerrno=0\n\n").unwrap();
        });
        let device = uapi_round_trip(&mut client, &command).unwrap();
        assert_eq!(device.errno, 0);
        assert!(device.pairs.iter().any(|(key, _)| key == "listen_port"));
        responder.join().unwrap();
    }

    #[test]
    fn supervisor_spawns_fixed_argv_with_controlled_env() {
        use std::os::unix::fs::PermissionsExt;

        // Mock helper only: a temp-dir script that ignores its `utun`
        // argument and sleeps. Proves fixed argv, env_clear foreground
        // marker, and fail-fast on immediate exit — without any interface.
        let dir = std::env::temp_dir().join(format!("wgm3-sup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let mock = dir.join("mock-helper");
        std::fs::write(&mock, "#!/bin/sh\nsleep 5\n").unwrap();
        std::fs::set_permissions(&mock, std::fs::Permissions::from_mode(0o700)).unwrap();
        let argv = HelperArgv::new(mock.clone()).unwrap();
        assert_eq!(argv.as_argv()[1], "utun");
        let mut helper = SupervisedHelper::spawn(&argv).unwrap();
        assert!(helper.is_alive());
        drop(helper);
        // Immediate-exit binary fails fast instead of lingering.
        let dead_bin = PathBuf::from("/usr/bin/true");
        if dead_bin.exists() {
            let dead = HelperArgv::new(dead_bin).unwrap();
            assert_eq!(
                SupervisedHelper::spawn(&dead).unwrap_err(),
                HelperError::StartupFailed
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interface_delta_requires_exactly_one_new_utun() {
        let before = vec!["utun0".to_owned(), "en0".to_owned()];
        let after = vec!["utun0".to_owned(), "en0".to_owned(), "utun4".to_owned()];
        assert_eq!(interface_delta(&before, &after).unwrap(), "utun4");
        assert_eq!(
            interface_delta(&before, &before).unwrap_err(),
            HelperError::StartupFailed
        );
        let two = vec!["utun0".to_owned(), "utun4".to_owned(), "utun7".to_owned()];
        assert_eq!(
            interface_delta(&before, &two).unwrap_err(),
            HelperError::DeviceAmbiguous
        );
        // Non-utun newcomers never satisfy the delta.
        let other = vec!["utun0".to_owned(), "en0".to_owned(), "ipsec0".to_owned()];
        assert!(interface_delta(&before, &other).is_err());
    }

    #[test]
    fn a_contended_device_namespace_is_not_reported_as_a_failed_helper() {
        // macOS creates and destroys `utun` devices on its own, so more than
        // one new device is a fact about the host and not about the helper.
        // Reporting it as a startup failure tells the operator the wrong
        // thing and tells a retrying caller that there is nothing to retry.
        let before = vec!["utun0".to_owned()];
        let after = vec!["utun0".to_owned(), "utun4".to_owned(), "utun5".to_owned()];
        assert_eq!(
            interface_delta(&before, &after).unwrap_err(),
            HelperError::DeviceAmbiguous
        );
        // And the two are distinguishable in the diagnostic names too.
        assert_eq!(
            HelperError::DeviceAmbiguous.as_str(),
            "managed_device_ambiguous"
        );
        assert_ne!(
            HelperError::DeviceAmbiguous.as_str(),
            HelperError::StartupFailed.as_str()
        );
    }

    #[test]
    fn ownership_proof_fails_closed_on_every_mismatch() {
        use crate::domain::{InstallationId, InterfaceId};

        let claim = OwnershipClaim {
            installation: InstallationId::new(),
            interface: InterfaceId::new(),
            expected_utun: "utun4".into(),
            helper_pid: 1234,
            uapi_socket: uapi_socket_path("utun4"),
        };
        let good = LiveObservation {
            utun_present: true,
            uapi_answers: true,
            helper_alive_with_pid: true,
            owner_tag_matches: true,
        };
        assert!(verify_ownership(&claim, &good).is_ok());
        for (name, bad) in [
            (
                "absent",
                LiveObservation {
                    utun_present: false,
                    ..good.clone()
                },
            ),
            (
                "helper",
                LiveObservation {
                    helper_alive_with_pid: false,
                    ..good.clone()
                },
            ),
            (
                "socket",
                LiveObservation {
                    uapi_answers: false,
                    ..good.clone()
                },
            ),
            (
                "owner",
                LiveObservation {
                    owner_tag_matches: false,
                    ..good.clone()
                },
            ),
        ] {
            assert!(verify_ownership(&claim, &bad).is_err(), "{name}");
        }
    }
}
