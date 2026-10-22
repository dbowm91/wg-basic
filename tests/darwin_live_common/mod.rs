//! Shared helpers for the Darwin privileged live qualifications.
//!
//! The hosted-runner suite (`tests/wireguard_darwin_live.rs`) and the
//! controlled-host suite (`tests/wireguard_darwin_controlled.rs`) drive the
//! same product on different hosts, so the helpers they share live here
//! rather than being copied between them.

#![allow(dead_code)]

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use wg_basic::launchd;
use wg_basic::wireguard::darwin as wg_darwin;

/// Opt-in gate: without it (or without root) the test fails loudly instead
/// of silently passing. There is no silent skip in live mode.
pub fn require_live(evidence: &mut Evidence) -> PathBuf {
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

pub fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

/// Evidence sink: every line goes to stderr immediately (CI `--nocapture`
/// keeps it on failure) and to an evidence file on success.
pub struct Evidence {
    pub name: &'static str,
    pub lines: Vec<String>,
}

impl Evidence {
    pub fn new(name: &'static str) -> Self {
        let mut evidence = Self {
            name,
            lines: Vec::new(),
        };
        evidence.log(&format!("live test: {name}"));
        evidence
    }

    pub fn log(&mut self, line: &str) {
        eprintln!("[live-evidence:{}] {line}", self.name);
        self.lines.push(line.to_owned());
    }

    pub fn write(self) {
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
pub fn sh(evidence: &mut Evidence, program: &str, args: &[&str]) -> String {
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

pub fn utun_names() -> Vec<String> {
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

pub fn wait_until(what: &str, timeout: Duration, mut ready: impl FnMut() -> bool) {
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

/// Waits for a condition, and reports whether it became true.
///
/// This is the bounded variant of [`wait_until`]: a caller that can recover
/// from a condition that never arrives uses this one, so the timeout becomes
/// evidence rather than the end of the run.
pub fn wait_until_or_false(
    _what: &str,
    timeout: Duration,
    mut ready: impl FnMut() -> bool,
) -> bool {
    let start = Instant::now();
    loop {
        if ready() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub fn uapi(socket: &Path, command: &str) -> wg_darwin::UapiDevice {
    let mut stream = UnixStream::connect(socket)
        .unwrap_or_else(|error| panic!("UAPI connect {}: {error}", socket.display()));
    wg_darwin::uapi_round_trip(&mut stream, command)
        .unwrap_or_else(|error| panic!("UAPI round trip failed: {error:?}"))
}

/// The same command with secret values redacted for evidence output.
pub fn redact_uapi(command: &str) -> String {
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

pub fn pair_u64(device: &wg_darwin::UapiDevice, key: &str) -> Option<u64> {
    device
        .pairs
        .iter()
        .find(|(entry, _)| entry == key)
        .and_then(|(_, value)| value.parse().ok())
}

pub fn latest_handshake(device: &wg_darwin::UapiDevice) -> Option<u64> {
    wg_darwin::last_handshake_secs(device)
}

/// One live tunnel endpoint: supervised helper + kernel `utun` + UAPI path.
pub struct LiveEndpoint {
    pub helper: wg_darwin::SupervisedHelper,
    pub utun: String,
    pub socket: PathBuf,
}

impl LiveEndpoint {
    pub fn spawn(
        evidence: &mut Evidence,
        helper_path: &Path,
        baseline: &[String],
        tag: &str,
    ) -> Self {
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

    pub fn get(&self, evidence: &mut Evidence) -> wg_darwin::UapiDevice {
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
    pub fn set_device(
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

pub fn ensure_uapi_dir(evidence: &mut Evidence) {
    let dir = Path::new(wg_darwin::UAPI_SOCKET_DIR);
    if !dir.exists() {
        std::fs::create_dir(dir).expect("create UAPI socket dir");
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .expect("UAPI socket dir owner-only");
    evidence.log(&format!("UAPI dir ready: {}", dir.display()));
}

/// First whitespace field of a `netstat -rn` line (the destination), or an
/// empty string for blank/header lines.
pub fn route_destination(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

/// Asserts a post-fixture `netstat -rn` inventory stayed within the
/// fixture's scope: only the managed utun and TEST-NET destinations
/// (`192.0.2.`/`2001:db8:`) may appear, and pre-existing destinations must
/// keep their gateways. Counter drift (Refs/Use/Expire) on pre-existing
/// gateway/ARP lines is background host noise, not fixture damage.
pub fn check_inventory_scoped(
    evidence: &mut Evidence,
    family: &str,
    baseline_routes: &str,
    utun: &str,
    netstat_args: &[&str],
) {
    let after_routes = sh(evidence, "netstat", netstat_args);
    let baseline_dests: HashSet<&str> = baseline_routes.lines().map(route_destination).collect();
    let mut baseline_gateways: HashSet<(&str, &str)> = HashSet::new();
    for line in baseline_routes.lines() {
        let destination = route_destination(line);
        if destination.is_empty() {
            continue;
        }
        let gateway = line.split_whitespace().nth(1).unwrap_or("");
        baseline_gateways.insert((destination, gateway));
    }
    for line in after_routes.lines() {
        let destination = route_destination(line);
        if destination.is_empty() {
            continue;
        }
        let gateway = line.split_whitespace().nth(1).unwrap_or("");
        if !baseline_dests.contains(destination) {
            assert!(
                line.contains(utun) || line.contains("192.0.2.") || line.contains("2001:db8:"),
                "{family}: added destination must be utun-scoped only: {line}"
            );
        } else {
            assert!(
                baseline_gateways.contains(&(destination, gateway)),
                "{family}: pre-existing destination {destination} changed gateway \
                 (now {gateway}): fixture must never reroute foreign state"
            );
        }
    }
    evidence.log(&format!("{family}: inventory stayed within fixture scope"));
}

pub fn remove_if_exists(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Runs a command as root without asserting success, for negative probes
/// (the transcript is still logged as evidence).
pub fn sh_unchecked(evidence: &mut Evidence, program: &str, args: &[&str]) -> (bool, String) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {program}: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let transcript = if stdout.len() > 2000 {
        format!("{}…[truncated]", &stdout[..2000])
    } else {
        stdout.into_owned()
    };
    evidence.log(&format!("$ {program} {}", args.join(" ")));
    evidence.log(&transcript);
    (output.status.success(), transcript)
}

/// M005 live platform proof: the forwarding toggle cycles and restores,
/// PF enables/disables, the dedicated anchor stays provably unattached
/// even while PF is enabled, and tunnel traffic without attachment
/// provably fails (no false convergence). The main-ruleset replacement the
/// product must never perform is attempted parse-only and recorded as
/// platform-refused. Effective NAT traffic stays unqualified (it needs that
/// refused attachment plus a v6 uplink hosted runners lack).
///
/// Removes the deployment and the disposable account when the test ends.
///
/// The cleanup runs when the test ends **including when an assertion
/// panics**: the next live test bootstraps the same launchd labels and must
/// find the system domain clean, so a failed test may not leave a job
/// registered or a socket behind.
pub struct DisposableDeployment {
    pub user: String,
    pub group: String,
}

impl DisposableDeployment {
    /// Waits until the system domain forgets both jobs.
    pub fn wait_until_unloaded(&self) {
        for job in [
            format!("system/{}", launchd::SERVE_LABEL),
            format!("system/{}", launchd::NETD_LABEL),
        ] {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let loaded = Command::new("launchctl")
                    .args(["print", &job])
                    .output()
                    .is_ok_and(|output| output.status.success());
                if !loaded {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

impl Drop for DisposableDeployment {
    fn drop(&mut self) {
        let _ = wg_basic::launchd_install::uninstall(Path::new("/"));
        self.wait_until_unloaded();
        for plist in [
            format!("/Library/LaunchDaemons/{}.plist", launchd::NETD_LABEL),
            format!("/Library/LaunchDaemons/{}.plist", launchd::SERVE_LABEL),
        ] {
            remove_if_exists(Path::new(&plist));
        }
        remove_if_exists(Path::new(launchd::BINARY_PATH));
        remove_if_exists(Path::new(launchd::HELPER_PATH));
        let _ = std::fs::remove_dir_all(Path::new(launchd::RUNTIME_DIR));
        let _ = std::fs::remove_dir_all(Path::new(launchd::STATE_DIR));
        let _ = std::fs::remove_dir_all("/var/log/wg-basic");
        let _ = std::fs::remove_dir_all("/usr/local/libexec/wg-basic");
        for record in [
            format!("/Users/{}", self.user),
            format!("/Groups/{}", self.group),
        ] {
            let _ = Command::new("dscl")
                .args([".", "-delete", &record])
                .output();
        }
    }
}

/// The tunnel the C001 product-path qualification converges.
///
/// A private IPv4 pool and a documentation IPv6 prefix, so nothing here
/// collides with the host's own network and no claim is made about a routed
/// or public prefix.
pub const TUNNEL_V4: &str = "10.77.0.0/24";
pub const TUNNEL_V6: &str = "2001:db8:77::/64";
pub const SERVER_V4: &str = "10.77.0.1";
pub const SERVER_V6: &str = "2001:db8:77::1";
/// The port the managed tunnel listens on.
pub const LISTEN_PORT: u16 = 51820;
/// The persistent keepalive an enrolled peer is given.
///
/// The peer holds no traffic of its own and sits behind a NAT, so without a
/// keepalive it never initiates a session and the two ends never meet.
pub const CLIENT_KEEPALIVE: u16 = 25;
/// The first identifier the disposable management identity may take.
///
/// Identifiers below this belong to the system's own accounts and the local
/// administrator range; a qualification identity is disposable, so it is
/// taken from above them.
pub const DISPOSABLE_UID_BASE: u32 = 8998;

/// The application firewall's control tool.
pub const FIREWALL_TOOL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Whether a directory-service search finds nothing.
pub fn dscl_search_empty(path: &str, key: &str, value: &str) -> bool {
    Command::new("dscl")
        .args([".", "-search", path, key, value])
        .output()
        .is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim().is_empty()
        })
}

/// The value a directory-service record already carries for an attribute.
///
/// `dscl -create` refuses to overwrite an attribute that already exists, so a
/// record that survives from an earlier run has to be read rather than
/// rewritten.
pub fn dscl_attribute(record: &str, key: &str) -> Option<String> {
    let output = Command::new("dscl")
        .args([".", "-read", record, key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}: ")))?
        .trim()
        .to_owned();
    (!value.is_empty()).then_some(value)
}

/// Sets an attribute on a record, replacing a value that differs.
///
/// `dscl -create` refuses to overwrite an attribute that already exists, so a
/// value that has to change is removed first.
pub fn dscl_set(evidence: &mut Evidence, record: &str, key: &str, value: &str) {
    if dscl_attribute(record, key).as_deref() == Some(value) {
        return;
    }
    let _ = Command::new("dscl")
        .args([".", "-delete", record, key])
        .output();
    sh(evidence, "dscl", &[".", "-create", record, key, value]);
}

/// Provisions the disposable management identity the installer binds to.
///
/// The installer never creates accounts and never adopts an unknown identity:
/// the qualification supplies one, exactly as an operator supplies it.
///
/// A controlled host is reused across qualification runs, and a local account
/// that was deleted keeps its numeric identifier reserved for a while. The
/// identity is therefore reused when the host still carries it and chosen
/// from the disposable range when it does not, so a second run on the same
/// host provisions a clean identity either way.
pub fn provision_management_identity(evidence: &mut Evidence) -> (u32, u32) {
    let group = launchd::SERVE_GROUP;
    let user = launchd::SERVE_USER;
    let user_record = format!("/Users/{user}");
    let group_record = format!("/Groups/{group}");

    let uid = match dscl_attribute(&user_record, "UniqueID") {
        Some(existing) => existing
            .parse()
            .expect("the management identity must carry a numeric identifier"),
        None => {
            let mut chosen = None;
            for offset in 0..64u32 {
                let candidate = DISPOSABLE_UID_BASE + offset;
                if dscl_search_empty("/Users", "UniqueID", &candidate.to_string()) {
                    chosen = Some(candidate);
                    break;
                }
            }
            chosen.expect("a free disposable management identity")
        }
    };
    // The group identifier is the group's own, so an account that survives
    // from an earlier run keeps the pair it was provisioned with instead of
    // being given a new one it does not match.
    let gid = match dscl_attribute(&group_record, "PrimaryGroupID") {
        Some(existing) => existing
            .parse()
            .expect("the management group must carry a numeric identifier"),
        None => {
            let mut chosen = None;
            for offset in 0..64u32 {
                let candidate = DISPOSABLE_UID_BASE + offset;
                if dscl_search_empty("/Groups", "PrimaryGroupID", &candidate.to_string()) {
                    chosen = Some(candidate);
                    break;
                }
            }
            chosen.expect("a free disposable management group")
        }
    };
    dscl_set(evidence, &group_record, "PrimaryGroupID", &gid.to_string());
    dscl_set(evidence, &user_record, "UserShell", "/usr/bin/false");
    dscl_set(evidence, &user_record, "PrimaryGroupID", &gid.to_string());
    dscl_set(evidence, &user_record, "UniqueID", &uid.to_string());
    dscl_set(evidence, &user_record, "NFSHomeDirectory", "/var/empty");
    dscl_set(evidence, &user_record, "RealName", "wg-basic serve");
    sh(
        evidence,
        "dscl",
        &[".", "-create", &group_record, "GroupMembership", user],
    );
    evidence.log(&format!(
        "preprovisioned the disposable management account and group (uid={uid} gid={gid})"
    ));
    (uid, gid)
}

/// Resolves the provisioned management identity.
///
/// The directory service publishes a new local record asynchronously, so the
/// identity is resolved with a bounded retry rather than a single lookup.
pub fn resolve_management_identity(evidence: &mut Evidence) -> launchd::ServiceIdentity {
    let mut resolved = None;
    for _ in 0..40 {
        if let Ok(identity) = launchd::resolve_service_identity(launchd::ServiceRole::Serve) {
            resolved = Some(identity);
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let identity = resolved.expect("the preprovisioned management identity must resolve");
    assert!(
        identity.uid >= launchd::MIN_SERVICE_UID,
        "the management identity must not be a reserved system id"
    );
    assert_ne!(identity.uid, 0, "the management daemon must never be root");
    evidence.log(&format!(
        "management identity {} uid={} gid={}",
        identity.user, identity.uid, identity.gid
    ));
    identity
}

/// Whether a system-domain launchd job is running.
pub fn launchd_running(job: &str) -> bool {
    Command::new("launchctl")
        .args(["print", job])
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("state = running")
        })
}

/// The off-host peer driver.
///
/// The peer half of the qualification is a second, independent WireGuard
/// implementation — the Linux kernel module, not the helper the product
/// supervises — on another host. The fixture drives a driver script with a
/// fixed contract, so the transport between the two hosts can change without
/// the qualification changing.
pub fn peer_driver() -> PathBuf {
    let command = std::env::var("WGB_PEER_COMMAND")
        .expect("WGB_PEER_COMMAND must point at the off-host peer driver");
    let path = PathBuf::from(&command);
    assert!(
        path.is_absolute(),
        "WGB_PEER_COMMAND must be absolute, got {command}"
    );
    assert!(
        path.is_file(),
        "the peer driver must exist: {}",
        path.display()
    );
    path
}

/// Runs the peer driver and returns its standard output.
pub fn peer_run(evidence: &mut Evidence, driver: &Path, args: &[&str]) -> String {
    let output = Command::new(driver)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run the peer driver: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    evidence.log(&format!("$ peer {}", args.join(" ")));
    evidence.log(stdout.trim());
    assert!(
        output.status.success(),
        "the peer driver failed for {}: {stderr}",
        args.join(" ")
    );
    stdout
}

/// One authenticated management HTTP request.
///
/// The shapes are the product's own: a JSON body, a session cookie, and the
/// CSRF token an unsafe request must carry.
pub fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: &str,
) -> (u16, String, Vec<(String, String)>) {
    use std::io::{BufRead, BufReader, Read, Write};
    // The management listener is started by launchd, so a request that
    // arrives right after the service is kicked off can be refused before the
    // listener is bound. The request waits for the listener rather than
    // failing on the first refusal.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut connection = None;
    while Instant::now() < deadline {
        match std::net::TcpStream::connect(addr) {
            Ok(stream) => {
                connection = Some(stream);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let mut stream = connection.expect("management listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let host = addr.to_string();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(origin) = origin {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    if let Some(cookie) = cookie {
        request.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    if let Some(csrf) = csrf {
        request.push_str(&format!("x-wg-basic-csrf: {csrf}\r\n"));
    }
    if !body.is_empty() {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).expect("write request");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("status line");
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status code");
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).expect("header line");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.to_owned(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).expect("body");
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    )
}

/// Parses a management-API response body as JSON, or `None` when it is not
/// JSON.
///
/// A deployment that is still converging answers the management surface with
/// `503 Service Unavailable` and the plain-text body `unavailable`. That is
/// the expected transient state, not a failure, so a wait that polls for
/// convergence must treat it as "not yet" and keep waiting instead of
/// panicking on the first response it cannot parse.
pub fn json_body(body: &str) -> Option<serde_json::Value> {
    serde_json::from_str(body).ok()
}

/// The IPv4 address an interface answers on.
///
/// The interface's own address is what a peer on the same network dials, so
/// the tunnel's advertised endpoint is taken from here rather than invented.
pub fn interface_ipv4(evidence: &mut Evidence, interface: &str) -> String {
    let listing = sh(evidence, "ifconfig", &[interface]);
    listing
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|rest| rest.split_whitespace().next())
        .find(|address| !address.is_empty())
        .map(|address| address.to_owned())
        .expect("the interface must have an IPv4 address")
}

/// The deployment's own logs.
///
/// A refusal from the privileged boundary is explained by the daemon that
/// refused it, so the qualification keeps what it said.
pub fn capture_daemon_logs(evidence: &mut Evidence) {
    for log in [launchd::NETD_LOG, launchd::SERVE_LOG] {
        match std::fs::read_to_string(log) {
            Ok(text) => {
                for line in text.lines() {
                    evidence.log(&format!("{}: {line}", log));
                }
            }
            Err(error) => evidence.log(&format!("{log}: unreadable ({error})")),
        }
    }
}

/// Removes the application-firewall allowance when the test ends.
///
/// The macOS application firewall is a host policy, not the product's: the
/// qualification allows the pinned helper to accept the tunnel's UDP and
/// leaves the host as it found it, including when an assertion panics.
pub struct FirewallAllowance {
    pub path: String,
}

impl Drop for FirewallAllowance {
    fn drop(&mut self) {
        let _ = Command::new(FIREWALL_TOOL)
            .args(["--remove", &self.path])
            .output();
    }
}
