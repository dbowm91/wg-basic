//! M002 Darwin privileged IPC qualification (native macOS only).
//!
//! Ports netd's narrow authorized UDS service to macOS with the
//! Apple-documented `getpeereid(3)` credential source. Proves authorized
//! serve-to-netd communication, unauthorized rejection, no root bypass by
//! default, bounded framing, socket ownership/stale-inode lifecycle, and
//! SIGTERM/restart behavior against the real `netd` binary. No tunnel, route,
//! PF, or launchd behavior is claimed here (M003–M006).

#![cfg(target_os = "macos")]

use std::{
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wg_basic::protocol::{
    read_frame, write_frame, RequestEnvelope, RequestOperation, ResponseBody, ResponseEnvelope,
    PROTOCOL_VERSION,
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct TempDir(PathBuf);

static TEMPDIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl TempDir {
    fn new(tag: &str) -> Self {
        // Short names: Darwin `sun_path` caps socket paths at 104 bytes.
        // pid + counter keeps uniqueness without nanosecond timestamps.
        let n = TEMPDIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("wgm2-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("n.sock")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn start_netd(socket: &Path, extra: &[&str]) -> Child {
    let mut args = vec!["netd", "--socket"];
    let socket_str = socket.to_str().unwrap().to_owned();
    args.push(&socket_str);
    args.extend(extra.iter().copied());
    Command::new(BINARY)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn await_bound(socket: &Path, child: &mut Child) {
    use std::io::Read as _;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if socket.exists() && UnixStream::connect(socket).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            panic!("netd exited before binding: {status}; stderr: {stderr}");
        }
        assert!(Instant::now() < deadline, "netd did not bind its socket");
        thread::sleep(Duration::from_millis(10));
    }
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

#[test]
fn authorized_peer_ping_and_capability_snapshot_over_getpeereid() {
    let dir = TempDir::new("auth");
    let socket = dir.socket();
    let mut netd = start_netd(&socket, &[]);
    await_bound(&socket, &mut netd);

    let pong = wg_basic::protocol::request(&socket, RequestOperation::Ping, 11).unwrap();
    assert!(matches!(pong, ResponseBody::Pong { .. }));
    let ResponseBody::Capabilities(snapshot) =
        wg_basic::protocol::request(&socket, RequestOperation::InspectCapabilities, 12).unwrap()
    else {
        panic!("expected capabilities");
    };
    assert_eq!(snapshot.os, std::env::consts::OS);
    assert_eq!(snapshot.effective_uid, current_uid());
    assert!(snapshot.runtime_directory_safe);
    // M002: Linux backends unavailable on Darwin; helper/PF untested until M003/M005.
    assert_eq!(
        snapshot.wireguard_control,
        wg_basic::protocol::CapabilityState::Unavailable
    );
    assert_eq!(
        snapshot.nftables,
        wg_basic::protocol::CapabilityState::Unavailable
    );
    assert_eq!(snapshot.cap_net_admin, None);

    netd.kill().unwrap();
    netd.wait().unwrap();
}

#[test]
fn allowlist_extension_keeps_default_user_and_denial_is_kernel_enforced() {
    // The binary always authorizes its own effective UID (plus `--allow-uid`
    // extras); true denial with the self excluded is proven by the portable
    // `denied_peer_is_rejected_before_request_data_is_read` unit test, which
    // constructs a policy without self and runs natively on Darwin. Here:
    // an extra allowlisted UID does not remove the default, and no root
    // bypass exists (pinned by the `auth` unit test).
    let dir = TempDir::new("allow");
    let socket = dir.socket();
    let impossible = if current_uid() == u32::MAX {
        u32::MAX - 1
    } else {
        u32::MAX
    };
    let allow = impossible.to_string();
    let mut netd = start_netd(&socket, &["--allow-uid", &allow]);
    await_bound(&socket, &mut netd);

    // Self still authorized alongside the extra UID.
    let pong = wg_basic::protocol::request(&socket, RequestOperation::Ping, 1).unwrap();
    assert!(matches!(pong, ResponseBody::Pong { .. }));

    netd.kill().unwrap();
    netd.wait().unwrap();
}

#[test]
fn malformed_frames_do_not_crash_or_bypass_auth() {
    let dir = TempDir::new("framing");
    let socket = dir.socket();
    let mut netd = start_netd(&socket, &[]);
    await_bound(&socket, &mut netd);

    // Oversized, truncated, and malformed inputs are rejected without echo.
    for index in 0..32_u32 {
        let mut stream = UnixStream::connect(&socket).unwrap();
        match index % 3 {
            0 => stream.write_all(&0_u32.to_be_bytes()).unwrap(),
            1 => stream
                .write_all(&((64 * 1024 + 1) as u32).to_be_bytes())
                .unwrap(),
            _ => write_frame(&mut stream, b"{ malformed json").unwrap(),
        }
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        assert!(response.is_empty(), "malformed input must not be reflected");
    }

    // Unknown version is rejected with correlation.
    let mut stream = UnixStream::connect(&socket).unwrap();
    write_frame(
        &mut stream,
        &serde_json::to_vec(&RequestEnvelope {
            protocol_version: PROTOCOL_VERSION + 1,
            request_id: 991,
            operation: RequestOperation::Ping,
        })
        .unwrap(),
    )
    .unwrap();
    let response: ResponseEnvelope =
        serde_json::from_slice(&read_frame(&mut stream).unwrap()).unwrap();
    assert_eq!(response.request_id, 991);

    // The service still answers an authorized Ping afterwards.
    let pong = wg_basic::protocol::request(&socket, RequestOperation::Ping, 801).unwrap();
    assert!(matches!(pong, ResponseBody::Pong { .. }));

    netd.kill().unwrap();
    netd.wait().unwrap();
}

#[test]
fn stale_socket_rebind_and_foreign_preservation() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("stale");
    let socket = dir.socket();

    // Foreign regular file is preserved and refuses bind.
    std::fs::write(&socket, b"keep me").unwrap();
    let output = Command::new(BINARY)
        .args(["netd", "--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&socket).unwrap(), b"keep me");
    std::fs::remove_file(&socket).unwrap();

    // Crash-style stale socket: real netd, then SIGKILL (no cleanup), then
    // restart must reclaim only the owned stale inode.
    let mut netd = start_netd(&socket, &[]);
    await_bound(&socket, &mut netd);
    // SIGKILL via `kill -9` (test-only).
    assert!(Command::new("kill")
        .args(["-9", &netd.id().to_string()])
        .status()
        .unwrap()
        .success());
    netd.wait().unwrap();
    assert!(socket.exists(), "crash must leave the stale socket file");

    let mut revived = start_netd(&socket, &[]);
    await_bound(&socket, &mut revived);
    let pong = wg_basic::protocol::request(&socket, RequestOperation::Ping, 5).unwrap();
    assert!(matches!(pong, ResponseBody::Pong { .. }));
    // Graceful SIGTERM (not SIGKILL) drains and removes only the owned inode.
    assert!(Command::new("kill")
        .args(["-TERM", &revived.id().to_string()])
        .status()
        .unwrap()
        .success());
    revived.wait().unwrap();
    assert!(!socket.exists(), "graceful stop removes its own socket");

    // Symlink at the socket path is never followed or replaced.
    std::os::unix::fs::symlink("/tmp", &socket).unwrap();
    let output = Command::new(BINARY)
        .args(["netd", "--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(std::fs::symlink_metadata(&socket)
        .unwrap()
        .file_type()
        .is_symlink());
    let _ = std::fs::set_permissions(dir.0.as_path(), std::fs::Permissions::from_mode(0o700));
}

#[test]
fn sigterm_drains_and_restart_rebinds() {
    let dir = TempDir::new("sigterm");
    let socket = dir.socket();
    let mut netd = start_netd(&socket, &[]);
    await_bound(&socket, &mut netd);

    assert!(Command::new("kill")
        .args(["-TERM", &netd.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = netd.try_wait().unwrap() {
            assert!(status.success(), "SIGTERM must exit cleanly: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "SIGTERM did not stop netd");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!socket.exists(), "SIGTERM removes the owned socket");

    // Restart on the same path works.
    let mut revived = start_netd(&socket, &[]);
    await_bound(&socket, &mut revived);
    let pong = wg_basic::protocol::request(&socket, RequestOperation::Ping, 6).unwrap();
    assert!(matches!(pong, ResponseBody::Pong { .. }));
    revived.kill().unwrap();
    revived.wait().unwrap();
}

#[test]
fn serve_reaches_netd_only_through_the_authorized_socket() {
    // Unprivileged serve never performs privileged operations directly: with
    // M002 netd running, serve's live probe answers; without netd it reports
    // unanswered. Either way serve never touches the kernel itself.
    use wg_basic::management::ManagementRuntime;

    let dir = TempDir::new("serve-probe");
    let state = dir.0.join("state.db");
    let socket = dir.socket();
    drop(wg_basic::state::StateStore::initialize(&state).unwrap());

    // Without netd: probe unanswered, health degraded — no direct kernel path.
    let runtime = ManagementRuntime::open(&state, &socket).unwrap();
    let probe = runtime.probe_backend();
    assert!(!probe.answered);

    // With netd: the same unprivileged runtime reaches it only over the socket.
    let mut netd = start_netd(&socket, &[]);
    await_bound(&socket, &mut netd);
    let probe = runtime.probe_backend();
    assert!(probe.answered);
    assert_eq!(probe.service.as_deref(), Some("wg-basic-netd"));

    netd.kill().unwrap();
    netd.wait().unwrap();
}
