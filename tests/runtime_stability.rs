//! Bounded process resource and row-growth smoke qualification for the long-lived serve role.
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{management::set_password_at, state::StateStore};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-runtime-stability-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcSample {
    descriptors: usize,
    threads: usize,
    rss_kib: u64,
}

fn sample(pid: u32) -> ProcSample {
    let root = format!("/proc/{pid}");
    let status = fs::read_to_string(format!("{root}/status")).unwrap();
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap();
    ProcSample {
        descriptors: fs::read_dir(format!("{root}/fd")).unwrap().count(),
        threads: fs::read_dir(format!("{root}/task")).unwrap().count(),
        rss_kib,
    }
}

fn rows(path: &Path) -> (i64, i64, i64) {
    let store = StateStore::open(path).unwrap();
    let sessions = store.session_count().unwrap();
    let enrollment = store.enrollment_capability_count().unwrap();
    let audit = rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();
    (sessions, enrollment, audit)
}

fn request(addr: std::net::SocketAddr, host: &str) -> u16 {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn repeated_valid_and_rejected_http_requests_have_bounded_resource_and_row_growth() {
    let scratch = Scratch::new();
    let state = scratch.path("state.db");
    drop(StateStore::initialize(&state).unwrap());
    set_password_at(&state, "admin", "an administrator password").unwrap();
    let socket = scratch.path("netd.sock");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let bind = addr.to_string();
    let mut child = ChildGuard(
        Command::new(BINARY)
            .args(["--log-format", "json", "serve", "--state"])
            .arg(&state)
            .args(["--socket"])
            .arg(&socket)
            .args(["--http-bind", &bind])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(25)).is_ok() {
            break;
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("serve exited before listener bind: {status}");
        }
        assert!(Instant::now() < deadline, "serve did not bind");
        thread::sleep(Duration::from_millis(10));
    }

    let before = sample(child.0.id());
    let before_rows = rows(&state);
    let valid_host = format!("127.0.0.1:{}", addr.port());
    for _ in 0..200 {
        assert_eq!(request(addr, &valid_host), 200);
        assert_eq!(request(addr, "not-the-configured-host.invalid"), 403);
    }
    let after = sample(child.0.id());
    let after_rows = rows(&state);
    assert!(
        after.descriptors <= before.descriptors + 2,
        "FD growth: {before:?} -> {after:?}"
    );
    assert_eq!(
        after.threads, before.threads,
        "thread count grew: {before:?} -> {after:?}"
    );
    assert!(
        after.rss_kib <= before.rss_kib + 16 * 1024,
        "RSS growth exceeded 16 MiB: {before:?} -> {after:?}"
    );
    assert_eq!(
        after_rows, before_rows,
        "read-only HTTP stress changed retained rows"
    );
}
