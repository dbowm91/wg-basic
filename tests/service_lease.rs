use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::state::{ServiceLease, StateStore};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct TempDirectory(PathBuf);
impl TempDirectory {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!(
            "wg-basic-lease-fixture-{}-{}",
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
}
impl Drop for TempDirectory {
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

fn serve(state: &Path, socket: &Path, bind: &str) -> Child {
    Command::new(BINARY)
        .args(["serve", "--state"])
        .arg(state)
        .args(["--socket"])
        .arg(socket)
        .args(["--http-bind", bind])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for_lease(state: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if ServiceLease::is_held(state).unwrap() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("serve exited before acquiring its lease: {status}");
        }
        assert!(Instant::now() < deadline, "serve did not acquire its lease");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn serve_is_singleton_and_sigkill_releases_the_advisory_lease() {
    let temporary = TempDirectory::new();
    let state = temporary.0.join("state.db");
    let socket = temporary.0.join("netd.sock");
    drop(StateStore::initialize(&state).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let bind = format!("127.0.0.1:{port}");

    let mut first = ChildGuard(serve(&state, &socket, &bind));
    wait_for_lease(&state, &mut first.0);
    let candidate = temporary.0.join("candidate.db");
    let store = StateStore::open(&state).unwrap();
    store.backup(&candidate).unwrap();
    drop(store);
    let restore = Command::new(BINARY)
        .args(["state", "restore"])
        .arg(&candidate)
        .args(["--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(!restore.status.success());
    assert!(String::from_utf8_lossy(&restore.stderr).contains("state service is active"));
    let second = serve(&state, &socket, &bind).wait_with_output().unwrap();
    assert!(!second.status.success());
    let error = String::from_utf8_lossy(&second.stderr);
    assert!(
        error.contains("state service lease is already held"),
        "{error}"
    );

    first.0.kill().unwrap();
    first.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while ServiceLease::is_held(&state).unwrap() {
        assert!(
            Instant::now() < deadline,
            "SIGKILL did not release the lease"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let restored = Command::new(BINARY)
        .args(["state", "restore"])
        .arg(&candidate)
        .args(["--state"])
        .arg(&state)
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );

    let mut restarted = ChildGuard(serve(&state, &socket, &bind));
    wait_for_lease(&state, &mut restarted.0);
}
