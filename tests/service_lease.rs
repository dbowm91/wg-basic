use std::{
    fs,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::{
    domain::{CsrfToken, SessionId, SessionToken},
    management::set_password_at,
    state::{ServiceLease, SessionRecord, StateStore},
};

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

fn wait_for_listener(bind: &str, child: &mut Child) {
    let address = bind.parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(20)).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("serve exited before listening: {status}");
        }
        assert!(Instant::now() < deadline, "serve did not bind HTTP");
        thread::sleep(Duration::from_millis(10));
    }
}

fn proc_entries(path: &str) -> usize {
    fs::read_dir(path).unwrap().count()
}

#[test]
fn serve_is_singleton_and_sigkill_releases_the_advisory_lease() {
    let temporary = TempDirectory::new();
    let state = temporary.0.join("state.db");
    let socket = temporary.0.join("netd.sock");
    drop(StateStore::initialize(&state).unwrap());
    set_password_at(&state, "admin", "an administrator password").unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let store = StateStore::open(&state).unwrap();
        let principal = store.principal_by_username("admin").unwrap().unwrap();
        store
            .insert_session(
                &SessionRecord {
                    id: SessionId::new(),
                    principal_id: principal.id,
                    csrf_token: CsrfToken::generate().unwrap(),
                    created_at: now - 7_200,
                    expires_at: now - 3_600,
                },
                &SessionToken::generate().unwrap().digest(),
            )
            .unwrap();
        assert_eq!(store.session_count().unwrap(), 1);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let bind = format!("127.0.0.1:{port}");

    let mut first = ChildGuard(serve(&state, &socket, &bind));
    wait_for_lease(&state, &mut first.0);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let store = StateStore::open(&state).unwrap();
        let count = store.session_count().unwrap();
        drop(store);
        if count == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "serve startup did not prune expired sessions"
        );
        thread::sleep(Duration::from_millis(10));
    }
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
    wait_for_listener(&bind, &mut restarted.0);
    restarted.0.kill().unwrap();
    restarted.0.wait().unwrap();
    drop(restarted);

    let file_descriptors = proc_entries("/proc/self/fd");
    let threads = proc_entries("/proc/self/task");
    for _ in 0..20 {
        let port_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cycle_bind = port_listener.local_addr().unwrap().to_string();
        drop(port_listener);
        let mut child = ChildGuard(serve(&state, &socket, &cycle_bind));
        wait_for_lease(&state, &mut child.0);
        wait_for_listener(&cycle_bind, &mut child.0);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        drop(child);
        assert!(!ServiceLease::is_held(&state).unwrap());
    }
    assert!(
        proc_entries("/proc/self/fd") <= file_descriptors + 1,
        "repeated serve crashes leaked file descriptors"
    );
    assert_eq!(
        proc_entries("/proc/self/task"),
        threads,
        "repeated serve crashes leaked threads"
    );
}
