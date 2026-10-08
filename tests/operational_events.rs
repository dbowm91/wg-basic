use std::{
    fs,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wg_basic::state::StateStore;

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-operational-events-{}-{}",
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

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn free_bind() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr.to_string()
}

fn start(state: &Path, socket: &Path, bind: &str, format: &str) -> Child {
    Command::new(BINARY)
        .args(["--log-format", format, "serve", "--state"])
        .arg(state)
        .args(["--socket"])
        .arg(socket)
        .args(["--http-bind", bind])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_listening(bind: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(addr) = bind.parse() {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(25)).is_ok() {
                return;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("serve exited before listening: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "serve did not bind its HTTP listener"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn stop(mut child: ChildGuard, bind: &str) -> std::process::Output {
    wait_listening(bind, child.0.as_mut().unwrap());
    child.0.as_mut().unwrap().kill().unwrap();
    child.0.take().unwrap().wait_with_output().unwrap()
}

#[test]
fn long_running_role_events_are_stderr_only_and_json_is_line_delimited() {
    let scratch = Scratch::new();
    let state = scratch.path("state.db");
    drop(StateStore::initialize(&state).unwrap());
    let socket = scratch.path("netd.sock");

    let json_bind = free_bind();
    let json = stop(
        ChildGuard(Some(start(&state, &socket, &json_bind, "json"))),
        &json_bind,
    );
    assert!(
        json.stdout.is_empty(),
        "serve operational events stay off stdout"
    );
    let stderr = String::from_utf8(json.stderr).unwrap();
    let parsed = stderr
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).expect("one JSON object per line")
        })
        .collect::<Vec<_>>();
    assert!(parsed
        .iter()
        .any(|event| event["event_code"] == "serve.started"));
    let secret_corpus = [
        "fixture-password-should-never-appear",
        "fixture-session-bearer-token",
        "fixture-csrf-token",
        "fixture-enrollment-token",
        "fixture-private-key",
        "fixture-preshared-key",
        "[Interface]",
    ];
    for secret in secret_corpus {
        assert!(!stderr.contains(secret), "operational log leaked {secret}");
    }

    let human_bind = free_bind();
    let human = stop(
        ChildGuard(Some(start(&state, &socket, &human_bind, "human"))),
        &human_bind,
    );
    assert!(human.stdout.is_empty());
    let human_stderr = String::from_utf8(human.stderr).unwrap();
    assert!(human_stderr
        .lines()
        .any(|line| line.starts_with("INFO serve serve.started")));
}
