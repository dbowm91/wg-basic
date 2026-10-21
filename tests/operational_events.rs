use std::{
    fs,
    io::Read,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use wg_basic::state::StateStore;

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        // The wall clock is too coarse to tell two concurrent tests apart: on
        // macOS consecutive `SystemTime::now()` calls routinely return the same
        // nanosecond value, so a timestamped scratch path is not unique. A
        // per-process counter is.
        static SCRATCH_SEQUENCE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "wg-basic-operational-events-{}-{}",
            std::process::id(),
            SCRATCH_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
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

/// The bound the harness gives the management daemon's HTTP listener to
/// come up: the product's own backend startup wait plus five seconds of
/// slack. On Linux the wait is zero, so the bound is five seconds; on
/// Darwin it is the wait the boot-race fix needs.
fn listener_deadline() -> Duration {
    wg_basic::management::BACKEND_STARTUP_WAIT + Duration::from_secs(5)
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
    // The harness's own "it hung" bound. The management daemon waits,
    // bounded, for the privileged daemon before its startup reconciliation on
    // the platforms that need it, so the listener can come up after that
    // budget when no backend is running. The bound therefore follows the
    // product's own startup wait plus the harness's slack, so a delay that
    // the product does not have is not tolerated here.
    let deadline = Instant::now() + listener_deadline();
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

/// Reads one piped stream into a shared buffer on its own thread.
///
/// The output has to be collected while the child is still running, so the
/// readiness event can be observed before the child is stopped.
fn read_pipe<R: Read + Send + 'static>(stream: R) -> (Arc<Mutex<Vec<u8>>>, thread::JoinHandle<()>) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buffer);
    let reader = thread::spawn(move || {
        let mut stream = std::io::BufReader::new(stream);
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => sink
                    .lock()
                    .expect("the pipe buffer lock")
                    .extend_from_slice(&chunk[..count]),
            }
        }
    });
    (buffer, reader)
}

/// Waits until the captured output contains the event code.
fn wait_for_event(buffer: &Arc<Mutex<Vec<u8>>>, event: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let seen = buffer
            .lock()
            .expect("the pipe buffer lock")
            .windows(event.len())
            .any(|window| window == event.as_bytes());
        if seen {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the child never reported {event}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// The captured output of one stopped `serve` process.
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn stop(mut guard: ChildGuard, bind: &str) -> Captured {
    let child = guard.0.as_mut().expect("a child");
    let stdout = child.stdout.take().expect("a piped stdout");
    let stderr = child.stderr.take().expect("a piped stderr");
    let (stdout_buffer, stdout_reader) = read_pipe(stdout);
    let (stderr_buffer, stderr_reader) = read_pipe(stderr);
    wait_listening(bind, guard.0.as_mut().expect("a child"));
    // The HTTP listener is bound before the readiness event is written, so
    // "the port accepts a connection" is not a sufficient readiness signal: a
    // child stopped in that window never reports that it started. The event
    // itself is the readiness signal.
    wait_for_event(&stderr_buffer, "serve.started", Duration::from_secs(15));
    let child = guard.0.as_mut().expect("a child");
    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
    let stdout_bytes = stdout_buffer.lock().expect("the pipe buffer lock").clone();
    let stderr_bytes = stderr_buffer.lock().expect("the pipe buffer lock").clone();
    Captured {
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    }
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
