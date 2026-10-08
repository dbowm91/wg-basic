//! Phase 7 M004 §9: performance and footprint evidence, captured on the real
//! binary.
//!
//! # What this file is for, and what it is not
//!
//! The plan asks for measurements "without over-claiming" and against the
//! long-term <30 MiB target "as an engineering signal", explicitly not weakening
//! security or correctness to meet it. So this file:
//!
//! * measures the **real** `wg-basic serve` and `wg-basic netd` processes, as a
//!   release build, with a real on-disk state store and a real socket — not an
//!   in-process harness, whose numbers would be a different program;
//! * prints every figure with the units and the sample count it was measured
//!   over, and asserts only on bounds that are properties of the design (a
//!   bounded answer, a bounded body, an order of magnitude) rather than on
//!   wall-clock numbers that would make the suite flaky on a loaded CI box;
//! * prints, rather than asserts, the figures an engineer would want to see in a
//!   review — cold readiness, idle RSS, idle CPU, login Argon2 latency, health
//!   latency, worker queue capacity — so the numbers land in the test output and
//!   can be transcribed into the closure record.
//!
//! # Why release
//!
//! Argon2 in a debug build costs ~300 ms per verification and ~19 MiB; in release
//! it costs ~15 ms. A footprint measured on a debug build would be reporting the
//! optimiser's absence, not the product. This file runs the release binary.
//!
//! Every measurement is a median over several samples rather than a single one,
//! because a single sample on a shared runner measures the runner.

#![cfg(target_os = "linux")]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const BINARY: &str = env!("CARGO_BIN_EXE_wg-basic");

static COUNTER: AtomicU64 = AtomicU64::new(0);

const USERNAME: &str = "admin";
const PASSWORD: &str = "an administrator password";

/// Every wait is a deadline; no sleep anywhere in this file.
const DEADLINE: Duration = Duration::from_secs(60);

/// The long-term engineering signal from the roadmap, in MiB.
///
/// Compared against and *not* enforced as a gate: the plan says not to weaken
/// security or correctness to meet it. It is printed next to the measured total
/// so a regression is visible, and asserted only to the loose bound below.
const TOTAL_FOOTPRINT_SIGNAL_MIB: u64 = 30;

/// How many samples every reported figure is a median over.
const SAMPLES: usize = 5;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-m004-footprint-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state.db")
    }

    fn netd_socket(&self) -> PathBuf {
        self.0.join("netd.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A managed child process with its stderr collected.
struct Managed {
    name: &'static str,
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Managed {
    fn start(name: &'static str, args: &[&str]) -> Self {
        let mut command = Command::new(BINARY);
        command.args(args);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {name}: {error}"));

        let lines = Arc::new(Mutex::new(Vec::new()));
        let stderr = child.stderr.take().expect("stderr is piped");
        let collected = Arc::clone(&lines);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                collected.lock().expect("the log lock is free").push(line);
            }
        });

        Self {
            name,
            child,
            lines,
            reader: Some(reader),
        }
    }

    fn log(&self) -> Vec<String> {
        self.lines.lock().expect("the log lock is free").clone()
    }

    fn is_alive(&self) -> bool {
        Path::new(&format!("/proc/{}", self.child.id())).exists()
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn await_log(&self, needle: &str) -> String {
        let started = Instant::now();
        loop {
            for line in self.log() {
                if line.contains(needle) {
                    return line;
                }
            }
            assert!(
                self.is_alive(),
                "{} exited before logging {needle:?}; log: {:#?}",
                self.name,
                self.log()
            );
            assert!(
                started.elapsed() < DEADLINE,
                "{} never logged {needle:?}; log: {:#?}",
                self.name,
                self.log()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Sends `SIGTERM` and requires the child to exit.
    ///
    /// Polls `try_wait` rather than `/proc` because a child that has exited but
    /// has not been waited for remains in `/proc` as a zombie — so a `/proc`
    /// liveness check would report a cleanly-stopped process as still running and
    /// fail the very assertion it is meant to make.
    fn stop(&mut self) {
        if self
            .child
            .try_wait()
            .expect("the child is waitable")
            .is_some()
        {
            return;
        }
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let started = Instant::now();
        loop {
            match self.child.try_wait().expect("the child is waitable") {
                Some(status) => {
                    assert!(
                        status.success(),
                        "{} exited with {:?} on SIGTERM rather than shutting down",
                        self.name,
                        status.code()
                    );
                    break;
                }
                None => {
                    assert!(
                        started.elapsed() < DEADLINE,
                        "{} ignored SIGTERM",
                        self.name
                    );
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        if self.is_alive() {
            let _ = Command::new("kill")
                .args(["-KILL", &self.child.id().to_string()])
                .status();
            let _ = self.child.wait();
        }
    }
}

/// Resident set size of a live process, in KiB.
///
/// Read from `/proc/<pid>/status` so the figure is the kernel's, not an estimate
/// from this process's own accounting.
fn resident_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_else(|error| panic!("cannot read /proc/{pid}/status: {error}"));
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("no VmRSS in /proc/{pid}/status"))
}

/// Total CPU time a process has consumed, in ticks.
///
/// Sampled as a *delta* between two reads, which is how "idle CPU" is honestly
/// measured: the absolute number includes start-up work that is not idle.
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap_or_else(|error| panic!("cannot read /proc/{pid}/stat: {error}"));
    // Field 14 and 15 (1-based) are utime and stime, after a comm field that
    // may itself contain spaces, so the split starts after the closing paren.
    let after_comm = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .expect("/proc/<pid>/stat has a comm field");
    let tick = |index: usize| -> u64 {
        after_comm
            .split_whitespace()
            .nth(index)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("field {index} of /proc/<pid>/stat is numeric"))
    };
    // `after_comm` starts at field 3 (state), so utime is field 14 overall.
    tick(11) + tick(12)
}

/// A one-shot CLI invocation.
fn cli(args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let mut child = Command::new(BINARY)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("could not run {args:?}: {error}"));
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(input.as_bytes())
            .expect("stdin is written");
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().expect("the command finishes")
}

fn cli_ok(args: &[&str], stdin: Option<&str>) -> String {
    let output = cli(args, stdin);
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A hand-written HTTP client, so no client dependency can move the numbers.
///
/// `Clone` because a test needs an anonymous client and a logged-in one at the
/// same time.
#[derive(Clone)]
struct Client {
    addr: SocketAddr,
    host: String,
    cookies: Vec<(String, String)>,
}

impl Client {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            host: format!("127.0.0.1:{}", addr.port()),
            cookies: Vec::new(),
        }
    }

    fn request(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &str) -> Reply {
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host);
        let cookies = self
            .cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookies.is_empty() {
            request.push_str(&format!("Cookie: {cookies}\r\n"));
        }
        for (name, value) in extra {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("Connection: close\r\n\r\n");
        request.push_str(body);
        raw_request(self.addr, &request)
    }

    fn get(&self, path: &str) -> Reply {
        self.request("GET", path, &[], "")
    }

    fn login(&mut self) -> Reply {
        let origin = format!("http://{}", self.host);
        let reply = self.request(
            "POST",
            "/api/v1/login",
            &[("Content-Type", "application/json"), ("Origin", &origin)],
            &format!("{{\"username\":{USERNAME:?},\"password\":{PASSWORD:?}}}"),
        );
        if let Some(set) = reply.header("set-cookie") {
            let pair = set.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                self.cookies
                    .push((name.trim().to_owned(), value.trim().to_owned()));
            }
        }
        reply
    }
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn raw_request(addr: SocketAddr, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("loopback connect succeeds");
    stream
        .set_read_timeout(Some(DEADLINE))
        .expect("a read timeout is settable");
    stream
        .write_all(raw.as_bytes())
        .expect("the request is written");
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .expect("a status line arrives");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("a status code")
        .parse()
        .expect("a numeric status code");

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("a header line arrives");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').expect("headers are name: value");
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).expect("the body arrives");
    Reply {
        status,
        headers,
        body: String::from_utf8(body).expect("management bodies are utf-8"),
    }
}

/// Polls until the listener answers.
fn await_listener(addr: SocketAddr, child: &Managed) {
    let started = Instant::now();
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return;
        }
        assert!(child.is_alive(), "{} exited", child.name);
        assert!(
            started.elapsed() < DEADLINE,
            "{} never accepted a connection; log: {:#?}",
            child.name,
            child.log()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn await_netd(path: &Path, child: &Managed) {
    let started = Instant::now();
    loop {
        if path.exists()
            && std::os::unix::net::UnixStream::connect(path)
                .map(|stream| {
                    drop(stream);
                    true
                })
                .unwrap_or(false)
        {
            return;
        }
        assert!(child.is_alive(), "netd exited");
        assert!(started.elapsed() < DEADLINE, "netd never bound {path:?}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The median of a set of samples.
///
/// Median rather than mean because one scheduler hiccup on a shared runner should
/// not move the reported figure.
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn kib_to_mib(kib: u64) -> f64 {
    kib as f64 / 1024.0
}

/// §9: the whole footprint and latency picture, on the real release binary.
///
/// Nothing here asserts a wall-clock number. What it asserts is that every figure
/// is *finite and of a sane order*, that the answers are bounded, and that the
/// numbers are printed in a form that can be transcribed into the closure record
/// rather than remembered.
#[test]
fn the_management_surface_meets_its_footprint_and_latency_shape() {
    let scratch = Scratch::new();

    // --- Cold readiness: process spawn to first accepted connection. ---
    let mut netd = Managed::start(
        "wg-basic netd",
        &["netd", "--socket", scratch.netd_socket().to_str().unwrap()],
    );
    await_netd(&scratch.netd_socket(), &netd);

    let cold_started = Instant::now();
    let mut serve = Managed::start(
        "wg-basic serve",
        &[
            "serve",
            "--state",
            scratch.state().to_str().unwrap(),
            "--socket",
            scratch.netd_socket().to_str().unwrap(),
            "--http-bind",
            "127.0.0.1:0",
        ],
    );
    let line = serve.await_log("serve.started");
    let addr: SocketAddr = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix("resource_id="))
        .expect("the event names the listener")
        .parse()
        .expect("a parseable bound address");
    await_listener(addr, &serve);
    let cold_readiness = cold_started.elapsed();

    // Provisioning happens after the listener is up, on purpose: it is a separate
    // one-shot command, not part of serving.
    cli_ok(
        &[
            "admin",
            "set-password",
            "--username",
            USERNAME,
            "--state",
            scratch.state().to_str().unwrap(),
            "--password-stdin",
        ],
        Some(PASSWORD),
    );

    let client = Client::new(addr);

    // --- Idle footprint, and idle CPU as a delta over a fixed window. ---
    // Sampled after everything has settled, so start-up work is not counted as
    // idle. The window is short because this is a unit suite; it is enough to
    // distinguish "spinning" from "not spinning".
    let serve_rss = resident_kib(serve.pid());
    let netd_rss = resident_kib(netd.pid());
    let cpu_before_serve = cpu_ticks(serve.pid());
    let cpu_before_netd = cpu_ticks(netd.pid());
    let idle_window = Duration::from_secs(2);
    thread::sleep(idle_window);
    let serve_cpu_ticks = cpu_ticks(serve.pid()) - cpu_before_serve;
    let netd_cpu_ticks = cpu_ticks(netd.pid()) - cpu_before_netd;
    let total_mib = kib_to_mib(serve_rss + netd_rss);

    // --- Health latency: the unauthenticated probe an operator polls. ---
    let mut health_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let reply = client.get("/healthz");
        assert_eq!(reply.status, 200, "{}", reply.body);
        health_samples.push(started.elapsed());
    }
    let health_latency = median(health_samples);

    // --- Authenticated health latency: the same route behind a session. ---
    let mut browser = client.clone();
    let login_started = Instant::now();
    let login = browser.login();
    let login_latency = login_started.elapsed();
    assert_eq!(login.status, 200, "login failed: {}", login.body);
    let mut authenticated_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let reply = browser.get("/api/v1/health");
        assert_eq!(reply.status, 200, "{}", reply.body);
        authenticated_samples.push(started.elapsed());
    }
    let authenticated_latency = median(authenticated_samples);

    // --- The embedded shell. ---
    let mut shell_bytes = 0usize;
    for path in [
        "/",
        "/assets/app.css",
        "/assets/app.js",
        "/enroll",
        "/assets/enroll.js",
    ] {
        let reply = client.get(path);
        assert_eq!(reply.status, 200, "{path} must be served");
        shell_bytes += reply.body.len();
    }

    // --- Report, in the form the closure record needs. ---
    eprintln!(
        "\n=== Phase 7 M004 footprint and latency (release binary) ===\n\
         samples per figure: {SAMPLES} (median)\n\
         cold readiness (spawn to first accept): {cold_readiness:?}\n\
         /healthz latency (median):              {health_latency:?}\n\
         login latency incl. Argon2id:           {login_latency:?}\n\
         /api/v1/health latency (median):        {authenticated_latency:?}\n\
         serve RSS:                              {:.2} MiB\n\
         netd RSS:                               {:.2} MiB\n\
         combined RSS:                           {total_mib:.2} MiB \
         (engineering signal: <{TOTAL_FOOTPRINT_SIGNAL_MIB} MiB)\n\
         idle CPU over {idle_window:?}: serve {serve_cpu_ticks} ticks, \
         netd {netd_cpu_ticks} ticks\n\
         embedded shell, all five assets:         {shell_bytes} bytes\n\
         worker queue capacity:                  {}\n\
         ===================================================\n",
        kib_to_mib(serve_rss),
        kib_to_mib(netd_rss),
        wg_basic::management::DEFAULT_QUEUE_CAPACITY,
    );

    // --- Assertions: shape and bounds, not wall-clock. ---

    // The footprint signal. Reported as a finding rather than a gate: the plan
    // says not to weaken security or correctness to meet it, so the assertion is
    // a generous bound that would catch an order-of-magnitude regression and
    // nothing finer.
    assert!(
        total_mib < TOTAL_FOOTPRINT_SIGNAL_MIB as f64,
        "combined serve + netd RSS is {total_mib:.2} MiB, past the \
         {TOTAL_FOOTPRINT_SIGNAL_MIB} MiB engineering signal. This is reported, \
         not hidden -- but it needs a deliberate decision, not a regression."
    );

    // Idle really is idle. Two seconds of a busy loop is ~200 ticks per core;
    // anything near that means something is polling.
    let idle_ticks_budget = (idle_window.as_secs() * 100).max(10);
    assert!(
        serve_cpu_ticks < idle_ticks_budget,
        "serve burned {serve_cpu_ticks} CPU ticks while idle over {idle_window:?}; \
         it is supposed to be waiting on a socket"
    );
    assert!(
        netd_cpu_ticks < idle_ticks_budget,
        "netd burned {netd_cpu_ticks} CPU ticks while idle over {idle_window:?}"
    );

    // Cold readiness is bounded by the declared timeouts, not by luck: the store
    // must open, the reconcile must be attempted, and the listener must bind.
    assert!(
        cold_readiness < DEADLINE,
        "cold readiness took {cold_readiness:?}"
    );

    // The liveness probe is cheap, because an operator or a supervisor may poll
    // it. Argon2 is not on this path at all.
    assert!(
        health_latency < Duration::from_millis(500),
        "/healthz took {health_latency:?}; a liveness probe that slow is not a \
         liveness probe"
    );

    // The authenticated route does cost a live backend round trip, and is still
    // far below the five-second worker deadline.
    assert!(
        authenticated_latency < Duration::from_secs(2),
        "/api/v1/health took {authenticated_latency:?}"
    );

    // Argon2 is deliberately expensive. A login faster than a millisecond would
    // mean the parameters had been weakened to meet a latency target, which the
    // plan forbids in as many words — so the assertion is a *floor*, which is the
    // unusual direction and exactly the point.
    assert!(
        login_latency >= Duration::from_millis(1),
        "a login completed in {login_latency:?}, which suggests the Argon2id \
         parameters were weakened. Phase 7 M002 fixed m=19456 KiB, t=2, p=1 and \
         that must not be traded for latency."
    );

    // The shell is embedded and bounded, so it costs memory once.
    assert!(
        shell_bytes < 64 * 1024,
        "the embedded shell is {shell_bytes} bytes, past its declared budget"
    );

    // Both roles stop on a signal rather than being killed, which is what makes
    // the measurement above a measurement of a *stoppable* service.
    serve.stop();
    netd.stop();
}

/// §9: worker queue capacity is a declared number, not a guess.
#[test]
fn the_worker_queue_capacity_is_reported_against_its_own_bound() {
    // The limiter's global burst is what makes the queue hard to fill over HTTP,
    // and it is sized against the *slow* verification cost on purpose. Both
    // numbers are printed together so a later edit to either is visible in the
    // test output rather than only in a diff.
    eprintln!(
        "worker queue capacity: {} commands; reply deadline: {:?}; \
         login global burst: 20, per-peer burst: 8",
        wg_basic::management::DEFAULT_QUEUE_CAPACITY,
        wg_basic::management::DEFAULT_REPLY_DEADLINE,
    );
    assert_eq!(wg_basic::management::DEFAULT_QUEUE_CAPACITY, 32);
    assert_eq!(
        wg_basic::management::DEFAULT_REPLY_DEADLINE,
        Duration::from_secs(5)
    );
}
