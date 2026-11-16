#![cfg(unix)]
//! Generic OIDC qualification (operator-auth-expansion M003).

#[path = "fixtures/fake_oidc_idp.rs"]
mod fake_oidc_idp;

use eggserve_server::Server;
use fake_oidc_idp::FakeOidcIdp;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use wg_basic::{
    http::{
        headers, AuthenticatedApi, Bucket, LoginLimiter, ManagementHttpConfig, ManagementService,
        OriginPolicy, OIDC_CALLBACK_PATH, OIDC_COMPLETE_PATH, SESSION_COOKIE_NAME,
        SESSION_COOKIE_SECURE_NAME,
    },
    management::{spawn, OidcSettingsUpdate, WorkerClient, WorkerConfig},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);
const PASSWORD: &str = "an administrator password";

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    #[allow(dead_code)]
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-oidc-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.db")
    }

    fn absent_socket(&self) -> PathBuf {
        self.0.join("no-such-netd.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Harness {
    addr: SocketAddr,
    canonical: String,
    host: String,
    control: eggserve_server::ServerControl,
    completion: eggserve_server::ServerCompletion,
    client: WorkerClient,
    idp: FakeOidcIdp,
}

impl Harness {
    async fn start(scratch: &Scratch) -> Self {
        let idp = FakeOidcIdp::spawn();
        let startup =
            spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
        let client = startup.client().clone();
        client
            .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
            .await
            .expect("admin provisioned");
        drop(startup);

        let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let bind = format!("127.0.0.1:{port}");
        let canonical = format!("https://127.0.0.1:{port}");
        let policy = Arc::new(
            OriginPolicy::behind_https_proxy(bind.parse().unwrap(), &canonical)
                .expect("https loopback policy"),
        );
        let api = AuthenticatedApi::new(
            client.clone(),
            policy,
            Arc::new(LoginLimiter::new(
                Bucket::per_second(1000, 1000),
                Bucket::per_second(1000, 1000),
                64,
            )),
        );
        let config = ManagementHttpConfig::new(&bind)
            .expect("bind")
            .runtime_config()
            .expect("runtime");
        let server = Server::builder().runtime(config).build().expect("server");
        let handle = server
            .start_with_service(ManagementService::new(api))
            .await
            .expect("start");
        let addr = handle.local_addr();
        let host = format!("127.0.0.1:{}", addr.port());
        let (control, completion) = handle.into_parts();
        Self {
            addr,
            canonical,
            host,
            control,
            completion,
            client,
            idp,
        }
    }

    async fn enable_oidc(&self) {
        let patch = OidcSettingsUpdate {
            issuer: Some(self.idp.issuer().to_owned()),
            client_id: Some(self.idp.client_id().to_owned()),
            set_client_secret: Some(self.idp.client_secret().to_owned()),
            clear_client_secret: false,
            display_name: Some("Test OIDC".to_owned()),
            enabled: Some(true),
        };
        self.client
            .update_oidc_settings(patch, self.canonical.clone())
            .await
            .expect("oidc settings stored");
    }

    fn request(&self, raw: &str) -> Reply {
        request_on(self.addr, raw)
    }

    fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        let cookie = cookie
            .map(|value| format!("Cookie: {value}\r\n"))
            .unwrap_or_default();
        self.request(&format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{cookie}Connection: close\r\n\r\n",
            self.host
        ))
    }

    async fn stop(mut self) {
        self.control.shutdown();
        self.completion.wait().await.expect("clean stop");
    }
}

fn request_on(addr: SocketAddr, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    stream.write_all(raw.as_bytes()).expect("request write");
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .expect("status line arrives");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("header line");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').expect("header shape");
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 {
        reader.read_exact(&mut body).expect("response body length");
    }
    Reply {
        status,
        headers,
        body: String::from_utf8(body).unwrap_or_default(),
    }
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap_or_default().to_owned()
}

fn follow_idp_to_callback(idp_authorize_url: &str, product_callback: &str) -> String {
    let rest = idp_authorize_url
        .strip_prefix("http://127.0.0.1:")
        .expect("loopback idp");
    let (port, path_and_query) = rest.split_once('/').expect("authorize path");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = format!("/{path_and_query}");
    let reply = request_on(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    );
    let location = reply.header("location").expect("idp redirect");
    assert!(
        location.starts_with(product_callback),
        "callback must target product"
    );
    location.to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_worker_login_callback_succeeds_against_fake_idp() {
    let scratch = Scratch::new();
    let idp = FakeOidcIdp::spawn();
    let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).unwrap();
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .unwrap();
    let canonical = "https://127.0.0.1:9443".to_owned();
    let patch = OidcSettingsUpdate {
        issuer: Some(idp.issuer().to_owned()),
        client_id: Some(idp.client_id().to_owned()),
        set_client_secret: Some(idp.client_secret().to_owned()),
        clear_client_secret: false,
        display_name: None,
        enabled: Some(true),
    };
    client
        .update_oidc_settings(patch, canonical.clone())
        .await
        .unwrap();
    let start = client.oidc_begin_login(canonical.clone()).await.unwrap();
    let callback_url = follow_idp_to_callback(
        &start.authorize_url,
        &format!("{canonical}{OIDC_CALLBACK_PATH}"),
    );
    let query = callback_url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let (state, code) = wg_basic::http::api::parse_oidc_callback_query(Some(query)).unwrap();
    let outcome = client
        .oidc_login_callback(state, code, canonical)
        .await
        .expect("login callback succeeds");
    assert!(!outcome.completion_token.expose_once().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_login_happy_path_issues_a_strict_session_cookie() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    harness.enable_oidc().await;

    let login = harness.get("/api/v1/auth/oidc/login", None);
    assert_eq!(login.status, 302, "login starts with redirect");
    let authorize = login.header("location").expect("authorize url");

    let callback_url = follow_idp_to_callback(
        authorize,
        &format!("{}{}", harness.canonical, OIDC_CALLBACK_PATH),
    );
    let callback_path = callback_url
        .strip_prefix(&harness.canonical)
        .unwrap_or(&callback_url);
    let callback = harness.get(callback_path, None);
    assert_eq!(callback.status, 302, "callback status");
    assert!(
        callback
            .header("location")
            .is_some_and(|l| l.contains("complete")),
        "callback should continue handoff, got {:?}",
        callback.header("location")
    );
    let callback_cookies = callback.set_cookies();
    let completion_cookie = callback_cookies
        .iter()
        .find(|value| value.contains("wg_basic_oidc_complete"))
        .expect("completion cookie");
    assert!(
        completion_cookie
            .to_ascii_lowercase()
            .contains("samesite=lax"),
        "completion cookie must be Lax"
    );

    let complete = harness.get(
        OIDC_COMPLETE_PATH,
        Some(cookie_pair(completion_cookie).as_str()),
    );
    assert_eq!(complete.status, 302, "complete upgrades to session");
    let complete_cookies = complete.set_cookies();
    let session_cookie = complete_cookies
        .iter()
        .find(|value| {
            value.contains(SESSION_COOKIE_SECURE_NAME) || value.contains(SESSION_COOKIE_NAME)
        })
        .expect("session cookie");
    assert!(
        session_cookie
            .to_ascii_lowercase()
            .contains("samesite=strict"),
        "product session must stay Strict"
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_callback_rejects_a_bad_state() {
    let scratch = Scratch::new();
    let harness = Harness::start(&scratch).await;
    harness.enable_oidc().await;
    let path = format!("{OIDC_CALLBACK_PATH}?state=bogus&code=bogus");
    let reply = harness.get(&path, None);
    assert_eq!(reply.status, 302);
    assert!(
        !reply
            .set_cookies()
            .iter()
            .any(|value| value.contains("wg_basic_oidc_complete")),
        "a bad state must not mint completion"
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_enable_is_refused_without_https_canonical_origin() {
    let scratch = Scratch::new();
    let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).unwrap();
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .unwrap();
    let idp = FakeOidcIdp::spawn();
    let patch = OidcSettingsUpdate {
        issuer: Some(idp.issuer().to_owned()),
        client_id: Some(idp.client_id().to_owned()),
        set_client_secret: Some(idp.client_secret().to_owned()),
        clear_client_secret: false,
        display_name: None,
        enabled: Some(true),
    };
    let err = client
        .update_oidc_settings(patch, "http://127.0.0.1:8000".to_owned())
        .await
        .expect_err("http origin must refuse enable");
    assert!(matches!(err, wg_basic::management::WorkerError::Rejected));
}

#[test]
fn oidc_callback_query_parser_is_strict() {
    use wg_basic::http::api::parse_oidc_callback_query;
    assert_eq!(
        parse_oidc_callback_query(Some("state=abc&code=def")),
        Some(("abc".to_owned(), "def".to_owned()))
    );
    assert_eq!(parse_oidc_callback_query(Some("state=only")), None);
    assert_eq!(parse_oidc_callback_query(None), None);
}

#[test]
fn product_session_cookie_policy_stays_strict_while_completion_is_lax() {
    let session = include_str!("../src/http/session_cookie.rs");
    let completion = include_str!("../src/http/oidc_cookie.rs");
    assert!(session.contains("SameSite::Strict"));
    assert!(completion.contains("SameSite::Lax"));
    let _ = headers::CONTENT_SECURITY_POLICY;
}
