#![cfg(unix)]
//! Prometheus scrape surface (observability M001).

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use wg_basic::{
    http::{AuthenticatedApi, Bucket, LoginLimiter, OriginPolicy, PROMETHEUS_METRICS_PATH},
    management::{spawn, MetricsSettingsUpdate, WorkerClient, WorkerConfig},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const ADMIN_PASSWORD: &str = "an administrator password";
const METRICS_PASSWORD: &str = "a metrics bearer password for scrape";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-prom-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
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
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:8000".parse().unwrap()
}

fn remote_peer() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 12345))
}

fn wide_limiter() -> Arc<LoginLimiter> {
    Arc::new(LoginLimiter::new(
        Bucket::per_second(1000, 1000),
        Bucket::per_second(1000, 1000),
        64,
    ))
}

fn head_get(path: &str, extra: &[(&str, &str)]) -> eggserve_primitives::RequestHead {
    let mut headers = eggserve_primitives::HeaderBlock::new();
    headers.push_str("host", "127.0.0.1:8000").unwrap();
    for (name, value) in extra {
        headers.push_str(*name, *value).unwrap();
    }
    eggserve_primitives::RequestHead::new(
        eggserve_primitives::Method::new("GET").unwrap(),
        eggserve_primitives::RequestTarget::parse(path).unwrap(),
        eggserve_primitives::HttpVersion::Http11,
        headers,
    )
}

async fn worker_client(scratch: &Scratch) -> WorkerClient {
    let startup =
        spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).expect("worker starts");
    startup
        .client()
        .set_admin_password("admin".to_owned(), ADMIN_PASSWORD.to_owned())
        .await
        .expect("admin provisioned");
    startup.client().clone()
}

async fn api(scratch: &Scratch) -> AuthenticatedApi {
    let client = worker_client(scratch).await;
    AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    )
}

async fn enable_prometheus(client: &WorkerClient, bearer: Option<&str>) {
    client
        .update_metrics_settings(MetricsSettingsUpdate {
            prometheus_enabled: Some(true),
            json_metrics_enabled: None,
            set_bearer_password: bearer.map(str::to_owned),
            clear_bearer_password: false,
        })
        .await
        .expect("settings updated");
}

fn body_text(mut response: eggserve_primitives::Response) -> String {
    String::from_utf8(
        response
            .take_body()
            .expect("body")
            .into_bytes()
            .expect("bytes"),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_prometheus_scrape_returns_400() {
    let scratch = Scratch::new();
    let api = api(&scratch).await;
    let response = api
        .prometheus_scrape(&head_get(PROMETHEUS_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(body_text(response), "metrics not enabled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_without_secret_admits_loopback_only() {
    let scratch = Scratch::new();
    let client = worker_client(&scratch).await;
    enable_prometheus(&client, None).await;
    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );
    let ok = api
        .prometheus_scrape(&head_get(PROMETHEUS_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(ok.status().as_u16(), 200);
    let body = body_text(ok);
    assert!(body.contains("# HELP wireguard_configured_peers"));
    assert!(body.contains("# TYPE wireguard_enabled_peers gauge"));

    let denied = api
        .prometheus_scrape(&head_get(PROMETHEUS_METRICS_PATH, &[]), remote_peer())
        .await;
    assert_eq!(denied.status().as_u16(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_with_bearer_secret_requires_valid_authorization() {
    let scratch = Scratch::new();
    let client = worker_client(&scratch).await;
    enable_prometheus(&client, Some(METRICS_PASSWORD)).await;
    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );

    let missing = api
        .prometheus_scrape(&head_get(PROMETHEUS_METRICS_PATH, &[]), remote_peer())
        .await;
    assert_eq!(missing.status().as_u16(), 401);

    let wrong = api
        .prometheus_scrape(
            &head_get(
                PROMETHEUS_METRICS_PATH,
                &[("authorization", "Bearer wrong-secret")],
            ),
            remote_peer(),
        )
        .await;
    assert_eq!(wrong.status().as_u16(), 401);

    let ok = api
        .prometheus_scrape(
            &head_get(
                PROMETHEUS_METRICS_PATH,
                &[("authorization", &format!("Bearer {METRICS_PASSWORD}"))],
            ),
            remote_peer(),
        )
        .await;
    assert_eq!(ok.status().as_u16(), 200);
    assert!(!body_text(ok).contains("endpoint"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_saturated_scrape_budget_still_admits_login() {
    let scratch = Scratch::new();
    let client = worker_client(&scratch).await;
    enable_prometheus(&client, None).await;
    let scrape = Arc::new(LoginLimiter::new(
        Bucket::per_second(1, 1),
        Bucket::per_second(1, 1),
        4,
    ));
    let instant = std::time::Instant::now();
    assert!(scrape.check(loopback(), instant).is_allowed());
    assert!(!scrape.check(loopback(), instant).is_allowed());

    let api = AuthenticatedApi::with_scrape_limiter(
        client.clone(),
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
        wide_limiter(),
        Some(scrape),
    );
    assert!(
        !api.scrape_limiter()
            .check(loopback(), std::time::Instant::now())
            .is_allowed(),
        "scrape must be refused after the budget is spent"
    );

    let login_body = serde_json::json!({
        "username": "admin",
        "password": ADMIN_PASSWORD,
    });
    // login uses POST
    let mut headers = eggserve_primitives::HeaderBlock::new();
    headers.push_str("host", "127.0.0.1:8000").unwrap();
    headers
        .push_str("content-type", "application/json")
        .unwrap();
    headers.push_str("origin", "http://127.0.0.1:8000").unwrap();
    let login_head = eggserve_primitives::RequestHead::new(
        eggserve_primitives::Method::new("POST").unwrap(),
        eggserve_primitives::RequestTarget::parse("/api/v1/login").unwrap(),
        eggserve_primitives::HttpVersion::Http11,
        headers,
    );
    api.login(&login_head, login_body.to_string().as_bytes(), loopback())
        .await
        .expect("login still admits while scrape is saturated");
}
