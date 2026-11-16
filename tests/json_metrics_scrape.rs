#![cfg(unix)]
//! JSON metrics scrape surface (observability M002).

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
    http::{
        AuthenticatedApi, Bucket, LoginLimiter, OriginPolicy, JSON_METRICS_PATH,
        PROMETHEUS_METRICS_PATH,
    },
    management::{spawn, MetricsSettingsUpdate, WorkerClient, WorkerConfig},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const ADMIN_PASSWORD: &str = "an administrator password";
const METRICS_PASSWORD: &str = "a metrics bearer password for scrape";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-json-metrics-{}-{}",
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

fn body_bytes(mut response: eggserve_primitives::Response) -> Vec<u8> {
    response
        .take_body()
        .expect("body")
        .into_bytes()
        .expect("bytes")
}

fn body_text(response: eggserve_primitives::Response) -> String {
    String::from_utf8(body_bytes(response)).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_json_scrape_returns_400() {
    let scratch = Scratch::new();
    let api = api(&scratch).await;
    let response = api
        .json_metrics_scrape(&head_get(JSON_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(body_text(response), "metrics not enabled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prometheus_and_json_enable_flags_are_independent() {
    let scratch = Scratch::new();
    let client = worker_client(&scratch).await;

    client
        .update_metrics_settings(MetricsSettingsUpdate {
            prometheus_enabled: Some(true),
            json_metrics_enabled: Some(false),
            set_bearer_password: None,
            clear_bearer_password: false,
        })
        .await
        .expect("settings updated");

    let api = AuthenticatedApi::new(
        client.clone(),
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );

    let prom = api
        .prometheus_scrape(&head_get(PROMETHEUS_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(prom.status().as_u16(), 200);

    let json = api
        .json_metrics_scrape(&head_get(JSON_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(json.status().as_u16(), 400);

    client
        .update_metrics_settings(MetricsSettingsUpdate {
            prometheus_enabled: Some(false),
            json_metrics_enabled: Some(true),
            set_bearer_password: None,
            clear_bearer_password: false,
        })
        .await
        .expect("settings updated");

    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );

    let prom = api
        .prometheus_scrape(&head_get(PROMETHEUS_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(prom.status().as_u16(), 400);

    let json = api
        .json_metrics_scrape(&head_get(JSON_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(json.status().as_u16(), 200);
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes(json)).unwrap();
    assert!(payload.get("wireguard_configured_peers").is_some());
    assert!(payload.get("clients").is_some());
    assert!(payload.get("truncated").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_without_secret_admits_loopback_only() {
    let scratch = Scratch::new();
    let client = worker_client(&scratch).await;
    client
        .update_metrics_settings(MetricsSettingsUpdate {
            prometheus_enabled: None,
            json_metrics_enabled: Some(true),
            set_bearer_password: None,
            clear_bearer_password: false,
        })
        .await
        .expect("settings updated");
    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );
    let ok = api
        .json_metrics_scrape(&head_get(JSON_METRICS_PATH, &[]), loopback())
        .await;
    assert_eq!(ok.status().as_u16(), 200);

    let denied = api
        .json_metrics_scrape(&head_get(JSON_METRICS_PATH, &[]), remote_peer())
        .await;
    assert_eq!(denied.status().as_u16(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_with_bearer_secret_requires_valid_authorization() {
    let scratch = Scratch::new();
    let client = worker_client(&scratch).await;
    client
        .update_metrics_settings(MetricsSettingsUpdate {
            prometheus_enabled: None,
            json_metrics_enabled: Some(true),
            set_bearer_password: Some(METRICS_PASSWORD.to_owned()),
            clear_bearer_password: false,
        })
        .await
        .expect("settings updated");
    let api = AuthenticatedApi::new(
        client,
        Arc::new(OriginPolicy::loopback_only(loopback())),
        wide_limiter(),
    );

    let missing = api
        .json_metrics_scrape(&head_get(JSON_METRICS_PATH, &[]), remote_peer())
        .await;
    assert_eq!(missing.status().as_u16(), 401);

    let wrong = api
        .json_metrics_scrape(
            &head_get(
                JSON_METRICS_PATH,
                &[("authorization", "Bearer wrong-secret")],
            ),
            remote_peer(),
        )
        .await;
    assert_eq!(wrong.status().as_u16(), 401);

    let ok = api
        .json_metrics_scrape(
            &head_get(
                JSON_METRICS_PATH,
                &[("authorization", &format!("Bearer {METRICS_PASSWORD}"))],
            ),
            remote_peer(),
        )
        .await;
    assert_eq!(ok.status().as_u16(), 200);
    let payload: serde_json::Value = serde_json::from_slice(&body_bytes(ok)).unwrap();
    assert!(payload["clients"].is_array());
}
