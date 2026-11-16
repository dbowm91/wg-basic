#![cfg(unix)]
//! Auth expansion M004 qualification (allow-list, auto-register, password disable, Google OIDC).

#[path = "fixtures/fake_oidc_idp.rs"]
mod fake_oidc_idp;

use fake_oidc_idp::FakeOidcIdp;
use wg_basic::{
    domain::{email_allowed_by_domain_list, parse_allowed_domains},
    management::{
        resolve_login_principal, spawn, AuthIdpPolicyUpdate, BrandedProviderSettingsUpdate,
        CallbackClaims, IdpProviderKey, WorkerConfig,
    },
    state::StateStore,
};

const PASSWORD: &str = "an administrator password";

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wg-basic-oauth-m004-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    fn db(&self) -> std::path::PathBuf {
        self.0.join("state.db")
    }

    fn absent_socket(&self) -> std::path::PathBuf {
        self.0.join("no-such-netd.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn domain_allow_list_blocks_outside_domain() {
    let domains = parse_allowed_domains("corp.example");
    assert!(!email_allowed_by_domain_list(
        "user@other.example",
        &domains
    ));
    assert!(email_allowed_by_domain_list("user@corp.example", &domains));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_disable_requires_linked_principal() {
    let scratch = Scratch::new();
    let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).unwrap();
    let client = startup.client().clone();
    let status = client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .unwrap();
    let err = client
        .update_idp_policy(
            status.principal_id,
            AuthIdpPolicyUpdate {
                password_auth_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect_err("must refuse without idp link");
    assert!(matches!(err, wg_basic::management::WorkerError::Rejected));
}

#[test]
fn cli_set_password_re_enables_password_auth() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    store
        .update_auth_idp_policy(false, "", "", false, 1)
        .unwrap();
    drop(store);
    wg_basic::management::set_password_at(scratch.db(), "admin", PASSWORD).unwrap();
    let store = StateStore::open(scratch.db()).unwrap();
    let policy = store.auth_idp_policy().unwrap();
    assert!(policy.password_auth_enabled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn google_worker_login_starts_with_fake_issuer() {
    let scratch = Scratch::new();
    let idp = FakeOidcIdp::spawn();
    let startup = spawn(WorkerConfig::new(scratch.db(), scratch.absent_socket())).unwrap();
    let client = startup.client().clone();
    client
        .set_admin_password("admin".to_owned(), PASSWORD.to_owned())
        .await
        .unwrap();
    let canonical = "https://127.0.0.1:9443".to_owned();
    client
        .update_branded_settings(
            IdpProviderKey::Google,
            BrandedProviderSettingsUpdate {
                issuer: Some(idp.issuer().to_owned()),
                client_id: Some(idp.client_id().to_owned()),
                set_client_secret: Some(idp.client_secret().to_owned()),
                clear_client_secret: false,
                enabled: Some(true),
                ..Default::default()
            },
            canonical.clone(),
        )
        .await
        .unwrap();
    let start = client
        .idp_begin_login(IdpProviderKey::Google, canonical)
        .await
        .unwrap();
    assert!(start.authorize_url.contains("/authorize"));
}

#[test]
fn auto_register_on_creates_principal_with_matching_domain() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    store
        .update_auth_idp_policy(true, "corp.example", "", true, 1)
        .unwrap();
    let claims = CallbackClaims {
        issuer: "https://idp.test".to_owned(),
        subject: "subj-1".to_owned(),
        email: "newadmin@corp.example".to_owned(),
        principal_id: None,
        now: 2,
    };
    let id = resolve_login_principal(&store, &claims, IdpProviderKey::Oidc).unwrap();
    assert!(store
        .principal_id_by_idp_email("newadmin@corp.example")
        .unwrap()
        .is_some());
    assert_eq!(
        store
            .idp_link_by_subject("https://idp.test", "subj-1")
            .unwrap()
            .unwrap()
            .principal_id,
        id
    );
}

#[test]
fn auto_register_off_rejects_unknown_email() {
    let scratch = Scratch::new();
    let store = StateStore::initialize(scratch.db()).unwrap();
    store
        .update_auth_idp_policy(false, "", "", true, 1)
        .unwrap();
    let claims = CallbackClaims {
        issuer: "https://idp.test".to_owned(),
        subject: "subj-2".to_owned(),
        email: "nobody@corp.example".to_owned(),
        principal_id: None,
        now: 2,
    };
    assert!(resolve_login_principal(&store, &claims, IdpProviderKey::Oidc).is_err());
}
