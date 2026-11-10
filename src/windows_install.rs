//! Service Control Manager installation for Windows Server 2025 x64.
//!
//! The SKU check runs before any account, file, or service is created. A
//! failed attempt removes only the objects that attempt created. Uninstall
//! does not delete a foreign NetNAT or a path outside the installation root.

use crate::platform::windows::{self, BIN_DIR, RUNTIME_DIR, STATE_DIR};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct InstallStatus {
    pub sku_ok: bool,
    pub serve_registered: bool,
    pub netd_registered: bool,
    pub serve_is_administrator: bool,
}

pub fn install(candidate: &Path, dll: &Path) -> Result<InstallStatus, String> {
    refuse_wrong_sku()?;
    if !windows::dll_matches_pin(dll) {
        return Err("wireguard.dll does not match the pinned digest".into());
    }
    let mut created_user = false;
    let mut created_serve = false;
    let mut created_netd = false;
    let password = random_password();
    let result: Result<(), String> = (|| {
        if !wg_basic_win32_sys::service_exists(windows::SERVE_SERVICE).unwrap_or(false) {
            wg_basic_win32_sys::create_local_user(windows::SERVE_ACCOUNT, &password)
                .map_err(|error| error.to_string())?;
            created_user = true;
            if wg_basic_win32_sys::account_in_administrators(windows::SERVE_ACCOUNT).unwrap_or(true)
            {
                return Err("the serve account is in Administrators".into());
            }
        }
        copy_layout(candidate, dll)?;
        let exe = Path::new(BIN_DIR).join("wg-basic.exe");
        let serve_sid = wg_basic_win32_sys::lookup_account_sid(windows::SERVE_ACCOUNT)
            .map_err(|error| error.to_string())?;
        wg_basic_win32_sys::restrict_to_sid(Path::new(STATE_DIR), &serve_sid)
            .map_err(|error| error.to_string())?;
        if !wg_basic_win32_sys::service_exists(windows::NETD_SERVICE).unwrap_or(false) {
            wg_basic_win32_sys::install_service(&wg_basic_win32_sys::ServiceSpec {
                name: windows::NETD_SERVICE,
                display: "wg-basic netd",
                command: format!(
                    "\"{}\" netd --socket {} --allow-user {}",
                    exe.display(),
                    windows::DEFAULT_PIPE,
                    windows::SERVE_ACCOUNT
                ),
                account: None,
            })
            .map_err(|error| error.to_string())?;
            created_netd = true;
        }
        if !wg_basic_win32_sys::service_exists(windows::SERVE_SERVICE).unwrap_or(false) {
            wg_basic_win32_sys::install_service(&wg_basic_win32_sys::ServiceSpec {
                name: windows::SERVE_SERVICE,
                display: "wg-basic",
                command: format!(
                    "\"{}\" serve --state {} --socket {}",
                    exe.display(),
                    windows::DEFAULT_STATE_PATH,
                    windows::DEFAULT_PIPE
                ),
                account: Some((windows::SERVE_ACCOUNT.to_owned(), password.clone())),
            })
            .map_err(|error| error.to_string())?;
            created_serve = true;
        }
        Ok(())
    })();
    if result.is_err() {
        if created_serve {
            let _ = wg_basic_win32_sys::delete_service(windows::SERVE_SERVICE);
        }
        if created_netd {
            let _ = wg_basic_win32_sys::delete_service(windows::NETD_SERVICE);
        }
        if created_user {
            let _ = wg_basic_win32_sys::delete_local_user(windows::SERVE_ACCOUNT);
        }
    }
    result?;
    status()
}

pub fn status() -> Result<InstallStatus, String> {
    let sku_ok = refuse_wrong_sku().is_ok();
    Ok(InstallStatus {
        sku_ok,
        serve_registered: wg_basic_win32_sys::service_exists(windows::SERVE_SERVICE)
            .unwrap_or(false),
        netd_registered: wg_basic_win32_sys::service_exists(windows::NETD_SERVICE).unwrap_or(false),
        serve_is_administrator: wg_basic_win32_sys::account_in_administrators(
            windows::SERVE_ACCOUNT,
        )
        .unwrap_or(false),
    })
}

pub fn uninstall() -> Result<(), String> {
    let _ = wg_basic_win32_sys::stop_service(windows::SERVE_SERVICE);
    let _ = wg_basic_win32_sys::stop_service(windows::NETD_SERVICE);
    let _ = wg_basic_win32_sys::delete_service(windows::SERVE_SERVICE);
    let _ = wg_basic_win32_sys::delete_service(windows::NETD_SERVICE);
    let _ = wg_basic_win32_sys::delete_local_user(windows::SERVE_ACCOUNT);
    let _ = std::fs::remove_dir_all(BIN_DIR);
    let _ = std::fs::remove_dir_all(RUNTIME_DIR);
    Ok(())
}

fn refuse_wrong_sku() -> Result<(), String> {
    let facts = wg_basic_win32_sys::os_facts().map_err(|error| error.to_string())?;
    windows::sku_allowed(&facts.installation_type, &facts.architecture, facts.build)
        .map_err(|reason| reason.as_str().to_owned())
}

fn copy_layout(candidate: &Path, dll: &Path) -> Result<(), String> {
    std::fs::create_dir_all(BIN_DIR).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(STATE_DIR).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(RUNTIME_DIR).map_err(|error| error.to_string())?;
    let exe = PathBuf::from(BIN_DIR).join("wg-basic.exe");
    std::fs::copy(candidate, &exe).map_err(|error| error.to_string())?;
    std::fs::copy(dll, PathBuf::from(BIN_DIR).join("wireguard.dll"))
        .map_err(|error| error.to_string())?;
    let license = dll.with_file_name("LICENSE.txt");
    if license.is_file() {
        std::fs::copy(&license, PathBuf::from(BIN_DIR).join("LICENSE.txt"))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn random_password() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("password entropy");
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    bytes
        .iter()
        .map(|byte| ALPHABET[(*byte as usize) % ALPHABET.len()] as char)
        .collect()
}
