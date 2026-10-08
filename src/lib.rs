#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod aggregate;
#[cfg(target_os = "linux")]
pub mod distribution;
pub mod doctor;
pub mod domain;
pub mod error;
#[cfg(target_os = "linux")]
pub mod firewall;
#[cfg(target_os = "linux")]
pub mod http;
pub mod management;
pub mod operational;
pub mod product;
#[cfg(target_os = "linux")]
pub mod protocol;
#[cfg(target_os = "linux")]
pub mod reconcile;
pub mod release;
pub mod state;
pub mod update;
#[cfg(target_os = "linux")]
pub mod wireguard;

#[cfg(target_os = "linux")]
pub mod platform {
    pub mod linux {}
}

#[cfg(not(target_os = "linux"))]
pub mod platform {
    use crate::error::AppError;

    pub fn require_linux_network_role() -> Result<(), AppError> {
        Err(AppError::UnsupportedPlatform("network roles require Linux"))
    }
}
