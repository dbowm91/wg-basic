#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod aggregate;
pub mod domain;
pub mod error;
#[cfg(target_os = "linux")]
pub mod firewall;
#[cfg(target_os = "linux")]
pub mod protocol;
#[cfg(target_os = "linux")]
pub mod reconcile;
pub mod state;
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
