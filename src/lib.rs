#![forbid(unsafe_code)]

pub mod domain;
pub mod error;

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
