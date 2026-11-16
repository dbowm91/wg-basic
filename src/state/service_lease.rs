//! Cross-process advisory ownership of one state path.

#[cfg(unix)]
#[path = "service_lease_unix.rs"]
mod imp;
#[cfg(windows)]
#[path = "service_lease_windows.rs"]
mod imp;

pub use imp::*;
