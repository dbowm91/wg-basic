//! Peer-credential authorization policy.
//!
//! The peer UID comes from the kernel, never from the request payload:
//! `SO_PEERCRED` on Linux, the Apple-documented `getpeereid(3)` on Darwin
//! (via the audited `nix::unistd::getpeereid` wrapper — no new unsafe in this
//! crate). By default Linux netd authorizes its own effective UID and root;
//! Darwin netd authorizes only its own effective UID with no root bypass.
//! `--allow-uid` adds explicit management-service UIDs on both OSes. Root on
//! Darwin is rejected unless explicitly allowlisted.

use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct AuthorizationPolicy {
    allowed_uids: HashSet<u32>,
}

impl AuthorizationPolicy {
    pub fn new(allowed_uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed_uids: allowed_uids.into_iter().collect(),
        }
    }

    /// Linux default: this user plus root.
    pub fn current_user_and_root() -> Self {
        Self::new([nix::unistd::geteuid().as_raw(), 0])
    }

    /// Darwin default (M002): this user only — root is not a universal
    /// bypass. An operator that runs netd as root and serve as another user
    /// passes `--allow-uid <serve-uid>` explicitly.
    pub fn current_user() -> Self {
        Self::new([nix::unistd::geteuid().as_raw()])
    }

    pub fn extend(&mut self, allowed_uids: impl IntoIterator<Item = u32>) {
        self.allowed_uids.extend(allowed_uids);
    }

    pub(crate) fn permits(&self, uid: u32) -> bool {
        self.allowed_uids.contains(&uid)
    }
}

/// Kernel-derived peer (uid, gid) for one accepted stream.
///
/// Linux: `SO_PEERCRED`. Darwin: `getpeereid(3)`. Never reads the request
/// payload, pid files, or socket path labels.
pub(crate) fn peer_identity(
    stream: &std::os::unix::net::UnixStream,
) -> std::io::Result<(u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let credentials = getsockopt(stream, PeerCredentials).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "could not verify local peer credentials",
            )
        })?;
        Ok((credentials.uid(), credentials.gid()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (uid, gid) = nix::unistd::getpeereid(stream).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "could not verify local peer credentials",
            )
        })?;
        Ok((uid.as_raw(), gid.as_raw()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_default_policy_has_no_root_bypass() {
        // M002: Darwin netd authorizes only its effective UID by default.
        // Root is rejected unless explicitly allowlisted via `--allow-uid 0`.
        let policy = AuthorizationPolicy::current_user();
        assert!(policy.permits(nix::unistd::geteuid().as_raw()));
        if nix::unistd::geteuid().as_raw() != 0 {
            assert!(
                !policy.permits(0),
                "root must not be authorized by default on Darwin"
            );
        }
        let mut explicit = AuthorizationPolicy::current_user();
        explicit.extend([0]);
        assert!(explicit.permits(0));
    }

    #[test]
    fn peer_identity_matches_kernel_credentials() {
        // Loopback UnixStream pair: getpeereid/SO_PEERCRED must report our own UID.
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (uid, _gid) = peer_identity(&a).unwrap();
        assert_eq!(uid, nix::unistd::geteuid().as_raw());
    }
}
