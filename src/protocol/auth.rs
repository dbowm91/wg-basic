//! Peer-credential authorization policy.
//!
//! The peer UID comes from `SO_PEERCRED`, never from the request payload. By
//! default netd authorizes its own effective UID and root; `--allow-uid` adds
//! explicit management-service UIDs.

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

    pub fn current_user_and_root() -> Self {
        Self::new([nix::unistd::geteuid().as_raw(), 0])
    }

    pub fn extend(&mut self, allowed_uids: impl IntoIterator<Item = u32>) {
        self.allowed_uids.extend(allowed_uids);
    }

    pub(crate) fn permits(&self, uid: u32) -> bool {
        self.allowed_uids.contains(&uid)
    }
}
