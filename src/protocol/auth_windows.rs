//! Windows peer authorization. The peer SID comes from the kernel at accept
//! time. Membership in Administrators is not an allow.

use std::io;

#[derive(Clone, Debug)]
pub struct AuthorizationPolicy {
    serve_sid: String,
}

impl AuthorizationPolicy {
    /// Resolves `account` on this host. An empty name authorizes nobody.
    pub fn for_account(account: &str) -> io::Result<Self> {
        if account.is_empty() {
            return Ok(Self {
                serve_sid: String::new(),
            });
        }
        let sid = wg_basic_win32_sys::lookup_account_sid(account)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(Self {
            serve_sid: sid.to_string(),
        })
    }

    pub(crate) fn serve_sid(&self) -> Option<&str> {
        if self.serve_sid.is_empty() {
            None
        } else {
            Some(self.serve_sid.as_str())
        }
    }

    pub(crate) fn permits(&self, peer_sid: &str) -> bool {
        crate::platform::windows::peer_is_serve(&self.serve_sid, peer_sid)
    }
}
