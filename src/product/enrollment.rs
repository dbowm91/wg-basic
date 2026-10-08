//! Short-lived, digest-only one-time enrollment capability values.

use super::model::EnrollmentCapabilityId;
use crate::domain::ClientId;
use std::fmt;
use zeroize::Zeroize;

pub const DEFAULT_ENROLLMENT_TTL_SECONDS: u64 = 10 * 60;
pub const MAX_ENROLLMENT_TTL_SECONDS: u64 = 24 * 60 * 60;

/// A raw capability token that is returned once and redacted from diagnostics.
pub struct EnrollmentToken(String);
impl EnrollmentToken {
    pub(crate) fn parse(mut value: String) -> Result<Self, EnrollmentTokenError> {
        if value.len() != 43
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            value.zeroize();
            return Err(EnrollmentTokenError::InvalidShape);
        }
        Ok(Self(value))
    }
    pub(crate) fn generate() -> Result<Self, EnrollmentTokenError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| EnrollmentTokenError::EntropyUnavailable)?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let token = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Ok(Self(token))
    }
    pub fn expose_once(mut self) -> String {
        std::mem::take(&mut self.0)
    }
    pub(crate) fn digest(&self) -> String {
        digest_token(&self.0)
    }
}
impl Drop for EnrollmentToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentToken([REDACTED])")
    }
}

fn digest_token(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnrollmentTokenError {
    #[error("operating system entropy is unavailable")]
    EntropyUnavailable,
    #[error("enrollment capability token has invalid shape")]
    InvalidShape,
}

/// The one-time response from capability creation.
pub struct CreatedEnrollmentLink {
    pub capability_id: EnrollmentCapabilityId,
    pub client_id: ClientId,
    pub token: EnrollmentToken,
    pub expires_at: i64,
}
impl fmt::Debug for CreatedEnrollmentLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedEnrollmentLink")
            .field("capability_id", &self.capability_id)
            .field("client_id", &self.client_id)
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
