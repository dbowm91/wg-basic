//! OIDC client-secret wrapping. Raw secrets never reach logs or ordinary reads.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A generic OIDC client secret stored alongside provider settings.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
pub struct OidcClientSecret(String);

impl OidcClientSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for OidcClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcClientSecret(REDACTED)")
    }
}

impl fmt::Display for OidcClientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}
