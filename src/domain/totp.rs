//! Time-based one-time password primitives for administrator second factor.
//!
//! Secrets live in [`TotpSecret`] wrappers that redact [`Debug`] and zeroize on
//! drop. Verification uses a ±1 step window around the current 30-second counter.

use std::fmt;
use totp_lite::{totp_custom, Sha1};
use zeroize::Zeroize;

/// Length of random material drawn for a new TOTP secret.
const SECRET_RANDOM_BYTES: usize = 20;

/// RFC 6238 time step, in seconds.
pub const TOTP_STEP_SECONDS: u64 = 30;

/// Authenticator code width.
pub const TOTP_DIGITS: u32 = 6;

/// How many steps before and after the current counter accept a code.
pub const TOTP_VERIFICATION_WINDOW: u64 = 1;

/// A stored or pending TOTP shared secret (Base32, no padding).
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(String);

impl TotpSecret {
    /// Draws a fresh secret from the OS CSPRNG.
    pub fn generate() -> Result<Self, crate::domain::AuthError> {
        let mut bytes = vec![0u8; SECRET_RANDOM_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| crate::domain::AuthError::RandomUnavailable)?;
        let encoded = base32_nopad_encode(&bytes);
        bytes.zeroize();
        Ok(Self(encoded))
    }

    /// Adopts a secret read from durable storage or a pending enroll row.
    pub fn parse(stored: impl Into<String>) -> Result<Self, crate::domain::AuthError> {
        let stored = stored.into();
        if stored.is_empty() || !stored.bytes().all(is_base32_char) {
            return Err(crate::domain::AuthError::CredentialsRejected);
        }
        Ok(Self(stored))
    }

    /// The Base32 secret for persistence or otpauth URIs.
    pub fn expose_for_storage(&self) -> &str {
        &self.0
    }

    /// Whether `code` is valid at `now_seconds` with the configured window.
    pub fn verify_code(&self, code: &str, now_seconds: i64) -> bool {
        let Ok(candidate) = normalize_totp_code(code) else {
            return false;
        };
        let Ok(secret_bytes) = base32_nopad_decode(self.0.as_bytes()) else {
            return false;
        };
        let base = now_seconds.max(0) as u64;
        for step_offset in 0..=(2 * TOTP_VERIFICATION_WINDOW) {
            let offset = step_offset as i64 - TOTP_VERIFICATION_WINDOW as i64;
            let time = ((base as i64) + offset * TOTP_STEP_SECONDS as i64).max(0) as u64;
            let expected = totp_custom::<Sha1>(TOTP_STEP_SECONDS, TOTP_DIGITS, &secret_bytes, time);
            if expected == candidate {
                return true;
            }
        }
        false
    }

    /// Builds an `otpauth://` URI for authenticator enrollment.
    pub fn otpauth_uri(&self, issuer: &str, account_name: &str) -> String {
        let label = format!(
            "{issuer}:{}",
            percent_encode_otpauth_component(account_name)
        );
        let issuer_param = percent_encode_otpauth_component(issuer);
        format!(
            "otpauth://totp/{label}?secret={}&issuer={issuer_param}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}",
            self.0
        )
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(REDACTED)")
    }
}

impl fmt::Display for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

impl Drop for TotpSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn normalize_totp_code(code: &str) -> Result<String, ()> {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    Ok(trimmed.to_owned())
}

fn base32_nopad_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::new();
    let mut buffer = 0u32;
    let mut bits_left = 0;
    for byte in input {
        buffer = (buffer << 8) | u32::from(*byte);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1f) as usize;
            output.push(ALPHABET[index] as char);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        output.push(ALPHABET[index] as char);
    }
    output
}

fn base32_nopad_decode(input: &[u8]) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits_left = 0;
    for byte in input {
        let upper = byte.to_ascii_uppercase();
        let Some(index) = ALPHABET.iter().position(|&c| c == upper) else {
            return Err(());
        };
        buffer = (buffer << 5) | u32::from(index as u8);
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            output.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }
    Ok(output)
}

fn is_base32_char(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'2'..=b'7')
}

fn percent_encode_otpauth_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_are_base32_and_redacted() {
        let secret = TotpSecret::generate().unwrap();
        assert!(secret.expose_for_storage().bytes().all(is_base32_char));
        assert!(!format!("{secret:?}").contains(secret.expose_for_storage()));
    }

    #[test]
    fn verification_accepts_the_current_code() {
        let secret = TotpSecret::generate().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let secret_bytes = base32_nopad_decode(secret.expose_for_storage().as_bytes()).unwrap();
        let code = totp_custom::<Sha1>(
            TOTP_STEP_SECONDS,
            TOTP_DIGITS,
            &secret_bytes,
            now.max(0) as u64,
        );
        assert!(secret.verify_code(&code, now));
        assert!(!secret.verify_code("000000", now));
    }
}
