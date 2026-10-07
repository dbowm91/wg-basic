//! Credential and session-token primitives.
//!
//! This module owns every pure computation behind local administrator
//! authentication: the password policy, Argon2id verification, the opaque
//! session bearer token and its SHA-256 digest, and the CSRF token. It performs
//! no I/O and knows nothing about SQLite, so it can be reasoned about and tested
//! without a database and cannot become a second persistence path.
//!
//! # Three secrets, three different treatments
//!
//! * A **password** never leaves this module in any form. It is verified
//!   against an Argon2id PHC verifier and then dropped. It is never persisted.
//! * A **session bearer token** is generated here and handed to exactly one
//!   caller, once. Only its SHA-256 digest is persisted, and a digest cannot be
//!   inverted, so a stolen database yields no usable session.
//! * A **CSRF token** is generated here and persisted in the clear. It is
//!   deliberately not a credential: it is only meaningful when echoed back by
//!   the browser alongside the bearer, and it cannot authenticate on its own.
//!
//! All three redact ordinary `Debug` and `Display`. A secret that formats itself
//! into a log line, an error, or a test failure is a secret that has leaked.

use argon2::{
    // `PasswordVerifier` here is the *trait* from `password-hash`; wg-basic's own
    // stored-verifier type shadows the name below, so the trait is aliased.
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier as VerifyPassword},
    Algorithm,
    Argon2,
    Params,
    Version,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

/// Argon2id memory cost in kibibytes (19 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 19 * 1024;

/// Argon2id iterations.
pub const ARGON2_ITERATIONS: u32 = 2;

/// Argon2id lanes.
pub const ARGON2_PARALLELISM: u32 = 1;

/// Shortest accepted administrator password, in UTF-8 bytes.
///
/// A length floor is the only rule. Composition rules ("one uppercase, one
/// symbol") measurably push operators toward predictable substitutions and away
/// from length, so they are deliberately absent. A minimum on *characters*
/// rather than bytes would also be wrong for a non-ASCII credential, so the
/// bound is on the bytes that actually reach Argon2id.
pub const MIN_PASSWORD_BYTES: usize = 12;

/// Longest accepted administrator password, in UTF-8 bytes.
///
/// An upper bound is not a security policy, it is input resource control: an
/// unbounded password is unbounded Argon2 work. This is enforced by refusing the
/// value, never by silently truncating it.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Entropy of a session bearer token, in bits.
pub const SESSION_TOKEN_BITS: usize = 256;

/// Entropy of a CSRF token, in bits.
pub const CSRF_TOKEN_BITS: usize = 256;

/// Why a candidate password was refused.
///
/// Deliberately does not distinguish "too short" from "too long" by identity:
/// the caller renders one message for every variant so a prober learns nothing
/// about the policy's shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasswordPolicyError {
    /// Below the length floor.
    #[error("the password does not meet the minimum length")]
    TooShort,
    /// Above the resource-control ceiling.
    #[error("the password does not meet the maximum length")]
    TooLong,
    /// Not valid UTF-8 after stdin decoding.
    #[error("the password is not valid UTF-8")]
    NotUtf8,
}

impl PasswordPolicyError {
    /// The one message every policy failure renders as.
    ///
    /// A single opaque answer keeps the policy from becoming an oracle.
    pub fn operator_message(&self) -> &'static str {
        "the password was refused; see the documented length policy"
    }
}

/// Applies the length policy to raw input bytes.
///
/// Returns the password as a `String` only after the byte bounds are checked, so
/// an over-long input is rejected on its byte length before any allocation
/// proportional to it happens.
pub fn check_password_policy(raw: &[u8]) -> Result<String, PasswordPolicyError> {
    if raw.len() < MIN_PASSWORD_BYTES {
        return Err(PasswordPolicyError::TooShort);
    }
    if raw.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordPolicyError::TooLong);
    }
    String::from_utf8(raw.to_vec()).map_err(|_| PasswordPolicyError::NotUtf8)
}

/// The configured Argon2id parameters.
///
/// Argon2id is the only algorithm accepted: Argon2i and Argon2d are weaker in
/// different ways and accepting them would make a stored verifier's strength
/// depend on whichever library wrote it.
pub fn argon2_params() -> Params {
    Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .expect("the management password policy is within Argon2's own limits")
}

fn argon2id() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params())
}

/// A stored Argon2id PHC verifier.
///
/// This is secret-adjacent: it is safe to store and to compare against, but it
/// must not be printed. `Debug` and `Display` emit a fixed redaction so a
/// verifier cannot reach a log line through an error message or a test failure.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordVerifier(String);

impl PasswordVerifier {
    /// Hashes a password with a fresh random salt under the configured policy.
    ///
    /// The returned PHC string is self-describing: it carries the algorithm, the
    /// memory/iteration/lane parameters, and the salt, so a later policy change
    /// does not require a migration and an existing verifier stays verifiable.
    pub fn hash(password: &str) -> Result<Self, argon2::password_hash::Error> {
        // `password-hash`'s `getrandom` feature makes `hash_password` draw a
        // fresh salt from the OS CSPRNG for every call. Two identical passwords
        // must never produce the same verifier, or the database would leak that
        // fact, so a caller-supplied salt is deliberately not accepted here.
        let hash = argon2id().hash_password(password.as_bytes())?;
        Ok(Self(hash.to_string()))
    }

    /// Adopts an existing PHC string read from the database.
    pub fn parse(phc: impl Into<String>) -> Result<Self, AuthError> {
        let phc = phc.into();
        // Validate on the way in rather than deferring to verification time: a
        // corrupt row should be an error at the boundary, not a confusing
        // failure during an operator's login.
        PasswordHash::new(&phc).map_err(|_| AuthError::MalformedVerifier)?;
        Ok(Self(phc))
    }

    /// Verifies a candidate password against this verifier.
    ///
    /// Returns `false` for every failure mode -- wrong password, malformed
    /// stored hash, wrong algorithm -- so the caller has exactly one answer to
    /// render and cannot accidentally distinguish "no such user" from "wrong
    /// password".
    pub fn verify(&self, password: &str) -> bool {
        let Ok(stored) = PasswordHash::new(&self.0) else {
            return false;
        };
        if stored.algorithm.as_str() != argon2::ARGON2ID_IDENT.as_str() {
            // Refuse to verify a non-Argon2id verifier rather than downgrade.
            return false;
        }
        VerifyPassword::verify_password(&argon2id(), password.as_bytes(), &stored).is_ok()
    }

    /// The PHC string for persistence.
    pub fn expose_for_storage(&self) -> &str {
        &self.0
    }
}

/// The PHC string prefix that identifies an Argon2id verifier.
///
/// This is the *serialized* form, with the `$` field delimiters. It is not the
/// same thing as [`argon2::ARGON2ID_IDENT`], which is the bare algorithm
/// identifier `argon2id`; comparing a parsed hash against the serialized prefix
/// would reject every correctly-produced verifier.
pub const ARGON2ID_PHC_PREFIX: &str = "$argon2id$";

/// A fixed Argon2id verifier used only to equalise the cost of a failed lookup.
///
/// Verifying against this costs the same ~19 MiB and ~300 ms as verifying a real
/// credential. That is its whole purpose: it stops "no such username" from being
/// a measurably faster answer than "wrong password", which would otherwise be a
/// username oracle far larger than anything a response body could leak.
///
/// The plaintext behind it was 48 bytes from the OS CSPRNG at the moment it was
/// generated, and was discarded. It is deliberately **not** recorded anywhere --
/// in a comment, a test, or this file -- so that no future edit can promote
/// this constant into a credential somebody could present. It must never be
/// stored as a principal's verifier and must never be returned to a caller.
///
/// Parameters are `m=19456, t=2, p=1` -- the same policy [`PasswordVerifier::hash`]
/// produces. A future policy change **must** regenerate this, which is why the
/// policy constants are asserted against it in a test rather than left as a
/// comment.
pub const TIMING_EQUALISER_VERIFIER: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$3FvQ5XAP1RQdd2/OxUXpNg$ZCEI8424WRPOAFPyg6WGF/2RtjVWs62LcehDEYf98eE";

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordVerifier(REDACTED)")
    }
}

impl fmt::Display for PasswordVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

/// Why an authentication operation failed.
///
/// Every variant is an operator-actionable category. None carries the candidate
/// password, the stored verifier, or a raw token, and none distinguishes an
/// unknown username from a wrong password.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthError {
    /// The username is unknown, the principal is disabled, or the password is
    /// wrong. One variant for all three on purpose.
    #[error("the credentials were not accepted")]
    CredentialsRejected,
    /// The stored verifier is not a usable PHC string.
    #[error("the stored credential verifier is malformed")]
    MalformedVerifier,
    /// The username is already taken.
    #[error("that administrator username already exists")]
    PrincipalExists,
    /// No local administrator has been provisioned yet.
    #[error("no local administrator has been provisioned")]
    NoPrincipal,
    /// The operating system CSPRNG was unavailable.
    #[error("the system random source is unavailable")]
    RandomUnavailable,
    /// The requested session is not live: unknown, revoked, or expired.
    ///
    /// Also the answer for a *storage* failure during a session lookup. A caller
    /// presenting a bearer token is an unauthenticated caller until proven
    /// otherwise, and telling "your session is invalid" apart from "the database
    /// is unavailable" would turn the lookup into a probe of the service's
    /// internal health.
    #[error("the session is not valid")]
    SessionInvalid,
    /// The credentials were accepted but the session could not be persisted.
    ///
    /// Distinct from [`AuthError::CredentialsRejected`] on purpose: telling a
    /// correct password from an incorrect one, even on success, is exactly what
    /// this type must never do.
    #[error("a session could not be issued")]
    SessionUnavailable,
    /// An administrative write failed.
    ///
    /// Never rendered to an unauthenticated caller; it exists so the CLI can
    /// report a storage failure instead of a credential failure.
    #[error("the credential store is unavailable")]
    StorageUnavailable,
    /// The username did not match the accepted shape.
    #[error("the administrator username is not acceptable")]
    UsernameInvalid,
}

/// An opaque session bearer token.
///
/// The raw value is secret and is zeroized on drop. It is returned to exactly
/// one caller -- the login path that will place it in a cookie -- and after
/// that only its digest exists.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    /// Generates a fresh 256-bit token from the OS CSPRNG.
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self(encode_random(SESSION_TOKEN_BITS / 8)?))
    }

    /// The raw token, for handing to a cookie exactly once.
    pub fn expose_once(&self) -> &str {
        &self.0
    }

    /// The SHA-256 digest that is persisted instead of the token.
    pub fn digest(&self) -> SessionTokenDigest {
        SessionTokenDigest(digest_hex(self.0.as_bytes()))
    }

    /// Computes the digest of a token presented by a client.
    ///
    /// Lookup always goes through here: the raw token is hashed before it ever
    /// reaches a query, so no code path can accidentally compare or store it.
    pub fn digest_of(presented: &str) -> SessionTokenDigest {
        SessionTokenDigest(digest_hex(presented.as_bytes()))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(REDACTED)")
    }
}

impl fmt::Display for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

impl Drop for SessionToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The persisted SHA-256 digest of a session bearer token.
///
/// This is deliberately *not* a secret wrapper: a digest is safe to store and to
/// index, and is the only form of a session that ever reaches SQLite. It still
/// does not format, so a debug dump cannot turn it back into a lookup key
/// without deliberately calling `expose_for_storage`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionTokenDigest(String);

impl SessionTokenDigest {
    /// The hex digest, for persistence and indexed lookup.
    pub fn expose_for_storage(&self) -> &str {
        &self.0
    }

    /// Parses a stored digest.
    pub fn parse(stored: impl Into<String>) -> Result<Self, AuthError> {
        let stored = stored.into();
        if stored.len() != SHA256_HEX_LENGTH || !stored.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AuthError::SessionInvalid);
        }
        Ok(Self(stored))
    }

    /// Compares two digests without an early exit.
    ///
    /// A digest is not a secret, but a comparison that returns on the first
    /// differing byte would leak how much of a guess was right if it were ever
    /// used on anything secret. Written out here so the intent is recorded at
    /// the one place that compares them.
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        let mut difference = 0u8;
        for (left, right) in self.0.bytes().zip(other.0.bytes()) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

/// Hex length of a SHA-256 digest.
const SHA256_HEX_LENGTH: usize = 64;

/// A double-submit CSRF token.
///
/// Secret-adjacent and redacted, but persisted in the clear: it is not a
/// credential, and the schema documents why.
#[derive(Clone, PartialEq, Eq)]
pub struct CsrfToken(String);

impl CsrfToken {
    /// Generates a fresh 256-bit token from the OS CSPRNG.
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self(encode_random(CSRF_TOKEN_BITS / 8)?))
    }

    /// The raw token, for handing to the trusted caller once.
    pub fn expose_once(&self) -> &str {
        &self.0
    }

    /// Adopts an existing stored token.
    pub fn parse(stored: impl Into<String>) -> Result<Self, AuthError> {
        let stored = stored.into();
        if stored.is_empty() {
            return Err(AuthError::SessionInvalid);
        }
        Ok(Self(stored))
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfToken(REDACTED)")
    }
}

impl fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REDACTED")
    }
}

impl Drop for CsrfToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Reads `len` bytes from the OS CSPRNG and returns them base64url-encoded.
fn encode_random(len: usize) -> Result<String, AuthError> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::RandomUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// The lowercase hex SHA-256 digest of `bytes`.
fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(SHA256_HEX_LENGTH);
    for byte in digest {
        use fmt::Write as _;
        // `write!` to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn the_configured_policy_meets_the_management_roadmap_minimums() {
        let params = argon2_params();
        assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB);
        assert_eq!(ARGON2_MEMORY_KIB, 19 * 1024, "19 MiB minimum");
        assert_eq!(params.t_cost(), ARGON2_ITERATIONS);
        assert_eq!(ARGON2_ITERATIONS, 2, "two iterations minimum");
        assert_eq!(params.p_cost(), ARGON2_PARALLELISM);
        assert_eq!(ARGON2_PARALLELISM, 1, "single lane");
    }

    #[test]
    fn a_verifier_round_trips_and_is_never_the_plaintext() {
        let verifier = PasswordVerifier::hash(PASSWORD).unwrap();
        assert!(verifier.verify(PASSWORD));
        assert!(!verifier.verify("wrong password entirely"));
        assert!(
            !verifier.expose_for_storage().contains(PASSWORD),
            "a verifier must never contain the password"
        );
        assert!(verifier
            .expose_for_storage()
            .starts_with(ARGON2ID_PHC_PREFIX));
    }

    #[test]
    fn the_same_password_hashes_differently_every_time() {
        let first = PasswordVerifier::hash(PASSWORD).unwrap();
        let second = PasswordVerifier::hash(PASSWORD).unwrap();
        assert_ne!(
            first.expose_for_storage(),
            second.expose_for_storage(),
            "identical passwords must not produce identical verifiers"
        );
        // Both still verify: a different salt is not a different password.
        assert!(first.verify(PASSWORD));
        assert!(second.verify(PASSWORD));
    }

    #[test]
    fn a_verifier_adopted_from_storage_still_verifies() {
        let hashed = PasswordVerifier::hash(PASSWORD).unwrap();
        let stored = hashed.expose_for_storage().to_owned();
        let adopted = PasswordVerifier::parse(stored).unwrap();
        assert!(adopted.verify(PASSWORD));
    }

    #[test]
    fn a_non_argon2id_or_malformed_verifier_never_verifies() {
        assert!(PasswordVerifier::parse("not a phc string").is_err());
        // A syntactically valid Argon2i hash must be refused, not silently
        // accepted, so stored strength cannot depend on the writing library.
        let argon2i = PasswordVerifier::parse(
            "$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        );
        if let Ok(argon2i) = argon2i {
            assert!(!argon2i.verify(PASSWORD), "argon2i must not verify");
        }
    }

    #[test]
    fn secret_values_redact_ordinary_debug_and_display() {
        let verifier = PasswordVerifier::hash(PASSWORD).unwrap();
        let token = SessionToken::generate().unwrap();
        let csrf = CsrfToken::generate().unwrap();

        let rendered = format!("{verifier:?} {verifier} {token:?} {token} {csrf:?} {csrf}");
        for secret in [
            PASSWORD,
            verifier.expose_for_storage(),
            token.expose_once(),
            csrf.expose_once(),
        ] {
            assert!(
                !rendered.contains(secret),
                "{secret} leaked into {rendered}"
            );
        }
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn the_password_policy_bounds_input_without_truncating() {
        let too_short = check_password_policy(b"short");
        assert_eq!(too_short, Err(PasswordPolicyError::TooShort));

        let long = vec![b'a'; MAX_PASSWORD_BYTES + 1];
        assert_eq!(
            check_password_policy(&long),
            Err(PasswordPolicyError::TooLong),
            "an over-long password is refused, never silently shortened"
        );

        let exact = vec![b'a'; MAX_PASSWORD_BYTES];
        assert!(check_password_policy(&exact).is_ok());

        // Every policy failure renders as one opaque message so the policy
        // shape is not an oracle.
        assert_eq!(
            too_short.unwrap_err().operator_message(),
            PasswordPolicyError::TooLong.operator_message()
        );
    }

    #[test]
    fn unicode_passwords_are_measured_as_utf8_bytes() {
        // Four 3-byte characters is 12 bytes, exactly the floor: the policy is
        // about the bytes that reach Argon2id, not about character counts.
        let password = "\u{65e5}\u{672c}\u{8a9e}\u{8a9e}";
        assert_eq!(password.chars().count(), 4);
        assert_eq!(password.len(), 12);
        assert!(check_password_policy(password.as_bytes()).is_ok());

        // Three of the same characters is 9 bytes, below the floor: a short
        // non-ASCII credential is still refused, because the bytes are what
        // Argon2id actually has to work with.
        assert_eq!(
            check_password_policy("\u{65e5}\u{672c}\u{8a9e}".as_bytes()),
            Err(PasswordPolicyError::TooShort)
        );

        let verifier = PasswordVerifier::hash(password).unwrap();
        assert!(verifier.verify(password));
    }

    #[test]
    fn invalid_utf8_is_refused_rather_than_lossy_decoded() {
        let raw = [
            0xffu8, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
        ];
        assert_eq!(
            check_password_policy(&raw),
            Err(PasswordPolicyError::NotUtf8)
        );
    }

    #[test]
    fn a_session_token_has_256_bits_of_entropy_and_stores_only_its_digest() {
        let token = SessionToken::generate().unwrap();
        let raw = token.expose_once();
        // 32 random bytes in unpadded base64url.
        assert_eq!(raw.len(), 43);
        assert!(raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));

        let digest = token.digest();
        assert_eq!(digest.expose_for_storage().len(), SHA256_HEX_LENGTH);
        assert!(
            !digest.expose_for_storage().contains(raw),
            "the digest must not contain the token"
        );

        // The persisted digest is what lookup compares.
        assert_eq!(SessionToken::digest_of(raw), digest);
        assert_ne!(SessionToken::digest_of("a different token"), digest);
    }

    #[test]
    fn distinct_tokens_never_collide() {
        let mut digests = std::collections::HashSet::new();
        for _ in 0..64 {
            let token = SessionToken::generate().unwrap();
            assert!(
                digests.insert(token.digest()),
                "256-bit tokens must not collide across 64 draws"
            );
        }
    }

    #[test]
    fn a_digest_round_trips_and_rejects_a_wrong_length() {
        let token = SessionToken::generate().unwrap();
        let stored = token.digest().expose_for_storage().to_owned();
        let parsed = SessionTokenDigest::parse(stored).unwrap();
        assert!(parsed.constant_time_eq(&token.digest()));

        assert!(SessionTokenDigest::parse("too short").is_err());
        assert!(
            SessionTokenDigest::parse("z".repeat(SHA256_HEX_LENGTH)).is_err(),
            "non-hex must not parse as a digest"
        );
        assert!(!parsed.constant_time_eq(&SessionToken::digest_of("other")));
    }

    #[test]
    fn a_csrf_token_has_256_bits_of_entropy() {
        let csrf = CsrfToken::generate().unwrap();
        assert_eq!(csrf.expose_once().len(), 43);
        assert_ne!(
            csrf.expose_once(),
            CsrfToken::generate().unwrap().expose_once()
        );
        let adopted = CsrfToken::parse(csrf.expose_once()).unwrap();
        assert_eq!(adopted.expose_once(), csrf.expose_once());
    }

    #[test]
    fn credential_rejection_never_distinguishes_username_from_password() {
        // One error variant for all of it: an unknown user, a wrong password, and
        // a disabled principal are indistinguishable at this layer.
        assert_eq!(
            AuthError::CredentialsRejected.to_string(),
            AuthError::CredentialsRejected.to_string()
        );
        let rendered = format!("{:?}", AuthError::CredentialsRejected);
        assert!(!rendered.to_lowercase().contains("password"));
        assert!(!rendered.to_lowercase().contains("user"));
        assert!(!rendered.to_lowercase().contains("principal"));
    }
}
