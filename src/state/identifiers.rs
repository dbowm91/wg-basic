//! Typed identifiers for the durable application-state store.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

/// Stable identity of one wg-basic installation.
///
/// Generated randomly once when a new store is created and preserved across
/// reopen, backup, and restore. It is deliberately not derived from hostname,
/// interface, path, MAC address, or public key, so restoring a backup onto a
/// different host recreates resources with the same durable owner identity.
///
/// This is an ordinary non-secret identifier. It is a correctness and
/// provenance marker, never an authorization token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstallationId(Uuid);

impl InstallationId {
    /// Generates a fresh random installation identity.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for InstallationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InstallationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for InstallationId {
    type Err = uuid::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// The initial desired generation of a freshly created store.
pub const INITIAL_DESIRED_GENERATION: DesiredGeneration = DesiredGeneration(1);

/// The largest desired generation representable in SQLite's signed 64-bit integer.
pub const MAX_DESIRED_GENERATION: DesiredGeneration = DesiredGeneration(i64::MAX as u64);

/// Monotonic revision of the committed desired state.
///
/// The generation advances by exactly one on every committed desired-state
/// mutation and never moves backward. A kernel-apply failure does not roll it
/// back and does not cause it to be reused, because a generation identifies a
/// committed snapshot rather than an apply attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DesiredGeneration(u64);

impl DesiredGeneration {
    /// Reconstructs a generation read from storage.
    ///
    /// Returns `None` for values that cannot have been produced by this
    /// implementation, which keeps a tampered or corrupted row from being
    /// silently accepted as authoritative.
    pub fn from_storage(value: i64) -> Option<Self> {
        if value <= 0 {
            return None;
        }
        let generation = Self(value as u64);
        (generation <= MAX_DESIRED_GENERATION).then_some(generation)
    }

    /// The value to bind into SQL.
    pub fn to_storage(self) -> i64 {
        self.0 as i64
    }

    /// Builds a generation from a caller-supplied value.
    ///
    /// Returns `None` for zero or any value past the SQLite storage ceiling, so
    /// an out-of-range number can never become authoritative state.
    pub fn new(value: u64) -> Option<Self> {
        (value > 0 && value <= MAX_DESIRED_GENERATION.0).then_some(Self(value))
    }

    /// The next generation, or `None` at the representable ceiling.
    pub fn next(self) -> Option<Self> {
        self.0
            .checked_add(1)
            .filter(|next| *next <= MAX_DESIRED_GENERATION.0)
            .map(Self)
    }
}

impl Default for DesiredGeneration {
    /// The generation a store reports before any mutation.
    fn default() -> Self {
        INITIAL_DESIRED_GENERATION
    }
}

impl fmt::Display for DesiredGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installation_id_is_random_stable_and_round_trips() {
        let first = InstallationId::new();
        let second = InstallationId::new();
        assert_ne!(first, second, "identities must be independently random");
        assert_eq!(first.to_string().parse::<InstallationId>().unwrap(), first);
    }

    #[test]
    fn generation_starts_at_one_and_increments_monotonically() {
        let initial = DesiredGeneration::default();
        assert_eq!(initial, INITIAL_DESIRED_GENERATION);
        assert_eq!(initial.to_storage(), 1);
        assert_eq!(initial.next(), Some(DesiredGeneration(2)));
        assert!(initial.next().unwrap() > initial);
    }

    #[test]
    fn caller_supplied_generations_are_range_checked() {
        assert_eq!(DesiredGeneration::new(1), Some(INITIAL_DESIRED_GENERATION));
        assert_eq!(DesiredGeneration::new(7), Some(DesiredGeneration(7)));
        assert_eq!(DesiredGeneration::new(0), None);
        assert_eq!(DesiredGeneration::new(u64::MAX), None);
    }

    #[test]
    fn generation_round_trips_through_sqlite_storage_form() {
        for value in [1_i64, 2, 1_000_000, i64::MAX] {
            let generation = DesiredGeneration::from_storage(value).expect("valid");
            assert_eq!(generation.to_storage(), value);
        }
    }

    #[test]
    fn invalid_or_tampered_storage_values_are_rejected() {
        assert_eq!(DesiredGeneration::from_storage(0), None);
        assert_eq!(DesiredGeneration::from_storage(-1), None);
        assert_eq!(DesiredGeneration::from_storage(i64::MIN), None);
    }

    #[test]
    fn generation_never_wraps_at_the_storage_ceiling() {
        assert_eq!(MAX_DESIRED_GENERATION.next(), None);
        assert_eq!(MAX_DESIRED_GENERATION.to_storage(), i64::MAX);
    }
}
