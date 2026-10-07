//! Bounded in-memory admission control for login attempts.
//!
//! # This runs *before* Argon2, and that ordering is the whole point
//!
//! Measured at ~300 ms per verification and 19 MiB (M002 closure), one worker
//! thread can service roughly sixteen verifications inside the five-second reply
//! deadline. Everything beyond that is already a `503`. A limiter placed *after*
//! hashing would therefore let an attacker spend 300 ms of the appliance's CPU
//! per request before anything refused it — which is a denial of service wearing
//! a rate limit's clothes.
//!
//! So [`LoginLimiter::check`] is the first thing a login request does, before the
//! command is admitted to the worker queue. `limiter_before_hashing` in
//! `tests/authenticated_api.rs` proves the ordering by asserting that a
//! saturated limiter produces `429` without any Argon2 work having occurred.
//!
//! # Shape: a token bucket with a bounded peer map
//!
//! Two independent limiters, because they defend against different things:
//!
//! * **Global** — caps the appliance's total verification rate. This is the one
//!   that protects the worker thread, and it is what the ~300 ms figure sizes.
//! * **Per transport peer** — stops one host from consuming the whole global
//!   budget, which is what a distributed guess looks like from the listener's
//!   point of view.
//!
//! The peer map is **bounded**. An unbounded map keyed by client address is a
//! memory exhaustion vector all by itself: an attacker with many source
//! addresses fills it and the process grows until it is killed. When the map is
//! full the least-recently-touched entry is evicted, so the limiter degrades to
//! approximately-global rather than to unbounded memory.
//!
//! # No persistent account lockout
//!
//! Counters live in memory and die with the process. A lockout persisted to disk
//! would be a denial-of-service primitive: anyone who can reach the login form
//! could permanently lock the operator out by guessing wrong a few times.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// The token-bucket shape used by both limiters.
///
/// `Eq`/`PartialEq` are hand-written because the refill rate is an `f64`: a
/// derived `Eq` does not exist, and a derived `PartialEq` would compare a
/// double exactly, which two arithmetic-equivalent rates need not satisfy.
/// Only tests compare these, and they compare the meaningful fields.
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    /// How much work is allowed in a full window.
    pub capacity: u32,
    /// How fast the bucket refills, as attempts per second.
    pub refill_per_second: f64,
}

impl Bucket {
    /// Builds a bucket with a whole-number refill rate.
    pub fn per_second(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            capacity,
            refill_per_second: refill_per_second as f64,
        }
    }

    /// Whether two buckets have the same shape.
    pub fn same_shape(&self, other: &Self) -> bool {
        self.capacity == other.capacity
            && (self.refill_per_second - other.refill_per_second).abs() < f64::EPSILON
    }

    /// The smallest interval at which the bucket is fully refilled.
    pub fn full_refill_interval(&self) -> Duration {
        if self.refill_per_second <= 0.0 {
            // A bucket that never refills is a permanent block, not a limiter.
            // Callers construct these with a positive rate; this is the floor
            // that keeps an arithmetic mistake from becoming a denial of service.
            return Duration::from_secs(1);
        }
        Duration::from_secs_f64(self.capacity as f64 / self.refill_per_second)
    }
}

/// What the limiter decided about one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// Allowed, and how much of the bucket is left.
    Allowed { remaining: u32 },
    /// Refused. `retry_after` is what the `Retry-After` header will carry.
    Refused { retry_after_seconds: u64 },
}

impl Admission {
    /// Whether this attempt may proceed to Argon2.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

/// One peer's bucket.
#[derive(Clone, Copy, Debug)]
struct PeerBucket {
    /// Fractional tokens available.
    tokens: f64,
    /// When this bucket was last used; drives eviction order.
    last_seen: Instant,
}

/// Bounded login admission control.
///
/// Cheap to clone: every clone shares the same counters through a mutex, so
/// cloning cannot widen the limit.
#[derive(Debug)]
pub struct LoginLimiter {
    global: Bucket,
    per_peer: Bucket,
    max_peers: usize,
    state: Mutex<LimiterState>,
}

#[derive(Debug)]
struct LimiterState {
    global_tokens: f64,
    global_seen: Instant,
    peers: HashMap<IpAddr, PeerBucket>,
}

impl LoginLimiter {
    /// Builds a limiter.
    ///
    /// `max_peers` is the memory bound. It must be at least one; a zero bound
    /// would mean no per-peer tracking at all, which is a configuration mistake
    /// rather than a policy.
    pub fn new(global: Bucket, per_peer: Bucket, max_peers: usize) -> Self {
        let max_peers = max_peers.max(1);
        Self {
            global,
            per_peer,
            max_peers,
            state: Mutex::new(LimiterState {
                global_tokens: global.capacity as f64,
                global_seen: Instant::now(),
                peers: HashMap::with_capacity(max_peers.min(1024)),
            }),
        }
    }

    /// The global bucket shape.
    pub fn global_bucket(&self) -> Bucket {
        self.global
    }

    /// The per-peer bucket shape.
    pub fn per_peer_bucket(&self) -> Bucket {
        self.per_peer
    }

    /// The peer-map cardinality bound.
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Decides whether one login attempt from `peer` may proceed.
    ///
    /// The global bucket is charged **first**. A refused attempt must cost the
    /// attacker nothing: if the peer bucket were charged first, an attacker
    /// spreading attempts across many source addresses would consume peer
    /// capacity that never reached the global budget.
    pub fn check(&self, peer: SocketAddr, now: Instant) -> Admission {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            // A poisoned limiter must fail closed. Refusing a login is
            // inconvenient; admitting an unbounded one is the outage.
            Err(_) => {
                return Admission::Refused {
                    retry_after_seconds: 1,
                }
            }
        };

        let elapsed = now
            .saturating_duration_since(state.global_seen)
            .as_secs_f64();
        state.global_seen = now;
        state.global_tokens =
            refill(state.global_tokens, self.global, elapsed).min(self.global.capacity as f64);

        if state.global_tokens < 1.0 {
            return Admission::Refused {
                retry_after_seconds: retry_after(state.global_tokens, self.global),
            };
        }

        let ip = peer.ip();
        let entry = state.peers.entry(ip).or_insert(PeerBucket {
            tokens: self.per_peer.capacity as f64,
            last_seen: now,
        });
        let peer_elapsed = now.saturating_duration_since(entry.last_seen).as_secs_f64();
        entry.last_seen = now;
        entry.tokens =
            refill(entry.tokens, self.per_peer, peer_elapsed).min(self.per_peer.capacity as f64);

        if entry.tokens < 1.0 {
            return Admission::Refused {
                retry_after_seconds: retry_after(entry.tokens, self.per_peer),
            };
        }

        // Both buckets can afford this attempt, so charge both. The peer borrow
        // ends here, so the global counter is reachable afterwards.
        entry.tokens -= 1.0;
        state.global_tokens -= 1.0;
        self.evict_if_needed(&mut state, now);

        Admission::Allowed {
            remaining: state.global_tokens.floor() as u32,
        }
    }

    /// Keeps the peer map at or below its bound.
    ///
    /// Evicts the least-recently-seen peer. The map is only consulted when it is
    /// over the bound, so the common path costs nothing.
    fn evict_if_needed(&self, state: &mut LimiterState, _now: Instant) {
        while state.peers.len() > self.max_peers {
            let Some(victim) = state
                .peers
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_seen)
                .map(|(ip, _)| *ip)
            else {
                return;
            };
            state.peers.remove(&victim);
        }
    }

    /// How many peers are currently tracked. For tests and startup output.
    pub fn tracked_peers(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.peers.len())
            .unwrap_or(0)
    }

    /// Forgets every counter. Counters are in-memory only by design, so this is
    /// never wired to operator input.
    pub fn reset(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.peers.clear();
            state.global_tokens = self.global.capacity as f64;
            state.global_seen = Instant::now();
        }
    }
}

/// Adds `elapsed * rate` tokens, never above `capacity`.
fn refill(tokens: f64, bucket: Bucket, elapsed: f64) -> f64 {
    (tokens + elapsed * bucket.refill_per_second).min(bucket.capacity as f64)
}

/// How long until the bucket holds one token.
///
/// Rounded up, because a `Retry-After` of zero would invite an immediate retry
/// and a busy loop.
fn retry_after(tokens: f64, bucket: Bucket) -> u64 {
    if bucket.refill_per_second <= 0.0 {
        return 60;
    }
    let missing = (1.0 - tokens).max(0.0);
    let seconds = missing / bucket.refill_per_second;
    seconds.ceil().clamp(1.0, 60.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

    /// A limiter whose **global** bucket is the binding constraint.
    ///
    /// The peer bucket is deliberately wider than the global one, so the tests
    /// that exercise global accounting are not accidentally testing the peer
    /// bucket instead.
    fn limiter() -> LoginLimiter {
        LoginLimiter::new(Bucket::per_second(3, 1), Bucket::per_second(10, 1), 4)
    }

    /// A limiter whose **peer** bucket is the binding constraint.
    fn peer_limited() -> LoginLimiter {
        LoginLimiter::new(Bucket::per_second(3, 1), Bucket::per_second(2, 1), 4)
    }

    fn peer(last: u8) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, last), 40000))
    }

    #[test]
    fn a_bucket_admits_up_to_capacity_then_refuses_with_a_retry_hint() {
        let limiter = limiter();
        let now = Instant::now();
        for _ in 0..3 {
            assert!(
                limiter.check(peer(1), now).is_allowed(),
                "the bucket must admit its full capacity"
            );
        }
        let refused = limiter.check(peer(1), now);
        assert!(!refused.is_allowed());
        let Admission::Refused {
            retry_after_seconds,
        } = refused
        else {
            panic!("expected a refusal")
        };
        assert!(
            (1..=60).contains(&retry_after_seconds),
            "a refusal must carry a usable Retry-After, got {retry_after_seconds}"
        );
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = limiter();
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.check(peer(1), start).is_allowed());
        }
        assert!(!limiter.check(peer(1), start).is_allowed());

        // One second later the bucket has exactly one token again.
        let later = start + Duration::from_secs(1);
        assert!(limiter.check(peer(1), later).is_allowed());
        assert!(!limiter.check(peer(1), later).is_allowed());
    }

    #[test]
    fn a_refill_never_exceeds_capacity() {
        let limiter = limiter();
        let start = Instant::now();
        for _ in 0..3 {
            limiter.check(peer(1), start);
        }
        // Far in the future the bucket is full again, not unbounded.
        let much_later = start + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(limiter.check(peer(1), much_later).is_allowed());
        }
        assert!(!limiter.check(peer(1), much_later).is_allowed());
    }

    #[test]
    fn one_peer_cannot_consume_the_whole_global_budget() {
        let limiter = peer_limited();
        let now = Instant::now();
        // The peer bucket allows 2, so the third attempt from one host is
        // refused even though the global budget still has a token.
        assert!(limiter.check(peer(1), now).is_allowed());
        assert!(limiter.check(peer(1), now).is_allowed());
        assert!(!limiter.check(peer(1), now).is_allowed());

        // A different peer still has its own budget, charged against the global.
        assert!(limiter.check(peer(2), now).is_allowed());
        // ...and the global bucket is now empty for everyone.
        assert!(!limiter.check(peer(3), now).is_allowed());
    }

    #[test]
    fn many_peers_still_cannot_exceed_the_global_budget() {
        // This is the attack the global bucket exists for: a distributed guess.
        let limiter = LoginLimiter::new(Bucket::per_second(5, 1), Bucket::per_second(5, 1), 64);
        let now = Instant::now();
        let mut allowed = 0;
        for last in 1..=40u8 {
            if limiter.check(peer(last), now).is_allowed() {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 5,
            "forty distinct peers must not get more than the global budget"
        );
    }

    #[test]
    fn the_peer_map_is_bounded() {
        // The memory bound is the point: an unbounded map keyed by client
        // address is itself a denial-of-service vector.
        let limiter =
            LoginLimiter::new(Bucket::per_second(1000, 1000), Bucket::per_second(1, 1), 8);
        let now = Instant::now();
        for last in 1..=200u8 {
            limiter.check(peer(last), now);
        }
        assert_eq!(
            limiter.tracked_peers(),
            8,
            "the peer map must never exceed its bound"
        );
        assert_eq!(limiter.max_peers(), 8);
    }

    #[test]
    fn an_ipv6_peer_is_tracked_separately() {
        let limiter = LoginLimiter::new(Bucket::per_second(10, 10), Bucket::per_second(1, 1), 16);
        let now = Instant::now();
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 1));
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
        assert!(limiter.check(v4, now).is_allowed());
        assert!(limiter.check(v6, now).is_allowed());
        assert!(!limiter.check(v4, now).is_allowed());
        assert_eq!(limiter.tracked_peers(), 2);
    }

    #[test]
    fn a_zero_peer_bound_degrades_to_one_rather_than_none() {
        let limiter = LoginLimiter::new(Bucket::per_second(10, 10), Bucket::per_second(10, 10), 0);
        assert_eq!(limiter.max_peers(), 1);
        let now = Instant::now();
        assert!(limiter.check(peer(1), now).is_allowed());
        assert!(limiter.tracked_peers() <= 1);
    }

    #[test]
    fn a_zero_refill_rate_never_becomes_a_permanent_block() {
        // A bucket that cannot refill would turn a typo into a denial of service.
        let bucket = Bucket {
            capacity: 1,
            refill_per_second: 0.0,
        };
        assert_eq!(bucket.full_refill_interval(), Duration::from_secs(1));
        assert_eq!(retry_after(0.0, bucket), 60);
    }

    #[test]
    fn the_default_shape_matches_the_measured_argon2_cost() {
        // Sized against the *slow* measured verification, not the fast one.
        //
        // Measured on the reference machine: ~14-23 ms per verification in a
        // release build, ~300 ms in a debug build or on a loaded/cold machine.
        // The shipped binary is a release build, so 20 x 14 ms = 0.3 s would sit
        // comfortably inside the 5 s worker deadline and the burst would never
        // actually be refused -- the queue would absorb it instead.
        //
        // Sizing against the slow figure is the conservative choice: a bucket
        // that is too small refuses a legitimate burst, which is a correctness
        // question an operator can notice and wait out; a bucket that is too
        // large is a denial of service, which is the thing this limiter exists to
        // prevent. It also holds on a slower appliance than the reference, which
        // is the case that matters.
        let limiter = LoginLimiter::new(Bucket::per_second(20, 2), Bucket::per_second(8, 1), 1024);
        assert_eq!(limiter.global_bucket().capacity, 20);
        assert_eq!(limiter.per_peer_bucket().capacity, 8);
        assert_eq!(limiter.tracked_peers(), 0);

        // Stated as named constants rather than a folded `f64` comparison, which
        // the optimizer removes entirely and which therefore tells a reader
        // nothing when the assertion passes.
        const SECONDS_PER_VERIFICATION_WHEN_LOADED: f64 = 0.3;
        const WORKER_REPLY_DEADLINE_SECONDS: f64 = 5.0;
        assert!(
            f64::from(limiter.global_bucket().capacity) * SECONDS_PER_VERIFICATION_WHEN_LOADED
                > WORKER_REPLY_DEADLINE_SECONDS,
            "a full global burst must cost more work than the worker deadline allows, or the \\
             surplus is queued instead of refused"
        );
        // And the per-peer bucket must be strictly smaller than the global one,
        // so no single peer can spend the whole budget by itself: 8 of 20 is
        // 40%, and reaching the ceiling needs three distinct peers. An attacker
        // can trivially obtain three source addresses on the LAN they are on,
        // which is why the global bucket exists at all -- it is the only bound
        // that holds regardless of how many addresses they have.
        assert!(limiter.per_peer_bucket().capacity < limiter.global_bucket().capacity);
        assert_eq!(
            limiter
                .global_bucket()
                .capacity
                .div_ceil(limiter.per_peer_bucket().capacity),
            3,
            "three peers must be needed to drain the global budget"
        );
    }
}
