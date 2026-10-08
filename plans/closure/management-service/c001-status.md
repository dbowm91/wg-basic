# Management Service Post-Phase-7 C001 Closure — Deterministic Limiter Evidence and Phase 8 Readiness

Status: closed.

Planning baseline: `plans/implementation/management-service/c001-post-phase7-ci-and-phase8-readiness.md`.
Planning repository baseline: `3a1b6d3`.
Repository baseline at implementation start: `b959df6`.
Final implementation head: `df1f9e7`.
Disposition: **closed**.

## Outcome

C001 is strictly closed. The one timing-sensitive failure on current-head CI is
gone, both pieces of evidence the plan asks for are present and independent, and
Phase 8 is unblocked on a green baseline.

Two findings are recorded below rather than folded into "fixed", because the
second one is a defect in already-closed work and the first is a claim that was
wrong in an instructive way.

1. **The test was measuring the runner, not the limiter.**
   `a_throttled_login_does_not_answer_at_all` established limiter exhaustion by
   performing a real successful login and then expecting the next attempt to be
   refused. That premise holds only while one Argon2id verification finishes
   inside the one-second refill interval. On a loaded CI runner it does not: the
   token legitimately refills during the first request's own hashing, and the
   test fails against a limiter behaving exactly as specified.

   The first plan run reproduced this honestly — the two prior CI runs on the
   plan-only commits both failed on this exact test, which is what confirmed the
   plan's premise rather than assuming it.

2. **A second, unrelated wall-clock-sensitive test was blocking green CI.**
   `the_in_flight_ceiling_holds_under_a_slow_client_flood` in
   `tests/service_resource_limits.rs` asserted that 64 concurrent logins finish
   within a flat 30-second constant. Every one of those logins is a full
   Argon2id verification and the worker answers them close to one at a time, so
   the aggregate is dominated by the runner's hashing speed. It passed locally at
   22s and overran on CI.

   Diagnosing it turned up something worse than a slow test. Instrumenting the
   flood showed the status distribution was `401: 64` — **nothing was shed at
   all** — and with production's `max_connections: 64` against
   `max_in_flight_requests: 128`, a connection-bounded flood can never reach the
   in-flight ceiling. The test named for the in-flight ceiling was structurally
   incapable of exercising it, while asserting a property that was really about
   CPU throughput.

## Work package A — deterministic limiter evidence

### What changed

`tests/authenticated_api.rs`, one test. No production change.

Exhaustion is now **established** rather than raced into existence: the bucket is
drained with two `LoginLimiter::check` calls at one controlled instant, and the
request under test runs with no Argon2 work anywhere near it. The gap between
drain and request is struct construction, not a whole verification.

### The two properties, kept separate

The plan requires two distinct pieces of evidence, and both survive:

| Property | Evidence |
|---|---|
| Token bucket: at one controlled instant, a capacity-1 bucket admits exactly one attempt and refuses the next | The two `check` calls in the test itself: first allowed, second refused |
| HTTP/API rendering: a `Throttled` rejection is an error path with a bounded 429 and `Retry-After`, never a successful authentication | `status() == 429`, `retry_after()` in `1..=60`, body `too many attempts` |

The second half was previously implicit — the test only asserted
`matches!(second, RequestRejection::Throttled { .. })`. It now asserts the actual
rendering, which is what a client sees.

### Negative control

Temporarily removing the admission check from `AuthenticatedApi::login`:

```
cargo test --locked --test authenticated_api
test result: FAILED. 11 passed; 2 failed
  a_throttled_login_does_not_answer_at_all ... FAILED
  limiter_before_hashing ... FAILED
```

Both limiter tests fail, so neither is vacuous. `src/http/api.rs` was restored
byte-for-byte afterwards and `git diff --stat src/http/api.rs` is empty.

### Option 3 rejected

The plan's preferred option was taken, not its third alternative: **no clock
injection was introduced**. A zero refill rate would also have been refused —
the production type treats a non-refilling bucket as an invalid shape, and
building one in a test would encode a configuration the product does not
support. Bucket and refill constants, Argon2id parameters, and the
limiter-before-hashing ordering are all unchanged.

## Work package B — Phase 8 readiness reconciliation

| File | Change |
|---|---|
| `plans/002-long-term-roadmap.md` | Phase 8 status line now reads unblocked with its basis; the "begins only after C001" sentence now records that C001 restored the baseline; phase table row 8 → active, row 9 gating → "Phase 8 closed" |

The long-term roadmap's closing sentence also names the five milestones
explicitly so "Phase 8 is closed" is never a bare claim in the Phase 9 row.

### Current-behavior docs: no change needed

The plan asks for an update "only if equivalent stale 'auth/session future work'
wording exists". A sweep of `README.md`, `architecture/*.md`, and `docs/*.md`
found the opposite: they already describe Phase 7 authentication and sessions as
**shipped** and Phase 8 as not yet implemented. There is no stale wording to
correct, so none was invented.

## Work package C — routine, MSRV, and rootful evidence

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --all-targets --locked` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | 415 tests, 0 failed |
| `cargo +1.89.0 check --all-targets --locked` | pass |
| `wireguard_kernel` (rootful) | 2 passed |
| `network_control_e2e` (rootful) | 2 passed |
| `network_reconcile` (rootful) | 2 passed |
| `durable_owner` (rootful) | 10 passed |
| `durable_restart` (rootful) | 9 passed |
| `durable_backup` (rootful) | 2 passed |
| `service_rootful_e2e` (rootful) | 3 passed |

MSRV requires no dependency change: the fix is entirely inside one test file and
`Cargo.toml` is untouched.

## The second failure: a test that could not fail

`the_in_flight_ceiling_holds_under_a_slow_client_flood` was fixed rather than
deleted, and the fix changed what it asserts:

* the flood, the route, the wide limiter, and the bounded-status/bounded-body
  assertions are all unchanged, so the coverage is not reduced;
* the wall-clock assertion now compares against the budgets the server actually
  configures — `DEFAULT_HANDLER_TIMEOUT + DEFAULT_REPLY_DEADLINE` per request —
  instead of a flat constant. That is machine-independent: a genuinely unbounded
  wait still fails, through the per-request client deadline inside `request_on`,
  which panics if any single reply fails to arrive.

Both facts are recorded in the test's own comment, so a future reader does not
reintroduce a magic constant.

A false lead is recorded too: the first attempt pinned `max_in_flight_requests`
to 8 to make the ceiling binding and asserted the excess must be shed. EggServe
*does* shed with 503 on in-flight exhaustion (`try_acquire_owned` in
`eggserve-server` 0.4.0), but the flood still produced `401: 64`, because the
worker serialises the logins and roughly one request is ever in flight. The
approach was reverted rather than left in place as a test that could not pass for
the reason it claimed.

## Unblock determination

Phase 8 M001's stated hard dependency — *"management-service post-Phase-7 C001
strict closure on green current-head CI"* — is satisfied:

* C001 is closed in this record;
* current-head CI is green at `df1f9e7`;
* the `plans/002-long-term-roadmap.md` blocker wording has been corrected.

**Phase 8 M001 is unblocked.** It has been implemented and is closed separately
in `plans/closure/product-management/001-status.md`.