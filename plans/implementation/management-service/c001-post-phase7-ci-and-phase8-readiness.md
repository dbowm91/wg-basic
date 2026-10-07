# Management Service C001 — Post-Phase-7 CI and Phase 8 Readiness Reconciliation

Status: ready

Repository baseline: `df872f1d6ac63584b58610d7521752ae51f1c902`

Source roadmap:

- `plans/subsystems/management-service-post-phase7-reconciliation-addendum.md`

Primary class: corrective / evidence / planning reconciliation

## 1. Objective

Restore a green deterministic current-head baseline after Phase 7 closure, without modifying the production security policy merely to satisfy a timing-sensitive test.

Also reconcile the canonical Phase 8 status before the Phase 8 implementation line is activated.

## 2. Evidence at baseline

Current GitHub Actions run `37681959105`:

- network-control-e2e: pass;
- network-reconcile-kernel: pass;
- durable-owner: pass;
- wireguard-kernel: pass;
- durable-restart: pass;
- durable-backup: pass;
- rust: fail.

The Rust job failure is exactly:

```text
authenticated_api::a_throttled_login_does_not_answer_at_all
expected second login to be throttled
actual: HTTP 200 successful session
```

All preceding unit/architecture/auth tests in the same job passed.

## 3. Root cause

The test's first request is a real valid login and therefore performs Argon2id.

The limiter fixture refills at one token/second.

The second API call obtains a fresh `Instant::now()`.

Therefore:

```text
first request admitted
    -> Argon2 work
    -> >= 1 second on loaded runner
    -> token refills
second request legitimately admitted
```

The phrase “second attempt in the same instant” in the test is false: the test does not control the instant.

## 4. Work package A — deterministic limiter evidence

Refactor the test so the limiter-exhaustion premise is deterministic.

Required evidence remains two separate properties:

1. **token bucket property**: at one controlled instant, a capacity-1 bucket admits exactly one attempt and refuses the next;
2. **HTTP/API rendering property**: a `Throttled` rejection is an error path, never a successful authentication/session response, and renders as bounded 429 with Retry-After through the service layer where applicable.

The existing `limiter_before_hashing` test remains load-bearing and MUST continue proving that exhausted admission avoids Argon2 work.

Preferred smallest patch:

- remove the wall-clock-sensitive full-login construction from `a_throttled_login_does_not_answer_at_all`;
- use a deliberately pre-exhausted/shared limiter or a test seam that makes `AuthenticatedApi::login` see an already-empty bucket without a preceding real Argon2 request.

If introducing test-only clock injection:

- compile it under `#[cfg(test)]` or make it an internal constructor;
- do not expose a production runtime clock override;
- do not change production call sites.

Do not add sleeps.

## 5. Work package B — planning/current-state reconciliation

Update:

- `plans/002-long-term-roadmap.md`: Phase 8 is unblocked for research/planning; implementation remains gated only by this C001 if the Phase 8 plans are written in parallel;
- `plans/registry.md`: current production summary must describe Phase 7 M001–M004 as closed, not only M001;
- README/architecture only if equivalent stale “auth/session future work” wording exists.

Phase 7 closure records remain unchanged.

## 6. Verification

Required:

```text
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Re-run all existing CI/rootful jobs.

At least one negative control must demonstrate the repaired test fails if limiter admission is incorrectly bypassed.

## 7. Acceptance criteria

C001 closes only when:

1. no limiter test depends on Argon2 completing in less than a refill interval;
2. the production bucket/refill constants are unchanged unless separately justified;
3. Argon2id parameters are unchanged;
4. limiter-before-hashing guard/test remains;
5. throttled-login response behavior remains bounded and non-authenticating;
6. all routine/MSRV checks pass;
7. all rootful jobs pass;
8. Phase 8 status is reconciled;
9. no high/medium finding remains.

## 8. Stop conditions

Stop/write a separate corrective if:

- a deterministic test reveals a genuine production double-admission bug at the same controlled instant;
- limiter state can be bypassed by cloning;
- the API path invokes Argon2 after a refused admission;
- fixing the issue requires changing authentication policy.

## 9. Closure evidence

Record:

- old failing test semantics;
- new deterministic fixture/seam;
- negative control;
- unchanged production limiter/Argon2 policy;
- routine/MSRV/rootful CI;
- final green current-head run;
- Phase 8 readiness disposition.
