# Management Service Post-Phase-7 Reconciliation Addendum

Status: closed; C001 closed. Evidence: `plans/closure/management-service/c001-status.md`.

Canonical references:

- `plans/000-long-term-specification.md`
- `plans/001-terminology-and-domain-model.md`
- `plans/002-long-term-roadmap.md`
- `plans/003-planning-process.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`
- `plans/subsystems/management-service-security-roadmap.md`

Historical closure references:

- `plans/closure/management-service/001-status.md`
- `plans/closure/management-service/002-status.md`
- `plans/closure/management-service/003-status.md`
- `plans/closure/management-service/004-status.md`

## 1. Purpose

Phase 7 remains closed.

This addendum owns one bounded post-closure corrective before Phase 8 implementation begins:

1. make current-head CI deterministic again without changing login-limiter or Argon2 production policy;
2. reconcile the stale Phase 8 status in the long-term roadmap and planning registry;
3. record the corrected closure head so Phase 8 starts from a green baseline.

It does not reopen Phase 7 architecture, authentication semantics, session semantics, HTTP perimeter policy, or service lifecycle.

## 2. Finding: limiter test depends on wall-clock Argon2 duration

Current HEAD `df872f1` fails only the ordinary Rust job in:

- `tests/authenticated_api.rs::a_throttled_login_does_not_answer_at_all`.

The test constructs:

```text
global bucket: capacity=1, refill=1 token/second
peer bucket:   capacity=1, refill=1 token/second
```

then:

1. performs one real successful login;
2. immediately performs a second login;
3. expects the second request to be throttled.

The first login performs Argon2id through the bounded worker. Under CI load that operation can take at least one second. Since `AuthenticatedApi::login` calls `Instant::now()` for each request, the production limiter correctly refills one token and admits the second login.

This is a test-timing defect. The production limiter's token-bucket behavior matches its documented policy.

## 3. Corrective rule

C001 MUST NOT “fix” the failure by:

- reducing Argon2 cost;
- increasing production login strictness solely for the test;
- removing/refactoring the limiter's refill behavior;
- inserting a wall-clock sleep/race;
- assuming a faster CI runner.

The test must establish exhaustion deterministically.

Preferred implementation options, in order:

1. exercise `LoginLimiter::check` at a fixed `Instant` for the exact “no second admission” property, while keeping API-level tests for response rendering;
2. introduce a test-only injectable clock/admission seam if the API-level no-answer property genuinely needs the full `AuthenticatedApi::login` path;
3. use a positive but very slow refill bucket in the API fixture only, with no production constant change.

Avoid a zero refill rate because the production type/documentation treats a non-refilling bucket as an invalid/permanent block shape.

## 4. Current-state planning reconciliation

Correct:

- Phase 8 in `plans/002-long-term-roadmap.md`: no longer “blocked on Phases 6–7”;
- registry current-state summary that still describes only Phase 7 M001 as shipped;
- any current docs saying authentication/sessions remain future work.

Historical closure records remain period-accurate.

## 5. Invariants

Preserve:

- Phase 7 strict closure;
- Argon2id policy;
- global/per-peer limiter production constants;
- limiter-before-Argon2 ordering;
- in-memory limiter/reset semantics;
- Host/Origin/CSRF/cookie rules;
- five authenticated/perimeter routes plus embedded shell routes;
- Phase 7 service footprint/lifecycle behavior;
- Rust 1.89 MSRV;
- all rootful network/durable/service suites.

## 6. Corrective milestone

### C001 — Deterministic limiter evidence and Phase 8 readiness reconciliation

Status: closed. Evidence: `plans/closure/management-service/c001-status.md`.

Implementation plan:

- `plans/implementation/management-service/c001-post-phase7-ci-and-phase8-readiness.md`

## 7. Exit conditions

C001 closes only when:

- the failing limiter test no longer relies on Argon2 wall-clock duration;
- a negative/control assertion still proves one exhausted bucket refuses before hashing;
- production limiter/Argon2 constants are unchanged unless a separate demonstrated defect justifies change;
- routine Rust/MSRV CI is green at the final head;
- all existing rootful suites remain green;
- Phase 8 planning status is reconciled;
- closure record identifies the failure as test evidence debt rather than rewriting Phase 7 history.

## 8. Closure record

Create:

- `plans/closure/management-service-post-phase7-reconciliation/c001-status.md`.
