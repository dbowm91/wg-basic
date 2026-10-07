# Management Service M004 — Service Lifecycle and Phase 7 Qualification

Status: closed at `d5d5ca9`. Closure record:
`plans/closure/management-service/004-status.md`. **Phase 7 is closed** and
Phase 8 is unblocked by it.

Source roadmap:

- `plans/subsystems/management-service-security-roadmap.md#8-m004--embedded-shell-process-lifecycle-and-phase-7-qualification`

Primary class: operational invariant / qualification

Hard dependency: M003 strict closure — **satisfied** at `cfe6860`.

Carry-forward from the M003 closure: the security headers are applied in exactly
one place (`headers::seal`, wrapping the completed answer in
`ManagementService::dispatch`), and architecture guards fail if that moves, or if
`Response::builder()` or a `ResponseBody` appears outside `response.rs`/`api.rs`.
The embedded asset shell must go through that same path. `/healthz` stays
unauthenticated with a body of exactly `ok` or `degraded`; readiness
differentiation must not widen it. The login limiter is in-memory by design and
resets on restart, and M004 must not add persistence for it.

## 1. Objective

Close Phase 7 as a stable service/security substrate for Phase 8.

M004 does not build the product management UI; it proves service lifecycle, embedded assets, restart/session behavior, and the full HTTP→worker→state/netd integration.

## 2. Embedded asset shell

Embed a minimal self-contained shell in the binary.

Requirements:

- no filesystem document root;
- no external scripts/fonts/styles/CDN;
- no inline-script requirement that weakens CSP;
- deterministic content type/length;
- bounded asset inventory.

The shell may be a simple placeholder/login-ready frame. It MUST NOT implement peer/client management.

## 3. Serve lifecycle

`wg-basic serve` becomes the canonical long-running unprivileged service role.

Lifecycle:

1. validate HTTP config;
2. start worker/open state;
3. attempt startup reconcile;
4. bind EggServe;
5. report readiness;
6. serve;
7. signal -> stop accepts;
8. drain bounded in-flight HTTP;
9. stop worker;
10. close DB;
11. exit cleanly.

Management must never spawn/elevate netd.

## 4. Readiness / health

Differentiate:

- process liveness;
- DB fatal startup state;
- backend degraded state;
- authenticated detailed management health.

The listener may be up while netd is unavailable/conflicted.

Do not make `/healthz` reveal why.

## 5. Session restart behavior

Because sessions are server-side persistent:

- restarting `serve` should preserve a non-expired session;
- logout still invalidates it;
- password reset invalidates every prior session;
- expiry survives restart.

Test using the actual HTTP cookie, not only state-store methods.

## 6. End-to-end service qualification

Build integration fixtures with:

- real on-disk SQLite;
- real `wg-basic netd` child;
- real `wg-basic serve` child;
- actual TCP HTTP client;
- real management worker;
- disposable Linux namespace where needed.

Required flow:

1. create/reset local admin through CLI;
2. start netd + serve;
3. login;
4. fetch session + authenticated health;
5. verify startup reconciliation state;
6. restart serve;
7. reuse valid session;
8. logout/revoke;
9. prove old cookie rejected.

At least one rootful fixture should include real netd/network state so the HTTP health surface reflects the same management runtime qualified in Phase 6.

## 7. Abuse/resource qualification

Required cases:

- HTTP connection/in-flight saturation;
- worker queue saturation;
- oversized login body;
- repeated throttled login;
- slow/stalled handler bounded by timeout;
- shutdown with in-flight request;
- worker unavailable during request;
- expired session cleanup.

No test should rely on unbounded sleeps.

## 8. Static architecture guards

Pin:

- HTTP modules do not import rusqlite;
- HTTP modules do not import network backends;
- netd does not import auth/state HTTP modules;
- only worker/runtime layer reaches ManagementRuntime;
- no JWT dependency;
- no Node/npm runtime files required;
- no external asset URL;
- no wildcard CORS.

## 9. Performance/footprint evidence

Capture, without over-claiming:

- cold service readiness;
- idle RSS for serve + netd on CI/reference Linux;
- idle CPU qualitative/short sample;
- login Argon2 latency;
- health endpoint latency;
- worker queue capacity.

Compare against the long-term <30 MiB total target as an engineering signal; do not weaken security/correctness solely to meet it.

## 10. Documentation

Add/update:

- `architecture/management-http.md`;
- `architecture/authentication.md`;
- deployment/bind-origin guidance;
- development HTTP test instructions;
- README current capabilities;
- registry/roadmap.

Clearly state:

- Phase 7 service/auth substrate implemented;
- Phase 8 product CRUD/UI/enrollment still absent;
- reverse proxy HTTPS profile;
- direct non-loopback HTTP is unsafe opt-in;
- no direct TLS in Phase 7.

## 11. Acceptance criteria

M004 closes only when:

1. embedded assets are binary-contained/self-contained;
2. serve lifecycle/shutdown is deterministic;
3. sessions survive serve restart and honor revocation/expiry;
4. actual HTTP + worker + SQLite + netd integration passes;
5. Host/Origin/CSRF/rate-limit security remains load-bearing in E2E tests;
6. saturation is bounded;
7. all existing rootful network/durable suites remain green;
8. no privileged capability appears in serve;
9. no unresolved high/medium security finding remains;
10. docs accurately state Phase 8 is still pending.

## 12. Stop conditions

Stop and write a corrective/ADR if Phase 7 needs peer/client CRUD to prove the substrate, HTTP service requires direct CAP_NET_ADMIN, session persistence conflicts with backup/restore semantics, graceful shutdown cannot bound worker/HTTP tasks, or security headers/origin policy require trusting forwarded headers.

## 13. Closure evidence

Record embedded asset inventory, process topology, shutdown trace, real HTTP auth/session restart flow, rootful HTTP→health/netd fixture, saturation results, footprint measurements, static guards, all CI, Phase 7 closed/conditional disposition, and Phase 8 readiness recommendation.


---

## Closure note

Closed at `d5d5ca9` with disposition **closed**. All ten acceptance criteria in
§11 are met and none of §12's stop conditions was reached.

Two defects were found and corrected in work this milestone was meant to
qualify, both of which the code alone would not have revealed:

* `serve` could not be stopped by a process supervisor. `ctrlc` handles `SIGINT`
  by default and puts `SIGTERM`/`SIGHUP` behind its `termination` feature, which
  was not enabled, so the long-running role died *from the signal* and skipped
  stop-accepts / drain / stop-worker / close-DB entirely. Found by asserting the
  exit status on the real binary.
* `ManagementHealth::netd_reachable` is derived from recorded convergence
  evidence, so a fresh installation reported the backend as unreachable whether it
  was up or down — §4 requires an operator to be able to tell those apart. A live
  read-only `Ping` was added on the authenticated route only; an unauthenticated
  caller must not be able to make the process dial the privileged backend.

Three findings were accepted rather than changed: `/healthz` reports the record
and can be stale about a backend that died since the last reconcile; a `Shutdown`
confirmation can miss its reply deadline after a saturated burst although the
thread is joined unconditionally either way; and the worker queue cannot be
saturated through HTTP, because the login limiter is always the binding
constraint. Full evidence, the footprint measurements, and the Phase 8 readiness
recommendation are in the closure record.

Carry-forward to Phase 8: the perimeter guards apply unchanged to the first
configuration-mutating route, a CRUD route needs a deliberately chosen body bound
rather than an inherited one, and the login limiter's global budget will need
re-sizing against whatever CRUD costs.
