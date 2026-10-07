# Management Service M002 Closure — Local Administrator and Session Persistence

Status: closed.

Planning baseline: `plans/implementation/management-service/002-local-admin-and-session-persistence.md`.
Repository baseline at implementation start: `66daa9d`.
Final implementation head: `60d1482`.
Disposition: **closed**.

## Outcome

M002 is strictly closed. The local administrator credential and server-side
session primitives exist, are fully qualified, and are reachable only through
the bounded management worker. **No HTTP route was added**: the surface still
publishes exactly `GET /healthz`, which is the plan's tenth acceptance criterion.

Every acceptance criterion in the plan is met. Two things are recorded below
rather than glossed over: the Phase 6 simulated-migration harness had to be
removed rather than extended, and the measured Argon2 cost is high enough that
M003's throttling ordering is a correctness requirement rather than a nicety.

## Dependency evidence

| Crate | Version | MSRV | Notes |
|---|---|---|---|
| `argon2` | 0.6.0 | 1.85 | Default features: PHC self-describing verifier + `getrandom` salt source |
| `sha2` | 0.11.0 | 1.85 | Session token digests |
| `getrandom` | 0.3.2 | 1.63 | OS CSPRNG for session and CSRF token entropy |

`cargo +1.89.0 check --all-targets --locked` passes, so the auth dependencies do
not raise the MSRV. All three are well under 1.89.

No JWT library was added, as the plan requires. `cookie` was deliberately **not**
added either: cookie parsing and serialization are M003's concern, and adding a
dependency now would mean qualifying it with no consumer.

New transitive dependencies: `blake2`, `base64ct`, `phc`, `digest`, `crypto-common`,
`block-buffer`, `cpufeatures`, `generic-array`, `typenum`, `subtle`, `constant_time_eq`.

## Requirement-to-evidence matrix

| Plan requirement | Evidence |
|---|---|
| §2 `argon2` 0.6, `sha2` 0.11, direct CSPRNG, no JWT | Table above. `the_management_http_surface_ships_no_router_or_client_crate` remains green; no signing or token library was introduced. |
| §3 typed/redacted `PrincipalId`, `SessionId`, `SessionToken`, `CsrfToken`, `PasswordVerifier` | `PrincipalId` and `SessionId` in `domain::identifiers`; the rest in `domain::auth`. `secret_values_redact_ordinary_debug_and_display` proves `Debug` and `Display` never emit a password, a verifier, a token, or a CSRF value. `PrincipalRecord`'s `Debug` is hand-written for the same reason. |
| §4 real `002_auth_sessions.sql` with `admin_principals` and `admin_sessions` | `src/state/migrations/002_auth_sessions.sql`, registered as production migration 2. `a_migration_fixture_is_a_real_v1_database` pins that the list contains exactly versions 1 and 2 and no test-only marker. |
| §4 auth/session changes must not modify `desired_generation` | `auth_writes_never_advance_the_desired_generation` covers the full lifecycle in-process; `authentication_across_the_worker_never_advances_the_desired_generation` covers it through the real worker queue and then re-opens the file. |
| §4 the migration runner takes a pre-migration recovery snapshot for a real v1 store | `the_upgrade_takes_a_recovery_snapshot_holding_the_v1_schema` asserts the snapshot exists at version 1, is `0600`, and that the live file has moved to version 2. |
| §5 Argon2id, m ≥ 19 MiB, t = 2, p = 1 | `the_configured_policy_meets_the_management_roadmap_minimums` and `the_argon2id_policy_is_the_roadmap_minimum`. The parameters are named constants, not literals buried in a call. |
| §5 store the PHC string so algorithm/parameters/salt are self-describing | `a_verifier_round_trips_and_is_never_the_plaintext` asserts the `$argon2id$v=19$m=19456,t=2,p=1$...` shape; `a_verifier_adopted_from_storage_still_verifies` proves a verifier written earlier still verifies. |
| §5 no composition rules; minimum length; explicit upper bound; UTF-8 bytes; no silent truncation | `the_password_policy_bounds_input_without_truncating` and `unicode_passwords_are_measured_as_utf8_bytes`. A 4-character/12-byte CJK password is accepted; a 3-character/9-byte one is refused. |
| §5 credential failure must not expose whether username or password was wrong | `credential_failure_never_distinguishes_username_from_password` and `a_disabled_principal_fails_authentication`. Storage failures during the pre-verification lookup collapse into the same answer, so the timing difference between "no such user" and "wrong password" — which Argon2 would otherwise expose — cannot exist either. |
| §6 local `admin set-password --password-stdin` and `admin status` | `src/main.rs`. `the_admin_cli_offers_no_argv_or_environment_secret_path` forbids `std::env`, forbids a `password` argument, and requires the explicit flag. |
| §6 password reset revokes all sessions | `reset_password_and_revoke_sessions` is one `IMMEDIATE` transaction; `a_password_reset_revokes_every_prior_session` and `a_password_reset_across_the_worker_revokes_every_session` prove it through both layers. |
| §6 output never prints verifier/token | `status_never_carries_a_credential`, `a_one_shot_admin_command_never_reports_a_credential`, and `the_raw_token_is_absent_from_the_database_after_a_worker_login`. |
| §7 256-bit token, SHA-256, 256-bit CSRF, persist digest + CSRF + expiry, return raw once | `a_session_token_has_256_bits_of_entropy_and_stores_only_its_digest`, `a_csrf_token_has_256_bits_of_entropy`, `distinct_tokens_never_collide`, and the worker-path integration test. |
| §7 raw session token never enters SQLite | `a_raw_session_token_has_no_path_into_the_database` — the persistence layer cannot even name the raw type — plus a file-bytes search in `the_raw_token_is_absent_from_the_database_after_a_worker_login`. |
| §7 finite lifetime, no remember-me | `DEFAULT_SESSION_LIFETIME` is 12 hours and `a_session_lifetime_is_bounded_and_cannot_be_instant` asserts both the finite bound and the week-long ceiling. |
| §8 authenticate / create / resolve / revoke / revoke-all / remove-expired | Six worker commands plus `AuthService`. Each is exercised through the real bounded queue in `the_worker_owns_credential_and_session_operations`. |
| §8 lookup hashes the presented token before querying | `find_session_by_digest` accepts only a `SessionTokenDigest`; `resolve_session` computes it from the presented string. `the_digest_is_what_is_looked_up_not_the_token`. |
| §9 typed auth/session worker commands; no HTTP route in M002 | `WorkerCommand` gained eight typed variants with a new `AuthFailure` reply type. `routing_is_an_exact_match` still finds only `/healthz`. |
| §9 the worker owns Argon2 and auth DB calls; the queue stays bounded | `management::auth` holds no `tokio::` and runs on the worker thread; `the_management_worker_queue_is_bounded` still passes. `authentication_is_reached_only_through_the_bounded_worker` forbids `argon2`/`PasswordVerifier` in the HTTP boundary and keeps `domain::auth` pure. |
| §10 real v1→v2 preserves identity, generation, state, convergence evidence | `an_upgrade_preserves_installation_identity_and_typed_state` (in-crate, over the production store opened at v1) and `a_real_v1_database_upgrades_to_v2_and_preserves_desired_state` (integration, over a file built from `001_initial.sql`). |
| §10 pre-migration snapshot contains v1 state | `the_upgrade_takes_a_recovery_snapshot_holding_the_v1_schema`. |
| §10 migration failure preserves the original database | `a_v1_database_that_cannot_migrate_is_left_at_version_one` plants a dangling foreign key, and asserts the open fails closed, the file stays at version 1, and neither auth table exists afterwards. |
| §10 Argon2 PHC round-trip and policy parameters | §5 rows above. |
| §10 password hash never equals plaintext | `a_verifier_round_trips_and_is_never_the_plaintext`, `a_raw_password_is_never_persisted`, and a file-bytes search. |
| §10 session token digest stored, raw token absent | `the_raw_token_is_never_persisted_only_its_digest` and the file-bytes integration test. |
| §10 CSRF token redaction | `secret_values_redact_ordinary_debug_and_display`. |
| §10 expiry; logout/revoke; reset revokes sessions | `an_expired_session_is_removed_rather_than_left_to_rot` (deterministic: expiry is evaluated against an explicit `now`, so the rule is proven without sleeping and without trusting a clock), `logout_revokes_the_session_immediately`, and the reset rows. |
| §10 disabled principal fails | `a_disabled_principal_fails_authentication`. |
| §10 password/session values absent from Debug/errors | `secret_values_redact_ordinary_debug_and_display`, `no_authentication_value_can_reach_a_database_query_as_plaintext`, `status_never_carries_a_credential`. |
| §11 Argon2 latency and memory recorded on CI | `argon2id_cost_evidence_is_printed_for_ci` prints parameters and per-sample timings under `--nocapture`, and asserts the cost stays inside a band. |
| §12.2 Rust 1.89 with auth deps | `cargo +1.89.0 check --all-targets --locked` passes. |
| §12.10 no HTTP login route exists yet | `/healthz` is still the only route; `routing_is_an_exact_match` is unchanged. |

## Verification actually run

All commands were run from the repository root on the final implementation head.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --all-targets --locked` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass, no warnings |
| `cargo test --locked` | pass — 183 lib + 22 architecture guards + 15 auth/session + 30 state store + 20 backup/restore + 9 management HTTP + 5 + 3 + 2, no failures |
| `cargo +1.89.0 check --all-targets --locked` | pass |
| `cargo test --locked --test privileged_protocol` | pass — 2 tests |
| `sudo cargo test --locked --features linux-integration --test wireguard_kernel` | pass — 2 tests |
| `sudo cargo test --locked --features linux-integration --test durable_owner` | pass — 10 tests |
| `sudo cargo test --locked --features linux-integration --test durable_restart` | pass — 9 tests |
| `sudo cargo test --locked --features linux-integration --test durable_backup` | pass — 2 tests |

The four rootful suites matter more than usual here: M002 changed the production
schema, so the real restart-recovery and restored-database fixtures are what
prove migration 2 does not disturb reconciliation, ownership, or WireGuard
behaviour.

## Argon2 cost evidence

Measured on the reference development machine, three samples:

```text
argon2id: m=19456 KiB t=2 p=1 hash=318.194004ms verify=306.506715ms
argon2id: m=19456 KiB t=2 p=1 hash=299.117492ms verify=295.382798ms
argon2id: m=19456 KiB t=2 p=1 hash=295.246489ms verify=295.106841ms
argon2id mean over 3 samples: hash=304.185995ms verify=298.998784ms memory=19456 KiB
```

~300 ms per verification, 19 MiB. That is a genuine work factor, and it is also
the single most important number for M003: see "Carry-forward for M003" below.

No ARM64 or SBC runner was available, so no advisory low-power figure was
captured. The plan explicitly forbids weakening the minimum parameters to hit a
latency target, and nothing here weakened them.

## The simulated-migration harness was removed, not extended

Phase 6 shipped exactly one migration, so its closure record qualified the
migration runner through a `#[cfg(test)]`-only step stamped at version 2, and
said explicitly that no closure claim could read it as evidence of a real
upgrade. That harness was correct then and unusable now: a genuine migration 2
collides with its version stamp.

It was replaced rather than renumbered, because the whole point of M002 is a
real upgrade:

- `initialize_at_version` now filters the **production** migration list, so
  `initialize_at_version(path, 1)` builds a real version-1 database.
- `StateStore::open_without_migrating` and
  `schema::open_connection_without_migrating` exist only under `#[cfg(test)]`.
  Every public store entry point migrates on open, which is correct; a fixture
  needs the other side of that to write real rows into a file that is still at
  the old version.
- `the_runner_upgrades_a_historical_fixture_to_the_latest_version` no longer
  ends in a `SchemaTooNew` refusal. It ends in a successful production open,
  because version 2 is now one this binary supports.
- `a_schema_newer_than_the_binary_is_refused_rather_than_downgraded` stamps 3.

## Two pre-existing tests were made robust rather than updated

`tests/state_backup_restore.rs` asserted `receipt.schema_version == 1` and
`StateError::SchemaTooNew { supported: 1 }`. Both became false the moment a
second migration shipped, and both would have become false again at migration 3.

They now read the real head instead — the store's own `schema_version()`, and a
range check on the reported `supported` value. This is a correction to test
brittleness, not a change in what those tests assert about behaviour.

## Corrective change: `ManagementRuntime::store` narrowed to `pub(super)`

`ManagementRuntime::store()` was `pub` before M002 and had **no caller anywhere**
in the crate or its tests. With the credential code now needing the store from
the worker, the honest fix was to narrow the existing accessor rather than add a
second one: `pub(super)` makes it reachable from exactly one place, the worker
thread, which is the ADR-003 boundary enforced by the compiler instead of by a
review comment.

Nothing outside `management` can reach SQLite through it, and the HTTP boundary
cannot reach it at all.

## Security and ownership evidence

- No password is persisted in any form. Verified by reading the raw database
  file bytes and searching for the plaintext.
- No raw session token is persisted. The persistence layer cannot name the type,
  so this is a compile error rather than a review convention.
- `desired_generation` is provably untouched by authentication, through both the
  in-process service and the real worker queue.
- A refused login is not an overload. `WorkerError::Rejected.is_refusal()` is
  true and `is_overload()` is false, so a caller cannot retry it by accident —
  which at 300 ms per attempt would be a CPU denial of service.
- Argon2 runs only on the bounded worker. A login flood is refused with `503`
  rather than queued.
- Phase 7 still serves no TLS and no authentication on any HTTP route, because
  there is no authentication route.
- `the_management_role_never_becomes_an_http_surface` still passes with the
  broadened rule: no web stack in `management`, `tokio::` only in `worker.rs`.

## Documentation evidence

- `architecture/authentication.md` (new): schema, password policy, why only a
  digest is stored, why the CSRF token is stored in the clear, the
  indistinguishable-failure rule, and the bounded-worker rationale.
- `architecture/overview.md`, `README.md`, `docs/development.md`: current state,
  including that there is still no login route.
- `architecture/management-http.md`: unchanged, and still accurate.

## Known limitations

- There is no login route, no session cookie, and no authenticated endpoint. The
  primitives are proven but not yet exposed, by design.
- A TTY password prompt was not added. The plan calls it optional and
  conditional on justifying a dependency; `--password-stdin` satisfies the
  requirement without one.
- Phase 7 supports exactly one local administrator. A second distinct username
  is refused rather than silently creating an unlisted way in.
- `measure_verification` reports a hash and a verify cost from the same
  reference machine, in debug builds. A release build would be faster; the number
  is recorded as an observation, not a specification.
- Expiry is proven against an injected `now` rather than by sleeping. That is
  stronger evidence, but it means no test exercises the real wall clock
  advancing.

## Unresolved findings

None. No high, medium, or low finding is open against M002.

## Carry-forward for M003

**Argon2 at ~300 ms per verification makes throttling ordering a correctness
requirement, not a hardening nicety.** With one worker thread and a 5-second reply
deadline, roughly sixteen concurrent verifications fit inside the deadline and
everything beyond that becomes a `503`. The management roadmap already forbids
throttling *after* hashing; the measured cost is why that ordering is load-bearing
rather than stylistic.

M003 must therefore:

1. rate-limit on the **client address**, decided before the command is admitted
   to the worker queue, so a flood never reaches Argon2 at all;
2. size that limiter against ~300 ms per attempt, not against a request rate;
3. keep the queue bound as the second line of defence rather than the only one.

Everything else M003 needs is real rather than assumed: eight typed worker
commands with a closed `AuthFailure` vocabulary, a session record carrying the
CSRF token and expiry, and a `ResolvedSession` that is safe to render.
