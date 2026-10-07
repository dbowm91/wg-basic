# Management Service M003 Closure — Authenticated HTTP Security Perimeter

Status: closed.

Planning baseline: `plans/implementation/management-service/003-authenticated-http-security-perimeter.md`.
Repository baseline at implementation start: `bab6087`.
Final implementation head: `cfe6860`.
Disposition: **closed**.

## Outcome

M003 is strictly closed. The management surface is authenticated, the HTTP
security perimeter is closed, and **no Phase 8 route exists**. Every acceptance
criterion in the plan is met.

Three findings are recorded below rather than glossed over, because two of them
are defects in already-closed work and one is a correctness requirement that
turned out to be a property of the *design* rather than of the code:

1. **An M002 defect**: `wg-basic admin set-password` failed on a fresh install.
   Both one-shot commands used `StateStore::open`, which refuses a file that does
   not exist, so the command reported `the credential store is unavailable` on
   exactly the fresh install it exists to set up. The documented order is to
   provision the administrator *before* first start, so this broke the documented
   workflow outright. M002's closure did not catch it because its tests used a
   store that something else had already created.
2. **A timing oracle left open by M002**: an unknown username returned in
   microseconds while a wrong password took ~300 ms. Plan §10 requires a dummy
   verifier for exactly this, and M002's closure record asserted the distinction
   could not exist — reasoning that was right about the *answer* and wrong about
   the *cost*. A fixed Argon2 verifier now runs on every failed lookup.
3. **The limiter-before-hashing ordering is a property of the code, not of a
   test.** The M002 carry-forward said throttling after hashing is "measurably an
   availability defect"; that turned out to understate it. It is an architecture
   guard, because a timing test cannot catch a refactor that moves the call.

## Dependency evidence

| Crate | Version | MSRV | Notes |
|---|---|---|---|
| `cookie` | 0.18 | 1.63 | `Set-Cookie` serialisation and request parsing only |

`cargo +1.89.0 check --all-targets --locked` passes, so the dependency does not
raise the MSRV.

**No JWT, OAuth, OpenID, PASETO, or session-middleware crate was added**, and
`the_management_surface_ships_no_token_or_oauth_dependency` enforces it. The
session bearer is an opaque 256-bit random token persisted only as a SHA-256
digest. A JWT would add a second, self-validating credential system with its own
key management — strictly more attack surface for no property this appliance
needs — and would make revocation impossible without a denylist, which is the
opposite of what `admin set-password` promises.

No router, no template engine, no HTTP client, and no external asset was added.

## Requirement-to-evidence matrix

### §2 Cookie support

| Requirement | Evidence |
|---|---|
| `cookie` 0.18 adopted; MSRV verified | Table above; `cargo +1.89.0 check --all-targets --locked` passes. |
| `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, finite `Max-Age` | `the_session_cookie_cannot_lose_its_defining_attributes` requires `.http_only(true)`, `.path("/")`, `SameSite::Strict`, `.max_age(` in shipped code, and forbids `.domain(` anywhere. `a_login_cookie_reaches_the_response_without_being_readable_by_a_script` checks the rendered header. The observed wire header is recorded below. |
| HTTPS external origin: `Secure` and `__Host-` name | `a_reverse_proxy_origin_gives_the_secure_cookie_profile`; on the wire, `the_cookie_profile_follows_the_canonical_origin_not_the_connection` observes `__Host-wg_basic_session=…; Secure`. |
| Direct loopback HTTP: host-only, non-prefixed, no false `Secure` claim | `a_loopback_deployment_never_claims_a_secure_transport` asserts no HSTS on a loopback deployment; the loopback login header observed on the wire is `wg_basic_session=…` with no `Secure` and no prefix. |
| Explicit local-only documentation | `architecture/management-http.md` origin-policy table and `docs/development.md` "Serving the management surface". |
| `Max-Age` matches server expiry | `session_set_cookie` takes the row's remaining lifetime; the observed header carried `Max-Age=43200` against a 12-hour `DEFAULT_SESSION_LIFETIME`. |

### §3 Routes

| Route | Requirement | Evidence |
|---|---|---|
| `POST /api/v1/login` | allowed `Host`, exact `Origin`, limiter admission | `an_unsafe_method_without_the_exact_origin_is_refused` (missing `Origin`, `null`, foreign, cross-site `Sec-Fetch-Site`), `a_throttled_login_does_not_answer_at_all`. |
| | issues session cookie; returns bounded metadata/CSRF | `a_correct_login_answers_once_and_only_once`; observed wire body carries `principal_id`, `session_id`, `expires_at`, `csrf_token` and nothing else. |
| | generic 401, no username/password distinction | `a_refusal_never_distinguishes_why_credentials_were_rejected` drives a wrong password, an unknown user, a non-JSON body, a wrong JSON shape, and an empty username, and asserts all five produce one identical `(status, body)`. |
| `POST /api/v1/logout` | session + `Host` + `Origin` + CSRF | `logout_without_a_csrf_token_changes_nothing` asserts `403` with no token and `403` with a wrong token, and that the session still authenticates after each. |
| | revokes, expires cookie | Observed on the wire: logout with the correct token returned `204` and the cookie's session then returned `401`. `revoking_a_session_makes_its_cookie_stop_working` proves the revocation through the API. |
| `GET /api/v1/session` | safe identity, expiry, CSRF | Observed wire body; `an_authenticated_route_refuses_an_unauthenticated_caller` covers the bare and forged-cookie cases. |
| | never returns password hash or bearer | The response body is built from a `SessionPayload` with no field for either; `session_values_redact_ordinary_debug_and_display` (M002) still passes, and the login body was read field by field on the wire. |
| `GET /api/v1/health` | session required; exactly `ManagementHealth` | `an_authenticated_route_refuses_an_unauthenticated_caller`. The health test asserts the body contains neither `password` nor `argon` in any case. |
| `GET /healthz` | unauthenticated, minimal | `an_ephemeral_loopback_bind_serves_the_health_route` asserts the body is exactly `ok` or `degraded`. |
| No peer/client CRUD | none exists | `routing_is_an_exact_match` matches exactly the five routes above; `no_module_outside_the_response_module_builds_a_management_response` and the closed `Route` enum make a hidden route a compile error. |
| `HEAD` answered nowhere | | `an_unsupported_method_is_refused_with_405_and_a_bounded_body` includes `HEAD` and asserts `405` with an empty body. |

### §4 Host validation

| Requirement | Evidence |
|---|---|
| Every request must carry an allowed `Host` | `a_rebinding_host_is_refused_before_routing` (on the wire, three foreign hosts, `403 forbidden`) and `a_rebinding_host_is_refused_for_every_route_and_method` (all four method/route combinations × eight hostile `Host` values). |
| Loopback mode allows only configured values | `the_allowed_host_set_is_not_a_wildcard` enumerates seven accepted and six refused spellings. |
| Unknown/malformed `Host` fails before route side effects | The `Host` check is step 2 of the pipeline in `route_request`, before `route()` is called at all. `a_foreign_host_is_refused_before_routing` additionally proves the accepted spelling still answers `200`, so the refusal discriminates rather than blanket-denying. |
| Do not derive trust from a loopback listener | This is the whole reason `OriginPolicy` exists and carries an explicit allowlist; `the_management_surface_never_trusts_a_forwarded_header` forbids reading any forwarded header. |

### §5 Origin / CSRF policy

| Requirement | Evidence |
|---|---|
| Unsafe methods require exact configured `Origin` | `only_the_exact_canonical_origin_is_accepted` enumerates one accepted and seven refused spellings; `an_unsafe_method_without_the_exact_origin_is_refused` observes `403` on the wire. |
| Authenticated unsafe requests require the CSRF token in a dedicated header | `an_unsafe_request_needs_the_exact_csrf_token`; `each_session_carries_its_own_csrf_token` proves another session's token is refused against this one. |
| Cookie + SameSite alone is insufficient | The header requirement is independent of the cookie, and `logout_without_a_csrf_token_changes_nothing` proves a valid cookie is not sufficient. |
| Reject missing/foreign `Origin`, invalid CSRF, missing CSRF, cross-site `Sec-Fetch-Site` | Four distinct refusal paths in `RequestGuard`, each covered by a named test. |
| No wildcard CORS; prefer none | `the_management_surface_emits_no_cors_header_at_all` forbids six CORS headers in shipped code across `src/http/`. `every_response_kind_carries_the_security_headers` and `assert_perimeter` assert zero CORS on the wire for success, 404, 405, and an authenticated-route refusal. |
| CSRF comparison does not early-exit | `check_csrf` accumulates differences and compares once; documented on the function. |

### §6 Login throttling

| Requirement | Evidence |
|---|---|
| Bounded in-memory bucket semantics before Argon2 | `limiter_before_hashing` in `tests/authenticated_api.rs`, measured: a throttled attempt must complete in under a tenth of an unthrottled login. Both ends are the worst case of five samples so the comparison survives a loaded machine. |
| Global limiter | Global bucket 20 burst / 2 per second; `the_global_bucket_is_charged_before_the_peer_bucket`. |
| Raw transport-peer limiter | Per-peer bucket 8 / 1 per second, keyed on the transport-observed `SocketAddr`, never a forwarded header. |
| Bounded peer map/cardinality | 1024 entries with LRU eviction; `the_limiter_peer_map_is_bounded` is an architecture guard, and `the_peer_map_is_bounded` asserts it at runtime. |
| 429 + `Retry-After` | Observed on the wire: `HTTP/1.1 429 Too Many Requests` with `retry-after: 1`. `a_refusal_always_carries_a_usable_retry_after` asserts the value stays in `1..=60` across nine bucket shapes, so a client is never told to retry immediately into a busy loop. |
| No persistent account lockout | The limiter holds no durable state and is built fresh per run; `each_run_gets_its_own_limiter`. A lockout persisted to disk would let anyone who can reach the login form permanently lock the operator out. |
| Test ordering so throttled requests do not hash | The measurement above, plus `the_login_limiter_is_consulted_before_the_worker_admits_the_command`, an architecture guard that asserts the call ordering textually. |

### §7 Bind / canonical origin configuration

| Requirement | Evidence |
|---|---|
| Default loopback bind | `DEFAULT_BIND` is `127.0.0.1:8000`; `an_ephemeral_loopback_bind_serves_the_health_route` asserts the socket is loopback. |
| Explicit canonical external origin | `--canonical-origin`; `an_acknowledged_routable_bind_is_built_with_a_restrictive_host_set`. |
| Loopback HTTP works by default | Observed: `wg-basic serve canonical origin http://127.0.0.1:8000, loopback listener (bind loopback)`. |
| Reverse-proxy HTTPS with a loopback listener | `a_reverse_proxy_origin_gives_the_secure_cookie_profile`; `the_cookie_profile_follows_the_canonical_origin_not_the_connection` on the wire. |
| Forwarded headers remain untrusted | `the_management_surface_never_trusts_a_forwarded_header` forbids `x-forwarded-*`, `forwarded`, and the `effective_*` accessors. The runtime disables proxy trust outright. The guard deliberately permits `.forwarded_standard(false)` — turning the trust off is the correct move and must remain possible. |
| Non-loopback HTTP requires explicit unsafe acknowledgement | Four CLI refusals verified against the real binary: a routable bind alone, an acknowledgement without an origin, an HTTPS claim on a routable listener, and a non-HTTPS origin on a loopback listener. `a_non_loopback_bind_is_never_permitted_without_acknowledgement` is an architecture guard. |
| Startup output states the effective bind/origin mode | Observed on the real process for both the loopback and proxied shapes. |
| No direct TLS | `HttpsClaimWithoutProxy`; the doc comment states it. |

### §8 Security headers

| Requirement | Evidence |
|---|---|
| Applied centrally to application responses | `headers::seal` runs once, at the end of `ManagementService::dispatch`, on every path. `every_security_header_is_applied_from_one_place` is an architecture guard that fails if `seal` is called from more or fewer than one place. |
| The six required headers | `every_response_kind_carries_the_security_headers` asserts all five unconditional headers, plus `no-store`, on success / 404 / 405 / 401 on the wire, and asserts each appears **exactly once**. |
| `Cache-Control: no-store` on API/auth/session responses | `no-store` is set in `response::build`, the only construction path; `no_module_outside_the_response_module_builds_a_management_response` enforces it structurally. |
| HSTS only for an HTTPS canonical origin | `an_https_deployment_gets_hsts_and_no_loopback_deployment_does`; `a_loopback_deployment_never_claims_a_secure_transport`; observed `strict-transport-security` present only under the proxied profile. `includeSubDomains` is absent by test. |
| Do not expose framework/server versions | `the_listener_advertises_no_server_stack` asserts no `Server` header on the wire. Nothing in the surface names EggServe, Rust, Hyper, or wg-basic. |

### §9 Request/response bounds

| Requirement | Evidence |
|---|---|
| Per-route body limits below the EggServe hard ceiling | Login body 4 KiB against the transport's 16 KiB. |
| Login JSON only large enough for bounded fields | `check_password_policy` (12-byte floor, 1024-byte ceiling) runs before the hash; `an_over_long_login_candidate_is_refused_before_hashing` (M002) still passes. |
| Reject wrong `Content-Type` for JSON routes | `a_login_must_be_json_and_a_simple_form_is_never_accepted` enumerates four refused types plus the absent case; `a_form_encoded_login_is_refused` observes it on the wire. |
| No `multipart/form-data` | Same two tests. A form post is the cross-site request shape a CSRF token exists to stop, and a simple form cannot carry a custom header at all. |
| No request-derived file path | The service declares `RequestBodyPolicy::Buffer` for `/api/v1/login` and `Reject` for every other route; `a_body_bearing_request_never_reaches_application_work` shows the transport refuses the body. No route maps a request value to a filesystem path. |

### §10 Auth failure timing

| Requirement | Evidence |
|---|---|
| Fixed dummy Argon2 verifier when no admin is configured | `the_one_shot_commands_work_on_a_path_nothing_has_opened` provisions through a fresh path; `reject_without_principal` runs on every `Ok(None) | Err(_)` branch. |
| …and when the username does not match | Same branch. |
| Keeps gross existence differences out of the browser surface | `an_unknown_username_costs_a_verification_rather_than_being_free` compares the two refusals directly: the unknown username must land within 8× of a wrong password. The window is deliberately wide — a skipped hash is three orders of magnitude cheaper and cannot hide inside it — and both ends are the worst of five samples so a scheduling hiccup cannot decide the result. The same comparison passes in debug and in release. |
| Do not claim perfect constant-time HTTP behaviour | Stated in the test's own comment and in `docs`/`architecture`. The claim is "same order of magnitude", and nothing asserts otherwise. |
| The constant is not a credential | `the_timing_equaliser_is_never_any_principals_verifier` asserts no plausible password verifies against it and that a provisioned administrator never holds it. The plaintext was 48 bytes from the OS CSPRNG at generation time and was discarded; `a_failed_login_lookup_always_spends_one_argon2_verification` forbids the string `wg-basic-equaliser-` from appearing anywhere in the repository. |

### §11 Tests

All fifteen required wire-level cases are covered. `tests/management_http.rs`
speaks real HTTP/1.1 over a real TCP socket to a real EggServe runtime (18 tests);
`tests/authenticated_api.rs` drives the assembled API over a real worker (13
tests).

| Required case | Test |
|---|---|
| login success / failure | `logout_without_a_csrf_token_changes_nothing` (success path) / `a_refusal_never_distinguishes_why_credentials_were_rejected` |
| missing / foreign `Host` | `an_unsafe_method_without_the_exact_origin_is_refused` / `a_foreign_host_is_refused_before_routing` |
| missing / foreign `Origin` | `an_unsafe_method_without_the_exact_origin_is_refused` |
| cookie flags under HTTP vs HTTPS origin | `the_cookie_profile_follows_the_canonical_origin_not_the_connection` |
| unauthenticated protected route | `an_authenticated_route_refuses_an_unauthenticated_caller` |
| CSRF missing / wrong / correct | `logout_without_a_csrf_token_changes_nothing` covers missing and wrong with the session proven still live; the correct case is the observed `204` |
| logout revocation | `revoking_a_session_makes_its_cookie_stop_working` and the observed `204` then `401` |
| session expiry | `an_expired_session_stops_authenticating` — a row with an expiry an hour in the past is written through a second store connection and the cookie naming it is refused on the wire, which is the same path a twelve-hour wait would take |
| no CORS | `the_management_surface_emits_no_cors_header_at_all` (guard) + `assert_perimeter` on the wire |
| all security headers | `every_response_kind_carries_the_security_headers` |
| limiter saturation | `a_throttled_login_does_not_answer_at_all`; observed twelve consecutive logins answered `200 ×10, 429 ×2` |
| limiter before Argon2 | `limiter_before_hashing` |
| large body / wrong content type | `a_body_bearing_request_never_reaches_application_work` / `a_form_encoded_login_is_refused` |
| generic errors | `a_refusal_never_distinguishes_why_credentials_were_rejected` |
| health exposes only `ManagementHealth` | `logout_without_a_csrf_token_changes_nothing` asserts the body contains no `password` and no `argon` |
| DNS-rebinding-style `Host` mismatch | `a_foreign_host_is_refused_before_routing` |

### §12 Acceptance criteria

All eleven are met: (1) `an_ephemeral_loopback_bind_serves_the_health_route` plus the whole authenticated flow on a real runtime; (2) the cookie-profile tests above; (3) `a_rebinding_host_is_refused_for_every_route_and_method`; (4) `an_unsafe_method_without_the_exact_origin_is_refused`; (5) `logout_without_a_csrf_token_changes_nothing`; (6) `limiter_before_hashing` plus the ordering guard; (7) the CORS guard; (8) the sealing guard plus the header tests; (9) the four CLI refusals, verified against the real binary; (10) `routing_is_an_exact_match`; (11) the verification table below.

## Verification actually run

All commands were run from the repository root on the final implementation head
`cfe6860`.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check --all-targets --locked` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass, no warnings |
| `cargo test --locked` | pass — 383 tests, no failures |
| `cargo test --locked` (three consecutive runs) | pass — 383 / 383 / 383, no flakes |
| `cargo test --locked` under 8 concurrent CPU spinners on 16 cores | pass, three runs |
| `cargo test --locked --release --lib management::auth` | pass — the timing assertions are mode-independent |
| `cargo +1.89.0 check --all-targets --locked` | pass |
| `cargo test --locked --test privileged_protocol` | pass — 2 tests |
| `sudo cargo test --locked --features linux-integration --test wireguard_kernel` | pass — 2 tests |
| `sudo cargo test --locked --features linux-integration --test durable_owner` | pass — 10 tests |
| `sudo cargo test --locked --features linux-integration --test durable_restart` | pass — 9 tests |
| `sudo cargo test --locked --features linux-integration --test durable_backup` | pass — 2 tests |

The four rootful suites are re-run against the unchanged Phase 6 schema on
purpose: M003 added no migration, so the correct result is that the real
restart-recovery, restored-database, ownership, and WireGuard fixtures behave
exactly as before.

### CLI behaviour verified against the real binary

```text
$ wg-basic serve --http-bind 0.0.0.0:8000
wg-basic: a routable bind serves the management surface to the network; pass
--allow-non-loopback together with --canonical-origin to say so

$ wg-basic serve --http-bind 0.0.0.0:8000 --allow-non-loopback
wg-basic: --allow-non-loopback also needs --canonical-origin, so there is
something to check Host and Origin against.

$ wg-basic serve --http-bind 0.0.0.0:8000 --allow-non-loopback \
    --canonical-origin https://vpn.example.com
wg-basic: a routable listener cannot claim an https origin without TLS; terminate
TLS in a reverse proxy and keep the listener on loopback

$ wg-basic serve --http-bind 127.0.0.1:8000 --canonical-origin http://vpn.example.com
wg-basic: `http://vpn.example.com` is not an https origin, and the listener is
loopback. Either drop --canonical-origin to use the loopback origin, or pass
--allow-non-loopback to say the bind is routable.

$ wg-basic serve --http-bind 127.0.0.1:8000 \
    --canonical-origin https://vpn.example.com
wg-basic serve listening on http://127.0.0.1:8000
wg-basic serve canonical origin https://vpn.example.com, loopback listener (bind loopback)
wg-basic serve startup reconciliation: nothing to apply
```

### Full authenticated flow observed on the wire

Against the real `wg-basic serve` process on loopback, with the administrator
provisioned through `admin set-password --password-stdin`:

```text
GET /healthz  Host: evil.example.com      -> 403 forbidden
POST /api/v1/login, no Origin             -> 403 forbidden

POST /api/v1/login (correct Host, Origin, Content-Type)
HTTP/1.1 200 OK
content-type: application/json
cache-control: no-store
set-cookie: wg_basic_session=cjsU4IO4jWK-UcBC29_teHc_xdY9o6jq3_b6nnJzN_4; HttpOnly;
            SameSite=Strict; Path=/; Max-Age=43200
content-security-policy: default-src 'self'; object-src 'none'; base-uri 'none';
            frame-ancestors 'none'; form-action 'self'
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: no-referrer
permissions-policy: accelerometer=(), autoplay=(), camera=(), …

{"principal_id":"e2592244-…","session_id":"6c3d6f59-…","expires_at":1791438979,
 "csrf_token":"e0hhQTJyHpYO67y1KlKhMAnTWrqFg2G55OUwRgFZPGk"}

GET  /api/v1/session    -> 200 (same shape)
POST /api/v1/logout, no x-wg-basic-csrf   -> 403 forbidden, session still live
POST /api/v1/logout, wrong x-wg-basic-csrf -> 403 forbidden, session still live
POST /api/v1/logout, correct token         -> 204
GET  /api/v1/session afterwards           -> 401 unauthorized
```

Twelve consecutive logins from one peer: `200 200 200 200 200 200 200 200 200 200
429 429` — the per-peer burst of 8 plus refill over the ~300 ms each Argon2
verification costs. The `429` carries `retry-after: 1`.

Under the proxied profile the same flow yields
`set-cookie: __Host-wg_basic_session=…; Secure; …` and
`strict-transport-security: max-age=63072000`, on the **same plain-HTTP
transport** — which is what proves the profile follows configuration rather than
the connection.

## Argon2 cost evidence

The M002 carry-forward figure, re-measured on the reference machine:

```text
release: argon2id m=19456 KiB t=2 p=1 hash=23.13ms  verify=15.67ms
release: argon2id m=19456 KiB t=2 p=1 hash=13.88ms  verify=13.39ms
release: argon2id m=19456 KiB t=2 p=1 hash=14.27ms  verify=13.64ms
debug:   argon2id m=19456 KiB t=2 p=1 hash≈300ms    verify≈300ms
```

The limiter's global bucket is sized against the **slow** figure, not the fast
one. Against 14 ms, a burst of 20 would cost 0.3 s — comfortably inside the 5 s
worker deadline, so the surplus would be absorbed by the queue and never
actually refused, which would make the limiter decorative in the shipped binary.
Against 300 ms, 20 × 0.3 = 6 s exceeds the deadline, which is the property the
plan asks for.

Sizing conservatively means a bucket that is too small refuses a legitimate
burst: a correctness question an operator can notice and wait out. A bucket that
is too large is a denial of service, which is the thing the limiter exists to
prevent. It also holds on a slower appliance than the reference, which is the
case that matters. `the_default_shape_matches_the_measured_argon2_cost` states
both figures and both arguments.

The M002 parameter minimums were not weakened to hit any latency target.

## Corrective change 1: `admin set-password` on a fresh path

M002's `set_password_at` and `status_at` opened the store with
`StateStore::open`, which uses `OpenIntent::Reopen` and refuses a file that does
not exist. `StateStore::initialize` is the path that creates one. The service
runtime already had the right answer in `open_store`: try `open`, fall back to
`initialize` on `MissingParent`. The one-shot commands did not.

The consequence: the documented workflow — provision the administrator before
first start — returned `the credential store is unavailable` at every step. The
error text also misdiagnosed the cause, since it named the credential store
rather than the missing database.

Both commands now share `open_or_initialize`, matching `open_store` exactly.
Covered by `the_one_shot_commands_work_on_a_path_nothing_has_opened` (which also
proves a second invocation is a reset rather than an initialise error, and that
the old password stops working) and `status_on_a_fresh_path_reports_no_administrator_rather_than_failing`.

M002's closure did not catch this because its tests opened a store that
something else had already created. The regression tests now start from a path
nothing has opened, which is the case the command is for.

## Corrective change 2: the username oracle

M002's closure asserted that "the timing difference between *no such user* and
*wrong password* — which Argon2 would otherwise expose — cannot exist either."
That reasoning was about the *answer*: both returned `CredentialsRejected`. It
was wrong about the *cost*. An unknown username took a microsecond; a wrong
password took 300 ms. That gap is a username oracle, and it is far larger and
far more reliable than anything a response body could leak.

`AuthService::authenticate` now spends one Argon2 verification against a fixed
dummy verifier on every refusal that finds no usable principal — unknown
username, storage failure, disabled account — and then refuses identically. The
plaintext behind the constant was 48 bytes from the OS CSPRNG at generation time
and was discarded, so no future edit can promote it into a credential somebody
could present. It is parsed once behind a `OnceLock`, because parsing the PHC
string per failed login would be a second, smaller signal.

Plan §10 required this and M002 did not do it. Recorded here rather than folded
into the main narrative because it is a defect in already-closed work.

## The limiter ordering is enforced structurally

M002's carry-forward said throttling after hashing is "measurably an
availability defect". It is, but a measurement is a weak guarantee: a refactor
that moves one statement would break the property and leave the test passing on
a fast machine. So the ordering is also an architecture guard,
`the_login_limiter_is_consulted_before_the_worker_admits_the_command`, which
asserts the call order in `src/http/api.rs` textually.

The measurement still earns its place — it proves the cost difference is real
and orders of magnitude — but it is now corroboration rather than the only line
of defence.

## Security-header application is total by construction

A security header a route must remember to set is one route will eventually
forget. M003's first cut applied the headers inside a response builder, which
meant four separate literal constructors could each drift. The final shape
applies them **after** construction, in exactly one place:
`ManagementService::dispatch` wraps the completed answer.

That ordering is what makes it total. A `Response` does not exist until routing
has chosen one, and it cannot leave `dispatch` unsealed, so a route that builds
its own response or returns a bounded literal still comes out correct. A route
cannot opt out; a new route gets the headers by existing.

Three guards pin it: `Response::builder()` may only appear in `response.rs` and
`api.rs`; `.body(ResponseBody::` may only appear there either; and `seal` must
be called from exactly one place.

`a_response_sealed_twice_would_duplicate_rather_than_replace` deliberately
documents that a second seal would *append* rather than replace, because
`HeaderBlock` keeps repeated fields. It does not bless the double seal — it
records why the single call site matters, so the constraint is visible rather
than discovered later from a duplicated header on the wire.

## `src/http/` cannot name the storage module

The M001 guard `the_http_boundary_never_reaches_the_durable_store_or_the_kernel`
began failing when `api.rs` needed the session type the worker returns. Rather
than narrow the guard, `SessionRecord` and `StoredSession` were re-exported
through `crate::management`.

The guard is now strictly stronger than it was in M001: `src/http/` cannot name
`crate::state` at all, so it cannot be tempted into a path that looks like it
reaches the database and does not.

## Security and ownership evidence

- **No CORS, anywhere.** Zero CORS headers in shipped code and zero on the wire,
  for success, 404, 405, and 401. A browser cannot read any response
  cross-origin.
- **`Host` is the only source of authority.** No forwarded header is read; the
  runtime disables proxy trust outright. An architecture guard forbids reading
  `x-forwarded-*`, `forwarded`, or the `effective_*` accessors.
- **The route surface cannot grow by accident.** Routing is an exact match
  against a closed `Route` enum, so adding a route forces a decision about its
  method set at compile time.
- **Every response body is a bounded literal or a small JSON document.** No code
  path formats an error, a path, a socket address, or an internal type into a
  response body, enforced by the body-construction guard.
- **No framework disclosure.** No `Server` header; nothing in the surface names
  EggServe, Rust, Hyper, or wg-basic.
- **A refusal cannot become an overload.** A `429` is distinguishable from a
  `401` on purpose — a client must be able to tell "come back later" from "you
  are wrong" — but a refused credential is never `503`, so a client cannot retry
  it by accident, which at 300 ms per attempt would be a CPU denial of service.
- **No Phase 8 capability exists.** No peer, client, or interface route; no
  desired-state mutation; the kernel is untouched by any of this work.
- **Sessions are opaque and revocable.** The bearer is a 256-bit token stored
  only as a SHA-256 digest; revocation is immediate, proven through the API and
  on the wire.

## Documentation evidence

- `architecture/management-http.md` (rewritten): the route table, the two
  boundaries, the ordered pipeline, the origin-policy table with its two
  load-bearing refusals, no CORS, the single-point header table, the limiter, the
  refusal vocabulary, the disclosure limits of `/healthz` and `/api/v1/health`,
  the configured limits table, fatal-versus-degraded startup, the lifecycle, and
  the command line including what a headless operator reads from the log.
- `architecture/authentication.md` (updated): the cookie attribute table and why
  a `Secure` cookie on plain loopback HTTP is the worst available failure mode;
  why `SameSite=Strict` alone is not the defence; why the login limiter sits
  where it does; why a login body is JSON and never a form; what a successful
  login publishes.
- `architecture/overview.md`, `README.md`: current state, including that no
  desired-state mutation route and no product UI exist.
- `docs/development.md`: a "Serving the management surface" section with the
  working `curl` login flow, the proxy deployment, and both refusals explained.
  Every command in it was executed against the real binary before being
  documented.

## Known limitations

- **Phase 7 terminates no TLS.** The HTTPS profile is for a reverse proxy in
  front of a loopback listener. There is no certificate handling, no client
  certificate support, and no HTTP/2 or HTTP/3 in front of the operator's own
  listener.
- **The listener is HTTP/1.1 only**, because EggServe's runtime is.
- **There is no embedded asset shell yet.** Nothing serves HTML, CSS, or
  JavaScript; the API is exercised with `curl`. That is M004.
- **There is no product UI**, and no route mutates desired state. This milestone
  deliberately stops at the perimeter.
- **The canonical origin is a single value.** There is no multi-origin
  redirect-URI validation, because there is no redirect URI: there is no OAuth
  flow and no third-party client.
- **Counters are in memory.** Restarting the service clears all limiter state,
  so an attacker who can restart the service gets a fresh budget. A persistent
  limiter was rejected deliberately — see above.
- **`admin set-password` still has no TTY prompt.** `--password-stdin` satisfies
  the requirement without one, as recorded in M002.
- **No ARM64 or SBC measurement** was available, so the ~14–23 ms release figure
  is x86-64 only. The limiter is sized against the debug/loaded figure precisely
  because the fast figure is not representative of a small appliance.
- **The timing assertions are ratio-based, not constant-time claims.** The plan
  explicitly does not claim perfect constant-time HTTP behaviour, and neither do
  the tests.

## Unresolved findings

None blocking. The following are recorded as accepted, with reasons:

| Severity | Finding | Disposition |
|---|---|---|
| Low | A spoofed source address behind a NAT is throttled as one peer, so several legitimate operators behind one NAT share an 8-burst budget. | Accepted. Widening the per-peer budget weakens the only per-source bound, and the global budget still caps the appliance's total cost. An operator behind a common NAT waits out a 1/second refill. |
| Low | `Sec-Fetch-Site` is honoured but never *required*. A non-browser client may omit every browser header and be refused on `Origin` alone. | Accepted. Requiring it would make the API unusable from `curl` and from the appliance's own tooling, and it is defence in depth rather than the primary check. |
| Low | The ephemeral-port listener matches any port on a loopback literal. | Accepted. Test and integration affordance only; the default bind is `127.0.0.1:8000`. The scheme and host must still match exactly, and a rebinding attacker owns a *name*, not a loopback literal. |
| Low | The global burst of 20 is sized against a debug-build Argon2 cost, so a release deployment refuses sooner than strictly necessary. | Accepted deliberately. See "Argon2 cost evidence". |

## Carry-forward for M004

- The embedded asset shell must be served by the same `dispatch`/`seal` path, or
  it becomes the one route that can ship without the security headers. If the
  asset shell is served from a separate origin or a reverse proxy, it must still
  go through `headers::seal`, and its CSP `script-src`/`style-src` will need to
  widen from the current `default-src 'self'` for inline asset hashes.
- The CSP is `default-src 'self'; object-src 'none'; base-uri 'none';
  frame-ancestors 'none'; form-action 'self'`. Anything the shell needs must be
  added deliberately and recorded here, not added by editing the header and
  discovering later that a rule was never tested.
- M004's readiness differentiation must not widen `/healthz`. It is unauthenticated
  and its body is exactly `ok` or `degraded`; a richer readiness payload would be
  a disclosure on a route anyone on the host can reach.
- The service lifecycle qualification can now start from a **running,
  authenticated** surface rather than a liveness-only one, so the restart and
  session-survival questions are answerable.
- The limiter's in-memory state resets on restart, which is correct. M004 should
  not add persistence for it.