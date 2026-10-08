# Management HTTP boundary and the bounded worker

This document describes **current implemented behaviour**. Phase 7's service
and security substrate is closed, and Phase 8 M001/M002 now expose the first
generation-safe product management API. Export, enrollment, telemetry, audit
query, and the product UI remain later Phase 8 milestones.

Architecture decisions behind this boundary are recorded in
[ADR-003](../plans/adr/003-management-http-auth-and-worker-boundary.md).
Credentials and sessions are in
[authentication](authentication.md).

## What exists today

`wg-basic serve` is the unprivileged management service role. It publishes the
authenticated service surface, product CRUD routes, one liveness probe, and the
embedded operator shell.

| Method | Path                | Auth    | CSRF     | Origin | Body |
| ------ | ------------------- | ------- | -------- | ------ | ---- |
| `POST` | `/api/v1/login`     | none    | none     | exact  | JSON ≤ 4 KiB |
| `POST` | `/api/v1/logout`    | session | required | exact  | none |
| `GET`  | `/api/v1/session`   | session | none     | —      | none |
| `GET`  | `/api/v1/health`    | session | none     | —      | none |
| `GET`  | `/api/v1/server`    | session | none     | —      | none |
| `POST` | `/api/v1/setup`     | session | required | exact  | JSON ≤ 8 KiB |
| `GET`  | `/api/v1/clients`   | session | none     | —      | none |
| `POST` | `/api/v1/clients`   | session | required | exact  | JSON ≤ 8 KiB |
| `GET`  | `/api/v1/clients/<canonical-uuid>` | session | none | — | none |
| `PATCH`| `/api/v1/clients/<canonical-uuid>` | session | required | exact | JSON ≤ 8 KiB |
| `POST` | `/api/v1/clients/<canonical-uuid>/enable` | session | required | exact | generation JSON ≤ 8 KiB |
| `POST` | `/api/v1/clients/<canonical-uuid>/disable` | session | required | exact | generation JSON ≤ 8 KiB |
| `DELETE` | `/api/v1/clients/<canonical-uuid>` | session | required | exact | generation JSON ≤ 8 KiB |
| `GET`  | `/healthz`          | none    | none     | —      | none |
| `GET`  | `/`                 | none    | none     | —      | none |
| `GET`  | `/assets/app.css`   | none    | none     | —      | none |
| `GET`  | `/assets/app.js`    | none    | none     | —      | none |

Login uses its 4 KiB bound. Product JSON mutations each use an explicit 8 KiB
bound; read routes accept no body. The three shell routes answer only `GET` and
are matched exactly from a closed table — there is no prefix rule, so `/assets/`
and `/assets/app.css.map` are `404`. Client IDs must be canonical lowercase
UUIDs, and dynamic routes require an exact segment count.

The product API is a thin typed-worker transport. Every unsafe request carries
`expected_generation`; a stale value returns `409` without a commit. A committed
mutation returns `200`/`201` when converged and `202` when enforcement is pending
or degraded. The JSON receipt names the committed generation and bounded
enforcement category. Ordinary server/client projections contain public
configuration metadata and public keys only; private keys are not representable
in those projection types. See [product management](product-management.md).

## What Phase 8 still owns

The following Phase 8 work is still absent:

* **No config export, QR, or enrollment flow.** The local administrator is
  provisioned by the CLI, never through the browser surface.
* **No live telemetry or audit query route.** `/api/v1/health` remains the
  service health projection; client activity is not exposed yet.
* **No product UI.** `/` remains the Phase 7 login shell and health readout.
* **No direct TLS.** Phase 7 terminates none; the HTTPS story is a
  TLS-terminating reverse proxy in front of a loopback listener.
* **No multi-user or roles.** Exactly one local administrator, no groups, no
  permissions model.

`HEAD` is answered nowhere. A probe that cannot distinguish `HEAD` from `GET` is
not this probe, and accepting a second method per route would set the precedent
that methods are added implicitly.

Everything else is a bounded `404 not found` or `405 method not allowed`.

## The two boundaries

The management process has exactly two HTTP-relevant boundaries and they do not
overlap.

```
src/http/                          src/management/
  mod.rs       ──┐                 worker.rs   ── owns ──> runtime.rs ──> StateStore / netd
  api.rs        ├──►               (bounded queue)              (only module that
  headers.rs     │                                              touches the store or netd)
  origin.rs      │
  ratelimit.rs   │
  response.rs    │
  session_cookie.rs
  assets.rs    ──┤   readiness.rs │
  service.rs   ──┘                 serve.rs
```

* `src/http/` owns the wire protocol: configuration and limits, origin policy,
  cookies, security headers, routing, status selection, and the process
  lifecycle. It may use EggServe primitives, the worker client, and safe
  configuration values.
* `src/management/worker.rs` owns the single OS thread that holds
  `ManagementRuntime`. It is the only way into management state.

`src/http/assets.rs` embeds the operator shell at compile time with
`include_str!`. There is no document root, no filesystem lookup at request time,
no external origin, and no build step: the three files in `src/http/assets/` are
the whole shell, 12,723 bytes in total. They need no inline script or style, so
the `default-src 'self'` policy every other response already carries applies to
them unchanged — the shell required no CSP concession, which was the point.

HTTP code never opens the database and never contacts `netd`. A request handler
reaching either would block a Tokio worker thread on synchronous disk I/O or on a
Unix socket round trip, and would be able to observe state the health projection
deliberately withholds. The `StoredSession` and `SessionRecord` types are
re-exported through `crate::management` precisely so `src/http/` never has to name
`crate::state` and be tempted down that path.

Architecture guards in `tests/architecture_guards.rs` enforce all of this.

## The request pipeline is an ordered contract

Every request crosses the same fixed sequence, and the order *is* the contract:

1. **Body policy** — decided by the transport *before* the service runs, so a
   read-only route can never make the process buffer attacker-chosen bytes.
2. **`Host`** — refused unless it is in the configured allowed set.
3. **Route** — an exact path match against a closed enum.
4. **Method** — refused unless the matched route answers it.
5. **`Origin`** — refused for an unsafe method that does not carry the exact
   configured origin.
6. **Session and CSRF** — for the authenticated routes.
7. **Handler**.

Steps 2 and 5 run before step 7 for **every** route. That is the point: a
security check that only some routes remember to perform is a check waiting to
be forgotten by the next route.

### Routing is a closed match

`route()` matches a request target against a closed enum, not a handler
closure, which keeps three properties checkable by reading one function:

* **Exhaustive** — adding a route without deciding its method set is a compile
  error, so "unknown method" cannot silently become a new capability.
* **Closed** — anything unmatched is `Route::Unknown`, a bounded `404`. No
  catch-all, no prefix match, no path-segment dispatch.
* **Body-declaring** — a route that accepts a body says so here and the
  transport enforces it.

`/healthz/` and `/api/v1/login/` are *unknown routes*, not near misses, so the
surface has no normalisation rules an attacker could lean on.

## Origin policy is configuration, not inference

A loopback listener is reachable by any process on the host and, through a
browser, by any page the operator visits. That is DNS rebinding. The request's
`Host` header is attacker-controlled in exactly that scenario, so "the socket is
loopback" is **not** evidence of who is asking. The operator therefore states an
allowed host set and a canonical external origin, and everything else follows.

| Deployment                          | Listener            | Canonical origin              | Session cookie                    |
| ----------------------------------- | ------------------- | ----------------------------- | --------------------------------- |
| Loopback HTTP (default)             | `127.0.0.1:8000`   | `http://127.0.0.1:8000`       | host-only, **not** `Secure`       |
| Reverse proxy in front (recommended)| `127.0.0.1:8000`   | `https://vpn.example.com`     | `__Host-` prefixed, `Secure`      |
| Acknowledged routable bind          | `0.0.0.0:8000`     | stated explicitly, plain HTTP | as per origin scheme              |

Direct TLS is **not** implemented in Phase 7. An `https` canonical origin means
a reverse proxy terminates TLS in front of a loopback listener, which is why
`OriginPolicy::behind_https_proxy` keeps the listener on loopback and only the
canonical origin external.

Two refusals are load-bearing:

* a **routable listener may not claim an `https` origin**. It terminates no TLS,
  so the claim would be false — and a false `Secure` cookie is a service that
  appears to authenticate and then silently fails.
* a **routable bind is refused outright** without `--allow-non-loopback` and a
  `--canonical-origin`. Accepting any `Host` is precisely the rebinding hole the
  policy exists to close, so the default degrades to *refusal*, never to
  permissiveness.

`Origin` is compared for exact scheme/host/port equality. `null` — what a
sandboxed or opaque origin sends, and exactly what an attacker wants — is always
refused.

### `Sec-Fetch-Site` is a second, unforgeable opinion

A request carrying `Sec-Fetch-Site: cross-site` is refused even when its `Origin`
matched. The browser sets that header and page JavaScript cannot forge it, so it
is decisive where `Origin` alone is a claim.

### Forwarded headers stay untrusted

`X-Forwarded-*` and `Forwarded` are ordinary untrusted headers. The runtime
disables proxy trust entirely, and no module in `src/http/` reads
`effective_authority`, `effective_client`, or `effective_scheme`. `Host` and
`Origin` come from configuration only.

## No CORS, at all

Not one CORS header is emitted, on any route, in any case. A browser therefore
cannot read any response cross-origin. That is a stronger position than any
allowlist and it costs nothing to maintain — and it means a future "just for the
asset shell" exception has to be argued for explicitly instead of appearing by
accumulation.

## Security headers are applied in one place

| Header                    | Value                                                              |
| ------------------------- | ------------------------------------------------------------------ |
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` |
| `X-Content-Type-Options`  | `nosniff`                                                          |
| `X-Frame-Options`         | `DENY`                                                             |
| `Referrer-Policy`         | `no-referrer`                                                      |
| `Permissions-Policy`      | every powerful feature explicitly `=()`                            |
| `Strict-Transport-Security` | `max-age=63072000` — **only** on an HTTPS canonical origin       |
| `Cache-Control`           | `no-store` on every response                                       |

A security header a route must remember to set is a header one route will
eventually forget. So `headers::seal` is applied in exactly one place — the end
of `ManagementService::dispatch` — on **every** return path: success, refusal,
unknown route, wrong method, and worker failure alike.

Sealing happens *after* construction rather than inside it, which is what makes
it total. A `Response` does not exist until routing has chosen one, and it does
not reach the wire until it has been through `seal`. A route that builds its own
response, or that returns one of the bounded literals, still comes out sealed.

HSTS is the one conditional header, and its condition is the **configured
canonical origin**, never the incoming connection: on a plain-HTTP loopback
listener it would poison a browser's cache for a host that legitimately serves
HTTP. `includeSubDomains` is deliberately absent — an appliance has no business
asserting HTTPS for an operator's whole domain.

Nothing here names EggServe, Rust, Hyper, or wg-basic. Combined with the absent
`Server` header, a probe learns nothing about the stack it is attacking.

## The login limiter runs before Argon2

Argon2id at the M002 policy costs ~19 MiB and ~300 ms per verification. One
worker thread services roughly sixteen verifications inside the five-second
reply deadline; everything beyond that is already a `503`.

So `LoginLimiter::check` is the **first** thing a login request does — before the
body is parsed, before the command is admitted to the bounded queue. A limiter
placed after the hash would be a denial of service wearing a rate limit's
clothes: the attacker would spend 300 ms of the appliance's CPU per request
before anything refused it. `limiter_before_hashing` in
`tests/authenticated_api.rs` proves the ordering by measurement — a throttled
attempt must return in under a tenth of an unthrottled login's time.

| Bucket          | Burst | Refill | What it defends                                    |
| --------------- | ----- | ------ | -------------------------------------------------- |
| Global          | 20    | 2/s    | The appliance's total verification rate             |
| Per transport peer | 8 | 1/s    | One host consuming the whole global budget          |

A throttled attempt is `429` with a `Retry-After` in `1..=60` seconds and the
body `too many attempts`. It is deliberately distinguishable from a refused
password: a client must be able to tell "come back later" from "you are wrong",
or the limiter is unusable.

The peer map is **bounded** (1024 entries) and evicts the least-recently-seen
peer when full. An unbounded map keyed by client address is a memory-exhaustion
vector by itself. Counters are in memory only: a lockout persisted to disk would
let anyone who can reach the login form permanently lock the operator out.

## The bounded worker

`ManagementRuntime` and `StateStore` are synchronous on purpose, and `netd`
requests block. Rather than let an async handler do that work, one dedicated OS
thread owns the runtime and callers submit typed commands through a **bounded**
`tokio::sync::mpsc` queue with one-shot replies.

"Bounded" is load-bearing. There is deliberately no unbounded channel and no
`spawn_blocking` escape hatch, so a flood of requests cannot become a backlog of
pending commands:

| Condition                    | Answer                                              |
| ---------------------------- | --------------------------------------------------- |
| Queue full                   | `503 unavailable` (admission refused, not awaited)   |
| No reply within the deadline | `503 unavailable`                                    |
| Worker stopped               | `503 unavailable`                                    |

The three are deliberately indistinguishable to a caller: a client that could
tell them apart would learn whether the appliance is merely slow or gone.

The command set and the reply types are closed enums, so adding an operation is
a deliberate, visible change.

## Every refusal is bounded and says nothing

| Condition                          | Status | Body                  |
| ---------------------------------- | ------ | --------------------- |
| `Host` absent or not allowed       | `403`  | `forbidden`           |
| `Origin` missing or foreign        | `403`  | `forbidden`           |
| `Sec-Fetch-Site: cross-site`       | `403`  | `forbidden`           |
| CSRF token missing or wrong        | `403`  | `forbidden`           |
| Body larger than the route bound   | `413`  | `request too large`   |
| Credentials rejected               | `401`  | `unauthorized`        |
| No session presented               | `401`  | `unauthorized`        |
| Login throttled                    | `429`  | `too many attempts`   |

A refused password, an unknown username, a disabled principal, a malformed
body, and an unknown session all render as **the same** `401 unauthorized`. If
they differed the surface would be a username oracle, and Argon2id's cost would
leak the difference anyway, because a refusal that skipped the hash would be
dramatically faster.

A refusal never names its own cause. Every response body on this surface is a
fixed literal; there is no code path that formats an error, a path, a socket
address, a generation, or an internal type into a response, so an error path
cannot leak by accident.

## What `/healthz` and `/api/v1/health` may disclose

`/healthz` answers `ok` or `degraded`, and nothing else. No installation ID, no
generation, no filesystem path, no desired-state fact, no backend failure detail.

Both classes are served with `200`. "Degraded" describes the appliance, not the
request: the request *was* answered. Serving it as `503` would conflate "the
thing you asked about is unhealthy" with "this endpoint is unavailable", and
would make a liveness probe restart a healthy listener.

`/api/v1/health` renders two things, but only to a caller that has already proven
a session:

```json
{
  "health":  { "database_healthy": true, "netd_reachable": false,
               "installation_id": "…", "current_desired_generation": 1,
               "last_converged_generation": 1, "convergence": "converged",
               "last_failure_category": null },
  "backend": { "answered": true, "service": "wg-basic-netd" }
}
```

`health` is the **record**: what stored evidence says. `backend` is one live,
read-only `Ping` over the authorized socket — what the backend says *now*.

Both are necessary, and neither subsumes the other. On a fresh installation that
manages an interface, `netd_reachable` is `false` because no reconcile had been
recorded when the snapshot was taken, while `backend.answered` is `true` because
netd is up. Collapsing them would leave an operator unable to tell "the backend is
down" from "nothing has been applied yet".

The probe costs a socket round trip, which is exactly why only the authenticated
route calls it. An unauthenticated caller must not be able to make this process
dial the privileged backend — so `/healthz` never probes, which has the
consequence, stated plainly: **`/healthz` reports the record and can be stale.**
A backend that dies after the last successful reconcile is invisible to
`/healthz` and visible immediately to `/api/v1/health`.

Neither payload has a receipt, error string, or key-material field, so neither
can carry one.

## Readiness is one lossy projection

`src/http/readiness.rs` holds the four states an operator has to tell apart, as
one exhaustive decision rather than four ad-hoc booleans:

| State                    | Meaning                                             | Listener |
| ------------------------ | --------------------------------------------------- | -------- |
| `Ready`                  | bound, answering, every observable dependency healthy | up     |
| `Degraded { unhealthy }` | bound and answering, but named dependencies are not  | up      |
| `Fatal { dependency }`   | the state could not be opened                        | never    |

`public_token()` reduces all of that to `ok` or `degraded`, and those two words
are literals in that module. Adding a dependency, or a reason, changes what the
operator's log says and cannot change what an anonymous caller receives — which
is the M003 carry-forward, enforced rather than merely intended.

Startup and runtime deliberately answer different questions:

* `Readiness::from_startup` asks *"did the mandatory startup work succeed?"*
* `Readiness::from_health` asks *"is the appliance healthy right now?"*

So a fresh install with nothing to apply and no netd listening is `Ready` at
startup and `Degraded` on `/healthz`. That is not a contradiction: there was
genuinely nothing to converge, and there is genuinely no evidence netd ever
answered.

## Configured limits

The defaults are management-surface defaults, not framework defaults. They are
written down in `src/http/config.rs` as named constants so they are reviewable as
product intent, and a test asserts that each one actually reaches the EggServe
runtime configuration.

| Limit                       | Default   |
| --------------------------- | --------- |
| Bind                        | `127.0.0.1:8000` |
| Concurrent connections      | 64        |
| In-flight requests          | 128       |
| Request headers             | 32 / 8 KiB |
| Request target              | 1 KiB     |
| Request body                | 16 KiB    |
| Login body (route bound)    | 4 KiB     |
| Header read timeout         | 5 s       |
| Body read timeout           | 5 s       |
| Handler timeout             | 10 s      |
| Response write timeout      | 10 s      |
| Keep-alive idle timeout     | 15 s      |
| Total connection lifetime   | 60 s      |
| Graceful shutdown grace     | 10 s      |
| Requests per connection     | 256       |
| Worker queue capacity       | 32        |
| Worker reply deadline       | 5 s       |
| Login global bucket         | 20 / 2 s  |
| Login per-peer bucket       | 8 / 1 s   |
| Login tracked peers         | 1024      |
| Session lifetime            | 12 h      |

The surface sets no `Server` header, no PROXY protocol, no trusted proxy, and
streams no files or tunnels.

## Startup: fatal versus degraded

Startup makes one unconditional reconciliation attempt, because stored
convergence evidence is a hint, not a reason to skip work — the kernel may have
drifted while the service was stopped.

| Startup condition                                  | Result                     |
| -------------------------------------------------- | -------------------------- |
| Store, path, or migration unusable                  | **Fatal** — no listener     |
| Projection of the desired snapshot fails            | **Fatal** — no listener     |
| `netd` unreachable, refusing, or conflicted         | **Degraded** — listener up  |
| Nothing to apply, or converged                      | Ready                       |

A netd outage is not fatal precisely because the operator needs the management
surface in order to see and fix it. The listener comes up, `/healthz` answers
`degraded`, and the reason is written to the service log rather than to an
unauthenticated HTTP response.

## Lifecycle and shutdown

`wg-basic serve` runs in this order, and the order is the contract — each step
depends on the previous one having succeeded:

1. validate the HTTP configuration and the origin policy — before any
   authority-bearing resource is opened, so a bad configuration cannot leave a
   half-started service holding the store;
2. start the worker, which opens the store and attempts the startup reconcile;
3. bind EggServe;
4. report readiness to the log, including the effective exposure mode and the
   classified readiness;
5. publish the startup snapshot to `run_publishing`'s callback, then serve;
6. on a signal: stop accepting, drain in-flight requests under the grace period,
7. stop the worker and join its thread, releasing the store,
8. exit `0`.

`run_publishing` exists so a supervisor — or a test that bound an ephemeral port
— can act on the startup snapshot without waiting for shutdown. It is a
parameter, not a global, so publishing readiness cannot be added for one
deployment and forgotten for another.

The worker is stopped and joined **unconditionally**, so a saturated queue during
shutdown cannot leave the database open. A test proves this by reopening the
store after the run returns.

### Both roles stop on `SIGTERM`

Both long-running roles handle `SIGINT` **and `SIGTERM`**/`SIGHUP`. Only `SIGINT`
is what a terminal sends; a process supervisor sends `SIGTERM`, so a role that
handled only `SIGINT` could not be stopped by one and had to be killed — which
skipped steps 6 to 8 entirely. That was a real defect: `serve` exited on the
signal with status `-1` and never drained. `tests/service_e2e.rs` and
`tests/service_rootful_e2e.rs` now assert exit status `0` on `SIGTERM`, and an
architecture guard pins the dependency feature that makes it work.

`Shutdown` is an ordinary queue entry, so after a saturated burst it waits behind
the backlog. Its *confirmation* can miss the five-second reply deadline; the
thread is joined either way. The wait is bounded by the queue draining, not by
the deadline.

## Command line

```
wg-basic serve [--state PATH] [--socket PATH] [--http-bind ADDR]
               [--canonical-origin ORIGIN] [--allow-non-loopback]
```

`--canonical-origin` takes `scheme://host[:port]` and nothing else: a path, a
query, or a fragment is refused, because accepting one would mean accepting an
origin comparison that quietly differs from what a browser sends.

The flag is how a headless operator confirms, from the log of a machine with no
browser attached, which origin the surface believes it has:

```
wg-basic serve canonical origin https://vpn.example.com, loopback listener (bind loopback)
wg-basic serve canonical origin http://vpn.example.com:8000, ROUTABLE LISTENER, ACKNOWLEDGED — serve only behind a TLS proxy (bind non-loopback)
```

Binding off-host prints an explicit warning that Phase 7 terminates no TLS and
that the session cookie and every credential would otherwise cross the network
in the clear.
