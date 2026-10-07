# Management HTTP boundary and the bounded worker

This document describes **current implemented behaviour**. Phase 7 is in
progress; the authenticated surface, sessions, and the product management UI are
described in [the management service roadmap](../plans/subsystems/management-service-security-roadmap.md)
as later milestones, not here.

Architecture decisions behind this boundary are recorded in
[ADR-003](../plans/adr/003-management-http-auth-and-worker-boundary.md).

## What exists today

`wg-basic serve` is the unprivileged management service role. It publishes one
HTTP route:

| Method | Path      | Answer                                       |
| ------ | --------- | -------------------------------------------- |
| `GET`  | `/healthz` | `200` with the body `ok` or `degraded`        |

Everything else is a bounded `404 not found` or `405 method not allowed`. There
is no authentication, no session, and no desired-state mutation route.

## The two boundaries

The management process has exactly two HTTP-relevant boundaries and they do not
overlap.

```
src/http/                 src/management/
  config.rs    ──┐         worker.rs   ── owns ──> runtime.rs ──> StateStore / netd
  response.rs   ├──►      (bounded queue)              (only module that
  service.rs   ──┘                                   touches the store or netd)
  serve.rs
```

* `src/http/` owns the wire protocol: configuration and limits, routing, status
  selection, and the process lifecycle. It may use EggServe primitives, the
  worker client, and safe configuration values.
* `src/management/worker.rs` owns the single OS thread that holds
  `ManagementRuntime`. It is the only way into management state.

HTTP code never opens the database and never contacts `netd`. A request handler
reaching either would block a Tokio worker thread on synchronous disk I/O or on a
Unix socket round trip, and would be able to observe state the health projection
deliberately withholds. Three architecture guards in
`tests/architecture_guards.rs` enforce this.

## The bounded worker

`ManagementRuntime` and `StateStore` are synchronous on purpose, and `netd`
requests block. Rather than let an async handler do that work, one dedicated OS
thread owns the runtime and callers submit typed commands through a **bounded**
`tokio::sync::mpsc` queue with one-shot replies.

"Bounded" is load-bearing. There is deliberately no unbounded channel and no
`spawn_blocking` escape hatch, so a flood of requests cannot become a backlog of
pending commands:

| Condition                        | Answer                                             |
| -------------------------------- | -------------------------------------------------- |
| Queue full                       | `503 unavailable` (admission refused, not awaited)  |
| No reply within the deadline     | `503 unavailable`                                  |
| Worker stopped                   | `503 unavailable`                                  |

The three are deliberately indistinguishable to a caller: a client that could
tell them apart would learn whether the appliance is merely slow or gone.

M001 ships exactly two commands, `Health` and `Shutdown`. Both the command set
and the reply types are closed enums, so adding an operation is a deliberate,
visible change.

## Startup: fatal versus degraded

Startup makes one unconditional reconciliation attempt, because stored
convergence evidence is a hint, not a reason to skip work — the kernel may have
drifted while the service was stopped.

The outcome decides whether a listener is ever bound:

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

## What `/healthz` may disclose

`/healthz` answers `ok` or `degraded`, and nothing else. It carries no
installation ID, no generation, no filesystem path, no desired-state fact, and no
backend failure detail.

Both classes are served with `200`. "Degraded" describes the appliance, not the
request: the request *was* answered. Serving it as `503` would conflate "the
thing you asked about is unhealthy" with "this endpoint is unavailable", and
would make a liveness probe restart a healthy listener.

Every response body on this surface is a fixed literal. There is no code path
that formats an error, a path, or an internal type into a response, so an error
path cannot leak by accident.

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

The surface sets no `Server` header, no PROXY protocol, no trusted proxy, and
streams no files or tunnels. Forwarded headers are not trusted, so a client
cannot forge its observed address.

## Lifecycle and shutdown

`wg-basic serve` runs in this order:

1. validate the HTTP configuration — before any authority-bearing resource is
   opened, so a bad limit cannot leave a half-started service holding the store;
2. start the worker, which opens the store and attempts the startup reconcile;
3. bind EggServe;
4. report readiness to the log;
5. serve;
6. on Ctrl-C: stop accepting, drain in-flight requests under the grace period,
   stop the worker, release the store, and exit.

The worker is stopped and joined **unconditionally**, so a saturated queue during
shutdown cannot leave the database open. A test proves this by reopening the
store after the run returns.

## Binding off-host

A non-loopback bind is permitted and warned about, not refused. Refusing would
block an operator with a legitimately proxied deployment; staying silent would
hide that Phase 7 serves no TLS and no authentication. The warning names the
risk. Put a TLS-terminating reverse proxy in front of any non-loopback bind.