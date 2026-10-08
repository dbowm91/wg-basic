# Development

Install Rust 1.89.0 with the `rustfmt` and `clippy` components. The checked-in `rust-toolchain.toml` selects this toolchain.

Run the repository's CI gates from the root:

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

The default unit/protocol suite does not require root or network namespace setup. The Linux WireGuard backend mutates only through typed requests to an existing device; the real-kernel integration test creates temporary namespaces and fixture links and requires root, `CAP_NET_ADMIN`, `iproute2`, `iputils-ping`, and kernel WireGuard support.

## Local netd

Create a private runtime directory owned by the user running `netd`, then start:

```sh
install -d -m 700 /tmp/wg-basic-runtime
cargo run --locked -- netd --socket /tmp/wg-basic-runtime/netd.sock
```

In another terminal, use `cargo run --locked -- doctor --state /tmp/wg-basic-runtime/state.db --socket /tmp/wg-basic-runtime/netd.sock` or `cargo run --locked -- serve --socket /tmp/wg-basic-runtime/netd.sock`. Doctor accepts `--json` and optional `--http-bind`, `--canonical-origin`, and `--allow-non-loopback` flags. Its exit code is 0 when all checks pass, 1 when warnings or unknowns need attention, and 2 for a required failure or invalid invocation. State inspection uses immutable read-only SQLite access and does not initialize or migrate a database; when WAL sidecars make an immutable view unsafe, it reports the state as unavailable. With configured product state, doctor asks netd for a typed aggregate plan and never applies it. Port availability that cannot be proven without binding is reported as unknown. `serve` is the unprivileged management service: it opens the durable state store on a dedicated bounded worker thread, attempts startup reconciliation, and serves the authenticated HTTP API (`--http-bind`, default `127.0.0.1:8000`) and embedded operator UI for login/session/health, server setup, client CRUD, config/QR export, one-time enrollment, live telemetry, and audit pages. Product mutations require the current `expected_generation`, the exact `Origin`, and the session CSRF token; their `200`/`201` versus `202` response distinguishes confirmed enforcement from a committed change still awaiting network application. The UI reports degraded disable/delete as not yet confirmed revoked. The unauthenticated `GET /healthz` remains a two-token liveness probe. For a separate management UID, start netd with `--allow-uid UID` and arrange socket group access. Both `netd` and `serve` exit on Ctrl-C; `netd` removes only the socket inode it created.

`serve` holds `<state>.serve.lock` using a nonblocking kernel advisory lock for
its full lifetime. A second `serve` for the same database exits before HTTP
binding. The lock is released by process death; its safe PID/start text is
informational only. Online backups use a shared `<state>.maintenance.lock`, so
they can run while serve is active. Restore and purge take the exclusive
maintenance lock.

## Local administrator credentials

Provision or reset the local administrator from the terminal. The same
credentials are what `POST /api/v1/login` exchanges for a session cookie:

```sh
install -d -m 700 /tmp/wg-basic-runtime
printf '%s\n' 'an administrator password' | \
  cargo run --locked -- admin set-password --password-stdin \
    --state /tmp/wg-basic-runtime/state.db
cargo run --locked -- admin status --state /tmp/wg-basic-runtime/state.db
```

The password is read only from standard input and only with `--password-stdin`.
It is never accepted as an argument or from the environment: an `argv` credential
is readable by every process on the host through `/proc`, and an environment one
is inherited by every child. `admin status` prints identity, enabled state, and
the live session count, and never a verifier, token, or password.

## Serving the management surface

The default is the only deployment that is correct without a decision being made:
a loopback listener whose allowed host set is loopback and whose canonical origin
is the loopback listener itself.

```sh
cargo run --locked -- serve \
  --state /tmp/wg-basic-runtime/state.db \
  --socket /tmp/wg-basic-runtime/netd.sock
```

Logging in is a JSON `POST` from the canonical origin with a correct `Host`. A
request without one is refused before routing — that is the DNS-rebinding
defence, and it applies to every route without exception:

```sh
curl -i http://127.0.0.1:8000/api/v1/login \
  -H 'Host: 127.0.0.1:8000' \
  -H 'Origin: http://127.0.0.1:8000' \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"an administrator password"}'
```

The reply carries the session in an `HttpOnly`, `SameSite=Strict`,
`Path=/` cookie. `GET /api/v1/session` returns that session's identity, expiry,
and CSRF token; the token must be echoed in `x-wg-basic-csrf` on every unsafe
method, and `POST /api/v1/logout` without it revokes nothing.

### Behind a TLS-terminating reverse proxy

Phase 7 serves no TLS. When a proxy terminates it, keep the listener on loopback
and declare the *external* origin:

```sh
cargo run --locked -- serve --http-bind 127.0.0.1:8000 \
  --canonical-origin https://vpn.example.com
```

An `https` origin switches the session cookie to the `__Host-` prefixed, `Secure`
form and enables HSTS. Two refusals are deliberate: a routable listener may not
claim an `https` origin, because it terminates no TLS and the claim would be
false; and a routable bind is refused outright without both `--allow-non-loopback`
and `--canonical-origin`, because accepting an arbitrary `Host` is the rebinding
hole the policy exists to close.

```sh
cargo run --locked -- serve --http-bind 0.0.0.0:8000 \
  --allow-non-loopback --canonical-origin http://vpn.example.com:8000
```

Startup prints the effective exposure mode to the service log, which is how a
headless operator confirms which origin the surface believes it has.

Long-running roles accept the global `--log-format human|json` option (default
`human`). Operational events go to stderr; JSON mode emits one JSON object per
line, while command results remain on stdout. The binary does not write log
files or rotate logs; use the service manager/journald for retention. Event
fields use bounded categories and omit credentials, tokens, key material, HTTP
bodies, and backend error strings.

Run Linux IPC integration coverage with:

```sh
cargo test --locked --test privileged_protocol -- --nocapture
```

Run the real kernel WireGuard handshake, telemetry, peer update, and preservation fixture with:

```sh
sudo -E cargo test --locked --features linux-integration --test wireguard_kernel -- --nocapture
```

The test starts its netd workers inside the two temporary network namespaces so each typed request controls the device in that namespace. CI runs this target on a rootful Linux runner; when `CI` is set, unavailable namespace/kernel prerequisites fail the test instead of silently skipping kernel evidence.

## Durable ownership and restart fixtures

Three rootful suites qualify the durable-state milestones against the real kernel. All need root, `iproute2`, `nftables`, and kernel WireGuard support, and all serialize with `--test-threads=1` because each creates disposable network namespaces with fixed names.

Owner tags and the generation-aware aggregate reconcile:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_owner -- --test-threads=1
```

Startup reconciliation and crash/restart recovery:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1
```

Product management's real-kernel suite, including HTTP-driven server setup and
client creation, config/QR export, one-time enrollment consume/replay, a real
exported-config handshake and traffic, telemetry/audit reads, disable,
re-enable, and delete:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test product_management_rootful -- --test-threads=1
```

Restored-state qualification (three namespaces, real handshake, forwarding, and NAT from a restored database):

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_backup -- --test-threads=1
```

`durable_restart` is a process-level fixture: it runs the real `wg-basic netd` binary and the real `wg-basic reconcile` management role as separate child processes against a temporary on-disk SQLite file, disposable namespaces, real RTNETLINK, and real nftables. It proves restart recovery rather than in-process reconstruction, so it depends on a built `wg-basic` executable and leaves its `netd` children to be reaped by the harness. CI runs these as the `durable-owner`, `durable-restart`, and `durable-backup` jobs.

The `-E env ... CARGO_HOME=...` form exists because `sudo` resets `HOME`, and Cargo needs a writable home to resolve the toolchain and registry cache when the tests are run as root.

## Doctor read-only namespace fixture

The doctor fixture first uses an empty installation in the ordinary test suite,
then creates a configured-but-unapplied installation in a disposable network
namespace. It asserts that the real doctor command plans repair without applying
it and that database, link, route, and nftables snapshots are unchanged. It
requires root, `iproute2`, and `nftables`:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test doctor_readonly -- --test-threads=1
```

## Operational maintenance fixtures

The unprivileged `service_lease` suite starts the real serve process, proves a
second process and restore are refused while its lock is held, then kills the
owner and verifies restore/restart can proceed:

```sh
cargo test --locked --test service_lease -- --test-threads=1
```

The rootful fixture qualifies CLI disable/re-enable through a real WireGuard
handshake, verifies disabled state survives management/backend restart, and
proves purge needs disabled+converged state plus a no-op plan while preserving
operator files:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test maintenance_rootful -- --test-threads=1
```

## Phase 9 old/new upgrade rehearsal

CI builds the immutable Phase 8 baseline (`e8fd6b1`) with its own lockfile and
builds the candidate into a separate target directory. The rootful rehearsal
uses disposable namespaces and a temporary state directory to exercise v4
product creation, real WireGuard traffic, explicit backup verification,
candidate migration/failed health, v4 restore, doctor, old-service recovery,
and candidate re-upgrade:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  CARGO_TARGET_DIR=/tmp/wg-basic-upgrade-rootful-target \
  WGB_OLD_BINARY=/path/to/phase8/wg-basic \
  WGB_CANDIDATE_BINARY=/path/to/candidate/wg-basic \
  cargo test --locked --features linux-integration \
    --test upgrade_rehearsal_rootful -- --ignored --nocapture --test-threads=1
```

The unprivileged companion test covers v4 product/session/enrollment/audit
preservation, config hashes, old-binary refusal, explicit restore and repeated
migration. It is run by the dedicated `upgrade-rehearsal` CI job.

## Phase 7 service suites

Phase 7 added eight unprivileged suites and one rootful fixture. The unprivileged
ones need nothing but a loopback socket and run with the ordinary suite:

| Suite                            | What it qualifies |
| -------------------------------- | ----------------- |
| `management_http`                | real EggServe over real TCP: routing, perimeter, security headers |
| `authenticated_api`              | pure request policy: `Host`, `Origin`, `Sec-Fetch-*`, CSRF, cookie, limiter |
| `auth_sessions`                  | real migration v1→v2, Argon2id cost, session persistence |
| `architecture_guards`            | 47 static invariants over the shipped source |
| `service_session_restart`        | §5: sessions across a real `serve` restart, over real cookies |
| `service_resource_limits`        | §7: connection, in-flight, worker-queue, body, timeout, and shutdown saturation |
| `service_e2e`                    | §6: real `admin`, `netd`, and `serve` child processes over a real socket |
| `service_footprint`              | §9: footprint and latency on the release binary |

```
cargo test --locked
cargo test --release --locked --test service_footprint -- --nocapture
```

`service_footprint` prints the figures — cold readiness, `/healthz` latency, login
Argon2 latency, serve and netd RSS, idle CPU, shell size — and asserts only on
bounds that are properties of the design. It asserts a *floor* on login latency,
because a login that got faster than a millisecond would mean the Argon2id
parameters had been weakened, which Phase 7 forbids outright.

Phase 9 adds `operational_events` for stderr format/secrecy, `runtime_stability`
for bounded HTTP and state-row growth, and repeated real-process SIGKILL/restart
cycles in `service_lease` and `service_e2e`. The existing
`service_resource_limits` suite remains the source of exact HTTP admission and
deadline boundaries. See [service hardening](../architecture/service-hardening.md)
for the Phase 10 systemd contract.

### The rootful service fixture

```
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test service_rootful_e2e -- --test-threads=1
```

It starts a real `netd` inside a disposable network namespace and runs `serve` on
the host against it over the shared socket path, then drives the management HTTP
surface. Three cases qualify: that the surface reflects real network state in
both directions (converged → `ok`, backend gone → `degraded`), that the
management role survives its backend disappearing and picks it up again without a
restart, and that no key material reaches any rendered response.

`serve` runs on the host rather than inside the namespace because a namespace has
its own loopback: a listener bound to `127.0.0.1` inside one is a different
socket from `127.0.0.1` outside it. `ip netns exec` does not remount `/tmp`, so
the netd socket is the same file on both sides and `serve` reaches the
in-namespace backend over exactly the authorized Unix socket the unprivileged
deployment uses.

### What the abort/resource cases actually prove

Every wait in these suites is a deadline that turns into a test failure, never a
sleep. Where a case needs the server to give up on a misbehaving client, the test
blocks on a *read* with its own timeout and asserts what the server did — a close
or a `408` — so removing a bound fails a test instead of hanging CI.

Two findings came out of writing them and are worth knowing before editing that
code:

* **The login limiter, not the worker queue, is the binding constraint over
  HTTP.** The global budget is 20 and the queue is 32, and every non-login route
  issues at most one fast command, so the queue cannot be filled through the
  surface. The queue bound is therefore qualified directly at the `WorkerClient`,
  where `Authenticate` is the only slow enough command to fill it.
* **`Shutdown` is an ordinary queue entry.** After a saturated burst its
  confirmation can miss the five-second reply deadline. The thread is joined
  either way, so the database is always released; only the confirmation is late.
