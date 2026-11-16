# S001 — Typed interpreter and admission corrective

Status: **closed** (2026-11-16). Raised by a repository security audit of the
tree at `2c38726`. Closure: `plans/closure/security-audit/001-status.md`.

Repository baseline: `2c38726` (`Keep the owned NetNAT name inside WinNAT's 80-byte key.`).

Source plans and closures this corrective must leave period-accurate:

- `plans/implementation/macos-native-server/c004-pf-nat-effective-gateway.md`
  and `plans/closure/macos-native-server-corrective/c004-status.md`
- `plans/implementation/network-control/005-firewall-forwarding-end-to-end.md`
- `plans/implementation/management-service/003-authenticated-http-security-perimeter.md`
- `plans/adr/003-management-http-auth-and-worker-boundary.md`

Canonical requirements and ADRs: `plans/000-long-term-specification.md`
(typed IPC, no raw nftables program, no shell); ADR-001 (Linux-native
privilege separation); ADR-003 (unauthenticated `/healthz`, login limiter
before Argon2, one bounded worker so HTTP never opens the database);
ADR-008 (Darwin PF is a typed, administrator-attached anchor);
`plans/003-planning-process.md` §12 and §13.

Primary work class: **corrective / invariant**. Three defects, one per
interpreter boundary. They share a contract: a caller who is already allowed
to speak a typed operation must not be able to widen that operation into a
second grammar or into a denial of the management worker.

No new ADR. The decision is the one those documents already record. This
plan restores it at the three places the audit found it incomplete.

## Objective

1. A Darwin gateway apply installs a PF rule only when every interface name
   in that rule is one interface token. A name that PF would read as an
   operator or a list is refused before `pfctl` runs, and the anchor is left
   unchanged.
2. Linux `netd` executes `nft` by an absolute path chosen from a fixed list.
   The process environment's `PATH` is not consulted.
3. An unauthenticated flood of `GET /healthz` cannot occupy the admission
   slots used by login and by state-changing management commands. `/healthz`
   stays unauthenticated and still answers only `ok` or `degraded`.

## Explicit non-goals

- No new protocol operation, no shell, no caller-supplied nft or PF source,
  and no new sysctl path.
- No change to C004's anchor ownership, parent-attachment rules, rule order,
  IPv4-only NAT, or teardown. C015 stays the interface-teardown handoff and
  is not part of this plan.
- No change to Linux nft quoting, table ownership, or the rule that
  forwarding is only ever written as `1`.
- No change to the Linux default that `netd` also authorizes uid 0.
- No in-process TLS, and no change to `--allow-non-loopback`.
- No authentication added to `/healthz`, and no extra fields in its body.
- No schema migration and no rewrite of stored rows.
- No edit to a historical closure record.
- The accepted `zip` advisories in `.cargo/audit.toml` stay as written.
- Windows NAT naming is already a fixed prefix plus hex. It is not part of
  this plan.

## The defects

### D1 — Darwin PF reads an interface name as PF syntax

`InterfaceName` (`src/domain/interface_name.rs`) rejects NUL, ASCII controls,
whitespace, `/`, and `:`. It accepts `!`, `{`, `}`, `,`, quotes, `;`, and
`#`, inside the 15-byte limit. `!en0` and `{en0,lo0}` are legal values.

`src/firewall/pf.rs` `render_policy` interpolates the egress and tunnel
names unquoted:

```text
pass in on <tunnel> from <prefix> to any keep state
nat on <egress> from <prefix> to any -> (<egress>)
```

`src/firewall/service_darwin.rs` `install_gateway_anchor` writes that text
and loads it with `/sbin/pfctl`. Gateway apply checks forwarding and parent
attachment. It does not require the egress string to be a single observed
interface. Routed LAN does compare the egress name to an observed interface,
and that mode does not install rules.

In PF, `!` is negation and `{en0,lo0}` is an interface list. `pass in on !en0`
matches every interface except `en0`. The same string on Linux is quoted by
`nft_quoted` before it reaches nft, so this defect is Darwin's.

The caller is any uid `netd` already allows, including the management role
sending `ApplyNetworkPolicy` or `ApplyInstallationNetworkIntent`. An
authenticated operator can store the same name as the server egress.

### D2 — Linux `nft` is found through `PATH`

`src/firewall/nft.rs` starts the backend with `Command::new("nft")`. M005
required a direct exec and internally rendered input, which this call meets,
and it did not require an absolute path. Darwin already pins `/sbin/pfctl`
and `/bin/launchctl`. The shipped `netd` unit sets `ProtectSystem=strict`
and does not set `PATH`, so a stock system-unit start is unlikely to search
an attacker-controlled directory. A `netd` started with a caller-controlled
`PATH` would execute whichever `nft` that search finds, as the network role.

### D3 — `/healthz` shares the mutation worker

`GET /healthz` is unauthenticated by ADR-003 and returns only `ok` or
`degraded`. `src/http/service.rs` serves it by calling `worker_health()` on
the single management worker. That worker's queue capacity is 32
(`DEFAULT_QUEUE_CAPACITY` in `src/management/worker.rs`). Login is limited
before Argon2. `/healthz` is not. Any local process that can connect to the
loopback listener can fill that queue. The effect is management-plane
availability. It does not disclose state and it does not cross into `netd`.

## Why the previous evidence missed them

**D1.** C004's closure compared rendered rules to `render_policy` for an
ordinary egress name and then carried translated traffic through that
anchor. The fixtures used names such as `en0`. A name that is also a PF
operator was never rendered, and the gateway install path was never required
to prove the name was one interface. M005's "validate interface names before
rendering" was written for the nft backend, which quotes. The PF renderer
did not inherit that check when C004 started installing the rendered text.

**D2.** M005's acceptance test for the nft backend was "direct exec, never a
shell." `Command::new("nft")` satisfies that sentence. Qualification ran
under the unit's default `PATH` and `ProtectSystem=strict`, so the lookup
succeeded against a root-owned directory and the missing pin was invisible.

**D3.** ADR-003 and the Phase 7 plan required `/healthz` to stay
unauthenticated and required the login limiter to run before hashing. The
test that proves that ordering saturates the login bucket. It does not send
a concurrent unauthenticated health flood, so the shared queue was never the
subject of the measurement.

## Invariants this change must not break

- Desired state in SQLite stays authoritative. A refused render does not
  advance convergence and does not change the committed generation.
- `netd` still owns kernel and PF mutation. `serve` still does not.
- The product still writes only its own installation anchor and anchor file.
  A refusal leaves that anchor as it was.
- Linux nft input stays internally rendered, quoted, bounded, and confined
  to `inet wg_basic`.
- `/healthz` stays unauthenticated and its body stays `ok` or `degraded`.
  HTTP still does not open the database or the netd socket on a Tokio worker
  thread.
- Login still runs the limiter before Argon2, and a throttled login still
  returns `429` without hashing.
- A stored database from this baseline still opens. No migration.

## Expected production changes

The mechanism inside each package is the implementer's, within the contract
below.

### Package A — one PF interface token

Every interface name that `render_policy` or `render_routed_policy` would
emit must match a single token: one to fifteen bytes from
`[A-Za-z0-9._-]`, and not `.` or `..`. `!`, braces, commas, quotes, `;`,
`#`, whitespace, `/`, and `:` are refused.

The check runs before any call that would spawn `pfctl` and before any
anchor file is written. Gateway apply returns the existing invalid-policy
error, installs nothing, and leaves the anchor and its file unchanged.
Routed-LAN rendering uses the same token rule, because that text is what the
operator is told to install and what drift detection compares.

An observed-interface check may sit beside the token rule. It does not
replace it. A name that happens to exist and still contains a PF operator
is refused.

`InterfaceName` may stay the wider stored type. Tightening it globally is
allowed only when every name the product already accepts on Linux still
parses, and a row that fails the new parse fails closed at apply with a
named error. Do not truncate a stored name.

Linux nft quoting stays. Do not "fix" D1 by handing the file to `pfctl` and
treating a non-zero exit as success-of-refusal. The product refuses, then
does not exec.

### Package B — absolute `nft`

Select the executable from a fixed absolute list, in order, for example
`/usr/sbin/nft` then `/sbin/nft`. Use the first entry that is a regular
file, executable, and not a symlink. If none qualifies, return the existing
unsupported-backend error. Do not consult `PATH`. Do not invoke a shell.
The argv, the stdin bound, the timeout, and the version floor stay as they
are.

The systemd unit does not gain a `PATH` assignment. The pin is in the
process invocation.

### Package C — health admission

`/healthz` remains an unauthenticated liveness answer. A burst of those
requests must leave a login, and a state-changing management command, able
to enter the worker under the limits that already exist for those commands.

Allowed shapes:

- a separate bounded queue or admission budget for the liveness read, so
  the mutation and login queue keeps its slots; or
- a rate limit applied to `/healthz` before it is admitted, sized so a
  saturated health budget sheds further health requests and still admits a
  login.

The HTTP handler still does not open SQLite and still does not dial `netd`
itself. A cached readiness value is acceptable when the cache is filled by
the worker and a stale cache still collapses to the same two liveness
tokens. The body, status class, and security headers of `/healthz` stay as
they are.

## Ordered work packages

1. **Token rule and renderer tests.** Add the token predicate and make both
   PF renderers refuse, with tests for `!en0`, a brace list, a quoted
   breakout, `;`, `#`, `.`, and `..`, plus an accepted `en0`, `utun4`, and
   `bridge0`.
2. **Gateway apply refuses before exec.** `install_gateway_anchor` and the
   apply path that calls it must not spawn `pfctl` and must not write the
   anchor file when the token rule fails. Cover that with a Darwin-gated
   test. The pure renderer tests in package 1 run on every host.
3. **Pin `nft`.** Replace the `PATH` lookup. Unit-test that the chosen path
   is one of the fixed absolute paths and that a symlink is skipped.
4. **Separate health admission.** Implement one of the two shapes in
   Package C. Test that a saturated health budget still admits one login
   attempt as far as the limiter, and that `/healthz` still answers only
   `ok` or `degraded` with the same sealed headers.
5. **Docs after the code.** Update `architecture/firewall.md` and
   `architecture/management-http.md` to describe the token rule, the
   absolute `nft` path, and the health admission split. Do that in the same
   change as the code. Do not describe the behavior as current before then.

## Privilege and security effects

The privileged surface gets narrower. Darwin `netd` will refuse a class of
`InterfaceName` values it currently loads into PF. Linux `netd` will refuse
to execute an `nft` that is not one of the pinned paths. `serve` gains no
privilege. No new file, socket, or capability is introduced.

A stored egress that fails the token rule fails closed at the next apply.
The operator sees the existing invalid-policy category. The previous anchor
contents remain until a valid policy is applied.

## Persistence, protocol, and configuration compatibility

No schema change. No protocol version change. A request that carries a
rejected interface name returns the existing invalid-input or invalid-policy
error, whichever the firewall boundary already uses for a policy that fails
`validate`. Callers that send `wg0`, `en0`, or `utunN` are unchanged.

`/healthz` request and response shape are unchanged. A shed health request
uses the existing unavailable or throttled response already defined for an
admission refusal, and it must not be distinguishable from those responses
in a way that reveals queue internals beyond the status the surface already
returns for overload.

## Failure, cancellation, restart, and contention

- Token refusal: no `pfctl`, no anchor-file write, no table or sysctl
  change, no generation update caused by the refusal itself. The caller's
  transaction behavior stays whatever the management worker already does
  when `netd` returns invalid input.
- `nft` missing or not a pinned regular file: `Unsupported`, and no child
  process. An apply that cannot start `nft` does not report the table as
  replaced.
- Health shed: the liveness route returns its bounded overload or throttle
  response. Login and mutation admission are unchanged. Restart clears
  in-memory limiters, as it does today.
- Contention: the firewall mutation lock stays the one the Darwin and Linux
  services already hold. The token check happens before that lock is used
  to spawn a process. A refused call must not leave the lock held.

## Focused tests

- Renderer: the names in package 1, on the pure `pf` tests, which already
  build on every host.
- Darwin apply: a gateway apply with egress `!en0` returns the invalid
  policy error and does not leave a new anchor file. Gate it to Darwin so
  Linux hosts do not need `pfctl`.
- `nft`: path selection rejects a relative name, a missing path, and a
  symlink, and accepts only the pinned absolute candidates.
- HTTP: health flood versus one login, from `tests/authenticated_api.rs` or
  `tests/management_http.rs`. Assert the login reached the limiter's allow
  path. Assert `/healthz` did not grow a new body.
- Regression: existing PF attachment tests, nft quoting tests, and the
  login-limiter-before-hash test stay green.

## Integration evidence

D1's claim is that `pfctl` is not executed for a bad token. That is proven
by the apply-path test, not by a packet capture. A controlled-host gateway
rerun is not required to close D1. Do not invent one.

D2's claim is the executable path. The unit test closes that claim. When a
Linux root host is available, run the existing rootful network-control
suite so a wrong pin is observed against real `nft`:

```sh
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test network_control_e2e -- --test-threads=1
```

If that host is absent, the closure record says so. It does not claim the
live suite passed.

D3 needs no root and no namespace. The ordinary `cargo test --locked` run
is the integration evidence.

## Broad verification

From `docs/development.md` and `.skills/wg-basic-gates/SKILL.md`, in order:

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

If a shared type such as `InterfaceName` changes, also run the
`linux-integration` cross clippy from the gates skill. That command
type-checks the Linux-only tests that a Darwin host otherwise skips.

Do not run a rootful suite unprompted. Record it only when it was actually
run.

## Documentation updates

In the same change as the code:

- `architecture/firewall.md` — PF names are one token; `nft` is an absolute
  pinned path.
- `architecture/management-http.md` — `/healthz` admission is separate from
  login and mutation admission.
- `architecture/privilege-boundary.md` — only if it still says the firewall
  helper is invoked by the bare name `nft`.

Operator docs stay a summary. Do not document a new flag or a new route.

## Acceptance criteria

1. `render_policy` and `render_routed_policy` refuse `!en0`, `{en0,lo0}`,
   a quote, `;`, and `#`, and accept `en0` and `utun4`.
2. Darwin gateway apply of a refused name does not spawn `pfctl` and does
   not replace the anchor file.
3. A successful render contains only token-safe interface names, still in
   C004's rule order, with IPv4-only NAT unchanged.
4. The `nft` child is started with an absolute path from the fixed list,
   and a `PATH` entry named `nft` is not used.
5. Existing nft quoting, version floor, input cap, and timeout tests pass.
6. A saturated `/healthz` budget still admits a login as far as the login
   limiter, and `/healthz` still returns only the two liveness bodies.
7. Login throttling still happens before Argon2.
8. `cargo test --locked` passes. The closure record states whether the
   rootful network-control suite was run.
9. The architecture pages named above match the code that landed.
10. No historical closure record was edited.

## Stop conditions

- Stop if the only way to refuse a bad PF name is to let `pfctl` parse it.
- Stop if the token rule would reject `utun` plus digits, `en0`, or
  `bridge0`.
- Stop if pinning `nft` seems to require a shell, a `PATH` search, or a
  caller-supplied path.
- Stop if separating health admission seems to require the HTTP thread to
  open the database or to dial `netd`.
- Stop if the fix needs a new privileged operation. That is an ADR, not this
  plan.
- Stop rather than fold C015, IPv6 forwarding ownership, or the uid-0 socket
  default into this change.

## Closure evidence requirements

The closure record names the commits, the baseline `2c38726`, and the final
head. It maps D1, D2, and D3 to the tests above, quotes the commands that
were run and their results, and says whether `network_control_e2e` ran.
Compilation alone is not closure for D2's live regression; the unit test of
the path is closure for the `PATH` claim, and a skipped rootful suite is
recorded as skipped.

Disposition is `closed` only when all ten acceptance criteria are met.
A package that lands without the others is `conditionally closed` and names
the unmet criteria. Do not write the closure record in advance of that
evidence.
