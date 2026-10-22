# Startup reconciliation and crash/restart recovery

The management role is unprivileged. It owns the durable state store and turns the committed desired generation into network state, but it reaches the kernel only by asking the authorized `netd` over its local socket. It never escalates privilege, never opens a privileged socket, and never spawns `netd`.

This document describes what happens on startup and after a crash. The store itself is described in [the state store](state-store.md); ownership proof is described in [ownership](ownership.md).

## The startup sequence

`ManagementRuntime::start` always runs the same steps, in this order:

1. validate the state directory and database path;
2. open the hardened store (`0600`, owner-checked, `O_NOFOLLOW`);
3. run and verify migrations;
4. load the current desired snapshot and its generation;
5. project it into an `InstallationNetworkIntent`;
6. connect to the authorized `netd`;
7. submit one aggregate apply for the current generation;
8. receive the receipt for that same generation;
9. record convergence evidence **only if the database still holds that generation**;
10. return to the caller, which exits for a one-shot command or idles for a service role.

Two properties matter more than the list itself.

### Startup always reconciles

Startup applies the current generation **even when `last_converged_generation == desired_generation`**. The convergence record is evidence about a past apply, not a statement about the present kernel. An operator can delete a link, flush a table, or reboot the host between runs; the only way to know the kernel still matches is to re-observe and re-apply.

Idempotence makes this cheap rather than expensive: re-applying a converged generation yields `NoChange`.

### A late receipt cannot mark newer state converged

An apply is not instantaneous, and a newer write can commit while one is in flight. `record_converged_if_current` re-checks the generation inside the same write transaction that updates the evidence:

- if the store still holds the applied generation, the receipt advances `last_converged_generation` and the outcome becomes `converged`;
- if the store has moved on, the receipt is recorded with the outcome `superseded` and convergence is left untouched.

This is the guard that makes out-of-order completion safe. A generation can never claim convergence on behalf of a generation that did not finish.

## The mutation-to-reconcile coordinator

The same coordinator serves startup and any in-process mutation, so there is exactly one path from a committed generation to an applied one.

`ReconcileCoordinator` is a bounded, single-slot machine, not a scheduler:

- several writes before an apply begins **coalesce** to the latest generation, so a burst of writes costs one apply;
- once an apply has been claimed, a newer generation **waits**;
- when the apply finishes, the latest state is reconciled immediately.

There is no unbounded per-write task and no background timer. Shutdown or cancellation at any point leaves the database holding a complete, recoverable desired generation.

## Reconcile-on-write and two distinct statuses

`commit_and_reconcile` returns the committed generation and the reconcile outcome **separately**, because they answer different questions:

> a committed database transaction means the desired state is durable. It says nothing about whether the kernel matches it.

So a caller can observe "committed generation 7, kernel not converged" without either fact hiding the other. In M003 this is exercised through the internal `reconcile` and `health` command roles; a future Phase 7 HTTP surface can render it as synchronous or asynchronous UX without changing the semantics.

## Failure classification and retry

Failures are separated by whether a fresh attempt can plausibly succeed.

| Class | Examples | Policy |
|---|---|---|
| `BackendUnavailable` | netd not listening yet, connection refused, broken pipe | bounded retry |
| `PartialFailure` | an earlier layer changed state and a later one failed | bounded retry |
| `Conflict` | foreign owner tag, foreign `inet wg_basic` table, wrong link kind, stale generation | fail fast, operator or state change required |
| `Unauthorized` | netd rejected the caller or lacks the capability | fail fast |
| `Rejected` | unsupported backend, invalid input, kernel rejection, malformed reply | fail fast |

Retryable failures get at most `MAX_TRANSIENT_RETRIES` attempts with a short fixed backoff. Everything else fails immediately: retrying an ownership conflict cannot resolve it, and spinning on it would hide the condition an operator needs to see.

The `netd` reply is preserved across the transport boundary. The protocol client stores the wire `ProtocolError` as the payload of the returned `io::Error` and keeps the historical `io::ErrorKind` mapping, so management classifies on what `netd` actually said instead of guessing from a lossy transport kind. This is why a foreign owner tag is diagnosed as a conflict rather than being retried as if `netd` were merely absent.

There is deliberately **no** permanent high-frequency reconciliation loop in the management role. A future service manager may restart the process; that is the recovery mechanism, and it must not be built here.

The privileged authority has one narrower exception, described below: it supervises the helper process it spawned. That is supervision of a child it owns, not a loop that decides whether the desired state changed.

## The helper is supervised by the authority that spawned it

On Darwin the managed tunnel is carried by a helper process that `netd` spawns. A helper that exits on its own takes the managed device with it: the kernel releases the `utunN` device, and the receipt that named the helper becomes a claim about something that is gone.

`netd` supervises that helper the way it supervises any child it owns:

- a monitor thread notices that the helper it spawned is no longer running;
- the desired interface that was applied for it is re-applied, which recreates the helper, re-adopts exactly one new device, and restores the configuration, addresses, and routes that belonged to the tunnel.

Three properties bound this:

- **It restores, it does not decide.** The re-apply uses the desired state `netd` already applied for that interface. The monitor never consults the store, never compares generations, and never changes what the desired state is.
- **It is scoped to a child `netd` owns.** The monitor only looks at helpers in its own supervision map. A device it cannot prove is not touched.
- **It is not a reconciliation loop.** It runs at a fixed, slow interval, only does work when a supervised child died, and does not observe the host for drift.

A helper that dies is therefore recovered without an operator, and the recovery is bounded: the re-apply is attempted a small number of times and its outcome is reported as an operational event.

### A receipt that cannot be re-proven is not a claim

The receipt names the helper that owns the tunnel. It is never sufficient on its own: the live host must re-prove it before anything is changed.

That rule applies to *creating* a tunnel as well as to observing one. A receipt whose helper is gone describes nothing that exists, so a create over it is allowed: the stale receipt is dropped and the tunnel is recreated. Refusing the create instead would leave the installation unable to bring its tunnel back at all, which is a worse failure than the one the refusal would have avoided.

A receipt that *does* re-prove is a live tunnel carrying that owner tag, and a create over it is refused: two devices must never carry the same durable proof.

### The recovery restores the tunnel, not the sessions

A WireGuard session is not a property of the interface. It is a negotiated keypair between two peers, and it lives in the helper's memory, so a replacement helper starts with no session with any peer.

What the recovery restores is everything the product owns: the device, its address, the routes, the peer policy, and the helper that carries them. The *sessions* come back on the peer's own schedule:

- a peer whose session is still valid keeps sending packets that the replacement helper cannot decrypt, and those packets are dropped;
- the peer re-keys on the protocol's own interval after its last handshake, and the handshake that follows is answered by the replacement helper, because it holds the peer's public key;
- the outage is therefore bounded by the peer's rekey interval, not by the recovery. The recovery itself is immediate.

The product cannot shorten that window on its own. The address a peer is reached at is learned from its handshake initiations, which is live telemetry, and the store does not persist live telemetry: the schema has no column for an observed endpoint or an observed handshake. A replacement helper therefore starts without a learned peer endpoint, and a peer behind a roaming address is a peer that waits for its own rekey.

The client's own view of this is available without any new surface: `GET /api/v1/clients/telemetry` reports each client's observed endpoint, last handshake, and handshake age, so an operator can see a peer with no endpoint and a handshake that predates the replacement.

## Health projection

`ManagementHealth` is the safe surface a future Phase 7 endpoint may render:

- `database_healthy`, `netd_reachable`;
- `current_desired_generation`, `last_converged_generation`;
- `convergence`: `Converged`, `Pending`, `Retryable`, or `Failed`;
- `last_failure_category`.

It has no field for a receipt, an error string, or key material. A stored `ProtocolError` or `FirewallError` message can carry kernel detail, so only the category is ever recorded.

## Secret handling during startup

- `PrivateKey` and `PresharedKey` redact `Debug` and `Display` and zeroize on drop, so a desired snapshot can be logged structurally without leaking key material.
- Reconcile outcomes are stored as **categories**, never messages, so the database cannot accumulate secret-bearing strings.
- Startup never dumps the full persisted snapshot, on success or on failure.
- Private keys are never placed in logs, process titles, arguments, environment, or temporary files.

## Kernel drift while stopped

The kernel is derivative state, so anything can change while the product is not running. Startup re-observes and repairs:

| Drift | Startup behavior |
|---|---|
| owned tagged link deleted | recreated and re-tagged |
| owned link present but peers/addresses/routes drifted | repaired |
| owned `inet wg_basic` table deleted | recreated with this installation's marker |
| owned table contents drifted | replaced from the desired policy |
| link owner tag removed or changed | **fails closed**; never re-adopted |
| nftables owner marker changed | **fails closed**; never re-adopted |
| the managed helper died while the product was running | replaced by the authority that spawned it, without an operator |

Failing closed is the important half. If ownership proof is lost, the correct action is to refuse and leave the state for an operator, not to adopt a resource on the strength of its name.

## Qualification

`tests/durable_restart.rs` is a process-level rootful harness. It runs the **real** `wg-basic netd` binary as a child process and the **real** `wg-basic reconcile` management role as another child process, against a temporary on-disk SQLite file, disposable network namespaces, real kernel WireGuard, real RTNETLINK, and real nftables.

It demonstrates process restart rather than in-process reconstruction, using explicit child-process lifecycle and bounded timeouts. It covers:

- **crash point A** — a generation committed before any `netd` call converges after a management restart;
- **crash point B** — a partially applied generation: the interface layer mutates and the firewall layer refuses, and the next start converges once the operator clears the conflict;
- **crash point C** — a converged kernel whose evidence was never committed replays idempotently;
- **crash point D** — a stale completion cannot mark a newer generation converged;
- owned link and owned nftables table deleted while stopped, then restored;
- a changed link owner tag and a foreign table marker, both failing closed;
- an absent `netd` as a bounded unavailable state rather than an unbounded loop;
- secret material absent from CLI output, snapshot `Debug`, and the database file mode.

Run it with:

```bash
sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo \
  cargo test --locked --features linux-integration --test durable_restart -- --test-threads=1
```

CI runs this as the `durable-restart` job.

## Out of scope here

- **HTTP / EggServe.** No web surface is added; `ManagementHealth` is shaped so one can be added later without exposing internals.
- **Service installation.** `wg-basic state backup|restore` assumes the operator stopped the management service; a systemd unit is Phase 10 work.
- **Service installation.** No systemd unit, packaging, or install command is introduced. "Restart the process" remains the operator or service manager's action.
- **Package rollback.** Restore is implemented, but only for the database. Phase 10 owns install/update lifecycle and general package rollback; a restored database is validated and installed, but wg-basic does not roll back the binary or the host.