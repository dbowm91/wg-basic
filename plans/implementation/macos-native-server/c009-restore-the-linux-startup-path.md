# macOS Native Server C009 — Restore the Linux Startup Path

Status: **active**; the implementation is in this branch and the closure
evidence is in `plans/closure/macos-native-server-corrective/c009-status.md`.
Baseline: `plans/macos-native-support@e37210b` (C006's implementation head).
Source: C006's corrective (C002's corrective);
`plans/implementation/macos-native-server/c006-boot-time-runtime-and-backend-readiness.md`;
ADR-002 (the listener must come up either way) and ADR-008.
Authority: `plans/003-planning-process.md` §13 (corrective passes), §12
(security rule); `AGENTS.md` — Linux behavior must not regress.
Primary class: corrective / invariant.

## 1. The defect, as observed

C006 made the management daemon wait, bounded, for the privileged daemon to
answer a read-only capability request before its startup reconciliation. That
wait is Darwin's need: `launchd` starts the two jobs concurrently, and
without the wait the startup reconciliation races the backend's socket. It is
**not** Linux's need: the Linux units already order the two services
(`Requires=`/`After=`) and gate the management daemon on a `doctor`
pre-flight.

The implementation applied the wait to **every** platform
(`src/management/worker.rs`, `BACKEND_STARTUP_WAIT = 10s`, unconditional), so
on Linux the management daemon now sits in the wait for the full ten seconds
before its listener binds — whenever the backend socket is not there, which
is the case in the Linux harnesses that start `serve` without a netd.

The Linux native CI shows it. Three jobs fail at the C006 head and at every
head since, and the same three pass at the pre-C006 head `cdc4439`:

| Linux CI job | Failing assertion | Message |
|---|---|---|
| `rust` | `tests/service_footprint.rs:613` | `the_management_surface_meets_its_footprint_and_latency_shape` |
| `upgrade-rehearsal` | `tests/upgrade_rehearsal.rs:138` | `serve did not bind` (5 s deadline) |
| `upgrade-rehearsal-rootful` | `tests/upgrade_rehearsal_rootful.rs:146` | `serve did not bind` (5 s deadline) |

C006 also **masked** the regression where it could: three Linux harnesses
(`tests/operational_events.rs`, `tests/runtime_stability.rs`,
`tests/service_lease.rs`) had their serve-listener deadline raised from 5 s
to 30 s "after that budget when no backend is running". The three files
above kept their own 5 s deadlines, so they are the ones that broke.

Two claims in C006's closure record are therefore false as written
(`plans/closure/macos-native-server-corrective/c006-status.md`, §4):
"**neither touches Linux**", and "on Linux the probe succeeds on the first
attempt". The second is true in production — systemd orders the units — and
false in every Linux harness that starts `serve` without a netd, which is
where the delay bites. The closure record was written against a local gate
set that cannot run those Linux-only tests, and the Linux CI at that head
was in fact red.

## 2. Why the earlier evidence missed it

- The defect is invisible on macOS: the local gate set runs on a macOS host,
  and the three failing suites (`service_footprint`, `upgrade_rehearsal`,
  `upgrade_rehearsal_rootful`) are Linux-only, so no local run can see it.
- C006's own gates were green *on macOS*, and the Linux CI failure was
  recorded as the pre-existing `dependency-audit` upstream advisory, which
  sits in the same red runs and hid three real failures behind it.
- The three harnesses C006 did adjust had their deadline raised instead of
  being investigated, so the product's new delay was accommodated rather
  than seen.

## 3. The fix

### 3.1 The wait is Darwin's

`BACKEND_STARTUP_WAIT` becomes platform-specific: ten seconds on Darwin,
zero everywhere else. A zero budget means the wait performs no probe and no
sleep — the Linux startup path is byte-for-byte the path that existed before
C006: the listener binds as soon as the worker starts.

The `WorkerConfig::backend_startup_wait` knob stays, so the bound is still
explicit and testable, and a caller that wants a wait on another platform can
still ask for one.

### 3.2 The Linux harnesses get their strictness back

The three raised deadlines revert to 5 s. With the product no longer
delaying the Linux listener, the strict deadline is correct again — and it
is what makes a future startup delay visible instead of tolerated.

### 3.3 The records stop claiming otherwise

C006's closure record keeps its own history but stops asserting that Linux
was untouched; it points at C009. The registry and the corrective roadmap
carry C009.

## 4. Ordered work packages

1. `src/management/worker.rs` — the platform-specific bound, and a unit test
   that pins the bound per platform.
2. `tests/operational_events.rs`, `tests/runtime_stability.rs`,
   `tests/service_lease.rs` — the serve-listener deadline back to 5 s.
3. `tests/architecture_guards.rs` — a guard that the wait is Darwin-gated
   and that the Linux units still order the two services.
4. `plans/closure/macos-native-server-corrective/c006-status.md` — the
   corrected Linux claim, with the pointer to C009.
5. `plans/closure/macos-native-server-corrective/c009-status.md` — this
   corrective's closure record.
6. `plans/registry.md` and
   `plans/subsystems/macos-native-server-corrective-roadmap.md` — C009's
   status.

## 5. Privilege and security effects

None. The change removes a delay; it adds no capability, no socket, no
identity, and no file ownership. The read-only capability request that
C006 introduced is no longer sent on Linux, which is a strict reduction: the
management daemon on Linux talks to the privileged daemon exactly as it did
before C006.

## 6. Compatibility effects

The Linux startup path returns to its pre-C006 behavior: the management
daemon's listener binds immediately, the startup reconciliation runs
immediately, and the degraded-vs-converged reporting is unchanged. The
Darwin path keeps C006's fix, and the Darwin cold-reboot leg keeps its
passing result.

No wire format, schema, protocol message, CLI surface, or installed state
changes.

## 7. Failure, cancellation, and contention semantics

The wait is a bounded, cancellable, side-effect-free probe loop, and it is
gone on Linux. Nothing else changes about the worker's failure semantics:
ADR-002's "the listener must come up either way" holds on both platforms.

## 8. Focused tests

- Unit (in-module): the bound is ten seconds on Darwin and zero elsewhere;
  a zero budget performs no probe and returns immediately.
- Guard: the wait is platform-gated, and the Linux units still order the two
  services.
- The Linux native CI: the three failing jobs must go green again, and the
  three harnesses whose deadlines were raised must still pass at 5 s.

## 9. Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo check --locked --target x86_64-apple-darwin --all-targets --locked
```

Plus the **Linux native CI**, which is the only environment that can run the
three Linux-only suites, and the macOS qualification workflow for the Darwin
path.

## 10. Documentation updates

- `plans/closure/macos-native-server-corrective/c006-status.md` — the
  corrected Linux claim.
- `architecture/privilege-boundary.md` — the Darwin-only bound, where the
  wait is described.
- `plans/registry.md`, `plans/subsystems/macos-native-server-corrective-roadmap.md`.

## 11. Acceptance criteria

1. On Linux the management daemon's listener binds as it did before C006:
   the three Linux CI jobs that fail at the C006 head are green.
2. The three Linux harnesses whose deadline C006 raised pass again at 5 s.
3. The Darwin path is unchanged: the wait is still ten seconds there, and
   the Darwin cold-reboot leg's fix still stands.
4. The bound is explicit, per platform, and pinned by a test.
5. No record claims that C006 left Linux untouched.

## 12. Stop conditions

Stop and record the discrepancy rather than working around it if:

- restoring the 5 s Linux deadlines makes the Linux harnesses flaky for a
  reason that is not the startup delay — then the deadline is the wrong
  thing to fix, and the flakiness is its own finding;
- the Linux startup path turns out to need *some* wait, which would mean
  the Linux units' ordering is not what the unit files claim, and that is a
  defect in the units, not in the bound.

## 13. Closure evidence requirements

`plans/closure/macos-native-server-corrective/c009-status.md` must record:
the implementation head and baseline, the requirement-to-evidence matrix
against §11, the exact commands and their output, the Linux CI runs at the
failing head and at the fixed head with the per-job results, the macOS
qualification result for the Darwin path, the security evidence, the
documentation evidence, the known limitations, the findings by severity, and
an explicit disposition. C006's own record stays period-accurate: it keeps
what it did and stops claiming what it did not.
