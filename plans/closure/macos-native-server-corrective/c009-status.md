# macOS Native Server C009 — Restore the Linux Startup Path

Disposition: **closed** (2026-10-21) — C006's backend startup wait is Darwin's
alone again, the Linux startup path is what it was before C006, the three
Linux CI jobs that C006 broke are green again, and C006's closure record no
longer claims that nothing it did touched Linux.

Date: 2026-10-21.

Source plan: `plans/implementation/macos-native-server/c009-restore-the-linux-startup-path.md`.
Baseline: `plans/macos-native-support@e37210b` (C006's implementation head).
Implementation head: `c4daf35` — *macos(c009): make the backend startup wait
Darwin's alone again*.

## Implementation revision

- Repository baseline: `e37210b` — C006's implementation.
- Implementation commit: `c4daf35` — the Darwin-only bound, the harness
  bounds derived from it, the guard, the unit test, and the correction to
  C006's record.
- C006 is the corrective this one follows. C006's own closure record
  (`plans/closure/macos-native-server-corrective/c006-status.md`) claimed
  that neither of its fixes "touches Linux" and that on Linux "the probe
  succeeds on the first attempt". The first claim was false and the second
  was true in production and false in every Linux harness that starts the
  management daemon without a privileged daemon beside it. Per
  `plans/003-planning-process.md` §13 a material post-implementation defect
  receives its own corrective, so C006's record keeps its history, carries a
  correction, and points here; it is not rewritten.
- This corrective's own scope is narrow: restore the Linux startup path, and
  make the Linux harnesses strict again.

## The defect, as observed

C006 added `wait_for_backend` to the management worker's startup and applied
it on **every** platform (`BACKEND_STARTUP_WAIT = 10s`, unconditional). On
Linux the management daemon therefore sat in the wait for the full ten
seconds before its HTTP listener bound, whenever the privileged daemon's
socket was not there — which is the case in every Linux harness that starts
`serve` without a netd.

The Linux native CI shows it. At the C006 head and at every head since,
three jobs fail; at the pre-C006 head `cdc4439` they pass:

| Linux CI job | Failing assertion | Message |
|---|---|---|
| `rust` | `tests/service_footprint.rs:613` | `the_management_surface_meets_its_footprint_and_latency_shape` |
| `upgrade-rehearsal` | `tests/upgrade_rehearsal.rs:138` | `serve did not bind` (5 s deadline) |
| `upgrade-rehearsal-rootful` | `tests/upgrade_rehearsal_rootful.rs:146` | `serve did not bind` (5 s deadline) |

C006 also **masked** the regression where it could: three Linux harnesses
(`tests/operational_events.rs`, `tests/runtime_stability.rs`,
`tests/service_lease.rs`) had their serve-listener deadline raised from 5 s
to 30 s, "after that budget when no backend is running". The three files
above kept their own 5 s deadlines, so they are the ones that broke — and
the raised deadlines are why the red runs looked like a single pre-existing
`dependency-audit` advisory.

## The correction

1. **`src/management/worker.rs`** — `BACKEND_STARTUP_WAIT` is
   platform-specific: ten seconds on Darwin (`#[cfg(target_os = "macos")]`),
   zero everywhere else. A zero budget means the wait performs **no probe
   and no sleep**: the deadline is checked before the request, so the Linux
   path neither talks to the backend nor waits for it. The
   `WorkerConfig::backend_startup_wait` knob is unchanged and still
   explicit.
2. **The three Linux harnesses** — their listener bound now *follows the
   product's own wait* (`BACKEND_STARTUP_WAIT + 5 s`) instead of a raised
   constant. On Linux that is five seconds, exactly what it was before
   C006; on Darwin it is the wait the boot-race fix legitimately needs, plus
   the same slack. A future startup delay that the product does not have is
   therefore not tolerated by the harnesses.
3. **The records stop claiming otherwise** — C006's §4 row and its
   disposition carry the correction and point here.

## Requirement-to-evidence matrix

| Requirement (plan §11) | Evidence | Result |
|---|---|---|
| §11.1 On Linux the management daemon's listener binds as it did before C006: the three Linux CI jobs that fail at the C006 head are green | `src/management/worker.rs`: `BACKEND_STARTUP_WAIT` is `Duration::ZERO` off Darwin, and `wait_for_backend` checks the deadline before it sends a request, so a zero budget is a true no-op. The Linux CI at the fixed head: the `rust`, `upgrade-rehearsal`, `upgrade-rehearsal-rootful`, and every other job are green except the pre-existing `dependency-audit` upstream advisory | Passed (code + Linux CI) |
| §11.2 The three Linux harnesses whose deadline C006 raised pass again at 5 s | The three harnesses derive the bound from `BACKEND_STARTUP_WAIT + 5 s`, which is five seconds on Linux. On the Linux CI at the fixed head, `operational_events`, `runtime_stability`, and `service_lease` pass with that bound | Passed (code + Linux CI) |
| §11.3 The Darwin path is unchanged: the wait is still ten seconds there, and the Darwin cold-reboot leg's fix still stands | `#[cfg(target_os = "macos")]` keeps the ten-second bound on Darwin; the unit test `the_startup_wait_bound_is_darwin_specific` pins both. The macOS qualification workflow's live jobs — which exercise the Darwin boot path's own fixtures — are green at the fixed head | Passed (code + unit + hosted) |
| §11.4 The bound is explicit, per platform, and pinned by a test | `BACKEND_STARTUP_WAIT` is a named constant with a platform split, exported as `wg_basic::management::BACKEND_STARTUP_WAIT`; the unit test pins the value per platform and pins that a zero budget neither probes nor sleeps; the guard `the_backend_startup_wait_is_darwin_specific` pins the split in the source and pins that the Linux units still order the two services with `Requires=`/`After=` — the reason Linux does not need the wait | Passed (code + unit + guard) |
| §11.5 No record claims that C006 left Linux untouched | C006's §4 row now reads "Corrected 2026-10-21" and points at C009; its disposition carries the correction; the registry and the corrective roadmap carry C009 | Passed (records) |

## Verification

Local, on the implementation head:

```text
$ cargo fmt --all -- --check
(no output — clean)

$ cargo clippy --all-targets --locked -- -D warnings
(no output — clean)

$ cargo test --locked
666 passed; 0 failed

$ cargo +1.89.0 check --all-targets --locked
Finished `dev` profile
```

Hosted: the **Linux native CI** is the only environment that can run the
three Linux-only suites, so it is the evidence that matters here. Run
**39564492722** (head `c4daf35`, `pull_request`):

| Linux CI job | At the C006 head | At the fixed head |
|---|---|---|
| `rust` | failure (`the_management_surface_meets_its_footprint_and_latency_shape`) | **success** |
| `upgrade-rehearsal` | failure (`serve did not bind`) | **success** |
| `upgrade-rehearsal-rootful` | failure (`serve did not bind`) | **success** |
| `dependency-audit` | failure (upstream `zip 6.0.0` advisory) | failure (the same pre-existing advisory) |
| `doctor-readonly`, `update-transaction-rootful`, `system-install-systemd`, `durable-backup`, `product-management-rootful`, `wireguard-kernel`, `durable-owner`, `durable-restart`, `network-reconcile-kernel`, `network-control-e2e`, `maintenance-rootful` | success | success |

The three jobs that C006 broke are green, and the only remaining red job is
the pre-existing upstream advisory, which is not resolvable in this
repository and is recorded below.

The macOS qualification workflow covers the Darwin path at the same head.

## Security and ownership evidence

- The change **removes** a delay. It adds no capability, no socket, no
  identity, no file ownership, and no protocol operation.
- On Linux the management daemon no longer sends the read-only capability
  request that C006 introduced: the Linux management daemon talks to the
  privileged daemon exactly as it did before C006. That is a strict
  reduction in what the management daemon does at startup.
- The Darwin path keeps C006's fix, and C006's read-only probe remains a
  read-only probe of a socket the management daemon is already allowed to
  use, with the same peer-credential check.
- ADR-002's "the listener must come up either way" holds on both platforms:
  the wait is bounded on Darwin and absent elsewhere, and a backend that
  never answers still leaves a degraded startup attempt rather than a
  listener that never comes up.

## Docs and operations evidence

- `plans/closure/macos-native-server-corrective/c006-status.md` — the
  corrected Linux claim and the pointer here.
- `architecture/privilege-boundary.md` — the bound is described as the
  Darwin-specific startup wait it now is.
- `plans/registry.md` and
  `plans/subsystems/macos-native-server-corrective-roadmap.md` — C009's
  status and its effect on C006.
- `plans/implementation/macos-native-server/c009-restore-the-linux-startup-path.md`
  — this corrective's plan.

## Known limitations

1. **The Linux startup path is verified by the Linux CI, not by a local
   run.** The three suites that caught the defect are Linux-only, so a
   macOS host cannot reproduce it. The Linux CI is the evidence, and it is
   the environment where the defect appeared in the first place.
2. **The Darwin wait is still ten seconds of listener latency on a host
   where the privileged daemon is absent.** That is C006's deliberate
   trade-off and is recorded there; the harnesses now express it as
   `BACKEND_STARTUP_WAIT + 5 s` rather than as a magic number, so the
   product's bound and the harness's bound cannot drift apart silently.
3. **The wait remains a fixed ten seconds on Darwin.** A host whose
   privileged daemon takes longer than that to bind still starts degraded —
   the wait is bounded on purpose, and ADR-002 accepts a degraded startup
   over a listener that never comes up.
4. **No release claim exists.** ADR-008/M007 still withholds every macOS
   release; this record changes nothing about that.

## Unresolved findings by severity

- **High (introduced by C006's implementation, found by the Linux CI, fixed
  here):** the Darwin boot-race fix was applied on every platform, so the
  Linux management daemon waited ten seconds for a privileged daemon that
  the Linux units had already ordered it behind. The Linux startup path was
  slower than it had ever been, and three Linux CI jobs failed. The wait is
  now Darwin's alone.
- **High (process, fixed here):** the defect was invisible to the gate set
  that C006 was closed against, because the three failing suites are
  Linux-only and the local host is macOS. The closure record's Linux claim
  was therefore made against a gate that could not see it, and the red Linux
  CI was read as the single pre-existing `dependency-audit` advisory. The
  records now say what was observed, and the claim "the Linux native CI run
  of the same head passes every job except the pre-existing
  `dependency-audit`" is only made where a Linux CI run was actually read.
- **Medium (introduced by C006's implementation, fixed here):** three
  Linux harnesses had their listener deadline raised from 5 s to 30 s to
  accommodate the product's new delay, which masked the regression in
  those files. The bound now follows the product's own wait, so the Linux
  harnesses are strict again and a delay the product does not have is not
  tolerated.
- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job
  fails on three upstream `zip 6.0.0` advisories reached through
  `eggup-archive = "=0.1.3"`. Not resolvable in this repository without an
  upstream release; unrelated to this corrective.
- **Informational:** the correction adds a platform split to a constant that
  was previously single-valued, and exports it so the harnesses can derive
  their bound from it rather than hard-coding one.

## Disposition

**Closed.** C006's backend startup wait is Darwin's alone again; the Linux
management daemon binds its listener as it did before C006; the three Linux
CI jobs that C006 broke are green again; the three Linux harnesses that
C006 relaxed are strict again, with their bound derived from the product's
own wait; and C006's closure record carries the correction and points here
instead of claiming that nothing it did touched Linux. No macOS release,
tag, or asset is claimed, and M007's MUST-NOT-release standing is
unchanged.
