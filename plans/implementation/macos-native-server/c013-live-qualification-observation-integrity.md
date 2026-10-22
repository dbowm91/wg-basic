# C013 — Live-qualification observation integrity

Status: **closed** (2026-10-22). The defect is reproduced from CI history and
diagnosed; the implementation and the evidence are recorded in
`plans/closure/macos-native-server-corrective/c013-status.md`.

Repository baseline: `c1d3d7d` (`plans/macos-native-support`).

Source: `plans/subsystems/macos-native-server-corrective-roadmap.md`, the
corrective line of the macOS native-server milestone; this is a corrective of
the corrective line's hosted macOS qualification, not a new capability.

Canonical requirements and ADRs: `plans/000-long-term-specification.md`
(macOS native headless server; the helper owns one kernel-assigned `utunN`
device); ADR-008 (macOS headless platform backends); ADR-009 (Apple silicon is
the only Darwin target); ADR-010 (the privileged authority supervises the
helper it spawned); the corrective roadmap's §5 — *"Run true Mac traffic tests
on disposable consented hosts; no silent skips. Distinguish hosted macOS
fixtures from controlled/rebootable/admin-integrated host evidence."*

Primary work class: **corrective / invariant** — a qualification that asserts
something it cannot measure, plus a product that reports an unreadable
observation as an empty one.

## Objective

Three things, one root cause.

1. The hosted macOS live qualification must assert only what it can prove. It
   currently compares the product's chosen device against a device inventory
   it snapshotted **at a different time**, and macOS recycles `utun` indices.
   The assertion can therefore fire on correct product behaviour, and it has:
   it is the cause of one of the two observed CI failures.
2. The product must not report an observation it failed to make as an
   observation that came back empty. `utun_interface_names()` discards a
   failed enumeration with `unwrap_or_default()`, so "I could not look" and
   "there is nothing there" are the same value to every caller. One of the
   call sites turns that into a **fail-open**: the teardown wait concludes
   that a device is gone when the inventory was merely unreadable.
3. The product must not report a mismatch it cannot prove. The ownership
   proof compares the executable path the kernel reports for the running
   helper against the path the receipt records, as strings. The kernel
   reports the **canonical** path, and `/tmp` is `/private/tmp` on every
   macOS, so a helper installed under a symlinked directory is reported as
   "not the pinned executable" while it is running correctly. The claim then
   reads as stale, the receipt is dropped, and the tunnel is recreated into
   the same verdict: an installation whose helper lives under such a
   directory can never hold a managed tunnel.

## Explicit non-goals

- The ownership model is **not** changed. A managed device is still adopted
  only when exactly one new `utun` appears; the product still refuses rather
  than guessing by number.
- The helper's identity pinning, fixed argv, `env_clear` environment, and
  supervision (ADR-010) are untouched.
- The identification *method* is not redesigned. Identifying the device by the
  UAPI socket the helper published would be a stronger proof, but it changes
  how ownership is proven — that is an ADR question, and this plan stops
  rather than making it (see *Stop conditions*).
- C004's PF/NAT gateway work, the Darwin target set, and the release standing
  are untouched. No claim is made that gateway mode exists.
- The hosted runner stays a **hosted fixture**. Nothing here promotes it to
  controlled-host evidence, and nothing here re-qualifies the routed-LAN leg
  on a controlled host; the leg is re-run only to keep C003's existing
  evidence true on the final head.

## Current repository evidence

The defect is reproduced from the branch's own CI history, not inferred.

| Fact | Source |
|---|---|
| The macOS qualification workflow failed on two heads and passed on others, with no code change between them | runs `39844925115` (`4a772e7`, failure), `39816330341` (`51976cd`, failure), `39813833270` (`b84cb8c`, success), `39816865801` (`4388dce`, success) |
| Both failures are in one test: `live_c001_production_backend_owns_and_configures_a_managed_tunnel` | the two logs above; `8 passed; 1 failed` each time |
| Failure A: `the managed device must be new, not an adopted foreign device` at `tests/wireguard_darwin_live.rs:1431` | run `39816330341` |
| Failure B: `spawn helper: StartupFailed` at `tests/wireguard_darwin_live.rs:1429` | run `39844925115` |
| The product's own log line in Failure A: `helper created utun4` | run `39816330341`, `[live-evidence:c001-production-backend]` |
| The two inventory mechanisms **agree**: `ifconfig -l` and `getifaddrs` list the same `utun0`–`utun6` on the maintainer's Mac, and every one of those devices has **no IPv4 address** while `getifaddrs` still lists it | measured on the maintainer's Mac, 2026-10-22 |
| The fixture's baseline is never logged, and the evidence file is written only on success, so the failing run uploaded **no** artifact for the failing test | `tests/wireguard_darwin_live.rs:1393` (`let baseline = utun_names();`, no log) and `tests/darwin_live_common/mod.rs:79` (`pub fn write(self)`) |
| The product discards a failed enumeration: `utun_interface_names()` ends in `.unwrap_or_default()` | `src/wireguard/darwin_backend.rs:441` |
| The kernel reports the helper's **canonical** executable path while the receipt records the installed path: `/private/tmp/wireguard-go` against `/tmp/wireguard-go` | measured on the disposable guest, 2026-10-22 — `lsof -p <pid>` shows `txt /private/tmp/wireguard-go` for a process started as `/tmp/wireguard-go`, and `/tmp` is a symlink to `private/tmp` |
| A helper's control socket is left behind when it is killed, and a helper given the same recycled index **replaces** it at the same path with a new inode | measured on the disposable guest, 2026-10-22 — the socket's inode changes from 132950 to 132952 across the respawn, and the helper survives the stale file |
| The teardown wait treats an unreadable inventory as "the device is gone" | `src/reconcile/backend_darwin.rs:561` |
| The CI runs the live fixture single-threaded, so test concurrency is **not** the cause | `.github/workflows/macos-qualification.yml:78` (`--ignored --test-threads=1 --nocapture`) |

**The mechanism, stated exactly.** The host's `utun` namespace is not
quiescent: macOS creates and destroys `utun` devices on its own (Apple's
networking services churn them), and it **recycles the index** when a device
goes away. The fixture snapshots the inventory at *T0*; the product snapshots
it again at *T1* and *T2*. If a device with index *N* existed at *T0*, was
destroyed before *T1*, and the kernel handed index *N* to the new helper, then
the product's before/after delta correctly reports *N* as new — and the
fixture's stale snapshot still contains *N*, so the assertion fires on correct
behaviour. The same churn makes the product's delta **ambiguous** (more than
one new device in the window), which the product correctly refuses; the
fixture's `.expect("spawn helper")` turns that correct refusal into a red
build.

## Invariants this change must not break

- **Never adopt or kill a device by numeric guess.** Exactly one new `utun`,
  or fail closed. Unchanged.
- **A receipt that cannot be re-proven is refused, never obeyed.** Unchanged.
- **An unreadable observation is not an absence.** This is the invariant the
  change *establishes*; the product already honoured it everywhere except
  where `unwrap_or_default()` erased it.
- The helper is spawned from a validated absolute path with fixed argv, a
  pinned digest, and a cleared environment. `tests/architecture_guards.rs`
  pins this; the change must not trip a guard.
- **A qualification may not weaken a product guarantee to make itself
  green.** Every fix here is either "assert what can be proved" or "name the
  failure accurately". None of them relaxes a product check.

## Expected production changes

1. `HelperError` gains `ObservationFailed` (the host's interface inventory
   could not be read) and `DeviceAmbiguous` (more than one new device
   appeared, so the device cannot be identified). Each gets a stable
   `as_str()` name.
2. `interface_delta` distinguishes *no new device* from *several new devices*
   instead of collapsing both into `StartupFailed`.
3. A new fallible observation, `observe_utun_interfaces() -> Result<Vec<String>,
   HelperError>`. `utun_interface_names()` stays as the documented best-effort
   view for the presence checks that fail closed anyway, and is no longer used
   where the *reason* matters.
4. `spawn_managed_tunnel` returns a `ManagedTunnel` carrying the helper, the
   device name, **and the inventory it observed immediately before the
   spawn**. That inventory is the product's own evidence that the device is
   new; a caller can now prove "not an adopted foreign device" against the
   same observation the decision was made from, instead of against a snapshot
   of its own.
5. `spawn_managed_tunnel` reports *why* it refused: the helper never
   published a device, the observation stayed ambiguous, or the inventory was
   unreadable.
6. `OwnershipOutcome` gains `InterfaceUnreadable`, and `OwnerClaim` gains
   `Unreadable`. A claim whose inventory could not be read is neither live
   nor stale: the product refuses to act on it and lets the reconcile retry.
   It does **not** drop the receipt — dropping a receipt because of a
   transient read error would destroy a valid proof. The ownership model's
   decisions for every *successful* observation are unchanged.
7. The teardown wait treats an unreadable inventory as "not yet gone" rather
   than "gone". This is a fail-open being closed.
8. The ownership proof compares the running helper's executable path with the
   recorded path **as the files they name**, not as strings. A path that
   cannot be resolved names nothing and matches nothing, so the proof still
   fails closed. The receipt's stored path is unchanged, and a receipt
   written before this change is proved correctly too.

No change to: the persisted state or its schema, the UAPI wire format, the
netd/serve protocol, the configuration surface, or the helper's argv.

## Ordered work packages

- **WP1 — the product's observation becomes fallible and named.** Items 1–3, 5,
  7 above, plus the `claim()` path (item 6). Unit-tested at each decision
  point: the decision functions take the observation as a parameter so all
  three outcomes are reachable without a real host.
- **WP2 — the product's evidence is returned to its caller.** Item 4, with
  the one production call site (`create_managed_tunnel`) adapted. The
  receipt is unchanged: it records the same fields as before.
- **WP3 — the fixture stops claiming what it cannot know.** The hosted live
  fixture proves "the managed device is new" from the product's own
  pre-spawn inventory. The leak check becomes per-device: the devices the
  fixture created must be gone, rather than a set difference against a stale
  snapshot (which the host's own churn can both trigger and hide). The
  fixture's inventory observations are logged. The fixture's *own* helper is
  identified by the control socket it publishes, by the socket's identity
  rather than its name: a device diff cannot be unambiguous on a host that
  creates and destroys `utun` devices on its own, and a recycled index puts
  the new socket at the old socket's path.
- **WP4 — the fixture tolerates a correct refusal.** Before identifying a
  device, the fixture waits for the host's inventory to be **quiescent** (two
  consecutive equal observations). If the product still refuses — which is
  correct behaviour under churn — the fixture waits for quiescence again and
  retries a bounded number of times, recording every attempt and every
  inventory. If the product refuses every time, the test fails, with the
  product's reason and the observed inventories as evidence. The product's
  refusal is never swallowed: it is retried, recorded, and still fatal if
  persistent.
- **WP5 — a failing fixture still leaves evidence.** The evidence file is
  written when the test ends, including when it ends in a panic, so the
  uploaded artifact contains the failing test's own transcript. The baseline
  the fixture compares against is logged.
- **WP6 — regression evidence.** Deterministic unit tests, described below.
- **WP7 — qualification.** The hosted live fixture is run repeatedly on a
  disposable macOS host, and the hosted CI job is run on the final head. The
  C003 routed-LAN leg is re-run on the disposable guest, because WP1–WP2
  change the product code that leg qualified; C003's closure record stays
  period-accurate and its evidence stays true.
- **WP8 — records.** This plan, the closure record, the registry, the
  roadmap, and the documentation below.

## Privilege and security effects

None new. The product reads one more thing from the host — the interface
inventory it already read — and distinguishes the failure. The fixture still
runs as root on a disposable host and still creates a `utun` device; it now
creates it less often, because it waits for a quiescent namespace first.

No new identity, no new socket, no new file the product owns, no change to
the privileged trust boundary.

## Persistence, protocol, and configuration compatibility

None. The state schema, the UAPI encoding, the netd/serve protocol, and the
configuration surface are untouched. `HelperError` and `OwnershipOutcome` are
in-process Rust types; the diagnostic names they carry are additive, and no
wire format changes.

## Failure, cancellation, restart, and contention semantics

- **Contention (the subject of this milestone).** The product's refusal under
  an ambiguous observation is unchanged and remains fail-closed. What changes
  is that the refusal is *named* (`device_ambiguous` rather than
  `helper_startup_failed`), that the fixture retries it a bounded number of
  times on a quiescent host, and that the retry is recorded.
- **Restart.** Unchanged: the receipt, the helper supervision (ADR-010), and
  the ownership re-proof are untouched.
- **Cancellation.** A fixture attempt that is abandoned drops its helper, and
  the helper's device disappears with it; the fixture's next attempt waits
  for quiescence, so a dying device cannot be mistaken for a new one.
- **Unreadable inventory.** New and explicit: the spawn reports it, the
  ownership proof reports it, the teardown keeps waiting, and no receipt is
  dropped.

## Focused tests

Deterministic, and each fails without the corresponding fix:

| Test | Proves |
|---|---|
| `interface_delta` reports *several* new devices as ambiguity, not absence | the product names contention instead of hiding it |
| the ownership decision maps *present*, *absent*, and *unreadable* observations to three distinct outcomes | an unreadable inventory is not an absence |
| the teardown decision treats an unreadable inventory as "not gone" | the fail-open is closed |
| the fixture's "the managed device is new" predicate holds for a device whose index was recycled after the product's own observation, and fails for a device that was present in that observation | the fixture proves what the product proved |
| the fixture's leak predicate reports a device the fixture created as leaked and does **not** report a device the host created on its own | the churn-induced false leak is gone |
| the fixture's retry decision retries a contention refusal and does not retry an identity mismatch | a correct refusal is retried; a real defect is not |
| the ownership proof accepts a helper whose installed path traverses a symlink, and rejects a different file and an unresolvable path | a live, correct helper is no longer reported as a mismatch; the proof is not weakened |

The ordinary gate order runs these on the Darwin host; the hosted macOS
`gates-arm64` job runs them too.

## Linux and network-namespace integration evidence

Not applicable to the defect itself: it is a macOS-host qualification
defect. The Linux evidence is the **non-regression** evidence — the whole
gate order, including the feature-bearing Linux cross-clippy, because the
changed crate is shared. The Linux rootful suites are unaffected by a change
that touches only the Darwin backend, and the C013 closure record says so
rather than implying they were re-qualified for this milestone.

## Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
  --features linux-integration -- -D warnings
```

plus the hosted macOS live job (`.github/workflows/macos-qualification.yml`,
`live-arm64`) on the final head, and the disposable-guest runs of WP7.

## Documentation updates

- `architecture/wireguard-control.md` — the ownership proof, the new
  observation outcomes, and the fact that the spawn returns its evidence.
- `architecture/testing-qualification.md` — the suite catalog: what the hosted
  live fixture now proves, and that a contention refusal is a legitimate
  outcome the fixture must handle.
- `docs/development.md` — the live fixture's host requirements: a disposable
  macOS host whose `utun` namespace may churn, and the rule that a fixture
  identifies its device only during a quiescent window.
- `.skills/wg-basic-gates/SKILL.md` — the live-fixture contention rule.

Current behaviour is described as current behaviour; nothing planned is
written into `architecture/` or `docs/` as if shipped.

## Acceptance criteria

1. The hosted macOS live job passes on the final head, and the fixture
   contains no comparison of the product's device against an inventory
   snapshot taken at a different instant.
2. The deterministic tests above exist and fail without the fix.
3. The live fixture has been run repeatedly on a disposable macOS host
   without a spurious failure, with every attempt and inventory recorded.
4. The product's refusal is named accurately: an ambiguous observation, an
   unreadable inventory, and a helper that never started are three different
   facts in the diagnostic.
5. The Linux gate order, including the feature-bearing cross-clippy, is green
   on the final head.
6. The C003 routed-LAN leg passes on the final head on the disposable guest.
7. The dependency audit's status is unchanged and is not claimed as green.

## Stop conditions

- If identifying the managed device by the UAPI socket the helper published
  turns out to be necessary to make the qualification stable, **stop**. That
  changes how ownership is proven and needs an ADR; it is not this plan.
- If the qualification can only be made stable by weakening a product
  guarantee — relaxing the exactly-one-new-device rule, adopting a device by
  number, or skipping the assertion — **stop**.
- If the disposable macOS host cannot run the live fixture at all, **stop**
  and report; the hosted runner is then the only evidence and the milestone
  stays open rather than claiming a qualification it did not run.
- If any test that mutates the canonical installation paths or the host's
  systemd units would have to run on a working host, **stop**; those are
  disposable-VM-only.
- If the routed-LAN leg fails on the final head for a reason C013 introduced,
  **stop** and open a corrective for that reason rather than amending C003.

## Closure evidence requirements

Per `plans/003-planning-process.md` §6: implementation commits; repository
baseline and final head; a requirement-to-evidence matrix; the exact
verification commands and their results; the network-namespace/real-kernel
evidence the milestone claims (here: the disposable-host live runs and the
hosted job, with the recorded inventories); the security/ownership evidence
(the ownership decisions before and after, per outcome); the documentation
evidence; the known limitations; the unresolved findings by severity; and a
disposition.

The closure record states plainly that the hosted runner is a hosted fixture
and not controlled-host evidence.

## Amendment (2026-10-22): closure

This milestone is **closed**. The three defects are corrected, the
requirement-to-evidence matrix, the exact commands, the findings by severity,
and the known limitations are in
`plans/closure/macos-native-server-corrective/c013-status.md`, and the
implementation heads are `120b1e2` and `f4bf28d` on
`plans/macos-native-support`.

Two of this plan's acceptance criteria need their exact reading, because the
evidence is narrower than the criterion's wording allows it to be.

**Criterion 3 — the live fixture on a disposable macOS host.** The live suite
was run on the disposable guest at the final head with the final head's
binaries (the digests compared on both sides before the run): **eight of the
nine tests pass.** The one that does not is
`live_forwarding_and_unattached_anchor_probe`, and it fails on the lab, not on
the code — the lab's `wg-qual` anchor carries `no nat` for the lab prefixes,
so the guest has no ICMP egress by design, and the test's own message says
exactly that. The hosted runner answers `8.8.8.8` and the test passes there.
This is **not** a run-count large enough to show the flake is gone: the
change removes the two mechanisms the flake was made of, and the hosted job
is where a recurrence would show up. "No red run observed" is not "no red run
possible", and the closure record says so.

**Criterion 5 — the Linux gate order.** The gate order is green at the final
head on the maintainer's Mac **and** natively on the controlled Linux host,
and the feature-bearing cross-clippy is green on the Mac. The controlled
host's ordinary suite produced **one** red run at this head — an unrelated
`service_session_restart` asserting 401 and receiving 503 — which did not
reproduce: the suite passed on re-run and that target passed five consecutive
times. Every product file this milestone changed is
`#[cfg(target_os = "macos")]` and compiles to nothing on Linux, so it cannot
be this change. The red run is recorded in the closure record rather than
dropped, and it is not this milestone's code.

**Criterion 6 — the C003 routed-LAN leg.** It passes on the final head on the
disposable guest, against the final head's product, so C003's controlled-host
evidence remains true of the code this milestone landed. C003's own closure
record is not rewritten.

Criterion 7 holds: the dependency audit is still red for the upstream reason
already recorded, and it is not claimed as green.

Nothing in this milestone widens what C004 may claim. The Darwin
Internet-exit gateway mode remains refused, the supported Darwin target
remains Apple silicon alone under ADR-009, installation and transactional
self-update remain unimplemented, and the M007 MUST-NOT-release standing is
unchanged.
