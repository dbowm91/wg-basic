# macOS Native Server C013 — Live-qualification observation integrity

Disposition: **closed** (2026-10-22) — the hosted macOS live qualification
asserted what it could not measure, and the product reported two observations
it had not made. The qualification now proves the managed device from the
product's own observation, waits for a quiescent device namespace, retries a
correct refusal with the refusal's own reason recorded, and keeps its evidence
when it fails. The product's interface observation is fallible and its
failures are named, an unreadable inventory is no longer an empty one, and
the ownership proof compares the helper's path as the file it names rather
than as the string it was spelled. The hosted macOS live job and the
controlled-host Linux qualification are green on the final head.

Date: 2026-10-22.

## 1. What was wrong

Three defects, one family: **something was reported that had not been
observed.** Two of them made the hosted macOS live job red on two of twenty
runs, with no code change between the red and the green runs.

### 1.1 The qualification compared two different moments (the observed flake)

The C001 live test took a snapshot of the host's `utun` inventory at the start
of the test and then asserted that the device the product chose was **not** in
that snapshot:

```rust
let baseline = utun_names();                 // ifconfig -l, at T0
...
let (child, utun) = spawn_managed_tunnel(&identity)...;   // the product's own observation, at T2
assert!(!baseline.contains(&utun), "the managed device must be new, ...");
```

macOS **recycles `utun` indices**. The host creates and destroys `utun`
devices on its own, and a destroyed device's index is handed to the next
device. So a device that existed at *T0* can be destroyed before the product's
own snapshot at *T1*, and the kernel can hand that same index to the helper
the product spawns at *T2*. The product's before/after diff then correctly
reports the device as new — and the qualification's stale snapshot still names
it, so the assertion fires **on correct product behaviour**.

The recorded failure is exactly that. From run `39816330341`:

```
[live-evidence:c001-production-backend] helper created utun4
thread '...' panicked at tests/wireguard_darwin_live.rs:1431:5:
the managed device must be new, not an adopted foreign device
```

The second symptom was the same churn seen from the other side. When the host
creates a device *inside* the product's spawn window, the product's diff sees
more than one new device and correctly refuses to identify its own — it will
not adopt a device by number. The qualification's `.expect("spawn helper")`
turned that correct refusal into a red build. From run `39844925115`:

```
thread '...' panicked at tests/wireguard_darwin_live.rs:1429:78:
spawn helper: StartupFailed
```

The two mechanisms were checked against each other before the diagnosis was
written down, because "the fixture used a different tool" would have been the
easier story and would have been wrong. They agree: on the maintainer's Mac,
`ifconfig -l` and `getifaddrs` list the same seven `utun` devices, and all
seven have **no IPv4 address** while `getifaddrs` still lists every one. The
defect is not a difference between the mechanisms. It is a difference between
two *instants*, plus index recycling.

### 1.2 The product reported an unreadable inventory as an empty one

`utun_interface_names()` ended in `.unwrap_or_default()`, so a failed
enumeration and an empty host were the same value to every caller. One caller
turned that into a **fail-open**: the teardown wait concluded that a device was
gone when the inventory had merely failed to be read, and dropped the receipt
for a device that was still there.

### 1.3 The ownership proof compared two spellings of one path

The proof checks that the recorded helper pid is still running the recorded
executable, and it compared the kernel's answer with the receipt's string.
The kernel reports the **canonical** path, and on macOS `/tmp` is
`/private/tmp` on every host. Measured on the disposable guest:

```
$ lsof -p <pid> | grep txt
wireguard 43718 root  txt REG 1,16 4674242 105763 /private/tmp/wireguard-go
$ ps -o command= -p <pid>
/tmp/wireguard-go utun
```

The helper was started as `/tmp/wireguard-go` and the kernel knows it as
`/private/tmp/wireguard-go`. The proof called a live, correct helper a
mismatch, so the claim read as stale, the receipt was dropped, and the tunnel
was recreated into the same verdict: **an installation whose helper lives
under a directory that is a symlink could never hold a managed tunnel.** The
hosted runner never sees it, because its helper lives under the runner's
temporary directory, which is not a symlink.

## 2. Why the previous evidence missed it

The hosted macOS job had been green on sixteen of twenty runs. The two red
runs were not a code change: they were two of twenty runs of the *same*
code, and nothing in the job recorded which condition it ran under. The
qualification's own evidence for the failing test was **lost**: the evidence
file was written only when the test succeeded, so the red runs uploaded an
artifact with no transcript of the failing test at all, and the baseline the
assertion compared against was never logged. A flake that cannot be
diagnosed from its own evidence is indistinguishable from a defect that
cannot be found.

## 3. The implementation

| Commit | What it changed |
|---|---|
| `120b1e2` | the product's observation becomes fallible and its failures are named; the spawn returns the inventory it read immediately before the helper started; the qualification proves the managed device from the product's own observation, waits for a quiescent namespace, retries a correct refusal, identifies its own helper by the socket it publishes, and keeps its evidence when it fails |
| `f4bf28d` | the ownership proof compares the helper's path as the file it names; the fixture identifies a control socket by its device and inode rather than by its name |

Plan: `plans/implementation/macos-native-server/c013-live-qualification-observation-integrity.md`.

No new ADR: the ownership model's decisions are unchanged for every
observation that succeeds, the helper's identity pinning and supervision
(ADR-010) are untouched, the privileged trust boundary is untouched, and the
persisted state, the UAPI encoding, the netd/serve protocol, and the
configuration surface are all unchanged. The plan's stop condition — that
identifying the managed device by the UAPI socket the helper published would
be an ADR question — was honoured: the *fixture* identifies its own helper by
the socket, which is the fixture's own business, and the *product's*
identification method was not redesigned.

## 4. Requirement-to-evidence matrix

| Requirement | Evidence |
|---|---|
| The qualification proves the managed device is new, from the product's own observation | `managed_device_is_new(&tunnel.devices_before_spawn, &utun)`; the spawn returns the inventory it read immediately before the helper started; unit regression `the_managed_device_is_proved_new_by_the_products_own_observation` and `a_recycled_index_is_not_an_adopted_foreign_device` |
| A contention refusal is retried, and the retry is recorded | `spawn_managed_tunnel_with_retries`; unit regression `a_contention_refusal_is_retried_and_an_identity_refusal_is_not`; the hosted run's evidence records every attempt and every inventory |
| The refusal's reason is the product's own | `HelperError::DeviceAmbiguous` (`managed_device_ambiguous`) and `HelperError::ObservationFailed` (`interface_inventory_unreadable`); unit regression `a_contended_device_namespace_is_not_reported_as_a_failed_helper` |
| An unreadable inventory is not an empty one | `observe_utun_interfaces()`; `classify_device_observation`; `OwnerClaim::Unreadable` is refused and retried rather than dropped; the teardown wait treats an unreadable inventory as "not yet gone"; unit regression `an_unreadable_inventory_is_not_an_absent_device` |
| The ownership proof accepts the helper that is actually running | `same_file`; unit regression `a_helper_under_a_symlinked_directory_is_still_the_pinned_executable` |
| The fixture identifies its own helper's device unambiguously | the control socket it publishes, by device and inode; the recorded measurement that a respawned helper replaces the socket at the same path with a new inode |
| The fixture's leak claim is about what the fixture created | `assert_fixture_left_nothing` — the helper, the control socket, and the receipt — rather than a set difference against a stale inventory |
| A failing qualification still leaves its evidence | `Evidence` writes its file when the test ends, including when it ends in a panic |
| The product is unchanged for every observation that succeeds | the ownership model's decisions, the helper's argv and digest pinning, and the fail-closed adoption rule are untouched; the whole Linux rootful qualification is green at the final head |
| The controlled Linux platform is unaffected | the full gate order and every rootful suite re-run on the controlled Linux host at the final head |

## 5. Commands and results

Everything in this section was run at the final head `f4bf28d`.

### 5.1 On the maintainer's Mac (the Darwin host)

```
cargo fmt --all -- --check                          GATE_EXIT 0
cargo check --all-targets --locked                  GATE_EXIT 0
cargo clippy --all-targets --locked -- -D warnings  GATE_EXIT 0
cargo test --locked                                 GATE_EXIT 0
cargo +1.89.0 check --all-targets --locked          GATE_EXIT 0
```

The ordinary suite: **43 binaries, 707 passed, 0 failed, 15 ignored**. The
fifteen ignored are the `#[ignore]`d tests the ordinary suite may not run:
the nine Darwin live fixtures, the two Darwin controlled-host legs, the Darwin
routed-LAN leg, the two upgrade-rehearsal fixtures, the canonical-path systemd
installation fixture, and the unrelated-uid IPC privilege check.

The gate order also includes the Linux cross-clippy, so that a Darwin host
type-checks the Linux-gated code:

```
CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets \
    --features linux-integration -- -D warnings      CROSS_CLIPPY_EXIT 0
```

### 5.2 On the controlled Linux host (`sugarwookie@192.168.182.143`)

The canonical platform's own gate order and every rootful suite, at the final
head, with `CI=true` so that a missing namespace or kernel prerequisite fails
the suite instead of skipping the kernel evidence:

```
cargo fmt --all -- --check                                           GATE_EXIT 0
cargo check --all-targets --locked                                   GATE_EXIT 0
cargo clippy --all-targets --locked -- -D warnings                   GATE_EXIT 0
cargo clippy --all-targets --locked --features linux-integration -- -D warnings   GATE_EXIT 0
cargo test --locked                                                  GATE_EXIT 0
cargo +1.89.0 check --all-targets --locked                           GATE_EXIT 0
```

and the rootful suites, each as
`sudo -E env "PATH=$PATH" CARGO_HOME=/tmp/wg-basic-root-cargo CI=true cargo test --locked --features linux-integration --test <target> -- --test-threads=1 --nocapture`:

| Target | Result |
|---|---|
| `wireguard_kernel` | ok — 2 passed |
| `network_reconcile` | ok — 2 passed |
| `network_control_e2e` | ok — 2 passed |
| `durable_owner` | ok — 10 passed |
| `durable_restart` | ok — 9 passed |
| `durable_backup` | ok — 2 passed |
| `product_management_rootful` | ok — 6 passed |
| `maintenance_rootful` | ok — 1 passed |
| `doctor_readonly` | ok — 2 passed |
| `service_rootful_e2e` | ok — 3 passed |
| `upgrade_rehearsal_rootful` | ok — 1 passed: the Phase 8 → current schema migration with real traffic |

**40 rootful tests across 11 targets. No suite skipped, no test ignored, no
test filtered out.** The ordinary suite on the same host: 43 binaries, 664
passed, 0 failed, 3 ignored — the three ignored are the Linux-only canonical
installation and update-transaction fixtures, which the ordinary suite may
not run.

**One run was red, and it is recorded rather than dropped.** The first
ordinary-suite run at this head failed `service_session_restart`:
`a_password_reset_invalidates_every_prior_session_across_a_restart` got HTTP
503 (`unavailable`) where it expected 401. Two facts bound what that is:

- It cannot be this milestone's change. Every product file C013 changed —
  `src/wireguard/darwin.rs`, `src/wireguard/darwin_backend.rs`,
  `src/reconcile/backend_darwin.rs` — is `#[cfg(target_os = "macos")]`, so on
  Linux they compile to nothing, and the failing test is in the HTTP/auth
  path, which C013 never touched.
- It did not reproduce. The whole ordinary suite was re-run at the same head
  and passed (664 passed, 0 failed), and that target was then run **five more
  times in a row**, each green (19.6 s, 16.1 s, 9.1 s, 13.3 s, 16.6 s).

The 503 is the HTTP surface's `unavailable` answer. That surface deliberately
maps a refusal-or-storage failure and an overload to the same status, so the
test's 503 does not by itself distinguish a credential-store that was
unavailable from a worker that was saturated or missed a deadline; what it
does establish is that the request was answered as "unavailable" rather than
as a refusal. The host this ran on is shared with another live session's
build load. The gate is recorded here as **green on re-run**, with the red run
and its resolution stated, rather than as green.

The host's unrelated state was inventoried before and after: the network
namespace list, the links, the IPv4 and IPv6 route tables, the nftables
ruleset and table list, the systemd units matching `wg-basic*`, the canonical
installation paths, and `wg show`. Namespaces, links, the nftables table list,
the units, the canonical paths, and `wg show` are **identical**; the route
tables differ only in the host's own IPv6 router-advertisement expiry counters
counting down, and the ruleset only in docker's own packet counters. No route,
rule, unit, or path was added or removed.

### 5.3 In hosted CI

On the implementation head `f4bf28d`, the macOS qualification workflow
(run `39857083983`): `gates-arm64` **success**, `live-arm64` **success**. The
`CI` workflow (run `39857091088`) is green on every job except
`dependency-audit`, which is red for the upstream reason already recorded and
is not claimed as green; the `Distribution foundation` workflow
(`39857090970`) is green.

The closure head `a91a91f` — the closure record, the registry, the roadmap,
and the documentation, with no change to the product — is qualified in hosted
CI as well: the macOS qualification workflow (`39862764048`) is **success**
on both `gates-arm64` and `live-arm64`, the `Distribution foundation`
workflow (`39862772950`) is **success**, and the `CI` workflow
(`39862772879`) is green on every job except the same `dependency-audit`.

The head that carries **F8** as well, `4423671`, is qualified the same way:
the macOS qualification workflow (`39865061526`) is **success** on both
`gates-arm64` and `live-arm64`, the `Distribution foundation` workflow
(`39865067063`) is **success**, and the `CI` workflow (`39865067046`) is
green on every job except `dependency-audit`. The commit that adds this line
changes only this record, so it carries the same product code and the same
gate results.

The hosted run's own evidence is what the new fixture is for:

```
baseline utun inventory: ["utun0", "utun1", "utun2", "utun3", "utun4"]
utun inventory still moving: ["utun0", …, "utun4"] -> ["utun0", …, "utun3"]
utun inventory quiescent: ["utun0", "utun1", "utun2", "utun3"]
attempt 1: the product will identify its device against ["utun0", …, "utun3"]
attempt 1: the product created utun4 from an inventory of ["utun0", …, "utun3"]
helper created utun4
the managed device is new by the product's own pre-spawn observation
ownership proven jointly from receipt, process, socket, and device
the fixture left no helper, socket, or device behind
```

The baseline is logged, the churn is recorded, and the device is proved new
from the product's own observation.

### 5.4 On the disposable macOS guest (192.168.64.3)

The hosted live qualification had never been run on the guest; it is written
for a hosted runner. Running it there is what exposed §1.3, which the hosted
runner's paths cannot expose.

The guest's own state was restored first: the previous legs had left it with
PF enabled, 45 loaded `wg-basic-v1-*` anchors, and the stale control sockets
of helpers that had been killed. macOS keeps a loaded anchor's *definitions*
across `pfctl -f` and `pfctl -F all`, so each stale anchor was emptied
explicitly; their rules are not inert, because a rule left in a stale anchor
still matches and a recycled `utun` index would make a stale rule match the
wrong device.

The binaries under test were built from the final head on the maintainer's Mac
and staged to the guest, and the digests were compared on both sides before
the run:

```
5459581d32941dad8416ab4f6b70c710fd8c553ba9039ac1829fe74f520e7425  wg-basic
29e3de20d7fe075e9335d9cc955c1c495acaa656038b1bbeeadc1a1352927b4e  wireguard_darwin_live
66890f08b4c4e76491af363c6c7b4d0865d526bbce067fecde17f392b93225dc  wireguard_darwin_routed
ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705  wireguard-go (the pinned helper, unchanged)
```

With the guest restored, the live suite was run as root with the same
invocation the hosted runner uses. **Eight of the nine tests pass.** The one
that does not is `live_forwarding_and_unattached_anchor_probe`, which needs an
echo target that answers:

```
no echo target answers from this runner: without ICMP egress the gateway
path is unprovable here
```

That is a property of the lab, not of the code: the host's `wg-qual` anchor
carries `no nat` for the lab prefixes, so the guest has no Internet egress by
design — the whole point of the lab's setup is that the product's translation
is the only one in the path. The hosted runner answers `8.8.8.8` and the
test passes there. The test's own message says exactly this.

### 5.5 C003's routed-LAN leg, re-run against this head

C003's controlled-host evidence is a historical record and is not rewritten.
It is re-run here so that it remains true of the code this milestone landed.
With the final head's `wg-basic` and `wireguard_darwin_routed` on the guest,
the leg **passes**: `1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered
out`, in 191.1 s.

Measuring what the leg left behind the host is what produced **F8** (§9): the
leg's teardown restores the ruleset and the routes but not the anchor's
loaded rules, and not PF's own state. The product's part is unaffected — it
writes no PF state — and the guest was restored afterwards by emptying every
`wg-basic-v1-*` anchor, moving the leftover anchor files aside, reloading the
stock ruleset, and disabling PF.

## 6. Security and ownership evidence

- **The adoption rule is unchanged.** Exactly one new `utun`, or fail closed.
  The change is that *several* is now reported as contention rather than as a
  helper that failed to start, so the diagnostic names the real condition.
- **The proof is not weakened.** The ownership proof still requires the
  recorded pid to be alive, still running the recorded executable, still
  hashing to the recorded digest, the socket still owner-only and still
  answering, and the device still present. The path comparison became a
  comparison of the files the two paths name, which resolves the false
  negative; a path that cannot be resolved names nothing and matches nothing,
  so the proof still fails closed.
- **A receipt is no longer dropped because of a transient read failure.** A
  claim whose inventory could not be read is neither live nor stale; it is
  refused and retried. The ownership model's decisions for every observation
  that succeeds are unchanged.
- **The qualification cannot launder a product guarantee.** Nothing in this
  change relaxes a product check to make a test pass: the fixture's claims
  were narrowed to what can be proved, and the product's refusals are still
  refusals — they are retried, recorded, and fatal if persistent.
- **No new privilege, identity, socket, or owned file.** The product reads
  one thing it already read. The fixture still runs as root on a disposable
  host.

## 7. Documentation evidence

- `architecture/wireguard-control.md` — the ownership proof compares the
  helper's path as the file it names; the new observation outcomes
  (`DeviceObservation::Unreadable`, `OwnershipOutcome::InterfaceUnreadable`,
  `OwnerClaim::Unreadable`) and the fact that the spawn returns its own
  pre-spawn inventory.
- `architecture/testing-qualification.md` — what the hosted live fixture now
  proves about the managed device, and that a contention refusal is a
  legitimate outcome.
- `docs/development.md` — the live fixture's host requirements: a host whose
  `utun` namespace may churn, a device identified only during a quiescent
  window, and a socket identified by device and inode.
- `.skills/wg-basic-gates/SKILL.md` — the live fixture's contention rule.

## 8. Known limitations

- **The hosted runner remains a hosted fixture.** Nothing here promotes it to
  controlled-host evidence, and the distinction the roadmap draws between
  hosted fixtures and controlled hosts is unchanged.
- **The live suite needs a host with ICMP egress.** It cannot be fully
  qualified on the disposable guest, which has none by the lab's design; the
  hosted runner is the evidence for that test.
- **The two red runs of the hosted live job were a flake, not a
  reproducible failure.** The diagnosis is confirmed by the product's own
  observation and by the guest run, and the fixture now records the condition
  it ran under. What it does not have is a *count*: the hosted job was green
  on sixteen of twenty runs before this change, and this milestone has not
  produced a run-count large enough to show the flake is gone. The change
  removes the two mechanisms the flake was made of, but "no red run observed"
  is not "no red run possible", and the hosted job remains the place where
  that would show up.
- **The product still identifies its device by diffing the host's inventory.**
  On a host whose `utun` namespace churns continuously, the identification can
  keep failing; the product refuses (correctly) and the reconcile retries.
  Identifying the device by the UAPI socket the helper published would be
  stronger, and would not be a numeric guess — but it changes how ownership
  is proven and is therefore an ADR question, which this milestone's stop
  condition explicitly refused to decide. It is proposed as the next
  milestone.
- **The routed-LAN leg's own global inventory comparison is unchanged.** It
  runs on the controlled guest, whose namespace does not churn, and it is
  C003's evidence rather than this milestone's subject.
- **C003's routed-LAN leg leaves its loaded filter rules behind** (**F8**,
  §9). This is a defect in that leg's fixture, not in the product and not in
  this milestone's code; it needs its own corrective, and C003's closure
  record carries the dated §12 amendment that says so.

## 9. Findings, by severity

- **F1 (medium, fixed here): the ownership proof compared the kernel's
  canonical executable path with the recorded path as strings.** An
  installation whose helper path traverses a symlinked directory could never
  hold a managed tunnel: the claim read as stale, the receipt was dropped,
  and the tunnel was recreated into the same verdict. The hosted CI never saw
  it because the runner's temporary directory is not a symlink.
- **F2 (medium, fixed here): the qualification compared the product's chosen
  device against an inventory snapshot taken at a different moment.** With
  macOS recycling `utun` indices, this fired on correct product behaviour and
  made the hosted job red on two of twenty runs.
- **F3 (low, fixed here): the product reported a failed interface
  enumeration as an empty host**, and one caller turned that into a fail-open
  that dropped a receipt for a device that was still there.
- **F4 (low, fixed here): the product reported a contended device namespace
  as a helper that failed to start**, so an operator was told the wrong thing
  and a retrying caller was told there was nothing to retry.
- **F5 (low, fixed here): a failing live qualification lost its own
  evidence**, and the baseline it compared against was never logged — so the
  flake could not be diagnosed from its own artifact.
- **F6 (low, open, proposed): the product identifies its device by diffing
  the host's inventory, which a churning host can defeat.** The product fails
  closed and the reconcile retries, so the behaviour is correct; a stronger
  identification would remove the contention entirely. It needs an ADR.
- **F7 (low, outside this milestone's code, recorded):** the controlled Linux
  host's ordinary suite produced one red `service_session_restart` run — a 503
  where a 401 was expected — on a host shared with another session's build
  load. It did not reproduce: the suite passed on re-run and that target
  passed five consecutive times. It is recorded in §5.2 rather than dropped,
  and it is not this milestone's code.
- **F8 (low, open, proposed, in C003's fixture):** re-running C003's
  routed-LAN leg against this head showed that the leg's teardown does not
  restore the guest's filter. macOS keeps a loaded anchor's **rules** across
  `pfctl -f` and `pfctl -F all`, and the teardown removes the anchor from
  `/etc/pf.conf` and deletes its anchor file without flushing the rules the
  anchor already had loaded, so the operator's filter is left loaded and
  being evaluated, with PF still enabled:

  ```
  $ pfctl -a wg-basic-v1-0349b3e7-3a2e-4a9b-a901-c521c4e31163 -s rules
  pass out on en0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
  pass out on en0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
  pass in on en0 inet from 10.20.20.0/24 to 10.77.0.0/24 flags S/SA keep state
  pass in on en0 inet6 from 2001:db8:20::/64 to 2001:db8:77::/64 flags S/SA keep state
  pass in on utun0 inet from 10.77.0.0/24 to 10.20.20.0/24 flags S/SA keep state
  pass in on utun0 inet6 from 2001:db8:77::/64 to 2001:db8:20::/64 flags S/SA keep state
  pass out on utun0 inet from 10.20.20.0/24 to 10.77.0.0/24 flags S/SA keep state
  pass out on utun0 inet6 from 2001:db8:20::/64 to 2001:db8:77::/64 flags S/SA keep state
  ```

  Two of those rules match on `utun0`, an index macOS recycles, so a later
  tunnel that took it would inherit the previous leg's rules — the hazard the
  leg's own drift control had already established, left behind by the leg
  itself. The fixture's `.drift` file also remains in `/etc/pf.anchors/`. The
  product wrote none of this state, the host is a disposable lab, and the leg
  itself still passes; the defect is in `tests/wireguard_darwin_routed.rs`,
  which is C003's fixture and not this milestone's code. It needs its own
  corrective, and it is recorded in C003's closure record as its dated §12
  amendment. The guest was restored afterwards: PF disabled, the stock
  ruleset, every `wg-basic-v1-*` anchor emptied, and the leftover anchor
  files moved aside.

## 10. Disposition

**Closed.** The hosted macOS live job passes on the final head. The
qualification proves the managed device from the product's own observation,
waits for a quiescent namespace, retries a correct refusal with the refusal's
own reason recorded, identifies its own helper by the socket the helper
published, claims only what it created, and keeps its evidence when it fails.
The product's interface observation is fallible and its failures are named; an
unreadable inventory is no longer an empty one; a claim that could not be
read is refused and retried rather than dropped; and the ownership proof
compares the helper's path as the file it names, so a live, correct helper is
no longer reported as a mismatch.

The controlled Linux platform's whole gate order and every rootful suite are
green at the final head, with the host's unrelated state preserved; one red
ordinary-suite run on that shared host is recorded with its resolution in
§5.2. The routed-LAN leg was re-run on the disposable guest against the final
head's product, so C003's controlled-host evidence remains true of the code
this milestone landed.

Nothing in this milestone widens what C004 may claim: the Darwin
Internet-exit gateway mode remains refused, the supported Darwin target
remains Apple silicon alone under ADR-009, installation and transactional
self-update remain unimplemented, and M007's MUST-NOT-release standing is
unchanged. The dependency audit's status is unchanged and is not claimed as
green.
