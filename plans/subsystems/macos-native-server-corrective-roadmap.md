# macOS Native Server — Post-M007 Integration and Release Corrective Roadmap

Status: active corrective line, 2026-10-21. Source branch `plans/macos-native-support`; corrective handoff recorded at `fc51146e811cabebd042d852449c6e7f4f854265`; **C001 and C002 implemented at `b53ce2d` and now `closed` (2026-10-21)** on their Apple silicon controlled-host evidence, with the native Intel arch of both retired by scope under **ADR-009**; **C006 closed at `e37210b`** — the two boot-path defects C002's cold-reboot qualification exposed are corrected and the leg re-run to a pass; **C007 closed at `1bf4bb3`** and **C008 closed at `62337c5`** — the two defects that no environmental condition prevented fixing; **C010 active** — the Apple-silicon-only target implementation of ADR-009. C003 is **closed** (2026-10-22; its same-day conditional closure is amended by §11 of its closure record, which discharges both conditions through C011 and C012 and evidences the Linux rootful half on a controlled Linux host). **C013 is closed** (2026-10-22) — the hosted live qualification asserted what it could not measure, and the product reported two observations it had not made; the qualification now proves the managed device from the product's own observation, and the product's interface observation is fallible and named. **C014 is raised and registered** (2026-10-23) — the **F8** finding C013's closure record made: C003's routed-LAN **fixture** does not restore the filter it loaded, because macOS keeps a loaded anchor's rules across `pfctl -f` and `pfctl -F all`, because the leg enables PF and never disables it, and because it leaves the `.drift` file behind. The defect is in the fixture, not in the product; C003's traffic evidence and closure stand, and C003's record carries the dated §12 amendment that recorded the finding. **C004 is closed** (2026-10-23) — the product's macOS PF observation became a bounded, installation-scoped write path over one anchor and one anchor file, and the controlled-host run carried real traffic through it: the IPv4 far side observed the **translated** source, the IPv6 far side the **untranslated** one, and the teardown emptied the anchor's two rule classes and left the administrator's parent in place. The mechanism was measured against the real `pfctl` before it was implemented, and the measurement corrected the plan twice: an absent anchor and an emptied one are different facts, and the rendered file's rule order is part of the contract. **C014 is closed** (2026-10-23) — C003's routed-LAN fixture now measures its own restoration, and two runs on the same guest with no PF reset between them leave the main filter and NAT rulesets byte-identical to the baseline. **C015 is raised and registered** (2026-10-23) — the **F10** finding C004's closure record made: the macOS managed interface's own teardown is refused, because the observed address forms never match the desired ones, so `network disable` commits its generation and reports `not yet enforced`. C005 remains open on the scoped network gates and the maintainer's release authority. The original M007 MUST-NOT-release verdict remains binding and nothing in this line changes it.

Authority: `plans/000-long-term-specification.md`; `plans/003-planning-process.md`; accepted ADR-001–009; `plans/subsystems/macos-native-server-roadmap.md`; M003–M007 historical closure records. The original M007 MUST-NOT-release verdict remains binding.

## 1. Evidence-triggered correction

The successful hosted run `38524007872` on native macOS arm64 and Intel (2026-10-14) proves specific low-level operations: WireGuard-Go/utun loopback handshakes, UAPI/ownership, v4/v6 address and route fixtures, PF anchor *unattached* probes, and an arm64 launchd lifecycle test. It does **not** demonstrate end-to-end production appliance convergence.

The missing integration is observable directly at this baseline:

- `src/wireguard.rs::WireGuardBackend` returns `UnsupportedBackend` on Darwin, notwithstanding helper/UAPI logic in `src/wireguard/darwin.rs`.
- `src/reconcile/service_darwin.rs::ReconciliationService` returns `BackendFailure` for plan/apply; the pure Darwin planner and direct live `ifconfig`/`route` fixture are not wired to this service.
- `src/firewall/service_darwin.rs::FirewallService` always returns `Unsupported`, so aggregate convergence through the real typed IPC cannot succeed.
- `src/main.rs::run_darwin` rejects system installation/update; `src/launchd.rs` contains install/plist *fixtures*, not a production CLI installation path.
- `src/launchd.rs::render_plist` does not set a restricted service `UserName`/`GroupName`. A system-domain LaunchDaemon defaults to root, risking root management HTTP/SQLite.
- `src/firewall/pf.rs::attachment_verified` uses substring membership and a filter-OR-NAT predicate; neither proves effective policy attachment for both required rule classes.
- Existing `tests/wireguard_darwin_live.rs` drives low-level helpers and direct host utilities; it does not prove an HTTP → management worker → privileged IPC → helper/reconciliation → SQLite receipt loop.
- Current Eggpack/release artifacts are Linux-only. Native reboot, off-host Linux-kernel interop, externally effective IPv4 NAT, routed IPv6 egress, native Intel launchd, and release binaries remain outstanding.

Prior closures were scoped to their recorded evidence and are **not** retroactively invalidated. This corrective records the product-integration gap those narrower fixtures did not exercise. Do not edit historical closures to claim they did.

**Status of the gap list above (2026-10-20, implementation head `b53ce2d`):** the
gaps above are the ones **C001 and C002 were created to close**, and both plans
are now implemented against them. The Darwin production backend is wired
(no longer `UnsupportedBackend`), the Darwin reconciliation service runs the
typed planner over the real Darwin APIs (no `ifconfig`/`route` subprocess), the
Darwin firewall refuses routed/NAT policies instead of blanket-no-oping, the
launchd plist sets a restricted service identity, and `src/main.rs` exposes a
real `system install/status/uninstall` path. The `pf.rs` `attachment_verified`
weakness is C004's subject and remains open. Both plans were dispositioned
**blocked (narrowed)** because each plan's own acceptance gate requires evidence
a hosted macOS runner cannot produce — see §3. Both are now **closed** (see
§3.1 and the scope decision below): their Apple silicon gates are met by
observed controlled-host evidence, and the native Intel arch of each gate was
retired by scope under ADR-009.

## 2. Product mode separation and release authority

Distinct capability levels, each requiring truthful observation:

1. **Host-only endpoint:** authenticated management; a managed Mac-owned tunnel and local host services; no forwarding/NAT. Supported only after C001 and C002 are evidenced; **not** automatically releasable.
2. **Routed LAN:** forwarding to specifically approved LAN prefixes and verified operator-managed upstream return routes; no NAT. C003 is an additional authorization and security gate.
3. **Internet exit gateway:** explicit administrator-integrated PF filter/NAT for IPv4; IPv6 routed without NAT66. C004; Apple TN3165 restricts this to advanced-administrator opt-in, not general consumer deployment.

C005 governs all distribution decisions. **ADR-008/M007 currently withhold every macOS release.** A separately scoped host-only or routed release requires a *new explicit maintainer decision and ADR/M007 release-criteria addendum* after its own end-to-end security/installation evidence. No implementer may silently remove the M007 IPv4 NAT/reboot gates or reinterpret a green CI job as release authorization. The **dual-architecture** gate was removed, but only by an explicit maintainer scope decision — ADR-009 (2026-10-21), recorded in the ADRs and in M007's own gate — and never silently. Full gateway release additionally requires C004 evidence and the existing M007 residuals.

## 3. Dependency graph and active registry

`C001 production host-only integration` (**implemented at `b53ce2d`; closed 2026-10-21** — no unmet hard predecessor; the **Apple silicon** closure gate is met by a controlled-host run against an off-host Linux-kernel peer, and the native Intel arch of the same path was retired by scope under ADR-009)
  → `C003 routed-LAN integration` (hard C001 closure — **discharged 2026-10-21**; C003's own implementation and qualification **complete and closed 2026-10-22** — the same-day conditional closure amended: its two conditions are corrected by C011, its own Linux breakage by C012, and its Linux rootful half is evidenced natively on a controlled Linux host)
  → `C004 administrator-integrated PF/NAT` (**implemented at `7c7da7b`; closed 2026-10-23** — hard C003 **discharged** by C003's closure; the external controlled host is the existing two-guest topology: the disposable macOS guest is the appliance, the Linux guest is the off-host client and far-side egress endpoint, and this Mac is a pure forwarder, so the product's translation is the only one in the path. The product now owns one installation-scoped anchor and one anchor file, installs and empties them reversibly, proves the parent invokes the anchor in **both** rule classes, and the controlled-host run carried real traffic: the IPv4 far side observed the translated source, the IPv6 far side the untranslated one)

`C002 launchd least-privilege/install` (**implemented at `b53ce2d`; closed 2026-10-21** — integrated closure is hard C001, and the plan additionally forbids closure unless reboot persistence is demonstrated; the three-phase cold-reboot qualification was run end to end on a disposable arm64 macOS guest and **passes** with the reboot observed, and the native Intel arch of the same leg was retired by scope under ADR-009)
  → `C005 native E2E / distribution / release decision` (hard C001 + C002 — **discharged 2026-10-21**; C003 if routed mode claimed — **discharged 2026-10-22** by C003's closure; C004 if gateway claimed — **discharged 2026-10-23** by C004's closure, with the macOS interface teardown's own refusal routed to C015; operational external host/authorization gates; and the maintainer's release authority, which is unchanged).

`C006 boot-time runtime directory and backend readiness` (**closed at `e37210b`** — C002's corrective, raised by the material post-implementation defects the cold-reboot qualification found; no successor depends on it directly, it restores C002's own reboot-persistence gate)

`C007 effective PF attachment verification` (**closed at `1bf4bb3`** — C004's corrective, raised by the one defect in C004's *model* half that no environmental condition prevented fixing; it makes C004's later live backend inherit an exact, per-class verifier, and it does not close C004's live half)

`C008 declared helper build input and provenance` (**closed at `62337c5`** — C005's corrective, raised by the repository-engineering half of C005 item 4; it makes the helper a declared, immutable build input with recorded provenance, and it does not close C005's release half)

| Corrective | Status | Primary class | Plan | Gate |
|---|---|---|---|---|
| C001 — product wiring and host-only convergence | **closed** 2026-10-21; implemented at `b53ce2d`; closure `plans/closure/macos-native-server-corrective/c001-status.md` | corrective / capability / invariant | `plans/implementation/macos-native-server/c001-production-wiring-host-only.md` | Existing M003/M004/M002 primitives — met. Off-host Linux-kernel peer, dual-stack off-host traffic, and API telemetry through the real authenticated HTTP path — **met on Apple silicon** on a controlled host. The native Intel arch of the same path was retired by scope under ADR-009, not by measurement |
| C002 — least-privilege launchd and CLI | **closed** 2026-10-21; implemented at `b53ce2d`; closure `plans/closure/macos-native-server-corrective/c002-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md` | Verified service identity, no root serve — met and observed at runtime. The cold-reboot leg — install, enroll, record the expectations, `shutdown -r now`, and the verify phase in the new boot — is **met on Apple silicon** on a disposable macOS guest: the reboot observed, both roles back from the system domain, the management daemon still unprivileged, the credential and enrolled client survived, the network reconverged, the uninstall leaving nothing behind. The API-traffic leg is met by C001's product path. The native Intel arch of the same leg was retired by scope under ADR-009, not by measurement |
| C006 — boot-time runtime directory and backend readiness (C002's corrective) | **closed** 2026-10-21; implemented at `e37210b`; closure `plans/closure/macos-native-server-corrective/c006-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c006-boot-time-runtime-and-backend-readiness.md` | The privileged daemon creates its own runtime directory when macOS's transient `/var/run` has been recreated; the management daemon waits, bounded, for the privileged daemon to answer before its startup reconciliation; the C002 cold-reboot leg re-run to a pass. **Corrected 2026-10-21 by C009:** the wait reached Linux, where it delayed the listener |
| C009 — restore the Linux startup path (C006's corrective) | **closed** 2026-10-21; closure `plans/closure/macos-native-server-corrective/c009-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c009-restore-the-linux-startup-path.md` | C006's backend startup wait is Darwin's need; Linux's units already order the two services, so the bound is zero elsewhere and the Linux startup path is what it was before C006. The three Linux CI jobs C006 broke are green again |
| C007 — effective PF attachment verification (C004's model carve-out) | **closed** 2026-10-21; implemented at `1bf4bb3`; closure `plans/closure/macos-native-server-corrective/c007-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c007-effective-pf-attachment-verification.md` | The attachment verifier is token-exact and per rule class: a filter-table `anchor` rule and a NAT-table `nat-anchor` rule, each naming the managed anchor as a whole token, and a verdict that is a conjunction over the required classes. A colliding name, a comment, another table's keyword, and a reference to the other class verify nothing |
| C008 — declared helper build input and provenance (C005's repository carve-out) | **closed** 2026-10-21; implemented at `62337c5`; closure `plans/closure/macos-native-server-corrective/c008-status.md` | corrective / infrastructure | `plans/implementation/macos-native-server/c008-declared-helper-build-input.md` | One declared, immutable build input for the `wireguard-go` helper; one builder that refuses a mismatched commit, license, or toolchain and records a provenance receipt; the macOS qualification builds through it on both architectures and keeps the receipt as an artifact |
| C003 — bounded routed LAN | **closed** 2026-10-22 — the same-day conditional closure is amended by §11 of the closure record; implemented and qualified on a controlled host; closure `plans/closure/macos-native-server-corrective/c003-status.md` | corrective / capability | `plans/implementation/macos-native-server/c003-routed-lan-no-nat.md` | **Met on Apple silicon on a controlled host:** the typed mode contract is in the persisted desired state with a schema-8 migration; the Darwin filter is observed read-only and never written, with the exact rules reported to the operator; real IPv4 and IPv6 traffic traversed the tunnel in both directions to an approved prefix and back, a destination outside the approved prefix and a spoofed source were refused, and every missing prerequisite produced its own named refusal. Twelve defects the qualification exposed are corrected, each with a test. Its two conditions are corrected by **C011** and its own Linux breakage by **C012**; its Linux rootful half is now evidenced natively on a controlled Linux host — the ordinary gate order clean, forty rootful tests across eleven targets with no skips, and the host's unrelated state preserved |
| C004 — effective opt-in PF/NAT | **closed** 2026-10-23 — implemented at `7c7da7b`; closure `plans/closure/macos-native-server-corrective/c004-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c004-pf-nat-effective-gateway.md` | TN3165, effective rules and real egress. The product owns one installation-scoped anchor and one anchor file: it installs its rendered filter and translation rules into that anchor with `pfctl -a <anchor> -f <file>`, proves the administrator's parent invokes the anchor in **both** the filter and the NAT table, refuses every incomplete attachment with its own remediation, and empties both classes and rewrites the file to its marker line on teardown. The controlled-host run carried real traffic — the IPv4 far side observed the **translated** source, the IPv6 far side the **untranslated** one — and the four negatives refused with their own remedies. The mechanism was measured against the real `pfctl` first, and the measurement corrected the plan: an absent anchor and an emptied one are different facts, and the rendered file's rule order is part of the contract |
| C014 — the routed-LAN leg restores the filter it loaded (C003's fixture corrective) | **closed** 2026-10-23 — implemented at `7855533`; closure `plans/closure/macos-native-server-corrective/c014-status.md` | corrective / invariant | `plans/implementation/macos-native-server/c014-routed-leg-filter-restoration.md` | The **F8** finding C013's closure record made by re-running C003's routed-LAN leg against C013's final head: the leg's teardown removed the anchor from `/etc/pf.conf` and deleted its file, which restores the *ruleset* but not the anchor's **loaded rules**, because macOS keeps them across `pfctl -f` and `pfctl -F all`; it did not disable PF, which it had enabled; and it did not remove the `.drift` file it wrote for the drift control. Two of the eight leftover rules match on `utun0`, and macOS recycles `utun` indices, so a later tunnel handed that index inherits the previous leg's rules. C014 restores PF's enable state, empties the managed anchor's filter **and** NAT rulesets, removes the anchor's file and its `.drift` sibling, and *measures* the restoration rather than asserting it. The defect is in C003's **fixture**, not in the product: the product writes no PF state, no forwarding sysctl, and no route in the routed-LAN mode, and C003's traffic evidence is unaffected. C003's closure record stays period-accurate and carries the dated §12 amendment that recorded the finding; C014 is where the defect itself is closed. **Closed:** the leg was run twice on the same disposable guest with no PF reset between the runs, and the filter inventory before run 1, after run 1 and after run 2 was captured and compared: both runs passed, the main filter and NAT rulesets were byte-identical to the baseline, PF's enable state was unchanged, and neither the anchor's file nor its `.drift` sibling remained. The only difference is the kernel's own **anchor objects**, which PF never destroys and which held no rules. Closure: `plans/closure/macos-native-server-corrective/c014-status.md` |
| C015 — the macOS managed interface's teardown is refused (C004's finding F10) | **ready** 2026-10-23 | corrective / invariant | `plans/implementation/macos-native-server/c015-macos-interface-teardown-acceptance.md` | The **F10** finding C004's closure record made: the interface layer's delete path compares the observed interface against the desired state, and on macOS the two can never be equal — the product's own `10.77.0.1/24` is observed as `/32` because the utun device is point-to-point, its `2001:db8:77::1/64` is observed as `/128`, and the kernel's link-local address is observed but never listed. `wg-basic network disable` therefore commits its generation and reports `not yet enforced (Degraded(BackendRefused))`, and the managed tunnel device is never removed. The firewall layer's teardown still runs and completes, so C004's anchor work is unaffected. The defect is in the **interface** layer and is outside C004's scope; C015 makes the comparison succeed for the product's own resources and keeps the refusal for a foreign one |
| C005 — integrated release qualification | **open** — C001/C002 closed 2026-10-21 and C003 closed 2026-10-22, so the routed-mode gate is discharged; still blocked on C004 for gateway mode and on the maintainer's release authority | corrective / qualification | `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md` | Native E2E, reboot, the supported architecture, provenance, maintainer authorization |
| C010 — Apple silicon only as the Darwin target (ADR-009's implementation) | **closed** 2026-10-21; closure `plans/closure/macos-native-server-corrective/c010-status.md` | scope amendment / infrastructure | `plans/implementation/macos-native-server/c010-apple-silicon-only-target.md` | The Darwin target set is Apple silicon only, an Intel Mac is refused with an actionable error, the declared helper build input names one target, and the qualification workflow has one architecture |
| C011 — service-lifecycle and helper-recovery correctives (C003's corrective) | **conditionally closed** 2026-10-22 | corrective / invariant | `plans/implementation/macos-native-server/c011-service-lifecycle-and-helper-recovery.md` | The three findings C003's controlled-host run left open: the management service's shutdown is bounded and its stop request cannot be refused; a helper that dies is replaced by the privileged authority that spawned it (ADR-010), and a receipt naming a dead helper no longer wedges the installation; the upstream route shape is verifiable. F1's observation was a misreading of a launchd-restarted successor and is corrected by assertion, not by a rewrite of C003's record. Closure: `plans/closure/macos-native-server-corrective/c011-status.md` |
| C012 — the Linux rootful qualification compiles again (C003's corrective) | **closed** 2026-10-22 | corrective / invariant | `plans/implementation/macos-native-server/c012-linux-rootful-qualification-recovery.md` | C003's policy-model change left the Linux-only fixtures uncompilable, so the Linux CI has been red on every job since `5238816`; the fixtures state their mode and the gate order type-checks the Linux-gated code from a Darwin host. Closure: `plans/closure/macos-native-server-corrective/c012-status.md` |
| C013 — live-qualification observation integrity | **closed** 2026-10-22 | corrective / invariant | `plans/implementation/macos-native-server/c013-live-qualification-observation-integrity.md` | The hosted live job was red on two of twenty runs of the same code and its own evidence for the failing test was lost, so the flake could not be diagnosed from its artifact. The qualification compared the product's chosen device against an inventory snapshot taken at a different moment, which fires on correct product behaviour because macOS recycles `utun` indices; it now proves the device from the product's own pre-spawn observation, waits for a quiescent namespace, retries a contention refusal with every attempt and inventory recorded, identifies its own helper's socket by device and inode, claims only what it created, and keeps its evidence when it fails. The product's interface observation is fallible with its failures named, an unreadable inventory is refused and retried rather than treated as an absent device, and the ownership proof compares the helper's path as the file it names. The product's fail-closed adoption rule is unchanged. Closure: `plans/closure/macos-native-server-corrective/c013-status.md`. **F8**, found by re-running C003's routed-LAN leg against this head: that leg's teardown restores the ruleset and the routes but not the anchor's loaded rules, and not PF's own state, so the operator's filter is left loaded on the disposable guest — a defect in C003's fixture, corrected in C003's closure record by its dated §12 amendment and needing its own corrective |

### Unblock assessment (2026-10-21)

**Nothing downstream unblocks.** C001 and C002 are implemented, but both are
dispositioned **blocked (narrowed)** rather than closed, so their hard
dependencies are unmet:

- **C003 stays blocked on C001.** C001's implementation satisfies the
  *engineering* predecessor; its closure gate (a second, independent
  Linux-kernel WireGuard peer reached through the real authenticated HTTP path,
  with dual-stack traffic and API telemetry on arm64 and Intel) does not. A
  hosted macOS runner has no second kernel.
- **C004 is closed (2026-10-23).** Its `pf.rs` effective-attachment weakness
  was already closed by C007; what remained was the code and the packet
  evidence, and both are produced. The controlled-host run carried real
  traffic through the product's own anchor.
- **C015 is open** on the one defect C004's qualification exposed outside its
  own scope: the macOS managed interface's teardown is refused because the
  observed address forms never match the desired ones.
- **C005 stays blocked on C001 + C002**, plus the claimed-mode gates and the
  operational external-host and maintainer-authorization gates.

Both unmet gates are **environmental, not code defects**, and both are now the
same residual shape — the **native Intel** arch of a path that is proven on
arm64:

- C001's arm64 gate was met by a controlled-host run against an off-host
  Linux-kernel WireGuard peer (real installer, real daemons, real authenticated
  HTTP surface, real handshake, dual-stack traffic, API telemetry). What
  remains is the **native Intel** arch of that same path, whose peer has to be
  reachable from a hosted runner.
- C002's arm64 cold-reboot gate was met by a **disposable arm64 macOS guest**
  where the reboot was taken and observed, both roles came back from the
  system domain, the management daemon was still unprivileged, the credential
  and the enrolled client survived, the network reconverged, and the uninstall
  left no job, plist, or binary behind. What remains is the **native Intel**
  arch of that same leg, because a hosted Intel runner cannot be rebooted and
  no native Intel host is available.

These are the same two residuals M003 (off-host interop) and M006 (reboot)
already record; the C001/C002 implementation narrows the *product* gap without
narrowing those environmental ones. When those hosts exist, the recorded
evidence is expected to satisfy the gates without further implementation, but
the planning process forbids closing a plan from expected evidence, so neither
is claimed.

**C006 closed the material defects, not the architectural residual.** The
first run of C002's cold-reboot leg failed and found two real boot-path defects
in C002's own implementation — macOS recreates `/var/run` at every boot, and
`launchd` starts the two jobs concurrently — so per §13 of the planning process
they were corrected under their own plan and closure record rather than folded
into C002's evidence. The leg was then re-run to a pass. C006 does not narrow
the native Intel residual and does not unblock anything downstream.

#### CI feasibility of the two residuals, and the scope decision (2026-10-21)

The two residuals above were re-assessed against every macOS CI substrate
available today. The assessment did not change the residuals' existence; it
changed their *shape*, and it is what the maintainer's scope decision rests on:

- **The native Intel arch is already in hosted CI.** `macos-15-intel` is a real
  Intel Mac, and this repository's `live-intel-tunnel` job already ran the
  WireGuard control plane there. What the maintainer does not have on the bench
  is Intel hardware; what the *project* lacked in CI was not the instruction set
  but **host lifecycle** and **topology**.
- **No hosted macOS runner can be rebooted, at any tier.** Each hosted macOS
  job is a fresh VM that is discarded when the job ends, and GitHub documents
  that nested virtualization is unsupported on macOS runners. An independent
  probe of all four hosted macOS images found the Intel image equally unable to
  start a guest. Booting a macOS guest inside the runner to reboot it is closed
  by the platform, not by policy, so C002's Intel cold-reboot leg has no hosted
  CI path.
- **A rented bare-metal Intel Mac would have satisfied C002's reboot leg**, and
  C001's peer leg when the peer is a Linux instance in the same cloud network.
  `mac1.metal` is a 2018 Intel Mac mini offered bare metal on a dedicated host
  with a 24-hour minimum allocation; `reboot-instances` is an ordinary OS
  reboot, and the destructive host scrubbing happens on stop or terminate, not
  on reboot. Registering it as a self-hosted runner with the runner application
  installed as a boot-scoped service is the documented way to have it return
  online after the reboot.
- **C003's topology requirement would have been satisfiable on the same
  substrate** — a private subnet inside one VPC is a routed, non-NAT domain
  with two real hosts — but C003 is blocked first by its own implementation
  package (a typed mode contract in the persisted desired state of the released
  v0.1.0, with a state-store migration and old-binary-refusal rehearsals),
  which is an implementation matter, not a CI matter.

**The maintainer's decision (ADR-009, 2026-10-21):** native Intel is dropped as
a target for this line. Apple silicon is the only supported Darwin target, and
an Intel Mac is refused at install time rather than running an unqualified
build. The two residuals are therefore retired **by scope, not by
measurement**: no Intel product-path run and no Intel cold reboot were
performed, and none is claimed. The rented-host route above is not funded and
is not planned; it is recorded because it is the only verified way the Intel
evidence could have been obtained, and a future maintainer may want to know
that. The macOS support floor is unchanged at macOS 13.0, and the Linux line is
untouched.

**C001 and C002 are closed (2026-10-21)** on their Apple silicon
controlled-host evidence, which was already observed and recorded before this
decision. Their closure records carry a dated scope-amendment section and keep
their history period-accurate. **C010** implements the decision: the Darwin
target set, the install refusal, the declared helper build input, and the
qualification workflow all become Apple-silicon-only.

**Host-only mode (capability level 1 in §2) is implemented but not releasable.**
C001 and C002 together deliver the host-only endpoint's mechanics; the
host-only release still requires C005's release decision and the explicit
maintainer ADR/M007 addendum described in §2. Nothing here authorizes a macOS
release, a tag, a release artifact, or a merge as completed support.

**C007 and C008 closed the two reachable defects, not the blocked work.**
The corrective roadmap's evidence-triggered gap list named two defects that
no environmental condition prevents fixing. The PF attachment verifier
failed open — a substring test over two rulesets joined by a disjunction —
and it is now token-exact and per rule class (C007). The helper's build
input was duplicated inside the qualification workflow and declared nowhere
in the repository, and it is now one declared, immutable input with one
builder and a provenance receipt (C008). Neither closes a downstream gate:
C004's *live* half (the bounded `pfctl` backend, the ordering analysis, the
effective-traffic evidence) still waits on C003 and on an
administrator-integrated controlled host, and C005's *release* half (the
Eggpack integration, the exact-target package, the release decision) still
waits on C001 and C002's closure and on the maintainer's authority.

## 4. Cross-cutting invariants and non-goals

SQLite desired generation and CAS remain authoritative; transient PID, utun number, helper socket and runtime receipts are evidence, never an independent desired-state database. `serve` is unprivileged and alone owns SQLite/HTTP; `netd` alone performs typed OS mutations. No arbitrary shell/PF source/file-write/sysctl/route/exec IPC. A foreign link, route, PF anchor, launchd label, helper, or database must never be adopted by name similarity. Re-observe before destructive operations and report conflicts/degraded instead of forging convergence. A zero-rule host-only firewall result is legal *only* when explicit policy and observable host forwarding behavior prove no forwarding or NAT obligation. No Linux semantics, kernel/nft/systemd CI, pre-existing persistent schemas, or checksums-only release truth may regress.

Keep existing `wireguard-go` as the first Darwin dataplane; do not rebuild protocol crypto, select WireGuardKit/NetworkExtension without a separately accepted ADR, or introduce compulsory Homebrew/Go/runtime package manager requirements. Keep PF advanced-admin-only and never edit `/etc/pf.conf` on behalf of the application.

## 5. Qualification and closure protocol

Each corrective creates its own **new** `plans/closure/macos-native-server-corrective/c00N-status.md` only after implementation. Record final SHA, changes, exact command results and run links, OS build/architecture, user/UID permission evidence, full negative controls, network/interface/PF before/after preservation, failure/retry behavior, unresolved findings with severity, and scope-specific verdict.

Normal gates: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo +1.89.0 check --all-targets --locked` on supported native targets, plus all pre-existing rootful Linux CI jobs. Run true Mac traffic tests on disposable consented hosts; no silent skips. Distinguish hosted macOS fixtures from controlled/rebootable/admin-integrated host evidence. The Linux rootful half is additionally run natively on a controlled Linux host with `CI=true`, so a missing namespace or kernel prerequisite fails the suite instead of skipping the kernel evidence, and with the host's unrelated state inventoried before and after — see `docs/development.md`. Do not release, tag, merge as completed support, or create release assets via this planning handoff.

### Applied to C001/C002/C003/C006/C007/C008/C009/C010/C011/C012/C013

Eleven closure records exist under `plans/closure/macos-native-server-corrective/`:
`c001-status.md`, `c002-status.md`, `c003-status.md`, `c006-status.md`,
`c007-status.md`, `c008-status.md`, `c009-status.md`, `c010-status.md`,
`c011-status.md`, `c012-status.md`, and `c013-status.md`. All eleven record the
implementation head, the
requirement-to-evidence matrix, the exact commands and runs, the
security/ownership evidence, the docs evidence, the known limitations, the
findings by severity, and a scope-specific verdict. C006's, C007's, C008's,
C009's, C010's, and C012's are **closed**; C001's and C002's are **closed** as of
2026-10-21, on their Apple silicon controlled-host evidence, with the native
Intel arch of each retired by scope under ADR-009 and the scope amendment
recorded in each record. C003's is **closed** as of 2026-10-22 by a dated
amendment that discharges its two conditions through C011 and its own Linux
breakage through C012, and that adds the controlled-host Linux rootful
evidence its §2 row pointed at but §3 did not contain. C011's is
**conditionally closed**, on the two conditions stated in its §9. C013's is
**closed** as of 2026-10-22: the hosted live qualification asserts only what
it can measure, and the product's own interface observation is fallible,
named, and never mistaken for an empty host.

Four rules from the qualification protocol shaped those verdicts and shape
every later corrective in this line:

1. **A hosted macOS runner is not a controlled host.** It has no second kernel
   to peer with, cannot be cold-rebooted, and carries no stable address or
   surviving state between jobs. Evidence produced there is recorded as hosted
   fixture evidence and is never written up as the controlled-host evidence
   C001/C002's acceptance requires. A self-hosted runner on a bare-metal Mac is
   a different substrate with different properties, and evidence produced on one
   is recorded as controlled-host evidence. That distinction is what the
   CI-feasibility assessment turned on, and ADR-009 resolved the residual by
   retiring the Intel scope rather than by funding that substrate.
2. **A green CI job is not release authorization and not closure.** The
   M007 MUST-NOT-release decision and the §2 release-authority rule are
   unchanged by any implementation in this line.
3. **A material post-implementation defect gets its own corrective.** The
   cold-reboot qualification found two boot-path defects in C002's own
   implementation. Rewriting C002's record so the leg looked as though it had
   always passed would have been a false record, so §13 of the planning process
   was followed: the defects were corrected under C006, with their own plan,
   their own closure record, and their own evidence, and C002's record points
   at them. C007 and C008 followed the same rule: each took one reachable
   defect out of a blocked successor (C004's verifier, C005's build input)
   into its own plan, record, and evidence, and each left its successor's
   own blocked scope exactly where it was.
4. **A fix that is unreachable by a gate is not yet evidenced.** C007's
   correction needed a *live* `pfctl` listing to be meaningful, so the live
   fixture gained the positive, collision, and negative controls it never
   had, and the Intel job was extended to run them too — that job was removed
   when ADR-009 dropped the Intel target. A correction whose
   evidence could only be produced on one architecture would have left the
   same kind of residual C001 and C002 carry.
