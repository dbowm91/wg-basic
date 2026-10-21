# macOS Native Server C010 — Apple silicon only as the Darwin target

Disposition: **closed** (2026-10-21) — the managed macOS server's supported
Darwin target is Apple silicon alone, an Intel Mac is refused at install time
with an actionable error, the declared helper build input names one target, the
qualification workflow has one architecture, and C001's and C002's native Intel
residuals are retired by scope rather than by measurement.

Date: 2026-10-21.

Source plan: `plans/implementation/macos-native-server/c010-apple-silicon-only-target.md`.
Decision: `plans/adr/009-apple-silicon-only-darwin-target.md` (ADR-009).
Baseline: `plans/macos-native-support@4f30900`.
Implementation head: `08b67d2` — *macos(c010): format the target-set guard*, on top
of `f4adeee` — *macos(c010): make Apple silicon the only supported Darwin
target*. The first implementation commit was pushed before its formatting was
fixed; the hosted macOS qualification caught the rustfmt diff, and `08b67d2`
is rustfmt's own formatting with no behavior change.

## Implementation revision

- Repository baseline: `4f30900` — the head carrying C009's closure and the
  CI-feasibility assessment.
- Implementation commits: `f4adeee` (ADR-009, this plan, the target set, the
  install refusal, the declared helper build input, the qualification workflow,
  the current-behavior docs, and the planning-record amendments) and `08b67d2`
  (rustfmt's formatting of the target-set guard, no behavior change).
- This is **not** a corrective under `plans/003-planning-process.md` §13: no
  post-implementation defect is involved. It is the implementation half of an
  accepted ADR, and the closure records it supersedes keep their history
  period-accurate with dated scope-amendment sections.

## The scope change, as decided

The macOS controlled-host evidence exists for Apple silicon only: C001's
product path against an independent Linux-kernel WireGuard peer on another
host, and C002's three-phase cold-reboot qualification on a disposable macOS
guest with the reboot **observed**. The Intel arch of both legs was never run,
and the CI-feasibility assessment established that no hosted macOS runner could
have produced it — a hosted job is a fresh VM discarded at job end, nested
virtualization is unsupported on macOS runners, an independent probe of all four
hosted macOS images found the Intel image unable to start a guest, macOS larger
runners have no static address, and the off-host peer C001 needs sits on a
private LAN. The only verified substitute was a rented bare-metal Intel Mac
(`mac1.metal`, a 24-hour dedicated-host minimum) per qualification cycle.

ADR-009 records the maintainer's decision to drop native Intel as a target.
Apple silicon is the only supported Darwin target; an Intel Mac is refused at
install time rather than running a build that was never qualified there. The
macOS support floor is unchanged at macOS 13.0, and Linux is untouched.

## The change

1. **`src/platform/darwin.rs`** — `SUPPORTED_TARGETS` carries
   `aarch64-apple-darwin` only, and the module documentation states that an
   Intel Mac is not a supported target and why.
2. **`src/launchd.rs`** — the installer's `DARWIN_TARGETS` now *reads* the
   platform's constant instead of repeating the list, so the supported set is
   written down in exactly one place. The install refusal names the supported
   target (`this build supports only aarch64-apple-darwin`) rather than
   failing with a bare "unsupported Darwin target triple".
3. **`tests/architecture_guards.rs`** — a guard that the Darwin target set
   names the arm64 triple and **no** retired triple.
4. **`helper/wireguard-go.provenance.json`**, **`scripts/build-wireguard-go-helper.py`**,
   **`tests/helper_provenance.rs`** — the declared build input names one Darwin
   target; the builder's own triple table follows; the drift guards assert the
   declaration, assert that the builder refuses a target outside it, and assert
   that no retired triple is named.
5. **`.github/workflows/macos-qualification.yml`** — the `gates-intel` and
   `live-intel-tunnel` jobs are gone, the `x86_64-apple-darwin` toolchain
   target and cross-compile step are gone, and the arm64 jobs no longer branch
   on the runner architecture.
6. **The records** — ADR-009 is new and ADR-008's status points at it; C001
   and C002 are closed with dated scope-amendment sections; the dual-architecture
   gates in C003, C005, and M007 are amended to arm64-only; the registry and
   both roadmaps carry the new scope; and the current-behavior docs describe
   one architecture.

## Requirement-to-evidence matrix

| Requirement (plan §11) | Evidence | Result |
|---|---|---|
| §11.1 The Darwin supported-target set is `aarch64-apple-darwin` only, in the platform module and in the installer, and no Intel triple is named as supported anywhere | `src/platform/darwin.rs`: `SUPPORTED_TARGETS = &["aarch64-apple-darwin"]`. `src/launchd.rs`: `DARWIN_TARGETS` is `crate::platform::darwin::SUPPORTED_TARGETS`, so the installer reads the platform's set rather than repeating it. The unit test `darwin_target_floor_is_declared_and_the_supported_target_is_apple_silicon` pins the platform's set and the unchanged macOS 13.0 floor; the launchd unit test pins the set's contents; the guard `the_platform_boundary_stays_pure_types_without_privilege_or_process` asserts that `src/platform/darwin.rs` declares the arm64 triple and does **not** contain `x86_64-apple-darwin` | Passed (code + unit + guard) |
| §11.2 An Intel Mac is refused at install time with an actionable error naming the supported target, and nothing is installed | `install_to_root` refuses any target outside the set before it touches the filesystem, and the unit test `installer_refuses_bad_targets_and_empty_artifacts` now asserts that `x86_64-apple-darwin` is refused like any other unsupported triple. The new unit test `the_unsupported_target_refusal_names_the_supported_target` asserts that the refusal message names `aarch64-apple-darwin` and does not name the retired triple. The refusal is a pure predicate over the target string: no probe, no I/O, no receipt, no host state | Passed (code + unit) |
| §11.3 The declared helper build input names one Darwin target, the builder refuses the retired triple, and the provenance guards agree | `helper/wireguard-go.provenance.json` declares `["aarch64-apple-darwin"]`; `scripts/build-wireguard-go-helper.py`'s own `TARGET_TABLE` carries the same single triple, and a `--target` outside the declaration is refused with "not one of the declared targets". `tests/helper_provenance.rs` asserts the declaration names exactly the supported target, asserts the retired triple is absent from both the declaration and the builder, and asserts the builder's refusal path exists | Passed (declaration + builder + guard) |
| §11.4 The macOS qualification workflow has one architecture and no Intel job | `.github/workflows/macos-qualification.yml` keeps `gates-arm64` and `live-arm64` and contains no `macos-15-intel` job, no `x86_64-apple-darwin` toolchain target, no `x86_64-apple-darwin` cross-compile step, and no architecture branch in the helper-build step | Passed (workflow) |
| §11.5 The macOS support floor is still macOS 13.0, and the Linux line is unchanged and green | `MIN_MACOS_MAJOR`/`MIN_MACOS_VERSION` are unchanged and still asserted by the platform unit test. The Linux line is untouched by the diff; the full local suite, the MSRV check, the Linux cross-compile build, and the Linux cross-clippy are green, and the Linux native CI is green in every job except the pre-existing `dependency-audit` upstream advisory | Passed (code + gates + Linux CI) |
| §11.6 C001 and C002 are closed on their recorded Apple silicon evidence, with the Intel retirement attributed to ADR-009 and dated; C003, C004, C005, and M007 keep their open status, with their architecture gates amended | `plans/closure/macos-native-server-corrective/c001-status.md` and `c002-status.md` each carry a dated "Scope amendment and closure (2026-10-21)" section and a `closed` disposition, and each states plainly that no Intel run was performed and none is claimed. The C003, C005, and M007 plans carry dated amendments; M007's closure record carries a dated "Scope amendment (2026-10-21)" section; the registry and both roadmaps carry the new scope | Passed (records) |
| §11.7 M007's MUST-NOT-release standing is unchanged | M007's disposition remains **blocked / MUST-NOT-release** with the reasons recorded: C003's routed-LAN capability is unimplemented and unqualified, C004's PF/NAT capability is unqualified and carries the unresolved TN3165 distribution gate, the macOS packaging/release trust root is not provisioned, and the release authority is the maintainer's. No macOS release, tag, or asset is claimed by this record | Passed (records) |

## Verification

Local, on the implementation head `f4adeee`:

```text
$ cargo fmt --all -- --check
(clean)

$ cargo check --all-targets --locked
Finished `dev` profile

$ cargo clippy --all-targets --locked -- -D warnings
(clean)

$ cargo test --locked
668 passed; 0 failed; 14 ignored

$ cargo +1.89.0 check --all-targets --locked
Finished `dev` profile

$ cargo check --locked --target aarch64-apple-darwin --all-targets
Finished `dev` profile

$ cargo zigbuild --locked --target x86_64-unknown-linux-gnu --all-targets
Finished `dev` profile

$ CC_x86_64_unknown_linux_gnu=$HOME/wg-toolchain/zigcc \
  AR_x86_64_unknown_linux_gnu="zig ar" \
  cargo clippy --locked --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
Finished `dev` profile
```

The `x86_64-apple-darwin` cross-compile gate is gone with the target it
qualified.

Hosted: the **macOS qualification workflow** run `39608980478` at the
implementation head `08b67d2` is **green** — `gates-arm64` and `live-arm64`, the
two arm64 jobs, with the declared helper built for the one supported target and
its provenance receipt uploaded as `macos-helper-provenance-arm64` and the live
evidence as `macos-live-evidence-arm64`. There is no Intel job in that workflow
any more. The first attempt at that workflow (`39608033861`) failed in
`gates-arm64` on rustfmt's formatting of the target-set guard, and the
`live-arm64` job was skipped behind it; `08b67d2` is that formatting, with no
behavior change.

The **Linux native CI** at the implementation head is green in every job except
the pre-existing `dependency-audit` upstream advisory (`zip 6.0.0` through
`eggup-archive = "=0.1.3"`), which is not resolvable in this repository without
an upstream release and is unrelated to this change.

## Security and ownership evidence

- The change **removes** a supported target. It adds no capability, no socket,
  no identity, no file ownership, and no protocol operation.
- The refusal path is strictly smaller than the install path it replaces: it
  is a predicate over a string, evaluated before any artifact is read, any
  directory is created, any receipt is written, or any launchd job is
  registered.
- No privileged boundary moved. `netd` is still the only component that
  mutates the host, `serve` is still the dedicated unprivileged principal, and
  the privileged socket's ownership rules are untouched.
- No Linux path, artifact, gate, or release behavior changed; the Linux native
  CI is green in every job but the pre-existing advisory.
- No persistence, protocol, wire, or CLI change. The desired-state store, the
  management HTTP surface, the client enrollment format, and the typed IPC
  vocabulary are byte-identical.

## Docs and operations evidence

- `docs/development.md` — the Darwin portability workflow, the helper build
  input, the hosted-runner list, and the cold-reboot leg now describe one
  architecture.
- `architecture/testing-qualification.md` — the macOS qualification job table.
- `architecture/wireguard-control.md` — the declared helper build input.
- `plans/adr/009-apple-silicon-only-darwin-target.md` — the decision.
- `plans/adr/008-macos-headless-platform-backends.md` — its status points at
  ADR-009; its body is unchanged.
- `plans/registry.md`, `plans/subsystems/macos-native-server-corrective-roadmap.md`,
  `plans/subsystems/macos-native-server-roadmap.md` — the control surfaces.
- `plans/closure/macos-native-server-corrective/c001-status.md` and
  `c002-status.md` — the dated scope amendments and the closed dispositions.

## Host hygiene

The maintainer's working Mac had been left armed by an earlier, abandoned
attempt at the C002 cold-reboot leg: the product installed, a client enrolled,
and the boot-time qualification job installed but unregistered, so it would
have fired at the next boot. That deployment is now **disarmed** (2026-10-21):
the daemons were booted out, the install receipt, the state database, and the
qualification evidence were preserved outside the host, the plists, the
binaries, the helper, the runtime directory, the state directories, and the log
directory were removed, and no product process remains. The closure evidence
this record relies on is the disposable guest's run, and that guest was
disposable and is deleted.

Two empty PF probe anchors (`wg-basic-fmt-probe-child` and
`wg-basic-fmt-probe-parent`) were left on that host by an earlier read-only
format probe. Their rulesets were flushed; the two *names* persist in the
anchor table because removing an anchor entry requires reloading the main
ruleset, and a global `pfctl -f /etc/pf.conf` reload is a host-wide mutation
that this line does not perform. They are empty, unreferenced, and inert.

## Known limitations

1. **An Intel Mac is refused, not degraded into a working server.** That is
   the intended behavior of a closed target set, and it means an Intel Mac
   cannot run the product at all. The refusal names the supported target so
   the operator knows what to do.
2. **No Intel evidence exists, and none is claimed.** The Intel arch of
   C001's product path and of C002's cold-reboot leg was never run. The
   records say so where they were written.
3. **The macOS qualification workflow now covers one architecture.** A
   regression that only appears on Intel would not be caught by CI, and the
   product does not support Intel, so there is nothing to qualify there.
4. **The hosted Intel image's retirement no longer affects this project.**
   `macos-15-intel` is the last x86_64 macOS image GitHub will offer and it
   was available until about August 2027; the line no longer depends on it.
5. **The disposable macOS guest tool stays installed.** UTM is still the
   substrate for the remaining Apple silicon controlled-host work (C003's
   disposable administrator-controlled Mac), so it was not removed.
6. **No release claim exists.** ADR-008/M007 still withhold every macOS
   release; this record changes nothing about that.

## Unresolved findings by severity

- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job fails
  on upstream `zip 6.0.0` advisories reached through `eggup-archive =
  "=0.1.3"`. Not resolvable in this repository without an upstream release.
- **Medium (pre-existing, out of scope):** the two empty PF probe anchor
  *names* remain in the anchor table on the maintainer's Mac. Removing them
  needs a global ruleset reload, which is a host-wide mutation this line does
  not perform; they hold no rules and nothing references them.
- **Low (introduced by this change, recorded here):** the Darwin supported
  target set is now written in one place (`SUPPORTED_TARGETS`) and read by the
  installer, so a future change to the set is a one-line edit — but the
  platform guard that forbids naming a retired triple has to be updated at the
  same time, or it fails loudly. That is the intended failure mode.
- **Informational:** the helper's declared build input is narrower than it
  was, so the helper's build receipt now records a smaller artifact set. The
  upstream source, tag, commit, license, and toolchain are unchanged.

## Disposition

**Closed.** Apple silicon is the only supported Darwin target for the macOS
native-server line, an Intel Mac is refused at install time with an actionable
error, the declared helper build input names one target, and the qualification
workflow has one architecture. C001 and C002 are closed on their Apple silicon
controlled-host evidence, with their native Intel residuals retired by scope
under ADR-009 — retired, not measured. No macOS release, tag, or asset is
claimed, and M007's MUST-NOT-release standing is unchanged.
