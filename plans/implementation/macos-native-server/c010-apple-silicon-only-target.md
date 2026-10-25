# macOS Native Server C010 — Apple silicon only as the Darwin target

Status: **active**; the implementation is in this branch and the closure
evidence is in `plans/closure/macos-native-server-corrective/c010-status.md`.
Baseline: `plans/macos-native-support@4f30900`.
Source: ADR-009 (the maintainer's scope decision) and the CI-feasibility
assessment in `plans/subsystems/macos-native-server-corrective-roadmap.md`;
`plans/implementation/macos-native-server/c001-production-wiring-host-only.md`;
`plans/implementation/macos-native-server/c002-launchd-privilege-and-install.md`;
`plans/implementation/macos-native-server/c003-routed-lan-no-nat.md`;
`plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md`;
`plans/implementation/macos-native-server/007-native-e2e-security-release-qualification.md`.
Canonical requirements and ADRs: ADR-008 (the headless macOS server model),
ADR-009 (Apple silicon is the only Darwin target).
Authority: `plans/003-planning-process.md` §3 (ADRs), §5 (implementation
plans), §13 (history stays period-accurate); `AGENTS.md` — Linux behavior must
not regress, and no host-network mutation or speculative architecture outside an
active plan.
Primary class: scope amendment / infrastructure.

## 1. The scope change, as decided

The macOS native-server line qualified its controlled-host legs on Apple
silicon only. The Intel arch of the same legs was never run and could not be
run on any GitHub-hosted macOS runner: a hosted job is a fresh VM discarded at
job end, nested virtualization is unsupported on macOS runners, macOS larger
runners have no static address, and the off-host peer C001 needs sits on a
private LAN. The only verified substitute is a rented bare-metal Intel Mac
(`mac1.metal`: a 2018 Intel Mac mini on a dedicated host with a 24-hour minimum
allocation) registered as a self-hosted runner, paid per qualification cycle,
for a platform Apple is abandoning and that GitHub will stop hosting for
x86_64 macOS after about August 2027.

The maintainer's decision, recorded in ADR-009, is to **drop native Intel as a
target for this line**. Apple silicon is the primary and only Darwin target.

This plan implements that decision. It is not a defect corrective: no
post-implementation defect is involved. It is the implementation half of an
accepted ADR, and the closure records it supersedes stay period-accurate.

## 2. Why the earlier evidence pointed elsewhere

The records said "blocked (narrowed) on the native Intel arch", and that was
literally true: the arm64 product path and the arm64 cold-reboot leg were
proven, and the Intel legs were not. What the records could not say was whether
the Intel legs were *reachable* or merely *unattempted*. The CI-feasibility
assessment in the corrective roadmap answered that: the hosted Intel runner is
a real Intel Mac and executes the product natively, but it cannot be rebooted
and cannot reach the private-LAN peer, so the Intel legs were not merely
unattempted, they were structurally unreachable there. Retiring the scope
resolves C001's and C002's residuals as scope, not as measurement.

## 3. The change

### 3.1 The target set is Apple silicon only

`src/platform/darwin.rs`'s `SUPPORTED_TARGETS` and `src/launchd.rs`'s
`DARWIN_TARGETS` carry `aarch64-apple-darwin` only. The module documentation
states that Intel is not a supported target and why. The macOS support floor
stays macOS 13.0: dropping an architecture is not a floor change.

### 3.2 An Intel Mac refuses, actionably

The installer's target check keeps its closed behavior and becomes specific:
`InstallError::UnsupportedTarget` names the supported triple, so an operator on
an Intel Mac is told what the product supports and that it does not support
their machine. Nothing is installed, no receipt is written, and no host state
changes on the refusal path.

### 3.3 The declared helper build input is one target

`helper/wireguard-go.provenance.json` declares one Darwin target. The builder's
triple table stays a closed mapping, and the declaration remains the authority:
`x86_64-apple-darwin` is now refused by the builder as "not one of the declared
targets". The provenance drift guards follow the declaration.

### 3.4 The qualification workflow has one architecture

`.github/workflows/macos-qualification.yml` keeps the arm64 gates and live job
and drops the two Intel jobs and the Intel cross-compile step. The arm64 jobs
stop installing the `x86_64-apple-darwin` toolchain target and stop
branching on the runner architecture.

### 3.5 The records stop asking for Intel

- The active plans' architecture gates (C003, C005, M007) are amended by dated
  amendment citing ADR-009.
- C001's and C002's closure records get a dated scope-amendment section and
  move to **closed**; their history stays period-accurate.
- The registry and both roadmaps carry the new scope, the two closures, and
  the unchanged release standing.

## 4. Ordered work packages

1. `src/platform/darwin.rs` — the target set and the module documentation.
2. `src/launchd.rs` — the installer's target set, the actionable refusal, and
   the unit assertions.
3. `tests/architecture_guards.rs` — a guard that the Darwin target set is Apple
   silicon only and names no Intel triple.
4. `helper/wireguard-go.provenance.json`, `scripts/build-wireguard-go-helper.py`,
   `tests/helper_provenance.rs` — the declared build input, the builder, and the
   drift guards.
5. `.github/workflows/macos-qualification.yml` — one architecture.
6. `plans/adr/009-apple-silicon-only-darwin-target.md` (new) and ADR-008's
   status line.
7. `plans/implementation/macos-native-server/c010-apple-silicon-only-target.md`
   (this plan) and
   `plans/closure/macos-native-server-corrective/c010-status.md`.
8. The plan amendments (C003, C005, M007), the two closure records
   (C001, C002), the registry, and the two roadmaps.
9. `docs/development.md`, `architecture/testing-qualification.md`, and any other
   current-behavior doc that names an Intel macOS target.

## 5. Privilege and security effects

None. The change removes a supported target; it adds no capability, no socket,
no identity, no file ownership, and no protocol operation. The install refusal
happens before any artifact is written and before any receipt exists, so the
refusal path has strictly less effect than the install path it replaces. No
Linux path is touched.

## 6. Compatibility effects

No wire format, schema, protocol message, CLI surface, or installed state
changes. The management HTTP surface, the client enrollment format, the typed
IPC vocabulary, the desired-state store, and the Linux backends are untouched.
The macOS helper's upstream source, tag, commit, license, and toolchain are
unchanged; only its target list narrows, so the helper's build receipt records
a different (smaller) artifact set than before.

## 7. Failure, cancellation, and contention semantics

The refusal is a pure predicate over the target string: no probe, no I/O, no
retry, no cancellation surface, and no contention. It is therefore safe on a
host with no network, no state, and no privileges beyond the caller's own. The
helper builder's refusal is likewise a pre-flight check on the declaration.

## 8. Focused tests

- Unit: the Darwin target set contains the arm64 triple and not the Intel one;
  the installer refuses `x86_64-apple-darwin` with `UnsupportedTarget`, and
  still refuses an empty artifact and a non-Darwin triple.
- Guard: the Darwin target set is Apple silicon only, and the supported-target
  surface names no Intel triple.
- Provenance: the declared target list is exactly the one supported triple, and
  the builder refuses the retired triple.
- Linux: the full Linux suite and the Linux CI must be unchanged and green.

## 9. Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
cargo check --locked --target aarch64-apple-darwin --all-targets
```

The `x86_64-apple-darwin` cross-compile gate is removed with the target. The
macOS qualification workflow and the Linux native CI are the remaining
environmental evidence.

## 10. Documentation updates

- `docs/development.md` — the Darwin portability workflow and the hosted-runner
  list.
- `architecture/testing-qualification.md` — the qualification job table.
- `architecture/overview.md` and `README.md` — only if they name a macOS
  architecture; their x86_64/aarch64 references are Linux and stay.
- The registry, both roadmaps, the amended plans, and the closure records.

## 11. Acceptance criteria

1. The Darwin supported-target set is `aarch64-apple-darwin` only, in the
   platform module and in the installer, and no Intel triple is named as
   supported anywhere.
2. An Intel Mac is refused at install time with an actionable error naming the
   supported target, and nothing is installed.
3. The declared helper build input names one Darwin target, the builder
   refuses the retired triple, and the provenance guards agree.
4. The macOS qualification workflow has one architecture and no Intel job.
5. The macOS support floor is still macOS 13.0, and the Linux line is
   unchanged and green.
6. C001 and C002 are closed on their recorded arm64 evidence, with the Intel
   retirement attributed to ADR-009 and dated; C003, C004, C005, and M007 keep
   their open status, with their architecture gates amended.
7. M007's MUST-NOT-release standing is unchanged.

## 12. Stop conditions

Stop and record the discrepancy rather than working around it if:

- any Linux path, artifact, gate, or release behavior changes as a side effect;
- the refusal path turns out to touch persistent state, a receipt, or a host
  resource before it refuses;
- removing the Intel triple exposes a code path that was only ever exercised on
  Intel, so that the arm64-only build is not self-consistent;
- the maintenance of an arm64-only target set turns out to require a schema,
  protocol, or state change (it must not).

## 13. Closure evidence requirements

`plans/closure/macos-native-server-corrective/c010-status.md` must record: the
implementation head and baseline, the requirement-to-evidence matrix against
§11, the exact commands and their output, the macOS qualification workflow
result and the Linux CI result, the security evidence, the documentation
evidence, the known limitations, the findings by severity, and an explicit
disposition. C001's and C002's closure records keep what they observed, gain a
dated scope-amendment section, and change their disposition; M007's standing is
restated unchanged.
