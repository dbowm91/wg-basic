# ADR-009 — Apple silicon is the only Darwin target for the native macOS server

Status: accepted (maintainer decision, 2026-10-21)

Date: 2026-10-21

Supersedes: the Darwin target list in ADR-008 §5 ("aarch64-apple-darwin and
x86_64-apple-darwin"). ADR-008's body is otherwise unchanged and stays a
historical record; only its status line points here.

## 1. Context and decision scope

wg-basic's macOS native-server line is a *headless server installed on a Mac*.
Its controlled-host qualification has always been an Apple-silicon exercise:

- the **arm64 product path** (C001) ran as root on a disposable arm64 Mac
  against an independent Ubuntu 24.04 Linux-kernel WireGuard peer on another
  host: the product's own installer, the real privileged `netd` and unprivileged
  `serve`, the real authenticated HTTP surface, a real handshake, dual-stack
  IPv4/IPv6 traffic, and API telemetry
  (`plans/closure/macos-native-server-corrective/c001-status.md`);
- the **arm64 cold-reboot leg** (C002) ran end to end on a disposable arm64
  macOS 26.6.2 guest under UTM on the Apple Virtualization.framework backend,
  with the reboot observed (the kernel boot time advanced), both roles back
  from the system domain, the management identity still unprivileged, the
  credential and enrolled client surviving, the network reconverging, and the
  uninstall leaving nothing behind
  (`plans/closure/macos-native-server-corrective/c002-status.md`).

The **Intel** arch of both legs was never run, and it could not be:

- a GitHub-hosted macOS job runs in a **fresh VM that is discarded when the job
  ends**, so a system-domain boot after a reboot cannot be observed there;
- **nested virtualization is unsupported on macOS runners** ("Nested-virtualization
  is not supported due to the limitation of Apple's Virtualization Framework"),
  and an independent probe of all four hosted macOS images found the Intel image
  equally unable to start a guest, so a macOS guest cannot be booted inside a
  runner to reboot it instead. GitHub's own tracking issue for the hypervisor
  framework on macOS runners is closed as not planned;
- macOS **larger runners do not offer Azure private networking or static IP
  assignment**, and hosted macOS runners span so many IP address ranges that
  GitHub declines to recommend them as allowlists for internal resources, so the
  private-LAN peer C001 needs is unreachable from a hosted Intel runner;
- the only verified substitute is a **rented bare-metal Intel Mac** (an EC2 Mac
  `mac1.metal`, a 2018 Intel Mac mini on a dedicated host with a 24-hour minimum
  allocation, per-second billing, and an ordinary OS reboot via
  `reboot-instances`) registered as a self-hosted runner. That is a paid host per
  qualification cycle for a platform Apple is abandoning.

The platform itself has moved: Apple silicon is the only macOS platform Apple
still develops for, and GitHub's `macos-15-intel` image is the last x86_64
macOS runner Actions will offer, available only until about August 2027, after
which "the x86_64 architecture will not be supported on GitHub Actions". The
project's own hosted Intel job therefore has a shelf life anyway.

This ADR decides the **Darwin target set** for the native macOS server. It does
not touch the Linux line, the desired-state store, the management HTTP surface,
the client enrollment format, or the release authority.

## 2. Options and evidence

- **Keep Intel as a qualification target.** Rejected: it requires a rented
  bare-metal Intel Mac for every cycle, keeps two CI jobs and two helper
  builds alive, and buys evidence for a platform with no vendor support path.
- **Keep `x86_64-apple-darwin` buildable but unqualified.** Rejected: an
  installable-but-unqualified platform is an unqualified support claim. The
  repo's own rule is that an unsupported OS/arch/mode must visibly refuse
  (ADR-008 §4, and M007's release-qualification requirements).
- **Keep a cross-compile check for Intel.** Rejected as incoherent with an
  arm64-only supported set: compiling for a triple the installer refuses
  protects nothing and keeps the "two targets" reading alive in the docs.
- **Emulated Intel.** Already excluded: ADR-008 §5 states that Rosetta
  translation never counts as native Intel evidence, and nothing here reopens
  it.
- **Drop Intel as a target.** Chosen.

## 3. Decision

1. The Darwin target set is `aarch64-apple-darwin` **only**. The platform's
   `SUPPORTED_TARGETS` and the installer's `DARWIN_TARGETS` carry one entry
   each, and the declared helper build input names one Darwin target.
2. The installer **refuses** any other Darwin triple with an actionable error
   that names the supported target. An Intel Mac visibly refuses to install
   rather than running an unqualified build.
3. The macOS qualification workflow keeps **one architecture** (the arm64
   hosted runner). No Intel job, no Intel helper artifact, and no
   `x86_64-apple-darwin` cross-compile gate remain.
4. The macOS native-server line's **published scope is Apple silicon**, on the
   unchanged macOS 13.0 support floor.
5. C001's and C002's Intel residuals are **removed by scope, not by evidence**.
   Both close on the arm64 controlled-host evidence already recorded; neither
   closure is claimed from expected evidence.
6. The dual-architecture gates in C003, C005, and M007 are **amended** to
   arm64-only, by dated amendment citing this ADR.
7. **Nothing about the Linux line changes**: Linux's architectures, artifacts,
   installer, gates, and release behavior are untouched.

## 4. Normative invariants

- The macOS server's supported target is Apple silicon. "Supported" means
  *qualified*: an unqualified platform must refuse, not degrade.
- A refusal must be actionable: it names the unsupported triple and the
  supported one.
- The macOS support floor stays macOS 13.0. Dropping a *architecture* is not a
  floor change and must not quietly move the OS floor.
- The desired-state store, the management HTTP surface, the client enrollment
  format, the typed IPC vocabulary, and the Linux backends are unchanged.
- No macOS release, tag, or asset is claimed by this ADR.

## 5. Contract/migration/distribution consequences

- **No protocol, schema, state, wire, or CLI change.** The refusal happens
  before any artifact is installed and touches no persistent state.
- **No released macOS artifact exists**, so no installed population needs
  migration. A developer machine that installed a development build on Intel is
  now refused at install time; that refusal is the intended behavior.
- The macOS helper's declared build input loses its second target. The
  upstream source, tag, commit, license, and toolchain are unchanged; only the
  target list narrows, and the provenance receipt records the narrower build.
- macOS release packaging, when it exists, is arm64-only.
- Linux artifacts, the Linux installer, and the Linux release gates are
  unaffected.

## 6. Integration and closure consequences

- C001 and C002 close on their recorded arm64 controlled-host evidence, with
  their Intel residuals retired by this ADR rather than by new measurement.
- C003's, C005's, and M007's architecture gates are amended to arm64-only.
  C003 remains unimplemented and unqualified; C004 and C005 remain open.
- **M007's MUST-NOT-release standing is unchanged.** The routed-LAN capability
  (C003) is still unimplemented, the PF/NAT distribution gate (ADR-008 §2,
  TN3165) is still unresolved, and the release authority is still the
  maintainer's.
- The corrective roadmap and the registry carry the amended gates and the two
  new closures.

## 7. Source references

- ADR-008 §5 (the superseded Darwin target list) and §4 (the actionable-refusal
  invariant).
- `plans/closure/macos-native-server-corrective/c001-status.md` and
  `plans/closure/macos-native-server-corrective/c002-status.md` (the arm64
  controlled-host evidence).
- `plans/subsystems/macos-native-server-corrective-roadmap.md` (the unblock
  assessment and the hosted-runner rule).
- GitHub-hosted runners reference: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- GitHub-hosted runner images, the Intel image's retirement window:
  https://github.com/actions/runner-images/issues/13045
- Nested virtualization on macOS runners, and the independent probe of all
  hosted macOS images:
  https://github.com/Sanne/incus-spawn/issues/774
- GitHub's tracking issue for the hypervisor framework on macOS runners:
  https://github.com/actions/runner-images/issues/13505
- Amazon EC2 Mac instances (the rented bare-metal Intel alternative that this
  ADR declines to fund):
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-mac-instances.html
