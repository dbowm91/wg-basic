# macOS Native Server C008 — Declared Helper Build Input and Provenance

Disposition: **closed** (2026-10-21) — the helper's build input is now a
single declared, immutable input; one builder produces it, refuses a
mismatched source, license, or toolchain, and records a provenance receipt;
the macOS qualification workflow builds through that builder on both
architectures and keeps the receipt as a run artifact. C005's own
disposition is unchanged: its release decision, the Eggpack producer and
consumer integration, the exact-target package, the cross-architecture
mixing refusal, the SBOM and advisory record, and the release-mode footprint
figures remain C005's, blocked on C001 and C002's closure and on the
maintainer's release authority.

Date: 2026-10-21.

Source plan: `plans/implementation/macos-native-server/c008-declared-helper-build-input.md`.
Baseline: `plans/macos-native-support@1bf4bb3`.
Implementation head: `62337c5` (the declaration, the builder, the guards, the
workflow, the docs).

## Implementation revision

- Repository baseline: `1bf4bb3` (C007's verifier).
- Implementation commit: `62337c5` — *macos(c008): declare the helper build
  input and record its provenance*.
- The gap was raised by C005 item 4 of
  `plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md`
  and by the corrective roadmap's gap list line 20
  (`plans/subsystems/macos-native-server-corrective-roadmap.md`). C005 is
  dispositioned blocked on C001 and C002, and the release decision it
  carries is not a code decision; the *repository engineering* half of item 4
  — declaring the build input, verifying it, and recording the evidence —
  depends on none of that. Per `plans/003-planning-process.md` §13 it was
  corrected under its own plan, with its own closure record and its own
  evidence. C005's record and disposition are not rewritten.

## The gap, as it was

The helper's upstream source, tag, commit, license, and toolchain existed
only as literals pasted into `.github/workflows/macos-qualification.yml`,
twice, verbatim:

```yaml
git clone --branch 0.0.20250522 --depth 1 https://github.com/WireGuard/wireguard-go "$RUNNER_TEMP/wireguard-go-src"
test "$(git -C "$RUNNER_TEMP/wireguard-go-src" rev-parse 'HEAD^{commit}')" = "f333402bd9cbe0f3eeb02507bd14e23d7d639280"
grep -q 'Permission is hereby granted, free of charge' "$RUNNER_TEMP/wireguard-go-src/LICENSE"
(cd "$RUNNER_TEMP/wireguard-go-src" && go build -o "$RUNNER_TEMP/wireguard-go" .)
shasum -a 256 "$RUNNER_TEMP/wireguard-go" | tee "$RUNNER_TEMP/wireguard-go.sha256"
```

Nothing in the repository *declared* the helper as a build input, so nothing
could check the declaration and no other consumer could refer to it; the two
architecture jobs carried their own copies and could drift; and the digest
was written to a scratch file that the next step consumed and then
discarded, so a qualification run could not afterwards be tied to a
specific helper build.

The product's runtime anchor was never at risk: the install receipt records
the digest of the installed bytes and the product refuses a helper whose
bytes changed. What was missing was the chain from the upstream source to
those bytes.

## The correction

### One declared input

`helper/wireguard-go.provenance.json` declares the upstream repository, the
release tag, the **immutable 40-character commit**, the SPDX license
identifier and the license text marker to look for, the Go toolchain
version, the two Darwin target triples, and the build flags. It is the
single source of truth; nothing else in the repository names the upstream
source, and the guards below prove it.

### One builder

`scripts/build-wireguard-go-helper.py` builds the helper from the
declaration and refuses to continue unless every declared property holds:
the clone's `HEAD` **is** the declared commit, the checkout is clean, the
license file carries the declared marker, and the Go toolchain is the
declared version. It writes the helper, a `sha256` file, and a **provenance
receipt** recording the source URL, tag and commit, the license identifier
and license file digest, the Go version, the target triple, the build flags,
the artifact's SHA-256 and size, and the binary's own embedded build
settings — including the `vcs.revision` stamp, which carries the same
commit.

### One workflow path

Both live jobs call the builder and upload the receipt as a run artifact;
the inline clone-and-build block is gone from both, so the two
architectures cannot be qualified against different helpers.

### The declaration cannot drift

`tests/helper_provenance.rs` (7 tests) pins the declaration's properties
and the absence of duplication: the declaration is well formed and fully
pinned; the builder reads the declaration and names neither the upstream URL
nor the commit nor the tag; the workflow calls the builder and contains no
`git clone` and no upstream URL.

## Requirement-to-evidence matrix

| Requirement (plan §11) | Evidence | Result |
|---|---|---|
| §11.1 The upstream source, tag, commit, license, and toolchain version are declared in exactly one place | `helper/wireguard-go.provenance.json` holds all of them. The guard `the_builder_reads_the_declaration_and_names_no_source_of_its_own` asserts the builder names neither the URL nor the tag nor the commit; `the_workflow_builds_the_helper_through_the_one_builder` asserts the workflow contains no `git clone` and no upstream URL | Passed (code + guard) |
| §11.2 The builder refuses a helper whose clone, license, or toolchain does not match the declaration | `load_declaration` validates the declaration's shape and fails closed; `clone_source` compares the resolved commit with the declared one and refuses a dirty checkout; `verify_license` requires the declared marker; `verify_toolchain` requires the exact declared Go version. The guard `the_builder_refuses_a_mismatched_source_license_or_toolchain` pins each refusal message. Observed refusals are reproduced in *Verification* below | Passed (code + guard + observed) |
| §11.3 The builder records the receipt's evidence | The receipt is written by `write_receipt` after every verification succeeded, and carries source, license, toolchain, target, flags, artifact digest and size, and the binary's embedded build settings. A real receipt is reproduced in full below | Passed (code + observed) |
| §11.4 The workflow builds the helper through the builder on both architectures and carries no inline clone | `.github/workflows/macos-qualification.yml`: both live jobs run `python3 scripts/build-wireguard-go-helper.py --output-dir "$RUNNER_TEMP/helper" --target "$target"` with the target derived from `uname -m`, and the Go toolchain version is read from the declaration rather than written in the workflow. The guard asserts the builder call, the absence of `git clone`, and the absence of the upstream URL | Passed (code + guard) |
| §11.5 The receipt is retained as a CI artifact of the qualification run | Both live jobs upload `macos-helper-provenance-arm64` / `macos-helper-provenance-intel` with `if: always()` | Passed (workflow) |
| §11.6 Every gate is green and the Linux native CI shows no regression | See *Verification* | Passed |

## The real build

On the maintainer's macOS 26.6.2 arm64 host, with Go 1.27.1:

```text
$ python3 scripts/build-wireguard-go-helper.py --output-dir ~/wg-helper-build/aarch64 --target aarch64-apple-darwin
built wireguard-go for aarch64-apple-darwin
sha256: ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705

$ python3 scripts/build-wireguard-go-helper.py --output-dir ~/wg-helper-build/x86_64 --target x86_64-apple-darwin
built wireguard-go for x86_64-apple-darwin
sha256: 98ed1addfddc0eb28b7458a7d23b523c76d16bf264fadc98b4cd58e2f3fe6dd9

$ shasum -a 256 ~/wg-helper-build/aarch64/wireguard-go ~/wg-helper-build/aarch64-2/wireguard-go ~/wg-helper-build/x86_64/wireguard-go
ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705  .../aarch64/wireguard-go
ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705  .../aarch64-2/wireguard-go
98ed1addfddc0eb28b7458a7d23b523c76d16bf264fadc98b4cd58e2f3fe6dd9  .../x86_64/wireguard-go

$ file ~/wg-helper-build/aarch64/wireguard-go ~/wg-helper-build/x86_64/wireguard-go
.../aarch64/wireguard-go: Mach-O 64-bit executable arm64
.../x86_64/wireguard-go:  Mach-O 64-bit executable x86_64
```

Two independent arm64 builds, each from a fresh clone of the declared
commit, produced the **identical** digest: the declared build input is
byte-reproducible, and the two architectures differ only by target triple.
The hosted runners later produced the **same two digests** (see *Hosted
qualification*), so the reproducibility holds across machines as well.

The arm64 receipt, reproduced in full:

```json
{
  "artifact": {
    "file": "wireguard-go",
    "sha256": "ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705",
    "size_bytes": 4674242
  },
  "build": {
    "flags": ["-trimpath"],
    "settings": [
      "go1.27.1",
      "\tpath\tgolang.zx2c4.com/wireguard",
      "\tmod\tgolang.zx2c4.com/wireguard\tv0.0.0-20250521234502-f333402bd9cb\t",
      "\tdep\tgolang.org/x/crypto\tv0.37.0\th1:kJNSjF/Xp7kU0iB2Z+9viTPMW4EqqsrywMXLJOOsXSE=",
      "\tdep\tgolang.org/x/net\tv0.39.0\th1:ZCu7HMWDxpXpaiKdhzIfaltL9Lp31x/3fCP11bc6/fY=",
      "\tdep\tgolang.org/x/sys\tv0.32.0\th1:s77OFDvIQeibCmezSnk/q6iAfkdiQaJi4VzroCFrN20=",
      "\tbuild\t-buildmode=exe",
      "\tbuild\t-compiler=gc",
      "\tbuild\t-trimpath=true",
      "\tbuild\tCGO_ENABLED=0",
      "\tbuild\tGOARCH=arm64",
      "\tbuild\tGOOS=darwin",
      "\tbuild\tGOARM64=v8.0",
      "\tbuild\tvcs=git",
      "\tbuild\tvcs.revision=f333402bd9cbe0f3eeb02507bd14e23d7d639280",
      "\tbuild\tvcs.time=2025-05-21T23:45:02Z",
      "\tbuild\tvcs.modified=false"
    ]
  },
  "builder": {
    "declaration": "helper/wireguard-go.provenance.json",
    "script": "scripts/build-wireguard-go-helper.py"
  },
  "helper": "wireguard-go",
  "license": {
    "file": "LICENSE",
    "marker": "Permission is hereby granted, free of charge",
    "sha256": "91276db973f25602d1aa43491f59cbc84cb88e6f151e1d0cc82a755563ce0195",
    "spdx": "MIT"
  },
  "schema_version": 1,
  "source": {
    "commit": "f333402bd9cbe0f3eeb02507bd14e23d7d639280",
    "tag": "0.0.20250522",
    "url": "https://github.com/WireGuard/wireguard-go"
  },
  "target": "aarch64-apple-darwin",
  "toolchain": {
    "go_version": "1.27.1",
    "reported": "go version go1.27.1 darwin/arm64"
  }
}
```

The module version the build recorded —
`v0.0.0-20250521234502-f333402bd9cb` — carries the same commit as the
declared one, and the binary's `vcs.revision` stamp is that commit with
`vcs.modified=false`, so the artifact names its own source.

## Verification

Local, on the implementation head:

```text
$ cargo fmt --all -- --check
(no output — clean)

$ cargo clippy --all-targets --locked -- -D warnings
(no output — clean)

$ cargo test --locked
664 passed; 0 failed

$ cargo +1.89.0 check --all-targets --locked
Finished `dev` profile

$ cargo check --locked --target x86_64-apple-darwin --all-targets
Finished `dev` profile
```

The builder's own refusals, observed:

```text
$ python3 scripts/build-wireguard-go-helper.py --output-dir /tmp/x --target aarch64-unknown-linux-gnu
helper build refused: aarch64-unknown-linux-gnu is not one of the declared targets

$ PATH=<a go that reports 1.26.0> python3 scripts/build-wireguard-go-helper.py --output-dir /tmp/x --target aarch64-apple-darwin
helper build refused: the Go toolchain is 1.26.0, but the declared version is 1.27.1

$ python3 scripts/build-wireguard-go-helper.py --output-dir /tmp/x --target aarch64-apple-darwin
   (with the declaration's commit changed to 000…0)
helper build refused: the clone resolved to commit f333402bd9cbe0f3eeb02507bd14e23d7d639280, but the declared commit is 0000000000000000000000000000000000000000

$ python3 scripts/build-wireguard-go-helper.py --output-dir /tmp/x --target aarch64-apple-darwin
   (with the declaration's license marker changed to one the file does not carry)
helper build refused: the declared license marker is not present in the license file
```

A refused build leaves **no** receipt in its output directory, so a consumer
that requires the receipt cannot pick up a half-built helper.

Hosted: the macOS qualification workflow builds the helper through the
builder on both architectures and uploads the receipt; see *Hosted
qualification* below.

## Hosted qualification

The macOS qualification runs of the implementation head build the helper
through the declared builder on the arm64 and the Intel runner, and upload
the receipt as `macos-helper-provenance-arm64` /
`macos-helper-provenance-intel`. From run **39557938154**
(`macos(c008): declare the helper build input and record its provenance`, all
four jobs green), the two receipts:

| | arm64 runner | Intel runner |
|---|---|---|
| target | `aarch64-apple-darwin` | `x86_64-apple-darwin` |
| source commit | `f333402bd9cbe0f3eeb02507bd14e23d7d639280` | the same |
| release tag | `0.0.20250522` | the same |
| license | MIT, `91276db973f25602…` | the same |
| toolchain | `go1.27.1` (`darwin/arm64`) | `go1.27.1` (`darwin/amd64`) |
| build flags | `-trimpath` | `-trimpath` |
| artifact SHA-256 | `ccc10eaf95306a80eb1fe91fee2d9c9d5f8585be43b44384cb2a28fa1093e705` | `98ed1addfddc0eb28b7458a7d23b523c76d16bf264fadc98b4cd58e2f3fe6dd9` |
| artifact size | 4 674 242 bytes | 4 968 784 bytes |
| VCS stamp | `vcs.revision=f333402bd9cbe…`, `vcs.modified=false` | the same |
| build run | `39557938154` attempt 1 | the same |
| developer path in the receipt | none | none |

**Both hosted artifacts are byte-identical to the locally built ones.** The
arm64 runner's digest equals the digest this maintainer's M4 Pro produced
from the same declared commit, and the Intel runner's digest equals the
cross-built one. The declared build input is therefore reproducible not only
across repeated builds but **across machines and across architectures**: the
same source, toolchain, and flags give the same bytes for a given target,
and different targets give different bytes.

The live fixtures of the same run then qualified against those helpers: the
helper digest the fixture checks is the one the builder recorded, and the
run's `live-arm64` and `live-intel-tunnel` jobs are green.

## Security and ownership evidence

- The builder runs in a developer or CI environment, with that environment's
  privileges. It clones a public repository, builds one binary, and writes
  the binary plus a receipt. It never installs, never writes
  `/usr/local`, never touches PF, launchd, the network, or any state, and
  it never runs on a qualification host.
- The build input is pinned to an **immutable commit**, not to a movable
  tag, and the builder fails closed when the clone does not match it, when
  the checkout is not clean, when the license marker is absent, or when the
  toolchain is not the declared version. A helper built from a different
  source is not produced by this path.
- The product's runtime anchor is unchanged: the install receipt still
  records the digest of the installed bytes, and the product still refuses
  a helper whose bytes changed (`verify_helper_sha256` before every spawn).
  The declaration adds the chain from the upstream source to those bytes;
  it does not weaken the runtime check.
- The receipt carries no secret, no credential, and no developer path: the
  binary's own path is stripped from the recorded build settings, and the
  receipt names the builder script and the declaration, not the machine.
- Process execution inside `src/` is untouched: the builder is a repository
  script, outside the product's privileged boundary, and the architecture
  guard that pins process execution to the audited backends still holds.

## Docs and operations evidence

- `architecture/wireguard-control.md` — the declared build input and the
  receipt are now the documented current behavior of the Darwin backend.
- `docs/development.md` — *Building the pinned wireguard-go helper* records
  the local procedure, what the builder refuses, and what the receipt
  contains.
- `architecture/testing-qualification.md` — the new suite is in the catalog.
- `plans/implementation/macos-native-server/c008-declared-helper-build-input.md`
  — this corrective's plan.
- `plans/subsystems/macos-native-server-corrective-roadmap.md` and
  `plans/registry.md` — C008's status and its effect on C005.

## Known limitations

1. **The declaration covers the build, not the release.** The Eggpack
   producer/consumer integration, the exact-target package and installer,
   the refusal of cross-architecture mixing, the SBOM and advisory record,
   and the release-mode footprint figures remain C005's. The Eggpack
   integration is a different repository and is not touched here.
2. **The declaration proves the helper's source, not the whole release's.**
   The `wg-basic` binary itself, its install receipt, and the trust root
   are covered by the release-readiness line, not by this corrective.
3. **The build is reproducible, not bit-for-bit guaranteed across
   toolchain updates.** A new Go release may produce different bytes; the
   declaration pins the toolchain precisely so that a change is visible
   rather than silent, and the receipt records the toolchain that built each
   artifact.
4. **The receipt is a build record, not a signature.** It is not signed and
   makes no trust claim; the existing checksums-only release policy is
   unchanged.
5. **No release claim exists.** ADR-008/M007 still withholds every macOS
   release; this record changes nothing about that.

## Unresolved findings by severity

- **Medium (pre-existing, fixed here):** the helper's build input was
  duplicated inside the qualification workflow, once per architecture, and
  existed nowhere as a declared input. The two jobs could have drifted, and
  nothing could have checked the declaration. There is now one declaration
  and one builder, and the guards fail if either duplicates.
- **Medium (pre-existing, fixed here):** the qualification run's helper
  evidence was not retained: the digest went to a scratch file that the
  next step consumed and discarded, and the upstream commit, the license,
  the toolchain, the target, and the build settings were never captured
  together. The receipt records all of them and is uploaded as a run
  artifact.
- **Low (introduced by this change, fixed here):** the first version of the
  builder recorded `go version -m`'s first line verbatim, which names the
  binary by its **absolute path** — on a developer machine that identifies
  the machine. The path is now stripped, and the receipt records the
  toolchain version instead. The built bytes are unaffected, because
  `-trimpath` keeps local paths out of the binary.
- **Medium (pre-existing, out of scope):** the `dependency-audit` CI job
  fails on three upstream `zip 6.0.0` advisories reached through
  `eggup-archive = "=0.1.3"`. Not resolvable in this repository without an
  upstream release; unrelated to this corrective.
- **Informational:** the helper's digests change with this corrective
  (`-trimpath` and a checked toolchain). Nothing pinned them: the runtime
  anchor is the install receipt, which records whatever was installed, and
  the qualification passes the build's digest in through `WGB_HELPER_SHA256`
  as before.

## Disposition

**Closed.** The helper's build input is a single declared, immutable input;
one builder produces it, refuses a mismatched source, license, or
toolchain, and records a provenance receipt that ties the artifact to the
upstream commit, the license, the toolchain, and the target; the macOS
qualification workflow builds through that builder on both architectures and
keeps the receipt as a run artifact; and the guards fail if the
declaration, the builder, or the workflow ever duplicate each other. The
release decision, the Eggpack integration, the exact-target package, and
the release-mode measurements are **not** claimed here: they remain C005's,
whose disposition is unchanged. No macOS release, tag, or asset is claimed,
and M007's MUST-NOT-release standing is unchanged.
