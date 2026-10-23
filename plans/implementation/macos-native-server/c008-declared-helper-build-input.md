# macOS Native Server C008 — Declared Helper Build Input and Provenance

Status: **active**; the implementation is in this branch and the closure
evidence is in `plans/closure/macos-native-server-corrective/c008-status.md`.
Baseline: `plans/macos-native-support@1bf4bb3`.
Source: corrective roadmap C005 item 4
(`plans/implementation/macos-native-server/c005-release-qualification-and-reconciliation.md`);
ADR-006 (supply chain) and ADR-008 (release authority);
`plans/subsystems/macos-native-server-corrective-roadmap.md` §1 line 20.
Authority: `plans/003-planning-process.md` §13 (corrective passes), §12
(security rule), §15 (documentation authority).
Primary class: corrective / infrastructure.

## 1. The gap, as observed

The Darwin dataplane is a supervised `wireguard-go` helper. The product
verifies that helper's digest against the **install receipt** before every
spawn (`src/wireguard/darwin.rs::verify_helper_sha256`), and the install
receipt records the digest of the bytes that were installed
(`src/launchd.rs::install_to_root`). That is a sound *runtime* anchor: a
replaced helper is refused rather than executed.

It is not a *supply-chain* anchor. The chain from the upstream source to the
installed bytes is asserted only inside a CI workflow:

```yaml
# .github/workflows/macos-qualification.yml, twice, verbatim
git clone --branch 0.0.20250522 --depth 1 https://github.com/WireGuard/wireguard-go "$RUNNER_TEMP/wireguard-go-src"
test "$(git -C "$RUNNER_TEMP/wireguard-go-src" rev-parse 'HEAD^{commit}')" = "f333402bd9cbe0f3eeb02507bd14e23d7d639280"
grep -q 'Permission is hereby granted, free of charge' "$RUNNER_TEMP/wireguard-go-src/LICENSE"
(cd "$RUNNER_TEMP/wireguard-go-src" && go build -o "$RUNNER_TEMP/wireguard-go" .)
shasum -a 256 "$RUNNER_TEMP/wireguard-go" | tee "$RUNNER_TEMP/wireguard-go.sha256"
```

Three properties follow, and all three are gaps:

1. **The declaration is not an input of the repository.** The upstream URL,
   tag, commit, license, and toolchain version exist only as literals
   inside a workflow file. Nothing in the repository *declares* the helper
   as a build input, so nothing can check the declaration, and no
   consumer (a second workflow, a local build, a release pipeline) can
   refer to it.
2. **The declaration is duplicated.** The same eleven lines are pasted into
   the arm64 job and the Intel job. They can drift, and when they do, the
   two architectures can be qualified against *different* helpers while
   still looking identical in the workflow.
3. **The evidence is not recorded as an artifact.** The digest is written
   to a scratch file that is consumed by the next step and then discarded.
   The upstream commit, the license, the Go toolchain version, the target
   triple, and the build settings are never captured together, so a
   qualification run cannot afterwards be tied to a specific helper build.

C005 item 4 asks for exactly this to be fixed: "make pinned `wireguard-go`
per-target helper a declared, immutable build input with recorded upstream
commit/tag, MIT license, Go compiler/toolchain and SHA-256 evidence."

## 2. Why this is a corrective and not a C005 body of work

C005 is dispositioned **blocked** on C001 and C002's closure, and the
release decision it carries is not the maintainer's to take by code. The
*repository engineering* half of item 4 — declaring the build input,
verifying it, and recording the evidence — does not depend on any of that
and is not the subject of C005's block. Per §13 a material gap is corrected
under its own plan, with its own closure record, and C005's own record
stays period-accurate.

C005's remaining clauses stay with C005: the Eggpack producer/consumer
integration (a different repository), the exact-target package and
installer, the cross-architecture mixing refusal, the SBOM and advisory
record, and the release-mode footprint figures.

## 3. The fix

### 3.1 One declared input

`helper/wireguard-go.provenance.json` declares the helper's build input:
the upstream repository URL, the release tag, the **immutable commit**, the
SPDX license identifier and the license text marker to look for, the Go
toolchain version, the supported target triples, and the build flags.

It is the single source of truth. The builder reads it, the tests check it,
and the documentation points at it. Nothing else may name the upstream
source.

### 3.2 One builder

`scripts/build-wireguard-go-helper.py` builds the helper from the
declaration and refuses to continue unless every declared property holds:

- the clone's `HEAD` **is** the declared commit (not merely a tag that
  could move);
- the checkout is clean;
- the license file exists and contains the declared marker, and its digest
  is recorded;
- the Go toolchain's version **is** the declared version;
- the build is done for the declared target triple with the declared flags.

It writes two artifacts: the helper binary, and a **provenance receipt**
recording the source URL, tag, resolved commit, license identifier and
license file digest, the Go version, the target triple, the build flags,
the binary's SHA-256, and the binary's own embedded build settings
(`go version -m`, which carries `vcs.revision`, `vcs.modified`, `GOOS`,
`GOARCH`, and the Go version the binary was built with).

The builder is a repository script, not product code: it executes `git` and
`go`, and it is not reachable from the product's privileged boundary. The
architecture guards continue to pin process execution inside `src/` to the
audited backends.

### 3.3 One workflow path

The macOS qualification workflow calls the builder in both live jobs and
uploads the receipt as an artifact. The inline clone-and-build block is
removed from both, so the two architectures cannot be qualified against
different helpers.

### 3.4 The declaration cannot drift

`tests/helper_provenance.rs` checks the properties that a build cannot
check for itself:

- the declaration is well formed, and every value is pinned (a full
  40-character commit, a fixed toolchain version, the two Darwin
  triples, a pinned license);
- the builder reads the declaration, and does **not** name the upstream
  source itself;
- the workflow calls the builder and contains **no** inline clone of the
  helper source, so there is exactly one place where the helper is built.

## 4. Ordered work packages

1. `helper/wireguard-go.provenance.json` — the declaration.
2. `scripts/build-wireguard-go-helper.py` — the builder and receipt writer.
3. `tests/helper_provenance.rs` — the drift guards.
4. `.github/workflows/macos-qualification.yml` — one builder, receipts as
   artifacts.
5. `architecture/wireguard-control.md` — the declared build input as
   current behavior.
6. `docs/development.md` — how to build the helper locally and what the
   receipt contains.
7. `architecture/testing-qualification.md` — the new suite in the catalog.

## 5. Privilege and security effects

None on the product. The builder runs in the developer or CI environment
with the privileges of that environment; it clones a public repository,
builds one binary, and writes it plus a receipt. It never installs, never
touches `/usr/local`, never mutates PF, launchd, or the network, and never
runs on a qualification host.

The declaration pins the helper to an **immutable commit**, not to a tag
that can move, and the builder fails closed when the clone does not match
it, when the license marker is absent, or when the toolchain is not the
declared version. A helper built from a different source is not produced
by this path.

## 6. Compatibility effects

The built helper's bytes change (the build now pins `-trimpath` and the
toolchain is checked rather than assumed), so its SHA-256 differs from the
value the previous workflow produced. Nothing pins that digest: the
runtime anchor is the install receipt, which records whatever was
installed, and the qualification passes the build's digest in through
`WGB_HELPER_SHA256` as before.

No wire format, schema, protocol message, CLI surface, Linux path, or
installed state changes.

## 7. Failure, cancellation, and contention semantics

The builder fails closed and says which declared property did not hold. It
writes no partial receipt: the receipt is written only after the build and
every verification have succeeded. A cancelled or failed build leaves the
output directory without a receipt, so a consumer that requires the receipt
cannot pick up a half-built helper.

## 8. Focused tests

- `tests/helper_provenance.rs` — the declaration's properties, the builder's
  use of it, and the workflow's single-builder property.
- The builder's own end-to-end run: a real clone, a real build for each
  Darwin triple, a real receipt, and the digests it records.

## 9. Broad verification commands

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.89.0 check --all-targets --locked
```

Plus the hosted macOS qualification workflow (arm64 and Intel) to prove the
builder produces a helper both architectures can qualify against, and the
Linux native CI for the no-regression claim.

## 10. Documentation updates

- `architecture/wireguard-control.md` — the declared build input and the
  receipt.
- `docs/development.md` — the local build procedure.
- `architecture/testing-qualification.md` — the new suite.

## 11. Acceptance criteria

1. The upstream source, tag, commit, license, and toolchain version are
   declared in exactly one place in the repository.
2. The builder refuses to produce a helper whose clone does not match the
   declared commit, whose license marker is absent, or whose toolchain is
   not the declared version.
3. The builder records a provenance receipt with the upstream commit, the
   license identifier and license digest, the Go version, the target
   triple, the build flags, the binary's SHA-256, and the binary's embedded
   build settings.
4. The macOS qualification workflow builds the helper through the builder
   in both live jobs, and contains no inline clone of the helper source.
5. The receipt is retained as a CI artifact of the qualification run.
6. Every gate in §9 is green, and the Linux native CI shows no regression.

## 12. Stop conditions

Stop and record the discrepancy rather than working around it if:

- the declared upstream commit or tag is no longer reachable, or the
  license marker no longer matches — the helper's provenance may not be
  re-declared on trust;
- the build cannot be made to produce the same digest from the same source
  and toolchain, because a helper that cannot be reproduced is not a
  declared input — in that case the *non-reproducibility* is the finding to
  record, not a licence to record an arbitrary digest;
- the receipt would have to carry a secret, a credential, or a path that
  identifies a developer's machine.

## 13. Closure evidence requirements

`plans/closure/macos-native-server-corrective/c008-status.md` must record:
the implementation head and baseline, the requirement-to-evidence matrix
against §11, the exact commands and their output, the real receipts the
builder produced for both Darwin triples with their digests, the hosted
workflow run that used the builder, the security evidence (what the
builder refuses), the documentation evidence, the known limitations, the
unresolved findings by severity, and an explicit disposition that leaves
C005's own disposition unchanged.
