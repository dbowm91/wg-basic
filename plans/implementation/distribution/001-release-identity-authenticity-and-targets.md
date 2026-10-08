# Distribution M001 — Release Identity, Authenticity, and Target Qualification

Status: ready

Repository implementation baseline: `f5a32c0a6123467321b124182dfeb63e2e62118a`

Planning baseline:

- ADR-006 at `842e8a0`;
- Phase 10 roadmap at `3fc8531`.

Source roadmap:

- `plans/subsystems/distribution-install-update-roadmap.md#5-m001--signed-release-identity-target-contract-and-verifier`

Canonical architecture:

- `plans/adr/006-distribution-install-authenticity-and-update.md`

Primary class: release identity / supply-chain trust / platform qualification

## 1. Objective

Establish the exact Phase 10 release identity, target set, compatibility floor, producer contract, and detached-signature verifier before any installer or self-update path is allowed to mutate a live installation.

M001 produces trusted release primitives and target evidence only.

It MUST NOT install system services, replace the running binary, migrate live state, or implement automatic update.

## 2. Stable release identity

Define one product-owned release/version module used by:

- CLI `--version`;
- release-contract tests;
- updater candidate validation;
- producer checks.

Required invariants:

```text
Cargo package version        X.Y.Z
Git release tag              vX.Y.Z
wg-basic --version           wg-basic X.Y.Z
Eggpack product ID           wg-basic
Eggpack release ID           X.Y.Z
Release source revision      exact tagged commit
```

Phase 10 supports stable SemVer only.

Add strict parser/comparator tests for:

- malformed versions;
- leading-zero components;
- prerelease/build metadata rejection for Phase 10 policy;
- same-version refusal;
- downgrade refusal;
- strict newer-version acceptance.

Do not invent a prerelease channel merely for testing.

## 3. Canonical target module

Add one internal target mapping shared by release/updater/installer tests:

```text
linux/x86_64  -> x86_64-unknown-linux-gnu
linux/aarch64 -> aarch64-unknown-linux-gnu
```

Accept common host aliases only at the host-detection seam:

- `x86_64`, `amd64`;
- `aarch64`, `arm64`.

Reject:

- armv7/arm;
- musl target selection;
- non-Linux OS;
- unknown architecture.

The release-contract target names remain canonical Rust triples, never host aliases.

## 4. Eggpack producer contracts

Create the Phase 10 producer-contract directory:

```text
release/eggpack/
    distribution.toml
    pack.toml
    build-bindings.toml
    qualification-bindings.toml
    consumer-validators.json
    install-policy.toml
    github-policy.json
    github-template.json
    installer-presentation.json
```

M001 owns the static contract files but not the final generated release workflow.

### distribution.toml

Exactly two direct targets:

- `aarch64-unknown-linux-gnu`;
- `x86_64-unknown-linux-gnu`.

Artifacts:

```text
wg-basic-aarch64-unknown-linux-gnu
wg-basic-x86_64-unknown-linux-gnu
```

Install identity remains `wg-basic`.

Each artifact has one SHA-256 sidecar.

No archive/bundle/ARMv7/musl target.

## 5. Build policy

Use the current Eggpack build-policy schema.

Preferred policy:

- `cargo_zigbuild`;
- exact cargo-zigbuild version pinned in producer policy;
- exact Zig version and archive SHA-256 pinned;
- release profile;
- `--locked`;
- native build host matching target architecture where practical;
- declared glibc compatibility floor.

Initial floor candidate: glibc 2.17.

M001 MUST NOT claim 2.17 merely because cargo-zigbuild accepts `.2.17`.

Evidence must include:

1. successful target build;
2. native execution of the exact artifact;
3. dynamic dependency inventory;
4. ELF symbol-version scan proving no required `GLIBC_*` version above the declared floor;
5. target qualification results stored as release evidence.

If any direct/transitive/native dependency requires a newer glibc, raise the producer contract floor to the lowest version actually proven and reconcile ADR/roadmap documentation.

## 6. Native qualification

### x86_64

Run the exact release artifact on a native x86_64 Linux runner.

At minimum:

- `--version`;
- `--help`;
- read-only `doctor --json` against a fixture with expected unsupported/absent runtime checks classified safely;
- no illegal instruction/dynamic loader failure.

### aarch64

Use a native aarch64 Linux runner.

Compilation or QEMU-only evidence cannot close required aarch64 support.

Run the same candidate identity/smoke checks.

The later Phase 10 M005 release lane will add systemd/install/product qualification; M001 proves the binary target itself.

## 7. Release-manifest authenticity model

Implement a small release-auth module that verifies:

```text
release-manifest.json
release-manifest.json.minisig
```

before manifest data is trusted.

Preferred dependency candidate:

```text
minisign-verify = "0.3"
```

M001 must explicitly prove:

- Cargo/MSRV Rust 1.89;
- license/dependency acceptability;
- verifier accepts a valid fixture signature;
- one-byte manifest mutation fails;
- truncated signature fails;
- wrong public key fails;
- malformed public key fails;
- malformed Minisign payload fails;
- signature diagnostics do not echo signed document contents.

Do not add signing/private-key APIs to the runtime.

## 8. Fixture trust root

Tests may contain a clearly named fixture signing keypair whose private key exists only under test/fixture material.

Requirements:

- never reused or labelled production;
- test private key never compiled into normal release binary;
- fixture public key can be used by verifier tests;
- production verifier path has a distinct configuration seam.

Architecture/static guards should reject test-private-key material from non-test modules.

## 9. Production public-key provisioning seam

Define the production trust-root shape without fabricating a real key.

Preferred representation:

- committed public-key text file under `release/trust/`;
- build-time inclusion into the binary;
- canonical human-display fingerprint/key ID;
- exact parser at startup/update verification.

Until the maintainer supplies the real public key:

- the production key file may be absent and production self-update remains compile/runtime-disabled or reports “release trust root not provisioned”;
- tests use the fixture verifier path;
- no placeholder key may be described as production.

The closure record must explicitly state whether production provisioning remains outstanding.

## 10. Authenticated manifest projection

After signature verification:

1. parse via `eggpack-manifest`/`eggup-eggpack`;
2. require product ID `wg-basic`;
3. require exact selected release ID;
4. require exact canonical host target;
5. project artifact exact size and SHA-256;
6. reject extra/ambiguous target selection.

Unsigned manifest bytes MUST never be passed to the update/install trust decision as authoritative metadata.

## 11. Version-policy tests

Using signed fixture manifests:

- signed newer release accepted;
- signed same version refused;
- signed older version refused;
- signed release ID differing from selection refused;
- signed wrong product refused;
- valid signature but absent host target refused;
- unsigned/tampered manifest refused before target/materialization.

Automatic rollback is explicitly exempt from monotonic “newer” policy because it operates on the retained locally verified prior generation, not a newly selected release.

## 12. Release artifact integrity tests

Create release-like fixture assets and prove:

- exact manifest size required;
- exact manifest SHA-256 required;
- wrong size rejected;
- wrong hash rejected;
- symlink/non-regular acquired path rejected by the Eggup adapter;
- executable permission intent preserved.

This is separate from the Minisign check and should remain visibly separate in code/tests.

## 13. Eggup/Eggpack registry graph qualification

Resolve the exact registry-only crate set M001/M004 expect.

At planning time versions differ across the workspace:

- Eggup core/acquisition/eggpack adapter repository is 0.1.3;
- published curl/service may still be 0.1.2.

Before adding dependencies:

1. inspect crates.io-published versions;
2. create an external fixture outside either workspace;
3. resolve the intended exact versions with no Git/path patch;
4. compile/test on Rust 1.89;
5. record the resulting graph.

If the required composition cannot resolve from published crates, stop and write an Eggup publication prerequisite plan in the Eggup repo rather than shipping wg-basic with Git dependencies.

## 14. No production acquisition/update yet

M001 may fetch nothing from GitHub at runtime.

No:

- `update` CLI;
- `install` CLI;
- service mutation;
- root filesystem write;
- release publishing.

Producer-contract validation and CI candidate builds are allowed.

## 15. CI additions

Add bounded Phase 10 foundation jobs:

- release-contract validation;
- x86_64 candidate build + smoke + ELF compatibility scan;
- aarch64 candidate build + smoke + ELF compatibility scan;
- Rust 1.89 verifier/unit tests;
- existing dependency audit.

Generated release workflows belong to M003, not M001.

## 16. Acceptance criteria

M001 closes only when:

1. stable release identity is explicit and tested;
2. exactly two canonical Linux GNU targets exist;
3. both exact target artifacts build and execute natively;
4. declared glibc floor is evidenced rather than copied;
5. Eggpack static producer contracts validate;
6. a verify-only Minisign path passes Rust 1.89;
7. signature/tamper/wrong-key tests are load-bearing;
8. signed manifest product/release/target/version policy is load-bearing;
9. exact Eggup/Eggpack registry dependency graph is known;
10. no install/update mutation exists;
11. production-key provisioning is stated truthfully;
12. all existing Phase 6–9 CI remains green.

## 17. Stop conditions

Stop and write a corrective/prerequisite if:

- the full binary cannot meet the declared glibc floor;
- required aarch64 native qualification is unavailable;
- Minisign verifier raises MSRV above 1.89 or introduces an unacceptable security/license surface;
- Eggup/Eggpack required versions cannot resolve from crates.io;
- implementation needs to trust unsigned manifest fields before signature verification;
- completing M001 would require generating a production private signing key.

## 18. Closure evidence

Record:

- exact release/version contract;
- target/build policy;
- actual glibc symbol/dependency evidence;
- native x86_64/aarch64 smoke;
- Eggpack contract validation;
- verifier crate/version/MSRV/license;
- signature negative matrix;
- signed manifest policy matrix;
- registry-only Eggup graph;
- production public-key provisioning disposition;
- all CI;
- M002 readiness.
